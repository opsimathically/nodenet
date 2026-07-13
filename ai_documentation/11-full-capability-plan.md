# Full raw-networking capability plan

Last updated: 2026-07-12

## Purpose

This document turns “fully capable raw networking for Node.js” into an explicit
Linux capability model and an implementation sequence. It is the detailed
handoff for Phase 5 and the compatibility guide for later family, option,
filter, and performance work.

The design favors typed APIs for common operations and bounded owned-byte
representations for safe forward compatibility. It does not expose unchecked
pointers, borrowed JavaScript memory, the socket's owned fd, or variadic syscall
mirrors.

## Capability model

| Area          | Phase 4 state                          | Planned baseline                                                            |
| ------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| IPv4 raw IP   | Basic send/receive, bind, five options | Full message flags, ancillary data, headers, errors, options, filtering     |
| IPv6 raw IP   | Implemented in Phase 6                 | Scoped addresses, hops/class/pktinfo/errors, message parity                 |
| `AF_PACKET`   | Raw/cooked, controls, batches, RX ring | Hardening; TX mmap/AF_XDP only after separate measurements                  |
| Message I/O   | `sendto`/`recvfrom` behavior           | `sendmsg`/`recvmsg`, control buffers, error queue, cancellation             |
| Extensibility | Closed typed option map                | Typed options plus bounded raw option bytes and owned unknown receive cmsgs |
| Performance   | Bounded mmsg and measured RX ring      | Release hardening and target-specific benchmarking                          |
| Distribution  | Local/source build                     | x86-64 and AArch64 glibc source/prebuilt packages                           |

Netlink configuration, TUN/TAP management, protocol decoders, firewall policy,
and eBPF program loading remain outside the baseline. AF_XDP is a post-baseline
evaluation, not a prerequisite for the first stable release.

## Public API direction

### Family and address model

The API evolves additively around discriminated families:

- `ipv4`: dotted-decimal address and protocol 1 through 255;
- `ipv6`: canonical/accepted IPv6 text plus explicit `scopeId` and `flowInfo`
  where applicable;
- `packet`: interface index, EtherType, packet type, hardware type, and bounded
  link-layer address.

The existing IPv4 string conveniences remain available. New message APIs use
family-specific discriminated address objects so future packet addresses cannot
be mistaken for IP strings. Rust must validate the family tag and every field;
the native layer never interprets a JavaScript buffer as a sockaddr.

### Message primitives

Phase 5 adds `sendMessage()` and `receiveMessage()` while retaining `send()` and
`receive()` as IPv4 compatibility conveniences.

A send request contains owned data, a checked destination, a closed set of
per-call flags, optional typed control messages, and an optional `AbortSignal`.
A receive request contains bounded data/control capacities, a closed set of
flags, and an optional `AbortSignal`.

A receive result contains:

- initialized data and the kernel-reported original data length;
- source address when Linux supplied one;
- `dataTruncated` and `controlTruncated` independently;
- returned message flags;
- typed known control messages;
- unknown receive control messages as `{ level, type, data }`, where `data` is
  copied, initialized, and charged to the control-buffer limit;
- the Phase 4 parsed IPv4 header metadata when a complete header is present.

Unknown outbound control messages are not accepted in Phase 5. They require the
same later safety review as raw socket-option bytes.

The Phase 5 TypeScript names and shapes are fixed as follows (field comments and
readonly modifiers may be added without changing the contract):

```ts
type SendMessageFlag = "dontRoute";
type ReceiveMessageFlag = "peek" | "errorQueue";
type ReceivedMessageFlag = "endOfRecord" | "outOfBand" | "errorQueue";

interface Ipv4MessageAddress {
  family: "ipv4";
  address: string;
}

interface SendMessageRequest {
  data: Uint8Array;
  destination: Ipv4MessageAddress;
  flags?: readonly SendMessageFlag[];
  control?: readonly SendControlMessage[];
  signal?: AbortSignal;
}

interface ReceiveMessageOptions {
  dataCapacity?: number;
  controlCapacity?: number;
  flags?: readonly ReceiveMessageFlag[];
  signal?: AbortSignal;
}

interface ReceivedMessage {
  data: Buffer;
  source: Ipv4MessageAddress | undefined;
  dataLength: number;
  dataTruncated: boolean;
  controlTruncated: boolean;
  flags: readonly ReceivedMessageFlag[];
  control: readonly ReceivedControlMessage[];
  ipv4: Ipv4PacketMetadata | undefined;
}
```

`sendMessage(request)` resolves to bytes sent. `receiveMessage(options?)`
resolves to `ReceivedMessage`. The legacy `send(data, destination, options?)`
and `receive(maxLength?, options?)` methods gain optional `{ signal }` and are
implemented through the same native message machinery without changing their
Phase 4 result shapes.

The initial discriminated control-message kinds are:

- outbound `ipv4PacketInfo` and `ipv4Ttl`;
- inbound `ipv4PacketInfo`, `ipv4Ttl`, `ipv4TypeOfService`,
  `timestampNanoseconds`, `receiveQueueOverflow`, `ipv4ExtendedError`, and
  `unknown`;
- `ipv4ExtendedError` includes errno, origin, ICMP type/code, info, data, and an
  optional offender IPv4 address;
- `unknown` includes signed-safe-integer `level`/`type` and owned Buffer data.

Phase 5 extends the typed option map with `receivePacketInfo`, `receiveTtl`,
`receiveTypeOfService`, `receiveTimestampNanoseconds`, `receiveQueueOverflow`,
and `receiveErrors` booleans plus `bindToDevice: string | null`. Interface names
must be nonempty when binding, contain no NUL, and encode to at most
`IFNAMSIZ - 1` bytes; `null` removes the binding.

When Linux reports `MSG_CTRUNC`, nix intentionally refuses unsafe iteration over
the partial cmsg buffer. The result therefore sets `controlTruncated: true` and
returns an empty control list; it never exposes a partially decoded message.
Malformed control iteration without `MSG_CTRUNC` produces
`ERR_MALFORMED_CONTROL`.

Native receive always adds `MSG_CMSG_CLOEXEC`. Any received `SCM_RIGHTS`
descriptors are unexpected for these socket families and are closed immediately;
they are never exposed as unknown bytes or leaked. Credential and other
semantically known but unsupported cmsgs fail with `ERR_UNSUPPORTED` unless
safely classified as an owned unknown payload.

### Cancellation

Every waiting public operation accepts an optional `AbortSignal`. Each admitted
operation has a shared atomic cancellation token registered by operation id.
Native cancellation marks that token and wakes eventfd; it does not depend on
space in the ordinary command queue. The reactor owns the settlement decision:

- abort before admission rejects without native work;
- abort after admission but before syscall removes queued work and rejects with
  `ERR_ABORTED`;
- completion that wins the race resolves/rejects normally and makes a later
  cancel a no-op;
- close wins over future admission and cancels remaining operations with
  `ERR_SOCKET_CLOSED`;
- cancellation never implicitly closes the socket.

The TypeScript layer removes abort listeners on every settlement. Native state
uses a bounded operation-id index. A wake pass inspects at most the documented
per-socket/global pending limits, so cancellation neither scans unbounded state
nor loses an abort because a command queue was full.

## Phase 5 frozen implementation contract

### Dependency boundary

Add exact-pinned nix 0.31.3 with default features disabled and only `socket`,
`uio`, and `net`. Its safe typed `recvmsg`/`sendmsg`, address, cmsg, and missing
sockopt support replaces hand-written alignment-sensitive FFI. rustix remains
the owner-oriented dependency for fds, epoll, eventfd, and existing calls.

Do not add direct libc calls or broadly relax crate-wide `unsafe_code = "deny"`
in Phase 5. D-020 records the sole function-scoped exception required to adopt
and immediately close raw descriptors returned by nix for unexpected
`SCM_RIGHTS`; it is not an FFI or layout adapter. If nix lacks another required
operation, defer it or record a new reviewed decision.

### Initial message flags

- Receive input: `peek`, `errorQueue`.
- Send input: `dontRoute`.
- Receive output: at least `endOfRecord`, `outOfBand`, `dataTruncated`,
  `controlTruncated`, and `errorQueue` when Linux returns them.

The descriptor is already nonblocking; a public `dontWait` flag would be
redundant. `waitAll` is excluded for datagram/raw semantics. Unknown numeric
flag masks are rejected rather than silently truncated.

Native send always adds `MSG_NOSIGNAL`. Native receive always adds `MSG_TRUNC`
to preserve original packet length and `MSG_CMSG_CLOEXEC` to protect any
unexpected received descriptors. These internal safety/metadata flags are not
optional public behavior.

### Initial control messages and enabling options

Receive and expose:

- IPv4 packet info: interface index, selected local address, and destination;
- IPv4 TTL and TOS;
- nanosecond software receive timestamp;
- receive-queue overflow counter;
- IPv4 extended error plus optional offender address;
- bounded unknown control messages.

Send typed IPv4 packet-info and per-message TTL where nix exposes safe support.
Add typed enabling/configuration options for packet info, TTL, TOS, receive
errors, timestamp-nanoseconds, queue-overflow reporting, and device binding.
Kernel-effective getters are included wherever Linux supports them.

`IP_HDRINCL` is implemented as a Phase 8 typed option through the reviewed D-023
fixed-width adapter because neither selected safe syscall crate exposes it.

Nix message calls accept a `RawFd`; adapters may derive that integer only inside
the syscall call from a live `OperationLease`. They never store it in a command,
operation table, callback, or result. Descriptor ownership remains entirely in
`OwnedFd`/`OperationLease` despite the borrowed integer API.

Timestamp values cross N-API as normalized signed seconds plus unsigned
nanoseconds, and the TypeScript facade exposes a lossless bigint nanosecond
value. No timestamp passes through a JavaScript `number` large enough to lose
integer precision.

### Bounds

The following defaults are part of Phase 5 review and may change only with a
decision-log entry and tests:

- data capacity: 1 through 65,535 bytes for IPv4;
- default control capacity: 4 KiB;
- maximum control capacity: 64 KiB;
- maximum one-message combined owned allocation: 128 KiB;
- maximum admitted operation-owned bytes: 4 MiB per socket and 16 MiB per
  environment, charged before copying/allocation and released exactly once;
- maximum total pending operations: 128 per environment;
- maximum total pending operations: 32 per socket;
- maximum pending sends and receives: 16 each per socket;
- command queue: 256;
- command processing turn: at most 64 commands before returning to readiness;
- maximum control-message count after parsing: 64;
- readiness turn: at most 16 operations or 1 MiB per socket before yielding.

Unknown cmsg payloads, timestamps, errors, and address objects all count toward
the same control limit. Checked addition occurs before allocation.

Admission validates sizes and reserves operation count plus byte budget before
copying outbound data/control or allocating receive storage. Every rejection
path uses a rollback guard so count/byte reservations cannot leak or underflow.

### Completion delivery

Completion delivery uses a bounded 64-entry thread-safe-function queue in
blocking mode. This provides lossless backpressure when JavaScript is stalled;
`QueueFull` can never silently discard a settlement. The reactor is the only
native caller and Node environment shutdown returns `Closing` instead of
waiting. D-026 supersedes the earlier nonblocking proof: admission counts are
released when native work completes, so a synchronous JavaScript submission
burst can exceed the nominal 32-operation limit before callbacks drain.

The completion sink remains environment-specific. No `napi_env`, callback, or
N-API value may cross Worker environments or be used after cleanup starts.

### Reactor data structures and fairness

Replace operation-type-only queues with a per-socket operation table keyed by
operation id plus ordered send/receive queues. The table owns leases, data,
control bytes, a shared cancellation token, and the terminal settlement state.
Cancel, close, readiness, and shutdown all transition through this table.

Readiness processing is round-robin across returned epoll events and observes
the per-socket operation/byte budget. Remaining level-triggered work is left
registered for the next epoll turn. Commands are drained with a finite budget
between readiness turns so a command flood cannot starve packets and a hot
socket cannot starve close/cancel commands.

### Error additions

Add stable `ERR_ABORTED`, `ERR_UNSUPPORTED`, and `ERR_MALFORMED_CONTROL`
categories. Extended network errors are successful error-queue message results,
not automatically thrown JavaScript exceptions. Syscall failures continue to use
`ERR_SYSTEM` with operation and errno context.

## Phase 5 implementation sequence

1. Record/pin nix and add Node-independent checked address, message flag,
   control-capacity, timestamp, and control-message types.
2. Implement safe IPv4 `sendmsg`/`recvmsg` adapters and unit-test known,
   unknown, malformed, truncated, and aligned cmsg handling.
3. Refactor reactor operation indexing, cancellation, command/readiness budgets,
   and the original nonblocking completion delivery with deterministic fake-sink
   tests (delivery mechanism later superseded by D-026).
4. Add N-API DTOs and TypeScript `sendMessage`/`receiveMessage` plus
   `AbortSignal` listener cleanup; retain legacy wrappers.
5. Add typed enabling options and bind-to-device support.
6. Add unprivileged boundary/race tests and isolated namespace tests for packet
   info, TTL/TOS, timestamp, error queue, cancellation, device binding, and
   two-socket fairness.
7. Run all existing gates, release build, package dry-run, repeated stress, and
   update the Phase 5 report before marking the phase complete.

## Phase 5 test matrix

| Layer             | Required cases                                                                                                                                            |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pure Rust         | Flag validation, address conversion, cmsg alignment/length, timestamp conversion, unknown cmsg copy, checked allocation sums                              |
| Reactor           | Cancel before/after readiness, close-vs-cancel, exactly-once completion, per-socket/global saturation, command/readiness fairness, completion queue fault |
| Node unprivileged | Plain-JS malformed inputs, already-aborted signal, listener cleanup, unsupported combinations, permission errors, Worker exit                             |
| Namespace IPv4    | Packet info, TTL/TOS, timestamp, queue overflow where deterministic, extended error queue, device bind, control truncation                                |
| Regression        | Every Phase 1–4 test, legacy send/receive shape, package import/require, release build and package contents                                               |

Tests that depend on a driver, hardware timestamp clock, or nondeterministic
queue overflow must be capability-detected and separated from deterministic
blocking gates.

## Later-phase design constraints

- IPv6 must use ancillary data for metadata that Linux does not place in the raw
  payload. It must not fabricate an IPv6 header for API symmetry.
- `IPV6_CHECKSUM` and `IP_HDRINCL` use the reviewed Phase 8 D-023 typed-option
  adapter because the selected safe crates do not expose them.
- Packet sockets use `sockaddr_ll`, not IP address types. `SO_BINDTODEVICE` is
  not their bind mechanism.
- Phase 7 established raw/cooked packet I/O. Phase 8 added membership, auxdata,
  statistics, fanout, and filter sockopts through the reviewed D-023 adapter.
- Error-queue messages and timestamps can arrive out of send order; identifiers
  must be exposed when Linux provides them.
- Batch APIs return per-message results and an explicit completed count; a
  partial batch is not flattened into one success or failure.
- Ring frame leases own bounded copies; no Buffer aliases the mutable mapping,
  and reads fail after release. Close unmaps reactor-owned ring memory while
  already-delivered copied leases remain independent.
- Raw option bytes are bounded owned copies with exact level/name/length. APIs
  that pass fds, pointers, or nested pointer structures are excluded from the
  generic escape hatch and require typed implementations.

## Authoritative references

Plan details were checked on 2026-07-12 against:

- [Linux raw IPv4 sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Linux IPv6 sockets](https://man7.org/linux/man-pages/man7/ipv6.7.html)
- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Linux `recvmsg` flags and error queues](https://man7.org/linux/man-pages/man2/recvmsg.2.html)
- [Linux socket options and filters](https://man7.org/linux/man-pages/man7/socket.7.html)
- [Linux kernel timestamping documentation](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
- [Linux kernel Packet MMAP documentation](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html)
- [Node-API environments, cleanup, and thread-safe functions](https://nodejs.org/api/n-api.html)
- [nix typed socket and control-message APIs](https://docs.rs/nix/0.31.3/nix/sys/socket/)
- [rustix networking APIs](https://docs.rs/rustix/1.1.4/rustix/net/)
