# nodenetraw

`nodenetraw` is a Linux-only Node.js native module for low-level raw socket
access. It exposes a TypeScript API backed by Rust through N-API, with an
emphasis on memory safety, correct file-descriptor ownership, stable Linux error
reporting, and a small dependency footprint.

> **Status:** IPv4, IPv6, and raw/cooked Linux packet sockets support typed
> message I/O, metadata, advanced options, packet controls, filter attachment,
> AbortSignal cancellation, stable errors, and explicit close. Version
> `0.1.0-rc.1` is a release candidate; Phase 10 does not publish it.

The initial support baseline is Node.js 26+, Rust 1.97.0 (updated with each
stable Rust release), and 64-bit glibc Linux on x86-64 or AArch64 with kernel
4.18+ and glibc 2.28+.

> **Architecture verification:** x86-64 is tested. AArch64 (also called ARM64)
> is an intended build target but is currently untested because no ARM64 test
> machine is available. Treat ARM64 packages as experimental until they pass on
> native AArch64 hardware or a native AArch64 CI runner.

## Direction

The project is intended to become Node's memory-safe bridge to Linux raw packet
networking: IPv4 and IPv6 raw IP, `AF_PACKET`, message flags and ancillary data,
extended errors and timestamps, filters, bounded batching, and measured packet
rings. It is deliberately Linux-specific so the API can describe kernel
semantics honestly instead of presenting incomplete portable abstractions.

The design separates responsibilities:

- TypeScript provides the public package surface, types, and Node conventions.
- Rust owns sockets, native buffers, syscall interaction, and lifecycle rules.
- N-API provides the ABI-stable bridge between Node.js and the Rust library.

Opening raw sockets commonly requires elevated Linux capabilities such as
`CAP_NET_RAW` (or sufficient privilege in the governing user/network namespace).
The library reports permission failures; it does not attempt to grant itself
privileges.

## Project principles

- Safe-by-default ownership and cleanup of native resources.
- No blocking network operations on the Node.js event-loop thread.
- Explicit validation at every language and kernel boundary.
- Linux errors represented without losing operation or `errno` context.
- Strict TypeScript, ESLint, and Prettier from the first implementation phase.
- Minimal runtime dependencies and justified development dependencies.
- Privileged tests kept opt-in and isolated from normal development and CI.

The package is ESM-only, built with npm and napi-rs v3 against Node-API 10. The
current slice covers IPv4/IPv6 raw IP and Linux raw/cooked packet sockets,
including advanced options, filters, bounded batches, and receive-only
TPACKET_V3 rings.

The x86-64 release artifact is built with napi-rs's pinned GNU compatibility
toolchain and rejected unless ELF inspection proves that its required glibc
symbols are at or below 2.28. This verifies the addon's link baseline; the
package still requires glibc 2.28 because that is the supported Node 26 floor.

Phases 5 through 10 are complete: bounded message I/O, cancellation, IPv4/IPv6,
Linux `AF_PACKET`, advanced configuration, filtering, batching, and measured
receive-ring work are in place, together with fuzz/sanitizer gates and
target-specific release rehearsal. See the
[full capability plan](ai_documentation/11-full-capability-plan.md).

## Supported feature matrix

| Area                                       | Status                | Conditions                                                                               |
| ------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------- |
| IPv4 and IPv6 raw sockets                  | Implemented           | Usually requires `CAP_NET_RAW`                                                           |
| `AF_PACKET` raw/cooked sockets             | Implemented           | Linux interface and `CAP_NET_RAW` required                                               |
| Ancillary data and error queues            | Implemented           | Individual controls/options remain kernel-dependent                                      |
| Typed/common/opaque options                | Implemented           | Privileged options may return `EPERM`; opaque tuples exclude ownership-sensitive options |
| Classic BPF and compatible eBPF attachment | Implemented           | Linux verifier applies; this module does not load eBPF programs                          |
| `sendmmsg`/`recvmmsg` batches              | Implemented           | 64 messages and 1 MiB per operation                                                      |
| TPACKET_V3 receive ring                    | Implemented           | Receive-only, copied frame leases, 64 MiB per ring                                       |
| Hardware timestamps and driver behavior    | Capability-detected   | Not a portable release gate                                                              |
| TX packet mmap and AF_XDP                  | Unsupported           | Require separate ownership and performance reviews                                       |
| x86-64 glibc Linux                         | Tested                | Kernel 4.18+, glibc 2.28+, Node 26+                                                      |
| AArch64/ARM64 glibc Linux                  | Untested/experimental | Intended target; requires verification on a native ARM64 runner                          |
| musl, non-Linux, and 32-bit targets        | Unsupported           | No fallback or install-time download                                                     |

## API

```ts
import { IPPROTO_ICMP, RawSocket } from "nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });

try {
  await socket.bind("127.0.0.1");
  await socket.setOption("ipTtl", 64);

  const receive = socket.receive();
  const bytesSent = await socket.send(icmpPacket, "127.0.0.1");
  const packet = await receive;

  console.log(
    bytesSent,
    packet.sourceAddress,
    packet.packetLength,
    packet.ipv4?.destinationAddress,
    packet.data,
  );
} finally {
  await socket.close();
}
```

Message I/O exposes Linux flags and ancillary metadata without numeric flag or
pointer escape hatches:

```ts
await socket.setOption("receivePacketInfo", true);
await socket.setOption("receiveTimestampNanoseconds", true);

const controller = new AbortController();
const incoming = socket.receiveMessage({ signal: controller.signal });
await socket.sendMessage({
  data: icmpPacket,
  destination: { family: "ipv4", address: "127.0.0.1" },
  flags: ["dontRoute"],
  control: [{ kind: "ipv4Ttl", value: 64 }],
});
const message = await incoming;
```

IPv6 uses the same message API with explicit scope and flow fields:

```ts
import { IPPROTO_ICMPV6, RawSocket } from "nodenetraw";

const socket6 = await RawSocket.open({
  family: "ipv6",
  protocol: IPPROTO_ICMPV6,
});
await socket6.bind({ family: "ipv6", address: "::1" });
const incoming6 = socket6.receiveMessage();
await socket6.sendMessage({
  data: icmpv6Packet,
  destination: { family: "ipv6", address: "::1", scopeId: 0 },
  control: [{ kind: "ipv6HopLimit", value: 64 }],
});
```

IPv6 receive buffers contain protocol payload, not an IPv6 header synthesized by
this library. Packet info, hop limit, traffic class, timestamps, and extended
errors are reported through ancillary controls.

Packet sockets use link-layer addresses and interface indices:

```ts
import { ETH_P_IP, RawSocket, interfaceIndex } from "nodenetraw";

const index = interfaceIndex("eth0");
const packets = await RawSocket.open({
  family: "packet",
  mode: "cooked",
  protocol: ETH_P_IP,
});
await packets.bind({
  family: "packet",
  interfaceIndex: index,
  protocol: ETH_P_IP,
});
const message = await packets.receiveMessage();
```

Raw packet mode includes the link header; cooked mode exposes the link payload.
Received packet addresses report interface index, `EtherType`, hardware address
and type, and Linux packet direction/type. Packet sockets also support explicit
promiscuous/multicast membership, `PACKET_AUXDATA`, statistics, fanout, and BPF
filters:

```ts
await packets.addPacketMembership({
  interfaceIndex: index,
  kind: "promiscuous",
});
await packets.setPacketAuxdata(true);
await packets.attachClassicFilter([
  { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0xffff_ffff },
]);
const message = await packets.receiveMessage();
console.log(message.packetAuxdata, await packets.packetStatistics());
await packets.detachFilter();
await packets.dropPacketMembership({
  interfaceIndex: index,
  kind: "promiscuous",
});
```

Classic BPF programs contain at most 4096 instructions and are structurally
checked before Linux performs its verifier pass. `attachEbpfFilter(fd)` attaches
a close-on-exec duplicate and never consumes the caller's descriptor.

The package exports a focused set of Linux-compatible `IPPROTO_*` and `ETH_P_*`
constants for readable socket creation and packet binding. These names are not
an exhaustive protocol registry; numeric values remain accepted for custom or
less-common protocols. IP `protocol` values must be integers from 1 through 255,
while packet-socket protocol values must be integers from 1 through 65,535.
`send()` accepts a non-empty `Uint8Array` of at most 65,535 bytes and a
dotted-decimal IPv4 destination.

The IP exports are `IPPROTO_ICMP`, `IPPROTO_IGMP`, `IPPROTO_IPIP`,
`IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_IPV6`, `IPPROTO_GRE`, `IPPROTO_ESP`,
`IPPROTO_AH`, `IPPROTO_ICMPV6`, `IPPROTO_SCTP`, `IPPROTO_UDPLITE`, and
`IPPROTO_RAW`. Packet exports are `ETH_P_ALL`, `ETH_P_IP`, `ETH_P_ARP`,
`ETH_P_8021Q`, `ETH_P_IPV6`, and `ETH_P_8021AD`. Values match the Linux UAPI
names and are ordinary zero-dependency TypeScript/JavaScript number exports.

`receive()` accepts an optional buffer length from 1 through 65,535 and returns
the received bytes, source address, and an explicit truncation flag. `close()`
is asynchronous and idempotent; it cancels admitted operations and releases the
descriptor before resolving.

`bind()` selects a local IPv4 address and `localAddress()` reports the current
binding. `getOption()` and `setOption()` support `broadcast`, `ipTtl`,
`ipTypeOfService`, `receiveBufferSize`, `sendBufferSize`, `receivePacketInfo`,
`receiveTtl`, `receiveTypeOfService`, `receiveTimestampNanoseconds`,
`receiveQueueOverflow`, `receiveErrors`, and `bindToDevice`. Socket buffer
requests are limited to 16 MiB; Linux may clamp or double them, so getters
report the effective kernel value.

Advanced typed names include `headerIncluded`, `ipv6ChecksumOffset`, `freebind`,
`transparent`, `priority`, `mark`, `pathMtuDiscovery`, multicast TTL/loop, and
bounded `busyPollMicroseconds`. `connect()` and `disconnect()` support both raw
IP families. For Linux options not yet modeled, `getSocketOption()` and
`setSocketOption()` copy at most 4096 initialized bytes; filter, descriptor,
ring, membership, fanout, and all typed tuples are rejected from this escape
hatch and must use their ownership-aware APIs.

`sendBatch()` and `receiveBatch()` use nonblocking `sendmmsg(2)` and
`recvmmsg(2)` with 64-message and 1 MiB limits. Batch ancillary controls remain
on the one-message API. Packet sockets can configure a receive-only TPACKET_V3
ring and obtain explicitly releasable copied frame leases:

```ts
await packets.configurePacketRing();
const lease = await packets.receiveRingFrame();
try {
  const frame = lease.read();
  console.log(frame, lease.timestamp, lease.originalLength);
} finally {
  lease.release();
}
```

No Buffer aliases mutable mmap memory, and `read()` fails after release. TX mmap
is intentionally deferred; the optimized namespace benchmark currently shows a
measured advantage for the safer `sendmmsg` path.

`receiveMessage()` independently reports data/control truncation and returns
typed packet-info, TTL, TOS, timestamp, overflow, and extended-error controls.
Unknown receive controls are bounded owned bytes. Timestamp controls include a
lossless bigint nanosecond value. `send()`, `receive()`, `sendMessage()`, and
`receiveMessage()` accept optional AbortSignals where they can wait.

Each received packet includes `packetLength`, which remains the original Linux
datagram length even when the capture buffer truncates it. When the captured
bytes contain a complete valid IPv4 header, `ipv4` reports destination,
protocol, TTL, TOS, header/total length, identification, and fragmentation
fields. It is `undefined` when a short capture cannot be parsed safely.

Failures are `RawSocketError` instances with stable `kind`, `code`, `operation`,
optional numeric `errno`, and optional `errnoName` fields. Queue limits fail
immediately with `ERR_QUEUE_FULL`; operations after close fail with
`ERR_SOCKET_CLOSED`.

## Documentation

The project plan begins at
[`ai_documentation/00-index.md`](ai_documentation/00-index.md). Contributors and
coding agents should also read [`AGENTS.md`](AGENTS.md) before making changes.

## Development

Prerequisites are Node.js 26+, npm 11+, Rust 1.97.0 through `rustup`, and a
working Linux linker. The pinned Rust toolchain is described by
`rust-toolchain.toml`.

```sh
npm ci
npm run build
npm test
```

Run the entire local quality gate with:

```sh
npm run ci
```

An optimized source build is explicit. It may fetch napi-rs's pinned build-time
GNU compatibility toolchain; installing the resulting npm packages performs no
download or compilation:

```sh
npm ci
npm run build:native:release
npm run build:typescript
```

`npm run release:consumer-test` stages the root and current-architecture native
packages, packs them, installs them into a temporary clean project with scripts
disabled, and tests ESM plus `require()`. `npm run release:reproducibility`
builds the optimized addon twice and compares SHA-256 hashes.
`npm run release:verify-artifact` checks ELF architecture and the glibc symbol
ceiling. Actual npm publication is intentionally not automated by these
commands.

Additional focused commands include `npm run typecheck`, `npm run lint`,
`npm run format:check`, `npm run rust:fmt`, `npm run rust:clippy`, and
`npm run rust:test`. See [`AGENTS.md`](AGENTS.md) for the complete command map.

Successful raw-socket integration tests can be launched with ordinary `sudo`:

```sh
sudo npm run test:privileged
```

The harness detects the invoking repository owner, builds with that user's Node
26/npm/rustup environment, and elevates only the already-built test process.
Tests run in a disposable network namespace with their own loopback and veth
fixtures, so they do not alter the host network namespace or leave root-owned
build artifacts. If Node 26 cannot be discovered automatically, set
`NODENETRAW_NODE` to its absolute executable path.

An entirely unprivileged alternative, where AppArmor and the host's user
namespace policy permit it, is:

```sh
npm run test:namespace
```

Do not use `sudo npm run build`; use the privileged test command above so the
build step can deliberately drop back to the repository owner.

Implementation and verification details are in the
[Phase 10 report](ai_documentation/17-phase-10-report.md) and the
[release-readiness audit](ai_documentation/18-release-readiness-audit.md).

## License

Licensed under the [MIT License](LICENSE).
