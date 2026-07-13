# Architecture

## Component boundaries

```text
Node application
      |
      v
TypeScript public API and declarations
      |
      v
N-API exports and value/error conversion
      |
      v
Rust socket state, validation, and async coordination
      |
      v
Linux socket syscalls and kernel-owned networking state
```

The TypeScript layer should remain thin: public exports, ergonomic types,
platform guards where helpful, and validation that improves error clarity. It
must not duplicate native ownership state.

The Rust layer owns descriptors, buffers involved in syscalls, operation state,
and translations between Linux results and stable N-API values.

## Module layers

- **Public TypeScript facade:** exports supported classes/functions and types;
  prevents consumers from relying on generated native binding details.
- **N-API adapter:** converts Node values to checked Rust types, schedules work,
  and maps results/errors back to Node.
- **Socket core:** models descriptor ownership, lifecycle, supported families,
  flags, addresses, options, and syscall outcomes without Node-specific logic
  where practical.
- **Linux syscall adapters:** contain the narrow platform-specific surface.
  rustix owns fd/event/readiness primitives and existing socket calls. Phase 5
  adds narrowly featured nix for typed message, control-message, address, and
  missing sockopt support rather than adding alignment-sensitive project FFI.

Separating the socket core from N-API conversion makes native invariants easier
to unit test and keeps JavaScript representation decisions out of syscall code.

## Resource ownership model

Each public socket object corresponds to one Rust-owned descriptor state. The
design must have one authoritative close transition and must not represent a
borrowed integer file descriptor as ownership.

The implemented lifecycle has `Open`, `Closing`, and `Closed` states guarded by
one mutex. The open state owns an `Arc<OwnedFd>`. Each operation clones that Arc
into an `OperationLease` while holding the lifecycle lock. Close is serialized
through the same lock, rejects every new lease after its transition, and drops
the core's descriptor ownership exactly once.

If no lease exists, close releases the descriptor immediately. If leases exist,
the state retains only a `Weak<OwnedFd>` and reports `Closing`; the last lease
drop releases the descriptor, and the next state observation normalizes it to
`Closed`. This means:

- an operation acquired before close may finish;
- no operation can acquire after close starts;
- a numeric descriptor cannot be reused while an operation lease still owns the
  original descriptor;
- repeated close is idempotent and reports that it did not initiate a new close;
- dropping the core releases its ownership even without explicit close.

Explicit `close()` is the normal API. Finalization is a leak-prevention fallback
and must never depend on JavaScript finalizer timing for correctness. Dropping a
public native handle initiates the same close transition; environment cleanup
stops reactor admission and reaps its thread outside the Node event-loop thread.

## Buffer model

Initial implementations should prefer ownership or scoped borrowing patterns
that the selected N-API framework can prove valid across the entire syscall.
Asynchronous operations must not retain a pointer into movable or collectable
JavaScript memory unless the N-API lifetime mechanism explicitly pins that
memory for the operation.

For an initial correctness-first API, copying outbound bytes into Rust-owned
memory and returning received bytes in a newly created Node buffer is
acceptable. Any later zero-copy path requires measurement plus a documented
lifetime proof.

All lengths and offsets require checked conversions between JavaScript numbers
or bigints, Rust integer types, `usize`, and Linux syscall types. The core now
provides checked raw IPv4 protocol numbers (1 through 255), packet buffer
lengths (1 through 65,535), and overflow-safe buffer ranges. The TypeScript
facade also enforces safe-integer and runtime type validation before N-API
conversion.

Message I/O extends this rule to two separately bounded owned regions: packet
data and ancillary control bytes. Every cmsg header, aligned step, payload
length, message count, and combined allocation is checked before access or
allocation. Known messages become typed Rust values; unknown receive messages
become bounded owned bytes. Outbound unknown messages are rejected until a
dedicated raw-control design proves their layout safe.

Phase 9 `PACKET_MMAP` receive rings keep all mutable mapping access on the
reactor. Checked frame bytes are copied before a block returns to the kernel;
the public lease owns only that copy, clears it on release, and never exposes a
Buffer into mmap storage. Batch message arenas likewise remain owned until the
single nonblocking mmsg syscall returns.

## Asynchronous I/O model

The public API is asynchronous for operations that may wait. Socket descriptors
are nonblocking and coordinated by one Rust-owned Linux `epoll` reactor per
Node-API environment. A nonblocking `eventfd` wakes the reactor for commands and
shutdown. Current limits are 64 sockets and 128 pending operations per Node
environment, 16 pending sends and 16 pending receives per socket, a 256-command
native queue, and a 64-item N-API completion queue. Excess admission fails with
`ERR_QUEUE_FULL`.

The reactor settles JavaScript work only through napi-rs mechanisms that are
valid from a native thread. It never calls N-API through a raw environment
pointer from the reactor. Environment cleanup first stops admission, signals the
reactor, drains or rejects tracked operations according to their lifecycle, and
joins native state without waiting on the Node event-loop thread.

The implementation uses a single reactor thread per Node environment, not one
thread per socket and not permanently blocking work on libuv's shared worker
pool. It uses level-triggered readiness and registers only directions with
pending work. Each readiness pass progresses admitted operations until the queue
is empty or Linux returns `EAGAIN`; `EINTR` is retried.

Every command owns an operation lease, so the numeric descriptor cannot be
closed and reused while queued or executing. The reactor owns a separate lease
while a descriptor is registered with epoll. Explicit close stops admission,
cancels queued sends and receives with `ERR_SOCKET_CLOSED`, deregisters the
descriptor, releases leases, settles the close operation, and clears the strong
completion callback. A retained closed JavaScript socket therefore does not keep
the event loop alive.

The accepted design must:

- never wait on the Node event-loop thread;
- define cancellation and close interaction;
- avoid an unbounded thread or queued-operation count;
- handle readiness races and interrupted syscalls;
- avoid resolving/rejecting promises after the Node environment is gone;
- provide backpressure or explicit concurrency constraints.

Phase 5 adds operation-level cancellation and fairness. A per-socket operation
table keyed by operation id becomes the single settlement authority for
readiness, cancellation, close, and shutdown. Readiness and command processing
receive finite work/byte budgets, preserving progress for other sockets and
control commands. Completion delivery becomes nonblocking with its queue bound
proven from per-socket admission; a full completion queue is an invariant
failure, never permission to drop a Promise settlement.

Changing away from this bounded reactor model or increasing its limits requires
a recorded decision and targeted load and teardown tests.

## Error model

Node-facing native errors should be ordinary `Error` instances (or documented
subclasses) with stable machine-readable fields. At minimum, syscall failures
should preserve:

- a library error code or category;
- the failed operation;
- Linux `errno` as a number;
- the conventional errno name when available;
- a human-readable message.

Argument, lifecycle, unsupported-feature, and system errors should be
distinguishable. Messages alone are not a stable programmatic API.

The Rust core implements this as `NativeError`, with stable `ErrorKind`, code,
operation, optional numeric errno, optional conventional errno name, and a human
message. Current stable codes are `ERR_INTERNAL`, `ERR_INVALID_ARGUMENT`,
`ERR_QUEUE_FULL`, `ERR_REACTOR_CLOSED`, `ERR_SOCKET_CLOSED`, and `ERR_SYSTEM`.
The TypeScript facade maps these fields onto `RawSocketError` without changing
their machine-readable meaning.

## API evolution

- Start with a narrow socket-family/protocol slice.
- Keep raw numeric escape hatches only where they can be validated safely and do
  not make future API compatibility impossible.
- Prefer typed option-specific methods or discriminated option forms over a
  single unchecked variadic syscall mirror.
- Add kernel features with feature detection and documented failure behavior.
- Do not claim support based solely on constants being present at build time.

The long-term public model uses discriminated `ipv4`, `ipv6`, and `packet`
families and address types. Existing IPv4 string methods remain conveniences;
family-neutral `sendMessage`/`receiveMessage` primitives carry per-call flags,
addresses, bounded control data, and optional cancellation. Family-specific
options and control messages must fail with `ERR_UNSUPPORTED` when applied to
the wrong socket rather than being ignored.

Typed options remain preferred, but complete Linux coverage ultimately needs a
bounded owned-byte option escape hatch. That later interface rejects pointer- or
fd-bearing layouts and reserved dangerous options; any project FFI required to
implement it is isolated and reviewed separately.

## Phase 4 configuration and metadata

Bind, local-address queries, and typed socket-option operations are commands in
the same bounded reactor queue as send and receive. They hold operation leases,
are ordered by admission, and never race descriptor close or execute against a
reused fd number. The initial typed option set is `SO_BROADCAST`, `IP_TTL`,
`IP_TOS`, `SO_RCVBUF`, and `SO_SNDBUF`. JavaScript and Rust both validate option
names and values; buffer requests are capped at 16 MiB. Getters return the
effective kernel value because Linux may clamp or double buffer requests.

Raw IPv4 receive already includes the IP header. The reactor parses only a
captured, structurally valid header and returns typed fields without retaining
any borrowed buffer. `packetLength` comes from `MSG_TRUNC` semantics and reports
the original datagram size even when the returned Buffer is shorter. Metadata is
absent when truncation or malformed bytes prevent safe parsing.

Binding to a local address provides address-based interface selection. A
device-name `SO_BINDTODEVICE` API and arbitrary ancillary control messages are
deferred: rustix 1.1.4 does not expose safe wrappers for those operations, and
Phase 4 does not add project-owned FFI or a generic raw option escape hatch.

Phase 5 adds narrowly configured nix for device binding, message I/O, and typed
control messages while retaining the no-project-owned-unsafe policy.

Phases 7 and 8 introduce the first narrowly reviewed project-owned syscall
adapters where safe crates do not expose fixed Linux layouts. Packet addresses
use initialized pointer-free `sockaddr_ll` values. Advanced configuration uses
initialized bounded option bytes, fixed-width integer values, transient copied
classic-BPF storage, fixed packet option structs, and an immediately owned
close-on-exec eBPF fd duplicate. These adapters never store borrowed pointers or
raw descriptors in reactor state; every call is made under an operation lease.

## Family-specific semantics

- IPv4 raw receive includes the IPv4 header; send normally lets Linux build the
  header unless `IP_HDRINCL` is enabled.
- IPv6 raw sockets expose Linux IPv6 payload and ancillary semantics directly.
  They do not synthesize a base header merely to resemble IPv4.
- Packet sockets expose `sockaddr_ll` link identity, EtherType, interface,
  packet direction/type, and hardware address. They never reuse IP address DTOs.

Shared lifecycle, message, cancellation, error, and queue machinery must not
erase these differences.

## Distribution boundary

Early development and initial internal packaging use source builds. Supported
hosts are x86-64 and AArch64 glibc Linux with kernel 4.18+ and glibc 2.28+,
matching the relevant Node Tier 1 Linux baseline. musl and other architectures
are not initially supported.

N-API reduces coupling to a particular Node/V8 build, but native artifacts still
vary by architecture and libc. Prebuilt x86-64/AArch64 glibc packages are a
Phase 10 goal after reproducibility, provenance, and release automation are
reviewed. Installation-time downloads are not permitted; eventual prebuilts must
be distributed as npm artifacts selected by package metadata.
