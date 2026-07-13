# Phase 5 completion report

Date: 2026-07-12

## Delivered

Phase 5 replaces the IPv4 byte-only syscall path with a bounded message-I/O
substrate while retaining the Phase 4 API. `sendMessage()` and
`receiveMessage()` expose checked IPv4 addresses, closed flag sets, typed
outbound/inbound ancillary messages, independent data/control truncation,
original message length, returned flags, optional source address, and parsed
IPv4 metadata. Legacy `send()` and `receive()` use the same native adapters.

The public receive controls cover packet info, TTL, TOS, nanosecond timestamps,
queue-overflow counters, IPv4 extended errors, and bounded initialized unknown
payloads. Timestamp seconds cross N-API as decimal text and become a lossless
`bigint` nanosecond value in TypeScript. Enabling options cover packet info,
TTL, TOS, timestamp nanoseconds, queue overflow, receive errors, and validated
`SO_BINDTODEVICE` get/set/unbind behavior.

Each admitted operation now has an atomic cancellation token and bounded
operation-id registry. Optional `AbortSignal` support was added to both message
and legacy waiting operations. Native cancellation wakes `eventfd`, settles in
the reactor, and does not close the socket. Admission is bounded to 32 total
operations and 4 MiB per socket, and 128 operations and 16 MiB per environment.
The reactor processes at most 64 commands per wake and 16 operations or 1 MiB
per socket readiness turn. Normal and error-queue receives have separate FIFO
queues. Completion delivery uses a 64-entry nonblocking thread-safe function.

The native dependency surface adds exact-pinned nix 0.31.3 with only `net`,
`socket`, and `uio`; rustix retains descriptor, epoll, eventfd, and existing
socket responsibilities.

## Safety note

Nix represents an unexpected received `SCM_RIGHTS` message as newly installed
raw descriptor integers. The message adapter has one reviewed, locally allowed
unsafe conversion that moves each such descriptor exactly once into `OwnedFd`
and immediately drops it. This prevents descriptor leaks and never exposes the
descriptor to JavaScript. No pointer arithmetic, native layout construction, or
borrow extension is project-owned unsafe code.

## Verification

The final ordinary gate runs strict TypeScript, ESLint, formatting, all-target
Clippy with warnings denied, Rust unit tests, builds, and Node tests through
`npm run ci`. Rust coverage is 29 tests, including message capacity/control
conversion, cancellation without socket close, lifecycle races, queue bounds,
and reactor behavior. The ordinary Node suite has five passing tests and four
capability-gated tests skipped.

The repository-owned isolated namespace command below passes all four privileged
tests:

```sh
npm run test:namespace
```

It covers legacy traffic/truncation/backpressure and message I/O with packet
info, TTL, TOS, nanosecond timestamps, metadata-enabling option getters, device
bind/unbind, error-queue admission, and native AbortSignal cancellation.

## Next phase

Phase 6 adds IPv6 raw sockets on this message, lifecycle, option, and
cancellation substrate. Phase 5 does not add `IP_HDRINCL`, arbitrary outbound
cmsgs, raw option bytes, batching, or packet sockets; those remain assigned to
later reviewed phases.
