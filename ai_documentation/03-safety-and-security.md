# Safety and security plan

## Scope of security

This project uses “security” to mean resistance to implementation bugs and
unsafe behavior at the Node/Rust/Linux boundary: memory corruption, invalid
access, resource leaks, descriptor confusion, denial of service caused by
unbounded library behavior, and incorrect handling of hostile bytes or
arguments.

Application authentication and authorization are out of scope. Linux privilege
requirements are not: the module must not bypass them, escalate privileges, or
hide permission failures.

## Boundary threat model

Inputs that must be considered untrusted include:

- every JavaScript value, including values produced through casts or plain JS;
- packet bytes and metadata received from the network;
- socket addresses, message flags, ancillary headers/payloads, timestamps,
  extended errors, interface indices, and hardware addresses;
- numeric sizes, flags, protocol identifiers, and option values;
- kernel return values and partial-operation results;
- operation ordering, including repeated or concurrent close/send/receive;
- garbage collection and Node environment teardown timing.
- abort timing, completion-queue saturation, sustained readiness, batch partial
  success, and future mapped-ring status transitions.

The library itself should not assume a malicious caller can be prevented from
sending malicious network traffic. It should ensure such a caller cannot turn
invalid API input into memory unsafety or corruption inside the hosting Node
process.

## Required invariants

### Descriptor safety

- A descriptor has exactly one owning Rust state.
- Every successful descriptor creation is paired with deterministic cleanup.
- Close is idempotent from JavaScript and the underlying descriptor is closed
  once.
- No syscall starts on a socket after it has entered its terminal lifecycle.
- In-flight work holds state that cannot become a stale descriptor number.
- `FD_CLOEXEC` is set atomically at creation when the Linux API supports it.

### Memory and conversion safety

- No native pointer outlives its owner or the N-API environment it requires.
- No JavaScript buffer is borrowed after its permitted callback/call scope.
- Every length, offset, and integer narrowing is checked.
- Kernel-written lengths are validated before slicing or initializing memory.
- Uninitialized memory is never exposed to Rust safe code or JavaScript.
- Allocation sizes have explicit practical bounds and fail predictably.
- Cmsg traversal validates header size, aligned advancement, payload bounds, and
  total control length before constructing typed or unknown values.
- Timestamp seconds/nanoseconds remain lossless across N-API and are normalized
  before exposure.
- Mapped packet memory, when added, is inaccessible after its explicit native
  frame/block lease ends.

### Concurrency and async safety

- Socket state transitions are synchronized without holding locks across Node
  callbacks or promise settlement.
- Close/receive and close/send races have specified outcomes.
- Cancel/readiness/close/shutdown races have one native settlement authority and
  exactly one observable completion.
- JavaScript pending-operation finalizers compose rather than overwrite one
  another; AbortSignal removal, receive-lane release, and future finalizers each
  run exactly once on every terminal settlement path.
- Pending settlement deletes its operation entry, runs an isolated ordered
  finalizer snapshot, and only then settles the promise, so reentrancy cannot
  duplicate cleanup or observe a stale lane/ring reservation.
- Queued work is bounded or subject to documented backpressure.
- Readiness and command processing have fairness budgets; one hot socket cannot
  monopolize the environment reactor.
- Completion delivery never drops a result. Its bounded queue may deliberately
  backpressure the reactor thread when JavaScript is unable to drain
  settlements, as governed by D-026.
- Teardown prevents callbacks into an invalid N-API environment.
- Panics are caught before any FFI boundary, while normal errors remain `Result`
  values rather than panic paths.

### Syscall safety

- `unsafe` code is isolated in the smallest practical Linux adapter functions.
- Each `unsafe` block includes a local `SAFETY:` explanation of pointer,
  initialization, size, alignment, lifetime, and ownership assumptions that
  apply.
- Interrupted, partial, would-block, and truncated results are handled
  deliberately rather than treated as generic success/failure.
- Structure sizes and address families are validated before interpreting unions
  or variable-length structures.
- Generic option bytes never accept pointer-bearing, fd-bearing, or nested
  pointer layouts; those require typed APIs.
- Received fds in ancillary data are closed immediately unless a future typed
  ownership API explicitly accepts them. Phase 5 does not expose `SCM_RIGHTS`.

## Abuse and robustness limits

The public API should define sensible maximum packet/buffer sizes and maximum
pending operation counts. Limits must be high enough for supported Linux
semantics but should prevent accidental multi-gigabyte allocations or an
unbounded queue of native work.

Backpressure belongs in the design of receive loops and repeated sends. Phase
11's event adapter fixes one receive in flight, no adapter message queue,
awaitable pause/detach quiescence, deterministic receive-lane ownership, and no
automatic retry after errors. Pause stops userspace rearming but cannot stop
kernel ingress or drops; asynchronous event listeners are not awaited and do not
provide backpressure.

Quiescence includes a successfully settled receive waiting for event dispatch;
no lifecycle race may discard it or emit it after the boundary. Claim/observer
installation and rollback are transactional, and simultaneous packet-ring calls
use distinct tokens rather than a shared boolean. A retained socket deliberately
retains at most its two attached lane sources until detach/close; garbage
collection and `FinalizationRegistry` are not correctness mechanisms.

Event listener failures are application exceptions, not native socket failures.
Dispatch must keep them out of internal promise-rejection channels while still
running controller cleanup. Node's process-wide `captureRejections` setting may
route rejected async listener promises to `error`, so that event accepts
`unknown`; adapter-generated receive failures remain structured `RawSocketError`
values. The inherited caller-accessible `emit()` method never changes protected
lifecycle or receive-claim state.

Control buffers, batches, filter programs, mapped rings, fanout groups, and
unknown option/control payloads need independent count/byte limits. A raw
networking API must not treat kernel capability as permission for unbounded
process memory retention.

## ICMPv4 codec and traceroute invariants

The protocol layer treats even checksum-valid ICMP as unauthenticated input.
Redirects, Router Advertisements, Address Masks, timestamps, quoted packets, and
traceroute responders are reported as data and never applied automatically to
routes, interfaces, clocks, or trust decisions.

Every parser checks its common minimum before the type-specific layout. IPv4
IHL/total length, ICMP message length, router address counts/entry words, quoted
datagram offsets, and RFC 4884 object lengths use checked arithmetic before
slicing or allocating. Truncation and checksum-unverifiable states are explicit.
Unknown types, codes, and extension objects are preserved only as owned bytes
within the 65,515-byte ICMPv4 message ceiling (the IPv4 maximum minus its
minimum header). Receivers preserve standards-defined ignored/reserved bytes as
validation issues instead of rejecting safely readable future-compatible data;
canonical encoding still writes every such field deterministically. RFC 4884
uses its length octet by default, treats zero as no extensions, and enables
fixed-128-byte legacy detection only by explicit opt-in with a verified
extension header and complete object chain.

Encoded and parsed variable data does not alias caller-mutable buffers. Each
public codec/checksum call first makes one bounded private copy and performs all
checksum and structural reads from it, so concurrently mutable shared input
cannot change meaning between passes. The first implementation deliberately
copies bounded fields; a zero-copy codec would require a new lifetime and
mutation review. Checksum routines do not mutate inputs and handle odd lengths
without reading an implicit byte.

Traceroute uses monotonic time, bounded probe counts/timers/in-flight work,
bounded token/payload sizes, an overall deadline, and compact retained results.
Strong correlation spans destination, protocol, identifier, sequence, and a
payload token; a short historical quote is explicitly weaker, while partial or
contradictory evidence returns unmatched rather than guessing. One settlement
authority arbitrates reply, timeout, cancellation, and close. Cancellation and
local I/O failure reject only after listener/timer/lane cleanup. The convenience
uses the existing normal receive lane and must conflict deterministically with
another receiver rather than silently split packets.

## Review checklist for every native export

1. Are all JS inputs type-, range-, and combination-checked?
2. Who owns every descriptor, buffer, pointer, and callback reference?
3. What happens if the socket closes before, during, or after the operation?
4. Can the operation block the event loop or create unbounded work?
5. Can a panic or exception cross an FFI boundary?
6. Are partial results, `EINTR`, `EAGAIN`, and platform errors meaningful here?
7. Does teardown or garbage collection invalidate any referenced state?
8. Are errors stable and rich enough to debug without parsing a message?
9. Are success, failure, boundary, and race paths tested?
10. Is new `unsafe` code truly necessary and locally justified?
11. Are cancellation and completion ownership exactly-once under every race?
12. Does this work consume its fair reactor budget and preserve other sockets'
    progress?
13. If the kernel returns an unknown message or partial batch, are all bytes and
    per-item outcomes still bounded and initialized?

## Verification strategy

- Unit-test state machines, checked conversions, error mapping, and address
  encoding without privileges.
- Test native exports with invalid plain-JavaScript values even when TypeScript
  would reject them.
- Use stress tests for repeated creation/close and concurrent operation races.
- Use sanitizers and dynamic analysis where compatible with the N-API test
  harness; document tool limitations rather than claiming nonexistent coverage.
- Run Clippy with warnings denied and audit dependencies before releases.
- Fuzz parsers/converters and native boundary inputs once the first API shape is
  stable.
- Fault-inject completion saturation, `EINTR`, `EAGAIN`, malformed/truncated
  cmsgs, partial batches, and close/cancel interleavings.
- Run two-hot-socket fairness tests and long-lived abort/listener leak tests.
- Keep successful raw-I/O integration tests gated behind explicit capability
  setup in an isolated Linux environment.

## Privileged-test policy

Normal tests must not require root. Tests should validate expected `EPERM` or
`EACCES` behavior when capabilities are unavailable. Tests that need
`CAP_NET_RAW` must be separately named, skipped by default, and run in a tightly
scoped container or dedicated environment. Do not set capabilities on general
Node executables or grant a broad CI job privilege merely for convenience.
