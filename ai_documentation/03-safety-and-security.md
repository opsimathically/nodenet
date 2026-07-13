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
- Queued work is bounded or subject to documented backpressure.
- Readiness and command processing have fairness budgets; one hot socket cannot
  monopolize the environment reactor.
- Completion delivery never blocks the reactor thread and never drops a result
  when its queue is saturated.
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

Backpressure belongs in the design of receive loops and repeated sends. If the
API later supports callbacks or event streams, it must define pause/stop and
overflow behavior before implementation.

Control buffers, batches, filter programs, mapped rings, fanout groups, and
unknown option/control payloads need independent count/byte limits. A raw
networking API must not treat kernel capability as permission for unbounded
process memory retention.

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
