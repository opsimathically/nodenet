# Phase 11 plan review

Status: complete historical preimplementation audit; Phase 11 is now implemented

Initial review: 2026-07-13

Adversarial second review: 2026-07-13

## Review objective

This review tests the Phase 11 event-adapter plan against the implemented
TypeScript facade, native reactor, Node 26 EventEmitter behavior, current test
and packaging tools, and the project's existing safety decisions. It is a
planning audit only; no production code is implemented by this review.

The authoritative implementation contract remains
[the Phase 11 plan](19-phase-11-event-api-plan.md). This document records why
that contract is feasible and which gaps were corrected before implementation.
The second pass deliberately reopened every readiness claim and traced same-turn
scheduling, transient lifecycle states, garbage collection, inherited
EventEmitter behavior, simultaneous ring operations, Worker teardown, and
release assembly rather than trusting the first checklist.

## Evidence inspected

- `src/index.ts`: `RawSocket`, `SocketState`, pending-operation dispatch,
  AbortSignal cleanup, receive methods, packet-ring methods, error
  normalization, and terminal close behavior.
- `native/src/reactor.rs`: separate normal/error receive queues, combined native
  receive limits, cancellation settlement, packet-ring exclusivity, and close.
- `native/src/packet.rs`: packet sockets reject error-queue receives.
- Existing unprivileged, privileged namespace, Worker, batch, ring,
  cancellation, completion-saturation, and release tests/scripts.
- Node 26's installed `node:events` declarations and runtime behavior for typed
  event maps, synchronous listener calls, `error`, `captureRejections`, and
  microtask exception reporting.
- Phase 10 release assembly, consumer, reproducibility, and ABI gates.

## Resolved findings

### R11-1 — Close recovery in the first draft was infeasible

`RawSocket.close()` sets its JavaScript admission flag permanently and caches
its close promise before native submission. If that promise rejects, later
operations and close attempts cannot return to an open/retryable API state.

Resolution: the adapter now mirrors this terminal-on-close-start contract. It
always ends and releases claims after close settlement, emits one
library-generated `close`, and returns the cached low-level resolve/reject
outcome. It no longer promises pause, detach, or retry after a rejected close.
Successful `close()` resolution remains the proof of descriptor release.

### R11-2 — EventEmitter rejection capture cannot be forced off locally

On the installed Node 26 runtime, a process-wide `events.captureRejections`
setting affects newly constructed emitters even when a constructor option of
`false` is supplied. A rejected async listener may therefore reach the error
path with an arbitrary rejection reason.

Resolution: the adapter does not mutate global EventEmitter policy or install a
custom rejection hook, which could recurse through an async `error` listener.
The `error` event accepts `unknown`; adapter-generated receives still emit
`RawSocketError`, and listener rejection does not change controller state. Async
listeners remain non-awaited and non-backpressuring. Default, capture-enabled,
and non-Error behavior must be tested in isolated subprocesses.

### R11-3 — Direct `emit()` inside a promise continuation changes exception channels

Calling `emit()` directly from the `receiveMessage().then(...)` continuation
would turn a synchronous listener throw into rejection of an internal promise,
contrary to ordinary EventEmitter expectations and capable of stranding pump
bookkeeping.

Resolution: user dispatch crosses a dedicated `queueMicrotask` with
`try/finally`. A synchronous listener throw reaches Node's uncaught-exception
channel, while controller cleanup/quiescence still completes and the pump rearms
only if state remains running. Child-process tests observe this without harming
the main test runner.

### R11-4 — Pending cleanup was not composable

The current `PendingOperation` has one optional cleanup function, assigned by
AbortSignal handling. Adding receive-lane release by assigning another callback
would overwrite listener cleanup or leak a lane count.

Resolution: Slice 11A begins by replacing the slot with isolated, idempotent,
exactly-once finalizers. All settlement paths—including already-aborted and
rejected native submission—run every finalizer. Lane claims are not implemented
until existing AbortSignal regression tests pass on the refactor.

### R11-5 — Packet-ring exclusion is socket-wide

The native reactor rejects ring configuration while either normal or error-queue
receives exist, and rejects all message receives after the ring is configured.
The first draft treated the ring as conflicting only with the normal lane.

Resolution: pending/active packet-ring mode excludes both event lanes. A packet
event source supports ordinary non-ring packet messages only; packet error-queue
sources are rejected as unsupported. Existing low-level post-configuration
`ERR_UNSUPPORTED` behavior remains unchanged.

### R11-6 — Receive ownership needed an exact settlement model

Direct receives can currently be concurrent, and normal/error queues are
distinct natively. An event source must not accidentally change valid direct
concurrency or expose its bypass token publicly.

Resolution: module-private `SocketState` tracks direct counts and one event
claim per lane. Normal and IP error-queue event sources may coexist. Existing
direct concurrency remains; only conflicts caused by an event claim return
`ERR_RECEIVER_ACTIVE`. A module-private friend/driver boundary admits event
receives without adding a public `receiveMessage()` overload or declaration.

### R11-7 — State errors and transition precedence were underspecified

The first draft did not define all repeated, overlapping, synchronous, and
asynchronous lifecycle calls.

Resolution: the plan now fixes the full state/method table, cached promises,
close-over-detach-over-pause precedence, synchronous versus rejected errors, and
`ERR_INVALID_STATE`. External close during detach returns the same socket in its
resulting lifecycle; completed detach removes its observer and receives no
future close event.

### R11-8 — Reactor shutdown is not a resumable receive error

Treating every error other than socket-closed as paused would offer `resume()`
after `ERR_REACTOR_CLOSED`, which can never make progress.

Resolution: reactor closure is terminal, invokes `RawSocket.close()` to close
the low-level JavaScript admission path, and produces observable `error` then
exactly-once `close` when the environment is still able to deliver them. Other
autonomous receive failures pause before `error` and never retry automatically.

### R11-9 — Privilege-free controller and consumer type tests needed a concrete seam

The public adapter requires a real `RawSocket`, whose successful construction
normally needs `CAP_NET_RAW`. The initial plan named a fake source but did not
define how tests could inject one without widening the package API.

Resolution: an internal built controller/driver module is testable by repository
relative import but is absent from package `exports`. The public root composes
it with `RawSocket`. A separate no-emit TypeScript fixture imports the built
root package and verifies actual consumer declarations. Package-content checks
treat required internal JavaScript as intentional while supported subpath
imports remain closed.

No supported module-created socket can be opened deterministically without raw
socket privilege. The receive-claim coordinator therefore also accepts fake
owners for internal tests. Ordinary CI covers that coordinator plus exports,
types, forged inputs, and permission errors; every genuine public attachment,
conflict, external close, and Worker path belongs to the isolated namespace
suite.

### R11-10 — Application-controlled EventEmitter memory and synthetic events needed boundaries

EventEmitter listener arrays and listener-retained messages can grow through
application actions, and inherited `emit()` is public.

Resolution: the adapter retains Node's default listener warning, never installs
an unlimited listener setting, and documents retained application memory as
caller-owned. Synthetic caller events do not mutate controller state, release
claims, or satisfy the library's exactly-once close notification.

### R11-11 — TypeScript-private construction is not a runtime authenticity check

`RawSocket` has a TypeScript-private constructor, but emitted JavaScript does
not enforce that keyword. `instanceof RawSocket` alone would therefore accept a
plain-JavaScript forged instance as an event source input.

Resolution: successful `RawSocket.open()` records sockets in a module-private
`WeakMap` carrying their internal state/friend closures. Event adapter
construction requires registry membership before using the driver. The map adds
no ownership root and keeps malformed plain JavaScript objects on a
deterministic `ERR_INVALID_ARGUMENT` path.

### R11-12 — Node's typed EventEmitter map is not a closed name whitelist

An in-memory TypeScript 6 probe against the installed Node 26 declarations
confirmed that known event arguments are strongly checked, but arbitrary custom
event names remain accepted by inherited EventEmitter methods.

Resolution: Phase 11 preserves Node's extensible event-name behavior. The type
fixture checks `message`, `error`, and `close` payloads plus custom-name
support; it does not assert that an unknown event name is a compiler error. Only
the three documented domain names are explicitly emitted by adapter logic;
inherited EventEmitter meta-events are addressed by R11-16.

## Resolved second-pass findings

### R11-13 — Receive settlement and event dispatch are separate race points

A receive promise can fulfill and queue event dispatch before a pause, detach,
or close call runs. Treating the native promise as no longer active at that
point could resolve quiescence and then emit a late message, or discard a
success that already won cancellation.

Resolution: one controller turn now spans admission, settlement, queued
dispatch, and bookkeeping. A settled-but-undispatched message remains the one
bounded active turn and is emitted before every quiescence boundary. The pump
uses one generation-checked scheduler, so stale or duplicate microtasks cannot
admit work after pause/detach or create two receives when an error listener
resumes synchronously.

### R11-14 — The lifecycle table still left implementation choices

The first review covered precedence but did not enumerate all five lifecycle
methods in all eight states, promise identity across cycles, whether
start/resume admit synchronously, or the `operation` field on new structured
errors.

Resolution: the plan now contains the complete matrix. `start()`/`resume()`
change status synchronously and schedule admission; asynchronous methods cache
one promise per lifecycle cycle; detached-versus-closed errors are distinct; and
every new error site has a stable operation name and validation precedence.

### R11-15 — One packet-ring boolean is unsafe with simultaneous calls

Two `configurePacketRing()` calls can both be provisionally admitted. If one
completion cleared a shared boolean while the other remained pending, an event
source could attach during a socket-wide mode transition. A pending
`receiveRingFrame()` also needed an explicit socket-wide classification.

Resolution: every ring configuration owns a distinct finalizer-backed token;
failure releases only that token and success atomically establishes active ring
mode. Pending ring-frame receives exclude event attachment socket-wide. Tests
cover two provisional calls with success/failure orderings plus close.

### R11-16 — EventEmitter itself produces observable events

The phrase "only library-generated event names" overlooked EventEmitter's
`newListener`/`removeListener` meta-events and the `events.errorMonitor` symbol.
A monitor observes `error` but intentionally does not prevent an unhandled error
from throwing.

Resolution: the contract now distinguishes the adapter's three domain events
from inherited EventEmitter behavior and preserves the latter without lifecycle
side effects. Subprocess tests include meta-events, monitoring, monitor-only
uncaught error, and ordinary/captured rejection cases.

### R11-17 — Dropped adapter references needed a resource-lifetime rule

If a retained socket holds an attached lane but the application drops only the
emitter reference, automatic GC release would make claim timing
nondeterministic; strong retention without documentation would look like a leak.

Resolution: `SocketState` deliberately retains attached idle, running, and
paused sources until explicit detach or terminal close, bounded to two lanes per
socket. Phase 11 uses no `FinalizationRegistry`; losing the emitter reference is
not cleanup. Running adapters retain the existing pending-receive process
liveness, and `ref()`/`unref()` remains deferred.

### R11-18 — Authenticity and observer installation must be transactional

A WeakSet membership check alone would not provide the state/driver access
needed outside `RawSocket`'s JavaScript `#private` body. Claim installation,
observer registration, or controller construction could also throw after only
part of the attachment became visible.

Resolution: a module-private `WeakMap<RawSocket, SocketInternals>` records only
successfully opened sockets and carries class-created friend closures plus
state. Construction validates first, then installs claim and observer as one
rollback-safe transaction. Close observers iterate snapshots with exception
isolation so one source cannot alter raw close or starve a sibling.

### R11-19 — Reactor loss must terminalize the wrapped low-level object

Caching an adapter-only rejected result on `ERR_REACTOR_CLOSED` would leave
`RawSocket`'s JavaScript admission flag open even though no future native work
can succeed.

Resolution: either terminal receive result ensures the idempotent
`RawSocket.close()` path has begun, making low-level admission terminal.
`ERR_SOCKET_CLOSED` remains silent; reactor loss emits its original autonomous
receive error before close. Later adapter close returns the cached raw-close
outcome, which need not contain the identical reactor error object.

### R11-20 — Shared close and Worker termination needed scoped guarantees

Closing either normal/error source necessarily closes their one shared socket,
but waiting for sibling listeners would couple independent application code.
Likewise forced Worker termination cannot promise additional JavaScript event
delivery after environment teardown.

Resolution: both sources become terminal, but each adapter close waits only for
its own turn and close-event dispatch and promises no cross-lane event ordering.
Cooperative Worker shutdown asserts lifecycle events; forced termination asserts
native cleanup, bounded resources, and process safety only.

### R11-21 — Finalizer ordering was not yet a linearization rule

"Exactly once" did not specify whether the pending entry disappears before
cleanup or whether promise continuations can observe stale lane counts.

Resolution: settlement deletes the pending entry first, runs a registration-
order snapshot of isolated finalizers, and only then resolves/rejects. Direct
lane and ring tokens register their finalizers before the already-aborted check
or native call, so every path has the same observable cleanup boundary.

### R11-22 — Public status does not prove that user dispatch is finished

The controller becomes `paused` before emitting an autonomous error and `closed`
before emitting its close event. A detach from an error listener could therefore
release its claim in the middle of the listener chain if implementation looked
only at status. Likewise a repeated close from a close listener was incorrectly
describable as already settled.

Resolution: controller turn activity is tracked separately from public status.
Paused detach waits any active error dispatch before release; closed close
returns the same promise, which remains pending until current close dispatch
finishes. Listener-reentrant pause, resume, detach, close, throw, and sibling
close combinations are explicit controller tests.

## Implementation order confirmed

Implementation must proceed in this dependency order:

1. Add ordered composable pending finalizers and prove all existing cancellation
   and settlement behavior unchanged.
2. Add public error kinds/types plus the privilege-free controller state
   machine, single pump scheduler, pending-dispatch state, and microtask
   dispatch tests.
3. Add the successful-open `WeakMap`, module-private `SocketState` receive
   counts, event claims, per-operation ring tokens, lifecycle observers, and the
   `RawSocket` friend closures.
4. Export `RawSocketEventEmitter` and add unprivileged boundary/type/Worker
   tests.
5. Add isolated repeated IPv4, IPv6, packet, and IP error-queue tests plus
   two-source fairness and lifecycle stress.
6. Update README/API/changelog, advance every coordinated manifest/policy/lock
   version to `0.1.0-rc.2`, and rerun consumer/artifact/provenance gates.

No later item may be used to conceal a failure in an earlier ownership or
settlement gate.

The error-queue gate is locally deterministic: an IPv4 raw UDP socket with
`receiveErrors` enabled sends a valid UDP header to an unused loopback port in
the isolated namespace, producing an ICMP port-unreachable extended error. This
exercises concurrent normal/error sources without relying on external routing,
hardware, or probabilistic overflow.

## Readiness checklist

- Public class, options, events, methods, states, errors, and ownership are
  named and typed.
- Every lifecycle transition and precedence rule has an expected outcome.
- Promise identity, synchronous status changes, scheduling boundaries, and
  stable error operation names are fixed.
- Pause/detach completion-winning and cancellation-winning races are specified.
- Close-start, close settlement, external close, two-lane close, and listener
  exception behavior are specified.
- Normal, error-queue, direct, batch, and ring receive conflicts are classified.
- All hidden queues, buffers, operations, listeners, and claims have bounds or
  explicit application ownership.
- Attached-source retention, shared-socket close, process liveness, and forced
  Worker teardown have explicit limits.
- Native memory and descriptor ownership remain unchanged.
- No new production dependency, Rust crate, N-API export, or unsafe code is
  expected.
- Privilege-free, privileged, Worker, subprocess, type, stress, fairness,
  regression, consumer, and release test layers are identified.
- The unpublished RC version/provenance update is included.
- Native AArch64 remains an honest publication gate and is not represented as
  tested.

## Verification performed for this review

- Ran repository Prettier formatting/checks on all changed planning documents.
- Ran `git diff --check`.
- Confirmed the installed runtime is Node 26 and the installed Node declarations
  support typed `EventEmitter` maps.
- Ran an in-memory TypeScript 6 probe proving known-event payload checking and
  inherited custom-event-name acceptance without creating repository files.
- Probed process-wide `captureRejections` and microtask exception channels in
  isolated Node subprocesses.
- Probed inherited `newListener`/`removeListener`, `errorMonitor`, and
  monitor-only uncaught-error behavior on the installed runtime.
- Cross-checked ring and receive-lane behavior in the implemented native reactor
  and existing privileged tests.
- Re-traced package exports, clean build/test ordering, no-top-level-await
  `require(esm)`, release manifests, and every coordinated RC version source.

Primary references used:

- [Node.js EventEmitter documentation](https://nodejs.org/api/events.html)
- [Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Linux `IP_RECVERR`](https://man7.org/linux/man-pages/man2/IP_RECVERR.2const.html)

## Conclusion

Phase 11 was complete as a plan after two independent passes, with no unresolved
design or feasibility question. Implementation subsequently followed the
required pending-finalizer-first sequence and is recorded in
`21-phase-11-report.md`.
