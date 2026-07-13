# Phase 11 plan — event-driven receive API

Status: implemented; see `21-phase-11-report.md`

Last updated: 2026-07-13

## Purpose

Phase 11 adds an optional Node-style event API without replacing or changing the
promise-oriented `RawSocket` contract. The feature is an ergonomic TypeScript
adapter over the existing bounded `receiveMessage()` operation, not a second
native networking implementation.

The phase succeeds when applications can receive an indefinite sequence of raw
messages through a familiar typed `EventEmitter`, while pause, detach, close,
errors, listener behavior, receive ownership, and memory bounds remain explicit
and deterministic.

## Required outcomes

- Preserve every existing `RawSocket` method and promise behavior.
- Add no production package dependency; use Node's built-in `node:events`.
- Add no Rust, syscall, N-API, descriptor, or native-buffer surface unless
  implementation proves an existing cancellation invariant insufficient and a
  new decision is accepted first.
- Reuse `ReceivedMessage`, `RawSocketError`, `receiveMessage()`, AbortSignal
  cancellation, and the current reactor admission limits.
- Keep exactly one receive operation in flight per event source.
- Support ordinary IPv4, IPv6, and non-ring packet-socket message reception.
- Make event-source start explicit so listeners can be installed before any
  packet is consumed.
- Provide awaitable quiescence for pause and detach, and exactly-once close
  notification.
- Prevent an event source and direct receive calls from silently competing for
  the same receive lane.
- Document that pausing userspace reads cannot stop ingress or kernel drops.

## Non-goals

Phase 11 does not:

- remove or deprecate promise-based receives;
- add callback overloads to every `RawSocket` operation;
- decode network protocols or transform `ReceivedMessage` values;
- await promises returned by event listeners;
- create an unbounded JavaScript message queue;
- claim true producer backpressure over raw network traffic;
- expose packet-ring frame leases as ordinary message events;
- add batch, stream, async-iterator, Observable, or Web Streams adapters;
- add `ref()`/`unref()` or change how pending native receives keep a Node
  environment alive;
- automatically retry receive failures;
- change native queue limits or packet-buffer limits.

Readable streams, async iteration, batch events, and packet-ring events remain
possible additive work after this phase. They must not be folded into Phase 11
without extending its ownership and backpressure review.

## Accepted public API direction

The new exported class is `RawSocketEventEmitter`. It extends Node's typed
`EventEmitter` and wraps an already-open `RawSocket` by composition. It exposes
the wrapped socket through a getter-only readonly `socket` property backed by
the original internal reference, so ordinary assignment cannot make the public
view disagree with the controller. Sending, configuration, filtering,
statistics, and other non-receive operations remain available through the
complete low-level API.

Its construction signature is `new RawSocketEventEmitter(socket, options?)`.
There is no second socket-opening factory: privilege errors and initial bind,
option, filter, and membership configuration remain explicit through
`RawSocket.open()` before wrapping.

The accompanying public types are:

- `RawSocketEventEmitterOptions`;
- `RawSocketEventEmitterStatus`;
- `RawSocketEventMap`.

### Construction options

`RawSocketEventEmitterOptions` contains only:

- `dataCapacity?: number`, with the same default and bounds as
  `ReceiveMessageOptions.dataCapacity`;
- `controlCapacity?: number`, with the same default and bounds as
  `ReceiveMessageOptions.controlCapacity`;
- `errorQueue?: boolean`, defaulting to `false`.

All option properties are readonly. Event payload objects reuse the existing
readonly `ReceivedMessage` declarations; the event-map argument tuples follow
the mutable tuple constraint of the installed Node 26 EventEmitter types.

The options are validated synchronously and copied during construction. The
adapter does not retain a caller-owned mutable options object.

Construction validates in this order: a module-created `RawSocket` recorded in
the internal `WeakMap` (not merely `instanceof`, because TypeScript-private
constructors are callable from plain emitted JavaScript), options
object/types/ranges, family compatibility, open JavaScript admission state, then
lane/ring conflicts. Existing receive methods retain their current priority of
closed/family checks and argument validation before the new event-claim check,
so attaching a source does not hide malformed caller input behind a mode error.

The event API deliberately does not accept arbitrary receive flags:

- `peek` is prohibited because automatic rearming would repeatedly deliver the
  same unconsumed datagram;
- `errorQueue: true` selects Linux error-queue messages without confusing them
  with the emitter's transport-level `error` event;
- a caller-controlled AbortSignal is unnecessary because the adapter owns an
  internal controller for pause, detach, and close.

There is no `autoStart` or configurable concurrency in Phase 11. Construction
does not consume packets. One receive per source is a fixed safety and ordering
property, not a tunable default.

`errorQueue: true` is accepted only for IPv4 and IPv6 sockets. Packet sockets
already reject `MSG_ERRQUEUE` as unsupported. The adapter does not silently
enable the family-specific `receiveErrors` option; applications configure that
option before `start()` when they want Linux to enqueue extended errors.

### Events

The typed event map is limited to:

| Event     | Arguments             | Meaning                                                              |
| --------- | --------------------- | -------------------------------------------------------------------- |
| `message` | one `ReceivedMessage` | One successful receive from the selected normal or error-queue lane. |
| `error`   | one `unknown`         | A receive-loop or Node-captured listener failure.                    |
| `close`   | none                  | The event source became terminal after socket close or reactor loss. |

These are the only domain events that the adapter explicitly emits. The
installed Node 26 generic EventEmitter types strongly check arguments for known
map keys but intentionally continue accepting arbitrary caller-defined event
names. The adapter preserves that standard extensibility rather than overriding
every inherited listener method to create a closed event-name whitelist.
Inherited EventEmitter behavior still produces `newListener` and
`removeListener` meta-events, and an emitted `error` is observable through
Node's `events.errorMonitor` symbol. An `errorMonitor` listener does not count
as an `error` handler, so monitor-only use retains Node's standard
uncaught-error behavior.

No `listening` event is added because socket creation, bind, and configuration
remain explicit promise operations performed before `start()`. Pause and resume
are observable through the synchronous status property and their method
completion, so they do not need redundant events.

Adapter-generated socket failures are always `RawSocketError` instances even
though the event is typed as `unknown`. The wider type is required because Node
may route any async-listener rejection reason to `error` when process-wide
`captureRejections` is enabled. The adapter does not intercept Node's rejection
hook: re-emitting from a custom hook could recurse when an `error` listener is
itself async.

### Methods and status

The class provides:

- `start(): this` to begin an idle source;
- `pause(): Promise<void>` to stop rearming and establish an awaitable
  no-further-message boundary;
- `resume(): this` to restart a fully paused source;
- `detach(): Promise<RawSocket>` to quiesce permanently, release the receive
  lane, and return the still-open low-level socket;
- `close(): Promise<void>` to stop receiving and idempotently close the wrapped
  socket;
- readonly `status` and `socket` properties.

`RawSocketEventEmitterStatus` contains `idle`, `running`, `pausing`, `paused`,
`detaching`, `detached`, `closing`, and `closed`. Transient states are public so
callers never have to infer whether an asynchronous lifecycle boundary has been
established.

`closed` is the event source's terminal state. Successful resolution of the
underlying close promise—not the status word or event alone—is the descriptor
release guarantee.

Stable error operation names are part of the contract:

| Failure site                                                         | `RawSocketError.operation`                                           |
| -------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Constructor validation, authenticity, family, or attachment conflict | `createRawSocketEventEmitter`                                        |
| Lifecycle state conflict                                             | The invoked method: `start`, `pause`, `resume`, `detach`, or `close` |
| Conflict caused in an existing low-level receive/ring method         | That existing method's current operation name                        |
| Autonomous receive failure                                           | The underlying `receiveMessage` operation                            |

Constructor option/forgery failures use `ERR_INVALID_ARGUMENT`; packet
error-queue incompatibility and active packet-ring mode use `ERR_UNSUPPORTED`;
closing/closed admission uses `ERR_SOCKET_CLOSED`; and a live ownership conflict
uses `ERR_RECEIVER_ACTIVE`. Existing methods retain their current closed,
family, and argument-validation precedence. After those checks, an active claim
wins over an already-aborted signal because no operation may be admitted into a
lane owned by another API style.

## Receive ownership

A socket can have two independently identified receive lanes:

1. the normal data lane;
2. the Linux error-queue lane.

At most one event source may claim each lane. This permits an application to
listen for normal messages and error-queue messages concurrently without
allowing two consumers to nondeterministically split the same lane.

| Existing operation                          | Ownership classification                  |
| ------------------------------------------- | ----------------------------------------- |
| `receive()`                                 | normal lane                               |
| `receiveMessage()` without `errorQueue`     | normal lane                               |
| `receiveMessage({ flags: ["errorQueue"] })` | error-queue lane                          |
| `receiveBatch()`                            | normal lane                               |
| pending/successful `configurePacketRing()`  | socket-wide exclusion of both event lanes |
| pending `receiveRingFrame()`                | socket-wide ring receive exclusion        |

Adding `peek` to a direct `receiveMessage()` does not change its lane. The event
adapter never requests it.

The existing module-private `SocketState` will become the single JavaScript-side
authority for receive claims, pending direct-receive counts, packet-ring mode,
close observers, and pending-operation finalizers. A module-private
`WeakMap<RawSocket, SocketInternals>` is both the runtime authenticity registry
and the friend boundary: an entry is considered valid only when
`RawSocket.open()` successfully completes, and contains the state plus closures
created inside the class that can submit a claimed receive and observe
admission/close state. This avoids relying on TypeScript `private`, exposing a
symbol method, or weakening a public method signature. No registry, closure,
claim field, or token may appear in generated public declarations.

The facade enforces:

- construction fails with `ERR_RECEIVER_ACTIVE` if the selected lane already has
  an event source or a direct receive pending;
- construction fails with `ERR_SOCKET_CLOSED` unless the socket's JavaScript
  admission state is still open; checking only the native `status` getter is
  insufficient after close has begun;
- direct `receive()`, `receiveMessage()`, `receiveBatch()`, and
  `receiveRingFrame()` calls reject with `ERR_RECEIVER_ACTIVE` when they
  conflict with an attached source;
- creation of a source fails while a conflicting direct receive is pending;
- a pending `receiveRingFrame()` is a socket-wide direct receive conflict, even
  if native ring validation will later reject it;
- packet-ring configuration is socket-wide receive mode and conflicts with both
  event lanes, matching the native reactor's existing exclusion of normal and
  error-queue receives after ring configuration;
- an event source cannot attach while packet-ring configuration is pending or
  active; each configuration call owns a distinct provisional token so
  simultaneous attempts cannot clear one another's state. Failure releases only
  that call's token, while any success atomically establishes active ring mode
  until socket close;
- the adapter uses a module-private claim token to invoke `receiveMessage()`;
- `detach()` releases the claim only after its receive has settled;
- `close()` and external socket closure release all claims.

The new stable error kind is `receiverActive` with code `ERR_RECEIVER_ACTIVE`.
It describes a deterministic API-mode conflict rather than an exhausted native
queue. Sending and non-receive configuration remain legal while an event source
owns a lane.

Claim accounting stays in TypeScript because it arbitrates two JavaScript API
styles over the same already-safe native operations. Rust remains the authority
for descriptor ownership and native admission.

Existing low-level behavior remains compatible: multiple direct receives may
still share a lane within native admission limits, and message receive after a
successfully configured ring continues to fail with `ERR_UNSUPPORTED` rather
than being relabeled as `ERR_RECEIVER_ACTIVE`. The new conflict code is used
only when an attached or attaching event source causes the conflict.

The exact ring conflict errors are stable: event attachment during provisional
ring configuration and ring configuration while an event source is attached use
`ERR_RECEIVER_ACTIVE`; attachment after successful ring configuration uses the
existing `ERR_UNSUPPORTED` because message mode is no longer available. Active
ring mode takes precedence over a simultaneous ring-frame pending count; before
ring activation, a pending ring-frame call produces `ERR_RECEIVER_ACTIVE` on
event attachment.

Construction is transactional. It validates first, then atomically installs one
lane claim and lifecycle observer; any exception after reservation rolls both
back before it escapes. An `idle` or `paused` source deliberately continues to
own its lane. `pause()` is not an ownership release; only successful detach or a
terminal close releases the claim. Normal and error-queue lanes otherwise remain
independent: a direct operation on one lane does not block attachment on the
other, and detaching one of two sources does not disturb its sibling.

### Exactly-once claim cleanup

`PendingOperation.cleanup` is currently a single optional callback used to
remove AbortSignal listeners. Slice 11A must replace it with a composable,
idempotent finalizer mechanism before adding receive counters. Central pending
settlement must run all finalizers exactly once for:

- successful completion;
- native error completion;
- rejected native submission;
- already-aborted admission;
- cancellation, close, and environment shutdown.

Finalizers are internal, idempotent, and required not to throw. Central cleanup
first removes the pending-map entry, then runs a snapshot of every finalizer in
registration order with per-finalizer exception isolation, and only then invokes
the operation's resolve/reject continuation. Deleting first makes a duplicate
completion a no-op; cleanup-before-settlement ensures a caller resuming from the
promise observes released counts and listeners. One invariant failure cannot
prevent remaining cleanup or replace the already chosen operation outcome.

Direct-receive lane counts and ring provisional tokens are reserved only after
public validation succeeds and before operation submission. Their finalizers
must be registered before checking an already-aborted signal or calling native
code, then release the exact reservation on every terminal path. Event receives
use their source's unexported claim token rather than incrementing
direct-receive counts. The implementation must use the module-private
friend/driver boundary and must not widen the public `receiveMessage()`
signature to expose that token.

## Lifecycle contract

### State transitions

| State       | `start()`                                          | `pause()`                                                                    | `resume()`                                         | `detach()`                                                                                                      | `close()`                                                                                 |
| ----------- | -------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `idle`      | Enter `running`, schedule one pump, return `this`. | Enter `paused`, cache/return a resolved boundary.                            | Throw `ERR_INVALID_STATE`.                         | Enter `detached`, synchronously release claim/observer, cache/return the socket promise.                        | Enter `closing` and immediately start raw close.                                          |
| `running`   | Return `this`.                                     | Enter `pausing`, stop scheduling, abort the turn, cache/return its boundary. | Return `this`.                                     | Enter `detaching`, stop scheduling, abort the turn, cache/return detach.                                        | Enter `closing` and immediately start raw close.                                          |
| `pausing`   | Throw `ERR_INVALID_STATE`.                         | Return the same pause promise.                                               | Throw `ERR_INVALID_STATE`.                         | Enter `detaching`; share quiescence, then release and resolve detach.                                           | Enter `closing`; close preempts pause.                                                    |
| `paused`    | Throw `ERR_INVALID_STATE`.                         | Return the most recent pause boundary.                                       | Enter `running`, schedule one pump, return `this`. | Enter `detaching`; wait for any active error-dispatch turn, then release claim/observer and resolve the socket. | Enter `closing` and immediately start raw close.                                          |
| `detaching` | Throw `ERR_INVALID_STATE`.                         | Reject `ERR_INVALID_STATE`.                                                  | Throw `ERR_INVALID_STATE`.                         | Return the same detach promise.                                                                                 | Enter `closing`; close preempts detach.                                                   |
| `detached`  | Throw `ERR_INVALID_STATE`.                         | Reject `ERR_INVALID_STATE`.                                                  | Throw `ERR_INVALID_STATE`.                         | Return the same resolved socket promise.                                                                        | Reject `ERR_INVALID_STATE`; use the returned `RawSocket` to close it.                     |
| `closing`   | Throw `ERR_SOCKET_CLOSED`.                         | Reject `ERR_SOCKET_CLOSED`.                                                  | Throw `ERR_SOCKET_CLOSED`.                         | Reject `ERR_SOCKET_CLOSED`.                                                                                     | Return the same adapter close promise.                                                    |
| `closed`    | Throw `ERR_SOCKET_CLOSED`.                         | Reject `ERR_SOCKET_CLOSED`.                                                  | Throw `ERR_SOCKET_CLOSED`.                         | Reject `ERR_SOCKET_CLOSED`.                                                                                     | Return the cached adapter close promise; it may still await the current `close` dispatch. |

`start()` and `resume()` use one idempotent pump scheduler; they change status
synchronously but native admission happens from its queued microtask. This makes
same-turn pause/close deterministic and lets an error listener resume without
creating a second turn during the current dispatch. `close()` may preempt
`pausing` or `detaching`; close has higher precedence than detach, which has
higher precedence than pause. A new pause cycle after a resume creates a new
promise; repeated calls within the same cycle preserve promise identity.

Public status and turn activity are separate dimensions. `paused` is set before
autonomous `error` emission, so `detach()` called inside that listener enters
`detaching` and releases only after the dispatch turn finishes. `closed` is set
before library `close` emission, so a repeated `close()` inside its listener
returns the still-pending cached promise; that promise settles in dispatch
`finally`. Outside those dispatch windows, paused detach releases synchronously
before its returned promise settles and a closed close promise is already
settled.

Construction, `start()`, and `resume()` report validation/state failures by
throwing synchronously. `pause()`, `detach()`, and `close()` report failures by
rejecting their returned promises. The new stable error kind `invalidState` and
code `ERR_INVALID_STATE` distinguish an event-controller transition error from
an invalid packet/socket argument.

When close preempts a pause, the pause promise still resolves after its
no-further-message boundary even though public status remains `closing`. When
close preempts detach, detach resolves with that now-closing or closed
`RawSocket`, while source status follows the winning close transition and the
library-generated close event still occurs. A normal detach completion removes
its lifecycle observer, remains `detached`, and emits no future `close` for
later activity on the returned socket.

If two lane sources wrap one socket, calling `close()` on either closes the
shared socket and drives both sources terminal. Each source awaits only its own
turn and close-event dispatch; neither adapter close promise waits for the
sibling's user listeners, and no ordering is promised between the siblings'
`close` events. The low-level socket close outcome is nevertheless shared.

### Receive pump

One pump turn includes native admission, receive settlement, any queued user
dispatch, and final bookkeeping. A fulfilled receive whose `message` dispatch
microtask has not run is still an active turn; lifecycle quiescence cannot treat
it as idle or discard its message.

The implementation sequence for each turn is fixed:

1. Confirm that the source is still `running` and owns its receive lane.
2. Create a fresh internal `AbortController` and admit one `receiveMessage()`
   using the immutable capacities and selected lane.
3. Store that one operation as the source's only active turn.
4. On success, retain that one bounded message until its dispatch microtask.
5. Synchronously emit one `message` in listener-registration order through a
   dedicated `queueMicrotask` boundary with `try/finally`, so a listener throw
   remains an uncaught EventEmitter exception rather than becoming an unhandled
   rejection of an internal promise.
6. After dispatch finishes, re-check state and schedule—not recursively call—the
   next receive on a later microtask only when still `running`.
7. In every path, clear operation/controller references and settle any
   quiescence waiter even if a listener throws.

This produces receive-completion ordering within one lane, prevents synchronous
recursion, and never accumulates an internal message list.

The scheduler has at most one queued admission and uses a generation/ownership
check so a stale microtask from an earlier pause/resume/detach cycle can only
become a no-op. `resume()` called synchronously from a nonterminal `error`
listener changes status to `running` but cannot admit until that error-dispatch
turn finishes. This single scheduling authority prevents both double admission
and a stranded source.

### Pause and detach races

`pause()` and `detach()` immediately prevent another receive from being armed,
then abort the current native receive, if any, and await the entire turn.

- If cancellation wins, `ERR_ABORTED` is internal control flow and is not
  emitted as an error.
- If receive wins, its message is emitted before the lifecycle promise resolves.
- If native success has already settled but dispatch is still queued, the
  message is emitted before pause, detach, or close reaches its quiescent
  boundary.
- After the promise resolves, no later `message` can be emitted by that source.
- A pause invoked inside a `message` listener prevents rearming after the
  current synchronous emission finishes.
- Detach releases its lane only after this same quiescence boundary, so a direct
  receive cannot overlap the adapter's final operation.

No successfully received message is silently discarded merely to make pause,
detach, or close appear immediate. If an autonomous receive error wins before a
later close request, its prescribed `error` dispatch occurs before `close`; an
intentional abort or socket-closed result chosen after close starts remains
silent control flow.

Quiescence waits for the current synchronous EventEmitter dispatch and internal
receive settlement, not promises previously returned by listeners. Those
application promises may finish or reject after pause, detach, or close.

### Close behavior

`close()` owns the normal adapter shutdown path. In the synchronous portion of
the call it caches the adapter close promise, enters `closing`, stops rearming,
cancels its turn, and invokes the existing idempotent `RawSocket.close()` so no
low-level operation can slip into the socket after event close began. It
releases receive claims after quiescence and returns the cached underlying close
outcome after adapter close-event dispatch has been attempted.

A module-private lifecycle observer on `RawSocket` lets every attached source
observe closure initiated through the low-level socket or the other receive
lane. The observer receives a nonthrowing synchronous `closing` notification
before native close submission so sources stop rearming immediately, followed by
an asynchronous terminal outcome after the low-level promise settles. A
socket-closed rejection from an active receive is treated as closure, not as an
`error` event.

Observer notification iterates a snapshot and isolates every callback. An
observer may update only internal controller state during the synchronous
`closing` notification; it may not emit to users there. One faulty or removing
observer cannot prevent sibling sources from seeing close, escape from
`RawSocket.close()`, or alter its promise. Observer registration and lane claim
installation/removal are one transaction.

Explicit method failures remain promise rejections and are not duplicated onto
`error`. The adapter itself emits `error` only for autonomous receive-pump
failures; Node may also emit it for captured async-listener rejection. Terminal
state and claim release occur before `close` is emitted, and event dispatch is
attempted before the adapter's close promise resolves. A close listener
exception does not turn a successful descriptor close into a rejected close
operation; bookkeeping and promise settlement run in `finally`.

The existing `RawSocket` public lifecycle is terminal from the instant
`RawSocket.close()` begins: its private admission flag remains closed and its
cached close promise is reused even if native close delivery rejects. The event
adapter must mirror that fact. It always becomes terminal, releases its claim,
and attempts one library-generated `close` after low-level settlement; its
`close()` resolves or rejects with the same cached low-level outcome. Here
`close` means the event source ended and the wrapped public socket accepts no
more work. Only successful resolution of `close()` proves the descriptor-release
guarantee documented by `RawSocket.close()`. There is no impossible
retry/resume/detach path after a rejected close.

Lifecycle observers may never invoke user listeners inline from
`RawSocket.close()`, throw into its settlement callback, or alter the low-level
promise outcome. `RawSocket.close()` called directly remains unaware of and does
not await adapter listeners; callers who need the event-dispatch boundary use
the adapter's `close()` or wait for its `close` event.

## Error and listener semantics

- An intentional pause/detach/close abort never emits `error`.
- `ERR_SOCKET_CLOSED` is silent terminal control flow. The adapter invokes the
  idempotent `RawSocket.close()` if necessary, follows `closing` until that
  cached outcome settles, then enters `closed` and emits `close` once. This
  covers both the ordinary observer-notified path and a native terminal result
  that arrives first.
- `ERR_REACTOR_CLOSED` is terminal: the adapter immediately invokes
  `RawSocket.close()` to make the wrapped socket's JavaScript admission state
  terminal, then, when the environment can still observe events, emits the
  original receive `error` followed by exactly-once `close`. Resuming a dead
  reactor is never offered. Later adapter `close()` returns its cached
  underlying raw-close outcome, which will normally reject with reactor closure
  but is not required to be the identical error object that triggered the pump.
  If an uncaught `error` is handled at process level, `try/finally` still
  permits the subsequent close dispatch.
- Any other receive failure transitions to `paused` before emitting a
  `RawSocketError` and creates a pause boundary that settles after error
  dispatch. There is no automatic retry, preventing persistent failures from
  becoming a CPU/error-event loop. The caller may inspect/fix state and
  explicitly resume. If an error listener resumes synchronously, its explicit
  transition wins and admission waits for dispatch completion; the pause
  boundary still resolves without overwriting the resumed state afterward.
- Emitting `error` without a listener retains Node's standard `EventEmitter`
  behavior and throws. For an adapter-generated receive error, the controller
  completes its prescribed paused or terminal transition before that throw;
  Node-captured listener rejection does not itself mutate controller state.
- `message` listeners run synchronously in registration order and receive the
  same `ReceivedMessage` object. A listener that needs mutation isolation must
  copy the Buffer before changing it.
- A synchronous listener exception is not converted into a socket error. It
  escapes according to Node event semantics, while `finally` restores pump
  bookkeeping and applies any requested lifecycle transition. If the process
  handles the exception and the source is still running, the next receive is
  scheduled rather than leaving the source stranded.
- Promise values returned by async listeners are not awaited and do not delay
  the next receive. Under Node's default EventEmitter setting, their rejection
  is an unhandled promise rejection. If the process enabled
  `events.captureRejections` before adapter construction, Node routes the
  rejection to `error` instead. The adapter neither changes that global nor
  claims all `error` values are `RawSocketError`; captured listener rejection
  does not mutate controller state. Async `error` listeners remain discouraged
  by Node. Tests cover both settings and non-Error rejection in isolated
  subprocesses.
- Starting without a `message` listener is permitted but consumes messages with
  no observer, matching ordinary `EventEmitter` behavior. Explicit `start()` is
  the caller's consent to consumption.
- The inherited public `emit()` method has ordinary Node behavior. Caller-made
  synthetic events never mutate controller state, release receive claims, or
  count as the adapter's internal exactly-once close notification.

## Backpressure, bounds, and memory ownership

The event adapter introduces no unbounded library queue:

- one source retains at most one receive promise, one AbortController, and one
  bounded `ReceivedMessage` until synchronous emission completes;
- the existing data/control capacity limits apply unchanged;
- received Buffers are the current initialized, JavaScript-owned copies and
  never alias mutable native or packet-ring memory;
- listeners may retain a message safely, and that retention is application
  memory rather than hidden adapter buffering;
- synchronous listener work delays rearming, providing limited userspace pacing;
- async listeners do not provide pacing because `EventEmitter` does not await
  them;
- while paused or slow, Linux continues receiving traffic into the configured
  socket buffer and may drop packets when it fills;
- packet statistics and queue-overflow metadata remain the mechanisms for
  observing applicable kernel drops.

The adapter retains Node's default maximum-listener warning and never disables
it with an unlimited setting. Listener arrays and Buffers deliberately retained
by application code are application-owned memory, but repeated lifecycle cycles
must not leak adapter-installed observers or AbortSignal listeners.

Attachment has explicit resource lifetime. While the caller retains a
`RawSocket`, its `SocketState` strongly retains each attached source and
lifecycle observer, including idle and paused sources. This keeps claims stable
if the caller drops only the emitter reference and bounds retention to at most
two sources per socket. Phase 11 deliberately does not use
`FinalizationRegistry` or nondeterministic garbage collection to release a
claim. Applications must call `detach()` to return a live lane or `close()` to
end the shared socket; losing the emitter reference is not cleanup.

A running source has the same process/Worker liveness consequence as repeatedly
holding a pending `receiveMessage()`. Phase 11 does not add `ref()`/`unref()` or
promise that an active source lets a process exit. Cooperative Worker teardown
must pause/detach/close and may assert JavaScript events; forced
`worker.terminate()` tests assert native cleanup and process safety only because
environment teardown is not required to run more JavaScript listeners.

Changing the one-operation rule or adding adapter buffering requires a new
decision with count/byte limits, overflow policy, ordering rules, and stress
measurements.

## Implementation slices

### Slice 11A — Pure TypeScript controller and types

- Add the typed event map, options, status, `invalidState`/`receiverActive`
  error kinds, and exported class.
- Refactor pending-operation cleanup into composable exactly-once finalizers and
  preserve all existing AbortSignal cleanup behavior before adding claims.
- Implement and unit-test the lifecycle state machine against a deterministic
  internal receive-source interface.
- Validate and snapshot capacities without admitting native work.
- Implement the one-turn receive pump, single/generation-checked scheduler,
  settled-but-undispatched state, microtask event-dispatch boundary, error
  pause/terminal handling, listener bookkeeping, and idempotent close
  notification.

The controller/driver lives in an internal built module that is not listed in
package `exports`. Tests may import that built relative path to inject a fake
driver, but the root declaration must expose neither driver interfaces nor claim
tokens. The release package may contain the internal JavaScript required by the
root entry point; package-content verification must treat it as intentional and
unimportable through supported package subpaths.

The internal controller is generic over received/error values and depends only
on injected receive, abort, close, dispatch, and lifecycle callbacks. It must
not import the public root or native binding, avoiding a root/controller module
cycle and allowing privilege-free tests to load without opening the addon.

The small finalizer/settlement helper is likewise native-free and internally
testable. Root `dispatchCompletion`, rejected submission, and already-aborted
paths delegate to it rather than each open-coding a different cleanup order.

Gate: fake-driver tests prove ordering, one-operation admission, pause/detach
quiescence, and every state transition without raw-socket privilege.

### Slice 11B — RawSocket integration and lane ownership

- Add module-private normal/error receive claims and lifecycle observers.
- Add the successful-open `WeakMap` registry/friend closures and transactional
  claim-plus-observer installation.
- Route the adapter through the existing `receiveMessage()` validation and
  cancellation machinery using an unexported friend/driver boundary and claim
  token, without adding a public overload.
- Reject conflicting direct, batch, and ring receives deterministically.
- Track each packet-ring configuration with its own provisional token and then
  active socket-wide receive mode; classify pending ring-frame receives as
  socket-wide while preserving existing `ERR_UNSUPPORTED` ring regressions.
- Ensure external close and two-lane close races settle every source once.
- Confirm no native code or dependency change is required.

Gate: privilege-free coordinator tests cover claims, ring transitions, and
closure with fake owners. Public unprivileged tests cover exports, declarations,
forged inputs, and unchanged permission errors. Isolated namespace tests cover
every genuine `RawSocket` attachment/conflict/close path and deliver repeated
IPv4, IPv6, packet, and error-queue messages.

### Slice 11C — Stress, documentation, and candidate rehearsal

- Add README examples for multiple-message event reception, pause/resume,
  detach, close, and error handling while preserving promise examples.
- Add an API comparison explaining when to choose promise or event style.
- Add a no-emit type fixture compiled by a dedicated TypeScript configuration;
  it must prove known event argument types, inherited custom-event-name support,
  and the absence of public claim/driver types against the built package
  declarations.
- Stress repeated start/pause/resume/close and Worker teardown with descriptor,
  listener, and bounded-RSS observations.
- Run the full ordinary and privileged verification gates.
- Advance the unreleased candidate to `0.1.0-rc.2` and regenerate release
  rehearsal/provenance so the Phase 10 `rc.1` evidence is not attributed to a
  changed public surface.
- Preserve no-top-level-await ESM output so Node 26 `require(esm)` consumption
  continues to work.

The coordinated version edit covers root `package.json`/`package-lock.json`,
`native/Cargo.toml`, both Cargo lockfiles' path-package entries, both target
package manifests, `release-policy.json`, README, and changelog. Generated
staged manifests/provenance are rebuilt rather than hand-edited.

Gate: package declarations and both ESM and Node 26 `require()` consumers expose
the typed class with zero runtime dependencies, and release policy checks pass.

## Required test matrix

| Layer                 | Required cases                                                                                                                                                                                                                                                                                                 |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type/lint             | Known event arguments enforced, `error` requires narrowing from `unknown`, inherited custom names accepted, options/socket readonly, no public driver/claim types.                                                                                                                                             |
| Pending finalizers    | Success, native error, rejected submission, already-aborted signal, close, and shutdown each release lane counts and AbortSignal listeners exactly once.                                                                                                                                                       |
| Controller unit       | Explicit start, one turn, single scheduler, stale-task no-op, settled/dispatch-pending races, ordered rearm, no recursion, full method/state matrix and promise identity, listener-reentrant lifecycle calls, transition precedence, pause cancel-win/receive-win, detach and close races.                     |
| Listener behavior     | Registration order, no-listener consumption, removal during emit, synthetic emit isolation, inherited meta-events/error monitor, synchronous throw bookkeeping, missing `error`, default/global rejection capture in subprocesses.                                                                             |
| Ownership             | Normal/error lanes coexist independently, duplicate lane rejected, transactional constructor rollback, dropped emitter remains attached, pending direct/ring-frame receive blocks attach, attached source blocks conflicts, simultaneous ring tokens and active ring exclude both lanes, detach releases once. |
| Unprivileged boundary | Package import/require, declarations, internal package-subpath rejection, getter-only socket identity, invalid/plain JS and forged `RawSocket`, internal fake-driver/coordinator lifecycle, permission errors unchanged.                                                                                       |
| Namespace lifecycle   | Genuine construction/options, all lane conflicts, packet error-queue rejection, ring pending/success/failure, external close in every state, Worker teardown.                                                                                                                                                  |
| Namespace IPv4        | Burst of multiple ICMP messages, ordering, pause/resume, close from listener, source metadata retained.                                                                                                                                                                                                        |
| Namespace IPv6        | Repeated ICMPv6 with ancillary metadata and the same lifecycle guarantees.                                                                                                                                                                                                                                     |
| Namespace packet      | Multiple cooked/raw veth messages without an active ring; address and auxdata preserved.                                                                                                                                                                                                                       |
| Error queue           | IP error-queue source remains distinct from `error`, requires explicit socket option setup, can coexist with normal lane, and pauses on actual receive failure.                                                                                                                                                |
| Fairness/stress       | Two hot sources progress, thousands of fake state cycles, real close/cancel/receive/dispatch interleavings, bounded operations, no descriptor/observer/listener leak, cooperative and forced Worker teardown, stable RSS envelope.                                                                             |
| Regression/release    | Existing Rust/Node/namespace/stress gates, package import/require, source and release builds, consumer install, artifact checks.                                                                                                                                                                               |

Tests must use deadlines so a missed rearm or quiescence settlement fails rather
than hanging the suite. Privileged cases remain opt-in and isolated by the
existing namespace harness.

The type fixture uses a dedicated no-emit `tsconfig` and imports the built
package entry point, so it verifies the declarations consumers actually receive
rather than only checking source types. Event exception/rejection tests that
would otherwise affect the test runner execute in child Node processes and
assert exit/error channels explicitly.

`npm run test:types` runs only after `build:typescript` in clean checkouts and
is included by both `npm test` and `npm run ci`. Consumer tests continue
covering both ESM import and synchronous Node 26 `require(esm)` so an accidental
top-level await in the new internal module is release-blocking.

The deterministic error-queue topology uses an IPv4 `IPPROTO_UDP` raw socket in
the isolated namespace with `receiveErrors` enabled. A normal source and an
error-queue source start together; the socket sends a valid eight-byte UDP
header with zero IPv4 UDP checksum to an unused loopback port. The normal lane
observes the outbound UDP packet and Linux returns the resulting ICMP port
unreachable through the error queue. The test filters by its chosen ports,
asserts the `errorQueue` message flag and typed extended-error control, and uses
a deadline. It uses no external route or nondeterministic queue overflow.

## Documentation obligations

The implementation phase must update:

- `README.md` with event and promise examples side by side;
- the API section with event names, statuses, ownership conflicts, and lifecycle
  return types;
- error examples that narrow `unknown` and distinguish `RawSocketError` from a
  Node-captured listener rejection;
- the limitations section with kernel-buffer/drop, async-listener, explicit
  detach/close lifetime, process-liveness, inherited meta-event/error-monitor,
  and two-source shared-close behavior;
- `CHANGELOG.md` with the additive API and `ERR_RECEIVER_ACTIVE`;
- `AGENTS.md`, the planning index, decision log, and this report with actual
  implementation and verification results;
- release-candidate version/provenance documents if the public package changes.

Documentation must never imply that `pause()` pauses the network, that async
listeners are awaited, or that event delivery uses packet-ring zero-copy memory.

## Exit gate

Phase 11 is complete only when all of the following are true:

1. The low-level promise API remains source-compatible and fully tested.
2. The adapter adds no external runtime dependency and ordinarily adds no native
   code or unsafe Rust.
3. Each event source has at most one receive operation in flight.
4. Conflicting receive consumers fail deterministically rather than splitting
   packets silently.
5. Existing AbortSignal cleanup and packet-ring `ERR_UNSUPPORTED` behavior
   remain regression-covered after the composable-finalizer/claim refactor.
6. Pause and detach resolve only after their no-further-message boundary.
7. Close and external-close races produce one library-generated `close` event
   and no leaked receive claim, AbortSignal listener, promise, descriptor, or
   Worker reference.
8. Persistent receive errors cannot create an automatic retry loop, and reactor
   closure is terminal.
9. Listener throws and promise rejections follow verified Node 26 EventEmitter
   channels without becoming unhandled internal controller promises.
10. A receive that has settled successfully but has not dispatched cannot be
    lost across pause, detach, close, or external close.
11. Received memory remains initialized, bounded, owned, and safe to retain;
    idle/paused attachment retention and explicit cleanup are documented.
12. Repeated IPv4, IPv6, packet, and error-queue delivery passes in isolated
    namespaces.
13. Full unprivileged CI, privileged namespace tests, event stress, consumer
    packaging, and release hardening gates pass with exact results recorded.
14. AArch64 remains described as untested until native execution actually
    passes; Phase 11 does not weaken that publication gate.

## Deferred follow-up candidates

These are explicitly outside Phase 11 and require separate acceptance:

- an object-mode `Readable` adapter with Node stream high-water-mark semantics;
- an async iterator with iterator-return cancellation semantics;
- awaited callback/handler concurrency with bounded application work;
- configurable receive concurrency or a bounded overflow queue;
- batch events based on `receiveBatch()`;
- packet-ring events that preserve explicit `PacketRingFrameLease.release()`;
- cross-lane ordering or merged normal/error-queue delivery;
- `ref()`/`unref()` support, which requires a separate native environment-
  liveness contract rather than an EventEmitter-only convenience.

There are no unresolved Phase 11 design questions. All three implementation
slices and their x86-64 gates are recorded in `21-phase-11-report.md`.
