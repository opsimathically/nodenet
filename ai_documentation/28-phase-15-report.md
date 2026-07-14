# Phase 15 completion report

Status: complete

Completed: 2026-07-13

Release candidate: `0.1.0-rc.6` (unpublished)

## Outcome

Phase 15 implements bounded conventional ICMP Echo traceroute in strict
TypeScript over the existing ICMPv4 codecs, per-message send helper, and
`RawSocketEventEmitter`. It adds no runtime dependency, Rust source, native I/O
engine, DNS lookup, global receive loop, route mutation, or deprecated ICMP
Traceroute type 30 behavior.

The root API now exports:

- `createIcmpTracerouteProbe(options)` for deterministic, owned TTL-limited Echo
  probe metadata and payload construction;
- `classifyIcmpTracerouteResponse(probe, received, receivedAt)` for pure direct
  Echo Reply and quoted diagnostic correlation with monotonic `bigint` RTTs; and
- `traceIcmpRoute(socket, destination, options?)` for a bounded increasing-TTL
  operation over a caller-owned IPv4 ICMP socket.

The builder and classifier allow applications that already own an event source
to implement their own scheduling. The convenience operation owns the normal
receive lane for exactly one trace, detaches it on every terminal path, and
leaves the socket open.

## Correlation and result contract

Direct destination replies require the expected source address, identifier,
sequence, and complete token. Quoted Time Exceeded and Destination Unreachable
messages use the checked Phase 13 IPv4/ICMP quote matcher. Full token evidence
is reported as a strong match; historical quotes that end after the embedded
Echo header can be reported as weak only when the destination, ICMP protocol,
identifier, and sequence still match. Parameter Problem and Redirect diagnostics
require strong evidence and are informational terminal-neutral results.

Invalid checksums, structurally incomplete parses, unrelated codes, mismatched
tuples, and late replies cannot complete a probe. Returned results retain only
compact hop, timing, classification, MTU, pointer, gateway, and extension
summaries. They do not retain received packets, raw quotes, or caller buffers.
Results are sorted by hop and probe ordinal even when responses arrive out of
order.

Normal completion distinguishes `destination`, `unreachable`, `maxHops`, and
`overallTimeout`. Per-probe and overall timeouts remain explicit compact probe
results. Exact deadline equality is a timeout. External cancellation and local
send, receive, socket-close, callback, or detach failures reject only after
timers, pending sends, and the internal event claim are cleaned up. The first
terminal outcome wins.

## Bounds and ownership

Public validation enforces:

- hops from 1 through 255, with the maximum not below the first hop;
- 1 through 10 probes per hop and at most that many active probes;
- a 1 through 60,000 millisecond probe timeout and a 1 through 3,600,000
  millisecond overall timeout;
- 1 through 64 token bytes and at most 4,096 caller payload bytes; and
- at most 2,550 retained compact probe results.

Defaults are hop 1 through 30, three probes per hop, one active probe, a
3-second probe timeout, a 5-minute overall timeout, stop on unreachable, a
random 16-byte token, and random 16-bit identifier/initial sequence values.
Explicit values make probe generation and tests deterministic. One hop is active
at a time, and every timer is rechecked against the monotonic deadline when it
fires.

## Tests and verification

Deterministic fake-clock and fake-driver tests cover owned construction, runtime
bounds, direct and quoted matching, strong and weak evidence, invalid checksums,
incomplete and unrelated input, loss, reordering, duplicates, late replies,
exact deadline boundaries, overall timeout precedence, destination and
unreachable policies, callback/send/source/detach failures, cancellation,
synchronous terminal detach, first-terminal-wins behavior, result ordering, and
the exact 2,550-result bound. Declaration fixtures exercise all new public types
and discriminated result variants.

The following gates passed on x86-64 Linux:

- `npm run ci`: Prettier, ESLint, strict TypeScript, Rust formatting, Clippy, 38
  Rust tests, 88 ordinary Node tests (73 passed and 15 privileged tests skipped
  by design), dependency audit, and release-policy verification;
- isolated privileged Docker namespaces: all 15 tests passed, including a
  source/router/destination route that proves TTL 1 intermediate discovery, TTL
  2 destination detection, unreachable and silent targets, lane conflict,
  cleanup, and caller-socket reuse;
- Phase 9 packet-ring stress: 256 iterations, stable descriptor count 21, and
  1,376,256 bytes of RSS growth;
- Phase 11 event stress: 256 iterations with four lifecycle cycles each, stable
  descriptor count 21, and 6,651,904 bytes of RSS growth;
- Phase 15 cancellation stress: 256 repeated trace cancellations and lane-reuse
  checks, stable descriptor count 21, and 5,332,992 bytes of RSS growth;
- `npm run release:consumer-test`: optimized x86-64 artifact, scoped
  target-package selection, clean ESM import, CommonJS `require()`, all three
  traceroute exports, and private-subpath rejection passed;
- `npm run release:verify-artifact`: x86-64 ELF architecture and the declared
  glibc 2.28 ceiling passed, with the highest required version at 2.16; and
- `npm run release:reproducibility`: two clean optimized builds produced the
  identical SHA-256
  `d016f2ae122e012f6f949a4ba3da33fb26cecf283d061567557b5565f3d24d67`.

The candidate version and target package metadata are aligned at `0.1.0-rc.6`.
Nothing was published.

## Remaining work

The accepted Phase 12–15 ICMPv4/traceroute sequence is complete. No subsequent
implementation phase is currently accepted. Streams, async iteration, batch
events, packet-ring events, `ref()`/`unref()`, and ICMPv6 protocol codecs remain
separate design decisions rather than implied follow-on work.

AArch64/ARM64 remains an intended but untested target. No native AArch64
execution claim is made by this phase.
