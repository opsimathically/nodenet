# Delivery roadmap

Each phase ends with a reviewable artifact and explicit verification. Later
phases may be refined, but their safety gates should not be removed silently.

## Phase 0 — Requirements and planning

Status: complete enough to proceed

Deliverables:

- project scope and non-goals;
- architectural ownership boundaries;
- initial safety threat model and invariants;
- tooling/test strategy;
- decision log and durable agent context.

Exit gate: documentation distinguishes confirmed requirements from pending
technical choices and identifies a bootstrap sequence.

## Phase 1 — Minimal environment bootstrap

Status: complete (2026-07-12)

Deliverables:

- encode the accepted Node.js 26+ and Rust 1.97.0 toolchain policy;
- configure npm, ESM output, and napi-rs v3 with Node-API 10;
- create minimal package, TypeScript, ESLint, and Prettier configuration;
- create the Rust native crate and reproducible development build path;
- add ignore/editor defaults and initial CI quality gates;
- expose one harmless native smoke-test operation to prove the toolchain only;
- document exact install, build, lint, format, typecheck, and test commands.

Exit gate: a clean checkout can install deterministically, compile the native
module, call the smoke-test export from Node, and pass all non-network quality
checks. No raw socket behavior is required.

Completion evidence: `npm run ci` passes formatting, linting, strict type
checking, Rust formatting, Clippy, Rust unit tests, native/TypeScript builds,
and ESM plus `require()` smoke tests. `npm run build:native:release` and
`npm pack --dry-run` also pass. See the [Phase 1 report](07-phase-1-report.md).

## Phase 2 — Socket core and lifecycle model

Status: complete (2026-07-12)

Deliverables:

- implement a Node-independent Rust descriptor/lifecycle core;
- define open/closing/closed behavior and operation leases;
- implement checked conversions and structured errors;
- isolate the first Linux syscall adapter;
- test creation failures, ownership, explicit/repeated close, and cleanup.

Exit gate: no successful privileged socket traffic is required, but all
lifecycle and failure behavior is testable and reviewed, including required
`unsafe` invariants.

Completion evidence: 17 Rust tests cover state, ownership, multiple leases,
idempotent close, drop cleanup, a 256-iteration acquire/close race, conversion
boundaries, error fields, atomic descriptor flags, deterministic syscall
failure, and capability-dependent raw creation. No project-owned `unsafe` was
required; the syscall adapter uses safe rustix APIs. See the
[Phase 2 report](08-phase-2-report.md).

## Phase 3 — First raw-socket API slice

Status: complete (2026-07-12)

Deliverables:

- select and document the initial address family and protocol scope;
- create raw sockets with atomic close-on-exec and appropriate nonblocking mode;
- expose asynchronous send and receive of byte buffers;
- implement stable Linux error mapping;
- add TypeScript types and public API documentation;
- add unprivileged negative tests and opt-in capability-gated integration tests.

Exit gate: the initial API works end-to-end on the supported Linux test matrix,
does not block the event loop, and passes lifecycle/race tests.

Completion evidence: `RawSocket` works end-to-end for ICMP loopback traffic in
an isolated user/network namespace. One bounded reactor per Node environment
handles nonblocking readiness, close cancellation, and Worker teardown. The
standard CI gate passes 21 Rust tests and 5 unprivileged Node tests; 2 opt-in
privileged tests cover successful traffic and queue backpressure/cancellation.
See the [Phase 3 report](09-phase-3-report.md).

## Phase 4 — Binding, metadata, and socket options

Status: complete (2026-07-12)

Delivered scope:

- bind/address support for the initial families;
- interface selection;
- typed common socket options;
- packet metadata and ancillary-data primitives;
- explicit truncation and partial-I/O semantics.

Exit gate: every added option has input validation, kernel-version behavior,
error mapping, and tests. Generic raw option escape hatches require a separate
safety/API review.

Completion evidence: bind and local-address queries, five typed socket options,
original packet length, explicit truncation, and safely parsed IPv4 header
metadata are serialized through the bounded reactor. Twenty-four Rust tests,
five ordinary Node tests, and three isolated capability-gated packet tests pass.
See the [Phase 4 report](10-phase-4-report.md).

## Phase 5 — Message I/O, ancillary data, cancellation, and fairness

Status: complete (2026-07-12)

Purpose: establish the family-neutral message substrate required by IPv6,
`AF_PACKET`, error queues, timestamps, and later batching. The exact contract is
frozen in [the full-capability plan](11-full-capability-plan.md).

Deliverables:

- add exact-pinned nix with only `socket`, `uio`, and `net` features for safe
  typed `sendmsg`/`recvmsg`, control-message, missing sockopt, and address
  support; retain rustix for owned fds, epoll, eventfd, and existing safe calls;
- introduce checked native message, address, flag, and control-message types;
- implement `sendMessage()` and `receiveMessage()` for IPv4 while retaining
  `send()` and `receive()` as compatibility conveniences;
- return original data length, data/control truncation, source address, message
  flags, typed known control messages, and bounded owned unknown receive control
  messages;
- support IPv4 packet info, received TTL/TOS, nanosecond software timestamps,
  receive-queue overflow counters, and IPv4 extended error-queue messages;
- add typed receive-metadata enablement, receive-errors, timestamp,
  queue-overflow, and `SO_BINDTODEVICE` configuration;
- add `AbortSignal` cancellation with exactly-once settlement and a native
  cancellation token/wakeup path that cannot be rejected by a full command queue
  and does not close the socket;
- impose a 32-operation total per-socket limit, readiness work/byte budgets, and
  a proven nonblocking completion-delivery bound so one busy socket or stalled
  JavaScript callback cannot block the environment reactor;
- add focused parser/serializer, cancellation-race, fairness, error-queue,
  truncation, Worker teardown, and isolated namespace tests.

Exit gate:

- all public inputs have JavaScript and Rust validation;
- every control/data allocation and queue has a documented maximum;
- close/cancel/readiness races settle each operation once;
- two continuously readable sockets both make bounded progress;
- no reactor thread blocks on Node completion delivery;
- legacy Phase 4 behavior remains covered;
- IPv4 packet-info, timestamp, error-queue, device-binding, and cancellation
  paths pass in isolated user/network namespaces.

Completion evidence: exact-pinned safe message adapters, typed message/control
APIs and options, native cancellation, byte/operation admission bounds, fair
reactor turns, separate error queues, and nonblocking completion delivery are
implemented. Twenty-nine Rust tests, five ordinary Node tests, and four isolated
namespace tests pass. See the [Phase 5 report](12-phase-5-report.md).

Post-Phase-10 audit note: D-026 supersedes the nonblocking callback mechanism.
The original 32-operation proof did not bound completions already queued for
JavaScript, so callback saturation could discard settlements. Delivery now uses
bounded lossless backpressure; active-loop fairness remains measured, while a
stalled JavaScript environment intentionally backpressures its reactor.

## Phase 6 — IPv6 raw sockets

Status: complete (2026-07-12)

Deliverables:

- add `AF_INET6`/`SOCK_RAW` creation with explicit protocol and discriminated
  family/address types, including scope id and flow info where Linux uses them;
- support IPv6 bind, optional connect/disconnect, send/receive messages, and
  source/local address queries without pretending IPv6 raw payload/header
  semantics match IPv4;
- add typed unicast hops, traffic class, packet info, hop limit, receive errors,
  path-MTU discovery, and applicable multicast options available through the
  accepted safe syscall dependencies;
- expose IPv6 packet-info, hop-limit, traffic-class, timestamp, and extended
  error control messages through the Phase 5 message model;
- test ICMPv6 loopback, link-local scope validation, truncation, cancellation,
  close races, and unsupported option/family combinations.

Exit gate: IPv4 and IPv6 share lifecycle/message infrastructure but retain
documented family-specific semantics; ICMPv6 succeeds in an isolated namespace;
no API fabricates an unavailable IPv6 header.

Completion evidence: IPv6 creation, scoped addresses, bind/local/connect,
message/control parity, safe typed options, cancellation, truncation, and ICMPv6
loopback are implemented. Thirty-one Rust tests, ordinary Node tests, and five
isolated namespace tests pass. See the [Phase 6 report](13-phase-6-report.md).

## Phase 7 — Linux packet sockets

Status: complete (2026-07-12)

Deliverables:

- add `AF_PACKET` `SOCK_RAW` and `SOCK_DGRAM` with checked EtherType and
  `sockaddr_ll` representations;
- support interface name/index lookup, bind, send/receive addresses, packet
  direction/type, hardware type/address, and link-layer protocol metadata;
- test on an isolated veth pair for Ethernet injection/capture, interface
  isolation, raw/cooked header semantics, truncation, and close/cancel races.

Exit gate: both packet socket modes operate end-to-end on a veth test topology;
link-layer addresses and metadata are never confused with IP addresses; no
packet-specific sockopt is emulated before the reviewed Phase 8 adapter exists.

Completion evidence: checked raw/cooked creation, `sockaddr_ll` bind/send,
interface lookup, link metadata, veth isolation, header semantics, truncation,
cancellation, and close are implemented. Thirty-three Rust tests, seven ordinary
Node tests, and six isolated namespace tests pass. See the
[Phase 7 report](14-phase-7-report.md).

## Phase 8 — Advanced configuration, errors, and filtering

Status: complete (2026-07-12)

Deliverables:

- expand typed IPv4/IPv6/common options for routing, PMTU, multicast,
  `IP_HDRINCL`, `IPV6_CHECKSUM`, freebind/transparent behavior, priority/mark,
  busy polling, device binding, error queues, and timestamping where applicable;
- add connected raw-socket operation and explicit disconnect semantics;
- add packet promiscuous/multicast/all-multicast membership with deterministic
  removal, `PACKET_AUXDATA`, statistics/loss/VLAN metadata, and bounded
  `PACKET_FANOUT` with explicit group ownership;
- provide classic BPF validation/attachment/detachment/locking and safe
  attachment of a duplicated compatible eBPF program fd; do not load programs;
- add a bounded low-level `getSocketOption`/`setSocketOption` byte interface for
  Linux options not yet modeled, with reserved dangerous cases rejected and all
  unsafe code isolated behind one reviewed adapter if safe crates are
  insufficient;
- provide an explicit close-on-exec duplicated-fd interoperability API only if
  ownership and caller-close responsibilities can be made unambiguous;
- build a kernel-version/capability/driver behavior matrix and test predictable
  `ENOPROTOOPT`, `EINVAL`, `EPERM`, and unsupported-library failures.

Exit gate: typed paths remain preferred, the low-level escape hatch is bounded
and cannot violate memory/fd ownership, filters have deterministic replacement
and cleanup, and unsupported features fail without corrupting socket state.

Completion evidence: advanced typed IPv4/IPv6/common options, IPv4 connected
operation, packet membership/auxdata/statistics/fanout, classic/eBPF attachment,
and a 4096-byte reserved-tuple-aware raw option adapter are implemented. Filter
replacement, lock behavior, caller-fd retention, VLAN auxdata, and namespace
traffic pass. Thirty-five Rust tests, seven ordinary Node tests, and six
isolated namespace tests pass. A general descriptor export was deliberately not
added. See the [Phase 8 report](15-phase-8-report.md).

## Phase 9 — Batching and high-throughput packet paths

Status: complete (2026-07-12)

Deliverables:

- add bounded `sendmmsg`/`recvmmsg` APIs with partial-success accounting and no
  dependence on the defective blocking `recvmmsg` timeout behavior;
- add per-environment performance and fairness benchmarks for copies,
  completions, batching, control parsing, and multiple hot sockets;
- implement `PACKET_MMAP` TPACKET_V3 receive rings with explicit copied frame
  leases, alignment validation, status transitions, bounded mapped memory, and
  close behavior; add transmit rings only if they outperform the safer measured
  `sendmmsg` path under a separately reviewed writable-frame contract;
- add packet fanout/ring stress tests and document driver/kernel limitations;
- evaluate AF_XDP only after packet rings, ownership, and benchmark goals are
  stable; it is not part of the initial release baseline.

Exit gate: batch and ring APIs demonstrate a measured benefit, cannot expose a
frame after lease release, remain fair under load, and pass long-running leak
and teardown stress tests.

Completion evidence: bounded `sendmmsg`/`recvmmsg` APIs and a receive-only
TPACKET_V3 ring are implemented through the fair reactor. Frame bytes never
alias mutable mmap storage and become inaccessible after lease release. A
release namespace benchmark measured a 2.81× batch-send speedup and 0.01 ms
two-hot-socket completion skew. Thirty-seven Rust tests, seven ordinary Node
tests, and six isolated namespace tests pass, including 16-frame ring stress,
cancellation, release invalidation, and close cleanup. A separate 256-cycle ring
teardown run retained the exact descriptor baseline with a 745,472-byte RSS
delta. TX mmap was evaluated and deferred because it needs a separate
writable-frame publication contract and has not demonstrated benefit over the
measured safe batch path. See the [Phase 9 report](16-phase-9-report.md).

## Phase 10 — Hardening, compatibility, and distribution

Status: implementation complete; AArch64 publication gate pending (2026-07-12)

Deliverables:

- fuzz every address, header, option, cmsg, batch, and ring parser/serializer;
- run native sanitizers, fd/memory leak tests, cancellation/close stress,
  syscall fault injection, and concurrency model tests where tools apply;
- test minimum/current supported Node releases and both x86-64/AArch64 glibc
  targets; document kernel- and hardware-dependent skips;
- complete dependency, license, advisory, and generated-artifact provenance
  review;
- benchmark release builds and freeze documented queue/allocation defaults;
- build reproducible npm-hosted prebuilt target packages without
  installation-time downloads, while retaining a documented source build;
- remove `private`, select the first semver version, publish a changelog and
  supported-feature table, and verify install/failure/capability guidance from a
  clean consumer project.

Exit gate: release artifacts are reproducible for the declared matrix, package
contents are intentional, all release-blocking safety gates pass, and the
published capability table distinguishes implemented, unsupported, privileged,
kernel-dependent, and hardware-dependent behavior.

Implementation evidence: hardening/release workflows, an independently locked
syscall-free fuzz target, ASan/TSan runs, advisory/license policy, frozen
limits, split target packages, provenance, clean-consumer testing, and
clean-build reproducibility are implemented. All local x86-64 gates pass. Native
AArch64 is a blocking CI/publication gate and has not been represented as
locally tested. See the [Phase 10 report](17-phase-10-report.md).

## Phase 11 — Event-driven receive adapter

Status: implementation complete (2026-07-13)

Purpose: add a familiar Node `EventEmitter` receive style as an optional,
zero-dependency TypeScript layer over the complete promise-oriented `RawSocket`
API. The exact contract is frozen in the
[Phase 11 plan](19-phase-11-event-api-plan.md).

Deliverables:

- export a typed `RawSocketEventEmitter` that wraps an open `RawSocket` and uses
  Node's built-in `node:events`;
- preserve every existing low-level method and avoid new Rust/N-API work unless
  a newly documented native requirement is proven;
- emit `message`, `error`, and exactly-once `close` events with explicit start,
  awaitable pause, resume, detach, and close lifecycle operations;
- keep one bounded `receiveMessage()` in flight per normal or error-queue event
  source, retain a fulfilled-but-undispatched result through lifecycle
  boundaries, and prohibit `peek` in an automatically rearmed loop;
- arbitrate normal/error receive lanes so direct, batch, ring, and event
  consumers cannot silently split the same traffic;
- make pending-operation finalizers composable before adding claims, and treat
  each packet-ring attempt/ring-frame receive as socket-wide relative to both
  event lanes;
- use transactional runtime-authenticated claims/observers, explicit
  detach/close lifetime rather than GC release, and terminalize the wrapped
  socket on reactor loss;
- document synchronous EventEmitter delivery, async-listener limitations, kernel
  buffering/drop behavior, and safe retained message ownership;
- add deterministic controller tests, unprivileged boundary/race tests, isolated
  multi-message family tests, Worker teardown, and long-running state stress;
- refresh the release candidate and provenance after the public API changes.

Exit gate: the promise API remains compatible; the event adapter has no
unbounded queue or runtime dependency; pause/detach/close have proven race
boundaries; conflicting receivers fail deterministically; repeated IPv4, IPv6,
packet, and error-queue events pass; and all ordinary, privileged, stress,
consumer, and release gates are recorded.

Implementation evidence: the native-free controller, composable pending
finalizers, runtime-authenticated lane claims, close observers, public typed
EventEmitter, declaration fixture, listener subprocess probes, genuine
multi-message namespace coverage, Worker teardown, and repeat-cycle fd/RSS
stress are implemented. No Rust, syscall, N-API, unsafe-code, or production
dependency change was required. See the [Phase 11 report](21-phase-11-report.md)
and the corrective [implementation audit](22-phase-11-implementation-audit.md).

## Phase 12 — ICMPv4 foundation and Echo utilities

Status: complete (2026-07-13)

Purpose: establish the pure, bounded protocol-codec layer and the first useful
ICMPv4 request/reply workflow without changing native socket ownership. The
complete contract is in the
[ICMP and traceroute plan](23-icmp-and-traceroute-plan.md).

Deliverables:

- add named ICMP type/code constants and discriminated construction/parse types;
- implement non-mutating Internet checksum calculation and validation;
- implement bounded `encodeIcmpMessage()`, structured `parseIcmpMessage()`, and
  shared `validateIcmpMessage()` results with owned output, unknown-message/
  code retention, and compatible-versus-canonical validation;
- expose the checked protocol captured when `RawSocket` opens so helpers can
  reject a non-ICMP socket without a native query;
- explicitly adapt IPv4 raw `ReceivedMessage` data, including its IPv4 header,
  into an ICMP packet without confusing send and receive layouts;
- implement Echo Request/Reply construction, parsing, validation, matching,
  one-operation send, and one-operation receive;
- document promise and existing event-adapter usage and add ordinary,
  declaration, malformed-input, and privileged loopback tests.

Exit gate: codecs cannot read outside input or allocate beyond the 65,515-byte
ICMPv4 bound; checksums and Echo messages pass independent vectors and loopback;
all short/malformed inputs return structured failures; canonical violations are
reported without confusing them with unsafe structure; inputs/results do not
alias and checksum/parse passes share one bounded input snapshot; the root
facade preserves existing argument errors without an ESM import cycle; and the
phase adds no runtime dependency, Rust code, native receive engine, or hidden
socket ownership.

Implementation evidence: root-exported constants/types and strict TypeScript
codecs implement RFC 1071 checksums, owned Echo encode/parse/validation,
compatible/canonical issues, unknown preservation, checked IPv4 raw-receive
extraction, authenticated socket helpers, per-message TTL, and correlation. The
ordinary test, declaration, lint, type, privileged loopback, stress, consumer,
artifact, and reproducibility gates pass with no Rust/native/runtime dependency
change. See the [Phase 12 report](25-phase-12-report.md).

## Phase 13 — ICMPv4 errors and quoted datagrams

Status: complete (2026-07-13); depends on Phase 12

Deliverables:

- add a checked IPv4 quote parser with enough Echo correlation metadata for
  diagnostic responses and traceroute;
- implement Destination Unreachable, RFC 1191 Fragmentation Needed, Time
  Exceeded, Parameter Problem, and Redirect codecs and code constants;
- support historical and longer quotes, explicit truncation, and RFC 4884
  extension envelopes while preserving unknown extension objects, using
  length-based compliant parsing by default and an explicit non-default legacy
  128-byte mode;
- keep construction explicit and Redirect informational, with no automatic error
  responses or route mutation;
- add golden, generated malformed, quote/extension boundary, and disposable
  namespace tests.

Exit gate: every quote, IHL, total length, extension boundary, MTU, pointer,
reserved field, and code has deterministic checked behavior; the RFC 4884 length
octet coexists correctly with RFC 1191 MTU and the 576-byte ceiling; zero-length
and legacy extension framing are unambiguous; all requested error messages
round-trip; malformed packets cannot cause unexpected exceptions; and no utility
treats unauthenticated diagnostic data as host policy.

Implementation evidence: strict TypeScript codecs cover every registered code in
the accepted error families, independently checked golden layouts, bounded owned
quotes, IPv4 options/fragments/truncation/checksums, MTU and pointer semantics,
weak/strong Echo correlation, compliant and explicit legacy RFC 4884 framing,
the exact 576-byte ceiling, and preserved unknown objects. Ordinary,
declaration, privileged crafted-packet, stress, clean-consumer, artifact, and
reproducibility gates pass without a native or runtime dependency change. See
the [Phase 13 report](26-phase-13-report.md).

## Phase 14 — Router discovery and legacy ICMPv4 messages

Status: complete (2026-07-13)

Deliverables:

- implement Router Solicitation and variable Router Advertisement codecs with
  bounded entries, signed preferences, lifetimes, and extension-word retention;
- implement Timestamp Request/Reply and preserve standard, high-bit
  non-standard, and invalid-standard-range timestamp semantics, with
  request-only fields canonically zeroed;
- implement deprecated Address Mask Request/Reply formats and contiguous-mask
  inspection without applying interface configuration, with canonical requests
  carrying a zero mask;
- expose the same explicit one-operation socket composition, enforce Router
  Discovery multicast destination/TTL rules, retain explicit broadcast
  permission, and add boundary, wire-vector, declaration, and isolated tests;
- clearly distinguish supported legacy parsing/construction from recommended
  modern host configuration.

Exit gate: count/entry-size arithmetic is overflow-safe; every wire field
extreme parses and is preserved, while canonical construction fields round-trip;
unknown extension words remain bounded; legacy messages never change clocks,
routes, routers, or interface masks; and documentation states their registry
status and trust limitations.

Implementation evidence: bounded owned codecs cover Router Solicitation and
Advertisement, all timestamp semantic ranges, and deprecated Address Mask
messages; captured multicast packets prove the correct destinations and
per-message TTL 1; wrong groups/conflicting TTLs and implicit broadcast are
rejected; declaration, malformed-input, ordinary, privileged, stress, consumer,
artifact, and reproducibility gates pass. See the
[Phase 14 report](27-phase-14-report.md).

## Phase 15 — ICMP traceroute utilities

Status: complete (2026-07-13); depends on Phases 12 through 14

Deliverables:

- construct and send per-message-TTL Echo probes without racing a socket-wide
  TTL option;
- strongly correlate direct Echo Replies and quoted Time Exceeded or Destination
  Unreachable responses using destination, protocol, identifier, sequence, and
  bounded token evidence;
- classify hop, destination, unreachable, and diagnostic responses; generate
  compact timeout results locally; reject cancellation after complete cleanup;
- add a bounded cancellable convenience traceroute over a dedicated existing
  ICMP socket, using an internally attached/detached event source for a
  lifetime-long lane claim, plus public builders/classifiers for callers that
  already own an event source;
- impose explicit hop/probe/payload/token/in-flight/per-probe/overall-time and
  compact-result-retention bounds;
- test fake-clock loss/reordering/late/duplicate races, callback failures, and
  an isolated multi-router topology with intermediate hops and destination
  detection;
- document ICMP filtering/rate limits, asymmetric/load-balanced paths,
  privileges, silent hops, and unauthenticated responses.

Exit gate: unrelated packets cannot complete probes; every send/receive/timer/
cancellation race settles once; configured bounds cap retained and in-flight
work; receive conflicts remain deterministic; every terminal path releases the
internal event claim without closing the caller-owned socket; an isolated route
demonstrates TTL-limited hops and destination completion; and all previous
release and stress gates remain green.

Implementation evidence: owned probe construction, pure strong/weak response
classification, monotonic RTTs, compact ordered results, exact deadline rules,
bounded one-hop scheduling, cancellation, and cleanup-ordered failure are
implemented in strict TypeScript. Fake-clock tests cover race boundaries; an
isolated source/router/destination topology proves intermediate and destination
hops, unreachable and silent targets, lane conflicts, cleanup, and socket reuse;
ordinary, declaration, privileged, repeated-cancellation stress, consumer,
artifact, and reproducibility gates pass. See the
[Phase 15 report](28-phase-15-report.md).

## Phase 16 — Protocol crate foundation

Status: complete on 2026-07-13

Create the syscall-free, non-published `nodenet-protocols` Rust crate.
Revalidate and exact-pin the narrowly featured codec dependency, establish
project-owned checked types and strict/compatible parse modes, build only into
bounded caller storage or owned buffers, and add independent golden vectors,
fuzz targets, and allocation baselines. The crate has no N-API or unsafe code.

Exit gate: hostile bytes cannot panic or allocate beyond declared packet/header
bounds; round-trip, golden, fuzz-smoke, dependency/license, x86-64, and AArch64
target-build gates pass.

Implementation evidence: the non-published `nodenet-protocols` crate owns
checked wire types, stable structured errors, explicit strict/ICMP-quote parse
modes, bounded owned copies, and transactional caller-owned packet output.
Exact-pinned, feature-minimal `etherparse` remains private. Independent golden
bytes, deterministic hostile/mutation tests, separate parser/serializer fuzz
targets, allocation assertions, and a microbenchmark baseline are in place. See
the [Phase 16 report](33-phase-16-report.md).

## Phase 17 — Link and internet protocols

Status: complete (2026-07-13)

Implement bounded Ethernet II, VLAN, ARP, IPv4, IPv6, fragment, extension-
header, and reusable frame-template support. Keep fragment state explicit and
attempt transport parsing only when its bytes are semantically present.

Exit gate: canonical L2/L3 construction and parsing pass independent capture
vectors; malformed lengths/nesting/fragments fail without ambiguity; and every
checked template patch is byte-identical to a full rebuild.

## Phase 18 — Transport, control, and correlation protocols

Status: complete (2026-07-13)

Add scanner-relevant TCP, UDP, ICMPv4, ICMPv6, and IPv6 Neighbor Discovery
codecs plus session-keyed TCP/ICMP/UDP correlation evidence. Preserve unknown
bounded options, distinguish checksum rules accurately, and reuse existing
TypeScript ICMP fixtures as an independent oracle.

Exit gate: ARP, NDP Neighbor Solicitation, ICMPv4/v6 Echo, TCP SYN, and UDP
probes can be built and correlated at their documented protocol-specific
evidence strength without scheduler- or N-API-owned byte parsing; forged,
fragmented, quoted, late, and malformed traffic matrices pass.

## Phase 19 — Bounded read-only Linux network snapshot

Status: complete (2026-07-14)

Create the non-published `nodenet-linux-context` crate. Use narrowly reviewed
netlink packet/syscall crates to perform bounded `NETLINK_ROUTE` GET dumps for
links, addresses, routes, necessary rules, and neighbors. Validate sender,
sequence, multipart completion, nested attributes, overruns, interruption, and
churn; bind to the descriptor's current network namespace without `setns()` and
publish no partial snapshot as complete.

Exit gate: namespace snapshots are deterministic, generation-ready, bounded, and
comparable to `ip -j` test oracles, while syscall tracing proves the library
issues no netlink create, set, delete, or replace operation.

The non-published context crate owns one namespace-anchored route-netlink
descriptor and publishes sorted immutable snapshots only after all bounded GET
dumps and interface-reference checks pass. Synthetic hostile streams,
unprivileged live snapshots, disposable dual-stack/veth/VLAN namespaces, `ip -j`
parity, repeated fd/RSS checks, and syscall tracing pass. See the
[Phase 19 report](36-phase-19-report.md).

## Phase 20 — Kernel route resolution and coherent refresh

Status: completed on 2026-07-14

Use targeted `RTM_GETROUTE` requests so Linux policy chooses source, interface,
gateway, table, MTU, and ECMP. Join resolution to one immutable generation,
model neighbor states without mutation, subscribe before initial dump, buffer
changes within a fixed limit, retry a route query whose generation changes, and
invalidate/resync on overflow or ambiguity. Freeze initial support to
Ethernet/VLAN and loopback; reject other links/encapsulation explicitly.

Exit gate: policy route, gateway/on-link, ECMP, unreachable, link-change,
neighbor-missing, notification-race, and resync scenarios pass; every result
identifies its complete context generation.

Completion evidence: [Phase 20 report](37-phase-20-report.md).

## Phase 21 — Syscall-free deterministic scan scheduler

Status: complete on 2026-07-14

Create `nodenetscanner-engine` with injected clock, transport, context, entropy,
and result sink. Normalize compact target ranges/exclusions, permute logical
probe indices reproducibly, and schedule explicit ARP/NDP link-neighbor, ICMP
Echo, TCP SYN, and UDP work with checked counts, adaptive timing, token-bucket
rate control, fairness, retry limits, late-response grace, evidence-based
classification, and bounded result backpressure. Every emitted setup, probe,
retry, and cleanup frame consumes the configured rate budget.

Exit gate: millions of virtual-clock transitions and property tests prove exact
deadlines, at-most-once tuples per attempt, exclusions, fairness, deterministic
replay, lifecycle races, and memory proportional to active state rather than
total targets.

Completion evidence: [Phase 21 report](38-phase-21-report.md).

## Phase 22 — Portable live scanner and initial Node API

Status: complete

Activate the private scanner package and add `nodenetscanner-native`. Its Rust
addon owns ordinary nonblocking raw/packet sockets, context, scheduling, packet
I/O, secrets, and bounded result storage. Expose scanner/session lifecycle,
explicit scan plans, context inspection, summaries, and a bounded `nextBatch()`
pull API from the first preview. Do not depend on the `nodenetraw` JavaScript
package or expose descriptors. Use one bounded runtime per Node environment;
keep N-API completion backpressure off its scheduler/I/O worker, ignore
`PACKET_OUTGOING`, interpret VLAN auxdata, and use raw IP rather than invented
Ethernet headers on loopback/local routes.

Exit gate: isolated dual-stack topologies accurately exercise live ARP/NDP,
ICMPv4/v6 Echo, TCP SYN, and UDP scanning; capture proves bytes, rate, retries,
exclusions, source/route selection, and no host-policy mutation; slow JavaScript
consumers cannot cause unbounded memory.

Completion evidence: [Phase 22 report](39-phase-22-report.md). The ordinary
native/Node gates and isolated live dual-stack namespace/VLAN matrix pass
locally. Native AArch64 cross-compilation passes; native AArch64 execution
remains a publication gate.

## Phase 23 — Scanner-oriented batching and backpressure

Status: complete

Freeze a versioned compact columnar result schema with explicit families and
byte order, sealed Node-owned storage, lazy TypeScript row access, bounded
dynamic command batches, lossless high/low-water result backpressure, coalesced
progress counters, one pending pull, AbortSignal handling, and an optional
batch-event adapter. No per-result event mode or native mapping crosses N-API.

Exit gate: N-API calls scale with batches rather than probes; saturation pauses
new transmission without result loss or deadlock; retained, mutated,
transferred, cancelled, and teardown batch cases remain safe.

Completion evidence: [Phase 23 report](40-phase-23-report.md). Schema version 1,
lazy TypeScript rows, Node-owned transferable storage, worker-ordered abortable
pulls, progress snapshots, high/low-water result hysteresis, bounded controls,
and the optional batch-event adapter are implemented. Ordinary and live
namespace gates pass locally; AArch64 native execution remains a publication
gate.

## Phase 24 — Portable scanner hardening and release candidate

Status: implementation complete on 2026-07-14; AArch64 publication gate remains

Stabilize API/errors/lifecycle/schema/probe support; complete documentation,
fuzzing, hostile-value tests, sanitizers, fault injection, Worker and memory/fd
stress, benchmarks, independent target-package assembly, consumer tests,
reproducibility, provenance, ABI, and native architecture gates. Only this phase
advances the scanner from private `0.0.0` to unpublished `0.1.0-rc.1`.

Exit gate: the portable scanner is independently accurate, bounded, documented,
reproducible, and publishable on its declared matrix. This is a complete useful
outcome even if no extreme backend follows.

Completion evidence: [Phase 24 report](41-phase-24-report.md). The package is an
unpublished `0.1.0-rc.1` candidate with frozen declarations, hostile-input and
resource stress, engine fuzzing, sanitizer/fault workflows, a metadata-recording
benchmark harness, and independently staged x64/AArch64 glibc packages. Local
x86-64 ordinary, cross-compile, ABI, clean-consumer, and reproducibility gates
pass. The sudo-only Phase 24 namespace/fault matrix and metadata-recording
benchmark also pass locally. Native AArch64 execution remains mandatory before
publication.

## Phase 25 — Extreme-backend evidence gate

Status: complete (`no-go`); Phase 26 is closed

Profile and prototype portable mmsg, `PACKET_MMAP` TX/RX, and AF_XDP paths on
fully recorded hardware. Select exactly one next backend only if at least ten
same-hardware repetitions and a bootstrap 95% confidence interval deliver at
least 1.5x sustained matched-result throughput at no greater CPU budget or 30%
lower CPU at equal throughput and accuracy/loss, without weakening ownership or
cleanup. Otherwise record a `no-go` and stop.

Exit gate: a decision record selects `no-go`, `PACKET_MMAP`, or experimental
AF_XDP with explicit kernel/driver/ownership requirements. The portable package
baseline remains unchanged.

Completion evidence: [Phase 25 report](42-phase-25-report.md). The portable rate
sweep, ordinary mmsg and TPACKET controls, writable TX-ring lab, and AF_XDP
capability/ownership review found no qualified end-to-end candidate. D-039
records `no-go`; no extreme backend was selected.

## Phase 26 — Conditional extreme backend and parity

Status: closed; Phase 25 recorded `no-go`

Implement the one selected backend behind the same engine/result contract. Keep
every writable ring and UMEM frame native-owned with checked geometry and
single-producer/single-consumer ownership; provide explicit engine selection,
creation-time-only fallback, portable-result parity, and complete partial-init,
interface-removal, cancellation, teardown, and state-restoration tests.

Exit gate: the final backend repeats the Phase 25 improvement threshold, matches
portable classifications, and passes sanitizer/stress/fault cleanup. Otherwise
it remains experimental and portable remains default.

The exact Phase 16–26 deliverables, bounds, APIs, dependency gates, test
topologies, research basis, and stop conditions are authoritative in the
[network and scanner evolution plan](31-network-and-scanner-evolution-plan.md).

## Phase 27 — UDP probe foundation and provenance contract

Status: complete; implemented 2026-07-14

Define the independently authored UDP catalogue, stable probe IDs, profiles,
risk/provenance fields, profile-independent risk consent, exact and dynamically
patched request plans, explicit custom exact versus legacy prefix-token
behavior, catalogue generator/checker, fallback/strategy rules, and the exact
schema-2 decoder/layout. Remove the native one-payload-per-family limitation
without adding protocol breadth or any Nmap build/runtime dependency.

Exit gate: exact custom bytes capture unchanged, catalogue/provenance validation
is deterministic and bounded, independent per-probe programmes survive native
admission, and the API/resource/license contract is frozen.

## Phase 28 — Multi-probe UDP scheduling and aggregation

Status: complete; implemented 2026-07-14

Represent one logical target/port as a bounded lazy sequence of physical UDP
subprobes. Rate-charge every variant/retry, reserve one terminal result plus
finite correlation state, preserve fairness and source-port/grace isolation, and
aggregate direct/ICMP/silence evidence through an arrival-order-independent
lattice. Physical work owns `maxOutstanding`; row and metadata-byte reservation
occur before transmission.

Exit gate: virtual and live matrices settle every logical endpoint exactly once
under multiple variants, loss, retries, contradictions, deferral, backpressure,
cancellation, and four-session concurrency with memory proportional to active
work.

## Phase 29 — Safe standards-based UDP probe pack

Status: complete; implemented 2026-07-14

Implement a reviewable low-impact core of independently specified,
protocol-valid builders and strict parsers for unicast DNS, NTP, SNMPv3 engine
discovery, RPC portmapper NULL, STUN, CoAP ping, RMCP/IPMI, memcached version,
and low-impact PCP ANNOUNCE. Add typed bounded service evidence, begin schema-2
emission, and make protocol-aware safe mode the default for an omitted UDP
policy.

Exit gate: independent golden vectors and dual-stack responders prove every safe
request, correlation field, port state, and service-family result; exact capture
proves no private prefix corrupts protocol requests.

## Phase 30 — Extended standards pack and explicit-risk enforcement

Status: complete; implemented 2026-07-14

Add independently specified mDNS/DNS-SD, NetBIOS node status, NFS, TFTP, SIP,
SSDP, IKE/L2TP, DTLS/QUIC, OpenVPN, RADIUS, SNMPv1, memcached statistics, and
DHCP candidates only where their protocol and dependency reviews pass. Enforce
amplification, stateful, fixed-source, multicast/broadcast,
authentication-attempt, and sensitive-read consent independently from catalogue
profile breadth.

Exit gate: every accepted extended request has independent provenance, bounded
live behavior, explicit impact classification, and responder evidence; adding
broader entries does not alter or weaken safe mode.

## Phase 31 — Comprehensive and legacy UDP catalogue parity

Status: complete; implemented 2026-07-14

Expand independently authored coverage across the behavioral scope, including
multiple variants, legacy/proprietary services, reviewed source constraints, and
a finite non-backtracking response-signature DSL. The repository ledger is
primary-source-derived; any Nmap mapping remains a separate non-distributed
owner audit.

Exit gate: every project candidate is equivalent, standards-superseded,
unsafe-opt-in, or blocked with independent evidence. No parity claim is made in
this phase.

## Phase 32 — Adaptive probing and scanner schema 2

Status: complete; implemented 2026-07-14

Order likely requests first, narrow follow-ups from soft service evidence, stop
unsent variants on decisive evidence, pace conservatively under ICMP rate
limiting, and freeze public profile/risk/intensity/strategy/fallback,
catalogue-version, custom-probe, logical/physical progress, service-confidence,
and schema-2 view semantics. Preserve schema-1 decoding rather than
reinterpreting old columns.

Exit gate: preregistered independent responder measurements show adaptive mode
preserves definitive states and service-family recall while reducing physical
requests or time to evidence; otherwise exhaustive mapped mode remains default.

## Phase 33 — UDP parity audit and release candidate

Status: implementation complete 2026-07-14; publication awaits native AArch64
execution

Audit provenance, parity scope, hostile parsing, fuzz/sanitizer/fault behavior,
dual-stack namespaces, lifecycle stress, resource bounds, artifacts, consumers,
reproducibility, and operator documentation. Compare aggregate behavior with the
frozen Nmap reference only through non-distributed manual evaluation on an
owner-controlled responder matrix. Do not claim complete Nmap service/version
compatibility.

Exit gate: the project capability ledger and external comparison have no
unreported gap, all available quality and release gates pass, documentation
states network impact and confidence correctly, and the scanner advances to
unpublished `0.2.0-rc.1`. Native AArch64 execution remains the mandatory
publication gate; see the [Phase 33 report](51-phase-33-report.md).

The authoritative Phase 27–33 scope, ownership, licensing boundary, proposed
API/schema, resource ceilings, verification matrix, and stop conditions are in
the [UDP protocol-probe parity plan](43-udp-probe-parity-plan.md). Its readiness
audit is [the UDP plan review](44-udp-probe-parity-plan-review.md).

## Phases 34–44 — Advanced UDP and link discovery evolution

Status: implementation complete; Phase 44 external release gates remain

The next roadmap adds discovery protocols that cannot honestly use the current
one-result-per-`(target, UDP port)` model. D-049 accepts a separate finite
discovery session for one-query/many-responder protocols, a bounded
evidence-derived endpoint graph for services on dynamic ports, registered-only
alternate-response-port correlation, and bounded state machines for modern
secure UDP transports. Existing scan schemas and catalogue identities remain
unchanged until an explicitly versioned successor is necessary.

### Phase 34 — Discovery session and bounded fan-out foundation

Freeze and implement a separate discovery plan/session, discriminated link and
target scopes, discovery result schema 1, deterministic one-to-many engine,
terminal entity aggregation, row/metadata reservation, pull backpressure,
lifecycle, and capability reporting without transmitting a live protocol.

Exit gate: synthetic multi-responder work settles deterministically under
duplicates, partial records, saturation, pause/cancel/close, context churn, and
Worker teardown with no unbounded state or schema ambiguity.

### Phase 35 — mDNS and DNS-SD discovery

Add bounded DNS compression and PTR/SRV/TXT/A/AAAA parsing, exact IPv4/IPv6
multicast interface/hop-limit ownership, adaptive service-type/instance/host
queries, per-interface identity, finite collection windows, and explicit
multicast/sensitive-read consent.

Exit gate: independent dual-stack responders yield correctly assembled bounded
service entities without cross-interface merging, unrelated-record admission, or
permanent cache behavior.

### Phase 36 — WS-Discovery and LLMNR

Reuse the fan-out engine for WS-Discovery/DPWS/ONVIF device discovery and
bounded LLMNR name evidence. Admit a streaming XML dependency only after a
separate license/advisory/binary-size/hostile-input review; prohibit DTD,
entities, external resources, and unbounded token/text work.

Exit gate: camera/printer/Windows-style responders and link-local naming work on
IPv4/IPv6 with exact scope, strict XML/DNS parsing, finite response windows, and
honest parsed rather than authenticated evidence.

### Phase 37 — Evidence-derived endpoints and adaptive rpcbind

Add a registered bounded parent/child derivation graph, target containment,
cycle suppression, provenance, reservation, and optional additive result
columns. Use typed rpcbind `GETADDR` operations to discover and probe selected
same-target NFS/mountd RPC ports; do not silently use unrestricted enumeration.

Exit gate: a parent response can schedule finite explainable child work without
escaping the target/exclusion set, hiding transmissions, or breaking retained
schema decoding.

### Phase 38 — Alternate-port correlation and TFTP

Add an internal registered-only first-valid same-target port-pinning state
machine and prove it with a session-random sentinel TFTP RRQ that stops after
the minimum typed ERROR/DATA/OACK evidence. Never expose a general loose-port
matcher or continue a file transfer.

Exit gate: correct alternate-port responses survive retries/grace while wrong,
competing, spoofed, late, and cross-interface traffic is rejected and all state
tears down exactly once.

### Phase 39 — High-yield targeted discovery pack

Add non-mutating NAT-PMP external-address discovery, direct Microsoft SQL
Browser discovery, and only a standards-valid explicitly configured Kerberos
realm probe. Each candidate independently passes provenance, consent,
amplification, strict parsing, and responder gates or remains blocked.

Exit gate: every admitted probe yields useful typed evidence without creating a
mapping, using an operator identity/credential, broadcasting implicitly, or
accepting malformed response markers.

### Phase 40 — QUIC version-negotiation discovery

Implement invariant long-header reserved-version requests, CID-correlated
Version Negotiation parsing, minimum datagram sizing, reviewed port eligibility,
and conservative unauthenticated QUIC evidence without completing TLS or
inferring HTTP/3 automatically.

Exit gate: independent QUIC v1/v2 responders are identified under strict
version/CID/size/work bounds without an unnecessary cryptographic dependency or
inflated service claim.

### Phase 41 — IKE and DTLS bounded handshakes

Implement the smallest useful specification-valid IKEv2 and DTLS exchanges only
after dependency, cryptographic, allocation, CPU, binary-size, target-impact,
and teardown review. Require stateful-handshake consent and stop before
authentication or long-lived state. A documented per-protocol no-go is valid.

Exit gate: every accepted exchange has bounded state/CPU/bytes, typed correlated
responses, exact cancellation cleanup, and discovery value exceeding its
dependency and network-impact cost.

### Phase 42 — DHCP topology discovery

Implement explicitly scoped DHCPv4 INFORM and DHCPv6 Information-request as
network-context discovery, not per-target port probes. Require interface,
fixed-source, multicast/broadcast, and sensitive-read consent; never acquire,
renew, release, or modify a lease or host configuration.

Exit gate: disposable DHCP topologies and syscall traces prove bounded option
evidence and no host-policy mutation or unsafe coexistence. Otherwise retain a
namespace-only or blocked contract.

### Phase 43 — Specialized opt-in discovery packs

Evaluate GTP Echo, MQTT-SN gateway discovery, officially documented industrial
protocols, and lower-priority game/voice discovery in that order. Every
candidate independently requires a stable primary specification, non-mutating
semantics, project-owned responder evidence, strict resource/risk bounds, and a
useful typed result. Candidate no-go decisions do not block the release.

Exit gate: every accepted candidate meets the core catalogue and discovery
quality bar; unsupported proprietary, credential-bound, malware, or
identity-bound payloads remain explicit blockers rather than approximations.

### Phase 44 — Integrated audit and release candidate

Freeze the discovery API/schema and any additive scan schema, audit all
ownership/parser/impact/dependency/provenance boundaries, complete ordinary and
privileged namespace matrices, fuzz/sanitizer/fault/resource stress, operator
documentation, native x64/AArch64 execution, artifacts, consumers, and
reproducibility, then prepare unpublished `0.3.0-rc.1`.

Exit gate: advanced discovery is bounded, correctly attributed, non-mutating,
documented, and release-rehearsed on both declared native architectures without
changing existing scan behavior or broadening the Phase 33 Nmap comparison.

The authoritative architecture, candidate dispositions, phase deliverables,
resource ceilings, verification matrix, stop conditions, and research basis are
in the
[advanced UDP discovery evolution plan](53-advanced-udp-discovery-evolution-plan.md).
The required Phase 34 questions and binding corrections are closed by the
[advanced UDP discovery plan review](54-advanced-udp-discovery-plan-review.md).

## Cross-phase rule

Do not expand breadth while a known descriptor-lifetime, buffer-lifetime,
event-loop blocking, exactly-once settlement, fairness, panic-boundary, or
teardown correctness issue remains unresolved in the preceding slice. A phase
may be split into reviewable sub-slices, but its exit gate remains blocking for
dependent phases.
