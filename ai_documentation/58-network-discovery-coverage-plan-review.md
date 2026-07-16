# Network discovery coverage plan review

Status: closed; Phase 45 is ready to implement  
Date: 2026-07-15  
Reviewed plan: `57-network-discovery-coverage-plan.md`  
Implementation changed: no

## Outcome

The Phase 45–58 direction is compatible with the implemented scanner after the
binding clarifications below. Phase 45 is deliberately syscall-free and can
proceed without changing scan schemas 1/2, discovery schema 1, UDP catalogue
`1.3.0`, discovery registry `1.0.0`, or current wire behavior.

Later phases remain gated by their predecessor exit tests and independent
protocol/provider admission decisions. Phase 58 cannot close the existing Phase
44 native AArch64 and release-hardening gates by documentation or
cross-compilation.

## Evidence inspected

- The current `nodenetscanner-engine` scan, discovery, budget, aggregation, and
  rpcbind-derived endpoint contracts.
- The native combined scan/discovery environment admission, result retention,
  discovery control thread, packet/raw transports, compact scan batches, and
  discovery rows.
- The TypeScript plan snapshotting, hostile batch validation, already-running
  sessions, abortable pulls, event adapters, summaries, and immutable views.
- The route-netlink context model and the protocol crate's strict link, IP,
  ICMP, NDP, DNS, XML, UDP, TCP, and discovery registries.
- The Phase 34–44 hardening report and all current ordinary Rust, TypeScript,
  native build, and Node tests, which passed before Phase 45 implementation.

## Binding corrections and decisions

### R-01 — Evidence identity requires a run-qualified origin

Scan rows have a stable logical tuple within one run but no globally stable row
ID. Discovery `entityId` is also run-local. Therefore an evidence origin is the
tuple `(source kind, source schema, caller/native run ID, source record ID)`.
The run ID is bounded opaque bytes, not a hostname or clock. Evidence IDs are
structured origins, not lossy hashes. A future sensor envelope adds its sensor
and network-domain origin outside this tuple.

### R-02 — Evidence batches are additive source records, not an asset database

Phase 45 records immutable evidence and exact conflicts. It does not merge
devices. Asset reconciliation belongs to Phase 54 and must retain the evidence
origins that justified every merge, split, or classification. This avoids
premature identity policy in scan/discovery adapters.

### R-03 — Expiry uses local monotonic time

Existing scan timestamps are monotonic session-relative values. Evidence uses
monotonic nanoseconds for ordering and expiry within a run, with checked
optional wall-clock context for presentation only. Cross-run and cross-sensor
freshness cannot compare unrelated monotonic epochs; Phase 55/57 must carry
explicit clock-domain and uncertainty metadata.

### R-04 — Current schemas remain source-of-truth records

Phase 45 adapters copy the semantically relevant fields required for evidence
while retaining source kind/schema/run/record identity. They do not replace the
existing batches, upgrade weak evidence, reinterpret silence, or invent missing
interface/MAC/service identity. Old decoders remain unchanged.

### R-05 — Derived authority is an independent decision from evidence strength

A strongly parsed response proves structure/correlation, not authorization. The
authority engine checks the immutable target allowlist/exclusions, same-address
rule, registered derivation kind and destination operation, independent risk
consent, graph bounds, and a pre-I/O resource reservation. Phase 37's rpcbind
child maps into the generalized registry without becoming less restrictive.

### R-06 — One canonical risk vocabulary is required

Passive, service, and enrichment risks receive stable independent bits. Profile
selection never grants a bit. Authentication attempt and target mutation remain
unadmittable rather than merely off by default. Existing UDP risk values retain
their public strings and meanings.

### R-07 — Observation output must be append-only

`ObservationSession` may deliver evidence before completion, unlike discovery
schema 1. It therefore emits immutable observations plus later explicit expiry
or withdrawal records. It never changes a previously delivered row. Pulling a
batch releases native queue capacity but does not replenish lifetime capture,
parse, or output budgets.

### R-08 — Passive visibility and fragments are explicit

Initial capture is non-promiscuous, metadata-only, interface-scoped, finite, and
reports outgoing inclusion, kernel/user drops, truncation, and filters. It does
not claim absence. Incomplete IP fragments cannot enter an upper-layer parser.
Bounded reassembly, if implemented, owns independent flow/fragment/ byte/time
limits and rejects overlaps.

### R-09 — All session kinds share environment capacity

Scan, discovery, observation, path, and service work share one environment
session ceiling and native metadata budget. A separate session class is not a
second runtime or memory allowance. Ordinary TCP/UDP-only work opens no raw
descriptor; passive capture and active raw control operations report exact Linux
permission failures.

### R-10 — TCP service work uses ordinary kernel TCP

Application conversations use nonblocking `SOCK_STREAM` descriptors and the
scanner's native scheduling/lifecycle boundary. They do not reconstruct TCP on
the raw SYN engine and do not occupy libuv workers with blocking I/O. The
generic engine accepts only registered finite state machines, not arbitrary
scripts or payloads.

### R-11 — Advertised endpoints cannot create crawler authority

DNS, mDNS, SSDP, WS-Discovery, UPnP, TLS, DHCP, route, and redirect fields are
untrusted evidence. A fetch or child probe is registered, same-address by
default, rechecked against caller scope/exclusions, separately risked, and fully
budgeted. URL redirects default to rejected. DNS resolution cannot change the
authorized address after admission.

### R-12 — Persistence and sensors remain application boundaries

Phase 55 provides deterministic snapshot/delta and adapter contracts but no
mandatory database. Phase 57 provides bounded untrusted envelope encoding,
decoding, and fusion but no listener, authentication scheme, remote execution,
or scan-plan transport. Applications own those policies.

## Phase 45 frozen initial bounds

- Evidence schema version: 1.
- Maximum evidence records per batch: 8,192.
- Maximum fields per evidence record: 128.
- Maximum relations per evidence record: 64.
- Maximum canonical key, source/run ID, field key, and individual field value: 1
  KiB each.
- Maximum variable bytes per evidence record: 16 KiB.
- Maximum variable bytes per evidence batch: 16 MiB.
- Derivation depth: 2.
- Derived endpoints per parent: 32.
- Derived endpoints per original target: 256.
- Authentication-attempt and target-mutation authority: never admissible.

Later phases may lower these bounds. Raising them requires stress evidence and a
new decision.

## Phase 45 exit tests

1. Current scan and discovery records adapt without changing their source
   schemas or original evidence strength.
2. Evidence sorting and replay are deterministic under source-order changes.
3. Duplicate records coalesce and conflicting records remain independently
   visible.
4. Weak names, vendors, certificates, or shared services cannot merge devices.
5. Hostile counts, offsets, byte lengths, UTF-8 projections, timestamps,
   relations, and schema versions fail before allocation or indexing.
6. Scope escape, exclusion escape, unregistered edges, risk escalation,
   cycles/duplicates, and every graph/resource ceiling fail before child I/O.
7. Reservations settle or release exactly once under success, rejection,
   cancellation, close, and panic containment.
8. No Phase 45 test opens a socket or transmits a packet.

## Readiness conclusion

All twelve questions in the authoritative plan are closed for Phase 45. Later
answers that depend on live AF_PACKET, TCP, provider, or multi-sensor evidence
remain implementation gates in their respective phases rather than assumptions
made here.
