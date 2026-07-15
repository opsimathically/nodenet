# Advanced UDP discovery plan review

Status: closed; Phase 34 is ready to implement  
Date: 2026-07-14  
Reviewed plan: `53-advanced-udp-discovery-evolution-plan.md`  
Implementation changed: no

## Outcome

The Phase 34–44 roadmap is coherent with the implemented scanner and is ready
for sequential implementation. The review found material API, reservation,
transport, schema, capability-ledger, and protocol-state gaps in the first
draft. Those gaps were corrected directly in the authoritative plan; readiness
applies to the corrected plan, not its earlier wording.

Phase 34 is implementation-ready. Later phases remain gated by the exit tests
and fresh dependency/impact decisions written into their own plans. A candidate
that records a protocol-specific no-go is not a failed phase when the safe and
honest alternative would be a malformed or over-privileged probe.

No Rust, TypeScript, native binding, package, fixture, or test implementation
was changed by this review.

## Evidence inspected

### Implemented project

- `packages/nodenetscanner/src/index.ts`: `Scanner.start()` returns an
  already-running `ScanSession`; pause/resume, cancellation-summary, pull,
  event-batch, summary, close, immutable plan snapshotting, and hostile batch
  validation establish the public lifecycle style discovery must retain.
- `crates/nodenetscanner-engine`: deterministic scheduling, injected time and
  transport boundaries, exact result reservations, target products, late grace,
  and lifecycle settlement establish the reusable engine conventions but do not
  presently model one-query/many-responder aggregation.
- `crates/nodenetscanner-native`: one environment runtime, four live sessions,
  raw/packet descriptor ownership, bounded receive turns, shared result queues,
  16 MiB session and 64 MiB environment metadata ceilings, sealed batches, and
  Worker teardown establish the native resource boundary.
- `crates/nodenet-protocols`: syscall-free safe-Rust builders/parsers, stable
  UDP catalogue identities, strict finite signature work, and the executable
  capability ledger establish protocol and provenance ownership.
- Phase 24, Phase 27–33, and their audit reports: retained schema decoding,
  native risk enforcement, source-lane correlation, two-dimensional reservation,
  parser hardening, packaging, and native AArch64 publication constraints.

### Primary protocol contracts

The review checked the relevant normative behavior in the primary references
listed by the plan. In particular:

- mDNS normal multicast traffic uses port 5353, while a query from another
  source port requests a legacy unicast response carrying the query ID; full
  multicast reception has explicit socket-reuse and host-daemon coexistence
  implications.
- WS-Discovery ProbeMatches require WS-Addressing relationship fields and
  bounded XML namespace-aware parsing; advertised `XAddrs` do not authorize a
  URL fetch or a new scan.
- TFTP selects a server transfer ID after the request to port 69. A positive
  DATA/OACK response creates server state, duplicate requests can create
  competing transfer IDs, and simply abandoning a positive response encourages
  retransmission.
- QUIC Version Negotiation is structurally correlatable through connection IDs
  but is not integrity-protected and cannot prove HTTP/3 or authenticated
  application identity.
- DHCP information operations still own fixed client ports, transaction/client
  identity, interface scope, coexistence, and privacy concerns even though they
  do not request a lease.

The review did not use Nmap source or data to define request bytes, parsers,
fixtures, port maps, or distributed project content.

## Closed findings

### F-01 — The provisional lifecycle contradicted the existing scanner API

The first discovery sketch exposed a second explicit `start()` lifecycle and a
synchronous summary even though `Scanner.start()` returns an already-running
session with awaitable worker-ordered controls.

Resolution: `Scanner.startDiscovery()` returns an already-running
`DiscoverySession`. Its pause, resume, cancel, pull, progress, event-batch,
summary, and close contracts align with `ScanSession` while retaining distinct
result types and native correlation state.

### F-02 — Fan-out reservation occurred after irreversible network work

Reserving a row only when a responder arrived could transmit one multicast query
and then discover that its possible lossless results did not fit shared
capacity.

Resolution: the normalized `maxResults` and `maxMetadataBytes` pool is reserved
against environment capacity before the first query. Every query then leases its
operation-declared worst-case new rows/metadata from that pool before send;
settlement commits accepted entities and releases the unused lease exactly once.
The plan also freezes a session deadline, physical-query ceiling,
accepted-datagram ceiling, byte ceiling, and fair per-tick receive limits so
zero-length or tiny datagrams cannot evade bounds. Committed row/metadata limits
are session-lifetime output budgets, so pulling batches cannot turn a bounded
native queue into unbounded Node-retainable output.

### F-03 — Discovery could accidentally double native environment capacity

A separate session type could have been interpreted as four scan sessions plus
four discovery sessions with a second 64 MiB budget.

Resolution: scan and discovery sessions share one combined four-session limit
and one combined 64 MiB environment metadata budget. Receive/parser work is fair
across both session kinds, and discovery owns no second environment runtime.

### F-04 — Reusing the current raw receive path was neither efficient nor exact

The implemented scanner opens packet/raw descriptors for target scanning. One
unfiltered `ETH_P_ALL` stream per discovery protocol or session would multiply
packet copies, privilege, parsing, and demultiplexing cost.

Resolution: Phase 34 freezes an operation-driven transport boundary. Ordinary
nonblocking UDP is preferred for multicast-query/unicast-response protocols;
multicast reception receives an explicit group membership, port coexistence,
filter, namespace, and cleanup review. Descriptors are opened lazily. UDP-only
discovery must not require `CAP_NET_RAW` or open raw/packet sockets, and partial
mixed-descriptor admission rolls back before transmission. Packet-info,
multicast-interface, and received-hop metadata provide exact interface
attribution where Linux supports them.

### F-05 — Discovery identity and conflict behavior were underspecified

JavaScript strings, last-writer-wins metadata, or arrival-ordered entity rows
would merge link-local identities incorrectly and make replay nondeterministic.

Resolution: schema 1 uses stable numeric vocabularies, offset-checked byte
sidecars, strict protocol text decoding, canonical wire identities, and
per-interface/scope keys. Exact duplicates coalesce. Conflicts are retained as a
bounded canonically sorted evidence set or produce explicit ambiguous/partial
results. Phase 34 fixes per-entity address, field, string, and variable-byte
bounds and validates them independently in Rust and TypeScript.

### F-06 — Existing blocked capabilities had no honest implementation reference

The UDP capability ledger can currently reference only destination-port
catalogue probe IDs. mDNS and WS-Discovery discovery operations do not belong in
that catalogue, but leaving them blocked after implementation would also be
false.

Resolution: a distinct semantically versioned discovery-operation registry owns
stable operation IDs and exact scope, parser, result, risk, resource,
provenance, and fixture metadata. Capability entries use checked tagged
references such as `UdpProbe(id)` and `DiscoveryOperation(id)`. Implementing a
discovery capability replaces its blocked disposition without changing UDP
catalogue `1.3.0`.

### F-07 — Advertised endpoints could silently expand caller authority

mDNS addresses, WS-Discovery `XAddrs`, SQL instance ports, rpcbind universal
addresses, and other metadata are attacker-controlled response content.

Resolution: advertised endpoints are bounded result metadata only. They do not
cause resolution, URL dereference, HTTP requests, or scans. Phase 37 is the only
accepted automatic derived-work path: registered same-target edges, original
allowlist/exclusion revalidation, checked graph bounds, reserved child work, and
an additive scan schema 3 with parent and derivation provenance.

### F-08 — mDNS receive modes and host-daemon coexistence were conflated

An ephemeral legacy-unicast query has useful transaction correlation and avoids
claiming port 5353, but it is not equivalent to full multicast browsing. Full
browse sockets can conflict with or duplicate traffic from the host mDNS daemon.

Resolution: Phase 35 implements and reports the selected receive form
explicitly. Legacy unicast carries a random query ID, reports truncation as
partial, and invents no TCP fallback. Full browsing is admitted only after group
membership and reuse/coexistence pass for the chosen namespace and interface.
Neither mode is called authenticated.

### F-09 — XML safety needed a dependency decision, not a tokenizer aspiration

Correct SOAP/WS-Addressing parsing requires namespaces, encodings, attributes,
and complete envelope structure; a small hand-written tokenizer is not
automatically safer.

Resolution: Phase 36 defaults to an exact-pinned, minimal-feature mature
streaming XML parser after license, advisory, allocation, binary-size, and
hostile-input review. DTDs, entities, external resources, unsupported encodings,
and unbounded namespace/attribute/text work are disabled. A project tokenizer
requires a separately accepted correctness proof.

### F-10 — TFTP termination and retry could create remote state

Stopping after DATA/OACK without a response leaves the server retransmitting.
Retrying the RRQ can also create multiple server transfer IDs.

Resolution: ERROR is terminal. A positive DATA/OACK response pins the first
valid same-target/interface server transfer ID and causes one rate-charged TFTP
ERROR requesting prompt termination. The default has no RRQ retry. Its
project-prefixed filename has at least 128 bits of session entropy but is called
collision-resistant, never nonexistent; an intentional collision is a required
cleanup test. Any future retry must account for every structurally valid
competing server transfer and send bounded Unknown-TID cleanup without weakening
the pinned exchange.

### F-11 — Later handshake evidence could be overstated

Version Negotiation, IKE negotiation, DTLS hello/cookie behavior, and multicast
presence do not by themselves authenticate a service or application.

Resolution: Phase 40 labels matched QUIC Version Negotiation as strong
structural but unauthenticated evidence and never infers HTTP/3. Phase 41 admits
IKE/DTLS independently only after fresh cryptographic/dependency/CPU/impact
review and stops at the least expensive sufficient response. Every family can
record no-go without causing fallback to a malformed approximation.

### F-12 — DHCP information queries still risked host-client interference

Calling INFORM or Information-request “read-only” did not resolve fixed-port
coexistence, client identity, transaction correlation, interface scope, or
configuration privacy.

Resolution: Phase 42 requires explicit interface/family and independent fixed-
source, multicast/broadcast, and sensitive-read consent. It uses the minimum
standards-valid identity, never fabricates a stable MAC/DUID, strictly matches
the transaction/interface/client fields actually sent, and performs no lease or
configuration mutation. If safe host coexistence is not proved, the operation
remains isolated-namespace-only or blocked.

### F-13 — Targeted entity discovery had no public scope

NAT-PMP gateway lookup, direct SQL Browser instance enumeration, and configured-
realm Kerberos need explicit targets and operation parameters. The first API
sketch allowed only link interfaces, while forcing these operations back into a
scan row would either lose multi-entity output or overload schema 2.

Resolution: Phase 34 freezes a discriminated discovery scope. `links` owns
explicit interfaces/families; `targets` reuses checked `ScanTarget` and
exclusion normalization plus an operation-gated kernel-default-IPv4-gateway
selector. Target scope does not inherit `ScanPlan` probes or authorize
advertised addresses. Phase 39 assigns all three candidates stable
discovery-operation IDs and emits bounded discovery entities without changing
scan schema 2.

## Readiness questions closed

1. **Separate session:** yes. Fan-out has distinct public/result/correlation
   state, explicit link/target scopes, and one shared native environment and
   lifecycle convention.
2. **Schema:** yes. Terminal immutable entities, partial/ambiguous outcomes,
   strict byte identities, deterministic conflicts, and per-row bounds are
   frozen for Phase 34.
3. **Interface and namespace scope:** yes. Explicit interface/family products,
   immutable context generations, IPv6 scopes, packet-info, hop limits, group
   ownership, and context invalidation are required.
4. **Reservation and rate:** yes. The full initial product and adaptive maxima
   use checked arithmetic; result pools precede the first query; every setup,
   query, retry, follow-up, and cleanup packet is charged.
5. **Lifecycle:** yes. Pause stops new sends after a worker boundary while
   bounded receive drainage continues; cancellation settles retained partials;
   close/disposal and teardown are exactly once.
6. **mDNS fan-out:** yes. Query graphs, entities, records, text, interfaces,
   modes, TTLs, deadlines, and truncation are bounded and observable.
7. **XML:** yes. The dependency and hostile-input acceptance gate is explicit;
   XML never performs external I/O.
8. **Derived endpoints:** yes. Same-target containment, exclusions, graph
   ceilings, provenance, reservation, and additive schema 3 are mandatory.
9. **Alternate ports:** yes. Only registered first-valid same-target/interface
   transitions are allowed, with explicit lower evidence and TFTP cleanup.
10. **Candidate independence:** yes. QUIC, IKE, DTLS, Kerberos, DHCP, and each
    specialized pack can independently pass or record no-go.
11. **Versioning and release:** yes. Discovery has its own registry/schema; scan
    schemas 1/2 and catalogue `1.3.0` remain stable; Phase 44 alone may prepare
    unpublished `0.3.0-rc.1` after native x64/AArch64 gates.
12. **Reproducibility and provenance:** yes. Project-owned virtual and namespace
    responders, primary specifications, canonical fixtures, capture, syscall
    trace, fuzz/sanitizer, lifecycle, resource, and artifact gates require no
    Internet service, third-party scanner, or unlicensed fixture.

## Implementation order

Phase 34 is the only next implementation phase. It must first freeze types,
numeric vocabularies, defaults, exact constants, registry version, descriptor
traits, and reservation/lifecycle matrices before wiring the native synthetic
transport. It emits no real discovery protocol. Phase 35 can begin only after
the Phase 34 exit gate and report pass; subsequent phases follow the dependency
table in the authoritative plan.

## Readiness decision

Accepted. The corrected plan is complete enough to start Phase 34 without an
unresolved product, ownership, safety, privilege, versioning, or test-topology
decision. Implementation discoveries that would alter a frozen invariant must
return to planning rather than being resolved silently in code.
