# Advanced UDP discovery evolution plan

Status: implementation complete; Phase 44 external release gates remain  
Date: 2026-07-14  
Phases: 34 through 44

## Post-implementation hardening amendment

The adversarial review and corrections in `56-phase-34-44-hardening-report.md`
are authoritative where the original implementation assumptions differ. In
particular, production discovery runs on a dedicated named native thread rather
than a libuv worker; Linux `AF_INET`/`AF_INET6`, packet-info, scope,
source-port, rate, query, descriptor, row, and metadata boundaries are enforced
in the live path; and default-gateway selection uses a policy-aware kernel route
query.

Discovery rows are mutable only inside Rust while dependency records are still
being aggregated. Public batches are immutable Node-owned objects emitted after
terminal aggregation, so the current schema has no post-emission revisions or
tombstones. This is finite buffered delivery bounded by 8,192 rows and 16 MiB,
not incremental pre-deadline row streaming. `progress()` is independently live.
Changing that delivery point requires a new revision-capable schema rather than
silently mutating already delivered entities.

## Objective

Evolve `@opsimathically/nodenetscanner` from protocol-aware, per-target UDP port
scanning into a broader but still bounded discovery platform. The next roadmap
must add the high-value UDP discovery protocols that do not honestly fit the
current one-logical-result-per-`(target, port)` model, then add selected
targeted protocols whose wire, correlation, and impact contracts can be proved
from primary specifications.

The completed work should materially improve discovery on home, enterprise, IoT,
industrial, carrier, and VPN networks while preserving:

- the existing raw and scanner package boundaries;
- Rust ownership of descriptors, packet bytes, native state, and parser work;
- deterministic scheduling, exact rate charging, bounded backpressure, and
  exactly-once lifecycle behavior;
- the existing UDP scan result schema 2 and catalogue `1.3.0` identities until
  an explicitly versioned successor is required;
- independent protocol authorship and the Nmap licensing/provenance boundary;
- conservative evidence claims when a response is unauthenticated, multicast,
  alternate-port, or only structurally recognizable; and
- a low-impact default with every multicast, broadcast, sensitive read,
  authentication attempt, amplifying request, fixed-source exchange, and
  stateful handshake independently consented to.

This roadmap expands `nodenetscanner`. It does not add discovery policy to
`nodenetraw`, reopen the Phase 26 extreme backend, or turn the project into a
credential scanner, vulnerability scanner, exploit framework, passive packet
collector, or complete service/version fingerprint database.

## Baseline and motivating gaps

Phases 27 through 33 provide 33 independently authored UDP request variants,
strict response identification, multi-variant scheduling, schema-2 service
evidence, adaptive probing, and an executable capability ledger. That design is
correct for a finite product of caller-selected targets and destination ports.

The next protocols require five additional execution models:

| Model                        | Examples                               | Why the existing endpoint model is insufficient                                                                              |
| ---------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| one request, many responders | mDNS/DNS-SD, WS-Discovery, LLMNR, DHCP | one multicast or broadcast request can create independently owned results for previously unknown addresses                   |
| one response, many entities  | SQL Browser                            | one target response can describe several independently bounded service instances                                             |
| evidence-derived endpoints   | rpcbind to NFS/mountd                  | a response identifies another port that should be probed without silently expanding caller scope                             |
| alternate response port      | TFTP                                   | the first valid server response intentionally comes from a port other than the requested port and has no echoed secret token |
| bounded handshake            | QUIC, IKE, DTLS                        | protocol-valid elicitation owns more request state, CPU, bytes, and teardown than a stateless catalogue payload              |

Forcing these models into the current UDP catalogue would either discard useful
responders, misattribute responses, weaken correlation, hide physical work, or
make result memory proportional to an uncontrolled response set. The
architecture must evolve before protocol breadth.

## Governing architectural decisions

### Separate discovery sessions and scopes

One-to-many discovery will use a separate public session type rather than an
empty target list or a magic `ScanProbe` variant. Link fan-out and explicitly
targeted entity discovery are different normalized scopes:

```ts
type DiscoveryScope =
  | {
      readonly kind: "links";
      readonly interfaces: readonly string[] | "allEligible";
      readonly families: readonly ("ipv4" | "ipv6")[];
    }
  | {
      readonly kind: "targets";
      readonly targets: readonly ScanTarget[] | "kernelDefaultIpv4Gateway";
      readonly exclude?: readonly ScanTarget[];
      readonly families: readonly ("ipv4" | "ipv6")[];
      readonly interface?: string;
    };

interface DiscoveryPlan {
  readonly scope: DiscoveryScope;
  readonly operations: readonly DiscoveryOperationSelection[];
  readonly deadlineMs: number;
  readonly limits?: {
    readonly maxResults?: number;
    readonly maxMetadataBytes?: number;
  };
  readonly allowRisks?: readonly UdpProbeRisk[];
  readonly rate?: ScanRateOptions;
  readonly timing?: ScanTimingOptions;
}

interface DiscoverySession {
  readonly state: DiscoverySessionState;
  pause(): Promise<void>;
  resume(): Promise<void>;
  cancel(reason?: string): Promise<DiscoverySummary>;
  nextBatch(options?: NextBatchOptions): Promise<DiscoveryResultBatch | null>;
  progress(): Promise<DiscoveryProgress>;
  batches(
    options?: DiscoveryBatchEventEmitterOptions,
  ): DiscoveryBatchEventEmitter;
  summary(): Promise<DiscoverySummary>;
  close(): Promise<void>;
}

interface Scanner {
  startDiscovery(plan: DiscoveryPlan): Promise<DiscoverySession>;
}
```

Names and exact fields remain provisional until Phase 34 freezes them. The
contract must nevertheless preserve these properties:

- operation selection is explicit; creating a discovery session never implies
  every multicast or broadcast protocol;
- link interface selection is explicit. `"allEligible"` is an affirmative
  choice, not an omitted default;
- target scope reuses checked `ScanTarget` normalization and exclusions but does
  not become a `ScanSession`, inherit scan probe selection, or permit response-
  advertised addresses to expand the normalized targets. The kernel-default-
  gateway selector is valid only for operations that explicitly declare it;
- IPv4 and IPv6 scopes are explicit and IPv6 link-local addresses retain their
  interface scope;
- the session is finite and deadline-bounded; this roadmap does not add a
  permanently running service browser;
- every transmitted setup/query/retry consumes the rate budget;
- the session's configured fan-out row/metadata pool is reserved against shared
  environment capacity before the first query. New responders and records
  consume that pool before retention, and unused capacity is released exactly
  once; and
- pause, cancellation, close, Worker teardown, namespace churn, interface
  removal, and slow JavaScript consumption retain exactly-once semantics.

The discovery session shares the environment-scoped native runtime, immutable
network-context generations, result backpressure machinery, and Node lifecycle
style with scan sessions. `Scanner.startDiscovery()` returns an already-running
session, matching `Scanner.start()`; there is no second explicit-start
lifecycle. The existing maximum of four live sessions and the 64 MiB environment
metadata budget apply to scan and discovery sessions combined, not four of each.
A discovery session does not share mutable per-session correlation maps or
reinterpret scan results.

Pause stops new queries and adaptive follow-ups after an awaitable worker-order
boundary, but the native runtime continues bounded receive/drain processing for
queries already on the wire so kernel buffers and reserved result promises are
not abandoned. Cancellation retires query admission, deterministically settles
or marks already retained partial entities, and returns a summary. Close may
explicitly discard queued results under the same counted-disposal contract as a
scan session.

Before each physical query, the engine leases that operation descriptor's
declared worst-case newly created entity rows and variable metadata from the
already reserved session pool. Enrichment-only follow-ups lease their declared
metadata maximum. A query waits or terminalizes before send when its lease is
unavailable; settlement converts accepted entities to committed pool usage and
releases the unused remainder exactly once. Protocol-violating excess fan-out is
counted and deterministically truncated, but valid descriptor-bounded responses
are never lost merely because several queries were admitted concurrently.

`maxResults` and `maxMetadataBytes` are lifetime committed-output budgets for
the finite discovery session, not merely queue high-water marks. Pulling or
transferring a batch does not replenish them; this keeps total Node-retainable
discovery rows and variable metadata bounded even when JavaScript holds every
batch. Query leases return unused capacity to the session pool, while committed
capacity remains consumed until session teardown releases the environment
reservation.

Phase 34 must freeze a discovery transport boundary instead of assuming that the
current per-scan `AF_PACKET`/raw descriptor set is reusable unchanged. Ordinary
nonblocking UDP sockets are preferred for protocols whose multicast request
receives unicast replies on an ephemeral port. A protocol that must receive
multicast responses requires reviewed group membership, coexistence,
source-port, filter, namespace, and cleanup semantics. No discovery session may
multiply an unfiltered `ETH_P_ALL` receive stream per selected protocol.

Descriptor admission is operation-driven and lazy. A discovery plan containing
only ordinary UDP operations must not open raw or packet sockets or require
`CAP_NET_RAW`; an operation requiring raw receive, a privileged fixed source
port, or another Linux capability reports that requirement independently before
its first transmission. Prefer `IP_PKTINFO`/`IPV6_RECVPKTINFO`, explicit
multicast-interface options, and received hop-limit metadata to privileged
device binding where they provide exact interface attribution. Mixed operation
sets open only their required descriptor classes, and partial descriptor setup
is rolled back exactly once on admission failure.

### Discovery operation registry and capability ledger

Discovery operations use a project-owned, statically linked, semantically
versioned registry distinct from the destination-port-based UDP probe catalogue.
Each stable operation ID records protocol, request form, interface/family scope,
builder/parser, result kind, evidence strength, response window, source and
destination requirements, resource ceilings, risk set, provenance, and fixture
status. Registry version/hash and selected operation IDs appear in capabilities,
summaries, and result batches.

The capability ledger evolves from `probe_ids: &[u16]` to a checked tagged
implementation reference such as `UdpProbe(id)` or `DiscoveryOperation(id)`.
Each project capability retains one authoritative disposition. Implementing mDNS
discovery therefore replaces its current blocked disposition with a
discovery-operation reference without assigning it a UDP catalogue probe ID or
changing catalogue `1.3.0`. Validators continue to reject unknown, duplicate,
uncovered, externally derived, or simultaneously blocked-and-implemented
entries.

### Component ownership

- `nodenet-protocols` owns discovery operation descriptors, pure builders,
  strict parsers, canonical wire identities, typed bounded records, and registry
  validation. It remains syscall-free, N-API-free, and safe-Rust-only unless a
  separately reviewed invariant proves otherwise.
- `nodenetscanner-engine` owns query programmes, collection windows, fan-out
  budget consumption, entity dependency/conflict aggregation, duplicate
  suppression, fairness, terminal outcomes, and derived-endpoint graphs under
  injected clock/transport/context/entropy/sink traits.
- `nodenetscanner-native` owns sockets, multicast membership, source ports,
  interface binding, entropy, packet/datagram buffers, receive demultiplexing,
  shared environment quotas, result queues, batch sealing, and teardown.
- TypeScript owns ergonomic immutable plans, hostile public-value validation,
  lazy batch views, event-batch convenience, and presentation. It never parses
  packets/XML/DNS, runs per-response callbacks in the native path, or owns a
  discovery cache.

### Separate discovery result schema

Discovery result batches begin at discovery schema version 1. Existing scan
result schemas 1 and 2 remain byte-for-byte decodable and keep their current
meaning.

One terminal discovery row represents one bounded entity or service observation,
not one transmitted datagram. The frozen Phase 34 schema must be able to
represent:

- session-local stable entity ID and optional parent entity ID;
- protocol and observation kind;
- responder address, address family, interface index, and IPv6 scope;
- optional instance name, service type, hostname, service port, and bounded
  addresses;
- bounded typed metadata with provenance to the response records that supplied
  it;
- first/last observation times and advertised lifetime/TTL when meaningful;
- evidence strength: structurally parsed, query-related, transaction-correlated,
  or authenticated only when the protocol actually proves it;
- complete, partial, truncated-by-policy, cancelled, deadline, and
  context-invalidated outcomes; and
- counts of physical requests, accepted/duplicate/rejected datagrams, parser
  work, and dropped discoveries.

Discovery rows use stable numeric protocol/operation/kind/evidence/outcome
vocabularies plus offset-checked byte sidecars. Phase 34 freezes per-row bounds:
at most 32 addresses, 128 metadata fields, 1 KiB per string value, and 16 KiB of
total variable metadata for one entity. A terminal row that cannot fit one
batch's 4 MiB variable-byte ceiling is impossible by construction. All offset,
count, width, endianness, UTF-8, discriminant, and exact-record-end rules are
validated independently in Rust and TypeScript.

Wire identity is canonical bytes, not a lossy JavaScript string. Protocol fields
declared as UTF-8 must decode strictly; invalid text may retain bounded escaped
diagnostic bytes but cannot become a typed name or deduplication key. No Unicode
normalization, case folding, URI dereference, or IDNA conversion is implicit.
DNS canonical comparison follows DNS/mDNS rules on label bytes; presentation
strings are derived only after identity and bounds are fixed.

The native layer aggregates bounded protocol records and emits an immutable
terminal entity row only when its dependency set is complete or its bounded
collection window ends. It must not emit a mutable JavaScript object and later
change it. If early incremental observations are eventually required, they need
an explicitly versioned append-only revision/tombstone contract; Phase 34 does
not assume one.

Exact duplicate records coalesce. Conflicting records are retained as a bounded,
canonically sorted evidence set or cause an explicit ambiguous/partial entity;
arrival order and last-writer-wins behavior never select a service address,
port, identity, or metadata value. Advertised mDNS addresses, WS-Discovery
`XAddrs`, SQL endpoints, and other response-derived addresses are result data
only. They never trigger HTTP fetches or new scans unless a separately accepted
derived-endpoint policy revalidates them against caller scope.

### Evidence-derived endpoint graph

Targeted scans may add a bounded derivation graph after Phase 37. A graph edge
means that a strongly parsed response from work already authorized by the caller
identified a new port or endpoint worth probing.

Required invariants:

- no derived address may escape the normalized target allowlist and exclusions;
- same-address/different-port derivation is the default; a different-address
  edge requires a future explicit policy and is not accepted by this roadmap;
- every permitted derivation kind and destination protocol is registered,
  provenance-bearing, and independently bounded;
- graph depth, fan-out per parent, total derived work, rows, metadata, and live
  correlations have hard ceilings;
- cycles and duplicate edges are suppressed deterministically;
- every child request consumes the normal packet, outstanding, retry, result,
  and metadata budgets;
- result schema 3, if required, is additive and records child result ID, parent
  result ID, derivation kind, and originating evidence. Schemas 1 and 2 remain
  accepted unchanged; and
- an operator can disable all derived probing while still receiving the parent
  service evidence.

Suggested initial ceilings are graph depth 2, at most 32 derived ports per
parent, and at most 256 derived logical endpoints per original target. Phase 37
must lower these values if stress evidence shows they are too generous.

### Alternate response endpoints

An alternate-port response policy is not a relaxed tuple matcher. It is a
protocol-specific state transition:

1. send a request to the registered well-known port;
2. accept only a structurally valid first response from the exact target
   address, expected interface/scope, and allowed time window;
3. atomically pin the server-selected port to that wire probe;
4. reject competing first responses and all later packets from other ports;
5. keep the pinned tuple through retry/late grace and release it exactly once;
6. report `alternateEndpoint` evidence without claiming secret-token strength.

No general public “accept any response port” switch is permitted.

### Stateful and cryptographic probes

QUIC, IKE, and DTLS must be implemented as bounded protocol state machines, not
static byte strings or permissive signatures. Each accepted state machine must
declare:

- maximum outbound and inbound datagrams/bytes;
- maximum handshake state and lifetime;
- entropy, nonce, connection-ID, cookie, sequence, and transaction ownership;
- parser depth/work and metadata bounds;
- whether cryptographic computation is necessary for elicitation or only for a
  complete authenticated exchange;
- per-host and global CPU/work pacing;
- amplification and target-impact classification;
- cancellation and partial-initialization cleanup; and
- dependency, license, advisory, binary-size, allocation, and platform review.

Discovery stops as soon as the least expensive response sufficient to identify
the service is received. It never completes authentication, installs a tunnel,
or creates long-lived application state.

## Scope and network-impact policy

The existing `UdpProbeRisk` vocabulary remains the common public vocabulary:

- `highAmplification`;
- `statefulHandshake`;
- `fixedSourcePort`;
- `multicastOrBroadcast`;
- `authenticationAttempt`; and
- `sensitiveRead`.

Protocol selection and risk consent remain independent. A comprehensive profile
or explicit discovery protocol does not itself authorize every risk declared by
that protocol. Native admission revalidates the immutable policy snapshot; the
TypeScript layer is not the enforcement boundary.

Additional rules:

- multicast/broadcast traffic is link-scoped and requires explicit interfaces;
- protocol-required destination group, source port, TTL/hop limit, and interface
  ownership are exact rather than caller-overridable;
- no built-in request writes configuration, creates a NAT mapping, transfers an
  operator file, uses a real user identity, brute-forces a credential, or
  deliberately exploits malformed-input behavior;
- synthetic sentinel names/principals must be session-randomized where useful,
  bounded, documented, never derived from a real operator resource, and given
  enough entropy that accidental collision is explicitly negligible rather than
  claimed impossible;
- a direct UDP response can prove an open endpoint even if service parsing
  fails, but it cannot create a typed service identity;
- multicast presence is query-related/parsed evidence, not authenticated host
  identity; and
- privacy-bearing TXT records, device descriptions, database instance lists,
  realms, routing data, and network configuration require `sensitiveRead`.

## Initial resource ceilings

Phase 34 must benchmark and freeze exact constants. The following are upper
bounds, not targets to silently increase:

| Resource                                                   |                             Initial maximum |
| ---------------------------------------------------------- | ------------------------------------------: |
| combined live scan/discovery sessions per Node environment |                                           4 |
| discovery session deadline                                 |                                        60 s |
| selected interfaces per discovery session                  |                                          16 |
| normalized target addresses per targeted discovery session |                                      65,536 |
| selected discovery operations per session                  |                                           8 |
| physical discovery queries per session                     |                                      65,536 |
| unique responders per session                              |                                       4,096 |
| terminal entities/services per session                     |                                       8,192 |
| combined promised discovery entities per environment       |                                      32,768 |
| retained protocol records per session                      |                                      32,768 |
| addresses retained per entity                              |                                          32 |
| metadata fields retained per entity                        |                                         128 |
| one discovery string value                                 |                                       1 KiB |
| variable metadata retained per entity                      |                                      16 KiB |
| retained discovery metadata per session                    |                                      16 MiB |
| combined scan/discovery metadata per environment           |                                      64 MiB |
| accepted inbound datagrams per discovery session           |                                     131,072 |
| accepted inbound bytes per discovery session               |                                      64 MiB |
| combined receive datagrams per environment scheduler tick  |                                         128 |
| accepted inbound bytes per environment per scheduler tick  |                                       1 MiB |
| parser work per target/interface scheduler turn            | 256 KiB or protocol-equivalent token budget |
| DNS compression-pointer traversals per name                |                                          32 |
| XML nesting depth                                          |                                          32 |
| XML tokens per envelope                                    |                                       4,096 |
| derivation graph depth                                     |                                           2 |
| derived ports per parent                                   |                                          32 |
| derived endpoints per original target                      |                                         256 |

Per-protocol datagram ceilings are lower when the primary specification permits
it: mDNS follows its reviewed message-size constraint, and WS-Discovery/DPWS
uses its 4,096-byte UDP-envelope limit. A response beyond a protocol ceiling may
still establish tuple-level network evidence in a targeted scan, but it is not
parsed or retained as discovery metadata.

When a discovery bound is reached, the session reports a deterministic
truncated-by-policy outcome and exact discarded counters. It does not evict an
already promised result silently, wrap a counter, allocate from an untrusted
declared length, or continue transmitting work that cannot reserve its result.
The normalized `maxResults` and `maxMetadataBytes` fan-out pool is reserved
before the first query and cannot exceed the session/environment ceilings.
Receive bytes and parser work are additionally scheduled fairly across all live
scan and discovery sessions; a flooded interface or protocol cannot consume
every runtime tick or starve commands, timers, cancellation, or other sessions.

## Phase 34 — Discovery session and bounded fan-out foundation

Status: implemented on 2026-07-14; readiness review passed

### Goal

Freeze and implement the separate one-to-many discovery ownership, lifecycle,
result, backpressure, and interface-scope foundation without adding a live
protocol yet.

### Deliverables

- Freeze the public `DiscoveryPlan`, `DiscoverySession`, batch, row, summary,
  progress, event-batch adapter, error, and capability types aligned with the
  existing already-running `Scanner.start()`/`ScanSession` lifecycle.
- Add a syscall-free deterministic discovery engine with injected clock,
  transport, context, entropy, and result sink.
- Represent one physical query producing zero to many independently bounded
  responder/entity candidates.
- Add discovery schema 1 with sealed Node-owned storage and lazy immutable
  TypeScript views; do not reinterpret scan schemas.
- Define terminal entity aggregation, duplicate suppression, record dependency,
  conflict/ambiguity, canonical ordering, quiet-window, deadline, and
  partial-result behavior.
- Validate explicit interface/family selection against one immutable context
  generation and retain IPv6 scope IDs. Define eligible links precisely; an
  `allEligible` selection that exceeds the interface ceiling fails rather than
  truncating silently.
- Freeze the discriminated link/target scope. Targeted discovery reuses checked
  target/exclusion normalization, admits the kernel default IPv4 gateway only
  for registered compatible operations, and cannot derive new addresses from
  response metadata.
- Normalize the complete initial `(operation, scope member, family)` work
  product and every adaptive-query ceiling with checked arithmetic before
  descriptor admission. Reject empty/duplicate/unsupported selections, deadlines
  above the frozen maximum, and any plan whose possible physical query count
  exceeds its session ceiling.
- Reserve the normalized session fan-out row/metadata pool before the first
  query. Lease every physical query's declared worst-case new rows/metadata from
  that pool before transmission, consume the lease before retaining candidates,
  and pause new queries/follow-ups under result backpressure while continuing
  bounded receive drainage for already-emitted work.
- Preserve one pending pull, Worker-ordered AbortSignal handling, pause/resume,
  cancellation-summary, close/disposal, Scanner close, Worker teardown, and
  environment teardown semantics across the combined four-session ceiling.
- Freeze a fair discovery datagram transport/descriptor boundary with explicit
  ephemeral/fixed source-port ownership, multicast membership where required,
  per-interface sending, receive filtering/demultiplexing, and idempotent
  cleanup.
- Open descriptor classes lazily per selected operation. Ordinary UDP-only
  discovery must work without `CAP_NET_RAW`; privileged operations must expose
  and enforce their capability requirements independently before any packet is
  sent. Prefer packet-info and multicast-interface controls for exact
  unprivileged attribution where Linux supports the required semantics.
- Add an empty semantically versioned discovery-operation registry, tagged
  capability-ledger references, and capability reporting for registry/schema/
  bounds/risks while reporting no live discovery operation as available.

### Tests

- virtual one-to-many response permutations, duplicates, delayed records,
  partial entities, quiet windows, deadline ties, and exact counters;
- responder/record/metadata/row saturation with lossless backpressure;
- zero-length/small-datagram floods, total datagram/query/deadline saturation,
  checked-product overflow, and deterministic counter terminalization;
- fan-out pool reservation failure before send, unused-pool release, combined
  scan/discovery session and environment-metadata saturation, and per-session
  receive/parser fairness under a flooded peer;
- per-query worst-case lease contention, valid maximum fan-out without loss,
  protocol-violating excess fan-out with exact truncation counters, and release
  of unused query leases on silence/error/cancel; batch pulls/transfers must not
  replenish lifetime committed capacity;
- interface removal, generation change, namespace isolation, IPv6 scope
  collisions, and loopback rejection/acceptance policy;
- pause/cancel/close/abort/Worker race matrices and fd/RSS stability;
- malformed batch columns, offsets, lengths, discriminants, transferred buffers,
  hostile JavaScript values, invalid UTF-8, canonical-key conflicts, oversized
  per-entity data, and panic containment;
- synthetic UDP unicast/multicast transport tests proving ephemeral port
  isolation, group join/leave where selected, filtering, source/interface/hop
  metadata, no duplicated unfiltered packet feed, and descriptor cleanup;
- an unprivileged UDP-only test proving that no raw/packet descriptor is opened,
  plus mixed-descriptor admission-failure tests proving complete rollback and no
  partial transmission; and
- deterministic replay of the same seed, virtual time, context, and input
  datagrams.

### Exit gate

The discovery engine can execute a synthetic query and deterministically settle
thousands of bounded multi-responder entities without syscalls, unbounded
memory, schema ambiguity, result loss, cross-session starvation, or lifecycle
races. Its native transport can safely carry a synthetic isolated-namespace
multicast request, but no real discovery protocol is emitted until Phase 35.

## Phase 35 — mDNS and DNS-SD discovery

Status: implemented on 2026-07-14; fixed-port browse recorded no-go

### Goal

Deliver the highest-value link-local discovery protocol with a bounded adaptive
query graph and strict DNS/mDNS parsing.

### Deliverables

- Implement independent DNS/mDNS builders and a strict parser for questions,
  compressed names, PTR, SRV, TXT, A, AAAA, and relevant negative/metadata
  records.
- Enforce label, name, pointer-depth, record-count, RDATA, message,
  cache-lifetime, and text bounds; reject compression loops and out-of-message
  pointers. mDNS names and DNS-SD text decode as strict UTF-8 where the
  specification requires it; malformed text never enters entity identity.
- Treat DNS-SD TXT keys according to their bounded printable-ASCII and case-
  insensitive key rules, reject duplicate keys within one TXT record, and keep
  values as bounded bytes. Expose a text projection only when a value is strict
  UTF-8; arbitrary TXT value bytes are never lossily decoded or used as an
  identity key.
- Send only to `224.0.0.251:5353` and `[ff02::fb]:5353` on explicitly selected
  interfaces, with protocol-required source/destination and TTL/hop-limit
  validation. Freeze two honest receive forms: an ephemeral-source legacy
  one-shot query whose unicast response repeats a random query ID, and full
  port-5353 multicast browsing only when reviewed bind/reuse or
  packet-membership coexistence can receive multicast responses without stealing
  or duplicating the host mDNS daemon's traffic.
- Make the selected receive form explicit in normalized plans, capability
  metadata, and summaries; never silently fall back between them. Legacy unicast
  mode reports truncated responses as partial and performs no invented TCP
  fallback. Full browse mode is admitted only after the host-daemon coexistence
  test passes for the selected namespace/interface.
- Start with `_services._dns-sd._udp.local.` enumeration, then bounded PTR,
  SRV/TXT, and host A/AAAA follow-ups. Rate-charge and reserve every query.
- Deduplicate records by canonical owner/type/class/RDATA/interface and assemble
  one terminal service entity without conflating identical link-local names on
  different interfaces.
- Preserve advertised TTLs as metadata without creating a permanent cache or
  continuing past the finite session deadline.
- Require `multicastOrBroadcast` and `sensitiveRead`. A valid legacy-unicast
  response with the repeated random query ID may be transaction-correlated;
  ordinary multicast answers are parsed/query-related only. Neither is
  authenticated.
- Keep direct unicast mDNS as a separately reviewed targeted variant rather than
  using it to approximate multicast browsing.

### Tests

- independently authored RFC vectors for compression, PTR/SRV/TXT/A/AAAA,
  cache-flush bits, duplicate answers, additional records, and known-answer
  behavior relevant to one-shot discovery;
- compression loops, pointer bombs, invalid labels, truncated counts, duplicate
  TXT keys, oversized text, unrelated answers, spoofed interface/scope, and
  malformed record combinations;
- dual-stack isolated namespaces with multiple responders, duplicate service
  names on different interfaces, delayed additional records, missing host
  addresses, and response floods;
- packet capture proving multicast groups, ports, hop limits, interface choice,
  legacy query IDs/source ports, multicast membership/reuse coexistence when
  enabled, query order, byte accuracy, rate accounting, and cleanup; and
- parser fuzzing, allocation ceilings, sanitizer runs, and bounded responder
  fan-out stress.

### Exit gate

A finite discovery session accurately returns bounded service instances,
hostnames, ports, addresses, TXT metadata, interface/scope, and partial outcomes
from independent IPv4/IPv6 responders. No response from an unselected interface
or unrelated record creates an entity.

## Phase 36 — WS-Discovery and LLMNR

Status: implemented on 2026-07-14

### Goal

Add Windows, printer, camera, ONVIF, and link-local name coverage while reusing
the proven fan-out engine rather than creating protocol-specific runtimes.

### Deliverables

- Implement WS-Discovery Probe messages with session-random message IDs and
  strict SOAP 1.2/WS-Addressing ProbeMatch parsing. Require the ProbeMatches
  action, `RelatesTo` equal to the request message ID, anonymous `To` where
  applicable, bounded `AppSequence`, complete endpoint reference, metadata
  version, and bounded types/scopes/XAddrs for every accepted match.
- Use only the registered IPv4/IPv6 WS-Discovery groups/port and explicit
  interfaces. Enforce application delay/collection windows and exact duplicate
  suppression.
- Select an exact-pinned, default-feature-minimized, mature streaming XML parser
  after dependency/license/advisory/binary-size review. A project-owned XML
  tokenizer is not the default and requires a separate accepted proof that it
  correctly implements the required XML namespace and encoding rules with less
  risk. Disable DTD, entity expansion, external resources, unsupported
  encodings, and unbounded namespace/attribute/text accumulation.
- Add DNS-wire LLMNR query/response parsing by reusing bounded DNS primitives
  while preserving LLMNR header, conflict, uniqueness, multicast, TTL, and scope
  rules.
- Limit LLMNR to explicitly useful configured names or reverse lookups. Do not
  claim wildcard service enumeration that the protocol does not provide.
- Require multicast and sensitive-read consent; require high-amplification
  consent for broad WS-Discovery probes if measured ratios cross the catalogue
  threshold.
- Report XAddrs as bounded untrusted metadata only. Do not resolve hostnames,
  dereference URLs, issue HTTP metadata requests, or derive scan targets from a
  ProbeMatch in this phase.

### Tests

- independent WS-Discovery and LLMNR responder matrices across IPv4/IPv6,
  multiple interfaces, duplicate messages, AppSequence/message-ID relations,
  fragmented metadata, and unrelated responses;
- hostile XML entity/DTD, namespace, depth, attribute, token, text, UTF-8,
  duplicate field, and oversized-envelope cases;
- hostile DNS compression/count/name cases inherited from Phase 35 plus LLMNR
  conflict and query-relationship cases;
- exact multicast destination, interface, hop-limit, retry, response-window, and
  rate capture; and
- dependency, fuzz, sanitizer, allocation, response-flood, and teardown gates.

### Exit gate

The same discovery API can safely enumerate mDNS services and WS-Discovery
devices and perform bounded LLMNR naming queries without schema changes,
unbounded XML/DNS work, cross-interface attribution, or hidden multicast.

## Phase 37 — Evidence-derived endpoints and adaptive rpcbind

Status: implemented on 2026-07-14

### Goal

Add a bounded evidence-derived endpoint graph and use it to discover ONC RPC
services that live on dynamic ports.

### Deliverables

- Freeze derived-probe policy, parent/child identity, summary/progress counters,
  schema compatibility, and capability reporting. Phase 37 must decide and
  freeze additive scan schema 3 before emitting a child result; it may not hide
  child evidence in an overloaded schema-2 metadata record.
- Add registered derivation kinds, deterministic cycle/duplicate suppression,
  depth/fan-out/total-work limits, and exact target/exclusion revalidation.
- Add strict rpcbind v3/v4 `GETADDR` handling for a small operator-selected or
  profile-selected programme set; prefer targeted lookups over unrestricted
  `DUMP`.
- Initially recognize NFS, mountd, and other independently specified RPC
  programmes only when a typed follow-up exists. Reject universal addresses that
  resolve outside the original target or permitted transport/family.
- Schedule child NULL or typed operations on returned ports, rate-charge them,
  reserve the child row and maximum metadata before transmission, and retain the
  stable derivation kind, parent logical result ID, originating
  operation/evidence, and child destination in the child result.
- Allow callers to collect rpcbind service evidence while disabling all child
  transmissions.
- Place broader programme enumeration behind `sensitiveRead` and, when measured,
  `highAmplification` consent.

### Tests

- virtual derivation graphs covering cycles, repeated ports, conflicting
  universal addresses, depth/fan-out/total saturation, exclusions, cancellation,
  and backpressure;
- strict XDR/RPC parsing, exact accepted-reply endings, wrong XIDs, malformed
  universal addresses, unsupported transports/families, and hostile counts;
- isolated rpcbind plus dynamic NFS/mountd responders, route changes, delayed
  child responses, ICMP contradictions, and capture of every charged frame;
- schemas 1/2 retained decoding and any additive schema-3 parent/derivation
  columns; and
- fuzz, allocation, sanitizer, four-session source-lane, fd/RSS, and teardown
  stress.

### Exit gate

One authorized rpcbind response can produce a bounded, explainable set of
same-target child probes and terminal results without target-scope expansion,
cycles, unreserved work, or weakening ordinary scan behavior.

## Phase 38 — Alternate-port correlation and TFTP

Status: implemented and integration-audited on 2026-07-14

### Goal

Implement the general internal alternate-response-port transition and prove it
with a safe, bounded TFTP discovery exchange.

### Deliverables

- Implement the registered-only alternate-endpoint state machine described by
  this plan; expose no arbitrary public loose-port matcher.
- Build a TFTP RRQ using a synthetic project-prefixed filename with at least 128
  bits of session entropy and reviewed mode/options chosen to elicit a bounded
  ERROR or first DATA/OACK. The name is collision-resistant, not guaranteed
  nonexistent; never derive it from a local/operator path.
- Require `sensitiveRead` and `statefulHandshake`, plus `highAmplification` when
  the declared first-block ratio crosses the project threshold. Never use an
  operator file path by default, write a file, acknowledge/continue a transfer
  beyond the minimum identification exchange, or retain transferred content.
- Strictly parse ERROR, DATA, and OACK lengths/options; cap response bytes and
  terminate native state immediately after sufficient evidence. A server ERROR
  is already terminal. An unexpected positive DATA/OACK creates server transfer
  state, so send one rate-charged TFTP ERROR to the pinned server TID to request
  prompt termination; do not merely abandon it to retransmit until timeout.
- Pin only the first structurally valid same-target/interface/scope response
  port during the response window; preserve it through late grace and report
  alternate-endpoint evidence honestly.
- Default to no RRQ retry. Any future single bounded retry must account for the
  RFC-defined possibility that duplicate requests create multiple server TIDs
  and must send a rate-charged Unknown-TID ERROR to each structurally valid
  competing transfer without disturbing the pinned exchange.

### Tests

- correct alternate-port exchange, wrong target, wrong interface/scope,
  spoofed-first response, two competing ports, delayed original-port ICMP,
  retry, duplicate, late response, cancellation, and grace reuse;
- sentinel construction/entropy, an intentional server-side filename collision,
  and proof that no local/operator filename is transmitted by default;
- truncated ERROR/DATA/OACK, oversized block/options, duplicate options,
  unsupported mode, and receive floods;
- packet capture proving one bounded identification exchange and no transfer
  continuation, including terminal ERROR cleanup for DATA/OACK and no hidden
  retry-created server state; and
- deterministic virtual races, namespace responders, fuzzing, sanitizers,
  allocation/fd/RSS, and four-session stress.

### Exit gate

TFTP discovery identifies a valid same-target server response from its selected
transfer port without accepting arbitrary cross-port traffic or continuing a
file transfer. The alternate-endpoint machinery remains inaccessible to
unregistered custom probes.

## Phase 39 — High-yield targeted discovery pack

Status: implemented on 2026-07-14; Kerberos candidate recorded no-go

### Goal

Add straightforward high-value unicast discovery for gateways, Microsoft SQL
Server, and explicitly configured Kerberos realms.

### Required candidates

- **NAT-PMP external-address request:** query only the kernel-resolved default
  IPv4 gateway or an explicit same-link target. Never request, renew, or delete
  a mapping.
- **SQL Server Resolution Protocol:** support direct per-host SQL Browser
  requests first. Parse instance records and reported endpoints under strict
  field/count/text bounds. Broadcast/multicast enumeration is optional only
  after it passes the discovery-session fan-out and amplification review.
- **Kerberos:** accept only a standards-valid, credential-free discovery request
  for an explicitly supplied realm using a randomized non-real principal. If a
  useful response cannot be elicited without operator identity or credential
  semantics, retain the blocked disposition rather than sending malformed data.

### Deliverables

- Add independently authored builders/parsers and stable discovery-operation IDs
  with primary-source provenance, canonical fixtures, target eligibility, risk
  classifications, response ceilings, and capability-ledger dispositions.
- Use targeted discovery scope for NAT-PMP, SQL Browser instance enumeration,
  and configured-realm Kerberos because each needs explicit per-operation input
  and/or can produce multiple entity observations. The normalized target or
  registered kernel-default-gateway selector is fixed before transmission;
  response-advertised addresses and ports do not expand it.
- Treat NAT-PMP as IPv4 gateway context and keep PCP ANNOUNCE unchanged.
- Require `sensitiveRead` for NAT-PMP external-address metadata and validate the
  response source as the exact queried gateway/target; the protocol has no
  transaction token.
- Require `sensitiveRead` and measured amplification consent for SQL instance
  enumeration.
- When one SQL Browser response describes multiple database instances, emit the
  endpoint observation and instances as separate bounded discovery entities
  instead of packing an unbounded list into schema-2 service metadata. Report
  advertised SQL ports as metadata only; do not scan them automatically.
- Require `authenticationAttempt` and `sensitiveRead` for Kerberos; never accept
  a real username/password/key in the built-in discovery plan.
- Reuse or introduce ASN.1/DER handling only after the same strict depth/count/
  length, dependency, allocation, and fuzz review as other structured parsers.
  Accept a complete correlated KRB-ERROR as KDC evidence without requiring a
  ticket response or TCP fallback.
- Parse service identity only from complete structural responses; tuple-valid
  arbitrary data proves only endpoint openness.

### Tests and exit gate

Independent ordinary and namespace responders, wrong transaction/identifier,
hostile length/text/ASN.1, amplification, policy matrices, exact packet capture,
fuzz/sanitizer/allocation, and lifecycle stress must pass. Every accepted probe
is non-mutating, bounded, explicitly consented, and useful on its intended
scope. A candidate that fails those conditions remains recorded as blocked and
does not block the other candidates.

## Phase 40 — QUIC version-negotiation discovery

Status: implemented on 2026-07-14

### Goal

Detect QUIC endpoints and advertised versions without completing TLS or claiming
authenticated application identity.

### Deliverables

- Independently implement QUIC invariant long-header and Version Negotiation
  construction/parsing using a reserved version, random destination/source
  connection IDs, protocol-correct minimum datagram size, and exact CID
  reversal/matching.
- Limit automatic eligibility to reviewed QUIC service ports; arbitrary ports
  remain caller-selected custom scope.
- Bound advertised version count, duplicates, reserved values, datagram bytes,
  parsing work, retries, and per-host rate.
- Classify a matched Version Negotiation response as strong QUIC structural
  evidence but explicitly unauthenticated. Do not infer HTTP/3 solely from QUIC.
- Review whether packet protection is actually necessary for the chosen
  version-negotiation path. Add no cryptographic dependency unless primary-spec
  and responder evidence demonstrate that it materially increases discovery.
- Preserve ordinary empty/custom/protocol UDP behavior and catalogue semantic
  versioning.

### Tests and exit gate

Exercise independently controlled QUIC v1/v2/multi-version responders, CID and
version mismatches, spoofed/duplicate/truncated/oversized lists, silence/ICMP,
minimum datagram capture, adaptive stopping, fuzzing, sanitizers, allocation,
and response-flood pacing. The phase exits only when it identifies QUIC without
TLS completion, unbounded work, or an inflated HTTP/3/authentication claim.

## Phase 41 — IKE and DTLS bounded handshakes

Status: closed no-go on 2026-07-14 after dependency/impact review

### Goal

Add opt-in VPN and secure-datagram discovery through the smallest
specification-valid exchanges that reliably elicit typed responses.

### Deliverables

- Implement IKEv2 `IKE_SA_INIT` on ports 500/4500 with exact initiator SPI,
  nonce, proposal, key-exchange, NAT-detection, cookie, message-ID, and NAT-T
  marker handling required by the accepted exchange.
- Consider IKEv1 only as a separate variant after its own impact and parser
  review; never silently fall back across versions.
- Implement DTLS ClientHello discovery only on reviewed DTLS service ports, with
  cookie/HelloRetryRequest handling when necessary and without completing
  application authentication.
- Exact-pin any new cryptographic crate with minimum features after license,
  advisory, constant-time, binary-size, allocation, platform, and maintenance
  review. Prefer existing reviewed primitives where correct.
- Zeroize secret ephemeral material where it is actually secret, bound state
  lifetime and CPU work, pace per host, and cancel/close partial handshakes
  exactly once.
- Require `statefulHandshake`; add `highAmplification` or other consents based
  on measured impact. Do not add OpenVPN, RADIUS, or WireGuard approximations.

### Tests and exit gate

Independent responder matrices cover algorithm/cookie/version negotiation,
NAT-T, wrong SPI/message/epoch/sequence, fragments, retransmission, malformed
payload chains/extensions, CPU/byte ceilings, dependency audits, fuzzing,
sanitizers, memory zeroization where testable, cancellation, and Worker
teardown. Each accepted handshake must improve service discovery enough to
justify its dependency and target cost; otherwise that family remains blocked
without preventing the phase report from recording the no-go.

## Phase 42 — DHCP topology discovery

Status: closed host-namespace no-go on 2026-07-14; isolated implementation not
shipped

### Goal

Add explicitly scoped network-configuration discovery as a topology operation,
not as a per-host UDP port probe.

### Deliverables

- Implement DHCPv4 INFORM and DHCPv6 Information-request only where the primary
  standards permit a non-address-allocation request from the host's current
  configuration.
- Require explicit interface, family, `fixedSourcePort`, `multicastOrBroadcast`,
  and `sensitiveRead` consent.
- Coordinate source-port ownership per network namespace and fail clearly if
  another socket/policy prevents exclusive or safe coexistence. Do not disrupt
  the host DHCP client.
- Never send DISCOVER, REQUEST, RELEASE, DECLINE, or another message that seeks
  or changes an address lease.
- Use the minimum standards-valid client identity. Correlate DHCPv4 with exact
  message type, transaction ID, current interface/address, and client identity
  fields actually sent; correlate DHCPv6 with exact message type, transaction
  ID, interface/scope, source port, and client identifier when present. Do not
  fabricate a MAC address or stable DUID merely to increase response rate, and
  record a server that requires unavailable identity as unsupported rather than
  weakening correlation.
- Strictly parse bounded option sets and expose network context such as DNS,
  domain search, NTP, routers, and server identity with per-field provenance.
- Keep observations separate from the read-only kernel context snapshot; do not
  mutate routes, addresses, resolvers, leases, or interface configuration.

### Tests and exit gate

Use disposable namespaces with independent DHCPv4/v6 responders, source-port
conflicts, multiple servers, relay information, malformed/duplicate/oversized
options, interface changes, cancellation, capture proving INFORM/Information-
request only, syscall tracing proving no network configuration writes, and
complete fuzz/sanitizer/resource gates. If coexistence with the host client
cannot be guaranteed, the public API must require isolated namespace ownership
or keep DHCP blocked.

## Phase 43 — Specialized opt-in discovery packs

Status: closed no-go on 2026-07-14; candidates did not pass the admission gate

### Goal

Add useful specialized coverage without making obscure protocol count a release
metric or accepting reverse-engineered payloads without a stable ownership
story.

### Candidate order

1. GTPv1/GTPv2 Echo for explicitly selected carrier-network targets.
2. MQTT-SN gateway discovery where unicast or explicitly consented
   multicast/broadcast behavior is specification-valid.
3. Beckhoff ADS discovery when official vendor documentation and an independent
   responder/permissioned fixture support a non-mutating request.
4. Other industrial UDP families, such as Omron FINS, only after the same
   specification, safety, and fixture gate.
5. Optional game/voice packs such as TeamSpeak, Mumble, or additional
   Quake-family discovery only when measured user value justifies maintenance.

### Admission gate for every candidate

- stable primary or protocol-owner wire specification;
- independently authored request, parser, and fixtures;
- non-mutating semantics and honest authentication/sensitive-read
  classification;
- bounded amplification, parser work, metadata, state, retries, and response
  fan-out;
- useful typed evidence beyond what empty UDP already establishes;
- namespace responder and exact packet-capture evidence;
- no new dependency unless its value exceeds supply-chain/binary cost; and
- an explicit implemented, unsafe-opt-in, superseded, or blocked ledger entry.

CLDAP, OpenVPN, RADIUS, Ubiquiti discovery, pcAnywhere, and WireGuard remain
blocked unless new authoritative specifications, permissioned fixtures, and a
non-credential/non-identity-bound discovery contract close their recorded
reasons. Malware/backdoor probes and exploit payloads remain out of scope.

### Exit gate

Every accepted specialized probe passes the same catalogue, parser, risk,
resource, lifecycle, and provenance gates as the core pack. A candidate no-go is
a successful outcome when its evidence is insufficient; the phase does not trade
safety or honest attribution for catalogue size.

## Phase 44 — Integrated audit, documentation, and release candidate

Status: implementation audit complete; publication remains blocked on external
namespace/release gates and native AArch64 execution

### Goal

Audit the complete advanced discovery architecture, freeze the supported public
surface, and prepare an unpublished `0.3.0-rc.1` candidate without weakening the
current scanner or its release claims.

### Deliverables

- Perform a line-by-line ownership, unsafe-code, parser, result-reservation,
  lifecycle, network-impact, dependency, and provenance audit.
- Freeze discovery schema 1 and any additive scan schema 3; retain exact schema
  1/2 decoding and catalogue semantic-version rules.
- Publish capability metadata listing implemented, opt-in, no-go, and blocked
  families plus exact resource ceilings and catalogue/schema identities.
- Document separate targeted scan and link/topology discovery examples, risk
  consent, root/capability requirements, interface scope, partial/truncated
  results, evidence strength, and network impact.
- Add end-to-end home/enterprise/IoT/VPN/carrier/industrial namespace matrices
  using only project-owned responders and fixtures.
- Complete hostile-input, fuzz, sanitizer, fault-injection, response-flood,
  slow-consumer, Worker, fd/RSS, benchmark, artifact, clean-consumer,
  reproducibility, ELF/GLIBC, and dependency/advisory gates.
- Run the complete release suite on native x86-64 and AArch64 glibc systems.
- Advance all scanner package/native target manifests together only after every
  declared platform and publication gate passes.

### Release claim rules

- Do not call multicast discovery authenticated unless the protocol proves it.
- Do not imply that discovery sees across routed boundaries when a protocol is
  link-local.
- Distinguish endpoint scanning, service discovery, and topology/configuration
  discovery.
- Publish exact implemented families and blocked/no-go candidates rather than a
  generic “all UDP protocols” claim.
- Retain the narrow Phase 33 Nmap comparison wording; advanced discovery is a
  project capability claim, not a new Nmap compatibility claim.
- Do not publish AArch64 artifacts or the complete package until native AArch64
  execution passes.

### Exit gate

All supported discovery operations are bounded, deterministic, correctly
attributed, documented, reproducible, and verifiably non-mutating on both native
architectures. The existing scan API and schemas retain their documented
behavior, and no blocked candidate is represented by a malformed approximation.

## Cross-phase verification matrix

| Boundary            | Required evidence                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| public API          | hostile TypeScript/native validation, immutable snapshots, exact lifecycle and compatibility    |
| discovery engine    | virtual time, one-to-many fan-out, terminal aggregation, deterministic truncation and replay    |
| network context     | namespace/interface anchoring, IPv6 scopes, route generation, interface removal and resync      |
| multicast/broadcast | exact group, interface, source port, hop limit, consent, rate, response window, cleanup         |
| derived endpoints   | target containment, graph bounds, cycles, provenance, reservation, parent/child schema          |
| alternate ports     | first-valid pin, same-target/interface, competing response, grace, teardown                     |
| protocol builders   | primary-spec golden bytes, entropy fields, exact lengths/checksums and packet capture           |
| parsers             | complete structure, query/transaction relationship, hostile bytes, fuzzing and work caps        |
| stateful probes     | CPU/byte/state lifetime, dependency/crypto review, cancellation and secret cleanup              |
| results             | sealed batches, row/metadata reservation, schemas 1/2 compatibility, transfer and slow consumer |
| impact              | independent risk consent, amplification, fixed-source ownership, non-mutation and syscall trace |
| release             | x64/AArch64 native execution, advisories, licenses, ELF/GLIBC, consumers and reproducibility    |

## Phase ordering and stop conditions

| Phase | Depends on                                     | Blocking exit condition                                                   |
| ----: | ---------------------------------------------- | ------------------------------------------------------------------------- |
|    34 | Phase 33 audit, D-049, closed readiness review | fan-out ownership, schema, bounds, and lifecycle are frozen               |
|    35 | 34                                             | mDNS/DNS-SD works across bounded dual-stack multi-responder scopes        |
|    36 | 35                                             | WS-Discovery/LLMNR reuse the engine with bounded XML/DNS parsing          |
|    37 | 36                                             | derived work cannot escape caller target/resource scope                   |
|    38 | 37                                             | alternate-port pinning resists spoofing/races and tears down exactly once |
|    39 | 38                                             | each high-yield candidate is valid, useful, non-mutating, and consented   |
|    40 | 39                                             | QUIC VN works without inflated authentication/application claims          |
|    41 | 40                                             | accepted IKE/DTLS value exceeds state/dependency/impact cost              |
|    42 | 36; sequenced after 41                         | DHCP cannot disturb host configuration or port ownership                  |
|    43 | all required architecture phases               | each specialized candidate independently passes or records no-go          |
|    44 | 34–43                                          | integrated native x64/AArch64 release and audit gates pass                |

Do not combine the fan-out foundation, its first protocol, derived endpoints,
alternate-port correlation, and cryptographic handshakes into one implementation
phase. A defect in parser completeness, scope attribution, resource reservation,
network impact, lifecycle, or provenance blocks the dependent phase until fixed
and reverified.

Phase 43 candidates are independent and may no-go without preventing Phase 44.
Phases 34 through 40 are the required capability path. Phase 41 may record a
protocol-specific no-go if dependency or impact evidence is unfavorable. Phase
42 may remain namespace-only if safe host coexistence is not proved.

## Required Phase 34 readiness review questions

Closed on 2026-07-14 by
[`54-advanced-udp-discovery-plan-review.md`](54-advanced-udp-discovery-plan-review.md).
The review answered these questions and made its binding corrections directly in
this plan:

1. Is a separate discovery session preferable to extending `ScanPlan` for every
   one-to-many operation, are its link/target scopes exact, and is shared
   runtime ownership unambiguous?
2. Does discovery schema 1 represent partial and terminal entities without
   mutable rows or unbounded native aggregation?
3. Are interface selection, IPv6 scope, namespace anchoring, multicast group
   ownership, and hop-limit validation exact?
4. Is every responder, record, entity, metadata byte, parser token, and physical
   query reserved and rate-charged before work?
5. Does pause/cancel/close/backpressure stop new transmission without dropping a
   promised terminal result?
6. Can mDNS query expansion remain bounded without silently missing or merging
   same-name services from different interfaces?
7. Is the proposed XML strategy safe, dependency-light, non-networking, and
   hostile-input bounded?
8. Does the derived endpoint graph preserve the original target allowlist and
   express parent/child results compatibly?
9. Is alternate-port first-response pinning honest about spoofing and evidence
   strength?
10. Are QUIC, IKE, DTLS, Kerberos, DHCP, and specialized candidates separable so
    one no-go cannot force a malformed approximation or block safe progress?
11. Are versioning, capability reporting, migration, and the proposed
    `0.3.0-rc.1` release story explicit?
12. Can every privileged topology be reproduced without Internet services,
    third-party scanners, or unlicensed fixtures?

## Provenance and primary research basis

The Phase 27–33 prohibition on importing or deriving distributed content from
Nmap source/data remains in force. The local Nmap checkout may inform private
behavioral comparison only. Every request, parser, port association, fixture,
and service field must come from a primary standard, protocol-owner document,
IANA registry, permissively licensed implementation documentation, or a
permissioned project-owned capture.

Initial primary sources for readiness review are:

- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html) and
  [RFC 6763 — DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763.html);
- [OASIS WS-Discovery 1.1](https://docs.oasis-open.org/ws-dd/discovery/1.1/wsdd-discovery-1.1-spec.html)
  and the
  [Devices Profile for Web Services 1.1](https://docs.oasis-open.org/ws-dd/dpws/1.1/os/wsdd-dpws-1.1-spec-os.html);
- [RFC 4795 — LLMNR](https://www.rfc-editor.org/rfc/rfc4795.html);
- [RFC 1833 — Binding Protocols for ONC RPC](https://www.rfc-editor.org/rfc/rfc1833.html),
  [RFC 5531 — RPC](https://www.rfc-editor.org/rfc/rfc5531.html), and
  [RFC 1813 — NFSv3](https://www.rfc-editor.org/rfc/rfc1813.html);
- [RFC 1350 — TFTP](https://www.rfc-editor.org/rfc/rfc1350.html);
- [RFC 6886 — NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886.html);
- [Microsoft SQL Server Resolution Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/);
- [RFC 4120 — Kerberos V5](https://www.rfc-editor.org/rfc/rfc4120.html);
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000.html),
  [RFC 8999 — QUIC invariants](https://www.rfc-editor.org/rfc/rfc8999.html),
  [RFC 9368 — QUIC version negotiation](https://www.rfc-editor.org/rfc/rfc9368.html),
  and [RFC 9369 — QUIC v2](https://www.rfc-editor.org/rfc/rfc9369.html);
- [RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html) and
  [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html);
- [RFC 2131 — DHCPv4](https://www.rfc-editor.org/rfc/rfc2131.html) and
  [RFC 8415 — DHCPv6](https://www.rfc-editor.org/rfc/rfc8415.html);
- the applicable 3GPP GTP specifications, reviewed from the official 3GPP
  archive before implementation; and
- an accepted MQTT-SN protocol-owner specification and official industrial
  vendor specifications before a Phase 43 candidate is admitted.

Specification URLs alone are not implementation approval. Each phase records the
exact revision/section, fixture provenance, wire review, impact review, and
reviewer before assigning a stable project ID.
