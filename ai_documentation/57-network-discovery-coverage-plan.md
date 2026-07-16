# Network discovery coverage expansion plan

Status: accepted planning contract; Phases 46–57 reopened and hardened under
D-056; readiness review closed  
Date: 2026-07-15  
Planned phases: 45 through 58  
Next implementation phase: none; Phase 58 awaits native AArch64 execution on an
available host

The second post-implementation adversarial pass and its repairs are recorded in
`61-phases-46-57-adversarial-repair-report.md`. That report is authoritative
where it corrects an earlier implementation description.

## Objective

Evolve `@opsimathically/nodenetscanner` from a strong active endpoint scanner
and finite link-discovery client into a provenance-preserving network discovery
platform. The expanded scanner should discover endpoints that do not answer
unsolicited probes, identify useful TCP services, describe routers and paths,
turn already-authorized observations into narrowly governed follow-up work,
reconcile evidence over time, and combine observations from multiple vantage
points.

The work must preserve the existing package boundary and performance model:

- `@opsimathically/nodenetraw` remains a policy-free low-level raw networking
  module;
- `@opsimathically/nodenetscanner` owns discovery policy, its descriptors, and
  its Rust data plane without calling `nodenetraw` through JavaScript;
- one native scanner addon links modular internal Rust crates and protocol
  registries, avoiding repeated N-API crossings or multiple native engines;
- TypeScript remains the strict, zero-runtime-dependency public control and
  presentation layer; and
- existing scan schemas 1/2, UDP catalogue `1.3.0`, discovery schema 1, and
  discovery registry `1.0.0` remain readable and behaviorally stable.

This roadmap improves discovery coverage. It does not turn the package into a
vulnerability scanner, credential tester, exploitation framework, packet
recorder, general-purpose web crawler, or network-management controller.

## Implemented baseline

Before Phase 45, the scanner already provides:

- live ARP, NDP, ICMPv4/v6 Echo, TCP SYN, and UDP target scans;
- a bounded 33-variant protocol-aware UDP catalogue with explicit risk policy;
- finite discovery sessions for legacy-unicast mDNS/DNS-SD, WS-Discovery,
  explicit-name LLMNR, NAT-PMP, SQL Browser, rpcbind/NFS, TFTP, and QUIC Version
  Negotiation;
- one registered same-target derived NFS child and registered-only alternate
  response-port correlation;
- bounded deterministic scheduling, native batching, backpressure, lifecycle,
  context snapshots, route selection, and structured evidence; and
- explicit no-go outcomes for operations whose coexistence, identity,
  dependency, impact, or responder gates were not met.

The important remaining coverage gaps are passive-only devices, TCP application
identity, router/path topology, cross-protocol enrichment, durable device
identity, longitudinal change, specialized service semantics, and observation
from more than one link.

## Governing architecture

### Evidence is the integration boundary

Phase 45 must freeze one additive internal evidence model before another live
protocol is implemented. Existing scan and discovery rows are immutable source
records. Adapters may project them into the evidence model, but must retain the
source schema/version, stable source record identity, raw bounded supporting
fields, and exact provenance. Existing result decoders are not replaced.

The model must represent at least:

- device candidates;
- physical or virtual interfaces;
- link-layer, IPv4, and IPv6 addresses with interface/scope;
- names and name sources;
- services, transports, ports, advertised endpoints, and negotiated traits;
- routers, prefixes, routes, path hops, adjacencies, and link membership;
- protocol observations and parent/child derivations;
- classifications with explicit supporting evidence; and
- appearance, expiry, withdrawal, conflict, and change observations.

Every fact carries a stable evidence ID, source kind and version, sensor and
interface scope, observation time, optional protocol lifetime/expiry,
confidence/evidence strength, parsed-versus-inferred disposition, and bounded
supporting data. Wall-clock time is presentation and cross-sensor context;
monotonic time owns local deadlines and ordering. Untrusted clocks must never
silently decide identity or freshness.

Exact duplicates coalesce deterministically. Conflicts are retained and
reported; last-writer-wins is not an identity rule. A hostname, OUI vendor,
certificate name, or shared service alone can never merge two devices. Strong
identifiers such as a MAC address, LLDP chassis ID, SMB server GUID, SNMP engine
ID, or UPnP UDN remain scoped to the protocol and observation context in which
they are valid. The model must support ambiguity rather than invent certainty.

### Separate session semantics

The public scanner retains distinct work types:

- `ScanSession`: finite target/probe products and target results;
- `DiscoverySession`: finite query/fan-out operations and terminal discovery
  entities;
- planned `ObservationSession`: finite passive collection yielding immutable
  append-only observations while it is running; and
- planned path/service operations: finite active work that may use the scan
  scheduler but has its own typed result contract where a target row is not an
  honest representation.

Phase 45 must decide the exact public entry points and naming. No session may
mutate a previously delivered JavaScript object. Incremental observation uses
append-only fact, expiry, and withdrawal records; it does not retrofit mutable
updates onto discovery schema 1. Every session keeps the established
already-running return, worker-ordered pause/resume/cancel, abortable pull,
bounded event adapter, summary, close, Worker teardown, and exactly-once
settlement conventions.

### Derived authority is never inherited from packet data

Received names, addresses, ports, URLs, SRV records, XML fields, certificate
names, redirects, and routing advertisements are attacker-controlled evidence.
They do not grant scanning authority.

The Phase 45 derived-work policy must enforce:

- original normalized allowlists and exclusions on every child;
- same-address follow-up by default;
- separately explicit same-device/different-address authority, disabled by
  default and unavailable until identity confidence and scope rules are proved;
- registered parent evidence kinds and registered child operations only;
- deterministic cycle and duplicate suppression;
- bounded graph depth, per-parent fan-out, per-target work, global child work,
  live correlations, rows, bytes, CPU, and elapsed time;
- independent risk consent for the child operation; and
- complete parent, evidence, policy, and transmission provenance in results.

URL processing defaults to metadata only. An admitted fetch must reject
userinfo, unsupported schemes, ambiguous literals, invalid zone identifiers,
cross-address redirects, DNS rebinding, target/exclusion escape, and responses
over its byte/content/decompression/parser limits. No redirect is followed by
default.

### Passive observation is metadata discovery, not packet recording

The initial passive API exposes typed bounded metadata and only the minimum
bounded bytes required for an explicit unsupported/malformed diagnostic. It does
not expose a general packet-capture stream or retain application payloads.
Promiscuous membership is a separate explicit permission and is disabled by
default. Capture scope is an explicit interface and address family/link protocol
set.

Passive results are visibility-qualified. A missing observation never means a
device or service is absent, and switched links normally expose only local,
broadcast, multicast, and traffic delivered to the sensor. Documentation and
result summaries must report capture mode, interfaces, filters, drops, limits,
and observation duration.

### Component ownership

- `crates/nodenet-protocols` owns syscall-free bounded codecs, semantic
  decoders, canonical identity bytes, protocol risk/provenance entries, and
  hostile-input fuzz surfaces.
- `crates/nodenet-linux-context` owns read-only route/rule/link/address/neighbor
  context and any separately admitted read-only Linux context providers.
- `crates/nodenetscanner-engine` owns evidence normalization, authority,
  reconciliation, classification rules, derived scheduling, lifecycle, exact
  reservations, and virtual transport/time tests.
- `crates/nodenetscanner-native` owns AF_PACKET, ordinary TCP/UDP, raw control
  sockets, epoll/timers, optional packet rings, capture filtering, descriptor
  lifetime, native bounded storage, and N-API delivery.
- `packages/nodenetscanner` owns strict plans, views, public errors, session
  adapters, capability reporting, and documentation. It must not reparse native
  packets or implement a second scheduler.

### Capability and versioning contracts

Every active probe, passive decoder, context provider, enrichment rule,
classifier, and sensor-envelope version has a stable registry identity,
provenance, scope, risk, bounds, and capability disposition. Implemented,
experimental, disabled, and no-go are distinct. Profile breadth never supplies
risk consent.

An evidence-batch version is independent from scan schema, discovery schema, UDP
catalogue, and discovery-operation registry versions. Additive result columns
require retained old decoding; incompatible identity or settlement semantics
require a new schema version. Capability reports must make compiled,
runtime-available, permission-blocked, and policy-disabled distinguishable.

## Safety, privacy, and resource contract

### Risk classes

Phase 45 must reconcile these proposed additions with the current canonical risk
vocabulary:

- passive link metadata;
- promiscuous capture;
- active link multicast/broadcast;
- server-first service observation;
- client-initiated service negotiation;
- stateful handshake;
- sensitive metadata read;
- authentication attempt; and
- target-impacting or configuration-changing work.

The roadmap admits no authentication attempt or configuration-changing action.
Credentials, brute force, default-password checks, anonymous-login attempts,
write operations, SOAP control actions, lease mutation, and vulnerability
payloads remain outside scope. A protocol candidate that cannot provide useful
discovery without those actions records a no-go.

### Candidate ceilings to benchmark and freeze

Exact constants are a Phase 45/46 deliverable, but the review must start from
finite conservative ceilings:

- scan, discovery, observation, path, and service sessions share one combined
  per-environment admission limit and native metadata budget;
- passive capture has finite duration, frames inspected, captured bytes,
  accepted observations, parser work, and kernel/user ring memory;
- suggested initial passive defaults are a 30-second duration, 4 KiB snap
  length, 8,192 retained observations, and 16 MiB retained metadata, with hard
  maxima no greater than 16 KiB snap length, 1,000,000 inspected frames, 64 MiB
  captured bytes, and the existing combined 64 MiB environment metadata cap;
- capture rings, if selected, remain native-owned, bounded, copied before N-API,
  and counted against one environment ring ceiling;
- TCP negotiation has finite simultaneous connects, per-host connects,
  write/read messages, bytes, parser work, redirects, handshake lifetime, and
  total sockets; and
- derived work reserves rows, metadata, correlations, sockets, packets, bytes,
  and CPU before irreversible network work.

These are planning upper bounds, not promises. Phases must lower them when
stress evidence warrants it. Pulling a batch never replenishes a lifetime
network-work or Node-retainable-output budget.

### Namespace and privilege boundary

Passive AF_PACKET work requires Linux raw-packet privilege and must fail with a
stable capability/permission error when unavailable. Ordinary TCP and UDP
operations must not open raw sockets unnecessarily. No library worker calls
`setns` in a multithreaded Node process. A sensor for another network namespace
must start inside that namespace or use an external application-owned process.

## Phase 45 — Evidence model and derived-work policy

Status: complete on 2026-07-15

### Goal

Freeze the common evidence, identity, authority, schema, registry, lifecycle,
and reservation contracts without adding network traffic.

### Deliverables

- Define stable Rust and TypeScript evidence vocabularies for entities,
  relations, source records, observations, confidence, conflict, expiry,
  withdrawal, and classification support.
- Implement pure adapters for retained scan schemas 1/2 and discovery schema 1;
  the original source records remain recoverable and no confidence is upgraded.
- Specify deterministic canonical keys and conservative merge/split rules for
  address, interface, device, service, router, and path evidence.
- Generalize the existing same-target derivation graph into a registered
  policy-evaluated authority engine while preserving Phase 37 behavior.
- Freeze append-only evidence batch ownership, hostile TypeScript validation,
  maximum row/field/string/byte/relation counts, and old-version decoding.
- Add capability registry shapes for passive decoders, service handshakes,
  context providers, classifiers, and sensor envelopes.
- Record exact environment/session/resource interactions and the initial risk
  vocabulary in the decision log.
- Add no live descriptor, socket, capture, or protocol transmission.

### Tests

- Deterministic replay produces byte-identical evidence independent of source
  batch order where protocol order has no meaning.
- Conflicting MAC/IP/name/service observations remain visible and cannot merge
  through weak evidence alone.
- Cycles, duplicate derivations, target/exclusion escape, risk escalation,
  depth/fan-out excess, and budget exhaustion fail before child admission.
- Hostile offsets, counts, UTF-8, canonical bytes, timestamps, relationships,
  schema versions, and retained legacy rows fail closed in Rust and TypeScript.
- Property tests prove reservations release exactly once under cancel, close,
  panic containment, saturation, and Worker teardown.

### Exit gate

The evidence model can losslessly project all current scanner outputs, express
ambiguity and expiry, and reject unauthorized derived work without changing any
existing wire behavior or public result semantics.

## Phase 46 — Passive observation session and Linux capture foundation

Status: complete on 2026-07-15

### Goal

Add a finite, bounded, metadata-only passive observation session over Linux
AF_PACKET with exact lifecycle, privilege, filtering, and resource behavior.

### Deliverables

- Add the reviewed `ObservationPlan`/`ObservationSession` public API and native
  session implementation with explicit interfaces, duration, protocol groups,
  capture mode, limits, pause/resume/cancel/pull/progress/summary/close, and
  optional bounded event batches.
- Use nonblocking AF_PACKET descriptors integrated with the environment reactor.
  Benchmark `recvmmsg` against a copied receive-only TPACKET_V3 path before
  selecting rings; never expose mmap-backed memory through N-API.
- Attach generated bounded classic BPF or separately reviewed eBPF filters;
  validate the generated program and keep a userspace protocol guard.
- Freeze fragment handling before passive protocol decoding. Either report IP
  fragments as bounded topology evidence without parsing an incomplete upper
  layer, or implement a separately budgeted per-interface IPv4/IPv6 reassembly
  cache with exact tuple keys, fragment/byte/flow/time ceilings, deterministic
  overlap rejection, atomic completion, and cancellation cleanup. Partial
  datagrams must never enter a service parser.
- Disable promiscuous membership by default. Request it only through separate
  explicit consent and report whether it was actually enabled.
- Prefer `PACKET_IGNORE_OUTGOING` where supported and record outgoing inclusion
  otherwise. Preserve VLAN, packet type, interface, timestamp, original length,
  captured length, and truncation/drop counters.
- Avoid one uncontrolled `ETH_P_ALL` copy stream per protocol. Phase 46 must
  choose and prove either an environment-owned per-interface capture hub with
  exact per-session demultiplexing or a finite per-session descriptor design
  whose duplication ceiling is lower and measured.
- Deliver only immutable bounded observation batches. General raw frame export
  remains unavailable.

### Tests

- Synthetic reactor tests cover zero traffic, floods, malformed frames,
  truncation, pause drainage, cancellation, close, descriptor rollback, callback
  failure, panic containment, and Worker teardown.
- Namespace tests prove explicit interface attribution, VLAN handling, outgoing
  filtering, non-promiscuous default, optional promiscuous membership,
  permission failure, context invalidation, and no traffic transmitted.
- Packet captures and syscall traces prove filter installation, membership,
  ring/descriptor cleanup, and no socket mutation outside the selected link.
- Slow-consumer, fd/RSS, ring corruption, parser budget, and concurrent
  scan/discovery/observation saturation tests remain within combined ceilings.

### Exit gate

A privileged finite observation session can safely watch selected links and emit
bounded append-only metadata without sending traffic, retaining payloads,
blocking Node, leaking descriptors, or overstating visibility.

## Phase 47 — Passive host and service discovery pack

Status: complete on 2026-07-15

### Goal

Discover otherwise silent endpoints from common link-local naming,
configuration, and service advertisements already present on the wire.

### Deliverables

- Add passive decoders and evidence mappings for ARP, IPv6 NS/NA, DHCPv4,
  DHCPv6, mDNS/DNS-SD, LLMNR, NBNS, SSDP, and WS-Discovery.
- Reuse current strict DNS and XML primitives where their receive assumptions
  remain valid. Passive decoders have their own source/scope/correlation rules
  and do not pretend an outstanding local transaction exists, but they must not
  weaken framing, namespace, compression, record, or size validation.
- Parse only discovery-relevant bounded DHCP fields such as assigned/client
  address evidence, server identity, host/client names, vendor class, requested
  options, DNS/search data, and lease lifetimes. Never expose authentication or
  opaque option payloads without a reviewed typed representation.
- Interpret mDNS cache-flush and goodbye semantics, DNS TTLs, SSDP cache
  lifetimes, WS metadata versions, and DHCP lease lifetimes as evidence expiry
  rather than permanent identity.
- Keep advertised URLs, names, addresses, and ports as metadata until Phase 53
  policy explicitly authorizes follow-up.

### Tests and exit gate

Project-owned dual-stack clients/responders in switched namespace topologies
must produce deterministic device/name/service evidence, correct TTL/withdrawal
records, and bounded conflicts under duplication, fragmentation, malformed
compression/XML/options, flood, and packet loss. No passive observation may
schedule active work.

## Phase 48 — Link and IPv6 control-plane topology

Status: complete on 2026-07-15

### Goal

Discover routers, prefixes, adjacent infrastructure, multicast membership, and
local control-plane relationships rather than only endpoints.

### Deliverables

- Complete passive IPv6 RS/RA/Redirect parsing and add an explicit active Router
  Solicitation operation with exact interface/source/hop-limit ownership.
- Parse bounded RA router lifetime/preference, Prefix Information, MTU, Route
  Information, RDNSS, DNSSL, captive-portal, and unknown-option diagnostics.
- Add passive LLDP with chassis/port/system identity, capabilities, management
  addresses, VLAN-related typed fields where standardized, and TTL withdrawal.
- Evaluate CDP independently behind a proprietary-protocol provenance and
  fixture gate; a no-go does not block LLDP.
- Add bounded passive STP/RSTP/MSTP, LACP, VRRP, IGMP/MLD, RIP, and OSPF
  presence/topology decoders where primary specifications and safe parsing
  provide useful evidence. Do not participate in elections, adjacencies, or
  routing.
- Expose complete bounded read-only route, rule, and neighbor records through a
  versioned context view rather than only summary counts.
- Detect address conflicts and router/prefix/DNS changes as evidence; do not
  modify kernel neighbor, route, address, or resolver state.

### Tests and exit gate

Isolated bridge/router namespaces and project-owned control-packet fixtures must
yield correctly scoped routers, prefixes, neighbors, adjacencies, and lifetimes
without accepting off-link RA/LLDP traffic, invalid IPv6 hop limits/checksums,
or malformed nested options. Active RS must be the only transmitted operation
and must require explicit link-multicast authority.

## Phase 49 — Scanner-native path discovery

Status: complete on 2026-07-15

### Goal

Promote TTL/hop-limit probing into bounded scanner-native IPv4/IPv6 path and
router discovery.

### Deliverables

- Add finite ICMP Echo, UDP, and TCP SYN trace modes with explicit targets,
  ports where applicable, first/max hop, attempts, deadlines, pacing, and stop
  policies.
- Reuse protocol quote/correlation primitives and preserve weak, strong,
  unreachable, administratively filtered, timeout, and destination-reached
  evidence separately.
- Emit path runs, ordered hop observations, per-attempt RTT, responding address,
  quoted correlation strength, destination status, and partial/truncated state.
- Model multiple responders at one hop without pretending a single run maps all
  ECMP paths. A future Paris-style mode requires a separate flow-identity
  review.
- Feed router/hop evidence into the common model without merging a hop into a
  destination device solely by address reuse or reverse DNS.
- Keep reverse DNS optional, separately budgeted, and governed by the Phase 53
  resolver policy.

### Tests and exit gate

Routed namespace topologies must prove IPv4/IPv6, UDP/ICMP/TCP termination,
silent hops, filtering, multiple responders, route change, cancellation, exact
deadlines, source-lane isolation, late grace, and bounded result settlement. No
mode may continue after its declared destination or resource stop condition.

## Phase 50 — Bounded TCP conversation engine

Status: complete on 2026-07-15

### Goal

Create a reusable ordinary-kernel-TCP engine for low-impact service identity
without embedding ad hoc socket loops in each protocol.

### Deliverables

- Add internal declarative/state-machine conversation plans with bounded
  connect/write/read/shutdown transitions, exact deadlines, cancellation, parser
  work, and terminal evidence.
- Use nonblocking ordinary `SOCK_STREAM` descriptors in the scanner runtime; do
  not implement application negotiation over the raw SYN scanner and do not
  consume libuv workers with blocking connections.
- Freeze global, session, host, and target-port connection concurrency, byte,
  message, retry, redirect, lifetime, and completion reservations.
- Support server-first, fixed-request, and bounded negotiated exchanges while
  forbidding authentication, STARTTLS downgrade ambiguity, unrestricted proxy
  use, or general user-supplied scripts.
- Register each conversation with exact request bytes/state generation, response
  parser, eligible ports, evidence strength, risk, provenance, and resource
  maxima. Custom arbitrary TCP payloads remain outside the high-level scanner
  API unless separately reviewed.
- Make confirmed SYN-open evidence an optional scheduling hint, never a truth
  requirement; direct advertised endpoints may authorize a connection under the
  same target policy.

### Tests and exit gate

Virtual and namespace servers must prove partial reads/writes, segmentation,
early FIN/RST, connect errors, banners split across records, slowloris behavior,
oversized input, parser failure, cancellation, fd reuse, fairness, and exact
reservation release. The engine itself ships no service claim until a protocol
probe passes Phase 51 or 52 admission.

## Phase 51 — Low-impact TCP identity pack

Status: complete for admitted candidates on 2026-07-15; TLS is an executable
no-go

### Goal

Cover common TCP services with server-first or minimal standards-valid
negotiation and no credentials.

### Candidate order

1. SSH identification exchange.
2. FTP, SMTP, POP3, and IMAP server greetings without login or commands beyond
   the minimum required to establish a typed greeting.
3. TLS ClientHello with bounded certificate-chain metadata, negotiated version,
   ALPN, and alert evidence; SNI only from an already authorized discovered or
   caller-supplied name.
4. HTTP `HEAD` with strict message framing and no redirects; a bounded `GET` is
   a separate sensitive-read option.
5. MySQL initial server handshake and other genuinely server-first database
   greetings that require no client identity.

### Deliverables and exit gate

Every candidate independently needs a primary specification or authoritative
implementation contract, project-owned responder, strict parser, exact port
eligibility, useful typed output, and a justified risk disposition. Results must
distinguish a banner, syntactically valid handshake, certificate, and
authenticated application identity. No request sends credentials, mail commands,
shell data, HTTP bodies, or database authentication material.

TLS is not implemented with project-authored cryptography. Its candidate must
pass an exact-pinned mature TLS/X.509 dependency review covering features,
entropy, certificate/decompression/allocation bounds, advisory history, license,
binary size, platform support, cancellation, and whether the minimum useful
handshake can stop without validating a caller trust policy.

The default TCP identity profile contains only candidates demonstrated to be
low-impact and non-sensitive; all others remain explicit opt-in or no-go.

## Phase 52 — Extended opt-in TCP service discovery

Status: complete on 2026-07-15; PostgreSQL and Redis admitted, other candidates
are executable no-go

### Goal

Add high-value stateful or metadata-reading TCP negotiations under explicit
independent consent.

### Candidate order

- SMB2 Negotiate and bounded server GUID/dialect/security evidence;
- RDP negotiation response without CredSSP or login;
- PostgreSQL SSLRequest capability evidence;
- Redis `PING`;
- MongoDB `hello`;
- LDAP RootDSE read; and
- explicitly reviewed service-specific candidates justified by the capability
  ledger rather than port popularity alone.

### Admission and exit gate

Each candidate must independently classify stateful-handshake, sensitive-read,
amplification, authentication-attempt, and target-impact behavior; define exact
request/response/CPU ceilings; and prove cleanup against a project-owned
responder. LDAP RootDSE, MongoDB metadata, SMB identity, or similar disclosures
must never enter the safe default implicitly. Any operation that requires an
anonymous bind, login, real tenant/database name, or configuration action
records a no-go rather than disguising authentication as discovery.

## Phase 53 — Governed cross-protocol enrichment

Status: complete on 2026-07-15; semantic enrichment is admitted and optional
active candidates that did not close their gates are executable no-go

### Goal

Use already discovered service evidence to schedule narrow, explainable
same-target enrichment without creating an uncontrolled crawler.

### Deliverables

- Add semantic mDNS/DNS-SD mappings for common SSH, HTTP(S), SMB, IPP/printer,
  AirPlay, Cast, HomeKit, and Matter service families while preserving unknown
  service/TXT data as bounded evidence.
- Add link-wide SSDP M-SEARCH and SLP discovery only after fan-out, coexistence,
  amplification, interface, and responder gates; keep existing unicast probes.
- Permit an optional same-responder SSDP `LOCATION` or WS-Discovery `XAddr`
  HTTP(S) description fetch under the strict Phase 45 URL policy. Parse bounded
  UPnP device/service descriptions but invoke no SOAP control action.
- Add bounded unicast DNS PTR, SRV, and NAPTR enrichment and configured-domain
  DNS-SD browsing. DNS answers do not authorize targets outside the original
  scope.
- Expand rpcbind through an allowlisted bounded program/version/netid mapping
  view; child NULL exchanges remain independently registered and limited.
- Add optional CoAP `/.well-known/core` and gateway PCP/NAT-PMP/UPnP-IGD
  description evidence only with their required sensitive-read policy. Evaluate
  SNMP system/interface/LLDP-MIB reads, but retain them as no-go under the
  current no-credential boundary unless a later explicit decision admits
  caller-provided read-only community/user material. No mapping or control
  action is sent.
- Record every enrichment edge, transmitted request, redirect rejection, partial
  result, and risk decision in the evidence graph and summary.

### Tests and exit gate

Hostile advertised URLs, DNS rebinding, redirects, address-family changes,
scope-zone confusion, decompression bombs, XML/DNS cycles, excessive SRV fanout,
and cross-target data must fail before unauthorized I/O. An operator can disable
all enrichment and still receive the original evidence unchanged.

## Phase 54 — Asset reconciliation and explainable classification

Status: complete on 2026-07-15

### Goal

Turn protocol observations into conservative device/service candidates and
useful explainable classifications without hiding ambiguity.

### Deliverables

- Implement deterministic reconciliation across MAC, address, name, LLDP, DHCP,
  mDNS, TLS, SMB, SNMP, UPnP, and service evidence with explicit split, merge,
  conflict, and confidence reasons.
- Add versioned rules for classifications such as router, switch, printer,
  camera, Windows host, DNS infrastructure, smart-home device, and industrial
  controller. Every classification exposes positive and conflicting evidence.
- Add an optional MAC OUI vendor data artifact only after license, provenance,
  update, integrity, package-size, and reproducibility review. Vendor evidence
  is weak and never establishes identity or device type alone.
- Keep classifiers deterministic, inspectable, bounded, and data driven. No
  opaque model, Internet lookup, telemetry, or runtime registry download is
  introduced.
- Expose candidate assets and relations as derived views; original observations
  and conflicts remain available.

### Tests and exit gate

Golden evidence corpora must prove stable classification, ambiguity, multi-homed
hosts, address reuse, virtual MACs, proxies, load balancers, duplicate names,
shared certificates, and conflicting vendors. A rule cannot claim a class unless
its evidence and confidence are visible to the caller.

## Phase 55 — Longitudinal inventory and local context providers

Status: complete on 2026-07-15; optional providers are executable no-go

### Goal

Discover change over time and incorporate useful read-only facts already known
to the local Linux host without forcing a database or daemon dependency.

### Deliverables

- Define bounded snapshot/delta import and export contracts with new, changed,
  expired, withdrawn, reappeared, and conflicted asset/service/topology events.
- Keep the scanner stateless by default. Provide a storage-adapter interface and
  deterministic reconciliation primitives; do not add a mandatory database or
  filesystem store.
- Add complete read-only neighbor/rule/context views and evaluate Linux
  `inet_diag` for local listening/connected socket inventory with an explicit
  local-host-only disposition.
- Evaluate optional Avahi and systemd-resolved cache/provider adapters to obtain
  full mDNS/resolver observations without competing for port 5353. Providers
  must be runtime optional and cannot become production dependencies.
- Evaluate `nl80211` wireless BSS/SSID/channel/security metadata as an explicit
  local radio context provider. The initial candidate may read an existing
  kernel BSS cache only; triggering active or directed wireless scans requires a
  separate network-impact review and consent. Never associate, authenticate,
  inject, or expose captured wireless payloads.
- Detect IP/MAC conflicts, new/lost devices and services, certificate changes,
  router/prefix/DNS changes, and topology movement with protocol-aware expiry
  and caller-configured grace.

### Tests and exit gate

Clock jumps, restart/import, corrupt snapshots, stale TTLs, reordered batches,
provider disappearance, daemon unavailability, large histories, and repeated
flaps must remain deterministic and bounded. Optional providers fail visibly
without weakening core scanning or adding a hidden system mutation.

## Phase 56 — Specialized opt-in discovery packs

Status: complete on 2026-07-15; candidates not already covered by admitted
protocol capabilities are executable no-go

### Goal

Add domain-specific coverage as modular registry packs without weakening the
core risk, provenance, parser, responder, and packaging bar.

### Candidate groups

- Printing: IPP capability/identity reads and printer DNS-SD semantics.
- Windows and media: richer SMB/WS evidence, RTSP identification, and admitted
  AirPlay/Cast/HomeKit/Matter semantic decoders.
- IoT and cameras: CoAP resource discovery and bounded ONVIF metadata follow-up.
- Network infrastructure: SNMP system/interface/LLDP-MIB views, passive LLDP,
  and any independently accepted CDP/control-plane decoders.
- Industrial/building: BACnet ReadProperty, EtherNet/IP identity enrichment,
  Modbus Encapsulated Interface device identification, OPC UA GetEndpoints, and
  independently reviewed S7/DNP3 identity exchanges.

### Admission and exit gate

Each candidate is independent. It requires a primary or authoritative public
wire contract, compatible license, project-owned parser and fixtures,
permissioned responder validation, non-mutating semantics, explicit risk, strict
bounds, stable typed evidence, and useful coverage beyond the existing UDP
marker. Proprietary ambiguity, authentication, unsafe device impact, or missing
responder evidence produces an executable no-go and does not block other
candidates.

## Phase 57 — Multi-vantage sensor interchange

Status: complete on 2026-07-15

### Goal

Allow applications to combine observations from sensors in different VLANs,
sites, containers, or network namespaces without building authentication, remote
execution, or a management server into the scanner.

### Deliverables

- Define a deterministic, versioned, bounded sensor envelope for evidence
  batches, capability snapshots, capture visibility, interface scope, sequence,
  local monotonic interval, wall-clock/uncertainty, truncation, and summary.
- Validate imported envelopes as untrusted input and preserve the caller-
  assigned sensor identity and source provenance through reconciliation.
- Provide transport-neutral encode/decode and fusion primitives. Applications
  own transport security, authentication, authorization, storage, deployment,
  and remote command policy.
- Do not expose an unauthenticated listener, accept remote scan plans, or invoke
  `setns`. A sensor process runs in its intended namespace and emits data only.
- Handle duplicate delivery, gaps, replay, clock skew, sensor restart,
  inconsistent interface names, and overlapping address spaces without silently
  coalescing separate networks.

### Tests and exit gate

Multi-sensor replay with duplicated and reordered envelopes, large clock skew,
identical RFC1918 addressing, sensor loss, corrupt fields, incompatible
versions, and bounded backpressure must preserve source separation and stable
results. No network service or trust policy is included in the package.

## Phase 58 — Integrated adversarial audit and release candidate

Status: all available x86-64 gates complete on 2026-07-15; native AArch64
execution remains an external publication gate

### Goal

Audit the complete discovery platform, document honest capability and visibility
claims, and prepare the next semantically appropriate unpublished release
candidate without bypassing the still-open Phase 44 external gates.

### Deliverables

- Freeze all new public APIs, registries, schemas, defaults, risk vocabulary,
  resource ceilings, capability/no-go entries, and migration notes.
- Conduct a cross-source identity and authority audit, passive privacy review,
  TCP state-machine review, URL/DNS expansion review, parser/dependency/license
  audit, and exact descriptor/buffer/callback/teardown review.
- Complete ordinary, unprivileged, privileged namespace, routed, VLAN,
  multicast, passive, TCP responder, topology, slow-consumer, fault-injection,
  fd/RSS, sanitizer, fuzz, benchmark, and reproducibility gates.
- Execute the native scanner suite and representative capture/TCP/topology
  matrices on both supported x86-64 and AArch64 glibc systems. Cross-compilation
  alone remains insufficient.
- Update end-user documentation with active, finite discovery, passive
  observation, topology, service negotiation, enrichment, classification,
  persistence-adapter, and sensor examples plus privilege and privacy guidance.
- State unsupported capture visibility, protocols, providers, architectures, and
  release gates explicitly. Do not claim Nmap compatibility, complete inventory,
  OS fingerprinting, vulnerability discovery, or authenticated service identity.

### Exit gate

All accepted features are bounded, explainable, correctly scoped, independently
risk-gated, reproducible, and verified on both declared native architectures;
all no-go and visibility limitations are executable and documented; existing
scan/discovery behavior remains compatible; and no earlier publication gate is
silently waived.

## Cross-phase verification matrix

Every phase uses the narrowest applicable subset and Phase 58 repeats the full
matrix:

- Rust unit, property, allocation, and deterministic replay tests;
- TypeScript type/API, hostile batch, lifecycle, and event-adapter tests;
- protocol parser/builder fuzzing with separate bounded fuzz crates;
- sanitizers and panic-boundary/fault-injection tests;
- project-owned ordinary TCP/UDP, raw, multicast, link-control, and malformed
  responders without depending on Internet services;
- Linux namespaces with veth, bridge, VLAN, routed IPv4/IPv6, multiple links,
  controlled packet loss/reordering, and packet-capture assertions;
- syscall traces for no unexpected writes, configuration mutation, namespace
  transitions, descriptor inheritance, or privilege expansion;
- concurrent scan/discovery/observation/path/service session saturation,
  slow-consumer backpressure, Worker teardown, fd/RSS, and long-duration tests;
- source provenance, license, advisory, binary-size, glibc baseline, artifact,
  clean-consumer, reproducibility, and native x86-64/AArch64 execution gates.

Captured third-party traffic is not committed as a fixture without an explicit
license and privacy review. Independent project-owned fixtures and responders
remain the default.

## Phase ordering and stop conditions

Phase 45 is the only next implementation phase, and only after a dedicated
readiness review closes the questions below. Phase 46 depends on its schema,
lifecycle, and resource decisions. Passive protocol phases depend on the capture
foundation. TCP protocol phases depend on the generic conversation engine.
Enrichment depends on the authority engine plus the relevant admitted protocol
operation. Classification and longitudinal views depend on stable evidence
semantics. Sensor interchange is last because it multiplies ambiguity and
untrusted-boundary concerns.

A later independent candidate may record a documented no-go without blocking the
roadmap. A foundational correctness failure blocks dependent work. Do not expand
breadth while any known descriptor lifetime, buffer lifetime, unbounded-parser,
authority-escape, identity-corruption, event-loop blocking, lossless-settlement,
fairness, panic-boundary, or teardown issue remains open.

## Required Phase 45 readiness review questions

1. Can every current scan and discovery row be represented without losing its
   source schema, correlation, confidence, conflict, or byte identity?
2. Are evidence, asset, observation, and result schemas named and versioned
   distinctly enough to avoid migration ambiguity?
3. Are identity merge rules conservative under NAT, proxies, virtual machines,
   containers, shared certificates, duplicate names, and address reuse?
4. Can expiry and withdrawal be append-only without mutating delivered rows or
   depending on a trustworthy wall clock?
5. Is every derived-work edge re-authorized against target scope, exclusions,
   risk, depth, fan-out, and resource reservations before I/O?
6. Do scan, discovery, observation, path, and service sessions share one exact
   environment admission and native memory model?
7. Does passive capture expose only typed metadata, default to non-promiscuous,
   report visibility/drop/truncation, and send no traffic?
8. Is ordinary TCP lifecycle integrated without raw-TCP reimplementation, libuv
   worker starvation, descriptor reuse, or unbounded slow peers?
9. Are URL, DNS, XML, certificate, DHCP, and advertised-endpoint inputs unable
   to escape authority or cause hidden network work?
10. Are optional data/provider dependencies licensed, pinned, reproducible,
    bounded, and absent from the production runtime unless their value wins the
    review?
11. Does sensor interchange remain transport neutral and avoid importing remote
    execution, authentication, or server scope into this package?
12. Are all public claims explicit about passive visibility, inferred identity,
    unauthenticated evidence, no-go protocols, and outstanding AArch64 gates?

## Primary research basis

Implementation must use current primary specifications and Linux documentation,
including at minimum:

- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
  and
  [Packet MMAP](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html);
- [RFC 4861 IPv6 Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861.html),
  [RFC 8106 RA DNS options](https://www.rfc-editor.org/rfc/rfc8106.html), and
  [RFC 8910 captive-portal identification](https://www.rfc-editor.org/rfc/rfc8910.html);
- [IEEE 802.1AB LLDP](https://standards.ieee.org/ieee/802.1AB/6047/);
- [RFC 6762 mDNS](https://www.rfc-editor.org/rfc/rfc6762.html),
  [RFC 6763 DNS-SD](https://www.rfc-editor.org/rfc/rfc6763.html), and
  [RFC 2782 DNS SRV](https://www.rfc-editor.org/rfc/rfc2782.html);
- [RFC 2131 DHCPv4](https://www.rfc-editor.org/rfc/rfc2131.html) and
  [RFC 8415 DHCPv6](https://www.rfc-editor.org/rfc/rfc8415.html);
- [RFC 5388 traceroute measurement model](https://www.rfc-editor.org/rfc/rfc5388.html);
- [RFC 9293 TCP](https://www.rfc-editor.org/rfc/rfc9293.html),
  [RFC 8446 TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html),
  [RFC 4253 SSH transport](https://www.rfc-editor.org/rfc/rfc4253.html), and
  [RFC 9110 HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html);
- [UPnP standards and architecture](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/);
- Linux route, neighbor, socket diagnostic, and wireless netlink specifications;
  and
- the primary public specification for every specialized protocol candidate.

Protocol implementations, fixtures, service classifications, or data artifacts
must not be derived from incompatible third-party source/data licenses. External
tools may inform black-box behavior only under the repository's existing
independent-authorship and non-distribution rules.
