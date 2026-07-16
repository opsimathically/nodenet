# UDP probe coverage expansion plan

Last updated: 2026-07-15

Status: implementation and adversarial repairs complete; report 66 closes the
review 65 repair order; native AArch64 execution remains an external Phase 69
publication gate

## Purpose

Phases 59 through 69 close the highest-value gaps found by comparing the
project's independently authored UDP capabilities with Nmap source commit
`10dfd2ff1cef6c1925232db45352149b659979b4`. The work is ordered by expected
network-discovery value, protocol safety, implementation confidence, and the
amount of reusable architecture it unlocks.

The comparison is behavioral research only. This project will not copy, parse,
generate from, load at runtime, translate, or redistribute Nmap probe bytes,
regular expressions, service names, or other data. Requests, parsers, fixtures,
and responders must be authored from primary protocol specifications or
authoritative upstream implementations under a separately reviewed licensing and
clean-room record.

The goal is better useful discovery coverage, not a larger payload counter.
Every candidate can independently finish as `admitted`, `implemented`, or
`no-go`. A no-go is the correct result when a stable contract, non-mutating
exchange, useful typed outcome, safe impact envelope, or project-owned live test
cannot be established.

## Baseline and claim boundary

At the comparison snapshot:

- Nmap defines 84 named UDP service probes; 83 are eligible as raw UDP scan
  payloads because `Sqlping` is marked `no-payload`.
- `nodenetscanner` catalogue `1.3.0` contains 33 target/port variants, with
  eight additional finite discovery operations outside that catalogue.
- A manual family-level comparison found approximately 29 direct or close
  behavioral analogues, 12 candidates represented by explicit blockers, and 43
  absent Nmap probe families. These figures are planning estimates, not byte,
  port, or fingerprint parity claims.
- Nmap's service-probe file also contains hundreds of UDP `match` and
  `softmatch` expressions. A valid request that elicits a datagram is not by
  itself equivalent to Nmap product/version fingerprinting.

Phase 59 must regenerate the comparison as a checked, human-reviewed capability
matrix. Public documentation must report at least these separate dimensions:

1. a request can be constructed and transmitted;
2. a response can be correlated and structurally validated;
3. typed service or topology evidence can be extracted;
4. a project-owned responder has passed live tests;
5. product/version identity is available, when independently justified; and
6. the capability is in a default, opt-in, or explicitly excluded policy tier.

No release may describe broad Nmap UDP parity unless an audit defines the exact
dimension and demonstrates it. The preferred claim remains narrower:
independently authored protocol-aware UDP discovery with explicit unsupported
families.

## Scope

This program may add:

- strict Rust codecs and response classifiers;
- dynamically correlated target/port variants;
- finite one-query/many-responder discovery operations;
- bounded stateful handshakes where a single datagram is not meaningful;
- typed evidence, service summaries, and explicitly authorized derived
  endpoints;
- additive catalogue, registry, schema, capability-ledger, policy, and
  documentation changes; and
- project-owned protocol responders and black-box comparison tooling.

This program does not add:

- credentials, authentication attempts, password or community guessing;
- vulnerability or exploit payloads;
- configuration, registration, lease acquisition, route mutation, peer
  announcement, file access, or other target mutation;
- automatic scanning of endpoints returned by a master server, routing table,
  DHT, or service response;
- Nmap data ingestion or a compatibility database derived from it;
- a malware command-and-control or backdoor scanner in normal profiles; or
- an unbounded crawler, routing-table participant, packet recorder, or daemon.

## Binding architecture

### Candidate admission state machine

Every candidate has an append-only capability-ledger record with one of these
states:

- `research`: no runtime bytes or public support claim;
- `admitted`: primary contract, ownership, impact, parser, result, and test
  design are approved, but runtime support is not yet claimed;
- `implemented`: all admission and verification gates pass; or
- `no-go`: the failed gate and reconsideration condition are explicit.

Moving to `implemented` requires all of the following:

- a stable primary wire contract or authoritative upstream implementation;
- a documented clean-room and license decision;
- an exact non-mutating request and bounded response grammar;
- meaningful typed evidence beyond “some UDP bytes arrived”;
- a correlation strategy resistant to stale, reflected, cross-target, and
  cross-subprobe responses;
- an impact classification and independently enforced consent;
- a project-owned responder with malformed, delayed, duplicate, truncated, and
  multi-datagram cases; and
- successful ordinary, privileged where applicable, fuzz, stress, cancellation,
  and teardown gates.

Marketing value, a copied magic byte string, or matching an Nmap probe name is
not an admission basis.

### Three execution models

Candidates must use the narrowest correct model:

1. **Target/port subprobe** — one explicit target and destination port, one
   logical scan result, and normal schema-2 physical-subprobe accounting.
2. **Finite discovery operation** — one explicit interface or destination can
   produce multiple responders or endpoints under discovery schema 1 and the
   shared environment reservation model.
3. **Bounded conversation** — a registered state machine owns correlation,
   retransmission, deadlines, and teardown when the protocol cannot safely be
   represented by a static payload.

Returned addresses are evidence, never authority. They may be exposed as bounded
derived-endpoint records, but scanning them requires a new application decision
and the existing derived-work checks for scope, exclusions, depth, fan-out,
duplicate suppression, risk, and capacity.

### Identity, catalogue, and schema rules

- Existing catalogue IDs 1–33 and discovery operation IDs remain immutable.
- New IDs are append-only and never reused, including after a no-go.
- Phase 59 selects additive catalogue and registry versions. A minor version is
  used when wire/public semantics remain compatible; a major version requires an
  explicit migration and retained decoder plan.
- Logical results retain one target/port identity even when several physical
  variants run. Every physical send is separately rate-, byte-, retry-, result-,
  and memory-charged.
- Request nonces, transaction IDs, epochs, node IDs, and source lanes are
  generated per operation from the operating system RNG where the protocol
  permits. Fixed identities from reference tools are forbidden.
- Evidence records retain exact origin, operation, variant, responder,
  destination, interface/network scope, receive time, confidence, expiration,
  and parser disposition.
- Product/version strings are accepted only from bounded protocol fields with a
  documented meaning. Generic byte-pattern inference remains separate from
  structural protocol validation.

### Safety and resource rules

All new code follows the existing Rust ownership and hostile-boundary model:

- parsers operate on borrowed bounded slices and use checked arithmetic;
- no wire length can cause an unchecked allocation, recursion, loop, or index;
- multi-datagram and fragmented exchanges have explicit packet, byte, fragment,
  sender, and elapsed-time ceilings;
- admission reserves worst-case work before network I/O;
- cancellation is prompt, idempotent, and followed by callback quiescence;
- descriptors, timers, buffers, result reservations, and state-machine entries
  have one auditable owner and deterministic teardown;
- unsolicited, duplicate, reflected, wrong-interface, wrong-family, wrong-port,
  wrong-nonce, late, and post-close datagrams cannot strengthen evidence;
- amplification-sensitive operations are opt-in, paced, unicast by default, and
  have strict response-byte ratios and early stop; and
- malformed or ambiguous fields are retained only as bounded opaque evidence
  when doing so cannot lend them semantic meaning.

No new candidate enters the safe default profile during its implementation
phase. Default-profile admission is a separate Phase 69 decision supported by
measured request/response impact and false-positive data.

## Prioritized phase sequence

| Phase | Focus                                             | Priority reason                                                |
| ----- | ------------------------------------------------- | -------------------------------------------------------------- |
| 59    | Coverage contract and admission harness           | Prevents unsafe one-off payload growth                         |
| 60    | RMCP/IPMI and remote-management discovery         | High-value infrastructure coverage                             |
| 61    | Enterprise database discovery                     | Common high-value service identity gaps                        |
| 62    | Routing and industrial discovery                  | Adds topology and operational-technology evidence              |
| 63    | Game-server and master discovery                  | Broadens lower-risk service coverage after core infrastructure |
| 64    | Voice and media server discovery                  | Useful but often proprietary and parser-heavy                  |
| 65    | Additional DHT discovery                          | Stateful and externally visible, so deliberately later         |
| 66    | Sensitive legacy enterprise protocols             | Higher disclosure and legacy-target risk                       |
| 67    | Cryptographic/authentication blocker reassessment | Highest CPU, logging, and semantic risk                        |
| 68    | Threat/backdoor probe boundary                    | Keeps malware semantics outside ordinary discovery             |
| 69    | Integrated coverage audit and release candidate   | Freezes claims only after adversarial evidence                 |

Phases are sequential. A phase can record independent candidate no-go outcomes
and still close, but unresolved ownership, memory-safety, lifecycle, authority,
or accounting defects block all dependent phases.

## Phase 59 — Coverage contract and admission harness

Phase 59 transmits no new protocol traffic. It turns the comparison and
admission rules into enforceable project structure before another payload is
added.

Deliverables:

- freeze the checked family-level matrix between current capabilities and the
  pinned Nmap snapshot, including request, correlation, typed parsing, live
  responder, fingerprint, policy, and provenance dimensions;
- add append-only candidate records for every Phase 60–68 family with stable
  IDs, likely ports, execution model, risk, source status, and disposition;
- make native Rust and TypeScript capability views derive from or validate
  against one canonical checked registry;
- define risk classes for management disclosure, topology disclosure,
  amplification, stateful network participation, legacy fragility, and threat
  signatures;
- define reusable bounded responder, multi-datagram, derived-endpoint, and
  stateful-correlation fixtures;
- freeze per-operation ceilings and an environment-wide worst-case reservation
  formula before selecting any new catalogue/registry versions;
- add a provenance checker that rejects Nmap paths/data as build or generation
  inputs while allowing an explicitly invoked black-box comparison report; and
- document the exact support-claim vocabulary in package README and release
  policy files.

Exit gate: the registry cannot claim `implemented` without sources,
independently enforced risk, parser/correlation tests, responder evidence, and
public support metadata; all existing IDs and behaviors remain unchanged.

## Phase 60 — RMCP/IPMI and remote-management discovery

This phase handles the first-priority infrastructure family. Each operation is
independent:

- **ASF/RMCP Presence Ping/Pong:** use DMTF DSP0136 on explicit unicast UDP 623
  or 664 targets; correlate the message tag; parse enterprise number and
  supported-entity/interaction bits; never issue power or control commands.
- **IPMI RMCP:** evaluate a credential-free Get Channel Authentication
  Capabilities exchange from the official IPMI contract. If admitted, report
  protocol/channel capability metadata only, classify it as sensitive management
  disclosure, and never negotiate a session or authenticate.
- **Apple Remote Desktop and Citrix discovery:** require a current public vendor
  contract or a separately reviewed authoritative upstream implementation.
  Otherwise retain named no-go records rather than reproduce unexplained magic
  payloads.

The ASF presence probe and the IPMI capability probe must not be conflated: a
valid RMCP Pong proves an RMCP-aware management endpoint, while an IPMI response
can disclose different and more sensitive capabilities.

Verification includes bit/reserved-field validation, wrong-tag and reflected
response rejection, IPMI checksum/length tests if admitted, bounded OEM fields,
no-session assertions, live project responders, and unicast amplification
measurements.

Exit gate: every admitted management exchange is unicast, credential-free,
non-mutating, separately consented, exactly correlated, and documented as
unauthenticated capability evidence; unsupported proprietary candidates are
executable no-go entries.

## Phase 61 — Enterprise database discovery

Evaluate and, where independently supportable, implement:

- IBM Db2 Administration Server UDP discovery; and
- SAP SQL Anywhere connectionless server discovery.

Both candidates require public vendor wire documentation or a license-approved
authoritative implementation. A recognizable literal in another scanner is not
sufficient. Admitted operations must use dynamic request identity where
available, reject uncorrelated advertisements, and expose bounded typed fields
such as server/product family, instance or database name, port, and version only
when the protocol assigns those meanings.

Broadcast or fan-out behavior belongs in a finite explicit-interface discovery
operation. Targeted unicast behavior belongs in a target/port subprobe. A
received alternate port is evidence-derived and never scanned automatically.

Exit gate: at least one project-owned responder demonstrates exact positive,
negative, malformed, duplicate, cross-target, and derived-port behavior for each
implemented database family; an absent authoritative contract produces a
documented no-go without blocking the phase.

## Phase 62 — Routing and industrial discovery

Implement the next high-value network and operational-technology candidates:

- **RIPv1:** independently encode and parse RFC 1058 requests/responses. Default
  to explicit-target unicast and a bounded diagnostic request rather than an
  implicit broadcast. A whole-table request is a separate high-risk topology-
  disclosure mode, is sent from an ephemeral source port, and caps response
  datagrams, bytes, routes, metrics, elapsed time, and amplification ratio.
- **Beckhoff ADS discovery:** use current Beckhoff documentation for ADS
  discovery semantics and UDP port 48899. Separate explicit-target unicast from
  link broadcast; bind responses to interface/network scope; validate all
  lengths and command/state fields; never add routes, write values, or establish
  a control session.

RIP routes and ADS-returned endpoints enter typed topology/service evidence.
Neither can authorize follow-up traffic. Route entries retain the responding
router, interface/network scope, metric, protocol version, and lifetime; they
are not merged into the kernel or scanner target plan.

Exit gate: project responders prove multi-datagram route bounds, malformed entry
handling, link-scope attribution, cancellation, and no mutation; broadcast modes
require separate explicit consent and complete resource reservation.

## Phase 63 — Game-server and master discovery

Add independently authored, opt-in status operations for useful open or
authoritatively documented game families, prioritizing Quake 1, Quake 2, Quake
3/ioquake3, Unreal Tournament 2000-style servers, All-Seeing Eye, and
Freelancer. Each family has its own admission decision and responder.

Server status parsers must bound infostrings, keys, values, player rows, text
encoding, datagrams, and total bytes. They emit syntactic service evidence such
as protocol, game/mod, map, player count/capacity, and advertised version; they
must not parse or download game content.

Quake master-server queries are a separate finite discovery operation. Returned
server endpoints are bounded, provenance-preserving derived-endpoint evidence.
The operation never scans, connects to, or recursively queries those endpoints.
The application must explicitly authorize any subsequent scan through the
existing derived-work policy.

Exit gate: status and master paths have independent risk/resource ceilings,
randomized correlation where supported, strict delimiter and list termination,
duplicate suppression, no implicit fan-out, and live responders derived from
authoritative upstream code rather than Nmap data.

## Phase 64 — Voice and media server discovery

Evaluate TeamSpeak 2, TeamSpeak 3, Mumble/Murmur, Ventrilo, and SqueezeCenter
discovery. These are deliberately later because several protocols are
proprietary, encrypted/obfuscated, version-fragile, or capable of returning
sensitive user/server metadata.

An admitted operation must:

- have a current authoritative contract and independently authored handshake;
- stop before authentication, channel join, registration, or media exchange;
- use fresh operation identity instead of copied client constants;
- cap handshake rounds, decompression if any, strings, users/channels, packets,
  bytes, CPU, and elapsed time; and
- expose only documented server capability/status fields under an explicit
  sensitive-service risk tier.

Murmur UDP ping and any other compact stateless operation must remain separate
from multi-step initialization protocols such as TeamSpeak 3. Opaque encrypted
responses that cannot be safely and usefully classified are no-go, not weak
fingerprints.

Exit gate: each implementation has a project responder and hostile state-machine
tests; unsupported proprietary formats remain named no-go records.

## Phase 65 — Additional DHT discovery

Evaluate Vuze/Azureus DHT and eDonkey/eMule Kademlia in addition to any existing
BitTorrent DHT capability. The purpose is direct endpoint identification, not
joining or crawling a distributed network.

Binding behavior:

- send at most a protocol-defined ping to an explicit target;
- generate an ephemeral, per-operation node identity and transaction identity;
- advertise read-only behavior when the protocol defines it;
- do not bootstrap, store contacts, maintain a routing table, call `find_node`
  or `get_peers`, announce a peer, publish, or recursively contact returned
  nodes;
- cap bencode/packet nesting, fields, endpoints, bytes, and CPU; and
- expire node identities and returned endpoint evidence with the operation.

BitTorrent BEP 5 is the model for a bounded ping contract, not permission to
assume wire equivalence for other DHTs. Each additional DHT requires its own
primary contract and responder.

Exit gate: packet captures and tests demonstrate one target, one bounded ping
exchange, no durable routing state, no returned-node fan-out, prompt
cancellation, and explicit stateful-network-participation consent.

## Phase 66 — Sensitive legacy enterprise protocols

Evaluate AFS/Rx version or ping discovery, Amanda `noop`, connectionless DCE/RPC
endpoint discovery, and VxWorks WDB target ping. These candidates are opt-in and
legacy-sensitive by definition.

Requirements:

- AFS work uses OpenAFS Rx documentation, confines itself to null-security
  read-only discovery, and implements only the minimum ACK/abort behavior needed
  for a bounded exchange;
- Amanda uses the authoritative Amanda source/protocol contract and never asks
  for backup configuration, indexes, credentials, or data;
- DCE/RPC uses the DCE 1.1/Microsoft RPCE connectionless contract, no
  authentication, no callbacks, strict PDU/fragment ceilings, and a read-only
  endpoint/interface query only if one can be proven safe; and
- WDB admits only a documented non-mutating ping. A target-connect or debugger
  attachment request is prohibited even if another scanner transmits it.

Each candidate is paced conservatively and carries legacy-fragility plus any
information-disclosure risk. Parser implementation alone does not admit live
transmission.

Exit gate: admitted operations are read-only, unauthenticated, bounded against
fragment/sequence abuse, tested against project responders, and disabled unless
explicitly selected; unsafe or undocumented candidates remain no-go.

## Phase 67 — Cryptographic and authentication blocker reassessment

Reopen, but do not presume reversal of, the existing blockers for Kerberos KDC
errors, DHCPv4 INFORM/DHCPv6 Information-request, IKEv1/IKEv2, DTLS, OpenVPN,
RADIUS, CLDAP, Ubiquiti discovery, pcAnywhere, and WireGuard.

Each candidate receives an independent current-source review covering:

- whether the packet is semantically an authentication attempt or creates
  durable target state;
- reflected/amplified traffic, cryptographic CPU, logs/alerts, rate limits, and
  identity/privacy disclosure;
- whether a fresh nonce/session/client identity can be generated without
  credentials or copied constants;
- whether a syntactic response supplies useful evidence beyond `open|filtered`;
- whether the full safe state machine can be implemented with existing audited
  primitives and strict packet/byte/CPU/deadline bounds; and
- whether a project-owned responder and privileged namespace topology can prove
  the behavior without contacting public infrastructure.

No family is admitted merely to match Nmap. In particular, a fabricated RADIUS
Access-Request, Kerberos principal, IKE transform offer, WireGuard initiation,
or OpenVPN control packet may be correctly retained as no-go because it crosses
authentication, CPU, logging, identity, or usefulness boundaries.

Exit gate: every blocker has a dated evidence-based decision and executable
ledger state; any admitted state machine passes independent consent, resource,
privacy, responder, fuzz, cancellation, and teardown gates.

## Phase 68 — Threat and backdoor probe boundary

Resolve the remaining malware/backdoor-oriented Nmap families, including
BackOrifice/BO ping, Trinoo, AndroMouse, AirHID, and comparable command-and-
control signatures.

The default decision is no active transmission in `nodenetscanner`. Phase 68
must:

- record these families in a distinct threat-signature exclusion ledger;
- ensure no safe, extended, comprehensive, discovery, adaptive, or derived-work
  profile can schedule their payloads;
- allow passive evidence only when it is based on structurally valid traffic
  already observed under the Phase 46 capture/privacy contract;
- decide whether any future active threat-identification work belongs in a
  separately named package with its own threat-scanning scope and consent; and
- add release tests that fail if threat payloads or names leak into ordinary
  probe registries.

This phase does not implement a malware scanner. Its product deliverable is an
enforceable scope boundary and a documented future-package decision.

Exit gate: ordinary discovery cannot actively emit threat/backdoor signatures,
passive evidence cannot authorize active work, and public coverage claims count
these families as intentionally excluded rather than missing implementation.

## Phase 69 — Integrated coverage audit and release candidate

Freeze the additive catalogues, registries, schemas, risk policy, and claims,
then perform a complete adversarial and release audit.

Required gates:

- regenerate the Phase 59 matrix against the same pinned Nmap snapshot and
  separately report request, correlation, typed parsing, responder, fingerprint,
  profile, no-go, and excluded dimensions;
- inspect newer Nmap changes only as a new behavioral delta, with no data
  ingestion or automatic plan expansion;
- verify catalogue/registry ID stability and native/TypeScript/release-policy
  parity;
- test safe-profile invariance before any separately justified default changes;
- complete project-responder ordinary and privileged namespace matrices for
  every implementation;
- run parser/state-machine fuzzing, sanitizers, Miri-appropriate pure-code
  suites, malformed/fault injection, cancellation/close races, descriptor/RSS/
  result-capacity stress, and amplification measurements;
- verify hostile returned endpoints never grant authority or cause implicit
  traffic;
- complete x86-64 and native AArch64 execution, artifact inspection, clean
  consumers, reproducibility, changelog, README examples, and release policy;
  and
- keep the package unpublished until all inherited Phase 44/58 architecture and
  native-publication gates are also closed.

Exit gate: every public claim names its dimension; all implemented operations
are independently authored, bounded, non-mutating, correctly risked, live-
tested, and reproducible on both declared architectures; all unsupported or
excluded families remain explicit.

## Verification matrix

Every implemented family must cover the applicable rows:

| Area        | Required evidence                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------- |
| Codec       | Exact independent request vectors and round-trip/negative tests                                         |
| Parser      | Truncation at every boundary, hostile lengths/counts/encodings, reserved fields                         |
| Correlation | Wrong nonce/tag/source/port/interface/family, stale, duplicate, reflected, and cross-subprobe rejection |
| Runtime     | Admission before I/O, pacing, retries, deadlines, cancellation, close, callback quiescence              |
| Resources   | Descriptor, timer, state, packet, byte, result, derived-endpoint, CPU, and amplification ceilings       |
| Policy      | Default exclusion, explicit risk consent, target/interface scope, no implicit derived work              |
| Responder   | Positive, silence, malformed, delayed, duplicate, multi-packet, and oversize modes                      |
| Evidence    | Typed field meaning, provenance, confidence, expiry, conflict, and hostile JS validation                |
| Platform    | IPv4/IPv6 where defined, namespace topology, x86-64, AArch64, clean consumer                            |
| Provenance  | Primary source, clean-room notes, fixture ownership, no Nmap-derived input                              |

## Stop conditions

Pause breadth and repair the preceding slice if any of these occurs:

- a parser panic, unchecked allocation/arithmetic path, use-after-close, leaked
  descriptor/timer/result reservation, or non-quiescent callback;
- transmitted traffic without the declared target/interface/risk authority;
- a returned endpoint, name, route, or service field silently authorizes work;
- an unbounded multi-datagram, fragmentation, decompression, list, or state-
  machine path;
- a responder cannot distinguish valid correlation from stale/reflected traffic;
- an active operation mutates target state, attempts authentication, or emits a
  threat/backdoor signature;
- a support claim exceeds live evidence; or
- Nmap or another scanner's payload/fingerprint data enters a source, fixture,
  generator, build, artifact, or package path.

## Primary research basis

The first readiness review must confirm current versions and exact clauses. The
initial primary research set is:

- local Nmap source commit `10dfd2ff1cef6c1925232db45352149b659979b4`,
  behavioral comparison only;
- [DMTF DSP0136 ASF 2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0136.pdf)
  for RMCP Presence Ping/Pong;
- the current official IPMI specification before admitting IPMI commands;
- [RFC 1058](https://www.rfc-editor.org/rfc/rfc1058.html) for RIPv1;
- [Beckhoff ADS discovery documentation](https://infosys.beckhoff.com/content/1033/tc3_grundlagen/6917981195.html);
- [id Software Quake III source](https://github.com/id-Software/Quake-III-Arena)
  and other authoritative upstream game implementations selected by Phase 63;
- current official vendor documentation for IBM Db2, SAP SQL Anywhere, Apple
  Remote Desktop, Citrix, TeamSpeak, Ventrilo, and SqueezeCenter before any
  admission;
- [BitTorrent BEP 5](https://www.bittorrent.org/beps/bep_0005.html) and
  [BEP 43](https://www.bittorrent.org/beps/bep_0043.html) for bounded/read-only
  BitTorrent DHT behavior, without assuming equivalence for Vuze or eDonkey;
- [OpenAFS Rx documentation](https://docs.openafs.org/doxygen-test/chap5.html),
  authoritative Amanda source, DCE 1.1, and
  [Microsoft RPCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/fb1ee8ad-3d98-4a17-a4d6-3d1693626410)
  for Phase 66; and
- the RFC Editor versions of the Kerberos, DHCP, IKE, DTLS, RADIUS, and LDAP/
  CLDAP specifications plus current official OpenVPN, Ubiquiti, pcAnywhere, and
  WireGuard material for Phase 67.

Secondary descriptions may identify research questions but cannot define shipped
bytes or parser meaning.
