# UDP protocol-probe parity plan

Status: readiness review closed; implementation has not started  
Date: 2026-07-14  
Phases: 27 through 33  
Readiness review: closed in `44-udp-probe-parity-plan-review.md`

## Objective

Replace the scanner's generic, session-wide UDP payload behavior with a bounded,
protocol-aware UDP subsystem that can elicit and classify responses as
effectively as Nmap's UDP port scanner, while preserving this project's MIT
license, Rust ownership model, deterministic scheduler, compact result boundary,
and zero production Node dependencies.

The completed work must:

- choose one or more protocol-correct requests from the destination port and
  selected probe policy;
- send byte-exact requests without an unconditional private prefix;
- support multiple independently correlated request variants for one logical
  target/port;
- aggregate direct UDP, ICMPv4, ICMPv6, silence, duplicate, late, and
  contradictory evidence deterministically;
- identify the responding UDP service when independently authored structural
  parsing or a bounded signature can justify it;
- keep every request, response, parser, correlation entry, transmission,
  retained result, and metadata field independently bounded;
- expose the distinction between logical endpoint results and physical probe
  transmissions; and
- demonstrate parity against a frozen behavioral baseline and an independently
  controlled responder matrix before making a parity claim.

This is an extension of the portable scanner. It does not reopen Phase 26 or
authorize an extreme packet backend.

## Scope and terminology

### Required UDP port-scan parity

For this plan, **UDP probe parity** means parity with the protocol-payload and
port-state behavior used by Nmap's UDP port scan, not blanket parity with every
feature of Nmap.

Required parity includes:

1. port-associated protocol requests rather than one generic payload;
2. every independently implementable payload-eligible protocol class in the
   frozen reference baseline;
3. multiple payload variants for a port when the reference behavior has them;
4. a zero-length UDP fallback for a selected port with no mapped request;
5. direct UDP response, target-originated port-unreachable, other ICMP error,
   and silence state distinctions for IPv4 and IPv6;
6. retries, host fairness, and ICMP-rate-limit-aware timing without allowing one
   protocol or quiet host to monopolize the scheduler; and
7. early service-family evidence when a response is structurally recognizable.

### Separate service/version scope

Nmap's complete service/version system is broader than UDP port probing. It
includes TCP probes, thousands of response patterns, product/version
substitutions, tunnel handling, and CPE metadata. Phases 27 through 33 do not
claim complete `-sV` parity.

This roadmap does require service-family identification for the UDP protocols it
implements and permits bounded product/version metadata when an independently
authored parser or signature supports it. A future claim of full Nmap
service/version parity would require a separate plan, data-licensing decision,
and fingerprint-maintenance program.

### Better-than-parity criteria

The project may claim behavior better than the frozen UDP port-scan baseline
only when the final Phase 33 audit demonstrates at least one of these without a
regression in response elicitation, definitive state accuracy, or resource
bounds:

- fewer physical requests for the same responder coverage through
  response-directed early stopping;
- stronger response correlation through protocol transaction fields;
- more precise service-family classification through strict typed parsers;
- clearer logical-versus-physical progress and evidence reporting;
- safer default handling of amplification-prone, broadcast, multicast, fixed-
  source-port, authentication-attempt, sensitive-read, stateful, or legacy
  requests; or
- lower false-positive service classification on the independent responder and
  hostile-response corpus.

## Nmap reference investigation

The planning reference is the local checkout at
`/home/tourist/nmap_source/nmap`, commit
`10dfd2ff1cef6c1925232db45352149b659979b4` dated 2026-07-14.

The inspected behavior is divided across:

- `payload.cc` and `payload.h`: create a destination-port-to-UDP-probe map from
  payload-eligible service probes and allow multiple payloads per port;
- `scan_engine_raw.cc`: send every mapped payload for a UDP port, or one empty
  datagram when none is mapped, use the same source port for the variants owned
  by one logical probe, and retain early direct responses;
- `scan_engine.cc`: initialize UDP silence as an ambiguous state, account for
  timing and retries, and apply state precedence;
- `service_scan.cc` and `service_scan.h`: order probable-port probes before
  other probes, apply rarity/intensity, hard/soft response matching, and
  fallback relationships; and
- `nmap-service-probes`: define request bytes, probable ports, rarity, waits,
  and response fingerprints.

At this frozen commit, a local, non-distributed analysis observed:

- 84 UDP probe records, of which 83 are payload-eligible;
- 33,110 unique destination ports with a mapped eligible UDP request;
- 33,205 eligible probe-to-port mapping assignments;
- at most four mapped request variants for one destination port; and
- 369 hard plus 48 soft UDP response-match directives.

These counts establish the comparison scope; they are not a data source for the
implementation.

The reference sends every mapped payload again when the logical probe is
retried, matches a direct response by target and reversed UDP tuple, and cannot
identify which same-source-port variant elicited it. Its later service scan can
test the retained response against the mapped probe matchers and fallbacks. This
project deliberately improves correlation by assigning each physical variant a
distinct wire identity/source-port lane when the protocol permits it.

## License and provenance boundary

Nmap and `nmap-service-probes` are covered by the Nmap Public Source License.
That license expressly discusses software that reads or includes Nmap data
files. This MIT project will therefore not copy, translate, generate from,
vendor, parse, load, link, execute as a helper, or redistribute Nmap source or
`nmap-service-probes` as part of its build, tests, runtime, or release
artifacts.

Implementation rules:

- Nmap source may inform high-level behavioral comparison and architecture
  review only.
- Every request builder, response parser, signature, port association, and
  metadata extractor must be authored from a cited primary protocol
  specification, an IANA registry, permissively licensed documentation, or a
  project-owned and permissioned capture.
- Every catalogue entry records its specification, relevant section, fixture
  provenance, safety profile, and reviewer.
- Nmap request bytes, response patterns, probe names, comments, and port lists
  must not be copied into the repository.
- The repository must never require the local Nmap checkout. A clean clone with
  no Nmap installation must build, test, and package identically.
- Any future decision to reuse Nmap code or data requires a separately accepted
  compatible license or written permission before that material enters the
  worktree.
- Manual comparison against an operator-installed Nmap may be recorded in an
  audit report, but no distributed project tool may be designed to run Nmap and
  parse its output.

Two ledgers remain deliberately separate:

- the repository-owned capability/provenance ledger is derived only from primary
  specifications, registries, and permissioned project fixtures and may ship
  with the project; and
- any reference-to-project comparison worksheet is an owner-controlled,
  non-distributed audit artifact outside the build/test/runtime tree. Only
  aggregate results and independently owned project identifiers enter the
  repository report.

This is an engineering provenance policy, not legal advice. If the owner wants
direct reuse rather than independent implementation, obtain qualified license
advice first.

## Current gap

The current public `udp` probe accepts selected ports and one optional payload.
Native session state stores only one IPv4 and one IPv6 UDP user payload, so
multiple UDP definitions do not retain independent payloads per port group. On
the wire, every UDP request prepends a 16-byte private correlation token before
the user bytes.

That design is useful for generic quote correlation but makes most application-
protocol requests invalid. It also cannot express:

- byte-exact DNS, NTP, SNMP, RPC, STUN, CoAP, IKE, or other requests;
- request selection by destination port;
- dynamic transaction IDs in protocol-defined fields;
- multiple request variants for one port;
- fixed or constrained source-port requirements;
- protocol-specific response validation;
- service metadata; or
- one logical UDP result aggregated from several physical requests.

Additional integration gaps found by the readiness audit are:

- the engine rejects duplicate probe-family definitions, so the public contract
  must retain exactly one UDP definition and represent variants inside its
  programme rather than implying several overlapping UDP entries;
- one ID currently owns both logical settlement and wire correlation;
- `maxOutstanding` and grace/source-port capacity currently count logical
  probes, not several live variants;
- aggregate transmissions are `u8` in the engine even though the version-1 wire
  column is already `u32`;
- result reservation counts rows but not variable metadata bytes; and
- native ICMP evidence currently collapses family/type information into a small
  code mapping, which is insufficient for the complete IPv4/IPv6 UDP state
  matrix.

The current state classifier remains valuable and is evolved rather than
replaced.

## Target architecture

```text
TypeScript ScanPlan
  udp policy: protocol | empty | custom
           |
           v
validated per-session UDP probe programme
  catalogue selection + exact custom requests + checked bounds
           |
           v
nodenetscanner-engine
  one logical (target, UDP port) result
  one bounded sequence of physical protocol subprobes
           |
           +--> nodenet-protocols request builders
           +--> protocol correlation descriptors
           +--> typed parsers / bounded signatures
           |
           v
nodenetscanner-native
  route/neighbor setup, source-port lanes, packet I/O, response capture
           |
           v
evidence lattice --> schema-v2 result batch
```

### Ownership

- `nodenet-protocols` owns syscall-free request builders, strict response
  parsers, catalogue types, checked dynamic field patching, and protocol
  evidence values.
- `nodenetscanner-engine` owns selection policy, subprobe order, retry and
  timeout state, logical aggregation, fairness, and evidence precedence.
- `nodenetscanner-native` owns descriptors, route bindings, source ports,
  transaction entropy, packet bytes, receive buffers, and live correlation
  entries.
- TypeScript owns ergonomic immutable policy types, compatibility validation,
  lazy schema-v2 views, and presentation. It does not receive raw packets or
  execute response callbacks in the packet path.

The current engine uses one probe ID for logical settlement and wire
correlation. Phase 28 separates a stable `logical_result_id` from a unique
`wire_probe_id` plus catalogue variant ID. Route/correlation/grace maps key the
wire ID; result reservation, evidence aggregation, and terminal batches key the
logical ID. Terminalizing one endpoint retires every emitted wire ID only after
its required late grace.

Stable numeric probe/service/confidence values remain compact engine evidence.
Variable product, version, and extra strings are retained only in a bounded
native-owned sidecar associated with correlated evidence. The evidence lattice
selects at most one winning sidecar transactionally for the logical result;
losing, malformed, duplicate, and expired metadata is discarded and counted.
Reservation accounts for the maximum winning sidecar before the first send.

### Built-in catalogue

The production catalogue is project-owned and statically linked. Its canonical
manifest records, for every variant:

- stable project probe identifier and service family;
- IPv4/IPv6 support;
- destination ports and ranges;
- safe, comprehensive, or legacy profile membership;
- amplification, broadcast/multicast, fixed-source-port, stateful,
  authentication-attempt, sensitive-read, and side-effect risk;
- maximum request and accepted response size;
- timeout class and maximum variants;
- request builder and response parser/signature identifiers;
- response-endpoint policy (`same-port` by default, or a narrowly specified
  alternate source-port rule for protocols such as TFTP);
- correlation fields and their minimum response/quote requirements; and
- primary specification and fixture provenance.

A deterministic repository-owned generator may convert the manifest into Rust
tables. It must use only Node built-ins or project Rust code, emit stable
output, and provide a check mode that fails on drift. Production builds never
parse an external registry and add no runtime Node dependency.

### Request construction and correlation

The unconditional token prefix is removed from protocol mode. Each request
declares one correlation strategy:

- a protocol transaction field such as a DNS ID, RPC XID, SNMP request ID, STUN
  transaction ID, CoAP token/message ID, IKE cookie, or NTP timestamp;
- a protocol-safe opaque field explicitly permitted by the specification;
- source/destination tuple plus exclusive active/grace source-port ownership
  when no body token is valid; or
- exact custom bytes with an explicitly selected tuple-only or legacy
  token-prefix policy.

Correlation strength is explicit. A valid protocol transaction response is
stronger than a tuple-only direct datagram. An ICMP quote containing only the
UDP header is tuple/window evidence; a longer quote that includes and validates
the protocol token may be stronger. No parser invents evidence from missing
bytes.

The target address must always match. A response from the probed destination
port is the default. A catalogue entry may admit an alternate response source
port only when the primary specification requires it and either:

- a protocol transaction field strongly correlates the response; or
- the protocol defines a first-response port-selection handshake, the local
  destination lane is exclusive, a strict parser validates the expected initial
  server role, and the first accepted source port is pinned for the remaining
  active/grace exchange.

The latter is a lower, explicitly reported structured correlation category for
protocols such as TFTP; it is not called secret-token strength. The alternate
endpoint always remains within the same target and active/grace window.
Tuple-only correlation can never authorize an arbitrary alternate source port.

Transaction values come from the session correlation secret/entropy source, not
the reproducible scheduling seed. Dynamic fields are patched through checked
builders and then checksums/lengths are computed. No dynamic patch may address
bytes outside the constructed request.

### Logical and physical work

One logical UDP endpoint is `(target, destination port)`. It produces exactly
one terminal result. A selected protocol programme may emit several physical
subprobes and retries for that endpoint.

- Every physical datagram consumes a rate token and increments physical
  transmission progress.
- `rate.maxOutstanding` means active physical probe datagrams awaiting evidence,
  not logical endpoints. One logical endpoint with four concurrent variants
  consumes four slots.
- An active source-port lane cannot be reused during late grace. Combined active
  and grace leases cannot exceed the collision-free lanes available to that
  session's four-way partition; admission defers when no lane is free even when
  active work is below `maxOutstanding`. Grace entries retain their separate
  existing hard ceiling.
- Every live subprobe has bounded correlation/grace state.
- Logical result capacity is reserved before the first subprobe.
- Route and neighbor setup may be shared safely across the endpoint programme,
  but each setup frame is still rate charged.
- A decisive response can stop unsent variants; already emitted variants retain
  correlation only through their finite grace window.
- Stopping sends is not the same as emitting the result. The logical endpoint
  enters a bounded settling state and retains its row/byte reservation until all
  emitted variants can no longer change a serialized field, or a proof of
  dominance makes later evidence irrelevant. ICMP `closed`/`filtered` evidence
  therefore waits for possible direct-open evidence from emitted variants.
- When several responses can identify a service, the winner is deterministic:
  stronger state evidence, then service confidence, then the lowest stable
  catalogue probe ID. Duplicate evidence for the same variant keeps the minimum
  valid RTT. Contradiction counters include every emitted variant observed
  before settlement.
- State-decisive and service-decisive are distinct. A tuple-valid direct reply
  proves `open`, but a policy may continue a bounded identification programme
  when no service parser matched. A transaction-valid service response may stop
  both state and identification work.
- Checked plan estimates include the worst-case physical request product, not
  only logical results.
- `timing.retries` applies independently to each selected physical variant. The
  checked maximum for one endpoint is `variants × (retries + 1)`, while the
  session deadline may still terminate unsent work normally.
- A result's `transmissions` counts UDP probe datagrams for that logical
  endpoint. Global `progress.sent` counts every rate-charged frame, including
  neighbor setup and cleanup that cannot be attributed safely to one endpoint.
  The existing result `attempt` keeps its logical-plan meaning and is not
  overloaded with variant or retry ordinals.

Checked estimates prevent overflow and inform summaries; they do not reject a
valid bounded plan merely because its configured rate could outlast its
deadline. The deadline remains an intentional terminal outcome for work not sent
or settled in time.

### Evidence lattice

State selection must not depend on packet arrival order.

From strongest to weakest relevant outcomes:

1. a structurally valid, transaction-correlated direct response establishes
   `open` and may identify a service;
2. a tuple-valid direct UDP response establishes `open`, while service remains
   unknown if its body does not match;
3. a target-originated, correlated ICMP port-unreachable establishes `closed`
   unless stronger direct-open evidence exists;
4. other correlated ICMP unreachable/prohibited/time-exceeded evidence
   establishes `filtered` or `unreachable` according to the existing family-
   specific policy, without overriding stronger open/closed evidence; and
5. exhaustion without conclusive evidence is `open|filtered`.

The normalized state matrix is frozen before Phase 28 implementation:

| Correlated observation                                            | UDP state                       |
| ----------------------------------------------------------------- | ------------------------------- |
| Valid direct UDP response from the allowed response endpoint      | `open`                          |
| IPv4 Destination Unreachable code 3, emitted by the probed target | `closed`                        |
| IPv4 Destination Unreachable codes 0, 1, 2, 9, 10, or 13          | `filtered`                      |
| IPv4 Time Exceeded code 0 or 1                                    | `filtered`                      |
| IPv6 Destination Unreachable code 4, emitted by the probed target | `closed`                        |
| Other recognized IPv6 Destination Unreachable codes               | `filtered`                      |
| IPv6 Parameter Problem code 0 with a correlated quoted UDP probe  | `open`                          |
| IPv6 Parameter Problem code 1 with a correlated quoted UDP probe  | `filtered`                      |
| Exhaustion without conclusive evidence                            | <code>open&#124;filtered</code> |
| Unknown/unrecognized or insufficiently quoted diagnostic          | no state change                 |

A port-unreachable from an intermediate system is `filtered`, not `closed`. This
plan does not add Nmap's optional ICMP-rate-limit shortcut that can report
`closed|filtered`; the project retains conservative `open|filtered` silence.
Native evidence therefore carries address family, ICMP type/code, quote
strength, and whether the emitter is the target until policy classification is
complete.

Contradictory evidence is counted and retained in bounded diagnostics. Strong
open evidence wins over a later unreachable caused by another variant. A
malformed body on a tuple-valid direct response may establish `open` but never
service identity.

The scanner does not add IP-fragment or application-message reassembly in these
phases. A first IP fragment with a complete UDP header may contribute only the
bounded tuple evidence that the parser can validate; a non-initial fragment
cannot identify an endpoint. Service evidence requires a complete accepted
application datagram. Multi-datagram protocols may establish service from one
independently valid response, but the scanner does not retain or join an
unbounded conversation.

## Proposed TypeScript boundary

Names are frozen only after the Phase 27 API review, but the semantic shape is:

```ts
type UdpProbeIntensity = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

type UdpProbeRisk =
  | "highAmplification"
  | "statefulHandshake"
  | "fixedSourcePort"
  | "multicastOrBroadcast"
  | "authenticationAttempt"
  | "sensitiveRead";

type UdpProbePolicy =
  | {
      readonly mode: "protocol";
      readonly profile?: "safe" | "comprehensive" | "legacy";
      readonly intensity?: UdpProbeIntensity;
      readonly strategy?: "adaptive" | "exhaustive";
      readonly emptyFallback?: "unmapped" | "afterProtocol" | "never";
      readonly allowRisks?: readonly UdpProbeRisk[];
    }
  | { readonly mode: "empty" }
  | {
      readonly mode: "custom";
      readonly payload: Uint8Array;
      readonly correlation?: "tuple" | "prefixToken";
    };

type UdpScanProbe = {
  readonly kind: "udp";
  readonly ports: readonly PortSelection[];
  readonly policy?: UdpProbePolicy;
};
```

Policy rules:

- omitted policy becomes protocol-aware `safe` mode in the next scanner release
  candidate;
- `safe` selects only low-impact current requests; `comprehensive` is a
  superset; `legacy` adds obsolete/historical variants. Profile breadth never
  grants network-impact consent;
- each variant declares zero or more risks and is eligible only when every
  declared risk is present in the snapshotted `allowRisks` set; unknown or
  duplicate values are rejected before native admission;
- intensity is an integer from 0 through 9 and only changes which catalogue
  alternatives are eligible; it never expands targets or destination ports;
- `exhaustive` sends every eligible mapped variant subject to the resource
  ceilings; `adaptive` may stop/narrow only under the Phase 32 evidence rule.
  Until that rule passes, omitted strategy means `exhaustive`;
- omitted `emptyFallback` means `unmapped`: send one exact empty datagram only
  when no eligible mapped variant remains for the endpoint. `afterProtocol` adds
  one empty variant after mapped variants lack decisive evidence, while `never`
  suppresses it;
- `empty` sends an exact zero-length UDP payload;
- `custom/tuple` sends the caller's bytes exactly;
- `custom/prefixToken` retains the current token-prefix behavior explicitly;
- the existing top-level `payload` spelling remains temporarily compatible with
  `custom/prefixToken`, is mutually exclusive with `policy`, and is marked
  deprecated without emitting process-global warnings;
- a plan retains exactly one UDP probe definition. Protocol variants live in its
  catalogue programme; an exact custom payload applies to every selected port.
  Duplicate UDP definitions remain rejected rather than creating overlapping
  logical results; and
- hostile getters and mutable payloads are snapshotted once before native
  admission.

Schema version 2 retains every version-1 column and its meaning. The existing
`transmissions` column is already encoded as `u32` and becomes the total UDP
probe-datagram count for the logical endpoint. Version 2 adds:

- `terminalUdpProbeIds`: one little-endian `u16` per row, zero when absent;
- `udpVariantsAttempted`: one little-endian `u16` per row;
- `udpResponseKinds`: one stable numeric byte per row;
- the existing evidence byte extended with stable correlation-strength codes;
- `udpServiceFamilies`: one little-endian `u16` per row, zero when absent;
- `udpServiceConfidences`: one stable numeric byte per row;
- `serviceMetadataBytes` plus little-endian `u32` offsets, containing a
  deterministic length-prefixed binary record with bounded product, version, and
  stable numeric extra-field identifiers rather than JSON or arbitrary keys; and
- contradiction/malformed-response diagnostics in summary counters rather than
  unbounded per-packet history.

The new stable byte vocabularies are fixed at Phase 27 admission:

- UDP response kind: `0` none/non-UDP, `1` direct UDP, `2` ICMPv4 target port
  unreachable, `3` other ICMPv4, `4` ICMPv6 target port unreachable, `5` ICMPv6
  Parameter Problem, `6` other ICMPv6, and `7` silence;
- service confidence: `0` none, `1` bounded signature, `2` structurally parsed
  family, and `3` structurally parsed plus protocol-transaction-correlated; and
- evidence strength retains schema-1 codes `0` through `4` and appends `5`
  protocol transaction up to 16 bits, `6` up to 32 bits, `7` at least 64 bits,
  and `8` specification-validated alternate-endpoint handshake. These are
  correlation categories, not authentication claims.

Each nonempty service-metadata record is little-endian: `u8` record version
(`1`), `u16` product byte length and UTF-8 bytes, `u16` version byte length and
UTF-8 bytes, `u8` extra count, then for each extra a `u16` stable field ID,
`u16` value byte length, and UTF-8 value bytes. Lengths remain at most 255,
extras at most 32, the enclosing record at most 1 KiB, and unknown record
versions/field IDs fail decoding rather than being guessed.

`metadataBytes` continues to contain the terminal reason only. Schema 1 decoding
remains supported for retained batches through an explicit encoded-batch union;
version 1 rejects version-2-only columns, and version 2 requires and validates
them. The native session emits only one schema version. Phase 27 freezes this
binary layout and compatibility decoder, Phase 29 begins native schema-2
emission for protocol-mode sessions, and Phase 32 freezes the ergonomic public
names without changing the wire layout.

The schema version is selected once at session admission and appears in the
terminal summary; it never changes between batches. A schema-2 batch uses zero
sentinels for non-UDP rows. `terminalUdpProbeIds` identifies the catalogue
variant that supplied the winning evidence and is zero for silence, lifecycle
outcomes, empty/custom probes, or no winner. `udpVariantsAttempted` counts
unique variants emitted at least once, while `transmissions` includes their
retries.

## Resource ceilings

These are independent maxima; smaller defaults are expected.

| Resource                                                       |                             Proposed maximum |
| -------------------------------------------------------------- | -------------------------------------------: |
| Built-in catalogue variants                                    |                                          256 |
| Selected variants for one endpoint in default safe mode        |                                           16 |
| Selected variants for one endpoint in explicit exhaustive mode |                                           64 |
| Concurrent wire variants for one logical endpoint              |                                            4 |
| Built-in request bytes per variant                             |                                        4 KiB |
| Exact custom UDP user bytes                                    |         existing 65,491-byte wire-safe limit |
| Total selected request-template bytes per session              |                               existing 1 MiB |
| Typed response bytes inspected per datagram                    |             65,527 bytes, without reassembly |
| All variable service metadata copied into one result           |                                        1 KiB |
| Queued service metadata per session / four-session environment |                              16 MiB / 64 MiB |
| Variable metadata across one sealed result batch               |                         existing 4 MiB total |
| Service/product/version/extra string                           |                         255 UTF-8 bytes each |
| Structured service metadata pairs                              |                                32 per result |
| Correlation fields per variant                                 |                                            8 |
| Parser nesting depth                                           |  16 unless a stricter protocol limit applies |
| Physical subprobe attempts                                     |      checked product of variants and retries |
| Active physical / grace entries                                | `maxOutstanding` / existing grace hard bound |
| Combined active+grace UDP source-port leases                   |    collision-free per-session lane partition |
| Received datagrams per runtime tick                            |                      existing maximum of 128 |
| Typed parser bytes per session / target in one runtime tick    |                              4 MiB / 256 KiB |

The exact IPv4/IPv6 payload ceiling is recalculated from actual headers before
admission. Catalogue requests above the path MTU are rejected or explicitly
fragmented only by a future reviewed feature; this plan does not add IP fragment
reassembly, application-message reassembly, or silent fragmentation.

Result reservation becomes two-dimensional: a logical endpoint reserves one row
and its catalogue-declared maximum winning-metadata bytes before its first send.
Commit releases unused bytes; cancellation and every losing/late/error path
release the whole reservation. The pull sealer may return fewer rows than
`maxResults` to keep the combined reason and service-metadata columns within 4
MiB. Response datagrams beyond a parser-work budget may receive bounded tuple
classification and counters but no service parsing; draining, cancellation, and
timeouts remain live.

## Safety and network-impact policy

- Safe-profile requests are informational, unauthenticated, and non-destructive.
  Broader built-ins remain non-destructive but may require explicit
  authentication-attempt, sensitive-read, or stateful consent.
- No default request writes configuration, creates accounts, authenticates with
  supplied credentials, enumerates private application data beyond ordinary
  service identification, or intentionally exploits malformed input.
- Broadcast, multicast, directed-broadcast, reflection-prone, high-
  amplification, fixed-source-port, authentication-attempt, sensitive-read, and
  materially stateful requests are not in the default safe profile. Profile
  selection alone never authorizes them: every declared risk requires a matching
  `allowRisks` value and still obeys target, route, rate, and response-byte
  bounds.
- The library never expands an operator target into a multicast or broadcast
  destination implicitly.
- Fixed-source variants always preserve collision-free ownership inside the
  module's four-session space. Because a raw sender cannot prove race-free
  ownership against every host process, external port ownership is never
  claimed: such a variant requires explicit `fixedSourcePort` consent and an
  operator-controlled namespace/host policy, or it is rejected.
- No built-in profile performs configuration writes, destructive requests,
  exploit payloads, credential brute force, or arbitrary user-data extraction.
- A built-in is `highAmplification` when its accepted/specification-supported
  response can exceed the greater of four times its request size or 1 KiB;
  reviewers may classify a lower-ratio protocol conservatively. Padding a
  request solely to evade this rule is not permitted unless the protocol
  specification defines that padding and it materially constrains reflection.
- Exact custom bytes are caller-authored low-level traffic and are not
  misrepresented as catalogue-vetted safe probes; they still obey target, rate,
  size, lifecycle, and correlation bounds.
- Parser work is length-first and bounded. Typed parsers are preferred. A
  project-owned byte-signature DSL may provide exact, prefix, masked-field, and
  bounded text extraction; it has no backtracking, recursion, arbitrary code, or
  JavaScript callback.
- Raw responses do not cross N-API. Returned metadata is copied, validated,
  UTF-8 normalized where promised, and capped.
- Per-host and global response-byte accounting prevents an amplification burst
  from starving control, timeout, cancellation, or another session.
- Every protocol builder/parser and the catalogue compiler deny unsafe Rust.

## Phase 27 — UDP probe foundation and provenance contract

Status: complete; implemented 2026-07-14

### Goal

Establish independently authored catalogue, exact-payload, dynamic-field, API,
and provenance foundations before changing scheduling breadth.

### Deliverables

- Implement under D-040 and freeze this plan's parity definition and NPSL
  separation.
- Add project-owned UDP catalogue descriptor types to `nodenet-protocols` with
  no syscall or N-API dependency.
- Define stable project probe IDs, service families, profile/risk flags,
  address-family support, port sets, response-endpoint policies,
  request/response bounds, correlation descriptors, and primary-source
  provenance.
- Implement checked request-plan construction into caller-owned storage, checked
  dynamic patch fields, and exact length reporting.
- Add a minimal deterministic catalogue generator/checker using no production
  dependency. Reject duplicate IDs, invalid ranges, unknown builders/parsers,
  unsafe profile combinations, missing provenance, oversized templates,
  impossible source constraints, and non-deterministic ordering.
- Replace the internal one-payload-per-family representation with a validated
  per-probe programme capable of retaining exact independent requests. Do not
  yet populate protocol breadth.
- Preserve the existing one-definition-per-family rule: reject duplicate UDP
  definitions and policy/payload conflicts, canonicalize risk opt-ins once, and
  resolve profile/intensity/strategy/fallback eligibility deterministically.
- Add exact custom payload mode and retain legacy prefix-token behavior only
  through the explicit compatibility path.
- Freeze the TypeScript policy discriminants, risk consent, fallback semantics,
  legacy conflict rules, snapshot semantics, exact schema-2 binary columns, and
  version-1/version-2 decoder union.
- Add capability metadata for catalogue version/hash and supported profiles
  without exposing request bytes or mutable native state.

### Tests

- manifest/generator deterministic-output and drift tests;
- malformed manifest, duplicate, overflow, invalid source-port, missing-
  provenance, and excessive-template rejection;
- exact custom payload capture proving no prefix or mutation;
- legacy prefix-token capture proving compatibility;
- dynamic patch boundary/property tests and allocation baselines;
- hostile JavaScript getter, detached buffer, mutation-after-start, and policy-
  combination tests;
- schema-1 retained-fixture decoding plus schema-2 hostile-column, offset,
  metadata-record, transfer, and detached-buffer tests; and
- x86-64/AArch64 compile plus ordinary dependency/license review.

### Exit gate

The catalogue/provenance contract is frozen, exact custom bytes are possible,
legacy behavior is explicit, the single session-wide payload limitation is gone,
and no Nmap code/data/build dependency exists. Protocol-aware mode may not
become the default until Phase 29 provides its safe pack.

## Phase 28 — Multi-probe scheduling, correlation, and aggregation

Status: complete; implemented 2026-07-14

### Goal

Teach the deterministic engine and live native path to execute several physical
UDP subprobes as one bounded logical endpoint result.

### Deliverables

- Extend the syscall-free engine with a compact `UdpProbeProgramme` and lazy
  subprobe cursor; never materialize target × port × variant products.
- Separate stable logical result IDs from unique physical wire IDs and carry the
  catalogue variant through emission/evidence without changing target/port
  result identity.
- Preserve one result reservation per logical endpoint while reserving bounded
  correlation/grace capacity for each emitted subprobe and the maximum declared
  winning-metadata bytes.
- Rate-charge neighbor setup, every variant, every retry, and any cleanup.
- Schedule variants fairly across targets and ports. A port with many variants
  cannot block a port with one variant, and a quiet host cannot consume the
  whole active window.
- Allocate collision-free source-port lanes per active/grace subprobe unless a
  reviewed protocol source constraint applies. Validate capacity before opening
  sockets.
- Support protocol transaction fields, tuple-only correlation, long and short
  ICMP quotes, and exact custom requests without changing the route/neighbor
  ownership model.
- Support specification-required alternate response source ports only through
  the same-target transaction or structured first-response-handshake catalogue
  policy; pin an accepted server port and reject arbitrary alternate-port
  tuple-only matches.
- Implement the deterministic evidence lattice, contradiction counters, decisive
  early stopping, bounded settlement, finite late grace, deterministic service
  winner, and exactly-once terminalization.
- Permit at most four concurrent wire variants for one endpoint; broader
  exhaustive programmes proceed in bounded fair waves.
- Add logical and physical progress counters. Existing `logicalProbes` and
  `results` retain endpoint meaning; `sent` remains all actual rate-charged
  frames, while result `transmissions` counts only endpoint UDP datagrams.
- Widen aggregate logical transmissions from the current `u8` to checked `u32`;
  retain a separately bounded per-variant retry/transmission ordinal.
- Make `maxOutstanding` count active physical variants; bound grace separately;
  prevent active+grace source-lane reuse; and enforce the checked
  `variants × (retries + 1)` product without materializing it.
- Preserve ICMP family, type, code, target-origin, and quote strength through
  classification and implement the frozen UDP state matrix exactly.
- Extend result-queue admission and batch sealing with byte reservations and the
  session/environment metadata ceilings.
- Ensure pause, backpressure, cancellation, close, context invalidation, route
  deferral, and environment teardown preserve unsent programme state and settle
  every reserved logical result.

### Tests

- virtual-clock matrices for zero, one, four, sixteen, and sixty-four variants;
- response-before-next-variant, response-after-all-variants, retry, duplicate,
  late, contradictory, malformed, and silence cases;
- close-before-open and service-winner permutations proving no result seals
  before a still-live emitted variant can change serialized evidence;
- direct-open versus ICMP-closed ordering permutations with identical output;
- source-port exhaustion/reuse-grace and fixed-source collision cases;
- same-port, valid alternate-port, wrong-target, and weak alternate-port
  response matrices;
- TFTP-style first-response port pinning, spoofed-first-response,
  duplicate-port, and grace-expiry matrices;
- initial/non-initial IP fragments and multi-datagram response cases proving
  that incomplete traffic cannot acquire service identity;
- million-logical-endpoint compact-state tests;
- prefix/result backpressure deferral with unresolved neighbors;
- row/byte reservation saturation, partial batch splitting, unused-byte release,
  and cancel/fault cleanup at every programme stage;
- the full IPv4/IPv6 ICMP state matrix including intermediate port-unreachable,
  Parameter Problem, unknown codes, and insufficient quotes;
- concurrent-session fairness and correlation isolation; and
- captured evidence replay proving deterministic logical results.

### Exit gate

The engine can execute and aggregate an arbitrary bounded protocol programme
with exact rate accounting, deterministic evidence precedence, memory
proportional to active state, and no regression in current empty/custom UDP
scans.

## Phase 29 — Safe standards-based UDP probe pack

Status: complete; implemented 2026-07-14

### Goal

Make protocol-aware safe mode useful for common modern UDP services and switch
the unpublished scanner candidate's no-payload default to that mode.

### Safe-core protocol families

Independently authored builders and strict parsers cover a deliberately small,
reviewable low-impact core:

- unicast DNS with a padded, bounded nonrecursive query and advertised response
  ceiling;
- NTP;
- SNMPv3 engine discovery without credentials or managed-object reads;
- ONC RPC portmapper NULL without a mapping dump;
- STUN binding;
- CoAP Empty Confirmable ping rather than resource enumeration;
- IPMI/RMCP ASF presence;
- memcached `version` without statistics or value reads; and
- any additional request that the Phase 29 safety review proves has equivalent
  low impact and independent specification coverage.

Primary RFCs or maintained protocol-owner specifications, not Nmap payloads, are
authoritative. A family is omitted from the phase rather than approximated with
malformed bytes when a safe request cannot be independently specified.
Cryptographic protocols use reviewed, exactly pinned Rust dependencies where
needed; the project does not invent cryptographic primitives. If a safe, bounded
request cannot be implemented within the dependency and resource policy, that
family moves to the Phase 30 review rather than weakening validation.

### Deliverables

- Add canonical request builders with randomized protocol fields and valid
  lengths/checksums.
- Add strict response parsers that validate transaction fields, message roles,
  lengths, counts, nested structures, and protocol limits before extracting
  bounded metadata.
- Define port associations from IANA plus protocol-owner assignments, with
  reviewed additional conventional ports recorded separately.
- Classify each request's amplification and statefulness and admit only safe
  unicast requests to the default profile.
- Add service-family/confidence evidence to the engine, begin native schema-2
  emission, and keep schema-1 fixture decoding.
- Keep engine selection fields numeric and compact. Retain variable parsed
  service metadata only in the bounded winning-evidence sidecar, and prove its
  cleanup on every losing, late, and terminal path.
- Make omitted UDP policy select protocol-aware safe mode. Preserve explicit
  empty and custom modes.
- Document that direct UDP proves an open endpoint even when its body is
  malformed or unidentified, while service identity requires parser success.

### Tests

- independently derived RFC golden requests and responses;
- IPv4/IPv6 UDP length and checksum vectors, including the different zero-
  checksum rules, captured without relying on host offload artifacts;
- wrong transaction, wrong endpoint, truncation, oversized count, malformed
  length, invalid checksum, arbitrary bytes, and mutation tests;
- a disposable dual-stack namespace with one minimal independent responder per
  protocol family;
- open, closed, filtered, silent, delayed, duplicated, and ICMP-rate-limited
  cases;
- exact packet capture proving no private prefix corrupts requests;
- parser/serializer fuzz targets and allocation ceilings; and
- safe-profile audit proving no implicit broadcast/multicast or fixed-source
  request.

### Exit gate

Every safe-pack request is protocol-valid, receives and correlates its expected
independent response, classifies state correctly, and returns bounded service
evidence. Generic UDP remains available explicitly, but it is no longer the
default for a payload-less UDP plan.

## Phase 30 — Extended standards pack and explicit-risk enforcement

Status: complete; implemented 2026-07-14

### Goal

Extend standards-based coverage beyond the low-impact core while proving that
broader catalogue selection and explicit risk consent are independent controls.

### Candidate protocol families

- mDNS and DNS-SD with explicit sensitive-read and multicast consent when
  required;
- NetBIOS node-status discovery only with explicit sensitive-read consent;
- NFS NULL discovery, SIP OPTIONS, and SSDP unicast discovery;
- TFTP read requests only with explicit sensitive-read consent and a project
  sentinel filename;
- IKEv1/IKEv2, L2TP, DTLS, QUIC, and independently specified OpenVPN discovery;
- RADIUS requests that can be specified safely, otherwise an explicit
  authentication-attempt classification;
- SNMPv1 only with explicit authentication-attempt and sensitive-read consent;
- memcached statistics only with explicit sensitive-read consent; and
- DHCP INFORM only with explicit multicast/broadcast and fixed-source consent,
  interface/source prerequisites, and an operator-controlled topology.

### Deliverables

- Add only independently specified builders/parsers that pass protocol-specific
  safety and dependency review; defer rather than approximate an unsupported
  family.
- Enforce every catalogue risk flag in native admission after TypeScript
  snapshotting; profile selection alone cannot bypass missing consent.
- Verify safe-profile requests remain unchanged when comprehensive/legacy
  catalogue entries are added.
- Add amplification ratio, parser-work, response-byte, state-lifetime, and
  source-port constraints to the catalogue and live runtime.
- Add protocol-specific alternate-response-port rules where required and prove
  same-target strong correlation.
- Prove no built-in variant performs writes, destructive actions, credential
  brute force, exploit delivery, or arbitrary data extraction.

### Tests

- per-family independent golden vectors, strict/mutation/fuzz parsing, and
  disposable responders;
- full profile × risk-consent eligibility snapshots and unknown/duplicate risk
  rejection;
- amplification, state timeout, parser-byte budget, and receive-flood fairness;
- multicast/broadcast target and interface/source prerequisite rejection;
- fixed-source four-session collision and external-ownership warning contract;
  and
- dependency, binary-size, and allocation review for cryptographic protocols.

### Exit gate

Every accepted extended request has independent provenance, explicit impact
classification, bounded live behavior, and a responder fixture; safe mode has
not gained any implicit risk, and deferred families are named for Phase 31.

### Implemented disposition

Accepted into catalogue `1.2.0`: NetBIOS node status, NFS v3 NULL, SIP OPTIONS,
SSDP unicast M-SEARCH, L2TP SCCRQ, SNMPv1 public `sysDescr.0`, and memcached
statistics. Every risk-bearing entry requires its exact native-enforced consent
set. Per-datagram response/parser ceilings, declared amplification ratios,
state-lifetime admission, and 4 MiB/session plus 256 KiB/target per-tick typed
parser budgets are enforced.

Deferred rather than approximated: mDNS/DNS-SD multi-responder multicast, TFTP's
alternate-port exchange, DHCP's fixed-source/broadcast topology, IKE/DTLS/QUIC
cryptographic handshakes, OpenVPN without an accepted stable public discovery
specification, and RADIUS without shared-secret/authentication semantics. The
detailed rationale and verification evidence are in `48-phase-30-report.md`.

## Phase 31 — Comprehensive and legacy catalogue parity

Status: complete; implemented 2026-07-14

### Goal

Expand independently authored coverage toward the frozen Nmap UDP port-payload
behavior, including multiple variants and legacy/proprietary families where safe
independent specifications exist, without turning reference data into a project
input.

### Deliverables

- Maintain the repository-owned primary-source coverage ledger for every project
  protocol family, request variant, port set, parser/signature, profile, and
  safety decision.
- Complete comprehensive and legacy profile breadth without changing safe
  defaults or bypassing per-risk consent.
- Cover game discovery, directory/database discovery, device management,
  industrial/building protocols, VPN/tunnel protocols, peer-to-peer discovery,
  remote-control protocols, and historical services represented in the frozen
  behavioral baseline.
- Implement required dynamic fields and source constraints rather than copying
  static reference bytes.
- Add a bounded project-owned byte-signature DSL for responses that do not
  justify a full typed parser. It supports only finite exact/prefix/masked-field
  tests and capped extraction; no PCRE-compatible backtracking or arbitrary
  substitutions enter the packet path.
- Permit several variants per port and checked ranges while retaining stable
  deterministic catalogue order.
- Mark requests that create server state/logs, attempt authentication, read
  sensitive metadata, broadcast/multicast, use obsolete cryptography, amplify
  substantially, or require fixed-source behavior with explicit risk flags.
- Record unsupported independently unspecified proprietary behavior as a hard
  parity blocker rather than silently copying or claiming equivalence.

### Project capability-ledger rules

Each independently researched project protocol candidate ends Phase 31 in
exactly one repository state:

- `equivalent`: an independent builder covers the behavior and passes its lab
  fixture;
- `superseded`: a standards-current request elicits the same service more
  safely/effectively and the evidence is recorded;
- `unsafe-opt-in`: an equivalent exists only in an explicit nondefault profile;
  or
- `blocked`: no legal, independently specified implementation is available.

The separate owner-controlled reference comparison may map these project IDs to
the frozen baseline, but that worksheet is not generated, parsed, or shipped by
the project. Phase 31 cannot claim Nmap parity; only Phase 33 may make a factual
coverage claim after the independent comparison. An owner may accept a narrower
published claim only through a decision-log update that names the aggregate gap
rather than importing reference data.

### Tests

- catalogue-wide build/parse/fuzz/property tests;
- per-entry request and response fixtures with provenance;
- all mapped port/range and multi-variant selection tests;
- safe/comprehensive/legacy profile snapshots;
- signature-DSL worst-case work and hostile extraction tests;
- source-port, amplification, broadcast/multicast, and side-effect policy tests;
  and
- binary/catalogue size and startup/allocation baselines.

### Exit gate

The project capability ledger has no unexamined entry, every implemented variant
has independent provenance and responder evidence, and every deferred or blocked
family is reported before adaptive optimization or external parity comparison
begins.

### Implemented disposition

Catalogue `1.3.0` retains IDs 1–16 and adds IDs 17–33: UDP Echo, Daytime, Quote
of the Day, Character Generator, Active Users, Network Status, RIPv2, XDMCP,
Source-engine information, RakNet unconnected ping, BACnet/IP Who-Is,
EtherNet/IP ListIdentity, KNXnet/IP Search, BitTorrent DHT ping, DNS CHAOS
`version.bind`, NTP mode-6 READVAR, and SLP service-agent discovery. Safe mode
remains exactly IDs 1–9. Comprehensive and legacy selection remains independent
from exact risk consent and supports checked destination-port ranges.

The syscall-free finite signature engine validates at most 32 exact, prefix,
masked-byte, or 255-byte ASCII extraction clauses with a fixed 65,527-byte
worst-case work ceiling and no recursion, backtracking, callbacks, or partial
extraction results. Typed parsers remain authoritative where protocol structure
or transaction correlation warrants them.

The executable project-owned ledger covers every catalogue ID exactly once and
records 13 named blockers, including the Phase 30 deferrals and additional
independently unspecified or credential-bound candidates. Ledger validation
rejects duplicate project IDs, unknown/duplicate/uncovered probes, empty
evidence, and a blocked entry that names an implementation. No external
comparison identifiers occur in the shippable ledger. See
`49-phase-31-report.md` and D-045.

## Phase 32 — Adaptive service-aware probing and public schema 2

Status: complete; implemented 2026-07-14 under D-046

### Goal

Use response evidence to reduce unnecessary traffic and improve identification,
then freeze the public service-aware UDP API and result schema.

### Deliverables

- Order mapped likely probes first, then profile/intensity-eligible alternatives
  and the frozen exact-empty fallback policy.
- Stop unsent variants after decisive open/closed evidence while retaining late
  correlation for emitted variants.
- Use soft service-family evidence only to narrow compatible follow-ups; it can
  never become a definitive port state or product identity by itself.
- Add per-host pacing that reacts conservatively to correlated ICMP rate-limit
  symptoms without treating missing ICMP as proof of openness.
- Freeze bounded profile, risk-consent, intensity, strategy, and fallback
  semantics. Intensity affects eligible alternatives, not target or port
  expansion.
- Freeze schema-2 lazy TypeScript views, service-confidence vocabulary,
  physical/logical progress, and compatibility decoding.
- Add a declarative bounded custom-probe facility only if it can remain fully
  native after admission. It may describe exact request bytes, finite port
  ranges, tuple/prefix correlation, and the bounded signature DSL; it may not
  install a JavaScript packet callback or unbounded regex.
- Expose catalogue version/hash and selected policy in terminal summaries so
  results remain reproducible after catalogue evolution.
- Define catalogue semantic-versioning: corrections to invalid bytes are
  patch-level data changes; added variants are minor; ID/result reinterpretation
  requires a new schema/catalogue major.

### Better-than comparison

On the fixed independent responder matrix, compare exhaustive mapped probes with
adaptive mode across at least ten deterministic repetitions. Record:

- definitive state and service-family recall;
- false-positive service classifications;
- logical endpoints and physical datagrams;
- time to first decisive evidence and total completion;
- parser-invalid, duplicate, late, contradictory, and kernel-drop counts;
- CPU, peak native memory, and retained result bytes; and
- behavior under ICMP rate limiting and packet loss.

Adaptive mode is accepted only if it preserves all definitive results and
service-family identifications while reducing median physical requests or time
to decisive evidence. Otherwise exhaustive mapped mode remains the default.

### Exit gate

The public API/schema is stable, old explicit empty/custom behavior remains
available, adaptive selection has evidence rather than intuition, and catalogue
evolution is reproducible and versioned.

## Phase 33 — Parity audit, hardening, documentation, and release candidate

Status: implementation complete 2026-07-14; publication awaits native AArch64
execution

### Goal

Prove the completed subsystem is accurate, bounded, independently authored,
portable, and understandable before publishing any parity statement.

### Deliverables

- Perform a line-by-line provenance audit of the project catalogue and confirm
  no Nmap source/data is required or distributed.
- Run an independent behavioral comparison against the frozen Nmap reference on
  the same owner-controlled UDP responder matrix. Keep comparison mechanics
  outside distributed project code and record only aggregate behavior and
  independently owned captures/results.
- Require at least equal protocol-class response elicitation and definitive
  state accuracy for the accepted parity scope. Investigate every difference; do
  not average away a missing protocol family.
- Complete arbitrary-byte fuzzing, catalogue-generator fuzz/property tests,
  sanitizers, malformed-response fault injection, Worker teardown, repeated
  cancel/close, descriptor, RSS, native-memory, and result-backpressure stress.
- Repeat the full dual-stack routed/veth/VLAN namespace matrix with safe,
  comprehensive, empty, exact custom, and legacy-token modes.
- Add operator documentation for profiles, network impact, result confidence,
  service metadata, logical/physical counts, custom requests, and the meaning of
  `open|filtered`.
- Update examples to use protocol mode for common DNS/NTP/SNMP scans and show
  explicit empty/custom modes only when intended.
- Repeat optimized x86-64 artifact, glibc, consumer, reproducibility,
  dependency, advisory, and package-content gates. Cross-compile AArch64 and
  retain native AArch64 execution as a publication requirement.
- Advance the unpublished scanner to `0.2.0-rc.1` because protocol-aware default
  behavior and schema 2 are material feature/API changes.

### Release claim rules

- Do not say “Nmap compatible” or imply affiliation.
- State the exact frozen Nmap commit used only as a behavioral comparison
  baseline.
- Distinguish UDP port-probe parity from complete service/version detection.
- Publish the project catalogue version, profile, protocol-family count,
  blocked/opt-in status, and test topology with the claim.
- If any Phase 31 capability entry or external comparison remains blocked, use a
  narrower factual coverage statement and do not claim full parity.

### Exit gate

All ordinary, privileged, fuzz, sanitizer, stress, artifact, consumer, and
reproducibility gates pass; the project capability ledger and external
comparison have no unreported gap; documentation describes network impact
accurately; and native AArch64 execution passes before an AArch64 artifact or
package-wide publication.

## Cross-phase verification matrix

| Boundary       | Required evidence                                                                  |
| -------------- | ---------------------------------------------------------------------------------- |
| Catalogue      | deterministic generation, stable IDs/order/hash, complete provenance, bounds       |
| Builders       | independent golden bytes, dynamic-field properties, exact lengths/checksums        |
| Parsers        | strict structure, transaction match, hostile bytes, fuzzing, allocation caps       |
| Engine         | virtual time, multi-variant fairness, rate/retry accounting, evidence permutations |
| Native wire    | dual-stack capture, source-port isolation, ICMP quotes, route/neighbor deferral    |
| Results        | schema 1 compatibility, schema 2 columns, row/byte reservation, transfer           |
| Lifecycle      | pause/cancel/close/fault/teardown exactly once with bounded retained state         |
| Network impact | profile/risk separation, amplification, broadcast/multicast, fixed-source policies |
| Parity         | independent responder coverage and aggregate comparison to the frozen baseline     |
| Release        | dependencies, licenses, advisories, ELF/glibc, consumer, reproducibility, AArch64  |

## Phase ordering

| Phase | Depends on                    | May begin when                                                       |
| ----- | ----------------------------- | -------------------------------------------------------------------- |
| 27    | 24, D-040, closed plan review | provenance/API/resource contract is accepted                         |
| 28    | 27                            | exact requests and catalogue programme validate without live breadth |
| 29    | 28                            | multi-subprobe virtual/live aggregation is correct                   |
| 30    | 29                            | safe core and provisional schema 2 work end to end                   |
| 31    | 30                            | extended standards and risk enforcement work end to end              |
| 32    | 31                            | project capability ledger is complete                                |
| 33    | 32                            | public policy/schema and adaptive decision are frozen                |

Do not combine catalogue infrastructure, scheduler restructuring, broad protocol
content, adaptive policy, and release claims into one implementation phase. A
correctness, provenance, or network-impact defect blocks the dependent phase
until corrected and reverified.

## Closed preimplementation review questions

The Phase 27 readiness review closes these questions explicitly in
`44-udp-probe-parity-plan-review.md`:

1. Does the provenance process prevent NPSL code/data from entering an MIT
   artifact while still permitting factual behavioral comparison?
2. Are logical endpoint and physical subprobe counts unambiguous in the engine,
   API, summaries, and result reservations?
3. Can every correlation strategy remain collision-safe across four sessions,
   retries, fixed-source protocols, specification-required alternate response
   ports, and late grace without admitting weak cross-port matches?
4. Does schema 2 add service evidence without reinterpreting schema 1?
5. Are exact custom bytes truly exact, and is legacy token-prefix behavior
   explicit and bounded?
6. Are amplification, multicast/broadcast, fixed-source, authentication,
   sensitive-read, and stateful risks enforced by native admission rather than
   documentation or profile selection alone?
7. Can the catalogue generator and signature DSL remain deterministic, bounded,
   dependency-light, and fuzzable?
8. Do the separate project provenance ledger and external comparison audit
   distinguish payload coverage, port-state accuracy, and full service/version
   fingerprinting honestly without importing Nmap data?
9. Can the namespace responder matrix exercise every protocol family without
   depending on Nmap or Internet services?
10. Is the `0.2.0-rc.1` compatibility and migration story sufficient for the
    unpublished current candidate?

## Research basis

Local primary implementation references reviewed for behavioral architecture:

- Nmap commit `10dfd2ff1cef6c1925232db45352149b659979b4`: `payload.cc`,
  `payload.h`, `scan_engine.cc`, `scan_engine_raw.cc`, `service_scan.cc`,
  `service_scan.h`, `nmap-service-probes`, and `LICENSE`.

Implementation content must instead cite primary protocol sources, beginning
with the IANA Service Name and Transport Protocol Port Number Registry and the
applicable protocol RFCs/specifications. Phase 29 records the exact source and
section for each accepted builder/parser before its code is merged.
