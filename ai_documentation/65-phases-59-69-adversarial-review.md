# Phases 59–69 adversarial implementation review

Last updated: 2026-07-15

Scope: D-057, D-058, Phases 59 through 69, and implementation report 64

Status: historical review; all findings repaired by report 66

## Verdict

The implementation has a sound bounded-parser and fail-closed admission base,
and every locally runnable ordinary and privileged test remains green. It is not
yet congruent with the accepted Phase 59–69 contracts closely enough to retain
the `implementation-complete` or Phase 69 release-candidate claims.

This review found one high-severity functional/contract defect, four
medium-severity correctness or enforcement defects, and two lower-severity
assurance/API defects. No memory unsafety, unchecked packet-sized allocation,
panic path across N-API, active no-go probe, copied comparison payload, or new
credential/mutation behavior was found.

Phases 59, 62, 63, 64, and 69 are reopened. The existing implementation report
remains useful as a historical record of what was built and which gates passed,
but it is not the current release-readiness authority.

## Findings

### F-065-01 — High — RIPv1 whole-table discovery terminates after one datagram and discards the routes

The emitted RIPv1 request is the RFC 1058 whole-table request, not a
single-route diagnostic. The implementation nevertheless uses an ordinary
target/port probe. Its parser accepts one response datagram, validates each
entry, and returns only the number of entries. It does not retain destination,
metric, responder, interface/network scope, or lifetime as topology evidence.

A direct UDP reply is rank-four decisive evidence in the shared scanner
scheduler. The first RIPv1 datagram therefore retires the physical probe and
finishes the logical programme. Additional response datagrams cannot contribute
routes. The project responder emits one route in one datagram, so the live gate
does not expose this behavior.

This violates the Phase 62 contract that whole-table mode bound response
datagrams, bytes, routes, metrics, elapsed time, and amplification, retain typed
route topology, and prove multi-datagram behavior. It also makes the public
`typedEvidence` dimension materially misleading: the implementation proves RIPv1
service presence and a first-datagram route count, not routing-table discovery.

Required disposition: implement RIPv1 as a bounded finite/conversation operation
with topology results and multi-datagram collection. Narrowing the capability to
single-datagram presence would not complete the accepted Phase 62 deliverable.

### F-065-02 — Medium — Valid Quake II and Quake III replies are rejected below authoritative protocol limits

Both Quake parsers pass their complete info string through the shared
`bounded_text` helper, which rejects values longer than 255 bytes. The pinned
authoritative Quake II implementation defines `MAX_INFO_STRING` as 512 bytes;
the pinned Quake III implementation defines it as 1,024 bytes. Their catalogue
descriptors allow responses up to 4,096 bytes, so the hidden 255-byte ceiling is
not visible in public bounds.

The shared per-field limits also fit neither family exactly: Quake II's pinned
key/value arrays are 64 bytes including termination, while Quake III permits
much larger bounded fields. The current 64-byte key and 256-byte value checks
can therefore accept noncanonical Quake II fields while rejecting valid Quake
III fields.

Quake II additionally rejects a 65th non-empty player row even though the pinned
Yamagi implementation defines `MAX_CLIENTS` as 256 and builds status replies up
to its bounded message capacity. A legal status reply can therefore yield an
`open` UDP result while losing the advertised typed service evidence. The short
canonical fixtures do not test 256/512/1,024-byte boundary cases or more than 64
player rows.

Required disposition: use protocol-specific borrowed-slice validation with the
authoritative per-family limits, retain the global allocation and metadata
ceilings, and add exact accepted/rejected boundary tests. Player rows should be
bounded by the wire envelope and authoritative family limit rather than the
unrelated Quake III client ceiling.

### F-065-03 — Medium — Transaction-correlated service results retain tuple-only generic evidence strength

The Quake III and Mumble parsers correctly return transaction-correlated service
confidence after exact 64-bit challenge/timestamp comparison. The result runtime
then derives generic evidence strength from a hard-coded probe-ID switch that
stops at earlier catalogue IDs. Probe IDs 36 and 37 fall through to
`TupleCorrelatedUnauthenticated`.

Consequently a result can simultaneously expose `udpServiceConfidence` as
`transactionCorrelated` and `evidence` as `tuple`. Quake III's descriptor makes
the drift worse: its prose says challenge-correlated, but its descriptor uses
`NO_TX`; Mumble has the expected offset-4 64-bit transaction metadata.

Required disposition: make correlation strength descriptor/parser-owned or add
the new IDs to one exhaustively validated mapping. Catalogue validation and
tests must prove that any implementation claiming correlation has matching
descriptor metadata, parser behavior, service confidence, and public strength.

### F-065-04 — Medium — The Phase 59 resource contract is published as hard admission data but is not cross-validated or enforced

The registry validator checks that resource values are nonzero and below a few
global maxima. It does not prove that:

- the compiled catalogue count is within `maximumCompiledVariants`;
- implemented probe/discovery descriptors are within response, query, metadata,
  endpoint, or state ceilings;
- individual descriptors are strictly narrower than the registry ceiling; or
- an admitted plan reserves against `maximumPhysicalQueries` or the other
  coverage-registry values.

Quake II and Quake III already use the full 4,096-byte registry response
ceiling, contradicting the readiness rule that individual descriptors be
strictly narrower. The public README calls these values hard ceilings, but
actual runtime admission uses separate scanner/session limits. A smaller but
internally inconsistent resource contract would pass the Rust validator.

Required disposition: connect this contract to catalogue, discovery, and runtime
admission validation; define each value's scope; and add mutation tests that
prove every undersized contract fails closed.

### F-065-05 — Medium — Implemented coverage dimensions are self-attested rather than demonstrated

The `implemented!` macro assigns request, correlation, typed-evidence, and
project-responder dimensions to every implemented row automatically. Registry
validation only checks that the bits exist and that the implementation ID is
present. It does not bind those dimensions to a builder, transaction definition,
typed parser, responder fixture, or positive/negative test identity.

This is why the Quake III descriptor/runtime correlation drift and incomplete
RIPv1 typed-evidence claim passed Phase 59 and Phase 69. The TypeScript test
confirms counts and IDs, not the semantic evidence behind each dimension.

Required disposition: validate explicit evidence references per dimension or
derive dimensions from checked implementation metadata. Tests must join every
implemented row to its descriptor, parser correlation kind, risk requirements,
canonical responder, and hostile/boundary cases.

### F-065-06 — Low — The provenance gate enforces paths, not the promised names or complete shippable surface

`udp:provenance:check` scans four files for three prohibited path fragments. It
does not reject comparison names, and it does not inspect fixtures, reports,
generated/staged package contents, or other release inputs. Rust validation
rejects the comparison name in four coverage-row fields only; it does not cover
catalogue, capability, or release-policy content generally.

No prohibited payload or runtime dependency was found, so this is an assurance
gap rather than evidence of contamination. It does mean the gate does not
implement R-059-07's stated source-tree behavior.

Required disposition: define an allowlisted clean-room vocabulary for necessary
historical documentation, then inspect all shippable registries, fixtures, and
staged artifacts for prohibited names, paths, generated inputs, and payload
provenance without false-positive matching the audit documents themselves.

### F-065-07 — Low — Public coverage risks cannot be mapped safely to runtime consent risks

`UDP_COVERAGE_CAPABILITIES.entries[].risks` uses a conceptual taxonomy such as
`amplification` and `topologyDisclosure`, while runtime admission uses names
such as `highAmplification` and `sensitiveRead`. Quake III and Mumble publicly
list only coverage-level amplification but require both runtime consents. The
README has the correct manual table and admission fails closed, but a caller
cannot derive a valid policy from the exported capability row.

Required disposition: explicitly name the conceptual field or export a separate
`requiredConsents` field derived from the descriptor. Native/TypeScript parity
should verify the exact consent set.

## Test and assurance gaps

The new implementation has useful canonical, arbitrary-byte, truncation,
catalogue-bound, ordinary API, and live namespace coverage. The following
accepted cases are not directly demonstrated:

- RIPv1 delayed, duplicate, multi-datagram, amplification-stop, cancellation,
  and route topology retention;
- Quake II/III authoritative info-string boundaries and Quake II player-count
  boundaries;
- explicit Quake III wrong-challenge and Mumble wrong-timestamp assertions in
  the focused parser suite;
- descriptor-to-result correlation-strength parity for IDs 34–37;
- undersized resource-contract mutation failures; and
- provenance rejection across the complete staged artifact surface.

Fuzzing and sanitizer success remain valuable memory-safety evidence, but they
do not replace semantic boundary assertions or prove a multidatagram state
machine that does not currently exist.

## Verified strengths

- Catalogue IDs 1–33 remain unchanged; catalogue `1.4.0` has 37 variants and the
  recorded stable digest.
- No new probe enters the safe profile. Runtime admission independently requires
  the documented `highAmplification` and `sensitiveRead` consents.
- No-go and threat-excluded rows have no schedulable implementation ID.
- The four new builders are bounded and independently framed; Quake III and
  Mumble compare their echoed 64-bit values exactly.
- New parsers operate on bounded slices with checked envelopes; no new `unsafe`
  block or packet-sized unbounded allocation was found.
- Native/TypeScript registry copies are immutable and fail closed on structural
  membership drift.
- All local ordinary and privileged gates listed below pass on x86-64 glibc
  Linux.

## Verification performed during this review

- `cargo test -p nodenet-protocols --locked`: 51 unit tests, allocation,
  foundation, Phase 17, and Phase 18 tests passed.
- `npm run test --workspace=@opsimathically/nodenetscanner`: 62 passed, 21
  privilege-gated skips, 0 failures.
- `sudo npm run test:namespace --workspace=@opsimathically/nodenetscanner`: 17
  passed, 0 skipped, including the four new responder paths.
- `npm run udp:catalogue:check`: catalogue `1.4.0`, 37 variants, digest
  `a925984228bf447e952d9f1f0970631ccafebddc4d25e6435b88c109573d1f32`.
- `npm run udp:provenance:check`: passed its current four-file/path-only scope.

Native AArch64 execution remains an external publication gate. These findings
are independent blockers on x86-64 and must be resolved before repeating the
full Phase 69 release matrix.

## Repair order

1. Replace RIPv1 target/port handling with the accepted bounded multi-datagram
   topology operation and its lifecycle/accounting tests.
2. Correct Quake protocol limits and add authoritative boundary fixtures.
3. Unify descriptor/parser/result correlation metadata and strength.
4. Make coverage dimensions and resources executable cross-registry contracts.
5. Export exact runtime consents and strengthen the provenance/artifact gate.
6. Repeat ordinary, namespace, fuzz, sanitizer, stress, artifact, consumer,
   reproducibility, x86-64, and native AArch64 gates before closing Phase 69.
