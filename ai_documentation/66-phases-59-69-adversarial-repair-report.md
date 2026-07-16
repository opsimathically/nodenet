# Phases 59–69 adversarial repair report

Last updated: 2026-07-15

Scope: findings F-065-01 through F-065-07, D-059, and reopened Phases 59, 62,
63, 64, and 69

Status: repairs complete; all available x86-64 gates pass; native AArch64
execution remains the external publication gate

## Outcome

All seven findings from adversarial review 65 are repaired without admitting a
new coverage candidate, changing catalogue IDs 1–37, broadening the safe
profile, or authorizing derived network work. Catalogue `1.4.1` contains the
same 37 variants with corrected Quake bounds and correlation metadata. Coverage
registry `1.1.0` contains the same 41 final dispositions and now exposes exact
runtime consents and validates its claims against executable implementations.

RIPv1 whole-table support is now discovery operation 10. Catalogue probe 34 is
retained as a deliberately narrow single-datagram compatibility/service probe;
it is no longer the implementation credited for route discovery.

## Repairs by finding

### F-065-01 — RIPv1 topology and response lifecycle

- Add a strict RFC 1058 whole-table request and response codec that retains each
  destination and metric.
- Add targeted IPv4 discovery operation 10, `ripv1-routing-table`, using one
  ephemeral-source request to port 520 and a 3,000 ms response window.
- Retain bounded typed `route` rows with router, destination, classful-address
  semantics, metric, protocol version, evidence lifetime, responder, port, and
  observed interface.
- Bound each target query to 10 tuple-valid datagrams, 5,040 bytes, 250 routes,
  32,768 metadata bytes, and the operation deadline. Charge malformed
  tuple-valid traffic before parsing, stop at exhaustion, and mark retained rows
  `truncatedByPolicy`.
- Preserve generic discovery cancellation, duplicate suppression, immutable
  batching, target/source validation, and shared environment admission.
- Extend the project namespace responder to return two independent datagrams and
  prove both routes propagate through the public TypeScript API.

### F-065-02 — Quake protocol envelopes

- Replace the shared 255-byte text helper with protocol-specific borrowed ASCII
  validation.
- Enforce Quake II's 511-byte information payload, 63-byte keys/values, and
  maximum 256 player rows within its 1,400-byte descriptor envelope.
- Enforce Quake III's 1,023-byte information, key, and value limits within its
  1,041-byte descriptor envelope.
- Truncate only exported product metadata to the existing 255-byte result-field
  ceiling instead of rejecting otherwise valid protocol evidence.
- Add accepted/rejected authoritative-envelope boundaries, 256/257 player
  boundaries, and explicit wrong-challenge/wrong-timestamp tests.

### F-065-03 — Correlation parity

- Give Quake III descriptor 36 an exact offset-28 64-bit transaction field.
- Map probes 36 and 37 to `ProtocolTransaction64` generic evidence strength.
- Test public strength for both IDs; parser tests independently prove exact
  challenge/timestamp rejection.

### F-065-04 and F-065-05 — Executable coverage contracts

- Cross-validate every implemented coverage row against the actual catalogue or
  discovery descriptor: execution model, builder/parser identity, response,
  metadata, entity, state-lifetime, physical-query, and required-risk bounds.
- Require individual implementations to remain strictly inside each aggregate
  coverage ceiling and require the compiled catalogue itself to fit.
- Maintain an explicit project-responder evidence allowlist for every credited
  implementation; a missing responder association fails registry validation.
- Add undersized-contract and consent-drift mutation tests. The four mandatory
  evidence dimensions are no longer accepted from an unresolvable ID.

### F-065-06 and F-065-07 — Provenance and public consent

- Extend the provenance gate from four whole-file path checks to exact shippable
  registry regions, project-owned fixture trees, release policy, and every
  present staged artifact. Shippable registry/fixture data rejects both
  prohibited comparison paths and the external scanner name; staged packages
  reject leaked comparison/build inputs without flagging historical audit prose.
- Export immutable `requiredConsents` on every coverage row and validate native,
  TypeScript, descriptor, release-policy, and test parity. ASF/RMCP requires no
  additional consent; RIPv1, Quake II, Quake III, and Mumble each require
  `highAmplification` and `sensitiveRead`.

## Verification record

Passing on x86-64 glibc Linux:

- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets --locked -- -D warnings`;
- `cargo test --workspace --locked`;
- scanner build, TypeScript type tests, Prettier, ESLint, and ordinary Node test
  suite: 62 passed, 22 privilege-gated skips, 0 failures;
- privileged namespace matrix: 18 passed, 0 skipped, including multi-datagram
  RIPv1 and all Phase 59 responder paths;
- Phase 24 worker teardown stress: passed with zero descriptor delta;
- protocol parser and serializer fuzz campaigns: no crash;
- native scanner unit tests under AddressSanitizer and ThreadSanitizer: 36 of 36
  passed under each;
- Miri coverage-registry suite: 3 of 3 passed;
- catalogue identity: `1.4.1`, 37 variants,
  `90c1589cd264385c6931cd6ed9efdc216f352239790a9026830bfe98cffe5e56`;
- expanded provenance, release policy, optimized x86-64 artifact/glibc check,
  staged package assembly, clean consumer install, and reproducible binary
  checks passed. The reproducible native digest was
  `dac3f03440f15d8c5a031ecc7f4f32c0e8579161b6dcf2e1d7cae52c05a839d3`.

## Remaining gate

Native AArch64 execution cannot be performed on this host and remains mandatory
before publication. No finding from review 65 remains open on x86-64. Phase 69
is locally complete but is not a cross-architecture release approval.
