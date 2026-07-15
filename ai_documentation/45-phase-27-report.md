# Phase 27 completion report

Status: complete  
Completed: 2026-07-14  
Scope authority: D-040, D-041, `43-udp-probe-parity-plan.md`, and
`44-udp-probe-parity-plan-review.md`

## Outcome

Phase 27 implements the bounded foundations needed for independently authored
protocol-aware UDP work without beginning Phase 28 scheduling or Phase 29
protocol breadth. The production catalogue deliberately has zero variants. No
Nmap source, probe registry, generated data, helper process, runtime link, or
build dependency entered the repository.

The scanner now distinguishes exact custom bytes, exact empty payloads, and the
legacy 16-byte token-prefix path. One UDP definition is normalized once into a
native-owned per-family request programme. Logical and physical identity types
are separate foundations, but the live scheduler remains single-variant until
Phase 28.

## Implemented contracts

### Catalogue, provenance, and request construction

- `nodenet-protocols` owns stable UDP probe/service IDs, profile and risk types,
  address-family and endpoint policies, source-port constraints, port ranges,
  intensity, response bounds, correlation fields, and primary-source provenance.
- Catalogue validation caps 256 variants, requires deterministic ID/port
  ordering, permits only registered builder/parser IDs, and rejects missing
  provenance, invalid/fixed source constraints, unsafe safe-profile entries,
  zero or greater-than-65,527-byte response bounds, overlapping/out-of-range
  correlation fields, more than eight correlation fields, and request templates
  above 4 KiB.
- The project-owned catalogue is version `1.0.0`, contains zero Phase 27
  variants, and has frozen canonical SHA-256
  `39a4b724558d17b4f159a954a7acf1c68fd1c2ae5b215c2d306f8a05bac1647f`.
  `npm run udp:catalogue:check` validates and prints that identity.
- `UdpRequestPlan` copies at most 4 KiB, admits at most eight non-overlapping
  checked dynamic fields, reports its exact encoded length, validates all patch
  indices/types/widths before mutation, and writes into caller-owned storage
  without allocation.

### TypeScript and native UDP policy

- Public policy discriminants cover `protocol`, `empty`, and `custom`, including
  exact profile/intensity/strategy/fallback names and the six independent risk
  consent names.
- Hostile getters are read once, payloads are copied before native admission,
  unknown/duplicate risks fail, and risk order becomes canonical.
- `custom/tuple` is byte-exact, `empty` has zero payload bytes, and
  `custom/prefixToken` deliberately prepends the existing token. The deprecated
  top-level `payload` spelling and omitted policy preserve legacy behavior.
- Policy and top-level payload conflict, duplicate UDP definitions fail, and
  native validation repeats the TypeScript boundary checks.
- Protocol policy is normalized but start returns `unsupported` in this phase.
  `UDP_PROBE_CATALOGUE.protocolModeAvailable` is therefore false. This is an
  intentional phase gate, not a missing fallback.

### Identity and retained result schema

- The deterministic engine exports distinct `LogicalProbeId`, `WireProbeId`,
  `ProbeVariantId`, and `WireProbeIdentity` foundations without changing the
  existing scheduler's one-emission behavior.
- The TypeScript retained-batch input is an explicit schema-1/schema-2 union.
  Native sessions continue emitting schema 1.
- Schema 2 retains all version-1 columns and requires terminal UDP probe ID,
  variants attempted, response kind, service family, service confidence, and
  bounded service-metadata columns.
- Validation enforces exact column widths, little-endian offsets, response and
  confidence vocabularies, schema-specific evidence codes, 1 KiB records,
  255-byte UTF-8 strings, 32 ordered unique extras, and known stable binary
  field IDs. Version 1 rejects version-2-only columns.
- Both schemas copy into Node-owned storage and preserve the existing mutation,
  lazy view, transfer-list, and detached-buffer behavior.

## Safety and resource evidence

- Protocol catalogue and request code remains syscall-free and denies unsafe
  Rust.
- Request-plan failures are transactional: output is unchanged for short
  buffers, duplicate/unknown fields, width mismatches, overlap, or overflow.
- Native packet payload assembly is tested directly for exact and explicit
  prefix modes; no custom exact byte is silently modified.
- Catalogue/template/session/control limits are independent and checked before
  live socket admission.
- Schema-2 offsets and records are checked before lazy access, copied across the
  hostile input boundary, and never retain caller-owned buffers.

## Verification

The following Phase 27-focused gates pass locally on x86-64 Linux:

- `cargo test -p nodenet-protocols -p nodenetscanner-engine -p nodenetscanner-native --locked`
- `cargo clippy -p nodenet-protocols -p nodenetscanner-engine -p nodenetscanner-native --all-targets --locked -- -D warnings`
- `npm test --workspace=@opsimathically/nodenetscanner`
- `npm run typecheck --workspace=@opsimathically/nodenetscanner`
- `npm run lint --workspace=@opsimathically/nodenetscanner`
- `npm run udp:catalogue:check`
- `npm run ci`
- `cargo check -p nodenet-protocols -p nodenetscanner-engine -p nodenetscanner-native --target aarch64-unknown-linux-gnu --locked`
- `sudo npm run test:phase22:namespace`

The scanner Node suite passed 26 ordinary tests with nine explicitly gated
privileged/stress cases skipped after the final detached-buffer test was added.
The focused Rust run passed 86 tests, and the complete workspace CI gate passed.
The privileged namespace matrix passed five tests, including receiver-side
exact-byte and explicit-prefix UDP assertions. All affected Rust crates compile
for AArch64. Native AArch64 execution remains an existing publication gate;
Phase 27 does not claim runtime verification on AArch64.

## Deferred by design

- multiple live physical variants per logical endpoint, resource reservation,
  correlation aggregation, and evidence settling: Phase 28;
- production safe protocol descriptors/builders/parsers and a payload-less
  protocol-aware default: Phase 29;
- extended risk-bearing standards and comprehensive/legacy breadth: Phases
  30–31;
- adaptive early stopping and final ergonomic service views: Phase 32;
- parity/provenance audit and any factual parity claim: Phase 33; and
- native schema-2 emission: Phase 29 after aggregation and the safe pack exist.

Phase 28 is now the next implementation phase. It must consume these contracts
without changing omitted UDP behavior or exposing Phase 29 protocol breadth.
