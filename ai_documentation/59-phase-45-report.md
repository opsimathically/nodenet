# Phase 45 completion report

Status: complete  
Date: 2026-07-15

## Outcome

Phase 45 adds the additive evidence schema, bounded deterministic evidence
ledger, current-result adapters, canonical risk vocabulary, and generalized
same-address derived-work authority required by the Phase 45–58 roadmap. It adds
no socket, descriptor, native runtime, protocol transmission, or production
dependency.

Existing scan schemas 1/2, discovery schema 1, UDP catalogue `1.3.0`, discovery
registry `1.0.0`, and Phase 37 rpcbind behavior are unchanged.

## Implemented contract

- Evidence schema 1 represents run-qualified source origins, typed entity keys,
  confidence, disposition, monotonic observation/expiry, optional wall context,
  bounded fields, and bounded relations.
- Rust and TypeScript enforce 8,192 records, 128 fields, 64 relations, 1 KiB
  items, 16 KiB per record, and 16 MiB per batch.
- Exact duplicates coalesce; distinct records under one canonical entity remain
  deterministic conflicts. Phase 45 does not merge devices.
- Scan and discovery adapters retain source kind/schema/run/record identity and
  never upgrade the source evidence strength.
- The derived-work authority registry rechecks target scope, exclusions,
  same-address containment, registered derivation/operation pairs, independent
  risk consent, depth, parent/target/total fan-out, and duplicates before work
  is admitted.
- Authentication-attempt and target-mutation risks are represented but never
  admitted by the Phase 45 registry.
- The original rpcbind graph remains available and compatible while later
  enrichment paths have stable registered vocabulary.

## Verification

- Pre-change `cargo test --workspace --locked`: passed.
- Pre-change scanner typecheck and complete ordinary Node tests: 37 passed, 14
  explicitly privileged/stress tests skipped.
- `cargo test -p nodenetscanner-engine --locked`: 53 tests passed, including new
  evidence and authority cases.
- `cargo clippy -p nodenetscanner-engine --all-targets --locked -- -D warnings`:
  passed.
- Scanner TypeScript build and strict type API test: passed.
- Focused Node evidence tests: 3 passed.
- Scanner ESLint gate: passed.
- Prettier and `git diff --check`: passed at the Phase 45 boundary.

No privileged test was required because this phase is intentionally
syscall-free. Phase 46 owns the first live capture and privilege matrix.
