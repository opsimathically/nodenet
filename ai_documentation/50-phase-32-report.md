# Phase 32 completion report

Date: 2026-07-14  
Status: implementation complete

## Outcome

Phase 32 adds opt-in adaptive protocol-aware UDP scheduling without changing the
default exhaustive contract. Adaptive endpoints emit one catalogue-ordered
variant at a time, allowing evidence to prevent later transmissions. Direct UDP
and target port-unreachable evidence stop unsent work while every emitted
correlation remains valid through late grace. Silence still settles only as
`open|filtered`.

The implementation is syscall-free in the scheduler and introduces no unsafe
code or production dependency. Existing exact-empty and exact/prefix-correlated
custom payload policies remain available and retain schema 1.

## Evidence policy

- Catalogue order is deterministic: mapped primary variants precede eligible
  alternatives and the configured empty fallback.
- Exhaustive programmes retain the existing bounded four-variant waves.
- Adaptive programmes admit one active variant per logical endpoint.
- Rank-4 direct UDP and rank-3 target port-unreachable evidence stop unsent
  adaptive variants. Lower-rank filtering evidence does not.
- A `UdpServiceHint` carries only a numeric family and narrows compatible
  follow-ups; it never updates state, terminal reason, or service metadata.
- Correlated ICMP followed by a fully silent adaptive attempt can delay later
  work for that active host by one checked timeout. The cooldown is diagnostic
  (`udpIcmpPacing`) and cannot change classification.

## Public API and reproducibility

The already-frozen `strategy: "adaptive" | "exhaustive"` input is now fully
implemented. Session summaries add a normalized `udp.policy` view and, for
protocol mode, the exact catalogue version and SHA-256. Summary progress keeps
logical work (`logicalProbes`) separate from physical transmissions
(`progress.sent`).

Schema-2 lazy rows now expose typed terminal catalogue ID, variants attempted,
response kind, service family, confidence, and bounded decoded service metadata.
The decoded record has a stable product, optional version, and ordered finite
field-ID/value list. Old schema-1 batches continue to decode without synthetic
UDP properties.

Catalogue evolution follows semantic versioning under D-046, with the content
hash as the exact identity. The optional declarative signature-DSL custom-probe
surface was deliberately not added: native exact custom bytes already satisfy
the retained customization requirement, and no Phase 32 measurement justified
expanding the public parser attack surface.

## Comparative verification

The deterministic engine comparison runs exhaustive and adaptive modes ten times
against the same four-variant responder event. Both retain identical definitive
open state. Median initial physical requests are four for exhaustive and one for
adaptive. Separate tests prove closed early stopping, late-grace retention, and
non-terminal soft narrowing.

The privileged namespace matrix adds ten repetitions per strategy against the
independent DNS responder. It requires identical open/service-family results,
checks recorded policy/catalogue identity, and requires adaptive median physical
UDP transmissions to fall from two to one. Phase 33 retains broader loss,
rate-limit, resource, and external owner-audit measurements.

## Verification record

- `cargo test --workspace --locked`: passed.
- `npm test --workspace=@opsimathically/nodenetscanner`: passed (ordinary tests;
  privileged cases skipped by design).
- `npm run test:phase28`: passed, including the ten-repetition comparison.
- `npm run ci`: passed, including formatting, ESLint, TypeScript, strict Clippy,
  all ordinary Rust/Node tests, dependency review, and release policy.
- `sudo npm run test:phase22:namespace`: passed 8/8, including ten exhaustive
  and ten adaptive DNS repetitions with identical open/family evidence and
  median UDP transmissions of two versus one.
- AArch64 `cargo check` passed for the protocol, engine, and native scanner
  crates.
- Scanner plan fuzz smoke completed 1,000 executions without a crash.

## Remaining work

Phase 33 is next. Native AArch64 execution remains a publication gate; local
AArch64 compilation is not a substitute.
