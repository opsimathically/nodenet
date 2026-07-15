# Phase 29 completion report

Status: complete

Date: 2026-07-14

## Outcome

Phase 29 implements the accepted safe-core UDP pack and makes it the default
when a UDP probe omits `policy`. The implementation is independently authored
from primary protocol specifications and does not copy, parse, load, or invoke
Nmap code or data. This closes the Phase 29 safe-core coverage gate; it is not
the final comprehensive Nmap parity claim, which remains gated through Phases
30–33.

Catalogue `1.1.0` contains nine bounded, unicast, ephemeral-source probes:

- DNS root A with nonrecursive flags, EDNS(0), a 512-byte advertised ceiling,
  and an RFC 7830 Padding option;
- NTP version-4 client;
- credential-free SNMPv3 USM engine discovery;
- ONC RPC rpcbind v2 NULL;
- STUN Binding;
- CoAP Empty Confirmable ping with Empty Reset correlation;
- DMTF ASF/RMCP presence ping;
- correctly UDP-framed memcached `version`; and
- PCP ANNOUNCE, added as a useful low-impact discovery request that creates no
  mapping.

Broader multicast, authentication, sensitive-read, fixed-source, stateful, and
amplification-prone candidates remain outside safe mode and under Phase 30 or
later review.

## Architecture and safety

- Destination-port eligibility is evaluated from the compact programme during
  admission and emission; it does not materialize target × port × variant
  products and prevents a protocol request from reaching unrelated ports.
- Per-transmission protocol fields derive from the existing session-secret
  correlation token. Builders produce exact payload bytes with no private
  prefix. Strict parsers check complete lengths, roles, transactions, nested
  structures, bounded text, and protocol ceilings before producing identity.
- Direct tuple-matched UDP remains `open` even on an unidentified/malformed
  body. Only parser success supplies service family, confidence, metadata, and
  the stronger protocol-transaction evidence code.
- Winning metadata is capped at 1 KiB, reserved before transmission, copied into
  Rust-owned result state, and released on pull, discard, cancellation, or drop.
  Session and environment ceilings remain 16 MiB and 64 MiB; one batch remains
  capped at 4 MiB of variable service metadata.
- Protocol sessions select native schema 2 once at admission. Schema 2 retains
  all schema-1 columns and adds terminal probe, variants attempted, response
  kind, service family/confidence, and deterministic metadata records. Explicit
  empty/custom compatibility sessions remain schema 1; both decode paths stay
  supported.

## Compatibility

- Omitted UDP policy now means safe protocol mode with `unmapped` empty
  fallback.
- `{ mode: "empty" }` and `{ mode: "custom", ... }` retain exact generic UDP
  behavior.
- The deprecated top-level `payload` remains explicit legacy token-prefix
  compatibility.
- Catalogue capability is version `1.1.0`, nine variants, SHA-256
  `776cfdda60f35e24e2b1512760c8f5c5ae4ef8a9358914763d64ee24ab59e16a`, and
  `protocolModeAvailable: true`.

## Verification

The completion run includes:

- `cargo test --workspace --all-targets`;
- deterministic catalogue validation and stable SHA-256 drift detection;
- canonical request/response, wrong-transaction, truncation, arbitrary-byte,
  port-eligibility, schema-2 sealing, and metadata-accounting unit tests;
- `npm test --workspace @opsimathically/nodenetscanner`;
- root lint, format, type, dependency, and build gates;
- privileged namespace scanner tests on the supported local x86-64 host; and
- AArch64 cross-compilation.

The final command results are recorded in the implementation handoff. Native
AArch64 execution remains the existing publication gate and is not claimed by
this phase.

## Next action

Phase 30 may implement the extended standards pack and explicit-risk consent. It
must preserve the Phase 29 safe default and cannot reclassify a risk-bearing
request as safe merely to increase coverage.
