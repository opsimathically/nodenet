# Phase 31 completion report

Status: complete

Date: 2026-07-14

## Outcome

Phase 31 expands the independently authored UDP catalogue from 16 to 33 stable
variants while preserving IDs 1–16 and the exact nine-probe safe default. The
new `1.3.0` catalogue adds:

- historical UDP Echo, Daytime, Quote of the Day, Character Generator, Active
  Users, and Network Status exchanges;
- RIPv2 routing-table and XDMCP status queries;
- Source-engine and RakNet game discovery;
- unicast BACnet/IP, EtherNet/IP, and KNXnet/IP discovery;
- BitTorrent DHT ping;
- explicit legacy DNS CHAOS `version.bind` and NTP mode-6 READVAR variants; and
- SLP service-agent discovery.

The frozen catalogue identity is:

```text
version 1.3.0
variants 33
sha256 427cdc09881907c610bbea8f6bc8cffa18e2819e3f7f04626adcf264e598b976
```

## Selection and network impact

Safe mode remains IDs 1–9 even with every risk consent. Comprehensive mode adds
only entries at or below the selected intensity and only when all independently
required risk values are present. Legacy mode is a superset but does not grant
consent by itself. The new candidates use the existing `highAmplification`,
`statefulHandshake`, and `sensitiveRead` gates; none requires an implicit
broadcast, multicast, fixed source port, or target expansion.

Catalogue destination eligibility now supports checked inclusive ranges. The
engine evaluates them lazily against each selected port; it does not expand a
range into per-port memory. Repeated stable IDs are accepted only on disjoint
ranges, while overlap is rejected deterministically. RakNet uses this contract
for ports 19132–19133.

## Finite signatures and parsers

`nodenet-protocols` now provides a syscall-free byte-signature engine for simple
responses. Definitions are validated before use and are limited to 32 clauses,
255 copied ASCII bytes per extraction, a 65,527-byte input/work ceiling, and
finite prefix, exact-offset, masked-byte, or extraction operations. Matching has
no recursion, regex engine, backtracking, arbitrary substitutions, JavaScript
callback, or partial extraction result.

Structured protocols retain independent typed parsers. They validate framing,
declared length, message role, counts, actual source-address fields, bounded
text, and available transaction fields before returning service evidence. A
tuple-valid datagram can still prove `open`; malformed bodies never acquire a
service identity.

## Capability ledger and blockers

The shippable project-owned ledger contains 46 entries: 33 implemented
dispositions covering every stable probe ID exactly once and 13 explicit
blockers. Its validator rejects empty provenance/evidence, duplicate project
IDs, unknown or duplicate probe coverage, uncovered catalogue probes, and a
blocked entry that names implementation IDs.

The blocked set is mDNS/DNS-SD, TFTP, DHCP, IKE, DTLS, QUIC, OpenVPN, RADIUS,
CLDAP, SQL Browser, Ubiquiti discovery, pcAnywhere status, and a WireGuard
handshake probe. Each has a primary-source link and an ownership,
multi-responder, alternate-port, fixed-source, credential, cryptographic, or
stable-specification rationale. These are reported omissions rather than
malformed approximations. The ledger contains no Nmap name, mapping, payload,
pattern, or source-derived data.

## Verification

The implementation includes:

- catalogue-wide request-bound checks and a frozen deterministic SHA-256 drift
  gate;
- canonical independently assembled responses for every new family plus
  truncation and arbitrary-input rejection across all 33 parsers;
- finite-signature structural, hostile-input, extraction, and constant-work
  tests;
- capability-ledger completeness and fail-closed mutation tests;
- safe/comprehensive/legacy profile and independent risk-consent snapshots;
- checked range matching, disjoint/overlap validation, and lazy engine tests;
- protocol, engine, native, TypeScript, lint, formatting, hardening, and package
  tests through the root CI command;
- the existing seven-test privileged dual-stack namespace/regression matrix and
  a deterministic 579-execution protocol parser-fuzz corpus smoke run; and
- AArch64 cross-compilation of the protocol, engine, and scanner native crates.

No production dependency was added. Native AArch64 execution remains the
pre-existing publication blocker and is not claimed here.

## Next action

Phase 32 may implement adaptive evidence-driven ordering and early stopping over
this complete project ledger, then freeze the ergonomic public schema-2 names.
Phase 31 does not claim Nmap parity; the separate aggregate comparison and any
factual coverage claim remain Phase 33 work.
