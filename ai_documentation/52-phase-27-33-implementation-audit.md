# Phases 27–33 post-implementation audit

Status: complete  
Date: 2026-07-14  
Scope: Phases 27 through 33, D-041 through D-047

## Outcome

The Phase 27–33 architecture, public policy, catalogue ownership, bounded
multi-variant scheduler, native correlation, schema-2 result model, adaptive
policy, and release structure remain coherent. The audit found no API or
catalogue-identity change that requires a new stable probe ID, catalogue
version, result schema, or release-candidate version.

The audit did find parser-validation defects in Phase 29 and Phase 31 codecs.
Those defects could not corrupt memory—the parsers are safe Rust over bounded
slices—but some malformed datagrams could be misclassified as typed service
evidence and some valid final NTP control responses were rejected. All known
cases are corrected and covered by regression tests.

Native AArch64 execution remains the only publication gate. Cross-compilation
still passes and is not treated as execution evidence.

## Phase trace

| Phase | Reviewed boundary                                                                                            | Result                                                                                        |
| ----- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| 27    | immutable catalogue/request contracts, provenance validation, compatibility policy, retained schema decoding | correct; no change                                                                            |
| 28    | logical/physical identities, bounded waves, retries, evidence lattice, grace, row/byte reservation           | correct; no change                                                                            |
| 29    | nine safe builders/parsers, default policy, schema-2 native emission                                         | SNMPv3 and rpcbind parsers hardened                                                           |
| 30    | comprehensive probes, independent risk consent, parser work/state/response ceilings                          | correct; no policy change                                                                     |
| 31    | catalogue breadth, canonical fixtures, finite signatures, capability ledger                                  | DHT, NTP control, XDMCP, BACnet, EtherNet/IP, KNXnet/IP, SLP, and RPC/NFS validation hardened |
| 32    | adaptive sequencing/stopping, soft hints, ICMP pacing, public schema-2 views and summaries                   | correct; no change                                                                            |
| 33    | provenance boundary, namespace/stress/fuzz/sanitizer/release gates, narrow comparison claim                  | all locally available x86-64 gates pass again                                                 |

## Corrections

- SNMPv3 discovery now parses the complete BER envelope, header, USM security
  parameters, scoped PDU, Report PDU, request ID, and variable-binding list.
  Embedded version or `0xa8` marker bytes no longer prove a response.
- rpcbind and NFS NULL replies now require the accepted-reply structure to end
  exactly after the success discriminator; trailing bytes are rejected.
- BitTorrent DHT responses now use a bounded, depth- and item-limited bencode
  parser with ordered dictionary keys, a top-level two-byte transaction, the
  response discriminator, and a 20-byte node ID. Marker smuggling is rejected.
- NTP mode-6 parsing now accepts a complete final response and rejects an
  isolated `more` fragment, mismatched version/opcode/sequence, nonzero offset,
  and inconsistent count.
- SLP Service Replies now validate the complete header, language tag, error and
  URL counts, URL entries, bounded authentication blocks, extension policy, and
  exact message end. The former 18-byte incomplete fixture is rejected.
- XDMCP Willing/Unwilling replies now validate their exact `ARRAY8` field
  layouts. BACnet I-Am replies now require all four typed service arguments.
  EtherNet/IP ListIdentity replies now validate every CPF identity item.
  KNXnet/IP Search Responses now require bounded Device Information and
  Supported Service Families DIBs.
- Canonical fixtures were replaced with structurally complete independently
  constructed messages, and hostile regression tests cover embedded markers,
  trailing bytes, incomplete fragments, and truncated replies.

These are receive-side validation corrections. Request bytes, profile/risk
selection, destination ports, stable IDs, catalogue `1.3.0`, and its SHA-256
`427cdc09881907c610bbea8f6bc8cffa18e2819e3f7f04626adcf264e598b976` remain
unchanged.

## Verification

The post-audit source passes:

- `npm run ci`;
- `npm run udp:catalogue:check` and `npm run test:phase28`;
- the full privileged Phase 24/33 dual-stack veth/VLAN and fault matrix: 8 mode
  tests plus 3 lifecycle/fairness/neighbor-deferral tests;
- repeated Worker teardown stress with descriptor delta 0 and bounded RSS growth
  of 24,629,248 bytes;
- protocol parse fuzzing for 40,930 executions and serialization fuzzing for
  6,076,432 executions without a crash;
- AddressSanitizer and ThreadSanitizer over all 27 scanner-native tests;
- optimized x86-64 assembly, ELF/GLIBC verification, staged clean-consumer ESM
  and CommonJS checks, and two-build reproducibility;
- reproducible stripped scanner binary SHA-256
  `6532bfcadc50021d4b5857c95a0bb4e7a1f658ee2cf0b6623ebb631ab4159d0b`; and
- AArch64 Rust/native-addon cross-checking for the protocol, engine, and native
  crates.

The strict-format review used the primary protocol references already recorded
in the project catalogue, including the X.Org XDMCP specification, ASHRAE BACnet
material, RFC 9327, RFC 2608, RFC 3414, RFC 5531, and BEP 5. No external probe
database, payload, parser, or fixture was imported.

## Remaining gate

Run ordinary, privileged, artifact, consumer, and reproducibility gates on a
native AArch64 glibc runner before publishing the AArch64 target or the complete
scanner release. No other Phase 27–33 implementation blocker remains known.
