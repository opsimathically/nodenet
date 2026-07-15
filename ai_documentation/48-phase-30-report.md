# Phase 30 completion report

Status: complete

Date: 2026-07-14

## Outcome

Phase 30 extends the independently authored UDP catalogue from nine safe probes
to 16 total variants without changing the safe profile. Catalogue `1.2.0` adds
seven comprehensive-profile exchanges:

|  ID | Request                    |  Port | Required consent                         |
| --: | -------------------------- | ----: | ---------------------------------------- |
|  10 | NetBIOS node status        |   137 | `sensitiveRead`                          |
|  11 | NFS v3 NULL                |  2049 | none                                     |
|  12 | SIP OPTIONS                |  5060 | `sensitiveRead`                          |
|  13 | SSDP unicast M-SEARCH      |  1900 | `highAmplification`, `sensitiveRead`     |
|  14 | L2TP SCCRQ                 |  1701 | `statefulHandshake`                      |
|  15 | SNMPv1 public `sysDescr.0` |   161 | `authenticationAttempt`, `sensitiveRead` |
|  16 | memcached `stats`          | 11211 | `highAmplification`, `sensitiveRead`     |

The implementation uses primary RFC or protocol-owner specifications and
project-owned responder fixtures. It does not load, parse, generate from, copy,
or distribute Nmap source or `nmap-service-probes` data.

The frozen catalogue identity is:

```text
version 1.2.0
variants 16
sha256 de305709b350dd107e51f10178d8fd45ce1ae85961fc98a8b60cc0e4b3159384
```

## Risk and resource enforcement

- `safe` includes exactly IDs 1–9 even when every risk consent is supplied.
- `comprehensive` includes risk-free NFS NULL at sufficient intensity without
  consent, then includes a risk-bearing entry only when every declared risk is
  present in the separately snapshotted canonical set.
- Unknown, duplicate, or noncanonical native risk values fail before socket
  admission. Profiles, intensity, and consent are independent filters.
- Protocol-mode multicast, IPv4 limited-broadcast, or IPv6 multicast targets
  require `multicastOrBroadcast` consent and an explicit interface. No target is
  expanded implicitly.
- Catalogue validation checks response and typed-parser ceilings, conservative
  rounded amplification ratios, risk classification above the accepted
  amplification threshold, and state-lifetime consistency.
- Native typed service parsing is capped at 4 MiB per session and 256 KiB per
  target per runtime tick in addition to the existing 128-datagram receive cap.
  Budget exhaustion preserves tuple-level open evidence but withholds service
  identity and metadata.
- L2TP admission rejects a `maximumTimeoutMs` above its 10-second declared live
  state ceiling. Fixed-source and alternate-port entries remain unavailable
  rather than claiming ownership the current runtime cannot prove.

## Protocol behavior

Every accepted builder produces exact application bytes with correlation only in
fields permitted by that protocol. Strict parsers validate complete message
lengths, roles, transactions, bounded text, record counts, nested BER/RPC/AVP
structure, and declared per-probe response ceilings before returning service
evidence. SIP reconstructs its Via sent-by using the actual native source port.
SSDP is intentionally unicast and reports parsed rather than transaction-
correlated confidence. Memcached statistics reuses the existing memcached
service-family ID while retaining its distinct stable probe ID.

## Deferred candidates

- **mDNS/DNS-SD:** one multicast query may yield many source addresses. The
  frozen logical endpoint and result model requires the response target address
  to match, so treating those replies as one target would be dishonest and
  treating them as many results would require a new bounded ownership model.
- **TFTP:** the first response moves to a server-selected port and carries no
  echoed secret transaction. It remains blocked on independently proven
  first-response port pinning, same-target validation, and teardown/grace tests.
- **DHCP INFORM:** requires fixed source port, broadcast/interface
  prerequisites, and operator-controlled external ownership the current API does
  not claim.
- **IKE, DTLS, and QUIC:** a specification-valid discovery exchange requires
  cryptographic or handshake construction and an exact-pinned dependency,
  allocation, and binary-size review.
- **OpenVPN:** no accepted stable public discovery wire specification has been
  selected independently.
- **RADIUS:** useful responses require shared-secret or authentication
  semantics; the project does not manufacture credentials or label an invalid
  packet a protocol probe.

These are Phase 31 inputs, not silent omissions or approximate payloads.

## Verification

The Phase 30 implementation was exercised with:

- focused Rust unit and integration tests across `nodenet-protocols`,
  `nodenetscanner-engine`, and `nodenetscanner-native`;
- independent canonical request/response fixtures for every accepted family;
- wrong-transaction, truncation, arbitrary bytes, BER/RPC/AVP framing, catalogue
  drift, amplification, parser-budget, state-lifetime, and risk-matrix tests;
- scanner native build, strict TypeScript declarations, and hostile Node API
  tests;
- a disposable privileged namespace with seven independent live responders,
  checking exact stable probe IDs, service families, confidence, and `open`
  state in schema 2;
- the complete workspace CI gate and AArch64 cross-compilation recorded in the
  final implementation handoff.

Native AArch64 execution remains the pre-existing publication blocker and is not
claimed by this phase.

## Next action

Phase 31 may build the comprehensive/legacy capability ledger, additional
reviewed variants, and finite response signatures. It must preserve catalogue
IDs 1–16, all Phase 30 consent/resource semantics, and the unchanged safe
default. Final parity remains a Phase 33 claim.
