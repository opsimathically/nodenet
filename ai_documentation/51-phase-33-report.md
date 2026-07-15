# Phase 33 completion report

Date: 2026-07-14

Status: implementation and x86-64 release audit complete; publication remains
blocked on native AArch64 execution

## Outcome

Phase 33 closes the independently authored UDP-probe implementation with a
narrow, evidence-backed release claim. The scanner is now the unpublished
`0.2.0-rc.1` candidate. Catalogue `1.3.0` contains 33 implemented variants in 33
line-audited descriptors and the separate 46-entry capability ledger retains 13
explicit blockers. Because blockers remain, the project does not claim full Nmap
probe-database, service/version-detection, or product-identification parity.

The accepted claim is limited to UDP response elicitation and port-state
accuracy on the owner-controlled IPv4/IPv6 responder matrix. Against frozen Nmap
commit `10dfd2ff1cef6c1925232db45352149b659979b4` as a black-box baseline, the
scanner produced a correlated direct response and definitive `open` state for
every accepted live responder. The baseline did not exceed that coverage. No
Nmap source, data, payload, mapping, pattern, output, or comparison tool is
loaded or distributed by this repository.

## Catalogue provenance audit

Every row below was checked against its compiled descriptor, project builder,
strict parser, canonical project fixture, primary-source URL, and capability
ledger entry. `validate_udp_probe_catalogue` now fails closed for non-HTTPS
provenance or any external-comparison marker in a shippable descriptor;
`validate_udp_capability_ledger` applies the same separation to all ledger
fields.

| ID  | Project descriptor           | Primary specification owner/source | Audit |
| --- | ---------------------------- | ---------------------------------- | ----- |
| 1   | `dns-root-a-edns`            | RFC 1035/6891/7830                 | pass  |
| 2   | `ntp-client`                 | RFC 5905                           | pass  |
| 3   | `snmpv3-engine-discovery`    | RFC 3414                           | pass  |
| 4   | `rpcbind-null`               | RFC 5531                           | pass  |
| 5   | `stun-binding`               | RFC 8489                           | pass  |
| 6   | `coap-empty-con`             | RFC 7252                           | pass  |
| 7   | `asf-rmcp-presence`          | DMTF DSP0136                       | pass  |
| 8   | `memcached-version`          | memcached protocol                 | pass  |
| 9   | `pcp-announce`               | RFC 6887                           | pass  |
| 10  | `netbios-node-status`        | RFC 1002                           | pass  |
| 11  | `nfs-v3-null`                | RFC 1813/5531                      | pass  |
| 12  | `sip-options`                | RFC 3261                           | pass  |
| 13  | `ssdp-unicast-all`           | UPnP Device Architecture 1.1       | pass  |
| 14  | `l2tp-sccrq`                 | RFC 2661                           | pass  |
| 15  | `snmpv1-public-sysdescr`     | RFC 1157/MIB-II                    | pass  |
| 16  | `memcached-statistics`       | memcached protocol                 | pass  |
| 17  | `udp-echo`                   | RFC 862                            | pass  |
| 18  | `daytime`                    | RFC 867                            | pass  |
| 19  | `quote-of-the-day`           | RFC 865                            | pass  |
| 20  | `character-generator`        | RFC 864                            | pass  |
| 21  | `active-users`               | RFC 866                            | pass  |
| 22  | `network-status`             | RFC 869                            | pass  |
| 23  | `ripv2-routing-table`        | RFC 2453                           | pass  |
| 24  | `xdmcp-query`                | X.Org XDMCP                        | pass  |
| 25  | `source-engine-info`         | Valve server-query protocol        | pass  |
| 26  | `raknet-unconnected-ping`    | RakNet protocol                    | pass  |
| 27  | `bacnet-who-is`              | ANSI/ASHRAE 135 BACnet/IP          | pass  |
| 28  | `ethernet-ip-list-identity`  | ODVA EtherNet/IP                   | pass  |
| 29  | `knxnet-ip-search`           | KNX Association KNXnet/IP          | pass  |
| 30  | `bittorrent-dht-ping`        | BEP 5                              | pass  |
| 31  | `dns-chaos-version`          | BIND convention/RFC 1035           | pass  |
| 32  | `ntp-control-read-variables` | RFC 9327/NTP mode 6                | pass  |
| 33  | `slp-service-agent`          | RFC 2608                           | pass  |

The frozen catalogue identity remains
`427cdc09881907c610bbea8f6bc8cffa18e2819e3f7f04626adcf264e598b976`. The audit
found no descriptor without provenance, no catalogue/ledger coverage gap, and no
third-party comparison reference in shippable catalogue data.

## Behavioral comparison

The comparison ran outside distributed repository mechanics. The exact frozen
baseline was built locally and invoked as a client against the same disposable
veth responder fixture used by the project namespace matrix. Only these
aggregate, project-owned results are retained:

| Family | Accepted live endpoints | Scanner direct/open | Baseline direct/open | Baseline silence |
| ------ | ----------------------: | ------------------: | -------------------: | ---------------: |
| IPv4   |                       9 |                   9 |                    7 |                2 |
| IPv6   |                       8 |                   8 |                    6 |                2 |

The two baseline silences in each family remained `open|filtered`; they were not
incorrectly reported closed. The scanner's independently authored correlated
requests elicited definitive direct replies from those responders. Every
difference was therefore understood and none represented a missing scanner
protocol class in the accepted matrix. Product/version fingerprint breadth was
not scored and is outside this claim.

## Implementation corrections

- Advance scanner, native addon, target manifests, lockfiles, changelog, and
  release policy together to `0.2.0-rc.1`.
- Correct the clean-consumer gate from obsolete result schema 1 expectations to
  emitted schema 2, retained schemas `[1, 2]`, and catalogue `1.3.0`/33.
- Record emitted/accepted schema semantics, catalogue/profile defaults, blocker
  count, and AArch64 publication status in the machine-readable release policy.
- Expand the live namespace responder and assertions so safe protocol,
  comprehensive, empty, exact custom, and legacy token-prefix modes cover both
  IPv4 and IPv6 where their protocol descriptors permit it.
- Reject insecure or externally derived shippable provenance at the Rust
  validation boundary.
- Replace two newly deprecated atomic `fetch_update` uses with stable
  `try_update`, keeping stable Rust and current nightly sanitizer builds clean.
- Update operator documentation and common examples to prefer protocol mode,
  explain profiles/consent, confidence, `open|filtered`, logical versus physical
  counts, and the narrow behavioral comparison result.

## Verification evidence

The following passed locally on Linux x86-64, Node.js 26.4.0, npm 11, and Rust
1.97.0/nightly as appropriate:

- `npm run ci`, including formatting, ESLint, strict TypeScript, Rust format,
  Clippy with warnings denied, all Rust/Node tests, license checks, and zero npm
  production vulnerabilities;
- the privileged dual-stack/veth/VLAN namespace matrix: 8 scanner mode/topology
  tests plus 3 context-fault, four-session fairness/backpressure, and mixed-
  subnet cleanup tests;
- 64 Worker close/forced-teardown cycles with descriptor delta 0 and bounded RSS
  growth of 24,195,072 bytes;
- full protocol parse and serialize fuzz campaigns: 40,930 and 6,076,432
  executions, respectively, without a crash;
- full scanner plan/scheduler fuzzing: 89,451 executions without a crash;
- AddressSanitizer and ThreadSanitizer over all 27 native scanner tests;
- RustSec checks for the workspace and both fuzz lockfiles with no vulnerability
  (the already accepted unmaintained `paste` warning remains);
- optimized x86-64 clean-consumer packing and ESM/CommonJS lifecycle smoke;
- stripped x86-64 ELF verification with highest required GLIBC symbol 2.16,
  below the supported 2.28 floor;
- two clean release builds with identical SHA-256
  `6532bfcadc50021d4b5857c95a0bb4e7a1f658ee2cf0b6623ebb631ab4159d0b`; and
- AArch64 native-addon cross-compilation/type-checking.

## Remaining publication gate

Native AArch64 execution was not available on the project owner's hardware.
Cross-compilation is not a substitute. The AArch64 target package and any
package-wide publication remain blocked until the ordinary, privileged,
artifact, consumer, and reproducibility gates execute on a native AArch64 glibc
runner. This is the only unclosed Phase 33 publication gate; it is not an
unreported implementation gap.

The later adversarial implementation audit tightened several receive parsers
without changing request bytes, catalogue identity, public schema, or release
version, then repeated all locally available gates. See
[`52-phase-27-33-implementation-audit.md`](52-phase-27-33-implementation-audit.md)
for the corrections and current evidence.
