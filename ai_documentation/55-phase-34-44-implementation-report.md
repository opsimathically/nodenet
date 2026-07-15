# Phases 34–44 implementation report

Status: implementation complete; Phase 44 external release gates remain open  
Date: 2026-07-14

## Outcome

The advanced discovery pass added the separate public discovery API, a checked
operation registry, ordinary-UDP native execution, bounded entity delivery, and
the accepted Phase 35–40 protocol families. The protocol candidates for which a
safe, specification-valid implementation was not justified were closed as
explicit no-go outcomes, as permitted by their phase gates.

Phase 37 is complete: accepted rpcbind NFSv3 endpoints can now authorize one
same-target, transaction-correlated NFSv3 NULL child probe, and the child result
retains its parent entity and stable derivation kind. Callers can set
`followUp: false` to collect rpcbind evidence without child traffic.

This report does not claim that Phase 44's external release matrix is closed.
Publication remains blocked until the new privileged namespace/resource gates
and native AArch64 execution are complete. No package version was advanced and
nothing was published.

## Implemented foundation

- `DiscoveryPlan` has explicit link or target scope, explicit families,
  operation selections, deadline, lifetime result/metadata limits, and canonical
  independent risk consent.
- `Scanner.startDiscovery()` returns an already-running finite
  `DiscoverySession` with native pause/resume/cancel boundaries, one pending
  pull, multiple bounded batches, summaries, and a Node event adapter.
- Scan and discovery share one environment runtime admission counter and a
  combined four-session ceiling. Discovery reserves its complete metadata pool
  against the same 64 MiB environment counter before socket admission.
- Discovery uses ordinary nonblocking UDP sockets. A discovery-only plan opens
  no raw or packet socket and needs no `CAP_NET_RAW`.
- Registry `1.0.0` has stable operation IDs, provenance, families, transport,
  risks, request/response ceilings, fan-out bounds, and response windows. The
  capability ledger uses checked `UdpProbe`/`DiscoveryOperation` tagged
  references and rejects uncovered or duplicate implementations.
- The syscall-free engine owns checked product normalization, lifetime query
  leases, canonical aggregation/conflict retention, same-target derivation graph
  ceilings, and registered-only alternate endpoint pinning.
- Discovery schema 1 uses bounded immutable entity rows with byte identities,
  typed evidence/outcomes, addresses, metadata, interface attribution, optional
  parent/derivation columns, and strict Rust plus hostile-TypeScript validation.
- Repeated identity observations merge distinct addresses and fields under the
  original lifetime reservation, then sort deterministically. The namespace
  matrix also corrected and freezes the RFC-defined LLMNR IPv6 group
  `ff02::1:3`.

## Implemented protocol operations

|  ID | Operation                              | Scope                        | Required consent                    | Result/evidence                                                  |
| --: | -------------------------------------- | ---------------------------- | ----------------------------------- | ---------------------------------------------------------------- |
|   1 | legacy-unicast mDNS/DNS-SD enumeration | links                        | multicast/broadcast, sensitive read | transaction-related DNS records                                  |
|   3 | WS-Discovery Probe                     | links                        | multicast/broadcast, sensitive read | related bounded ProbeMatches                                     |
|   4 | explicitly named LLMNR query           | links                        | multicast/broadcast, sensitive read | transaction-related DNS records                                  |
|   5 | NAT-PMP external address               | targets/default IPv4 gateway | sensitive read                      | exact gateway metadata                                           |
|   6 | SQL Browser enumeration                | targets                      | high amplification, sensitive read  | endpoint plus one entity per bounded instance                    |
|   7 | rpcbind v4 GETADDR for NFS v3          | targets                      | sensitive read                      | derived-port evidence plus optional same-target NFSv3 NULL child |
|   8 | TFTP sentinel read                     | targets                      | stateful handshake, sensitive read  | alternate-port ERROR/DATA/OACK with cleanup                      |
|   9 | QUIC Version Negotiation               | targets                      | none                                | CID-related unauthenticated QUIC versions                        |

DNS compression pointers, TXT bytes/duplicate keys, SOAP namespaces and
relationship fields, SQL framing/text, XDR accepted replies, TFTP options and
transfer IDs, and QUIC connection IDs/version lists are parsed in bounded safe
Rust. XML uses exact-pinned `quick-xml 0.41.0` with default features disabled;
DTD/entity/unsupported encoding and depth/token/text excess fail closed.

## Accepted no-go outcomes

- Full port-5353 mDNS browsing: no-go until bind/reuse behavior proves it can
  coexist with the host mDNS daemon without stealing or duplicating traffic.
- Kerberos: no-go because the pass did not prove a useful credential-free,
  non-real-principal request plus bounded ASN.1 dependency was worth shipping.
- IKEv1/IKEv2 and DTLS: no-go after the fresh dependency/CPU/impact review; no
  malformed static handshake approximation was substituted.
- DHCPv4 INFORM and DHCPv6 Information-request in the host namespace: no-go
  because fixed-port coexistence with the host DHCP client was not proved.
- GTP, MQTT-SN, Beckhoff ADS, Omron FINS, and optional game/voice candidates:
  no-go because authoritative wire ownership plus independent permissioned
  responder evidence was not available for every admission requirement.

The runtime `DISCOVERY_CAPABILITIES.noGo` list makes these outcomes executable
and visible rather than implying generic UDP coverage.

## Verification completed

- `cargo test --workspace --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- scanner TypeScript build, type API test, ESLint, and formatting gates: passed.
- `npm test --workspace=@opsimathically/nodenetscanner`: passed, including a
  real unprivileged NAT-PMP loopback responder, endpoint-plus-instance SQL
  Browser paging, native pause/resume/cancel, hostile plan rejection, registry
  integrity, and combined four-session saturation.
- A focused native test proves exact rpcbind accepted-reply parsing, one derived
  NFSv3 request, returned-port targeting, transaction correlation, and stable
  parent/derivation identity.
- `sudo npm run test:namespace --workspace=@opsimathically/nodenetscanner`:
  passed all ten privileged cases. The project-owned dual-stack rpcbind/NFS
  responder proves four charged transmissions, two parents, two correlated
  children, same-address provenance, and complete parent resolution inside an
  isolated veth namespace. Separate IPv4/IPv6 mDNS, WS-Discovery, and LLMNR
  multicast responders prove interface attribution and deterministic merging of
  responder-scoped dual-stack entities without conflating distinct responders.
- `npm audit --omit=dev --audit-level=high`: zero vulnerabilities.
- `cargo audit`: zero vulnerabilities; retained the pre-existing allowed
  unmaintained `paste 1.0.15` transitive warning.
- scanner `hardening:verify`: passed after refreshing both separate fuzz-crate
  lockfiles; all 77 Rust packages passed the license/policy review.
- The protocol parse fuzz target completed 40,848 executions with no crash while
  exercising the newly wired discovery parser surface.
- x86-64 release build, stripped ELF/GLIBC verification, staged-package clean
  consumer installation, and two-build reproducibility passed for the initial
  implementation snapshot. Artifact hashes must be regenerated after the
  product-hardening changes recorded in the following report.

## Remaining work

1. Add packet-capture assertions and any scenario-specific namespace variants
   beyond the completed dual-stack targeted and multicast responder matrix.
2. Run the remaining discovery-specific sanitizer, fault-injection, fd/RSS, and
   slow-consumer stress gates.
3. Run the complete native suite on a physical or otherwise accepted AArch64
   glibc host. AArch64 remains untested and blocks Phase 44/package publication.
