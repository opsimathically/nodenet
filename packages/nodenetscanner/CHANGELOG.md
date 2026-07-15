# Changelog

## Unreleased

- Add a separate bounded discovery session API, immutable capability registry,
  explicit link/target scopes, lifecycle controls, paged pulls, event batches,
  risk consent, and shared environment resource admission.
- Add strict ordinary-UDP discovery for legacy-unicast mDNS/DNS-SD,
  WS-Discovery, explicit-name LLMNR, NAT-PMP, SQL Browser, rpcbind/NFSv3, TFTP,
  and QUIC Version Negotiation.
- Add a single bounded same-target rpcbind-derived NFSv3 NULL follow-up with
  optional suppression, transaction correlation, and public parent/derivation
  result identity.
- Harden discovery execution with a dedicated native thread, live coherent
  progress, aggregate pacing, 256-socket/1,024-query ceilings, per-query result
  leases, packet-info/hop-limit attribution, observed responder ports, and
  responder-scoped aggregation.
- Complete adaptive legacy-unicast DNS-SD service walking, strict LLMNR answer
  selection, TFTP transfer-port pinning/terminal cleanup, SQL endpoint rows and
  high-amplification consent, policy-aware default-gateway selection, and
  same-link/exclusion enforcement.
- Record fixed-port mDNS browse, Kerberos, IKE/DTLS, host-namespace DHCP, and
  specialized candidates that did not pass admission as explicit no-go outcomes
  instead of emitting protocol approximations.
- Harden SNMPv3, RPC/NFS, BitTorrent DHT, NTP control, SLP, XDMCP, BACnet,
  EtherNet/IP, and KNXnet/IP response validation so typed service evidence
  requires complete protocol structure and exact message boundaries.
- Replace incomplete protocol test skeletons with structurally complete
  canonical fixtures and add marker-smuggling, trailing-data, fragment, and
  truncation regressions.

All notable changes use Semantic Versioning. The scanner is not yet stable;
release-candidate APIs may change before `1.0.0`.

## 0.2.0-rc.1 - 2026-07-14

- Expand the independently authored UDP catalogue to `1.3.0` with 33 variants,
  including opt-in game, directory, device, industrial/building, peer-to-peer,
  remote-control, routing, and historical discovery exchanges.
- Add checked catalogue port ranges, finite byte signatures, and a complete
  project capability/disposition ledger while leaving the nine-probe safe
  profile unchanged.
- Implement opt-in adaptive UDP ordering, evidence-only early stopping, soft
  family narrowing, and conservative ICMP pacing; exhaustive remains default.
- Add reproducible normalized UDP policy/catalogue summary metadata and typed
  lazy schema-2 UDP service/result views while retaining schema-1 decoding.
- Complete the provenance, frozen-reference behavioral, dual-stack namespace,
  fuzz/sanitizer/stress, staged-consumer, artifact, and reproducibility release
  audit. Native AArch64 execution remains required before publication.

## 0.1.0-rc.1 - 2026-07-14

- Add a bounded Linux-native portable scan engine for ARP, NDP, ICMPv4/ICMPv6
  Echo, TCP SYN, and UDP discovery across Ethernet, explicit VLAN, loopback, and
  local raw-IP paths.
- Add compact target normalization and exclusions, seeded scheduling, adaptive
  or fixed timeouts, retry/deadline/rate controls, authenticated correlation,
  and terminal cleanup accounting.
- Add a zero-runtime-dependency TypeScript API with pull-based versioned
  columnar result batches, lazy views, progress, cancellation, pause/resume,
  stable structured errors, and an optional batch event adapter.
- Add read-only Linux interface, address, route, rule, neighbor, and namespace
  context inspection without changing host configuration.
- Add ordinary, namespace, fuzz, sanitizer, fault, saturation, Worker, fd/RSS,
  benchmark, clean-consumer, artifact, provenance, and reproducibility gates.
- Add loader-only root and exact-version x86-64/AArch64 glibc target packages
  with no install scripts or production Node dependencies.
- Harden post-audit admission and correlation with collision-free four-session
  ICMP/source-port lanes, a public 65,491-byte UDP payload ceiling, and
  repository-owner-built privileged context tests.
- Preserve ARP/NDP setup when unresolved cached routes are deferred by prefix or
  result-capacity admission, so mixed scans settle silent neighbors per probe
  instead of failing the entire session.
- Add the Phase 27 UDP foundation: exact custom and empty payload policies,
  explicit legacy token-prefix compatibility, bounded catalogue provenance and
  request-plan contracts, immutable catalogue capabilities, and strict retained
  schema-1/schema-2 batch decoding. Protocol-aware multi-variant transmission
  remains gated for Phase 28.
- Add the Phase 28 bounded physical UDP programme scheduler, collision-free
  per-variant correlation, deterministic logical evidence aggregation, and
  row/metadata-byte reservation.
- Add the Phase 29 safe protocol pack for DNS, NTP, SNMPv3 discovery, rpcbind
  NULL, STUN, CoAP ping, ASF/RMCP presence, framed memcached version, and PCP
  ANNOUNCE. Omitted UDP policy now selects this safe pack, protocol sessions
  emit schema 2 service evidence, and explicit empty/custom compatibility
  remains schema 1.
- Add the Phase 30 comprehensive standards pack for NetBIOS node status, NFS v3
  NULL, SIP OPTIONS, SSDP unicast discovery, L2TP SCCRQ, SNMPv1 `sysDescr.0`,
  and memcached statistics. Catalogue breadth and amplification, stateful,
  authentication-attempt, sensitive-read, and multicast/broadcast consent are
  enforced independently in native admission, with bounded parser work and
  state/response ceilings.

Nothing has been published by the Phase 24 implementation itself.
