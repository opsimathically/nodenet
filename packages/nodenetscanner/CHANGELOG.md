# Changelog

All notable changes use Semantic Versioning. The scanner is not yet stable;
release-candidate APIs may change before `0.1.0`.

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

Nothing has been published by the Phase 24 implementation itself.
