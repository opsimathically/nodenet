# Changelog

All notable changes use Semantic Versioning. This project is not yet stable;
release-candidate APIs may change before `0.1.0`.

## 0.1.0-rc.1 - 2026-07-12

- Add Linux IPv4, IPv6, and raw/cooked packet sockets through Node-API 10.
- Add bounded asynchronous byte, message, ancillary, batch, error-queue, and
  receive-only TPACKET_V3 ring operations.
- Add typed and bounded socket options, packet membership/fanout/statistics,
  classic BPF validation, and compatible eBPF attachment.
- Add deterministic cancellation, idempotent close, bounded fair reactor work,
  copied ring-frame leases, and stable structured Linux errors.
- Add x86-64/AArch64 glibc package layouts, clean-consumer and reproducibility
  checks, fuzz targets, sanitizer/advisory workflows, and release provenance.
- Make bounded Node completion delivery lossless under callback saturation and
  make close wait for every admitted native operation to settle.
- Recover safely from malformed packet-ring blocks and reject truncated or
  oversized kernel link-address metadata.
- Enforce release ELF architecture and glibc compatibility; optimized GNU
  artifacts now use napi-rs's pinned compatibility cross toolchain.
- Reject IP-only disconnect semantics on packet sockets at both public and
  native boundaries.
- Make `sudo npm run test:privileged` build as the invoking repository owner and
  elevate only an isolated network-namespace test process.
- Export a focused zero-dependency set of Linux `IPPROTO_*` and `ETH_P_*`
  constants and use them throughout the public examples.

Nothing has been published by the Phase 10 implementation itself.
