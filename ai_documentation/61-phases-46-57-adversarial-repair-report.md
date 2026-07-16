# Phases 46–57 adversarial repair report

Status: implementation repairs and all available x86-64 gates complete  
Date: 2026-07-15

## Purpose

This report reopens the completed Phase 46–57 slices after their second
adversarial review. It records the concrete correctness and product-readiness
repairs that supersede the corresponding implementation claims in report 60. The
accepted phase scope and no-go decisions remain unchanged.

## Reconciliation, inventory, and sensor interchange

- Reconciliation ignores expired and withdrawn evidence, rejects ambiguous
  network scope, and merges the complete set of scoped strong identifiers
  transitively. Weak names never classify or merge a device by themselves.
- TypeScript and Rust use unambiguous scoped identity keys. Sensor IDs and
  scopes reject embedded NUL values, and both fusion implementations have a
  finite 4,096-stream ceiling.
- Evidence and inventory operations enforce 16 MiB aggregate input ceilings in
  addition to per-record/per-asset bounds.
- Sensor admission is transactional: a failed envelope does not consume its
  sequence number. Imported provenance fields are stripped and regenerated,
  upstream record identity is retained separately, and origin record IDs are
  unique across every envelope record.
- Envelope version 1 now carries optional bounded capability snapshots,
  interface/protocol capture visibility, promiscuous/outgoing visibility, and
  accepted/drop summaries. These fields do not add a transport or trust policy.

## Passive observation and evidence lifetime

- IPv4 and IPv6 envelopes are parsed in strict mode. IPv6 extension headers are
  walked before upper-layer classification; incomplete fragments never reach UDP
  or service decoders.
- UDP length and checksum rules are enforced, including mandatory IPv6 UDP
  checksums. DHCP, DNS-family, SSDP, WS-Discovery, RIP, RA/NDP, and LLDP
  classifiers require bounded protocol structure before assigning a semantic
  protocol.
- AF_PACKET capture enables Linux `PACKET_AUXDATA`. Final checksum bytes are
  validated directly unless the kernel explicitly reports `CSUM_VALID` or
  `CSUMNOTREADY`; those offload states are retained as observation metadata so
  locally offloaded frames are not falsely rejected or silently overclaimed.
- Ethernet/IPv4 ARP now requires a complete 28-byte header, Ethernet hardware,
  IPv4 protocol, 6/4 address widths, and a request/reply operation.
- DNS canonical wire names are decoded explicitly rather than treated as UTF-8.
  Queries, malformed messages, and unrelated payloads do not become service
  evidence.
- Lifetime and withdrawal policy is record-role specific. A DNS TTL, SSDP
  byebye, or DHCP release cannot withdraw the underlying device candidate.
- Observation record ID lanes are disjoint across consecutive packets. Native
  worker failures enter a terminal failed state and settle pending pulls.
- `ObservationSession.batches()` supplies a bounded optional event adapter over
  the retained pull API with one pull in flight and native backpressure.

## Path, Router Solicitation, and TCP service work

- Path probes use a per-run kernel-random nonce, strong ICMP identifier/token
  checks, finite receive-event work, and do not invent the target as a responder
  for local error-queue failures.
- `pacingMs` is a public finite path-plan control bounded to 0–1,000 ms. Pacing
  occurs on the owned native thread in 25 ms cancellation slices and remains
  subordinate to the run deadline.
- Router Solicitation now uses an owned bounded thread and explicit cancellation
  control instead of a libuv worker. Invalid advertisements do not poison
  responder deduplication, polling handles error/hangup states, and receive work
  has a finite ceiling.
- AbortSignal startup races are closed for path, Router Solicitation, and
  service identification by registering and then rechecking the caller's signal.
- TCP service reads detect incremental framing without repeatedly parsing the
  full accumulated buffer. A zero-byte write is terminal, MySQL waits for its
  declared packet, and HTTP status/header syntax and selected field sizes are
  strict.
- Rust exports its service registry through N-API and TypeScript compares every
  entry and port at module load. The Phase 56 no-go entries and SNMP identifier
  now match exactly, preventing silent registry drift.

## Regression coverage

Targeted tests cover forged sensor provenance, cross-scope identity, failed
transactional fusion, replay/gap boundaries, DNS wire semantics, record-level
expiry, strict ARP, malformed passive transport, segmented MySQL, service
registry parity, bounded/cancellable path pacing, observation event types, and
Router Solicitation abort/result types.

## Verification evidence

The following pass on the local x86-64 GNU/Linux host after the repairs:

- complete `npm run ci`, including Prettier, ESLint, strict TypeScript,
  warning-denied workspace Clippy, all workspace Rust and ordinary Node tests,
  dependency audit, and both package release-policy checks;
- 49 protocol unit tests and 34 scanner-native unit tests, including strict ARP,
  passive semantic, checksum-offload, path pacing, and service segmentation
  regressions;
- all 16 privileged scanner namespace cases, including observation, dual-stack
  multicast evidence, Router Solicitation, routed path correlation, VLAN,
  retained scans, derived discovery, and adaptive/protocol UDP behavior;
- repeated Worker teardown stress with zero descriptor delta and bounded RSS;
  and
- x86-64 release ELF/glibc verification, staged root plus native-package
  consumer install/load, and byte-for-byte reproducible native release builds.

The ordinary scanner Node suite reports 81 tests: 61 passed and 20 privileged
cases skipped by design outside the namespace harness.

## Remaining release boundary

The repaired implementation does not admit any Phase 56 no-go candidate and does
not add reverse DNS, a sensor listener, remote plan execution, credentials, or
authentication claims. Native AArch64 execution remains the only known external
architecture publication gate and is not waived by this repair pass.
