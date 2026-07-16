# Phases 46–58 implementation and adversarial status

Status: Phases 46–57 complete; all available Phase 58 x86-64 gates complete;
native AArch64 execution remains an external publication gate  
Date: 2026-07-15

Superseded in repaired implementation details by
`61-phases-46-57-adversarial-repair-report.md`. The phase scope, no-go outcomes,
and AArch64 release boundary remain current.

## Outcome

The scanner now has a bounded discovery-platform layer above its retained scan
and UDP-discovery APIs. The implementation adds passive metadata observation,
router solicitation, native path tracing, credential-free TCP service
identification, append-only evidence, conservative reconciliation and inventory,
and scope-preserving sensor interchange. Existing scan schemas 1/2, UDP
catalogue `1.3.0`, discovery schema 1, and discovery registry `1.0.0` remain
compatible.

The phase sequence was preserved. Optional candidates were admitted only when
their independent protocol, impact, responder, dependency, and lifecycle gates
closed. The remaining candidates are explicit capability `noGo` outcomes; they
are not partial protocol approximations.

## Phase-by-phase result

### Phase 46 — Passive observation

- `Scanner.startObservation()` provides finite receive-only AF_PACKET metadata
  observation over one through four explicit interfaces.
- Capture is nonblocking/CLOEXEC, incoming-only and non-promiscuous by default,
  binds before use, installs a generated classic BPF filter, and repeats the
  protocol guard in userspace.
- Promiscuous capture needs independent consent. Frame payloads and mmap-backed
  memory never cross N-API.
- Duration, snap length, inspected/captured bytes, rows, metadata, descriptors,
  shared session admission, pause/resume/cancel/pull, callback settlement, and
  teardown are bounded.

### Phase 47 — Passive host and service semantics

- Strict bounded decoders cover ARP, NDP, DHCPv4/v6, mDNS/DNS-SD, LLMNR, NBNS,
  SSDP, and WS-Discovery.
- Incomplete fragments never enter discovery parsers.
- DNS TTL, DHCP lease, SSDP cache, mDNS goodbye/cache-flush, and protocol
  withdrawal signals become append-only expiry/withdrawal evidence rather than
  mutable or permanent identity.

### Phase 48 — Link and IPv6 topology

- Passive IPv6 RS/RA/Redirect, LLDP, STP, LACP, VRRP, IGMP/MLD, RIP, and OSPF
  presence metadata is strictly decoded without joining an election or
  adjacency.
- Complete normalized read-only rule and neighbor context is exposed alongside
  retained summaries.
- `Scanner.solicitRouters()` is the sole admitted active control-plane
  operation. It sends a standards-valid interface-scoped IPv6 Router
  Solicitation only with explicit link-multicast consent and validates returned
  router advertisements.

### Phase 49 — Native path discovery

- `Scanner.tracePath()` provides finite IPv4/IPv6 ICMP, UDP, and TCP modes with
  first/max hop, attempts, pacing, deadline, ports, AbortSignal cancellation,
  exact destination stopping, per-attempt RTT/correlation, silent attempts,
  partial results, and multiple responders.
- A dedicated bounded native worker owns nonblocking sockets and short poll
  slices; it does not consume a libuv worker or run an unbounded socket loop in
  TypeScript.
- Path and hop rows project into evidence without treating an address or reverse
  name as sufficient device identity.

### Phases 50–52 — TCP conversation and identity

- `Scanner.identifyService()` uses ordinary nonblocking TCP with a 30-second
  hard deadline, 25 ms cancellation slices, four-session shared admission, 128
  KiB reservation per operation, bounded request/response/parser work, no retry,
  no redirect, no credentials, and no user-supplied scripts.
- Admitted server-first identities are SSH, FTP, SMTP, POP3, IMAP, and MySQL.
- Admitted canonical client negotiations are HTTP `HEAD`, PostgreSQL
  `SSLRequest`, and Redis `PING`; exact request bytes are generated internally.
- TLS ClientHello/certificate processing remains `noGo` because no dependency
  review was accepted. SMB, RDP, MongoDB, LDAP, and other candidates whose
  independent impact or responder gates did not close also remain executable
  `noGo` entries.
- Results distinguish connection, timeout, refusal, cancellation, transport
  failure, parser rejection, response limit, and syntactically identified
  service. They do not claim authentication.

### Phase 53 — Governed enrichment

- DNS-SD service types map to bounded SSH, HTTP, SMB, printing, AirPlay, Cast,
  HomeKit, and Matter semantic families while unknown service types remain
  evidence.
- Same-responder literal HTTP(S) URL authority rejects DNS rebinding, userinfo,
  fragments, invalid/ambiguous literals, scope escape, and implicit redirects.
- Existing registered unicast discovery and derived rpcbind/NFS work retain
  their original target/risk/fan-out authority.
- Link-wide SSDP/SLP crawling, advertised-description fetching, unrestricted DNS
  expansion, and SNMP reads remain `noGo`; disabling enrichment never alters the
  source evidence.

### Phases 54–55 — Assets and longitudinal inventory

- Reconciliation joins only co-observed or shared, network-scoped strong
  identifiers such as MAC, LLDP chassis, SMB GUID, SNMP engine, and UPnP UDN.
  Weak names, addresses, certificates, and classifications never merge assets.
- Merge and conflict reasons stay visible. Deterministic classifiers expose
  their positive and conflicting evidence.
- Bounded snapshots and storage-neutral adapters support deterministic `new`,
  `changed`, `expired`, `withdrawn`, `reappeared`, and `conflicted` changes.
- Asset comparison is order-stable and hostile snapshot lists, strings, counts,
  and aggregate bytes are bounded.
- Optional `inet_diag`, Avahi, systemd-resolved, and `nl80211` providers remain
  `noGo`; no database, daemon, radio scan, or host mutation was added.

### Phase 56 — Specialized candidates

- Already-admitted UDP, passive, and DNS-SD capabilities remain usable as
  independent registry packs.
- Additional printing, Windows/media, camera, SNMP, OPC UA, S7, DNP3, and other
  specialized active candidates did not independently clear the authoritative
  contract, non-mutating impact, project responder, and typed-evidence gates.
  They are recorded as `noGo` rather than guessed or credential-bearing probes.

### Phase 57 — Multi-vantage interchange

- Versioned transport-neutral sensor envelopes are deterministic and bounded to
  8,192 records and 16 MiB, with per-record field/relation/byte limits.
- Decode treats nested values as hostile, bounds decimal and base64 work,
  rejects replay/gaps, preserves upstream provenance, adds explicit sensor and
  network scope, and reserves room for fusion metadata.
- Identical private addresses or MAC values from different network scopes do not
  merge. The package adds no listener, transport security policy, remote
  executor, or namespace transition.

## Adversarial corrections

The closing audit corrected issues rather than documenting around them:

- observation startup now becomes ready only after the descriptor is bound and
  its filter/membership policy is installed;
- path and service work use bounded native workers with explicit cancellation
  rather than blocking libuv work;
- TCP response parsing handles segmentation, early close, overflow, malformed
  data, slow peers, and exact canonical requests;
- native risk validation rejects duplicate consent as well as wrong consent;
- socket polling handles hang-up and invalid-descriptor events without waiting
  to the deadline;
- passive RA test traffic preserves valid link-local/multicast behavior;
- imported evidence is validated before reconciliation, sensor aggregate bytes
  are bounded before encoding/fusion, and fusion reserves its provenance fields;
- inventory comparison is independent of caller array order and hostile asset
  content has count and byte ceilings; and
- scoped strong identifiers cannot bridge two sensor networks.

## Verification evidence

The following passed on the local x86-64 GNU/Linux host:

- complete `npm run ci`, including Prettier, ESLint, strict TypeScript,
  `cargo fmt`, workspace Clippy with warnings denied, all Rust tests, all
  workspace Node tests, npm audit, and release-policy verification;
- 16 of 16 privileged scanner namespace cases, including observation, VLAN,
  Router Solicitation, routed IPv4/IPv6 path correlation, cancellation, and
  retained scan/discovery behavior;
- scanner Worker/fd/RSS stress with zero descriptor delta;
- protocol, scanner-plan, and raw-surface fuzz runs with no crash; local LLVM
  symbolizer IPC was disabled for these runs with `ASAN_OPTIONS=symbolize=0`;
- focused service and platform regressions, including partial I/O, cancellation,
  four-operation admission, hostile envelopes, scope separation, inventory
  ordering, and capacity failures;
- release artifact architecture/glibc verification (highest required glibc
  symbol version `2.16.0`, below the `2.28` project floor);
- staged root plus `linux-x64-gnu` package assembly and a clean external
  consumer install/load test; and
- reproducible scanner release build verification.

The ordinary Node scanner suite reports 78 tests: 58 passed and 20 privileged
cases skipped by design outside the namespace harness. The final native scanner
unit suite reports 33 passed.

## Remaining external release gate

Phase 58 is locally complete but cannot satisfy its cross-architecture exit gate
on this host. Native execution of the scanner suite and representative
capture/TCP/topology matrix on AArch64 GNU/Linux remains mandatory before npm
publication. Cross-compilation is not substituted for native execution, and the
README continues to state that ARM64 is untested. No publication guard or
earlier Phase 44 gate is waived.
