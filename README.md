# nodenet

`nodenet` is the development workspace for Linux-native Node.js networking
libraries implemented with TypeScript, Rust, and Node-API.

## Packages

- [`@opsimathically/nodenetraw`](packages/nodenetraw/README.md) is the active,
  Linux-only raw socket and ICMP/traceroute package.
- [`@opsimathically/nodenetscanner`](packages/nodenetscanner/README.md) is an
  unpublished `0.2.0-rc.1` bounded native scanner. Its TypeScript API drives
  live ARP/NDP, ICMPv4/v6 Echo, TCP SYN, protocol-aware UDP scans, and bounded
  link/target UDP discovery through a Rust-owned portable Linux data plane. It
  also includes finite passive AF_PACKET metadata observation, strict passive
  and service codecs, live bounded path/router/TCP service identification,
  evidence/authority primitives, conservative asset and inventory views, and
  transport-neutral scope-preserving sensor envelopes.

The public packages remain independently versioned. Performance-sensitive Rust
code can be shared as compile-time workspace crates, while each Node package
keeps an explicit public API and native-addon boundary.

The accepted and preimplementation-reviewed evolution roadmap builds a bounded
Rust protocol toolkit, read-only Linux network context, deterministic scheduler,
portable scanner, and compact result batching before considering an evidence-
gated extreme backend. See the
[network and scanner evolution plan](ai_documentation/31-network-and-scanner-evolution-plan.md)
and closed
[readiness review](ai_documentation/32-network-evolution-plan-review.md). Phase
16 completion and dependency evidence are in the
[protocol foundation report](ai_documentation/33-phase-16-report.md). Phase 17
link/internet codec and live-capture evidence is in the
[Phase 17 report](ai_documentation/34-phase-17-report.md). Phase 18
transport/control and correlation evidence is in the
[Phase 18 report](ai_documentation/35-phase-18-report.md), and the bounded
route-netlink snapshot evidence is in the
[Phase 19 report](ai_documentation/36-phase-19-report.md). Policy-aware
resolution and coherent refresh evidence is in the
[Phase 20 report](ai_documentation/37-phase-20-report.md). Deterministic target,
scheduling, timing, classification, and lifecycle evidence is in the
[Phase 21 report](ai_documentation/38-phase-21-report.md). The initial portable
scanner runtime and Node API are recorded in the
[Phase 22 report](ai_documentation/39-phase-22-report.md). Compact batching is
recorded in the [Phase 23 report](ai_documentation/40-phase-23-report.md),
portable release hardening in the
[Phase 24 report](ai_documentation/41-phase-24-report.md), and the measured
extreme-backend `no-go` in the
[Phase 25 report](ai_documentation/42-phase-25-report.md). Phase 26 is closed.
The independently authored UDP catalogue and adaptive service-aware foundation
through Phase 33 are recorded in the
[UDP plan](ai_documentation/43-udp-probe-parity-plan.md) and
[Phase 33 report](ai_documentation/51-phase-33-report.md). All available x86-64
release gates pass; native AArch64 execution remains mandatory before
publication. The later adversarial parser and lifecycle review is recorded in
the
[Phases 27–33 implementation audit](ai_documentation/52-phase-27-33-implementation-audit.md).
The advanced one-to-many UDP discovery architecture and its protocol-specific
admission/no-go decisions are tracked in the
[Phases 34–44 plan](ai_documentation/53-advanced-udp-discovery-evolution-plan.md).
The implementation, no-go dispositions, and remaining external release gates are
recorded in the
[Phases 34–44 implementation report](ai_documentation/55-phase-34-44-implementation-report.md).
The evidence-driven discovery platform implemented in Phases 45–57 and its local
Phase 58 adversarial/release verification are recorded in the
[Phases 46–58 implementation report](ai_documentation/60-phases-46-58-implementation-report.md).
All available x86-64 gates pass; native ARM64/AArch64 execution remains untested
and mandatory before publication.

The Phase 59–69 UDP coverage program advances the independently authored
catalogue to `1.4.1` with 37 variants. Its separate public decision registry
records all 41 researched candidates as 5 implemented, 32 no-go, or 4
threat-excluded. New opt-in RIPv1, Quake II, Quake III, and Mumble support does
not change the nine-probe safe default. RIPv1 route discovery now collects a
bounded multi-datagram response window and retains typed routes; catalogue probe
34 remains a single-reply compatibility probe. See the
[repair report](ai_documentation/66-phases-59-69-adversarial-repair-report.md).

## Development

The repository requires Node.js 26+, npm 11+, and the Rust toolchain pinned in
[`rust-toolchain.toml`](rust-toolchain.toml).

```sh
npm ci
npm run ci
npm run test:phase17:namespace
npm run test:phase19:namespace
npm run test:phase19:stress
npm run test:phase20:namespace
npm run test:phase20:stress
npm run test:phase21
npm run test:phase22
sudo npm run test:phase22:namespace
npm run test:phase23
sudo npm run test:phase23:namespace
npm run test:phase24
sudo npm run test:phase24:namespace
sudo npm run benchmark:phase25
```

The Phase 17, 19, and 20 namespace commands use disposable user/network
namespaces for live frame and route-context oracles. On hosts that disable
unprivileged user namespaces, run the applicable command with `sudo`; the
wrappers preserve the invoking owner's build environment and avoid root-owned
artifacts.

Phase 21 is entirely syscall- and privilege-free; `npm run test:phase21` runs
its deterministic virtual-clock and scripted-collaborator suite directly.

Phase 22 ordinary tests include capability-free context and API checks. Its
namespace command builds as the invoking user, then runs the live dual-stack
veth/VLAN matrix with raw-socket authority in disposable network namespaces.

Root commands orchestrate the relevant workspace package. Package-specific
source, tests, release tooling, and documentation live under `packages/`; Rust
crates live under `crates/`.

Licensed under the [MIT License](LICENSE).
