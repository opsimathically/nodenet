# Phase 28 completion report

Status: complete  
Completed: 2026-07-14  
Scope: bounded multi-probe UDP scheduling, correlation, and logical aggregation

## Outcome

Phase 28 implements the execution layer between the Phase 27 catalogue/request
contracts and the future Phase 29 standards-based probe pack. One UDP
target/port remains one logical result even when its immutable per-family
programme contains many physical requests. The programme product is decoded
lazily; targets, ports, and variants are never materialized as one Cartesian
table.

The engine now owns:

- checked `UdpProbeProgramme` and `UdpProbeVariant` descriptors with a hard
  sixty-four-variant endpoint ceiling and 1 KiB per-winner metadata declaration;
- distinct logical result and physical wire IDs, stable catalogue/request
  identity on every emission, and checked `u32` aggregate UDP transmissions;
- fair round-robin physical admission with at most four active variants for one
  endpoint and `maxOutstanding` charged to physical work;
- one row/maximum-metadata reservation per logical endpoint, with cleanup on
  success, close, cancellation, deadline, context invalidation, and transport
  failure;
- finite per-wire late grace, decisive unsent-work stopping, deterministic
  winner selection, bounded contradiction counting, and exactly-once logical
  settlement; and
- the frozen IPv4/IPv6 UDP evidence matrix. Direct UDP is `open`; a correlated
  target-originated port-unreachable is `closed`; an intermediate
  port-unreachable and the other recognized unreachable/time-exceeded cases are
  `filtered`; IPv6 Parameter Problem code 0 is `open` and code 1 is `filtered`;
  unknown evidence cannot change state; exhaustion remains `open|filtered`.

The native path now looks up routes by logical ID while deriving packet tokens,
IP identifiers, source ports, and quote correlation from unique physical IDs.
Source ports use an explicit collision-free lane allocator across active and
grace probes rather than modulo aliasing. Receive normalization carries ICMP
family, type, code, target origin, and quote strength to the engine. Request
selection consumes the emitted variant index, so later independently authored
catalogue entries require no scheduler rewrite.

## Resource and compatibility boundary

Only four physical variants for an endpoint may be active concurrently. The
existing global/prefix/target fairness and token bucket charge setup, every UDP
datagram, and every retry. Correlation capacity counts active plus grace state,
and source lanes are returned only after finite grace.

The native queue reserves at most 16 MiB of possible service metadata per
session and 64 MiB across one Node environment. Phase 28 produces zero service
metadata, immediately releasing the reservation when a result settles. Phase 29
owns nonzero winning sidecars and the 4 MiB batch split.

Existing empty, custom tuple, and explicit legacy prefix-token scans retain
their payload bytes and schema-1 output. Aggregate transmission storage widens
internally to the already documented `u32` batch column. Native schema-2
emission does not begin in this phase. The production protocol catalogue remains
empty, so protocol mode can exercise `unmapped`/`afterProtocol` empty fallback
or `never` without claiming a safe protocol pack. Adaptive strategy remains
gated.

## Verification

The Phase 28 virtual-clock suite covers zero, one, four, sixteen, and sixty-four
variants; four-wire waves; silence; exact-timeout late evidence; reordered
open/closed contradictions; deterministic winning probe identity; metadata
reservation; explicit close cleanup; and the frozen IPv4/IPv6 ICMP matrix.
Native tests cover source-lane collision/exhaustion/reuse, four-session
partitioning, protocol fallback admission, and metadata ceiling behavior.

Verified locally on x86-64 Linux:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run ci
sudo npm run test:phase22:namespace
cargo check -p nodenet-protocols -p nodenetscanner-engine \
  -p nodenetscanner-native --target aarch64-unknown-linux-gnu --locked
```

All gates pass. The privileged namespace regression passes five live cases,
including dual-stack transport/discovery, compact batching, VLAN traffic, and
byte-exact empty/custom UDP payload capture. The AArch64 cross-check passes for
all three Phase 28 Rust crates.

Native AArch64 execution remains untested and remains a publication gate.

## Deferred by design

- protocol-valid DNS/NTP/SNMPv3/RPC/STUN/CoAP/RMCP/memcached requests and strict
  response parsers;
- nonzero service metadata and native schema-2 emission;
- changing omitted UDP policy to protocol-aware safe mode; and
- broader explicit-risk, legacy, adaptive, and parity work.

Those remain Phases 29 through 33. Phase 29 is the next implementation phase.
