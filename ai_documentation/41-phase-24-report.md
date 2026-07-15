# Phase 24 completion report

Date: 2026-07-14

## Outcome

Phase 24 implementation is complete. `@opsimathically/nodenetscanner` is now an
independently staged, zero-runtime-dependency, unpublished `0.1.0-rc.1` release
candidate. D-038 freezes the portable release boundary without beginning the
optional extreme-performance work in Phases 25–26.

Publication is intentionally still blocked on native AArch64 execution. The
supported privileged Phase 24 namespace/fault matrix and benchmark now pass
locally on x86-64.

## Stable public boundary

- Result-batch schema version 1 remains unchanged and is now exported as
  `RESULT_BATCH_SCHEMA_VERSION`.
- `SUPPORTED_SCAN_PROBES` freezes ARP, NDP, ICMPv4 Echo, ICMPv6 Echo, TCP SYN,
  and UDP result names.
- `SCANNER_LIMITS` publishes scanner/session/operation/control/batch admission
  ceilings without exposing mutable native state.
- Existing stable `ScannerError`, lifecycle, summary, progress, context,
  compact-batch, pull, and batch-event declarations remain the release API.
- Runtime Node dependencies remain zero. The package is Linux/glibc-only on
  x86-64 and AArch64, Node.js 26+, Node-API 10, and kernel 4.18+.

The README now covers discovery, TCP SYN, UDP, IPv6, exclusions, route
inspection, progress, pull batches, event batches, cancellation, privilege
setup, VLAN selection, source-port/local-RST interaction, namespace binding,
offload/VLAN metadata, ICMP rate limits, and the distinction between observed
`AF_PACKET` traffic and host-firewall/application reachability.

## Hardening

- A syscall-free engine fuzz target exercises compact target normalization,
  exclusion, boundary lookup, checked plan construction, seeded permutation, and
  lazy tuple decoding. Existing protocol parse/build fuzz targets remain in the
  same scheduled hardening job.
- Hostile JavaScript plans, throwing proxies, null/wrong nested values,
  non-finite numbers, and maximum control payloads fail as controlled errors.
  Every plan and nested getter is snapshotted once into owned primitives before
  validation and native admission.
- Weekly address/thread sanitizer jobs now include the scanner addon; dependency
  advisory checks include the engine fuzz lockfile.
- Native completion-queue testing performs 262,144 reserve/saturate/drain
  settlements with exact accounting. A deterministic 4,096-probe total-loss
  engine simulation proves terminal settlement without retained reservations.
- Worker stress performs 64 clean and forced environment terminations and checks
  process fd/RSS deltas. The recorded local result was zero descriptor growth
  and 22,458,368 bytes RSS growth, below the 96 MiB gate.
- The Phase 24 namespace extension brings an interface down during a live scan,
  drains every terminal result, and runs four retained-result sessions
  concurrently. The existing matrix continues to cover loopback, dual-stack
  veth, Ethernet, VLAN, ARP/NDP, ICMPv4/v6, TCP, UDP, and kernel-drop behavior.

## Benchmarks

`npm run benchmark:scanner` runs inside the disposable topology and emits JSON
containing timestamp, Node/architecture, CPU model/count, memory, kernel,
interface/link/MTU data, workload configuration, elapsed nanoseconds,
logical-probe throughput, and N-API batch count. It covers a one-probe full
packet-build/TX/RX/correlation path and a 1,024-probe scheduling/batching/N-API
path. The four-session namespace gate supplies the fairness workload; protocol
foundation benchmarks retain packet build/parse and allocation baselines. No
timing assertion or high-rate marketing claim is made.

The recorded local run used Node.js 26.4.0 on an Intel Core i7-14700KF (28
logical CPUs), 33,475,129,344 bytes of memory, Linux 6.17.0-35-generic, loopback
MTU 65,536, and veth MTU 1,500. At the configured 100,000 packet/s ceiling and
500 ms timeout, the one-probe end-to-end workload completed in 20,074,635 ns
(49.81 probes/s), while the 1,024-probe scheduling/batching/N-API workload
completed in 283,207,850 ns (3,615.72 probes/s) and one result batch. These are
development-build namespace observations, not release throughput claims.

## Release artifacts

Release assembly creates:

- loader-only `@opsimathically/nodenetscanner`;
- `@opsimathically/nodenetscanner-linux-x64-gnu`; and
- `@opsimathically/nodenetscanner-linux-arm64-gnu`.

The root staging manifest injects exact-version optional target dependencies.
Target packages contain only the stripped addon, README, license, and manifest.
There are no install scripts. Provenance records the source commit,
`SOURCE_DATE_EPOCH`, Node/Rust versions, Cargo lock hash, and hashes/sizes of
all staged files. Direct source-tree publication remains rejected.

## Verification

The following gates pass locally on Linux x86-64 with Node.js 26 and Rust
1.97.0:

- ordinary scanner build, declaration tests, hostile tests, and batch tests;
- engine/native Rust tests, including long-run loss and queue saturation;
- engine fuzz-manifest compile and Clippy;
- 10,000 local engine fuzz executions without a crash or sanitizer finding;
- scanner release-policy, dependency-license, and production audit checks;
- 64-cycle Worker fd/RSS stress;
- the complete sudo-only loopback/dual-stack/VLAN/fault/four-session namespace
  matrix;
- the metadata-recording scanner benchmark described above;
- AArch64 native-addon cross-compilation;
- optimized x86-64 ELF machine, stripping, and GLIBC requirement inspection;
- clean loader/target package installation with lifecycle smoke testing; and
- two clean optimized builds with identical SHA-256
  `5ff54dc69b9e8f9b33479f352cac3c2b6667266814c8b519964abe965f07f0c6` after the
  post-completion audit corrections.

Scheduled CI now executes engine/protocol fuzzing, address/thread sanitizers,
advisory checks, stress/namespace faults, ordinary x86-64/AArch64 gates, and
independent release rehearsals on native architecture runners.

Native AArch64 execution/release packaging has not been executed locally and
remains a publication gate; it is not silently waived by cross-compilation.

## Post-completion audit corrections

The Phase 16–25 implementation audit identified and corrected four release
candidate defects:

- ICMPv4/v6 Echo correlation now allocates a unique bounded 30-bit lane for
  every outstanding/grace probe and reserves the upper two identifier bits for
  the four concurrent session slots. Short ICMP error quotes can no longer be
  ambiguous across sessions.
- TCP/UDP source ports now come from four explicit non-overlapping partitions,
  including for custom ranges whose size is not divisible by four. Capacity is
  rejected during plan validation.
- UDP user payload validation accounts for the private 16-byte token, UDP
  header, and IPv4 header. The public maximum is 65,491 bytes and violations
  fail before runtime/session admission; aggregate retained templates remain
  within the 1 MiB budget.
- The Phase 19/20 sudo namespace harness builds the integration-test binary as
  the repository owner and executes only that binary with namespace authority,
  preserving both `CAP_NET_ADMIN` behavior and non-root artifact ownership.

Focused Rust and Node regression tests cover all corrected boundaries. The
canonical `sudo npm run test:phase19:namespace` and Phase 20 wrapper now run
without Cargo-path or dropped-capability workarounds.

## Next phase

Phase 25 is an evidence-only backend decision gate. Do not implement an extreme
backend merely because Phase 24 code exists; first close the publication gates,
record at least ten comparable portable/backend runs, and apply the accepted
confidence/throughput/CPU threshold.
