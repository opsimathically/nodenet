# Phase 10 implementation report

Date: 2026-07-12

## Outcome

Phase 10 implementation is complete. The public package is now the unpublished
`0.1.0-rc.1` release candidate, with an architecture-independent root package
and install-script-free x86-64/AArch64 glibc target packages. Release assembly,
clean-consumer testing, provenance, dependency policy, reproducibility, fuzzing,
sanitizers, advisory checks, and native architecture CI are repository-owned
gates. No npm publication, git push, tag, or GitHub release occurred.

The local x86-64 release gates pass. Native AArch64 execution is encoded as a
blocking GitHub Actions job but cannot be executed from this x86-64 checkout;
the first publication remains blocked until that job passes on the committed
revision. This preserves the roadmap requirement that cross-compilation alone is
not compatibility evidence.

## Hardening

- `native/fuzz` is an independently locked `cargo-fuzz` crate. Its only target
  calls the `fuzzing` feature's deterministic, syscall-free adapter. Inputs
  exercise IPv4/IPv6 text and protocol parsing, checked ranges, packet-address
  serialization, IPv4 headers, packet auxdata, known/unknown cmsg conversion,
  outbound cmsg serialization, raw/typed option names and reservation,
  classic-BPF control flow, message/batch bounds, and TPACKET_V3 geometry.
- The production build does not enable `fuzzing`. The fuzz-only feature uses
  napi-rs dynamic symbol resolution so a standalone libFuzzer executable can
  link without a Node process; it does not change the published addon.
- Weekly ASan and TSan jobs rebuild the Rust standard library with the selected
  sanitizer and run all native tests. A local run of each sanitizer passed all
  37 tests. These jobs observe Rust/native code, not V8 or kernel internals.
- The existing 256-cycle packet-ring stress gate is retained as the kernel-side
  fd, mmap, cancellation, close, and RSS check. Deterministic syscall-failure,
  lifecycle races, completion saturation, cancellation, and fairness remain in
  the ordinary native/namespace layers rather than being duplicated in a fuzz
  binary that is forbidden from making syscalls.
- The hardening workflow runs full npm and RustSec advisory checks weekly.
  Direct production and development versions remain exact-pinned and both Rust
  lockfiles are committed.

## Compatibility and skips

The ordinary workflow now runs the full unprivileged Node 26 gate on native
`ubuntu-24.04` x86-64 and `ubuntu-24.04-arm` AArch64 runners. Node 26 is both
the minimum and current supported major at this phase; future Node majors are
added when released and accepted. Both jobs build against Node-API 10.

The declared baseline remains Linux 4.18+, glibc 2.28+, x86-64/AArch64. musl,
non-Linux, and 32-bit targets are rejected. Raw socket success paths require
`CAP_NET_RAW`; unprivileged permission failures remain part of the ordinary
gate. User-namespace integration may be unavailable when a host disables it.
Hardware timestamps, driver behavior, real overflow, transparent routing, and
privileged mark/filter behavior are capability-detected rather than portable
release gates. The README table distinguishes these from unsupported TX mmap and
AF_XDP.

## Artifact contract

D-025 freezes the distribution model:

- `nodenetraw` contains ESM output, declarations, the generated loader,
  documentation, changelog, license, and machine-readable release policy;
- `nodenetraw-linux-x64-gnu` and `nodenetraw-linux-arm64-gnu` each contain one
  native addon plus manifest, license, and readme;
- root optional dependencies use the exact root version and npm platform
  selectors choose the applicable target package;
- no package has an install script, native download hook, or Node runtime
  dependency;
- source builds remain explicit repository commands;
- staged file SHA-256 values, toolchain/source identity, Cargo.lock SHA-256, and
  artifact inputs are recorded under ignored `release/` output;
- release rehearsal never publishes and uploads short-retention artifacts only
  after the native target's build, complete gate, clean double-build hash, and
  clean-consumer test pass.

The local staged x86-64 target tarball contained four files and was 373.2 kB;
the root contained ten files and was 34.1 kB. A temporary clean project
installed both local tarballs with lifecycle scripts disabled and loaded
`nativeSmokeTest()` successfully through ESM and `require()`.

## Frozen release defaults and measurement

`release-policy.json` is the machine-readable source for supported platforms and
allocation defaults: 65,535 packet bytes; 4 KiB default/64 KiB maximum control
storage; 4 KiB opaque options; 32 pending operations per socket; 64 messages/1
MiB per batch; 64 MiB per ring and 128 MiB per environment; and 4096 classic-BPF
instructions.

The final local optimized namespace measurement reported a 2.15x batch-send
speedup, 0.089 ms two-hot-socket completion skew, 2130 MiB/s owned-copy
throughput, and 25,834 controlled messages/s. Measurements are informative and
do not become timing-sensitive correctness gates.

## Verification evidence

- clean `npm ci`: 150 development packages installed; zero reported advisories;
- `npm run ci`: formatting, ESLint, strict TypeScript, Rust formatting, Clippy,
  37 Rust tests, native/TypeScript builds, seven ordinary Node tests, release
  metadata/license policy, and production audit pass;
- `cargo check --manifest-path native/fuzz/Cargo.toml --locked`: fuzz crate and
  fuzz-only adapters compile;
- a 20-second ASan-backed libFuzzer run completed without a finding; the weekly
  job uses 300 seconds;
- local nightly ASan and TSan runs each passed all 37 native tests;
- `cargo audit --file native/Cargo.lock` and the fuzz-lock equivalent reported
  no vulnerabilities;
- `npm run test:namespace`: six isolated namespace tests pass;
- `npm run test:phase9:stress`: 256 cycles retained the 24-fd baseline exactly
  with a 917,504-byte RSS delta;
- `npm run release:reproducibility`: two clean Cargo target directories produced
  identical native SHA-256
  `bab0f704948fb5b7bd57aa18fbd259eee93deb1d604a78c1bf1272f4fc26ad43`;
- `npm run release:consumer-test`: intentional package contents and clean ESM
  plus CommonJS consumption pass on x86-64.

## Publication gate

Before any first npm publication, an operator must push the intended revision,
observe successful x86-64 and AArch64 CI plus hardening workflows, run the
manual release-artifact rehearsal, compare both provenance outputs, and then
make a separate explicit publish decision. Phase 10 intentionally provides no
automatic publish command.
