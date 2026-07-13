# Release-readiness audit

Date: 2026-07-12

## Outcome

The full x86-64 local audit passes after correcting six concrete issues. The
TypeScript API, generated N-API declarations, Rust boundary validation,
descriptor/operation ownership, reactor lifecycle, Linux syscall adapters,
unsafe blocks, package contents, workflows, and release artifact ABI were
reviewed. No known x86-64 release-blocking defect remains in the audited scope.

This is not ARM64 verification. AArch64 remains untested and experimental until
the native GitHub runner executes the committed revision. Hardware/driver-only
features and runtime execution on the oldest supported kernel/glibc combination
also remain external compatibility evidence, as documented in the README.

## Corrections made

1. N-API completion delivery used a 64-entry nonblocking queue and accepted
   `QueueFull`, which could discard a completion and leave a Promise unresolved.
   Delivery now uses bounded blocking backpressure from the reactor thread. A
   namespace test accumulates 96 completions while JavaScript is deliberately
   blocked and proves that all settle.
2. `close()` could finalize while an admitted operation was still in the reactor
   command channel. Per-socket admission state now follows the socket into the
   reactor, and close completion waits until every admitted operation has
   produced its cancellation/error completion and released its descriptor lease.
   The regression test submits the full 16 pending-receive queue before closing
   and was repeated 100 times locally.
3. Native Ubuntu 24.04 release builds required symbols through `GLIBC_2.34`
   despite the package claiming glibc 2.28. Release builds now use napi-rs's
   pinned GNU compatibility toolchain. Assembly verifies the ELF architecture
   and rejects glibc requirements above 2.28; the audited x86-64 artifact's
   highest requirement is `GLIBC_2.16`.
4. A malformed userspace-owned TPACKET_V3 block could repeatedly poison future
   ring receives and remain withheld from the kernel. Error recovery now clears
   traversal state and returns the block to kernel ownership. A private mmap
   unit test verifies the ownership transition.
5. Batch receive now validates the kernel-returned sockaddr length before
   decoding it. Single and batch packet receives reject an impossible hardware
   address length instead of silently truncating metadata.
6. Packet sockets now reject IP-only `disconnect()` semantics at both the
   TypeScript and native boundaries. A nightly Rust deprecation warning was also
   removed without changing behavior.
7. The privileged test entry point now supports ordinary `sudo`: it discovers
   the invoking user's Node 26 and rustup environments, drops privileges for the
   build, then runs only the already-built suite as root in a disposable network
   namespace. This avoids AppArmor user-namespace restrictions, host-network
   mutation, and root-owned build output.
8. The public TypeScript API now provides a focused set of zero-dependency Linux
   `IPPROTO_*` and `ETH_P_*` number constants. Numeric protocols remain accepted
   for custom identifiers, and all public README examples use the named forms.

D-026 records the completion backpressure tradeoff and D-027 records the GNU
artifact build/ABI rule.

## Verification evidence

Audit host: x86-64 Ubuntu 24.04, Linux 6.17.0, glibc 2.39, Node 26.4.0, npm
11.17.0, and Rust 1.97.0.

- clean `npm ci`: 150 development packages; zero npm advisories;
- `npm run ci`: Prettier, ESLint, strict TypeScript, Rustfmt, all-target Clippy
  with warnings denied, 38 Rust tests, seven ordinary Node tests, builds,
  release metadata/license policy, and production audit pass;
- generated declaration comparison: all 38 native functions match the manually
  typed TypeScript binding interface;
- `npm run test:namespace`: seven privileged isolated tests pass across IPv4,
  IPv6, raw/cooked AF_PACKET, packet rings, filters, ancillary metadata,
  cancellation, close, and callback saturation;
- `npm run test:phase9:stress`: 256 ring configure/cancel/close cycles retained
  the descriptor baseline exactly (24 to 24); final RSS delta was 917,504 bytes;
- `npm run benchmark:namespace`: 2.88x batch-send speedup, 0.027 ms two-hot-
  socket completion skew, 3776 MiB/s owned-copy throughput, and 20,681
  controlled messages/s (informative, not a timing gate);
- one-minute libFuzzer run: 8,569,313 executions, no crash or sanitizer finding;
- final nightly ASan and TSan runs: all 38 native tests pass under each;
- full `npm audit`, `cargo audit --file native/Cargo.lock`, and fuzz-lock audit:
  no reported vulnerabilities;
- workflow files parse as YAML and their folded `run` commands resolve to the
  intended shell commands;
- `npm run release:reproducibility`: two clean compatibility builds produced
  SHA-256 `3e5f1aa773a413e324682d0b6041a9e3147a6bdf7bb5e0dc3d5a3c2e866c36c4`;
- `npm run release:consumer-test`: ELF/glibc gate passed, staged contents were
  four files/375.0 kB for the x86-64 target and ten files/34.7 kB for the root,
  and a clean install loaded through both ESM and `require()` with scripts
  disabled.

The ordinary test command reports the seven privileged tests as skipped by
design; `test:namespace` executes that same complete privileged file with its
required isolated loopback/veth setup. No host-network privileged test was run
outside the namespace.

## Remaining publication gates

- Commit and push the intended revision, then run native x86-64 and AArch64 CI.
- Treat ARM64 as untested until its native job and release rehearsal pass.
- Run the manual artifact workflow on both architectures and compare provenance
  before any explicit npm publication decision.
- Continue the scheduled five-minute fuzz, sanitizers, audits, and namespace
  stress. Local one-minute fuzzing is evidence, not a substitute for the
  scheduled duration.

No package was published, no tag or release was created, and no remote state was
changed by this audit.
