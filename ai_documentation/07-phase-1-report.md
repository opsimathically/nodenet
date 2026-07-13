# Phase 1 completion report

Completed: 2026-07-12

## Outcome

The environment bootstrap is operational. An ESM TypeScript entry point loads a
generated CommonJS native loader and calls a harmless Rust function through
stable Node-API 10. The package also loads synchronously through Node 26
`require(esm)` interoperability. No networking or socket code was added.

## Toolchain

- Node.js 26.4.0 (supported floor remains 26.0.0)
- npm 11.17.0
- Rust and Cargo 1.97.0, exactly pinned in `rust-toolchain.toml`
- Rust 2024 edition
- TypeScript 6.0.3
- napi-rs 3.10.4 / napi-derive 3.5.10 / napi-build 2.3.2
- `@napi-rs/cli` 3.7.3
- ESLint 10.7.0 with typescript-eslint 8.63.0
- Prettier 3.9.5

TypeScript 7.0.2 was current during bootstrap but was not selected because the
current typescript-eslint peer range ends below TypeScript 6.1. The latest
compatible TypeScript release was pinned instead of running an unsupported lint
combination.

## Added structure

- Root npm, TypeScript, ESLint, Prettier, npm-engine, and Rust toolchain files.
- `native/`: a `cdylib` Rust crate with exact direct dependency versions and a
  committed Cargo lockfile.
- `src/index.ts`: the public ESM facade.
- `test/smoke.test.mjs`: ESM and synchronous `require()` boundary tests.
- `.github/workflows/ci.yml`: unprivileged Node 26/Linux x86-64 CI with actions
  pinned by commit SHA.
- Generated output is isolated under ignored `build/`, `dist/`, and
  `native/target/` directories.

The package is marked private at version 0.0.0 to prevent accidental publication
before the raw-socket API and release process exist.

## Safety properties established

- The Rust crate denies handwritten unsafe code by default. `forbid` cannot be
  used because napi-rs's reviewed export macro applies its own scoped generated
  unsafe allowance; `deny` still requires an explicit local override for future
  project-owned unsafe code.
- napi uses only the stable `napi10` feature; experimental Node-API is disabled.
- TypeScript uses strict checking plus checked indexed access and exact optional
  property semantics.
- The public package has no Node runtime dependencies.
- Both npm and Cargo lockfiles are committed.
- CI is unprivileged and has read-only repository contents permission.

## Verification record

The following completed successfully on x86-64 glibc Linux:

- `npm install`: 151 total npm packages audited, zero known vulnerabilities at
  verification time.
- `npm run ci`: Prettier, ESLint with zero warnings, strict TypeScript checking,
  rustfmt, all-target Clippy with warnings denied, one Rust unit test, native
  and TypeScript builds, and two Node boundary tests.
- `npm run build:native:release`: optimized native build.
- `npm pack --dry-run`: nine intended package files; no source tree,
  dependencies, or development artifacts included.

Successful local verification does not claim AArch64 execution coverage. That
target becomes a blocking test before prebuilt artifacts are published.

## Next phase

Phase 2 builds the Node-independent Rust socket lifecycle core. Before syscalls
are exposed, it must specify descriptor ownership, open/closing/closed
transitions, operation leases, close races, structured Linux errors, and checked
integer/address conversions.
