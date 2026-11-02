# nodenet

Linux raw-networking and bounded scanner libraries with TypeScript APIs and Rust native implementations.

## Packages

- [nodenetraw](packages/nodenetraw/README.md): IPv4/IPv6 raw IP and Linux packet sockets, typed message I/O, bounded batching, filters, receive rings, cancellation, stable errors, event receive adapters and ICMPv4 helpers.
- [nodenetscanner](packages/nodenetscanner/README.md): policy-aware bounded host/port discovery, deterministic target and task handling, protocol probes and portable scanner orchestration. See its API reference for catalogue coverage and explicit exclusions.

The Rust workspace contains Linux-context, shared-protocol, scanner-engine and two native N-API crates. This separation keeps kernel resource ownership, protocol codecs and scanner policy distinct.

## Platform

Use Node.js26+ with npm11+, Rust1.97.0 from [rust-toolchain.toml](rust-toolchain.toml), and a supported 64-bit glibc Linux system. Package READMEs describe kernel/glibc floors and architecture limits. AArch64 remains experimental until verified on native hardware. There is no musl, non-Linux or32-bit fallback or install-time native download.

Raw sockets commonly require CAP_NET_RAW or sufficient privilege. The library reports permission failures and never grants itself privileges. Network tests and traffic generation require an authorized environment and explicit selection of the relevant integration commands.

## Development

```sh
npm ci --ignore-scripts
npm run build
npm run typecheck
npm test
```

The normal workspace build compiles the native addons and TypeScript declarations. Tests, types, lint and Rust checks have focused scripts in [package.json](package.json). Privileged, namespace, stress, benchmark and fuzz commands are separate opt-in developer tools; inspect their scope and prerequisites before using them. Do not use sudo for builds.

## Local package tooling

The source workspace refuses direct publication. Maintainer release assembly stages packages, checks architecture/glibc and provenance, and requires a clean Git worktree. Release commands do not automate npm publication. Generated build/release files and historical fuzz corpus inputs are not source inputs to commit; keep required historical data outside Git and choose any recovery explicitly.

## API boundaries

The raw layer owns Linux resources and message operations. The shared protocol crate owns bounded codecs/parsers and catalogue data. The scanner layer owns policy, budgets, scheduling and result classification. Stable public registry fields such as phase remain compatibility metadata; they are not instructions to execute a development plan. No AF_XDP/XDP loader, writable TX ring, unrestricted high-rate backend, full service fingerprinting or ARM64 readiness is implied.

## License

Owned source is [MIT licensed](LICENSE). Dependency and probe-data notices/provenance retain their own terms. See package references and catalogue provenance before redistributing derived artifacts.
