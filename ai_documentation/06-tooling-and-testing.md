# Tooling and testing plan

## Bootstrap principles

Phase 1 should create only enough tooling to produce, validate, and package the
TypeScript/N-API boundary. Use npm, commit `package-lock.json`, and pin current
compatible package releases when the scaffold is created.

Production dependencies should remain near zero on the TypeScript side. Build
and quality tools are development dependencies and should be kept narrowly
configured.

## Accepted TypeScript toolchain

- Node.js `>=26.0.0`, declared in package engines and checked at runtime/build
  boundaries where an actionable platform error is useful.
- npm as the only supported package manager.
- ESM-only TypeScript/JavaScript output with no top-level await so Node 26
  `require(esm)` remains usable; native loading may use an internal
  `createRequire()` bridge.
- TypeScript with strict checking, including strict null behavior and indexed
  access checks where compatible with the public design.
- ESLint using its current supported TypeScript integration and flat
  configuration unless compatibility research shows a reason not to.
- Prettier with a small explicit configuration and formatting check script.
- Node's built-in test runner as the default candidate to avoid an additional
  test framework dependency.
- Package scripts as the single documented entry point for local and CI checks.

ESLint should focus on correctness and boundary clarity rather than duplicating
Prettier's formatting role. Generated native-loader or declaration files should
be ignored or checked according to how they are produced, not patched manually.

## Accepted Rust toolchain

- Rust 1.97.0 stable pinned exactly through a toolchain file, using Rust 2024
  edition. Update the pin intentionally whenever a later stable Rust release is
  adopted; never track an unpinned `stable` channel in CI.
- `rustfmt`, Clippy, and `cargo test` as baseline gates.
- napi-rs v3 with stable Node-API 10 and only required features.
- Narrow Linux syscall bindings with unused crate features disabled.
- Phase 5 adds exact-pinned nix 0.31.3 with only `socket`, `uio`, and `net` for
  safe typed message/cmsg/address APIs that rustix does not provide. Do not add
  direct libc calls in that phase.
- Release profile settings reviewed for panic behavior, overflow behavior, and
  debug-symbol needs rather than copied blindly.

If abort-on-panic is considered, it must not substitute for returning errors or
catching all project-controlled panic paths at N-API exports. Process abort is
not safe error handling for a library.

## Commands

- `npm ci`: reproduce the Node development dependency tree from the lockfile.
- `npm run build`: build the native development addon and compile TypeScript.
- `npm run build:native`: build the native development addon only.
- `npm run build:native:release`: build the optimized native addon.
- `npm run build:typescript`: compile the public TypeScript layer.
- `npm run typecheck`: strict TypeScript verification without output.
- `npm run lint` / `npm run lint:fix`: verify or fix ESLint findings.
- `npm run format` / `npm run format:check`: write or verify Prettier output.
- `npm run rust:fmt`: verify `rustfmt` output.
- `npm run rust:clippy`: run all-target Clippy with warnings denied.
- `npm run rust:test`: run Rust unit tests with the committed Cargo lockfile.
- `npm run test:phase21`: run the deterministic syscall-free scanner-engine
  suite with virtual time and scripted collaborators.
- `npm test`: build and run the unprivileged Node tests.
- Phase 11 adds `npm run test:types`: compile consumer-facing event API fixtures
  against built declarations with no output; `npm test` and `npm run ci` include
  it after the TypeScript build.
- `sudo npm run test:privileged`: detect the invoking repository owner, build
  with that user's Node/rustup environment, then run successful raw-packet
  integration tests as root in a disposable network namespace.
- `sudo npm run test:phase11:stress`: use the same owner-safe build and isolated
  namespace harness for 256 event-source lifecycle cycles with fd/RSS checks.
- `npm run ci`: run every current unprivileged quality gate.

The privileged command is intentionally separate and must never be folded into
ordinary `npm test`. Where supported, run it inside an isolated user/network
namespace without host-level privilege:

```sh
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && NODENETRAW_PRIVILEGED_TESTS=1 node --test packages/nodenetraw/test/privileged.test.mjs'
```

Phase 5 adds the repository-owned `npm run test:namespace` harness so capability
scope and loopback setup are reproducible rather than embedded in ad hoc shell
commands. Later veth/error-route topology extends that harness. Hosts that
disable unprivileged user namespaces should report the kernel failure rather
than silently claim integration coverage.

The release-readiness follow-up adds a sudo-aware privileged wrapper for hosts
whose AppArmor policy blocks unprivileged UID mappings. It drops privileges for
the build, uses root only for `unshare --net` and test execution, and never
changes the host network namespace.

## Test layers

### Rust unit tests

Cover address encoding, range conversion, flags, error mapping, lifecycle state,
close idempotence, operation leases, and syscall-adapter behavior that can be
injected or exercised without raw-socket privilege.

Phase 5 extends this layer with cmsg alignment/length traversal, known and
unknown control messages, timestamp normalization, checked combined allocation,
operation-index cancellation, fake readiness, completion saturation, and
deterministic fairness tests.

### Node boundary tests

Load the built addon through the same public entry point consumers use. Test
plain JavaScript invalid values, TypeScript-facing success types, exceptions,
promise settlement, repeated close, garbage-collection-sensitive behavior where
reliable, and concurrent operation ordering.

Every `AbortSignal` path must test already-aborted, abort-after-admission,
completion-winning, close-winning, listener removal, and Worker teardown.

Phase 11 adds deterministic TypeScript controller tests using an internal fake
receive source, plus public-boundary tests for typed EventEmitter declarations,
one-operation rearming, pause/detach cancellation races, normal/error receive
lane conflicts, settled-but-undispatched lifecycle races, synchronous listener
exceptions, inherited meta-events/error monitoring, missing error listeners,
external/shared close, and Worker teardown. Event tests use deadlines so a
stranded pump fails rather than hanging the runner. Successful multi-message
IPv4, IPv6, packet, and error-queue behavior remains in the isolated privileged
suite.

The fake controller module is built as an internal implementation file and is
not a package export. A dedicated no-emit TypeScript fixture imports the built
root package to verify consumer declarations, including expected invalid event
payloads, inherited custom event names, and absence of claim/driver types.
Exception-channel and `captureRejections` cases run in child Node processes so
expected uncaught exceptions or unhandled rejections cannot corrupt the main
test runner. The ownership matrix includes composable pending finalizers and
simultaneous packet-ring configuration tokens, pending ring-frame receives, and
pending/success/failure against both event lanes.

Because every module-created supported socket requires raw-socket privilege,
ordinary CI cannot deterministically construct a valid public event adapter.
Privilege-free tests therefore exercise the internal controller and claim
coordinator with fake owners, plus root exports, types, forged inputs, and
permission failures. Genuine adapter construction, lane conflicts, external
close, packet-ring interaction, and Worker integration run in the isolated
namespace suite; they must not be falsely reported as ordinary coverage.

Controller tests cover all lifecycle methods in all eight states, cached promise
identity, same-turn start/pause/close, a fulfilled message waiting for dispatch,
stale scheduler tasks, synchronous resume from an error listener, transactional
constructor rollback, and dropped-emitter strong attachment. Cooperative Worker
tests assert events; forced termination asserts native cleanup/process safety
without requiring JavaScript callbacks after environment teardown.

`npm run test:types` executes after the built declarations exist. Clean CI and
consumer gates retain both ESM import and synchronous Node 26 `require(esm)` so
the internal controller must not introduce top-level await.

### Unprivileged Linux integration tests

Verify platform detection, permission errors, invalid protocols/options,
descriptor cleanup, process exit behavior, and operations on closed sockets.
These run in the normal test command and CI.

### Privileged Linux integration tests

Verify successful send/receive behavior and kernel metadata in an isolated
network namespace or container with only the required capability. These tests
are opt-in, visibly reported as skipped when unavailable, and must have cleanup
and timeouts.

Use loopback for IPv4/IPv6 protocol tests and a private veth pair for interface,
packet-socket, membership/fanout, and device-binding tests. Hardware timestamps,
driver-specific behavior, and nondeterministic overflow tests are informative
capability-detected jobs, not portable deterministic gates.

### Hardening tests

Add stress tests, fuzz targets, leak checks, and sanitizer workflows as native
structures stabilize. Keep them reproducible and state which boundary each tool
actually observes.

Phase 9 adds `npm run benchmark:namespace` for optimized batch, copy, ancillary
control, and two-hot-socket measurements. It is informative rather than a
timing-sensitive CI gate. `npm run test:phase9:stress` runs 256 ring
configure/cancel/close cycles and checks fd/RSS stability. Required future
targets include parser/serializer fuzzing; repeated cancel/close/readiness races
with syscall fault injection; two-hot-socket fairness; fd and resident-memory
stability; applicable ASan/LSan/TSan runs; and additional long-duration
mapped-ring teardown and resource-exhaustion runs.

Phase 10 adds one syscall-free `cargo-fuzz` surface target covering checked
address conversion, IPv4-header and packet-auxdata parsing, option reservation,
classic-BPF structure, message/batch allocations, ancillary serialization, and
ring geometry. Weekly ASan and TSan jobs observe native unit/concurrency paths;
the namespace stress job observes kernel descriptor, mmap, cancellation, and RSS
behavior. Sanitizers do not claim to instrument V8 or the Linux kernel.

Phase 11 adds native-free two-source fairness over 2,000 receive turns and the
privileged `test:phase11:stress` gate. The latter performs 256 socket cycles
with four start/pause/resume transitions each, alternates detach/reattach and
direct close, requires the descriptor count to return exactly to baseline, and
bounds RSS growth to 32 MiB.

Phase 12 begins, and Phases 13 through 15 extend, native-free ICMPv4 codec tests
in the ordinary Node gate: independent wire vectors, every short length,
odd/even/max checksums, runtime numeric boundaries, deterministic valid-message
generation, arbitrary byte parsing, compatible/canonical validation differences,
input/result ownership (including shared-memory snapshot isolation), and
TypeScript narrowing fixtures. Packet parsers must return structured results for
hostile bytes and must not leak `RangeError` or allocate from unchecked wire
lengths. RFC 4884 coverage includes exact length/MTU byte layouts, zero-length
default behavior, explicit legacy framing, extension checksums/objects, and the
576-byte ceiling.

Privileged ICMP coverage uses loopback for Echo and a disposable veth/network-
namespace router chain for quoted errors, MTU, TTL expiry, and traceroute. The
traceroute coordinator also receives a native-free fake-clock/fake-socket suite
covering loss, reordering, duplicates, late replies, per-probe/overall timeout,
cancellation, identifier reuse, short-quote match strength, callback failure,
lane conflict, and terminal destination/unreachable outcomes. Router Discovery
tests assert multicast destinations/TTL and explicit broadcast permission.
Repeated cancel/close runs retain descriptor and bounded-RSS checks. These
additions do not make ordinary CI privileged.

### Planned scanner verification layers

Phases 16 through 18 implemented syscall-free Rust golden/round-trip/property
tests, allocation baselines, pcap replay, and fuzz targets for every protocol
and nested quote entry point. The existing TypeScript ICMP vectors remain an
independent oracle. Phase 16 records the exact protocol dependency version,
features, MSRV, license, advisories, transitive diff, and build scripts before
the lockfile changes, plus a coverage/ownership matrix for dependency-supported
versus project-owned codecs and a reviewed correlation-token design. Protocol
tests distinguish strong TCP/token-bearing ICMP evidence from weaker ARP/NDP,
UDP, and short-quote matching; they cover ESP/unknown/No-Next-Header stops,
ICMPv6 pseudo-header checksums, and all RFC 4861 validation predicates.

Phase 16 implements the first layer with these canonical commands:

```sh
cargo test -p nodenet-protocols --locked
cargo clippy -p nodenet-protocols --all-targets --all-features --locked -- -D warnings
npm run fuzz:protocols
npm run benchmark:protocols
npm run test:phase17:namespace
```

Phase 27 adds `npm run udp:catalogue:check`. It validates the compiled,
project-owned UDP descriptor catalogue and fails when its canonical content no
longer matches the frozen version/hash. Protocol request-plan unit and
allocation tests remain part of `cargo test -p nodenet-protocols --locked`;
TypeScript UDP policy and schema-1/schema-2 hostile-boundary tests remain part
of the ordinary scanner package suite.

Phase 28 adds `crates/nodenetscanner-engine/tests/phase28.rs`. Its virtual-clock
matrix covers zero, one, four, sixteen, and sixty-four variants, the four-wire
per-endpoint ceiling, checked aggregate transmission counts, deterministic
contradictory evidence, the IPv4/IPv6 UDP ICMP state matrix, finite late grace,
and row/metadata reservation cleanup. Native unit tests additionally cover
collision-free source-port lane allocation/reuse and the 16 MiB session/64 MiB
environment metadata reservation boundary. These remain part of `rust:test`. Run
the focused matrix with `npm run test:phase28`.

The two protocol fuzz targets are `parse` and `serialize` in an independently
locked cargo-fuzz workspace. `test/fixtures/protocol` is the shared independent
wire-oracle directory. Allocation tests use a development-only instrumented
allocator; the runtime protocol graph remains only feature-minimal `etherparse`
plus `arrayvec`.

Phase 17 expands those targets across Ethernet/VLAN, ARP, IPv4, IPv6 extension
walking, fragments, and templates. `test:phase17:namespace` generates three
frames through the Rust builders, injects them through the existing raw packet-
socket API in a disposable veth namespace, and compares captured ARP, IPv4, and
IPv6 bytes exactly. Run it directly where unprivileged user namespaces work, or
with `sudo npm run test:phase17:namespace`; the wrapper still builds Rust/Node
artifacts as the repository owner so it does not create root-owned outputs.

Phase 19 implements the first read-only network-context layer with these
canonical commands:

```sh
cargo test -p nodenet-linux-context --locked
cargo clippy -p nodenet-linux-context --all-targets --locked -- -D warnings
npm run test:phase19:namespace
npm run test:phase19:stress
```

Phase 20 adds policy-aware route resolution, coherent multicast refresh, pure
route planning, and the bounded asynchronous context owner. Its additional
canonical gates are:

```sh
npm run test:phase20:namespace
npm run test:phase20:stress
```

The namespace command creates loopback, veth, VLAN, dual-stack addresses,
multiple route tables, blackhole/prohibit routes, rules, and fixed ARP/NDP
neighbors, then compares the complete snapshot with `ip -j` as a test-only
oracle. Run it with `sudo` where unprivileged user/network namespaces are
disabled. The stress lane warms the allocator and checks 512 complete snapshots
for descriptor retention and bounded RSS.

Phases 19 and 20 use synthetic multipart netlink streams plus disposable
namespace topologies for links, VLANs, dual-stack addresses, routes, rules,
ECMP, blackhole/prohibit outcomes, and every relevant neighbor state. Tests must
exercise dump interruption, overrun, `ENOBUFS`, sequence mismatch, malformed
attributes, notification races, and bounded resync. `ip -j` is a test oracle,
not a runtime dependency. Syscall tracing must prove no create/set/delete/
replace network operation. Tests launch the process in the target namespace and
prove the addon never invokes `setns()`; route-query races must retry rather
than mislabel a result with a new generation.

Phase 21 is fully privilege-free and uses an injected monotonic virtual clock,
scripted transport/context/evidence, and deterministic entropy. It runs millions
of transitions without sleeping and property-tests exclusions, permutations,
exact deadlines, at-most-once attempts, fairness, backpressure, replay
determinism, and memory proportional to active state.

Phases 22 and 23 add isolated dual-stack source/router/target namespaces with
veth/VLAN links and packet capture. They verify live ARP/NDP, ICMP Echo, TCP
SYN, and UDP open/closed/silent/error outcomes; exact bytes/checksums;
source/route selection; rate/retry/exclusion ceilings; forged/late response
rejection; context churn; result saturation; cancel/close; Worker teardown; and
fd/RSS/native-memory stability. Add loopback/local raw-IP and explicit
unsupported-link cases; outgoing-loop suppression, VLAN auxdata/offload,
truncation, drop-counter accounting, cross-session token/port allocation,
stalled-JavaScript completion delivery, and setup/retry/cleanup traffic rate
accounting. A captured evidence stream must replay identically through the pure
engine.

Phase 24 adds scanner-specific declarations, clean consumers, artifact ABI and
glibc checks, reproducibility, provenance, fuzz/sanitizer/fault gates, and
native x86-64/AArch64 execution before architecture artifacts can publish. Phase
25 performance work runs only on fully identified hardware and records kernel,
driver, NIC, queues, CPU/NUMA, MTU, ring geometry, packet mix, loss, CPU/power,
and latency. Shared CI never enforces timing thresholds. Conditional Phase 26
adds hardware/backend parity and ownership fault tests only for the selected
backend. Phase 25 uses identical preregistered workloads, at least ten steady-
state repetitions, and a bootstrap 95% confidence interval that must remain
beyond the accepted threshold.

The implemented local evidence command is `sudo npm run benchmark:phase25`. It
builds scanner/raw controls and the non-public Rust backend lab as the
repository owner, then runs a disposable namespace. Set
`NODENETSCANNER_PHASE25_OUTPUT=/path/evidence.json` to retain the JSON. D-039
records `no-go`, so this command is diagnostic and does not authorize Phase 26.

Scanner commands are introduced by the phase that owns them and then added to
the root orchestration. Until implementation starts, documentation must not list
aspirational scripts as runnable commands.

### UDP protocol-probe verification

Phases 27–30 add and exercise the project-owned catalogue, safe/extended codecs,
risk matrix, schema 2, and live responder matrix without making the local Nmap
checkout a build, test, or runtime dependency. Phases 31–33 extend these same
gates. Catalogue checks require stable generated output, unique IDs, valid
port/range/profile/source constraints, complete primary-source provenance,
bounded templates, known builders/parsers, and a reproducible catalogue hash.
Clean-clone and release tests run with no Nmap installation or source tree
present.

Every UDP builder receives independent specification-derived golden bytes and
dynamic transaction-field properties. Every parser receives valid, wrong-
transaction, wrong-endpoint, truncated, malformed-length/count, arbitrary-byte,
and mutation cases plus allocation ceilings and fuzz coverage. Typed protocol
responders in disposable dual-stack namespaces provide independent open-service
oracles; closed, prohibited, unreachable, silent, delayed, duplicated,
contradictory, and ICMP-rate-limited paths exercise the evidence lattice.

The syscall-free engine uses virtual time to cover several variants per logical
endpoint, retry products, decisive early stopping, source-port/grace exhaustion,
fairness, result reservation, backpressure, cancellation, context invalidation,
and teardown. Captured project-owned evidence replays deterministically. Live
capture proves protocol requests are byte exact and that exact custom mode has
no prefix while legacy prefix mode remains explicit.

Reservation tests cover both rows and the 16 MiB per-session/64 MiB environment
service-metadata budgets; batch sealing may shorten a pull to keep all variable
columns within 4 MiB. `maxOutstanding` tests count physical variants. The ICMP
matrix retains family/type/code/target-origin detail through policy, including
intermediate port-unreachable and IPv6 Parameter Problem. Profile snapshots are
crossed with independent risk-consent sets so catalogue breadth can never grant
amplification, state, fixed-source, multicast/broadcast, authentication, or
sensitive-read permission.

Phase 31 maintains and validates the independently sourced project
capability/provenance ledger, exact catalogue coverage, finite signature work
bounds, canonical per-family fixtures, checked ranges, and profile/risk
snapshots. Phase 32 preregisters an adaptive-versus-exhaustive comparison on the
independent responder matrix. Phase 33 records only the manual aggregate
comparison with the frozen Nmap reference; no distributed script executes Nmap
or parses its data/output. The accepted release claim distinguishes UDP
payload/state elicitation from full service/version fingerprinting. Exact local
commands and results are recorded in `51-phase-33-report.md`.

Implementation phases introduce canonical command names only when the owned
tests exist. The eventual gates must integrate with ordinary CI, protocol and
engine fuzzing, sanitizers, privileged namespace tests, repeated lifecycle/RSS/
fd stress, clean consumers, artifact ABI/glibc inspection, reproducibility, and
native AArch64 execution.

### Advanced discovery verification

Phase 34 begins with syscall-free virtual one-query/many-responder tests for
aggregation, duplicates, partial entities, quiet windows, exact deadlines,
link/target scopes, session-pool and per-query row/metadata reservation,
datagram/query/deadline saturation, backpressure, deterministic replay, and
pause/cancel/close/Worker races. Discovery schema 1 receives the same sealed
buffer, hostile offset/length/discriminant, transfer, and lazy-view tests as
scan schemas without reinterpreting schemas 1/2. Synthetic native transport
tests also prove that ordinary UDP-only discovery opens no raw/packet descriptor
or requires `CAP_NET_RAW`, while mixed-descriptor setup failure rolls back
before transmission.

Phases 35–36 add disposable multi-responder IPv4/IPv6 interface topologies and
capture exact multicast groups, ports, source/interface selection, hop limits,
query expansion, retries, response windows, and rate accounting. DNS compression
and XML event parsing receive structural mutation, depth/work/size, allocation,
fuzz, sanitizer, entity/DTD/external-resource, and response-flood coverage.

Phases 37–38 use virtual graph/race models and live dynamic-port responders to
prove target containment, graph bounds, cycle suppression, parent/child
reservation, first-valid alternate-port pinning, spoofed/competing responses,
late grace, and exactly-once cleanup. Phases 39–43 require independent canonical
responders and protocol-specific byte/CPU/state/amplification/risk matrices; a
candidate can no-go without weakening the gate.

Phase 44 repeats ordinary and privileged end-to-end topologies, hostile input,
fuzzing, sanitizers, fault injection, slow consumers, Worker/fd/RSS stress,
dependencies/advisories, clean consumers, ELF/GLIBC, reproducibility, and native
x86-64/AArch64 execution. Planned command names are not documented as runnable
until their owning phase implements them.

## CI shape

The first CI workflow should be unprivileged and should run formatting, linting,
type checking, native checks, builds, and ordinary tests. Cache usage must not
be required for correctness. A separate privileged workflow may be added only
with a documented isolation and capability model.

The Phase 5 namespace harness is available locally without making ordinary CI
privileged. A future isolated CI job may invoke it where the runner permits user
namespaces. Phase 6 added IPv6; Phase 7 added veth packet-socket coverage. Phase
8 added connected IPv4, advanced typed options, packet membership,
auxdata/statistics/fanout, filter replacement/locking, and caller-fd retention.
Release gates require x86-64 and AArch64 execution, not cross-compilation alone.

The initial matrix tests Node 26 as the minimum and adds later Node majors when
they become supported. Native targets are x86-64 and AArch64 glibc Linux with
kernel 4.18+ and glibc 2.28+. At least x86-64 runs the full unprivileged gate in
Phase 1; AArch64 becomes a blocking target before artifacts are published.

## Dependency review

There are no Node runtime dependencies. Exact direct development dependencies
are locked in `package-lock.json`:

- TypeScript 6.0.3 and `@types/node` 26.1.1 provide compilation and Node types.
  TypeScript 7 was not selected because `typescript-eslint` 8.63.0 currently
  declares support only below TypeScript 6.1.
- ESLint 10.7.0, `@eslint/js` 10.0.1, and `typescript-eslint` 8.63.0 provide the
  flat strict type-aware lint configuration.
- Prettier 3.9.5 is formatting-only and does not overlap ESLint policy.
- `@napi-rs/cli` 3.7.3 performs local native builds and binding generation.

The Rust crate pins napi 3.10.4, napi-derive 3.5.10, rustix 1.1.4, and
build-only napi-build 2.3.2. napi disables default features and enables only
stable Node-API 10; napi-derive enables strict macro checks and type definition
generation. rustix disables defaults and enables only `std`, `event`, `fs`, and
`net` so the Linux socket, epoll, and eventfd boundary remains safe without
pulling in a general async runtime. All transitive Rust versions are committed
in the root `Cargo.lock`.

Phase 5 adds nix 0.31.3 as a direct native dependency with default features
disabled and only `socket`, `uio`, and `net`. The implementation change records
the resolved transitive diff, licenses, build scripts, advisories, and overlap
with rustix. Nix is selected specifically for typed message/control/address
coverage; it does not replace rustix's owned-fd and reactor primitives.

For every direct dependency, record or make reviewable:

- why the standard library/current tool cannot reasonably replace it;
- runtime, build-time, or development-only classification;
- disabled/default feature choices;
- maintenance and release activity;
- license compatibility;
- native code, install scripts, or binary download behavior;
- effect on the published package.

Automated advisory checks can help but do not replace review of N-API build
scripts and release artifact provenance.
