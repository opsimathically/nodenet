# Decision log

Use this document for choices that affect the public API, safety model, build,
testing, or support matrix. Accepted decisions should include a date and enough
rationale to avoid repeating the investigation.

## Accepted decisions

### D-001 — Linux-only support

- Status: accepted
- Date: 2026-07-12
- Decision: target Linux APIs directly; do not provide cross-platform fallbacks.
- Rationale: the project exists to expose Linux raw socket functionality and
  should model its semantics accurately.

### D-002 — TypeScript public environment with Rust through N-API

- Status: accepted
- Date: 2026-07-12
- Decision: consumers receive a typed Node module; Rust implements the native
  boundary and low-level socket behavior using N-API.
- Rationale: combines Node ergonomics with explicit native memory/resource
  ownership and an ABI-stable Node extension interface.

### D-003 — Minimize dependencies without reimplementing safety machinery

- Status: accepted
- Date: 2026-07-12
- Decision: dependencies require concrete value and narrow configuration, but
  dependency count does not override safety or maintainability.
- Rationale: hand-written N-API or syscall FFI can create more risk than a
  carefully selected maintained crate.

### D-004 — Explicit cleanup is primary

- Status: accepted
- Date: 2026-07-12
- Decision: the public API will provide explicit, idempotent socket close;
  garbage-collection finalization is a defensive fallback.
- Rationale: GC timing is nondeterministic and unsuitable as the primary method
  for releasing scarce kernel descriptors.

### D-005 — Node.js, Node-API, and Rust baseline

- Status: accepted
- Date: 2026-07-12
- Decision: support Node.js `>=26.0.0` and stable Node-API 10. Use the latest
  stable Rust release, exactly pinned in the repository and updated
  intentionally on each stable release; begin with Rust 1.97.0 and Rust 2024
  edition.
- Rationale: Node 26 is the requested minimum and supports Node-API 10. A
  rolling latest-stable Rust policy provides current safety and language fixes
  without making nightly Rust part of the build contract.
- Consequences: Node 26 is tested as the minimum release line. CI should add
  later supported Node majors as they ship. A Rust update is a reviewed lockstep
  repository change, not an unpinned build-time download.

### D-006 — Initial Linux platform baseline

- Status: accepted
- Date: 2026-07-12
- Decision: initially support x86-64 and AArch64 GNU/Linux with kernel 4.18+ and
  glibc 2.28+. musl, 32-bit, and additional architectures are unsupported until
  separately tested and accepted.
- Rationale: this matches Node's Tier 1 glibc Linux baseline for its primary
  64-bit architectures and avoids promising an untested libc matrix.

### D-007 — npm and ESM-only public output

- Status: accepted
- Date: 2026-07-12
- Decision: use npm with a committed `package-lock.json` and publish one
  ESM-only public entry point. Use an internal CommonJS loader via
  `createRequire()` where necessary to load the `.node` addon.
- Rationale: npm ships with Node and adds no package-manager prerequisite. Node
  26 provides mature ESM and synchronous `require(esm)` interoperability, so a
  dual TypeScript build is unnecessary. Native loading mechanics remain hidden.
- Consequences: both `import` and Node 26 `require()` consumption are tested,
  but there is only one public JavaScript build format and no top-level await.

### D-008 — napi-rs v3 with Node-API 10

- Status: accepted
- Date: 2026-07-12
- Decision: use napi-rs v3 with stable Node-API 10 and only the required Cargo
  features. Scaffold it manually for npm rather than importing an entire package
  template.
- Rationale: napi-rs supplies reviewed value/lifetime conversion, panic and
  async integration, type generation, and maintained Node 26 testing. This
  removes more project-owned FFI risk than its dependency cost introduces.
- Consequences: generated bindings/loaders are treated as generated artifacts;
  project-specific lifecycle and syscall safety still remain our responsibility.

### D-009 — Bounded epoll reactor

- Status: accepted
- Date: 2026-07-12
- Decision: use nonblocking descriptors with one bounded, environment-scoped
  Rust reactor based on Linux `epoll`, woken for commands and shutdown through
  `eventfd`. Do not park indefinite socket waits in libuv's shared worker pool.
- Rationale: this directly models Linux readiness, bounds thread use, provides
  an explicit close/shutdown wakeup, and avoids a large general async runtime.
- Consequences: the reactor state machine, queue limits, Node environment
  teardown, and promise settlement paths require focused tests and review.

### D-010 — First socket slice is IPv4 raw IP

- Status: accepted
- Date: 2026-07-12
- Decision: first implement `AF_INET`/`SOCK_RAW` with an explicit IP protocol,
  asynchronous byte send/receive, Linux error preservation, and explicit close.
- Rationale: it proves raw descriptor ownership and packet I/O with a smaller
  address model before adding IPv6 and link-layer packet sockets.
- Consequences: the exact public names receive a focused Phase 3 API review;
  IPv6 and `AF_PACKET` are not part of the first usable slice.

### D-011 — Source builds before prebuilt artifacts

- Status: accepted
- Date: 2026-07-12
- Decision: use source builds during bootstrap and early development. Add
  prebuilt x86-64/AArch64 glibc npm artifacts only during the hardening and
  distribution phase; do not use installation-time binary downloads.
- Rationale: source builds keep early release machinery small while the native
  ABI and target policy stabilize. npm-hosted target packages later provide a
  more auditable installation path than arbitrary download scripts.

### D-012 — Safe Linux syscall bindings through rustix

- Status: accepted
- Date: 2026-07-12
- Decision: use rustix 1.1.4 with default features disabled and only `std`,
  `fs`, and `net` enabled for the Phase 2 Linux socket and descriptor boundary.
- Rationale: rustix returns owned descriptors and provides safe typed wrappers
  for atomic socket flags and errno. It removes project-owned FFI and unsafe
  ownership conversion while remaining narrower than a general async runtime.
- Consequences: rustix and its locked transitive Linux bindings become part of
  the audited native dependency surface. Raw libc calls require a separate
  recorded justification when rustix cannot express a needed Linux operation.

### D-013 — Phase 3 public API and bounded admission

- Status: accepted
- Date: 2026-07-12
- Decision: expose an owned `RawSocket` with asynchronous `open`, `send`,
  `receive`, and idempotent `close`, plus synchronous lifecycle status. Copy
  outbound bytes into Rust ownership and return received bytes in a new Buffer.
  Bound each environment to 64 sockets and 128 pending operations, each socket
  to 16 pending sends and 16 pending receives, the command queue to 256, and the
  N-API completion queue to 64. Reject excess admission with `ERR_QUEUE_FULL`.
- Rationale: the narrow class keeps descriptor ownership explicit; copying
  eliminates cross-thread JavaScript buffer lifetime assumptions; fixed limits
  provide deterministic backpressure and cap retained memory and callbacks.
- Consequences: queue limits are part of observable behavior and require review
  before change. Close cancels admitted work, and successful packet tests remain
  opt-in because they require `CAP_NET_RAW` in the governing namespace.

### D-014 — Serialized typed IPv4 configuration and parsed metadata

- Status: accepted
- Date: 2026-07-12
- Decision: serialize bind, local-address, and typed option operations through
  the environment reactor. Support `SO_BROADCAST`, `IP_TTL`, `IP_TOS`,
  `SO_RCVBUF`, and `SO_SNDBUF`, with a 16 MiB requested-buffer cap. Report the
  original datagram length and parse a complete valid IPv4 header into typed
  receive metadata.
- Rationale: reactor serialization preserves close and fd-lease invariants;
  typed options permit dual-boundary validation; parsing the already-received
  IPv4 header adds useful metadata without ancillary-buffer FFI or borrowed
  memory.
- Consequences: Linux may clamp/double socket buffer requests, so getters expose
  effective values. Address binding can select a local interface by address.
  Device-name binding and generic ancillary/option escape hatches remain
  deferred until safe syscall support and a dedicated API review exist.

### D-015 — Full-capability baseline and family sequencing

- Status: accepted
- Date: 2026-07-12
- Decision: define practical full raw-networking coverage as IPv4 raw IP, IPv6
  raw IP, Linux packet sockets, message/control/error semantics, typed plus
  bounded extensible configuration, filtering, bounded batching, measured packet
  rings, and release hardening. Implement the message substrate before IPv6 and
  `AF_PACKET`; implement those families separately before advanced escape
  hatches and performance paths.
- Rationale: IPv6 metadata relies on control messages and packet sockets use a
  distinct address/lifecycle model. A shared message foundation prevents
  family-specific duplicate reactors without pretending the families have
  identical Linux semantics.
- Consequences: the roadmap expands through Phase 10. Netlink, TUN/TAP, protocol
  decoding, firewall policy, and eBPF program loading remain outside the
  baseline. AF_XDP is a later evaluation.

### D-016 — Add nix for typed message and ancillary support

- Status: accepted and implemented
- Date: 2026-07-12
- Decision: add exact-pinned nix 0.31.3 with default features disabled and only
  `socket`, `uio`, and `net`. Use it for typed `sendmsg`/`recvmsg`, cmsgs,
  family addresses, and options absent from rustix. Retain rustix for owned fds,
  epoll/eventfd, and existing safe operations.
- Rationale: nix exposes owned typed IPv4/IPv6 packet info, TTL/hop-limit,
  TOS/traffic-class, timestamps, extended errors, unknown cmsgs, packet
  addresses, batching, and bind-to-device. This removes alignment-sensitive
  project FFI at a justified dependency cost. It is MIT licensed and its Rust
  1.69 MSRV is below the project toolchain.
- Consequences: two focused syscall crates are audited and locked. Phase 5 adds
  no direct libc calls; D-020 records the sole function-scoped unsafe exception
  to the default crate-wide denial.

### D-017 — Message primitives and AbortSignal cancellation

- Status: accepted
- Date: 2026-07-12
- Decision: add family-neutral `sendMessage`/`receiveMessage` primitives with
  bounded data/control capacities, typed flags/control messages, owned unknown
  receive cmsgs, and optional `AbortSignal`. Keep existing IPv4 `send`/`receive`
  as compatibility conveniences. The native reactor operation table owns
  exactly-once completion across readiness, cancel, close, and shutdown.
- Rationale: one-message APIs expose Linux `sendmsg`/`recvmsg` semantics without
  requiring callbacks or unbounded streams. Native cancellation avoids closing a
  socket merely to stop one wait.
- Consequences: Phase 5 adds `ERR_ABORTED`, `ERR_UNSUPPORTED`, and
  `ERR_MALFORMED_CONTROL`, per-socket total admission, abort-listener cleanup,
  and cancellation/fairness stress tests.

### D-018 — Typed-first bounded extensibility

- Status: accepted
- Date: 2026-07-12
- Decision: keep typed options/control messages as the preferred API, preserve
  bounded unknown receive cmsgs as owned bytes, and later add raw
  get/set-socket-option bytes for unmodeled Linux features. Reject generic
  pointer-bearing, nested-pointer, and fd-bearing layouts; implement those only
  as typed ownership-aware operations.
- Rationale: a fully capable bridge cannot wait for a release for every new
  harmless kernel option, but a variadic unchecked syscall mirror would defeat
  memory and descriptor safety.
- Consequences: any project-owned unsafe adapter requires its own accepted
  design record, localized lint allowance, fuzzing, and fault tests. Unknown
  outbound cmsgs are not admitted in Phase 5.

### D-019 — Optimize only behind the same ownership model

- Status: accepted
- Date: 2026-07-12
- Decision: add bounded `sendmmsg`/`recvmmsg` only after message correctness,
  then add TPACKET_V3 rings only with explicit mapped-memory frame/block leases
  and benchmarks. Do not use blocking `recvmmsg` timeouts. AF_XDP is not an
  initial release requirement.
- Rationale: Linux documents timeout/error edge cases for `recvmmsg`, and mapped
  rings introduce a second resource-lifetime system. Performance features must
  not bypass cancellation, fairness, truncation, or close invariants.
- Consequences: batch/ring APIs have partial-result models, strict memory
  limits, long-running teardown tests, and measured acceptance gates.

### D-020 — Immediately own and close unexpected received descriptors

- Status: accepted
- Date: 2026-07-12
- Decision: permit one localized unsafe `OwnedFd::from_raw_fd` conversion for
  each descriptor returned by nix in an unexpected received `SCM_RIGHTS` control
  message, followed by immediate drop and `ERR_UNSUPPORTED`.
- Rationale: Linux installs these descriptors in the process before nix returns
  them as raw integers. Rejecting the message without adopting ownership would
  leak process descriptors, while exposing them is outside the raw-networking
  API. Nix 0.31.3 does not return `OwnedFd` for this control variant.
- Consequences: the adapter converts each newly returned descriptor exactly once
  and never stores or exports it. The allowance is function-scoped with a
  `SAFETY:` ownership proof and focused control conversion tests. Crate-wide
  unsafe denial remains the default; this decision authorizes no pointer or
  layout unsafe code.

### D-021 — Additive IPv6 family contract

- Status: accepted and implemented
- Date: 2026-07-12
- Decision: preserve `RawSocket.open({ protocol })` as IPv4 and add
  `family: "ipv6"` to select `AF_INET6`. Every socket exposes its immutable
  family. Message addresses are discriminated `ipv4` or `ipv6`; IPv6 addresses
  carry checked `scopeId` and `flowInfo` fields. `bind()` accepts only a
  matching family address, `localMessageAddress()` returns the full address
  object, and `connect()`/`disconnect()` provide serialized kernel peer
  selection. Legacy string `send`, `receive`, and `localAddress` remain
  IPv4-only conveniences.
- Rationale: this adds IPv6 without changing Phase 3–5 IPv4 call shapes or
  erasing scope information. Kernel IPv6 raw receives contain protocol payload,
  not a fabricated IPv6 header; metadata comes from ancillary messages.
- Consequences: Phase 6 adds typed IPv6 packet-info, hop-limit, traffic-class,
  extended-error controls and matching safe sockopts. It defers `IPV6_CHECKSUM`,
  path-MTU discovery, and IPv6 multicast-loop configuration because the accepted
  safe crates do not expose them; D-018/Phase 8 governs those additions.

### D-022 — Packet address contract and localized sockaddr_ll construction

- Status: accepted and implemented
- Date: 2026-07-12
- Decision: extend socket family with `packet` and require a mode of `raw` or
  `cooked` plus a nonzero 16-bit EtherType in host order. Packet message
  addresses contain a checked interface index, EtherType, and up to eight
  hardware-address bytes; received addresses additionally expose hardware type
  and packet type. Add bounded interface name/index lookup. Use one localized
  Linux adapter to initialize `sockaddr_ll` by value and call `bind(2)` and
  `sendto(2)` because nix 0.31.3 can safely decode `LinkAddr` but exposes no
  safe constructor, and rustix 1.1.4 exposes no packet address type.
- Rationale: substituting `SO_BINDTODEVICE` is not valid packet-socket bind
  semantics, and omitting a destination prevents deterministic cooked/raw
  injection. The kernel ABI structure is fixed-size and contains no pointers.
- Consequences: the adapter is the only new Phase 7 unsafe surface. It
  zero-initializes every field, bounds `sll_halen` to eight, converts protocol
  to network byte order exactly once, keeps all references within the syscall,
  and retains `OwnedFd`/operation-lease ownership. Membership, auxdata,
  statistics, fanout, and filtering remain Phase 8.

### D-023 — Bounded option and filter safety boundary

- Status: implemented in Phase 8
- Date: 2026-07-12
- Decision: bound generic socket-option values to 4096 initialized bytes and
  reject all known fd-, pointer-, nested-layout-, ownership-, ring-, filter-,
  packet-membership-, fanout-, and project-typed option tuples. Implement those
  as typed operations. Bound classic BPF programs to 4096 instructions, validate
  jump targets and a terminal return, and let Linux perform its full verifier
  pass. Compatible eBPF attachment duplicates the caller fd with `CLOEXEC`,
  attaches that duplicate, and closes it immediately; the library never assumes
  ownership of the caller's fd. No general descriptor-export API is added.
- Rationale: initialized opaque bytes safely cover scalar and harmless struct
  options, but pointer/fd layouts and ownership transitions cannot be modeled as
  arbitrary bytes. Kernel filter APIs copy or retain their inputs, so explicit
  typed adapters can make lifetimes deterministic.
- Consequences: one reviewed advanced Linux adapter owns raw `getsockopt`/
  `setsockopt`, classic `sock_fprog`, packet membership/statistics/fanout, and
  compatible eBPF attachment. Every call uses a live operation lease and fixed
  bounds. Packet rings remain Phase 9.

### D-024 — Bounded batch and packet-ring lease contract

- Status: implemented in Phase 9
- Date: 2026-07-12
- Decision: batch calls admit 1 through 64 messages and at most 1 MiB of
  operation-owned data. They use nonblocking `sendmmsg(2)`/`recvmmsg(2)` on the
  reactor, return after one productive syscall, and report the explicit
  completed prefix; unattempted messages are never represented as successful.
  The first fast batch slice excludes ancillary control data so every native
  header has a fixed reviewed lifetime. Receive batches retain per-message
  source, flags, original length, and truncation semantics.

  Packet rings use `TPACKET_V3` only, cap each mapped ring at 64 MiB and each
  environment at 128 MiB, and validate all block/frame alignment and offsets
  before access. JavaScript never receives a Buffer backed directly by mutable
  ring memory. The reactor copies a validated frame before returning its block
  to the kernel; the JavaScript lease owns only that bounded copy, exposes
  copied reads while live, and clears it on explicit release. Socket close stops
  new leases, unmaps the ring on the reactor, and already-delivered copied
  leases remain independent. Transmit rings are implemented only if the same
  ownership model and measurements show a benefit.

- Rationale: nonblocking mmsg preserves reactor cancellation/fairness without
  the defective blocking timeout path. Direct external Buffers cannot be made
  observably invalid after lease release, while copied lease reads preserve the
  enforceable lifetime boundary and still amortize receive syscalls.
- Consequences: batch ancillary data remains on the one-message API until a
  separately reviewed stable native header arena exists. Ring performance claims
  include the copy cost. Release measurements showed a 2.81× `sendmmsg` speedup;
  TX mmap remains deferred because its writable-frame contract adds risk without
  a demonstrated improvement. AF_XDP remains outside the baseline.

### D-025 — Release-candidate artifact and provenance contract

- Status: accepted and implemented in Phase 10
- Date: 2026-07-12
- Decision: use `0.1.0-rc.1` as the first externally installable version and
  keep publication a separate human-authorized action. Distribute an
  architecture-independent root package plus exact-version optional
  `@opsimathically/nodenetraw-linux-x64-gnu` and
  `@opsimathically/nodenetraw-linux-arm64-gnu` packages. Target packages contain
  only the native addon, license, readme, and manifest; they have
  Linux/CPU/glibc selectors and no install scripts. Release assembly records
  SHA-256 file provenance, clean-consumer tests both ESM and `require()`, and a
  double optimized build must have identical native hashes.
- Rationale: target packages allow npm to select one checked artifact without
  installation-time network scripts or compilation, while the repository remains
  a documented source-build path. An RC communicates that the complete low-level
  surface is implemented but has not accumulated stable-release field
  experience.
- Consequences: x86-64 and AArch64 execute the full unprivileged gate on native
  GitHub-hosted runners. Artifact rehearsal is manual and never publishes.
  Releasing requires both target jobs, advisory/hardening gates, intentional
  package contents, and matching versions. musl and other platforms fail as
  unsupported rather than building or downloading during install.

## Remaining design details

Phases 1 through 18 are implemented and the workspace migration is accepted in
D-030. D-031 accepts the Phase 16–26 scanner evolution boundary; Phase 19 is the
next implementation phase. Publishing an artifact remains an explicit operator
action outside implementation. Changes to the accepted scanner package/crate
boundary, protocol/context scope, portable-first rule, or evidence threshold
require a new decision. Unrelated raw-package stream, async-iterator, or packet-
ring-event work remains separately undecided.

### D-026 — Lossless bounded Node completion backpressure

- Status: accepted; supersedes the nonblocking completion-delivery portion of
  the Phase 5 plan
- Date: 2026-07-12
- Decision: use the bounded 64-entry N-API thread-safe-function queue in
  blocking mode from the reactor thread. Treat `Ok` and environment `Closing` as
  the only valid delivery outcomes. Keep socket I/O nonblocking and never invoke
  blocking callback delivery from the JavaScript thread.
- Rationale: native admission is released when reactor work completes, before
  JavaScript drains its callback queue. A synchronous caller can therefore
  submit more than the nominal 32-operation limit over time. Nonblocking
  delivery can return `QueueFull`, and there is no safe second channel through
  which to settle the already-dropped Promise. Bounded backpressure preserves
  exactly-once settlement and memory bounds.
- Consequences: a JavaScript environment that is not draining callbacks may
  pause its reactor at completion delivery. That environment cannot observe
  network progress while stalled in any case. A 96-completion namespace test
  intentionally exceeds queue capacity and must settle every Promise.

### D-027 — Enforced GNU artifact compatibility baseline

- Status: accepted
- Date: 2026-07-12
- Decision: optimized release artifacts use napi-rs's pinned GNU compatibility
  cross toolchain. Assembly and rehearsal must inspect the ELF machine and
  reject any required glibc symbol newer than 2.28. Development builds remain
  native-host builds and are not release artifacts.
- Rationale: a native build on Ubuntu 24.04 required symbols through glibc 2.34
  despite package metadata claiming glibc 2.28. Platform selectors do not prove
  ABI compatibility. The compatibility build currently requires no symbol newer
  than glibc 2.16, safely below the Node 26 package floor.
- Consequences: release builds may fetch the pinned napi-rs build-time
  toolchain. `readelf` is a release prerequisite. Clean-consumer,
  reproducibility, and artifact rehearsal all transitively enforce the ABI
  check; installing staged packages still runs no script or download.

### D-028 — Typed event adapter over bounded message receives

- Status: accepted and implemented in Phase 11
- Date: 2026-07-13
- Decision: preserve `RawSocket` as the complete low-level promise API and add a
  separate typed `RawSocketEventEmitter` implemented in TypeScript with Node's
  built-in `node:events`. Each explicitly started event source repeatedly issues
  at most one bounded `receiveMessage()` for either the normal or Linux
  error-queue lane. It provides awaitable pause and detach boundaries, explicit
  resume, idempotent socket close, and `message`, `error`, and exactly-once
  `close` events. Module-private lane claims reject conflicting direct, batch,
  ring, or event receivers with `ERR_RECEIVER_ACTIVE`; packet-ring mode excludes
  both event lanes. State-transition conflicts use `ERR_INVALID_STATE`. `peek`,
  automatic start, configurable concurrency, internal message queues, and
  awaited listener promises are excluded. EventEmitter rejection capture follows
  the Node process setting; because JavaScript may reject with any value,
  `error` accepts `unknown`, while adapter-generated receive failures remain
  `RawSocketError`.
- Rationale: composition provides familiar Node event ergonomics while reusing
  the mature native cancellation, ownership, bounds, and error model. Explicit
  start prevents listener-registration races. One operation and no adapter queue
  bound retained memory and preserve ordering. Awaitable pause/detach avoids
  silently losing a receive that wins cancellation. Lane arbitration prevents
  nondeterministic packet splitting, while separate normal and error lanes
  preserve useful Linux concurrency.
- Consequences: the adapter adds no runtime dependency and ordinarily no native
  or unsafe code. Synchronous listeners delay rearming; asynchronous listeners
  are not backpressure. Pausing cannot stop kernel ingress or packet loss. A
  non-lifecycle receive error pauses before emitting `error` and never retries
  automatically; reactor closure is terminal. The adapter mirrors the existing
  terminal-on-close-start `RawSocket` contract even when the cached close
  promise rejects. A pump turn includes fulfilled-but-undispatched delivery;
  attachment is strongly retained until explicit detach/close; per-operation
  ring tokens and transactional claim/observer installation prevent mode races;
  and reactor loss calls low-level close to terminalize admission. Inherited
  EventEmitter meta-events and error monitoring retain Node semantics.
  Packet-ring, batch, stream, and async-iterator delivery remain separate
  designs. The changed release candidate advances to `0.1.0-rc.2`, and all Phase
  10 artifact/provenance gates must be rerun.

### D-029 — Pure bounded ICMPv4 utilities over existing socket ownership

- Status: accepted for Phases 12 through 15; Phase 12 implemented
- Date: 2026-07-13
- Decision: implement the enumerated ICMPv4 codecs, checksum helpers, received-
  IPv4 adapter, one-operation socket helpers, and bounded Echo traceroute in
  strict TypeScript with Node built-ins and zero runtime dependencies. Codecs
  allocate owned bounded outputs, return structured failures for hostile packet
  input, preserve unknown safe data, and separate checksum/structure/policy.
  Receive parsing is compatible by default and reports safely decodable
  non-canonical fields; canonical validation escalates those findings without
  conflating them with unsafe structural failure. Internal codecs remain
  independent of root error factories, while the root facade preserves the
  existing runtime argument-error contract. Socket helpers accept an existing
  `RawSocket` and delegate to its message API; event applications parse existing
  event messages. Traceroute uses a dedicated socket, one internally
  attached/detached event source for its lifetime-long lane claim, per-message
  TTL, strong direct/quoted correlation, monotonic deadlines, explicit
  probe/time/payload/in-flight/result bounds, and cleanup before cancellation or
  local-failure rejection. RFC 4884 parsing is length-based by default; zero
  length means no extension, and fixed-128-byte legacy detection is explicit
  opt-in. It does not implement deprecated ICMP type 30. The accepted message
  list is ICMPv4; ICMPv6 codecs remain a separate future design.
- Rationale: protocol encoding and parsing are bounded byte transforms that do
  not benefit from another N-API crossing or native ownership layer. TypeScript
  keeps the public types and wire logic reviewable, while composition reuses the
  already hardened Rust descriptor/reactor boundary. Explicit separation of
  standalone ICMP bytes from Linux IPv4 raw receive frames prevents a common
  header-offset error. Structured parse results are suitable for untrusted event
  loops without exception-driven packet handling.
- Consequences: no new runtime or Rust dependency is planned. Parser performance
  includes deliberate bounded copies until measurement justifies a separately
  reviewed immutable/zero-copy contract. Redirect, router discovery, timestamps,
  and Address Masks remain informational and never alter host configuration. A
  high-level traceroute owns the normal lane and conflicts with other receivers;
  event consumers use public builders/classifiers instead. Every public-surface
  phase advances the release candidate and reruns declaration, privileged,
  stress, consumer, reproducibility, and artifact gates.

### D-030 — Neutral monorepo with independent Node packages and shared Rust builds

- Status: accepted and implemented
- Date: 2026-07-13
- Decision: develop `nodenetraw` and the future `nodenetscanner` in the renamed
  `nodenet` repository. The repository root is a private npm workspace and a
  virtual Cargo workspace. The existing public package lives at
  `packages/nodenetraw`; its native addon lives at `crates/nodenetraw-native`.
  `packages/nodenetscanner` is initially a private, non-publishable placeholder
  with no API or implementation. Use npm's built-in workspaces, one root npm
  lock, one root Cargo lock, and no manual `npm link`, Lerna, Nx, Turborepo, or
  second package manager. Public Node packages version and publish
  independently. Reusable performance-sensitive Rust code may later move into
  `publish = false` workspace crates only after a focused contract, benchmark,
  and safety review.
- Rationale: public package separation preserves a clear, policy-free raw
  networking API while allowing a scanner addon to keep scheduling, packet
  construction, correlation, and result batching inside Rust. Package boundaries
  do not create hot-path overhead when shared Rust code is linked at compile
  time and N-API is crossed only for configuration, control, and bounded
  results. A long-lived fork would duplicate fixes, native ownership logic,
  release work, and security review.
- Consequences: repository-root commands remain the canonical operator interface
  and target `nodenetraw` explicitly until another implemented package has its
  own gates. The root can never be published. Direct source-tree publication of
  `nodenetraw` remains blocked; release assembly still produces independently
  inspectable root and architecture packages. Structural migration must not
  alter public API behavior, artifact contents, ABI policy, or privilege
  handling. Scanner work cannot expand `nodenetraw`'s public scope implicitly,
  and shared-crate extraction is a later change rather than part of this move.

### D-031 — Portable-first native scanner evolution with internal Rust crates

- Status: accepted and preimplementation-reviewed for Phases 16 through 26;
  Phase 16 is complete
- Date: 2026-07-13
- Decision: evolve in five ordered stages: protocol toolkit, read-only Linux
  network context, deterministic scheduler plus portable live scanning,
  scanner-oriented batching and hardening, then an optional evidence-gated
  extreme backend. `nodenetraw` remains a policy-free public package.
  `nodenetscanner` owns a separate N-API addon and its descriptors, packet hot
  loop, timers, correlation, and result storage; it does not call the raw
  package through JavaScript or borrow a `RawSocket` fd. Add non-published
  `nodenet-protocols`, `nodenet-linux-context`, and `nodenetscanner-engine`
  crates without N-API dependencies, plus a `nodenetscanner-native` addon crate.
  Do not create a third public protocol or context package. Network context uses
  bounded GET/query/subscription operations only and never mutates host state.
  Make the ordinary raw/packet-socket engine release-capable before optimizing
  it. Phase 25 may select one backend only after showing at least 1.5x sustained
  matched-result throughput or 30% lower CPU at equal verified loss/accuracy;
  otherwise record `no-go`.
- Rationale: independent Node packages give users clear capability boundaries,
  while compile-time Rust sharing and one batch-oriented N-API boundary avoid
  per-packet composition overhead. A protocol foundation and kernel-derived
  route context prevent the scheduler from duplicating unsafe parsers or
  guessing Linux forwarding policy. A pure scheduler makes timing and lifecycle
  behavior exhaustively testable before privilege and live I/O are introduced.
  The portable-first gate prevents specialized ring/XDP ownership, privilege,
  kernel, and hardware requirements from becoming scope without evidence.
- Consequences: Phase 16 begins with dependency/version/license/advisory
  revalidation and contains no scanner API or syscall work. Scanner public APIs
  start only in Phase 22 and use bounded result batches from their first
  preview. Phase 24 is a complete release outcome; Phases 25 and 26 are not
  required for project success. AF_XDP may require an explicit XDP program and
  higher optional platform requirements, but it can never raise the portable
  installation baseline or silently replace operator-owned BPF state. The
  detailed resource ceilings, gates, topology, and stop conditions live in
  `31-network-and-scanner-evolution-plan.md`. The closed preimplementation audit
  additionally freezes protocol-specific evidence strength, one bounded scanner
  runtime per Node environment, Ethernet/VLAN/loopback initial support, no
  `setns()`, generation-race retries, all-frame rate accounting, reserved
  terminal-result capacity, packet outgoing/VLAN handling, and the repeated
  95%-confidence performance gate. See `32-network-evolution-plan-review.md`.

### D-032 — Protocol dependency boundary and correlation encoding

- Status: accepted and implemented through the syscall-free Phase 18 boundary;
  OS entropy injection remains owned by the Phase 22 scanner runtime
- Date: 2026-07-13
- Decision: use exact-pinned `etherparse` 0.20.3 with default features disabled
  behind project-owned types and errors. Dependency lax parsing is exposed only
  as the explicit `CompatibleIcmpQuote` mode and tolerates truncation, never
  malformed content. Phase 18 correlation uses HMAC-SHA-256 with a distinct
  32-byte OS-random session key and constant-time comparison from a reviewed
  library. The scheduling seed is never key material. The fixed canonical HMAC
  input is the 16 ASCII bytes `nodenet/probe/v1`, address-family byte (4 or 6),
  IP-protocol byte, big-endian attempt `u32`, source and destination as two
  16-byte addresses (IPv4 is twelve zero bytes followed by its four octets),
  big-endian source port, destination port, ICMP identifier, and ICMP sequence
  (`u16`, zero when inapplicable), then the big-endian internal probe ID `u64`.
  The full correlation value is 32 bytes. Token-bearing UDP and ICMP payloads
  carry the first 16 bytes; compare exactly 16 bytes in constant time after
  tuple/protocol validation. TCP carries the first four bytes as its sequence
  number and validates the reply acknowledgement as sequence plus one modulo
  2^32 after tuple/flag validation. A minimal ICMP quote that omits a token is
  explicitly weaker evidence and is never upgraded by guesswork.
- Rationale: the exact dependency pin and wrapper prevent a changing codec API
  from leaking across crates. HMAC-SHA-256 is a reviewed keyed primitive; fixed-
  width, domain-separated encoding avoids ambiguous concatenation, while
  distinct OS entropy prevents reproducible scheduling from making correlation
  predictable. Truncation reflects real ICMP quotation without accepting
  malformed packets through a silent fallback.
- Consequences: Phase 18 exact-pins the selected HMAC and constant-time crates,
  accepts session-key bytes from the future scanner native runtime, zeroizes its
  key storage, and tests protocol-specific truncation and comparison rules. The
  32-bit TCP wire token has an inherent smaller search space than a 128-bit
  payload token and evidence classification says so. Phase 22 must obtain each
  session key from OS entropy; the syscall-free protocol crate does not generate
  entropy.

### D-033 — Minimal read-only route-netlink boundary

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: implement Linux context in the non-published, N-API-independent
  `nodenet-linux-context` crate using exact-pinned `netlink-packet-core` 0.8.1,
  `netlink-packet-route` 0.31.0, and `netlink-sys` 0.8.8 with default features
  disabled. Own one `NETLINK_ROUTE` datagram descriptor and expose only bounded
  immutable GET-dump snapshots. Do not add `rtnetlink`, an async runtime,
  mutation operations, procfs parsing, subprocess calls, or `setns()`.
- Rationale: the packet crates remove unsafe duplicated ABI parsing while the
  syscall crate retains a narrow synchronous descriptor model. Project-owned
  preflight validation, ceilings, multipart state, normalization, retries, and
  coherence checks prevent dependency behavior from becoming the trust policy. A
  descriptor created in the target namespace provides stable namespace identity
  without unsafe process-wide namespace transitions.
- Consequences: the crate contains two localized, documented unsafe socket-
  option calls for `SO_RCVTIMEO` and `SO_NETNS_COOKIE`; all netlink parsing and
  public records remain safe Rust. Phase 20 extends this same serialized context
  with query/subscription coherence and may not weaken the read-only request
  surface or publish records from mixed generations.

### D-034 — Kernel-selected egress and bounded context owner

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: extend the Phase 19 descriptor with targeted `RTM_GETROUTE`,
  subscribed route-netlink multicast refresh, a pure generation-bound route
  planner, and one optional background `RouteContextDriver`. Linux remains the
  sole policy/ECMP selector. The driver owns one context on one thread, admits
  at most 1,024 operations, starts deadlines at enqueue, and exposes cooperative
  cancellation plus polling or bounded waiting without adding an async runtime.
- Rationale: user-space longest-prefix or ECMP selection would diverge from
  Linux rules, marks, UID, and port policy. Subscription-before-dump plus atomic
  notification application closes snapshot races. A small bounded owner gives
  the future scanner a nonblocking integration seam without creating a thread
  per query or committing the workspace to Tokio.
- Consequences: notifications are authenticated by the kernel recvmsg sender;
  their header sequence/port may identify the userspace mutation that caused the
  multicast event and are not required to be zero. Overflow, malformed state,
  abandoned replies, or generation churn invalidate rather than relabel context.
  Only Ethernet/VLAN and local/loopback plans are initially usable; other link
  and encapsulation forms are structured unsupported results.

### D-035 — Deterministic scanner engine and bounded settlement

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: implement Phase 21 as the non-published, syscall-free
  `nodenetscanner-engine` crate. It depends only on `nodenet-protocols` and
  receives monotonic time, scheduling entropy, context resolution, frame
  emission, and result capacity through injected traits. Compact target
  intervals and a checked logical Cartesian product remain lazy; a seeded
  constant-memory affine permutation determines reproducible order. The public
  scheduling seed is never a correlation secret.
- Decision: reserve one terminal result before first emission, charge every
  setup/probe/retry/TCP-cleanup frame to one exact fixed-point token bucket, and
  cap active, deferred, grace, target, prefix, and per-drive transition state
  independently. Timeout equality is terminal (`now >= deadline`); response
  evidence at that boundary is late and cannot resurrect a result. Pause queues
  eligible retransmission without sending it. Deadline, cancel, and fatal
  transport settlement drain through the same 4,096-transition drive budget.
- Decision: preserve protocol-specific silence semantics and evidence strength.
  Invalid, forged, duplicate, fragmented, opaque, or insufficient evidence
  updates diagnostics only. Context and sink collaborator errors preserve the
  unadmitted or reserved probe so a caller never loses work through a partially
  advanced scheduler transition.
- Rationale: separating the state machine from Linux descriptors makes target
  arithmetic, timing, loss behavior, fairness, replay, and lifecycle boundaries
  deterministic and exhaustively testable without privilege or wall-clock
  sleeps. Reservation-before-emission is the simplest proof that slow future
  JavaScript result consumption cannot force a positive result drop.
- Consequences: Phase 22 owns packet construction, secrets, correlation, Linux
  descriptors, route-context adaptation, and multi-session round-robin driving.
  It must not bypass the engine's emission charge or result reservation seams.
  The engine itself exposes no N-API or public TypeScript scanner API.

### D-036 — Environment-owned portable scanner runtime and pull API

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: implement Phase 22 in a separate `nodenetscanner-native` addon that
  statically links the protocol, read-only context, and deterministic engine
  crates. One `epoll`/`eventfd` worker per Node environment owns all session
  descriptors, packet buffers, timers, context state, and independently random
  correlation secrets. It multiplexes at most four scanner objects and four
  active sessions and admits only bounded command and result state.
- Decision: use `AF_PACKET` for supported Ethernet/VLAN egress and raw IP
  sockets for loopback/local routes. Missing direct-neighbor state may be
  learned only from explicit ARP/NDP probes into session-owned state. Receive
  processing rejects truncation, ignores `PACKET_OUTGOING`, reconstructs a
  stripped VLAN header from `PACKET_AUXDATA`, and accumulates packet-drop deltas
  without treating reset-on-read counters as lifetime totals. An explicit
  `TP_STATUS_CSUMNOTREADY` completes the TCP/UDP checksum in a private copy
  before strict parsing; it is not a general checksum-validation bypass.
- Decision: expose explicit immutable scan plans, capability-free context
  inspection and scanner creation, structured errors, lifecycle controls,
  terminal summaries, and bounded pull batches. No descriptor or native packet
  storage crosses N-API. Control tasks may wait for worker replies away from the
  Node event loop, while the I/O worker never waits for JavaScript delivery.
  Environment cleanup invalidates admission, wakes the worker, and joins it
  before the cleanup hook completes.
- Rationale: a scanner-specific native data plane preserves the raw package's
  policy-free boundary while avoiding per-packet JavaScript crossings. A pull
  API and reservation-before-emission make slow JavaScript an explicit bounded
  backpressure condition rather than an allocation or result-loss hazard.
- Consequences: the scanner remains private at `0.0.0`; Phase 23 may replace the
  straightforward object-vector batch representation only through its planned
  versioned compact schema. The default TCP/UDP source range can interact with
  host ephemeral users, and raw SYN-ACK replies may provoke host TCP resets; the
  addon documents these facts and never installs firewall policy. Native AArch64
  execution and the full privileged namespace matrix remain mandatory before
  public release.

### D-037 — Versioned scanner batch and backpressure boundary

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: freeze scanner result-batch schema version 1 as independently owned
  columns. Address octets use network byte order with explicit per-row family
  and scope columns; every fixed-width integer column is little-endian. Zero
  marks a missing port, state, scope, or evidence value, while `u64::MAX` marks
  a missing RTT. RTT and terminal timestamp columns contain unsigned nanoseconds
  relative to the session monotonic origin; the current scheduler provides
  microsecond resolution widened exactly to nanoseconds. Reason metadata is
  fatal UTF-8 with bounded `u32` offsets. The schema carries no wall time and no
  native pointer.
- Decision: the worker seals plain Rust vectors, the N-API resolve step creates
  Node buffers, and TypeScript copies each column into an ordinary transferable
  `ArrayBuffer` before exposing it. Lazy row views, iteration, filtering, and
  explicit materialization are TypeScript-only. JavaScript mutation or transfer
  can affect only the retained batch and never native scanner state.
- Decision: identify every pull monotonically. A worker-ordered cancellation
  returns an aborted pull only when it precedes delivery; a sealed batch that
  won the race is delivered. Abort cancels the wait, not the scan. The optional
  batch event emitter is a one-pull adapter and emits no per-result events.
- Decision: result admission enters backpressure at the high-water capacity and
  does not resume until occupancy reaches the half-capacity low-water mark.
  Receive, expiry, cancellation, close, and result draining remain live. A
  waiting pull seals immediately at its requested maximum or terminal drain, and
  otherwise allows one bounded 2 ms worker interval to coalesce newly available
  rows. Terminal results are never dropped. Progress is a coalesced
  exact-`bigint` snapshot, and one plan/control command is limited to 65,536
  items and 4 MiB.
- Rationale: these boundaries make crossings proportional to result batches,
  eliminate JS-managed storage from the worker thread, prevent queue
  oscillation, and preserve deterministic cancellation and teardown ownership.
- Consequences: schema changes require a new version rather than
  reinterpretation. A transferred batch becomes explicitly detached in its
  sending realm. Phase 24 may harden and document this contract but may not
  silently change its encoding.

### D-038 — Independent portable scanner release boundary

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: stabilize `@opsimathically/nodenetscanner` at the unpublished
  `0.1.0-rc.1` boundary. Schema version 1, the six-probe result matrix,
  lifecycle/error declarations, read-only context shape, and public admission
  limits are frozen for this release candidate. Changes that reinterpret these
  contracts require a later release rather than silent loader or schema drift.
- Decision: distribute the scanner independently as a loader-only root package
  plus exact-version x86-64 and AArch64 glibc target packages. No package has an
  install script or production Node dependency. Assembly verifies ELF machine,
  the glibc 2.28 ceiling, stripping, clean ESM/`require()` consumption,
  reproducibility, dependency licenses/advisories, and recorded provenance.
- Decision: keep publication mechanically separate from implementation. Native
  AArch64 execution and supported privileged namespace tests on release
  artifacts remain mandatory even when x86-64 tests and AArch64 cross-compiles
  pass. Phase 25 may measure alternatives only after these portable gates; it
  may not weaken the release baseline.
- Rationale: an independently useful, bounded portable scanner is a safer
  product boundary than making publication depend on a speculative high-rate
  backend. Exact target packages avoid install-time compilation while retaining
  one JavaScript API and one native ownership model.
- Consequences: the source tree deliberately rejects direct `npm publish`.
  Releases come only from inspected staging directories. The benchmark harness
  records hardware, kernel, interface, and configuration metadata, and no
  Masscan-class throughput claim is made. The sudo-only x86-64
  namespace/benchmark gates pass locally; the owner still must execute the
  native AArch64 release workflow before publishing this candidate.

### D-039 — No extreme scanner backend selected

- Status: accepted and implemented
- Date: 2026-07-14
- Decision: complete Phase 25 with `no-go`. Keep the portable scanner as the
  only backend and close Phase 26. A non-public evidence harness may retain the
  frozen backend-neutral ownership contract, deterministic bootstrap tools,
  ordinary mmsg and TPACKET_V3 controls, a bounded native-owned TPACKET_V2 TX
  lab, and non-mutating AF_XDP capability probes, but none becomes product API.
- Rationale: ten-repetition portable rate sweeps were accurate and lossless,
  while no alternative completed the identical scheduler/TX/RX/correlation/
  result workload needed for the 1.5x-throughput or 30%-CPU selection test.
  PACKET_MMAP microbenchmarks cannot be composed into a valid end-to-end ratio.
  AF_XDP copy and zero-copy were unavailable without an XDP/XSKMAP fixture, and
  the host had no isolated physical peer. Missing qualified evidence is not a
  performance win and cannot justify writable-ring, UMEM, loader, privilege,
  cleanup, dependency, or artifact-ABI scope.
- Consequences: `engine` selection is not added; install and kernel baselines do
  not change; no writable ring or UMEM crosses N-API; and Phase 26 work is
  prohibited. Reopening requires a new decision and plan review, an isolated
  declared physical fixture, explicit XDP ownership when relevant, and fresh
  preregistered same-workload evidence. Phase 24's native AArch64 publication
  gate remains independently outstanding. See the Phase 25 report.

### D-040 — Independently authored protocol-aware UDP evolution

- Status: accepted
- Date: 2026-07-14
- Decision: implement service-aware UDP probing in Phases 27–33 as an extension
  of the portable scanner. One logical `(target, UDP port)` result may execute a
  bounded programme of physical protocol subprobes. Every physical setup,
  variant, and retry consumes the rate budget and owns finite correlation/grace
  state; the engine aggregates direct UDP, ICMP, and silence through a
  deterministic evidence lattice. Protocol mode uses specification-valid
  transaction fields or tuple/source-port ownership rather than an unconditional
  private payload prefix. Exact custom bytes and explicit legacy token-prefix
  behavior remain available separately.
- Decision: create a project-owned, statically linked, versioned catalogue with
  stable probe IDs, profiles, port sets, builders/parsers, correlation
  strategies, resource bounds, network-impact classification, and primary-
  source provenance. Builders, typed parsers, and any finite response-signature
  DSL live in `nodenet-protocols`; selection/aggregation live in
  `nodenetscanner-engine`; descriptors, entropy, source ports, packet bytes, and
  live correlation remain native-owned. Schema version 2 adds bounded UDP
  service evidence and physical/logical accounting without reinterpreting
  schema 1.
- Decision: the closed readiness review makes `maxOutstanding` a physical
  subprobe/correlation ceiling, requires separate logical and wire IDs, reserves
  result rows and variable metadata bytes before transmission, preserves full
  ICMP family/type/code/origin detail through state policy, and freezes schema 2
  as additive columns plus a deterministic length-prefixed metadata record.
- Decision: Nmap commit `10dfd2ff1cef6c1925232db45352149b659979b4` is a frozen
  behavioral architecture baseline only. The MIT project will not copy,
  translate, generate from, vendor, parse, load, link, execute as a helper, or
  redistribute Nmap source or `nmap-service-probes`. Every implementation entry
  is authored from a primary specification, registry, permissively licensed
  documentation, or a permissioned project-owned capture. Direct reuse requires
  a separate compatible license or written permission.
- Decision: protocol-aware safe mode becomes the default for a payload-less UDP
  probe only after the safe pack passes Phase 29. Broadcast/multicast,
  amplification-prone, materially stateful, authentication-attempt,
  sensitive-read, and conflicting fixed-source behavior requires explicit risk
  consent independent of comprehensive/legacy breadth. Repository
  provenance/capability data remains primary-source-derived; reference mapping
  remains an owner-controlled non-distributed audit. Only Phase 33 may make a
  factual parity claim.
- Rationale: a generic token-prefixed datagram cannot form valid application-
  protocol requests and therefore overproduces `open|filtered` results. Native
  protocol programmes improve response elicitation without per-packet N-API
  crossings, while independent provenance preserves the project's license and
  distribution model. Logical aggregation retains bounded user-facing results
  even when several physical requests are necessary.
- Consequences: Phase 26 remains closed; this decision does not authorize an
  extreme backend. The Phase 27 preimplementation audit is closed in the UDP
  plan review. The material default/schema change targets an unpublished
  `0.2.0-rc.1` scanner candidate. Full Nmap service/version fingerprint parity
  remains a separate possible future scope. See `43-udp-probe-parity-plan.md`.

### D-041 — Phase 27 UDP compatibility and schema foundation

- Status: accepted on 2026-07-14
- Decision: Phase 27 keeps omitted UDP policy and the deprecated top-level
  `payload` spelling on the existing 16-byte correlation-token prefix path.
  Explicit `custom/tuple` sends caller bytes exactly, `custom/prefixToken`
  selects compatibility deliberately, and `empty` sends a zero-length payload. A
  plan still admits exactly one UDP definition. Native state now owns a
  per-family vector programme even though Phase 27 admission deliberately limits
  it to one request; Phase 28 owns live multi-variant scheduling.
- Decision: protocol policy normalizes to profile `safe`, intensity `7`,
  strategy `exhaustive`, fallback `unmapped`, and a canonical unique risk set
  when fields are omitted. The discriminants are frozen, but a Phase 27 start
  rejects protocol mode as unsupported and capability metadata reports
  `protocolModeAvailable: false`. This prevents a partially bounded live path
  and does not switch the omitted default before the Phase 29 safe pack.
- Decision: catalogue source is project-owned Rust data validated in stable ID
  order. Its first empty infrastructure catalogue is version `1.0.0`, SHA-256
  `39a4b724558d17b4f159a954a7acf1c68fd1c2ae5b215c2d306f8a05bac1647f`. The
  checker rejects unregistered builders/parsers, duplicate or unordered
  identifiers/ports, missing provenance, unsafe profile/risk/source-port
  combinations, unbounded responses, and oversized templates. No Nmap source,
  data, runtime, or build dependency was added.
- Decision: schema 2 is an additive retained-batch input contract while native
  sessions continue emitting schema 1. Schema 1 rejects schema-2-only columns;
  schema 2 requires all frozen UDP columns and validates numeric vocabularies,
  monotonic offsets, 1 KiB length-prefixed service records, UTF-8, stable extra
  field IDs, and transfer/detachment behavior. Native schema-2 emission remains
  a Phase 29 gate.
- Consequences: Phase 27 is complete. The production catalogue intentionally
  contains zero protocol variants, makes no parity claim, and does not authorize
  the Phase 29 safe pack. See `45-phase-27-report.md`.

### D-042 — Phase 28 physical UDP programme scheduling and settlement

- Status: accepted on 2026-07-14
- Decision: a UDP programme remains one logical target/port result and reserves
  one result row plus its maximum possible winning metadata before emission.
  Programmes execute lazily with unique physical wire IDs, no more than four
  active variants per endpoint, `maxOutstanding` charged to physical work, and
  every setup/probe/retry frame charged to the common token bucket. Aggregate
  UDP transmissions are checked `u32`; per-variant retry ordinals remain `u8`.
- Decision: active and grace physical probes retain collision-free session-local
  source-port lanes. Native routes remain owned by logical IDs while packet,
  token, and quote correlation use physical IDs. A lane cannot return until its
  finite engine grace expires; compatibility single-request scans retain their
  prior result timing and schema-1 output.
- Decision: direct UDP outranks target-originated port-unreachable, which
  outranks other recognized filtered ICMP evidence, which outranks silence.
  IPv4/IPv6 family, type, code, target origin, and quote strength survive
  receive normalization. Ties select the lowest stable catalogue ID/request
  index; contradictions saturate a bounded counter; unknown or insufficient
  evidence cannot change state. A logical result waits until every emitted
  variant that could alter it has left finite grace.
- Decision: native result admission enforces 16 MiB reserved metadata per
  session and 64 MiB across the Node environment. Phase 28 consumes no service
  metadata and native sessions continue emitting schema 1. Protocol mode may
  traverse the scheduler with exact empty fallback, but capability remains false
  while the production catalogue is empty; safe payloads, service parsing,
  schema-2 emission, and the omitted-policy default remain Phase 29.
- Consequences: Phase 28 is complete without importing Nmap data or adding
  protocol payload breadth. See `46-phase-28-report.md`.

### D-043 — Safe UDP pack, PCP addition, and protocol-session schema 2

- Status: accepted
- Date: 2026-07-14
- Decision: Catalogue `1.1.0` supplies nine safe, unicast, ephemeral-source
  probes: DNS root A with EDNS padding and a 512-byte ceiling, NTP client,
  SNMPv3 engine discovery, rpcbind v2 NULL, STUN Binding, CoAP Empty CON,
  ASF/RMCP presence, framed memcached `version`, and PCP ANNOUNCE. PCP ANNOUNCE
  is the Phase 29 addition because it requests no mapping and has a small
  bounded response. Omitted UDP policy selects safe exhaustive protocol mode
  with an unmapped empty fallback. Explicit empty/custom behavior remains.
  Protocol-mode sessions emit frozen batch schema 2; compatibility sessions
  remain schema 1, and both decode paths are retained.
- Rationale: Protocol-valid, transaction-correlated requests materially improve
  common UDP discovery without importing Nmap data or granting risk consent.
  Port eligibility is evaluated lazily so a protocol request is never sent to
  unrelated selected ports. Variable metadata remains Rust-owned, validated,
  capped at 1 KiB per result, and covered by session/environment reservations.
- Consequences: Direct tuple-correlated UDP still establishes `open` even when
  its body is malformed, but service family/confidence requires strict parser
  success. Phase 29 satisfies the accepted safe-core parity gate only; extended,
  comprehensive, adaptive, and final Nmap-behavior parity remain Phases 30–33.

### D-044 — Extended UDP standards pack and independent risk admission

- Status: accepted
- Date: 2026-07-14
- Decision: catalogue `1.2.0` adds comprehensive-profile NetBIOS node status,
  NFS v3 NULL, SIP OPTIONS, SSDP unicast M-SEARCH, L2TP SCCRQ, SNMPv1 public
  `sysDescr.0`, and memcached statistics. Profile breadth is evaluated before,
  and independently from, the canonical `allowRisks` set. NFS NULL has no
  additional risk flag; every other new entry requires its declared sensitive-
  read, high-amplification, stateful-handshake, or authentication-attempt
  consent. Supplying consent to `safe` never adds an extended probe.
- Decision: catalogue descriptors now freeze response and typed-parser byte
  ceilings, a conservative maximum amplification ratio, and a nonzero maximum
  state lifetime exactly when a probe is materially stateful. Native receive
  processing caps typed service parsing at 4 MiB per session and 256 KiB per
  target per runtime tick while retaining the existing 128-datagram work cap.
  Oversized or budget-exhausted direct datagrams may still prove UDP `open` by
  tuple, but cannot produce service identity.
- Decision: protocol-mode multicast or limited-broadcast targets require both
  explicit `multicastOrBroadcast` consent and an explicit interface; the scanner
  never expands targets. Fixed-source entries remain rejected until an
  operator-controlled host/namespace ownership contract exists. Stateful entries
  reject a configured maximum timeout above their declared lifetime.
- Decision: mDNS/DNS-SD is deferred because one multicast query can produce
  several unicast responders and cannot honestly fit the frozen target-address
  correlation/one-result model. TFTP is deferred until the alternate-port
  first-response pinning path has independent live proof. DHCP is deferred until
  fixed-source/broadcast ownership exists. IKE, DTLS, and QUIC are deferred
  pending exact-pinned cryptographic/dependency review; OpenVPN lacks an
  accepted independently stable discovery wire specification; RADIUS cannot be
  probed safely without shared-secret or authentication semantics.
- Rationale: seven one-datagram standards exchanges materially broaden useful
  UDP discovery while keeping the Phase 29 safe default byte-for-byte and
  preventing a broad profile name from acting as network-impact authorization.
  Deferral is safer and more interoperable than sending approximate handshake
  bytes or weakening response attribution.
- Consequences: Phase 30 is complete and Phase 31 may expand comprehensive and
  legacy breadth from catalogue `1.2.0`. Only Phase 33 may make the final frozen
  Nmap-behavior parity claim. See `48-phase-30-report.md`.

### D-045 — Comprehensive/legacy catalogue and executable capability ledger

- Status: accepted
- Date: 2026-07-14
- Decision: catalogue `1.3.0` preserves IDs 1–16 and adds 17 independently
  specified comprehensive/legacy variants across game, directory, device,
  industrial/building, peer-to-peer, remote-control, routing, and historical
  services. The safe profile remains exactly IDs 1–9. Every impact-bearing
  request remains gated by its exact amplification, stateful, authentication, or
  sensitive-read consent independently from profile selection.
- Decision: destination eligibility now supports checked inclusive port ranges
  without materializing every port. Repeated stable probe IDs are legal only on
  disjoint eligibility ranges; overlapping eligibility fails plan construction.
  This permits protocol-owner conventional ranges while retaining deterministic
  catalogue order and one matching variant per endpoint.
- Decision: simple response identification may use the project-owned finite
  byte-signature engine. A signature has at most 32 exact, prefix, masked-byte,
  or capped ASCII-extraction clauses and at most 65,527 bytes of declared work.
  It has no regex, recursion, backtracking, substitution, callback, or partial-
  result behavior. Structured and transaction-bearing protocols retain typed
  parsers.
- Decision: the shippable 46-entry project capability ledger covers all 33
  catalogue IDs exactly once and records 13 explicit blockers. Validation fails
  on duplicate project IDs, unknown, duplicate, or uncovered probes, empty
  evidence, and implemented blocked entries. The ledger contains no external
  comparison mappings. mDNS/DNS-SD, TFTP, DHCP, IKE, DTLS, QUIC, OpenVPN,
  RADIUS, CLDAP, SQL Browser, Ubiquiti discovery, pcAnywhere, and WireGuard
  handshake behavior remain blocked for the recorded ownership, specification,
  authentication, or protocol-model reasons.
- Rationale: broad service discovery is useful only when every emitted request
  has independent provenance, bounded parsing, explicit impact, and an honest
  unsupported disposition. Static signatures cover finite simple banners without
  introducing a regex dependency or an unbounded packet-path engine.
- Consequences: Phase 31 is complete, but makes no Nmap parity claim. Phase 32
  may implement evidence-driven adaptive selection; only Phase 33 may report an
  aggregate comparison after the separate owner-controlled audit. See
  `49-phase-31-report.md`.

### D-046 — Evidence-bounded adaptive UDP and public schema-2 views

- Status: accepted
- Date: 2026-07-14
- Decision: `exhaustive` remains the compatibility default. Opt-in `adaptive`
  schedules at most one physical variant per logical UDP endpoint, preserving
  immutable catalogue order: mapped likely request, eligible alternatives, then
  the selected exact-empty fallback. Direct UDP and target-originated port-
  unreachable evidence stop unsent adaptive variants. Correlations already
  emitted remain alive through bounded late grace.
- Decision: a soft service-family hint can only skip incompatible adaptive
  follow-ups. It never enters the network-state lattice, service result, or
  product metadata. Missing ICMP remains silence. Correlated ICMP followed by
  silence may add a bounded per-host cooldown, recorded in diagnostics, without
  strengthening the result.
- Decision: terminal summaries freeze the normalized UDP mode, profile,
  intensity, strategy, fallback, exact risk-consent set, custom correlation, and
  catalogue version/hash. `logicalProbes` is logical work and `progress.sent` is
  physical frames. Lazy schema-2 rows expose stable response-kind, service-
  confidence, catalogue-probe, variant-count, family, and bounded decoded
  product/version/field views; schema-1 decoding is unchanged.
- Decision: catalogue versions follow semantic versioning. Removing or
  reinterpreting an existing ID requires a major version; additive reviewed
  variants are minor; compatible fixes are patch. The SHA-256 identity remains
  authoritative. The optional declarative custom signature API is not admitted:
  exact native custom payloads already remain available, while exposing the
  signature DSL would add public attack surface without Phase 32 evidence.
- Rationale: sequential evidence boundaries are what let adaptive mode reduce
  traffic honestly. Parser guesses, silence, or discarded late correlations
  would trade correctness for speed and violate the scanner's evidence model.
- Consequences: Phase 32 is complete. Exhaustive and explicit empty/custom
  behavior remain compatible; Phase 33 owns the final external parity and
  release audit. See `50-phase-32-report.md`.

### D-047 — Narrow UDP elicitation parity claim and `0.2.0-rc.1`

- Status: accepted
- Date: 2026-07-14
- Decision: advance the unpublished scanner, native addon, and target manifests
  together to `0.2.0-rc.1`. Protocol mode emits result schema 2 while the
  decoder continues accepting schemas 1 and 2. Catalogue `1.3.0`, its hash, 33
  implemented variants, nine safe variants, default safe/exhaustive policy, and
  13 blocked capability entries are part of the release policy.
- Decision: the only external comparison statement accepted for this candidate
  is that, on the owner-controlled IPv4/IPv6 responder matrix, independently
  authored requests matched or exceeded frozen Nmap commit
  `10dfd2ff1cef6c1925232db45352149b659979b4` in protocol-class response
  elicitation and definitive UDP port-state evidence. Do not call the package
  Nmap-compatible or claim full probe-database, service/version, product, OS, or
  fingerprint parity.
- Decision: external comparison mechanics and detailed output remain
  non-distributed. Shippable catalogue/ledger validators require HTTPS primary
  provenance and reject any external-comparison marker. Only aggregate counts
  and project-owned evidence may appear in the completion report.
- Rationale: the accepted responder result is useful and reproducible, but the
  13 explicit blockers and deliberately smaller typed service-evidence model
  make a broad compatibility claim false. Version `0.2.0-rc.1` honestly marks
  the protocol-aware default behavior and schema-2 feature boundary.
- Consequences: Phase 33 implementation and every available x86-64 release gate
  are complete. Native AArch64 execution remains mandatory before AArch64 or
  package-wide publication. See `51-phase-33-report.md`.

### D-048 — Phases 27–33 parser-hardening audit

- Status: accepted
- Date: 2026-07-14
- Decision: retain catalogue `1.3.0`, result schema 2, the public UDP policy,
  stable probe IDs, and scanner `0.2.0-rc.1`, while correcting receive-side
  structural validation for SNMPv3, RPC/NFS, BitTorrent DHT, NTP control, SLP,
  XDMCP, BACnet, EtherNet/IP, and KNXnet/IP. A typed service identity now
  requires the complete supported message structure and exact message end.
- Rationale: the request catalogue and public contracts were correct, but
  marker-based or skeletal parsing could accept malformed datagrams, and the NTP
  control parser required an incomplete fragment. Tightening response validation
  is a compatible release-candidate bug fix; changing catalogue IDs or schema
  would misrepresent an unchanged transmit and result contract.
- Consequences: all locally available ordinary, privileged, stress, fuzz,
  sanitizer, x86-64 artifact/consumer/reproducibility, and AArch64 cross-check
  gates pass again. Native AArch64 execution remains the only publication gate.
  See `52-phase-27-33-implementation-audit.md`.

### D-049 — Separate bounded discovery architecture and advanced UDP evolution

- Status: accepted; readiness conditions closed by D-050
- Date: 2026-07-14
- Decision: implement Phases 34–44 as the next scanner evolution. Link-scoped
  one-query/many-responder protocols use a separate finite discovery plan,
  session, summary, and discovery result schema rather than a magic target or a
  reinterpretation of the existing scan schema. Discovery shares the native
  environment runtime, immutable network context, pull-batch style, and
  lifecycle conventions, but owns independent bounded correlation, aggregation,
  and result state.
- Decision: add evidence-derived endpoints only through a registered bounded
  parent/child graph that revalidates the original target allowlist and
  exclusions, defaults to same-address/different-port edges, rate-charges and
  reserves every child, suppresses cycles, and records provenance. Add alternate
  response ports only through registered protocol state machines that pin the
  first structurally valid same-target/interface response; do not expose a
  general loose-port matcher.
- Decision: sequence mDNS/DNS-SD, WS-Discovery/LLMNR, adaptive rpcbind, TFTP,
  NAT-PMP/SQL Browser/configured Kerberos, QUIC Version Negotiation, reviewed
  IKE/DTLS, DHCP topology discovery, and optional specialized GTP/MQTT-SN/
  industrial packs behind their prerequisite architecture. Each candidate may
  remain blocked or record no-go rather than approximate a malformed request.
- Decision: retain the current `UdpProbeRisk` vocabulary and independent native
  risk enforcement. Interface and family scope are explicit; omitted options do
  not authorize all interfaces, multicast/broadcast, fixed-source behavior,
  sensitive reads, authentication attempts, amplification, or stateful
  handshakes. Built-ins remain non-mutating and never complete authentication,
  create a lease/mapping/tunnel, transfer a file, or use a real operator
  identity by default.
- Decision: existing scan result schemas 1 and 2 and catalogue `1.3.0` retain
  their meaning. Discovery batches begin with a separate schema 1. Any scan
  parent/child columns require an additive schema 3 with retained schema-1/2
  decoding. Only the final integrated Phase 44 may prepare unpublished
  `0.3.0-rc.1`, after native x86-64 and AArch64 execution and all release gates.
- Rationale: the highest-value remaining UDP discovery protocols have fan-out,
  dynamic-port, alternate-endpoint, or handshake semantics that cannot be
  represented honestly by one terminal `(target, port)` result. Separate,
  bounded execution models improve real discovery while preserving correlation,
  resource accounting, compatibility, and conservative evidence claims.
- Consequences: D-050 and `54-advanced-udp-discovery-plan-review.md` close the
  preimplementation conditions. Phase 26 remains closed, the Phase 33 Nmap
  comparison wording is not broadened, and `nodenetraw` remains a low-level
  policy-free package.

### D-050 — Phase 34 discovery-foundation readiness

- Status: accepted
- Date: 2026-07-14
- Decision: approve Phase 34 as the next implementation phase after correcting
  the Phase 34–44 plan to match the existing already-running session lifecycle,
  reserve the configured fan-out result pool before the first query, share the
  existing four-session and 64 MiB environment ceilings, and define a separate
  discovery registry/schema with deterministic byte identity and conflict
  behavior. Freeze explicit link and targeted discovery scopes so dynamic-input
  multi-entity operations do not overload scan schema 2.
- Decision: make discovery transport operation-driven and lazy. Ordinary
  UDP-only discovery opens no raw/packet descriptor and requires no
  `CAP_NET_RAW`; every privileged descriptor or fixed-source requirement is
  declared and admitted independently. Multicast receive owns exact Linux group,
  port-coexistence, packet-info, hop-limit, namespace, demultiplexing, and
  cleanup contracts.
- Decision: treat advertised endpoints as untrusted metadata unless Phase 37's
  separately bounded same-target derivation graph authorizes child work. Freeze
  explicit mDNS legacy/full-browse modes, safe streaming XML dependency gates,
  TFTP positive-response cleanup/no-retry behavior, unauthenticated QUIC
  evidence, and minimum-identity DHCP correlation/coexistence gates.
- Rationale: the original direction was sound, but implementation would have
  been ambiguous at exactly the boundaries where fan-out can multiply memory,
  descriptor privilege, result identity, remote protocol state, and caller
  authority. The corrected contracts are compatible with the implemented scanner
  and make those costs finite and observable before network work.
- Consequences: Phase 34 may begin and emits no live discovery protocol. It must
  first freeze the exact types, numeric vocabularies, defaults, constants,
  registry version, transport traits, and lifecycle/reservation matrices. Phase
  35 remains blocked until the Phase 34 report proves its synthetic engine and
  isolated native transport exit gates. See
  `54-advanced-udp-discovery-plan-review.md`.

### D-051 — Ship bounded ordinary-UDP discovery operations and record unsupported families as no-go

- Date: 2026-07-14
- Status: accepted
- Decision: add registry `1.0.0` and discovery schema 1 with legacy-unicast
  mDNS/DNS-SD, WS-Discovery, explicit-name LLMNR, NAT-PMP external-address, SQL
  Browser, rpcbind GETADDR evidence, TFTP sentinel discovery, and QUIC Version
  Negotiation. Use ordinary nonblocking UDP and shared scan/discovery
  session/metadata admission. Retain fixed-port mDNS browse, Kerberos, IKE,
  DTLS, host-namespace DHCP, and specialized Phase 43 candidates as explicit
  no-go outcomes. Do not advance the release version while rpcbind child
  execution, the new namespace matrix, or native AArch64 execution remains.
- Rationale: these eight operations have independently owned bounded codecs and
  useful non-mutating evidence. The no-go families did not close their
  coexistence, identity, cryptographic dependency, or authoritative fixture
  gates, and malformed approximations would weaken the project.
- Consequences: `DISCOVERY_CAPABILITIES` exposes exact implemented operations,
  ceilings, risks, registry identity, and no-go families. Rpcbind child work is
  a single typed same-target NFSv3 NULL exchange, can be disabled per operation,
  and carries parent/derivation identity in discovery schema 1. Phase 44's
  external release gates remain open as recorded in report 55.

### D-052 — Evidence-driven active, passive, topology, and longitudinal discovery

- Status: accepted planning direction; Phase 45 readiness review required
- Date: 2026-07-15
- Decision: evolve `@opsimathically/nodenetscanner` through Phases 45–58 around
  one additive provenance-preserving evidence model and one re-authorized
  derived-work policy. Add separate finite metadata-only passive observation,
  link/IPv6 topology and path discovery, a bounded ordinary-TCP conversation
  engine and independently risked service packs, governed cross-protocol
  enrichment, explainable asset reconciliation, longitudinal/local context,
  optional specialized packs, and transport-neutral multi-vantage evidence. Keep
  one native scanner addon with modular internal Rust crates/registries and
  distinct session/result schemas. Retain existing scan schemas 1/2, UDP
  catalogue `1.3.0`, discovery schema 1, and discovery registry `1.0.0`.
- Rationale: the scanner already has broad active UDP and finite discovery
  coverage. Its largest remaining blind spots are silent devices observable only
  through ambient traffic, application identity behind open TCP ports, routers
  and paths, disconnected evidence that could safely authorize narrow
  follow-ups, identity/change over time, and links outside one broadcast domain.
  A common evidence and authority foundation prevents those features from
  becoming unrelated one-off probes or an uncontrolled crawler.
- Consequences: Phase 45 is the only next implementation phase and transmits no
  traffic. Passive capture defaults to non-promiscuous typed metadata and never
  claims completeness. Received URLs, DNS data, ports, names, routes, and
  identities never grant authority. Authentication attempts, credentials,
  configuration changes, vulnerability payloads, general packet recording,
  mandatory persistence, and a built-in remote sensor server remain out of
  scope. Applications own sensor transport security and authorization. Every
  optional protocol/provider can independently record no-go. The still-open
  Phase 44 native AArch64 and release-hardening gates remain mandatory. See
  `57-network-discovery-coverage-plan.md`.

### D-053 — Structured evidence origins and re-authorized derived work

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: evidence schema 1 identifies a source record by source kind, source
  schema, bounded opaque run ID, and run-local record ID. It retains immutable
  typed entity/field/relation evidence, monotonic observation/expiry, optional
  wall context, confidence, and disposition under the Phase 45 bounds. Exact
  duplicates coalesce and conflicts remain; device merging is deferred to
  Phase 54. Generalized derived work is admitted only through a stable
  registered derivation/operation pair that rechecks same-address target scope,
  exclusions, risk consent, depth, fan-out, duplicates, and capacity before I/O.
- Rationale: current scan rows and discovery entity IDs are intentionally
  run-local, and correlation strength does not grant network authority.
  Structured origins avoid collision-prone hashes while preserving source
  provenance; separating evidence retention from asset merging prevents weak
  names or shared traits from becoming false identity.
- Consequences: current scan/discovery schemas and rpcbind behavior remain
  compatible. Phase 45 adds no I/O or dependency. Authentication attempts and
  target mutation are not admissible derived risks. Phase 46 and later producers
  must emit schema-1 evidence or an explicitly versioned successor and share the
  same lifetime limits. See `58-network-discovery-coverage-plan-review.md` and
  `59-phase-45-report.md`.

### D-054 — Finite filtered observation descriptors and honest partial phase status

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: Phase 46 uses at most four per-session AF_PACKET descriptors over
  explicit interfaces, within the combined four-session environment ceiling.
  Every descriptor is bound, nonblocking/CLOEXEC, classic-BPF filtered, and
  userspace guarded. Capture defaults to incoming, non-promiscuous metadata;
  promiscuous membership is independent consent. Later roadmap phases record
  foundation, no-go, and live-exit status separately.
- Rationale: the finite descriptor design has a hard 16-descriptor environment
  maximum and avoids adding an uncontrolled capture hub before measured demand.
  Keeping phase status exact prevents a codec or policy validator from being
  mistaken for a live path/TCP/enrichment engine.
- Consequences: one interface can have up to four capture descriptors under
  maximum concurrent sessions. This ceiling must be included in fd/RSS stress. A
  future shared hub requires a measured replacement decision. Native AArch64
  remains open; the unpublished version does not advance.

### D-055 — Admit bounded live discovery slices and retain independent no-go candidates

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: complete Phases 47–57 with append-only passive lifetime semantics,
  explicit Router Solicitation, dedicated bounded native path and ordinary-TCP
  workers, credential-free service conversations, semantic DNS-SD enrichment,
  scoped strong-identifier reconciliation, bounded inventory, and hostile sensor
  fusion. Admit SSH/FTP/SMTP/POP3/IMAP/MySQL greetings, HTTP HEAD, PostgreSQL
  SSLRequest, and Redis PING. Retain TLS, SMB, RDP, MongoDB, LDAP, active
  description crawling, optional host providers, and specialized candidates as
  executable no-go entries until their independent gates close.
- Rationale: each admitted operation has canonical internally generated bytes,
  finite parser/network work, explicit risk, project-owned tests, prompt
  cancellation, and no authentication. A native worker avoids event-loop and
  libuv-worker blocking while exact shared admission bounds concurrency.
  Network-scoped strong identifiers and re-provenanced sensor data prevent
  cross-site identity corruption.
- Consequences: `tracePath`, `identifyService`, and `solicitRouters` are public
  finite operations. Service results are syntactic unauthenticated evidence, not
  identity proof. Optional no-go entries do not imply partial support. Phase 58
  passes all locally available x86-64, namespace, fuzz, stress, artifact,
  clean-consumer, and reproducibility gates; native AArch64 execution remains
  mandatory before publication.

### D-056 — Reopen and harden the Phase 46–57 implementation contracts

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: retain the admitted Phase 46–57 feature scope while repairing
  passive parser strictness, evidence lifetime/identity semantics, sensor
  interchange bounds and provenance, owned-thread cancellation, randomized path
  correlation, incremental service parsing, and native/TypeScript registry
  parity. Add bounded path pacing and optional sensor capability/visibility
  context because both were already required by the accepted phase contracts.
- Rationale: the second adversarial review found several cases where a valid
  outer envelope could lend meaning to malformed inner traffic, stale evidence
  could influence current assets, imported provenance could collide, or two
  public registry sources could drift. These are correctness and trust-boundary
  defects, not reasons to broaden protocol scope.
- Consequences: report 61 supersedes report 60 on repaired implementation
  details. Phase 56 no-go outcomes, transport-neutral sensor ownership, and the
  native AArch64 publication gate remain unchanged.

### D-057 — Expand UDP coverage through gated protocol families, not payload count

- Status: accepted and implemented by D-058
- Date: 2026-07-15
- Decision: sequence Phases 59–69 around a checked multidimensional coverage
  matrix and append-only candidate-admission harness, then address RMCP/IPMI and
  remote management, enterprise databases, routing/industrial discovery, game
  and master servers, voice/media, additional DHTs, sensitive legacy enterprise
  protocols, and a current-source review of cryptographic/authentication
  blockers. Keep threat/backdoor active signatures in a distinct enforced
  exclusion boundary. Continue independently authoring requests, parsers,
  fixtures, and responders from primary sources; use pinned Nmap source only for
  human-reviewed black-box behavioral comparison.
- Rationale: the present catalogue provides broad protocol-aware UDP discovery
  but lacks several high-value infrastructure and legacy families found in Nmap.
  Simply copying magic payloads would weaken licensing provenance, correlation,
  safety, typed evidence, and support honesty. Ordering reusable
  admission/accounting architecture before protocols and higher-risk stateful
  families after safer infrastructure work expands real coverage without
  converting the scanner into an unbounded crawler, authenticator, or malware
  scanner.
- Consequences: Phase 59 was the only next implementation phase and added no
  wire traffic. Existing catalogue/discovery IDs and default behavior remain
  stable. Every candidate may independently finish as no-go when a stable
  primary contract, non-mutating request, useful typed response, safe
  resource/impact envelope, or project responder is unavailable. Returned
  endpoints and routes remain evidence rather than authority. Request,
  correlation, typed parsing, live responder, fingerprint, and policy dimensions
  must be reported separately. Native AArch64 and inherited release gates remain
  mandatory. See `62-udp-probe-coverage-expansion-plan.md`. D-058 records the
  final admission and implementation results.

### D-058 — Close UDP coverage candidates through evidence-gated admission

- Status: accepted; implementation corrected and superseded by D-059
- Date: 2026-07-15
- Decision: release additive catalogue `1.4.0` with exact probes 34–37 for
  RIPv1, Quake II, challenge-correlated Quake III, and timestamp-correlated
  Mumble; credit existing ASF/RMCP probe 7; and freeze coverage registry `1.0.0`
  with 5 implemented, 32 no-go, and 4 threat-excluded candidates. Keep all new
  probes out of the safe profile and expose the registry through native-owned,
  TypeScript-validated immutable capabilities.
- Rationale: these five families satisfy the primary-contract, correlation,
  typed-evidence, bounded-parser, policy, and project-responder gates. Every
  other candidate either lacks a stable independent contract/responder, crosses
  authentication or mutation boundaries, cannot justify network participation,
  or is an active threat signature.
- Consequences: IDs 1–33 and safe defaults remain stable; no-go and excluded
  rows cannot schedule work; public claims report separate evidence dimensions.
  All available x86-64 and namespace gates pass, but native AArch64 execution
  remains mandatory before publication. See
  `64-phases-59-69-implementation-report.md`.

### D-059 — Repair UDP coverage claims through executable implementation joins

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: retain all catalogue IDs and candidate dispositions while releasing
  corrective catalogue `1.4.1`, discovery registry `1.1.0`, and coverage
  registry `1.1.0`. Credit RIPv1 route discovery to new discovery operation 10;
  retain probe 34 only as a single-reply compatibility probe. Cross-validate
  implemented coverage rows against actual descriptor resources, parsers, risks,
  and project responders, and export exact runtime `requiredConsents`.
- Rationale: adversarial review 65 demonstrated that structurally present IDs
  and self-declared dimension bits did not prove multi-datagram topology,
  authoritative protocol envelopes, correlation parity, or enforceable resource
  and consent claims. The corrective versions make those relationships
  executable without broadening network behavior or changing safe defaults.
- Consequences: RIPv1 discovery is finite at one request, ten response
  datagrams, 5,040 response bytes, 250 routes, and 3,000 ms per target. Quake II
  and III use family-specific authoritative bounds; Quake III and Mumble publish
  64-bit transaction strength. Provenance checks exact shipped data, owned
  fixtures, and staged artifacts. All available x86-64, namespace, fuzz,
  sanitizer, Miri, stress, artifact, consumer, and reproducibility gates pass.
  Native AArch64 execution remains mandatory before publication. See
  `66-phases-59-69-adversarial-repair-report.md`.

### D-060 — Fail closed across release identity and fatal native ownership boundaries

- Status: accepted and implemented
- Date: 2026-07-15
- Decision: stage releases only from a clean, verified Git `HEAD`; exchange
  TPACKET block ownership with acquire/release atomics; settle every
  discoverable queued or registered reactor operation before discarding
  completion sinks; and make high-level observation ID removal the single
  close-ownership decision.
- Rationale: unchecked provenance, compiler-only packet-ring ordering, and
  teardown paths that discard completion or handle ownership can produce output
  that appears valid while no longer corresponding to its source or caller
  lifecycle. These boundaries must fail visibly and deterministically.
- Consequences: maintainers must commit or intentionally discard changes before
  release assembly. Reactor terminal failures reject admitted work under its
  original operation, observation close races cannot double-close an ID, and
  privileged raw gates run in scheduled and release CI. Native AArch64 execution
  remains a separate mandatory publication gate. See
  `67-project-wide-adversarial-repair-report.md`.

## Research references

Compatibility facts were verified on 2026-07-12 against primary project
documentation:

- [Node.js 26 release announcement](https://nodejs.org/en/blog/release/v26.0.0)
  and
  [release schedule](https://nodejs.org/en/blog/announcements/evolving-the-nodejs-release-schedule)
- [Node-API version matrix](https://nodejs.org/api/n-api.html)
- [Node.js supported Linux platforms](https://github.com/nodejs/node/blob/main/BUILDING.md)
- [Node.js ESM and CommonJS interoperability](https://nodejs.org/api/modules.html)
- [Node.js EventEmitter semantics](https://nodejs.org/api/events.html), checked
  again for D-028 on 2026-07-13
- [Rust latest stable release](https://blog.rust-lang.org/releases/latest/)
- [napi-rs v3 setup and compatibility](https://napi.rs/docs/introduction/getting-started)
- [napi-rs native package distribution](https://napi.rs/docs/deep-dive/release)
- [Linux raw IPv4 sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Linux IPv6 sockets](https://man7.org/linux/man-pages/man7/ipv6.7.html)
- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Linux message receive and error queues](https://man7.org/linux/man-pages/man2/recvmsg.2.html)
- [Linux socket options and filters](https://man7.org/linux/man-pages/man7/socket.7.html)
- [Linux kernel timestamping](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
- [Linux kernel Packet MMAP](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html)
- Linux kernel route and neighbor netlink specifications,
  [route](https://www.kernel.org/doc/html/next/networking/netlink_spec/rt-route.html)
  and
  [neighbor](https://kernel.org/doc/html/latest/netlink/specs/rt-neigh.html),
  plus [AF_XDP](https://docs.kernel.org/networking/af_xdp.html), checked for
  D-031 on 2026-07-13
- [Nmap port-scanning algorithms](https://nmap.org/book/port-scanning-algorithms.html)
  and Masscan's official
  [design description](https://github.com/robertdavidgraham/masscan#design),
  checked for D-031 on 2026-07-13
- [nix 0.31.3 socket APIs](https://docs.rs/nix/0.31.3/nix/sys/socket/)
- [IANA ICMP Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml),
  [RFC 792 ICMPv4](https://www.rfc-editor.org/rfc/rfc792.html),
  [RFC 1071 Internet checksum](https://www.rfc-editor.org/rfc/rfc1071.html),
  [RFC 1122 host requirements](https://www.rfc-editor.org/rfc/rfc1122.html),
  [RFC 1191 Path MTU Discovery](https://www.rfc-editor.org/rfc/rfc1191.html),
  [RFC 1256 Router Discovery](https://www.rfc-editor.org/rfc/rfc1256.html),
  [RFC 4884 multi-part ICMP](https://www.rfc-editor.org/rfc/rfc4884.html),
  [RFC 950 subnetting](https://www.rfc-editor.org/rfc/rfc950.html), and
  [RFC 6918 legacy ICMP deprecation](https://www.rfc-editor.org/rfc/rfc6918.html),
  checked for D-029 on 2026-07-13

## Decision template

```markdown
### D-NNN — Title

- Status: accepted | superseded
- Date: YYYY-MM-DD
- Decision: ...
- Rationale: ...
- Consequences: ...
- Supersedes/Superseded by: ... (when applicable)
```
