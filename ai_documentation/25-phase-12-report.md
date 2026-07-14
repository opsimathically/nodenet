# Phase 12 completion report

Status: complete on x86-64; AArch64 remains untested

Date: 2026-07-13

## Outcome

Phase 12 adds the zero-runtime-dependency ICMPv4 foundation and Echo slice over
the existing raw-socket promise and event APIs. The unpublished package
candidate advances to `0.1.0-rc.3`. No package was published.

All protocol work is strict TypeScript. Rust, the native ABI, descriptor
ownership, reactor behavior, and production dependency count are unchanged.

## Delivered public surface

- Linux-compatible named ICMPv4 type and registered code constants for the
  accepted Phase 12–14 message families.
- `computeInternetChecksum()` and `validateInternetChecksum()` over one owned,
  bounded snapshot with RFC 1071 odd-octet and carry-folding behavior.
- Discriminated Echo Request/Reply construction types and `encodeIcmpMessage()`
  with canonical code/reserved/checksum fields.
- `parseIcmpMessage()` and `validateIcmpMessage()` with structured hostile-input
  failures, compatible/canonical validation issues, explicit
  require/report/ignore checksum policy, and owned unknown message/code bytes.
- `parseIcmpReceivedMessage()` for Linux IPv4 raw receives, including checked
  IPv4 header boundaries/checksum, fragmentation, total/captured length,
  truncation, source, and native metadata cross-validation.
- `sendIcmpMessage()` and `receiveIcmpMessage()` as exactly one existing
  `sendMessage()`/`receiveMessage()` operation, with per-message IPv4 TTL and no
  hidden retries, filtering, receive engine, or queue.
- `matchesIcmpEchoReply()` for complete, checksum-valid replies with explicit
  identifier, sequence, optional source/destination, and complete token-prefix
  evidence.
- A readonly `RawSocket.protocol` getter backed by the checked value captured
  during socket open. ICMP helpers authenticate sockets through the existing
  private registry and reject non-IPv4/non-ICMP sockets before I/O.

## Safety and ownership

- Standalone ICMPv4 messages are capped at 65,515 bytes; checksum input is
  capped at 65,535 bytes. Every fixed field is length-checked before access.
- Parser inputs are snapshotted once. Encoded output, Echo payloads, and unknown
  bodies are owned copies and cannot alias mutable caller storage.
- Arbitrary byte input produces a bounded discriminated result. Local runtime
  misuse retains the stable `RawSocketError` argument shape; hostile getters or
  unexpected exceptions are normalized at the public boundary.
- Incomplete captures and initial fragments with more fragments never claim a
  valid full-message checksum. Non-initial fragments fail structurally.
- Outer IPv4 bytes and native metadata are treated as two untrusted
  representations and must agree; neither silently overrides the other.
- Socket helpers reuse existing cancellation, close, queue, lane, and Linux
  error behavior. Event consumers call the public received-message parser in
  their existing synchronous listener.

## Tests added

- Independent checksum and Echo golden packets.
- Empty, odd, even, maximum, overflow, mutation, and ownership boundaries.
- Checksum-policy and compatible/canonical differential cases.
- Exhaustive lengths below the Echo fixed header plus 2,000 deterministic
  arbitrary-byte parser cases.
- IPv4 raw-frame metadata, header-checksum, truncation, and correlation cases.
- Runtime malformed values and TypeScript discriminant/narrowing fixtures.
- A genuine privileged loopback test covering `sendIcmpMessage()`, two explicit
  one-shot receives, reply correlation, and event-driven composition through
  `RawSocketEventEmitter` plus `parseIcmpReceivedMessage()`.

## Verification record

Passed in this workspace on x86-64 Linux with Node 26 and Rust 1.97.0:

- `npm run ci`: formatting, ESLint, strict TypeScript, Rust formatting, Clippy,
  38 Rust tests, build, declaration fixtures, ordinary Node tests, and hardening
  verification passed; 58 Node tests were discovered, with 46 ordinary tests
  passing and 12 privilege-gated tests visibly skipped.
- Disposable Node 26 container network namespace with `CAP_NET_ADMIN` and the
  standard container capability set including `CAP_NET_RAW`: all 12 privileged
  tests passed, including Phase 12 promise/event loopback. The host network
  namespace was not modified.
- Phase 9 stress: 256 cycles, descriptors 21 before/after, RSS delta 1,376,256
  bytes.
- Phase 11 event stress: 256 sockets, 256 same-turn cycles, and 1,024 lifecycle
  cycles, descriptors 21 before/after, RSS delta 8,286,208 bytes.
- `npm run release:consumer-test`: optimized assembly, scripts-disabled staged
  installation, ESM, synchronous `require(esm)`, and export boundaries passed.
- `npm run release:verify-artifact`: x86-64 ELF and glibc ceiling passed; the
  highest required glibc symbol version is 2.16.
- `npm pack --dry-run`: the root package contained the expected 22 files.
- `npm run release:reproducibility`: two clean optimized builds matched SHA-256
  `430d1a5dd05d4d9c7a3e7d276ee68698d0d8e4c5eaa5f2b86faf0fb2885e06a6`.

The host-facing `sudo npm run test:privileged` wrapper could not receive a
password from the non-interactive agent terminal, so the same built package and
test file were executed as root in the disposable container namespace. The
normal `sudo` command remains the documented operator path. AArch64 remains
explicitly untested until native execution is available.

## Remaining work

Phase 13 is next: bounded quoted-IPv4 parsing, Destination Unreachable and
Fragmentation Needed, Time Exceeded, Parameter Problem, Redirect, and RFC 4884
extension framing. Phase 12 does not silently decode those messages as their
future known variants; safe bytes remain available through the unknown packet
model.
