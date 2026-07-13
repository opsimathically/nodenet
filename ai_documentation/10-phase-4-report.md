# Phase 4 completion report

Completed: 2026-07-12

## Delivered API

The IPv4 `RawSocket` surface now adds:

- `bind(address)` and `localAddress()` for local IPv4 address binding;
- generic `getOption()` and `setOption()` signatures backed by a closed typed
  option-name map;
- boolean `broadcast` and numeric `ipTtl`, `ipTypeOfService`,
  `receiveBufferSize`, and `sendBufferSize` options;
- `packetLength` on every receive, preserving the original datagram length when
  the requested capture buffer truncates it;
- optional parsed IPv4 destination, protocol, TTL, TOS, header length, total
  length, identification, fragment offset, and fragmentation flags.

The option layer has no arbitrary level/name/value escape hatch. TTL is limited
to 1 through 255, TOS to 0 through 255, broadcast to a boolean, and requested
kernel buffers to 1 through 16 MiB. Linux may clamp or double buffer requests;
the getters intentionally report effective values.

## Safety and ordering

All new syscalls are safe rustix calls. Bind and option commands are admitted to
the Phase 3 bounded reactor, own operation leases, and settle through the same
environment-specific completion channel. This preserves FIFO admission and fd
reuse protection without blocking the Node event loop.

The command dispatcher now checks socket lifecycle again immediately before a
syscall. A command admitted before close but not yet executed is rejected with
`ERR_SOCKET_CLOSED`, closing a small Phase 3 race window.

IPv4 parsing operates on Rust-owned initialized bytes. It requires a complete
minimum header, IPv4 version, valid IHL, and a total length no smaller than the
header. Incomplete captures return `ipv4: undefined`; no uninitialized or
out-of-range bytes are read. `MSG_TRUNC` supplies `packetLength` independently
of captured Buffer length.

No project-owned unsafe Rust or new dependency was added.

## Explicit deferrals

Binding a local IPv4 address provides address-based interface selection.
Device-name `SO_BINDTODEVICE`, `IP_PKTINFO` ancillary messages, `IP_HDRINCL`,
and arbitrary `setsockopt` access are not part of this phase. rustix 1.1.4 lacks
the necessary safe wrappers for several of these, and adding manual FFI or a
second native dependency requires a separate safety and dependency review.

That later review is now recorded as D-016: Phase 5 will use narrowly featured,
exact-pinned nix for safe message/cmsg/device-binding support. `IP_HDRINCL` and
generic socket-option bytes remain deferred to the advanced configuration phase.

## Verification record

On x86-64 glibc Linux with Node 26.4.0 and Rust 1.97.0:

- `npm run ci` passed formatting, lint, strict TypeScript, rustfmt, strict
  Clippy, 24 Rust tests, builds, and 5 ordinary Node tests;
- 3 isolated user/network namespace tests passed for bind and all five options,
  ICMP send/receive metadata, queue cancellation, and deliberately truncated
  capture length;
- `npm run build:native:release`, `npm pack --dry-run`, and `git diff --check`
  passed.

The three capability-dependent tests remain visibly skipped by ordinary
`npm test`. Successful AArch64 execution remains required before publishing
prebuilt artifacts.
