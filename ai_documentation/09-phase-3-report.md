# Phase 3 completion report

Completed: 2026-07-12

## Delivered public slice

The package now exports an owned `RawSocket` for Linux IPv4 raw IP sockets:

- `RawSocket.open({ protocol })` creates `AF_INET`/`SOCK_RAW` with atomic
  nonblocking and close-on-exec flags;
- `send(data, destination)` asynchronously sends one owned byte copy to a
  dotted-decimal IPv4 address;
- `receive(maxLength?)` asynchronously returns a Buffer, source IPv4 address,
  and explicit truncation flag;
- `status` exposes `open`, `closing`, or `closed`;
- `close()` is asynchronous, idempotent, cancels pending work, and resolves
  after deregistration and descriptor release;
- `RawSocketError` exposes stable kind, code, operation, errno, and errno-name
  context.

The supported protocol and packet length range is 1 through 255 and 1 through
65,535 bytes respectively. Both TypeScript and Rust validate untrusted boundary
values. Raw socket creation normally requires `CAP_NET_RAW` in the governing
user namespace; the package never attempts to acquire privileges.

## Reactor and ownership invariants

Each Node-API environment owns one Rust thread running nonblocking
`epoll`/`eventfd` coordination. Main and Worker environments do not share
reactor state. The event-loop thread only validates, copies outbound input, and
submits bounded commands; it never waits for socket readiness.

Admission limits are:

- 64 sockets and 128 total pending operations per Node environment;
- 16 pending sends and 16 pending receives per socket;
- 256 commands in the native reactor queue;
- 64 completions in the N-API thread-safe-function queue.

Level-triggered interest is enabled only while a direction has pending work.
Every queued or active operation owns an `OperationLease`, and epoll
registration owns a separate lease. Consequently, an fd number cannot be closed
and reused while reactor state still refers to it. Close stops new leases,
cancels pending work, deregisters readiness, drops all leases, settles the close
promise, and releases its strong completion callback. Environment cleanup stops
admission and joins via a detached reaper so it does not block Node teardown.

All syscall interaction uses safe rustix APIs. The crate continues to deny
project-owned unsafe Rust.

## Verification record

The following passed on x86-64 glibc Linux with Node 26.4.0 and Rust 1.97.0:

- `npm run ci`: formatting, ESLint, strict TypeScript, rustfmt, strict Clippy,
  21 Rust tests, native/TypeScript builds, and 5 unprivileged Node tests;
- isolated `NODENETRAW_PRIVILEGED_TESTS=1` execution in a new user/network
  namespace: 2 tests passed for ICMP loopback send/receive and receive-queue
  overflow plus close cancellation;
- `npm run build:native:release`;
- `npm pack --dry-run`.

The ordinary Node suite leaves the 2 capability-dependent tests visibly skipped.
Successful AArch64 execution remains a support-matrix task before publishing
prebuilt artifacts.

## Phase 4 handoff

Phase 4 should propose binding, typed options, and richer packet metadata as
small additions. It must preserve the established descriptor leases, bounded
admission, explicit truncation, stable errors, and environment teardown model.
