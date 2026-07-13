# Phase 2 completion report

Completed: 2026-07-12

## Outcome

The Node-independent Rust socket core is implemented and tested. It establishes
descriptor ownership, operation leases, explicit/idempotent close, checked raw
IPv4 conversions, structured errors, and a safe Linux socket creation adapter.
No socket class or function is exported through N-API yet.

## Lifecycle state machine

```text
                  acquire lease
             +--------------------+
             |                    v
Open(Arc<OwnedFd>)           OperationLease(Arc<OwnedFd>)
       |
       | close; no leases                 last lease drops
       +---------------------------> Closed <-----------+
       |                                                |
       | close; one or more leases                      |
       v                                                |
Closing(Weak<OwnedFd>) ---------------------------------+
```

- One mutex serializes acquire, close, and status normalization.
- Only `Open` grants a new operation lease.
- Close drops the core's strong descriptor owner exactly once.
- Existing leases hold the same `OwnedFd`, never a copied integer descriptor.
- `Closing` retains only a weak observer, so it cannot prolong descriptor life.
- The final lease drop closes the descriptor; the next status check normalizes
  `Closing` to `Closed`.
- Repeated close reports `initiated: false` and never closes twice.
- Dropping the core without explicit close still releases its ownership.

This model allows an already admitted operation to finish after close starts
while preventing a descriptor-number reuse bug in that operation.

## Checked boundary types

- `RawIpv4Protocol`: accepts only nonzero values 1 through 255 and safely
  narrows to the Linux protocol representation.
- `PacketBufferLength`: accepts only 1 through 65,535 bytes.
- `BufferRange`: checks `u64` to `usize` conversion, addition overflow, and the
  final buffer bound. An empty range exactly at the buffer end is valid.

These are Rust-side invariants. Phase 3 must additionally reject non-integer or
unsafe JavaScript numbers before conversion.

## Error contract

`NativeError` retains:

- stable category and library code;
- stable operation identifier;
- optional numeric Linux errno;
- conventional errno name for currently mapped creation failures;
- human-readable system or validation message.

Implemented codes are `ERR_INVALID_ARGUMENT`, `ERR_SOCKET_CLOSED`, and
`ERR_SYSTEM`. Phase 3 must transfer these fields to JavaScript errors rather
than flattening them into a message.

## Linux adapter

The adapter calls rustix's safe `socket_with` wrapper for `AF_INET`/`SOCK_RAW`
and passes `SOCK_CLOEXEC | SOCK_NONBLOCK` atomically at creation. It returns an
owned descriptor directly into `SocketCore`. Linux performs `CAP_NET_RAW`
checking, and failures retain errno. The adapter never elevates privileges.

rustix 1.1.4 is exact-pinned with default features disabled and only `std`,
`fs`, and `net` enabled. Phase 2 introduced no project-owned unsafe block. The
crate-level `unsafe_code = "deny"` policy remains active.

## Verification

The following passed on x86-64 glibc Linux:

- 17 Rust tests, including 256 repeated acquire/close race iterations;
- immediate and lease-delayed descriptor cleanup observed through Unix socket
  peer EOF behavior;
- multiple leases retaining the descriptor until the final drop;
- deterministic invalid-family syscall failure with errno mapping;
- atomic `FD_CLOEXEC` and `O_NONBLOCK` flag verification;
- capability-dependent raw creation that accepts either a correctly owned socket
  or a structured Linux permission/system error;
- `npm run ci`, including Clippy with warnings denied and existing Node tests;
- optimized native release build;
- `npm pack --dry-run`, still limited to the nine intended package files.

No privileged packet was sent or received. AArch64 execution remains unverified
until the distribution matrix is implemented.

## Phase 3 handoff

Before exposing raw sockets to Node, Phase 3 must finalize:

- public TypeScript class/function and error shapes;
- bounded reactor command and per-socket operation limits;
- epoll readiness discipline and eventfd wakeup/shutdown;
- send/receive buffer ownership and copying rules;
- close/cancellation/promise settlement ordering;
- N-API environment cleanup and worker-thread behavior;
- separate unprivileged and capability-gated test entry points.
