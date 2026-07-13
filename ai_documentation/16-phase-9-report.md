# Phase 9 completion report

Date: 2026-07-12

## Outcome

Phase 9 is complete. `RawSocket` now provides bounded nonblocking Linux batch
I/O across IPv4, IPv6, and packet destinations plus a receive-only TPACKET_V3
packet ring. Both paths remain inside the existing environment reactor and
consume its cancellation, close, admission, completion, and fairness budgets.

## Batch contract

- `sendBatch()` maps one admitted operation to one productive `sendmmsg(2)`. It
  accepts 1 through 64 same-family messages and at most 1 MiB of combined
  payload data. The result reports `requested`, the completed prefix, and the
  byte count for every completed entry. A partial syscall never fabricates an
  outcome for the untouched suffix.
- `receiveBatch()` maps one admitted operation to one productive nonblocking
  `recvmmsg(2)`. It returns 1 through the requested 64 available messages with
  independent source address, original length, truncation, flags, and copied
  data. Count multiplied by capacity is capped at 1 MiB.
- Batch native address, iovec, header, and initialized receive arenas remain
  stable for the complete syscall and are released with the operation.
- Ancillary controls and per-message flags remain on `sendMessage()` and
  `receiveMessage()`. Phase 9 does not create a pointer-bearing generic control
  arena merely for API symmetry.

## Receive-ring contract

`configurePacketRing()` installs one receive-only TPACKET_V3 ring on an
`AF_PACKET` socket. Geometry is checked against the runtime page size, 16-byte
frame alignment, integral frames per block, nonzero retirement timeout, a 64 MiB
per-ring limit, and a retained 128 MiB per-environment limit.

The reactor is the only code that traverses the mapping. It checks every block
status, packet count, first/next offset, header extent, `tp_mac`, snapshot
length, and payload end before copying. It publishes a block back to the kernel
only after consuming its final frame. Every mapping has unique ownership and is
unmapped once during reactor-side socket cleanup.

`receiveRingFrame()` returns a `PacketRingFrameLease` containing a bounded copy,
timestamp, original/snapshot lengths, status, and VLAN fields. `read()` returns
another owned copy while live. `release()` is idempotent, clears the retained
bytes, and makes later reads fail with `ERR_INVALID_ARGUMENT`. No Buffer aliases
mutable mmap memory, so a stale JavaScript reference cannot observe a frame
after the kernel reuses its block.

Ordinary and batch receives are rejected after ring configuration rather than
mixing incompatible consumption models. Pending ring receives support
AbortSignal cancellation and close settlement through the existing reactor.

## Transmit-ring evaluation

Linux supports TPACKET_V3 TX rings, but they require userspace to publish
writable frame status and then trigger transmission. That is a different
ownership state machine from receive-ring traversal. Phase 9 does not expose it:
the safe `sendmmsg` path already measured a substantial improvement, and TX mmap
has not demonstrated enough additional benefit to justify writable shared
frames. A future addition requires a separate decision, lease model, driver
matrix, and benchmark. The evaluation follows the
[Linux kernel Packet MMAP documentation](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html).

AF_XDP remains outside the initial baseline.

## Measurements

Command: `npm run benchmark:namespace`, optimized build, isolated loopback user
and network namespace on Linux 6.17.0 x86-64.

| Measurement                                     |                 Result |
| ----------------------------------------------- | ---------------------: |
| 256 sequential sends                            |                4.23 ms |
| 256 sends in batches of 32                      |                1.50 ms |
| Batch speedup                                   |                  2.81× |
| Two concurrently hot batch sockets              |          1.42 ms total |
| Hot-socket completion skew                      |                0.01 ms |
| 64 MiB owned copy throughput                    |             3651 MiB/s |
| 64 messages with packet-info/timestamp controls | 3.79 ms / 16,893 msg/s |

These figures are informative local evidence, not portable performance
guarantees or timing-sensitive CI thresholds. The benchmark script reports raw
JSON so later supported targets can retain their own baselines.

## Safety review

The D-024 adapter isolates the new unsafe surface in `batch.rs` and `ring.rs`.
All syscall counts, sizes, pointer arenas, address widths, mapping products,
offset additions, and returned lengths are checked. Receive buffers are
initialized before kernel writes. Ring mapping pointers do not leave the
reactor, and the sole `Send` assertion is documented by reactor confinement.

If mmap fails after ring allocation, the adapter submits a zero request to
disable the half-configured RX ring before returning the preserved mapping
error. Retained environment accounting is reserved before configuration and
released on every failure or ring drop.

## Verification

- `npm run ci`: formatting, ESLint, strict TypeScript, Rust formatting, Clippy,
  37 Rust tests, native/TypeScript builds, and 7 ordinary Node tests pass.
- `npm run test:namespace`: 6 isolated integration tests pass.
- Packet namespace coverage includes two-entry raw IPv4 batches, veth packet
  batch sends, TPACKET_V3 capture, 16 concurrent ring frame waits, copied lease
  release invalidation, cancellation, incompatible receive rejection, and close.
- `npm run benchmark:namespace`: optimized measurements above.
- `npm run test:phase9:stress`: 256 configure/cancel/close cycles retained the
  24-descriptor baseline exactly; observed RSS delta was 745,472 bytes.
- `npm run build:native:release` and `npm pack --dry-run` pass.

## Next phase

Phase 10 hardens the complete surface with fuzzing, sanitizers, longer fd/RSS
and race stress, supported Node/architecture execution, dependency/provenance
review, reproducible prebuilts, and first-release packaging.
