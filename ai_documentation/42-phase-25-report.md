# Phase 25 completion report

Date: 2026-07-14

## Outcome

Phase 25 is complete with a **no-go** decision. Neither `PACKET_MMAP` nor
`AF_XDP` produced qualified, same-workload, end-to-end scanner evidence that
could satisfy the accepted selection threshold. Phase 26 therefore must not
start. The portable scanner remains the only scanner backend and its install,
kernel, privilege, ownership, and release contracts are unchanged.

This is a successful stop-gate outcome, not a claim that either Linux facility
is intrinsically slow. The evidence shows that this repository and available
host fixture do not currently justify accepting their additional ownership and
operational cost.

## Implemented evidence boundary

- `crates/nodenetscanner-native/src/backend.rs` freezes a non-Node-API internal
  contract for owned frame-template batches, owned receive batches, monotonic
  time, interface/queue identity, drops, backpressure, cancellation, and
  shutdown. No ring or UMEM view crosses this boundary.
- `phase25_backend_lab` is a non-public Rust example. It owns and bounds a
  TPACKET_V2 writable TX mapping, initializes every frame before changing its
  status to `SEND_REQUEST`, waits for kernel ownership to return, unmaps before
  descriptor release, and separately probes AF_XDP copy and zero-copy
  socket/UMEM setup without loading, replacing, or detaching an XDP program.
- `phase25-benchmark.mjs` records the preregistration, host and namespace
  inventory, rate sweep, CPU, RAPL snapshots, latency, loss, ordinary mmsg
  control, TPACKET_V3 RX control, and lab results. It performs two warmups and
  ten measured repetitions per workload. Raw receive operations have explicit
  deadlines. Scanner repetitions use distinct destination-port ranges and a 250
  ms unmeasured quiescence interval. Backend probes run only after the portable
  baseline so their packets cannot contaminate it.
- `phase25-statistics.mjs` provides deterministic paired bootstrap intervals and
  p50/p95/p99 summaries. Its tests cover positive selection thresholds, negative
  CPU deltas, interpolation, mismatched sets, and non-finite input.

The privileged command is:

```sh
sudo npm run benchmark:phase25
```

Set `NODENETSCANNER_PHASE25_OUTPUT` to retain the emitted JSON at a chosen path.
The command builds as the repository owner even when invoked through `sudo`.

## Recorded system

The accepted local run used Node.js 26.4.0, Rust 1.97.0, Linux 6.17.0-35-generic
x86-64, one Intel Core i7-14700KF socket with 20 physical/28 logical CPUs, one
NUMA node, and 33,475,129,344 bytes of memory. The process was eligible for CPUs
0-27. The isolated interfaces used MTU 1,500 veth pairs and the loopback mmsg
control used MTU 65,536.

Host inventory found one down one-queue `e1000e` interface, one live one-queue
USB `ax88179_178a` interface, one down `iwlwifi` interface, and no isolated
physical peer. The live USB interface was not commandeered for destructive or
uncontrolled traffic. Consequently there is no dedicated-physical-link or
hardware zero-copy result, and that missing evidence independently blocks a
positive backend selection.

The complete 31.591-second harness interval consumed approximately 2,776,584,933
package-domain microjoules according to the first RAPL snapshot pair. This
includes namespace setup, target process, every workload, and lab cleanup and is
recorded only as a whole-run operational observation; it is not attributable to
an individual backend and cannot support a power-efficiency claim.

## Portable baseline

Each scanner repetition issued 1,024 closed TCP SYN probes across the isolated
veth target. Every repetition produced 1,024 terminal results, zero timeouts,
zero kernel drops, zero forged/unrelated observations, and no accuracy
trade-off.

| Configured ceiling | Mean results/s | p95 results/s | Mean CPU cores | Mean elapsed ms |
| -----------------: | -------------: | ------------: | -------------: | --------------: |
|       10,000 pkt/s |       4,387.75 |      4,515.63 |          0.825 |          233.53 |
|       50,000 pkt/s |       4,424.15 |      4,515.47 |          0.832 |          231.53 |
|      100,000 pkt/s |       4,392.79 |      4,553.15 |          0.833 |          233.41 |

Against the 10,000 pkt/s sweep point, the paired bootstrap throughput-ratio 95%
interval was 0.989-1.031 at 50,000 pkt/s and 0.969-1.032 at 100,000 pkt/s. The
corresponding CPU-reduction intervals were -2.49%-0.73% and -2.29%-0.09%. These
comparisons describe the portable rate plateau only; they are not
candidate-backend qualification results.

The optimized syscall-free protocol benchmark remains the offline construction
control: strict Ethernet/IPv4/UDP parsing was 23.8 ns/op, the Phase 17 Ethernet
IPv4+IPv6 parse pair 85.1 ns/op, IPv4 construction 13.0 ns/op, and template
patching 7.8 ns/op, with zero allocations in all recorded paths. This separates
packet construction/checksum work from the live scheduler, syscall, copy, N-API,
veth, and kernel response path.

## Prototype observations

The ordinary loopback `sendmmsg`/`recvmmsg` control moved 640 96-byte messages
with zero loss in every repetition. It averaged 149,767.27 messages/s and 1.487
CPU cores. This is not an extreme backend: bounded mmsg remains a possible
portable implementation optimization and the control does not perform scanner
route selection, transmit/receive correlation, or result classification.

The TPACKET_V3 receive control paired existing bounded `sendmmsg` TX with a
receive-only 8 KiB ring and 16-operation admission batches. It received 640/640
frames in all ten repetitions, averaging 929.54 frames/s and 0.057 CPU cores.
Its 16 ms block retirement and one-owned-lease-at-a-time Node control path make
the number intentionally non-comparable to a native scanner hot loop. It proves
RX mapping ownership and cleanup, not an end-to-end scanner improvement.

The writable TPACKET_V2 lab mapped 262,144 bytes and submitted/completed 640/640
frames in 321,156 ns. No writable frame or pointer left Rust. However, the lab
does not include RX, scheduler, correlation, result batching, cancellation under
load, or parity. Combining unrelated TX and RX microbenchmarks would be
statistically invalid, so no PACKET_MMAP throughput ratio or selection interval
was computed.

AF_XDP socket/UMEM probes reported both copy and zero-copy unavailable on the
veth fixture. No benchmark-owned XDP program or XSKMAP was attached. The host
has the `libbpf1` runtime (Ubuntu package 1:1.3.0-2build2, dual
LGPL-2.1/BSD-2-Clause for the main library) but lacks libbpf/libxdp development
metadata, and the repository has no accepted loader, wrapper, artifact ABI, or
program ownership dependency. Adding any of those would expand build and host
state obligations without qualifying evidence.

## Ownership and operational assessment

`PACKET_MMAP` would require native-only writable TX slots, checked geometry and
status transitions, explicit `WRONG_FORMAT`/ring exhaustion behavior, and
shutdown that waits for every kernel-owned frame before unmapping. The prototype
demonstrates the minimum lifecycle but not scanner cancellation or fault parity.
That cost is unjustified without a matched-result win.

AF_XDP additionally requires queue-matched sockets, one authoritative producer
and consumer per ring, complete UMEM frame accounting across fill/RX/TX/
completion/cancel, and truthful copy/zero-copy reporting. An XDP program and
XSKMAP need an explicit external or module-owned lifecycle. The module may not
replace an operator program, and crash-safe identity-matched cleanup would need
its own accepted design. No such lifecycle was authorized for this evidence run.

## Decision and remaining work

No candidate reached the point where an identical matched-result scanner
workload could be compared. The accepted rule permits selection only after a
candidate's bootstrap 95% interval remains beyond 1.5x throughput at no greater
CPU or 30% CPU reduction at equal throughput, accuracy, and loss. Absence of a
qualified comparison cannot be treated as an improvement; therefore D-039
records `no-go` and Phase 26 is closed.

The portable scanner remains independently releasable. Its existing native
AArch64 execution publication gate from Phase 24 is still outstanding and is
unrelated to this backend decision. Reopening extreme-backend work requires a
new decision, an isolated physical peer with declared driver/queues, an
operator-approved XDP ownership model if applicable, and a fresh preregistered
same-workload review. Microbenchmark numbers from this report are insufficient.
