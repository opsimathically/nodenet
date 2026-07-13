# Phase 8 completion report

Date: 2026-07-12

## Outcome

Phase 8 is complete. The public TypeScript API now exposes advanced typed Linux
configuration, connected raw IPv4 parity, packet-socket controls and metadata,
classic/eBPF filter attachment, and a bounded opaque socket-option escape hatch.
All operations remain serialized through the environment reactor and use the
existing operation-lease lifecycle.

## Delivered API

- Typed IPv4/common options: `headerIncluded`, `freebind`, `transparent`,
  `priority`, `mark`, `pathMtuDiscovery`, `multicastTtl`, `multicastLoop`, and
  `busyPollMicroseconds`.
- Typed IPv6/common options: `ipv6ChecksumOffset`, `priority`, `mark`,
  `pathMtuDiscovery`, `multicastLoop`, and `busyPollMicroseconds`, in addition
  to the Phase 6 hop/multicast configuration.
- IPv4 `connect()` now shares the existing explicit `disconnect()` contract with
  IPv6.
- Packet membership supports promiscuous, all-multicast, and checked multicast
  hardware addresses with deterministic add/drop calls.
- `setPacketAuxdata()` exposes copied VLAN/status/length/offset metadata on
  receives; `packetStatistics()` returns Linux packet/drop counters;
  `setPacketFanout()` accepts all eight checked Linux fanout modes and a 16-bit
  group identifier. Kernel socket lifetime owns fanout membership.
- Classic BPF accepts 1 through 4096 checked instructions, validates jumps and
  the terminal return, and relies on Linux for full instruction verification.
  Reattachment atomically replaces the kernel-owned copy. Filters can be
  detached or permanently locked.
- eBPF attachment accepts an already compatible program fd, duplicates it with
  `F_DUPFD_CLOEXEC`, attaches the duplicate, then closes the duplicate. It does
  not load programs and never consumes or exports the caller's fd.
- `getSocketOption()` and `setSocketOption()` copy initialized byte values with
  a 4096-byte ceiling. Known typed, fd-bearing, pointer-bearing, membership,
  filter, fanout, statistics, auxdata, and ring tuples are reserved and
  rejected.

A general duplicated-descriptor export was not added. Although ownership could
be documented, it would broaden the public authority surface without a Phase 8
use case; typed eBPF duplication provides the required interoperability without
transferring socket ownership to JavaScript.

## Safety review

The D-023 adapter in `native/src/advanced.rs` contains the Phase 8 unsafe
surface. Every output buffer is initialized before `getsockopt`; every length is
checked against its actual allocation; fixed Linux structs are fully
initialized; transient BPF pointers remain live until the copying syscall
returns; and every successful fd duplication becomes one `OwnedFd` immediately.
No pointer or borrowed raw fd is queued in reactor state.

Packet auxdata parsing copies a bounded control payload and validates its exact
minimum structure length before native-endian field decoding. Unexpected or
duplicate packet controls fail as malformed control data. Packet receives do not
use `MSG_CMSG_CLOEXEC` because Linux rejects that flag for this AF_PACKET path
and `PACKET_AUXDATA` cannot carry descriptors.

The TypeScript and Rust boundaries independently check numeric widths, family
compatibility, membership address lengths, fanout modes, option byte bounds,
classic instruction widths/count, and nonnegative eBPF descriptors.

## Linux behavior matrix

Test host: Linux 6.17.0 x86-64, Node.js 26.4.0, npm 11.17.0, Rust 1.97.0.

| Behavior                              | Public result                                                                  | Verification                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Unknown option unsupported by kernel  | `ERR_SYSTEM` with preserved `ENOPROTOOPT` where returned                       | Raw adapter delegates harmless unknown tuples without rewriting errno |
| Invalid option value/layout           | JavaScript/Rust `ERR_INVALID_ARGUMENT`, otherwise kernel `ERR_SYSTEM`/`EINVAL` | Width, bounds, malformed BPF, and kernel verifier tests               |
| Capability-required option/filter     | `ERR_SYSTEM` with preserved `EPERM`/`EACCES`                                   | Namespace capability paths and locked-filter denial                   |
| Reserved raw tuple                    | `ERR_UNSUPPORTED` before syscall                                               | Unit and ordinary Node tests use `SO_ATTACH_FILTER`                   |
| Oversized raw value/program           | `ERR_INVALID_ARGUMENT` before allocation/syscall                               | 4096-byte/instruction boundary tests                                  |
| Non-BPF fd passed for eBPF attachment | `ERR_SYSTEM`; caller fd remains open                                           | Namespace test with `/dev/null` and subsequent `fstat`                |
| Filter replacement and lock           | Replacement succeeds; detach after lock returns `ERR_SYSTEM`                   | Namespace packet test                                                 |
| Unsupported driver/hardware behavior  | Preserved structured kernel error; no fabricated fallback                      | API never emulates driver-specific options                            |

The project baseline remains kernel 4.18+. Individual advanced options can still
return `ENOPROTOOPT`, `EINVAL`, or permission errors on older kernels,
restricted namespaces, or drivers that do not implement them. These are stable
structured failures, not feature emulation.

## Verification

- `npm run format:check`
- `npm run lint`
- `npm run typecheck`
- `npm run rust:fmt`
- `npm run rust:clippy`
- `npm run rust:test`: 35 passed
- `npm test`: 7 passed, 6 privileged cases skipped as designed
- `npm run test:namespace`: 6 passed
- `npm run ci`
- `npm run build:native:release`
- `npm pack --dry-run`

The namespace suite covers IPv4 typed options and connect/disconnect, IPv6
regression behavior, veth packet traffic, membership removal, auxdata,
statistics, fanout, classic-filter replacement/detach/lock, eBPF caller-fd
retention, cancellation, truncation, and lifecycle cleanup.

## Next phase

Phase 9 adds bounded batch message APIs, performance/fairness benchmarks, and
only then explicitly leased `TPACKET_V3` packet rings. Ring layouts and mapped
memory remain excluded from the Phase 8 opaque option interface.
