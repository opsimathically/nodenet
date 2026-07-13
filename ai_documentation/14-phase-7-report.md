# Phase 7 completion report

Date: 2026-07-12

## Delivered

Phase 7 adds Linux `AF_PACKET` sockets to the shared descriptor, admission,
reactor, cancellation, and nonblocking completion model. Packet sockets are
opened with `{ family: "packet", mode: "raw" | "cooked", protocol }`, where the
protocol is a checked nonzero 16-bit `EtherType` in host byte order.

Packet addresses are family-discriminated and contain a nonzero interface index,
`EtherType`, and up to eight hardware-address bytes. Receive addresses also
expose Linux hardware type and packet type. Interface name/index lookup is
available through `interfaceIndex()` and `interfaceName()` with validation at
both the TypeScript and Rust boundaries.

Bind and send use checked `sockaddr_ll` values. Raw sockets preserve complete
link-layer frames; cooked sockets omit or synthesize the link header according
to Linux `SOCK_DGRAM` packet semantics. Receives preserve original length,
truncation, interface isolation, protocol, direction/type, hardware type, and
hardware address. Existing byte/operation bounds, fair readiness turns,
AbortSignal cancellation, close behavior, and Worker teardown apply unchanged.

Packet membership, promiscuous/all-multicast modes, auxdata, statistics, fanout,
filters, and packet-specific control messages remain Phase 8. `SO_BINDTODEVICE`
is rejected for packet sockets because `sockaddr_ll` binding is the correct
Linux mechanism.

## Safety adapter

Nix safely decodes received `LinkAddr` values but exposes no safe Linux
constructor, while rustix has no packet address type. D-022 therefore permits
two localized unsafe syscall sites for `bind(2)` and `sendto(2)`. Both operate
on a fully initialized, pointer-free stack `sockaddr_ll`, pass its exact checked
size, keep packet bytes borrowed only for the syscall, and retain descriptor
ownership in `OperationLease`. Protocol byte order, interface range, and
hardware-address length are checked before the adapter.

## Verification

`npm run ci` passes formatting, ESLint, strict TypeScript, all-target Clippy, 33
Rust tests, native/TypeScript builds, and seven ordinary Node tests. The
repository namespace harness creates a deterministic veth pair and all six
privileged tests pass with `npm run test:namespace`.

The packet test proves cooked injection to raw capture with an Ethernet header,
raw injection to cooked payload capture, deterministic interface isolation,
source link metadata, original-length truncation, independent cancellation, and
close cleanup.

## Next phase

Phase 8 adds reviewed advanced options, packet membership/auxdata/statistics/
fanout, classic BPF validation, safe compatible eBPF attachment, and bounded raw
option bytes.
