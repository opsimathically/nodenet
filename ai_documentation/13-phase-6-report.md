# Phase 6 completion report

Date: 2026-07-12

## Delivered

Phase 6 adds `AF_INET6`/`SOCK_RAW` sockets through the same owned descriptor,
bounded reactor, cancellation, and nonblocking completion substrate as IPv4.
`RawSocket.open({ family: "ipv6", protocol })` selects IPv6; omitting `family`
retains the existing IPv4 behavior. Each socket exposes its immutable family.

IPv6 message addresses carry an address, scope id, and flow info. Both the
TypeScript and Rust boundaries validate the family, numeric ranges, address
syntax, absence of embedded zone suffixes, and the requirement for a nonzero
scope on link-local destinations. IPv6 bind, local address, connect, and
disconnect are serialized through the reactor. Legacy string send/receive and
local-address methods remain explicitly IPv4-only; the discriminated message
methods provide IPv6 operations.

Typed IPv6 outbound controls cover packet info, per-message hop limit, and
traffic class. Receive controls cover packet info, hop limit, traffic class,
timestamps, queue overflow, extended errors, and bounded unknown data. Options
cover unicast/multicast hops, traffic class, packet-info/hop-limit/class
reception, timestamps, overflow, receive errors, effective `ipv6Only`, common
buffers, and device binding. Linux raw IPv6 sockets expose `ipv6Only` as an
effective getter but reject attempts to change it, so the facade reports that
setter as unsupported instead of leaking a kernel-specific `EINVAL`.

Raw IPv6 receive data is protocol payload. The implementation never parses or
fabricates an IPv6 header; destination, hop, and class metadata comes from
ancillary messages.

## Deliberate deferrals

`IPV6_CHECKSUM`, path-MTU discovery configuration, IPv6 multicast-loop
configuration, and membership structs remain in the Phase 8 typed-option/safe
extensibility review because the accepted safe dependencies do not expose the
required Linux operations. ICMPv6 is supported because Linux supplies its
checksum behavior.

## Verification

`npm run ci` passes formatting, ESLint, strict TypeScript, all-target Clippy, 31
Rust tests, native/TypeScript builds, and ordinary Node tests. The isolated
`npm run test:namespace` suite passes five tests. Its IPv6 test covers ICMPv6
loopback, bind/local address, connect/disconnect, hop/class options and
controls, packet info, protocol-payload semantics, truncation, family mismatch
rejection, link-local scope validation, cancellation, and close.

## Next phase

Phase 7 adds Linux `AF_PACKET` raw and cooked sockets with checked link-layer
addresses and the same bounded message/reactor model.
