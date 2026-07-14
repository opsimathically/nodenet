# Phase 14 completion report

Status: complete

Completed: 2026-07-13

Release candidate: `0.1.0-rc.5` (unpublished)

## Outcome

Phase 14 implements the accepted Router Discovery, Timestamp, and deprecated
Address Mask ICMPv4 scope in strict TypeScript over the existing bounded codec
and raw-socket helpers. It adds no runtime dependency, native I/O path, timer,
hidden receive loop, automatic responder, discovery state, clock access, route
selection, or interface configuration.

The root API now constructs, encodes, parses, validates, sends, and receives:

- Router Solicitation with a canonical zero reserved field;
- Router Advertisement with 1 through 255 IPv4 entries, a 16-bit lifetime,
  signed 32-bit preferences, and canonical two-word entries;
- Timestamp Request and Reply with explicit 16-bit identifiers/sequences and all
  three unsigned 32-bit timestamp fields; and
- deprecated Address Mask Request and Reply with canonical zero-mask requests
  and explicit dotted-decimal reply masks.

Compatible parsing retains safely decodable noncanonical data and reports it as
issues. Canonical construction rejects invalid local values rather than silently
normalizing them.

## Router Discovery safety and send policy

Router Advertisements check the address count and entry size before computing or
slicing the total entry area. The parser accepts forward-compatible entries of
two or more 32-bit words, returns standard address/preference fields, and copies
additional words and trailing data into bounded owned results. Preference is
read as signed two's-complement data; `-2147483648` is exposed with
`defaultEligible: false`.

`sendIcmpMessage()` recognizes Router Discovery after canonical encoding. For
multicast, Router Solicitation accepts only `224.0.0.2`, Router Advertisement
accepts only `224.0.0.1`, and a per-message IPv4 TTL of 1 is supplied unless an
equivalent control already exists. A conflicting TTL is rejected. Interface
choice and multicast membership remain caller-owned. Broadcast is never enabled
implicitly, so Linux rejects a broadcast send until the caller explicitly sets
the socket's `broadcast` option.

## Timestamp and Address Mask semantics

Timestamp values preserve every raw unsigned 32-bit value. The parser and
`classifyIcmpTimestamp()` distinguish standard milliseconds within one UTC day,
high-bit non-standard time, and the invalid middle range that lacks the required
high bit. Canonical builders reject that middle range. Request builders always
write receive and transmit timestamps as zero; compatible parsing preserves and
reports nonzero received request fields. `createIcmpTimestampReply()` copies the
identifier, sequence, and originate value from a parsed request while requiring
explicit receive and transmit values. It does not consult a system clock.

Address Mask parsing owns the four wire bytes and reports the dotted-decimal
address, contiguity, and prefix length when contiguous. Noncontiguous masks are
preserved with no prefix length. The helpers never apply, normalize, or
recommend the received value as host configuration, and the README labels types
17 and 18 as deprecated.

## Tests and verification

Independent ICMP tests cover canonical wire bytes and checksums, Router
Solicitation reserved/trailing fields, Router Advertisement count 0/1/255/256,
entry sizes below/equal/above two words, truncation, extension words, lifetime
extremes, signed preference extrema, timestamp range boundaries, request-owned
zero fields, trailing bytes, mask contiguity boundaries, malformed values,
unknown codes, owned results, and public declaration narrowing.

The following gates passed on x86-64 Linux:

- `npm run ci`: Prettier, ESLint, strict TypeScript, Rust formatting, Clippy, 38
  Rust tests, 77 ordinary Node tests (63 passed and 14 privileged tests skipped
  by design), and dependency/release-policy verification;
- isolated privileged Docker namespace: all 14 tests passed, including captured
  Router Solicitation and Advertisement packets with the correct multicast
  destinations and IPv4 TTL 1, rejected wrong-group/conflicting-TTL sends, and
  explicit broadcast permission behavior;
- Phase 9 packet-ring stress: 256 iterations, stable descriptor count 21, and
  1,925,120 bytes of RSS growth;
- Phase 11 event stress: 256 iterations with four lifecycle cycles each, stable
  descriptor count 21, and 6,889,472 bytes of RSS growth;
- `npm run release:consumer-test`: optimized x86-64 artifact, glibc requirement
  no higher than 2.16, scoped target-package selection, clean ESM import,
  CommonJS `require()`, and private-subpath rejection passed;
- `npm run release:verify-artifact`: x86-64 ELF architecture and the declared
  glibc 2.28 ceiling passed; and
- `npm run release:reproducibility`: two clean optimized builds produced the
  identical SHA-256
  `fdbddb0452569b99941a8e730e4446378b49cefe5fb42c6e2154bf215a83d9c2`.

The candidate version and target package metadata are aligned at `0.1.0-rc.5`.
Nothing was published.

## Remaining work

Phase 15 is next: bounded conventional increasing-TTL ICMP Echo traceroute,
including strong direct/quoted matching, destination classification, explicit
timeouts/cancellation, receive-lane cleanup, and an isolated routed topology.

AArch64/ARM64 remains an intended but untested target. No native AArch64
execution claim is made by this phase.
