# ICMPv4 and traceroute plan review

Status: complete; all blocking findings are closed and Phase 12 is ready

Reviewed: 2026-07-13

## Review objective

This is the preimplementation audit for Phases 12 through 15. It tests the
planned ICMPv4 and traceroute layer against the implemented `RawSocket` and
`RawSocketEventEmitter` contracts, Linux raw-socket behavior, current IANA
registries, the governing RFC wire formats, existing test/release machinery, and
the project's bounded-memory and exactly-once lifecycle rules.

This review changes planning documents only. The authoritative implementation
contract remains [the capability plan](23-icmp-and-traceroute-plan.md); this
document records the gaps found and why the corrected plan is ready.

## Evidence inspected

- `src/index.ts`: public socket/message types, private socket registry, family
  and lane validation, per-message `ipv4Ttl`, AbortSignal settlement, typed
  options, error normalization, and event-source attach/detach behavior.
- Ordinary, privileged, namespace, Worker, stress, consumer, reproducibility,
  and artifact test entry points already used through Phase 11.
- The current IANA ICMP type/code and extension-object registries.
- RFC 792, RFC 950, RFC 1071, RFC 1122, RFC 1191, RFC 1256, RFC 1812, RFC 4884,
  RFC 6633, and RFC 6918.
- Linux `raw(7)` and `ip(7)` behavior for IPv4 receive headers, kernel-built
  send headers, protocol filtering, per-packet TTL, and broadcast permission.

## Closed findings

### RICMP-1 — Receive compatibility and canonical encoding were conflated

Several RFC fields are sent as zero but ignored on receive. Rejecting all
nonzero reserved fields would incorrectly discard safely readable packets and
future-compatible extensions; accepting everything silently would hide
noncanonical input.

Resolution: parsing is structurally safe and compatible by default. It preserves
ignored/reserved/trailing data and emits validation issues. Canonical validation
escalates applicable issues, while canonical encoders write fixed, zero, and
length fields deterministically. `validateIcmpMessage()` shares the parser and
defines `valid` precisely; it is not a second wire implementation.

### RICMP-2 — Pure codecs could not depend on existing root error factories

The current stable `RawSocketError` helpers are private to the package root. If
pure codec modules imported the root to throw those errors, the planned root
re-exports would create an ESM initialization cycle.

Resolution: internal codecs accept and return neutral typed values and never
import the root, socket classes, or socket errors. Root-facade wrappers perform
runtime JavaScript validation and use the existing argument-error path before
delegation. Hostile byte input remains a structured parse result; local API
misuse retains the package's established thrown/rejected error shape.

### RICMP-3 — Known type plus unknown code needed a representation

The original direction distinguished unknown types but could accidentally decode
an unsupported code as a supported code-zero layout. The live IANA registry also
assigns Router Advertisement code 16 to Mobile IP semantics, outside the
requested RFC 1256 utility scope.

Resolution: a known type with an unregistered or out-of-scope code becomes an
owned `unknownCode` variant and a validation issue. It is never mislabeled as a
known semantic message. Mobile IP Agent Advertisement behavior remains outside
scope pending a separate design.

### RICMP-4 — Linux send and receive framing required an explicit boundary

Linux IPv4 raw receives include the IPv4 header, while normal raw sends let the
kernel build that header. A standalone ICMP parser cannot safely guess which
layout it was given. The existing `RawSocket` also did not retain its checked
open protocol publicly.

Resolution: standalone codecs begin at the ICMP type; a separate
`parseIcmpReceivedMessage()` checks and removes the received IPv4 header and
cross-checks metadata. Phase 12 captures and exposes readonly socket protocol
without a native query. Helpers authenticate sockets through the existing
private registry, require IPv4/ICMP, use the normal receive lane, and document
kernel-header mode as a precondition rather than pretending an asynchronous
option check could prevent concurrent mutation.

### RICMP-5 — RFC 4884 framing was incomplete and overlapped RFC 1191

RFC 4884 reuses the sixth ICMP octet for original-datagram length. In a
Fragmentation Needed message this must coexist with, not replace, the two-byte
next-hop MTU. A zero length is compliant “no extensions”; legacy deployed
extensions use an implicit fixed 128-byte quote and must not be autodetected by
default.

Resolution: the plan fixes the exact second-word byte layouts for Destination
Unreachable, Time Exceeded, and Parameter Problem. Default parsing uses the
nonzero 32-bit-word length, minimum 128-byte padded quote, version-2 header,
object-chain bounds, and extension checksum. Zero means no extensions. An
explicit non-default legacy option probes the fixed boundary only when the
version, checksum, and complete object chain validate. Redirect cannot carry
this extension. Construction and parsing enforce the RFC 4884 576-byte ICMP
message ceiling for extended errors.

### RICMP-6 — Router Discovery policy had receive and transmit gaps

RFC 1256 says Router Solicitation reserved bytes and additional octets are
ignored on reception. Its multicast destinations require TTL 1, while limited
broadcast still depends on Linux `SO_BROADCAST`. The utility is not a router or
host discovery state machine.

Resolution: compatible receive parsing preserves and reports ignored bytes.
Router Discovery multicast helpers apply TTL 1 and reject conflicting
destination/TTL combinations; they do not choose an interface/source, join a
group, or enable broadcast. Parsing and construction never select a router,
schedule advertisements, or mutate host routes.

### RICMP-7 — Timestamp wire values had an unclassified range

RFC 792 defines 0 through 86,399,999 as milliseconds since midnight UTC and uses
the high bit to flag non-standard time. Values above the day range with the high
bit clear fit the field but satisfy neither semantic category.

Resolution: parsers preserve all 32-bit wire values and classify them as
`standard`, `nonStandard`, or `invalidStandardRange`; the last form carries an
issue. Canonical builders accept only the first two. No utility changes or
claims authority over a system clock.

### RICMP-8 — Error-quote probe correlation needed fragment and evidence rules

Matching only type, identifier, or sequence can attribute another process's
traffic to a probe. Historical ICMP errors may quote too little data to contain
a token, while NAT may legitimately rewrite the quoted tuple.

Resolution: quoted matching requires IPv4, ICMP, expected destination, initial
fragment, Echo Request type, identifier, and sequence. A token is required
whenever the quote contains enough bytes and is always required for direct Echo
Reply. Short historical quotes are explicitly weaker matches; contradictory,
non-initial-fragment, malformed, checksum-invalid, and partial tuples remain
unmatched. NAT can therefore produce a safe false negative, not an unsafe guess.

### RICMP-9 — Traceroute terminal and cancellation outcomes were mixed

Network responses, local silence, user cancellation, socket failure, and the
overall session deadline require different contracts. Treating cancellation as a
fabricated hop result would obscure cleanup and error handling.

Resolution: the pure classifier returns network-response matches only. Each
silent probe produces a compact timeout result. Normal resolution has an
explicit destination/unreachable/max-hops/overall-timeout termination reason.
Abort, send, receive, callback, and socket failures reject after listeners,
timers, pending state, and the internal event lane have quiesced. The caller's
socket remains open unless it was externally closed. A terminal message-listener
decision begins detach synchronously before returning, preventing a new receive
turn from being admitted during asynchronous result cleanup.

### RICMP-10 — Traceroute resource and retention bounds were incomplete

A hop limit alone does not bound timer duration, caller bytes, concurrent sends,
or retained packet data. Raw `ReceivedMessage` or quote retention would multiply
memory by every probe.

Resolution: the plan fixes ranges and defaults for first/highest hop, probes per
hop, per-probe and overall deadlines, token, caller payload, and within-hop
in-flight work. At most 2,550 compact probe results are retained, with no full
payload, raw quote, or received packet per probe. Match registration precedes
send admission, results have deterministic order, and one settlement authority
owns every probe. Each deadline is capped by the overall deadline, exact
deadline equality is a timeout, and overall expiry settles admitted pending
probes before cleanup without admitting another hop. Admission and message paths
check that monotonic bound directly, so unrelated traffic cannot prolong the
logical session while a timer callback waits to run.

### RICMP-11 — The privileged topology needed observable protocol assertions

A simple loopback ping cannot verify TTL expiry, quote correlation, router
multicast scope, next-hop MTU, or cleanup across hops.

Resolution: Phase 12 begins with isolated loopback Echo; later gates use
disposable namespaces/veth routing to prove crafted errors and a route with at
least one intermediate hop. Assertions cover TTL 1/2, destination reply,
unreachable and silent probes, quote/MTU fields, Router Discovery multicast and
broadcast permission, lane cleanup, fd/RSS baselines, and explicit capability
and tool skips. Test setup must restore or destroy all namespace-local state.

### RICMP-12 — Legacy request fields needed canonical ownership rules

A generic three-timestamp or one-mask construction shape could let callers put
reply-owned values into Requests. Timestamp Requests originate one time for the
receiver to augment; RFC 950 examples consistently send Address Mask Requests
with a zero mask for an authority to fill.

Resolution: canonical Timestamp Request builders accept the originate time and
zero receive/transmit; canonical Address Mask Request builders write a zero
mask. Reply builders require the response values explicitly and never consult a
clock or interface configuration. Compatible parsers preserve nonzero request
fields with issues so safely readable historical traffic is not discarded.

### RICMP-13 — Error construction needed a minimum quote contract

The parse plan represented incomplete historical quotes, but the construction
side did not say whether it could emit one or treat bytes past the inner IPv4
total length as original data.

Resolution: canonical error construction requires a complete valid inner IPv4
header and at least the lesser of the original total length or `IHL + 8` bytes.
It may include more original bytes up to that total length, never includes bytes
beyond it as quote data, and adds only separately defined RFC 4884 zero padding.
Parsing can still report shorter hostile/captured input as incomplete without
reading absent fields.

### RICMP-14 — Traceroute classifier inputs were underspecified

The proposed classifier signature did not say whether it reparsed a raw
`ReceivedMessage`, accepted a successful packet only, or shared the session's
monotonic clock. Destination syntax was also left implicit.

Resolution: the classifier consumes the structured result from
`parseIcmpReceivedMessage()` and returns unmatched for failed/incomplete input;
it does not duplicate framing logic. Probe send and receive times are monotonic
nonnegative `bigint` values from one clock domain, receive cannot precede send,
and RTT is never narrowed to `number`. Socket helpers and traceroute use the
existing checked `Ipv4MessageAddress` and never perform DNS resolution.

### RICMP-15 — Mutable byte views could invalidate a two-pass parse

Copying only returned variable fields does not make checksum-then-parse logic
deterministic when a `Uint8Array` is backed by memory another Worker can mutate.
It also left the standalone checksum helper without an event-loop work bound.

Resolution: each public checksum/codec operation first makes one private bounded
copy and uses it for every checksum and structural read. Checksum input is
capped at 65,535 bytes; standalone ICMP parsing retains its 65,515-byte cap.
Larger local checksum input is an argument error, oversized hostile ICMP is a
structured length failure, and no returned field aliases the caller's view.

## Readiness decision

No blocking design question remains for Phase 12. Its public function direction,
module dependency rule, runtime error boundary, ownership model, receive-lane
behavior, allocation ceiling, checksum policy, compatibility policy,
implementation order, and ordinary/privileged/release gates are specified.

Phases 13 through 15 also have coherent dependency and exit gates. Their exact
TypeScript declaration details are intentionally finalized within their own
phase before export, but their wire semantics, non-goals, safety limits, and
composition constraints are already binding. Any later scope expansion—ICMPv6,
Mobile IP, decoded extension-object classes, UDP/TCP traceroute, or
daemon/policy behavior—requires a new recorded decision rather than being folded
into these phases.

## Next action

Begin Phase 12 in the implementation order recorded in the capability plan. Mark
it in progress before changing production files; do not start Phase 13 until
every Phase 12 exit gate and release-candidate verification is recorded.

## Primary references

- [IANA ICMP Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
- [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792.html)
- [RFC 1071 — Computing the Internet Checksum](https://www.rfc-editor.org/rfc/rfc1071.html)
- [RFC 1191 — Path MTU Discovery](https://www.rfc-editor.org/rfc/rfc1191.html)
- [RFC 1256 — ICMP Router Discovery Messages](https://www.rfc-editor.org/rfc/rfc1256.html)
- [RFC 4884 — Extended ICMP](https://www.rfc-editor.org/rfc/rfc4884.html)
- [RFC 6918 — Deprecation of several ICMP extensions](https://www.rfc-editor.org/rfc/rfc6918.html)
- [Linux `raw(7)`](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Linux `ip(7)`](https://man7.org/linux/man-pages/man7/ip.7.html)
