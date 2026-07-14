# ICMPv4 utilities and traceroute capability plan

Status: Phase 12 complete; Phases 13–15 planned

Last updated: 2026-07-13

The preimplementation audit and closed findings are recorded in
[the Phase 12–15 plan review](24-icmp-plan-review.md). This document remains the
authoritative implementation contract. Phase 12 evidence is recorded in the
[completion report](25-phase-12-report.md).

## Purpose

Phases 12 through 15 add a zero-runtime-dependency protocol utility layer over
the completed `RawSocket` and `RawSocketEventEmitter` APIs. The layer will let
applications construct, encode, send, receive, parse, validate, and correlate
the requested ICMPv4 messages without weakening the low-level byte-oriented
surface.

The requested message numbers and formats are ICMP for IPv4. ICMPv6 is a
different protocol with different types, checksum rules, and Neighbor Discovery
semantics. It remains supported by the low-level socket API, but high-level
ICMPv6 codecs are not silently included in these phases.

## Governing principles

- Preserve `RawSocket` as the ownership and I/O authority. Protocol utilities
  accept existing sockets; they do not duplicate descriptors or create another
  reactor.
- Keep wire codecs and checksum logic pure TypeScript with Node built-ins only.
  No Rust, N-API, native dependency, or runtime package is planned for these
  bounded packet transforms.
- Treat every received byte, type, code, length, reserved field, quoted packet,
  extension object, and address as untrusted.
- Allocate a fresh bounded `Buffer` for encoded output and owned copies of
  variable parsed fields. Codec-owned fields never alias a caller-mutable
  packet; a received adapter may separately retain the original
  `ReceivedMessage` for access to its existing metadata.
- Snapshot accepted byte input once at public-operation entry before checksum
  and structural reads. This keeps parser/checksum results internally consistent
  even when a view is backed by concurrently mutable shared memory.
- Use network byte order explicitly and checked arithmetic before every offset,
  product, and allocation.
- Preserve unknown type/code/extension data as bounded owned bytes where it is
  safe to do so. Forward compatibility must not turn unknown data into a known
  semantic claim.
- Separate structural parsing, checksum status, and semantic policy. A packet
  can be structurally readable while having an invalid or unverifiable checksum.
- Never change a route, install a default router, answer a request, or trust an
  ICMP redirect automatically. Construction and parsing do not imply policy.
- Do not hide receive-lane ownership. A high-level promise receive or traceroute
  owns the same normal lane as `receiveMessage()`; event consumers parse the
  messages already delivered by their `RawSocketEventEmitter`.
- Keep all loops bounded. ICMP utilities do not add an internal receive queue,
  and traceroute has explicit hop, probe, payload, timeout, and in-flight
  limits.

## Scope matrix

| Family                                                  | Construct/encode | Parse/validate          | One-shot send/receive | Phase |
| ------------------------------------------------------- | ---------------- | ----------------------- | --------------------- | ----- |
| Echo Request and Echo Reply                             | yes              | yes                     | yes                   | 12    |
| Destination Unreachable, including Fragmentation Needed | yes              | yes                     | yes                   | 13    |
| Time Exceeded                                           | yes              | yes                     | yes                   | 13    |
| Parameter Problem                                       | yes              | yes                     | yes                   | 13    |
| Redirect                                                | yes              | yes                     | yes                   | 13    |
| Router Solicitation and Router Advertisement            | yes              | yes                     | yes                   | 14    |
| Timestamp Request and Timestamp Reply                   | yes              | yes                     | yes                   | 14    |
| Address Mask Request and Address Mask Reply             | yes              | yes                     | yes                   | 14    |
| TTL-limited Echo probes and reply correlation           | yes              | yes                     | session support       | 15    |
| ICMP traceroute and destination detection               | probe support    | response classification | bounded orchestration | 15    |

“Fragmentation Needed” is modeled as the specialized code-4 variant of
Destination Unreachable, not as an invented standalone ICMP type. Address Mask
messages are supported as explicitly deprecated legacy formats. Source Quench,
Information Request/Reply, the deprecated ICMP Traceroute type 30, and extended
Echo types are not part of the accepted scope.

## Planned public organization

The package root will re-export the accepted types and functions so consumers do
not import private files. Implementation should be split internally into small
modules such as `src/icmp/constants.ts`, `checksum.ts`, `codec.ts`, and
`traceroute.ts`; those paths are not public contracts. Pure codec modules must
not import the package root. RawSocket-aware helpers must either be wired after
the class definition in the root facade or depend on a narrow internal interface
so the implementation does not introduce an ESM initialization cycle.

Internal codecs return neutral values or structured failures and never import
`RawSocket`, `RawSocketError`, or root error factories. Root-facade wrappers
validate runtime JavaScript value types and use the existing private
`invalidArgument()` path before delegating to the codecs. This preserves the
stable public error shape without moving the established socket error model or
creating a circular dependency.

### Constants

Export named zero-dependency numeric constants for all implemented types and the
registered codes whose semantics are in scope. Names use the Linux/IANA spelling
where practical, including:

- `ICMP_ECHOREPLY`, `ICMP_DEST_UNREACH`, `ICMP_REDIRECT`, `ICMP_ECHO`,
  `ICMP_ROUTERADVERT`, `ICMP_ROUTERSOLICIT`, `ICMP_TIME_EXCEEDED`,
  `ICMP_PARAMETERPROB`, `ICMP_TIMESTAMP`, `ICMP_TIMESTAMPREPLY`, `ICMP_ADDRESS`,
  and `ICMP_ADDRESSREPLY`;
- readable code constants for all currently registered Destination Unreachable,
  Redirect, Time Exceeded, and Parameter Problem variants;
- aliases only when Linux and common RFC terminology materially differ, with one
  canonical documented name.

The registered Router Advertisement code 16 belongs to Mobile IP Agent
Advertisement semantics and is not silently decoded as an RFC 1256 code-zero
advertisement. It remains available as a numeric unknown-code packet until a
separate Mobile IP scope is accepted.

Constants are ordinary numbers. Parsed unions remain forward-compatible with
unknown numeric types and codes rather than assuming this snapshot is an
exhaustive registry.

### Pure checksum API

The foundation exports non-mutating helpers with RFC 1071 semantics:

```ts
computeInternetChecksum(data: Uint8Array): number;
validateInternetChecksum(data: Uint8Array): boolean;
```

The algorithm pairs octets as big-endian 16-bit words, pads an odd final octet
with zero for calculation only, folds carries without JavaScript signed-bitwise
overflow, and validates the complete ICMP message including its checksum field.
The same implementation is shared by encoding and parsing and is covered by
independent vectors, odd/even lengths, split carry cases, and all boundary
lengths. Public checksum helpers accept at most 65,535 bytes and calculate from
one bounded snapshot; larger local inputs throw the stable argument error rather
than monopolizing the event loop. The ICMP parser separately enforces its
65,515-byte standalone-message maximum as a structured length failure.

### Codec result and error model

`encodeIcmpMessage(message)` accepts a discriminated construction union,
validates JavaScript callers at runtime, writes reserved fields
deterministically, computes the checksum, and returns a fresh `Buffer`.

`parseIcmpMessage(data, options?)` expects bytes beginning at the ICMP type and
returns a discriminated result instead of using exceptions for ordinary hostile
network input:

```ts
type IcmpParseResult =
  | { readonly ok: true; readonly packet: ParsedIcmpPacket }
  | { readonly ok: false; readonly error: IcmpParseFailure };

type IcmpChecksumStatus = "valid" | "invalid" | "unverifiable" | "notChecked";

interface IcmpValidationIssue {
  readonly code: string;
  readonly severity: "error" | "warning";
  readonly offset?: number;
  readonly message: string;
}
```

The planned failure object is reserved for inputs that cannot be decoded safely,
with a stable reason such as `truncated`, `invalidLength`, `invalidChecksum`, or
`unsupportedStructure`, plus the byte offset and required/available lengths when
applicable. A successful structural parse carries validation issues for
decodable but non-canonical input such as an unknown code, nonzero ignored
field, or unexpected trailing bytes. Parser options select checksum policy:

- `require` rejects an invalid checksum;
- `report` returns a packet whose checksum status is `valid` or `invalid`;
- `ignore` is explicit and intended for independently verified/offload-derived
  data and reports `notChecked`.

The default for complete standalone ICMP bytes is `require`. Parsing a truncated
`ReceivedMessage` reports checksum state as `unverifiable` rather than claiming
validity. Every successful parsed packet includes the numeric `type`, numeric
`code`, received checksum, checksum status, and discriminated `message`. An
unknown type produces an `unknown` message with owned body bytes. An
unregistered or out-of-scope code for a known type produces an `unknownCode`
message with an owned body and an issue; it is never mislabeled as the code-zero
known variant. Known variable fields and unknown/trailing data are copied
independently so no exposed Buffer aliases the caller's input or another mutable
result field.

Parsing defaults to compatible receive semantics: insufficient or contradictory
lengths fail, while reserved/unused bytes that standards direct receivers to
ignore are preserved and reported rather than rejected. A `conformance` option
selects `compatible` (default) or `canonical`. Canonical validation treats a
wrong known code, nonzero ignored field, or disallowed trailing data as an error
issue; encoding always emits the canonical form. Unknown future type/code data
remains distinguishable from a currently registered value in both modes.

`validateIcmpMessage(data, options?)` runs the same parser and returns a report
containing `valid`, checksum status, validation issues, and the parsed packet
when structurally available. It does not maintain a second implementation of the
wire rules. `valid` means structural decoding succeeded, no error-severity issue
exists under the selected conformance mode, and the selected checksum policy is
satisfied; with checksum `ignore`, it deliberately says nothing about checksum
integrity. Runtime misuse such as a non-`Uint8Array` argument throws the stable
local argument error; arbitrary bytes of the correct input type always produce a
structured parse/validation result.

Encoding invalid construction inputs throws the existing stable argument error
shape because those values are local programming errors, not network parse
outcomes. The exact operation name identifies the builder/encoder.

### Received IPv4 adapter

Linux IPv4 raw receives include an IPv4 header, whereas sends normally accept
the ICMP message body for the kernel to wrap. A dedicated adapter will make that
asymmetry explicit:

```ts
parseIcmpReceivedMessage(message: ReceivedMessage, options?):
  IcmpReceivedParseResult;
```

It verifies that IPv4 metadata exists, protocol is `IPPROTO_ICMP`, header length
is within the received bytes, total-length and truncation facts are consistent,
and the ICMP region begins at the checked IPv4-header boundary. It retains the
original `ReceivedMessage` beside the parsed packet so source address, control
messages, timestamps, queue-overflow metadata, and truncation remain available.
When truncation leaves enough fixed header to identify a message, the result
marks it incomplete, exposes only the owned received prefix, and uses
`unverifiable`; it never synthesizes missing payload or checksum validity. The
adapter parses the outer IPv4 source/destination, flags, fragment offset, and
header checksum independently and compares all overlapping facts with the native
metadata and `ReceivedMessage.source`. A mismatch is a structured failure, not a
reason to trust one representation silently.

Event-driven applications call this adapter in their existing `message`
listener. No second event source, hidden receive, or transformed event queue is
added.

### One-operation socket helpers

The planned helpers accept an already-open IPv4 `RawSocket` whose protocol is
ICMP:

```ts
sendIcmpMessage(socket, message, options): Promise<number>;
receiveIcmpMessage(socket, options?): Promise<IcmpReceivedParseResult>;
```

Send options require a destination and may include a per-message TTL, flags,
ancillary controls, and `AbortSignal` where the underlying operation supports
them. A TTL is conveyed through the existing per-message IPv4 TTL control, not
by racing a mutable socket-wide option. The helper encodes first, then delegates
to `sendMessage()`. Destination uses the existing checked `Ipv4MessageAddress`
shape; helpers do not add DNS or accept ambiguous host names.

Receive performs exactly one underlying `receiveMessage()`, accepts existing
data/control capacities and cancellation, then returns the received adapter's
structured parse result. Socket/cancellation failures reject the promise;
malformed network bytes do not. It does not loop past unrelated or malformed
traffic. This makes packet consumption observable and preserves current
lane-conflict behavior.

Phase 12 also adds a readonly `RawSocket.protocol` getter backed by the checked
value captured at open, requiring no native query. Helpers reject non-IPv4 or
non-ICMP sockets before starting I/O. `sendIcmpMessage()` is for the normal
kernel-built IPv4-header mode; callers using `headerIncluded` encode the ICMP
body and compose the complete IPv4 packet through the low-level API. Concurrent
mutation of header mode while a helper is active is unsupported and documented.

Socket helpers authenticate the socket through the existing private
`socketInternals` registry rather than duck typing. `receiveIcmpMessage()` uses
only the normal lane and does not accept `peek` or `errorQueue`. A convenience
`ttl` and an explicit `ipv4Ttl` control are mutually exclusive. Native send,
receive, cancellation, and close failures retain their original low-level
operation and `errno`; helpers do not obscure them by remapping every error to a
protocol-level operation name.

## Message model and validation contract

### Common header

Every message has a four-octet type/code/checksum header. Encoders set the
checksum field to zero during calculation. Parsers check the minimum before any
field access and include every byte, including unknown/trailing bytes, in
checksum validation.

Canonical encoders emit no unspecified trailing data. Compatible parsers decode
the complete fixed fields and preserve any trailing bytes with a validation
issue; canonical validation marks that issue as an error. This rule avoids
silently discarding checksum-covered bytes without treating safe forward data as
an out-of-bounds condition.

### Echo Request and Reply

- Type 8 request and type 0 reply; code must be zero.
- Identifier and sequence are checked unsigned 16-bit integers.
- Payload is an owned byte sequence whose encoded message remains within the
  65,515-byte maximum ICMPv4 message bound (the IPv4 maximum minus its minimum
  20-byte header). A configured IPv4 option or path MTU may impose a lower
  kernel limit that remains a normal structured send error.
- A correlation helper compares reply type, identifier, sequence, expected
  source/destination context, and an optional opaque payload token.
- Reply construction can explicitly copy identifier, sequence, and data from a
  parsed request, but no automatic responder is added.

### Quoted-datagram error foundation

Destination Unreachable, Time Exceeded, Parameter Problem, and Redirect carry an
original IPv4 datagram quote. The common quote utility:

- preserves the complete bounded quote bytes;
- validates IPv4 version, IHL, total length, fragmentation fields, protocol, and
  present payload prefix using checked offsets;
- accepts the historically required IPv4 header plus 64 payload bits while
  supporting longer modern quotes;
- represents an incomplete quote explicitly instead of reading absent fields;
- exposes enough correlation metadata for ICMP Echo: addresses, IPv4
  identification, protocol, fragment offset, and quoted ICMP identifier,
  sequence, and optional token prefix when present;
- separates quote validity from the outer ICMP checksum;
- recognizes the RFC 4884 original-datagram length and extension boundary,
  validates the extension header/object lengths and checksum when present, and
  preserves unknown extension objects as owned bytes. Decoding MPLS or other
  object-class semantics is future work.

The quote result reports its IPv4-header checksum independently when the full
header is present. Probe correlation requires IPv4 version 4, protocol ICMP, the
expected quoted destination, fragment offset zero, a quoted Echo Request header,
and matching identifier/sequence. A token is additionally required when enough
quoted payload contains it. A non-initial fragment or partial tuple never
matches merely because coincidental bytes resemble an ICMP header.

Canonical construction of any quoted ICMPv4 error is capped at 576 ICMP bytes,
matching the IPv4 minimum reassembly-buffer constraint used by RFC 1812 and
RFC 4884. Without extensions, a zero length attribute means that every remaining
octet is the original-datagram field. With compliant extensions, the sixth ICMP
octet contains a nonzero quote length in 32-bit words, the padded quote is at
least 128 octets, and the remaining bytes are exactly one extension header plus
one or more objects.

RFC 4884 parsing is compliant by default: a zero length attribute means no
extension, even if bytes at the historic fixed offset resemble one. An explicit
`legacyExtensions: true` parse option enables the RFC-required non-default
compatibility mode that probes for a version-2 extension header after an exact
128-byte quote and accepts it only when its checksum and complete object chain
validate. The mode and detected framing are exposed in the parsed result.

An extension object length is at least four octets, a multiple of four, and no
larger than the remaining extension bytes. Parsing is iterative, requires at
least one object, and is bounded by the 576-byte message ceiling. Unknown class/
type objects are retained. The extension checksum status is separately `valid`,
`invalid`, or `notProvided`; an all-zero transmitted checksum means
`notProvided`, while a nonzero checksum must validate before objects are
trusted.

Constructors require an explicit quote and do not generate an error in response
to traffic. Canonical construction requires a complete valid quoted IPv4 header
and at least `min(original total length, IHL + 8)` unpadded original bytes,
never accepts bytes beyond the quoted total length as original data, and adds
only the RFC 4884 zero padding needed for extended framing. Application policy
remains responsible for RFC rules about which datagrams may elicit ICMP errors.

### Destination Unreachable and Fragmentation Needed

- Type 3 supports registered codes 0 through 15 as named variants while
  preserving unknown future codes on parse.
- In the second word, octet 4 is unused, octet 5 is the RFC 4884 quote-length
  attribute, and octets 6–7 are the RFC 1191 `nextHopMtu` for code 4 or unused
  for other codes. Canonical non-extension encodings zero both unused/length
  octets; compliant extensions set octet 5 without overwriting the MTU.
- A zero MTU is preserved as “not supplied,” not guessed. Nonzero ignored bytes
  are validation issues on receive rather than unsafe parse failures.
- Semantic helpers classify terminal destination/port/protocol and
  administrative failures without claiming that receipt proves authenticity.

### Time Exceeded

- Type 11 supports code 0 (TTL exceeded in transit) and code 1 (fragment
  reassembly time exceeded).
- The second word is unused octet, RFC 4884 quote-length octet, and two unused
  octets. Canonical encoders zero unused bytes; compatible parsing preserves and
  reports them.
- Traceroute classification uses only code 0 as a hop response.

### Parameter Problem

- Type 12 exposes the pointer octet and currently registered code meanings.
- The second word is pointer, RFC 4884 quote-length octet, and two unused
  octets. Canonical encoders zero unused bytes; compatible parsing preserves and
  reports them.
- The pointer is preserved even if it identifies an unavailable part of a
  truncated quote; a semantic flag reports whether the referenced octet is
  present.

### Redirect

- Type 5 supports registered redirect codes and a checked IPv4 gateway address.
- Its gateway field and quoted original datagram are validated; RFC 4884
  extensions do not apply to Redirect.
- Parsing is informational only. No helper installs routes, mutates the Linux
  route cache, or describes an unverified gateway as trusted.

### Router Solicitation and Advertisement

- Type 10 solicitation requires code zero. Encoders write four reserved zero
  octets; receivers preserve and ignore nonzero values with a validation issue,
  as RFC 1256 requires.
- Type 9 advertisement requires code zero, at least one address, an address
  entry size of at least two 32-bit words, an unsigned 16-bit lifetime, and
  checked `numAddresses * entrySize * 4` arithmetic.
- Builders emit the standard two-word entry of IPv4 address plus signed 32-bit
  preference and accept at most 255 entries while respecting the total packet
  bound.
- Parsers preserve additional per-address words and trailing bytes for forward
  compatibility. The signed minimum preference retains RFC 1256's “not a
  default” meaning.
- Utilities do not maintain timers, select a default router, send periodic
  advertisements, or mutate host configuration. Any later discovery client or
  router daemon requires a separate policy/state-machine phase.
- For a Router Solicitation sent to `224.0.0.2` or an Advertisement sent to
  `224.0.0.1`, `sendIcmpMessage()` supplies TTL 1 by default and rejects a
  conflicting TTL or the other router-discovery multicast destination. It does
  not join multicast groups, choose an interface/source address, or enable
  broadcast automatically. Limited-broadcast sends remain possible and retain
  Linux's explicit `broadcast` socket-option requirement.
- Code 16 Router Advertisements are retained as the out-of-scope numeric code,
  not interpreted using RFC 1256 fields as though they were code zero.

### Timestamp Request and Reply

- Types 13 and 14 require code zero, unsigned 16-bit identifier and sequence,
  and three unsigned 32-bit timestamp fields. Canonical length is 20 octets;
  compatible parsing preserves longer checksum-covered trailing bytes.
- A canonical Timestamp Request builder accepts the originate timestamp and
  writes receive/transmit timestamps as zero. Compatible parsing preserves a
  request whose latter fields are nonzero and reports them; a Reply builder
  accepts all three times explicitly or copies the originate value from a parsed
  request while requiring explicit receive/transmit values.
- A timestamp helper classifies each raw value as `standard` milliseconds since
  midnight UTC (0 through 86,399,999), `nonStandard` (high bit set), or
  `invalidStandardRange` (above the standard range with the high bit clear).
  Parsers always preserve the raw 32-bit value and report the third form as a
  validation issue. Canonical builders accept only the first two forms.
- No wall-clock synchronization or accuracy claim is made. Reply construction is
  explicit and does not happen automatically.

### Address Mask Request and Reply

- Types 17 and 18 require code zero, unsigned 16-bit identifier and sequence,
  and one 32-bit IPv4 mask. Canonical length is 12 octets; compatible parsing
  preserves longer checksum-covered trailing bytes.
- A canonical Request builder writes the mask as zero. Compatible parsing
  preserves and reports a nonzero request mask; a Reply builder requires the
  explicit mask it is reporting.
- The parsed result exposes both the four-octet mask and dotted-decimal form,
  plus a semantic contiguous-mask check without rejecting a structurally valid
  non-contiguous wire value.
- Documentation labels these types deprecated by the current IANA registry.
  Utilities never apply the mask to an interface.
- Sending to a broadcast destination does not silently enable `SO_BROADCAST`,
  and constructing a reply does not assert that the caller is an authoritative
  mask agent.

## Traceroute contract

Phase 15 builds traceroute support from the Phase 12/13 public primitives. It
does not implement or encourage the deprecated ICMP type-30 experiment.

### Probe primitives

The public composition surface is planned around:

```ts
createIcmpTracerouteProbe(options): IcmpTracerouteProbe;
classifyIcmpTracerouteResponse(probe, received, receivedAt):
  IcmpTracerouteMatch;
traceIcmpRoute(socket, destination, options?): Promise<IcmpTracerouteResult>;
```

The builder requires explicit identifier, sequence, token, TTL, and monotonic
send time and is therefore deterministic. The classifier is pure. The
convenience function owns random defaults, bounded timers, and receive-lane
attachment. `received` is the structured result of `parseIcmpReceivedMessage()`,
not an unparsed `ReceivedMessage`; failures and incomplete results classify as
unmatched. `receivedAt` is a monotonic `bigint` from the same clock domain as
the probe send time. `destination` uses the existing `Ipv4MessageAddress` shape
and never triggers name resolution. Public wrappers require nonnegative `bigint`
send/receive times and reject a receive time earlier than its probe send time as
local invalid input; round-trip nanoseconds remain `bigint` and are never
narrowed to a JavaScript number.

- Build Echo Request probes with TTL values from 1 through 255.
- Use checked identifier/sequence fields plus a caller-supplied bounded token in
  the pure builder. `traceIcmpRoute()` uses `node:crypto` for a random session
  identifier/token unless the caller supplies deterministic values.
- Send TTL through `sendMessage()` ancillary control so parallel callers do not
  race on `IP_TTL`.
- Record a monotonic `process.hrtime.bigint()` send time; wall-clock time is not
  used for round-trip duration.
- Match Echo Replies directly and match Time Exceeded or Destination Unreachable
  responses through their quoted IPv4/ICMP prefix.
- Reject mismatched identifier, sequence, destination, protocol, and token
  rather than attributing unrelated traffic to a probe.
- Require the entire token in an Echo Reply. For an ICMP error quote, require
  the token whenever all token bytes are present; a historical
  eight-payload-octet quote can match only through the complete IPv4/ICMP tuple
  and is explicitly reported as a weaker match. NAT rewriting that tuple may
  make a legitimate response unmatched, which is safer than guessing.

### Response classification

The pure response classifier returns `matched: false` for unrelated packets or
one of these matched network responses:

- `hop`: valid Time Exceeded code 0 with responder and round-trip duration;
- `destination`: matching Echo Reply from the intended destination;
- `unreachable`: matching Destination Unreachable, preserving code and MTU;
- `parameterProblem` or `redirect`: strongly matched diagnostic response, not
  success.

Malformed, checksum-invalid, or only partially correlatable packets are not
attributed to a probe. The session counts them as ignored diagnostics without
retaining their packet bytes. `timeout` is a session-generated probe result, not
a received-response classification. External cancellation rejects the
`traceIcmpRoute()` promise with the existing `ERR_ABORTED` error after cleanup;
it is never represented as a fabricated packet or hop.

Destination detection requires a matching Echo Reply from the target. A
Destination Unreachable is diagnostic rather than proof of destination state;
the convenience stops on it by default but exposes `stopOnUnreachable: false`.
Time Exceeded from the target is still a hop response, not destination success.

### Bounded orchestration

The convenience traceroute operation accepts an existing dedicated ICMP socket
and has explicit options:

- `firstHop` 1 through 255, default 1;
- `maxHops` (the highest TTL to attempt) 1 through 255, default 30 and not less
  than `firstHop`;
- `probesPerHop` 1 through 10, default 3;
- `timeoutMilliseconds` 1 through 60,000 per probe, default 3,000;
- `overallTimeoutMilliseconds` 1 through 3,600,000, default 300,000;
- caller payload from 0 through 4,096 copied bytes; token from 1 through 64
  copied bytes, default 16; the encoded Echo data is the token followed by the
  caller payload and is therefore capped at 4,160 bytes;
- `maxInFlight` from 1 through `probesPerHop`, default 1 and never above 10;
- `stopOnUnreachable`, default true;
- optional `AbortSignal` and a synchronous progress callback.

Only one TTL is active at a time; `maxInFlight` applies within that hop. Each
probe receives a session-unique sequence number, matcher registration and a
monotonic deadline before send admission, and one settlement authority shared by
send failure, response, and timeout. Replies may arrive in any order, while
returned probes are sorted by hop and probe ordinal. A terminal destination or
default-terminal unreachable stops admission of later probes and cancels only
library timers/state; it cannot retract packets already sent.

Each probe deadline is the earlier of its per-probe deadline and the session's
overall deadline. A response is timely only when its captured monotonic receive
time is strictly earlier than both applicable deadlines; equality is a timeout,
so timer/message callback ordering cannot change the boundary rule. Overall
expiry synchronously stops new admission, settles every still-pending admitted
probe as a compact timeout attributed to the overall deadline, and returns the
`overallTimeout` termination after detach. A shorter overall timeout is valid
and intentionally overrides the per-probe value. Admission and every message
listener check the monotonic overall deadline before doing more work, so a flood
of unrelated ICMP cannot extend the logical session until a timer callback runs.

The result retains compact hop data only: probe ordinal, responder address,
round-trip nanoseconds, response kind/code, MTU, match strength, and selected
extension summaries. It never retains full Echo payloads, raw quoted packets, or
the original `ReceivedMessage` per probe. At most 2,550 probe results and small
ignored/invalid counters can be retained. The operation stops on destination,
configured terminal unreachable, overall timeout, cancellation, or `maxHops`. It
does not resolve DNS, geolocate hops, modify routes, retry forever, or maintain
a global identifier registry.

Successful resolution includes a termination discriminant of `destination`,
`unreachable`, `maxHops`, or `overallTimeout`. Individual silence is represented
by a probe `timeout`. External AbortSignal cancellation and local send/receive/
socket failures reject only after cleanup, preserving existing `RawSocketError`
codes where applicable.

The convenience operation installs and starts one internal
`RawSocketEventEmitter` to claim the normal receive lane for its complete
lifetime, then detaches it on success, failure, timeout, or cancellation so the
caller-owned socket remains open. Existing lane arbitration rejects an active
direct, batch, ring, or event receiver before traffic can be split. External
socket close remains terminal. For event-driven applications, public probe
builders and response classifiers can instead be fed from their own
`RawSocketEventEmitter`; the convenience operation does not wrap or compete with
an already active source.

Listeners for `message`, `error`, and `close` are installed before `start()`,
and the internal message listener remains synchronous. A receive/send failure
rejects the operation after quiescence; external socket close rejects with the
socket-closed outcome. A progress-callback exception is preserved as the
operation failure but cannot bypass cleanup. Deadline callbacks compare
`process.hrtime.bigint()` and rearm if an early timer fires. A terminal decision
inside the message listener begins `detach()` synchronously before the listener
returns so the event controller cannot admit another receive turn. Every
terminal path awaits that detach; an unexpected detach failure is never
swallowed and becomes the rejection when no earlier failure exists.

## Phase sequence

### Phase 12 — ICMPv4 foundation and Echo

Status: complete (2026-07-13)

Deliverables:

- finalize root exports, discriminated message types, constants, parse-result
  error/validation-issue shape, compatible/canonical policy, checksum policy,
  and the readonly captured-protocol getter;
- implement the non-mutating Internet checksum and bounded codec framework;
- implement one shared parse/validation engine plus root runtime-value wrappers
  without creating a root/codec import cycle;
- implement unknown-message preservation and received-IPv4 extraction;
- implement Echo Request/Reply construction, parsing, validation, correlation,
  one-operation send, and one-operation receive;
- document promise and event usage with explicit socket ownership;
- add golden vectors, malformed/truncated/checksum tests, declaration fixtures,
  and privileged IPv4 loopback Echo tests.

Exit gate:

- every offset/allocation is checked and all variable results are owned;
- checksum vectors and exhaustive short-input cases pass;
- Echo payloads round-trip at zero, odd, even, and maximum accepted lengths;
- malformed input produces a structured parse failure rather than an uncaught
  range exception;
- nonzero ignored fields and unknown codes follow compatible versus canonical
  policy without being confused with unsafe structural failure;
- promise and event examples operate over the existing API without a second
  receive engine;
- no runtime dependency or native code is added.

Implementation order:

1. Add public constants/types and internal neutral codec-result types, then add
   the captured readonly `RawSocket.protocol` field/getter and declaration
   fixture before any socket helper depends on it.
2. Implement and independently vector-test the checksum primitive, common header
   parser, checked reader/writer helpers, validation issues, and unknown/
   unknown-code ownership.
3. Add Echo construction/parsing/correlation and exhaustive short/arbitrary-byte
   tests while the work is still pure and privilege-free.
4. Add the Linux received-IPv4 adapter and root-facade argument normalization,
   then compose one-operation send/receive through authenticated socket
   internals without widening the low-level receive API.
5. Add declaration, event-composition, privileged loopback, README, consumer,
   stress, reproducibility, and artifact gates; only then mark Phase 12 complete
   and advance the release candidate.

### Phase 13 — ICMPv4 errors, quotes, and extensions

Status: planned; depends on Phase 12

Deliverables:

- implement the bounded quoted-IPv4 parser and Echo correlation extraction;
- implement Destination Unreachable and specialized Fragmentation Needed, Time
  Exceeded, Parameter Problem, and Redirect codecs;
- cover registered code constants and preserve unknown future codes safely;
- parse RFC 1191 next-hop MTU and the RFC 4884 extension envelope/unknown
  objects, including compliant length framing and explicit non-default legacy
  128-byte framing, without adding protocol-specific extension dependencies;
- add send/receive examples that make the non-automatic policy explicit;
- add generated malformed quote/extension cases and isolated crafted-packet
  integration tests.

Exit gate:

- no quote, IPv4 IHL, total length, extension length, or object count can cause
  unchecked arithmetic or out-of-bounds access;
- short historical quotes, longer quotes, fragments, options, truncation, and
  unknown extensions have deterministic results;
- all requested errors serialize to independently checked golden bytes and parse
  back losslessly for modeled fields;
- code-4 MTU zero/nonzero and reserved-field behavior match RFC 1191;
- RFC 4884 quote length, minimum quote, 576-byte ceiling, padding, extension
  checksum, object lengths, zero-length default, and legacy-mode cases pass;
- Redirect remains data only and cannot mutate host routing state.

### Phase 14 — Router discovery and legacy informational messages

Status: planned; depends on Phase 12 and reuses Phase 13 validation patterns

Deliverables:

- implement Router Solicitation and variable Router Advertisement codecs;
- implement Timestamp Request/Reply with standard/non-standard time semantics;
- implement deprecated Address Mask Request/Reply with mask helpers and clear
  documentation;
- add one-operation socket examples without automatic responders, discovery
  state, or host configuration changes;
- document and test multicast TTL/destination rules and explicit broadcast
  option requirements;
- add boundary tests for every counter, signed preference, lifetime, timestamp,
  address, reserved field, extension word, and total length.

Exit gate:

- router entry multiplication and slicing are overflow-safe and bounded;
- minimum/maximum entries, forward-compatible entry words, preference extremes,
  and lifetimes round-trip;
- timestamp parsers preserve every 32-bit value and classify standard,
  explicitly non-standard, and invalid-standard-range encodings; canonical
  builders reject the third form;
- canonical Timestamp and Address Mask Requests zero their reply-owned fields,
  while compatible parsers preserve/report nonzero received forms;
- mask parsing never silently applies or normalizes network configuration;
- README/API docs distinguish supported legacy wire formats from recommended
  modern configuration mechanisms.

### Phase 15 — ICMP traceroute utilities

Status: planned; depends on Phases 12 and 13

Deliverables:

- implement TTL-limited Echo probe construction and per-message send;
- implement strong direct/quoted response matching and response classification;
- implement a bounded cancellable ICMP traceroute convenience operation over a
  dedicated existing socket, with an internally attached/detached event source
  holding the receive claim for the session lifetime;
- expose the same builders/classifiers for event-driven consumers without adding
  an event queue or general async-iterator abstraction;
- add deterministic fake-clock/fake-socket tests for loss, reordering, duplicate
  replies, late replies, overall/probe timeouts, cancellation, identifier reuse,
  weak historical quotes, callback failures, and terminal outcomes;
- add a disposable multi-namespace or multi-router veth topology proving TTL 1,
  TTL 2, destination Echo Reply, unreachable, timeout, and cleanup behavior;
- document privileges, firewalls/rate limiting, asymmetric paths, load
  balancing, silent hops, and the fact that ICMP responses are unauthenticated.

Exit gate:

- no unrelated packet can complete a probe using only a type or sequence match;
- every timer, receive, send, and cancellation path settles once and cleans up;
- configured bounds cap probe/overall time, payloads, retained compact results,
  timers, and in-flight work;
- a three-node-or-greater isolated route reports ordered intermediate hops and
  the destination, while deterministic tests cover missing/reordered replies;
- traceroute conflicts with another normal-lane receiver predictably instead of
  splitting traffic;
- every terminal path detaches the internal event source and leaves the
  caller-owned socket open unless it was externally closed;
- all earlier quality, privileged, stress, consumer, and release gates remain
  green.

## Verification plan

### Ordinary tests

- independent golden packets for every requested type and code-specific layout;
- checksum vectors for empty/even/odd/max input, carry folding, input
  immutability, and checksum corruption;
- all byte lengths below every minimum, exact minimum, trailing bytes, and
  maximum accepted packet size;
- invalid runtime JavaScript types, NaN/infinities/fractions, signed/unsigned
  boundaries, and hostile accessors where relevant;
- deterministic randomized encode/parse round trips for valid modeled messages;
- randomized arbitrary-byte parsing with the invariant “structured result, no
  unexpected exception, bounded output”;
- compatible/canonical differential cases for ignored fields, wrong known codes,
  trailing bytes, unknown values, and all RFC 4884 framing modes;
- TypeScript declaration tests for narrowing every discriminated union and for
  rejecting invalid construction shapes;
- event-adapter tests that parse delivered `ReceivedMessage` objects without
  opening another receive lane.

### Privileged tests

- loopback Echo request/reply using the kernel ICMP path;
- raw crafted error and informational packets in a disposable namespace;
- veth/router topology for quotes, TTL expiry, next-hop MTU, and traceroute;
- Router Discovery multicast TTL/destination and broadcast-permission cases;
- descriptor/RSS baselines across repeated helper and traceroute cancellation;
- skips that state the missing capability/tool rather than treating absence as
  success.

### Review gates

- compare type/code values with the current IANA ICMP registry at implementation
  and release time;
- compare every wire layout and semantic validation rule with its governing RFC
  and applicable verified errata;
- run format, lint, typecheck, ordinary tests, privileged tests, Phase 11
  stress, hardening, consumer, reproducibility, and artifact verification after
  each public-surface release candidate change;
- keep AArch64 explicitly untested until native execution occurs.

## Explicit non-goals

- ICMPv6 codecs, Neighbor Discovery, Router Advertisement for IPv6, or IPv6
  traceroute in these phases;
- deprecated Source Quench, Information Request/Reply, or ICMP type-30
  Traceroute construction;
- automatic ping daemon, router-discovery daemon, route installation, redirect
  acceptance, address-mask application, or timestamp synchronization;
- UDP/TCP traceroute probe construction, DNS lookup, geolocation, command-line
  rendering, or terminal UI;
- interpreting all RFC 4884 extension object classes in the first slice;
- unbounded streams, async iterators, listener queues, automatic retries, or
  concurrency hidden from socket lane ownership;
- privilege acquisition, firewall changes, namespace creation in library code,
  or treating unauthenticated ICMP as authoritative policy.

## Risks and mitigations

| Risk                                             | Mitigation                                                                                  |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| IPv4 receive includes a header but send does not | Separate standalone ICMP and `ReceivedMessage` adapters; test IHL/options/truncation        |
| Malformed length fields cause slicing errors     | Check minimums and arithmetic before every read; structured failures; arbitrary-byte tests  |
| Mutable input changes parsed meaning             | Snapshot once before checksum/parse; copy result fields/output; exclude zero-copy initially |
| Checksum is claimed valid on truncated data      | Use explicit `unverifiable`; default complete-packet policy is `require`                    |
| Error quote cannot identify a probe              | Require all available tuple/token evidence and return unmatched rather than guessing        |
| Traceroute consumes another caller's packets     | Dedicated socket guidance and existing deterministic lane conflicts                         |
| Async listeners create unbounded work            | No transformed event queue; document pause/application-queue backpressure                   |
| Redirect/router advertisement is spoofed         | Parse as untrusted data only; never modify routes or default-router state                   |
| Legacy utilities imply recommendation            | Mark registry status in types/docs/examples and avoid automated application                 |
| Large router entries/extensions exhaust memory   | 65,515-byte ICMPv4 ceiling, checked counts/words, owned bounded copies                      |
| Timer/reply races settle twice                   | One probe settlement authority, monotonic deadlines, deterministic race tests               |
| Protocol registry evolves                        | Named current constants plus numeric unknown preservation and release-time registry review  |

## Primary references

Reviewed on 2026-07-13:

- [IANA ICMP Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
- [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792.html)
- [RFC 950 — Internet Standard Subnetting Procedure](https://www.rfc-editor.org/rfc/rfc950.html)
- [RFC 1071 — Computing the Internet Checksum](https://www.rfc-editor.org/rfc/rfc1071.html)
- [RFC 1122 — Requirements for Internet Hosts](https://www.rfc-editor.org/rfc/rfc1122.html)
- [RFC 1191 — Path MTU Discovery](https://www.rfc-editor.org/rfc/rfc1191.html)
- [RFC 1256 — ICMP Router Discovery Messages](https://www.rfc-editor.org/rfc/rfc1256.html)
- [RFC 1812 — Requirements for IPv4 Routers](https://www.rfc-editor.org/rfc/rfc1812.html)
- [RFC 4884 — Extended ICMP to Support Multi-Part Messages](https://www.rfc-editor.org/rfc/rfc4884.html)
- [RFC 6633 — Deprecation of ICMP Source Quench](https://www.rfc-editor.org/rfc/rfc6633.html)
- [RFC 6918 — Deprecation of several ICMP extensions](https://www.rfc-editor.org/rfc/rfc6918.html)
- [Linux `raw(7)` — raw IPv4 socket semantics](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Linux `ip(7)` — IPv4 socket and broadcast semantics](https://man7.org/linux/man-pages/man7/ip.7.html)

The experimental RFC 1393 ICMP Traceroute message is deliberately not the
traceroute mechanism planned here. Phase 15 uses conventional increasing-TTL
Echo probes, Time Exceeded responses, and matching Echo Replies.
