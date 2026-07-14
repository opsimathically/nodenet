# Phase 13 completion report

Status: complete

Completed: 2026-07-13

Release candidate: `0.1.0-rc.4` (unpublished)

## Outcome

Phase 13 implements the accepted ICMPv4 diagnostic-error, quoted-datagram, and
extension scope in strict TypeScript over the existing Phase 12 codec and raw
socket helpers. It adds no runtime dependency, native I/O path, hidden receive
loop, automatic ICMP response, Redirect acceptance, or route mutation.

The root API now constructs, encodes, parses, validates, sends, and receives:

- Destination Unreachable with registered codes 0 through 15, including RFC 1191
  Fragmentation Needed and its exact zero/nonzero next-hop MTU;
- Time Exceeded codes 0 and 1;
- Parameter Problem codes 0 through 2 with the pointer and whether the quoted
  octet is present;
- Redirect codes 0 through 3 with a checked IPv4 gateway address; and
- unknown future codes as bounded owned `unknownCode` bodies rather than known
  semantic variants.

All accepted type/code values have readable root-exported constants. The
`classifyIcmpDestinationUnreachable()` helper returns informational categories
without elevating received ICMP to trusted policy.

## Quoted-datagram safety and correlation

The shared quote parser owns its input and checks IPv4 version, IHL, options,
total length, fragmentation, protocol, header checksum, available bytes, and the
required IPv4-header-plus-eight-payload prefix. It represents incomplete quotes
without reading absent data and reports malformed quote facts as error issues
separate from the outer ICMP checksum.

For initial ICMP fragments it extracts only the bounded prefix actually present.
`matchIcmpEchoQuote()` requires a valid quote, expected destination, ICMP
protocol, initial fragment, Echo Request type/code, identifier, sequence, and
every available token octet. It reports a strong match only when the entire
token is present and a weak match when a valid historical short quote cannot
carry it. Non-initial fragments and mismatched partial evidence do not match.

Constructors accept only a valid IPv4 quote with a complete header checksum and
at least `min(totalLength, IHL + 8)` original octets. They reject bytes beyond
the IPv4 total length and snapshot caller-owned bytes before encoding.

## RFC 4884 extensions

Canonical construction and parsing implement the reviewed multi-part framing:

- the sixth ICMP octet carries the padded quote length in 32-bit words;
- the original datagram is at least 128 bytes when an extension is present and
  is zero-padded to a word boundary;
- extended ICMPv4 errors are capped at exactly 576 bytes;
- extension version 2, reserved bits, optional checksum, and every object length
  are checked before object data is exposed;
- objects are at least four bytes, word-aligned, bounded by the remaining
  structure, and preserved as owned class/type/data values;
- a nonzero invalid extension checksum marks the packet invalid and withholds
  parsed objects while retaining bounded raw evidence; and
- default zero-length parsing means no extension. Explicit
  `legacyExtensions: true` recognizes only the historical valid-checksum
  Destination Unreachable/Time Exceeded form after an exact 128-byte quote.

Redirect rejects extension construction and remains informational data only.

## Tests and verification

Ordinary ICMP tests independently generate checksums and IPv4 quotes rather than
sharing codec internals. They cover every registered accepted code, golden wire
bytes, MTU zero and 1500, IPv4 options, fragments, short and complete quotes,
invalid quote checksums, owned input/output, strong and weak matching, unknown
codes/objects, compliant and legacy framing, zero/nonzero/invalid extension
checksums, padding, invalid object lengths, exact 576-byte success,
577-byte/constructor overflow rejection, arbitrary-byte parsing, and public
declaration narrowing.

The following gates passed on x86-64 Linux:

- `npm run ci`: Prettier, ESLint, strict TypeScript, Rust formatting, Clippy, 38
  Rust tests, 68 ordinary Node tests (55 passed and 13 privileged tests skipped
  by design), and dependency/release-policy verification;
- isolated privileged Docker namespace: all 13 tests passed, including a crafted
  loopback Fragmentation Needed packet with an RFC 4884 unknown object that was
  received, parsed, checksum-validated, and strongly correlated;
- Phase 11 event stress: 256 iterations with four lifecycle cycles each, stable
  descriptor count 21, and bounded RSS growth;
- Phase 9 packet-ring stress: 256 iterations, stable descriptor count 21, and
  bounded RSS growth;
- `npm run release:consumer-test`: optimized x86-64 artifact, glibc requirement
  no higher than 2.16, scoped target-package selection, clean ESM import,
  CommonJS `require()`, and private-subpath rejection passed; and
- `npm run release:reproducibility`: two clean optimized builds produced the
  identical SHA-256
  `84d1ddf1dacc1640fa3ec114e6cb678a3c8b82c4dddfc860f7926b74a57ffea0`.

The release plumbing was also aligned with the scoped
`@opsimathically/nodenetraw` package name, including self-import fixtures,
platform package manifests, loader-compatible optional dependencies, tarball
consumer paths, and release policy. Nothing was published.

## Remaining work

Phase 14 is next: Router Solicitation/Advertisement, Timestamp Request/Reply,
and deprecated Address Mask Request/Reply under the already reviewed bounds and
non-automatic policy. Phase 15 remains the bounded conventional ICMP Echo
traceroute composition.

AArch64/ARM64 remains an intended but untested target. No native AArch64
execution claim is made by this phase.
