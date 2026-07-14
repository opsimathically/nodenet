# Phase 12–15 implementation audit

Status: complete; identified defects corrected and regression-tested

Completed: 2026-07-13

Release candidate: `0.1.0-rc.6` (unpublished)

## Objective

This post-implementation audit adversarially reviewed the complete ICMPv4 and
traceroute sequence against D-029 and the accepted Phase 12–15 plan. It checked
wire layouts and registry values against the governing RFCs and current IANA
registry, reconstructed every public hostile-input boundary, audited ownership
and allocation bounds, and walked traceroute matching, deadlines, callback
failure, cancellation, lane release, and caller-socket reuse.

The audit covered the pure TypeScript codecs, root exports and socket helpers,
event composition, deterministic scheduler, declarations, documentation,
ordinary and privileged tests, stress harnesses, clean-consumer packaging,
artifact policy, and reproducibility. No Rust or native I/O change was needed.

## Corrected findings

### A12-15-1 — Hostile byte and array lengths could weaken allocation bounds

Severity: defensive boundary/resource safety; high

Several codec paths checked `Uint8Array.byteLength` before copying the bytes.
JavaScript permits an instance property to shadow that accessor, so an
adversarial typed array could report a small length during validation while
`Buffer.from()` copied its full backing view. This did not create native memory
unsafety, but it could bypass the intended protocol allocation ceilings.
Likewise, an array proxy could report a negative or fractional count instead of
an ordinary array's nonnegative integer length.

Correction: byte inputs now obtain their real length through the captured
intrinsic typed-array accessor, enforce the relevant bound, and copy exactly
once into owned storage. Checksum, Echo, diagnostic quote, extension, received
frame, correlation, and traceroute token/payload paths share this rule. Bounded
array consumers capture one count and require the correct safe-integer range
before arithmetic or iteration. Regressions use typed arrays with misleading own
`byteLength` properties and array proxies with invalid counts, then prove
rejection or structured parse failure at the true boundary.

### A12-15-2 — Mutable send controls could change after ICMP policy validation

Severity: correctness/policy enforcement; high

`sendIcmpMessage()` inspected caller-owned destinations, flags, and control
messages and then forwarded the same objects to `RawSocket.sendMessage()`.
Stateful getters or proxies could therefore present Router Discovery multicast
TTL 1 during the ICMP policy check and a different value during the underlying
send validation.

Correction: the helper now snapshots the IPv4 destination, flag array, control
array, and each supported control field into plain owned values before policy
checks. Counts and getters are observed once. A privileged packet-capture
regression uses stateful proxies and proves that the transmitted Router
Solicitation still has TTL 1.

### A12-15-3 — Overall timeout could call progress again after callback failure

Severity: callback/lifecycle semantics; medium

An overall timeout records every pending probe so the final bounded result is
complete. If the first `onProgress` call threw, the original loop correctly
retained the failure but still invoked the callback for later pending probes.
That violated callback quiescence after the first terminal local failure.

Correction: result retention continues through overall-timeout settlement, but
progress delivery stops immediately once a failure is recorded. A deterministic
two-probe test proves exact thrown-object rejection, one callback invocation,
and completed event-source detachment.

### A12-15-4 — Forged classifier extension lists were not independently bounded

Severity: defensive boundary/resource safety; medium

Legitimate Phase 13 parse results can contain at most 142 RFC 4884 extension
objects, but the public traceroute classifier also accepts ordinary JavaScript
objects at runtime. Its compact-summary step previously trusted the nominal
parsed type and mapped any supplied list, allowing a forged result to request an
unbounded allocation.

Correction: classifier summaries capture the list count once, enforce the
142-object wire-derived ceiling, validate class/type octets, and snapshot each
data field under the 576-byte extension ceiling. Invalid forged results become
stable `ERR_INVALID_ARGUMENT` errors. Focused regression coverage exercises the
oversized public-boundary case.

## Protocol and lifecycle conclusions

The reviewed encoders produce canonical ICMPv4 Echo, diagnostic error, Router
Discovery, Timestamp, and Address Mask layouts. Compatible parsers preserve
unknown codes and bounded trailing/extension data while distinguishing
truncation, checksum failure, and noncanonical fields. RFC 4884's length and
padding rules remain separate from explicit legacy framing, and RFC 1191's
zero-MTU semantics are preserved.

Traceroute requires complete direct Echo evidence and checked strong or
historically limited weak quoted evidence. Exact deadline equality remains a
timeout, result retention is capped at 2,550, in-flight work is bounded, and
every success, timeout, cancellation, callback failure, socket failure, and
detach failure follows cleanup-before-settlement. The caller-owned socket is not
closed by the trace.

## Final verification

The audited implementation passes on x86-64 Linux with Node 26.4.0, npm 11.17.0,
and Rust 1.97.0:

- `npm run ci`: Prettier, ESLint, strict TypeScript, Rust formatting, Clippy, 38
  Rust tests, declaration fixtures, 89 ordinary Node tests (74 passed and 15
  privileged tests skipped by design), dependency audit, and release-policy
  verification passed;
- focused Phase 12–15 tests: 37 of 37 passed;
- focused built-in coverage measured the protocol internals at 89.25% line,
  81.45% branch, and 97.87% function coverage, and traceroute internals at
  91.36% line, 79.01% branch, and 95.65% function coverage; privileged wire
  paths supplement the syscall-free suite rather than inflating these figures;
- isolated privileged Node 26 namespace: 15 of 15 passed, including real Echo,
  crafted extensions, Router Discovery policy, and routed traceroute behavior;
- Phase 9 ring, Phase 11 event, and Phase 15 traceroute stress: 256 iterations
  each, descriptors 21 before/after, with RSS deltas of 1,146,880, 7,348,224,
  and 5,750,784 bytes respectively;
- clean ESM and synchronous `require()` consumer packaging passed for the x86-64
  target package;
- the optimized x86-64 ELF passed the glibc 2.28 ceiling with 2.16 as its
  highest required symbol version; and
- two clean optimized builds produced the identical SHA-256
  `d016f2ae122e012f6f949a4ba3da33fb26cecf283d061567557b5565f3d24d67`.

`git diff --check` also passed. Nothing was published.

## Health conclusion

No known Phase 12–15 wire-format, allocation-bound, ownership, matching,
scheduler, cleanup, API-shape, or x86-64 integration defect remains after these
corrections. The implementation still adds no runtime dependency, native I/O
path, hidden receive queue, or host network-policy mutation.

Native AArch64/ARM64 execution remains untested and is the outstanding platform
verification caveat. The deprecated message families remain intentionally
available as codecs, not as recommended host configuration mechanisms.
