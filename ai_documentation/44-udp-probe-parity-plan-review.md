# UDP protocol-probe parity plan review

Status: closed; Phase 27 is ready to implement  
Date: 2026-07-14  
Reviewed plan: `43-udp-probe-parity-plan.md`  
Implementation changed: no

## Outcome

The Phase 27–33 roadmap is coherent with the implemented scanner and is ready
for sequential implementation. The review found and corrected material gaps in
the original Phase 27–32 draft; readiness is based on the corrected plan, not on
the earlier wording.

The binding corrections are:

1. profile breadth and network-impact consent are separate;
2. one public UDP definition owns a per-port variant programme;
3. empty fallback, strategy, intensity, retry, and progress meanings are exact;
4. logical result IDs and physical wire IDs/capacity are separate;
5. result reservation is bounded by rows and variable bytes;
6. schema 2 has an explicit additive binary layout and schema-1 decoder path;
7. family/type/code/origin ICMP detail survives until state classification;
8. fixed-source behavior never claims external host-port ownership;
9. project provenance and Nmap comparison use separate ledgers; and
10. protocol breadth is split into reviewable Phases 29–31, moving adaptive
    policy to Phase 32 and final audit/release to Phase 33;
11. decisive evidence stops sends but waits in bounded settlement before a
    still-live variant can change the serialized winner; and
12. specification-defined alternate-port handshakes are distinct from arbitrary
    weak cross-port tuple matching.

No implementation code was written or changed by this review.

## Evidence inspected

### Current project

- `packages/nodenetscanner/src/index.ts`: public plan snapshotting, one optional
  UDP payload, result schema-1 decoder, transfer semantics, and control bounds;
- `crates/nodenetscanner-engine/src/plan.rs`: exactly one definition per probe
  family and lazy target/family/port product;
- `crates/nodenetscanner-engine/src/types.rs` and `scheduler.rs`: one shared
  logical/wire ID, `u8` transmissions, logical outstanding capacity, current
  state classification, result reservation, retries, and lifecycle paths;
- `crates/nodenetscanner-native/src/model.rs`: last-payload-per-family native
  storage, four-session source-port partitioning, retry and template admission;
- `crates/nodenetscanner-native/src/wire.rs`: unconditional 16-byte UDP token,
  tuple response matching, code-collapsed ICMP evidence, route/grace ownership,
  and packet construction;
- `crates/nodenetscanner-native/src/session.rs`: row-only result reservations,
  262,144-row queue ceiling, schema-1 sealing, 4,096-row pulls, and reason-byte
  metadata; and
- the Phase 24/25 reports, D-038/D-039, current architecture, safety, testing,
  and release constraints.

### Frozen Nmap reference

The local source at `/home/tourist/nmap_source/nmap`, commit
`10dfd2ff1cef6c1925232db45352149b659979b4`, was rechecked:

- `payload.cc` builds a destination-port map from payload-eligible UDP service
  probes, permits several payloads per port, supplies one empty datagram when no
  payload maps, and later tries mapped matchers/fallbacks against retained
  responses;
- `scan_engine_raw.cc` sends every mapped payload for one logical probe using
  the same source port, repeats the set on retry, matches direct UDP by reversed
  tuple, stores early response bytes, and classifies quoted ICMP;
- `scan_engine.cc` defaults UDP silence to `open|filtered` unless its optional
  ICMP-rate-limit shortcut is selected; and
- `LICENSE` expressly identifies reading or including `nmap-service-probes`,
  purpose-built execution/output parsing, and helpers as derivative-work cases
  under the NPSL.

The project may use those facts for a behavioral comparison. It may not make
Nmap source/data a catalogue, build, test, runtime, or distributed audit-tool
input. This is an engineering policy, not legal advice.

## Closed findings

### F-01 — Provenance and comparison ledgers were conflated

The earlier Phase 30 text required a repository ledger for every frozen
reference class while also prohibiting generation from Nmap data. Those
requirements could conflict.

Resolution: the repository capability/provenance ledger contains only project
IDs derived from primary specifications, registries, permissive documentation,
and permissioned fixtures. Any reference-to-project mapping remains an
owner-controlled, non-distributed Phase 33 audit worksheet. Repository reports
may contain aggregate outcomes and project-owned identifiers, never imported
Nmap payloads, fingerprints, port maps, or a generated derivative catalogue.

### F-02 — Profile selection could accidentally authorize risky traffic

The original `safe | comprehensive | legacy` shape did not prove that selecting
legacy breadth was distinct from consenting to amplification, state, fixed
source ports, multicast/broadcast, authentication attempts, or sensitive reads.

Resolution: profiles select catalogue breadth only. Every risky built-in has
explicit risk flags, and every flag must be present in the separately
snapshotted `allowRisks` set. Unknown and duplicate risk values fail admission.
No built-in profile may write configuration, send destructive/exploit payloads,
brute-force credentials, or extract arbitrary user data. Exact custom mode is
low-level caller-authored traffic and is never labelled catalogue-safe.

### F-03 — Public UDP normalization and fallback were ambiguous

The engine already rejects duplicate family definitions, but the earlier plan
could be read as enabling multiple overlapping UDP entries. A boolean empty
fallback also failed to distinguish Nmap-style unmapped fallback from an extra
empty probe after mapped variants.

Resolution: a plan contains exactly one UDP definition. Catalogue variants live
inside that definition's per-port programme; one custom payload applies to all
its selected ports. Duplicate UDP entries remain invalid. Empty fallback is
`unmapped`, `afterProtocol`, or `never`; omitted means `unmapped`. Profile,
intensity, strategy, risk, family compatibility, and fallback are canonicalized
once before native admission.

### F-04 — Physical capacity was not tied to `maxOutstanding`

Four concurrent variants for one endpoint could otherwise consume four source
ports and grace entries while appearing as one outstanding item.

Resolution: `rate.maxOutstanding` counts active physical subprobes awaiting
evidence. One endpoint using four concurrent variants consumes four slots. Grace
retains its separate hard bound. Active and grace leases share the
collision-free source-port lanes in each four-way session partition, and new
work defers rather than reusing a lane still in grace. `timing.retries` applies
per variant, and admission checks `variants × (retries + 1)` with checked
arithmetic without materializing the product.

Logical `attempt` retains its existing meaning. Result `transmissions` counts
the endpoint's UDP datagrams and widens to `u32`; global `progress.sent` counts
all rate-charged frames, including shared neighbor setup and cleanup.

### F-05 — Variable service metadata lacked lossless backpressure bounds

The current queue reserves one row only. A 1 KiB service sidecar multiplied by
262,144 queued rows would bypass the intended reservation invariant, and 4,096
maximal rows plus reasons can exceed a 4 MiB batch.

Resolution: reservation is two-dimensional. Before first transmission, an
endpoint reserves one row and its catalogue-declared maximum winning-metadata
bytes. Unused bytes are released on commit; every losing, late, malformed,
cancelled, faulted, and teardown path releases its reservation. Service metadata
is capped at 1 KiB per result, 16 MiB queued per session, and 64 MiB across four
sessions. The sealer returns fewer than `maxResults` when needed to keep all
variable columns within the existing 4 MiB batch aggregate.

### F-06 — Schema-2 compatibility was descriptive, not executable

Resolution: schema 2 retains every schema-1 column and meaning. The existing
little-endian `u32` transmissions column carries the widened count. Additive
columns carry terminal UDP probe ID, variants attempted, response kind, service
family, service confidence, and deterministic length-prefixed service metadata
with stable numeric extra-field identifiers. The existing metadata column
continues to carry terminal reason.

The TypeScript boundary is an explicit schema-1/schema-2 encoded union. Version
1 rejects version-2-only columns; version 2 requires and validates every new
column and offset. Retained schema-1 fixtures, hostile schema-2 buffers,
transfer/detachment, and lazy views are required. Phase 27 freezes the binary
layout; Phase 29 begins native emission; Phase 32 freezes ergonomic public names
without changing that layout.

### F-07 — ICMP evidence lost information required for parity

The current native path reduces ICMP response meaning too early. Address family,
type, code, whether the emitter is the target, and quote strength are all needed
to distinguish closed, filtered, open, and diagnostic-only outcomes.

Resolution: those fields remain in compact evidence until engine policy applies
the frozen matrix. In particular, target-originated IPv4 type 3/code 3 and IPv6
type 1/code 4 establish `closed`; intermediate port-unreachable is `filtered`;
recognized unreachable/time-exceeded cases are `filtered`; correlated IPv6
Parameter Problem code 0 establishes `open`; code 1 is `filtered`; unknown or
insufficient diagnostics do not change state. Silence remains conservative
`open|filtered`; `closed|filtered` is not added.

### F-08 — Safe-pack breadth was too large and mixed incompatible risks

The original Phase 29 grouped low-impact discovery, multicast discovery,
credential-like SNMPv1, sensitive statistics, stateful handshakes, fixed-source
DHCP, and cryptographic protocols into one implementation gate.

Resolution: Phase 29 owns a small safe core. Phase 30 owns extended standards
and proves risk enforcement. Phase 31 owns comprehensive/legacy breadth and the
project capability ledger. TFTP requires sensitive-read consent; SNMPv1, NetBIOS
node status, memcached statistics, DHCP, multicast discovery, and handshake
protocols are not silently safe. Reviewed exact-pinned dependencies are used
where cryptography is necessary; no homegrown cryptographic primitive is
accepted.

### F-09 — Fixed-source ownership promise was too strong

A raw sender can partition the module's own ports but cannot prove race-free
ownership against every unrelated host process.

Resolution: module-internal four-session collision isolation is mandatory.
Fixed-source variants also require explicit consent and an operator-controlled
host/namespace policy, or are rejected. Documentation never claims the scanner
has bound, reserved, or proven exclusive external ownership of that port.

### F-10 — Receive amplification needed work budgets, not only size bounds

Resolution: retain the current maximum of 128 received datagrams per runtime
tick, cap typed parsing at 4 MiB per session and 256 KiB per target per tick,
and keep timers/cancellation/control live when those budgets are exhausted.
Excess traffic may receive bounded tuple classification and counters but no
service metadata parsing. Parser input remains one complete datagram; these
phases add no IP-fragment or application-message reassembly.

### F-11 — Early terminalization could violate arrival-order independence

A close/filter response from one variant cannot be emitted while another
already-sent variant can still produce stronger direct-open evidence. Likewise,
sealing the first service response can make product metadata depend on receive
order.

Resolution: decisive evidence stops unsent work but moves the logical endpoint
into a bounded settling state. Its row/byte reservation remains held until all
emitted variants can no longer change a serialized field or dominance proves
that later evidence is irrelevant. Winners are ordered by state strength,
service confidence, and lowest stable catalogue probe ID; duplicate evidence
keeps the minimum valid RTT. Settlement, cancel, fault, and grace paths are
explicit Phase 28 matrices.

### F-12 — TFTP-style alternate ports lack an echoed transaction token

Requiring every alternate-port response to echo a strong transaction field would
make specification-correct TFTP discovery impossible, while allowing an
arbitrary same-target source port on tuple evidence would be too weak.

Resolution: alternate ports are admitted either by a returned protocol
transaction field or by a catalogue-declared first-response port-selection
handshake. The latter requires an exclusive local lane, same target, strict
initial server-role parsing, active-window timing, and pinning the first
accepted server port for the rest of the exchange. It has its own lower evidence
category and never claims secret-token strength. Arbitrary tuple-only cross-port
matching remains forbidden.

## Readiness questions closed

1. **NPSL separation:** yes, through the two-ledger rule, clean-clone tests, and
   prohibition on Nmap-derived project inputs or distributed comparison tools.
2. **Logical/physical accounting:** yes, one endpoint result, unique wire IDs,
   physical `maxOutstanding`, per-variant retries, and distinct result/global
   transmission meanings are frozen.
3. **Correlation safety:** yes, source-port lanes key physical IDs through late
   grace; alternate response ports require either a returned transaction field
   or a specification-declared, strictly parsed first-response handshake;
   arbitrary tuple-only cross-port matches are forbidden.
4. **Schema compatibility:** yes, schema 2 is additive, schema 1 retains its
   exact meanings, and both have explicit validation paths.
5. **Custom compatibility:** yes, exact custom bytes are unchanged;
   `prefixToken` is explicit; the old top-level payload maps only to the
   deprecated compatibility path and conflicts with policy.
6. **Network impact:** yes, native admission enforces independent risk consent,
   target/rate/response bounds, and protocol prerequisites.
7. **Catalogue/signature bounds:** yes, deterministic generation, stable IDs,
   finite exact/prefix/masked matching, numeric extraction identifiers, fuzzing,
   and no regex/backtracking/arbitrary callbacks are required.
8. **Parity honesty:** yes, payload/state behavior, project service evidence,
   and full service/version fingerprinting are separate claims; project and
   reference ledgers are separate.
9. **Independent responders:** yes, every accepted family needs a disposable
   dual-stack responder/fixture derived independently of Nmap or Internet
   services; a family without one cannot pass its phase.
10. **Migration/release:** yes, the scanner is unpublished, explicit
    empty/custom behavior remains, the old payload spelling has a bounded
    deprecation path, schema-1 fixtures decode, and the material default/schema
    change advances only at Phase 33 to `0.2.0-rc.1`.

## Phase 27 implementation boundary

Phase 27 may now begin. It must stop at infrastructure and compatibility:

- catalogue descriptor/provenance/risk types and deterministic checker;
- exact request plans and checked dynamic patch fields;
- one-UDP-definition policy normalization and legacy conflict handling;
- exact custom and explicit prefix-token capture behavior;
- logical/wire ID type foundations without multi-variant live scheduling;
- frozen schema-2 encoded types/decoder validation while native emission remains
  schema 1; and
- capability catalogue version/hash metadata.

Phase 27 must not add the safe protocol pack, change omitted UDP behavior to
protocol mode, claim parity, or expose a partially bounded live multi-variant
path. Those belong to later gates.

## Final readiness decision

No unresolved design blocker remains for Phase 27. Each later phase has a single
dominant concern and a blocking exit gate:

| Phase | Dominant concern                                      |
| ----- | ----------------------------------------------------- |
| 27    | catalogue/API/provenance/schema foundations           |
| 28    | physical scheduling/correlation/aggregation/resources |
| 29    | low-impact safe core and schema-2 emission            |
| 30    | extended standards and explicit-risk enforcement      |
| 31    | comprehensive/legacy breadth and project ledger       |
| 32    | adaptive evidence and public API/view freeze          |
| 33    | external parity audit, hardening, docs, release       |

Any implementation discovery that invalidates a frozen bound, correlation rule,
schema column, provenance boundary, or network-impact rule reopens this review
before dependent work proceeds.
