# UDP coverage expansion readiness review

Last updated: 2026-07-15

Scope: Phases 59 through 69 and D-057

Status: closed; Phase 59 may proceed with the binding corrections below

## Outcome

The Phase 59–69 plan is implementable without changing the scanner's ownership
model or importing third-party scanner data. The existing target/port catalogue,
finite discovery registry, schema-2 physical-subprobe accounting, evidence
schema, derived-work authority, and native/TypeScript parity checks are the
correct foundations.

The review found that support must not be measured by candidate count. Several
planned families lack a stable public wire contract, cross authentication or
target-mutation boundaries, or cannot provide useful correlated evidence. The
phase gates already allow those candidates to close as executable no-go or
excluded outcomes.

## Existing capability reconciliation

- ASF/RMCP Presence Ping is already implemented as catalogue probe 7 with tag
  correlation, strict parsing, an independent responder, and safe-profile
  admission. Phase 60 must preserve and credit that implementation rather than
  add a duplicate payload.
- RIPv2 table discovery is catalogue probe 23. RIPv1 requires a distinct
  descriptor, parser, risk record, and service-family identity because its
  version and route-entry semantics differ.
- Source-engine query support is catalogue probe 25. Quake 2 and Quake 3 remain
  distinct wire families and may not be claimed through that implementation.
- BitTorrent BEP 5 ping is catalogue probe 30. It does not establish Vuze or
  eDonkey/eMule wire compatibility.
- The current capability ledger covers every compiled target/port and discovery
  implementation and already blocks ten authentication/proprietary candidates.
  Phase 59 adds a separate roadmap-candidate registry rather than weakening that
  exact implementation ledger.

## Binding corrections

### R-059-01 — Canonical coverage registry

Add one Rust-owned, versioned candidate registry exported through N-API. The
TypeScript surface consumes the native registry and freezes hostile-boundary
copies; it does not duplicate candidate rows. Each row contains a stable ID,
phase, family, disposition, execution model, policy, risk classes, primary
source, decision rationale, optional compiled implementation, and separate
request/correlation/typed-evidence/responder/fingerprint dimensions.

### R-059-02 — Final dispositions are executable

`implemented` must resolve to a real catalogue or discovery ID and demonstrate
request, correlation, typed parsing, and responder dimensions. `noGo` and
`excluded` must not resolve to runtime work. Excluded entries require a threat
or mutation boundary and cannot appear in an active profile.

### R-059-03 — Additive catalogue release

New target/port probes append after ID 33. Catalogue `1.4.0` is additive: scan
schemas 1/2, IDs 1–33, the nine-entry safe profile, and default exhaustive safe
behavior remain unchanged. New variants are comprehensive or legacy opt-in and
are independently rate/resource charged.

### R-059-04 — Candidate-level admission

The following exchanges have adequate primary-source and safety foundations for
implementation in this pass:

- existing ASF/RMCP presence;
- RIPv1 explicit-target table request;
- Quake 2 status;
- Quake 3 challenge-correlated info; and
- Mumble legacy extended UDP ping.

RIPv1, Quake 2, and Mumble disclose operational metadata and/or can amplify;
they require explicit risks. Quake 3 uses the source protocol's challenge echo
for stronger correlation. No new variant enters the safe profile.

### R-059-05 — No-go is not partial support

Remote management, proprietary database, industrial, voice, DHT, and legacy
enterprise candidates without an authoritative public wire contract remain named
no-go entries. Existing cryptographic/authentication blockers receive dated
reassessment rows but no fabricated identity or incomplete handshake. Backdoor
and command-and-control signatures are `excluded`, not `noGo`, and are provably
absent from active registries.

### R-059-06 — Resource contract

Freeze one registry-level resource contract: at most 64 candidate rows, 256
compiled target/port variants, 1,024 physical queries per finite operation,
4,096 bytes per newly admitted response, 64 KiB typed metadata, 1,024 returned
endpoints, and 60 seconds of state lifetime. Individual descriptors must be
strictly narrower. Admission continues reserving all physical subprobes before
I/O under the existing environment ceilings.

### R-059-07 — Provenance boundary

The shipped registry, catalogue, fixtures, and reports contain project IDs and
primary sources only. The pinned Nmap checkout remains a human-operated external
comparison input and is never a build, generator, fixture, test, or runtime
dependency. A source-tree check fails on prohibited comparison paths or names in
the shippable registries.

## Primary-source decisions

- ASF/RMCP remains based on DMTF DSP0136.
- RIPv1 uses RFC 1058 request/response and strict version-1 reserved-field
  behavior.
- Quake 2 uses Yamagi Quake II commit
  `3046d9b26d2969b449c3462a8fd2fdcf9be97792`, whose server accepts an
  out-of-band `status` command and returns an out-of-band `print` status.
- Quake 3 uses id Software commit `dbe4ddb10315479fc00086f08e25d968b4b43c49`,
  whose `getinfo` response echoes a caller challenge and returns bounded server
  information.
- Mumble uses upstream commit `6fd92e3a6622d79f6914e098ccb0aba34802898d`, whose
  legacy extended UDP ping echoes the opaque timestamp and adds version, user
  counts, and bandwidth.

Source implementations were inspected to establish behavior only. Shipped Rust
code and fixtures are independently authored and contain no copied source
fragments.

## Required verification

Phase 69 must demonstrate:

- registry validation, native/TypeScript parity, immutability, and hostile N-API
  boundary handling;
- request vectors and strict positive/negative parsers for every new variant;
- wrong challenge/timestamp, truncation, oversize, delimiter, route-count,
  metric, and reserved-field rejection;
- project-owned IPv4/IPv6 responders where the protocol supports both;
- policy rejection before I/O when required risks are absent;
- safe-profile count and behavior invariance;
- catalogue hash, release policy, consumer, and documentation parity; and
- all available ordinary, namespace, stress, fuzz, sanitizer, artifact, and
  reproducibility gates, with native AArch64 still external until executed.

## Readiness decision

With R-059-01 through R-059-07 binding, Phase 59 is ready. Later phases may
close with a mixture of implemented, no-go, and excluded candidates, but cannot
claim completion until every planned candidate has one validated final row and
the Phase 69 matrix reports each evidence dimension separately.
