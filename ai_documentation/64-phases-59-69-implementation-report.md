# Phases 59–69 implementation and audit report

Last updated: 2026-07-15

Scope: D-057, D-058, and Phases 59 through 69

Status: historical pre-review implementation record; superseded for release
readiness by adversarial review 65

## Outcome

The UDP coverage program is complete under the candidate-level admission rule
frozen by the readiness review. Catalogue `1.4.0` appends probes 34–37 without
changing IDs 1–33, result schemas 1/2, the nine-probe safe profile, or default
exhaustive behavior. The separate coverage registry `1.0.0` gives every one of
the 41 planned candidates exactly one final disposition:

- 5 implemented;
- 32 no-go; and
- 4 actively excluded threat-signature families.

No-go and excluded rows have no executable implementation ID. They document a
reviewed support boundary and cannot schedule traffic.

## Phase results

| Phase | Implemented                                                                                             |                                                                              No-go |                                Excluded |
| ----: | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------: | --------------------------------------: |
|    59 | versioned candidate registry, dimensions, resource contract, native/TypeScript parity, provenance check |                                                                                  0 |                                       0 |
|    60 | existing ASF/RMCP presence as exact probe 7                                                             |                       IPMI channel-auth capabilities, Apple Remote Desktop, Citrix |                                       0 |
|    61 | 0                                                                                                       |                                                      IBM Db2 DAS, SAP SQL Anywhere |                                       0 |
|    62 | RIPv1 table request as probe 34                                                                         |                                                                       Beckhoff ADS |                                       0 |
|    63 | Quake II status as probe 35; challenge-correlated Quake III info as probe 36                            |                                  Quake 1, Quake III masters, UT2K, ASE, Freelancer |                                       0 |
|    64 | Mumble extended ping as probe 37                                                                        |                                             TeamSpeak 2/3, Ventrilo, SqueezeCenter |                                       0 |
|    65 | 0                                                                                                       |                                           Vuze/Azureus DHT, eDonkey/eMule Kademlia |                                       0 |
|    66 | 0                                                                                                       |                   AFS/Rx, Amanda, connectionless DCE/RPC, VxWorks WDB ping/connect |                                       0 |
|    67 | 0                                                                                                       | Kerberos, DHCP, IKE, DTLS, OpenVPN, RADIUS, CLDAP, Ubiquiti, pcAnywhere, WireGuard |                                       0 |
|    68 | 0                                                                                                       |                                                                                  0 | BackOrifice, Trinoo, AndroMouse, AirHID |
|    69 | catalogue/registry/release-policy freeze and integrated local audit                                     |                                                                                  0 |                                       0 |

These no-go outcomes are intentional implementations of the plan's stop rule: a
copied magic payload, incomplete handshake, fabricated identity, unstable
proprietary format, or mutation/authentication-shaped exchange is not support.

## Coverage dimensions

| Project capability   | Request |   Correlation    | Typed evidence | Project responder | Product fingerprint | Profile                        |
| -------------------- | :-----: | :--------------: | :------------: | :---------------: | :-----------------: | ------------------------------ |
| ASF/RMCP presence    |   yes   |       tag        |      yes       |        yes        |         no          | safe                           |
| RIPv1 table          |   yes   |   target tuple   |      yes       |     yes, IPv4     |         no          | legacy + explicit risks        |
| Quake II status      |   yes   |   target tuple   |      yes       |  yes, dual stack  |         no          | legacy + explicit risks        |
| Quake III info       |   yes   | echoed challenge |      yes       |  yes, dual stack  |         yes         | comprehensive + explicit risks |
| Mumble extended ping |   yes   | echoed timestamp |      yes       |  yes, dual stack  |         yes         | comprehensive + explicit risks |

The public `UDP_COVERAGE_CAPABILITIES` object exposes these dimensions rather
than collapsing them into a payload count. It is constructed from the native
Rust registry, validated at the JavaScript boundary, and deeply frozen.

## Wire and parser contracts

- RIPv1 accepts only response command 2/version 1, complete 20-byte route
  entries, IPv4 AFI, zero reserved fields, and metrics 1 through 16. Requests
  and responses are bounded at 24 and 504 bytes.
- Quake II requires the complete out-of-band `print` status envelope, bounded
  ASCII info pairs, case-insensitive unique keys, at most 64 bounded player
  lines, and no raw response exposure.
- Quake III uses `getinfo`, not uncorrelated status or master enumeration. Its
  response must echo the exact generated challenge and contain one complete,
  bounded, duplicate-free info record.
- Mumble requires an exact 24-byte response, exact opaque timestamp echo,
  nonzero version/capacity/bandwidth, and a user count no greater than capacity.

All builders remain inside descriptor limits. Every new parser has canonical,
wrong-transaction, truncation, malformed, delimiter/count, and arbitrary-byte
coverage and participates in the protocol fuzz target.

## Policy and resource results

No new probe enters the safe profile. RIPv1, Quake II, Quake III, and Mumble
remain explicit opt-ins and require both `highAmplification` and
`sensitiveRead`. The registry-level hard ceilings are 64 candidates, 256
compiled variants, 1,024 physical queries, 4,096 response bytes, 64 KiB typed
metadata, 1,024 returned endpoints, and 60 seconds of state. Existing native
per-session, rate, outstanding-work, result, metadata, and source-lane
reservations remain authoritative and occur before I/O.

## Provenance

The admitted wire behavior was independently implemented from DMTF DSP0136, RFC
1058, and the pinned upstream Quake II, Quake III, and Mumble sources named in
the readiness review. The external scanner checkout remains a human-only
behavioral comparison input. It is not read by builds, tests, generators,
fixtures, runtime code, or release assembly. `udp:provenance:check` rejects
prohibited comparison input paths from shippable registries, while Rust
validation rejects external-comparison names in runtime rows.

## Verification record

Passing local gates on x86-64 glibc Linux:

- `cargo test --workspace --all-targets --locked` after updating the frozen
  comprehensive/legacy membership expectations;
- `cargo clippy --workspace --all-targets --locked -- -D warnings` and
  `cargo fmt --all --check`;
- scanner native build, strict TypeScript build/type tests, ESLint, Prettier,
  and 83 ordinary scanner tests with 62 passing and 21 privileged skips;
- privileged scanner namespace matrix: 17 of 17 passing, including the new
  RIPv1, Quake II, Quake III, and Mumble responder test;
- protocol parse fuzzing with the corpus plus new Quake branches and serializer
  fuzzing with no crash;
- scanner native unit tests under AddressSanitizer and ThreadSanitizer: 34 of 34
  passing under each;
- Miri execution of the pure coverage-registry suite: 2 of 2 passing;
- catalogue identity check: `1.4.0`, 37 variants,
  `a925984228bf447e952d9f1f0970631ccafebddc4d25e6435b88c109573d1f32`;
- provenance, release-policy, staged artifact, clean-consumer, and
  reproducibility gates recorded by the final command pass.

The sanitizer pass also surfaced a nightly deprecation in the existing atomic
reservation path. Replacing `fetch_update` with its semantics-equivalent
`try_update` name restored both stable and nightly hardening builds.

## Remaining publication gate

Native AArch64 execution is still untested on this host and remains mandatory
before publication. The package stays unpublished. This does not leave a Phase
59–68 candidate undecided, but it prevents Phase 69 from claiming a fully
releasable cross-architecture artifact.
