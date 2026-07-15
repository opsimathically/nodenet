# Phases 34–44 product-hardening report

Status: implementation corrections complete; external release gates remain  
Date: 2026-07-15

## Outcome

The adversarial pass found several places where the initial implementation met
the prototype happy path but not the frozen production invariants. The live
runtime, public API, protocol state machines, Linux attribution, and tests were
corrected rather than documenting the defects as acceptable behavior.

Phase 44 is still not a publication approval. Native AArch64 execution and the
post-change artifact/reproducibility matrix remain external gates.

## Runtime and resource corrections

- Discovery no longer occupies napi-rs/libuv async workers for its complete
  deadline. Each admitted run owns one named Rust thread and delivers exactly
  one bounded terminal completion through a capacity-one threadsafe callback.
  Four simultaneous 500 ms discovery runs no longer delay an unrelated Node
  filesystem callback.
- The production path now uses `DiscoveryBudget` leases, registered per-query
  entity/metadata ceilings, global 8,192-row/16 MiB retention ceilings, a
  configurable aggregate token bucket (100 packets/s, burst 16 by default), a
  1,024 physical-query ceiling, and a separately advertised 256-socket ceiling.
  Over-ceiling fan-out fails before opening discovery sockets.
- Pending adaptive work discarded at a deadline/resource boundary is charged to
  truncation accounting. TFTP terminal ERROR cleanup remains eligible across
  pause and cancellation once DATA/OACK has created remote transfer state.
- `progress()` reads a coherent mutex-protected native snapshot while the run is
  active. It no longer waits for the terminal result.
- Public batches drain every retained page through the event adapter. Cancel,
  completion, close, and control-removal races use the authoritative native run
  state; cancelled summaries retain accepted rows and counters.
- Scanner close now cancels and awaits every active discovery completion.
  Discovery thread panics are contained and converted to one structured terminal
  failure; callback-construction failures cannot strand control-map entries or
  environment reservations.

## Linux and correlation corrections

- Route-netlink address families now compare against Linux `AF_INET` and
  `AF_INET6`, not IP version numbers. This fixes eligible-link discovery,
  same-link NAT-PMP checks, and related loopback behavior.
- `kernelDefaultIpv4Gateway` uses a policy-aware kernel route lookup and retains
  the selected output interface. Explicit exclusions remain effective after
  gateway expansion, and explicit NAT-PMP targets must be directly attached.
- IPv6 multicast destinations retain their scope ID. `IP_PKTINFO`/
  `IPV6_PKTINFO` and received TTL/hop-limit control messages provide observed
  interface and hop metadata; mismatched requested interfaces are rejected.
- Tokenless operations require their registered response source port. Rpcbind
  permits only its correlated returned NFS port; TFTP pins the first
  structurally valid same-address transfer port and rejects competitors.
- Results expose the observed `responderPort`. Aggregation keys include
  operation, interface, responder address, responder port, and identity, while
  rpcbind parent/child association deliberately permits its registered port
  transition on the same responder address.

## Protocol corrections

- Legacy-unicast mDNS now requires the explicit `legacyUnicast` receive mode and
  walks `_services._dns-sd._udp.local` through service PTR, instance PTR, SRV,
  TXT, A, and AAAA dependencies. It emits bounded service entities with
  partial/complete state and exact TXT bytes instead of unrelated record rows.
- LLMNR chooses A for IPv4 and AAAA for IPv6, requires the queried owner name,
  class and type, and exposes only the answer address rather than the packet
  sender as resolved data.
- SQL Browser requires both `highAmplification` and `sensitiveRead`, emits an
  endpoint entity even when no instances are advertised, and retains bounded
  instance entities separately.
- TFTP DATA must begin at block 1, the first valid transfer port is pinned, and
  cleanup is bounded to one terminal ERROR. Rpcbind/NFS retains exact
  transaction, target, derived-port, and parent relationships.
- The executable no-go ledger now includes the deferred game/voice, CLDAP,
  OpenVPN, RADIUS, Ubiquiti, pcAnywhere, and WireGuard candidates instead of
  implying support.

## Boundary hardening

- Hostile native result arrays are length-checked before copying. Identity,
  address, metadata-field, key, byte, UTF-8 projection, row, and aggregate-byte
  ceilings are revalidated in TypeScript.
- Native row bounding includes UTF-8 text bytes and address cardinality. Per-
  query maximum response bytes and response windows are enforced before parser
  work; oversized or wrong-tuple datagrams do not become evidence.
- Default discovery retention was raised to the advertised 8,192 rows/16 MiB so
  ordinary dual-stack mDNS, WS-Discovery, and LLMNR queries can reserve their
  registered worst cases concurrently. Smaller caller-selected ceilings remain
  valid and deliberately apply backpressure/truncation.

## Verification

- `cargo test --workspace --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `npm test --workspace=@opsimathically/nodenetscanner`: 37 passed, 14
  privileged/stress cases skipped by their explicit gates.
- `npm run lint`, `npm run format:check`, and workspace TypeScript typecheck:
  passed.
- `sudo npm run test:namespace --workspace=@opsimathically/nodenetscanner`: 10
  passed. The discovery case proves two responder-scoped entities for each of
  mDNS, WS-Discovery, and LLMNR, 16 paced initial/adaptive transmissions, eight
  deterministic DNS-SD duplicate merges, observed interface attribution, and
  both advertised address families.

## Remaining release gates

1. Run the native scanner suite on an accepted AArch64 glibc host.
2. Repeat the post-change release artifact, clean consumer, GLIBC-symbol, and
   reproducibility gates and record the new hashes.
3. Run the gated discovery fault-injection, long Worker/fd/RSS, slow-consumer,
   sanitizer, and extended fuzz campaigns intended for the release candidate.

Public result delivery is intentionally terminally aggregated and bounded.
Incremental pre-deadline entity delivery would require a versioned revision or
tombstone schema and is not claimed by this implementation.
