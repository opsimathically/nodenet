# @opsimathically/nodenetscanner

`@opsimathically/nodenetscanner` is an unpublished `0.2.0-rc.1` candidate for a
bounded, Linux-native network scanner for Node.js 26+. TypeScript provides the
public control API; Rust owns route inspection, raw and packet sockets, packet
bytes, correlation secrets, scheduling, timers, result storage, and cleanup.

The package has not been published by this repository. It is developed
independently from `@opsimathically/nodenetraw` and does not call that package
or borrow its file descriptors. Shared protocol, read-only network-context, and
scheduler code is linked into the scanner addon at build time.

## Current capabilities

- IPv4 ARP and IPv6 Neighbor Discovery for directly connected targets;
- ICMPv4 and ICMPv6 Echo discovery;
- IPv4 and IPv6 TCP SYN scanning;
- IPv4 and IPv6 UDP scanning with explicit empty, exact custom, or legacy
  token-prefixed payload policy;
- Ethernet, explicit 802.1Q VLAN, loopback, and local raw-IP paths;
- compact CIDR or inclusive-range targets and exclusions;
- bounded rate, outstanding-work, retry, deadline, and result controls;
- pause, resume, cancel, terminal summaries, abortable compact result batches,
  coalesced progress snapshots, and an optional batch event adapter; and
- read-only interface, address, route, rule, and neighbor inspection;
- finite link discovery through legacy-unicast mDNS/DNS-SD, WS-Discovery, and
  explicit-name LLMNR; and
- finite targeted discovery for NAT-PMP, SQL Browser, rpcbind/NFS endpoint
  evidence, TFTP, and QUIC Version Negotiation;
- finite IPv4/IPv6 ICMP Echo, UDP, and TCP path tracing with per-attempt
  correlation, exact responder/RTT evidence, deadline settlement, and
  `AbortSignal` cancellation;
- active IPv6 Router Solicitation on an explicit interface with validated
  link-local Router Advertisement results; and
- ordinary-kernel-TCP service identification for credential-free server-first
  SSH/FTP/SMTP/POP3/IMAP/MySQL greetings, canonical HTTP `HEAD`, PostgreSQL SSL
  capability, and Redis `PING`.

The scanner does not change links, addresses, routes, neighbors, firewall rules,
or network namespaces. It does not enable promiscuous mode and never tries to
elevate its own privileges.

## Build and test

From the monorepo root:

```sh
npm ci
npm run build --workspace=@opsimathically/nodenetscanner
npm run test:phase24
```

The ordinary tests do not require raw-socket authority. The live dual-stack,
veth, and VLAN matrix runs in disposable network namespaces:

```sh
sudo npm run test:phase24:namespace
```

The wrapper builds as the invoking user before entering the namespace, which
avoids root-owned build artifacts. It requires `ip`, `unshare`, `nsenter`, and
Node.js 26+.

## Scan example

Creating a scanner and inspecting network context do not open raw sockets.
Raw-socket authority is checked when `start()` opens a session, normally through
root or `CAP_NET_RAW` in the current user/network namespace.

```ts
import {
  ScannerError,
  createScanner,
  inspectNetworkContext,
} from "@opsimathically/nodenetscanner";

const context = await inspectNetworkContext();
console.log(context.generation, context.interfaces);

const scanner = await createScanner();

try {
  const session = await scanner.start({
    targets: [{ cidr: "192.0.2.0/24" }, { cidr: "2001:db8::/120" }],
    exclude: [{ cidr: "192.0.2.1/32" }],
    probes: [
      { kind: "icmpEcho", family: "ipv4" },
      { kind: "icmpEcho", family: "ipv6" },
      { kind: "tcpSyn", ports: [22, 443, { start: 8000, end: 8010 }] },
      {
        kind: "udp",
        // Omitted policy selects low-impact protocol-aware requests on mapped
        // ports (DNS, NTP, and SNMP here).
        ports: [53, 123, 161],
      },
    ],
    deadlineMs: 30_000,
    rate: {
      packetsPerSecond: 1_000,
      burst: 32,
      maxOutstanding: 1_024,
    },
    timing: {
      timeoutMs: 1_000,
      retries: 1,
    },
    sourcePortRange: { start: 49_152, end: 65_535 },
  });

  for (;;) {
    const batch = await session.nextBatch({ maxResults: 512 });
    if (batch === null) break;

    // Rows are decoded lazily. `batch.results` is also a compatible lazy,
    // indexable iterable when that spelling is more convenient.
    for (const result of batch) {
      console.log(result.target, result.probe, result.port, result.state);
    }
  }

  console.log(await session.summary());
  await session.close();
} catch (error) {
  if (error instanceof ScannerError) {
    console.error(error.kind, error.code, error.operation, error.errno);
  }
  throw error;
} finally {
  await scanner.close();
}
```

## Discovery examples

`startDiscovery()` is separate from target/port scanning because one multicast
query can return many independently bounded entities. It starts immediately,
uses ordinary UDP sockets, and therefore does not require root or `CAP_NET_RAW`.
Every link and address family is explicit; `"allEligible"` is an affirmative
selection and fails if more than 16 eligible links exist.

Legacy-unicast mDNS/DNS-SD and WS-Discovery require both multicast and sensitive
read consent:

```ts
import {
  DISCOVERY_CAPABILITIES,
  createScanner,
} from "@opsimathically/nodenetscanner";

const scanner = await createScanner();
const discovery = await scanner.startDiscovery({
  scope: {
    kind: "links",
    interfaces: ["eth0"], // or the explicit sentinel "allEligible"
    families: ["ipv4", "ipv6"],
  },
  operations: [
    { operation: "mdnsDnsSdLegacy", receiveMode: "legacyUnicast" },
    { operation: "wsDiscoveryProbe" },
    { operation: "llmnrQuery", query: "printer.local" },
  ],
  allowRisks: ["multicastOrBroadcast", "sensitiveRead"],
  deadlineMs: 5_000,
  limits: { maxResults: 8_192, maxMetadataBytes: 16 * 1024 * 1024 },
});

for (;;) {
  const batch = await discovery.nextBatch({ maxResults: 512 });
  if (batch === null) break;
  for (const entity of batch) {
    console.log(
      entity.protocol,
      entity.responder,
      entity.responderPort,
      entity.kind,
      entity.addresses,
      entity.metadata.map(({ key, text }) => [key, text]),
    );
  }
}
console.log(await discovery.summary());
await discovery.close();
await scanner.close();

console.log(DISCOVERY_CAPABILITIES.registryVersion);
console.table(DISCOVERY_CAPABILITIES.operations);
```

Targeted discovery reuses bounded CIDR/range normalization and exclusions. The
special default-gateway selector is accepted only by the non-mutating NAT-PMP
external-address operation:

```ts
const gateway = await scanner.startDiscovery({
  scope: {
    kind: "targets",
    targets: "kernelDefaultIpv4Gateway",
    families: ["ipv4"],
  },
  operations: [{ operation: "natPmpExternalAddress" }],
  allowRisks: ["sensitiveRead"],
  deadlineMs: 2_000,
});

const services = await scanner.startDiscovery({
  scope: {
    kind: "targets",
    targets: [{ cidr: "192.0.2.0/24" }],
    exclude: [{ cidr: "192.0.2.1/32" }],
    families: ["ipv4"],
  },
  operations: [
    { operation: "sqlBrowserEnumeration" },
    // By default, a valid NFSv3 endpoint authorizes one same-target NFS NULL
    // child probe. Set followUp: false to collect rpcbind evidence only.
    { operation: "rpcbindGetAddress", followUp: true },
    { operation: "tftpSentinelRead" },
    { operation: "quicVersionNegotiation" },
  ],
  allowRisks: [
    "highAmplification", // required by SQL Browser enumeration
    "statefulHandshake",
    "sensitiveRead",
  ],
  deadlineMs: 4_000,
  rate: { packetsPerSecond: 100, burst: 16 },
});
```

RIPv1 routing-table discovery is an IPv4-only targeted operation. It sends one
whole-table request from an ephemeral source port and retains typed `route`
entities from multiple replies:

```ts
const routes = await scanner.startDiscovery({
  scope: {
    kind: "targets",
    targets: [{ cidr: "192.0.2.1/32" }],
    families: ["ipv4"],
  },
  operations: [{ operation: "ripv1RoutingTable" }],
  allowRisks: ["highAmplification", "sensitiveRead"],
  deadlineMs: 3_500,
});

for (;;) {
  const batch = await routes.nextBatch({ maxResults: 128 });
  if (batch === null) break;
  for (const route of batch) {
    console.log(
      route.responder,
      route.addresses[0],
      route.metadata.find(({ key }) => key === "metric")?.text,
    );
  }
}
await routes.close();
```

The RIPv1 operation accepts at most 10 tuple-valid response datagrams, 5,040
response bytes, and 250 route entities per target query. Malformed datagrams
still consume that budget, duplicates are merged, and reaching a ceiling marks
retained rows `truncatedByPolicy`. Destinations have RIPv1 classful semantics;
they are evidence only and never alter routes or authorize more scanning. The
older comprehensive-profile port-520 probe remains a single-datagram
compatibility/service-presence probe; use `ripv1RoutingTable` when route
retention is required.

SQL advertised ports, mDNS addresses, and WS-Discovery `XAddrs` remain untrusted
result metadata and never cause new work or URL fetches. Rpcbind is the narrow
exception: a transaction-correlated NFSv3 `GETADDR` reply may authorize exactly
one typed NFSv3 NULL child probe to the same original target. Its result exposes
`parentEntityId` and `derivationKind: "rpcbindGetAddress"`; it cannot expand the
target scope, and `followUp: false` disables that child transmission. TFTP uses
a randomized project-prefixed sentinel, pins only the first structurally valid
same-target transfer port, and sends one terminal ERROR after DATA/OACK rather
than continuing a file transfer. QUIC reports matched Version Negotiation only;
it does not claim HTTP/3 or authentication.

`progress()` is a live native snapshot while discovery is running; it does not
wait for the response deadline. Results are finite and bounded by `limits`, and
`nextBatch()` exposes immutable Node-owned batches after correlation and
aggregation are complete. The summary records `receiveModes: ["legacyUnicast"]`
when mDNS legacy-unicast collection was selected.

The response tuple is explicit: `responder` contains the IP address,
`responderPort` contains the observed UDP source port, and `interfaceIndex`
contains packet-info attribution when available. This matters for registered
alternate-port exchanges such as TFTP. A session admits at most 256 UDP sockets
and 1,024 total initial/adaptive physical queries; both ceilings are exported
through `DISCOVERY_CAPABILITIES`.

The frozen `DISCOVERY_CAPABILITIES` export lists exact operation bounds and
no-go families. Fixed-port mDNS browsing remains a no-go until coexistence with
the host mDNS daemon is proved. Kerberos, IKE, DTLS, host-namespace DHCP, GTP,
MQTT-SN, ADS, and FINS remain explicit no-go/blocked candidates; no malformed
approximation is sent for catalogue breadth.

## Passive observation

`startObservation()` is a finite receive-only AF_PACKET metadata session. It
requires root or `CAP_NET_RAW`, an explicit interface list, and explicit kernel
filter groups. It defaults to non-promiscuous capture with outgoing packets
suppressed. No frame or application payload is returned to JavaScript; rows
contain link/network/transport identity plus bounded typed discovery metadata.
Switched-network visibility is inherently limited, so silence is never reported
as evidence that a device or service is absent.

```ts
import {
  createEvidenceRecord,
  createScanner,
  evidenceFromObservation,
} from "@opsimathically/nodenetscanner";

const scanner = await createScanner();
const observation = await scanner.startObservation({
  interfaces: ["eth0"],
  protocols: ["arp", "ipv4", "ipv6", "lldp", "controlPlane"],
  durationMs: 30_000,
  snapLength: 4_096,
  maxResults: 8_192,
  maxMetadataBytes: 16 * 1024 * 1024,
  allowRisks: ["passiveMetadata"],
});

const runId = crypto.getRandomValues(new Uint8Array(16));
for (;;) {
  const batch = await observation.nextBatch({ maxResults: 512 });
  if (batch === null) break;
  for (const row of batch) {
    console.log(
      row.protocol,
      row.sourceAddress,
      row.destinationAddress,
      row.metadata,
    );
    const evidence = createEvidenceRecord(evidenceFromObservation(row, runId));
    // Store or reconcile `evidence` in application-owned state.
    void evidence;
  }
}

console.log(await observation.summary());
await observation.close();
await scanner.close();
```

Observation batches also have the same bounded optional event adapter as scan
and discovery sessions. It serializes one pull at a time and preserves the
session's native backpressure:

```ts
const events = observation.batches({ maxResults: 512 });
events.on("batch", (batch) => {
  for (const row of batch) console.log(row.protocol, row.sourceAddress);
});
events.once("error", console.error);
events.once("end", () => console.log("observation complete"));
```

Promiscuous membership is separately gated:

```ts
const observation = await scanner.startObservation({
  interfaces: ["eth0"],
  protocols: ["arp", "ipv4", "ipv6"],
  promiscuous: true,
  allowRisks: ["passiveMetadata", "promiscuousCapture"],
});
```

Capture sessions share the same four-session and 64 MiB environment ceilings as
scans and finite discovery. Their lifetime frame, captured-byte, row, metadata,
snap-length, and duration limits are not replenished by pulling a batch.
Generated classic BPF is attached before capture and a separate userspace
protocol guard remains in place. IPv4/IPv6 fragments are reported as fragments
but incomplete upper layers never enter a service parser.

Linux checksum-offload state is read from `PACKET_AUXDATA`. When a frame carries
kernel-validated or not-yet-materialized checksum bytes, metadata includes
`transportChecksumStatus` as `kernelValidated` or `offloadPending`; otherwise
the captured transport checksum bytes are validated directly.

The passive decoder recognizes ARP, NDP, DHCPv4/v6, mDNS/DNS-SD, LLMNR, NBNS,
SSDP, WS-Discovery, IPv6 Router Discovery/Redirect, LLDP, STP, LACP, VRRP,
IGMP/MLD, RIP, and OSPF. Metadata includes bounded DHCP identity/configuration
options, DNS names/SRV/TXT/address records and TTLs, RA options, and LLDP
identity/capability TLVs. The API does not retain opaque payloads, transmit a
query, join a routing protocol, or modify kernel state.

## Path, service, asset, inventory, and sensor primitives

The package exports deterministic foundations used to build higher-level
discovery workflows:

- `tracePath()` executes bounded ICMP/UDP/TCP path plans and retains each
  responder attempt without pretending one run enumerates every ECMP path.
  `PathRun` provides the matching syscall-free accumulator.
- `SERVICE_CAPABILITIES` makes implemented, opt-in, and no-go service identity
  operations explicit. `validateServiceConversation()` accepts only registered
  finite state-machine shapes and canonical fixed requests; it is not a custom
  TCP scripting escape hatch.
- `authorizeAdvertisedUrl()` enforces literal same-responder HTTP(S) authority,
  rejects userinfo, fragments, DNS rebinding opportunities, cross-address
  endpoints, and redirects, and performs no fetch itself.
- `reconcileEvidence()` merges only scoped strong identifiers, while
  `classifyAsset()` returns every supporting and conflicting reason.
- `inventoryDelta()` is storage-neutral; the scanner does not add a database or
  write snapshots to disk.
- `encodeSensorEnvelope()`, `decodeSensorEnvelope()`, and `SensorFusion` provide
  bounded transport-neutral multi-vantage interchange. Applications own sensor
  authentication, encryption, authorization, transport, deployment, and storage;
  the package exposes no listener or remote scan command service.

Path discovery is a finite one-shot operation. Cancellation closes the native
descriptor and resolves with `state: "cancelled"`; it does not leave a libuv
worker or detached probe loop running:

```ts
const controller = new AbortController();
const path = await scanner.tracePath(
  {
    target: "192.0.2.80",
    mode: "udp",
    port: 33434,
    firstHop: 1,
    maximumHop: 30,
    attemptsPerHop: 3,
    pacingMs: 10,
    deadlineMs: 15_000,
  },
  { signal: controller.signal },
);

for (const attempt of path.attempts) {
  console.log(
    attempt.hop,
    attempt.responder,
    attempt.roundTripMicroseconds,
    attempt.outcome,
    attempt.icmp,
  );
}
```

Sensor envelope version 1 can optionally report the producing sensor's bounded
capability snapshot, selected interfaces/protocols, promiscuous/outgoing
visibility, and accepted/drop summary. Fusion treats these as context only;
applications still assign and authenticate `sensorId` and `networkScopeId`.

Service identification selects a registry-owned conversation. The caller never
supplies arbitrary TCP bytes. Registry ports are safe scheduling defaults; after
another scan finds a service on a nonstandard port, explicitly selecting the
capability and that port is allowed.

```ts
import {
  SERVICE_CAPABILITIES,
  evidenceFromServiceIdentification,
} from "@opsimathically/nodenetscanner";

console.table(SERVICE_CAPABILITIES);

const identity = await scanner.identifyService({
  capabilityId: "http-head",
  target: "192.0.2.80",
  port: 8080,
  deadlineMs: 2_000,
  allowRisks: ["clientNegotiation"],
});

if (identity.outcome === "identified") {
  console.log(identity.protocol, identity.confidence, identity.fields);
}

const evidence = evidenceFromServiceIdentification(
  identity,
  crypto.getRandomValues(new Uint8Array(16)),
  0n,
  process.hrtime.bigint(),
);
```

Server-first identification uses `allowRisks: ["serverFirst"]` and transmits
zero application bytes. PostgreSQL and Redis use exact canonical requests under
`clientNegotiation`. No operation sends credentials, login commands, mail
commands, database authentication material, HTTP bodies, or redirects.

Active IPv6 router discovery is separately link-multicast gated:

```ts
const routers = await scanner.solicitRouters({
  interface: "eth0",
  deadlineMs: 2_000,
  maxResults: 16,
  allowRisks: ["linkMulticast"],
});

for (const advertisement of routers.advertisements) {
  console.log(advertisement.responder, advertisement.metadata);
}
```

The strict service codecs cover SSH, FTP, SMTP, POP3, IMAP, MySQL greetings, TLS
record metadata, HTTP response headers, SMB2/RDP/PostgreSQL/Redis/MongoDB
response discrimination. Only registry entries marked `implemented` or `optIn`
may execute. HTTP `HEAD`, PostgreSQL SSLRequest, and Redis `PING` have live
bounded native conversations. TLS handshakes, SMB/RDP/Mongo negotiation, LDAP,
SNMP, and specialized printing/media/IoT/industrial exchanges remain explicit
`noGo` entries until their dependency, responder, impact, and bounded-I/O gates
are independently closed.

`inspectNetworkContext()` now returns the complete normalized read-only `rules`
and `neighbors` arrays in addition to interfaces, addresses, and routes; the
retained `ruleCount` and `neighborCount` fields remain compatible summary
values.

The supported probe matrix is also exported as the frozen
`SUPPORTED_SCAN_PROBES` tuple:

| Plan probe          | Target family | Result probe   | Typical positive state     |
| ------------------- | ------------- | -------------- | -------------------------- |
| `arp`               | IPv4, on-link | `arp`          | `up`                       |
| `ndp`               | IPv6, on-link | `ndp`          | `up`                       |
| `icmpEcho` / `ipv4` | IPv4          | `icmpEchoIpv4` | `up`                       |
| `icmpEcho` / `ipv6` | IPv6          | `icmpEchoIpv6` | `up`                       |
| `tcpSyn`            | IPv4 or IPv6  | `tcpSyn`       | `open` or `closed`         |
| `udp`               | IPv4 or IPv6  | `udp`          | `open`, `closed`, or `open | filtered` |

Focused discovery, TCP SYN, UDP, and IPv6 scans differ only in their explicit
probe and target lists:

```ts
const discovery = [{ kind: "icmpEcho", family: "ipv4" }] as const;
const tcp = [{ kind: "tcpSyn", ports: [22, 80, 443] }] as const;
const udp = [
  { kind: "udp", ports: [53, 123] }, // safe protocol-aware probes by default
] as const;
const ipv6 = [
  { kind: "icmpEcho", family: "ipv6" },
  { kind: "tcpSyn", ports: [443] },
] as const;

const session = await scanner.start({
  targets: [{ cidr: "2001:db8::/120" }],
  exclude: [{ cidr: "2001:db8::1/128" }],
  probes: ipv6,
  deadlineMs: 15_000,
});
```

ARP accepts IPv4 targets and NDP accepts IPv6 targets only when route context
shows that the target is on-link. Their learned link address is session-local;
it is not inserted into the kernel neighbor table.

### UDP payload policy

One plan may contain one UDP definition. Its policy applies independently to
every selected target and port:

```ts
const safeServices = {
  kind: "udp",
  ports: [53, 111, 123, 161, 623, 3478, 5351, 5683, 11211],
} as const;
```

With no `policy`, the scanner sends an independently authored, unicast,
low-impact request only on the corresponding assigned port: DNS root A with EDNS
padding and a 512-byte ceiling, rpcbind v2 NULL, NTP client, SNMPv3 engine
discovery, ASF/RMCP presence, STUN Binding, PCP ANNOUNCE, CoAP Empty
Confirmable, or framed memcached `version`. PCP ANNOUNCE is an additional safe
probe: it discovers PCP without creating or changing a mapping. An unlisted port
receives the default exact empty fallback. No safe request broadcasts,
multicasts, uses a fixed source port, authenticates, reads application data, or
changes server state.

```ts
const exact = {
  kind: "udp",
  ports: [53],
  policy: {
    mode: "custom",
    payload: Uint8Array.from([0x12, 0x34]),
    correlation: "tuple",
  },
} as const; // sends exactly 12 34

const empty = {
  kind: "udp",
  ports: [123],
  policy: { mode: "empty" },
} as const; // sends a zero-length UDP payload

const compatible = {
  kind: "udp",
  ports: [7],
  policy: {
    mode: "custom",
    payload: Uint8Array.from([1, 2, 3]),
    correlation: "prefixToken",
  },
} as const; // prepends the scanner's 16-byte correlation token
```

The older top-level `payload` property remains temporarily supported and means
`custom/prefixToken`; it is mutually exclusive with `policy`. Explicit `empty`
and `custom` policies preserve generic UDP behavior. The immutable
`UDP_PROBE_CATALOGUE` export identifies the 37-entry `1.4.1` catalogue and its
content hash. `protocolModeAvailable: true` means the built-in safe pack is
compiled in. `exhaustive` remains the compatibility default and emits every
eligible variant. Opt-in `adaptive` emits the most likely mapped request first,
waits for evidence before sending an alternative, stops unsent variants after a
direct UDP response or target port-unreachable, and never treats silence as
proof that a port is open:

```ts
const adaptiveUdp = {
  kind: "udp",
  ports: [53, 123, 161, 11211],
  policy: {
    mode: "protocol",
    profile: "safe",
    intensity: 7,
    strategy: "adaptive",
    emptyFallback: "unmapped",
  },
} as const;
```

Already-emitted correlations remain valid through the bounded late-response
grace. A parser-only service-family hint may narrow compatible follow-ups, but
cannot classify a port or assert a product. After correlated ICMP followed by
silence, adaptive mode may delay further work for that host; it does not change
the result state. `summary.udpIcmpPacing` records those conservative cooldowns.

The `comprehensive` profile adds extended standards probes, but profile breadth
never grants permission for their network impact. Each catalogue entry is
eligible only when every risk it declares is also present in `allowRisks`:

| Probe                          |        Port | Required consent                         |
| ------------------------------ | ----------: | ---------------------------------------- |
| NFS v3 NULL                    |        2049 | none                                     |
| NetBIOS node status            |         137 | `sensitiveRead`                          |
| SIP OPTIONS                    |        5060 | `sensitiveRead`                          |
| SSDP unicast M-SEARCH          |        1900 | `highAmplification`, `sensitiveRead`     |
| L2TP SCCRQ                     |        1701 | `statefulHandshake`                      |
| SNMPv1 public `sysDescr.0` GET |         161 | `authenticationAttempt`, `sensitiveRead` |
| memcached `stats`              |       11211 | `highAmplification`, `sensitiveRead`     |
| Source engine `A2S_INFO`       |       27015 | `highAmplification`, `sensitiveRead`     |
| RakNet unconnected ping        | 19132–19133 | `highAmplification`, `sensitiveRead`     |
| BACnet/IP Who-Is (unicast)     |       47808 | `highAmplification`, `sensitiveRead`     |
| EtherNet/IP ListIdentity       |       44818 | `highAmplification`, `sensitiveRead`     |
| KNXnet/IP Search (unicast)     |        3671 | `sensitiveRead`                          |
| BitTorrent DHT ping            |        6881 | `statefulHandshake`                      |
| SLP service-agent request      |         427 | `highAmplification`, `sensitiveRead`     |
| Quake III `getinfo`            |       27960 | `highAmplification`, `sensitiveRead`     |
| Mumble extended ping           |       64738 | `highAmplification`, `sensitiveRead`     |

At intensity 8 and above, comprehensive mode also includes the RIPv2 routing-
table request on port 520, gated by `highAmplification` and `sensitiveRead`. The
`legacy` profile is a superset and adds UDP Echo, Daytime, Quote of the Day,
Character Generator, Active Users, Network Status, XDMCP, the DNS CHAOS
`version.bind` convention, NTP mode-6 READVAR, a RIPv1 whole-table request on
port 520, and Quake II status on port 27910. RIPv1 and Quake II status each
require `highAmplification` and `sensitiveRead`. Amplifying or sensitive legacy
variants still require their corresponding consent; selecting `legacy` alone
does not authorize any risk-bearing member. Risk-free Echo and Daytime remain
eligible at their configured intensities.

For example, this admits the sensitive-read probes and risk-free NFS while
leaving amplification-prone, stateful, and authentication-attempt probes out:

```ts
const session = await scanner.start({
  targets: [{ cidr: "192.0.2.0/24" }],
  probes: [
    {
      kind: "udp",
      ports: [137, 161, 1900, 2049, 5060, 11211],
      policy: {
        mode: "protocol",
        profile: "comprehensive",
        intensity: 7,
        strategy: "exhaustive",
        allowRisks: ["sensitiveRead"],
      },
    },
  ],
  deadlineMs: 30_000,
});
```

Selecting `safe` always retains the original nine-entry safe pack even when
`allowRisks` is supplied. Unknown or duplicate consent values fail admission.
Protocol-mode multicast or limited-broadcast targets additionally require
`multicastOrBroadcast` consent and an explicit interface; the scanner never
expands a unicast target into multicast or broadcast traffic.

For example, this explicitly admits the four additions while keeping them out of
the default safe profile:

```ts
const session = await scanner.start({
  targets: [{ cidr: "192.0.2.10/32" }],
  probes: [
    {
      kind: "udp",
      ports: [520, 27910, 27960, 64738],
      policy: {
        mode: "protocol",
        profile: "legacy",
        intensity: 8,
        allowRisks: ["highAmplification", "sensitiveRead"],
      },
    },
  ],
  deadlineMs: 10_000,
});
```

The project-owned capability ledger gives every researched family exactly one
disposition: implemented equivalent, standards-superseded, explicit unsafe
opt-in, or blocked. Current blockers include multi-responder mDNS/DNS-SD,
alternate-port TFTP, fixed-source/broadcast DHCP, identity- or secret-dependent
VPN/authentication exchanges, and proprietary protocols without an accepted
stable public wire specification. These are reported omissions, not approximate
payloads. The catalogue and release artifacts never load or redistribute a
third-party probe database.

`UDP_COVERAGE_CAPABILITIES` is the immutable decision registry behind Phases
59–68. Each row reports its project-owned identifier, phase, disposition,
execution model, policy, risks, exact required runtime consents, evidence
dimensions, primary source, rationale, and exact implementation ID when shipped.
Registry `1.1.0` contains 41 candidates: 5 implemented (ASF/RMCP presence,
RIPv1, Quake II, Quake III, and Mumble), 32 explicit no-go decisions, and 4
threat-signature exclusions. A no-go or excluded row has no schedulable
implementation. Its presence documents the support boundary; it does not imply
that the scanner emits that protocol. The registry also publishes hard
candidate, variant, query, response, metadata, returned-endpoint, and
state-lifetime ceilings.

Protocol-mode sessions emit result schema 2. Its retained columns identify the
winning probe, attempted variants, direct/ICMP/silence response kind, numeric
service family and confidence, and a bounded length-prefixed service-metadata
record. Schema 1 remains accepted for retained batches and is still emitted by
explicit empty/custom sessions. A direct, tuple-matched UDP datagram proves the
endpoint is open even if its body is malformed; service identity and metadata
are present only after the protocol parser validates the complete response and
its transaction field. Raw response datagrams never cross the Node boundary.
Lazy rows expose `udpTerminalProbeId`, `udpVariantsAttempted`,
`udpResponseKind`, `udpServiceFamily`, `udpServiceConfidence`, and decoded
bounded `udpService` product/version/field metadata. These properties are absent
for schema-1 and non-UDP rows.

Every summary separates logical and physical work: `logicalProbes` is the
planned target/port count, while `progress.sent` is the number of physical
frames actually transmitted, including UDP variants and retries. For UDP
sessions, `summary.udp.policy` contains the normalized selected policy. Protocol
summaries also contain the exact catalogue version and SHA-256 identity, making
adaptive runs reproducible.

Catalogue versions use semantic versioning: a major change may alter or remove
an existing probe contract, a minor change only adds independently reviewed
variants or compatible metadata, and a patch fixes behavior or documentation
without changing catalogue membership. The content hash remains the
authoritative byte-for-byte identity regardless of version.

To select an explicit VLAN path, capture the interface, source address, and tag
in the plan:

```ts
const session = await scanner.start({
  targets: [{ cidr: "198.51.100.2/32" }],
  probes: [{ kind: "arp" }, { kind: "tcpSyn", ports: [443] }],
  deadlineMs: 10_000,
  interface: "eth0",
  sourceAddress: "198.51.100.1",
  vlan: { identifier: 42, priority: 0 },
});
```

Unsupported link types, routes, source overrides, and probe/family combinations
fail explicitly rather than guessing an Ethernet header or route.

## Compact batches

Protocol-mode sessions emit `ScanResultBatch` schema version 2; compatibility
empty/custom sessions emit version 1. The retained decoder accepts both frozen
schemas. Creating a batch does not create one JavaScript object per result. Use
`batch.at(index)`, iterate the batch, use `batch.filter(predicate)`, or call
`batch.materialize()` only when owned ordinary objects are wanted. Exact RTTs,
terminal timestamps, and route generations are `bigint`; timestamps are unsigned
nanoseconds from the session's monotonic origin and never wall time.

The public `columns` contain copied, Node-owned `Uint8Array` storage.
Fixed-width integers are little-endian; IP address octets remain in network byte
order and each row carries an explicit family. Mutating these views can change
how that batch decodes but cannot affect native correlation or scanner state. To
transfer the columns to a Worker, use `batch.transferList()` as the
structured-clone transfer list. Accessing the original batch after transfer
fails explicitly.

```ts
const batch = await session.nextBatch({ maxResults: 512 });
if (batch !== null) {
  const open = Array.from(
    batch.filter((row) => row.state === "open"),
    (row) => row.materialize(),
  );
  console.log(open);

  worker.postMessage(
    {
      schemaVersion: batch.schemaVersion,
      rowCount: batch.length,
      byteOrder: batch.byteOrder,
      ...batch.columns,
    },
    batch.transferList(),
  );
}
```

## Pull, progress, and lifecycle semantics

`nextBatch()` defaults to at most 512 results and accepts 1 through 4,096. At
most one pull may wait per session. Pass an `AbortSignal` to cancel only that
wait; the scan continues. If native delivery wins the cancellation race, the
sealed batch is delivered. A terminal session remains drainable: queued batches
are returned first, followed by `null`.

```ts
const controller = new AbortController();
const waiting = session.nextBatch({ signal: controller.signal });
controller.abort();
await waiting; // rejects with AbortError unless a batch was already delivered
```

`progress()` returns a coalesced snapshot with exact `bigint` counts for sent,
received, matched, duplicate, invalid, timed-out, retried, kernel-dropped, and
application-backpressured work. Result saturation stops new transmissions and
does not resume until the bounded queue reaches its low-water mark; receive,
expiry, cancel, close, and result draining continue.

```ts
const timer = setInterval(async () => {
  const progress = await session.progress();
  console.log(progress.sent, progress.matched, progress.timedOut);
}, 250);
const stop = new AbortController();
process.once("SIGINT", () => stop.abort());
try {
  while (!stop.signal.aborted) {
    const batch = await session.nextBatch({
      maxResults: 1024,
      signal: stop.signal,
    });
    if (batch === null) break;
    for (const row of batch) console.log(row.materialize());
  }
} catch (error) {
  if (!(error instanceof Error && error.name === "AbortError")) throw error;
  await session.cancel("operator cancellation");
} finally {
  clearInterval(timer);
}
```

`pause()` stops new transmission after its promise resolves; receive processing,
timeouts, cancellation, and result draining continue. `resume()` permits
transmission again. `cancel()` stops admission and resolves with the terminal
summary after native I/O ownership has ended. `summary()` waits for the same
terminal summary. `close()` is idempotent and intentionally discards any
undrained results; scanner close cancels and closes all of its sessions.

If a live context or socket boundary fails, the summary state is `failed` and
`summary.error` retains its stable kind/code, operation, message, and Linux
`errno` when one exists. Already reserved probes still produce
`contextInvalidated` or `transportFailed` terminal results.

One Node environment has one native runtime with no process-global scanner
state. It accepts at most four scanner objects, four concurrent sessions, 64
pending control operations, and independently bounded command, active-probe,
grace, and result storage. Slow JavaScript consumption can stop new admission;
it cannot cause unbounded native allocation.

## Batch events

For Node applications that prefer event-driven consumption, `session.batches()`
creates an adapter over `nextBatch()`; it does not add another native receive
loop or a per-result event mode. Call `start()` explicitly. `pause()` and
`detach()` are awaitable boundaries, while `close()` closes the underlying scan
session. A fulfilled batch is emitted before any competing pause, detach, or
close boundary settles.

```ts
const events = session.batches({ maxResults: 512 });

events.on("batch", (batch) => {
  for (const result of batch) console.log(result.target, result.state);
});
events.once("end", () => console.log("all queued results drained"));
events.on("error", console.error);
events.start();

await events.pause();
events.resume();

// Stop event delivery but keep direct ownership of the scan session.
const directSession = await events.detach();
const next = await directSession.nextBatch();
```

## Accuracy and host interaction

Raw scan replies are unauthenticated network evidence. Results record the
protocol-specific evidence strength and distinguish `open`, `closed`,
`filtered`, `open|filtered`, `up`, `unreachable`, and `unknown` where the wire
protocol permits that conclusion. UDP silence is `open|filtered`; discovery
silence is `unknown`.

Ethernet and explicit single-tag 802.1Q paths use `AF_PACKET`; Linux loopback
and locally routed paths use raw IP where an Ethernet header would be false. The
scanner binds every descriptor and context watcher to the network namespace in
which the session starts and never moves it later. Unsupported link kinds or
ambiguous routes fail explicitly. An `AF_PACKET` result reports traffic observed
on that wire boundary—it does not prove that the host firewall would admit the
same packet to an application or that a full connection could complete.

The default TCP/UDP source range is 49152–65535. Choose a range that does not
conflict with local applications or the host ephemeral allocator. The host TCP
stack may send a reset after receiving a SYN-ACK for a raw SYN probe; the
library deliberately does not install firewall rules to suppress it. Source port
reuse is separated across outstanding work and late-response grace state. The
range is divided into four non-overlapping session partitions; any remainder is
left unused. A custom range must therefore provide at least four times the
requested `maxOutstanding` capacity. Applications remain responsible for
coordinating other host users of an explicit range.

UDP user payloads are limited to `SCANNER_LIMITS.udpPayloadBytes` (65,491
bytes). The remaining IPv4 packet capacity is reserved for the private
correlation token and UDP/IP headers. Invalid payloads and insufficient source
port ranges are rejected during `scanner.start()` before raw sockets or session
resources are admitted.

Packet parsing rejects truncation, ignores locally looped `PACKET_OUTGOING`
frames, interprets stripped VLAN tags through packet auxiliary metadata, and
reports lifetime kernel-drop accounting in the terminal summary.

Checksum, segmentation, receive aggregation, and VLAN offloads can make a host
capture differ from physical wire bytes. The scanner constructs valid complete
probe packets and understands Linux VLAN auxiliary metadata, but operators
should record interface offload configuration with captures and benchmarks. ICMP
and ICMPv6 responders commonly rate-limit replies; silence or a lower match
count is therefore not proof that a target is down.

## Privileges and route inspection

Run the application as root, or grant the Node executable/process the exact
`CAP_NET_RAW` authority appropriate for the deployment. Capabilities are tied to
executables, namespaces, and deployment policy; the library never invokes
`sudo`, changes credentials, or grants itself authority. `createScanner()` and
`inspectNetworkContext()` are capability-free; `scanner.start()` is the first
raw-socket boundary.

```ts
const context = await inspectNetworkContext();
for (const route of context.routes) {
  console.log(
    route.family,
    route.destination,
    route.prefixLength,
    route.gateway,
    route.interfaceIndex,
  );
}
```

Use the disposable namespace test to validate authority without scanning the
external network: `sudo npm run test:phase24:namespace` from the monorepo root.

## Support status

This Phase 69 package is an unpublished `0.2.0-rc.1` release candidate. Linux
x86-64 development, ordinary tests, and disposable privileged namespace tests
are the local baseline. AArch64 glibc packages are configured and
cross-compilable, but native AArch64 execution remains untested by the project
owner and is a mandatory publication gate. The root package is loader-only;
exact-version x64/AArch64 target packages contain the stripped addon, with no
install scripts and no production Node dependencies.

The project catalogue is independently authored from primary protocol
specifications. In the Phase 33 owner-controlled comparison, catalogue `1.3.0`
was evaluated against Nmap commit `10dfd2ff1cef6c1925232db45352149b659979b4` as
a black-box behavioral baseline on the same disposable IPv4/IPv6 responder
classes. The scanner elicited a direct response and definitive `open` state from
every accepted responder in that comparison; the baseline did not exceed that
coverage. This is a narrow UDP port-probe and state-accuracy result, not Nmap
compatibility, affiliation, or parity with its complete service/version
detection system. Thirteen researched capabilities remain explicitly blocked in
the core probe catalogue. The separate coverage registry records 41 later
candidates as 5 implemented, 32 explicit no-go decisions, and 4 threat-signature
exclusions. These documented boundaries mean the package makes no full-database
or full-service-fingerprinting claim.

Phase 25 retained this portable engine as the only backend. Controlled
`PACKET_MMAP` and AF_XDP prototypes did not produce a qualified, identical
end-to-end scanner improvement, so the accepted decision is `no-go` and Phase 26
is closed. No extreme-backend selector, XDP loader, writable ring, or UMEM
surface is part of this package. Maintainers can reproduce the internal evidence
gate with `sudo npm run benchmark:phase25` from the monorepo root; this is a
diagnostic benchmark, not an end-user throughput promise.

The authoritative design is the
[Phase 16–26 network and scanner evolution plan](../../ai_documentation/31-network-and-scanner-evolution-plan.md)
and the
[Phase 27–33 UDP protocol-probe plan](../../ai_documentation/43-udp-probe-parity-plan.md).
The advanced discovery and UDP coverage extensions are specified in the
[Phase 34–44 plan](../../ai_documentation/53-advanced-udp-discovery-evolution-plan.md),
[Phase 45–58 plan](../../ai_documentation/57-network-discovery-coverage-plan.md),
and
[Phase 59–69 plan](../../ai_documentation/62-udp-probe-coverage-expansion-plan.md).
The current implementation and repair evidence is in the
[Phase 59–69 repair report](../../ai_documentation/66-phases-59-69-adversarial-repair-report.md).

Release assembly is intentionally maintainer-only. It requires a clean Git
worktree so every staged package provenance document names the exact verified
`HEAD` commit; direct publication from this source directory is rejected.
