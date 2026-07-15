import {
  DISCOVERY_CAPABILITIES,
  DISCOVERY_OPERATIONS,
  RESULT_BATCH_SCHEMA_VERSION,
  SCANNER_LIMITS,
  SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS,
  SUPPORTED_SCAN_PROBES,
  UDP_PROBE_CATALOGUE,
  createScanner,
  inspectNetworkContext,
  type ScanPlan,
  type DiscoveryPlan,
  type ScanResultBatch,
  type ScanSummary,
} from "../../src/index.js";

RESULT_BATCH_SCHEMA_VERSION satisfies 2;
SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS satisfies readonly [1, 2];
UDP_PROBE_CATALOGUE.version satisfies "1.3.0";
UDP_PROBE_CATALOGUE.protocolModeAvailable satisfies true;
SUPPORTED_SCAN_PROBES satisfies readonly [
  "arp",
  "ndp",
  "icmpEchoIpv4",
  "icmpEchoIpv6",
  "tcpSyn",
  "udp",
];
SCANNER_LIMITS.batchResults satisfies 4096;
SCANNER_LIMITS.udpPayloadBytes satisfies 65491;
DISCOVERY_OPERATIONS.quicVersionNegotiation satisfies 9;
DISCOVERY_CAPABILITIES.schemaVersion satisfies 1;
DISCOVERY_CAPABILITIES.maxSockets satisfies number;
DISCOVERY_CAPABILITIES.maxPhysicalQueries satisfies number;
DISCOVERY_CAPABILITIES.operations[0]?.supportsFollowUp satisfies
  boolean | undefined;

const discoveryPlan: DiscoveryPlan = {
  scope: {
    kind: "links",
    interfaces: "allEligible",
    families: ["ipv4", "ipv6"],
  },
  operations: [
    { operation: "mdnsDnsSdLegacy", receiveMode: "legacyUnicast" },
    { operation: "llmnrQuery", query: "printer.local" },
  ],
  allowRisks: ["multicastOrBroadcast", "sensitiveRead"],
  deadlineMs: 3_000,
};

const plan: ScanPlan = {
  targets: [{ cidr: "127.0.0.1/32" }],
  probes: [
    { kind: "icmpEcho", family: "ipv4" },
    { kind: "tcpSyn", ports: [22, { start: 80, end: 81 }] },
    { kind: "udp", ports: [53], payload: new Uint8Array([1, 2, 3]) },
    { kind: "udp", ports: [123], policy: { mode: "empty" } },
    {
      kind: "udp",
      ports: [161],
      policy: {
        mode: "custom",
        payload: new Uint8Array([1, 2, 3]),
        correlation: "tuple",
      },
    },
  ],
  deadlineMs: 5_000,
  seed: 1n,
};

async function consume(): Promise<void> {
  const context = await inspectNetworkContext();
  context.generation satisfies bigint;
  const scanner = await createScanner();
  const discovery = await scanner.startDiscovery(discoveryPlan);
  const discoveries = await discovery.nextBatch({ maxResults: 32 });
  discoveries?.at(0)?.identity satisfies Uint8Array | undefined;
  discoveries?.at(0)?.metadata[0]?.value satisfies Uint8Array | undefined;
  discoveries?.at(0)?.parentEntityId satisfies bigint | undefined;
  discoveries?.at(0)?.derivationKind satisfies "rpcbindGetAddress" | undefined;
  discoveries?.at(0)?.responderPort satisfies number | undefined;
  const discoveryEvents = discovery.batches();
  discoveryEvents.on(
    "batch",
    (eventBatch) => eventBatch.length satisfies number,
  );
  const discoverySummary = await discovery.summary();
  discoverySummary.registryVersion satisfies string;
  discoverySummary.receiveModes satisfies readonly "legacyUnicast"[];
  await discovery.close();
  const session = await scanner.start(plan);
  const batch: ScanResultBatch | null = await session.nextBatch({
    maxResults: 64,
    signal: new AbortController().signal,
  });
  if (batch?.results[0] !== undefined) {
    batch.results[0].routeGeneration satisfies bigint;
    batch.results[0].udpResponseKind satisfies
      import("../../src/index.js").UdpResponseKind | undefined;
    batch.results[0].udpService?.product satisfies string | undefined;
  }
  batch?.at(0)?.timestampNanoseconds satisfies bigint | undefined;
  batch?.transferList() satisfies ArrayBuffer[] | undefined;
  const progress = await session.progress();
  progress.applicationBackpressured satisfies bigint;
  const events = session.batches({ maxResults: 128 });
  events.on("batch", (eventBatch) => eventBatch.length satisfies number);
  events.on("end", () => undefined);
  const summary: ScanSummary = await session.cancel("test complete");
  summary.results satisfies bigint;
  summary.udpIcmpPacing satisfies bigint;
  summary.udp?.policy satisfies
    import("../../src/index.js").UdpSelectedPolicy | undefined;
  summary.error satisfies import("../../src/index.js").ScannerError | undefined;
  await session.close();
  await scanner.close();
}

void consume;
