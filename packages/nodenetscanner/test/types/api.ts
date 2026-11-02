import {
  DISCOVERY_CAPABILITIES,
  DISCOVERY_OPERATIONS,
  EVIDENCE_LIMITS,
  EVIDENCE_SCHEMA_VERSION,
  EvidenceLedger,
  PathRun,
  OBSERVATION_CAPABILITIES,
  RESULT_BATCH_SCHEMA_VERSION,
  SCANNER_LIMITS,
  SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS,
  SUPPORTED_SCAN_PROBES,
  UDP_PROBE_CATALOGUE,
  UDP_COVERAGE_CAPABILITIES,
  SERVICE_CAPABILITIES,
  createScanner,
  evidenceFromServiceIdentification,
  evidenceRecordsFromPath,
  evidenceFromScanResult,
  inspectNetworkContext,
  type ScanPlan,
  type DiscoveryPlan,
  type ObservationPlan,
  type RouterSolicitationPlan,
  type ScanResultBatch,
  type ScanSummary,
} from "../../src/index.js";

RESULT_BATCH_SCHEMA_VERSION satisfies 2;
SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS satisfies readonly [1, 2];
UDP_PROBE_CATALOGUE.version satisfies "1.4.1";
UDP_PROBE_CATALOGUE.protocolModeAvailable satisfies true;
UDP_COVERAGE_CAPABILITIES.version satisfies "1.1.0";
UDP_COVERAGE_CAPABILITIES.entries[0]?.projectId satisfies string | undefined;
UDP_COVERAGE_CAPABILITIES.entries[0]?.requiredConsents satisfies
  readonly import("../../src/index.js").UdpProbeRisk[] | undefined;
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
DISCOVERY_OPERATIONS.ripv1RoutingTable satisfies 10;
DISCOVERY_CAPABILITIES.schemaVersion satisfies 1;
DISCOVERY_CAPABILITIES.maxSockets satisfies number;
DISCOVERY_CAPABILITIES.maxPhysicalQueries satisfies number;
DISCOVERY_CAPABILITIES.operations[0]?.supportsFollowUp satisfies
  boolean | undefined;
EVIDENCE_SCHEMA_VERSION satisfies 1;
EVIDENCE_LIMITS.records satisfies 8192;
OBSERVATION_CAPABILITIES.retainsFramePayloads satisfies false;
SERVICE_CAPABILITIES[0]?.id satisfies string | undefined;
new PathRun({
  target: "192.0.2.1",
  mode: "icmpEcho",
  deadlineMs: 1_000,
}).stopped satisfies boolean;

const evidenceLedger = new EvidenceLedger({ maxRecords: 8, maxBytes: 4096 });
const evidence = evidenceFromScanResult(
  {
    target: "127.0.0.1",
    probe: "tcpSyn",
    port: 443,
    state: "open",
    outcome: "network",
    attempt: 0,
    transmissions: 1,
    timestampNanoseconds: 1n,
    routeGeneration: 1n,
    reason: "tcpSynAcknowledgment",
  },
  { runId: new Uint8Array([1]), recordId: 1n, sourceSchema: 2 },
);
evidenceLedger.retain(
  evidence,
) satisfies import("../../src/index.js").EvidenceRetainOutcome;

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

const observationPlan: ObservationPlan = {
  interfaces: ["eth0"],
  protocols: ["arp", "ipv4", "ipv6", "lldp"],
  durationMs: 1_000,
  allowRisks: ["passiveMetadata"],
};

const routerSolicitationPlan: RouterSolicitationPlan = {
  interface: "eth0",
  deadlineMs: 1_000,
  allowRisks: ["linkMulticast"],
};

async function consume(): Promise<void> {
  const context = await inspectNetworkContext();
  context.generation satisfies bigint;
  const scanner = await createScanner();
  const routers = await scanner.solicitRouters(routerSolicitationPlan, {
    signal: new AbortController().signal,
  });
  routers.state satisfies "completed" | "cancelled";
  routers.advertisements.at(0)?.responder satisfies string | undefined;
  const pathController = new AbortController();
  const path = await scanner.tracePath(
    {
      target: "192.0.2.1",
      mode: "udp",
      port: 33434,
      pacingMs: 10,
      deadlineMs: 1_000,
    },
    { signal: pathController.signal },
  );
  path.attempts.at(0)?.icmp?.type satisfies number | undefined;
  const service = await scanner.identifyService({
    capabilityId: "redis-ping",
    target: "192.0.2.1",
    port: 6379,
    deadlineMs: 1_000,
    allowRisks: ["clientNegotiation"],
  });
  service.fields.at(0)?.value satisfies Uint8Array | undefined;
  evidenceFromServiceIdentification(
    service,
    Uint8Array.of(1),
    0n,
    process.hrtime.bigint(),
  ).entity.kind satisfies string;
  evidenceRecordsFromPath(path, Uint8Array.of(1), process.hrtime.bigint())
    .length satisfies number;
  const observation = await scanner.startObservation(observationPlan);
  const observations = await observation.nextBatch({ maxResults: 32 });
  observations?.at(0)?.metadata[0]?.value satisfies Uint8Array | undefined;
  const observationEvents = observation.batches({ maxResults: 32 });
  observationEvents.on(
    "batch",
    (eventBatch) => eventBatch.length satisfies number,
  );
  observationEvents.on("end", () => undefined);
  (await observation.summary())
    .protocols satisfies readonly import("../../src/index.js").ObservationProtocol[];
  await observation.close();
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
