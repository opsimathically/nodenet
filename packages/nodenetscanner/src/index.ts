import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { isIP } from "node:net";

import {
  DISCOVERY_PLATFORM_VERSIONS,
  SERVICE_CAPABILITIES,
} from "./platform.js";
import type {
  PathAttempt,
  PathPlan,
  PathTraceOptions,
  PathTraceRun,
  ServiceIdentificationOptions,
  ServiceIdentificationPlan,
  ServiceIdentificationRun,
} from "./platform.js";

export * from "./platform.js";

export type ScanTarget =
  { readonly cidr: string } | { readonly start: string; readonly end: string };

export type PortSelection =
  number | { readonly start: number; readonly end: number };

export type UdpProbeIntensity = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

export type UdpProbeRisk =
  | "highAmplification"
  | "statefulHandshake"
  | "fixedSourcePort"
  | "multicastOrBroadcast"
  | "authenticationAttempt"
  | "sensitiveRead";

export type UdpProbePolicy =
  | {
      readonly mode: "protocol";
      readonly profile?: "safe" | "comprehensive" | "legacy";
      readonly intensity?: UdpProbeIntensity;
      readonly strategy?: "adaptive" | "exhaustive";
      readonly emptyFallback?: "unmapped" | "afterProtocol" | "never";
      readonly allowRisks?: readonly UdpProbeRisk[];
    }
  | { readonly mode: "empty" }
  | {
      readonly mode: "custom";
      readonly payload: Uint8Array;
      readonly correlation?: "tuple" | "prefixToken";
    };

/** Immutable, normalized UDP execution policy recorded in session summaries. */
export type UdpSelectedPolicy =
  | {
      readonly mode: "protocol";
      readonly profile: "safe" | "comprehensive" | "legacy";
      readonly intensity: UdpProbeIntensity;
      readonly strategy: "adaptive" | "exhaustive";
      readonly emptyFallback: "unmapped" | "afterProtocol" | "never";
      readonly allowRisks: readonly UdpProbeRisk[];
    }
  | { readonly mode: "empty" }
  | {
      readonly mode: "custom";
      readonly correlation: "tuple" | "prefixToken";
    };

export interface UdpScanSummary {
  readonly policy: UdpSelectedPolicy;
  readonly catalogue?: {
    readonly version: string;
    readonly sha256: string;
  };
}

export type UdpScanProbe = {
  readonly kind: "udp";
  readonly ports: readonly PortSelection[];
} & (
  | {
      readonly policy: UdpProbePolicy;
      readonly payload?: never;
    }
  | {
      readonly policy?: never;
      /** @deprecated Use `{ policy: { mode: "custom", payload, correlation: "prefixToken" } }`. */
      readonly payload?: Uint8Array;
    }
);

export type ScanProbe =
  | { readonly kind: "arp" }
  | { readonly kind: "ndp" }
  | { readonly kind: "icmpEcho"; readonly family: "ipv4" | "ipv6" }
  | { readonly kind: "tcpSyn"; readonly ports: readonly PortSelection[] }
  | UdpScanProbe;

export interface ScanRateOptions {
  readonly packetsPerSecond?: number;
  readonly burst?: number;
  readonly maxOutstanding?: number;
}

export interface ScanTimingOptions {
  readonly timeoutMs?: number;
  readonly minimumTimeoutMs?: number;
  readonly maximumTimeoutMs?: number;
  readonly retries?: number;
  readonly fixed?: boolean;
}

export interface ScanVlanOptions {
  readonly identifier: number;
  readonly priority?: number;
  readonly dropEligible?: boolean;
}

export interface ScanPlan {
  readonly targets: readonly ScanTarget[];
  readonly exclude?: readonly ScanTarget[];
  readonly probes: readonly ScanProbe[];
  readonly deadlineMs: number;
  readonly rate?: ScanRateOptions;
  readonly timing?: ScanTimingOptions;
  readonly seed?: bigint;
  readonly sourceAddress?: string;
  readonly interface?: string;
  readonly vlan?: ScanVlanOptions;
  readonly sourcePortRange?: { readonly start: number; readonly end: number };
}

export const DISCOVERY_OPERATIONS = Object.freeze({
  mdnsDnsSdLegacy: 1,
  wsDiscoveryProbe: 3,
  llmnrQuery: 4,
  natPmpExternalAddress: 5,
  sqlBrowserEnumeration: 6,
  rpcbindGetAddress: 7,
  tftpSentinelRead: 8,
  quicVersionNegotiation: 9,
  ripv1RoutingTable: 10,
} as const);

export type DiscoveryOperationName = keyof typeof DISCOVERY_OPERATIONS;

export type DiscoveryOperationSelection =
  | {
      readonly operation: "mdnsDnsSdLegacy";
      readonly receiveMode: "legacyUnicast";
      readonly query?: never;
      readonly followUp?: never;
    }
  | {
      readonly operation: "llmnrQuery";
      readonly query: string;
      readonly followUp?: never;
      readonly receiveMode?: never;
    }
  | {
      readonly operation: "rpcbindGetAddress";
      /** Defaults to true; false collects rpcbind evidence without child traffic. */
      readonly followUp?: boolean;
      readonly query?: never;
      readonly receiveMode?: never;
    }
  | {
      readonly operation: Exclude<
        DiscoveryOperationName,
        "mdnsDnsSdLegacy" | "llmnrQuery" | "rpcbindGetAddress"
      >;
      readonly receiveMode?: never;
      readonly query?: never;
      readonly followUp?: never;
    };

export type DiscoveryScope =
  | {
      readonly kind: "links";
      readonly interfaces: readonly string[] | "allEligible";
      readonly families: readonly ("ipv4" | "ipv6")[];
    }
  | {
      readonly kind: "targets";
      readonly targets: readonly ScanTarget[] | "kernelDefaultIpv4Gateway";
      readonly exclude?: readonly ScanTarget[];
      readonly families: readonly ("ipv4" | "ipv6")[];
    };

export interface DiscoveryPlan {
  readonly scope: DiscoveryScope;
  readonly operations: readonly DiscoveryOperationSelection[];
  readonly deadlineMs: number;
  /** Lifetime retention ceilings. Defaults to the advertised 8192-row/16 MiB session maxima. */
  readonly limits?: {
    readonly maxResults?: number;
    readonly maxMetadataBytes?: number;
  };
  /** Explicit aggregate discovery transmission budget. Defaults to 100 pps with burst 16. */
  readonly rate?: {
    readonly packetsPerSecond?: number;
    readonly burst?: number;
  };
  readonly allowRisks?: readonly UdpProbeRisk[];
}

export type ObservationRisk = "passiveMetadata" | "promiscuousCapture";
export type ObservationProtocol =
  "arp" | "ipv4" | "ipv6" | "lldp" | "controlPlane";

export const OBSERVATION_CAPABILITIES = Object.freeze({
  schemaVersion: 1 as const,
  maxSessionsPerEnvironment: 4,
  maxInterfaces: 4,
  maxDurationMs: 300_000,
  maxSnapLength: 16_384,
  maxInspectedFrames: 1_000_000,
  maxCapturedBytes: 64 * 1_024 * 1_024,
  maxResults: 8_192,
  maxMetadataBytes: 16 * 1_024 * 1_024,
  protocols: Object.freeze([
    "arp",
    "ipv4",
    "ipv6",
    "lldp",
    "controlPlane",
  ] as const),
  promiscuousByDefault: false,
  includesOutgoingByDefault: false,
  retainsFramePayloads: false,
});

/** Finite, receive-only AF_PACKET metadata observation. */
export interface ObservationPlan {
  /** One through four explicit Linux interface names. */
  readonly interfaces: readonly string[];
  /** Explicit kernel-filtered link protocol groups. */
  readonly protocols: readonly ObservationProtocol[];
  /** Defaults to 30 seconds; maximum five minutes. */
  readonly durationMs?: number;
  /** Per-frame inspection ceiling; payload bytes are never returned. */
  readonly snapLength?: number;
  readonly maxResults?: number;
  readonly maxMetadataBytes?: number;
  /** Disabled by default and additionally suppressed in the kernel. */
  readonly includeOutgoing?: boolean;
  /** Disabled by default and requires `promiscuousCapture` consent. */
  readonly promiscuous?: boolean;
  readonly allowRisks?: readonly ObservationRisk[];
}

export interface RouterSolicitationPlan {
  /** The one Linux link on which `ff02::2` will be solicited. */
  readonly interface: string;
  /** Defaults to three seconds; maximum ten seconds. */
  readonly deadlineMs?: number;
  /** Defaults to 16; maximum 64 unique link-local responders. */
  readonly maxResults?: number;
  /** Active link multicast is never implicit. */
  readonly allowRisks: readonly ["linkMulticast"];
}

export interface RouterAdvertisementResult {
  readonly responder: string;
  readonly interfaceIndex: number;
  readonly roundTripMicroseconds: bigint;
  readonly metadata: readonly Readonly<{
    key: string;
    value: Uint8Array;
  }>[];
}

export interface RouterSolicitationRun {
  readonly schemaVersion: 1;
  readonly state: "completed" | "cancelled";
  readonly interface: string;
  readonly interfaceIndex: number;
  readonly transmitted: number;
  readonly received: number;
  readonly rejected: number;
  readonly advertisements: readonly Readonly<RouterAdvertisementResult>[];
}

export interface RouterSolicitationOptions {
  readonly signal?: AbortSignal;
}

export type ObservationSessionState =
  | "running"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "failed"
  | "closed";

export interface ObservationResult {
  readonly sequence: bigint;
  readonly interfaceIndex: number;
  readonly timestampNanoseconds: bigint;
  readonly wallTimeMilliseconds?: bigint;
  readonly originalLength: number;
  readonly capturedLength: number;
  readonly packetType: number;
  readonly direction: "incoming" | "outgoing";
  readonly protocol: string;
  readonly sourceMac: Uint8Array;
  readonly destinationMac: Uint8Array;
  readonly etherType: number;
  readonly vlanIds: readonly number[];
  readonly sourceAddress?: string;
  readonly destinationAddress?: string;
  readonly sourcePort?: number;
  readonly destinationPort?: number;
  readonly metadata: readonly {
    readonly key: string;
    readonly value: Uint8Array;
  }[];
  readonly truncated: boolean;
}

export interface ObservationProgress {
  readonly inspected: bigint;
  readonly capturedBytes: bigint;
  readonly accepted: bigint;
  readonly dropped: bigint;
  /** Packets the Linux packet socket reported losing before userspace. */
  readonly kernelDropped: bigint;
  /** Parsed rows omitted solely because immutable retention limits were full. */
  readonly retentionDropped: bigint;
  readonly filtered: bigint;
  readonly truncated: bigint;
}

export interface ObservationSummary {
  readonly schemaVersion: 1;
  readonly state: "completed" | "cancelled" | "failed";
  readonly interfaces: readonly string[];
  readonly protocols: readonly ObservationProtocol[];
  readonly promiscuous: boolean;
  readonly includeOutgoing: boolean;
  readonly progress: ObservationProgress;
  readonly error?: ScannerError;
}

export interface ObservationBatchEventEmitterOptions {
  readonly maxResults?: number;
}

export interface ObservationBatchEventMap {
  batch: [batch: ObservationResultBatch];
  end: [];
  error: [error: Error];
  close: [];
}

export type DiscoverySessionState =
  | "running"
  | "pausing"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "failed"
  | "closed";

export type DiscoveryEvidence =
  "Parsed" | "QueryRelated" | "TransactionCorrelated";

export type DiscoveryOutcome = "complete" | "partial" | "truncatedByPolicy";

export interface DiscoveryMetadataField {
  readonly key: string;
  readonly value: Uint8Array;
  readonly text?: string;
}

export interface DiscoveryResult {
  readonly entityId: bigint;
  /** Result that authorized this bounded same-target child probe. */
  readonly parentEntityId?: bigint;
  /** Stable derivation vocabulary when this result came from child work. */
  readonly derivationKind?: "rpcbindGetAddress";
  readonly operationId: number;
  readonly protocol: string;
  readonly kind: string;
  readonly evidence: DiscoveryEvidence;
  readonly outcome: DiscoveryOutcome;
  readonly responder: string;
  readonly responderPort: number;
  readonly interfaceIndex?: number;
  readonly identity: Uint8Array;
  readonly addresses: readonly string[];
  readonly metadata: readonly DiscoveryMetadataField[];
  readonly truncated: boolean;
}

export interface DiscoveryProgress {
  readonly queries: bigint;
  readonly sent: bigint;
  readonly received: bigint;
  readonly receivedBytes: bigint;
  readonly accepted: bigint;
  readonly duplicate: bigint;
  readonly rejected: bigint;
  readonly truncated: bigint;
  readonly cleanupSent: bigint;
}

export interface DiscoverySummary {
  readonly schemaVersion: 1;
  readonly registryVersion: string;
  readonly registrySha256: string;
  readonly state: "completed" | "failed" | "cancelled";
  readonly results: bigint;
  readonly allowRisks: readonly UdpProbeRisk[];
  /** Explicit non-default receive modes used by this run. */
  readonly receiveModes: readonly "legacyUnicast"[];
  readonly progress: DiscoveryProgress;
  readonly error?: ScannerError;
}

export interface DiscoveryBatchEventEmitterOptions {
  readonly maxResults?: number;
}

export interface DiscoveryBatchEventMap {
  batch: [batch: DiscoveryResultBatch];
  end: [];
  error: [error: Error];
  close: [];
}

export type EvidenceSourceKind =
  | "scanResult"
  | "discoveryResult"
  | "passiveObservation"
  | "pathObservation"
  | "serviceConversation"
  | "localContext"
  | "importedSensor";

export type EvidenceEntityKind =
  | "deviceCandidate"
  | "interface"
  | "address"
  | "name"
  | "service"
  | "router"
  | "prefix"
  | "path"
  | "hop"
  | "adjacency"
  | "classification";

export type EvidenceRelationKind =
  | "hasAddress"
  | "hasName"
  | "offersService"
  | "attachedToInterface"
  | "routesPrefix"
  | "nextHop"
  | "advertisedBy"
  | "derivedFrom"
  | "classifiedAs";

export type EvidenceConfidence =
  "weak" | "structural" | "transactionCorrelated" | "strongCorrelated";

export type EvidenceDisposition =
  "observed" | "inferred" | "expired" | "withdrawn" | "conflict";

export interface EvidenceOrigin {
  readonly source: EvidenceSourceKind;
  readonly sourceSchema: number;
  readonly runId: Uint8Array;
  readonly recordId: bigint;
}

export interface EvidenceEntityKey {
  readonly kind: EvidenceEntityKind;
  readonly canonical: Uint8Array;
}

export interface EvidenceField {
  readonly key: string;
  readonly value: Uint8Array;
}

export interface EvidenceRelation {
  readonly kind: EvidenceRelationKind;
  readonly target: EvidenceEntityKey;
}

export interface EvidenceRecord {
  readonly schemaVersion: 1;
  readonly origin: EvidenceOrigin;
  readonly entity: EvidenceEntityKey;
  readonly confidence: EvidenceConfidence;
  readonly disposition: EvidenceDisposition;
  readonly observedAtNanoseconds: bigint;
  readonly expiresAtNanoseconds?: bigint;
  readonly wallTimeMilliseconds?: bigint;
  readonly fields: readonly EvidenceField[];
  readonly relations: readonly EvidenceRelation[];
}

export interface EvidenceAdapterOptions {
  readonly runId: Uint8Array;
  readonly recordId: bigint;
  readonly sourceSchema: 1 | 2;
  readonly wallTimeMilliseconds?: bigint;
}

export interface EvidenceLedgerCounters {
  readonly accepted: bigint;
  readonly duplicates: bigint;
  readonly conflicts: bigint;
  readonly rejectedCapacity: bigint;
}

export type EvidenceRetainOutcome = "accepted" | "duplicate" | "conflict";

export type ScanSessionState =
  | "created"
  | "running"
  | "pausing"
  | "paused"
  | "cancelling"
  | "completed"
  | "failed"
  | "closed";

export type ScanNetworkState =
  | "open"
  | "closed"
  | "filtered"
  | "open|filtered"
  | "up"
  | "unreachable"
  | "unknown"
  | "downByPolicy";

export type UdpResponseKind =
  | "directUdp"
  | "icmpv4TargetPortUnreachable"
  | "otherIcmpv4"
  | "icmpv6TargetPortUnreachable"
  | "icmpv6ParameterProblem"
  | "otherIcmpv6"
  | "silence";

export type UdpServiceConfidence =
  "signature" | "parsed" | "transactionCorrelated";

export interface UdpServiceMetadata {
  readonly product: string;
  readonly version?: string;
  readonly fields: readonly {
    readonly id: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
    readonly value: string;
  }[];
}

export interface ScanResult {
  readonly target: string;
  readonly probe:
    "arp" | "ndp" | "icmpEchoIpv4" | "icmpEchoIpv6" | "tcpSyn" | "udp";
  readonly port?: number | undefined;
  readonly state?: ScanNetworkState | undefined;
  readonly outcome:
    | "network"
    | "cancelled"
    | "deadline"
    | "transportFailed"
    | "contextInvalidated";
  readonly attempt: number;
  readonly transmissions: number;
  readonly rttMicros?: bigint | undefined;
  readonly rttNanoseconds?: bigint | undefined;
  readonly timestampNanoseconds: bigint;
  readonly routeGeneration: bigint;
  readonly evidence?:
    | "tuple"
    | "truncatedQuote"
    | "tcpSequence32"
    | "payload128"
    | "transaction16"
    | "transaction32"
    | "transaction64"
    | "alternateEndpoint"
    | undefined;
  readonly reason: string;
  readonly udpTerminalProbeId?: number | undefined;
  readonly udpVariantsAttempted?: number | undefined;
  readonly udpResponseKind?: UdpResponseKind | undefined;
  readonly udpServiceFamily?: number | undefined;
  readonly udpServiceConfidence?: UdpServiceConfidence | undefined;
  readonly udpService?: UdpServiceMetadata | undefined;
}

export interface ScanResultBatchColumnsV1 {
  readonly addressBytes: Uint8Array;
  readonly addressOffsets: Uint8Array;
  readonly families: Uint8Array;
  readonly scopes: Uint8Array;
  readonly probes: Uint8Array;
  readonly ports: Uint8Array;
  readonly states: Uint8Array;
  readonly outcomes: Uint8Array;
  readonly attempts: Uint8Array;
  readonly transmissions: Uint8Array;
  readonly rttNanoseconds: Uint8Array;
  readonly timestampsNanoseconds: Uint8Array;
  readonly routeGenerations: Uint8Array;
  readonly evidence: Uint8Array;
  readonly metadataBytes: Uint8Array;
  readonly metadataOffsets: Uint8Array;
}

export interface ScanResultBatchColumnsV2 extends ScanResultBatchColumnsV1 {
  readonly terminalUdpProbeIds: Uint8Array;
  readonly udpVariantsAttempted: Uint8Array;
  readonly udpResponseKinds: Uint8Array;
  readonly udpServiceFamilies: Uint8Array;
  readonly udpServiceConfidences: Uint8Array;
  readonly serviceMetadataBytes: Uint8Array;
  readonly serviceMetadataOffsets: Uint8Array;
}

export type ScanResultBatchColumns =
  ScanResultBatchColumnsV1 | ScanResultBatchColumnsV2;

export interface EncodedScanResultBatchV1 extends ScanResultBatchColumnsV1 {
  readonly schemaVersion: 1;
  readonly rowCount: number;
  readonly byteOrder: "little-endian";
}

export interface EncodedScanResultBatchV2 extends ScanResultBatchColumnsV2 {
  readonly schemaVersion: 2;
  readonly rowCount: number;
  readonly byteOrder: "little-endian";
}

export type EncodedScanResultBatch =
  EncodedScanResultBatchV1 | EncodedScanResultBatchV2;

export interface ScanResultRows extends Iterable<ScanResultView> {
  readonly length: number;
  readonly [index: number]: ScanResultView | undefined;
  at(index: number): ScanResultView | undefined;
  materialize(): ScanResult[];
}

export interface ScanSummary {
  readonly schemaVersion: 1 | 2;
  readonly state: ScanSessionState;
  readonly logicalProbes: bigint;
  readonly results: bigint;
  readonly open: bigint;
  readonly closed: bigint;
  readonly filtered: bigint;
  readonly openOrFiltered: bigint;
  readonly up: bigint;
  readonly unreachable: bigint;
  readonly unknown: bigint;
  readonly cancelled: bigint;
  readonly deadline: bigint;
  readonly discarded: bigint;
  readonly kernelDropped: bigint;
  readonly forgedOrUnrelated: bigint;
  readonly duplicates: bigint;
  readonly lateResponses: bigint;
  readonly udpIcmpPacing: bigint;
  readonly udp?: UdpScanSummary;
  readonly progress: ScanProgress;
  readonly schedulingSeed?: bigint;
  readonly accuracyTradeoff: boolean;
  readonly error?: ScannerError;
}

export interface NextBatchOptions {
  readonly maxResults?: number;
  readonly signal?: AbortSignal;
}

export interface ScanProgress {
  readonly sent: bigint;
  readonly received: bigint;
  readonly matched: bigint;
  readonly duplicate: bigint;
  readonly invalid: bigint;
  readonly timedOut: bigint;
  readonly retried: bigint;
  readonly kernelDropped: bigint;
  readonly applicationBackpressured: bigint;
  readonly coalescedUpdates: bigint;
}

export interface ScanBatchEventEmitterOptions {
  readonly maxResults?: number;
}

export type ScanBatchEventEmitterStatus =
  | "idle"
  | "running"
  | "pausing"
  | "paused"
  | "detaching"
  | "detached"
  | "closing"
  | "ended"
  | "closed";

export interface ScanBatchEventMap {
  batch: [batch: ScanResultBatch];
  end: [];
  error: [error: Error];
  close: [];
}

export interface NetworkInterface {
  readonly index: number;
  readonly name: string;
  readonly flags: number;
  readonly linkLayerType: number;
  readonly mtu?: number;
  readonly hardwareAddress: Uint8Array;
  readonly linkKind?: string;
}

export interface NetworkAddress {
  readonly interfaceIndex: number;
  readonly family: 2 | 10;
  readonly prefixLength: number;
  readonly address?: string;
  readonly local?: string;
}

export interface NetworkRoute {
  readonly family: 2 | 10;
  readonly destination?: string;
  readonly prefixLength: number;
  readonly gateway?: string;
  readonly preferredSource?: string;
  readonly interfaceIndex?: number;
  readonly table: number;
  readonly routeType: number;
}

export interface NetworkRule {
  readonly family: 2 | 10;
  readonly destination?: string;
  readonly destinationPrefixLength: number;
  readonly source?: string;
  readonly sourcePrefixLength: number;
  readonly table: number;
  readonly action: number;
  readonly priority?: number;
  readonly inputInterface?: string;
  readonly outputInterface?: string;
  readonly firewallMark?: number;
  readonly firewallMask?: number;
  readonly ipProtocol?: number;
}

export interface NetworkNeighbor {
  readonly family: 2 | 10;
  readonly interfaceIndex: number;
  readonly destination?: string;
  readonly state: number;
  readonly flags: number;
  readonly neighborType: number;
  readonly linkLayerAddress: Uint8Array;
  readonly probes?: number;
}

export interface NetworkContextSnapshot {
  readonly generation: bigint;
  readonly netnsCookie?: bigint;
  readonly interfaces: readonly NetworkInterface[];
  readonly addresses: readonly NetworkAddress[];
  readonly routes: readonly NetworkRoute[];
  readonly rules: readonly NetworkRule[];
  readonly neighbors: readonly NetworkNeighbor[];
  readonly ruleCount: number;
  readonly neighborCount: number;
}

export type ScannerErrorKind =
  | "invalidPlan"
  | "permission"
  | "unsupported"
  | "resourceLimit"
  | "lifecycle"
  | "context"
  | "io"
  | "environmentClosed"
  | "internal";

/** Stable scanner failure with the underlying Linux operation and errno when present. */
export class ScannerError extends Error {
  override readonly name = "ScannerError";
  readonly kind: ScannerErrorKind;
  readonly code: string;
  readonly operation: string;
  readonly errno: number | undefined;

  constructor(
    kind: ScannerErrorKind,
    code: string,
    operation: string,
    errno: number | undefined,
    message: string,
  ) {
    super(message);
    this.kind = kind;
    this.code = code;
    this.operation = operation;
    this.errno = errno;
  }
}

/** Frozen result-batch wire schema accepted by this release line. */
export const RESULT_BATCH_SCHEMA_VERSION = 2 as const;

/** Encoded schemas accepted by the retained-batch decoder. Protocol sessions emit version 2. */
export const SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS = Object.freeze([
  1, 2,
] as const);

/** Immutable provenance identity for the independently authored UDP catalogue. */
export const UDP_PROBE_CATALOGUE = Object.freeze({
  version: "1.4.1",
  sha256: "90c1589cd264385c6931cd6ed9efdc216f352239790a9026830bfe98cffe5e56",
  variants: 37,
  supportedProfiles: Object.freeze([
    "safe",
    "comprehensive",
    "legacy",
  ] as const),
  protocolModeAvailable: true,
} as const);

export type UdpCoverageDisposition = "implemented" | "noGo" | "excluded";
export type UdpCoverageExecutionModel =
  "none" | "targetPort" | "discovery" | "conversation";
export type UdpCoveragePolicy = "safe" | "optIn" | "excluded";
export type UdpCoverageRisk =
  | "managementDisclosure"
  | "topologyDisclosure"
  | "amplification"
  | "statefulParticipation"
  | "legacyFragility"
  | "threatSignature";
export type UdpCoverageDimension =
  | "request"
  | "correlation"
  | "typedEvidence"
  | "projectResponder"
  | "productFingerprint";

export interface UdpCoverageEntry {
  readonly id: number;
  readonly projectId: string;
  readonly phase: number;
  readonly family: string;
  readonly disposition: UdpCoverageDisposition;
  readonly executionModel: UdpCoverageExecutionModel;
  readonly policy: UdpCoveragePolicy;
  readonly risks: readonly UdpCoverageRisk[];
  /** Exact `allowRisks` values required by the resolved runtime implementation. */
  readonly requiredConsents: readonly UdpProbeRisk[];
  readonly dimensions: readonly UdpCoverageDimension[];
  readonly implementation:
    | { readonly kind: "udpProbe" | "discoveryOperation"; readonly id: number }
    | undefined;
  readonly primarySourceUrl: string;
  readonly rationale: string;
}

/** Probe kinds implemented by the portable scanner engine. */
export const SUPPORTED_SCAN_PROBES = Object.freeze([
  "arp",
  "ndp",
  "icmpEchoIpv4",
  "icmpEchoIpv6",
  "tcpSyn",
  "udp",
] as const);

/** Public admission bounds; callers can validate work before allocating it. */
export const SCANNER_LIMITS = Object.freeze({
  scannersPerEnvironment: 4,
  sessionsPerEnvironment: 4,
  pendingOperationsPerEnvironment: 64,
  controlItems: 65_536,
  controlBytes: 4 * 1_024 * 1_024,
  udpPayloadBytes: 65_491,
  batchResults: 4_096,
  defaultBatchResults: 512,
} as const);

export const EVIDENCE_SCHEMA_VERSION = 1 as const;

export const EVIDENCE_LIMITS = Object.freeze({
  records: 8_192,
  fieldsPerRecord: 128,
  relationsPerRecord: 64,
  itemBytes: 1_024,
  recordBytes: 16 * 1_024,
  batchBytes: 16 * 1_024 * 1_024,
} as const);

const MAX_BATCH_RESULTS = SCANNER_LIMITS.batchResults;
const MAX_BATCH_METADATA_BYTES = 4 * 1_024 * 1_024;
const MISSING_U64 = 0xffff_ffff_ffff_ffffn;
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const textEncoder = new TextEncoder();

/** One lazy row view over sealed, Node-owned compact batch storage. */
export class ScanResultView implements ScanResult {
  readonly #batch: ScanResultBatch;
  readonly #index: number;

  constructor(batch: ScanResultBatch, index: number) {
    this.#batch = batch;
    this.#index = index;
  }

  get target(): string {
    return this.#batch.targetAt(this.#index);
  }

  get probe(): ScanResult["probe"] {
    return decodeProbe(this.#batch.byteAt("probes", this.#index));
  }

  get port(): number | undefined {
    const value = this.#batch.u16At("ports", this.#index);
    return value === 0 ? undefined : value;
  }

  get state(): ScanNetworkState | undefined {
    return decodeState(this.#batch.byteAt("states", this.#index));
  }

  get outcome(): ScanResult["outcome"] {
    return decodeOutcome(this.#batch.byteAt("outcomes", this.#index));
  }

  get attempt(): number {
    return this.#batch.u32At("attempts", this.#index);
  }

  get transmissions(): number {
    return this.#batch.u32At("transmissions", this.#index);
  }

  get rttNanoseconds(): bigint | undefined {
    const value = this.#batch.u64At("rttNanoseconds", this.#index);
    return value === MISSING_U64 ? undefined : value;
  }

  get rttMicros(): bigint | undefined {
    const value = this.rttNanoseconds;
    return value === undefined ? undefined : value / 1_000n;
  }

  get timestampNanoseconds(): bigint {
    return this.#batch.u64At("timestampsNanoseconds", this.#index);
  }

  get routeGeneration(): bigint {
    return this.#batch.u64At("routeGenerations", this.#index);
  }

  get evidence(): ScanResult["evidence"] | undefined {
    return decodeEvidence(this.#batch.byteAt("evidence", this.#index));
  }

  get reason(): string {
    return this.#batch.metadataAt(this.#index);
  }

  get udpTerminalProbeId(): number | undefined {
    return this.#batch.udpU16At("terminalUdpProbeIds", this.#index);
  }

  get udpVariantsAttempted(): number | undefined {
    return this.probe === "udp"
      ? this.#batch.udpCountAt("udpVariantsAttempted", this.#index)
      : undefined;
  }

  get udpResponseKind(): UdpResponseKind | undefined {
    return decodeUdpResponseKind(
      this.#batch.udpByteAt("udpResponseKinds", this.#index),
    );
  }

  get udpServiceFamily(): number | undefined {
    return this.#batch.udpU16At("udpServiceFamilies", this.#index);
  }

  get udpServiceConfidence(): UdpServiceConfidence | undefined {
    return decodeUdpServiceConfidence(
      this.#batch.udpByteAt("udpServiceConfidences", this.#index),
    );
  }

  get udpService(): UdpServiceMetadata | undefined {
    return this.#batch.serviceMetadataAt(this.#index);
  }

  materialize(): ScanResult {
    const port = this.port;
    const state = this.state;
    const rttNanoseconds = this.rttNanoseconds;
    const evidence = this.evidence;
    const udpTerminalProbeId = this.udpTerminalProbeId;
    const udpVariantsAttempted = this.udpVariantsAttempted;
    const udpResponseKind = this.udpResponseKind;
    const udpServiceFamily = this.udpServiceFamily;
    const udpServiceConfidence = this.udpServiceConfidence;
    const udpService = this.udpService;
    return {
      target: this.target,
      probe: this.probe,
      ...(port === undefined ? {} : { port }),
      ...(state === undefined ? {} : { state }),
      outcome: this.outcome,
      attempt: this.attempt,
      transmissions: this.transmissions,
      ...(rttNanoseconds === undefined
        ? {}
        : {
            rttNanoseconds,
            rttMicros: rttNanoseconds / 1_000n,
          }),
      timestampNanoseconds: this.timestampNanoseconds,
      routeGeneration: this.routeGeneration,
      ...(evidence === undefined ? {} : { evidence }),
      reason: this.reason,
      ...(udpTerminalProbeId === undefined ? {} : { udpTerminalProbeId }),
      ...(udpVariantsAttempted === undefined ? {} : { udpVariantsAttempted }),
      ...(udpResponseKind === undefined ? {} : { udpResponseKind }),
      ...(udpServiceFamily === undefined ? {} : { udpServiceFamily }),
      ...(udpServiceConfidence === undefined ? {} : { udpServiceConfidence }),
      ...(udpService === undefined ? {} : { udpService }),
    };
  }
}

/** Versioned little-endian columnar result batch with lazy row decoding. */
export class ScanResultBatch implements Iterable<ScanResultView> {
  readonly schemaVersion: 1 | 2;
  readonly byteOrder = "little-endian" as const;
  readonly length: number;
  readonly columns: ScanResultBatchColumns;
  readonly results: ScanResultRows;

  constructor(encoded: EncodedScanResultBatch) {
    const snapshot = snapshotEncodedBatch(encoded);
    validateEncodedBatch(snapshot);
    const owned = ownedEncodedBatch(snapshot);
    validateEncodedBatch(owned);
    this.schemaVersion = owned.schemaVersion;
    this.length = owned.rowCount;
    const common: ScanResultBatchColumnsV1 = {
      addressBytes: owned.addressBytes,
      addressOffsets: owned.addressOffsets,
      families: owned.families,
      scopes: owned.scopes,
      probes: owned.probes,
      ports: owned.ports,
      states: owned.states,
      outcomes: owned.outcomes,
      attempts: owned.attempts,
      transmissions: owned.transmissions,
      rttNanoseconds: owned.rttNanoseconds,
      timestampsNanoseconds: owned.timestampsNanoseconds,
      routeGenerations: owned.routeGenerations,
      evidence: owned.evidence,
      metadataBytes: owned.metadataBytes,
      metadataOffsets: owned.metadataOffsets,
    };
    this.columns = Object.freeze(
      owned.schemaVersion === 1
        ? common
        : {
            ...common,
            terminalUdpProbeIds: owned.terminalUdpProbeIds,
            udpVariantsAttempted: owned.udpVariantsAttempted,
            udpResponseKinds: owned.udpResponseKinds,
            udpServiceFamilies: owned.udpServiceFamilies,
            udpServiceConfidences: owned.udpServiceConfidences,
            serviceMetadataBytes: owned.serviceMetadataBytes,
            serviceMetadataOffsets: owned.serviceMetadataOffsets,
          },
    );
    this.results = createResultRows(this);
    Object.freeze(this);
  }

  get detached(): boolean {
    // Every valid batch has at least one family byte. The documented
    // transferList moves every column together, so this is an unambiguous
    // detached sentinel without misclassifying an empty metadata payload.
    return this.columns.families.byteLength === 0;
  }

  at(index: number): ScanResultView | undefined {
    if (!Number.isInteger(index)) return undefined;
    const normalized = index < 0 ? this.length + index : index;
    if (normalized < 0 || normalized >= this.length) return undefined;
    this.assertAttached();
    return new ScanResultView(this, normalized);
  }

  *[Symbol.iterator](): IterableIterator<ScanResultView> {
    for (let index = 0; index < this.length; index += 1) {
      yield new ScanResultView(this, index);
    }
  }

  *filter(
    predicate: (row: ScanResultView, index: number) => boolean,
  ): IterableIterator<ScanResultView> {
    let index = 0;
    for (const row of this) {
      if (predicate(row, index)) yield row;
      index += 1;
    }
  }

  materialize(): ScanResult[] {
    return Array.from(this, (row) => row.materialize());
  }

  transferList(): ArrayBuffer[] {
    this.assertAttached();
    return batchColumns(this.columns).map((column) => {
      if (!(column.buffer instanceof ArrayBuffer)) {
        throw batchDataError(
          "batch column is not backed by a transferable ArrayBuffer",
        );
      }
      return column.buffer;
    });
  }

  byteAt(
    column: "probes" | "states" | "outcomes" | "evidence",
    index: number,
  ): number {
    this.assertIndex(index);
    const value = this.columns[column][index];
    if (value === undefined)
      throw batchDataError(`${column} column is truncated`);
    return value;
  }

  u16At(column: "ports", index: number): number {
    return this.dataView(column, 2).getUint16(index * 2, true);
  }

  udpU16At(
    column:
      "terminalUdpProbeIds" | "udpVariantsAttempted" | "udpServiceFamilies",
    index: number,
  ): number | undefined {
    this.assertIndex(index);
    if (!("terminalUdpProbeIds" in this.columns)) return undefined;
    const value = new DataView(
      this.columns[column].buffer,
      this.columns[column].byteOffset,
      this.columns[column].byteLength,
    ).getUint16(index * 2, true);
    return value === 0 ? undefined : value;
  }

  udpCountAt(
    column: "udpVariantsAttempted",
    index: number,
  ): number | undefined {
    this.assertIndex(index);
    if (!("terminalUdpProbeIds" in this.columns)) return undefined;
    return new DataView(
      this.columns[column].buffer,
      this.columns[column].byteOffset,
      this.columns[column].byteLength,
    ).getUint16(index * 2, true);
  }

  udpByteAt(
    column: "udpResponseKinds" | "udpServiceConfidences",
    index: number,
  ): number | undefined {
    this.assertIndex(index);
    if (!("terminalUdpProbeIds" in this.columns)) return undefined;
    const value = this.columns[column][index];
    if (value === undefined)
      throw batchDataError(`${column} column is truncated`);
    return value === 0 ? undefined : value;
  }

  serviceMetadataAt(index: number): UdpServiceMetadata | undefined {
    this.assertIndex(index);
    if (!("terminalUdpProbeIds" in this.columns)) return undefined;
    const offsets = new DataView(
      this.columns.serviceMetadataOffsets.buffer,
      this.columns.serviceMetadataOffsets.byteOffset,
      this.columns.serviceMetadataOffsets.byteLength,
    );
    const start = offsets.getUint32(index * 4, true);
    const end = offsets.getUint32((index + 1) * 4, true);
    if (start === end) return undefined;
    return decodeServiceMetadataRecord(
      this.columns.serviceMetadataBytes.subarray(start, end),
    );
  }

  u32At(
    column: "attempts" | "scopes" | "transmissions",
    index: number,
  ): number {
    return this.dataView(column, 4).getUint32(index * 4, true);
  }

  u64At(
    column: "routeGenerations" | "rttNanoseconds" | "timestampsNanoseconds",
    index: number,
  ): bigint {
    return this.dataView(column, 8).getBigUint64(index * 8, true);
  }

  targetAt(index: number): string {
    this.assertIndex(index);
    const start = this.offsetAt("addressOffsets", index);
    const end = this.offsetAt("addressOffsets", index + 1);
    const family = this.columns.families[index];
    const expected = family === 4 ? 4 : family === 6 ? 16 : 0;
    if (
      expected === 0 ||
      end - start !== expected ||
      end > this.columns.addressBytes.length
    ) {
      throw batchDataError("address family or offset is invalid");
    }
    const bytes = this.columns.addressBytes.subarray(start, end);
    const address = family === 4 ? ipv4String(bytes) : ipv6String(bytes);
    const scope = this.u32At("scopes", index);
    return scope === 0 ? address : `${address}%${String(scope)}`;
  }

  metadataAt(index: number): string {
    this.assertIndex(index);
    const start = this.offsetAt("metadataOffsets", index);
    const end = this.offsetAt("metadataOffsets", index + 1);
    if (end < start || end > this.columns.metadataBytes.length) {
      throw batchDataError("metadata offset is invalid");
    }
    try {
      return textDecoder.decode(
        this.columns.metadataBytes.subarray(start, end),
      );
    } catch {
      throw batchDataError("metadata is not valid UTF-8");
    }
  }

  private offsetAt(
    column: "addressOffsets" | "metadataOffsets",
    index: number,
  ): number {
    return this.dataView(column, 4, true).getUint32(index * 4, true);
  }

  private dataView(
    column: keyof ScanResultBatchColumns,
    width: number,
    offsetColumn = false,
  ): DataView {
    if (!offsetColumn) this.assertAttached();
    const value = this.columns[column];
    const required = (offsetColumn ? this.length + 1 : this.length) * width;
    if (value.byteLength !== required) {
      throw batchDataError(`${column} column has an invalid length`);
    }
    return new DataView(value.buffer, value.byteOffset, value.byteLength);
  }

  private assertIndex(index: number): void {
    this.assertAttached();
    if (!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw new RangeError("scan result index is out of range");
    }
  }

  private assertAttached(): void {
    if (this.detached)
      throw batchDataError("batch storage has been transferred or detached");
  }
}

function createResultRows(batch: ScanResultBatch): ScanResultRows {
  const rows = {
    get length(): number {
      return batch.length;
    },
    at(index: number): ScanResultView | undefined {
      return batch.at(index);
    },
    materialize(): ScanResult[] {
      return batch.materialize();
    },
    [Symbol.iterator](): Iterator<ScanResultView> {
      return batch[Symbol.iterator]();
    },
  };
  return new Proxy(rows, {
    get(target, property, receiver) {
      void receiver;
      if (typeof property === "string" && /^(0|[1-9]\d*)$/.test(property)) {
        return batch.at(Number(property));
      }
      if (property === "length") return target.length;
      if (property === "at") return (index: number) => target.at(index);
      if (property === "materialize") return () => target.materialize();
      if (property === Symbol.iterator) return () => target[Symbol.iterator]();
      return undefined;
    },
  });
}

function ownedBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw batchDataError("batch columns must be Uint8Array values");
  }
  return Uint8Array.from(value);
}

function ownedEncodedBatch(
  value: EncodedScanResultBatch,
): EncodedScanResultBatch {
  const common = {
    rowCount: value.rowCount,
    byteOrder: value.byteOrder,
    addressBytes: ownedBytes(value.addressBytes),
    addressOffsets: ownedBytes(value.addressOffsets),
    families: ownedBytes(value.families),
    scopes: ownedBytes(value.scopes),
    probes: ownedBytes(value.probes),
    ports: ownedBytes(value.ports),
    states: ownedBytes(value.states),
    outcomes: ownedBytes(value.outcomes),
    attempts: ownedBytes(value.attempts),
    transmissions: ownedBytes(value.transmissions),
    rttNanoseconds: ownedBytes(value.rttNanoseconds),
    timestampsNanoseconds: ownedBytes(value.timestampsNanoseconds),
    routeGenerations: ownedBytes(value.routeGenerations),
    evidence: ownedBytes(value.evidence),
    metadataBytes: ownedBytes(value.metadataBytes),
    metadataOffsets: ownedBytes(value.metadataOffsets),
  };
  return value.schemaVersion === 1
    ? { schemaVersion: 1, ...common }
    : {
        schemaVersion: 2,
        ...common,
        terminalUdpProbeIds: ownedBytes(value.terminalUdpProbeIds),
        udpVariantsAttempted: ownedBytes(value.udpVariantsAttempted),
        udpResponseKinds: ownedBytes(value.udpResponseKinds),
        udpServiceFamilies: ownedBytes(value.udpServiceFamilies),
        udpServiceConfidences: ownedBytes(value.udpServiceConfidences),
        serviceMetadataBytes: ownedBytes(value.serviceMetadataBytes),
        serviceMetadataOffsets: ownedBytes(value.serviceMetadataOffsets),
      };
}

function snapshotEncodedBatch(
  value: EncodedScanResultBatch,
): EncodedScanResultBatch {
  const untrusted = value as unknown as UntrustedEncodedScanResultBatch;
  const schemaVersion = untrusted.schemaVersion;
  const rowCount = untrusted.rowCount;
  const byteOrder = untrusted.byteOrder;
  if (byteOrder !== "little-endian")
    throw batchDataError("unsupported scan result batch byte order");
  const common = {
    rowCount,
    byteOrder: "little-endian" as const,
    addressBytes: untrusted.addressBytes,
    addressOffsets: untrusted.addressOffsets,
    families: untrusted.families,
    scopes: untrusted.scopes,
    probes: untrusted.probes,
    ports: untrusted.ports,
    states: untrusted.states,
    outcomes: untrusted.outcomes,
    attempts: untrusted.attempts,
    transmissions: untrusted.transmissions,
    rttNanoseconds: untrusted.rttNanoseconds,
    timestampsNanoseconds: untrusted.timestampsNanoseconds,
    routeGenerations: untrusted.routeGenerations,
    evidence: untrusted.evidence,
    metadataBytes: untrusted.metadataBytes,
    metadataOffsets: untrusted.metadataOffsets,
  };
  const possibleV2 = untrusted;
  const terminalUdpProbeIds = possibleV2.terminalUdpProbeIds;
  const udpVariantsAttempted = possibleV2.udpVariantsAttempted;
  const udpResponseKinds = possibleV2.udpResponseKinds;
  const udpServiceFamilies = possibleV2.udpServiceFamilies;
  const udpServiceConfidences = possibleV2.udpServiceConfidences;
  const serviceMetadataBytes = possibleV2.serviceMetadataBytes;
  const serviceMetadataOffsets = possibleV2.serviceMetadataOffsets;
  const v2Values = [
    terminalUdpProbeIds,
    udpVariantsAttempted,
    udpResponseKinds,
    udpServiceFamilies,
    udpServiceConfidences,
    serviceMetadataBytes,
    serviceMetadataOffsets,
  ];
  if (schemaVersion === 1) {
    if (v2Values.some((column) => column !== undefined))
      throw batchDataError("schema 1 batch contains schema 2 columns");
    return { schemaVersion: 1, ...common };
  }
  if (schemaVersion !== 2)
    throw batchDataError("unsupported scan result batch schema version");
  return {
    schemaVersion: 2,
    ...common,
    terminalUdpProbeIds: requiredV2Column(
      terminalUdpProbeIds,
      "terminalUdpProbeIds",
    ),
    udpVariantsAttempted: requiredV2Column(
      udpVariantsAttempted,
      "udpVariantsAttempted",
    ),
    udpResponseKinds: requiredV2Column(udpResponseKinds, "udpResponseKinds"),
    udpServiceFamilies: requiredV2Column(
      udpServiceFamilies,
      "udpServiceFamilies",
    ),
    udpServiceConfidences: requiredV2Column(
      udpServiceConfidences,
      "udpServiceConfidences",
    ),
    serviceMetadataBytes: requiredV2Column(
      serviceMetadataBytes,
      "serviceMetadataBytes",
    ),
    serviceMetadataOffsets: requiredV2Column(
      serviceMetadataOffsets,
      "serviceMetadataOffsets",
    ),
  };
}

interface UntrustedEncodedScanResultBatch extends ScanResultBatchColumnsV1 {
  readonly schemaVersion: number;
  readonly rowCount: number;
  readonly byteOrder: string;
  readonly terminalUdpProbeIds?: Uint8Array;
  readonly udpVariantsAttempted?: Uint8Array;
  readonly udpResponseKinds?: Uint8Array;
  readonly udpServiceFamilies?: Uint8Array;
  readonly udpServiceConfidences?: Uint8Array;
  readonly serviceMetadataBytes?: Uint8Array;
  readonly serviceMetadataOffsets?: Uint8Array;
}

function requiredV2Column(
  value: Uint8Array | undefined,
  name: string,
): Uint8Array {
  if (value === undefined) throw batchDataError(`schema 2 requires ${name}`);
  return value;
}

function batchColumns(value: ScanResultBatchColumns): readonly Uint8Array[] {
  const common = [
    value.addressBytes,
    value.addressOffsets,
    value.families,
    value.scopes,
    value.probes,
    value.ports,
    value.states,
    value.outcomes,
    value.attempts,
    value.transmissions,
    value.rttNanoseconds,
    value.timestampsNanoseconds,
    value.routeGenerations,
    value.evidence,
    value.metadataBytes,
    value.metadataOffsets,
  ];
  return "terminalUdpProbeIds" in value
    ? [
        ...common,
        value.terminalUdpProbeIds,
        value.udpVariantsAttempted,
        value.udpResponseKinds,
        value.udpServiceFamilies,
        value.udpServiceConfidences,
        value.serviceMetadataBytes,
        value.serviceMetadataOffsets,
      ]
    : common;
}

function validateEncodedBatch(value: EncodedScanResultBatch): void {
  if (
    untrustedBatchColumns(value).some(
      (column) => !(column instanceof Uint8Array),
    )
  ) {
    throw batchDataError("batch columns must be Uint8Array values");
  }
  if (
    !Number.isInteger(value.rowCount) ||
    value.rowCount < 1 ||
    value.rowCount > MAX_BATCH_RESULTS
  ) {
    throw batchDataError("scan result batch row count is out of range");
  }
  if (value.metadataBytes.byteLength > MAX_BATCH_METADATA_BYTES) {
    throw batchDataError("scan result batch metadata exceeds 4 MiB");
  }
  if (
    value.addressBytes.byteLength < value.rowCount * 4 ||
    value.addressBytes.byteLength > value.rowCount * 16
  ) {
    throw batchDataError("scan result address storage is out of range");
  }
  const exact: readonly [Uint8Array, number, string][] = [
    [value.families, 1, "families"],
    [value.scopes, 4, "scopes"],
    [value.probes, 1, "probes"],
    [value.ports, 2, "ports"],
    [value.states, 1, "states"],
    [value.outcomes, 1, "outcomes"],
    [value.attempts, 4, "attempts"],
    [value.transmissions, 4, "transmissions"],
    [value.rttNanoseconds, 8, "rttNanoseconds"],
    [value.timestampsNanoseconds, 8, "timestampsNanoseconds"],
    [value.routeGenerations, 8, "routeGenerations"],
    [value.evidence, 1, "evidence"],
  ];
  for (const [column, width, name] of exact) {
    if (column.byteLength !== value.rowCount * width) {
      throw batchDataError(`${name} column has an invalid length`);
    }
  }
  if (value.schemaVersion === 1) {
    for (const evidence of value.evidence) {
      if (evidence > 4) throw batchDataError("evidence code is invalid");
    }
  }
  if (value.schemaVersion === 2) {
    const version2Exact: readonly [Uint8Array, number, string][] = [
      [value.terminalUdpProbeIds, 2, "terminalUdpProbeIds"],
      [value.udpVariantsAttempted, 2, "udpVariantsAttempted"],
      [value.udpResponseKinds, 1, "udpResponseKinds"],
      [value.udpServiceFamilies, 2, "udpServiceFamilies"],
      [value.udpServiceConfidences, 1, "udpServiceConfidences"],
    ];
    for (const [column, width, name] of version2Exact) {
      if (column.byteLength !== value.rowCount * width)
        throw batchDataError(`${name} column has an invalid length`);
    }
    if (value.serviceMetadataBytes.byteLength > MAX_BATCH_METADATA_BYTES)
      throw batchDataError("scan result service metadata exceeds 4 MiB");
    validateOffsets(
      value.serviceMetadataOffsets,
      value.rowCount,
      value.serviceMetadataBytes.length,
      "service metadata",
    );
    validateSchema2Values(value);
  }
  validateOffsets(
    value.addressOffsets,
    value.rowCount,
    value.addressBytes.length,
    "address",
  );
  validateOffsets(
    value.metadataOffsets,
    value.rowCount,
    value.metadataBytes.length,
    "metadata",
  );
}

function untrustedBatchColumns(
  value: ScanResultBatchColumns,
): readonly unknown[] {
  const common = [
    value.addressBytes,
    value.addressOffsets,
    value.families,
    value.scopes,
    value.probes,
    value.ports,
    value.states,
    value.outcomes,
    value.attempts,
    value.transmissions,
    value.rttNanoseconds,
    value.timestampsNanoseconds,
    value.routeGenerations,
    value.evidence,
    value.metadataBytes,
    value.metadataOffsets,
  ];
  return "terminalUdpProbeIds" in value
    ? [
        ...common,
        value.terminalUdpProbeIds,
        value.udpVariantsAttempted,
        value.udpResponseKinds,
        value.udpServiceFamilies,
        value.udpServiceConfidences,
        value.serviceMetadataBytes,
        value.serviceMetadataOffsets,
      ]
    : common;
}

function validateOffsets(
  offsets: Uint8Array,
  rows: number,
  bytes: number,
  name: string,
): void {
  if (offsets.byteLength !== (rows + 1) * 4) {
    throw batchDataError(`${name} offsets have an invalid length`);
  }
  const view = new DataView(
    offsets.buffer,
    offsets.byteOffset,
    offsets.byteLength,
  );
  let previous = 0;
  for (let index = 0; index <= rows; index += 1) {
    const current = view.getUint32(index * 4, true);
    if (
      current < previous ||
      current > bytes ||
      (index === 0 && current !== 0)
    ) {
      throw batchDataError(`${name} offsets are not bounded and monotonic`);
    }
    previous = current;
  }
  if (previous !== bytes)
    throw batchDataError(`${name} offsets do not cover their storage`);
}

const MAX_SERVICE_METADATA_RECORD_BYTES = 1_024;
const MAX_SERVICE_METADATA_STRING_BYTES = 255;
const MAX_SERVICE_METADATA_EXTRAS = 32;
// Stable schema-2 binary IDs. Human-facing names remain a later API decision.
const SERVICE_METADATA_FIELD_IDS = new Set([1, 2, 3, 4, 5, 6, 7, 8]);

function validateSchema2Values(value: EncodedScanResultBatchV2): void {
  for (const response of value.udpResponseKinds) {
    if (response > 7) throw batchDataError("UDP response-kind code is invalid");
  }
  for (const confidence of value.udpServiceConfidences) {
    if (confidence > 3)
      throw batchDataError("UDP service-confidence code is invalid");
  }
  for (const evidence of value.evidence) {
    if (evidence > 8) throw batchDataError("evidence code is invalid");
  }
  const familyView = new DataView(
    value.udpServiceFamilies.buffer,
    value.udpServiceFamilies.byteOffset,
    value.udpServiceFamilies.byteLength,
  );
  const offsets = new DataView(
    value.serviceMetadataOffsets.buffer,
    value.serviceMetadataOffsets.byteOffset,
    value.serviceMetadataOffsets.byteLength,
  );
  for (let row = 0; row < value.rowCount; row += 1) {
    const family = familyView.getUint16(row * 2, true);
    const confidence = value.udpServiceConfidences[row] ?? 0;
    const start = offsets.getUint32(row * 4, true);
    const end = offsets.getUint32((row + 1) * 4, true);
    const record = value.serviceMetadataBytes.subarray(start, end);
    if (record.byteLength === 0) {
      if (family !== 0 || confidence !== 0)
        throw batchDataError(
          "UDP service identity requires a service metadata record",
        );
      continue;
    }
    if (family === 0 || confidence === 0)
      throw batchDataError(
        "UDP service metadata requires family and confidence",
      );
    validateServiceMetadataRecord(record);
  }
}

function validateServiceMetadataRecord(record: Uint8Array): void {
  if (record.byteLength > MAX_SERVICE_METADATA_RECORD_BYTES)
    throw batchDataError("UDP service metadata record exceeds 1 KiB");
  let cursor = 0;
  const byte = (): number => {
    const result = record[cursor];
    if (result === undefined)
      throw batchDataError("UDP service metadata record is truncated");
    cursor += 1;
    return result;
  };
  const u16 = (): number => byte() | (byte() << 8);
  const string = (): void => {
    const length = u16();
    if (length > MAX_SERVICE_METADATA_STRING_BYTES)
      throw batchDataError("UDP service metadata string exceeds 255 bytes");
    const end = cursor + length;
    if (end > record.byteLength)
      throw batchDataError("UDP service metadata string is truncated");
    try {
      textDecoder.decode(record.subarray(cursor, end));
    } catch {
      throw batchDataError("UDP service metadata is not valid UTF-8");
    }
    cursor = end;
  };
  if (byte() !== 1)
    throw batchDataError("UDP service metadata version is unsupported");
  string();
  string();
  const extras = byte();
  if (extras > MAX_SERVICE_METADATA_EXTRAS)
    throw batchDataError("UDP service metadata has too many extra fields");
  let priorField = 0;
  for (let index = 0; index < extras; index += 1) {
    const field = u16();
    if (!SERVICE_METADATA_FIELD_IDS.has(field))
      throw batchDataError("UDP service metadata field ID is unsupported");
    if (field <= priorField)
      throw batchDataError(
        "UDP service metadata fields are not unique and ordered",
      );
    priorField = field;
    string();
  }
  if (cursor !== record.byteLength)
    throw batchDataError("UDP service metadata record has trailing bytes");
}

function decodeServiceMetadataRecord(record: Uint8Array): UdpServiceMetadata {
  validateServiceMetadataRecord(record);
  let cursor = 1;
  const string = (): string => {
    const length = (record[cursor] ?? 0) | ((record[cursor + 1] ?? 0) << 8);
    cursor += 2;
    const value = textDecoder.decode(record.subarray(cursor, cursor + length));
    cursor += length;
    return value;
  };
  const product = string();
  const version = string();
  const count = record[cursor] ?? 0;
  cursor += 1;
  const fields: { id: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8; value: string }[] = [];
  for (let index = 0; index < count; index += 1) {
    const id = (record[cursor] ?? 0) | ((record[cursor + 1] ?? 0) << 8);
    cursor += 2;
    fields.push({
      id: id as 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8,
      value: string(),
    });
  }
  return Object.freeze({
    product,
    ...(version.length === 0 ? {} : { version }),
    fields: Object.freeze(fields.map((field) => Object.freeze(field))),
  });
}

function decodeUdpResponseKind(
  value: number | undefined,
): UdpResponseKind | undefined {
  const decoded = [
    undefined,
    "directUdp",
    "icmpv4TargetPortUnreachable",
    "otherIcmpv4",
    "icmpv6TargetPortUnreachable",
    "icmpv6ParameterProblem",
    "otherIcmpv6",
    "silence",
  ][value ?? 0];
  return decoded as UdpResponseKind | undefined;
}

function decodeUdpServiceConfidence(
  value: number | undefined,
): UdpServiceConfidence | undefined {
  const decoded = [undefined, "signature", "parsed", "transactionCorrelated"][
    value ?? 0
  ];
  return decoded as UdpServiceConfidence | undefined;
}

function decodeProbe(value: number): ScanResult["probe"] {
  const decoded = [
    undefined,
    "arp",
    "ndp",
    "icmpEchoIpv4",
    "icmpEchoIpv6",
    "tcpSyn",
    "udp",
  ][value];
  if (decoded === undefined) throw batchDataError("probe code is invalid");
  return decoded as ScanResult["probe"];
}

function decodeState(value: number): ScanNetworkState | undefined {
  const decoded = [
    undefined,
    "open",
    "closed",
    "filtered",
    "open|filtered",
    "up",
    "unreachable",
    "unknown",
    "downByPolicy",
  ][value];
  if (value !== 0 && decoded === undefined)
    throw batchDataError("network-state code is invalid");
  return decoded as ScanNetworkState | undefined;
}

function decodeOutcome(value: number): ScanResult["outcome"] {
  const decoded = [
    undefined,
    "network",
    "cancelled",
    "deadline",
    "transportFailed",
    "contextInvalidated",
  ][value];
  if (decoded === undefined) throw batchDataError("outcome code is invalid");
  return decoded as ScanResult["outcome"];
}

function decodeEvidence(value: number): ScanResult["evidence"] | undefined {
  const decoded = [
    undefined,
    "tuple",
    "truncatedQuote",
    "tcpSequence32",
    "payload128",
    "transaction16",
    "transaction32",
    "transaction64",
    "alternateEndpoint",
  ][value];
  if (value !== 0 && decoded === undefined)
    throw batchDataError("evidence code is invalid");
  return decoded as ScanResult["evidence"] | undefined;
}

function ipv4String(bytes: Uint8Array): string {
  return Array.from(bytes, String).join(".");
}

function ipv6String(bytes: Uint8Array): string {
  const groups = Array.from(
    { length: 8 },
    (_, index) => ((bytes[index * 2] ?? 0) << 8) | (bytes[index * 2 + 1] ?? 0),
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start + 1;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestStart === -1)
    return groups.map((group) => group.toString(16)).join(":");
  const left = groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function batchDataError(message: string): ScannerError {
  return new ScannerError(
    "internal",
    "ERR_INVALID_BATCH",
    "decode result batch",
    undefined,
    message,
  );
}

interface NativeTarget {
  cidr?: string;
  start?: string;
  end?: string;
}

interface NativeProbe {
  kind: string;
  family?: string;
  ports?: { start: number; end: number }[];
  payload?: number[];
  udpMode?: "legacyPrefix" | "empty" | "custom" | "protocol";
  udpProfile?: "safe" | "comprehensive" | "legacy";
  udpIntensity?: number;
  udpStrategy?: "adaptive" | "exhaustive";
  udpEmptyFallback?: "unmapped" | "afterProtocol" | "never";
  udpAllowRisks?: UdpProbeRisk[];
  udpCorrelation?: "tuple" | "prefixToken";
}

interface NativePlan {
  targets: NativeTarget[];
  exclude?: NativeTarget[];
  probes: NativeProbe[];
  deadlineMs: number;
  rate?: ScanRateOptions;
  timing?: ScanTimingOptions;
  seed?: string;
  sourceAddress?: string;
  interface?: string;
  vlan?: ScanVlanOptions;
  sourcePortStart?: number;
  sourcePortEnd?: number;
}

interface NativeDiscoveryPlan {
  scope: {
    kind: "links" | "targets";
    interfaces?: string[];
    allEligible?: boolean;
    families: ("ipv4" | "ipv6")[];
    targets?: NativeTarget[];
    exclude?: NativeTarget[];
    kernelDefaultIpv4Gateway?: boolean;
  };
  operations: {
    id: number;
    query?: string;
    followUp?: boolean;
    receiveMode?: "legacyUnicast";
  }[];
  deadlineMs: number;
  limits?: { maxResults?: number; maxMetadataBytes?: number };
  rate?: { packetsPerSecond?: number; burst?: number };
  allowRisks?: UdpProbeRisk[];
}

interface NativeDiscoveryRun {
  schemaVersion: number;
  registryVersion: string;
  registrySha256: string;
  state: "completed" | "cancelled";
  allowRisks: string[];
  receiveModes: "legacyUnicast"[];
  rows: {
    entityId: string;
    parentEntityId?: string;
    derivationKind?: string;
    operationId: number;
    protocol: string;
    kind: string;
    evidence: string;
    outcome: string;
    responder: string;
    responderPort: number;
    interfaceIndex?: number;
    identity: number[];
    addresses: string[];
    metadata: { key: string; value: number[]; text?: string }[];
    truncated: boolean;
  }[];
  progress: {
    queries: string;
    sent: string;
    received: string;
    receivedBytes: string;
    accepted: string;
    duplicate: string;
    rejected: string;
    truncated: string;
    cleanupSent: string;
  };
}

interface NativeDiscoveryCompletion {
  run?: unknown;
  error?: NativeFailure;
}

interface NativeObservationPlan {
  interfaces: string[];
  protocols: ObservationProtocol[];
  durationMs?: number;
  snapLength?: number;
  maxResults?: number;
  maxMetadataBytes?: number;
  includeOutgoing?: boolean;
  promiscuous?: boolean;
  allowRisks?: ObservationRisk[];
}

interface NativeRouterSolicitationPlan {
  interface: string;
  deadlineMs?: number;
  maxResults?: number;
  allowRisks: string[];
}

interface NativeRouterSolicitationRun {
  schemaVersion: number;
  state: string;
  interface: string;
  interfaceIndex: number;
  transmitted: number;
  received: number;
  rejected: number;
  advertisements: {
    responder: string;
    interfaceIndex: number;
    roundTripMicroseconds: string;
    metadata: { key: string; value: number[] }[];
  }[];
}

interface NativeRouterSolicitationCompletion {
  run?: unknown;
  error?: NativeFailure;
}

interface NativePathPlan {
  target: string;
  mode: string;
  port?: number;
  firstHop?: number;
  maximumHop?: number;
  attemptsPerHop?: number;
  pacingMs?: number;
  deadlineMs: number;
}

interface NativePathRun {
  schemaVersion: number;
  target: string;
  mode: string;
  state: string;
  destinationReached: boolean;
  truncated: boolean;
  attempts: {
    hop: number;
    attempt: number;
    responder?: string;
    roundTripMicroseconds?: string;
    outcome: string;
    correlation: string;
    icmpFamily?: number;
    icmpType?: number;
    icmpCode?: number;
  }[];
}

interface NativePathCompletion {
  run?: NativePathRun;
  error?: NativeFailure;
}

interface NativeServiceIdentificationPlan {
  capabilityId: string;
  target: string;
  port: number;
  deadlineMs: number;
  allowRisks: string[];
}

interface NativeServiceIdentificationRun {
  schemaVersion: number;
  capabilityId: string;
  target: string;
  port: number;
  state: string;
  outcome: string;
  protocol?: string;
  confidence?: string;
  fields: { key: string; value: number[] }[];
  requestBytes: number;
  responseBytes: number;
}

interface NativeServiceCompletion {
  run?: NativeServiceIdentificationRun;
  error?: NativeFailure;
}

interface NativeObservationRow {
  sequence: string;
  interfaceIndex: number;
  timestampNanoseconds: string;
  wallTimeMilliseconds?: string;
  originalLength: number;
  capturedLength: number;
  packetType: number;
  direction: "incoming" | "outgoing";
  protocol: string;
  sourceMac: number[];
  destinationMac: number[];
  etherType: number;
  vlanIds: number[];
  sourceAddress?: string;
  destinationAddress?: string;
  sourcePort?: number;
  destinationPort?: number;
  metadata: { key: string; value: number[] }[];
  truncated: boolean;
}

interface NativeObservationProgress {
  inspected: string;
  capturedBytes: string;
  accepted: string;
  dropped: string;
  kernelDropped: string;
  retentionDropped: string;
  filtered: string;
  truncated: string;
}

interface NativeObservationBatch {
  state: "running" | "paused" | "cancelling" | "completed" | "failed";
  rows: NativeObservationRow[];
  progress: NativeObservationProgress;
}

interface NativeObservationRun {
  schemaVersion: number;
  state: "completed" | "cancelled";
  interfaces: string[];
  protocols: ObservationProtocol[];
  promiscuous: boolean;
  includeOutgoing: boolean;
  progress: NativeObservationProgress;
}

interface NativeObservationCompletion {
  run?: NativeObservationRun;
  error?: NativeFailure;
}

type NativeBatch = EncodedScanResultBatch;

interface NativePullResult {
  status: "batch" | "terminal" | "aborted";
  batch?: NativeBatch;
}

interface NativeProgress {
  sent: string;
  received: string;
  matched: string;
  duplicate: string;
  invalid: string;
  timedOut: string;
  retried: string;
  kernelDropped: string;
  applicationBackpressured: string;
  coalescedUpdates: string;
}

interface NativeSummary {
  schemaVersion: 1 | 2;
  state: ScanSessionState;
  logicalProbes: string;
  results: string;
  open: string;
  closed: string;
  filtered: string;
  openOrFiltered: string;
  up: string;
  unreachable: string;
  unknown: string;
  cancelled: string;
  deadline: string;
  discarded: string;
  kernelDropped: string;
  forgedOrUnrelated: string;
  duplicates: string;
  lateResponses: string;
  udpIcmpPacing?: string;
  udpCatalogueVersion?: string;
  udpCatalogueSha256?: string;
  udpPolicyMode?: "protocol" | "empty" | "custom";
  udpProfile?: "safe" | "comprehensive" | "legacy";
  udpIntensity?: UdpProbeIntensity;
  udpStrategy?: "adaptive" | "exhaustive";
  udpEmptyFallback?: "unmapped" | "afterProtocol" | "never";
  udpAllowRisks?: UdpProbeRisk[];
  udpCustomCorrelation?: "tuple" | "prefixToken";
  progress: NativeProgress;
  schedulingSeed?: string;
  accuracyTradeoff: boolean;
  error?: NativeFailure;
}

interface NativeFailure {
  kind: ScannerErrorKind;
  code: string;
  operation: string;
  errno?: number;
  message: string;
}

interface NativeSnapshot {
  generation: string;
  netnsCookie?: string;
  interfaces: (Omit<NetworkInterface, "hardwareAddress"> & {
    hardwareAddress: number[];
  })[];
  addresses: NetworkAddress[];
  routes: NetworkRoute[];
  rules: NetworkRule[];
  neighbors: (Omit<NetworkNeighbor, "linkLayerAddress"> & {
    linkLayerAddress: number[];
  })[];
  ruleCount: number;
  neighborCount: number;
}

interface NativeScannerHandle {
  ready(): Promise<unknown>;
  solicitRouters(
    plan: NativeRouterSolicitationPlan,
    solicitationId: number,
    callback: (completion: NativeRouterSolicitationCompletion) => void,
  ): void;
  cancelRouterSolicitation(solicitationId: number): void;
  tracePath(
    plan: NativePathPlan,
    pathId: number,
    callback: (completion: NativePathCompletion) => void,
  ): void;
  cancelPath(pathId: number): void;
  identifyService(
    plan: NativeServiceIdentificationPlan,
    serviceId: number,
    callback: (completion: NativeServiceCompletion) => void,
  ): void;
  cancelService(serviceId: number): void;
  start(plan: NativePlan): Promise<unknown>;
  discover(
    plan: NativeDiscoveryPlan,
    discoveryId: number,
    callback: (completion: NativeDiscoveryCompletion) => void,
  ): void;
  pauseDiscovery(discoveryId: number): void;
  resumeDiscovery(discoveryId: number): void;
  cancelDiscovery(discoveryId: number): void;
  discoveryState(discoveryId: number): string;
  discoveryProgress(discoveryId: number): NativeDiscoveryRun["progress"];
  observe(
    plan: NativeObservationPlan,
    observationId: number,
    callback: (completion: NativeObservationCompletion) => void,
  ): void;
  readyObservation(observationId: number): Promise<unknown>;
  pauseObservation(observationId: number): void;
  resumeObservation(observationId: number): void;
  cancelObservation(observationId: number): void;
  observationBatch(
    observationId: number,
    maximum?: number,
  ): NativeObservationBatch;
  observationProgress(observationId: number): NativeObservationProgress;
  closeObservation(observationId: number): void;
  pause(sessionId: number): Promise<unknown>;
  resume(sessionId: number): Promise<unknown>;
  cancel(sessionId: number): Promise<unknown>;
  nextBatch(
    sessionId: number,
    pullId: number,
    maximum?: number,
  ): Promise<unknown>;
  cancelPull(sessionId: number, pullId: number): Promise<unknown>;
  progress(sessionId: number): Promise<unknown>;
  summary(sessionId: number): Promise<unknown>;
  closeSession(sessionId: number): Promise<unknown>;
  state(sessionId: number): string;
  close(): Promise<unknown>;
}

interface NativeBinding {
  createNativeScanner(): NativeScannerHandle;
  inspectNetworkContext(): Promise<unknown>;
  udpProbeCatalogueCapabilities(): {
    version: string;
    sha256: string;
    variants: number;
  };
  udpCoverageCapabilities(): {
    version: string;
    maximumCandidates: number;
    maximumCompiledVariants: number;
    maximumPhysicalQueries: number;
    maximumResponseBytes: number;
    maximumMetadataBytes: number;
    maximumReturnedEndpoints: number;
    maximumStateLifetimeMs: number;
    entries: {
      id: number;
      projectId: string;
      phase: number;
      family: string;
      disposition: string;
      executionModel: string;
      policy: string;
      risks: string[];
      requiredConsents: string[];
      dimensions: string[];
      implementationKind?: string;
      implementationId?: number;
      primarySourceUrl: string;
      rationale: string;
    }[];
  };
  serviceRegistryCapabilities(): {
    version: string;
    entries: {
      id: string;
      ports: number[];
      disposition: string;
      risk: string;
      maximumRequestBytes: number;
      maximumResponseBytes: number;
    }[];
  };
  discoveryCapabilities(): {
    registryVersion: string;
    registrySha256: string;
    schemaVersion: number;
    maxSessions: number;
    maxResults: number;
    maxMetadataBytes: number;
    maxSockets: number;
    maxPhysicalQueries: number;
    operations: {
      id: number;
      name: string;
      scope: string;
      families: string[];
      destinationPort: number;
      requiredRisks: string[];
      maximumRequestBytes: number;
      maximumResponseBytes: number;
      maximumEntitiesPerQuery: number;
      maximumMetadataBytesPerQuery: number;
      responseWindowMs: number;
      supportsFollowUp: boolean;
      receiveModes: "legacyUnicast"[];
    }[];
    noGo: string[];
  };
}

const require = createRequire(import.meta.url);
const native = require("../build/native/binding.cjs") as NativeBinding;
const compiledUdpCatalogue = native.udpProbeCatalogueCapabilities();
if (
  compiledUdpCatalogue.version !== UDP_PROBE_CATALOGUE.version ||
  compiledUdpCatalogue.sha256 !== UDP_PROBE_CATALOGUE.sha256 ||
  compiledUdpCatalogue.variants !== UDP_PROBE_CATALOGUE.variants
) {
  throw new Error("native and TypeScript UDP probe catalogue metadata differ");
}
const nativeUdpCoverage = native.udpCoverageCapabilities();

const UDP_COVERAGE_DISPOSITIONS = new Set<UdpCoverageDisposition>([
  "implemented",
  "noGo",
  "excluded",
]);
const UDP_COVERAGE_EXECUTION_MODELS = new Set<UdpCoverageExecutionModel>([
  "none",
  "targetPort",
  "discovery",
  "conversation",
]);
const UDP_COVERAGE_POLICIES = new Set<UdpCoveragePolicy>([
  "safe",
  "optIn",
  "excluded",
]);
const UDP_COVERAGE_RISKS = new Set<UdpCoverageRisk>([
  "managementDisclosure",
  "topologyDisclosure",
  "amplification",
  "statefulParticipation",
  "legacyFragility",
  "threatSignature",
]);
const UDP_COVERAGE_RUNTIME_CONSENTS = new Set<UdpProbeRisk>([
  "highAmplification",
  "statefulHandshake",
  "authenticationAttempt",
  "multicastOrBroadcast",
  "sensitiveRead",
]);
const UDP_COVERAGE_DIMENSIONS = new Set<UdpCoverageDimension>([
  "request",
  "correlation",
  "typedEvidence",
  "projectResponder",
  "productFingerprint",
]);
const DISCOVERY_OPERATION_IDS = new Set<number>(
  Object.values(DISCOVERY_OPERATIONS),
);

function checkedUdpCoverageEntry(
  entry: ReturnType<
    NativeBinding["udpCoverageCapabilities"]
  >["entries"][number],
  index: number,
): UdpCoverageEntry {
  const disposition = entry.disposition as UdpCoverageDisposition;
  const executionModel = entry.executionModel as UdpCoverageExecutionModel;
  const policy = entry.policy as UdpCoveragePolicy;
  const risks = entry.risks as UdpCoverageRisk[];
  const requiredConsents = entry.requiredConsents as UdpProbeRisk[];
  const dimensions = entry.dimensions as UdpCoverageDimension[];
  const implementationPairPresent =
    entry.implementationKind !== undefined &&
    entry.implementationId !== undefined;
  if (
    entry.id !== index + 1 ||
    entry.id < 1 ||
    entry.phase < 60 ||
    entry.phase > 68 ||
    entry.projectId.length === 0 ||
    entry.family.length === 0 ||
    entry.rationale.length === 0 ||
    !entry.primarySourceUrl.startsWith("https://") ||
    !UDP_COVERAGE_DISPOSITIONS.has(disposition) ||
    !UDP_COVERAGE_EXECUTION_MODELS.has(executionModel) ||
    !UDP_COVERAGE_POLICIES.has(policy) ||
    risks.some((risk) => !UDP_COVERAGE_RISKS.has(risk)) ||
    requiredConsents.some(
      (consent) => !UDP_COVERAGE_RUNTIME_CONSENTS.has(consent),
    ) ||
    new Set(requiredConsents).size !== requiredConsents.length ||
    dimensions.some((dimension) => !UDP_COVERAGE_DIMENSIONS.has(dimension)) ||
    (entry.implementationKind !== undefined) !==
      (entry.implementationId !== undefined) ||
    (entry.implementationId !== undefined &&
      (!Number.isInteger(entry.implementationId) ||
        entry.implementationId < 1)) ||
    (implementationPairPresent &&
      entry.implementationKind !== "udpProbe" &&
      entry.implementationKind !== "discoveryOperation") ||
    (entry.implementationKind === "udpProbe" &&
      entry.implementationId !== undefined &&
      entry.implementationId > UDP_PROBE_CATALOGUE.variants) ||
    (entry.implementationKind === "discoveryOperation" &&
      entry.implementationId !== undefined &&
      !DISCOVERY_OPERATION_IDS.has(entry.implementationId))
  ) {
    throw new Error(`invalid native UDP coverage entry ${String(index + 1)}`);
  }
  const requiredDimensions: readonly UdpCoverageDimension[] = [
    "request",
    "correlation",
    "typedEvidence",
    "projectResponder",
  ];
  if (
    (disposition === "implemented") !== implementationPairPresent ||
    (disposition === "implemented" &&
      (executionModel === "none" ||
        policy === "excluded" ||
        requiredDimensions.some(
          (dimension) => !dimensions.includes(dimension),
        ))) ||
    (disposition !== "implemented" &&
      (executionModel !== "none" ||
        policy !== "excluded" ||
        dimensions.length !== 0 ||
        requiredConsents.length !== 0)) ||
    (disposition === "excluded" && !risks.includes("threatSignature"))
  ) {
    throw new Error(
      `inconsistent native UDP coverage entry ${String(index + 1)}`,
    );
  }
  const implementation =
    entry.implementationKind !== undefined &&
    entry.implementationId !== undefined
      ? Object.freeze({
          kind: entry.implementationKind as "udpProbe" | "discoveryOperation",
          id: entry.implementationId,
        })
      : undefined;
  return Object.freeze({
    id: entry.id,
    projectId: entry.projectId,
    phase: entry.phase,
    family: entry.family,
    disposition,
    executionModel,
    policy,
    risks: Object.freeze([...risks]),
    requiredConsents: Object.freeze([...requiredConsents]),
    dimensions: Object.freeze([...dimensions]),
    implementation,
    primarySourceUrl: entry.primarySourceUrl,
    rationale: entry.rationale,
  });
}

if (
  nativeUdpCoverage.version !== "1.1.0" ||
  nativeUdpCoverage.entries.length === 0 ||
  nativeUdpCoverage.entries.length > nativeUdpCoverage.maximumCandidates ||
  nativeUdpCoverage.maximumCandidates !== 64 ||
  nativeUdpCoverage.maximumCompiledVariants !== 256 ||
  nativeUdpCoverage.maximumPhysicalQueries !== 1_024 ||
  nativeUdpCoverage.maximumResponseBytes !== 4_096 ||
  nativeUdpCoverage.maximumMetadataBytes !== 65_536 ||
  nativeUdpCoverage.maximumReturnedEndpoints !== 1_024 ||
  nativeUdpCoverage.maximumStateLifetimeMs !== 60_000
) {
  throw new Error("invalid native UDP coverage registry contract");
}

/** Final Phase 59–68 candidate decisions, support dimensions, and hard ceilings. */
const checkedUdpCoverageEntries = nativeUdpCoverage.entries.map(
  checkedUdpCoverageEntry,
);
if (
  checkedUdpCoverageEntries.length !== 41 ||
  new Set(checkedUdpCoverageEntries.map((entry) => entry.projectId)).size !==
    checkedUdpCoverageEntries.length ||
  checkedUdpCoverageEntries.filter(
    (entry) => entry.disposition === "implemented",
  ).length !== 5 ||
  checkedUdpCoverageEntries.filter((entry) => entry.disposition === "noGo")
    .length !== 32 ||
  checkedUdpCoverageEntries.filter((entry) => entry.disposition === "excluded")
    .length !== 4
) {
  throw new Error("native UDP coverage registry membership differs");
}

export const UDP_COVERAGE_CAPABILITIES = Object.freeze({
  version: "1.1.0" as const,
  resources: Object.freeze({
    maximumCandidates: nativeUdpCoverage.maximumCandidates,
    maximumCompiledVariants: nativeUdpCoverage.maximumCompiledVariants,
    maximumPhysicalQueries: nativeUdpCoverage.maximumPhysicalQueries,
    maximumResponseBytes: nativeUdpCoverage.maximumResponseBytes,
    maximumMetadataBytes: nativeUdpCoverage.maximumMetadataBytes,
    maximumReturnedEndpoints: nativeUdpCoverage.maximumReturnedEndpoints,
    maximumStateLifetimeMs: nativeUdpCoverage.maximumStateLifetimeMs,
  }),
  entries: Object.freeze(checkedUdpCoverageEntries),
});
const nativeDiscoveryCapabilities = native.discoveryCapabilities();
const nativeServiceRegistry = native.serviceRegistryCapabilities();
if (
  nativeServiceRegistry.version !==
    DISCOVERY_PLATFORM_VERSIONS.serviceRegistry ||
  nativeServiceRegistry.entries.length !== SERVICE_CAPABILITIES.length ||
  nativeServiceRegistry.entries.some((entry, index) => {
    const typescript = SERVICE_CAPABILITIES[index];
    return (
      entry.id !== typescript?.id ||
      entry.disposition !== typescript.disposition ||
      entry.risk !== typescript.risk ||
      entry.maximumRequestBytes !== typescript.maximumRequestBytes ||
      entry.maximumResponseBytes !== typescript.maximumResponseBytes ||
      entry.ports.length !== typescript.ports.length ||
      entry.ports.some(
        (port, portIndex) => port !== typescript.ports[portIndex],
      )
    );
  })
) {
  throw new Error("native and TypeScript service registries differ");
}

/** Runtime discovery registry, resource ceilings, and explicit no-go families. */
export const DISCOVERY_CAPABILITIES = Object.freeze({
  registryVersion: nativeDiscoveryCapabilities.registryVersion,
  registrySha256: nativeDiscoveryCapabilities.registrySha256,
  schemaVersion: 1 as const,
  maxSessions: nativeDiscoveryCapabilities.maxSessions,
  maxResults: nativeDiscoveryCapabilities.maxResults,
  maxMetadataBytes: nativeDiscoveryCapabilities.maxMetadataBytes,
  maxSockets: nativeDiscoveryCapabilities.maxSockets,
  maxPhysicalQueries: nativeDiscoveryCapabilities.maxPhysicalQueries,
  operations: Object.freeze(
    nativeDiscoveryCapabilities.operations.map((operation) =>
      Object.freeze({
        ...operation,
        families: Object.freeze([...operation.families]),
        requiredRisks: Object.freeze([...operation.requiredRisks]),
        receiveModes: Object.freeze([...operation.receiveModes]),
      }),
    ),
  ),
  noGo: Object.freeze([...nativeDiscoveryCapabilities.noGo]),
} as const);

/** Copy and validate one immutable evidence record at the public boundary. */
export function createEvidenceRecord(record: EvidenceRecord): EvidenceRecord {
  if (
    (record as { readonly schemaVersion: unknown }).schemaVersion !==
    EVIDENCE_SCHEMA_VERSION
  )
    throw new RangeError("unsupported evidence schema version");
  if (
    !Number.isInteger(record.origin.sourceSchema) ||
    record.origin.sourceSchema <= 0
  )
    throw new RangeError("evidence source schema must be a positive integer");
  if (record.origin.recordId < 0n)
    throw new RangeError("evidence record identifier must be non-negative");
  if (record.observedAtNanoseconds < 0n)
    throw new RangeError("evidence observation time must be non-negative");
  if (
    record.expiresAtNanoseconds !== undefined &&
    record.expiresAtNanoseconds < record.observedAtNanoseconds
  )
    throw new RangeError("evidence expiry precedes its observation");
  if (record.fields.length > EVIDENCE_LIMITS.fieldsPerRecord)
    throw new RangeError("evidence field ceiling exceeded");
  if (record.relations.length > EVIDENCE_LIMITS.relationsPerRecord)
    throw new RangeError("evidence relation ceiling exceeded");
  assertEvidenceEnum(
    record.origin.source,
    EVIDENCE_SOURCE_KINDS,
    "evidence source kind",
  );
  assertEvidenceEnum(
    record.entity.kind,
    EVIDENCE_ENTITY_KINDS,
    "evidence entity kind",
  );
  assertEvidenceEnum(
    record.confidence,
    EVIDENCE_CONFIDENCES,
    "evidence confidence",
  );
  assertEvidenceEnum(
    record.disposition,
    EVIDENCE_DISPOSITIONS,
    "evidence disposition",
  );
  const runId = evidenceBytes(
    record.origin.runId,
    "evidence run identifier",
    true,
  );
  const canonical = evidenceBytes(
    record.entity.canonical,
    "evidence canonical key",
    true,
  );
  const fields = record.fields.map((field) => {
    if (typeof field.key !== "string" || field.key.length === 0)
      throw new TypeError("evidence field key must be a non-empty string");
    if (textEncoder.encode(field.key).byteLength > EVIDENCE_LIMITS.itemBytes)
      throw new RangeError("evidence field key ceiling exceeded");
    return Object.freeze({
      key: field.key,
      value: evidenceBytes(field.value, "evidence field value", false),
    });
  });
  fields.sort(compareEvidenceFields);
  const dedupedFields = fields.filter((field, index) => {
    if (index === 0) return true;
    const previous = fields.at(index - 1);
    return (
      previous === undefined || compareEvidenceFields(field, previous) !== 0
    );
  });
  const relations = record.relations.map((relation) => {
    assertEvidenceEnum(
      relation.kind,
      EVIDENCE_RELATION_KINDS,
      "evidence relation kind",
    );
    assertEvidenceEnum(
      relation.target.kind,
      EVIDENCE_ENTITY_KINDS,
      "evidence relation entity kind",
    );
    return Object.freeze({
      kind: relation.kind,
      target: Object.freeze({
        kind: relation.target.kind,
        canonical: evidenceBytes(
          relation.target.canonical,
          "evidence relation canonical key",
          true,
        ),
      }),
    });
  });
  relations.sort(compareEvidenceRelations);
  const dedupedRelations = relations.filter((relation, index) => {
    if (index === 0) return true;
    const previous = relations.at(index - 1);
    return (
      previous === undefined ||
      compareEvidenceRelations(relation, previous) !== 0
    );
  });
  const variableBytes = dedupedFields.reduce(
    (total, field) =>
      checkedEvidenceBytes(
        checkedEvidenceBytes(total, textEncoder.encode(field.key).byteLength),
        field.value.byteLength,
      ),
    checkedEvidenceBytes(runId.byteLength, canonical.byteLength),
  );
  const withRelations = dedupedRelations.reduce(
    (total, relation) =>
      checkedEvidenceBytes(total, relation.target.canonical.byteLength),
    variableBytes,
  );
  if (withRelations > EVIDENCE_LIMITS.recordBytes)
    throw new RangeError("evidence record byte ceiling exceeded");
  return Object.freeze({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    origin: Object.freeze({
      source: record.origin.source,
      sourceSchema: record.origin.sourceSchema,
      runId,
      recordId: record.origin.recordId,
    }),
    entity: Object.freeze({ kind: record.entity.kind, canonical }),
    confidence: record.confidence,
    disposition: record.disposition,
    observedAtNanoseconds: record.observedAtNanoseconds,
    ...(record.expiresAtNanoseconds === undefined
      ? {}
      : { expiresAtNanoseconds: record.expiresAtNanoseconds }),
    ...(record.wallTimeMilliseconds === undefined
      ? {}
      : { wallTimeMilliseconds: record.wallTimeMilliseconds }),
    fields: Object.freeze(dedupedFields),
    relations: Object.freeze(dedupedRelations),
  });
}

/** Losslessly project one decoded scan result into additive address evidence. */
export function evidenceFromScanResult(
  result: ScanResult,
  options: EvidenceAdapterOptions,
): EvidenceRecord {
  const sourceSchema = (options as { readonly sourceSchema: unknown })
    .sourceSchema;
  if (sourceSchema !== 1 && sourceSchema !== 2)
    throw new RangeError("scan evidence source schema must be 1 or 2");
  const fields: EvidenceField[] = [
    evidenceTextField("scan.probe", result.probe),
    evidenceTextField("scan.outcome", result.outcome),
    evidenceTextField("scan.reason", result.reason),
  ];
  if (result.state !== undefined)
    fields.push(evidenceTextField("scan.networkState", result.state));
  if (result.port !== undefined)
    fields.push(evidenceTextField("scan.port", String(result.port)));
  if (result.evidence !== undefined)
    fields.push(evidenceTextField("scan.correlation", result.evidence));
  if (result.udpService !== undefined) {
    fields.push(
      evidenceTextField("scan.udp.product", result.udpService.product),
    );
    if (result.udpService.version !== undefined)
      fields.push(
        evidenceTextField("scan.udp.version", result.udpService.version),
      );
  }
  return createEvidenceRecord({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    origin: {
      source: "scanResult",
      sourceSchema: options.sourceSchema,
      runId: options.runId,
      recordId: options.recordId,
    },
    entity: {
      kind: "address",
      canonical: textEncoder.encode(result.target),
    },
    confidence: scanEvidenceConfidence(result.evidence),
    disposition: "observed",
    observedAtNanoseconds: result.timestampNanoseconds,
    ...(options.wallTimeMilliseconds === undefined
      ? {}
      : { wallTimeMilliseconds: options.wallTimeMilliseconds }),
    fields,
    relations: [],
  });
}

/** Losslessly project one discovery entity into additive typed evidence. */
export function evidenceFromDiscoveryResult(
  result: DiscoveryResult,
  options: EvidenceAdapterOptions,
): EvidenceRecord {
  if (options.sourceSchema !== 1)
    throw new RangeError("discovery evidence source schema must be 1");
  const fields: EvidenceField[] = [
    evidenceTextField("discovery.protocol", result.protocol),
    evidenceTextField("discovery.kind", result.kind),
    evidenceTextField("discovery.outcome", result.outcome),
    evidenceTextField("discovery.responder", result.responder),
    evidenceTextField("discovery.responderPort", String(result.responderPort)),
    evidenceTextField("discovery.operation", String(result.operationId)),
  ];
  fields.push(
    ...result.metadata.map((field) => ({ key: field.key, value: field.value })),
  );
  const relations: EvidenceRelation[] = [];
  if (result.parentEntityId !== undefined) {
    relations.push({
      kind: "derivedFrom",
      target: {
        kind: "service",
        canonical: textEncoder.encode(
          `${bytesHex(options.runId)}:${result.parentEntityId.toString(10)}`,
        ),
      },
    });
  }
  return createEvidenceRecord({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    origin: {
      source: "discoveryResult",
      sourceSchema: 1,
      runId: options.runId,
      recordId: options.recordId,
    },
    entity: {
      kind: discoveryEvidenceEntityKind(result.kind),
      canonical: result.identity,
    },
    confidence:
      result.evidence === "TransactionCorrelated"
        ? "transactionCorrelated"
        : result.evidence === "Parsed"
          ? "structural"
          : "weak",
    disposition: result.truncated ? "conflict" : "observed",
    observedAtNanoseconds: 0n,
    ...(options.wallTimeMilliseconds === undefined
      ? {}
      : { wallTimeMilliseconds: options.wallTimeMilliseconds }),
    fields,
    relations,
  });
}

/** Deterministic bounded retention without device-identity merging. */
export class EvidenceLedger {
  readonly #maximumRecords: number;
  readonly #maximumBytes: number;
  readonly #records = new Map<string, Map<string, EvidenceRecord>>();
  #recordCount = 0;
  #variableBytes = 0;
  #accepted = 0n;
  #duplicates = 0n;
  #conflicts = 0n;
  #rejectedCapacity = 0n;

  constructor(options?: {
    readonly maxRecords?: number;
    readonly maxBytes?: number;
  }) {
    this.#maximumRecords = boundedEvidenceInteger(
      options?.maxRecords ?? EVIDENCE_LIMITS.records,
      1,
      EVIDENCE_LIMITS.records,
      "evidence record capacity",
    );
    this.#maximumBytes = boundedEvidenceInteger(
      options?.maxBytes ?? EVIDENCE_LIMITS.batchBytes,
      1,
      EVIDENCE_LIMITS.batchBytes,
      "evidence byte capacity",
    );
  }

  retain(input: EvidenceRecord): EvidenceRetainOutcome {
    const record = createEvidenceRecord(input);
    const entityKey = `${record.entity.kind}:${bytesHex(record.entity.canonical)}`;
    const fingerprint = evidenceFingerprint(record);
    const records = this.#records.get(entityKey);
    if (records?.has(fingerprint) === true) {
      this.#duplicates += 1n;
      return "duplicate";
    }
    const bytes = evidenceVariableBytes(record);
    if (
      this.#recordCount >= this.#maximumRecords ||
      this.#variableBytes + bytes > this.#maximumBytes
    ) {
      this.#rejectedCapacity += 1n;
      throw new RangeError("evidence ledger capacity exceeded");
    }
    const conflict = records !== undefined;
    const destination = records ?? new Map<string, EvidenceRecord>();
    destination.set(fingerprint, record);
    if (!conflict) this.#records.set(entityKey, destination);
    this.#recordCount += 1;
    this.#variableBytes += bytes;
    if (conflict) {
      this.#conflicts += 1n;
      return "conflict";
    }
    this.#accepted += 1n;
    return "accepted";
  }

  get size(): number {
    return this.#recordCount;
  }

  get variableBytes(): number {
    return this.#variableBytes;
  }

  counters(): EvidenceLedgerCounters {
    return Object.freeze({
      accepted: this.#accepted,
      duplicates: this.#duplicates,
      conflicts: this.#conflicts,
      rejectedCapacity: this.#rejectedCapacity,
    });
  }

  materialize(): EvidenceRecord[] {
    return [...this.#records.values()]
      .flatMap((records) => [...records.values()])
      .sort(compareEvidenceRecords);
  }
}

const EVIDENCE_SOURCE_KINDS = new Set<EvidenceSourceKind>([
  "scanResult",
  "discoveryResult",
  "passiveObservation",
  "pathObservation",
  "serviceConversation",
  "localContext",
  "importedSensor",
]);
const EVIDENCE_ENTITY_KINDS = new Set<EvidenceEntityKind>([
  "deviceCandidate",
  "interface",
  "address",
  "name",
  "service",
  "router",
  "prefix",
  "path",
  "hop",
  "adjacency",
  "classification",
]);
const EVIDENCE_RELATION_KINDS = new Set<EvidenceRelationKind>([
  "hasAddress",
  "hasName",
  "offersService",
  "attachedToInterface",
  "routesPrefix",
  "nextHop",
  "advertisedBy",
  "derivedFrom",
  "classifiedAs",
]);
const EVIDENCE_CONFIDENCES = new Set<EvidenceConfidence>([
  "weak",
  "structural",
  "transactionCorrelated",
  "strongCorrelated",
]);
const EVIDENCE_DISPOSITIONS = new Set<EvidenceDisposition>([
  "observed",
  "inferred",
  "expired",
  "withdrawn",
  "conflict",
]);

function assertEvidenceEnum<T extends string>(
  value: T,
  allowed: ReadonlySet<T>,
  label: string,
): void {
  if (!allowed.has(value)) throw new TypeError(`${label} is invalid`);
}

function evidenceBytes(
  value: Uint8Array,
  label: string,
  nonempty: boolean,
): Uint8Array {
  if (!(value instanceof Uint8Array))
    throw new TypeError(`${label} must be Uint8Array`);
  if (nonempty && value.byteLength === 0)
    throw new RangeError(`${label} is empty`);
  if (value.byteLength > EVIDENCE_LIMITS.itemBytes)
    throw new RangeError(`${label} ceiling exceeded`);
  return Uint8Array.from(value);
}

function checkedEvidenceBytes(left: number, right: number): number {
  const value = left + right;
  if (!Number.isSafeInteger(value))
    throw new RangeError("evidence byte count overflow");
  return value;
}

function boundedEvidenceInteger(
  value: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new RangeError(`${label} is outside its supported range`);
  return value;
}

function bytesHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function evidenceTextField(key: string, value: string): EvidenceField {
  return { key, value: textEncoder.encode(value) };
}

function compareEvidenceFields(
  left: EvidenceField,
  right: EvidenceField,
): number {
  return (
    compareEvidenceText(left.key, right.key) ||
    compareEvidenceText(bytesHex(left.value), bytesHex(right.value))
  );
}

function compareEvidenceRelations(
  left: EvidenceRelation,
  right: EvidenceRelation,
): number {
  return (
    compareEvidenceText(left.kind, right.kind) ||
    compareEvidenceText(left.target.kind, right.target.kind) ||
    compareEvidenceText(
      bytesHex(left.target.canonical),
      bytesHex(right.target.canonical),
    )
  );
}

function evidenceVariableBytes(record: EvidenceRecord): number {
  let total = checkedEvidenceBytes(
    record.origin.runId.byteLength,
    record.entity.canonical.byteLength,
  );
  for (const field of record.fields) {
    total = checkedEvidenceBytes(
      total,
      textEncoder.encode(field.key).byteLength,
    );
    total = checkedEvidenceBytes(total, field.value.byteLength);
  }
  for (const relation of record.relations)
    total = checkedEvidenceBytes(total, relation.target.canonical.byteLength);
  return total;
}

function evidenceFingerprint(record: EvidenceRecord): string {
  return [
    record.origin.source,
    String(record.origin.sourceSchema),
    bytesHex(record.origin.runId),
    record.origin.recordId.toString(10),
    record.confidence,
    record.disposition,
    record.observedAtNanoseconds.toString(10),
    record.expiresAtNanoseconds?.toString(10) ?? "",
    record.wallTimeMilliseconds?.toString(10) ?? "",
    ...record.fields.map((field) => `${field.key}=${bytesHex(field.value)}`),
    ...record.relations.map(
      (relation) =>
        `${relation.kind}:${relation.target.kind}:${bytesHex(relation.target.canonical)}`,
    ),
  ].join("\u0000");
}

function compareEvidenceRecords(
  left: EvidenceRecord,
  right: EvidenceRecord,
): number {
  return (
    compareEvidenceText(left.entity.kind, right.entity.kind) ||
    compareEvidenceText(
      bytesHex(left.entity.canonical),
      bytesHex(right.entity.canonical),
    ) ||
    compareEvidenceText(evidenceFingerprint(left), evidenceFingerprint(right))
  );
}

function compareEvidenceText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function scanEvidenceConfidence(
  value: ScanResult["evidence"],
): EvidenceConfidence {
  if (value === "tcpSequence32" || value === "payload128")
    return "strongCorrelated";
  if (
    value === "transaction16" ||
    value === "transaction32" ||
    value === "transaction64" ||
    value === "alternateEndpoint"
  )
    return "transactionCorrelated";
  return "weak";
}

function discoveryEvidenceEntityKind(kind: string): EvidenceEntityKind {
  const normalized = kind.toLowerCase();
  if (normalized.includes("name")) return "name";
  if (normalized.includes("gateway")) return "router";
  if (normalized.includes("device")) return "deviceCandidate";
  return "service";
}

/** One environment-owned scanner control object. */
export class Scanner {
  readonly #handle: NativeScannerHandle;
  #closePromise: Promise<void> | undefined;
  #closed = false;
  #nextDiscoveryId = 1;
  readonly #discoveryRuns = new Set<Promise<NativeDiscoveryRun>>();
  #nextObservationId = 1;
  readonly #observationRuns = new Set<Promise<NativeObservationRun>>();
  readonly #observationIds = new Set<number>();
  #nextRouterSolicitationId = 1;
  readonly #routerSolicitationRuns = new Set<
    Promise<NativeRouterSolicitationRun>
  >();
  #nextPathId = 1;
  readonly #pathRuns = new Set<Promise<NativePathRun>>();
  #nextServiceId = 1;
  readonly #serviceRuns = new Set<Promise<NativeServiceIdentificationRun>>();

  constructor(handle: NativeScannerHandle) {
    this.#handle = handle;
  }

  async start(plan: ScanPlan): Promise<ScanSession> {
    if (this.#closed) {
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "start session",
        undefined,
        "scanner is closed",
      );
    }
    try {
      const id = (await this.#handle.start(nativePlan(plan))) as number;
      return new ScanSession(this.#handle, id);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async solicitRouters(
    plan: RouterSolicitationPlan,
    options: RouterSolicitationOptions = {},
  ): Promise<RouterSolicitationRun> {
    const signal = options.signal;
    if (this.#closed)
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "start router solicitation",
        undefined,
        "scanner is closed",
      );
    if (signal?.aborted === true) throw abortError(signal);
    try {
      const snapshot = nativeRouterSolicitationPlan(plan);
      if (this.#nextRouterSolicitationId > 0xffff_ffff)
        throw new ScannerError(
          "resourceLimit",
          "ERR_ROUTER_SOLICITATION_ID_EXHAUSTED",
          "start router solicitation",
          undefined,
          "router solicitation identifier space exhausted",
        );
      const id = this.#nextRouterSolicitationId++;
      let resolveRun: (value: NativeRouterSolicitationRun) => void = () =>
        undefined;
      let rejectRun: (reason: unknown) => void = () => undefined;
      const running = new Promise<NativeRouterSolicitationRun>(
        (resolve, reject) => {
          resolveRun = resolve;
          rejectRun = reject;
        },
      );
      this.#handle.solicitRouters(snapshot, id, (completion) => {
        try {
          if (!isRecord(completion)) {
            rejectRun(
              batchDataError(
                "native router solicitation completion is invalid",
              ),
            );
          } else if (completion.error !== undefined) {
            rejectRun(publicNativeFailure(completion.error));
          } else if (!isRecord(completion.run)) {
            rejectRun(
              batchDataError("native router solicitation run is invalid"),
            );
          } else {
            resolveRun(
              completion.run as unknown as NativeRouterSolicitationRun,
            );
          }
        } catch (error) {
          rejectRun(normalizeError(error));
        }
      });
      this.#routerSolicitationRuns.add(running);
      const abort = (): void => {
        try {
          this.#handle.cancelRouterSolicitation(id);
        } catch {
          // Completion may win the race with cancellation.
        }
      };
      signal?.addEventListener("abort", abort, { once: true });
      if (abortSignalIsAborted(signal)) abort();
      try {
        return publicRouterSolicitationRun(await running);
      } finally {
        signal?.removeEventListener("abort", abort);
        this.#routerSolicitationRuns.delete(running);
      }
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async tracePath(
    plan: PathPlan,
    options: PathTraceOptions = {},
  ): Promise<PathTraceRun> {
    const signal = options.signal;
    if (this.#closed)
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "start path trace",
        undefined,
        "scanner is closed",
      );
    if (signal?.aborted === true) throw abortError(signal);
    try {
      const snapshot = nativePathPlan(plan);
      if (this.#nextPathId > 0xffff_ffff)
        throw new ScannerError(
          "resourceLimit",
          "ERR_PATH_ID_EXHAUSTED",
          "start path trace",
          undefined,
          "path identifier space exhausted",
        );
      const id = this.#nextPathId++;
      let resolveRun: (value: NativePathRun) => void = () => undefined;
      let rejectRun: (reason: unknown) => void = () => undefined;
      const running = new Promise<NativePathRun>((resolve, reject) => {
        resolveRun = resolve;
        rejectRun = reject;
      });
      this.#handle.tracePath(snapshot, id, (completion) => {
        try {
          if (!isRecord(completion)) {
            rejectRun(batchDataError("native path completion is invalid"));
          } else if (completion.error !== undefined) {
            rejectRun(publicNativeFailure(completion.error));
          } else if (completion.run === undefined) {
            rejectRun(
              batchDataError("native path completion is missing its run"),
            );
          } else if (!isRecord(completion.run)) {
            rejectRun(batchDataError("native path run is invalid"));
          } else {
            resolveRun(completion.run as unknown as NativePathRun);
          }
        } catch (error) {
          rejectRun(normalizeError(error));
        }
      });
      this.#pathRuns.add(running);
      const abort = (): void => {
        try {
          this.#handle.cancelPath(id);
        } catch {
          // Completion may win the race with cancellation.
        }
      };
      signal?.addEventListener("abort", abort, { once: true });
      if (abortSignalIsAborted(signal)) abort();
      try {
        return publicPathRun(await running);
      } finally {
        signal?.removeEventListener("abort", abort);
        this.#pathRuns.delete(running);
      }
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async identifyService(
    plan: ServiceIdentificationPlan,
    options: ServiceIdentificationOptions = {},
  ): Promise<ServiceIdentificationRun> {
    const signal = options.signal;
    if (this.#closed)
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "start service identification",
        undefined,
        "scanner is closed",
      );
    if (signal?.aborted === true) throw abortError(signal);
    try {
      const snapshot = nativeServiceIdentificationPlan(plan);
      if (this.#nextServiceId > 0xffff_ffff)
        throw new ScannerError(
          "resourceLimit",
          "ERR_SERVICE_ID_EXHAUSTED",
          "start service identification",
          undefined,
          "service identifier space exhausted",
        );
      const id = this.#nextServiceId++;
      let resolveRun: (value: NativeServiceIdentificationRun) => void = () =>
        undefined;
      let rejectRun: (reason: unknown) => void = () => undefined;
      const running = new Promise<NativeServiceIdentificationRun>(
        (resolve, reject) => {
          resolveRun = resolve;
          rejectRun = reject;
        },
      );
      this.#handle.identifyService(snapshot, id, (completion) => {
        try {
          if (!isRecord(completion)) {
            rejectRun(batchDataError("native service completion is invalid"));
          } else if (completion.error !== undefined) {
            rejectRun(publicNativeFailure(completion.error));
          } else if (!isRecord(completion.run)) {
            rejectRun(batchDataError("native service run is invalid"));
          } else {
            resolveRun(
              completion.run as unknown as NativeServiceIdentificationRun,
            );
          }
        } catch (error) {
          rejectRun(normalizeError(error));
        }
      });
      this.#serviceRuns.add(running);
      const abort = (): void => {
        try {
          this.#handle.cancelService(id);
        } catch {
          // Completion may win the race with cancellation.
        }
      };
      signal?.addEventListener("abort", abort, { once: true });
      if (abortSignalIsAborted(signal)) abort();
      try {
        return publicServiceIdentificationRun(await running);
      } finally {
        signal?.removeEventListener("abort", abort);
        this.#serviceRuns.delete(running);
      }
    } catch (error) {
      throw normalizeError(error);
    }
  }

  startDiscovery(plan: DiscoveryPlan): Promise<DiscoverySession> {
    try {
      if (this.#closed) {
        throw new ScannerError(
          "lifecycle",
          "ERR_INVALID_STATE",
          "start discovery session",
          undefined,
          "scanner is closed",
        );
      }
      const snapshot = nativeDiscoveryPlan(plan);
      if (this.#nextDiscoveryId > 0xffff_ffff)
        throw new ScannerError(
          "resourceLimit",
          "ERR_DISCOVERY_ID_EXHAUSTED",
          "start discovery session",
          undefined,
          "discovery identifier space exhausted",
        );
      const id = this.#nextDiscoveryId++;
      let resolveRun: (value: NativeDiscoveryRun) => void = () => undefined;
      let rejectRun: (reason: unknown) => void = () => undefined;
      const running = new Promise<NativeDiscoveryRun>((resolve, reject) => {
        resolveRun = resolve;
        rejectRun = reject;
      });
      this.#handle.discover(snapshot, id, (completion) => {
        try {
          if (!isRecord(completion)) {
            rejectRun(batchDataError("native discovery completion is invalid"));
            return;
          }
          if (completion.error !== undefined) {
            rejectRun(publicNativeFailure(completion.error));
            return;
          }
          resolveRun(validateNativeDiscoveryRun(completion.run));
        } catch (error) {
          rejectRun(normalizeError(error));
        }
      });
      this.#discoveryRuns.add(running);
      void running.then(
        () => this.#discoveryRuns.delete(running),
        () => this.#discoveryRuns.delete(running),
      );
      return Promise.resolve(new DiscoverySession(this.#handle, id, running));
    } catch (error) {
      return Promise.reject(normalizeError(error));
    }
  }

  startObservation(plan: ObservationPlan): Promise<ObservationSession> {
    try {
      if (this.#closed)
        throw new ScannerError(
          "lifecycle",
          "ERR_INVALID_STATE",
          "start observation session",
          undefined,
          "scanner is closed",
        );
      const snapshot = nativeObservationPlan(plan);
      if (this.#nextObservationId > 0xffff_ffff)
        throw new ScannerError(
          "resourceLimit",
          "ERR_OBSERVATION_ID_EXHAUSTED",
          "start observation session",
          undefined,
          "observation identifier space exhausted",
        );
      const id = this.#nextObservationId++;
      let resolveRun: (value: NativeObservationRun) => void = () => undefined;
      let rejectRun: (reason: unknown) => void = () => undefined;
      const running = new Promise<NativeObservationRun>((resolve, reject) => {
        resolveRun = resolve;
        rejectRun = reject;
      });
      this.#handle.observe(snapshot, id, (completion) => {
        if (completion.error !== undefined) {
          rejectRun(publicNativeFailure(completion.error));
        } else if (completion.run === undefined) {
          rejectRun(batchDataError("native observation completion is invalid"));
        } else {
          resolveRun(completion.run);
        }
      });
      this.#observationRuns.add(running);
      this.#observationIds.add(id);
      void running.then(
        () => this.#observationRuns.delete(running),
        () => this.#observationRuns.delete(running),
      );
      const releaseObservation = (): void => {
        this.#observationIds.delete(id);
      };
      const session = new ObservationSession(
        this.#handle,
        id,
        running,
        releaseObservation,
      );
      return this.#handle.readyObservation(id).then(
        () => session,
        (error: unknown) => {
          try {
            this.#handle.closeObservation(id);
          } catch {
            // Readiness failure may race native teardown.
          } finally {
            releaseObservation();
          }
          throw normalizeError(error);
        },
      );
    } catch (error) {
      return Promise.reject(normalizeError(error));
    }
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    const runs = [...this.#discoveryRuns];
    const observationRuns = [...this.#observationRuns];
    const observationIds = [...this.#observationIds];
    const routerSolicitationRuns = [...this.#routerSolicitationRuns];
    const pathRuns = [...this.#pathRuns];
    const serviceRuns = [...this.#serviceRuns];
    const nativeClose = this.#handle.close().then(
      () => undefined,
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    this.#closePromise = Promise.all([
      nativeClose,
      ...runs.map((run) =>
        run.then(
          () => undefined,
          () => undefined,
        ),
      ),
      ...observationRuns.map((run) =>
        run.then(
          () => undefined,
          () => undefined,
        ),
      ),
      ...routerSolicitationRuns.map((run) =>
        run.then(
          () => undefined,
          () => undefined,
        ),
      ),
      ...pathRuns.map((run) =>
        run.then(
          () => undefined,
          () => undefined,
        ),
      ),
      ...serviceRuns.map((run) =>
        run.then(
          () => undefined,
          () => undefined,
        ),
      ),
    ]).then(() => {
      for (const id of observationIds) {
        if (!this.#observationIds.delete(id)) continue;
        try {
          this.#handle.closeObservation(id);
        } catch {
          // The environment may already have released the native handle.
        }
      }
    });
    return this.#closePromise;
  }
}

/** One immutable passive-metadata batch. */
export class ObservationResultBatch implements Iterable<ObservationResult> {
  readonly schemaVersion = 1 as const;
  readonly #rows: readonly ObservationResult[];

  constructor(rows: readonly ObservationResult[]) {
    this.#rows = Object.freeze([...rows]);
  }

  get length(): number {
    return this.#rows.length;
  }

  at(index: number): ObservationResult | undefined {
    return this.#rows.at(index);
  }

  materialize(): ObservationResult[] {
    return [...this.#rows];
  }

  [Symbol.iterator](): Iterator<ObservationResult> {
    return this.#rows[Symbol.iterator]();
  }
}

/** A finite already-running, receive-only Linux link observation. */
export class ObservationSession {
  readonly #handle: NativeScannerHandle;
  readonly #id: number;
  readonly #run: Promise<NativeObservationRun>;
  readonly #releaseObservation: () => void;
  #state: ObservationSessionState = "running";
  #pullPending = false;
  #closed = false;
  #cancelled = false;
  #summaryPromise: Promise<ObservationSummary> | undefined;

  constructor(
    handle: NativeScannerHandle,
    id: number,
    run: Promise<NativeObservationRun>,
    releaseObservation: () => void = () => undefined,
  ) {
    this.#handle = handle;
    this.#id = id;
    this.#releaseObservation = releaseObservation;
    this.#run = run.then(
      (value) => {
        if (!this.#closed) this.#state = value.state;
        return value;
      },
      (error: unknown) => {
        if (!this.#closed) this.#state = "failed";
        throw normalizeError(error);
      },
    );
  }

  get state(): ObservationSessionState {
    return this.#closed ? "closed" : this.#state;
  }

  pause(): Promise<void> {
    if (this.#closed || this.#state !== "running")
      throw discoveryStateError("pause observation", this.#state);
    try {
      this.#handle.pauseObservation(this.#id);
      this.#state = "paused";
      return Promise.resolve();
    } catch (error) {
      throw normalizeError(error);
    }
  }

  resume(): Promise<void> {
    if (this.#closed || this.#state !== "paused")
      throw discoveryStateError("resume observation", this.#state);
    try {
      this.#handle.resumeObservation(this.#id);
      this.#state = "running";
      return Promise.resolve();
    } catch (error) {
      throw normalizeError(error);
    }
  }

  cancel(reason?: string): Promise<ObservationSummary> {
    void reason;
    if (!this.#cancelled && !this.#closed) {
      try {
        this.#handle.cancelObservation(this.#id);
      } catch {
        // Completion can race this idempotent terminal control.
      }
      this.#cancelled = true;
      this.#state = "cancelling";
    }
    return this.summary();
  }

  async nextBatch(
    options: NextBatchOptions = {},
  ): Promise<ObservationResultBatch | null> {
    validateBatchMaximum(options.maxResults);
    if (this.#closed) return null;
    if (options.signal?.aborted === true) throw abortError(options.signal);
    if (this.#pullPending)
      throw new ScannerError(
        "resourceLimit",
        "ERR_PENDING_PULL",
        "pull observation batch",
        undefined,
        "only one observation nextBatch operation may be pending",
      );
    this.#pullPending = true;
    try {
      for (;;) {
        const batch = this.#handle.observationBatch(
          this.#id,
          options.maxResults,
        );
        const rows = batch.rows.map(publicObservationRow);
        if (rows.length !== 0) return new ObservationResultBatch(rows);
        if (
          batch.state === "completed" ||
          batch.state === "cancelling" ||
          batch.state === "failed"
        )
          return null;
        await abortableDelay(2, options.signal);
      }
    } catch (error) {
      if (isAbortError(error)) throw error;
      throw normalizeError(error);
    } finally {
      this.#pullPending = false;
    }
  }

  async progress(): Promise<ObservationProgress> {
    if (!this.#closed) {
      try {
        return publicObservationProgress(
          this.#handle.observationProgress(this.#id),
        );
      } catch {
        // Fall through to the terminal authoritative run.
      }
    }
    return publicObservationProgress((await this.#run).progress);
  }

  batches(
    options: ObservationBatchEventEmitterOptions = {},
  ): ObservationBatchEventEmitter {
    return new ObservationBatchEventEmitter(this, options);
  }

  summary(): Promise<ObservationSummary> {
    if (this.#summaryPromise !== undefined) return this.#summaryPromise;
    this.#summaryPromise = this.#run.then<
      ObservationSummary,
      ObservationSummary
    >(
      (run) =>
        Object.freeze({
          schemaVersion: 1,
          state: run.state,
          interfaces: Object.freeze([...run.interfaces]),
          protocols: Object.freeze([...run.protocols]),
          promiscuous: run.promiscuous,
          includeOutgoing: run.includeOutgoing,
          progress: publicObservationProgress(run.progress),
        }),
      (error: unknown) =>
        Object.freeze({
          schemaVersion: 1,
          state: "failed",
          interfaces: Object.freeze([]),
          protocols: Object.freeze([]),
          promiscuous: false,
          includeOutgoing: false,
          progress: zeroObservationProgress(),
          error: normalizeError(error),
        }),
    );
    return this.#summaryPromise;
  }

  close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      this.#state = "closed";
      try {
        this.#handle.closeObservation(this.#id);
      } catch {
        // Already closed or environment teardown.
      } finally {
        this.#releaseObservation();
      }
    }
    return this.#run.then(
      () => undefined,
      () => undefined,
    );
  }
}

/** Optional Node-style events layered over the bounded observation pull API. */
export class ObservationBatchEventEmitter extends EventEmitter<ObservationBatchEventMap> {
  readonly #session: ObservationSession;
  readonly #maximum: number | undefined;
  #started = false;
  #closed = false;

  constructor(
    session: ObservationSession,
    options: ObservationBatchEventEmitterOptions = {},
  ) {
    super();
    validateBatchMaximum(options.maxResults);
    this.#session = session;
    this.#maximum = options.maxResults;
  }

  start(): this {
    if (this.#closed) throw discoveryStateError("start adapter", "closed");
    if (this.#started) return this;
    this.#started = true;
    void this.#pump();
    return this;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#session.close();
    this.emit("close");
  }

  async #pump(): Promise<void> {
    try {
      while (!this.#closed) {
        const batch = await this.#session.nextBatch(
          this.#maximum === undefined ? {} : { maxResults: this.#maximum },
        );
        if (this.#closedAfterPull()) return;
        if (batch === null) break;
        this.emit("batch", batch);
      }
      this.emit("end");
    } catch (error) {
      this.emit(
        "error",
        error instanceof Error ? error : normalizeError(error),
      );
    }
  }

  #closedAfterPull(): boolean {
    return this.#closed;
  }
}

/** One immutable discovery batch. */
export class DiscoveryResultBatch implements Iterable<DiscoveryResult> {
  readonly schemaVersion = 1 as const;
  readonly #rows: readonly DiscoveryResult[];

  constructor(rows: readonly DiscoveryResult[]) {
    this.#rows = Object.freeze([...rows]);
  }

  get length(): number {
    return this.#rows.length;
  }

  at(index: number): DiscoveryResult | undefined {
    return this.#rows.at(index);
  }

  materialize(): DiscoveryResult[] {
    return [...this.#rows];
  }

  [Symbol.iterator](): Iterator<DiscoveryResult> {
    return this.#rows[Symbol.iterator]();
  }
}

/** A finite, already-running discovery session. */
export class DiscoverySession {
  readonly #handle: NativeScannerHandle;
  readonly #id: number;
  readonly #run: Promise<NativeDiscoveryRun>;
  #state: DiscoverySessionState = "running";
  #nextRow = 0;
  #pullPending = false;
  #cancelled = false;
  #closed = false;
  #resume: (() => void) | undefined;
  #summaryPromise: Promise<DiscoverySummary> | undefined;
  #closePromise: Promise<void> | undefined;

  constructor(
    handle: NativeScannerHandle,
    id: number,
    run: Promise<NativeDiscoveryRun>,
  ) {
    this.#handle = handle;
    this.#id = id;
    this.#run = run.then(
      (value) => {
        if (!this.#closed) this.#state = value.state;
        return value;
      },
      (error: unknown) => {
        if (!this.#closed) this.#state = "failed";
        throw normalizeError(error);
      },
    );
  }

  get state(): DiscoverySessionState {
    return this.#closed ? "closed" : this.#state;
  }

  pause(): Promise<void> {
    if (this.#closed || this.#state !== "running")
      throw discoveryStateError("pause", this.#state);
    this.#state = "pausing";
    try {
      this.#handle.pauseDiscovery(this.#id);
    } catch (error) {
      this.#state = "running";
      throw normalizeError(error);
    }
    this.#state = "paused";
    return Promise.resolve();
  }

  resume(): Promise<void> {
    if (this.#closed || this.#state !== "paused")
      throw discoveryStateError("resume", this.#state);
    try {
      this.#handle.resumeDiscovery(this.#id);
    } catch (error) {
      throw normalizeError(error);
    }
    this.#state = "running";
    this.#resume?.();
    this.#resume = undefined;
    return Promise.resolve();
  }

  cancel(reason?: string): Promise<DiscoverySummary> {
    void reason;
    if (this.#state === "completed" || this.#state === "cancelled")
      return this.#summary();
    if (this.#cancelled) return this.#summary();
    try {
      this.#handle.cancelDiscovery(this.#id);
      this.#cancelled = true;
      if (!this.#closed) this.#state = "cancelling";
    } catch (error) {
      // Native completion removes the control entry before its completion is
      // delivered to JavaScript. Treat that race as an idempotent terminal
      // cancel and let the authoritative native run state decide the summary.
      void error;
    }
    this.#resume?.();
    this.#resume = undefined;
    return this.#summary();
  }

  async nextBatch(
    options: NextBatchOptions = {},
  ): Promise<DiscoveryResultBatch | null> {
    validateBatchMaximum(options.maxResults);
    if (this.#closed || this.#cancelled) return null;
    if (this.#pullPending)
      throw new ScannerError(
        "resourceLimit",
        "ERR_PENDING_PULL",
        "pull discovery result batch",
        undefined,
        "only one discovery nextBatch operation may be pending",
      );
    if (options.signal?.aborted === true) throw abortError(options.signal);
    this.#pullPending = true;
    try {
      if (this.#state === "paused") {
        await new Promise<void>((resolve, reject) => {
          const abort = (): void => {
            reject(abortError(options.signal));
          };
          options.signal?.addEventListener("abort", abort, { once: true });
          this.#resume = () => {
            options.signal?.removeEventListener("abort", abort);
            resolve();
          };
        });
      }
      const run = await abortablePromise(this.#run, options.signal);
      if (this.#deliveryStopped() || this.#nextRow >= run.rows.length)
        return null;
      const maximum = options.maxResults ?? 512;
      const end = Math.min(this.#nextRow + maximum, run.rows.length);
      const rows = run.rows.slice(this.#nextRow, end).map(publicDiscoveryRow);
      this.#nextRow = end;
      return new DiscoveryResultBatch(rows);
    } finally {
      this.#pullPending = false;
    }
  }

  async progress(): Promise<DiscoveryProgress> {
    if (
      !this.#closed &&
      (this.#state === "running" ||
        this.#state === "pausing" ||
        this.#state === "paused" ||
        this.#state === "cancelling")
    ) {
      try {
        return publicDiscoveryProgress(
          this.#handle.discoveryProgress(this.#id),
        );
      } catch {
        // The native control entry is removed immediately before its terminal
        // completion callback. Fall through to that authoritative snapshot.
      }
    }
    const run = await this.#run;
    return publicDiscoveryProgress(run.progress);
  }

  batches(
    options: DiscoveryBatchEventEmitterOptions = {},
  ): DiscoveryBatchEventEmitter {
    return new DiscoveryBatchEventEmitter(this, options);
  }

  summary(): Promise<DiscoverySummary> {
    return this.#summary();
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    this.#state = "closed";
    try {
      this.#handle.cancelDiscovery(this.#id);
    } catch {
      // A completed native job has already released its control entry.
    }
    this.#resume?.();
    this.#resume = undefined;
    this.#closePromise = this.#run.then(
      () => undefined,
      () => undefined,
    );
    return this.#closePromise;
  }

  #summary(): Promise<DiscoverySummary> {
    if (this.#summaryPromise !== undefined) return this.#summaryPromise;
    const summary = this.#run.then<DiscoverySummary, DiscoverySummary>(
      (run) => ({
        schemaVersion: 1,
        registryVersion: run.registryVersion,
        registrySha256: run.registrySha256,
        state: run.state,
        results: BigInt(run.rows.length),
        allowRisks: Object.freeze([
          ...run.allowRisks,
        ]) as readonly UdpProbeRisk[],
        receiveModes: Object.freeze([...run.receiveModes]),
        progress: publicDiscoveryProgress(run.progress),
      }),
      (error: unknown) => ({
        schemaVersion: 1,
        registryVersion: DISCOVERY_CAPABILITIES.registryVersion,
        registrySha256: DISCOVERY_CAPABILITIES.registrySha256,
        state: "failed",
        results: 0n,
        allowRisks: Object.freeze([]),
        receiveModes: Object.freeze([]),
        progress: zeroDiscoveryProgress(),
        error: normalizeError(error),
      }),
    );
    this.#summaryPromise = summary;
    return summary;
  }

  #deliveryStopped(): boolean {
    return this.#cancelled || this.#closed;
  }
}

export class DiscoveryBatchEventEmitter extends EventEmitter<DiscoveryBatchEventMap> {
  readonly #session: DiscoverySession;
  readonly #maxResults: number | undefined;
  #started = false;
  #closed = false;

  constructor(
    session: DiscoverySession,
    options: DiscoveryBatchEventEmitterOptions = {},
  ) {
    super();
    validateBatchMaximum(options.maxResults);
    this.#session = session;
    this.#maxResults = options.maxResults;
  }

  start(): this {
    if (this.#closed) throw discoveryStateError("start adapter", "closed");
    if (this.#started) return this;
    this.#started = true;
    void this.#pump();
    return this;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#session.close();
    this.emit("close");
  }

  async #pump(): Promise<void> {
    try {
      while (!this.#closed) {
        const batch = await this.#session.nextBatch(
          this.#maxResults === undefined
            ? {}
            : { maxResults: this.#maxResults },
        );
        if (this.#closedAfterPull()) return;
        if (batch === null) break;
        this.emit("batch", batch);
      }
      this.emit("end");
    } catch (error) {
      this.emit(
        "error",
        error instanceof Error ? error : normalizeError(error),
      );
    }
  }

  #closedAfterPull(): boolean {
    return this.#closed;
  }
}

/** A native scan session with pull-based bounded result delivery. */
export class ScanSession {
  readonly #handle: NativeScannerHandle;
  readonly #id: number;
  #cancelPromise: Promise<ScanSummary> | undefined;
  #summaryPromise: Promise<ScanSummary> | undefined;
  #closePromise: Promise<void> | undefined;
  #pullPending = false;
  #nextPullId = 1;
  #closed = false;

  constructor(handle: NativeScannerHandle, id: number) {
    this.#handle = handle;
    this.#id = id;
  }

  get state(): ScanSessionState {
    if (this.#closed) return "closed";
    try {
      return this.#handle.state(this.#id) as ScanSessionState;
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async pause(): Promise<void> {
    await this.#control(() => this.#handle.pause(this.#id));
  }

  async resume(): Promise<void> {
    await this.#control(() => this.#handle.resume(this.#id));
  }

  cancel(reason?: string): Promise<ScanSummary> {
    void reason;
    if (this.#cancelPromise !== undefined) return this.#cancelPromise;
    this.#cancelPromise = this.#handle.cancel(this.#id).then(
      (value) => publicSummary(value as NativeSummary),
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#cancelPromise;
  }

  async nextBatch(
    options: NextBatchOptions = {},
  ): Promise<ScanResultBatch | null> {
    if (this.#closed) return null;
    if (options.signal?.aborted === true) throw abortError(options.signal);
    if (this.#pullPending) {
      throw new ScannerError(
        "resourceLimit",
        "ERR_PENDING_PULL",
        "pull result batch",
        undefined,
        "only one nextBatch operation may be pending",
      );
    }
    if (this.#nextPullId > 0xffff_ffff) {
      throw new ScannerError(
        "resourceLimit",
        "ERR_PULL_ID_EXHAUSTED",
        "pull result batch",
        undefined,
        "pull identifier space exhausted",
      );
    }
    const pullId = this.#nextPullId;
    this.#nextPullId += 1;
    this.#pullPending = true;
    const abort = (): void => {
      void this.#handle.cancelPull(this.#id, pullId).catch(() => undefined);
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      const value = (await this.#handle.nextBatch(
        this.#id,
        pullId,
        options.maxResults,
      )) as NativePullResult;
      if (value.status === "terminal") return null;
      if (value.status === "aborted") {
        throw abortError(options.signal);
      }
      if (value.batch === undefined) {
        throw batchDataError("native pull returned an invalid status");
      }
      return new ScanResultBatch(value.batch);
    } catch (error) {
      if (isAbortError(error)) throw error;
      throw normalizeError(error);
    } finally {
      options.signal?.removeEventListener("abort", abort);
      this.#pullPending = false;
    }
  }

  async progress(): Promise<ScanProgress> {
    try {
      return publicProgress(
        (await this.#handle.progress(this.#id)) as NativeProgress,
      );
    } catch (error) {
      throw normalizeError(error);
    }
  }

  batches(options: ScanBatchEventEmitterOptions = {}): ScanBatchEventEmitter {
    return new ScanBatchEventEmitter(this, options);
  }

  summary(): Promise<ScanSummary> {
    if (this.#summaryPromise !== undefined) return this.#summaryPromise;
    this.#summaryPromise = this.#handle.summary(this.#id).then(
      (value) => publicSummary(value as NativeSummary),
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#summaryPromise;
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#handle.closeSession(this.#id).then(
      () => undefined,
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#closePromise;
  }

  async #control(operation: () => Promise<unknown>): Promise<void> {
    if (this.#closed) {
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "control session",
        undefined,
        "session is closed",
      );
    }
    try {
      await operation();
    } catch (error) {
      throw normalizeError(error);
    }
  }
}

/** Optional Node-style batch events layered over one cancellable pull at a time. */
export class ScanBatchEventEmitter extends EventEmitter<ScanBatchEventMap> {
  readonly #session: ScanSession;
  readonly #maxResults: number | undefined;
  #status: ScanBatchEventEmitterStatus = "idle";
  #controller: AbortController | undefined;
  #pumpPromise: Promise<void> | undefined;
  #pausePromise: Promise<void> | undefined;
  #detachPromise: Promise<ScanSession> | undefined;
  #closePromise: Promise<void> | undefined;

  constructor(
    session: ScanSession,
    options: ScanBatchEventEmitterOptions = {},
  ) {
    super();
    validateBatchMaximum(options.maxResults);
    this.#session = session;
    this.#maxResults = options.maxResults;
  }

  get status(): ScanBatchEventEmitterStatus {
    return this.#status;
  }

  start(): this {
    if (this.#status === "running") return this;
    if (this.#status !== "idle") throw adapterStateError("start", this.#status);
    this.#status = "running";
    this.#beginPump();
    return this;
  }

  resume(): this {
    if (this.#status === "running") return this;
    if (this.#status !== "paused")
      throw adapterStateError("resume", this.#status);
    this.#status = "running";
    this.#pausePromise = undefined;
    this.#beginPump();
    return this;
  }

  pause(): Promise<void> {
    if (this.#pausePromise !== undefined) return this.#pausePromise;
    if (this.#status === "idle") {
      this.#status = "paused";
      this.#pausePromise = Promise.resolve();
      return this.#pausePromise;
    }
    if (this.#status === "paused") return Promise.resolve();
    if (this.#status !== "running") {
      return Promise.reject(adapterStateError("pause", this.#status));
    }
    this.#status = "pausing";
    this.#controller?.abort();
    this.#pausePromise = (this.#pumpPromise ?? Promise.resolve()).then(() => {
      if (this.#status === "pausing") this.#status = "paused";
    });
    return this.#pausePromise;
  }

  detach(): Promise<ScanSession> {
    if (this.#detachPromise !== undefined) return this.#detachPromise;
    if (this.#status === "closed" || this.#status === "closing") {
      return Promise.reject(adapterStateError("detach", this.#status));
    }
    this.#status = "detaching";
    this.#controller?.abort();
    this.#detachPromise = (this.#pumpPromise ?? Promise.resolve()).then(() => {
      this.#status = "detached";
      return this.#session;
    });
    return this.#detachPromise;
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    if (this.#status === "detached" || this.#status === "detaching") {
      return Promise.reject(adapterStateError("close", this.#status));
    }
    this.#status = "closing";
    this.#controller?.abort();
    this.#closePromise = (this.#pumpPromise ?? Promise.resolve())
      .then(() => this.#session.close())
      .then(() => {
        this.#status = "closed";
        this.emit("close");
      });
    return this.#closePromise;
  }

  #beginPump(): void {
    this.#pumpPromise = this.#pump();
  }

  async #pump(): Promise<void> {
    while (this.#status === "running") {
      const controller = new AbortController();
      this.#controller = controller;
      try {
        const batch = await this.#session.nextBatch({
          ...(this.#maxResults === undefined
            ? {}
            : { maxResults: this.#maxResults }),
          signal: controller.signal,
        });
        if (batch === null) {
          this.#status = "ended";
          this.emit("end");
          return;
        }
        // A pull fulfilled before its cancellation command is observable and
        // must cross the adapter boundary before pause/detach/close settles.
        this.emit("batch", batch);
      } catch (error) {
        if (isAbortError(error) && this.#isBoundaryStatus()) {
          return;
        }
        this.#status = "paused";
        this.emit(
          "error",
          error instanceof Error ? error : normalizeError(error),
        );
        return;
      } finally {
        if (this.#controller === controller) this.#controller = undefined;
      }
    }
  }

  #isBoundaryStatus(): boolean {
    return (
      this.#status === "pausing" ||
      this.#status === "detaching" ||
      this.#status === "closing"
    );
  }
}

/** Captures a complete read-only snapshot without requiring raw-socket authority. */
export async function inspectNetworkContext(): Promise<NetworkContextSnapshot> {
  try {
    const value = (await native.inspectNetworkContext()) as NativeSnapshot;
    return {
      generation: BigInt(value.generation),
      ...(value.netnsCookie === undefined
        ? {}
        : { netnsCookie: BigInt(value.netnsCookie) }),
      interfaces: value.interfaces.map((item) => ({
        ...item,
        hardwareAddress: Uint8Array.from(item.hardwareAddress),
      })),
      addresses: value.addresses,
      routes: value.routes,
      rules: value.rules,
      neighbors: value.neighbors.map((item) => ({
        ...item,
        linkLayerAddress: Uint8Array.from(item.linkLayerAddress),
      })),
      ruleCount: value.ruleCount,
      neighborCount: value.neighborCount,
    };
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Creates one scanner over the environment-scoped native runtime. */
export async function createScanner(): Promise<Scanner> {
  const handle = native.createNativeScanner();
  try {
    await handle.ready();
    return new Scanner(handle);
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw normalizeError(error);
  }
}

function nativeObservationPlan(plan: ObservationPlan): NativeObservationPlan {
  try {
    if (!isRecord(plan))
      throw invalidPlanData("observation plan must be an object");
    const interfaceInput = plan.interfaces;
    const protocolInput = plan.protocols;
    const riskInput = plan.allowRisks;
    const promiscuous = plan.promiscuous;
    const includeOutgoing = plan.includeOutgoing;
    const durationInput = plan.durationMs;
    const snapLengthInput = plan.snapLength;
    const maxResultsInput = plan.maxResults;
    const maxMetadataBytesInput = plan.maxMetadataBytes;
    const interfaces = snapshotArray(
      interfaceInput,
      "observation interfaces",
      (name) => {
        if (
          typeof name !== "string" ||
          name.length < 1 ||
          name.length > 15 ||
          name.includes("\0")
        )
          throw invalidPlanData(
            "observation interface names must contain 1 through 15 non-NUL characters",
          );
        return name;
      },
    ).sort(compareEvidenceText);
    if (
      interfaces.length < 1 ||
      interfaces.length > 4 ||
      new Set(interfaces).size !== interfaces.length
    )
      throw invalidPlanData(
        "observation interfaces must contain one through four unique names",
      );
    const protocols = snapshotArray(
      protocolInput,
      "observation protocols",
      (protocol) => {
        if (
          protocol !== "arp" &&
          protocol !== "ipv4" &&
          protocol !== "ipv6" &&
          protocol !== "lldp" &&
          protocol !== "controlPlane"
        )
          throw invalidPlanData("observation protocol group is unsupported");
        return protocol;
      },
    ).sort(compareEvidenceText);
    if (
      protocols.length < 1 ||
      protocols.length > 5 ||
      new Set(protocols).size !== protocols.length
    )
      throw invalidPlanData(
        "observation protocols must contain one through five unique groups",
      );
    const bounded = (
      value: unknown,
      minimum: number,
      maximum: number,
      label: string,
    ): number | undefined => {
      if (value === undefined) return undefined;
      if (
        !Number.isInteger(value) ||
        (value as number) < minimum ||
        (value as number) > maximum
      )
        throw invalidPlanData(
          `${label} must be an integer from ${String(minimum)} through ${String(maximum)}`,
        );
      return value as number;
    };
    const risks = snapshotArray(
      riskInput ?? [],
      "observation risks",
      (risk) => {
        if (risk !== "passiveMetadata" && risk !== "promiscuousCapture")
          throw invalidPlanData("observation risk is unsupported");
        return risk;
      },
    );
    if (new Set(risks).size !== risks.length)
      throw invalidPlanData("observation risks must be unique");
    if (promiscuous === true && !risks.includes("promiscuousCapture"))
      throw invalidPlanData(
        "promiscuous observation requires promiscuousCapture consent",
      );
    if (promiscuous !== undefined && typeof promiscuous !== "boolean")
      throw invalidPlanData("observation promiscuous must be boolean");
    if (includeOutgoing !== undefined && typeof includeOutgoing !== "boolean")
      throw invalidPlanData("observation includeOutgoing must be boolean");
    const durationMs = bounded(durationInput, 1, 300_000, "durationMs");
    const snapLength = bounded(snapLengthInput, 64, 16_384, "snapLength");
    const maxResults = bounded(maxResultsInput, 1, 8_192, "maxResults");
    const maxMetadataBytes = bounded(
      maxMetadataBytesInput,
      1,
      16 * 1_024 * 1_024,
      "maxMetadataBytes",
    );
    return {
      interfaces,
      protocols,
      ...(durationMs === undefined ? {} : { durationMs }),
      ...(snapLength === undefined ? {} : { snapLength }),
      ...(maxResults === undefined ? {} : { maxResults }),
      ...(maxMetadataBytes === undefined ? {} : { maxMetadataBytes }),
      ...(includeOutgoing === undefined ? {} : { includeOutgoing }),
      ...(promiscuous === undefined ? {} : { promiscuous }),
      allowRisks: risks,
    };
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("observation plan property access failed");
  }
}

function nativeRouterSolicitationPlan(
  plan: RouterSolicitationPlan,
): NativeRouterSolicitationPlan {
  try {
    if (!isRecord(plan))
      throw invalidPlanData("router solicitation plan must be an object");
    if (
      typeof plan.interface !== "string" ||
      plan.interface.length < 1 ||
      plan.interface.length > 15 ||
      plan.interface.includes("\0")
    )
      throw invalidPlanData(
        "router solicitation interface must contain 1 through 15 non-NUL characters",
      );
    const bounded = (
      value: unknown,
      maximum: number,
      label: string,
    ): number | undefined => {
      if (value === undefined) return undefined;
      if (
        !Number.isInteger(value) ||
        (value as number) < 1 ||
        (value as number) > maximum
      )
        throw invalidPlanData(
          `${label} must be an integer from 1 through ${String(maximum)}`,
        );
      return value as number;
    };
    const deadlineMs = bounded(plan.deadlineMs, 10_000, "deadlineMs");
    const maxResults = bounded(plan.maxResults, 64, "maxResults");
    const risks = snapshotArray(
      plan.allowRisks,
      "router solicitation risks",
      (risk) => {
        if (risk !== "linkMulticast")
          throw invalidPlanData("router solicitation risk is unsupported");
        return risk;
      },
    );
    if (risks.length !== 1)
      throw invalidPlanData(
        "router solicitation requires exactly linkMulticast consent",
      );
    return {
      interface: plan.interface,
      ...(deadlineMs === undefined ? {} : { deadlineMs }),
      ...(maxResults === undefined ? {} : { maxResults }),
      allowRisks: risks,
    };
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("router solicitation plan property access failed");
  }
}

function nativePathPlan(plan: PathPlan): NativePathPlan {
  try {
    if (
      !isRecord(plan) ||
      typeof plan.target !== "string" ||
      isIP(plan.target) === 0
    )
      throw invalidPlanData("path target must be an IPv4 or IPv6 literal");
    const bounded = (
      value: unknown,
      minimum: number,
      maximum: number,
      label: string,
    ): number | undefined => {
      if (value === undefined) return undefined;
      if (
        !Number.isInteger(value) ||
        (value as number) < minimum ||
        (value as number) > maximum
      )
        throw invalidPlanData(
          `${label} must be an integer from ${String(minimum)} through ${String(maximum)}`,
        );
      return value as number;
    };
    const firstHop = bounded(plan.firstHop, 1, 64, "firstHop");
    const maximumHop = bounded(plan.maximumHop, 1, 64, "maximumHop");
    const attemptsPerHop = bounded(plan.attemptsPerHop, 1, 8, "attemptsPerHop");
    const pacingMs = bounded(plan.pacingMs, 0, 1_000, "pacingMs");
    if ((maximumHop ?? 30) < (firstHop ?? 1))
      throw invalidPlanData("maximumHop must not precede firstHop");
    const deadlineMs = bounded(plan.deadlineMs, 1, 300_000, "deadlineMs");
    if (deadlineMs === undefined)
      throw invalidPlanData("path deadlineMs is required");
    const port = bounded(plan.port, 1, 65_535, "port");
    if (
      (plan.mode === "icmpEcho" && port !== undefined) ||
      (plan.mode !== "icmpEcho" && port === undefined)
    )
      throw invalidPlanData("path mode and port combination is invalid");
    return {
      target: plan.target,
      mode: plan.mode,
      ...(port === undefined ? {} : { port }),
      ...(firstHop === undefined ? {} : { firstHop }),
      ...(maximumHop === undefined ? {} : { maximumHop }),
      ...(attemptsPerHop === undefined ? {} : { attemptsPerHop }),
      ...(pacingMs === undefined ? {} : { pacingMs }),
      deadlineMs,
    };
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("path plan property access failed");
  }
}

function nativeServiceIdentificationPlan(
  plan: ServiceIdentificationPlan,
): NativeServiceIdentificationPlan {
  try {
    if (!isRecord(plan))
      throw invalidPlanData("service identification plan must be an object");
    const capabilityId = plan.capabilityId;
    const target = plan.target;
    const port = plan.port;
    const deadlineMs = plan.deadlineMs;
    const allowRisks = plan.allowRisks;
    const capability = SERVICE_CAPABILITIES.find(
      (entry) => entry.id === capabilityId,
    );
    if (capability === undefined || capability.disposition === "noGo")
      throw invalidPlanData("service capability is unavailable");
    if (typeof target !== "string" || isIP(target) === 0)
      throw invalidPlanData("service target must be an IPv4 or IPv6 literal");
    if (!Number.isInteger(port) || port < 1 || port > 65_535)
      throw invalidPlanData("service port must be from 1 through 65535");
    if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 30_000)
      throw invalidPlanData("service deadlineMs must be from 1 through 30000");
    if (
      !Array.isArray(allowRisks) ||
      allowRisks.length !== 1 ||
      allowRisks[0] !== capability.risk
    )
      throw invalidPlanData(
        "allowRisks must contain exactly the capability's required risk",
      );
    return {
      capabilityId,
      target,
      port,
      deadlineMs,
      allowRisks: [capability.risk],
    };
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("service identification plan property access failed");
  }
}

function nativeDiscoveryPlan(plan: DiscoveryPlan): NativeDiscoveryPlan {
  try {
    if (!isRecord(plan))
      throw invalidPlanData("discovery plan must be an object");
    if (!isRecord(plan.scope))
      throw invalidPlanData("discovery scope must be an object");
    if (
      !Number.isInteger(plan.deadlineMs) ||
      plan.deadlineMs < 1 ||
      plan.deadlineMs > 60_000
    )
      throw invalidPlanData(
        "discovery deadlineMs must be an integer from 1 through 60000",
      );
    const families = snapshotArray(
      plan.scope.families,
      "discovery families",
      (family) => {
        if (family !== "ipv4" && family !== "ipv6")
          throw invalidPlanData("discovery family must be ipv4 or ipv6");
        return family;
      },
    );
    const familySet = new Set(families);
    if (
      familySet.size !== families.length ||
      families.length < 1 ||
      families.length > 2
    )
      throw invalidPlanData(
        "discovery families must be a nonempty unique list",
      );
    const canonicalFamilies = (["ipv4", "ipv6"] as const).filter((family) =>
      familySet.has(family),
    );
    const scope: NativeDiscoveryPlan["scope"] =
      plan.scope.kind === "links"
        ? (() => {
            const interfaces = plan.scope.interfaces;
            if (interfaces === "allEligible") {
              return {
                kind: "links" as const,
                allEligible: true,
                families: [...canonicalFamilies],
              };
            }
            const names = snapshotArray(
              interfaces,
              "discovery interfaces",
              (name) => {
                if (
                  typeof name !== "string" ||
                  name.length < 1 ||
                  name.length > 64 ||
                  name.includes("\0")
                )
                  throw invalidPlanData(
                    "discovery interface names must contain 1 through 64 non-NUL characters",
                  );
                return name;
              },
            ).sort();
            if (
              names.length < 1 ||
              names.length > 16 ||
              new Set(names).size !== names.length
            )
              throw invalidPlanData(
                "discovery interfaces must be a unique list of 1 through 16 names",
              );
            return {
              kind: "links" as const,
              interfaces: names,
              families: [...canonicalFamilies],
            };
          })()
        : (() => {
            const targets = plan.scope.targets;
            const exclude =
              plan.scope.exclude === undefined
                ? undefined
                : snapshotArray(
                    plan.scope.exclude,
                    "discovery exclusions",
                    snapshotTarget,
                  );
            if (targets === "kernelDefaultIpv4Gateway") {
              if (!familySet.has("ipv4"))
                throw invalidPlanData("kernelDefaultIpv4Gateway requires ipv4");
              return {
                kind: "targets" as const,
                families: [...canonicalFamilies],
                kernelDefaultIpv4Gateway: true,
                ...(exclude === undefined ? {} : { exclude }),
              };
            }
            return {
              kind: "targets" as const,
              families: [...canonicalFamilies],
              targets: snapshotArray(
                targets,
                "discovery targets",
                snapshotTarget,
              ),
              ...(exclude === undefined ? {} : { exclude }),
            };
          })();
    const operations = snapshotArray(
      plan.operations,
      "discovery operations",
      (selection): NativeDiscoveryPlan["operations"][number] => {
        if (!isRecord(selection) || typeof selection.operation !== "string")
          throw invalidPlanData(
            "discovery operation selection must be an object",
          );
        if (!(selection.operation in DISCOVERY_OPERATIONS))
          throw invalidPlanData("discovery operation is unsupported");
        const name = selection.operation as DiscoveryOperationName;
        const query = selection.query;
        const followUp = selection.followUp;
        const receiveMode = selection.receiveMode;
        if (name === "mdnsDnsSdLegacy") {
          if (receiveMode !== "legacyUnicast")
            throw invalidPlanData(
              "mDNS discovery requires receiveMode legacyUnicast",
            );
        } else if (receiveMode !== undefined) {
          throw invalidPlanData("only mDNS accepts a receiveMode parameter");
        }
        if (name === "llmnrQuery") {
          if (
            typeof query !== "string" ||
            query.length < 1 ||
            query.length > 255 ||
            query.includes("\0")
          )
            throw invalidPlanData(
              "LLMNR query must contain 1 through 255 non-NUL characters",
            );
        } else if (query !== undefined) {
          throw invalidPlanData(
            "only LLMNR accepts a discovery query parameter",
          );
        }
        if (name === "rpcbindGetAddress") {
          if (followUp !== undefined && typeof followUp !== "boolean")
            throw invalidPlanData("rpcbind followUp must be a boolean");
        } else if (followUp !== undefined) {
          throw invalidPlanData(
            "only rpcbind accepts a discovery followUp parameter",
          );
        }
        return {
          id: DISCOVERY_OPERATIONS[name],
          ...(query === undefined ? {} : { query }),
          ...(followUp === undefined ? {} : { followUp }),
          ...(receiveMode === undefined
            ? {}
            : { receiveMode: "legacyUnicast" as const }),
        };
      },
    ).sort((left, right) => left.id - right.id);
    if (operations.length < 1 || operations.length > 8)
      throw invalidPlanData(
        "discovery operations must contain 1 through 8 selections",
      );
    if (
      operations.some(
        (operation, index) =>
          index > 0 && operations[index - 1]?.id === operation.id,
      )
    )
      throw invalidPlanData("discovery operations must not contain duplicates");
    const limits = snapshotDiscoveryLimits(plan.limits);
    const rate = snapshotDiscoveryRate(plan.rate);
    return {
      scope,
      operations,
      deadlineMs: plan.deadlineMs,
      ...(limits === undefined ? {} : { limits }),
      ...(rate === undefined ? {} : { rate }),
      allowRisks: snapshotUdpRisks(plan.allowRisks),
    };
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("discovery plan property access failed");
  }
}

function snapshotDiscoveryRate(
  value: unknown,
): NativeDiscoveryPlan["rate"] | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value))
    throw invalidPlanData("discovery rate must be an object");
  const packetsPerSecond = value.packetsPerSecond;
  const burst = value.burst;
  if (
    packetsPerSecond !== undefined &&
    (!Number.isInteger(packetsPerSecond) ||
      (packetsPerSecond as number) < 1 ||
      (packetsPerSecond as number) > 1_000_000)
  )
    throw invalidPlanData(
      "discovery packetsPerSecond must be from 1 through 1000000",
    );
  if (
    burst !== undefined &&
    (!Number.isInteger(burst) ||
      (burst as number) < 1 ||
      (burst as number) > 65_536)
  )
    throw invalidPlanData("discovery burst must be from 1 through 65536");
  return {
    ...(packetsPerSecond === undefined
      ? {}
      : { packetsPerSecond: packetsPerSecond as number }),
    ...(burst === undefined ? {} : { burst: burst as number }),
  };
}

function snapshotDiscoveryLimits(
  value: unknown,
): NativeDiscoveryPlan["limits"] | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value))
    throw invalidPlanData("discovery limits must be an object");
  const maxResults = value.maxResults;
  const maxMetadataBytes = value.maxMetadataBytes;
  if (
    maxResults !== undefined &&
    (!Number.isInteger(maxResults) ||
      (maxResults as number) < 1 ||
      (maxResults as number) > 8_192)
  )
    throw invalidPlanData(
      "discovery maxResults must be an integer from 1 through 8192",
    );
  if (
    maxMetadataBytes !== undefined &&
    (!Number.isInteger(maxMetadataBytes) ||
      (maxMetadataBytes as number) < 1 ||
      (maxMetadataBytes as number) > 16 * 1_024 * 1_024)
  )
    throw invalidPlanData(
      "discovery maxMetadataBytes must be from 1 through 16777216",
    );
  return {
    ...(maxResults === undefined ? {} : { maxResults: maxResults as number }),
    ...(maxMetadataBytes === undefined
      ? {}
      : { maxMetadataBytes: maxMetadataBytes as number }),
  };
}

function validateNativeDiscoveryRun(value: unknown): NativeDiscoveryRun {
  if (!isRecord(value))
    throw batchDataError("native discovery result must be an object");
  if (
    value.schemaVersion !== 1 ||
    value.registryVersion !== DISCOVERY_CAPABILITIES.registryVersion ||
    value.registrySha256 !== DISCOVERY_CAPABILITIES.registrySha256 ||
    (value.state !== "completed" && value.state !== "cancelled") ||
    !Array.isArray(value.rows) ||
    value.rows.length > DISCOVERY_CAPABILITIES.maxResults ||
    !Array.isArray(value.allowRisks) ||
    !Array.isArray(value.receiveModes) ||
    !isRecord(value.progress)
  )
    throw batchDataError("native discovery result header is invalid");
  const allowRisks = snapshotUdpRisks(value.allowRisks);
  const receiveModes = snapshotArray(
    value.receiveModes,
    "discovery receive modes",
    (mode) => {
      if (mode !== "legacyUnicast")
        throw batchDataError("native discovery receive mode is invalid");
      return "legacyUnicast" as const;
    },
  );
  if (new Set(receiveModes).size !== receiveModes.length)
    throw batchDataError("native discovery receive modes must be unique");
  const rows = value.rows.map((row, index) =>
    validateNativeDiscoveryRow(row, index),
  );
  let retainedBytes = 0;
  for (const row of rows) {
    retainedBytes += row.identity.length;
    retainedBytes += row.addresses.reduce(
      (total, address) => total + Buffer.byteLength(address),
      0,
    );
    retainedBytes += row.metadata.reduce(
      (total, field) =>
        total +
        Buffer.byteLength(field.key) +
        field.value.length +
        (field.text === undefined ? 0 : Buffer.byteLength(field.text)),
      0,
    );
    if (retainedBytes > DISCOVERY_CAPABILITIES.maxMetadataBytes)
      throw batchDataError("native discovery result exceeds metadata capacity");
  }
  const rowsById = new Map<string, NativeDiscoveryRun["rows"][number]>();
  for (const row of rows) {
    if (rowsById.has(row.entityId))
      throw batchDataError("native discovery entity IDs must be unique");
    rowsById.set(row.entityId, row);
  }
  for (const row of rows) {
    if (row.parentEntityId === undefined) continue;
    const parent = rowsById.get(row.parentEntityId);
    if (
      parent === undefined ||
      parent.parentEntityId !== undefined ||
      parent.operationId !== 7 ||
      row.operationId !== 7 ||
      parent.responder !== row.responder ||
      parent.interfaceIndex !== row.interfaceIndex
    )
      throw batchDataError("native discovery derivation graph is invalid");
  }
  const progressNames = [
    "queries",
    "sent",
    "received",
    "receivedBytes",
    "accepted",
    "duplicate",
    "rejected",
    "truncated",
    "cleanupSent",
  ] as const;
  const progress = Object.fromEntries(
    progressNames.map((name) => {
      const raw = (value.progress as Record<string, unknown>)[name];
      if (typeof raw !== "string" || !/^(0|[1-9][0-9]*)$/.test(raw))
        throw batchDataError(`native discovery progress ${name} is invalid`);
      return [name, raw];
    }),
  ) as unknown as NativeDiscoveryRun["progress"];
  return {
    schemaVersion: 1,
    registryVersion: value.registryVersion,
    registrySha256: value.registrySha256,
    state: value.state,
    allowRisks,
    receiveModes,
    rows,
    progress,
  };
}

function validateNativeDiscoveryRow(
  value: unknown,
  index: number,
): NativeDiscoveryRun["rows"][number] {
  const label = `discovery row ${String(index)}`;
  if (!isRecord(value)) throw batchDataError(`${label} is invalid`);
  const entityId = boundedDiscoveryString(value.entityId, `${label} entityId`);
  const parentEntityId =
    value.parentEntityId === undefined
      ? undefined
      : boundedDiscoveryString(value.parentEntityId, `${label} parentEntityId`);
  const derivationKind =
    value.derivationKind === undefined
      ? undefined
      : boundedDiscoveryString(value.derivationKind, `${label} derivationKind`);
  const protocol = boundedDiscoveryString(value.protocol, `${label} protocol`);
  const kind = boundedDiscoveryString(value.kind, `${label} kind`);
  const evidence = boundedDiscoveryString(value.evidence, `${label} evidence`);
  const outcome = boundedDiscoveryString(value.outcome, `${label} outcome`);
  const responder = boundedDiscoveryString(
    value.responder,
    `${label} responder`,
  );
  if (
    typeof value.responderPort !== "number" ||
    !Number.isInteger(value.responderPort) ||
    value.responderPort < 1 ||
    value.responderPort > 65_535
  )
    throw batchDataError(`${label} responderPort is invalid`);
  const operationId = discoveryInteger(
    value.operationId,
    `${label} operationId`,
  );
  const interfaceIndex =
    value.interfaceIndex === undefined
      ? undefined
      : discoveryInteger(value.interfaceIndex, `${label} interfaceIndex`);
  const identity = discoveryByteArray(
    value.identity,
    `${label} identity`,
    1_024,
  );
  const addresses = snapshotBoundedNativeArray(
    value.addresses,
    `${label} addresses`,
    32,
    (address) => {
      if (typeof address !== "string" || address.length > 64)
        throw batchDataError(`${label} address is invalid`);
      return address;
    },
  );
  if (
    operationId < 1 ||
    !DISCOVERY_CAPABILITIES.operations.some(
      (operation) => operation.id === operationId,
    ) ||
    (interfaceIndex !== undefined && interfaceIndex < 1) ||
    typeof value.truncated !== "boolean" ||
    identity.length < 1 ||
    identity.length > 1_024 ||
    addresses.length > 32
  )
    throw batchDataError(`${label} columns are invalid`);
  let metadataBytes = 0;
  const metadata = snapshotBoundedNativeArray(
    value.metadata,
    `${label} metadata`,
    128,
    (field) => {
      const fieldLabel = `${label} metadata field`;
      if (!isRecord(field)) throw batchDataError(`${fieldLabel} is invalid`);
      const key = boundedDiscoveryString(field.key, `${fieldLabel} key`);
      const bytes = discoveryByteArray(
        field.value,
        `${fieldLabel} value`,
        1_024,
      );
      const text = field.text;
      if (
        key.length < 1 ||
        Buffer.byteLength(key) > 1_024 ||
        bytes.length > 1_024 ||
        (text !== undefined &&
          (typeof text !== "string" || Buffer.byteLength(text) > 1_024))
      )
        throw batchDataError(`${fieldLabel} is invalid`);
      metadataBytes +=
        Buffer.byteLength(key) +
        bytes.length +
        (text === undefined ? 0 : Buffer.byteLength(text));
      if (metadataBytes > 16 * 1_024)
        throw batchDataError(`${label} metadata exceeds 16 KiB`);
      if (text !== undefined && !Buffer.from(text).equals(Buffer.from(bytes)))
        throw batchDataError(
          `${fieldLabel} text is not an exact UTF-8 projection`,
        );
      return { key, value: bytes, ...(text === undefined ? {} : { text }) };
    },
  );
  if (metadata.length > 128)
    throw batchDataError(`${label} contains too many metadata fields`);
  if (!/^(0|[1-9][0-9]*)$/.test(entityId))
    throw batchDataError(`${label} entityId is invalid`);
  if (
    (parentEntityId !== undefined &&
      (!/^[1-9][0-9]*$/.test(parentEntityId) || parentEntityId === entityId)) ||
    (derivationKind !== undefined && derivationKind !== "rpcbindGetAddress") ||
    (parentEntityId === undefined) !== (derivationKind === undefined)
  )
    throw batchDataError(`${label} derivation columns are invalid`);
  if (
    evidence !== "Parsed" &&
    evidence !== "QueryRelated" &&
    evidence !== "TransactionCorrelated"
  )
    throw batchDataError(`${label} evidence is invalid`);
  if (
    outcome !== "complete" &&
    outcome !== "partial" &&
    outcome !== "truncatedByPolicy"
  )
    throw batchDataError(`${label} outcome is invalid`);
  return {
    entityId,
    ...(parentEntityId === undefined ? {} : { parentEntityId }),
    ...(derivationKind === undefined ? {} : { derivationKind }),
    operationId,
    protocol,
    kind,
    evidence,
    outcome,
    responder,
    responderPort: value.responderPort,
    ...(interfaceIndex === undefined ? {} : { interfaceIndex }),
    identity,
    addresses,
    metadata,
    truncated: value.truncated,
  };
}

function boundedDiscoveryString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 1_024)
    throw batchDataError(`${label} is invalid`);
  return value;
}

function discoveryInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw batchDataError(`${label} is invalid`);
  return value;
}

function discoveryByteArray(
  value: unknown,
  label: string,
  maximum: number,
): number[] {
  return snapshotBoundedNativeArray(value, label, maximum, (byte) => {
    if (!isByte(byte))
      throw batchDataError(`${label} contains a non-byte value`);
    return byte as number;
  });
}

function snapshotBoundedNativeArray<T>(
  value: unknown,
  label: string,
  maximum: number,
  convert: (item: unknown) => T,
): T[] {
  if (!Array.isArray(value) || value.length > maximum)
    throw batchDataError(`${label} is invalid or oversized`);
  const output = new Array<T>(value.length);
  for (let index = 0; index < value.length; index += 1)
    output[index] = convert(value[index]);
  return output;
}

function isByte(value: unknown): boolean {
  return (
    Number.isInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= 255
  );
}

function publicDiscoveryRow(
  row: NativeDiscoveryRun["rows"][number],
): DiscoveryResult {
  const metadata = row.metadata.map((field) =>
    Object.freeze({
      key: field.key,
      value: Uint8Array.from(field.value),
      ...(field.text === undefined ? {} : { text: field.text }),
    }),
  );
  return Object.freeze({
    entityId: BigInt(row.entityId),
    ...(row.parentEntityId === undefined
      ? {}
      : { parentEntityId: BigInt(row.parentEntityId) }),
    ...(row.derivationKind === undefined
      ? {}
      : {
          derivationKind: row.derivationKind as "rpcbindGetAddress",
        }),
    operationId: row.operationId,
    protocol: row.protocol,
    kind: row.kind,
    evidence: row.evidence as DiscoveryEvidence,
    outcome: row.outcome as DiscoveryOutcome,
    responder: row.responder,
    responderPort: row.responderPort,
    ...(row.interfaceIndex === undefined
      ? {}
      : { interfaceIndex: row.interfaceIndex }),
    identity: Uint8Array.from(row.identity),
    addresses: Object.freeze([...row.addresses]),
    metadata: Object.freeze(metadata),
    truncated: row.truncated,
  });
}

function publicDiscoveryProgress(
  value: NativeDiscoveryRun["progress"],
): DiscoveryProgress {
  return Object.freeze({
    queries: BigInt(value.queries),
    sent: BigInt(value.sent),
    received: BigInt(value.received),
    receivedBytes: BigInt(value.receivedBytes),
    accepted: BigInt(value.accepted),
    duplicate: BigInt(value.duplicate),
    rejected: BigInt(value.rejected),
    truncated: BigInt(value.truncated),
    cleanupSent: BigInt(value.cleanupSent),
  });
}

function publicObservationRow(row: NativeObservationRow): ObservationResult {
  if (
    !Array.isArray(row.sourceMac) ||
    !Array.isArray(row.destinationMac) ||
    !Array.isArray(row.vlanIds) ||
    !Array.isArray(row.metadata) ||
    row.metadata.length > 32 ||
    !row.sourceMac.every(isByte) ||
    !row.destinationMac.every(isByte) ||
    row.sourceMac.length > 6 ||
    row.destinationMac.length > 6 ||
    row.vlanIds.length > 2 ||
    row.vlanIds.some(
      (identifier) =>
        !Number.isInteger(identifier) || identifier < 0 || identifier > 4_095,
    ) ||
    row.metadata.some(
      (field) =>
        typeof field.key !== "string" ||
        field.key.length < 1 ||
        field.key.length > 64 ||
        !Array.isArray(field.value) ||
        field.value.length > 512 ||
        !field.value.every(isByte),
    )
  )
    throw batchDataError("native observation row is invalid");
  return Object.freeze({
    sequence: BigInt(row.sequence),
    interfaceIndex: row.interfaceIndex,
    timestampNanoseconds: BigInt(row.timestampNanoseconds),
    ...(row.wallTimeMilliseconds === undefined
      ? {}
      : { wallTimeMilliseconds: BigInt(row.wallTimeMilliseconds) }),
    originalLength: row.originalLength,
    capturedLength: row.capturedLength,
    packetType: row.packetType,
    direction: row.direction,
    protocol: row.protocol,
    sourceMac: Uint8Array.from(row.sourceMac),
    destinationMac: Uint8Array.from(row.destinationMac),
    etherType: row.etherType,
    vlanIds: Object.freeze([...row.vlanIds]),
    ...(row.sourceAddress === undefined
      ? {}
      : { sourceAddress: row.sourceAddress }),
    ...(row.destinationAddress === undefined
      ? {}
      : { destinationAddress: row.destinationAddress }),
    ...(row.sourcePort === undefined ? {} : { sourcePort: row.sourcePort }),
    ...(row.destinationPort === undefined
      ? {}
      : { destinationPort: row.destinationPort }),
    metadata: Object.freeze(
      row.metadata.map((field) =>
        Object.freeze({ key: field.key, value: Uint8Array.from(field.value) }),
      ),
    ),
    truncated: row.truncated,
  });
}

function publicObservationProgress(
  value: NativeObservationProgress,
): ObservationProgress {
  return Object.freeze({
    inspected: BigInt(value.inspected),
    capturedBytes: BigInt(value.capturedBytes),
    accepted: BigInt(value.accepted),
    dropped: BigInt(value.dropped),
    kernelDropped: BigInt(value.kernelDropped),
    retentionDropped: BigInt(value.retentionDropped),
    filtered: BigInt(value.filtered),
    truncated: BigInt(value.truncated),
  });
}

function publicRouterSolicitationRun(
  run: NativeRouterSolicitationRun,
): RouterSolicitationRun {
  if (
    run.schemaVersion !== 1 ||
    !["completed", "cancelled"].includes(run.state) ||
    typeof run.interface !== "string" ||
    !Number.isInteger(run.interfaceIndex) ||
    run.interfaceIndex < 1 ||
    !Number.isInteger(run.transmitted) ||
    run.transmitted !== 1 ||
    !Number.isInteger(run.received) ||
    run.received < 0 ||
    !Number.isInteger(run.rejected) ||
    run.rejected < 0 ||
    !Array.isArray(run.advertisements) ||
    run.advertisements.length > 64
  )
    throw batchDataError("native router solicitation run is invalid");
  const advertisements = run.advertisements.map((advertisement) => {
    if (
      typeof advertisement.responder !== "string" ||
      isIP(advertisement.responder) !== 6 ||
      advertisement.interfaceIndex !== run.interfaceIndex ||
      !Array.isArray(advertisement.metadata) ||
      advertisement.metadata.length > 32 ||
      advertisement.metadata.some(
        (field) =>
          typeof field.key !== "string" ||
          field.key.length < 1 ||
          field.key.length > 64 ||
          !Array.isArray(field.value) ||
          field.value.length > 512 ||
          !field.value.every(isByte),
      )
    )
      throw batchDataError("native router advertisement is invalid");
    const roundTripMicroseconds = BigInt(advertisement.roundTripMicroseconds);
    if (roundTripMicroseconds < 0n)
      throw batchDataError("native router advertisement RTT is invalid");
    return Object.freeze({
      responder: advertisement.responder,
      interfaceIndex: advertisement.interfaceIndex,
      roundTripMicroseconds,
      metadata: Object.freeze(
        advertisement.metadata.map((field) =>
          Object.freeze({
            key: field.key,
            value: Uint8Array.from(field.value),
          }),
        ),
      ),
    });
  });
  return Object.freeze({
    schemaVersion: 1,
    state: run.state as RouterSolicitationRun["state"],
    interface: run.interface,
    interfaceIndex: run.interfaceIndex,
    transmitted: run.transmitted,
    received: run.received,
    rejected: run.rejected,
    advertisements: Object.freeze(advertisements),
  });
}

function publicPathRun(run: NativePathRun): PathTraceRun {
  if (
    run.schemaVersion !== 1 ||
    isIP(run.target) === 0 ||
    !["icmpEcho", "udp", "tcpSyn"].includes(run.mode) ||
    !["completed", "partial", "cancelled"].includes(run.state) ||
    typeof run.destinationReached !== "boolean" ||
    typeof run.truncated !== "boolean" ||
    !Array.isArray(run.attempts) ||
    run.attempts.length > 512
  )
    throw batchDataError("native path run is invalid");
  const attempts = run.attempts.map((attempt) => {
    if (
      !Number.isInteger(attempt.hop) ||
      attempt.hop < 1 ||
      attempt.hop > 64 ||
      !Number.isInteger(attempt.attempt) ||
      attempt.attempt < 1 ||
      attempt.attempt > 8 ||
      (attempt.responder !== undefined && isIP(attempt.responder) === 0) ||
      !isPathOutcome(attempt.outcome) ||
      (attempt.correlation !== "weak" && attempt.correlation !== "strong")
    )
      throw batchDataError("native path attempt is invalid");
    const roundTripMicroseconds =
      attempt.roundTripMicroseconds === undefined
        ? undefined
        : BigInt(attempt.roundTripMicroseconds);
    if (roundTripMicroseconds !== undefined && roundTripMicroseconds < 0n)
      throw batchDataError("native path RTT is invalid");
    const hasIcmp =
      attempt.icmpFamily !== undefined ||
      attempt.icmpType !== undefined ||
      attempt.icmpCode !== undefined;
    if (
      hasIcmp &&
      ((attempt.icmpFamily !== 4 && attempt.icmpFamily !== 6) ||
        !Number.isInteger(attempt.icmpType) ||
        !Number.isInteger(attempt.icmpCode))
    )
      throw batchDataError("native path ICMP detail is invalid");
    return Object.freeze({
      hop: attempt.hop,
      attempt: attempt.attempt,
      ...(attempt.responder === undefined
        ? {}
        : { responder: attempt.responder }),
      ...(roundTripMicroseconds === undefined ? {} : { roundTripMicroseconds }),
      outcome: attempt.outcome,
      correlation: attempt.correlation,
      ...(hasIcmp
        ? {
            icmp: Object.freeze({
              family: attempt.icmpFamily as 4 | 6,
              type: Number(attempt.icmpType),
              code: Number(attempt.icmpCode),
            }),
          }
        : {}),
    });
  });
  return Object.freeze({
    schemaVersion: 1,
    target: run.target,
    mode: run.mode as PathTraceRun["mode"],
    state: run.state as PathTraceRun["state"],
    destinationReached: run.destinationReached,
    truncated: run.truncated,
    attempts: Object.freeze(attempts),
  });
}

const SERVICE_OUTCOMES = new Set([
  "identified",
  "timeout",
  "cancelled",
  "connectRefused",
  "connectError",
  "writeError",
  "readError",
  "closed",
  "parserRejected",
  "responseLimit",
]);

function publicServiceIdentificationRun(
  run: NativeServiceIdentificationRun,
): ServiceIdentificationRun {
  const capability = SERVICE_CAPABILITIES.find(
    (entry) => entry.id === run.capabilityId,
  );
  if (
    run.schemaVersion !== 1 ||
    capability === undefined ||
    capability.disposition === "noGo" ||
    isIP(run.target) === 0 ||
    !Number.isInteger(run.port) ||
    run.port < 1 ||
    run.port > 65_535 ||
    !["completed", "cancelled"].includes(run.state) ||
    !SERVICE_OUTCOMES.has(run.outcome) ||
    !Number.isInteger(run.requestBytes) ||
    run.requestBytes < 0 ||
    run.requestBytes > capability.maximumRequestBytes ||
    !Number.isInteger(run.responseBytes) ||
    run.responseBytes < 0 ||
    run.responseBytes > capability.maximumResponseBytes ||
    !Array.isArray(run.fields) ||
    run.fields.length > 64 ||
    (run.protocol !== undefined &&
      (typeof run.protocol !== "string" || run.protocol.length > 64)) ||
    (run.confidence !== undefined &&
      (typeof run.confidence !== "string" || run.confidence.length > 128))
  )
    throw batchDataError("native service identification run is invalid");
  let fieldBytes = 0;
  const fields = run.fields.map((field) => {
    if (
      typeof field.key !== "string" ||
      field.key.length < 1 ||
      field.key.length > 64 ||
      !Array.isArray(field.value) ||
      field.value.length > 4_096 ||
      !field.value.every(isByte)
    )
      throw batchDataError("native service identity field is invalid");
    fieldBytes += field.key.length + field.value.length;
    if (fieldBytes > 65_536)
      throw batchDataError("native service identity fields exceed their bound");
    return Object.freeze({
      key: field.key,
      value: Uint8Array.from(field.value),
    });
  });
  if (
    (run.outcome === "identified") !==
    (run.protocol !== undefined && run.confidence !== undefined)
  )
    throw batchDataError("native service identity outcome is inconsistent");
  return Object.freeze({
    schemaVersion: 1,
    capabilityId: run.capabilityId,
    target: run.target,
    port: run.port,
    state: run.state as ServiceIdentificationRun["state"],
    outcome: run.outcome as ServiceIdentificationRun["outcome"],
    ...(run.protocol === undefined ? {} : { protocol: run.protocol }),
    ...(run.confidence === undefined ? {} : { confidence: run.confidence }),
    fields: Object.freeze(fields),
    requestBytes: run.requestBytes,
    responseBytes: run.responseBytes,
  });
}

function isPathOutcome(value: string): value is PathAttempt["outcome"] {
  return (
    value === "timeout" ||
    value === "hopResponse" ||
    value === "destinationReached" ||
    value === "unreachable" ||
    value === "administrativelyFiltered"
  );
}

function zeroObservationProgress(): ObservationProgress {
  return Object.freeze({
    inspected: 0n,
    capturedBytes: 0n,
    accepted: 0n,
    dropped: 0n,
    kernelDropped: 0n,
    retentionDropped: 0n,
    filtered: 0n,
    truncated: 0n,
  });
}

function abortableDelay(
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> {
  if (signal?.aborted === true) return Promise.reject(abortError(signal));
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    const abort = (): void => {
      clearTimeout(timer);
      reject(abortError(signal));
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}

function zeroDiscoveryProgress(): DiscoveryProgress {
  return Object.freeze({
    queries: 0n,
    sent: 0n,
    received: 0n,
    receivedBytes: 0n,
    accepted: 0n,
    duplicate: 0n,
    rejected: 0n,
    truncated: 0n,
    cleanupSent: 0n,
  });
}

function discoveryStateError(operation: string, state: string): ScannerError {
  return new ScannerError(
    "lifecycle",
    "ERR_INVALID_STATE",
    operation,
    undefined,
    `discovery session is ${state}`,
  );
}

function abortablePromise<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) return Promise.reject(abortError(signal));
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => {
      reject(abortError(signal));
    };
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error instanceof Error ? error : normalizeError(error));
      },
    );
  });
}

function nativePlan(plan: ScanPlan): NativePlan {
  try {
    if (!isRecord(plan)) throw invalidPlanData("scan plan must be an object");
    const targetsValue = plan.targets;
    const excludeValue = plan.exclude;
    const probesValue = plan.probes;
    const deadlineMs = plan.deadlineMs;
    const rateValue = plan.rate;
    const timingValue = plan.timing;
    const seed = plan.seed;
    const sourceAddress = plan.sourceAddress;
    const interfaceName = plan.interface;
    const vlanValue = plan.vlan;
    const sourcePortValue = plan.sourcePortRange;
    if (typeof deadlineMs !== "number" || !Number.isFinite(deadlineMs))
      throw invalidPlanData("deadlineMs must be a finite number");
    if (seed !== undefined && typeof seed !== "bigint")
      throw invalidPlanData("seed must be a bigint");
    if (sourceAddress !== undefined && typeof sourceAddress !== "string")
      throw invalidPlanData("sourceAddress must be a string");
    if (interfaceName !== undefined && typeof interfaceName !== "string")
      throw invalidPlanData("interface must be a string");
    const targets = snapshotArray(targetsValue, "targets", snapshotTarget);
    const exclude =
      excludeValue === undefined
        ? undefined
        : snapshotArray(excludeValue, "exclude", snapshotTarget);
    const probes = snapshotArray(probesValue, "probes", snapshotProbe);
    const rate = snapshotRate(rateValue);
    const timing = snapshotTiming(timingValue);
    const vlan = snapshotVlan(vlanValue);
    const sourcePortRange = snapshotSourcePortRange(sourcePortValue);
    const snapshot: NativePlan = {
      targets,
      ...(exclude === undefined ? {} : { exclude }),
      probes,
      deadlineMs,
      ...(rate === undefined ? {} : { rate }),
      ...(timing === undefined ? {} : { timing }),
      ...(seed === undefined ? {} : { seed: seed.toString() }),
      ...(sourceAddress === undefined ? {} : { sourceAddress }),
      ...(interfaceName === undefined ? {} : { interface: interfaceName }),
      ...(vlan === undefined ? {} : { vlan }),
      ...(sourcePortRange === undefined
        ? {}
        : {
            sourcePortStart: sourcePortRange.start,
            sourcePortEnd: sourcePortRange.end,
          }),
    };
    validateControlPlan(snapshot);
    return snapshot;
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw invalidPlanData("scan plan property access failed");
  }
}

function validateControlPlan(plan: NativePlan): void {
  let items =
    plan.targets.length + (plan.exclude?.length ?? 0) + plan.probes.length;
  if (items > SCANNER_LIMITS.controlItems) throw controlItemsError();
  let bytes = 0;
  for (const targets of [plan.targets, plan.exclude ?? []]) {
    for (const target of targets) {
      if (target.cidr !== undefined) bytes += Buffer.byteLength(target.cidr);
      else if (target.start !== undefined && target.end !== undefined)
        bytes +=
          Buffer.byteLength(target.start) + Buffer.byteLength(target.end);
    }
  }
  for (const probe of plan.probes) {
    if (probe.kind === "tcpSyn" || probe.kind === "udp") {
      items += probe.ports?.length ?? 0;
      if (items > SCANNER_LIMITS.controlItems) throw controlItemsError();
      if (probe.kind === "udp") {
        bytes += probe.payload?.length ?? 0;
        const risks = probe.udpAllowRisks ?? [];
        items += risks.length;
        for (const risk of risks) bytes += Buffer.byteLength(risk);
        if (items > SCANNER_LIMITS.controlItems) throw controlItemsError();
      }
    }
  }
  // Account for fixed object/field framing in addition to variable payloads.
  bytes += items * 32;
  if (bytes > SCANNER_LIMITS.controlBytes) {
    throw new ScannerError(
      "resourceLimit",
      "ERR_CONTROL_BYTES",
      "validate scan plan",
      undefined,
      "one scanner control command may contain at most 4 MiB",
    );
  }
}

function controlItemsError(): ScannerError {
  return new ScannerError(
    "resourceLimit",
    "ERR_CONTROL_ITEMS",
    "validate scan plan",
    undefined,
    "one scanner control command may contain at most 65536 items",
  );
}

function snapshotTarget(target: unknown): NativeTarget {
  if (!isRecord(target))
    throw invalidPlanData("every target must be an object");
  const cidr = target.cidr;
  const start = target.start;
  const end = target.end;
  if (typeof cidr === "string" && start === undefined && end === undefined)
    return { cidr };
  if (
    cidr === undefined &&
    typeof start === "string" &&
    typeof end === "string"
  )
    return { start, end };
  throw invalidPlanData("a target must be exactly one CIDR or address range");
}

function snapshotProbe(probe: unknown): NativeProbe {
  if (!isRecord(probe)) throw invalidPlanData("every probe must be an object");
  const kind = probe.kind;
  if (kind === "arp" || kind === "ndp") return { kind };
  if (kind === "icmpEcho") {
    const family = probe.family;
    if (family !== "ipv4" && family !== "ipv6")
      throw invalidPlanData("an ICMP Echo probe requires ipv4 or ipv6");
    return { kind, family };
  }
  if (kind !== "tcpSyn" && kind !== "udp")
    throw invalidPlanData("probe kind is unsupported");
  const ports = probe.ports;
  const snappedPorts = snapshotArray(ports, "probe ports", (port) =>
    typeof port === "number"
      ? { start: port, end: port }
      : snapshotPortRange(port),
  );
  if (kind === "tcpSyn") return { kind, ports: snappedPorts };
  const payload = probe.payload;
  const policy = probe.policy;
  if (payload !== undefined && policy !== undefined)
    throw invalidPlanData("UDP payload and policy are mutually exclusive");
  if (policy === undefined) {
    const copied = snapshotUdpPayload(payload, "UDP payload");
    if (copied === undefined)
      return {
        kind,
        ports: snappedPorts,
        udpMode: "protocol",
        udpProfile: "safe",
        udpIntensity: 0,
        udpStrategy: "exhaustive",
        udpEmptyFallback: "unmapped",
        udpAllowRisks: [],
      };
    return {
      kind,
      ports: snappedPorts,
      udpMode: "legacyPrefix",
      payload: copied,
    };
  }
  return {
    kind,
    ports: snappedPorts,
    ...snapshotUdpPolicy(policy),
  };
}

function snapshotUdpPolicy(
  policy: unknown,
): Omit<NativeProbe, "kind" | "ports"> {
  if (!isRecord(policy)) throw invalidPlanData("UDP policy must be an object");
  const mode = policy.mode;
  if (mode === "empty") return { udpMode: "empty", payload: [] };
  if (mode === "custom") {
    const payload = policy.payload;
    const correlation = policy.correlation;
    const copied = snapshotUdpPayload(payload, "custom UDP payload");
    if (copied === undefined)
      throw invalidPlanData("custom UDP policy requires a payload");
    if (
      correlation !== undefined &&
      correlation !== "tuple" &&
      correlation !== "prefixToken"
    )
      throw invalidPlanData("custom UDP correlation is unsupported");
    return {
      udpMode: "custom",
      udpCorrelation: correlation ?? "tuple",
      payload: copied,
    };
  }
  if (mode !== "protocol")
    throw invalidPlanData("UDP policy mode is unsupported");
  const profile = policy.profile;
  const intensity = policy.intensity;
  const strategy = policy.strategy;
  const emptyFallback = policy.emptyFallback;
  const allowRisks = policy.allowRisks;
  if (
    profile !== undefined &&
    profile !== "safe" &&
    profile !== "comprehensive" &&
    profile !== "legacy"
  )
    throw invalidPlanData("UDP profile is unsupported");
  if (
    intensity !== undefined &&
    (typeof intensity !== "number" ||
      !Number.isInteger(intensity) ||
      intensity < 0 ||
      intensity > 9)
  )
    throw invalidPlanData("UDP intensity must be an integer from 0 through 9");
  if (
    strategy !== undefined &&
    strategy !== "adaptive" &&
    strategy !== "exhaustive"
  )
    throw invalidPlanData("UDP strategy is unsupported");
  if (
    emptyFallback !== undefined &&
    emptyFallback !== "unmapped" &&
    emptyFallback !== "afterProtocol" &&
    emptyFallback !== "never"
  )
    throw invalidPlanData("UDP empty fallback is unsupported");
  const risks = snapshotUdpRisks(allowRisks);
  return {
    udpMode: "protocol",
    udpProfile: profile ?? "safe",
    udpIntensity: intensity ?? 7,
    udpStrategy: strategy ?? "exhaustive",
    udpEmptyFallback: emptyFallback ?? "unmapped",
    udpAllowRisks: risks,
  };
}

const UDP_PROBE_RISKS = [
  "highAmplification",
  "statefulHandshake",
  "fixedSourcePort",
  "multicastOrBroadcast",
  "authenticationAttempt",
  "sensitiveRead",
] as const satisfies readonly UdpProbeRisk[];

function snapshotUdpRisks(value: unknown): UdpProbeRisk[] {
  if (value === undefined) return [];
  const risks = snapshotArray(value, "UDP risk consent", (risk) => {
    if (
      typeof risk !== "string" ||
      !(UDP_PROBE_RISKS as readonly string[]).includes(risk)
    )
      throw invalidPlanData("UDP risk consent is unsupported");
    return risk as UdpProbeRisk;
  });
  const unique = new Set(risks);
  if (unique.size !== risks.length)
    throw invalidPlanData("UDP risk consent must not contain duplicates");
  return UDP_PROBE_RISKS.filter((risk) => unique.has(risk));
}

function snapshotUdpPayload(
  value: unknown,
  field: string,
): number[] | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof Uint8Array))
    throw invalidPlanData(`${field} must be a Uint8Array`);
  if (value.byteLength >= SCANNER_LIMITS.controlBytes)
    throw new ScannerError(
      "resourceLimit",
      "ERR_CONTROL_BYTES",
      "validate scan plan",
      undefined,
      "one scanner control command may contain at most 4 MiB",
    );
  if (value.byteLength > SCANNER_LIMITS.udpPayloadBytes)
    throw invalidPlanData(
      "UDP payload plus correlation, UDP, and IPv4 headers exceeds the maximum IP packet length",
    );
  return Array.from(Uint8Array.from(value));
}

function snapshotPortRange(value: unknown): { start: number; end: number } {
  if (!isRecord(value)) throw invalidPlanData("port range must be an object");
  const start = value.start;
  const end = value.end;
  if (typeof start !== "number" || typeof end !== "number")
    throw invalidPlanData("port range endpoints must be numbers");
  return { start, end };
}

function snapshotRate(value: unknown): ScanRateOptions | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw invalidPlanData("rate must be an object");
  return optionalNumbers(value, [
    "packetsPerSecond",
    "burst",
    "maxOutstanding",
  ]);
}

function snapshotTiming(value: unknown): ScanTimingOptions | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw invalidPlanData("timing must be an object");
  const fixed = value.fixed;
  if (fixed !== undefined && typeof fixed !== "boolean")
    throw invalidPlanData("timing.fixed must be boolean");
  return {
    ...optionalNumbers(value, [
      "timeoutMs",
      "minimumTimeoutMs",
      "maximumTimeoutMs",
      "retries",
    ]),
    ...(fixed === undefined ? {} : { fixed }),
  };
}

function snapshotVlan(value: unknown): ScanVlanOptions | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw invalidPlanData("vlan must be an object");
  const identifier = value.identifier;
  const priority = value.priority;
  const dropEligible = value.dropEligible;
  if (typeof identifier !== "number")
    throw invalidPlanData("vlan.identifier must be a number");
  if (priority !== undefined && typeof priority !== "number")
    throw invalidPlanData("vlan.priority must be a number");
  if (dropEligible !== undefined && typeof dropEligible !== "boolean")
    throw invalidPlanData("vlan.dropEligible must be boolean");
  return {
    identifier,
    ...(priority === undefined ? {} : { priority }),
    ...(dropEligible === undefined ? {} : { dropEligible }),
  };
}

function snapshotSourcePortRange(
  value: unknown,
): { start: number; end: number } | undefined {
  if (value === undefined) return undefined;
  return snapshotPortRange(value);
}

function optionalNumbers(
  value: Record<PropertyKey, unknown>,
  names: readonly string[],
): Record<string, number> {
  const result: Record<string, number> = {};
  for (const name of names) {
    const item = value[name];
    if (item !== undefined) {
      if (typeof item !== "number" || !Number.isFinite(item))
        throw invalidPlanData(`${name} must be a finite number`);
      result[name] = item;
    }
  }
  return result;
}

function snapshotArray<T>(
  value: unknown,
  name: string,
  convert: (item: unknown) => T,
): T[] {
  if (!Array.isArray(value)) throw invalidPlanData(`${name} must be an array`);
  const length = value.length;
  if (length > SCANNER_LIMITS.controlItems) throw controlItemsError();
  const result = new Array<T>(length);
  for (let index = 0; index < length; index += 1)
    result[index] = convert(value[index]);
  return result;
}

function isRecord(value: unknown): value is Record<PropertyKey, unknown> {
  return typeof value === "object" && value !== null;
}

function invalidPlanData(message: string): ScannerError {
  return new ScannerError(
    "invalidPlan",
    "ERR_INVALID_SCAN_PLAN",
    "validate scan plan",
    undefined,
    message,
  );
}

function publicSummary(value: NativeSummary): ScanSummary {
  return {
    schemaVersion: value.schemaVersion,
    state: value.state,
    logicalProbes: BigInt(value.logicalProbes),
    results: BigInt(value.results),
    open: BigInt(value.open),
    closed: BigInt(value.closed),
    filtered: BigInt(value.filtered),
    openOrFiltered: BigInt(value.openOrFiltered),
    up: BigInt(value.up),
    unreachable: BigInt(value.unreachable),
    unknown: BigInt(value.unknown),
    cancelled: BigInt(value.cancelled),
    deadline: BigInt(value.deadline),
    discarded: BigInt(value.discarded),
    kernelDropped: BigInt(value.kernelDropped),
    forgedOrUnrelated: BigInt(value.forgedOrUnrelated),
    duplicates: BigInt(value.duplicates),
    lateResponses: BigInt(value.lateResponses),
    udpIcmpPacing: BigInt(value.udpIcmpPacing ?? "0"),
    ...(value.udpPolicyMode === undefined
      ? {}
      : { udp: publicUdpSummary(value) }),
    progress: publicProgress(value.progress),
    ...(value.schedulingSeed === undefined
      ? {}
      : { schedulingSeed: BigInt(value.schedulingSeed) }),
    accuracyTradeoff: value.accuracyTradeoff,
    ...(value.error === undefined
      ? {}
      : {
          error: new ScannerError(
            value.error.kind,
            value.error.code,
            value.error.operation,
            value.error.errno,
            value.error.message,
          ),
        }),
  };
}

function publicNativeFailure(value: unknown): ScannerError {
  if (
    !isRecord(value) ||
    typeof value.kind !== "string" ||
    typeof value.code !== "string" ||
    typeof value.operation !== "string" ||
    (value.errno !== undefined && !Number.isInteger(value.errno)) ||
    typeof value.message !== "string"
  )
    return batchDataError("native discovery failure is invalid");
  return new ScannerError(
    value.kind as ScannerErrorKind,
    value.code,
    value.operation,
    value.errno as number | undefined,
    value.message,
  );
}

function publicUdpSummary(value: NativeSummary): UdpScanSummary {
  let policy: UdpSelectedPolicy;
  if (value.udpPolicyMode === "protocol") {
    policy = {
      mode: "protocol",
      profile: value.udpProfile ?? "safe",
      intensity: value.udpIntensity ?? 7,
      strategy: value.udpStrategy ?? "exhaustive",
      emptyFallback: value.udpEmptyFallback ?? "unmapped",
      allowRisks: Object.freeze([...(value.udpAllowRisks ?? [])]),
    };
  } else if (value.udpPolicyMode === "custom") {
    policy = {
      mode: "custom",
      correlation: value.udpCustomCorrelation ?? "tuple",
    };
  } else {
    policy = { mode: "empty" };
  }
  return {
    policy: Object.freeze(policy),
    ...(value.udpCatalogueVersion === undefined ||
    value.udpCatalogueSha256 === undefined
      ? {}
      : {
          catalogue: Object.freeze({
            version: value.udpCatalogueVersion,
            sha256: value.udpCatalogueSha256,
          }),
        }),
  };
}

function publicProgress(value: NativeProgress): ScanProgress {
  return {
    sent: BigInt(value.sent),
    received: BigInt(value.received),
    matched: BigInt(value.matched),
    duplicate: BigInt(value.duplicate),
    invalid: BigInt(value.invalid),
    timedOut: BigInt(value.timedOut),
    retried: BigInt(value.retried),
    kernelDropped: BigInt(value.kernelDropped),
    applicationBackpressured: BigInt(value.applicationBackpressured),
    coalescedUpdates: BigInt(value.coalescedUpdates),
  };
}

function validateBatchMaximum(value: number | undefined): void {
  if (
    value !== undefined &&
    (!Number.isInteger(value) || value < 1 || value > MAX_BATCH_RESULTS)
  ) {
    throw new ScannerError(
      "invalidPlan",
      "ERR_INVALID_ARGUMENT",
      "configure batch adapter",
      undefined,
      "maxResults must be from 1 through 4096",
    );
  }
}

function adapterStateError(
  operation: string,
  status: ScanBatchEventEmitterStatus,
): ScannerError {
  return new ScannerError(
    "lifecycle",
    "ERR_INVALID_STATE",
    `${operation} batch event adapter`,
    undefined,
    `batch event adapter is ${status}`,
  );
}

function abortError(signal: AbortSignal | undefined): Error {
  const reason = signal?.reason as unknown;
  if (reason instanceof Error) return reason;
  return new DOMException(
    typeof reason === "string" ? reason : "The operation was aborted",
    "AbortError",
  );
}

function abortSignalIsAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function isAbortError(error: unknown): error is Error {
  return error instanceof Error && error.name === "AbortError";
}

function normalizeError(error: unknown): ScannerError {
  if (error instanceof ScannerError) return error;
  const message = error instanceof Error ? error.message : String(error);
  const marker = "NODENET_SCANNER|";
  const start = message.indexOf(marker);
  if (start !== -1) {
    const [kind, code, operation, errno, ...rest] = message
      .slice(start + marker.length)
      .split("|");
    if (
      kind !== undefined &&
      code !== undefined &&
      operation !== undefined &&
      errno !== undefined
    ) {
      return new ScannerError(
        kind as ScannerErrorKind,
        code,
        operation,
        errno === "" ? undefined : Number(errno),
        rest.join("|"),
      );
    }
  }
  return new ScannerError(
    "internal",
    "ERR_SCANNER_INTERNAL",
    "native scanner",
    undefined,
    message,
  );
}
