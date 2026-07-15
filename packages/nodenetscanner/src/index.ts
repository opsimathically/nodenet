import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";

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

export interface NetworkContextSnapshot {
  readonly generation: bigint;
  readonly netnsCookie?: bigint;
  readonly interfaces: readonly NetworkInterface[];
  readonly addresses: readonly NetworkAddress[];
  readonly routes: readonly NetworkRoute[];
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
  version: "1.3.0",
  sha256: "427cdc09881907c610bbea8f6bc8cffa18e2819e3f7f04626adcf264e598b976",
  variants: 33,
  supportedProfiles: Object.freeze([
    "safe",
    "comprehensive",
    "legacy",
  ] as const),
  protocolModeAvailable: true,
} as const);

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

const MAX_BATCH_RESULTS = SCANNER_LIMITS.batchResults;
const MAX_BATCH_METADATA_BYTES = 4 * 1_024 * 1_024;
const MISSING_U64 = 0xffff_ffff_ffff_ffffn;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

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
  ruleCount: number;
  neighborCount: number;
}

interface NativeScannerHandle {
  ready(): Promise<unknown>;
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
const nativeDiscoveryCapabilities = native.discoveryCapabilities();

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

/** One environment-owned scanner control object. */
export class Scanner {
  readonly #handle: NativeScannerHandle;
  #closePromise: Promise<void> | undefined;
  #closed = false;
  #nextDiscoveryId = 1;
  readonly #discoveryRuns = new Set<Promise<NativeDiscoveryRun>>();

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

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    const runs = [...this.#discoveryRuns];
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
    ]).then(() => undefined);
    return this.#closePromise;
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
