import { Buffer } from "node:buffer";
import { isIP } from "node:net";

import type { EvidenceRecord, ObservationResult } from "./index.js";

export const DISCOVERY_PLATFORM_VERSIONS = Object.freeze({
  pathSchema: 1,
  serviceConversationSchema: 1,
  assetSchema: 1,
  inventorySchema: 1,
  sensorEnvelope: 1,
  serviceRegistry: "1.0.0",
} as const);

export const PASSIVE_PROTOCOL_CAPABILITIES = Object.freeze([
  "arp",
  "ipv6NeighborDiscovery",
  "dhcpv4",
  "dhcpv6",
  "mdnsDnsSd",
  "llmnr",
  "nbns",
  "ssdp",
  "wsDiscovery",
  "routerAdvertisement",
  "routerSolicitation",
  "ipv6Redirect",
  "lldp",
  "stp",
  "lacp",
  "vrrp",
  "igmp",
  "mld",
  "rip",
  "ospf",
] as const);

export const ENRICHMENT_CAPABILITIES = Object.freeze({
  sameResponderHttpPolicy: "implemented",
  dnsSdSemanticFamilies: "implemented",
  unicastDns: "policyFoundationOnly",
  ssdpDescriptionFetch: "noGo",
  wsDiscoveryDescriptionFetch: "noGo",
  coapResourceFetch: "noGo",
  snmpRead: "noGo",
} as const);

export const LOCAL_CONTEXT_CAPABILITIES = Object.freeze({
  interfaces: "implemented",
  addresses: "implemented",
  routes: "implemented",
  rules: "implemented",
  neighbors: "implemented",
  inetDiag: "noGo",
  avahi: "noGo",
  systemdResolved: "noGo",
  nl80211Cache: "noGo",
} as const);

export type DiscoveryPlatformRisk =
  | "passiveMetadata"
  | "promiscuousCapture"
  | "linkMulticast"
  | "serverFirst"
  | "clientNegotiation"
  | "statefulHandshake"
  | "sensitiveRead";

export interface PathPlan {
  readonly target: string;
  readonly mode: "icmpEcho" | "udp" | "tcpSyn";
  readonly port?: number;
  readonly firstHop?: number;
  readonly maximumHop?: number;
  readonly attemptsPerHop?: number;
  /** Delay between probes. Defaults to zero and is bounded to one second. */
  readonly pacingMs?: number;
  readonly deadlineMs: number;
}

export interface PathTraceOptions {
  readonly signal?: AbortSignal;
}

export interface PathAttempt {
  readonly hop: number;
  readonly attempt: number;
  readonly responder?: string;
  readonly roundTripMicroseconds?: bigint;
  readonly outcome:
    | "timeout"
    | "hopResponse"
    | "destinationReached"
    | "unreachable"
    | "administrativelyFiltered";
  readonly correlation: "weak" | "strong";
  readonly icmp?: Readonly<{ family: 4 | 6; type: number; code: number }>;
}

export interface PathTraceRun {
  readonly schemaVersion: 1;
  readonly target: string;
  readonly mode: PathPlan["mode"];
  readonly state: "completed" | "partial" | "cancelled";
  readonly destinationReached: boolean;
  readonly truncated: boolean;
  readonly attempts: readonly Readonly<PathAttempt>[];
}

export class PathRun {
  readonly plan: Readonly<
    Required<Omit<PathPlan, "port">> & Pick<PathPlan, "port">
  >;
  readonly #attempts = new Map<string, Readonly<PathAttempt>>();
  #stopped = false;

  constructor(plan: PathPlan) {
    this.plan = normalizePathPlan(plan);
  }

  get stopped(): boolean {
    return this.#stopped;
  }

  record(attempt: PathAttempt): void {
    if (
      this.#stopped ||
      !Number.isInteger(attempt.hop) ||
      attempt.hop < this.plan.firstHop ||
      attempt.hop > this.plan.maximumHop ||
      !Number.isInteger(attempt.attempt) ||
      attempt.attempt < 1 ||
      attempt.attempt > this.plan.attemptsPerHop ||
      (attempt.roundTripMicroseconds !== undefined &&
        attempt.roundTripMicroseconds < 0n)
    )
      throw new RangeError("path attempt is outside its declared finite plan");
    const copy = Object.freeze({ ...attempt });
    this.#attempts.set(
      `${String(attempt.hop)}:${String(attempt.attempt)}`,
      copy,
    );
    if (
      attempt.outcome === "destinationReached" ||
      attempt.outcome === "unreachable"
    )
      this.#stopped = true;
  }

  materialize(): readonly Readonly<PathAttempt>[] {
    return Object.freeze(
      [...this.#attempts.values()].sort(
        (left, right) => left.hop - right.hop || left.attempt - right.attempt,
      ),
    );
  }
}

function normalizePathPlan(
  plan: PathPlan,
): Readonly<Required<Omit<PathPlan, "port">> & Pick<PathPlan, "port">> {
  const firstHop = plan.firstHop ?? 1;
  const maximumHop = plan.maximumHop ?? 30;
  const attemptsPerHop = plan.attemptsPerHop ?? 3;
  const pacingMs = plan.pacingMs ?? 0;
  if (
    typeof plan.target !== "string" ||
    isIP(plan.target) === 0 ||
    !Number.isInteger(firstHop) ||
    firstHop < 1 ||
    !Number.isInteger(maximumHop) ||
    maximumHop < firstHop ||
    maximumHop > 64 ||
    !Number.isInteger(attemptsPerHop) ||
    attemptsPerHop < 1 ||
    attemptsPerHop > 8 ||
    !Number.isInteger(pacingMs) ||
    pacingMs < 0 ||
    pacingMs > 1_000 ||
    !Number.isInteger(plan.deadlineMs) ||
    plan.deadlineMs < 1 ||
    plan.deadlineMs > 300_000
  )
    throw new RangeError("invalid bounded path plan");
  if (
    (plan.mode === "icmpEcho" && plan.port !== undefined) ||
    (plan.mode !== "icmpEcho" &&
      (plan.port === undefined ||
        !Number.isInteger(plan.port) ||
        plan.port < 1 ||
        plan.port > 65_535))
  )
    throw new RangeError("path transport has an invalid port");
  return Object.freeze({
    target: plan.target,
    mode: plan.mode,
    ...(plan.port === undefined ? {} : { port: plan.port }),
    firstHop,
    maximumHop,
    attemptsPerHop,
    pacingMs,
    deadlineMs: plan.deadlineMs,
  });
}

export type ServiceDisposition = "implemented" | "optIn" | "noGo";

export interface ServiceCapability {
  readonly id: string;
  readonly ports: readonly number[];
  readonly disposition: ServiceDisposition;
  readonly risk: DiscoveryPlatformRisk;
  readonly maximumRequestBytes: number;
  readonly maximumResponseBytes: number;
  readonly phase: 51 | 52 | 56;
  readonly reason?: string;
}

const service = (
  id: string,
  ports: readonly number[],
  disposition: ServiceDisposition,
  risk: DiscoveryPlatformRisk,
  maximumRequestBytes: number,
  maximumResponseBytes: number,
  phase: 51 | 52 | 56,
  reason?: string,
): ServiceCapability =>
  Object.freeze({
    id,
    ports: Object.freeze([...ports]),
    disposition,
    risk,
    maximumRequestBytes,
    maximumResponseBytes,
    phase,
    ...(reason === undefined ? {} : { reason }),
  });

export const SERVICE_CAPABILITIES: readonly ServiceCapability[] = Object.freeze(
  [
    service(
      "ssh-identification",
      [22],
      "implemented",
      "serverFirst",
      0,
      255,
      51,
    ),
    service("ftp-greeting", [21], "implemented", "serverFirst", 0, 4_096, 51),
    service(
      "smtp-greeting",
      [25, 587],
      "implemented",
      "serverFirst",
      0,
      4_096,
      51,
    ),
    service("pop3-greeting", [110], "implemented", "serverFirst", 0, 4_096, 51),
    service("imap-greeting", [143], "implemented", "serverFirst", 0, 4_096, 51),
    service(
      "mysql-initial-handshake",
      [3306],
      "implemented",
      "serverFirst",
      0,
      65_536,
      51,
    ),
    service(
      "tls-client-hello",
      [443, 465, 636, 853, 993, 995, 8443],
      "noGo",
      "statefulHandshake",
      0,
      0,
      51,
      "pinned TLS/X.509 dependency review and bounded handshake engine are not closed",
    ),
    service(
      "http-head",
      [80, 8000, 8080, 8888],
      "optIn",
      "clientNegotiation",
      4_096,
      65_536,
      51,
    ),
    service(
      "smb2-negotiate",
      [445],
      "noGo",
      "statefulHandshake",
      0,
      0,
      52,
      "bounded negotiate request integration is not closed",
    ),
    service(
      "rdp-negotiation",
      [3389],
      "noGo",
      "statefulHandshake",
      0,
      0,
      52,
      "bounded negotiation request integration is not closed",
    ),
    service(
      "postgresql-ssl-request",
      [5432],
      "optIn",
      "clientNegotiation",
      8,
      1,
      52,
    ),
    service("redis-ping", [6379], "optIn", "clientNegotiation", 14, 4_096, 52),
    service(
      "mongodb-hello",
      [27017],
      "noGo",
      "sensitiveRead",
      0,
      0,
      52,
      "metadata request integration is not closed",
    ),
    service(
      "ldap-root-dse",
      [389, 636],
      "noGo",
      "sensitiveRead",
      0,
      0,
      52,
      "anonymous bind/read is outside the no-authentication boundary",
    ),
    service(
      "ipp-identity",
      [631],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "project-owned responder and typed request gate remain open",
    ),
    service(
      "rtsp-options",
      [554, 8554],
      "noGo",
      "clientNegotiation",
      0,
      0,
      56,
      "project-owned responder gate remains open",
    ),
    service(
      "onvif-metadata",
      [80, 8000],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "bounded XML follow-up gate remains open",
    ),
    service(
      "bacnet-read-property",
      [47808],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "device-impact and responder gates remain open",
    ),
    service(
      "ethernet-ip-identity",
      [44818],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "device-impact and responder gates remain open",
    ),
    service(
      "modbus-device-identification",
      [502],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "device-impact and responder gates remain open",
    ),
    service(
      "opc-ua-get-endpoints",
      [4840],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "device-impact and responder gates remain open",
    ),
    service(
      "s7-identity",
      [102],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "proprietary impact contract is not independently closed",
    ),
    service(
      "dnp3-identity",
      [20000],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "safe non-mutating identity exchange is not independently closed",
    ),
    service(
      "snmp-system-read",
      [161],
      "noGo",
      "sensitiveRead",
      0,
      0,
      56,
      "credentials/community material remain outside package scope",
    ),
  ],
);

export interface ConversationStep {
  readonly kind: "connect" | "write" | "read" | "shutdown";
  readonly bytes?: Uint8Array;
  readonly maximumReadBytes?: number;
  readonly deadlineMs: number;
}

export interface ServiceConversationPlan {
  readonly capabilityId: string;
  readonly target: string;
  readonly port: number;
  readonly allowRisks: readonly DiscoveryPlatformRisk[];
  readonly steps: readonly ConversationStep[];
}

export interface ServiceIdentificationPlan {
  readonly capabilityId: string;
  readonly target: string;
  readonly port: number;
  readonly deadlineMs: number;
  readonly allowRisks: readonly DiscoveryPlatformRisk[];
}

export interface ServiceIdentificationOptions {
  readonly signal?: AbortSignal;
}

export interface ServiceIdentityField {
  readonly key: string;
  readonly value: Uint8Array;
}

export interface ServiceIdentificationRun {
  readonly schemaVersion: 1;
  readonly capabilityId: string;
  readonly target: string;
  readonly port: number;
  readonly state: "completed" | "cancelled";
  readonly outcome:
    | "identified"
    | "timeout"
    | "cancelled"
    | "connectRefused"
    | "connectError"
    | "writeError"
    | "readError"
    | "closed"
    | "parserRejected"
    | "responseLimit";
  readonly protocol?: string;
  readonly confidence?: string;
  readonly fields: readonly Readonly<ServiceIdentityField>[];
  readonly requestBytes: number;
  readonly responseBytes: number;
}

/** Converts a bounded path run into append-only path and hop evidence records. */
export function evidenceRecordsFromPath(
  run: PathTraceRun,
  runId: Uint8Array,
  observedAtNanoseconds: bigint,
): readonly EvidenceRecord[] {
  if (
    !(runId instanceof Uint8Array) ||
    runId.byteLength < 1 ||
    runId.byteLength > 1_024 ||
    observedAtNanoseconds < 0n ||
    run.attempts.length > 512
  )
    throw new RangeError("path evidence input exceeds its bound");
  const pathKey = {
    kind: "path" as const,
    canonical: Buffer.from(`${run.mode}:${run.target}`),
  };
  const base = {
    schemaVersion: 1 as const,
    origin: {
      source: "pathObservation" as const,
      sourceSchema: 1,
      runId: Uint8Array.from(runId),
      recordId: 0n,
    },
    confidence: "strongCorrelated" as const,
    disposition: "observed" as const,
    observedAtNanoseconds,
    relations: [] as const,
  };
  const records: EvidenceRecord[] = [
    {
      ...base,
      entity: pathKey,
      fields: [
        { key: "target", value: Buffer.from(run.target) },
        { key: "mode", value: Buffer.from(run.mode) },
        { key: "state", value: Buffer.from(run.state) },
        {
          key: "destinationReached",
          value: Uint8Array.of(run.destinationReached ? 1 : 0),
        },
      ],
    },
  ];
  for (const attempt of run.attempts) {
    if (attempt.responder === undefined) continue;
    const recordId = BigInt(records.length);
    records.push({
      ...base,
      origin: { ...base.origin, recordId },
      entity: {
        kind: "hop",
        canonical: Buffer.from(
          `${run.mode}:${run.target}:${String(attempt.hop)}:${attempt.responder}`,
        ),
      },
      confidence:
        attempt.correlation === "strong" ? "strongCorrelated" : "weak",
      fields: [
        { key: "responder", value: Buffer.from(attempt.responder) },
        { key: "hop", value: Buffer.from(String(attempt.hop)) },
        { key: "attempt", value: Buffer.from(String(attempt.attempt)) },
        { key: "outcome", value: Buffer.from(attempt.outcome) },
        ...(attempt.roundTripMicroseconds === undefined
          ? []
          : [
              {
                key: "roundTripMicroseconds",
                value: Buffer.from(attempt.roundTripMicroseconds.toString()),
              },
            ]),
      ],
      relations: [{ kind: "derivedFrom", target: pathKey }],
    });
  }
  return Object.freeze(records.map((record) => Object.freeze(record)));
}

/** Converts one terminal native TCP conversation into scoped evidence. */
export function evidenceFromServiceIdentification(
  run: ServiceIdentificationRun,
  runId: Uint8Array,
  recordId: bigint,
  observedAtNanoseconds: bigint,
): EvidenceRecord {
  if (
    !(runId instanceof Uint8Array) ||
    runId.byteLength < 1 ||
    runId.byteLength > 1_024 ||
    recordId < 0n ||
    observedAtNanoseconds < 0n
  )
    throw new RangeError("service evidence input exceeds its bound");
  const identified = run.outcome === "identified";
  const evidence: EvidenceRecord = {
    schemaVersion: 1,
    origin: {
      source: "serviceConversation",
      sourceSchema: 1,
      runId: Uint8Array.from(runId),
      recordId,
    },
    entity: {
      kind: identified ? "service" : "address",
      canonical: Buffer.from(
        identified
          ? `${run.target}:${String(run.port)}:${run.capabilityId}`
          : run.target,
      ),
    },
    confidence: identified ? "strongCorrelated" : "weak",
    disposition: "observed",
    observedAtNanoseconds,
    fields: [
      { key: "address", value: Buffer.from(run.target) },
      { key: "port", value: Buffer.from(String(run.port)) },
      { key: "capability", value: Buffer.from(run.capabilityId) },
      { key: "outcome", value: Buffer.from(run.outcome) },
      ...(run.protocol === undefined
        ? []
        : [{ key: "service", value: Buffer.from(run.protocol) }]),
      ...(run.confidence === undefined
        ? []
        : [{ key: "serviceConfidence", value: Buffer.from(run.confidence) }]),
      ...run.fields.map((field) => ({
        key: `identity.${field.key}`,
        value: Uint8Array.from(field.value),
      })),
    ],
    relations: identified
      ? [
          {
            kind: "derivedFrom",
            target: { kind: "address", canonical: Buffer.from(run.target) },
          },
        ]
      : [],
  };
  return Object.freeze(evidence);
}

/** Validates a registry-owned finite conversation; it performs no network I/O. */
export function validateServiceConversation(
  plan: ServiceConversationPlan,
): Readonly<ServiceConversationPlan> {
  const capability = SERVICE_CAPABILITIES.find(
    (entry) => entry.id === plan.capabilityId,
  );
  if (capability === undefined || capability.disposition === "noGo")
    throw new RangeError("service capability is unavailable");
  if (plan.allowRisks.length !== 1 || plan.allowRisks[0] !== capability.risk)
    throw new RangeError("service capability risk was not authorized");
  if (
    isIP(plan.target) === 0 ||
    !Number.isInteger(plan.port) ||
    plan.port < 1 ||
    plan.port > 65_535 ||
    plan.steps.length < 2 ||
    plan.steps.length > 32 ||
    plan.steps[0]?.kind !== "connect" ||
    plan.steps.at(-1)?.kind !== "shutdown"
  )
    throw new RangeError("invalid service conversation state machine");
  const kinds = plan.steps.map((step) => step.kind).join(",");
  const serverFirst = capability.maximumRequestBytes === 0;
  if (
    (serverFirst && kinds !== "connect,read,shutdown") ||
    (!serverFirst && kinds !== "connect,write,read,shutdown")
  )
    throw new RangeError(
      "conversation does not match its registered state machine",
    );
  let bytes = 0;
  const steps = plan.steps.map((step) => {
    if (
      !Number.isInteger(step.deadlineMs) ||
      step.deadlineMs < 1 ||
      step.deadlineMs > 30_000
    )
      throw new RangeError("invalid conversation deadline");
    const written = step.bytes?.byteLength ?? 0;
    const read = step.maximumReadBytes ?? 0;
    if (
      (step.kind === "write" && written === 0) ||
      (step.kind === "read" && read === 0) ||
      ((step.kind === "connect" || step.kind === "shutdown") &&
        (written !== 0 || read !== 0))
    )
      throw new RangeError("invalid conversation step");
    bytes += written + read;
    return Object.freeze({
      ...step,
      ...(step.bytes === undefined
        ? {}
        : { bytes: Uint8Array.from(step.bytes) }),
    });
  });
  if (
    bytes > 65_536 ||
    bytes > capability.maximumRequestBytes + capability.maximumResponseBytes
  )
    throw new RangeError("conversation byte ceiling exceeded");
  const written = steps.find((step) => step.kind === "write")?.bytes;
  if (
    capability.id === "postgresql-ssl-request" &&
    !bytesEqual(written, Uint8Array.of(0, 0, 0, 8, 4, 210, 22, 47))
  )
    throw new RangeError("PostgreSQL SSLRequest bytes are not canonical");
  if (
    capability.id === "redis-ping" &&
    !bytesEqual(written, Buffer.from("*1\r\n$4\r\nPING\r\n"))
  )
    throw new RangeError("Redis PING bytes are not canonical");
  if (capability.id === "http-head") {
    const host = isIP(plan.target) === 6 ? `[${plan.target}]` : plan.target;
    if (
      !bytesEqual(
        written,
        Buffer.from(
          `HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`,
        ),
      )
    )
      throw new RangeError("HTTP HEAD bytes are not canonical");
  }
  return Object.freeze({
    capabilityId: capability.id,
    target: plan.target,
    port: plan.port,
    allowRisks: Object.freeze([...new Set(plan.allowRisks)].sort()),
    steps: Object.freeze(steps),
  });
}

export interface GovernedUrl {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly port: number;
  readonly path: string;
}

export type DnsSdServiceFamily =
  | "ssh"
  | "http"
  | "smb"
  | "printing"
  | "airplay"
  | "cast"
  | "homekit"
  | "matter"
  | "unknown";

export interface DnsSdServiceSemantic {
  readonly serviceType: string;
  readonly transport: "tcp" | "udp";
  readonly family: DnsSdServiceFamily;
}

const DNS_SD_FAMILIES: Readonly<Record<string, DnsSdServiceFamily>> =
  Object.freeze({
    _ssh: "ssh",
    _sftp_ssh: "ssh",
    _http: "http",
    _https: "http",
    _smb: "smb",
    _ipp: "printing",
    _ipps: "printing",
    _printer: "printing",
    _pdl_datastream: "printing",
    _airplay: "airplay",
    _raop: "airplay",
    _googlecast: "cast",
    _hap: "homekit",
    _homekit: "homekit",
    _matter: "matter",
    _matterc: "matter",
    _matterd: "matter",
  });

/** Maps a bounded DNS-SD owner/PTR name while preserving unknown service types. */
export function dnsSdServiceSemantic(
  value: string,
): DnsSdServiceSemantic | undefined {
  if (typeof value !== "string" || Buffer.byteLength(value) > 1_024)
    throw new TypeError("DNS-SD service name is invalid");
  const match = /(?:^|\.)(_[-a-zA-Z0-9]{1,63})\._(tcp|udp)(?:\.|$)/.exec(value);
  if (match?.[1] === undefined || (match[2] !== "tcp" && match[2] !== "udp"))
    return undefined;
  const serviceType = match[1].toLowerCase();
  const family = DNS_SD_FAMILIES[serviceType] ?? "unknown";
  return Object.freeze({
    serviceType,
    transport: match[2],
    family,
  });
}

/** Same-responder URL authority. DNS names, userinfo, fragments and redirects are refused. */
export function authorizeAdvertisedUrl(
  value: string,
  responder: string,
): GovernedUrl {
  if (value.length > 2_048 || value.includes("@") || value.includes("#"))
    throw new TypeError("advertised URL is invalid");
  const match =
    /^(https?):\/\/(\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(\/[^\s]*)?$/.exec(
      value,
    );
  if (match === null)
    throw new TypeError("advertised URL must use an IP literal");
  const scheme = match[1] as "http" | "https";
  const rawHost = match.at(2);
  if (rawHost === undefined)
    throw new TypeError("advertised URL host is missing");
  const host = canonicalIp(rawHost.replace(/^\[|\]$/g, ""));
  if (host !== canonicalIp(responder))
    throw new RangeError("advertised URL escapes the authorized responder");
  const port =
    match[3] === undefined ? (scheme === "http" ? 80 : 443) : Number(match[3]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535)
    throw new RangeError("advertised URL port is invalid");
  return Object.freeze({ scheme, host, port, path: match[4] ?? "/" });
}

function canonicalIp(value: string): string {
  const family = isIP(value);
  if (family === 4)
    return value
      .split(".")
      .map((part) => String(Number(part)))
      .join(".");
  if (family === 6) {
    const hostname = new URL(`http://[${value}]/`).hostname;
    return hostname.slice(1, -1).toLowerCase();
  }
  throw new TypeError("IP literal is invalid");
}

export interface AssetCandidate {
  readonly id: string;
  readonly strongIdentifiers: readonly string[];
  readonly addresses: readonly string[];
  readonly names: readonly string[];
  readonly services: readonly string[];
  readonly conflicts: readonly string[];
  readonly mergeReasons?: readonly string[];
  readonly conflictReasons?: readonly string[];
}

const textDecoder = new TextDecoder("utf-8", { fatal: true });
const MAX_EVIDENCE_AGGREGATE_BYTES = 16 * 1_024 * 1_024;
const MAX_INVENTORY_AGGREGATE_BYTES = 16 * 1_024 * 1_024;
const MAX_SENSOR_STREAMS = 4_096;
const SENSOR_PROVENANCE_FIELDS = new Set([
  "sensorId",
  "networkScopeId",
  "upstreamSource",
  "upstreamRunId",
  "upstreamRecordId",
]);

/** Conservative deterministic reconciliation. Only scoped strong identifiers merge records. */
export function reconcileEvidence(
  records: readonly EvidenceRecord[],
): readonly AssetCandidate[] {
  if (records.length > 8_192)
    throw new RangeError("evidence capacity exceeded");
  let aggregateBytes = 0;
  for (const evidence of records) {
    aggregateBytes += validateImportedEvidence(evidence);
    if (aggregateBytes > MAX_EVIDENCE_AGGREGATE_BYTES)
      throw new RangeError("evidence aggregate byte capacity exceeded");
  }
  const activeRecords = records.filter(
    (record) =>
      record.disposition !== "expired" && record.disposition !== "withdrawn",
  );
  const strongNames = new Set([
    "mac",
    "lldpChassisId",
    "smbServerGuid",
    "snmpEngineId",
    "upnpUdn",
  ]);
  const scopeFor = (record: EvidenceRecord): string => {
    const fields = record.fields.filter(
      (item) => item.key === "networkScopeId",
    );
    if (fields.length === 0) return "local";
    if (fields.length !== 1)
      throw new TypeError("evidence has ambiguous network scope provenance");
    const field = fields[0];
    if (field === undefined)
      throw new TypeError("evidence network scope provenance is invalid");
    try {
      return `scope:${textDecoder.decode(field.value)}`;
    } catch {
      return `scopeHex:${Buffer.from(field.value).toString("hex")}`;
    }
  };
  const strongFor = (record: EvidenceRecord): string[] =>
    [
      ...new Set(
        record.fields
          .filter(
            (field) => strongNames.has(field.key) && field.value.byteLength > 0,
          )
          .map(
            (field) =>
              `${scopeFor(record)}:${field.key}:${Buffer.from(field.value).toString("hex")}`,
          ),
      ),
    ].sort();
  const parents = new Map<string, string>();
  const find = (value: string): string => {
    let root = parents.get(value) ?? value;
    while ((parents.get(root) ?? root) !== root)
      root = parents.get(root) ?? root;
    let cursor = value;
    while ((parents.get(cursor) ?? cursor) !== root) {
      const next = parents.get(cursor) ?? cursor;
      parents.set(cursor, root);
      cursor = next;
    }
    parents.set(value, root);
    return root;
  };
  const union = (left: string, right: string): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot === rightRoot) return;
    const [root, child] =
      leftRoot < rightRoot ? [leftRoot, rightRoot] : [rightRoot, leftRoot];
    parents.set(child, root);
  };
  const strongCounts = new Map<string, number>();
  for (const record of activeRecords) {
    const strong = strongFor(record);
    for (const value of strong)
      strongCounts.set(value, (strongCounts.get(value) ?? 0) + 1);
    for (const value of strong.slice(1)) union(strong[0] ?? value, value);
  }
  const assets = new Map<
    string,
    {
      strongIdentifiers: Set<string>;
      addresses: Set<string>;
      names: Set<string>;
      services: Set<string>;
      conflicts: Set<string>;
      mergeReasons: Set<string>;
      conflictReasons: Set<string>;
    }
  >();
  for (const record of activeRecords) {
    const strong = strongFor(record);
    const id =
      strong.length === 0
        ? `${scopeFor(record)}:${record.entity.kind}:${Buffer.from(record.entity.canonical).toString("hex")}`
        : find(strong[0] ?? "");
    const asset = assets.get(id) ?? {
      strongIdentifiers: new Set<string>(),
      addresses: new Set<string>(),
      names: new Set<string>(),
      services: new Set<string>(),
      conflicts: new Set<string>(),
      mergeReasons: new Set<string>(),
      conflictReasons: new Set<string>(),
    };
    for (const value of strong) {
      asset.strongIdentifiers.add(value);
      const count = strongCounts.get(value) ?? 0;
      if (count > 1)
        asset.mergeReasons.add(
          `shared ${value.split(":").at(-2) ?? "identifier"} across ${String(count)} evidence records`,
        );
    }
    if (strong.length > 1)
      asset.mergeReasons.add("co-observed scoped strong identifiers");
    for (const field of record.fields) {
      let text: string;
      try {
        text = textDecoder.decode(field.value);
      } catch {
        continue;
      }
      if (field.key === "address" || field.key === "responder")
        asset.addresses.add(text);
      if (field.key === "name" || field.key === "hostname")
        asset.names.add(text);
      if (field.key === "service" || field.key === "protocol")
        asset.services.add(text);
      if (record.disposition === "conflict") {
        asset.conflicts.add(text);
        asset.conflictReasons.add(`conflicting ${field.key}`);
      }
    }
    assets.set(id, asset);
  }
  return Object.freeze(
    [...assets.entries()]
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([id, asset]) =>
        Object.freeze({
          id,
          strongIdentifiers: sorted(asset.strongIdentifiers),
          addresses: sorted(asset.addresses),
          names: sorted(asset.names),
          services: sorted(asset.services),
          conflicts: sorted(asset.conflicts),
          mergeReasons: sorted(asset.mergeReasons),
          conflictReasons: sorted(asset.conflictReasons),
        }),
      ),
  );
}

export type AssetClassification =
  | "router"
  | "switch"
  | "printer"
  | "camera"
  | "windowsHost"
  | "dnsInfrastructure"
  | "smartHome"
  | "industrialController";

export interface ClassificationResult {
  readonly classification: AssetClassification;
  readonly positiveEvidence: readonly string[];
  readonly conflictingEvidence: readonly string[];
}

export function classifyAsset(
  asset: AssetCandidate,
): readonly ClassificationResult[] {
  validateAssetCandidate(asset);
  const services = new Set(asset.services.map((entry) => entry.toLowerCase()));
  const rows: [AssetClassification, boolean, string][] = [
    [
      "router",
      services.has("routeradvertisement") ||
        services.has("pcp") ||
        services.has("nat-pmp"),
      "router control-plane evidence",
    ],
    [
      "switch",
      services.has("lldp") && !services.has("routeradvertisement"),
      "LLDP infrastructure evidence",
    ],
    [
      "printer",
      services.has("ipp") || services.has("printer"),
      "printing service evidence",
    ],
    [
      "camera",
      services.has("rtsp") || services.has("onvif"),
      "camera/media evidence",
    ],
    [
      "windowsHost",
      services.has("smb") || services.has("ws-discovery"),
      "Windows service evidence",
    ],
    ["dnsInfrastructure", services.has("dns"), "DNS service evidence"],
    [
      "smartHome",
      services.has("matter") || services.has("homekit") || services.has("cast"),
      "smart-home evidence",
    ],
    [
      "industrialController",
      ["modbus", "bacnet", "ethernet-ip", "s7"].some((item) =>
        services.has(item),
      ),
      "industrial protocol evidence",
    ],
  ];
  return Object.freeze(
    rows
      .filter(([, matches]) => matches)
      .map(([classification, , reason]) =>
        Object.freeze({
          classification,
          positiveEvidence: Object.freeze([reason]),
          conflictingEvidence: Object.freeze([...asset.conflicts]),
        }),
      ),
  );
}

export interface InventorySnapshot {
  readonly schemaVersion: 1;
  readonly sequence: bigint;
  readonly assets: readonly AssetCandidate[];
  readonly withdrawnAssetIds?: readonly string[];
  readonly previouslySeenAssetIds?: readonly string[];
}

export interface InventoryChange {
  readonly kind:
    "new" | "changed" | "expired" | "withdrawn" | "reappeared" | "conflicted";
  readonly assetId: string;
}

export interface InventoryStorageAdapter {
  load(): Promise<InventorySnapshot | undefined>;
  save(snapshot: InventorySnapshot): Promise<void>;
}

export function inventoryDelta(
  before: InventorySnapshot,
  after: InventorySnapshot,
): readonly InventoryChange[] {
  validateInventorySnapshot(before);
  validateInventorySnapshot(after);
  if (after.sequence <= before.sequence)
    throw new RangeError("inventory sequence must increase");
  const left = new Map(before.assets.map((asset) => [asset.id, asset]));
  const right = new Map(after.assets.map((asset) => [asset.id, asset]));
  const withdrawn = new Set(after.withdrawnAssetIds ?? []);
  const previouslySeen = new Set(after.previouslySeenAssetIds ?? []);
  const changes: InventoryChange[] = [];
  for (const [id, asset] of right) {
    const previous = left.get(id);
    if (withdrawn.has(id)) changes.push({ kind: "withdrawn", assetId: id });
    else if (previous === undefined)
      changes.push({
        kind: previouslySeen.has(id) ? "reappeared" : "new",
        assetId: id,
      });
    else if (assetFingerprint(previous) !== assetFingerprint(asset))
      changes.push({ kind: "changed", assetId: id });
    if (
      asset.conflicts.length > 0 &&
      (previous === undefined ||
        asset.conflicts.some((value) => !previous.conflicts.includes(value)))
    )
      changes.push({ kind: "conflicted", assetId: id });
  }
  for (const id of left.keys())
    if (!right.has(id) && !withdrawn.has(id))
      changes.push({ kind: "expired", assetId: id });
  for (const id of withdrawn)
    if (!right.has(id)) changes.push({ kind: "withdrawn", assetId: id });
  const kindOrder = [
    "new",
    "reappeared",
    "changed",
    "conflicted",
    "withdrawn",
    "expired",
  ];
  return Object.freeze(
    changes
      .sort((a, b) =>
        a.assetId < b.assetId
          ? -1
          : a.assetId > b.assetId
            ? 1
            : kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind),
      )
      .map((change) => Object.freeze(change)),
  );
}

function assetFingerprint(asset: AssetCandidate): string {
  const ordered = (values: readonly string[] | undefined): string[] =>
    [...(values ?? [])].sort();
  return JSON.stringify([
    asset.id,
    ordered(asset.strongIdentifiers),
    ordered(asset.addresses),
    ordered(asset.names),
    ordered(asset.services),
    ordered(asset.conflicts),
    ordered(asset.mergeReasons),
    ordered(asset.conflictReasons),
  ]);
}

function validateInventorySnapshot(snapshot: InventorySnapshot): void {
  const value: unknown = snapshot;
  if (
    !record(value) ||
    value.schemaVersion !== 1 ||
    typeof value.sequence !== "bigint" ||
    value.sequence < 1n ||
    !Array.isArray(value.assets) ||
    value.assets.length > 8_192
  )
    throw new TypeError("inventory snapshot is invalid");
  const ids = new Set<string>();
  let aggregateBytes = 0;
  for (const asset of value.assets) {
    const byteCount = validateAssetCandidate(asset);
    if (!record(asset) || typeof asset.id !== "string")
      throw new TypeError("inventory asset is invalid");
    if (ids.has(asset.id)) throw new TypeError("inventory asset is duplicated");
    aggregateBytes += byteCount;
    if (aggregateBytes > MAX_INVENTORY_AGGREGATE_BYTES)
      throw new RangeError("inventory aggregate byte capacity exceeded");
    ids.add(asset.id);
  }
  for (const values of [
    value.withdrawnAssetIds ?? [],
    value.previouslySeenAssetIds ?? [],
  ]) {
    if (
      !Array.isArray(values) ||
      values.length > 8_192 ||
      values.some((item) => {
        return (
          typeof item !== "string" ||
          item.length < 1 ||
          Buffer.byteLength(item) > 2_048
        );
      }) ||
      new Set(values).size !== values.length
    )
      throw new TypeError("inventory history identifiers are invalid");
  }
}

function validateAssetCandidate(input: unknown): number {
  if (
    !record(input) ||
    typeof input.id !== "string" ||
    input.id.length < 1 ||
    Buffer.byteLength(input.id) > 2_048 ||
    !Array.isArray(input.strongIdentifiers) ||
    !Array.isArray(input.addresses) ||
    !Array.isArray(input.names) ||
    !Array.isArray(input.services) ||
    !Array.isArray(input.conflicts)
  )
    throw new TypeError("inventory asset is invalid");
  const lists = [
    input.strongIdentifiers,
    input.addresses,
    input.names,
    input.services,
    input.conflicts,
    input.mergeReasons ?? [],
    input.conflictReasons ?? [],
  ];
  let elementCount = 0;
  let byteCount = Buffer.byteLength(input.id);
  for (const entries of lists) {
    if (!Array.isArray(entries))
      throw new TypeError("inventory asset list is invalid");
    elementCount += entries.length;
    for (const entry of entries) {
      if (typeof entry !== "string" || Buffer.byteLength(entry) > 2_048)
        throw new TypeError("inventory asset value is invalid");
      byteCount += Buffer.byteLength(entry);
    }
  }
  if (elementCount > 8_192 || byteCount > 1_024 * 1_024)
    throw new RangeError("inventory asset capacity exceeded");
  return byteCount;
}

export interface SensorCapabilitySnapshotEntry {
  readonly id: string;
  readonly version: string;
}

export interface SensorCaptureVisibility {
  readonly interfaces: readonly string[];
  readonly protocols: readonly string[];
  readonly promiscuous: boolean;
  readonly includesOutgoing: boolean;
}

export interface SensorEnvelopeSummary {
  readonly acceptedRecords: number;
  readonly droppedRecords: number;
}

export interface SensorEnvelope {
  readonly version: 1;
  readonly sensorId: string;
  readonly networkScopeId: string;
  readonly sequence: bigint;
  readonly monotonicStartNanoseconds: bigint;
  readonly monotonicEndNanoseconds: bigint;
  readonly wallTimeMilliseconds?: bigint;
  readonly clockUncertaintyMilliseconds: number;
  readonly truncated: boolean;
  readonly capabilities?: readonly Readonly<SensorCapabilitySnapshotEntry>[];
  readonly captureVisibility?: Readonly<SensorCaptureVisibility>;
  readonly summary?: Readonly<SensorEnvelopeSummary>;
  readonly records: readonly EvidenceRecord[];
}

/** Bounded deterministic transport-neutral encoding; applications own transport trust. */
export function encodeSensorEnvelope(envelope: SensorEnvelope): Uint8Array {
  validateSensorEnvelope(envelope);
  const json = JSON.stringify({
    ...envelope,
    sequence: envelope.sequence.toString(),
    monotonicStartNanoseconds: envelope.monotonicStartNanoseconds.toString(),
    monotonicEndNanoseconds: envelope.monotonicEndNanoseconds.toString(),
    wallTimeMilliseconds: envelope.wallTimeMilliseconds?.toString(),
    records: envelope.records.map(serializeEvidence),
  });
  const bytes = Buffer.from(json);
  if (bytes.byteLength > 16 * 1_024 * 1_024)
    throw new RangeError("sensor envelope byte ceiling exceeded");
  return Uint8Array.from(bytes);
}

export function decodeSensorEnvelope(bytes: Uint8Array): SensorEnvelope {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > 16 * 1_024 * 1_024)
    throw new RangeError("sensor envelope byte ceiling exceeded");
  const value: unknown = JSON.parse(textDecoder.decode(bytes));
  if (
    !record(value) ||
    !Array.isArray(value.records) ||
    value.records.length > 8_192 ||
    typeof value.sensorId !== "string" ||
    typeof value.networkScopeId !== "string" ||
    typeof value.clockUncertaintyMilliseconds !== "number" ||
    typeof value.truncated !== "boolean"
  )
    throw new TypeError("sensor envelope is invalid");
  if (value.version !== 1)
    throw new TypeError("sensor envelope version is unsupported");
  const envelope: SensorEnvelope = {
    version: value.version,
    sensorId: value.sensorId,
    networkScopeId: value.networkScopeId,
    sequence: boundedDecimal(value.sequence, false),
    monotonicStartNanoseconds: boundedDecimal(
      value.monotonicStartNanoseconds,
      false,
    ),
    monotonicEndNanoseconds: boundedDecimal(
      value.monotonicEndNanoseconds,
      false,
    ),
    ...(value.wallTimeMilliseconds === undefined
      ? {}
      : {
          wallTimeMilliseconds: boundedDecimal(
            value.wallTimeMilliseconds,
            true,
          ),
        }),
    clockUncertaintyMilliseconds: value.clockUncertaintyMilliseconds,
    truncated: value.truncated,
    ...(value.capabilities === undefined
      ? {}
      : {
          capabilities: decodeSensorCapabilities(value.capabilities),
        }),
    ...(value.captureVisibility === undefined
      ? {}
      : {
          captureVisibility: decodeSensorCaptureVisibility(
            value.captureVisibility,
          ),
        }),
    ...(value.summary === undefined
      ? {}
      : { summary: decodeSensorSummary(value.summary) }),
    records: value.records.map(deserializeEvidence),
  };
  validateSensorEnvelope(envelope);
  return Object.freeze({
    ...envelope,
    ...(envelope.capabilities === undefined
      ? {}
      : {
          capabilities: Object.freeze(
            envelope.capabilities.map((entry) => Object.freeze({ ...entry })),
          ),
        }),
    ...(envelope.captureVisibility === undefined
      ? {}
      : {
          captureVisibility: Object.freeze({
            ...envelope.captureVisibility,
            interfaces: Object.freeze([
              ...envelope.captureVisibility.interfaces,
            ]),
            protocols: Object.freeze([...envelope.captureVisibility.protocols]),
          }),
        }),
    ...(envelope.summary === undefined
      ? {}
      : { summary: Object.freeze({ ...envelope.summary }) }),
    records: Object.freeze([...envelope.records]),
  });
}

function decodeSensorCapabilities(
  value: unknown,
): readonly SensorCapabilitySnapshotEntry[] {
  if (!Array.isArray(value))
    throw new TypeError("sensor capability snapshot is invalid");
  return value.map((entry) => {
    if (
      !record(entry) ||
      typeof entry.id !== "string" ||
      typeof entry.version !== "string"
    )
      throw new TypeError("sensor capability snapshot is invalid");
    return { id: entry.id, version: entry.version };
  });
}

function decodeSensorCaptureVisibility(
  value: unknown,
): SensorCaptureVisibility {
  if (
    !record(value) ||
    !Array.isArray(value.interfaces) ||
    !value.interfaces.every((entry) => typeof entry === "string") ||
    !Array.isArray(value.protocols) ||
    !value.protocols.every((entry) => typeof entry === "string") ||
    typeof value.promiscuous !== "boolean" ||
    typeof value.includesOutgoing !== "boolean"
  )
    throw new TypeError("sensor capture visibility is invalid");
  return {
    interfaces: value.interfaces,
    protocols: value.protocols,
    promiscuous: value.promiscuous,
    includesOutgoing: value.includesOutgoing,
  };
}

function decodeSensorSummary(value: unknown): SensorEnvelopeSummary {
  if (
    !record(value) ||
    typeof value.acceptedRecords !== "number" ||
    typeof value.droppedRecords !== "number"
  )
    throw new TypeError("sensor summary is invalid");
  return {
    acceptedRecords: value.acceptedRecords,
    droppedRecords: value.droppedRecords,
  };
}

export class SensorFusion {
  readonly #sequences = new Map<string, bigint>();

  admit(envelope: SensorEnvelope): readonly EvidenceRecord[] {
    validateSensorEnvelope(envelope);
    const key = JSON.stringify([envelope.sensorId, envelope.networkScopeId]);
    const previous = this.#sequences.get(key);
    if (previous !== undefined && envelope.sequence <= previous)
      throw new RangeError("duplicate or replayed sensor envelope");
    if (previous !== undefined && envelope.sequence !== previous + 1n)
      throw new RangeError("sensor envelope sequence gap");
    if (previous === undefined && this.#sequences.size >= MAX_SENSOR_STREAMS)
      throw new RangeError("sensor fusion stream capacity exceeded");
    const fused = fuseSensorEnvelope(envelope);
    this.#sequences.set(key, envelope.sequence);
    return fused;
  }
}

/** Re-provenances imported evidence and scopes strong identities to its sensor network. */
export function fuseSensorEnvelope(
  envelope: SensorEnvelope,
): readonly EvidenceRecord[] {
  validateSensorEnvelope(envelope);
  const runId = Buffer.from(
    JSON.stringify([
      envelope.sensorId,
      envelope.networkScopeId,
      envelope.sequence.toString(),
    ]),
  );
  let aggregateBytes = 0;
  const records = envelope.records.map((record, index) => {
    const fields = record.fields
      .filter((field) => !SENSOR_PROVENANCE_FIELDS.has(field.key))
      .map((field) => ({
        key: field.key,
        value: Uint8Array.from(field.value),
      }));
    const fused: EvidenceRecord = {
      ...record,
      origin: {
        source: "importedSensor",
        sourceSchema: envelope.version,
        runId: Uint8Array.from(runId),
        recordId: BigInt(index),
      },
      fields: [
        ...fields,
        { key: "sensorId", value: Buffer.from(envelope.sensorId) },
        {
          key: "networkScopeId",
          value: Buffer.from(envelope.networkScopeId),
        },
        { key: "upstreamSource", value: Buffer.from(record.origin.source) },
        {
          key: "upstreamRunId",
          value: Uint8Array.from(record.origin.runId),
        },
        {
          key: "upstreamRecordId",
          value: Buffer.from(record.origin.recordId.toString()),
        },
      ],
      relations: record.relations.map((relation) => ({
        kind: relation.kind,
        target: {
          kind: relation.target.kind,
          canonical: Uint8Array.from(relation.target.canonical),
        },
      })),
    };
    aggregateBytes += validateImportedEvidence(fused);
    if (aggregateBytes > MAX_EVIDENCE_AGGREGATE_BYTES)
      throw new RangeError("fused sensor evidence byte ceiling exceeded");
    return Object.freeze(fused);
  });
  return Object.freeze(records);
}

export function evidenceFromObservation(
  observation: ObservationResult,
  runId: Uint8Array,
): EvidenceRecord {
  const address = observation.sourceAddress;
  const mac = Buffer.from(observation.sourceMac).toString("hex");
  const hasStableMac =
    observation.sourceMac.byteLength === 6 &&
    observation.sourceMac.some((byte) => byte !== 0);
  const entityKind = observationEvidenceEntityKind(observation.protocol);
  const lifetimeSeconds = observationLifetimeSeconds(observation, entityKind);
  const withdrawn = observationWithdrawsEvidence(
    observation,
    entityKind,
    lifetimeSeconds,
  );
  const expiresAtNanoseconds =
    lifetimeSeconds === undefined
      ? undefined
      : observation.timestampNanoseconds +
        BigInt(lifetimeSeconds) * 1_000_000_000n;
  const baseIdentity = hasStableMac
    ? `mac:${mac}`
    : `interface:${String(observation.interfaceIndex)}:address:${address ?? "unknown"}`;
  return {
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: Uint8Array.from(runId),
      recordId: observation.sequence,
    },
    entity: {
      kind: entityKind,
      canonical: Buffer.from(
        entityKind === "deviceCandidate"
          ? baseIdentity
          : `${observation.protocol}:${baseIdentity}`,
      ),
    },
    confidence: "structural",
    disposition: withdrawn ? "withdrawn" : "observed",
    observedAtNanoseconds: observation.timestampNanoseconds,
    ...(observation.wallTimeMilliseconds === undefined
      ? {}
      : { wallTimeMilliseconds: observation.wallTimeMilliseconds }),
    ...(expiresAtNanoseconds === undefined ? {} : { expiresAtNanoseconds }),
    fields: [
      ...(hasStableMac
        ? [{ key: "mac", value: Uint8Array.from(observation.sourceMac) }]
        : []),
      { key: "protocol", value: Buffer.from(observation.protocol) },
      ...(address === undefined
        ? []
        : [{ key: "address", value: Buffer.from(address) }]),
      ...observation.metadata.map((field) => ({
        key: field.key,
        value: Uint8Array.from(field.value),
      })),
    ],
    relations: [
      {
        kind: "attachedToInterface",
        target: {
          kind: "interface",
          canonical: Buffer.from(String(observation.interfaceIndex)),
        },
      },
    ],
  };
}

/**
 * Projects one passive packet into conservative device, service, and name
 * records without authorizing any active follow-up. The original observation
 * remains recoverable in every record's fields.
 */
export function evidenceRecordsFromObservation(
  observation: ObservationResult,
  runId: Uint8Array,
): readonly EvidenceRecord[] {
  const primary = evidenceFromObservation(observation, runId);
  const baseIdentity = passiveDeviceIdentity(observation);
  const deviceKey = {
    kind: "deviceCandidate" as const,
    canonical: baseIdentity,
  };
  const sequenceBase = observation.sequence * 32n;
  const records: EvidenceRecord[] = [];
  const { expiresAtNanoseconds: primaryExpiry, ...primaryWithoutExpiry } =
    primary;
  void primaryExpiry;
  const device: EvidenceRecord = {
    ...primaryWithoutExpiry,
    origin: { ...primary.origin, recordId: sequenceBase },
    entity: deviceKey,
    disposition: "observed",
    relations: primary.relations,
  };
  records.push(device);
  if (primary.entity.kind !== "deviceCandidate")
    records.push({
      ...primary,
      origin: { ...primary.origin, recordId: sequenceBase + 1n },
      relations: [
        ...primary.relations,
        { kind: "advertisedBy", target: deviceKey },
      ],
    });
  const names = new Map<string, Uint8Array>();
  for (const field of observation.metadata) {
    if (
      [
        "dnsRecordName",
        "dnsPtr",
        "dnsSrvTarget",
        "dhcpHostName",
        "dhcpv6ClientFqdn",
        "systemName",
      ].includes(field.key) &&
      field.value.byteLength > 0
    )
      names.set(Buffer.from(field.value).toString("hex"), field.value);
  }
  for (const value of [...names.values()].slice(0, 8)) {
    const presentation = passiveNamePresentation(value);
    if (presentation === undefined) continue;
    const index = BigInt(records.length);
    records.push(
      withObservationPolicy(
        {
          ...primary,
          origin: { ...primary.origin, recordId: sequenceBase + index },
          entity: { kind: "name", canonical: Uint8Array.from(value) },
          fields: [
            { key: "name", value: Buffer.from(presentation) },
            { key: "protocol", value: Buffer.from(observation.protocol) },
          ],
          relations: [{ kind: "advertisedBy", target: deviceKey }],
        },
        observation,
        "name",
      ),
    );
  }
  const semantics = new Map<string, DnsSdServiceSemantic>();
  for (const field of observation.metadata) {
    if (!["dnsRecordName", "dnsPtr"].includes(field.key)) continue;
    try {
      const presentation = dnsWireNameToPresentation(field.value);
      const semantic = dnsSdServiceSemantic(presentation);
      if (semantic !== undefined)
        semantics.set(
          `${semantic.serviceType}:${semantic.transport}`,
          semantic,
        );
    } catch {
      // Malformed text remains available in the original bounded metadata.
    }
  }
  for (const semantic of [...semantics.values()].slice(0, 8)) {
    records.push(
      withObservationPolicy(
        {
          ...primary,
          origin: {
            ...primary.origin,
            recordId: sequenceBase + BigInt(records.length),
          },
          entity: {
            kind: "service",
            canonical: Buffer.from(
              `${semantic.serviceType}:${semantic.transport}:${Buffer.from(baseIdentity).toString("hex")}`,
            ),
          },
          fields: [
            { key: "service", value: Buffer.from(semantic.family) },
            { key: "serviceType", value: Buffer.from(semantic.serviceType) },
            { key: "transport", value: Buffer.from(semantic.transport) },
          ],
          relations: [{ kind: "advertisedBy", target: deviceKey }],
        },
        observation,
        "service",
      ),
    );
  }
  return Object.freeze(records.map((record) => Object.freeze(record)));
}

function passiveDeviceIdentity(observation: ObservationResult): Uint8Array {
  const stableMac =
    observation.sourceMac.byteLength === 6 &&
    observation.sourceMac.some((byte) => byte !== 0);
  return Buffer.from(
    stableMac
      ? `mac:${Buffer.from(observation.sourceMac).toString("hex")}`
      : `interface:${String(observation.interfaceIndex)}:address:${observation.sourceAddress ?? "unknown"}`,
  );
}

function observationEvidenceEntityKind(
  protocol: string,
): EvidenceRecord["entity"]["kind"] {
  if (
    [
      "routerAdvertisement",
      "routerSolicitation",
      "ipv6Redirect",
      "vrrp",
      "rip",
      "ospf",
    ].includes(protocol)
  )
    return "router";
  if (["lldp", "stp", "lacp", "igmp", "mld"].includes(protocol))
    return "adjacency";
  if (["mdns", "llmnr", "nbns", "ssdp", "wsDiscovery"].includes(protocol))
    return "service";
  return "deviceCandidate";
}

function observationLifetimeSeconds(
  observation: ObservationResult,
  entityKind: EvidenceRecord["entity"]["kind"],
): number | undefined {
  const lifetimes: number[] = [];
  for (const field of observation.metadata) {
    let value: number | undefined;
    if (
      ((field.key === "dnsTtl" &&
        (entityKind === "name" || entityKind === "service")) ||
        (field.key === "ssdpMaxAge" && entityKind === "service")) &&
      field.value.byteLength === 4
    )
      value = Buffer.from(field.value).readUInt32BE(0);
    if (
      ((field.key === "ttl" && entityKind === "adjacency") ||
        (field.key === "routerLifetime" && entityKind === "router")) &&
      field.value.byteLength === 2
    )
      value = Buffer.from(field.value).readUInt16BE(0);
    if (value !== undefined) lifetimes.push(value);
  }
  return lifetimes.length === 0 ? undefined : Math.min(...lifetimes);
}

function observationWithdrawsEvidence(
  observation: ObservationResult,
  entityKind: EvidenceRecord["entity"]["kind"],
  lifetimeSeconds: number | undefined,
): boolean {
  if (lifetimeSeconds === 0) return true;
  return observation.metadata.some((field) => {
    if (field.key === "ssdpNts" && entityKind === "service")
      return Buffer.from(field.value)
        .toString("ascii")
        .trim()
        .toLowerCase()
        .includes("ssdp:byebye");
    return false;
  });
}

function withObservationPolicy(
  record: EvidenceRecord,
  observation: ObservationResult,
  entityKind: EvidenceRecord["entity"]["kind"],
): EvidenceRecord {
  const lifetimeSeconds = observationLifetimeSeconds(observation, entityKind);
  const withdrawn = observationWithdrawsEvidence(
    observation,
    entityKind,
    lifetimeSeconds,
  );
  return {
    ...record,
    disposition: withdrawn ? "withdrawn" : "observed",
    ...(lifetimeSeconds === undefined
      ? {}
      : {
          expiresAtNanoseconds:
            observation.timestampNanoseconds +
            BigInt(lifetimeSeconds) * 1_000_000_000n,
        }),
  };
}

function passiveNamePresentation(value: Uint8Array): string | undefined {
  try {
    return dnsWireNameToPresentation(value);
  } catch {
    try {
      return textDecoder.decode(value);
    } catch {
      return undefined;
    }
  }
}

function dnsWireNameToPresentation(value: Uint8Array): string {
  if (value.byteLength < 1 || value.byteLength > 255)
    throw new TypeError("canonical DNS name is invalid");
  const labels: string[] = [];
  let offset = 0;
  while (offset < value.byteLength) {
    const length = value[offset];
    if (length === undefined)
      throw new TypeError("canonical DNS name is truncated");
    offset += 1;
    if (length === 0) {
      if (offset !== value.byteLength)
        throw new TypeError("canonical DNS name has trailing bytes");
      return labels.join(".");
    }
    if (length > 63 || offset + length > value.byteLength)
      throw new TypeError("canonical DNS label is invalid");
    const label = textDecoder.decode(value.subarray(offset, offset + length));
    if (!/^[\x21-\x7e]+$/.test(label))
      throw new TypeError("canonical DNS label is not presentable");
    labels.push(label);
    offset += length;
  }
  throw new TypeError("canonical DNS name is unterminated");
}

function validateSensorEnvelope(envelope: SensorEnvelope): void {
  const value: unknown = envelope;
  if (
    !record(value) ||
    value.version !== 1 ||
    typeof value.sensorId !== "string" ||
    value.sensorId.length < 1 ||
    Buffer.byteLength(value.sensorId) > 256 ||
    value.sensorId.includes("\0") ||
    typeof value.networkScopeId !== "string" ||
    value.networkScopeId.length < 1 ||
    Buffer.byteLength(value.networkScopeId) > 256 ||
    value.networkScopeId.includes("\0") ||
    typeof value.sequence !== "bigint" ||
    value.sequence < 1n ||
    typeof value.monotonicStartNanoseconds !== "bigint" ||
    value.monotonicStartNanoseconds < 0n ||
    typeof value.monotonicEndNanoseconds !== "bigint" ||
    value.monotonicEndNanoseconds < value.monotonicStartNanoseconds ||
    (value.wallTimeMilliseconds !== undefined &&
      typeof value.wallTimeMilliseconds !== "bigint") ||
    !Number.isInteger(value.clockUncertaintyMilliseconds) ||
    typeof value.clockUncertaintyMilliseconds !== "number" ||
    value.clockUncertaintyMilliseconds < 0 ||
    value.clockUncertaintyMilliseconds > 86_400_000 ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.records) ||
    value.records.length > 8_192
  )
    throw new TypeError("sensor envelope header is invalid");
  if (value.capabilities !== undefined) {
    if (!Array.isArray(value.capabilities) || value.capabilities.length > 256)
      throw new RangeError("sensor capability snapshot exceeds its bound");
    const identifiers = new Set<string>();
    for (const entry of value.capabilities) {
      if (
        !record(entry) ||
        typeof entry.id !== "string" ||
        entry.id.length < 1 ||
        Buffer.byteLength(entry.id) > 256 ||
        entry.id.includes("\0") ||
        typeof entry.version !== "string" ||
        entry.version.length < 1 ||
        Buffer.byteLength(entry.version) > 64 ||
        entry.version.includes("\0") ||
        identifiers.has(entry.id)
      )
        throw new TypeError("sensor capability snapshot is invalid");
      identifiers.add(entry.id);
    }
  }
  if (value.captureVisibility !== undefined) {
    const visibility = value.captureVisibility;
    if (
      !record(visibility) ||
      !Array.isArray(visibility.interfaces) ||
      visibility.interfaces.length > 64 ||
      !Array.isArray(visibility.protocols) ||
      visibility.protocols.length > 32 ||
      typeof visibility.promiscuous !== "boolean" ||
      typeof visibility.includesOutgoing !== "boolean"
    )
      throw new TypeError("sensor capture visibility is invalid");
    for (const entries of [
      visibility.interfaces as unknown[],
      visibility.protocols as unknown[],
    ]) {
      for (const item of entries) {
        if (
          typeof item !== "string" ||
          item.length < 1 ||
          Buffer.byteLength(item) > 256 ||
          item.includes("\0")
        )
          throw new TypeError("sensor capture visibility entry is invalid");
      }
    }
  }
  if (value.summary !== undefined) {
    const summary = value.summary;
    if (
      !record(summary) ||
      !Number.isSafeInteger(summary.acceptedRecords) ||
      (summary.acceptedRecords as number) < 0 ||
      (summary.acceptedRecords as number) > 8_192 ||
      !Number.isSafeInteger(summary.droppedRecords) ||
      (summary.droppedRecords as number) < 0 ||
      (summary.droppedRecords as number) > 4_294_967_295
    )
      throw new TypeError("sensor summary is invalid");
  }
  let aggregateBytes = 0;
  for (const evidence of value.records) {
    aggregateBytes += validateImportedEvidence(evidence);
    if (
      !record(evidence) ||
      !Array.isArray(evidence.fields) ||
      evidence.fields.length > 123
    )
      throw new RangeError("sensor evidence has no provenance field capacity");
    if (aggregateBytes > 16 * 1_024 * 1_024)
      throw new RangeError("sensor envelope byte ceiling exceeded");
  }
}

function validateImportedEvidence(input: unknown): number {
  const sources = new Set([
    "scanResult",
    "discoveryResult",
    "passiveObservation",
    "pathObservation",
    "serviceConversation",
    "localContext",
    "importedSensor",
  ]);
  const entities = new Set([
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
  const confidences = new Set([
    "weak",
    "structural",
    "transactionCorrelated",
    "strongCorrelated",
  ]);
  const dispositions = new Set([
    "observed",
    "inferred",
    "expired",
    "withdrawn",
    "conflict",
  ]);
  if (
    !record(input) ||
    input.schemaVersion !== 1 ||
    !record(input.origin) ||
    !record(input.entity) ||
    !Array.isArray(input.fields) ||
    !Array.isArray(input.relations)
  )
    throw new TypeError("sensor evidence record is invalid");
  const evidence = input;
  const origin = evidence.origin;
  const entity = evidence.entity;
  const fields = evidence.fields;
  const relations = evidence.relations;
  if (
    !record(origin) ||
    !record(entity) ||
    !Array.isArray(fields) ||
    !Array.isArray(relations)
  )
    throw new TypeError("sensor evidence record is invalid");
  if (
    typeof origin.source !== "string" ||
    !sources.has(origin.source) ||
    !Number.isInteger(origin.sourceSchema) ||
    typeof origin.sourceSchema !== "number" ||
    origin.sourceSchema < 1 ||
    !(origin.runId instanceof Uint8Array) ||
    origin.runId.byteLength < 1 ||
    origin.runId.byteLength > 1_024 ||
    typeof origin.recordId !== "bigint" ||
    origin.recordId < 0n ||
    typeof entity.kind !== "string" ||
    !entities.has(entity.kind) ||
    !(entity.canonical instanceof Uint8Array) ||
    entity.canonical.byteLength < 1 ||
    entity.canonical.byteLength > 1_024 ||
    typeof evidence.confidence !== "string" ||
    !confidences.has(evidence.confidence) ||
    typeof evidence.disposition !== "string" ||
    !dispositions.has(evidence.disposition) ||
    typeof evidence.observedAtNanoseconds !== "bigint" ||
    evidence.observedAtNanoseconds < 0n ||
    (evidence.expiresAtNanoseconds !== undefined &&
      (typeof evidence.expiresAtNanoseconds !== "bigint" ||
        evidence.expiresAtNanoseconds < evidence.observedAtNanoseconds)) ||
    (evidence.wallTimeMilliseconds !== undefined &&
      typeof evidence.wallTimeMilliseconds !== "bigint") ||
    fields.length > 128 ||
    relations.length > 64
  )
    throw new TypeError("sensor evidence record is invalid");
  let bytes = origin.runId.byteLength + entity.canonical.byteLength;
  for (const field of fields) {
    if (
      !record(field) ||
      typeof field.key !== "string" ||
      field.key.length < 1 ||
      Buffer.byteLength(field.key) > 1_024 ||
      !(field.value instanceof Uint8Array) ||
      field.value.byteLength > 1_024
    )
      throw new TypeError("sensor evidence field is invalid");
    bytes += Buffer.byteLength(field.key) + field.value.byteLength;
  }
  for (const relation of relations) {
    if (
      !record(relation) ||
      !record(relation.target) ||
      typeof relation.kind !== "string" ||
      ![
        "hasAddress",
        "hasName",
        "offersService",
        "attachedToInterface",
        "routesPrefix",
        "nextHop",
        "advertisedBy",
        "derivedFrom",
        "classifiedAs",
      ].includes(relation.kind) ||
      typeof relation.target.kind !== "string" ||
      !entities.has(relation.target.kind) ||
      !(relation.target.canonical instanceof Uint8Array) ||
      relation.target.canonical.byteLength < 1 ||
      relation.target.canonical.byteLength > 1_024
    )
      throw new TypeError("sensor evidence relation is invalid");
    bytes += relation.target.canonical.byteLength;
  }
  if (bytes > 16 * 1_024)
    throw new RangeError("sensor evidence record byte ceiling exceeded");
  return bytes;
}

function serializeEvidence(value: EvidenceRecord): unknown {
  return {
    ...value,
    origin: {
      ...value.origin,
      runId: Buffer.from(value.origin.runId).toString("base64"),
      recordId: value.origin.recordId.toString(),
    },
    entity: {
      ...value.entity,
      canonical: Buffer.from(value.entity.canonical).toString("base64"),
    },
    observedAtNanoseconds: value.observedAtNanoseconds.toString(),
    expiresAtNanoseconds: value.expiresAtNanoseconds?.toString(),
    wallTimeMilliseconds: value.wallTimeMilliseconds?.toString(),
    fields: value.fields.map((field) => ({
      key: field.key,
      value: Buffer.from(field.value).toString("base64"),
    })),
    relations: value.relations.map((relation) => ({
      kind: relation.kind,
      target: {
        kind: relation.target.kind,
        canonical: Buffer.from(relation.target.canonical).toString("base64"),
      },
    })),
  };
}

function deserializeEvidence(value: unknown): EvidenceRecord {
  if (
    !record(value) ||
    value.schemaVersion !== 1 ||
    !record(value.origin) ||
    !record(value.entity) ||
    !Array.isArray(value.fields) ||
    !Array.isArray(value.relations)
  )
    throw new TypeError("sensor evidence record is invalid");
  const fields: unknown[] = value.fields;
  const relations: unknown[] = value.relations;
  if (fields.length > 128 || relations.length > 64)
    throw new RangeError("sensor evidence nested capacity exceeded");
  for (const field of fields)
    if (!record(field)) throw new TypeError("sensor evidence field is invalid");
  for (const relation of relations)
    if (!record(relation) || !record(relation.target))
      throw new TypeError("sensor evidence relation is invalid");
  return Object.freeze({
    schemaVersion: 1,
    origin: Object.freeze({
      source: value.origin.source as EvidenceRecord["origin"]["source"],
      sourceSchema: value.origin.sourceSchema as number,
      runId: decodeBase64(value.origin.runId),
      recordId: boundedDecimal(value.origin.recordId, false),
    }),
    entity: Object.freeze({
      kind: value.entity.kind as EvidenceRecord["entity"]["kind"],
      canonical: decodeBase64(value.entity.canonical),
    }),
    confidence: value.confidence as EvidenceRecord["confidence"],
    disposition: value.disposition as EvidenceRecord["disposition"],
    observedAtNanoseconds: boundedDecimal(value.observedAtNanoseconds, false),
    ...(value.expiresAtNanoseconds === undefined
      ? {}
      : {
          expiresAtNanoseconds: boundedDecimal(
            value.expiresAtNanoseconds,
            false,
          ),
        }),
    ...(value.wallTimeMilliseconds === undefined
      ? {}
      : {
          wallTimeMilliseconds: boundedDecimal(
            value.wallTimeMilliseconds,
            true,
          ),
        }),
    fields: Object.freeze(
      fields.map((field) => {
        if (!record(field))
          throw new TypeError("sensor evidence field is invalid");
        return Object.freeze({
          key: field.key as string,
          value: decodeBase64(field.value),
        });
      }),
    ),
    relations: Object.freeze(
      relations.map((relation) => {
        if (!record(relation) || !record(relation.target))
          throw new TypeError("sensor evidence relation is invalid");
        return Object.freeze({
          kind: relation.kind as EvidenceRecord["relations"][number]["kind"],
          target: Object.freeze({
            kind: relation.target.kind as EvidenceRecord["entity"]["kind"],
            canonical: decodeBase64(relation.target.canonical),
          }),
        });
      }),
    ),
  });
}

function sorted(values: ReadonlySet<string>): readonly string[] {
  return Object.freeze([...values].sort());
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function bytesEqual(left: Uint8Array | undefined, right: Uint8Array): boolean {
  return (
    left?.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index])
  );
}

function decodeBase64(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length > 21_848 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  )
    throw new TypeError("sensor evidence base64 is invalid");
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value)
    throw new TypeError("sensor evidence base64 is non-canonical");
  return Uint8Array.from(decoded);
}

function boundedDecimal(value: unknown, signed: boolean): bigint {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 40 ||
    !(signed ? /^-?(?:0|[1-9]\d*)$/ : /^(?:0|[1-9]\d*)$/).test(value)
  )
    throw new TypeError("sensor integer is invalid");
  return BigInt(value);
}
