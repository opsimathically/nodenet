import { isIPv4 } from "node:net";

export const MAX_INTERNET_CHECKSUM_LENGTH = 65_535;
export const MAX_ICMPV4_MESSAGE_LENGTH = 65_515;
const ICMP_COMMON_HEADER_LENGTH = 4;
const ICMP_ECHO_HEADER_LENGTH = 8;
const IPV4_MINIMUM_HEADER_LENGTH = 20;

export const ICMP_ECHOREPLY = 0;
export const ICMP_DEST_UNREACH = 3;
export const ICMP_REDIRECT = 5;
export const ICMP_ECHO = 8;
export const ICMP_ROUTERADVERT = 9;
export const ICMP_ROUTERSOLICIT = 10;
export const ICMP_TIME_EXCEEDED = 11;
export const ICMP_PARAMETERPROB = 12;
export const ICMP_TIMESTAMP = 13;
export const ICMP_TIMESTAMPREPLY = 14;
export const ICMP_ADDRESS = 17;
export const ICMP_ADDRESSREPLY = 18;

export const ICMP_NET_UNREACH = 0;
export const ICMP_HOST_UNREACH = 1;
export const ICMP_PROT_UNREACH = 2;
export const ICMP_PORT_UNREACH = 3;
export const ICMP_FRAG_NEEDED = 4;
export const ICMP_SR_FAILED = 5;
export const ICMP_NET_UNKNOWN = 6;
export const ICMP_HOST_UNKNOWN = 7;
export const ICMP_HOST_ISOLATED = 8;
export const ICMP_NET_ANO = 9;
export const ICMP_HOST_ANO = 10;
export const ICMP_NET_UNR_TOS = 11;
export const ICMP_HOST_UNR_TOS = 12;
export const ICMP_PKT_FILTERED = 13;
export const ICMP_PREC_VIOLATION = 14;
export const ICMP_PREC_CUTOFF = 15;

export const ICMP_REDIR_NET = 0;
export const ICMP_REDIR_HOST = 1;
export const ICMP_REDIR_NETTOS = 2;
export const ICMP_REDIR_HOSTTOS = 3;

export const ICMP_EXC_TTL = 0;
export const ICMP_EXC_FRAGTIME = 1;

export const ICMP_PARAMPROB_POINTER = 0;
export const ICMP_PARAMPROB_MISSING_OPTION = 1;
export const ICMP_PARAMPROB_BAD_LENGTH = 2;
export const ICMP_PARAMPROB_ERRATPTR = ICMP_PARAMPROB_POINTER;
export const ICMP_PARAMPROB_OPTABSENT = ICMP_PARAMPROB_MISSING_OPTION;
export const ICMP_PARAMPROB_LENGTH = ICMP_PARAMPROB_BAD_LENGTH;

export type IcmpChecksumPolicy = "require" | "report" | "ignore";
export type IcmpConformance = "compatible" | "canonical";
export type IcmpChecksumStatus =
  "valid" | "invalid" | "unverifiable" | "notChecked";

export interface IcmpParseOptions {
  readonly checksum?: IcmpChecksumPolicy;
  readonly conformance?: IcmpConformance;
}

export interface NormalizedIcmpParseOptions {
  readonly checksum: IcmpChecksumPolicy;
  readonly conformance: IcmpConformance;
}

export interface IcmpValidationIssue {
  readonly code: string;
  readonly severity: "error" | "warning";
  readonly offset?: number;
  readonly message: string;
}

export type IcmpParseFailureReason =
  | "truncated"
  | "invalidLength"
  | "invalidChecksum"
  | "unsupportedStructure"
  | "invalidIpv4Header"
  | "metadataMismatch";

export interface IcmpParseFailure {
  readonly reason: IcmpParseFailureReason;
  readonly message: string;
  readonly offset: number;
  readonly requiredLength?: number;
  readonly availableLength?: number;
}

export interface IcmpEchoRequest {
  readonly kind: "echoRequest";
  readonly identifier: number;
  readonly sequence: number;
  readonly data?: Uint8Array;
}

export interface IcmpEchoReply {
  readonly kind: "echoReply";
  readonly identifier: number;
  readonly sequence: number;
  readonly data?: Uint8Array;
}

export type IcmpMessage = IcmpEchoRequest | IcmpEchoReply;

export interface ParsedIcmpEchoRequest {
  readonly kind: "echoRequest";
  readonly identifier: number;
  readonly sequence: number;
  readonly data: Buffer;
}

export interface ParsedIcmpEchoReply {
  readonly kind: "echoReply";
  readonly identifier: number;
  readonly sequence: number;
  readonly data: Buffer;
}

export interface ParsedUnknownIcmpMessage {
  readonly kind: "unknown";
  readonly body: Buffer;
}

export interface ParsedUnknownCodeIcmpMessage {
  readonly kind: "unknownCode";
  readonly knownType: number;
  readonly body: Buffer;
}

export type ParsedIcmpMessage =
  | ParsedIcmpEchoRequest
  | ParsedIcmpEchoReply
  | ParsedUnknownIcmpMessage
  | ParsedUnknownCodeIcmpMessage;

export interface ParsedIcmpPacket {
  readonly type: number;
  readonly code: number;
  readonly checksum: number;
  readonly checksumStatus: IcmpChecksumStatus;
  readonly incomplete: boolean;
  readonly issues: readonly IcmpValidationIssue[];
  readonly message: ParsedIcmpMessage;
}

export type IcmpParseResult =
  | { readonly ok: true; readonly packet: ParsedIcmpPacket }
  | {
      readonly ok: false;
      readonly error: IcmpParseFailure;
      readonly checksumStatus: IcmpChecksumStatus;
      readonly issues: readonly IcmpValidationIssue[];
    };

export interface IcmpValidationResult {
  readonly valid: boolean;
  readonly checksumStatus: IcmpChecksumStatus;
  readonly issues: readonly IcmpValidationIssue[];
  readonly packet?: ParsedIcmpPacket;
  readonly error?: IcmpParseFailure;
}

export interface ParsedIpv4Header {
  readonly sourceAddress: string;
  readonly destinationAddress: string;
  readonly protocol: number;
  readonly ttl: number;
  readonly typeOfService: number;
  readonly headerLength: number;
  readonly totalLength: number;
  readonly identification: number;
  readonly fragmentOffset: number;
  readonly dontFragment: boolean;
  readonly moreFragments: boolean;
  readonly checksum: number;
  readonly checksumStatus: "valid" | "invalid";
}

export interface Ipv4MetadataForIcmp {
  readonly destinationAddress: string;
  readonly protocol: number;
  readonly ttl: number;
  readonly typeOfService: number;
  readonly headerLength: number;
  readonly totalLength: number;
  readonly identification: number;
  readonly fragmentOffset: number;
  readonly dontFragment: boolean;
  readonly moreFragments: boolean;
}

export type IcmpIpv4FrameParseResult =
  | {
      readonly ok: true;
      readonly ipv4: ParsedIpv4Header;
      readonly packet: ParsedIcmpPacket;
      readonly incomplete: boolean;
    }
  | {
      readonly ok: false;
      readonly error: IcmpParseFailure;
      readonly checksumStatus: IcmpChecksumStatus;
      readonly issues: readonly IcmpValidationIssue[];
      readonly ipv4?: ParsedIpv4Header;
    };

export class IcmpInputError extends Error {
  override readonly name = "IcmpInputError";
}

export function normalizeIcmpParseOptions(
  options: unknown,
): NormalizedIcmpParseOptions {
  if (options === undefined) {
    return { checksum: "require", conformance: "compatible" };
  }
  const rawOptions: unknown = options;
  if (typeof rawOptions !== "object" || rawOptions === null) {
    throw new IcmpInputError("options must be an object");
  }
  const candidate = rawOptions as Record<string, unknown>;
  const checksum = candidate.checksum ?? "require";
  if (
    checksum !== "require" &&
    checksum !== "report" &&
    checksum !== "ignore"
  ) {
    throw new IcmpInputError("checksum must be require, report, or ignore");
  }
  const conformance = candidate.conformance ?? "compatible";
  if (conformance !== "compatible" && conformance !== "canonical") {
    throw new IcmpInputError("conformance must be compatible or canonical");
  }
  return { checksum, conformance };
}

export function computeInternetChecksumInternal(data: Uint8Array): number {
  validateByteInput(data, MAX_INTERNET_CHECKSUM_LENGTH, "data");
  return checksumSnapshot(Buffer.from(data));
}

export function validateInternetChecksumInternal(data: Uint8Array): boolean {
  return computeInternetChecksumInternal(data) === 0;
}

export function encodeIcmpMessageInternal(message: IcmpMessage): Buffer {
  const rawMessage: unknown = message;
  if (typeof rawMessage !== "object" || rawMessage === null) {
    throw new IcmpInputError("message must be an object");
  }
  const candidate = rawMessage as Record<string, unknown>;
  const kind = candidate.kind;
  if (kind !== "echoRequest" && kind !== "echoReply") {
    throw new IcmpInputError("message.kind must be echoRequest or echoReply");
  }
  const identifier = candidate.identifier;
  const sequence = candidate.sequence;
  validateUnsignedInteger(identifier, 0xffff, "message.identifier");
  validateUnsignedInteger(sequence, 0xffff, "message.sequence");
  const data: unknown = candidate.data ?? new Uint8Array();
  validateByteInput(
    data,
    MAX_ICMPV4_MESSAGE_LENGTH - ICMP_ECHO_HEADER_LENGTH,
    "message.data",
  );
  const ownedData = Buffer.from(data);
  const output = Buffer.alloc(ICMP_ECHO_HEADER_LENGTH + ownedData.byteLength);
  output[0] = kind === "echoRequest" ? ICMP_ECHO : ICMP_ECHOREPLY;
  output[1] = 0;
  output.writeUInt16BE(identifier, 4);
  output.writeUInt16BE(sequence, 6);
  ownedData.copy(output, ICMP_ECHO_HEADER_LENGTH);
  output.writeUInt16BE(checksumSnapshot(output), 2);
  return output;
}

export function parseIcmpMessageInternal(
  data: Uint8Array,
  options: NormalizedIcmpParseOptions,
): IcmpParseResult {
  if (!(data instanceof Uint8Array)) {
    throw new IcmpInputError("data must be a Uint8Array");
  }
  if (data.byteLength > MAX_ICMPV4_MESSAGE_LENGTH) {
    return parseFailure(
      "invalidLength",
      `ICMPv4 message must not exceed ${String(MAX_ICMPV4_MESSAGE_LENGTH)} bytes`,
      MAX_ICMPV4_MESSAGE_LENGTH,
      undefined,
      data.byteLength,
      "unverifiable",
    );
  }
  return parseIcmpSnapshot(Buffer.from(data), options, true);
}

export function validateIcmpMessageInternal(
  data: Uint8Array,
  options: NormalizedIcmpParseOptions,
): IcmpValidationResult {
  const result = parseIcmpMessageInternal(data, options);
  if (!result.ok) {
    return {
      valid: false,
      checksumStatus: result.checksumStatus,
      issues: result.issues,
      error: result.error,
    };
  }
  const hasErrorIssue = result.packet.issues.some(
    (issue) => issue.severity === "error",
  );
  const checksumSatisfied =
    result.packet.checksumStatus === "valid" ||
    result.packet.checksumStatus === "notChecked";
  return {
    valid: !hasErrorIssue && checksumSatisfied,
    checksumStatus: result.packet.checksumStatus,
    issues: result.packet.issues,
    packet: result.packet,
  };
}

export function parseIcmpIpv4FrameInternal(
  data: Uint8Array,
  dataLength: number,
  dataTruncated: boolean,
  metadata: Ipv4MetadataForIcmp,
  sourceAddress: string | undefined,
  options: NormalizedIcmpParseOptions,
): IcmpIpv4FrameParseResult {
  if (!(data instanceof Uint8Array)) {
    throw new IcmpInputError("message.data must be a Uint8Array");
  }
  if (data.byteLength > MAX_INTERNET_CHECKSUM_LENGTH) {
    return frameFailure(
      "invalidLength",
      "received IPv4 data exceeds 65535 bytes",
      MAX_INTERNET_CHECKSUM_LENGTH,
      undefined,
      data.byteLength,
    );
  }
  const snapshot = Buffer.from(data);
  if (snapshot.byteLength < IPV4_MINIMUM_HEADER_LENGTH) {
    return frameFailure(
      "truncated",
      "received data does not contain a complete minimum IPv4 header",
      0,
      IPV4_MINIMUM_HEADER_LENGTH,
      snapshot.byteLength,
    );
  }
  if (snapshot[0] === undefined || snapshot[0] >> 4 !== 4) {
    return frameFailure(
      "invalidIpv4Header",
      "received data is not an IPv4 packet",
      0,
    );
  }
  const headerLength = (snapshot[0] & 0x0f) * 4;
  if (
    headerLength < IPV4_MINIMUM_HEADER_LENGTH ||
    headerLength > snapshot.byteLength
  ) {
    return frameFailure(
      "invalidIpv4Header",
      "IPv4 header length is outside the captured data",
      0,
      headerLength,
      snapshot.byteLength,
    );
  }
  const totalLength = snapshot.readUInt16BE(2);
  if (totalLength < headerLength) {
    return frameFailure(
      "invalidIpv4Header",
      "IPv4 total length is smaller than its header length",
      2,
      headerLength,
      totalLength,
    );
  }
  const fragment = snapshot.readUInt16BE(6);
  const ipv4: ParsedIpv4Header = {
    sourceAddress: formatIpv4(snapshot, 12),
    destinationAddress: formatIpv4(snapshot, 16),
    protocol: snapshot[9] ?? 0,
    ttl: snapshot[8] ?? 0,
    typeOfService: snapshot[1] ?? 0,
    headerLength,
    totalLength,
    identification: snapshot.readUInt16BE(4),
    fragmentOffset: fragment & 0x1fff,
    dontFragment: (fragment & 0x4000) !== 0,
    moreFragments: (fragment & 0x2000) !== 0,
    checksum: snapshot.readUInt16BE(10),
    checksumStatus:
      checksumSnapshot(snapshot.subarray(0, headerLength)) === 0
        ? "valid"
        : "invalid",
  };
  if (ipv4.checksumStatus === "invalid") {
    return frameFailure(
      "invalidIpv4Header",
      "IPv4 header checksum is invalid",
      10,
      undefined,
      undefined,
      ipv4,
    );
  }
  if (ipv4.protocol !== 1) {
    return frameFailure(
      "unsupportedStructure",
      "received IPv4 packet protocol is not ICMP",
      9,
      undefined,
      ipv4.protocol,
      ipv4,
    );
  }
  const metadataMismatch = compareIpv4Metadata(ipv4, metadata, sourceAddress);
  if (metadataMismatch !== undefined) {
    return frameFailure(
      "metadataMismatch",
      metadataMismatch,
      0,
      undefined,
      undefined,
      ipv4,
    );
  }
  if (dataLength !== totalLength) {
    return frameFailure(
      "metadataMismatch",
      "received dataLength does not match the IPv4 total length",
      2,
      totalLength,
      dataLength,
      ipv4,
    );
  }
  if (snapshot.byteLength > totalLength) {
    return frameFailure(
      "metadataMismatch",
      "captured data extends beyond the IPv4 total length",
      totalLength,
      totalLength,
      snapshot.byteLength,
      ipv4,
    );
  }
  const actuallyTruncated = snapshot.byteLength < totalLength;
  if (dataTruncated !== actuallyTruncated) {
    return frameFailure(
      "metadataMismatch",
      "dataTruncated is inconsistent with the IPv4 total length",
      snapshot.byteLength,
      totalLength,
      snapshot.byteLength,
      ipv4,
    );
  }
  if (ipv4.fragmentOffset !== 0) {
    return frameFailure(
      "unsupportedStructure",
      "a non-initial IPv4 fragment does not begin with an ICMP header",
      6,
      undefined,
      ipv4.fragmentOffset,
      ipv4,
    );
  }

  const incomplete = actuallyTruncated || ipv4.moreFragments;
  const icmpBytes = snapshot.subarray(headerLength);
  const parsed = parseIcmpSnapshot(icmpBytes, options, !incomplete);
  if (!parsed.ok) {
    return {
      ok: false,
      error: parsed.error,
      checksumStatus: parsed.checksumStatus,
      issues: parsed.issues,
      ipv4,
    };
  }
  return { ok: true, ipv4, packet: parsed.packet, incomplete };
}

function parseIcmpSnapshot(
  snapshot: Buffer,
  options: NormalizedIcmpParseOptions,
  complete: boolean,
): IcmpParseResult {
  if (snapshot.byteLength < ICMP_COMMON_HEADER_LENGTH) {
    return parseFailure(
      "truncated",
      "ICMP message does not contain its complete common header",
      0,
      ICMP_COMMON_HEADER_LENGTH,
      snapshot.byteLength,
      "unverifiable",
    );
  }
  const checksum = snapshot.readUInt16BE(2);
  const checksumStatus: IcmpChecksumStatus = !complete
    ? "unverifiable"
    : options.checksum === "ignore"
      ? "notChecked"
      : checksumSnapshot(snapshot) === 0
        ? "valid"
        : "invalid";
  if (options.checksum === "require" && checksumStatus === "invalid") {
    return parseFailure(
      "invalidChecksum",
      "ICMP checksum is invalid",
      2,
      undefined,
      undefined,
      checksumStatus,
    );
  }

  const type = snapshot[0] ?? 0;
  const code = snapshot[1] ?? 0;
  const issues: IcmpValidationIssue[] = [];
  const isEcho = type === ICMP_ECHO || type === ICMP_ECHOREPLY;
  if (isEcho && code !== 0) {
    issues.push(
      issue(
        "unexpectedCode",
        options.conformance,
        1,
        `ICMP Echo type ${String(type)} requires code zero`,
      ),
    );
    return {
      ok: true,
      packet: {
        type,
        code,
        checksum,
        checksumStatus,
        incomplete: !complete,
        issues,
        message: {
          kind: "unknownCode",
          knownType: type,
          body: Buffer.from(snapshot.subarray(ICMP_COMMON_HEADER_LENGTH)),
        },
      },
    };
  }
  if (isEcho) {
    if (snapshot.byteLength < ICMP_ECHO_HEADER_LENGTH) {
      return parseFailure(
        "truncated",
        "ICMP Echo message does not contain its complete fixed header",
        ICMP_COMMON_HEADER_LENGTH,
        ICMP_ECHO_HEADER_LENGTH,
        snapshot.byteLength,
        checksumStatus,
        issues,
      );
    }
    return {
      ok: true,
      packet: {
        type,
        code,
        checksum,
        checksumStatus,
        incomplete: !complete,
        issues,
        message: {
          kind: type === ICMP_ECHO ? "echoRequest" : "echoReply",
          identifier: snapshot.readUInt16BE(4),
          sequence: snapshot.readUInt16BE(6),
          data: Buffer.from(snapshot.subarray(ICMP_ECHO_HEADER_LENGTH)),
        },
      },
    };
  }

  issues.push(
    issue(
      "unsupportedType",
      options.conformance,
      0,
      `ICMP type ${String(type)} is not implemented by this codec phase`,
    ),
  );
  return {
    ok: true,
    packet: {
      type,
      code,
      checksum,
      checksumStatus,
      incomplete: !complete,
      issues,
      message: {
        kind: "unknown",
        body: Buffer.from(snapshot.subarray(ICMP_COMMON_HEADER_LENGTH)),
      },
    },
  };
}

function checksumSnapshot(data: Uint8Array): number {
  let sum = 0;
  let offset = 0;
  while (offset + 1 < data.byteLength) {
    sum += ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
    sum = (sum & 0xffff) + Math.floor(sum / 0x1_0000);
    offset += 2;
  }
  if (offset < data.byteLength) {
    sum += (data[offset] ?? 0) << 8;
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + Math.floor(sum / 0x1_0000);
  }
  return 0xffff - sum;
}

function issue(
  code: string,
  conformance: IcmpConformance,
  offset: number,
  message: string,
): IcmpValidationIssue {
  return {
    code,
    severity: conformance === "canonical" ? "error" : "warning",
    offset,
    message,
  };
}

function parseFailure(
  reason: IcmpParseFailureReason,
  message: string,
  offset: number,
  requiredLength: number | undefined,
  availableLength: number | undefined,
  checksumStatus: IcmpChecksumStatus,
  issues: readonly IcmpValidationIssue[] = [],
): IcmpParseResult {
  const error = failure(
    reason,
    message,
    offset,
    requiredLength,
    availableLength,
  );
  return { ok: false, error, checksumStatus, issues };
}

function frameFailure(
  reason: IcmpParseFailureReason,
  message: string,
  offset: number,
  requiredLength?: number,
  availableLength?: number,
  ipv4?: ParsedIpv4Header,
): IcmpIpv4FrameParseResult {
  const error = failure(
    reason,
    message,
    offset,
    requiredLength,
    availableLength,
  );
  const result = {
    ok: false as const,
    error,
    checksumStatus: "unverifiable" as const,
    issues: [] as readonly IcmpValidationIssue[],
  };
  return ipv4 === undefined ? result : { ...result, ipv4 };
}

function failure(
  reason: IcmpParseFailureReason,
  message: string,
  offset: number,
  requiredLength?: number,
  availableLength?: number,
): IcmpParseFailure {
  return {
    reason,
    message,
    offset,
    ...(requiredLength === undefined ? {} : { requiredLength }),
    ...(availableLength === undefined ? {} : { availableLength }),
  };
}

function validateByteInput(
  data: unknown,
  maximumLength: number,
  name: string,
): asserts data is Uint8Array {
  if (!(data instanceof Uint8Array)) {
    throw new IcmpInputError(`${name} must be a Uint8Array`);
  }
  if (data.byteLength > maximumLength) {
    throw new IcmpInputError(
      `${name}.byteLength must not exceed ${String(maximumLength)}`,
    );
  }
}

function validateUnsignedInteger(
  value: unknown,
  maximum: number,
  name: string,
): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new IcmpInputError(
      `${name} must be an integer from 0 to ${String(maximum)}`,
    );
  }
}

function formatIpv4(data: Uint8Array, offset: number): string {
  return [
    data[offset] ?? 0,
    data[offset + 1] ?? 0,
    data[offset + 2] ?? 0,
    data[offset + 3] ?? 0,
  ].join(".");
}

function compareIpv4Metadata(
  parsed: ParsedIpv4Header,
  metadata: Ipv4MetadataForIcmp,
  sourceAddress: string | undefined,
): string | undefined {
  if (!isIPv4(metadata.destinationAddress)) {
    return "native IPv4 destination metadata is invalid";
  }
  const comparisons: readonly (readonly [
    keyof Ipv4MetadataForIcmp,
    number | string | boolean,
  ])[] = [
    ["destinationAddress", parsed.destinationAddress],
    ["protocol", parsed.protocol],
    ["ttl", parsed.ttl],
    ["typeOfService", parsed.typeOfService],
    ["headerLength", parsed.headerLength],
    ["totalLength", parsed.totalLength],
    ["identification", parsed.identification],
    ["fragmentOffset", parsed.fragmentOffset],
    ["dontFragment", parsed.dontFragment],
    ["moreFragments", parsed.moreFragments],
  ];
  for (const [key, expected] of comparisons) {
    if (metadata[key] !== expected) {
      return `native IPv4 ${key} metadata does not match received bytes`;
    }
  }
  if (sourceAddress !== undefined) {
    if (!isIPv4(sourceAddress)) {
      return "received IPv4 source address is invalid";
    }
    if (sourceAddress !== parsed.sourceAddress) {
      return "received IPv4 source address does not match the IPv4 header";
    }
  }
  return undefined;
}
