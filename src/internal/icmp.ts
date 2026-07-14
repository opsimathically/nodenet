import { isIPv4 } from "node:net";

export const MAX_INTERNET_CHECKSUM_LENGTH = 65_535;
export const MAX_ICMPV4_MESSAGE_LENGTH = 65_515;
const ICMP_COMMON_HEADER_LENGTH = 4;
const ICMP_ECHO_HEADER_LENGTH = 8;
const ICMP_ERROR_HEADER_LENGTH = 8;
const ICMP_ROUTER_DISCOVERY_HEADER_LENGTH = 8;
const ICMP_ROUTER_ADVERTISEMENT_ENTRY_LENGTH = 8;
const ICMP_TIMESTAMP_LENGTH = 20;
const ICMP_ADDRESS_MASK_LENGTH = 12;
const IPV4_MINIMUM_HEADER_LENGTH = 20;
const RFC4884_MINIMUM_QUOTE_LENGTH = 128;
const RFC4884_MAXIMUM_MESSAGE_LENGTH = 576;
const RFC4884_EXTENSION_HEADER_LENGTH = 4;
const RFC4884_OBJECT_HEADER_LENGTH = 4;
const typedArrayByteLengthGetter = (() => {
  const descriptor = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype) as object,
    "byteLength",
  );
  if (descriptor?.get === undefined) {
    throw new Error("Uint8Array byteLength intrinsic is unavailable");
  }
  // The accessor is deliberately invoked below with an explicit typed-array receiver.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const getter = descriptor.get;
  return (value: Uint8Array): number =>
    Reflect.apply(getter, value, []) as number;
})();

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
  readonly legacyExtensions?: boolean;
}

export interface NormalizedIcmpParseOptions {
  readonly checksum: IcmpChecksumPolicy;
  readonly conformance: IcmpConformance;
  readonly legacyExtensions: boolean;
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

export type IcmpDestinationUnreachableCode =
  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15;
export type IcmpTimeExceededCode = 0 | 1;
export type IcmpParameterProblemCode = 0 | 1 | 2;
export type IcmpRedirectCode = 0 | 1 | 2 | 3;

export interface IcmpExtensionObject {
  readonly classNumber: number;
  readonly cType: number;
  /** Object payload; its length must be a multiple of four octets. */
  readonly data?: Uint8Array;
}

export interface IcmpDestinationUnreachable {
  readonly kind: "destinationUnreachable";
  readonly code: IcmpDestinationUnreachableCode;
  readonly quote: Uint8Array;
  /** Valid only for code 4; zero explicitly means not supplied. */
  readonly nextHopMtu?: number;
  readonly extensions?: readonly IcmpExtensionObject[];
}

export interface IcmpTimeExceeded {
  readonly kind: "timeExceeded";
  readonly code: IcmpTimeExceededCode;
  readonly quote: Uint8Array;
  readonly extensions?: readonly IcmpExtensionObject[];
}

export interface IcmpParameterProblem {
  readonly kind: "parameterProblem";
  readonly code: IcmpParameterProblemCode;
  readonly pointer: number;
  readonly quote: Uint8Array;
  readonly extensions?: readonly IcmpExtensionObject[];
}

export interface IcmpRedirect {
  readonly kind: "redirect";
  readonly code: IcmpRedirectCode;
  readonly gatewayAddress: string;
  readonly quote: Uint8Array;
}

export interface IcmpRouterSolicitation {
  readonly kind: "routerSolicitation";
}

export interface IcmpRouterAdvertisementEntry {
  readonly address: string;
  readonly preference: number;
}

export interface IcmpRouterAdvertisement {
  readonly kind: "routerAdvertisement";
  readonly lifetime: number;
  readonly addresses: readonly IcmpRouterAdvertisementEntry[];
}

export interface IcmpTimestampRequest {
  readonly kind: "timestampRequest";
  readonly identifier: number;
  readonly sequence: number;
  readonly originateTimestamp: number;
}

export interface IcmpTimestampReply {
  readonly kind: "timestampReply";
  readonly identifier: number;
  readonly sequence: number;
  readonly originateTimestamp: number;
  readonly receiveTimestamp: number;
  readonly transmitTimestamp: number;
}

export interface IcmpTimestampReplyTimes {
  readonly receiveTimestamp: number;
  readonly transmitTimestamp: number;
}

export interface IcmpAddressMaskRequest {
  readonly kind: "addressMaskRequest";
  readonly identifier: number;
  readonly sequence: number;
}

export interface IcmpAddressMaskReply {
  readonly kind: "addressMaskReply";
  readonly identifier: number;
  readonly sequence: number;
  readonly mask: string;
}

export type IcmpMessage =
  | IcmpEchoRequest
  | IcmpEchoReply
  | IcmpDestinationUnreachable
  | IcmpTimeExceeded
  | IcmpParameterProblem
  | IcmpRedirect
  | IcmpRouterSolicitation
  | IcmpRouterAdvertisement
  | IcmpTimestampRequest
  | IcmpTimestampReply
  | IcmpAddressMaskRequest
  | IcmpAddressMaskReply;

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

export interface ParsedQuotedIcmpPrefix {
  readonly type: number;
  readonly code: number | undefined;
  readonly fixedHeaderComplete: boolean;
  readonly identifier: number | undefined;
  readonly sequence: number | undefined;
  readonly dataPrefix: Buffer;
}

export interface ParsedIcmpQuote {
  readonly bytes: Buffer;
  readonly valid: boolean;
  readonly incomplete: boolean;
  readonly minimumComplete: boolean;
  readonly datagramComplete: boolean;
  readonly requiredMinimumLength: number | undefined;
  readonly ipv4: ParsedIpv4Header | undefined;
  readonly icmp: ParsedQuotedIcmpPrefix | undefined;
  readonly issues: readonly IcmpValidationIssue[];
}

export type IcmpExtensionChecksumStatus = "valid" | "invalid" | "notProvided";

export interface ParsedIcmpExtensionObject {
  readonly length: number;
  readonly classNumber: number;
  readonly cType: number;
  readonly data: Buffer;
}

export interface ParsedIcmpExtensions {
  readonly framing: "rfc4884" | "legacy";
  readonly quoteLengthWords: number;
  readonly paddedQuoteLength: number;
  readonly version: number;
  readonly reserved: number;
  readonly checksum: number;
  readonly checksumStatus: IcmpExtensionChecksumStatus;
  readonly objects: readonly ParsedIcmpExtensionObject[];
  readonly raw: Buffer;
}

interface ParsedIcmpErrorBase {
  readonly quoteLengthWords: number;
  readonly quote: ParsedIcmpQuote;
  readonly extensions: ParsedIcmpExtensions | undefined;
}

export interface ParsedIcmpDestinationUnreachable extends ParsedIcmpErrorBase {
  readonly kind: "destinationUnreachable";
  readonly code: IcmpDestinationUnreachableCode;
  readonly unused: number;
  readonly nextHopMtu: number | undefined;
  readonly unusedWord: number | undefined;
}

export interface ParsedIcmpTimeExceeded extends ParsedIcmpErrorBase {
  readonly kind: "timeExceeded";
  readonly code: IcmpTimeExceededCode;
  readonly unused: number;
  readonly unusedWord: number;
}

export interface ParsedIcmpParameterProblem extends ParsedIcmpErrorBase {
  readonly kind: "parameterProblem";
  readonly code: IcmpParameterProblemCode;
  readonly pointer: number;
  readonly unusedWord: number;
  readonly pointerPresent: boolean;
}

export interface ParsedIcmpRedirect {
  readonly kind: "redirect";
  readonly code: IcmpRedirectCode;
  readonly gatewayAddress: string;
  readonly quote: ParsedIcmpQuote;
}

export interface ParsedIcmpRouterSolicitation {
  readonly kind: "routerSolicitation";
  readonly reserved: number;
  readonly trailingData: Buffer;
}

export interface ParsedIcmpRouterAdvertisementEntry {
  readonly address: string;
  readonly preference: number;
  readonly defaultEligible: boolean;
  readonly extensionWords: readonly number[];
}

export interface ParsedIcmpRouterAdvertisement {
  readonly kind: "routerAdvertisement";
  readonly numberOfAddresses: number;
  readonly addressEntrySizeWords: number;
  readonly lifetime: number;
  readonly addresses: readonly ParsedIcmpRouterAdvertisementEntry[];
  readonly trailingData: Buffer;
}

export type IcmpTimestampClassification =
  "standard" | "nonStandard" | "invalidStandardRange";

export interface IcmpTimestampValue {
  readonly raw: number;
  readonly classification: IcmpTimestampClassification;
}

interface ParsedIcmpTimestampBase {
  readonly identifier: number;
  readonly sequence: number;
  readonly originateTimestamp: IcmpTimestampValue;
  readonly receiveTimestamp: IcmpTimestampValue;
  readonly transmitTimestamp: IcmpTimestampValue;
  readonly trailingData: Buffer;
}

export interface ParsedIcmpTimestampRequest extends ParsedIcmpTimestampBase {
  readonly kind: "timestampRequest";
}

export interface ParsedIcmpTimestampReply extends ParsedIcmpTimestampBase {
  readonly kind: "timestampReply";
}

export interface IcmpAddressMaskInfo {
  readonly address: string;
  readonly bytes: Buffer;
  readonly contiguous: boolean;
  readonly prefixLength: number | undefined;
}

interface ParsedIcmpAddressMaskBase {
  readonly identifier: number;
  readonly sequence: number;
  readonly mask: IcmpAddressMaskInfo;
  readonly trailingData: Buffer;
}

export interface ParsedIcmpAddressMaskRequest extends ParsedIcmpAddressMaskBase {
  readonly kind: "addressMaskRequest";
}

export interface ParsedIcmpAddressMaskReply extends ParsedIcmpAddressMaskBase {
  readonly kind: "addressMaskReply";
}

export type ParsedIcmpMessage =
  | ParsedIcmpEchoRequest
  | ParsedIcmpEchoReply
  | ParsedIcmpDestinationUnreachable
  | ParsedIcmpTimeExceeded
  | ParsedIcmpParameterProblem
  | ParsedIcmpRedirect
  | ParsedIcmpRouterSolicitation
  | ParsedIcmpRouterAdvertisement
  | ParsedIcmpTimestampRequest
  | ParsedIcmpTimestampReply
  | ParsedIcmpAddressMaskRequest
  | ParsedIcmpAddressMaskReply
  | ParsedUnknownIcmpMessage
  | ParsedUnknownCodeIcmpMessage;

export interface IcmpEchoQuoteMatchOptions {
  readonly expectedDestinationAddress: string;
  readonly identifier: number;
  readonly sequence: number;
  readonly token?: Uint8Array;
}

export type IcmpEchoQuoteMatchResult =
  | { readonly matched: false }
  | {
      readonly matched: true;
      readonly strength: "strong" | "weak";
      readonly tokenCompared: boolean;
    };

export type IcmpDestinationUnreachableCategory =
  | "network"
  | "host"
  | "protocol"
  | "port"
  | "fragmentationNeeded"
  | "sourceRouteFailed"
  | "administrativelyProhibited"
  | "other";

export interface IcmpDestinationUnreachableClassification {
  readonly category: IcmpDestinationUnreachableCategory;
  readonly terminal: boolean;
  readonly administrativelyProhibited: boolean;
}

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
    return {
      checksum: "require",
      conformance: "compatible",
      legacyExtensions: false,
    };
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
  const legacyExtensions = candidate.legacyExtensions ?? false;
  if (typeof legacyExtensions !== "boolean") {
    throw new IcmpInputError("legacyExtensions must be boolean");
  }
  return { checksum, conformance, legacyExtensions };
}

export function computeInternetChecksumInternal(data: Uint8Array): number {
  return checksumSnapshot(
    snapshotByteInputInternal(data, MAX_INTERNET_CHECKSUM_LENGTH, "data"),
  );
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
  if (
    kind !== "echoRequest" &&
    kind !== "echoReply" &&
    kind !== "destinationUnreachable" &&
    kind !== "timeExceeded" &&
    kind !== "parameterProblem" &&
    kind !== "redirect" &&
    kind !== "routerSolicitation" &&
    kind !== "routerAdvertisement" &&
    kind !== "timestampRequest" &&
    kind !== "timestampReply" &&
    kind !== "addressMaskRequest" &&
    kind !== "addressMaskReply"
  ) {
    throw new IcmpInputError(
      "message.kind must be a supported ICMPv4 message kind",
    );
  }
  if (
    kind === "destinationUnreachable" ||
    kind === "timeExceeded" ||
    kind === "parameterProblem" ||
    kind === "redirect"
  ) {
    return encodeIcmpErrorMessage(candidate, kind);
  }
  if (kind !== "echoRequest" && kind !== "echoReply") {
    return encodeIcmpInformationalMessage(candidate, kind);
  }
  const identifier = candidate.identifier;
  const sequence = candidate.sequence;
  validateUnsignedInteger(identifier, 0xffff, "message.identifier");
  validateUnsignedInteger(sequence, 0xffff, "message.sequence");
  const ownedData = snapshotByteInputInternal(
    candidate.data ?? new Uint8Array(),
    MAX_ICMPV4_MESSAGE_LENGTH - ICMP_ECHO_HEADER_LENGTH,
    "message.data",
  );
  const output = Buffer.alloc(ICMP_ECHO_HEADER_LENGTH + ownedData.byteLength);
  output[0] = kind === "echoRequest" ? ICMP_ECHO : ICMP_ECHOREPLY;
  output[1] = 0;
  output.writeUInt16BE(identifier, 4);
  output.writeUInt16BE(sequence, 6);
  ownedData.copy(output, ICMP_ECHO_HEADER_LENGTH);
  output.writeUInt16BE(checksumSnapshot(output), 2);
  return output;
}

function encodeIcmpInformationalMessage(
  candidate: Record<string, unknown>,
  kind:
    | "routerSolicitation"
    | "routerAdvertisement"
    | "timestampRequest"
    | "timestampReply"
    | "addressMaskRequest"
    | "addressMaskReply",
): Buffer {
  if (kind === "routerSolicitation") {
    if (
      candidate.reserved !== undefined ||
      candidate.trailingData !== undefined
    ) {
      throw new IcmpInputError(
        "Router Solicitation construction does not accept reserved or trailing data",
      );
    }
    const output = Buffer.alloc(ICMP_ROUTER_DISCOVERY_HEADER_LENGTH);
    output[0] = ICMP_ROUTERSOLICIT;
    output.writeUInt16BE(checksumSnapshot(output), 2);
    return output;
  }

  if (kind === "routerAdvertisement") {
    const lifetime = candidate.lifetime;
    validateUnsignedInteger(lifetime, 0xffff, "message.lifetime");
    const rawAddresses = candidate.addresses;
    if (!Array.isArray(rawAddresses)) {
      throw new IcmpInputError(
        "message.addresses must contain from 1 through 255 router entries",
      );
    }
    const count = rawAddresses.length;
    if (!Number.isSafeInteger(count) || count < 1 || count > 0xff) {
      throw new IcmpInputError(
        "message.addresses must contain from 1 through 255 router entries",
      );
    }
    const output = Buffer.alloc(
      ICMP_ROUTER_DISCOVERY_HEADER_LENGTH +
        count * ICMP_ROUTER_ADVERTISEMENT_ENTRY_LENGTH,
    );
    output[0] = ICMP_ROUTERADVERT;
    output[4] = count;
    output[5] = 2;
    output.writeUInt16BE(lifetime, 6);
    for (let index = 0; index < count; index += 1) {
      const rawEntry: unknown = rawAddresses[index];
      if (typeof rawEntry !== "object" || rawEntry === null) {
        throw new IcmpInputError(
          "each router advertisement entry must be an object",
        );
      }
      const entry = rawEntry as Record<string, unknown>;
      const address = entry.address;
      const preference = entry.preference;
      if (typeof address !== "string" || !isIPv4(address)) {
        throw new IcmpInputError(
          "router advertisement entry.address must be a dotted-decimal IPv4 address",
        );
      }
      validateSignedInteger(
        preference,
        "router advertisement entry.preference",
      );
      const offset =
        ICMP_ROUTER_DISCOVERY_HEADER_LENGTH +
        index * ICMP_ROUTER_ADVERTISEMENT_ENTRY_LENGTH;
      writeIpv4(output, offset, address);
      output.writeInt32BE(preference, offset + 4);
    }
    output.writeUInt16BE(checksumSnapshot(output), 2);
    return output;
  }

  if (kind === "timestampRequest" || kind === "timestampReply") {
    const identifier = candidate.identifier;
    const sequence = candidate.sequence;
    const originateTimestamp = candidate.originateTimestamp;
    validateUnsignedInteger(identifier, 0xffff, "message.identifier");
    validateUnsignedInteger(sequence, 0xffff, "message.sequence");
    validateCanonicalTimestamp(
      originateTimestamp,
      "message.originateTimestamp",
    );
    let receiveTimestamp = 0;
    let transmitTimestamp = 0;
    if (kind === "timestampRequest") {
      if (
        candidate.receiveTimestamp !== undefined ||
        candidate.transmitTimestamp !== undefined
      ) {
        throw new IcmpInputError(
          "Timestamp Request construction does not accept receive or transmit timestamps",
        );
      }
    } else {
      receiveTimestamp = candidate.receiveTimestamp as number;
      transmitTimestamp = candidate.transmitTimestamp as number;
      validateCanonicalTimestamp(receiveTimestamp, "message.receiveTimestamp");
      validateCanonicalTimestamp(
        transmitTimestamp,
        "message.transmitTimestamp",
      );
    }
    const output = Buffer.alloc(ICMP_TIMESTAMP_LENGTH);
    output[0] =
      kind === "timestampRequest" ? ICMP_TIMESTAMP : ICMP_TIMESTAMPREPLY;
    output.writeUInt16BE(identifier, 4);
    output.writeUInt16BE(sequence, 6);
    output.writeUInt32BE(originateTimestamp, 8);
    output.writeUInt32BE(receiveTimestamp, 12);
    output.writeUInt32BE(transmitTimestamp, 16);
    output.writeUInt16BE(checksumSnapshot(output), 2);
    return output;
  }

  const identifier = candidate.identifier;
  const sequence = candidate.sequence;
  validateUnsignedInteger(identifier, 0xffff, "message.identifier");
  validateUnsignedInteger(sequence, 0xffff, "message.sequence");
  const output = Buffer.alloc(ICMP_ADDRESS_MASK_LENGTH);
  output[0] = kind === "addressMaskRequest" ? ICMP_ADDRESS : ICMP_ADDRESSREPLY;
  output.writeUInt16BE(identifier, 4);
  output.writeUInt16BE(sequence, 6);
  if (kind === "addressMaskRequest") {
    if (candidate.mask !== undefined) {
      throw new IcmpInputError(
        "Address Mask Request construction does not accept a mask",
      );
    }
  } else {
    const mask = candidate.mask;
    if (typeof mask !== "string" || !isIPv4(mask)) {
      throw new IcmpInputError(
        "message.mask must be a dotted-decimal IPv4 mask",
      );
    }
    writeIpv4(output, 8, mask);
  }
  output.writeUInt16BE(checksumSnapshot(output), 2);
  return output;
}

function encodeIcmpErrorMessage(
  candidate: Record<string, unknown>,
  kind:
    "destinationUnreachable" | "timeExceeded" | "parameterProblem" | "redirect",
): Buffer {
  const rawCode = candidate.code;
  const maximumCode =
    kind === "destinationUnreachable"
      ? 15
      : kind === "redirect"
        ? 3
        : kind === "parameterProblem"
          ? 2
          : 1;
  validateUnsignedInteger(rawCode, maximumCode, "message.code");
  const quote = snapshotByteInputInternal(
    candidate.quote,
    RFC4884_MAXIMUM_MESSAGE_LENGTH - ICMP_ERROR_HEADER_LENGTH,
    "message.quote",
  );
  const quotedHeader = validateConstructedQuote(quote);

  if (kind === "redirect") {
    if (candidate.extensions !== undefined) {
      throw new IcmpInputError(
        "message.extensions are not supported for Redirect",
      );
    }
    const gatewayAddress = candidate.gatewayAddress;
    if (typeof gatewayAddress !== "string" || !isIPv4(gatewayAddress)) {
      throw new IcmpInputError(
        "message.gatewayAddress must be a dotted-decimal IPv4 address",
      );
    }
    const output = Buffer.alloc(ICMP_ERROR_HEADER_LENGTH + quote.byteLength);
    output[0] = ICMP_REDIRECT;
    output[1] = rawCode;
    writeIpv4(output, 4, gatewayAddress);
    quote.copy(output, ICMP_ERROR_HEADER_LENGTH);
    output.writeUInt16BE(checksumSnapshot(output), 2);
    return output;
  }

  const extensions = encodeIcmpExtensions(candidate.extensions);
  let quoteField = quote;
  let quoteLengthWords = 0;
  if (extensions !== undefined) {
    const minimumOriginalLength = Math.min(
      quotedHeader.totalLength,
      RFC4884_MINIMUM_QUOTE_LENGTH,
    );
    if (quote.byteLength < minimumOriginalLength) {
      throw new IcmpInputError(
        "message.quote must include at least 128 original octets when available before adding extensions",
      );
    }
    const paddedLength = roundUpToWord(
      Math.max(RFC4884_MINIMUM_QUOTE_LENGTH, quote.byteLength),
    );
    quoteLengthWords = paddedLength / 4;
    quoteField = Buffer.alloc(paddedLength);
    quote.copy(quoteField);
  }

  const totalLength =
    ICMP_ERROR_HEADER_LENGTH +
    quoteField.byteLength +
    (extensions?.byteLength ?? 0);
  if (totalLength > RFC4884_MAXIMUM_MESSAGE_LENGTH) {
    throw new IcmpInputError("encoded ICMPv4 error must not exceed 576 bytes");
  }
  const output = Buffer.alloc(totalLength);
  output[0] =
    kind === "destinationUnreachable"
      ? ICMP_DEST_UNREACH
      : kind === "timeExceeded"
        ? ICMP_TIME_EXCEEDED
        : ICMP_PARAMETERPROB;
  output[1] = rawCode;
  output[5] = quoteLengthWords;
  if (kind === "destinationUnreachable") {
    const rawMtu = candidate.nextHopMtu;
    if (rawCode === ICMP_FRAG_NEEDED) {
      const nextHopMtu = rawMtu ?? 0;
      validateUnsignedInteger(nextHopMtu, 0xffff, "message.nextHopMtu");
      output.writeUInt16BE(nextHopMtu, 6);
    } else if (rawMtu !== undefined) {
      throw new IcmpInputError(
        "message.nextHopMtu is valid only for Fragmentation Needed",
      );
    }
  } else if (kind === "parameterProblem") {
    const pointer = candidate.pointer;
    validateUnsignedInteger(pointer, 0xff, "message.pointer");
    output[4] = pointer;
  }
  quoteField.copy(output, ICMP_ERROR_HEADER_LENGTH);
  extensions?.copy(output, ICMP_ERROR_HEADER_LENGTH + quoteField.byteLength);
  output.writeUInt16BE(checksumSnapshot(output), 2);
  return output;
}

function validateConstructedQuote(quote: Buffer): ParsedIpv4Header {
  if (quote.byteLength < IPV4_MINIMUM_HEADER_LENGTH) {
    throw new IcmpInputError(
      "message.quote must contain a complete IPv4 header",
    );
  }
  if ((quote[0] ?? 0) >> 4 !== 4) {
    throw new IcmpInputError("message.quote must contain IPv4 version 4");
  }
  const headerLength = ((quote[0] ?? 0) & 0x0f) * 4;
  if (
    headerLength < IPV4_MINIMUM_HEADER_LENGTH ||
    headerLength > 60 ||
    headerLength > quote.byteLength
  ) {
    throw new IcmpInputError("message.quote contains an invalid IPv4 IHL");
  }
  const totalLength = quote.readUInt16BE(2);
  if (totalLength < headerLength || quote.byteLength > totalLength) {
    throw new IcmpInputError(
      "message.quote must not extend beyond its valid IPv4 total length",
    );
  }
  if (checksumSnapshot(quote.subarray(0, headerLength)) !== 0) {
    throw new IcmpInputError(
      "message.quote must contain a valid IPv4 header checksum",
    );
  }
  const requiredMinimumLength = Math.min(totalLength, headerLength + 8);
  if (quote.byteLength < requiredMinimumLength) {
    throw new IcmpInputError(
      "message.quote must contain the IPv4 header and at least eight original payload octets when available",
    );
  }
  return parseIpv4HeaderSnapshot(quote, headerLength, totalLength);
}

function encodeIcmpExtensions(value: unknown): Buffer | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new IcmpInputError(
      "message.extensions must contain from 1 through 142 objects",
    );
  }
  const objectCount = value.length;
  if (
    !Number.isSafeInteger(objectCount) ||
    objectCount < 1 ||
    objectCount > 142
  ) {
    throw new IcmpInputError(
      "message.extensions must contain from 1 through 142 objects",
    );
  }
  const encodedObjects: Buffer[] = [];
  let totalLength = RFC4884_EXTENSION_HEADER_LENGTH;
  for (let index = 0; index < objectCount; index += 1) {
    const rawObject: unknown = value[index];
    if (typeof rawObject !== "object" || rawObject === null) {
      throw new IcmpInputError("each extension object must be an object");
    }
    const candidate = rawObject as Record<string, unknown>;
    const classNumber = candidate.classNumber;
    const cType = candidate.cType;
    const ownedData = snapshotByteInputInternal(
      candidate.data ?? new Uint8Array(),
      RFC4884_MAXIMUM_MESSAGE_LENGTH,
      "extension.data",
    );
    validateUnsignedInteger(classNumber, 0xff, "extension.classNumber");
    validateUnsignedInteger(cType, 0xff, "extension.cType");
    if (ownedData.byteLength % 4 !== 0) {
      throw new IcmpInputError(
        "extension.data.byteLength must be a multiple of four",
      );
    }
    const objectLength = RFC4884_OBJECT_HEADER_LENGTH + ownedData.byteLength;
    totalLength += objectLength;
    if (totalLength > RFC4884_MAXIMUM_MESSAGE_LENGTH) {
      throw new IcmpInputError("ICMP extension structure is too large");
    }
    const object = Buffer.alloc(objectLength);
    object.writeUInt16BE(objectLength, 0);
    object[2] = classNumber;
    object[3] = cType;
    ownedData.copy(object, RFC4884_OBJECT_HEADER_LENGTH);
    encodedObjects.push(object);
  }
  const output = Buffer.alloc(totalLength);
  output[0] = 0x20;
  let offset = RFC4884_EXTENSION_HEADER_LENGTH;
  for (const object of encodedObjects) {
    object.copy(output, offset);
    offset += object.byteLength;
  }
  const checksum = checksumSnapshot(output);
  output.writeUInt16BE(checksum === 0 ? 0xffff : checksum, 2);
  return output;
}

export function parseIcmpMessageInternal(
  data: Uint8Array,
  options: NormalizedIcmpParseOptions,
): IcmpParseResult {
  if (!(data instanceof Uint8Array)) {
    throw new IcmpInputError("data must be a Uint8Array");
  }
  const byteLength = intrinsicUint8ArrayByteLength(data, "data");
  if (byteLength > MAX_ICMPV4_MESSAGE_LENGTH) {
    return parseFailure(
      "invalidLength",
      `ICMPv4 message must not exceed ${String(MAX_ICMPV4_MESSAGE_LENGTH)} bytes`,
      MAX_ICMPV4_MESSAGE_LENGTH,
      undefined,
      byteLength,
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
  const byteLength = intrinsicUint8ArrayByteLength(data, "message.data");
  if (byteLength > MAX_INTERNET_CHECKSUM_LENGTH) {
    return frameFailure(
      "invalidLength",
      "received IPv4 data exceeds 65535 bytes",
      MAX_INTERNET_CHECKSUM_LENGTH,
      undefined,
      byteLength,
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

  const isPhase14Message =
    type === ICMP_ROUTERADVERT ||
    type === ICMP_ROUTERSOLICIT ||
    type === ICMP_TIMESTAMP ||
    type === ICMP_TIMESTAMPREPLY ||
    type === ICMP_ADDRESS ||
    type === ICMP_ADDRESSREPLY;
  if (isPhase14Message && code !== 0) {
    issues.push(
      issue(
        "unexpectedCode",
        options.conformance,
        1,
        `ICMP type ${String(type)} requires code zero`,
      ),
    );
    return successfulPacket(
      type,
      code,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: "unknownCode",
        knownType: type,
        body: Buffer.from(snapshot.subarray(ICMP_COMMON_HEADER_LENGTH)),
      },
    );
  }
  if (isPhase14Message) {
    return parseIcmpInformationalSnapshot(
      snapshot,
      type,
      checksum,
      checksumStatus,
      complete,
      options,
      issues,
    );
  }

  if (
    type === ICMP_DEST_UNREACH ||
    type === ICMP_TIME_EXCEEDED ||
    type === ICMP_PARAMETERPROB ||
    type === ICMP_REDIRECT
  ) {
    const maximumCode =
      type === ICMP_DEST_UNREACH
        ? 15
        : type === ICMP_REDIRECT
          ? 3
          : type === ICMP_PARAMETERPROB
            ? 2
            : 1;
    if (code > maximumCode) {
      issues.push(
        issue(
          "unexpectedCode",
          options.conformance,
          1,
          `ICMP type ${String(type)} does not define code ${String(code)}`,
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
    return parseIcmpErrorSnapshot(
      snapshot,
      type,
      code,
      checksum,
      checksumStatus,
      complete,
      options,
      issues,
    );
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

function parseIcmpInformationalSnapshot(
  snapshot: Buffer,
  type: number,
  checksum: number,
  checksumStatus: IcmpChecksumStatus,
  complete: boolean,
  options: NormalizedIcmpParseOptions,
  issues: IcmpValidationIssue[],
): IcmpParseResult {
  if (type === ICMP_ROUTERSOLICIT) {
    if (snapshot.byteLength < ICMP_ROUTER_DISCOVERY_HEADER_LENGTH) {
      return parseFailure(
        "truncated",
        "Router Solicitation does not contain its complete fixed header",
        ICMP_COMMON_HEADER_LENGTH,
        ICMP_ROUTER_DISCOVERY_HEADER_LENGTH,
        snapshot.byteLength,
        checksumStatus,
        issues,
      );
    }
    const reserved = snapshot.readUInt32BE(4);
    const trailingData = Buffer.from(
      snapshot.subarray(ICMP_ROUTER_DISCOVERY_HEADER_LENGTH),
    );
    if (reserved !== 0) {
      issues.push(
        issue(
          "nonzeroReservedField",
          options.conformance,
          4,
          "Router Solicitation reserved field is nonzero",
        ),
      );
    }
    if (trailingData.byteLength > 0) {
      issues.push(
        issue(
          "unexpectedTrailingData",
          options.conformance,
          ICMP_ROUTER_DISCOVERY_HEADER_LENGTH,
          "Router Solicitation contains ignored trailing data",
        ),
      );
    }
    return successfulPacket(
      type,
      0,
      checksum,
      checksumStatus,
      complete,
      issues,
      { kind: "routerSolicitation", reserved, trailingData },
    );
  }

  if (type === ICMP_ROUTERADVERT) {
    if (snapshot.byteLength < ICMP_ROUTER_DISCOVERY_HEADER_LENGTH) {
      return parseFailure(
        "truncated",
        "Router Advertisement does not contain its complete fixed header",
        ICMP_COMMON_HEADER_LENGTH,
        ICMP_ROUTER_DISCOVERY_HEADER_LENGTH,
        snapshot.byteLength,
        checksumStatus,
        issues,
      );
    }
    const numberOfAddresses = snapshot[4] ?? 0;
    const addressEntrySizeWords = snapshot[5] ?? 0;
    if (numberOfAddresses === 0) {
      return parseFailure(
        "unsupportedStructure",
        "Router Advertisement must contain at least one address",
        4,
        1,
        0,
        checksumStatus,
        issues,
      );
    }
    if (addressEntrySizeWords < 2) {
      return parseFailure(
        "unsupportedStructure",
        "Router Advertisement address entry size must be at least two words",
        5,
        2,
        addressEntrySizeWords,
        checksumStatus,
        issues,
      );
    }
    const entryLength = addressEntrySizeWords * 4;
    const requiredLength =
      ICMP_ROUTER_DISCOVERY_HEADER_LENGTH + numberOfAddresses * entryLength;
    if (snapshot.byteLength < requiredLength) {
      return parseFailure(
        "truncated",
        "Router Advertisement address entries are truncated",
        ICMP_ROUTER_DISCOVERY_HEADER_LENGTH,
        requiredLength,
        snapshot.byteLength,
        checksumStatus,
        issues,
      );
    }
    const addresses: ParsedIcmpRouterAdvertisementEntry[] = [];
    for (let index = 0; index < numberOfAddresses; index += 1) {
      const offset = ICMP_ROUTER_DISCOVERY_HEADER_LENGTH + index * entryLength;
      const preference = snapshot.readInt32BE(offset + 4);
      const extensionWords: number[] = [];
      for (let word = 2; word < addressEntrySizeWords; word += 1) {
        extensionWords.push(snapshot.readUInt32BE(offset + word * 4));
      }
      addresses.push({
        address: formatIpv4(snapshot, offset),
        preference,
        defaultEligible: preference !== -0x8000_0000,
        extensionWords,
      });
    }
    const trailingData = Buffer.from(snapshot.subarray(requiredLength));
    if (trailingData.byteLength > 0) {
      issues.push(
        issue(
          "unexpectedTrailingData",
          options.conformance,
          requiredLength,
          "Router Advertisement contains ignored trailing data",
        ),
      );
    }
    return successfulPacket(
      type,
      0,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: "routerAdvertisement",
        numberOfAddresses,
        addressEntrySizeWords,
        lifetime: snapshot.readUInt16BE(6),
        addresses,
        trailingData,
      },
    );
  }

  if (type === ICMP_TIMESTAMP || type === ICMP_TIMESTAMPREPLY) {
    if (snapshot.byteLength < ICMP_TIMESTAMP_LENGTH) {
      return parseFailure(
        "truncated",
        "ICMP Timestamp message does not contain its complete fixed fields",
        ICMP_COMMON_HEADER_LENGTH,
        ICMP_TIMESTAMP_LENGTH,
        snapshot.byteLength,
        checksumStatus,
        issues,
      );
    }
    const originateTimestamp = classifyTimestampRaw(snapshot.readUInt32BE(8));
    const receiveTimestamp = classifyTimestampRaw(snapshot.readUInt32BE(12));
    const transmitTimestamp = classifyTimestampRaw(snapshot.readUInt32BE(16));
    for (const [offset, label, value] of [
      [8, "originate", originateTimestamp],
      [12, "receive", receiveTimestamp],
      [16, "transmit", transmitTimestamp],
    ] as const) {
      if (value.classification === "invalidStandardRange") {
        issues.push(
          issue(
            "invalidStandardTimestampRange",
            options.conformance,
            offset,
            `${label} timestamp is above one day without the non-standard high bit`,
          ),
        );
      }
    }
    if (type === ICMP_TIMESTAMP && receiveTimestamp.raw !== 0) {
      issues.push(
        issue(
          "nonzeroRequestReplyField",
          options.conformance,
          12,
          "Timestamp Request receive timestamp is nonzero",
        ),
      );
    }
    if (type === ICMP_TIMESTAMP && transmitTimestamp.raw !== 0) {
      issues.push(
        issue(
          "nonzeroRequestReplyField",
          options.conformance,
          16,
          "Timestamp Request transmit timestamp is nonzero",
        ),
      );
    }
    const trailingData = Buffer.from(snapshot.subarray(ICMP_TIMESTAMP_LENGTH));
    if (trailingData.byteLength > 0) {
      issues.push(
        issue(
          "unexpectedTrailingData",
          options.conformance,
          ICMP_TIMESTAMP_LENGTH,
          "ICMP Timestamp message contains trailing data",
        ),
      );
    }
    return successfulPacket(
      type,
      0,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: type === ICMP_TIMESTAMP ? "timestampRequest" : "timestampReply",
        identifier: snapshot.readUInt16BE(4),
        sequence: snapshot.readUInt16BE(6),
        originateTimestamp,
        receiveTimestamp,
        transmitTimestamp,
        trailingData,
      },
    );
  }

  if (snapshot.byteLength < ICMP_ADDRESS_MASK_LENGTH) {
    return parseFailure(
      "truncated",
      "ICMP Address Mask message does not contain its complete fixed fields",
      ICMP_COMMON_HEADER_LENGTH,
      ICMP_ADDRESS_MASK_LENGTH,
      snapshot.byteLength,
      checksumStatus,
      issues,
    );
  }
  const mask = inspectMaskBytes(snapshot.subarray(8, 12));
  if (type === ICMP_ADDRESS && mask.address !== "0.0.0.0") {
    issues.push(
      issue(
        "nonzeroRequestReplyField",
        options.conformance,
        8,
        "Address Mask Request mask is nonzero",
      ),
    );
  }
  const trailingData = Buffer.from(snapshot.subarray(ICMP_ADDRESS_MASK_LENGTH));
  if (trailingData.byteLength > 0) {
    issues.push(
      issue(
        "unexpectedTrailingData",
        options.conformance,
        ICMP_ADDRESS_MASK_LENGTH,
        "ICMP Address Mask message contains trailing data",
      ),
    );
  }
  return successfulPacket(type, 0, checksum, checksumStatus, complete, issues, {
    kind: type === ICMP_ADDRESS ? "addressMaskRequest" : "addressMaskReply",
    identifier: snapshot.readUInt16BE(4),
    sequence: snapshot.readUInt16BE(6),
    mask,
    trailingData,
  });
}

function parseIcmpErrorSnapshot(
  snapshot: Buffer,
  type: number,
  code: number,
  checksum: number,
  checksumStatus: IcmpChecksumStatus,
  complete: boolean,
  options: NormalizedIcmpParseOptions,
  issues: IcmpValidationIssue[],
): IcmpParseResult {
  if (snapshot.byteLength < ICMP_ERROR_HEADER_LENGTH) {
    return parseFailure(
      "truncated",
      "ICMP error does not contain its complete fixed header",
      ICMP_COMMON_HEADER_LENGTH,
      ICMP_ERROR_HEADER_LENGTH,
      snapshot.byteLength,
      checksumStatus,
      issues,
    );
  }

  if (type === ICMP_REDIRECT) {
    const quote = parseQuotedIpv4(
      snapshot.subarray(ICMP_ERROR_HEADER_LENGTH),
      ICMP_ERROR_HEADER_LENGTH,
    );
    issues.push(...quote.issues);
    return successfulPacket(
      type,
      code,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: "redirect",
        code: code as IcmpRedirectCode,
        gatewayAddress: formatIpv4(snapshot, 4),
        quote,
      },
    );
  }

  const quoteLengthWords = snapshot[5] ?? 0;
  const split = splitErrorQuoteAndExtensions(
    snapshot,
    type,
    quoteLengthWords,
    options,
    issues,
  );
  if (!split.ok) {
    return parseFailure(
      split.reason,
      split.message,
      split.offset,
      split.requiredLength,
      split.availableLength,
      checksumStatus,
      issues,
    );
  }
  const quote = parseQuotedIpv4(split.quote, ICMP_ERROR_HEADER_LENGTH);
  issues.push(...quote.issues);

  if (type === ICMP_DEST_UNREACH) {
    const unused = snapshot[4] ?? 0;
    const word = snapshot.readUInt16BE(6);
    if (unused !== 0) {
      issues.push(
        issue(
          "nonzeroUnusedField",
          options.conformance,
          4,
          "Destination Unreachable unused octet is nonzero",
        ),
      );
    }
    if (code !== ICMP_FRAG_NEEDED && word !== 0) {
      issues.push(
        issue(
          "nonzeroUnusedField",
          options.conformance,
          6,
          "Destination Unreachable unused word is nonzero",
        ),
      );
    }
    return successfulPacket(
      type,
      code,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: "destinationUnreachable",
        code: code as IcmpDestinationUnreachableCode,
        unused,
        quoteLengthWords,
        nextHopMtu: code === ICMP_FRAG_NEEDED ? word : undefined,
        unusedWord: code === ICMP_FRAG_NEEDED ? undefined : word,
        quote,
        extensions: split.extensions,
      },
    );
  }

  if (type === ICMP_TIME_EXCEEDED) {
    const unused = snapshot[4] ?? 0;
    const unusedWord = snapshot.readUInt16BE(6);
    if (unused !== 0 || unusedWord !== 0) {
      issues.push(
        issue(
          "nonzeroUnusedField",
          options.conformance,
          unused !== 0 ? 4 : 6,
          "Time Exceeded unused field is nonzero",
        ),
      );
    }
    return successfulPacket(
      type,
      code,
      checksum,
      checksumStatus,
      complete,
      issues,
      {
        kind: "timeExceeded",
        code: code as IcmpTimeExceededCode,
        unused,
        unusedWord,
        quoteLengthWords,
        quote,
        extensions: split.extensions,
      },
    );
  }

  const pointer = snapshot[4] ?? 0;
  const unusedWord = snapshot.readUInt16BE(6);
  if (unusedWord !== 0) {
    issues.push(
      issue(
        "nonzeroUnusedField",
        options.conformance,
        6,
        "Parameter Problem unused word is nonzero",
      ),
    );
  }
  return successfulPacket(
    type,
    code,
    checksum,
    checksumStatus,
    complete,
    issues,
    {
      kind: "parameterProblem",
      code: code as IcmpParameterProblemCode,
      pointer,
      unusedWord,
      pointerPresent: pointer < quote.bytes.byteLength,
      quoteLengthWords,
      quote,
      extensions: split.extensions,
    },
  );
}

interface SplitErrorSuccess {
  readonly ok: true;
  readonly quote: Buffer;
  readonly extensions: ParsedIcmpExtensions | undefined;
}

interface SplitErrorFailure {
  readonly ok: false;
  readonly reason: IcmpParseFailureReason;
  readonly message: string;
  readonly offset: number;
  readonly requiredLength?: number;
  readonly availableLength?: number;
}

function splitErrorQuoteAndExtensions(
  snapshot: Buffer,
  type: number,
  quoteLengthWords: number,
  options: NormalizedIcmpParseOptions,
  issues: IcmpValidationIssue[],
): SplitErrorSuccess | SplitErrorFailure {
  if (quoteLengthWords === 0) {
    if (
      options.legacyExtensions &&
      (type === ICMP_DEST_UNREACH || type === ICMP_TIME_EXCEEDED) &&
      snapshot.byteLength >=
        ICMP_ERROR_HEADER_LENGTH +
          RFC4884_MINIMUM_QUOTE_LENGTH +
          RFC4884_EXTENSION_HEADER_LENGTH +
          RFC4884_OBJECT_HEADER_LENGTH
    ) {
      const extensionOffset =
        ICMP_ERROR_HEADER_LENGTH + RFC4884_MINIMUM_QUOTE_LENGTH;
      const candidate = parseExtensionStructure(
        snapshot.subarray(extensionOffset),
        "legacy",
        0,
        RFC4884_MINIMUM_QUOTE_LENGTH,
        options,
        extensionOffset,
      );
      if (candidate.ok && candidate.extensions.checksumStatus === "valid") {
        issues.push(...candidate.issues);
        const paddedQuote = snapshot.subarray(
          ICMP_ERROR_HEADER_LENGTH,
          extensionOffset,
        );
        return {
          ok: true,
          quote: removeKnownQuotePadding(
            paddedQuote,
            options,
            issues,
            ICMP_ERROR_HEADER_LENGTH,
          ),
          extensions: candidate.extensions,
        };
      }
    }
    return {
      ok: true,
      quote: Buffer.from(snapshot.subarray(ICMP_ERROR_HEADER_LENGTH)),
      extensions: undefined,
    };
  }

  if (snapshot.byteLength > RFC4884_MAXIMUM_MESSAGE_LENGTH) {
    return {
      ok: false,
      reason: "invalidLength",
      message: "extended ICMPv4 error exceeds the 576-byte ceiling",
      offset: RFC4884_MAXIMUM_MESSAGE_LENGTH,
      availableLength: snapshot.byteLength,
    };
  }
  const paddedQuoteLength = quoteLengthWords * 4;
  if (paddedQuoteLength < RFC4884_MINIMUM_QUOTE_LENGTH) {
    return {
      ok: false,
      reason: "unsupportedStructure",
      message: "RFC 4884 quote length is smaller than 128 bytes",
      offset: 5,
      requiredLength: RFC4884_MINIMUM_QUOTE_LENGTH,
      availableLength: paddedQuoteLength,
    };
  }
  const extensionOffset = ICMP_ERROR_HEADER_LENGTH + paddedQuoteLength;
  const minimumLength =
    extensionOffset +
    RFC4884_EXTENSION_HEADER_LENGTH +
    RFC4884_OBJECT_HEADER_LENGTH;
  if (snapshot.byteLength < minimumLength) {
    return {
      ok: false,
      reason: "truncated",
      message: "RFC 4884 extension structure is missing or truncated",
      offset: extensionOffset,
      requiredLength: minimumLength,
      availableLength: snapshot.byteLength,
    };
  }
  const paddedQuote = snapshot.subarray(
    ICMP_ERROR_HEADER_LENGTH,
    extensionOffset,
  );
  const normalizedQuote = removeKnownQuotePadding(
    paddedQuote,
    options,
    issues,
    ICMP_ERROR_HEADER_LENGTH,
  );
  const parsed = parseExtensionStructure(
    snapshot.subarray(extensionOffset),
    "rfc4884",
    quoteLengthWords,
    paddedQuoteLength,
    options,
    extensionOffset,
  );
  if (!parsed.ok) return parsed;
  issues.push(...parsed.issues);
  return {
    ok: true,
    quote: normalizedQuote,
    extensions: parsed.extensions,
  };
}

function removeKnownQuotePadding(
  paddedQuote: Buffer,
  options: NormalizedIcmpParseOptions,
  issues: IcmpValidationIssue[],
  baseOffset: number,
): Buffer {
  if (paddedQuote.byteLength < IPV4_MINIMUM_HEADER_LENGTH) {
    return Buffer.from(paddedQuote);
  }
  const totalLength = paddedQuote.readUInt16BE(2);
  if (totalLength >= paddedQuote.byteLength) {
    return Buffer.from(paddedQuote);
  }
  const padding = paddedQuote.subarray(totalLength);
  if (padding.some((value) => value !== 0)) {
    issues.push(
      issue(
        "nonzeroExtensionPadding",
        options.conformance,
        baseOffset + totalLength,
        "RFC 4884 quote padding contains nonzero octets",
      ),
    );
  }
  return Buffer.from(paddedQuote.subarray(0, totalLength));
}

type ExtensionParseResult =
  | {
      readonly ok: true;
      readonly extensions: ParsedIcmpExtensions;
      readonly issues: readonly IcmpValidationIssue[];
    }
  | SplitErrorFailure;

function parseExtensionStructure(
  data: Buffer,
  framing: "rfc4884" | "legacy",
  quoteLengthWords: number,
  paddedQuoteLength: number,
  options: NormalizedIcmpParseOptions,
  baseOffset: number,
): ExtensionParseResult {
  if (
    data.byteLength <
    RFC4884_EXTENSION_HEADER_LENGTH + RFC4884_OBJECT_HEADER_LENGTH
  ) {
    return {
      ok: false,
      reason: "truncated",
      message: "ICMP extension structure requires a header and one object",
      offset: baseOffset,
      requiredLength:
        RFC4884_EXTENSION_HEADER_LENGTH + RFC4884_OBJECT_HEADER_LENGTH,
      availableLength: data.byteLength,
    };
  }
  const version = (data[0] ?? 0) >> 4;
  if (version !== 2) {
    return {
      ok: false,
      reason: "unsupportedStructure",
      message: "ICMP extension header version is not 2",
      offset: baseOffset,
    };
  }
  const reserved = (((data[0] ?? 0) & 0x0f) << 8) | (data[1] ?? 0);
  const checksum = data.readUInt16BE(2);
  const checksumStatus: IcmpExtensionChecksumStatus =
    checksum === 0
      ? "notProvided"
      : checksumSnapshot(data) === 0
        ? "valid"
        : "invalid";
  const localIssues: IcmpValidationIssue[] = [];
  if (reserved !== 0) {
    localIssues.push(
      issue(
        "nonzeroExtensionReservedField",
        options.conformance,
        baseOffset,
        "ICMP extension header reserved bits are nonzero",
      ),
    );
  }

  const parsedObjects: ParsedIcmpExtensionObject[] = [];
  let offset = RFC4884_EXTENSION_HEADER_LENGTH;
  while (offset < data.byteLength) {
    if (data.byteLength - offset < RFC4884_OBJECT_HEADER_LENGTH) {
      return {
        ok: false,
        reason: "truncated",
        message: "ICMP extension object header is truncated",
        offset: baseOffset + offset,
        requiredLength: RFC4884_OBJECT_HEADER_LENGTH,
        availableLength: data.byteLength - offset,
      };
    }
    const length = data.readUInt16BE(offset);
    if (
      length < RFC4884_OBJECT_HEADER_LENGTH ||
      length % 4 !== 0 ||
      length > data.byteLength - offset
    ) {
      return {
        ok: false,
        reason: "unsupportedStructure",
        message: "ICMP extension object has an invalid bounded length",
        offset: baseOffset + offset,
        requiredLength: RFC4884_OBJECT_HEADER_LENGTH,
        availableLength: length,
      };
    }
    parsedObjects.push({
      length,
      classNumber: data[offset + 2] ?? 0,
      cType: data[offset + 3] ?? 0,
      data: Buffer.from(
        data.subarray(offset + RFC4884_OBJECT_HEADER_LENGTH, offset + length),
      ),
    });
    offset += length;
  }
  if (parsedObjects.length === 0) {
    return {
      ok: false,
      reason: "unsupportedStructure",
      message: "ICMP extension structure contains no objects",
      offset: baseOffset + RFC4884_EXTENSION_HEADER_LENGTH,
    };
  }
  if (checksumStatus === "invalid") {
    localIssues.push(
      hardIssue(
        "invalidExtensionChecksum",
        baseOffset + 2,
        "ICMP extension checksum is invalid; extension objects are untrusted",
      ),
    );
  }
  return {
    ok: true,
    issues: localIssues,
    extensions: {
      framing,
      quoteLengthWords,
      paddedQuoteLength,
      version,
      reserved,
      checksum,
      checksumStatus,
      objects: checksumStatus === "invalid" ? [] : parsedObjects,
      raw: Buffer.from(data),
    },
  };
}

function parseQuotedIpv4(data: Buffer, baseOffset: number): ParsedIcmpQuote {
  const bytes = Buffer.from(data);
  const issues: IcmpValidationIssue[] = [];
  if (bytes.byteLength < IPV4_MINIMUM_HEADER_LENGTH) {
    issues.push(
      hardIssue(
        "truncatedQuotedIpv4Header",
        baseOffset,
        "quoted datagram does not contain a complete minimum IPv4 header",
      ),
    );
    return {
      bytes,
      valid: false,
      incomplete: true,
      minimumComplete: false,
      datagramComplete: false,
      requiredMinimumLength: IPV4_MINIMUM_HEADER_LENGTH,
      ipv4: undefined,
      icmp: undefined,
      issues,
    };
  }
  if ((bytes[0] ?? 0) >> 4 !== 4) {
    issues.push(
      hardIssue(
        "invalidQuotedIpv4Version",
        baseOffset,
        "quoted datagram is not IPv4 version 4",
      ),
    );
    return invalidQuote(bytes, issues);
  }
  const headerLength = ((bytes[0] ?? 0) & 0x0f) * 4;
  if (
    headerLength < IPV4_MINIMUM_HEADER_LENGTH ||
    headerLength > 60 ||
    headerLength > bytes.byteLength
  ) {
    issues.push(
      hardIssue(
        "invalidQuotedIpv4HeaderLength",
        baseOffset,
        "quoted IPv4 header length is invalid or unavailable",
      ),
    );
    return {
      ...invalidQuote(bytes, issues),
      incomplete: headerLength > bytes.byteLength,
      requiredMinimumLength: headerLength,
    };
  }
  const totalLength = bytes.readUInt16BE(2);
  if (totalLength < headerLength) {
    issues.push(
      hardIssue(
        "invalidQuotedIpv4TotalLength",
        baseOffset + 2,
        "quoted IPv4 total length is smaller than its header length",
      ),
    );
    return invalidQuote(bytes, issues);
  }
  let valid = true;
  if (bytes.byteLength > totalLength) {
    valid = false;
    issues.push(
      hardIssue(
        "quotedDataBeyondTotalLength",
        baseOffset + totalLength,
        "quoted datagram contains octets beyond its IPv4 total length",
      ),
    );
  }
  const ipv4 = parseIpv4HeaderSnapshot(bytes, headerLength, totalLength);
  if (ipv4.checksumStatus === "invalid") {
    valid = false;
    issues.push(
      hardIssue(
        "invalidQuotedIpv4Checksum",
        baseOffset + 10,
        "quoted IPv4 header checksum is invalid",
      ),
    );
  }
  const requiredMinimumLength = Math.min(totalLength, headerLength + 8);
  const minimumComplete = bytes.byteLength >= requiredMinimumLength;
  if (!minimumComplete) {
    valid = false;
    issues.push(
      hardIssue(
        "truncatedQuotedPayload",
        baseOffset + bytes.byteLength,
        "quoted datagram does not contain the required leading payload octets",
      ),
    );
  }
  const datagramComplete = bytes.byteLength >= totalLength;
  const availableLength = Math.min(bytes.byteLength, totalLength);
  let icmp: ParsedQuotedIcmpPrefix | undefined;
  if (
    ipv4.protocol === 1 &&
    ipv4.fragmentOffset === 0 &&
    availableLength > headerLength
  ) {
    const fixedHeaderComplete = availableLength >= headerLength + 8;
    icmp = {
      type: bytes[headerLength] ?? 0,
      code:
        availableLength >= headerLength + 2
          ? (bytes[headerLength + 1] ?? 0)
          : undefined,
      fixedHeaderComplete,
      identifier: fixedHeaderComplete
        ? bytes.readUInt16BE(headerLength + 4)
        : undefined,
      sequence: fixedHeaderComplete
        ? bytes.readUInt16BE(headerLength + 6)
        : undefined,
      dataPrefix: fixedHeaderComplete
        ? Buffer.from(bytes.subarray(headerLength + 8, availableLength))
        : Buffer.alloc(0),
    };
  }
  return {
    bytes,
    valid,
    incomplete: !datagramComplete,
    minimumComplete,
    datagramComplete,
    requiredMinimumLength,
    ipv4,
    icmp,
    issues,
  };
}

function invalidQuote(
  bytes: Buffer,
  issues: readonly IcmpValidationIssue[],
): ParsedIcmpQuote {
  return {
    bytes,
    valid: false,
    incomplete: true,
    minimumComplete: false,
    datagramComplete: false,
    requiredMinimumLength: undefined,
    ipv4: undefined,
    icmp: undefined,
    issues,
  };
}

function successfulPacket(
  type: number,
  code: number,
  checksum: number,
  checksumStatus: IcmpChecksumStatus,
  complete: boolean,
  issues: readonly IcmpValidationIssue[],
  message: ParsedIcmpMessage,
): IcmpParseResult {
  return {
    ok: true,
    packet: {
      type,
      code,
      checksum,
      checksumStatus,
      incomplete: !complete,
      issues,
      message,
    },
  };
}

export function matchIcmpEchoQuoteInternal(
  quote: ParsedIcmpQuote,
  expected: {
    readonly expectedDestinationAddress: string;
    readonly identifier: number;
    readonly sequence: number;
    readonly token: Buffer | undefined;
  },
): IcmpEchoQuoteMatchResult {
  const ipv4 = quote.ipv4;
  const icmp = quote.icmp;
  if (
    !quote.valid ||
    ipv4?.protocol !== 1 ||
    ipv4.destinationAddress !== expected.expectedDestinationAddress ||
    ipv4.fragmentOffset !== 0 ||
    icmp?.fixedHeaderComplete !== true ||
    icmp.type !== ICMP_ECHO ||
    icmp.code !== 0 ||
    icmp.identifier !== expected.identifier ||
    icmp.sequence !== expected.sequence
  ) {
    return { matched: false };
  }
  const token = expected.token;
  if (token === undefined || token.byteLength === 0) {
    return { matched: true, strength: "weak", tokenCompared: false };
  }
  const comparedLength = Math.min(token.byteLength, icmp.dataPrefix.byteLength);
  for (let index = 0; index < comparedLength; index += 1) {
    if (token[index] !== icmp.dataPrefix[index]) return { matched: false };
  }
  if (icmp.dataPrefix.byteLength < token.byteLength) {
    return {
      matched: true,
      strength: "weak",
      tokenCompared: comparedLength > 0,
    };
  }
  return { matched: true, strength: "strong", tokenCompared: true };
}

export function classifyDestinationUnreachableInternal(
  code: IcmpDestinationUnreachableCode,
): IcmpDestinationUnreachableClassification {
  const administrativelyProhibited =
    code === ICMP_NET_ANO ||
    code === ICMP_HOST_ANO ||
    code === ICMP_PKT_FILTERED ||
    code === ICMP_PREC_VIOLATION ||
    code === ICMP_PREC_CUTOFF;
  const category: IcmpDestinationUnreachableCategory =
    code === ICMP_NET_UNREACH ||
    code === ICMP_NET_UNKNOWN ||
    code === ICMP_NET_UNR_TOS
      ? "network"
      : code === ICMP_HOST_UNREACH ||
          code === ICMP_HOST_UNKNOWN ||
          code === ICMP_HOST_ISOLATED ||
          code === ICMP_HOST_UNR_TOS
        ? "host"
        : code === ICMP_PROT_UNREACH
          ? "protocol"
          : code === ICMP_PORT_UNREACH
            ? "port"
            : code === ICMP_FRAG_NEEDED
              ? "fragmentationNeeded"
              : code === ICMP_SR_FAILED
                ? "sourceRouteFailed"
                : administrativelyProhibited
                  ? "administrativelyProhibited"
                  : "other";
  return {
    category,
    terminal:
      category === "protocol" ||
      category === "port" ||
      category === "administrativelyProhibited",
    administrativelyProhibited,
  };
}

export function classifyIcmpTimestampInternal(
  value: number,
): IcmpTimestampValue {
  validateUnsignedInteger(value, 0xffff_ffff, "timestamp");
  return classifyTimestampRaw(value);
}

export function inspectIpv4AddressMaskInternal(
  mask: string,
): IcmpAddressMaskInfo {
  if (typeof mask !== "string" || !isIPv4(mask)) {
    throw new IcmpInputError("mask must be a dotted-decimal IPv4 address mask");
  }
  const bytes = Buffer.alloc(4);
  writeIpv4(bytes, 0, mask);
  return inspectMaskBytes(bytes);
}

function classifyTimestampRaw(value: number): IcmpTimestampValue {
  return {
    raw: value,
    classification:
      (value & 0x8000_0000) !== 0
        ? "nonStandard"
        : value <= 86_399_999
          ? "standard"
          : "invalidStandardRange",
  };
}

function inspectMaskBytes(value: Uint8Array): IcmpAddressMaskInfo {
  const bytes = Buffer.from(value);
  let prefixLength = 0;
  let foundZero = false;
  let contiguous = true;
  for (let index = 0; index < 32; index += 1) {
    const octet = bytes[Math.floor(index / 8)] ?? 0;
    const set = (octet & (0x80 >> (index % 8))) !== 0;
    if (set) {
      if (foundZero) contiguous = false;
      else prefixLength += 1;
    } else {
      foundZero = true;
    }
  }
  return {
    address: formatIpv4(bytes, 0),
    bytes,
    contiguous,
    prefixLength: contiguous ? prefixLength : undefined,
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

function hardIssue(
  code: string,
  offset: number,
  message: string,
): IcmpValidationIssue {
  return { code, severity: "error", offset, message };
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

export function snapshotByteInputInternal(
  data: unknown,
  maximumLength: number,
  name: string,
): Buffer {
  if (!(data instanceof Uint8Array)) {
    throw new IcmpInputError(`${name} must be a Uint8Array`);
  }
  const byteLength = intrinsicUint8ArrayByteLength(data, name);
  if (byteLength > maximumLength) {
    throw new IcmpInputError(
      `${name}.byteLength must not exceed ${String(maximumLength)}`,
    );
  }
  return Buffer.from(data);
}

function intrinsicUint8ArrayByteLength(data: Uint8Array, name: string): number {
  try {
    return typedArrayByteLengthGetter(data);
  } catch {
    throw new IcmpInputError(`${name} must be a directly readable Uint8Array`);
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

function validateSignedInteger(
  value: unknown,
  name: string,
): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < -0x8000_0000 ||
    value > 0x7fff_ffff
  ) {
    throw new IcmpInputError(`${name} must be a signed 32-bit integer`);
  }
}

function validateCanonicalTimestamp(
  value: unknown,
  name: string,
): asserts value is number {
  validateUnsignedInteger(value, 0xffff_ffff, name);
  if (classifyTimestampRaw(value).classification === "invalidStandardRange") {
    throw new IcmpInputError(
      `${name} must be milliseconds within one UTC day or have the non-standard high bit set`,
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

function writeIpv4(data: Buffer, offset: number, address: string): void {
  const octets = address.split(".");
  for (let index = 0; index < 4; index += 1) {
    data[offset + index] = Number(octets[index]);
  }
}

function roundUpToWord(length: number): number {
  return Math.ceil(length / 4) * 4;
}

function parseIpv4HeaderSnapshot(
  data: Buffer,
  headerLength: number,
  totalLength: number,
): ParsedIpv4Header {
  const fragment = data.readUInt16BE(6);
  return {
    sourceAddress: formatIpv4(data, 12),
    destinationAddress: formatIpv4(data, 16),
    protocol: data[9] ?? 0,
    ttl: data[8] ?? 0,
    typeOfService: data[1] ?? 0,
    headerLength,
    totalLength,
    identification: data.readUInt16BE(4),
    fragmentOffset: fragment & 0x1fff,
    dontFragment: (fragment & 0x4000) !== 0,
    moreFragments: (fragment & 0x2000) !== 0,
    checksum: data.readUInt16BE(10),
    checksumStatus:
      checksumSnapshot(data.subarray(0, headerLength)) === 0
        ? "valid"
        : "invalid",
  };
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
