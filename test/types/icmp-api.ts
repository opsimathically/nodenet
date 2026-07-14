import {
  ICMP_ECHO,
  IPPROTO_ICMP,
  RawSocket,
  computeInternetChecksum,
  classifyIcmpTimestamp,
  classifyIcmpDestinationUnreachable,
  classifyIcmpTracerouteResponse,
  createIcmpTracerouteProbe,
  createIcmpTimestampReply,
  encodeIcmpMessage,
  matchIcmpEchoQuote,
  matchesIcmpEchoReply,
  parseIcmpMessage,
  parseIcmpReceivedMessage,
  receiveIcmpMessage,
  sendIcmpMessage,
  traceIcmpRoute,
  inspectIpv4AddressMask,
  validateIcmpMessage,
  type IcmpEchoReplyMatch,
  type IcmpEchoQuoteMatchResult,
  type IcmpExtensionObject,
  type IcmpMessage,
  type IcmpParseOptions,
  type IcmpReceivedParseResult,
  type IcmpTimestampValue,
  type IcmpTracerouteMatch,
  type IcmpTracerouteProbe,
  type IcmpTracerouteResult,
  type TraceIcmpRouteOptions,
} from "@opsimathically/nodenetraw";

const options: IcmpParseOptions = {
  checksum: "report",
  conformance: "canonical",
  legacyExtensions: false,
};
const request: IcmpMessage = {
  kind: "echoRequest",
  identifier: 1,
  sequence: 2,
  data: Uint8Array.of(3),
};
const encoded: Buffer = encodeIcmpMessage(request);
const checksum: number = computeInternetChecksum(encoded);
const parsed = parseIcmpMessage(encoded, options);
if (parsed.ok && parsed.packet.message.kind === "echoRequest") {
  const identifier: number = parsed.packet.message.identifier;
  const data: Buffer = parsed.packet.message.data;
  void identifier;
  void data;
} else if (!parsed.ok) {
  const reason: string = parsed.error.reason;
  void reason;
}
const valid: boolean = validateIcmpMessage(encoded).valid;
void checksum;
void valid;
void ICMP_ECHO;

declare const socket: RawSocket;
const sent: Promise<number> = sendIcmpMessage(socket, request, {
  destination: { family: "ipv4", address: "127.0.0.1" },
  ttl: 1,
});
const received: Promise<IcmpReceivedParseResult> = receiveIcmpMessage(socket, {
  dataCapacity: 1024,
  parse: { checksum: "require" },
});
void sent;
void received;
void IPPROTO_ICMP;

declare const rawReceived: Parameters<typeof parseIcmpReceivedMessage>[0];
const parsedReceived = parseIcmpReceivedMessage(rawReceived);
const match: IcmpEchoReplyMatch = {
  identifier: 1,
  sequence: 2,
  expectedSourceAddress: "127.0.0.1",
  token: Uint8Array.of(3),
};
const matches: boolean = matchesIcmpEchoReply(parsedReceived, match);
void matches;

const extension: IcmpExtensionObject = {
  classNumber: 1,
  cType: 1,
  data: Uint8Array.of(0, 0, 0, 1),
};
const errorMessage: IcmpMessage = {
  kind: "destinationUnreachable",
  code: 4,
  nextHopMtu: 1500,
  quote: new Uint8Array(28),
  extensions: [extension],
};
void encodeIcmpMessage(errorMessage);

if (parsed.ok && parsed.packet.message.kind === "destinationUnreachable") {
  const mtu: number | undefined = parsed.packet.message.nextHopMtu;
  const quote = parsed.packet.message.quote;
  const quoteMatch: IcmpEchoQuoteMatchResult = matchIcmpEchoQuote(quote, {
    expectedDestinationAddress: "127.0.0.1",
    identifier: 1,
    sequence: 2,
  });
  void mtu;
  void quoteMatch;
}
const category: string = classifyIcmpDestinationUnreachable(3).category;
void category;

const advertisement: IcmpMessage = {
  kind: "routerAdvertisement",
  lifetime: 1800,
  addresses: [{ address: "192.0.2.1", preference: -1 }],
};
const timestampRequest: IcmpMessage = {
  kind: "timestampRequest",
  identifier: 1,
  sequence: 2,
  originateTimestamp: 3,
};
const maskReply: IcmpMessage = {
  kind: "addressMaskReply",
  identifier: 1,
  sequence: 2,
  mask: "255.255.255.0",
};
void encodeIcmpMessage(advertisement);
void encodeIcmpMessage(timestampRequest);
void encodeIcmpMessage(maskReply);
const timestampValue: IcmpTimestampValue = classifyIcmpTimestamp(3);
const maskPrefix: number | undefined =
  inspectIpv4AddressMask("255.255.255.0").prefixLength;
void timestampValue;
void maskPrefix;

const tracerouteProbe: IcmpTracerouteProbe = createIcmpTracerouteProbe({
  destination: { family: "ipv4", address: "198.51.100.9" },
  identifier: 1,
  sequence: 2,
  token: Uint8Array.of(3),
  payload: Uint8Array.of(4),
  ttl: 1,
  sentAt: 5n,
});
const tracerouteMatch: IcmpTracerouteMatch = classifyIcmpTracerouteResponse(
  tracerouteProbe,
  parsedReceived,
  6n,
);
if (tracerouteMatch.matched && tracerouteMatch.kind === "unreachable") {
  const code: number = tracerouteMatch.code;
  const rtt: bigint = tracerouteMatch.roundTripNanoseconds;
  void code;
  void rtt;
}
const traceOptions: TraceIcmpRouteOptions = {
  firstHop: 1,
  maxHops: 30,
  probesPerHop: 3,
  maxInFlight: 1,
  token: Uint8Array.of(1),
  onProgress(progress) {
    const hop: number = progress.result.hop;
    void hop;
  },
};
const traceResult: Promise<IcmpTracerouteResult> = traceIcmpRoute(
  socket,
  { family: "ipv4", address: "198.51.100.9" },
  traceOptions,
);
void traceResult;

if (parsed.ok && parsed.packet.message.kind === "routerAdvertisement") {
  const preference: number = parsed.packet.message.addresses[0]!.preference;
  const extensionWords: readonly number[] =
    parsed.packet.message.addresses[0]!.extensionWords;
  void preference;
  void extensionWords;
}
if (parsed.ok && parsed.packet.message.kind === "timestampRequest") {
  const reply = createIcmpTimestampReply(parsed.packet.message, {
    receiveTimestamp: 4,
    transmitTimestamp: 5,
  });
  const replyKind: "timestampReply" = reply.kind;
  void replyKind;
}
if (parsed.ok && parsed.packet.message.kind === "addressMaskReply") {
  const contiguous: boolean = parsed.packet.message.mask.contiguous;
  void contiguous;
}

// @ts-expect-error ICMP constructors require the supported discriminant.
encodeIcmpMessage({ kind: "other", identifier: 1, sequence: 2 });
// @ts-expect-error identifiers are numbers, not strings.
encodeIcmpMessage({ kind: "echoReply", identifier: "1", sequence: 2 });
sendIcmpMessage(socket, request, {
  // @ts-expect-error the ICMP helper accepts only an IPv4 destination.
  destination: { family: "ipv6", address: "::1" },
});
// @ts-expect-error Destination Unreachable construction accepts registered codes only.
encodeIcmpMessage({ kind: "destinationUnreachable", code: 16, quote: encoded });
encodeIcmpMessage({
  kind: "redirect",
  code: 0,
  // @ts-expect-error Redirect requires a checked string gateway address.
  gatewayAddress: 1,
  quote: encoded,
});
encodeIcmpMessage({
  kind: "routerAdvertisement",
  lifetime: 1,
  // @ts-expect-error Router Advertisement preferences are numeric.
  addresses: [{ address: "192.0.2.1", preference: "high" }],
});
encodeIcmpMessage({
  kind: "timestampRequest",
  identifier: 1,
  sequence: 2,
  originateTimestamp: 3,
  // @ts-expect-error Timestamp Request does not expose reply-owned timestamps.
  receiveTimestamp: 4,
});
encodeIcmpMessage({
  kind: "addressMaskRequest",
  identifier: 1,
  sequence: 2,
  // @ts-expect-error Address Mask Request construction always writes a zero mask.
  mask: "0.0.0.0",
});
createIcmpTracerouteProbe({
  destination: { family: "ipv4", address: "198.51.100.9" },
  identifier: 1,
  sequence: 2,
  token: Uint8Array.of(3),
  // @ts-expect-error traceroute TTL is numeric.
  ttl: "1",
  sentAt: 0n,
});
traceIcmpRoute(socket, {
  // @ts-expect-error traceroute is IPv4-only.
  family: "ipv6",
  address: "::1",
});
