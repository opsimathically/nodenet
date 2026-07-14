import {
  ICMP_ECHO,
  IPPROTO_ICMP,
  RawSocket,
  computeInternetChecksum,
  encodeIcmpMessage,
  matchesIcmpEchoReply,
  parseIcmpMessage,
  parseIcmpReceivedMessage,
  receiveIcmpMessage,
  sendIcmpMessage,
  validateIcmpMessage,
  type IcmpEchoReplyMatch,
  type IcmpMessage,
  type IcmpParseOptions,
  type IcmpReceivedParseResult,
} from "../../dist/index.js";

const options: IcmpParseOptions = {
  checksum: "report",
  conformance: "canonical",
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

// @ts-expect-error ICMP constructors require the supported discriminant.
encodeIcmpMessage({ kind: "other", identifier: 1, sequence: 2 });
// @ts-expect-error identifiers are numbers, not strings.
encodeIcmpMessage({ kind: "echoReply", identifier: "1", sequence: 2 });
sendIcmpMessage(socket, request, {
  // @ts-expect-error the ICMP helper accepts only an IPv4 destination.
  destination: { family: "ipv6", address: "::1" },
});
