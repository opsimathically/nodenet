import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  ICMP_DEST_UNREACH,
  ICMP_ECHO,
  ICMP_EXC_FRAGTIME,
  ICMP_EXC_TTL,
  ICMP_FRAG_NEEDED,
  ICMP_HOST_ANO,
  ICMP_HOST_ISOLATED,
  ICMP_HOST_UNKNOWN,
  ICMP_HOST_UNREACH,
  ICMP_HOST_UNR_TOS,
  ICMP_NET_ANO,
  ICMP_NET_UNKNOWN,
  ICMP_NET_UNREACH,
  ICMP_NET_UNR_TOS,
  ICMP_PARAMETERPROB,
  ICMP_PARAMPROB_BAD_LENGTH,
  ICMP_PARAMPROB_MISSING_OPTION,
  ICMP_PARAMPROB_POINTER,
  ICMP_PKT_FILTERED,
  ICMP_PORT_UNREACH,
  ICMP_PREC_CUTOFF,
  ICMP_PREC_VIOLATION,
  ICMP_PROT_UNREACH,
  ICMP_REDIRECT,
  ICMP_REDIR_HOST,
  ICMP_REDIR_HOSTTOS,
  ICMP_REDIR_NET,
  ICMP_REDIR_NETTOS,
  ICMP_SR_FAILED,
  ICMP_TIME_EXCEEDED,
  RawSocketError,
  classifyIcmpDestinationUnreachable,
  encodeIcmpMessage,
  matchIcmpEchoQuote,
  parseIcmpMessage,
  validateIcmpMessage,
} from "../dist/index.js";

const destinationCodes = [
  ICMP_NET_UNREACH,
  ICMP_HOST_UNREACH,
  ICMP_PROT_UNREACH,
  ICMP_PORT_UNREACH,
  ICMP_FRAG_NEEDED,
  ICMP_SR_FAILED,
  ICMP_NET_UNKNOWN,
  ICMP_HOST_UNKNOWN,
  ICMP_HOST_ISOLATED,
  ICMP_NET_ANO,
  ICMP_HOST_ANO,
  ICMP_NET_UNR_TOS,
  ICMP_HOST_UNR_TOS,
  ICMP_PKT_FILTERED,
  ICMP_PREC_VIOLATION,
  ICMP_PREC_CUTOFF,
];

test("constructs and parses every Phase 13 ICMPv4 error family", () => {
  assert.deepEqual(
    destinationCodes,
    Array.from({ length: 16 }, (_, i) => i),
  );
  const quote = createEchoDatagram(Buffer.from("quoted-payload"));
  const minimumQuote = quote.subarray(0, 28);

  for (const code of destinationCodes) {
    const encoded = encodeIcmpMessage({
      kind: "destinationUnreachable",
      code,
      quote: minimumQuote,
      ...(code === ICMP_FRAG_NEEDED ? { nextHopMtu: 1500 } : {}),
    });
    assert.equal(encoded[0], ICMP_DEST_UNREACH);
    assert.equal(encoded[1], code);
    assert.equal(encoded[4], 0);
    assert.equal(encoded[5], 0);
    assert.equal(encoded.readUInt16BE(6), code === ICMP_FRAG_NEEDED ? 1500 : 0);
    assert.equal(testChecksum(encoded), 0);
    const parsed = parseIcmpMessage(encoded);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.packet.message.kind, "destinationUnreachable");
    assert.equal(parsed.packet.message.code, code);
    assert.deepEqual(parsed.packet.message.quote.bytes, minimumQuote);
    assert.equal(parsed.packet.message.quote.minimumComplete, true);
  }

  for (const code of [ICMP_EXC_TTL, ICMP_EXC_FRAGTIME]) {
    const encoded = encodeIcmpMessage({
      kind: "timeExceeded",
      code,
      quote: minimumQuote,
    });
    assert.equal(encoded[0], ICMP_TIME_EXCEEDED);
    assert.equal(encoded.readUInt32BE(4), 0);
    assert.equal(parseIcmpMessage(encoded).packet.message.code, code);
  }

  for (const code of [
    ICMP_PARAMPROB_POINTER,
    ICMP_PARAMPROB_MISSING_OPTION,
    ICMP_PARAMPROB_BAD_LENGTH,
  ]) {
    const encoded = encodeIcmpMessage({
      kind: "parameterProblem",
      code,
      pointer: 7,
      quote: minimumQuote,
    });
    assert.equal(encoded[0], ICMP_PARAMETERPROB);
    assert.equal(encoded[4], 7);
    const message = parseIcmpMessage(encoded).packet.message;
    assert.equal(message.kind, "parameterProblem");
    assert.equal(message.pointer, 7);
    assert.equal(message.pointerPresent, true);
  }

  for (const code of [
    ICMP_REDIR_NET,
    ICMP_REDIR_HOST,
    ICMP_REDIR_NETTOS,
    ICMP_REDIR_HOSTTOS,
  ]) {
    const encoded = encodeIcmpMessage({
      kind: "redirect",
      code,
      gatewayAddress: "192.0.2.1",
      quote: minimumQuote,
    });
    assert.equal(encoded[0], ICMP_REDIRECT);
    assert.deepEqual(encoded.subarray(4, 8), Buffer.from([192, 0, 2, 1]));
    const message = parseIcmpMessage(encoded).packet.message;
    assert.equal(message.kind, "redirect");
    assert.equal(message.gatewayAddress, "192.0.2.1");
    assert.equal(message.extensions, undefined);
  }
});

test("matches independent golden bytes and RFC 1191 MTU zero semantics", () => {
  const quote = createEchoDatagram().subarray(0, 28);
  const encoded = encodeIcmpMessage({
    kind: "destinationUnreachable",
    code: ICMP_FRAG_NEEDED,
    quote,
    nextHopMtu: 0,
  });
  const golden = Buffer.alloc(8 + quote.byteLength);
  golden[0] = 3;
  golden[1] = 4;
  quote.copy(golden, 8);
  golden.writeUInt16BE(testChecksum(golden), 2);
  assert.deepEqual(encoded, golden);
  const message = parseIcmpMessage(encoded).packet.message;
  assert.equal(message.kind, "destinationUnreachable");
  assert.equal(message.nextHopMtu, 0);

  const withMtu = Buffer.from(encoded);
  withMtu.writeUInt16BE(1500, 6);
  rewriteIcmpChecksum(withMtu);
  assert.equal(parseIcmpMessage(withMtu).packet.message.nextHopMtu, 1500);
});

test("parses bounded quoted IPv4 and extracts Echo correlation evidence", () => {
  const token = Buffer.from("correlation-token");
  const datagram = createEchoDatagram(token);
  const weakPacket = encodeIcmpMessage({
    kind: "timeExceeded",
    code: ICMP_EXC_TTL,
    quote: datagram.subarray(0, 28),
  });
  const weakQuote = parseIcmpMessage(weakPacket).packet.message.quote;
  assert.equal(weakQuote.valid, true);
  assert.equal(weakQuote.incomplete, true);
  assert.equal(weakQuote.ipv4.destinationAddress, "198.51.100.9");
  assert.deepEqual(
    matchIcmpEchoQuote(weakQuote, {
      expectedDestinationAddress: "198.51.100.9",
      identifier: 0x1234,
      sequence: 0x5678,
      token,
    }),
    { matched: true, strength: "weak", tokenCompared: false },
  );

  const strongPacket = encodeIcmpMessage({
    kind: "timeExceeded",
    code: ICMP_EXC_TTL,
    quote: datagram,
  });
  const strongQuote = parseIcmpMessage(strongPacket).packet.message.quote;
  assert.deepEqual(
    matchIcmpEchoQuote(strongQuote, {
      expectedDestinationAddress: "198.51.100.9",
      identifier: 0x1234,
      sequence: 0x5678,
      token,
    }),
    { matched: true, strength: "strong", tokenCompared: true },
  );
  assert.equal(
    matchIcmpEchoQuote(strongQuote, {
      expectedDestinationAddress: "198.51.100.9",
      identifier: 0x1234,
      sequence: 0x5678,
      token: Buffer.from("wrong"),
    }).matched,
    false,
  );

  const fragmented = createEchoDatagram(token, { fragmentOffset: 1 });
  const fragmentedQuote = parseIcmpMessage(
    encodeIcmpMessage({
      kind: "timeExceeded",
      code: 0,
      quote: fragmented,
    }),
  ).packet.message.quote;
  assert.equal(fragmentedQuote.icmp, undefined);
  assert.equal(
    matchIcmpEchoQuote(fragmentedQuote, {
      expectedDestinationAddress: "198.51.100.9",
      identifier: 0x1234,
      sequence: 0x5678,
      token,
    }).matched,
    false,
  );
});

test("encodes and parses compliant RFC 4884 extensions with owned objects", () => {
  const shortDatagram = createEchoDatagram();
  const encoded = encodeIcmpMessage({
    kind: "timeExceeded",
    code: ICMP_EXC_TTL,
    quote: shortDatagram,
    extensions: [
      { classNumber: 1, cType: 1, data: Buffer.from([0, 1, 2, 3]) },
      { classNumber: 250, cType: 7 },
    ],
  });
  assert.equal(encoded.byteLength, 8 + 128 + 16);
  assert.equal(encoded[5], 32);
  assert.equal(encoded[136] >> 4, 2);
  assert.equal(testChecksum(encoded), 0);

  const parsed = parseIcmpMessage(encoded);
  assert.equal(parsed.ok, true);
  const message = parsed.packet.message;
  assert.equal(message.kind, "timeExceeded");
  assert.equal(message.quoteLengthWords, 32);
  assert.deepEqual(message.quote.bytes, shortDatagram);
  assert.equal(message.extensions.framing, "rfc4884");
  assert.equal(message.extensions.paddedQuoteLength, 128);
  assert.equal(message.extensions.checksumStatus, "valid");
  assert.deepEqual(message.extensions.objects, [
    {
      length: 8,
      classNumber: 1,
      cType: 1,
      data: Buffer.from([0, 1, 2, 3]),
    },
    { length: 4, classNumber: 250, cType: 7, data: Buffer.alloc(0) },
  ]);
  encoded.fill(0);
  assert.deepEqual(
    message.extensions.objects[0].data,
    Buffer.from([0, 1, 2, 3]),
  );

  const maximumQuote = createEchoDatagram(Buffer.alloc(532));
  const maximum = encodeIcmpMessage({
    kind: "timeExceeded",
    code: ICMP_EXC_TTL,
    quote: maximumQuote,
    extensions: [{ classNumber: 255, cType: 255 }],
  });
  assert.equal(maximum.byteLength, 576);
  assert.equal(parseIcmpMessage(maximum).ok, true);
  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "timeExceeded",
        code: ICMP_EXC_TTL,
        quote: maximumQuote,
        extensions: [{ classNumber: 255, cType: 255, data: Buffer.alloc(4) }],
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );
});

test("handles RFC 4884 checksum, padding, and legacy framing policies", () => {
  const datagram = createEchoDatagram();
  const canonical = encodeIcmpMessage({
    kind: "destinationUnreachable",
    code: ICMP_PORT_UNREACH,
    quote: datagram,
    extensions: [{ classNumber: 9, cType: 3, data: Buffer.alloc(4) }],
  });
  const extensionOffset = 8 + 128;

  const notProvided = Buffer.from(canonical);
  notProvided.writeUInt16BE(0, extensionOffset + 2);
  rewriteIcmpChecksum(notProvided);
  assert.equal(
    parseIcmpMessage(notProvided).packet.message.extensions.checksumStatus,
    "notProvided",
  );

  const invalid = Buffer.from(canonical);
  invalid[extensionOffset + 7] ^= 1;
  rewriteIcmpChecksum(invalid);
  const invalidParsed = parseIcmpMessage(invalid);
  assert.equal(
    invalidParsed.packet.message.extensions.checksumStatus,
    "invalid",
  );
  assert.deepEqual(invalidParsed.packet.message.extensions.objects, []);
  assert.equal(validateIcmpMessage(invalid).valid, false);

  const nonzeroPadding = Buffer.from(canonical);
  nonzeroPadding[8 + datagram.byteLength] = 0xa5;
  rewriteIcmpChecksum(nonzeroPadding);
  const compatible = parseIcmpMessage(nonzeroPadding);
  assert.equal(
    compatible.packet.issues.some(
      (issue) => issue.code === "nonzeroExtensionPadding",
    ),
    true,
  );
  assert.equal(
    validateIcmpMessage(nonzeroPadding, { conformance: "canonical" }).valid,
    false,
  );

  const legacy = Buffer.from(canonical);
  legacy[5] = 0;
  rewriteIcmpChecksum(legacy);
  assert.equal(parseIcmpMessage(legacy).packet.message.extensions, undefined);
  const legacyParsed = parseIcmpMessage(legacy, { legacyExtensions: true });
  assert.equal(legacyParsed.packet.message.extensions.framing, "legacy");
  assert.deepEqual(legacyParsed.packet.message.quote.bytes, datagram);
});

test("rejects malformed RFC 4884 boundaries as structured failures", () => {
  const datagram = createEchoDatagram(Buffer.alloc(120));
  const canonical = encodeIcmpMessage({
    kind: "timeExceeded",
    code: 0,
    quote: datagram.subarray(0, 128),
    extensions: [{ classNumber: 1, cType: 1, data: Buffer.alloc(4) }],
  });
  const extensionOffset = 136;

  const badObjectLength = Buffer.from(canonical);
  badObjectLength.writeUInt16BE(0, extensionOffset + 4);
  rewriteExtensionChecksum(badObjectLength, extensionOffset);
  rewriteIcmpChecksum(badObjectLength);
  assert.equal(parseIcmpMessage(badObjectLength).ok, false);
  assert.equal(
    parseIcmpMessage(badObjectLength).error.reason,
    "unsupportedStructure",
  );

  const tooShortQuoteLength = Buffer.from(canonical);
  tooShortQuoteLength[5] = 31;
  rewriteIcmpChecksum(tooShortQuoteLength);
  assert.equal(parseIcmpMessage(tooShortQuoteLength).ok, false);

  const missingExtension = Buffer.from(canonical.subarray(0, 140));
  rewriteIcmpChecksum(missingExtension);
  const missing = parseIcmpMessage(missingExtension);
  assert.equal(missing.ok, false);
  assert.equal(missing.error.reason, "truncated");

  const oversized = Buffer.alloc(577);
  oversized[0] = ICMP_TIME_EXCEEDED;
  oversized[5] = 32;
  rewriteIcmpChecksum(oversized);
  const oversizedResult = parseIcmpMessage(oversized);
  assert.equal(oversizedResult.ok, false);
  assert.equal(oversizedResult.error.reason, "invalidLength");
});

test("reports malformed, truncated, optioned, and noncanonical quotes safely", () => {
  const shortOuter = Buffer.alloc(8 + 12);
  shortOuter[0] = ICMP_TIME_EXCEEDED;
  rewriteIcmpChecksum(shortOuter);
  const shortQuote = parseIcmpMessage(shortOuter).packet.message.quote;
  assert.equal(shortQuote.valid, false);
  assert.equal(shortQuote.incomplete, true);

  const withOptions = createEchoDatagram(Buffer.alloc(8), { headerLength: 24 });
  const optioned = parseIcmpMessage(
    encodeIcmpMessage({ kind: "timeExceeded", code: 0, quote: withOptions }),
  ).packet.message.quote;
  assert.equal(optioned.valid, true);
  assert.equal(optioned.ipv4.headerLength, 24);

  const badChecksum = Buffer.from(createEchoDatagram());
  badChecksum[10] ^= 1;
  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "timeExceeded",
        code: 0,
        quote: badChecksum,
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );

  const badReceivedQuote = Buffer.from(
    encodeIcmpMessage({
      kind: "timeExceeded",
      code: 0,
      quote: createEchoDatagram().subarray(0, 28),
    }),
  );
  badReceivedQuote[8 + 10] ^= 1;
  rewriteIcmpChecksum(badReceivedQuote);
  const badReceived = parseIcmpMessage(badReceivedQuote);
  assert.equal(badReceived.ok, true);
  assert.equal(badReceived.packet.message.quote.valid, false);
  assert.equal(validateIcmpMessage(badReceivedQuote).valid, false);

  const noncanonical = Buffer.from(
    encodeIcmpMessage({
      kind: "timeExceeded",
      code: 0,
      quote: createEchoDatagram().subarray(0, 28),
    }),
  );
  noncanonical[4] = 1;
  rewriteIcmpChecksum(noncanonical);
  assert.equal(validateIcmpMessage(noncanonical).valid, true);
  assert.equal(
    validateIcmpMessage(noncanonical, { conformance: "canonical" }).valid,
    false,
  );
});

test("preserves unknown error codes and classifies registered unreachable codes", () => {
  const unknown = Buffer.alloc(12);
  unknown[0] = ICMP_DEST_UNREACH;
  unknown[1] = 16;
  unknown.writeUInt32BE(0xaabbccdd, 4);
  rewriteIcmpChecksum(unknown);
  const parsed = parseIcmpMessage(unknown);
  assert.equal(parsed.packet.message.kind, "unknownCode");
  assert.deepEqual(
    parsed.packet.message.body,
    Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0]),
  );

  assert.deepEqual(classifyIcmpDestinationUnreachable(ICMP_PORT_UNREACH), {
    category: "port",
    terminal: true,
    administrativelyProhibited: false,
  });
  assert.deepEqual(classifyIcmpDestinationUnreachable(ICMP_FRAG_NEEDED), {
    category: "fragmentationNeeded",
    terminal: false,
    administrativelyProhibited: false,
  });
  assert.deepEqual(classifyIcmpDestinationUnreachable(ICMP_PKT_FILTERED), {
    category: "administrativelyProhibited",
    terminal: true,
    administrativelyProhibited: true,
  });
});

test("rejects unsafe local error construction without mutating inputs", () => {
  const invalidExtensionCount = new Proxy([], {
    get(target, property, receiver) {
      if (property === "length") return -1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "timeExceeded",
        code: 0,
        quote: createEchoDatagram(),
        extensions: invalidExtensionCount,
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );

  const quote = createEchoDatagram();
  const before = Buffer.from(quote);
  const disguisedExtensionData = new Uint8Array(5);
  Object.defineProperty(disguisedExtensionData, "byteLength", { value: 4 });
  for (const message of [
    { kind: "destinationUnreachable", code: 16, quote },
    { kind: "destinationUnreachable", code: 3, quote, nextHopMtu: 1500 },
    { kind: "timeExceeded", code: 2, quote },
    { kind: "parameterProblem", code: 0, pointer: 256, quote },
    { kind: "redirect", code: 0, gatewayAddress: "not-an-ip", quote },
    { kind: "timeExceeded", code: 0, quote: quote.subarray(0, 27) },
    {
      kind: "timeExceeded",
      code: 0,
      quote,
      extensions: [{ classNumber: 1, cType: 1, data: Buffer.alloc(1) }],
    },
    {
      kind: "timeExceeded",
      code: 0,
      quote: createEchoDatagram(Buffer.alloc(200)).subarray(0, 28),
      extensions: [{ classNumber: 1, cType: 1 }],
    },
    { kind: "timeExceeded", code: 0, quote, extensions: [] },
    {
      kind: "timeExceeded",
      code: 0,
      quote,
      extensions: [{ classNumber: 1, cType: 1, data: disguisedExtensionData }],
    },
  ]) {
    assert.throws(
      () => encodeIcmpMessage(message),
      (error) => {
        assert.ok(error instanceof RawSocketError);
        assert.equal(error.code, "ERR_INVALID_ARGUMENT");
        return true;
      },
    );
  }
  assert.deepEqual(quote, before);
  assert.throws(() => classifyIcmpDestinationUnreachable(16), {
    code: "ERR_INVALID_ARGUMENT",
  });
});

function createEchoDatagram(payload = Buffer.alloc(0), options = {}) {
  const headerLength = options.headerLength ?? 20;
  const icmp = Buffer.alloc(8 + payload.byteLength);
  icmp[0] = ICMP_ECHO;
  icmp.writeUInt16BE(0x1234, 4);
  icmp.writeUInt16BE(0x5678, 6);
  payload.copy(icmp, 8);
  rewriteIcmpChecksum(icmp);

  const packet = Buffer.alloc(headerLength + icmp.byteLength);
  packet[0] = 0x40 | (headerLength / 4);
  packet[1] = 0x2e;
  packet.writeUInt16BE(packet.byteLength, 2);
  packet.writeUInt16BE(0x3456, 4);
  packet.writeUInt16BE(options.fragmentOffset ?? 0, 6);
  packet[8] = 1;
  packet[9] = 1;
  packet.set([192, 0, 2, 10], 12);
  packet.set([198, 51, 100, 9], 16);
  if (headerLength > 20) packet.fill(1, 20, headerLength);
  packet.writeUInt16BE(testChecksum(packet.subarray(0, headerLength)), 10);
  icmp.copy(packet, headerLength);
  return packet;
}

function rewriteIcmpChecksum(data) {
  data.writeUInt16BE(0, 2);
  data.writeUInt16BE(testChecksum(data), 2);
}

function rewriteExtensionChecksum(data, offset) {
  data.writeUInt16BE(0, offset + 2);
  const checksum = testChecksum(data.subarray(offset));
  data.writeUInt16BE(checksum === 0 ? 0xffff : checksum, offset + 2);
}

function testChecksum(data) {
  let sum = 0;
  for (let index = 0; index < data.byteLength; index += 2) {
    sum += (data[index] << 8) | (data[index + 1] ?? 0);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
}
