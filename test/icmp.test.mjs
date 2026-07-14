import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  ICMP_ADDRESS,
  ICMP_ADDRESSREPLY,
  ICMP_DEST_UNREACH,
  ICMP_ECHO,
  ICMP_ECHOREPLY,
  ICMP_EXC_FRAGTIME,
  ICMP_EXC_TTL,
  ICMP_FRAG_NEEDED,
  ICMP_HOST_UNREACH,
  ICMP_PARAMETERPROB,
  ICMP_PARAMPROB_BAD_LENGTH,
  ICMP_PARAMPROB_ERRATPTR,
  ICMP_PARAMPROB_LENGTH,
  ICMP_PARAMPROB_MISSING_OPTION,
  ICMP_PARAMPROB_OPTABSENT,
  ICMP_PARAMPROB_POINTER,
  ICMP_PORT_UNREACH,
  ICMP_REDIRECT,
  ICMP_ROUTERADVERT,
  ICMP_ROUTERSOLICIT,
  ICMP_TIMESTAMP,
  ICMP_TIMESTAMPREPLY,
  ICMP_TIME_EXCEEDED,
  RawSocket,
  RawSocketError,
  computeInternetChecksum,
  encodeIcmpMessage,
  matchesIcmpEchoReply,
  parseIcmpMessage,
  parseIcmpReceivedMessage,
  receiveIcmpMessage,
  sendIcmpMessage,
  validateIcmpMessage,
  validateInternetChecksum,
} from "../dist/index.js";

test("exports Linux-compatible ICMP type and code constants", () => {
  assert.deepEqual(
    {
      ICMP_ECHOREPLY,
      ICMP_DEST_UNREACH,
      ICMP_REDIRECT,
      ICMP_ECHO,
      ICMP_ROUTERADVERT,
      ICMP_ROUTERSOLICIT,
      ICMP_TIME_EXCEEDED,
      ICMP_PARAMETERPROB,
      ICMP_TIMESTAMP,
      ICMP_TIMESTAMPREPLY,
      ICMP_ADDRESS,
      ICMP_ADDRESSREPLY,
      ICMP_HOST_UNREACH,
      ICMP_PORT_UNREACH,
      ICMP_FRAG_NEEDED,
      ICMP_EXC_TTL,
      ICMP_EXC_FRAGTIME,
      ICMP_PARAMPROB_POINTER,
      ICMP_PARAMPROB_MISSING_OPTION,
      ICMP_PARAMPROB_BAD_LENGTH,
      ICMP_PARAMPROB_ERRATPTR,
      ICMP_PARAMPROB_OPTABSENT,
      ICMP_PARAMPROB_LENGTH,
    },
    {
      ICMP_ECHOREPLY: 0,
      ICMP_DEST_UNREACH: 3,
      ICMP_REDIRECT: 5,
      ICMP_ECHO: 8,
      ICMP_ROUTERADVERT: 9,
      ICMP_ROUTERSOLICIT: 10,
      ICMP_TIME_EXCEEDED: 11,
      ICMP_PARAMETERPROB: 12,
      ICMP_TIMESTAMP: 13,
      ICMP_TIMESTAMPREPLY: 14,
      ICMP_ADDRESS: 17,
      ICMP_ADDRESSREPLY: 18,
      ICMP_HOST_UNREACH: 1,
      ICMP_PORT_UNREACH: 3,
      ICMP_FRAG_NEEDED: 4,
      ICMP_EXC_TTL: 0,
      ICMP_EXC_FRAGTIME: 1,
      ICMP_PARAMPROB_POINTER: 0,
      ICMP_PARAMPROB_MISSING_OPTION: 1,
      ICMP_PARAMPROB_BAD_LENGTH: 2,
      ICMP_PARAMPROB_ERRATPTR: 0,
      ICMP_PARAMPROB_OPTABSENT: 1,
      ICMP_PARAMPROB_LENGTH: 2,
    },
  );
});

test("computes independent RFC 1071 checksum vectors without mutation", () => {
  const rfcVector = Uint8Array.of(
    0x00,
    0x01,
    0xf2,
    0x03,
    0xf4,
    0xf5,
    0xf6,
    0xf7,
  );
  const before = Uint8Array.from(rfcVector);
  assert.equal(computeInternetChecksum(rfcVector), 0x220d);
  assert.deepEqual(rfcVector, before);

  assert.equal(computeInternetChecksum(Uint8Array.of()), 0xffff);
  assert.equal(computeInternetChecksum(Uint8Array.of(0x01)), 0xfeff);
  assert.equal(
    validateInternetChecksum(
      Uint8Array.of(0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x22, 0x0d),
    ),
    true,
  );
  assert.equal(validateInternetChecksum(Uint8Array.of(1, 2, 3)), false);

  assert.throws(() => computeInternetChecksum("bytes"), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "computeInternetChecksum",
  });
  assert.throws(() => computeInternetChecksum(new Uint8Array(65_536)), {
    code: "ERR_INVALID_ARGUMENT",
  });
});

test("encodes and parses canonical Echo Request and Reply golden packets", () => {
  const request = encodeIcmpMessage({
    kind: "echoRequest",
    identifier: 0x1234,
    sequence: 1,
    data: Uint8Array.of(0x61, 0x62, 0x63),
  });
  assert.deepEqual(
    request,
    Buffer.from([
      0x08, 0x00, 0x21, 0x68, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63,
    ]),
  );
  assert.equal(validateInternetChecksum(request), true);

  const parsedRequest = parseIcmpMessage(request);
  assert.equal(parsedRequest.ok, true);
  assert.equal(parsedRequest.packet.checksumStatus, "valid");
  assert.equal(parsedRequest.packet.incomplete, false);
  assert.deepEqual(parsedRequest.packet.issues, []);
  assert.deepEqual(parsedRequest.packet.message, {
    kind: "echoRequest",
    identifier: 0x1234,
    sequence: 1,
    data: Buffer.from("abc"),
  });

  const reply = encodeIcmpMessage({
    kind: "echoReply",
    identifier: 0x1234,
    sequence: 1,
    data: Uint8Array.of(0x61, 0x62, 0x63),
  });
  assert.deepEqual(
    reply,
    Buffer.from([
      0x00, 0x00, 0x29, 0x68, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63,
    ]),
  );
  assert.equal(parseIcmpMessage(reply).packet.message.kind, "echoReply");
});

test("copies mutable inputs and handles Echo payload boundaries", () => {
  for (const length of [0, 1, 2, 255, 65_507]) {
    const data = new Uint8Array(length);
    if (length > 0) data[length - 1] = 0xa5;
    const encoded = encodeIcmpMessage({
      kind: "echoRequest",
      identifier: 0,
      sequence: 0xffff,
      data,
    });
    assert.equal(encoded.byteLength, length + 8);
    const parsed = parseIcmpMessage(encoded);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.packet.message.kind, "echoRequest");
    assert.equal(parsed.packet.message.data.byteLength, length);
    if (length > 0) assert.equal(parsed.packet.message.data[length - 1], 0xa5);
  }

  const mutable = Uint8Array.of(1, 2, 3, 4);
  const encoded = encodeIcmpMessage({
    kind: "echoRequest",
    identifier: 7,
    sequence: 8,
    data: mutable,
  });
  mutable.fill(9);
  assert.deepEqual(encoded.subarray(8), Buffer.from([1, 2, 3, 4]));
  const parsed = parseIcmpMessage(encoded);
  encoded.fill(0);
  assert.deepEqual(parsed.packet.message.data, Buffer.from([1, 2, 3, 4]));

  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "echoRequest",
        identifier: 0,
        sequence: 0,
        data: new Uint8Array(65_508),
      }),
    { code: "ERR_INVALID_ARGUMENT", operation: "encodeIcmpMessage" },
  );
});

test("snapshots construction and parse-option getters once", () => {
  const constructionReads = new Map();
  const message = new Proxy(
    {
      kind: "echoRequest",
      identifier: 9,
      sequence: 10,
      data: Uint8Array.of(11),
    },
    {
      get(target, property, receiver) {
        constructionReads.set(
          property,
          (constructionReads.get(property) ?? 0) + 1,
        );
        return Reflect.get(target, property, receiver);
      },
    },
  );
  const encoded = encodeIcmpMessage(message);
  for (const property of ["kind", "identifier", "sequence", "data"]) {
    assert.equal(constructionReads.get(property), 1);
  }

  const optionReads = new Map();
  const options = new Proxy(
    { checksum: "require", conformance: "compatible" },
    {
      get(target, property, receiver) {
        optionReads.set(property, (optionReads.get(property) ?? 0) + 1);
        return Reflect.get(target, property, receiver);
      },
    },
  );
  assert.equal(parseIcmpMessage(encoded, options).ok, true);
  assert.equal(optionReads.get("checksum"), 1);
  assert.equal(optionReads.get("conformance"), 1);

  const disguisedOversized = new Uint8Array(65_536);
  Object.defineProperty(disguisedOversized, "byteLength", { value: 1 });
  assert.throws(() => computeInternetChecksum(disguisedOversized), {
    code: "ERR_INVALID_ARGUMENT",
  });
  const oversizedParse = parseIcmpMessage(disguisedOversized);
  assert.equal(oversizedParse.ok, false);
  assert.equal(oversizedParse.error.reason, "invalidLength");

  const disguisedEchoData = new Uint8Array(65_508);
  Object.defineProperty(disguisedEchoData, "byteLength", { value: 0 });
  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "echoRequest",
        identifier: 1,
        sequence: 2,
        data: disguisedEchoData,
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );
});

test("separates checksum policy, structural failure, and conformance issues", () => {
  const valid = encodeIcmpMessage({
    kind: "echoRequest",
    identifier: 1,
    sequence: 2,
  });
  const corrupt = Buffer.from(valid);
  corrupt[7] ^= 1;
  assert.deepEqual(parseIcmpMessage(corrupt), {
    ok: false,
    error: {
      reason: "invalidChecksum",
      message: "ICMP checksum is invalid",
      offset: 2,
    },
    checksumStatus: "invalid",
    issues: [],
  });
  const reported = parseIcmpMessage(corrupt, { checksum: "report" });
  assert.equal(reported.ok, true);
  assert.equal(reported.packet.checksumStatus, "invalid");
  assert.equal(
    validateIcmpMessage(corrupt, { checksum: "report" }).valid,
    false,
  );
  assert.equal(
    parseIcmpMessage(corrupt, { checksum: "ignore" }).packet.checksumStatus,
    "notChecked",
  );

  const wrongCode = Buffer.from(valid);
  wrongCode[1] = 9;
  wrongCode.writeUInt16BE(0, 2);
  wrongCode.writeUInt16BE(computeInternetChecksum(wrongCode), 2);
  const compatible = parseIcmpMessage(wrongCode);
  assert.equal(compatible.ok, true);
  assert.equal(compatible.packet.message.kind, "unknownCode");
  assert.equal(compatible.packet.issues[0].severity, "warning");
  assert.equal(validateIcmpMessage(wrongCode).valid, true);
  const canonical = validateIcmpMessage(wrongCode, {
    conformance: "canonical",
  });
  assert.equal(canonical.valid, false);
  assert.equal(canonical.issues[0].severity, "error");

  const unknown = Buffer.from([99, 7, 0, 0, 1, 2, 3]);
  unknown.writeUInt16BE(computeInternetChecksum(unknown), 2);
  const parsedUnknown = parseIcmpMessage(unknown);
  assert.equal(parsedUnknown.ok, true);
  assert.equal(parsedUnknown.packet.message.kind, "unknown");
  assert.deepEqual(parsedUnknown.packet.message.body, Buffer.from([1, 2, 3]));
  unknown.fill(0);
  assert.deepEqual(parsedUnknown.packet.message.body, Buffer.from([1, 2, 3]));
});

test("returns structured bounded results for short and arbitrary byte input", () => {
  for (let length = 0; length < 8; length += 1) {
    const bytes = new Uint8Array(length);
    if (length > 0) bytes[0] = ICMP_ECHO;
    const result = parseIcmpMessage(bytes, { checksum: "ignore" });
    assert.equal(result.ok, false);
    assert.equal(result.error.reason, "truncated");
  }

  let state = 0x1234_5678;
  for (let sample = 0; sample < 2_000; sample += 1) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    const length = state & 0xff;
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      bytes[index] = state & 0xff;
    }
    const result = parseIcmpMessage(bytes, { checksum: "ignore" });
    assert.equal(typeof result.ok, "boolean");
  }

  const oversized = parseIcmpMessage(new Uint8Array(65_516), {
    checksum: "ignore",
  });
  assert.equal(oversized.ok, false);
  assert.equal(oversized.error.reason, "invalidLength");
  assert.throws(() => parseIcmpMessage(new Uint8Array(), null), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "parseIcmpMessage",
  });
  assert.throws(
    () => parseIcmpMessage(new Uint8Array(), { checksum: "sometimes" }),
    { code: "ERR_INVALID_ARGUMENT" },
  );
});

test("adapts and cross-checks Linux IPv4 raw receive frames", () => {
  const icmp = encodeIcmpMessage({
    kind: "echoReply",
    identifier: 0x1111,
    sequence: 0x2222,
    data: Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd),
  });
  const frame = createIpv4Frame(icmp);
  const received = createReceivedMessage(frame);
  const parsed = parseIcmpReceivedMessage(received);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.incomplete, false);
  assert.equal(parsed.ipv4.sourceAddress, "127.0.0.1");
  assert.equal(parsed.ipv4.destinationAddress, "127.0.0.2");
  assert.equal(parsed.ipv4.checksumStatus, "valid");
  assert.equal(parsed.packet.message.kind, "echoReply");
  assert.equal(parsed.packet.message.identifier, 0x1111);
  assert.equal(
    matchesIcmpEchoReply(parsed, {
      identifier: 0x1111,
      sequence: 0x2222,
      expectedSourceAddress: "127.0.0.1",
      expectedDestinationAddress: "127.0.0.2",
      token: Uint8Array.of(0xaa, 0xbb),
    }),
    true,
  );
  assert.equal(
    matchesIcmpEchoReply(parsed, {
      identifier: 0x1111,
      sequence: 0x2222,
      token: Uint8Array.of(0xaa, 0xbc),
    }),
    false,
  );

  const mismatch = createReceivedMessage(frame);
  mismatch.ipv4 = { ...mismatch.ipv4, ttl: 63 };
  const mismatchResult = parseIcmpReceivedMessage(mismatch);
  assert.equal(mismatchResult.ok, false);
  assert.equal(mismatchResult.error.reason, "metadataMismatch");

  const corruptHeader = Buffer.from(frame);
  corruptHeader[8] ^= 1;
  const corruptResult = parseIcmpReceivedMessage(
    createReceivedMessage(corruptHeader, { ttl: 63 }),
  );
  assert.equal(corruptResult.ok, false);
  assert.equal(corruptResult.error.reason, "invalidIpv4Header");

  const withoutMetadata = createReceivedMessage(frame);
  withoutMetadata.ipv4 = undefined;
  assert.equal(
    parseIcmpReceivedMessage(withoutMetadata).error.reason,
    "invalidIpv4Header",
  );
});

test("reports captured ICMP prefixes as incomplete and unverifiable", () => {
  const icmp = encodeIcmpMessage({
    kind: "echoReply",
    identifier: 3,
    sequence: 4,
    data: new Uint8Array(32).fill(7),
  });
  const frame = createIpv4Frame(icmp);
  const received = createReceivedMessage(frame.subarray(0, 30));
  received.dataLength = frame.byteLength;
  received.dataTruncated = true;
  received.ipv4.totalLength = frame.byteLength;
  const parsed = parseIcmpReceivedMessage(received);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.incomplete, true);
  assert.equal(parsed.packet.incomplete, true);
  assert.equal(parsed.packet.checksumStatus, "unverifiable");
  assert.equal(parsed.packet.message.kind, "echoReply");
  assert.equal(parsed.packet.message.data.byteLength, 2);
  assert.equal(
    matchesIcmpEchoReply(parsed, { identifier: 3, sequence: 4 }),
    false,
  );
});

test("rejects local misuse of codecs and socket helpers with stable errors", () => {
  for (const message of [
    null,
    {},
    { kind: "other", identifier: 1, sequence: 1 },
    { kind: "echoRequest", identifier: -1, sequence: 1 },
    { kind: "echoRequest", identifier: Number.NaN, sequence: 1 },
    { kind: "echoRequest", identifier: Number.POSITIVE_INFINITY, sequence: 1 },
    { kind: "echoRequest", identifier: 1.5, sequence: 1 },
    { kind: "echoReply", identifier: 1, sequence: 65_536 },
    { kind: "echoRequest", identifier: 1, sequence: 1, data: "x" },
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

  const forged = new RawSocket();
  assert.throws(
    () =>
      sendIcmpMessage(
        forged,
        { kind: "echoRequest", identifier: 1, sequence: 1 },
        { destination: { family: "ipv4", address: "127.0.0.1" } },
      ),
    { code: "ERR_INVALID_ARGUMENT", operation: "sendIcmpMessage" },
  );
  assert.throws(() => receiveIcmpMessage(forged), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "receiveIcmpMessage",
  });
});

function createIpv4Frame(icmp) {
  const frame = Buffer.alloc(20 + icmp.byteLength);
  frame[0] = 0x45;
  frame[1] = 0x10;
  frame.writeUInt16BE(frame.byteLength, 2);
  frame.writeUInt16BE(0x3456, 4);
  frame.writeUInt16BE(0x4000, 6);
  frame[8] = 64;
  frame[9] = 1;
  frame.set([127, 0, 0, 1], 12);
  frame.set([127, 0, 0, 2], 16);
  frame.writeUInt16BE(testChecksum(frame.subarray(0, 20)), 10);
  icmp.copy(frame, 20);
  return frame;
}

function createReceivedMessage(data, overrides = {}) {
  return {
    data: Buffer.from(data),
    source: { family: "ipv4", address: "127.0.0.1" },
    dataLength: data.byteLength,
    dataTruncated: false,
    controlTruncated: false,
    flags: [],
    control: [],
    ipv4: {
      destinationAddress: "127.0.0.2",
      protocol: 1,
      ttl: overrides.ttl ?? 64,
      typeOfService: 0x10,
      headerLength: 20,
      totalLength: data.byteLength,
      identification: 0x3456,
      fragmentOffset: 0,
      dontFragment: true,
      moreFragments: false,
    },
    packetAuxdata: undefined,
  };
}

function testChecksum(data) {
  let sum = 0;
  for (let index = 0; index < data.byteLength; index += 2) {
    sum += (data[index] << 8) | (data[index + 1] ?? 0);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
}
