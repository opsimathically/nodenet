import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  ICMP_ADDRESS,
  ICMP_ADDRESSREPLY,
  ICMP_ROUTERADVERT,
  ICMP_ROUTERSOLICIT,
  ICMP_TIMESTAMP,
  ICMP_TIMESTAMPREPLY,
  RawSocketError,
  classifyIcmpTimestamp,
  createIcmpTimestampReply,
  encodeIcmpMessage,
  inspectIpv4AddressMask,
  parseIcmpMessage,
  validateIcmpMessage,
} from "../dist/index.js";

test("encodes and parses canonical Router Solicitation fields", () => {
  const encoded = encodeIcmpMessage({ kind: "routerSolicitation" });
  assert.deepEqual(encoded.subarray(0, 2), Buffer.from([10, 0]));
  assert.equal(encoded.byteLength, 8);
  assert.equal(encoded.readUInt32BE(4), 0);
  assert.equal(testChecksum(encoded), 0);

  const parsed = parseIcmpMessage(encoded);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.packet.message.kind, "routerSolicitation");
  assert.equal(parsed.packet.message.reserved, 0);
  assert.deepEqual(parsed.packet.message.trailingData, Buffer.alloc(0));

  const compatibleBytes = Buffer.concat([encoded, Buffer.from([1, 2, 3])]);
  compatibleBytes.writeUInt32BE(0x0102_0304, 4);
  rewriteIcmpChecksum(compatibleBytes);
  const compatible = parseIcmpMessage(compatibleBytes);
  assert.equal(compatible.ok, true);
  assert.equal(compatible.packet.message.reserved, 0x0102_0304);
  assert.deepEqual(
    compatible.packet.message.trailingData,
    Buffer.from([1, 2, 3]),
  );
  assert.equal(validateIcmpMessage(compatibleBytes).valid, true);
  assert.equal(
    validateIcmpMessage(compatibleBytes, { conformance: "canonical" }).valid,
    false,
  );

  for (let length = 4; length < 8; length += 1) {
    const short = Buffer.alloc(length);
    short[0] = ICMP_ROUTERSOLICIT;
    rewriteIcmpChecksum(short);
    assert.equal(parseIcmpMessage(short).ok, false);
  }
});

test("round-trips Router Advertisements and signed preference extremes", () => {
  const encoded = encodeIcmpMessage({
    kind: "routerAdvertisement",
    lifetime: 0xffff,
    addresses: [
      { address: "192.0.2.1", preference: -0x8000_0000 },
      { address: "198.51.100.2", preference: 0x7fff_ffff },
    ],
  });
  assert.equal(encoded[0], ICMP_ROUTERADVERT);
  assert.equal(encoded[4], 2);
  assert.equal(encoded[5], 2);
  assert.equal(encoded.readUInt16BE(6), 0xffff);
  assert.deepEqual(encoded.subarray(8, 12), Buffer.from([192, 0, 2, 1]));
  assert.equal(encoded.readInt32BE(12), -0x8000_0000);
  assert.equal(testChecksum(encoded), 0);

  const message = parseIcmpMessage(encoded).packet.message;
  assert.equal(message.kind, "routerAdvertisement");
  assert.equal(message.numberOfAddresses, 2);
  assert.equal(message.addressEntrySizeWords, 2);
  assert.equal(message.lifetime, 0xffff);
  assert.deepEqual(message.addresses, [
    {
      address: "192.0.2.1",
      preference: -0x8000_0000,
      defaultEligible: false,
      extensionWords: [],
    },
    {
      address: "198.51.100.2",
      preference: 0x7fff_ffff,
      defaultEligible: true,
      extensionWords: [],
    },
  ]);
});

test("bounds Router Advertisement counts and preserves extension words", () => {
  const extended = Buffer.alloc(8 + 16 + 3);
  extended[0] = ICMP_ROUTERADVERT;
  extended[4] = 1;
  extended[5] = 4;
  extended.writeUInt16BE(1800, 6);
  extended.set([203, 0, 113, 9], 8);
  extended.writeInt32BE(-7, 12);
  extended.writeUInt32BE(0x0102_0304, 16);
  extended.writeUInt32BE(0xfefd_fc00, 20);
  extended.set([9, 8, 7], 24);
  rewriteIcmpChecksum(extended);
  const parsed = parseIcmpMessage(extended);
  assert.equal(parsed.ok, true);
  assert.deepEqual(
    parsed.packet.message.addresses[0].extensionWords,
    [0x0102_0304, 0xfefd_fc00],
  );
  assert.deepEqual(parsed.packet.message.trailingData, Buffer.from([9, 8, 7]));
  assert.equal(validateIcmpMessage(extended).valid, true);
  assert.equal(
    validateIcmpMessage(extended, { conformance: "canonical" }).valid,
    false,
  );
  extended.fill(0);
  assert.deepEqual(
    parsed.packet.message.addresses[0].extensionWords,
    [0x0102_0304, 0xfefd_fc00],
  );
  assert.deepEqual(parsed.packet.message.trailingData, Buffer.from([9, 8, 7]));

  const entries = Array.from({ length: 255 }, (_, index) => ({
    address: `192.0.2.${String((index % 254) + 1)}`,
    preference: index - 127,
  }));
  const maximum = encodeIcmpMessage({
    kind: "routerAdvertisement",
    lifetime: 0,
    addresses: entries,
  });
  assert.equal(maximum.byteLength, 8 + 255 * 8);
  assert.equal(parseIcmpMessage(maximum).packet.message.addresses.length, 255);

  for (const [count, size, expectedReason] of [
    [0, 2, "unsupportedStructure"],
    [1, 1, "unsupportedStructure"],
    [2, 2, "truncated"],
  ]) {
    const malformed = Buffer.alloc(16);
    malformed[0] = ICMP_ROUTERADVERT;
    malformed[4] = count;
    malformed[5] = size;
    rewriteIcmpChecksum(malformed);
    const result = parseIcmpMessage(malformed);
    assert.equal(result.ok, false);
    assert.equal(result.error.reason, expectedReason);
  }

  const maximumDeclaredShape = Buffer.alloc(8);
  maximumDeclaredShape[0] = ICMP_ROUTERADVERT;
  maximumDeclaredShape[4] = 0xff;
  maximumDeclaredShape[5] = 0xff;
  rewriteIcmpChecksum(maximumDeclaredShape);
  const maximumDeclaredResult = parseIcmpMessage(maximumDeclaredShape);
  assert.equal(maximumDeclaredResult.ok, false);
  assert.equal(maximumDeclaredResult.error.reason, "truncated");
  assert.equal(maximumDeclaredResult.error.requiredLength, 8 + 255 * 255 * 4);
});

test("snapshots Router Advertisement array length before allocation", () => {
  let lengthReads = 0;
  const addresses = new Proxy([{ address: "192.0.2.1", preference: 0 }], {
    get(target, property, receiver) {
      if (property === "length") {
        lengthReads += 1;
        return lengthReads === 1 ? 1 : 255;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const encoded = encodeIcmpMessage({
    kind: "routerAdvertisement",
    lifetime: 1,
    addresses,
  });
  assert.equal(lengthReads, 1);
  assert.equal(encoded.byteLength, 16);
});

test("classifies and round-trips every Timestamp semantic range", () => {
  assert.deepEqual(classifyIcmpTimestamp(0), {
    raw: 0,
    classification: "standard",
  });
  assert.equal(classifyIcmpTimestamp(86_399_999).classification, "standard");
  assert.equal(
    classifyIcmpTimestamp(86_400_000).classification,
    "invalidStandardRange",
  );
  assert.equal(
    classifyIcmpTimestamp(0x7fff_ffff).classification,
    "invalidStandardRange",
  );
  assert.equal(
    classifyIcmpTimestamp(0x8000_0000).classification,
    "nonStandard",
  );
  assert.equal(
    classifyIcmpTimestamp(0xffff_ffff).classification,
    "nonStandard",
  );

  const nonStandardRequest = parseIcmpMessage(
    encodeIcmpMessage({
      kind: "timestampRequest",
      identifier: 0,
      sequence: 0xffff,
      originateTimestamp: 0xffff_ffff,
    }),
  ).packet.message;
  assert.equal(nonStandardRequest.identifier, 0);
  assert.equal(nonStandardRequest.sequence, 0xffff);
  assert.equal(
    nonStandardRequest.originateTimestamp.classification,
    "nonStandard",
  );

  const request = encodeIcmpMessage({
    kind: "timestampRequest",
    identifier: 0x1234,
    sequence: 0x5678,
    originateTimestamp: 86_399_999,
  });
  assert.equal(request[0], ICMP_TIMESTAMP);
  assert.equal(request.byteLength, 20);
  assert.equal(request.readUInt32BE(12), 0);
  assert.equal(request.readUInt32BE(16), 0);
  const parsedRequest = parseIcmpMessage(request).packet.message;
  assert.equal(parsedRequest.kind, "timestampRequest");

  const replyValue = createIcmpTimestampReply(parsedRequest, {
    receiveTimestamp: 0x8000_0001,
    transmitTimestamp: 12_345,
  });
  const reply = encodeIcmpMessage(replyValue);
  assert.equal(reply[0], ICMP_TIMESTAMPREPLY);
  const parsedReply = parseIcmpMessage(reply).packet.message;
  assert.equal(parsedReply.kind, "timestampReply");
  assert.equal(parsedReply.identifier, 0x1234);
  assert.equal(parsedReply.sequence, 0x5678);
  assert.deepEqual(parsedReply.originateTimestamp, {
    raw: 86_399_999,
    classification: "standard",
  });
  assert.deepEqual(parsedReply.receiveTimestamp, {
    raw: 0x8000_0001,
    classification: "nonStandard",
  });
});

test("preserves noncanonical Timestamp fields and trailing bytes", () => {
  const packet = Buffer.alloc(22);
  packet[0] = ICMP_TIMESTAMP;
  packet.writeUInt16BE(1, 4);
  packet.writeUInt16BE(2, 6);
  packet.writeUInt32BE(86_400_000, 8);
  packet.writeUInt32BE(1, 12);
  packet.writeUInt32BE(2, 16);
  packet.set([0xaa, 0xbb], 20);
  rewriteIcmpChecksum(packet);
  const parsed = parseIcmpMessage(packet);
  assert.equal(parsed.ok, true);
  assert.equal(
    parsed.packet.message.originateTimestamp.classification,
    "invalidStandardRange",
  );
  assert.deepEqual(
    parsed.packet.message.trailingData,
    Buffer.from([0xaa, 0xbb]),
  );
  assert.equal(validateIcmpMessage(packet).valid, true);
  assert.equal(
    validateIcmpMessage(packet, { conformance: "canonical" }).valid,
    false,
  );

  for (let length = 4; length < 20; length += 1) {
    const short = Buffer.alloc(length);
    short[0] = ICMP_TIMESTAMPREPLY;
    rewriteIcmpChecksum(short);
    assert.equal(parseIcmpMessage(short).ok, false);
  }
});

test("encodes deprecated Address Mask messages and inspects masks", () => {
  const request = encodeIcmpMessage({
    kind: "addressMaskRequest",
    identifier: 9,
    sequence: 10,
  });
  assert.equal(request[0], ICMP_ADDRESS);
  assert.equal(request.byteLength, 12);
  assert.equal(request.readUInt32BE(8), 0);

  const reply = encodeIcmpMessage({
    kind: "addressMaskReply",
    identifier: 9,
    sequence: 10,
    mask: "255.255.255.0",
  });
  assert.equal(reply[0], ICMP_ADDRESSREPLY);
  const message = parseIcmpMessage(reply).packet.message;
  assert.equal(message.kind, "addressMaskReply");
  assert.deepEqual(message.mask, {
    address: "255.255.255.0",
    bytes: Buffer.from([255, 255, 255, 0]),
    contiguous: true,
    prefixLength: 24,
  });
  reply.fill(0);
  assert.deepEqual(message.mask.bytes, Buffer.from([255, 255, 255, 0]));

  for (const [mask, contiguous, prefixLength] of [
    ["0.0.0.0", true, 0],
    ["255.255.255.255", true, 32],
    ["255.240.0.0", true, 12],
    ["255.0.255.0", false, undefined],
  ]) {
    const info = inspectIpv4AddressMask(mask);
    assert.equal(info.contiguous, contiguous);
    assert.equal(info.prefixLength, prefixLength);
  }

  for (let length = 4; length < 12; length += 1) {
    const short = Buffer.alloc(length);
    short[0] = ICMP_ADDRESSREPLY;
    rewriteIcmpChecksum(short);
    assert.equal(parseIcmpMessage(short).ok, false);
  }
});

test("preserves noncanonical Address Mask requests and unknown codes", () => {
  const packet = Buffer.alloc(14);
  packet[0] = ICMP_ADDRESS;
  packet.writeUInt16BE(1, 4);
  packet.writeUInt16BE(2, 6);
  packet.set([255, 0, 255, 0], 8);
  packet.set([3, 4], 12);
  rewriteIcmpChecksum(packet);
  const parsed = parseIcmpMessage(packet);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.packet.message.mask.contiguous, false);
  assert.deepEqual(parsed.packet.message.trailingData, Buffer.from([3, 4]));
  assert.equal(validateIcmpMessage(packet).valid, true);
  assert.equal(
    validateIcmpMessage(packet, { conformance: "canonical" }).valid,
    false,
  );

  for (const type of [
    ICMP_ROUTERADVERT,
    ICMP_ROUTERSOLICIT,
    ICMP_TIMESTAMP,
    ICMP_TIMESTAMPREPLY,
    ICMP_ADDRESS,
    ICMP_ADDRESSREPLY,
  ]) {
    const unknown = Buffer.alloc(8);
    unknown[0] = type;
    unknown[1] = type === ICMP_ROUTERADVERT ? 16 : 1;
    rewriteIcmpChecksum(unknown);
    assert.equal(parseIcmpMessage(unknown).packet.message.kind, "unknownCode");
  }
});

test("rejects unsafe local informational construction", () => {
  const invalidAddressCount = new Proxy([], {
    get(target, property, receiver) {
      if (property === "length") return 1.5;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () =>
      encodeIcmpMessage({
        kind: "routerAdvertisement",
        lifetime: 1,
        addresses: invalidAddressCount,
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );

  for (const message of [
    { kind: "routerSolicitation", reserved: 1 },
    { kind: "routerAdvertisement", lifetime: 1, addresses: [] },
    {
      kind: "routerAdvertisement",
      lifetime: 1,
      addresses: Array.from({ length: 256 }, () => ({
        address: "192.0.2.1",
        preference: 0,
      })),
    },
    {
      kind: "routerAdvertisement",
      lifetime: 0x1_0000,
      addresses: [{ address: "192.0.2.1", preference: 0 }],
    },
    {
      kind: "routerAdvertisement",
      lifetime: 1,
      addresses: [{ address: "invalid", preference: 0 }],
    },
    {
      kind: "routerAdvertisement",
      lifetime: 1,
      addresses: [{ address: "192.0.2.1", preference: 0x8000_0000 }],
    },
    {
      kind: "routerAdvertisement",
      lifetime: 1,
      addresses: [{ address: "192.0.2.1", preference: -0x8000_0001 }],
    },
    {
      kind: "timestampRequest",
      identifier: 1,
      sequence: 2,
      originateTimestamp: 86_400_000,
    },
    {
      kind: "timestampRequest",
      identifier: 1,
      sequence: 2,
      originateTimestamp: 1,
      receiveTimestamp: 1,
    },
    {
      kind: "timestampReply",
      identifier: 1,
      sequence: 2,
      originateTimestamp: 1,
      receiveTimestamp: -1,
      transmitTimestamp: 2,
    },
    { kind: "addressMaskRequest", identifier: 1, sequence: 2, mask: "0.0.0.0" },
    {
      kind: "addressMaskReply",
      identifier: 1,
      sequence: 2,
      mask: "not-a-mask",
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
  assert.throws(() => classifyIcmpTimestamp(0x1_0000_0000), {
    code: "ERR_INVALID_ARGUMENT",
  });
  assert.throws(() => classifyIcmpTimestamp(Number.NaN), {
    code: "ERR_INVALID_ARGUMENT",
  });
  assert.throws(() => inspectIpv4AddressMask("invalid"), {
    code: "ERR_INVALID_ARGUMENT",
  });
});

function rewriteIcmpChecksum(data) {
  data.writeUInt16BE(0, 2);
  data.writeUInt16BE(testChecksum(data), 2);
}

function testChecksum(data) {
  let sum = 0;
  for (let offset = 0; offset < data.byteLength; offset += 2) {
    sum +=
      ((data[offset] ?? 0) << 8) |
      (offset + 1 < data.byteLength ? (data[offset + 1] ?? 0) : 0);
    while (sum > 0xffff) sum = (sum & 0xffff) + Math.floor(sum / 0x1_0000);
  }
  return 0xffff - sum;
}
