import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { setImmediate } from "node:timers/promises";
import test from "node:test";

import {
  ICMP_FRAG_NEEDED,
  IPPROTO_ICMP,
  RawSocketError,
  classifyIcmpTracerouteResponse,
  createIcmpTracerouteProbe,
  encodeIcmpMessage,
  parseIcmpReceivedMessage,
} from "../dist/index.js";
import { traceIcmpRouteInternal } from "../dist/internal/traceroute.js";

const destination = { family: "ipv4", address: "198.51.100.9" };
const localAddress = "192.0.2.10";
const token = Buffer.from([0x54, 0x52, 0x43, 0x45]);

test("builds deterministic owned TTL-limited probes", () => {
  const mutableToken = Buffer.from(token);
  const mutablePayload = Buffer.from([1, 2, 3]);
  const probe = createIcmpTracerouteProbe({
    destination,
    identifier: 0x1234,
    sequence: 0xffff,
    token: mutableToken,
    payload: mutablePayload,
    ttl: 255,
    sentAt: 123n,
  });
  mutableToken.fill(0);
  mutablePayload.fill(0);
  assert.deepEqual(probe.destination, destination);
  assert.deepEqual(probe.token, token);
  assert.deepEqual(probe.payload, Buffer.from([1, 2, 3]));
  assert.deepEqual(probe.data, Buffer.concat([token, Buffer.from([1, 2, 3])]));
  assert.equal(probe.ttl, 255);
  assert.equal(probe.sentAt, 123n);

  const reads = new Map();
  const accessorOptions = {};
  for (const [name, value] of Object.entries({
    destination,
    identifier: 7,
    sequence: 8,
    token,
    payload: Buffer.from([9]),
    ttl: 10,
    sentAt: 11n,
  })) {
    Object.defineProperty(accessorOptions, name, {
      enumerable: true,
      get() {
        reads.set(name, (reads.get(name) ?? 0) + 1);
        return value;
      },
    });
  }
  const accessorProbe = createIcmpTracerouteProbe(accessorOptions);
  assert.equal(accessorProbe.identifier, 7);
  assert.deepEqual(
    Object.fromEntries(reads),
    Object.fromEntries([...reads.keys()].map((name) => [name, 1])),
  );

  const disguisedToken = new Uint8Array(65);
  Object.defineProperty(disguisedToken, "byteLength", { value: 1 });
  assert.throws(
    () =>
      createIcmpTracerouteProbe({
        destination,
        identifier: 1,
        sequence: 2,
        token: disguisedToken,
        ttl: 1,
        sentAt: 0n,
      }),
    { code: "ERR_INVALID_ARGUMENT" },
  );

  for (const options of [
    null,
    {
      destination,
      identifier: 1,
      sequence: 2,
      token: Buffer.alloc(0),
      ttl: 1,
      sentAt: 0n,
    },
    { destination, identifier: 1, sequence: 2, token, ttl: 0, sentAt: 0n },
    { destination, identifier: 1, sequence: 2, token, ttl: 1, sentAt: -1n },
    {
      destination: { family: "ipv4", address: "invalid" },
      identifier: 1,
      sequence: 2,
      token,
      ttl: 1,
      sentAt: 0n,
    },
    {
      destination,
      identifier: 0x1_0000,
      sequence: 2,
      token,
      ttl: 1,
      sentAt: 0n,
    },
    {
      destination,
      identifier: 1,
      sequence: 2,
      token: Buffer.alloc(65),
      ttl: 1,
      sentAt: 0n,
    },
    {
      destination,
      identifier: 1,
      sequence: 2,
      token,
      payload: Buffer.alloc(4097),
      ttl: 1,
      sentAt: 0n,
    },
  ]) {
    assert.throws(() => createIcmpTracerouteProbe(options), {
      code: "ERR_INVALID_ARGUMENT",
    });
  }
});

test("classifies direct replies and rejects unrelated or invalid local evidence", () => {
  const probe = makeProbe(7, 1_000n);
  const reply = parsedResponse(
    {
      kind: "echoReply",
      identifier: probe.identifier,
      sequence: probe.sequence,
      data: probe.data,
    },
    destination.address,
  );
  assert.deepEqual(classifyIcmpTracerouteResponse(probe, reply, 1_250n), {
    matched: true,
    kind: "destination",
    responderAddress: destination.address,
    roundTripNanoseconds: 250n,
    matchStrength: "strong",
  });

  const wrongToken = parsedResponse(
    {
      kind: "echoReply",
      identifier: probe.identifier,
      sequence: probe.sequence,
      data: Buffer.from([0, ...probe.data.subarray(1)]),
    },
    destination.address,
  );
  assert.deepEqual(classifyIcmpTracerouteResponse(probe, wrongToken, 1_250n), {
    matched: false,
  });
  const wrongSource = parsedResponse(
    {
      kind: "echoReply",
      identifier: probe.identifier,
      sequence: probe.sequence,
      data: probe.data,
    },
    "203.0.113.1",
  );
  assert.deepEqual(classifyIcmpTracerouteResponse(probe, wrongSource, 1_250n), {
    matched: false,
  });
  assert.deepEqual(
    classifyIcmpTracerouteResponse(probe, { ok: false }, 1_250n),
    { matched: false },
  );
  assert.throws(() => classifyIcmpTracerouteResponse(probe, reply, 999n), {
    code: "ERR_INVALID_ARGUMENT",
  });
});

test("classifies strong and historical weak quoted diagnostics", () => {
  const probe = makeProbe(9, 2_000n);
  const fullQuote = quotedProbe(probe, probe.data);
  const hop = parsedResponse(
    { kind: "timeExceeded", code: 0, quote: fullQuote },
    "203.0.113.1",
  );
  assert.deepEqual(classifyIcmpTracerouteResponse(probe, hop, 2_500n), {
    matched: true,
    kind: "hop",
    responderAddress: "203.0.113.1",
    roundTripNanoseconds: 500n,
    matchStrength: "strong",
  });

  const shortQuote = quotedProbe(probe, Buffer.alloc(0));
  const weakHop = parsedResponse(
    { kind: "timeExceeded", code: 0, quote: shortQuote },
    "203.0.113.2",
  );
  assert.equal(
    classifyIcmpTracerouteResponse(probe, weakHop, 2_600n).matchStrength,
    "weak",
  );

  const unreachable = parsedResponse(
    {
      kind: "destinationUnreachable",
      code: ICMP_FRAG_NEEDED,
      nextHopMtu: 1400,
      quote: fullQuote,
      extensions: [
        {
          classNumber: 250,
          cType: 7,
          data: Buffer.from([1, 2, 3, 4]),
        },
      ],
    },
    "203.0.113.3",
  );
  assert.deepEqual(classifyIcmpTracerouteResponse(probe, unreachable, 2_700n), {
    matched: true,
    kind: "unreachable",
    responderAddress: "203.0.113.3",
    roundTripNanoseconds: 700n,
    matchStrength: "strong",
    code: ICMP_FRAG_NEEDED,
    nextHopMtu: 1400,
    extensions: [{ classNumber: 250, cType: 7, dataLength: 4 }],
  });
  const oversizedExtensions = {
    ...unreachable,
    packet: {
      ...unreachable.packet,
      message: {
        ...unreachable.packet.message,
        extensions: {
          ...unreachable.packet.message.extensions,
          objects: Array.from({ length: 143 }, () => ({
            classNumber: 1,
            cType: 1,
            data: Buffer.alloc(0),
          })),
        },
      },
    },
  };
  assert.throws(
    () => classifyIcmpTracerouteResponse(probe, oversizedExtensions, 2_700n),
    { code: "ERR_INVALID_ARGUMENT" },
  );

  const parameter = parsedResponse(
    { kind: "parameterProblem", code: 0, pointer: 8, quote: fullQuote },
    "203.0.113.4",
  );
  assert.equal(
    classifyIcmpTracerouteResponse(probe, parameter, 2_800n).kind,
    "parameterProblem",
  );
  const weakParameter = parsedResponse(
    {
      kind: "parameterProblem",
      code: 0,
      pointer: 8,
      quote: shortQuote,
    },
    "203.0.113.4",
  );
  assert.deepEqual(
    classifyIcmpTracerouteResponse(probe, weakParameter, 2_800n),
    { matched: false },
  );
  const redirect = parsedResponse(
    {
      kind: "redirect",
      code: 1,
      gatewayAddress: "203.0.113.254",
      quote: fullQuote,
    },
    "203.0.113.5",
  );
  assert.equal(
    classifyIcmpTracerouteResponse(probe, redirect, 2_900n).kind,
    "redirect",
  );
  const fragmentTimeout = parsedResponse(
    { kind: "timeExceeded", code: 1, quote: fullQuote },
    "203.0.113.6",
  );
  assert.deepEqual(
    classifyIcmpTracerouteResponse(probe, fragmentTimeout, 3_000n),
    { matched: false },
  );
});

test("orchestrates reordered hops and detaches synchronously on destination", async () => {
  const harness = new FakeTracerouteHarness();
  const running = traceIcmpRouteInternal(normalizedOptions(), harness.driver);
  await flush();
  assert.equal(harness.sent.length, 3);

  harness.emit({ ok: false });
  const unrelatedProbe = makeProbe(0x3333, 0n);
  harness.emit(
    parsedResponse(
      {
        kind: "echoReply",
        identifier: unrelatedProbe.identifier,
        sequence: unrelatedProbe.sequence,
        data: unrelatedProbe.data,
      },
      destination.address,
    ),
  );

  harness.advanceTo(1_000_000n);
  for (const index of [2, 0, 1]) {
    const probe = harness.sent[index];
    const response = parsedResponse(
      {
        kind: "timeExceeded",
        code: 0,
        quote: quotedProbe(probe, probe.data),
      },
      `203.0.113.${String(index + 1)}`,
    );
    harness.emit(response);
    if (index === 2) harness.emit(response);
  }
  await flush();
  assert.equal(harness.sent.length, 6);

  harness.advanceTo(2_000_000n);
  const destinationProbe = harness.sent[4];
  harness.emit(
    parsedResponse(
      {
        kind: "echoReply",
        identifier: destinationProbe.identifier,
        sequence: destinationProbe.sequence,
        data: destinationProbe.data,
      },
      destination.address,
    ),
  );
  assert.equal(harness.attached, false);
  const result = await running;
  assert.equal(result.termination, "destination");
  assert.deepEqual(
    result.hops[0].probes.map((probe) => probe.ordinal),
    [0, 1, 2],
  );
  assert.deepEqual(
    result.hops[1].probes.map((probe) => probe.ordinal),
    [1],
  );
  assert.equal(result.ignoredResponses, 2);
  assert.equal(result.invalidResponses, 1);
  assert.equal(harness.detachCalls, 1);
});

test("makes exact probe and overall deadlines deterministic", async () => {
  const perProbe = new FakeTracerouteHarness();
  const probeRun = traceIcmpRouteInternal(
    normalizedOptions({
      maxHops: 1,
      probesPerHop: 1,
      maxInFlight: 1,
      timeoutNanoseconds: 5_000_000n,
      overallTimeoutNanoseconds: 100_000_000n,
      onProgress: ({ result }) => {
        result.hop = 99;
      },
    }),
    perProbe.driver,
  );
  await flush();
  perProbe.advanceTo(5_000_000n);
  const probeResult = await probeRun;
  assert.equal(probeResult.termination, "maxHops");
  assert.equal(probeResult.hops[0].probes[0].kind, "timeout");
  assert.equal(probeResult.hops[0].probes[0].hop, 1);
  assert.equal(probeResult.hops[0].probes[0].timeoutKind, "probe");

  const overall = new FakeTracerouteHarness();
  const overallRun = traceIcmpRouteInternal(
    normalizedOptions({
      probesPerHop: 2,
      maxInFlight: 2,
      overallTimeoutNanoseconds: 10_000_000n,
    }),
    overall.driver,
  );
  await flush();
  overall.advanceTo(10_000_000n);
  assert.equal(overall.attached, false);
  const overallResult = await overallRun;
  assert.equal(overallResult.termination, "overallTimeout");
  assert.deepEqual(
    overallResult.hops[0].probes.map((probe) => probe.timeoutKind),
    ["overall", "overall"],
  );
});

test("rejects cancellation, send failure, and callback failure after cleanup", async () => {
  const cancellation = new FakeTracerouteHarness();
  const controller = new globalThis.AbortController();
  const cancellationError = cancellation.abortError;
  const cancelled = traceIcmpRouteInternal(
    normalizedOptions({ signal: controller.signal }),
    cancellation.driver,
  );
  await flush();
  controller.abort();
  assert.equal(cancellation.attached, false);
  await assert.rejects(cancelled, (error) => error === cancellationError);
  assert.equal(cancellation.detachCalls, 1);

  const sendFailure = new FakeTracerouteHarness();
  const sendError = new Error("send failed");
  sendFailure.sendError = sendError;
  const failedSend = traceIcmpRouteInternal(
    normalizedOptions(),
    sendFailure.driver,
  );
  await assert.rejects(failedSend, (error) => error === sendError);
  assert.equal(sendFailure.attached, false);

  const callbackFailure = new FakeTracerouteHarness();
  const callbackError = new Error("progress failed");
  const failedCallback = traceIcmpRouteInternal(
    normalizedOptions({
      maxHops: 1,
      probesPerHop: 1,
      maxInFlight: 1,
      timeoutNanoseconds: 1_000_000n,
      onProgress: () => {
        throw callbackError;
      },
    }),
    callbackFailure.driver,
  );
  await flush();
  callbackFailure.advanceTo(1_000_000n);
  await assert.rejects(failedCallback, (error) => error === callbackError);
  assert.equal(callbackFailure.attached, false);

  const overallCallbackFailure = new FakeTracerouteHarness();
  const overallCallbackError = new Error("overall progress failed");
  let overallCallbackCalls = 0;
  const failedOverallCallback = traceIcmpRouteInternal(
    normalizedOptions({
      probesPerHop: 2,
      maxInFlight: 2,
      overallTimeoutNanoseconds: 1_000_000n,
      onProgress: () => {
        overallCallbackCalls += 1;
        throw overallCallbackError;
      },
    }),
    overallCallbackFailure.driver,
  );
  await flush();
  overallCallbackFailure.advanceTo(1_000_000n);
  await assert.rejects(
    failedOverallCallback,
    (error) => error === overallCallbackError,
  );
  assert.equal(overallCallbackCalls, 1);
  assert.equal(overallCallbackFailure.attached, false);
});

test("continues after configured unreachable and preserves the first terminal outcome", async () => {
  const continuing = new FakeTracerouteHarness();
  const continuingRun = traceIcmpRouteInternal(
    normalizedOptions({
      probesPerHop: 1,
      maxInFlight: 1,
      stopOnUnreachable: false,
    }),
    continuing.driver,
  );
  await flush();
  const first = continuing.sent[0];
  continuing.advanceTo(1_000_000n);
  continuing.emit(
    parsedResponse(
      {
        kind: "destinationUnreachable",
        code: 1,
        quote: quotedProbe(first, first.data),
      },
      "203.0.113.1",
    ),
  );
  await flush();
  const second = continuing.sent[1];
  continuing.advanceTo(2_000_000n);
  continuing.emit(
    parsedResponse(
      {
        kind: "echoReply",
        identifier: second.identifier,
        sequence: second.sequence,
        data: second.data,
      },
      destination.address,
    ),
  );
  const continuedResult = await continuingRun;
  assert.equal(continuedResult.termination, "destination");
  assert.deepEqual(
    continuedResult.hops.flatMap((hop) =>
      hop.probes.map((probe) => probe.kind),
    ),
    ["unreachable", "destination"],
  );

  const firstTerminal = new FakeTracerouteHarness();
  const controller = new globalThis.AbortController();
  let releaseDetach;
  firstTerminal.detachPromise = new Promise((resolve) => {
    releaseDetach = resolve;
  });
  const firstTerminalRun = traceIcmpRouteInternal(
    normalizedOptions({
      probesPerHop: 1,
      maxInFlight: 1,
      signal: controller.signal,
    }),
    firstTerminal.driver,
  );
  await flush();
  const terminalProbe = firstTerminal.sent[0];
  firstTerminal.emit(
    parsedResponse(
      {
        kind: "echoReply",
        identifier: terminalProbe.identifier,
        sequence: terminalProbe.sequence,
        data: terminalProbe.data,
      },
      destination.address,
    ),
  );
  controller.abort();
  releaseDetach();
  assert.equal((await firstTerminalRun).termination, "destination");
});

test("turns source close and detach failure into cleanup-ordered rejection", async () => {
  const closed = new FakeTracerouteHarness();
  const closedRun = traceIcmpRouteInternal(normalizedOptions(), closed.driver);
  await flush();
  closed.callbacks.close();
  await assert.rejects(closedRun, (error) => error === closed.socketError);
  assert.equal(closed.attached, false);

  const detachFailure = new FakeTracerouteHarness();
  detachFailure.detachError = new Error("detach failed");
  const detachRun = traceIcmpRouteInternal(
    normalizedOptions({
      maxHops: 1,
      probesPerHop: 1,
      maxInFlight: 1,
      timeoutNanoseconds: 1_000_000n,
    }),
    detachFailure.driver,
  );
  await flush();
  detachFailure.advanceTo(1_000_000n);
  await assert.rejects(
    detachRun,
    (error) => error === detachFailure.detachError,
  );
});

test("retains exactly the bounded 2550-result maximum", async () => {
  const harness = new FakeTracerouteHarness();
  const running = traceIcmpRouteInternal(
    normalizedOptions({
      maxHops: 255,
      probesPerHop: 10,
      maxInFlight: 10,
      timeoutNanoseconds: 1_000_000n,
      overallTimeoutNanoseconds: 1_000_000_000n,
    }),
    harness.driver,
  );
  await flush();
  for (let hop = 1; hop <= 255; hop += 1) {
    harness.advanceTo(BigInt(hop) * 1_000_000n);
    await flush();
  }
  const result = await running;
  const probes = result.hops.flatMap((hop) => hop.probes);
  assert.equal(result.termination, "maxHops");
  assert.equal(result.hops.length, 255);
  assert.equal(probes.length, 2_550);
  assert.equal(new Set(probes.map((probe) => probe.sequence)).size, 2_550);
});

function makeProbe(sequence, sentAt) {
  return createIcmpTracerouteProbe({
    destination,
    identifier: 0x5152,
    sequence,
    token,
    payload: Buffer.from([0xaa, 0xbb]),
    ttl: 1,
    sentAt,
  });
}

function quotedProbe(probe, data) {
  return ipv4Packet(
    encodeIcmpMessage({
      kind: "echoRequest",
      identifier: probe.identifier,
      sequence: probe.sequence,
      data,
    }),
    localAddress,
    destination.address,
    probe.ttl,
  );
}

function parsedResponse(message, sourceAddress) {
  const frame = ipv4Packet(
    encodeIcmpMessage(message),
    sourceAddress,
    localAddress,
    64,
  );
  return parseIcmpReceivedMessage({
    data: frame,
    source: { family: "ipv4", address: sourceAddress },
    dataLength: frame.byteLength,
    dataTruncated: false,
    controlTruncated: false,
    flags: [],
    control: [],
    ipv4: {
      destinationAddress: localAddress,
      protocol: IPPROTO_ICMP,
      ttl: 64,
      typeOfService: 0,
      headerLength: 20,
      totalLength: frame.byteLength,
      identification: 0x4242,
      fragmentOffset: 0,
      dontFragment: false,
      moreFragments: false,
    },
    packetAuxdata: undefined,
  });
}

function ipv4Packet(payload, sourceAddress, destinationAddress, ttl) {
  const packet = Buffer.alloc(20 + payload.byteLength);
  packet[0] = 0x45;
  packet.writeUInt16BE(packet.byteLength, 2);
  packet.writeUInt16BE(0x4242, 4);
  packet[8] = ttl;
  packet[9] = IPPROTO_ICMP;
  writeIpv4(packet, 12, sourceAddress);
  writeIpv4(packet, 16, destinationAddress);
  packet.writeUInt16BE(testChecksum(packet.subarray(0, 20)), 10);
  payload.copy(packet, 20);
  return packet;
}

function writeIpv4(buffer, offset, address) {
  buffer.set(address.split(".").map(Number), offset);
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

function normalizedOptions(overrides = {}) {
  return {
    destination,
    firstHop: 1,
    maxHops: 2,
    probesPerHop: 3,
    timeoutNanoseconds: 100_000_000n,
    overallTimeoutNanoseconds: 1_000_000_000n,
    payload: Buffer.from([0xaa]),
    token,
    identifier: 0x5152,
    initialSequence: 0xfffe,
    maxInFlight: 3,
    stopOnUnreachable: true,
    signal: undefined,
    onProgress: undefined,
    ...overrides,
  };
}

class FakeTracerouteHarness {
  now = 0n;
  sent = [];
  timers = new Map();
  nextTimer = 1;
  callbacks;
  attached = false;
  detachCalls = 0;
  abortError = new RawSocketError({
    kind: "aborted",
    code: "ERR_ABORTED",
    operation: "traceIcmpRoute",
    message: "aborted",
  });
  socketError = new Error("socket closed");
  sendError;
  detachError;
  detachPromise;

  driver = {
    now: () => this.now,
    send: async (probe) => {
      this.sent.push(probe);
      if (this.sendError !== undefined) throw this.sendError;
    },
    attach: (callbacks) => {
      if (this.attached) throw new Error("lane already claimed");
      this.callbacks = callbacks;
      this.attached = true;
      return {
        start: () => {
          assert.equal(this.attached, true);
        },
        detach: async () => {
          this.detachCalls += 1;
          this.attached = false;
          if (this.detachError !== undefined) throw this.detachError;
          if (this.detachPromise !== undefined) await this.detachPromise;
        },
      };
    },
    setTimer: (callback, milliseconds) => {
      const id = this.nextTimer;
      this.nextTimer += 1;
      this.timers.set(id, {
        at: this.now + BigInt(milliseconds) * 1_000_000n,
        callback,
      });
      return id;
    },
    clearTimer: (timer) => {
      this.timers.delete(timer);
    },
    abortedError: () => this.abortError,
    socketClosedError: () => this.socketError,
  };

  emit(received) {
    assert.equal(this.attached, true);
    this.callbacks.message(received);
  }

  advanceTo(now) {
    assert.ok(now >= this.now);
    this.now = now;
    for (;;) {
      const due = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= now)
        .sort((left, right) => (left[1].at < right[1].at ? -1 : 1))[0];
      if (due === undefined) return;
      this.timers.delete(due[0]);
      due[1].callback();
    }
  }
}

async function flush() {
  await setImmediate();
  await setImmediate();
}
