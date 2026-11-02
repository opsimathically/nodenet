import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import dgram from "node:dgram";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import {
  DISCOVERY_CAPABILITIES,
  DISCOVERY_OPERATIONS,
  ScannerError,
  createScanner,
} from "../dist/index.js";

test("discovery capabilities expose the checked registry and no-go ledger", () => {
  assert.equal(DISCOVERY_CAPABILITIES.schemaVersion, 1);
  assert.equal(DISCOVERY_CAPABILITIES.registryVersion, "1.1.0");
  assert.equal(DISCOVERY_CAPABILITIES.operations.length, 9);
  assert.equal(DISCOVERY_CAPABILITIES.maxSockets, 256);
  assert.equal(DISCOVERY_CAPABILITIES.maxPhysicalQueries, 1_024);
  assert.equal(DISCOVERY_OPERATIONS.mdnsDnsSdLegacy, 1);
  assert.equal(DISCOVERY_OPERATIONS.quicVersionNegotiation, 9);
  assert.equal(DISCOVERY_OPERATIONS.ripv1RoutingTable, 10);
  assert.equal(
    DISCOVERY_CAPABILITIES.operations.find((operation) => operation.id === 7)
      ?.supportsFollowUp,
    true,
  );
  assert.deepEqual(
    DISCOVERY_CAPABILITIES.operations.find((operation) => operation.id === 1)
      ?.receiveModes,
    ["legacyUnicast"],
  );
  assert.ok(DISCOVERY_CAPABILITIES.noGo.includes("kerberos"));
});

test("targeted NAT-PMP discovery sends, parses, and delivers a bounded entity", async (t) => {
  const responder = dgram.createSocket("udp4");
  t.after(() => responder.close());
  await new Promise((resolve, reject) => {
    responder.once("error", reject);
    responder.bind(5351, "127.0.0.1", resolve);
  });
  responder.on("message", (request, remote) => {
    assert.deepEqual(request, Buffer.from([0, 0]));
    responder.send(
      Buffer.from([0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7]),
      remote.port,
      remote.address,
    );
  });

  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.1/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "natPmpExternalAddress" }],
    allowRisks: ["sensitiveRead"],
    deadlineMs: 100,
  });
  const batch = await session.nextBatch();
  assert.equal(batch?.length, 1);
  const result = batch?.at(0);
  assert.equal(result?.protocol, "nat-pmp-external-address");
  assert.equal(result?.responderPort, 5351);
  assert.equal(result?.evidence, "Parsed");
  assert.equal(
    result?.metadata.find((field) => field.key === "externalAddress")?.text,
    "203.0.113.7",
  );
  assert.equal(await session.nextBatch(), null);
  const summary = await session.summary();
  assert.equal(summary.state, "completed");
  assert.equal(summary.results, 1n);
  assert.deepEqual(summary.receiveModes, []);
  assert.equal((await session.cancel()).state, "completed");
});

test("tokenless targeted discovery rejects a valid packet from the wrong source port", async (t) => {
  const listener = dgram.createSocket("udp4");
  const wrongPort = dgram.createSocket("udp4");
  t.after(() => listener.close());
  t.after(() => wrongPort.close());
  await Promise.all([
    new Promise((resolve, reject) => {
      listener.once("error", reject);
      listener.bind(5351, "127.0.0.1", resolve);
    }),
    new Promise((resolve, reject) => {
      wrongPort.once("error", reject);
      wrongPort.bind(0, "127.0.0.1", resolve);
    }),
  ]);
  listener.on("message", (_request, remote) => {
    wrongPort.send(
      Buffer.from([0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7]),
      remote.port,
      remote.address,
    );
  });
  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.1/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "natPmpExternalAddress" }],
    allowRisks: ["sensitiveRead"],
    deadlineMs: 50,
  });
  assert.equal(await session.nextBatch(), null);
  assert.equal((await session.progress()).rejected, 1n);
});

test("SQL Browser emits one endpoint and one bounded entity per instance", async (t) => {
  const responder = dgram.createSocket("udp4");
  t.after(() => responder.close());
  await new Promise((resolve, reject) => {
    responder.once("error", reject);
    responder.bind(1434, "127.0.0.1", resolve);
  });
  responder.on("message", (request, remote) => {
    assert.deepEqual(request, Buffer.from([2]));
    const body = Buffer.from(
      "ServerName;LAB;InstanceName;ONE;IsClustered;No;tcp;1433;;" +
        "ServerName;LAB;InstanceName;TWO;IsClustered;Yes;tcp;1434;;",
    );
    const response = Buffer.alloc(body.length + 3);
    response[0] = 5;
    response.writeUInt16LE(body.length, 1);
    body.copy(response, 3);
    responder.send(response, remote.port, remote.address);
  });

  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.1/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "sqlBrowserEnumeration" }],
    allowRisks: ["highAmplification", "sensitiveRead"],
    deadlineMs: 100,
  });
  const first = await session.nextBatch({ maxResults: 1 });
  const second = await session.nextBatch({ maxResults: 1 });
  const third = await session.nextBatch({ maxResults: 1 });
  assert.equal(first?.length, 1);
  assert.equal(second?.length, 1);
  assert.equal(third?.length, 1);
  assert.notDeepEqual(first?.at(0)?.identity, second?.at(0)?.identity);
  assert.equal(await session.nextBatch(), null);
  assert.equal((await session.summary()).results, 3n);
});

test("discovery event adapter drains every bounded batch before end", async (t) => {
  const responder = dgram.createSocket("udp4");
  t.after(() => responder.close());
  await new Promise((resolve, reject) => {
    responder.once("error", reject);
    responder.bind(1434, "127.0.0.1", resolve);
  });
  responder.on("message", (_request, remote) => {
    const body = Buffer.from(
      "ServerName;LAB;InstanceName;ONE;;" + "ServerName;LAB;InstanceName;TWO;;",
    );
    const response = Buffer.alloc(body.length + 3);
    response[0] = 5;
    response.writeUInt16LE(body.length, 1);
    body.copy(response, 3);
    responder.send(response, remote.port, remote.address);
  });
  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.1/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "sqlBrowserEnumeration" }],
    allowRisks: ["highAmplification", "sensitiveRead"],
    deadlineMs: 100,
  });
  const adapter = session.batches({ maxResults: 1 });
  let delivered = 0;
  const ended = new Promise((resolve, reject) => {
    adapter.on("batch", (batch) => {
      delivered += batch.length;
    });
    adapter.once("end", resolve);
    adapter.once("error", reject);
  });
  adapter.start();
  await ended;
  assert.equal(delivered, 3);
  await adapter.close();
});

test("hostile discovery plans fail before native network work", async (t) => {
  const scanner = await createScanner();
  t.after(() => scanner.close());
  await assert.rejects(
    scanner.startDiscovery({
      scope: {
        kind: "targets",
        targets: [{ cidr: "127.0.0.1/32" }],
        families: ["ipv4"],
      },
      operations: [
        // @ts-expect-error runtime validation intentionally receives hostile data
        { operation: "notAProtocol" },
      ],
      deadlineMs: 100,
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
});

test("discovery rejects descriptor fan-out above its advertised socket ceiling", async (t) => {
  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "192.0.2.0/23" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "quicVersionNegotiation" }],
    deadlineMs: 100,
  });
  await assert.rejects(
    session.nextBatch(),
    (error) => error instanceof ScannerError && error.kind === "resourceLimit",
  );
  const summary = await session.summary();
  assert.equal(summary.state, "failed");
  assert.equal(summary.results, 0n);
});

test("scan and discovery share the four-session native admission ceiling", async (t) => {
  const scanner = await createScanner();
  t.after(() => scanner.close());
  const plan = {
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.2/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "natPmpExternalAddress" }],
    allowRisks: ["sensitiveRead"],
    deadlineMs: 150,
  };
  const sessions = await Promise.all(
    Array.from({ length: 4 }, () => scanner.startDiscovery(plan)),
  );
  await assert.rejects(
    scanner.startDiscovery(plan),
    (error) => error instanceof ScannerError && error.kind === "resourceLimit",
  );
  await Promise.all(sessions.map((session) => session.close()));
});

test("discovery pause/resume/cancel cross the native send boundary", async (t) => {
  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.2/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "natPmpExternalAddress" }],
    allowRisks: ["sensitiveRead"],
    deadlineMs: 1_000,
  });
  await session.pause();
  assert.equal(session.state, "paused");
  await session.resume();
  assert.equal(session.state, "running");
  const progressStarted = performance.now();
  assert.ok((await session.progress()).queries <= 1n);
  assert.ok(performance.now() - progressStarted < 100);
  const started = performance.now();
  const summary = await session.cancel("bounded test cancellation");
  assert.equal(summary.state, "cancelled");
  assert.ok(performance.now() - started < 500);
  await session.close();
});

test("cancelled discovery retains accepted rows and authoritative counters", async (t) => {
  const responder = dgram.createSocket("udp4");
  t.after(() => responder.close());
  await new Promise((resolve, reject) => {
    responder.once("error", reject);
    responder.bind(1434, "127.0.0.1", resolve);
  });
  responder.on("message", (_request, remote) => {
    const body = Buffer.from("ServerName;LAB;InstanceName;CANCELLED;;");
    const response = Buffer.alloc(body.length + 3);
    response[0] = 5;
    response.writeUInt16LE(body.length, 1);
    body.copy(response, 3);
    responder.send(response, remote.port, remote.address);
  });

  const scanner = await createScanner();
  t.after(() => scanner.close());
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.1/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "sqlBrowserEnumeration" }],
    allowRisks: ["highAmplification", "sensitiveRead"],
    deadlineMs: 1_000,
  });
  for (let attempts = 0; attempts < 100; attempts += 1) {
    if ((await session.progress()).accepted === 2n) break;
    await delay(2);
  }
  assert.equal((await session.progress()).accepted, 2n);
  const summary = await session.cancel("retain accepted evidence");
  assert.equal(summary.state, "cancelled");
  assert.equal(summary.results, 2n);
  assert.equal(summary.progress.accepted, 2n);
  await session.close();
});

test("scanner close cancels and joins active discovery completions", async () => {
  const scanner = await createScanner();
  const session = await scanner.startDiscovery({
    scope: {
      kind: "targets",
      targets: [{ cidr: "127.0.0.2/32" }],
      families: ["ipv4"],
    },
    operations: [{ operation: "natPmpExternalAddress" }],
    allowRisks: ["sensitiveRead"],
    deadlineMs: 1_000,
  });
  const started = performance.now();
  await scanner.close();
  assert.ok(performance.now() - started < 500);
  assert.equal((await session.summary()).state, "cancelled");
  await session.close();
});
