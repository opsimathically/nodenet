import assert from "node:assert/strict";
import test from "node:test";

import {
  Scanner,
  ScannerError,
  createScanner,
  inspectNetworkContext,
} from "../dist/index.js";

test("concurrent observation and scanner closure releases an id exactly once", async () => {
  const closed = [];
  let finishNativeClose = () => undefined;
  const run = {
    state: "completed",
    interfaces: ["lo"],
    protocols: ["arp"],
    promiscuous: false,
    includeOutgoing: false,
    progress: {
      framesSeen: 0,
      framesAccepted: 0,
      resultsRetained: 0,
      resultsDropped: 0,
      metadataBytes: 0,
    },
  };
  const handle = {
    observe(_plan, _id, callback) {
      void Promise.resolve().then(() => callback({ run }));
    },
    readyObservation() {
      return Promise.resolve();
    },
    closeObservation(id) {
      closed.push(id);
    },
    close() {
      return new Promise((resolve) => {
        finishNativeClose = resolve;
      });
    },
  };
  const scanner = new Scanner(handle);
  const observation = await scanner.startObservation({
    interfaces: ["lo"],
    protocols: ["arp"],
    durationMs: 1,
    allowRisks: ["passiveMetadata"],
  });

  const scannerClose = scanner.close();
  const observationClose = observation.close();
  finishNativeClose();
  await Promise.all([scannerClose, observationClose]);
  assert.deepEqual(closed, [1]);
});

test("observation readiness failure releases scanner ownership", async () => {
  const closed = [];
  const expected = new Error("readiness failed");
  const handle = {
    observe(_plan, _id, callback) {
      callback({
        run: {
          state: "completed",
          interfaces: ["lo"],
          protocols: ["arp"],
          promiscuous: false,
          includeOutgoing: false,
          progress: {},
        },
      });
    },
    readyObservation() {
      return Promise.reject(expected);
    },
    closeObservation(id) {
      closed.push(id);
    },
    close() {
      return Promise.resolve();
    },
  };
  const scanner = new Scanner(handle);

  await assert.rejects(
    scanner.startObservation({
      interfaces: ["lo"],
      protocols: ["arp"],
      durationMs: 1,
      allowRisks: ["passiveMetadata"],
    }),
    (error) =>
      error instanceof ScannerError && error.message === expected.message,
  );
  await scanner.close();
  assert.deepEqual(closed, [1]);
});

test("read-only context inspection works without raw-socket setup", async () => {
  const snapshot = await inspectNetworkContext();
  assert.equal(typeof snapshot.generation, "bigint");
  assert.ok(snapshot.interfaces.length > 0);
  assert.ok(
    snapshot.interfaces.every(
      (item) => item.hardwareAddress instanceof Uint8Array,
    ),
  );
});

test("createScanner is capability-free and invalid plans fail before raw sockets", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({ targets: [], probes: [], deadlineMs: 1_000 }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await assert.rejects(
    scanner.solicitRouters({
      interface: "lo",
      deadlineMs: 1,
      allowRisks: [],
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await assert.rejects(
    scanner.tracePath({
      target: "not-an-address",
      mode: "udp",
      port: 33434,
      deadlineMs: 1_000,
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await scanner.close();
  await scanner.close();
});

test("environment scanner admission is bounded independently of raw authority", async () => {
  const scanners = await Promise.all(
    Array.from({ length: 4 }, () => createScanner()),
  );
  await assert.rejects(
    createScanner(),
    (error) => error instanceof ScannerError && error.kind === "resourceLimit",
  );
  await Promise.all(scanners.map((scanner) => scanner.close()));
});

test("valid start either opens a session or preserves Linux permission context", async () => {
  const scanner = await createScanner();
  try {
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [{ kind: "icmpEcho", family: "ipv4" }],
      deadlineMs: 1_000,
      timing: { timeoutMs: 100, retries: 0 },
      rate: { packetsPerSecond: 10, burst: 1, maxOutstanding: 1 },
    });
    await session.cancel();
    await session.close();
  } catch (error) {
    assert.ok(error instanceof ScannerError);
    assert.equal(error.kind, "permission");
    assert.equal(error.code, "ERR_PERMISSION");
    assert.equal(typeof error.operation, "string");
    assert.equal(typeof error.errno, "number");
  } finally {
    await scanner.close();
  }
});

test("scanner control commands enforce the independent 4 MiB boundary", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        { kind: "udp", ports: [7], payload: new Uint8Array(4 * 1024 * 1024) },
      ],
      deadlineMs: 1_000,
    }),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_CONTROL_BYTES",
  );
  await scanner.close();
});
