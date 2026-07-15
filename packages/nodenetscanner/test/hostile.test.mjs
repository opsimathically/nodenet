import assert from "node:assert/strict";
import test from "node:test";

import {
  RESULT_BATCH_SCHEMA_VERSION,
  SCANNER_LIMITS,
  SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS,
  SUPPORTED_SCAN_PROBES,
  UDP_PROBE_CATALOGUE,
  ScannerError,
  createScanner,
} from "../dist/index.js";

test("release capability and bound declarations are immutable", () => {
  assert.equal(RESULT_BATCH_SCHEMA_VERSION, 2);
  assert.deepEqual(SUPPORTED_SCAN_PROBES, [
    "arp",
    "ndp",
    "icmpEchoIpv4",
    "icmpEchoIpv6",
    "tcpSyn",
    "udp",
  ]);
  assert.equal(Object.isFrozen(SUPPORTED_SCAN_PROBES), true);
  assert.equal(Object.isFrozen(SCANNER_LIMITS), true);
  assert.equal(SCANNER_LIMITS.batchResults, 4096);
  assert.equal(SCANNER_LIMITS.udpPayloadBytes, 65_491);
  assert.deepEqual(SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS, [1, 2]);
  assert.equal(Object.isFrozen(SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS), true);
  assert.equal(UDP_PROBE_CATALOGUE.version, "1.3.0");
  assert.equal(UDP_PROBE_CATALOGUE.variants, 33);
  assert.equal(UDP_PROBE_CATALOGUE.sha256.length, 64);
  assert.equal(UDP_PROBE_CATALOGUE.protocolModeAvailable, true);
  assert.equal(Object.isFrozen(UDP_PROBE_CATALOGUE), true);
  assert.equal(Object.isFrozen(UDP_PROBE_CATALOGUE.supportedProfiles), true);
});

test("hostile JavaScript plan values fail as controlled scanner errors", async () => {
  const scanner = await createScanner();
  const values = [
    null,
    undefined,
    1,
    "plan",
    {},
    { targets: null, probes: [], deadlineMs: 1 },
    { targets: [], probes: null, deadlineMs: Number.NaN },
    { targets: [], probes: [], deadlineMs: Number.POSITIVE_INFINITY },
    new Proxy(
      {},
      {
        get() {
          throw new Error("hostile getter");
        },
      },
    ),
  ];
  for (const value of values) {
    await assert.rejects(
      scanner.start(value),
      (error) => error instanceof ScannerError && error.kind === "invalidPlan",
    );
  }
  await scanner.close();
});

test("plan and nested getters are snapshotted once before native admission", async () => {
  const reads = new Map();
  const field = (name, value) => ({
    enumerable: true,
    get() {
      reads.set(name, (reads.get(name) ?? 0) + 1);
      return value;
    },
  });
  const target = Object.defineProperties(
    {},
    {
      cidr: field("target.cidr", "not-a-cidr"),
      start: field("target.start", undefined),
      end: field("target.end", undefined),
    },
  );
  const probe = Object.defineProperties(
    {},
    {
      kind: field("probe.kind", "icmpEcho"),
      family: field("probe.family", "ipv4"),
    },
  );
  const plan = Object.defineProperties(
    {},
    {
      targets: field("plan.targets", [target]),
      exclude: field("plan.exclude", undefined),
      probes: field("plan.probes", [probe]),
      deadlineMs: field("plan.deadlineMs", 1_000),
      rate: field("plan.rate", undefined),
      timing: field("plan.timing", undefined),
      seed: field("plan.seed", undefined),
      sourceAddress: field("plan.sourceAddress", undefined),
      interface: field("plan.interface", undefined),
      vlan: field("plan.vlan", undefined),
      sourcePortRange: field("plan.sourcePortRange", undefined),
    },
  );
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start(plan),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  assert.ok([...reads.values()].every((count) => count === 1));
  await scanner.close();
});

test("hostile nested and oversized values never cross as unchecked native input", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        {
          kind: "udp",
          ports: [7],
          payload: new Uint8Array(SCANNER_LIMITS.controlBytes),
        },
      ],
      deadlineMs: 1,
    }),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_CONTROL_BYTES",
  );
  await scanner.close();
});

test("UDP wire-size violations fail before native session admission", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        {
          kind: "udp",
          ports: [7],
          payload: new Uint8Array(SCANNER_LIMITS.udpPayloadBytes + 1),
        },
      ],
      deadlineMs: 1_000,
    }),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_INVALID_SCAN_PLAN",
  );
  await scanner.close();
});

test("UDP policy conflicts, risks, and duplicate definitions fail deterministically", async () => {
  const scanner = await createScanner();
  const base = {
    targets: [{ cidr: "127.0.0.1/32" }],
    deadlineMs: 1_000,
  };
  await assert.rejects(
    scanner.start({
      ...base,
      probes: [
        {
          kind: "udp",
          ports: [7],
          payload: new Uint8Array(),
          policy: { mode: "empty" },
        },
      ],
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  for (const allowRisks of [
    ["sensitiveRead", "sensitiveRead"],
    ["unknownRisk"],
  ]) {
    await assert.rejects(
      scanner.start({
        ...base,
        probes: [
          {
            kind: "udp",
            ports: [7],
            policy: { mode: "protocol", allowRisks },
          },
        ],
      }),
      (error) => error instanceof ScannerError && error.kind === "invalidPlan",
    );
  }
  await assert.rejects(
    scanner.start({
      ...base,
      probes: [
        { kind: "udp", ports: [7], policy: { mode: "empty" } },
        {
          kind: "udp",
          ports: [9],
          policy: {
            mode: "custom",
            payload: Uint8Array.from([1]),
          },
        },
      ],
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await scanner.close();
});

test("UDP policy getters and mutable payloads are snapshotted once", async () => {
  const scanner = await createScanner();
  const reads = new Map();
  const field = (name, value) => ({
    enumerable: true,
    get() {
      reads.set(name, (reads.get(name) ?? 0) + 1);
      return value;
    },
  });
  const payload = Uint8Array.from([1, 2, 3]);
  const policy = Object.defineProperties(
    {},
    {
      mode: field("mode", "custom"),
      payload: field("payload", payload),
      correlation: field("correlation", "tuple"),
    },
  );
  const pending = scanner.start({
    targets: [{ cidr: "127.0.0.1/32" }],
    probes: [
      { kind: "udp", ports: [7], policy },
      { kind: "udp", ports: [9], policy: { mode: "empty" } },
    ],
    deadlineMs: 1_000,
  });
  payload.fill(0xff);
  await assert.rejects(
    pending,
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  assert.deepEqual(Object.fromEntries(reads), {
    mode: 1,
    payload: 1,
    correlation: 1,
  });
  await scanner.close();
});

test("detached custom UDP payloads fail as controlled plan errors", async () => {
  const scanner = await createScanner();
  const payload = Uint8Array.from([1, 2, 3]);
  globalThis.structuredClone(payload, { transfer: [payload.buffer] });
  assert.equal(payload.buffer.detached, true);
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        {
          kind: "udp",
          ports: [7],
          policy: { mode: "custom", payload, correlation: "tuple" },
        },
      ],
      deadlineMs: 1_000,
    }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await scanner.close();
});

test("protocol-aware UDP mode reaches Phase 28 scheduling after validation", async () => {
  const scanner = await createScanner();
  try {
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        {
          kind: "udp",
          ports: [53],
          policy: {
            mode: "protocol",
            profile: "safe",
            intensity: 7,
            strategy: "exhaustive",
            emptyFallback: "unmapped",
            allowRisks: [],
          },
        },
      ],
      deadlineMs: 1_000,
    });
    await session.cancel();
    await session.close();
  } catch (error) {
    assert.ok(error instanceof ScannerError);
    assert.notEqual(error.kind, "invalidPlan");
    assert.notEqual(error.kind, "unsupported");
  }
  await scanner.close();
});

test("source-port capacity fails before raw socket admission", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [{ kind: "tcpSyn", ports: [7] }],
      deadlineMs: 1_000,
      rate: { packetsPerSecond: 1, burst: 1, maxOutstanding: 2 },
      sourcePortRange: { start: 60_000, end: 60_004 },
    }),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_INVALID_SCAN_PLAN",
  );
  await scanner.close();
});
