import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  PathRun,
  SERVICE_CAPABILITIES,
  SensorFusion,
  authorizeAdvertisedUrl,
  classifyAsset,
  decodeSensorEnvelope,
  dnsSdServiceSemantic,
  encodeSensorEnvelope,
  evidenceFromObservation,
  evidenceRecordsFromObservation,
  fuseSensorEnvelope,
  inventoryDelta,
  reconcileEvidence,
  validateServiceConversation,
} from "../dist/index.js";

test("path runs retain multiple responders and stop at destination", () => {
  const run = new PathRun({
    target: "192.0.2.5",
    mode: "udp",
    port: 33434,
    deadlineMs: 1_000,
  });
  run.record({
    hop: 1,
    attempt: 1,
    responder: "192.0.2.1",
    outcome: "hopResponse",
    correlation: "strong",
  });
  run.record({
    hop: 1,
    attempt: 2,
    responder: "192.0.2.2",
    outcome: "hopResponse",
    correlation: "strong",
  });
  run.record({
    hop: 2,
    attempt: 1,
    responder: "192.0.2.5",
    outcome: "destinationReached",
    correlation: "strong",
  });
  assert.equal(run.stopped, true);
  assert.equal(run.materialize().length, 3);
  assert.throws(() =>
    run.record({ hop: 3, attempt: 1, outcome: "timeout", correlation: "weak" }),
  );
});

test("advertised URL authority stays on the responder", () => {
  assert.deepEqual(
    authorizeAdvertisedUrl("http://192.0.2.1/device.xml", "192.0.2.1"),
    {
      scheme: "http",
      host: "192.0.2.1",
      port: 80,
      path: "/device.xml",
    },
  );
  assert.throws(() =>
    authorizeAdvertisedUrl("http://192.0.2.2/device.xml", "192.0.2.1"),
  );
  assert.throws(() =>
    authorizeAdvertisedUrl("http://device.local/device.xml", "192.0.2.1"),
  );
  assert.throws(() =>
    authorizeAdvertisedUrl("http://user@192.0.2.1/", "192.0.2.1"),
  );
  assert.throws(() => authorizeAdvertisedUrl("http://999.0.2.1/", "999.0.2.1"));
});

test("DNS-SD semantic families preserve unknown service types", () => {
  assert.deepEqual(dnsSdServiceSemantic("Office._ipp._tcp.local"), {
    serviceType: "_ipp",
    transport: "tcp",
    family: "printing",
  });
  assert.deepEqual(dnsSdServiceSemantic("_vendor-device._udp.local"), {
    serviceType: "_vendor-device",
    transport: "udp",
    family: "unknown",
  });
  assert.equal(dnsSdServiceSemantic("fixture.local"), undefined);
});

test("service registry enforces opt-in and no-go boundaries", () => {
  assert.equal(
    SERVICE_CAPABILITIES.find((entry) => entry.id === "ldap-root-dse")
      ?.disposition,
    "noGo",
  );
  const plan = validateServiceConversation({
    capabilityId: "ssh-identification",
    target: "192.0.2.1",
    port: 22,
    allowRisks: ["serverFirst"],
    steps: [
      { kind: "connect", deadlineMs: 1_000 },
      { kind: "read", maximumReadBytes: 255, deadlineMs: 1_000 },
      { kind: "shutdown", deadlineMs: 1_000 },
    ],
  });
  assert.equal(plan.steps.length, 3);
  assert.throws(() =>
    validateServiceConversation({
      capabilityId: "ssh-identification",
      target: "192.0.2.1",
      port: 22,
      allowRisks: [],
      steps: [
        { kind: "connect", deadlineMs: 1_000 },
        { kind: "shutdown", deadlineMs: 1_000 },
      ],
    }),
  );
});

test("reconciliation does not merge weak duplicate names", () => {
  const make = (id, canonical, mac) => ({
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: Uint8Array.of(1),
      recordId: BigInt(id),
    },
    entity: { kind: "deviceCandidate", canonical: Buffer.from(canonical) },
    confidence: "structural",
    disposition: "observed",
    observedAtNanoseconds: 1n,
    fields: [
      { key: "name", value: Buffer.from("duplicate.local") },
      ...(mac === undefined
        ? []
        : [{ key: "mac", value: Buffer.from(mac, "hex") }]),
    ],
    relations: [],
  });
  assert.equal(
    reconcileEvidence([
      make(1, "one"),
      make(2, "two"),
      make(3, "three", "001122334455"),
    ]).length,
    3,
  );
});

test("reconciliation bridges scoped strong identifiers without crossing sensor networks", () => {
  const make = (id, fields) => ({
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: Uint8Array.of(1),
      recordId: BigInt(id),
    },
    entity: { kind: "deviceCandidate", canonical: Buffer.from(`device-${id}`) },
    confidence: "structural",
    disposition: "observed",
    observedAtNanoseconds: 1n,
    fields,
    relations: [],
  });
  const bridged = reconcileEvidence([
    make(1, [
      { key: "mac", value: Buffer.from("001122334455", "hex") },
      { key: "address", value: Buffer.from("192.0.2.1") },
    ]),
    make(2, [
      { key: "mac", value: Buffer.from("001122334455", "hex") },
      { key: "lldpChassisId", value: Buffer.from("switch-port") },
    ]),
    make(3, [
      { key: "lldpChassisId", value: Buffer.from("switch-port") },
      { key: "service", value: Buffer.from("ssh") },
    ]),
  ]);
  assert.equal(bridged.length, 1);
  assert.deepEqual(bridged[0].addresses, ["192.0.2.1"]);
  assert.deepEqual(bridged[0].services, ["ssh"]);
  assert.ok(bridged[0].mergeReasons.length > 0);

  const envelope = (sensorId, networkScopeId) => ({
    version: 1,
    sensorId,
    networkScopeId,
    sequence: 1n,
    monotonicStartNanoseconds: 1n,
    monotonicEndNanoseconds: 2n,
    clockUncertaintyMilliseconds: 1,
    truncated: false,
    records: [
      make(4, [{ key: "mac", value: Buffer.from("aabbccddeeff", "hex") }]),
    ],
  });
  assert.equal(
    reconcileEvidence([
      ...fuseSensorEnvelope(envelope("sensor-a", "site-a")),
      ...fuseSensorEnvelope(envelope("sensor-b", "site-b")),
    ]).length,
    2,
  );
});

test("classification exposes supporting evidence", () => {
  const rows = classifyAsset({
    id: "fixture",
    strongIdentifiers: [],
    addresses: [],
    names: ["office-printer"],
    services: ["ipp"],
    conflicts: [],
  });
  assert.equal(rows[0]?.classification, "printer");
  assert.equal(rows[0]?.positiveEvidence.length, 1);
});

test("inventory delta and sensor envelope remain deterministic and scoped", () => {
  const asset = {
    id: "asset",
    strongIdentifiers: [],
    addresses: [],
    names: [],
    services: [],
    conflicts: [],
  };
  assert.deepEqual(
    inventoryDelta(
      { schemaVersion: 1, sequence: 1n, assets: [] },
      { schemaVersion: 1, sequence: 2n, assets: [asset] },
    ),
    [{ kind: "new", assetId: "asset" }],
  );
  const envelope = {
    version: 1,
    sensorId: "sensor-a",
    networkScopeId: "lab-vlan-11",
    sequence: 1n,
    monotonicStartNanoseconds: 10n,
    monotonicEndNanoseconds: 20n,
    clockUncertaintyMilliseconds: 5,
    truncated: false,
    capabilities: [{ id: "passive-observation", version: "1.0.0" }],
    captureVisibility: {
      interfaces: ["eth0"],
      protocols: ["arp", "ipv6"],
      promiscuous: false,
      includesOutgoing: false,
    },
    summary: { acceptedRecords: 0, droppedRecords: 2 },
    records: [],
  };
  const decoded = decodeSensorEnvelope(encodeSensorEnvelope(envelope));
  assert.equal(decoded.sensorId, "sensor-a");
  assert.equal(decoded.capabilities?.[0]?.id, "passive-observation");
  assert.deepEqual(decoded.captureVisibility?.interfaces, ["eth0"]);
  assert.equal(decoded.summary?.droppedRecords, 2);
  assert.ok(Object.isFrozen(decoded.captureVisibility?.interfaces));
  assert.throws(() =>
    encodeSensorEnvelope({
      ...envelope,
      capabilities: [
        { id: "duplicate", version: "1" },
        { id: "duplicate", version: "2" },
      ],
    }),
  );
  assert.throws(() =>
    encodeSensorEnvelope({
      ...envelope,
      summary: { acceptedRecords: 8_193, droppedRecords: 0 },
    }),
  );
  const fusion = new SensorFusion();
  fusion.admit(decoded);
  assert.throws(() => fusion.admit(decoded));

  const hostile = JSON.parse(
    Buffer.from(encodeSensorEnvelope(envelope)).toString("utf8"),
  );
  hostile.records = [
    {
      schemaVersion: 1,
      origin: {
        source: "importedSensor",
        sourceSchema: 1,
        runId: "***not-base64***",
        recordId: "1",
      },
      entity: { kind: "deviceCandidate", canonical: "YQ==" },
      confidence: "weak",
      disposition: "observed",
      observedAtNanoseconds: "1",
      fields: [],
      relations: [],
    },
  ];
  assert.throws(() =>
    decodeSensorEnvelope(Buffer.from(JSON.stringify(hostile))),
  );
  hostile.records = [];
  hostile.sequence = "9".repeat(100);
  assert.throws(() =>
    decodeSensorEnvelope(Buffer.from(JSON.stringify(hostile))),
  );
});

test("inventory distinguishes conflict, withdrawal, expiry, and reappearance", () => {
  const asset = (id, conflicts = []) => ({
    id,
    strongIdentifiers: [],
    addresses: [],
    names: [],
    services: [],
    conflicts,
  });
  assert.deepEqual(
    inventoryDelta(
      {
        schemaVersion: 1,
        sequence: 1n,
        assets: [asset("a"), asset("b"), asset("c")],
      },
      {
        schemaVersion: 1,
        sequence: 2n,
        assets: [asset("b", ["address reuse"]), asset("d")],
        withdrawnAssetIds: ["c"],
        previouslySeenAssetIds: ["d"],
      },
    ),
    [
      { kind: "expired", assetId: "a" },
      { kind: "changed", assetId: "b" },
      { kind: "conflicted", assetId: "b" },
      { kind: "withdrawn", assetId: "c" },
      { kind: "reappeared", assetId: "d" },
    ],
  );
});

test("inventory comparison is order-stable and rejects oversized assets", () => {
  const asset = (services) => ({
    id: "ordered",
    strongIdentifiers: ["second", "first"],
    addresses: [],
    names: [],
    services,
    conflicts: [],
  });
  assert.deepEqual(
    inventoryDelta(
      { schemaVersion: 1, sequence: 1n, assets: [asset(["ssh", "http"])] },
      { schemaVersion: 1, sequence: 2n, assets: [asset(["http", "ssh"])] },
    ),
    [],
  );
  assert.throws(() =>
    inventoryDelta(
      { schemaVersion: 1, sequence: 1n, assets: [] },
      {
        schemaVersion: 1,
        sequence: 2n,
        assets: [asset(Array.from({ length: 8_193 }, () => "service"))],
      },
    ),
  );
});

test("sensor envelopes retain room for fusion provenance fields", () => {
  const evidence = {
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: Uint8Array.of(1),
      recordId: 1n,
    },
    entity: { kind: "deviceCandidate", canonical: Uint8Array.of(1) },
    confidence: "weak",
    disposition: "observed",
    observedAtNanoseconds: 1n,
    fields: Array.from({ length: 125 }, (_, index) => ({
      key: `field-${String(index)}`,
      value: Uint8Array.of(1),
    })),
    relations: [],
  };
  assert.throws(() =>
    encodeSensorEnvelope({
      version: 1,
      sensorId: "sensor",
      networkScopeId: "scope",
      sequence: 1n,
      monotonicStartNanoseconds: 1n,
      monotonicEndNanoseconds: 2n,
      clockUncertaintyMilliseconds: 0,
      truncated: false,
      records: [evidence],
    }),
  );
});

test("sensor fusion replaces forged provenance and commits sequences transactionally", () => {
  const make = (recordId, fields) => ({
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: Uint8Array.of(1),
      recordId,
    },
    entity: { kind: "deviceCandidate", canonical: Uint8Array.of(1) },
    confidence: "structural",
    disposition: "observed",
    observedAtNanoseconds: 1n,
    fields,
    relations: [],
  });
  const envelope = (sensorId, scope, records) => ({
    version: 1,
    sensorId,
    networkScopeId: scope,
    sequence: 1n,
    monotonicStartNanoseconds: 1n,
    monotonicEndNanoseconds: 2n,
    clockUncertaintyMilliseconds: 0,
    truncated: false,
    records,
  });
  const forged = [
    ...fuseSensorEnvelope(
      envelope("sensor-a", "site-a", [
        make(7n, [
          { key: "networkScopeId", value: Buffer.from("attacker-shared") },
          { key: "mac", value: Buffer.from("001122334455", "hex") },
        ]),
      ]),
    ),
    ...fuseSensorEnvelope(
      envelope("sensor-b", "site-b", [
        make(7n, [
          { key: "networkScopeId", value: Buffer.from("attacker-shared") },
          { key: "mac", value: Buffer.from("001122334455", "hex") },
        ]),
      ]),
    ),
  ];
  assert.equal(reconcileEvidence(forged).length, 2);
  assert.ok(
    forged.every(
      (record) =>
        record.fields.filter((field) => field.key === "networkScopeId")
          .length === 1,
    ),
  );

  const fusion = new SensorFusion();
  const nearLimitFields = Array.from({ length: 16 }, (_, index) => ({
    key: `f${String(index)}`,
    value: new Uint8Array(index === 15 ? 900 : 1_024),
  }));
  assert.throws(() =>
    fusion.admit(envelope("sensor", "scope", [make(1n, nearLimitFields)])),
  );
  assert.doesNotThrow(() =>
    fusion.admit(envelope("sensor", "scope", [make(1n, [])])),
  );
  assert.throws(() =>
    encodeSensorEnvelope(envelope("bad\0sensor", "scope", [])),
  );
});

test("passive lifetimes and withdrawals become append-only evidence semantics", () => {
  const base = {
    sequence: 7n,
    interfaceIndex: 2,
    timestampNanoseconds: 1_000_000_000n,
    originalLength: 128,
    capturedLength: 128,
    packetType: 0,
    direction: "incoming",
    protocol: "ssdp",
    sourceMac: Uint8Array.from([2, 0, 0, 0, 0, 1]),
    destinationMac: Uint8Array.from([1, 0, 94, 127, 255, 250]),
    etherType: 0x0800,
    vlanIds: [],
    sourceAddress: "192.0.2.10",
    sourcePort: 1900,
    destinationPort: 1900,
    truncated: false,
  };
  const alive = evidenceFromObservation(
    {
      ...base,
      metadata: [{ key: "ssdpMaxAge", value: Uint8Array.from([0, 0, 0, 10]) }],
    },
    Uint8Array.of(1),
  );
  assert.equal(alive.entity.kind, "service");
  assert.equal(alive.expiresAtNanoseconds, 11_000_000_000n);
  assert.equal(alive.disposition, "observed");
  const withdrawn = evidenceFromObservation(
    {
      ...base,
      metadata: [{ key: "ssdpNts", value: Buffer.from("ssdp:byebye") }],
    },
    Uint8Array.of(1),
  );
  assert.equal(withdrawn.disposition, "withdrawn");
  const records = evidenceRecordsFromObservation(
    {
      ...base,
      protocol: "mdns",
      metadata: [
        { key: "dnsRecordName", value: Buffer.from("fixture.local") },
        { key: "dnsTtl", value: Uint8Array.from([0, 0, 0, 120]) },
      ],
    },
    Uint8Array.of(1),
  );
  assert.deepEqual(
    records.map((record) => record.entity.kind),
    ["deviceCandidate", "service", "name"],
  );
  assert.equal(records[1].relations.at(-1)?.kind, "advertisedBy");
});

test("passive evidence uses disjoint IDs, DNS wire semantics, and record-level expiry", () => {
  const wire = (name) =>
    Buffer.concat([
      ...name
        .split(".")
        .map((label) =>
          Buffer.concat([
            Buffer.from([Buffer.byteLength(label)]),
            Buffer.from(label),
          ]),
        ),
      Buffer.from([0]),
    ]);
  const base = {
    interfaceIndex: 2,
    timestampNanoseconds: 1_000_000_000n,
    originalLength: 128,
    capturedLength: 128,
    packetType: 0,
    direction: "incoming",
    protocol: "mdns",
    sourceMac: Uint8Array.from([2, 0, 0, 0, 0, 1]),
    destinationMac: Uint8Array.from([1, 0, 94, 0, 0, 251]),
    etherType: 0x0800,
    vlanIds: [],
    sourceAddress: "192.0.2.10",
    sourcePort: 5353,
    destinationPort: 5353,
    truncated: false,
    metadata: [
      { key: "dnsRecordName", value: wire("_ipp._tcp.local") },
      { key: "dnsPtr", value: wire("Office._ipp._tcp.local") },
      { key: "dnsTtl", value: Uint8Array.from([0, 0, 0, 120]) },
    ],
  };
  const first = evidenceRecordsFromObservation(
    { ...base, sequence: 1n },
    Uint8Array.of(1),
  );
  const second = evidenceRecordsFromObservation(
    { ...base, sequence: 2n },
    Uint8Array.of(1),
  );
  const ids = new Set(
    [...first, ...second].map((record) => record.origin.recordId.toString()),
  );
  assert.equal(ids.size, first.length + second.length);
  assert.ok(
    first.some(
      (record) =>
        record.entity.kind === "service" &&
        record.fields.some(
          (field) =>
            field.key === "service" &&
            Buffer.from(field.value).toString() === "printing",
        ),
    ),
  );

  const goodbye = evidenceRecordsFromObservation(
    {
      ...base,
      sequence: 3n,
      metadata: [
        { key: "dnsRecordName", value: wire("_ipp._tcp.local") },
        { key: "dnsTtl", value: Uint8Array.of(0, 0, 0, 0) },
      ],
    },
    Uint8Array.of(1),
  );
  assert.equal(goodbye[0].entity.kind, "deviceCandidate");
  assert.equal(goodbye[0].disposition, "observed");
  assert.ok(
    goodbye.slice(1).every((record) => record.disposition === "withdrawn"),
  );
  assert.equal(reconcileEvidence(goodbye.slice(1)).length, 0);
});
