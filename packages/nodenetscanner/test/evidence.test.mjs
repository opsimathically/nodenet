import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  EVIDENCE_LIMITS,
  EVIDENCE_SCHEMA_VERSION,
  EvidenceLedger,
  createEvidenceRecord,
  evidenceFromDiscoveryResult,
  evidenceFromScanResult,
} from "../dist/index.js";

const runId = new Uint8Array([1, 2, 3, 4]);

test("scan and discovery adapters preserve qualified source evidence", () => {
  const scan = evidenceFromScanResult(
    {
      target: "192.0.2.1",
      probe: "tcpSyn",
      port: 443,
      state: "open",
      outcome: "network",
      attempt: 0,
      transmissions: 1,
      timestampNanoseconds: 12_000n,
      routeGeneration: 1n,
      evidence: "tcpSequence32",
      reason: "tcpSynAcknowledgment",
    },
    { runId, recordId: 7n, sourceSchema: 1 },
  );
  assert.equal(scan.schemaVersion, EVIDENCE_SCHEMA_VERSION);
  assert.equal(scan.origin.source, "scanResult");
  assert.equal(scan.origin.sourceSchema, 1);
  assert.equal(scan.confidence, "strongCorrelated");
  assert.equal(scan.observedAtNanoseconds, 12_000n);

  const discovery = evidenceFromDiscoveryResult(
    {
      entityId: 9n,
      operationId: 5,
      protocol: "nat-pmp",
      kind: "gateway",
      evidence: "TransactionCorrelated",
      outcome: "complete",
      responder: "192.0.2.254",
      responderPort: 5351,
      identity: new Uint8Array([5, 6, 7]),
      addresses: ["192.0.2.254"],
      metadata: [{ key: "external", value: new Uint8Array([203, 0, 113, 1]) }],
      truncated: false,
    },
    { runId, recordId: 9n, sourceSchema: 1 },
  );
  assert.equal(discovery.entity.kind, "router");
  assert.equal(discovery.confidence, "transactionCorrelated");

  runId.fill(0);
  assert.deepEqual([...scan.origin.runId], [1, 2, 3, 4]);
  assert.deepEqual([...discovery.origin.runId], [1, 2, 3, 4]);
});

test("evidence ledger is deterministic and retains conflicts", () => {
  const first = fixture("alpha", 1n);
  const second = fixture("beta", 2n);
  const left = new EvidenceLedger({ maxRecords: 8, maxBytes: 4_096 });
  const right = new EvidenceLedger({ maxRecords: 8, maxBytes: 4_096 });
  assert.equal(left.retain(first), "accepted");
  assert.equal(left.retain(second), "conflict");
  assert.equal(left.retain(first), "duplicate");
  right.retain(second);
  right.retain(first);
  assert.deepEqual(left.materialize(), right.materialize());
  assert.deepEqual(left.counters(), {
    accepted: 1n,
    duplicates: 1n,
    conflicts: 1n,
    rejectedCapacity: 0n,
  });
});

test("hostile evidence fails every public count, byte, and time boundary", () => {
  assert.throws(
    () =>
      createEvidenceRecord({
        ...fixture("alpha", 1n),
        expiresAtNanoseconds: 9n,
      }),
    /expiry precedes/,
  );
  assert.throws(
    () =>
      createEvidenceRecord({
        ...fixture("alpha", 1n),
        origin: {
          ...fixture("alpha", 1n).origin,
          runId: new Uint8Array(EVIDENCE_LIMITS.itemBytes + 1),
        },
      }),
    /ceiling exceeded/,
  );
  const ledger = new EvidenceLedger({ maxRecords: 1, maxBytes: 1_024 });
  ledger.retain(fixture("alpha", 1n));
  assert.throws(() => ledger.retain(fixture("other", 2n)), /capacity exceeded/);
  assert.equal(ledger.counters().rejectedCapacity, 1n);
});

function fixture(name, recordId) {
  return createEvidenceRecord({
    schemaVersion: 1,
    origin: {
      source: "passiveObservation",
      sourceSchema: 1,
      runId: new Uint8Array([1]),
      recordId,
    },
    entity: {
      kind: "deviceCandidate",
      canonical: new Uint8Array([10]),
    },
    confidence: "structural",
    disposition: "observed",
    observedAtNanoseconds: 10n,
    expiresAtNanoseconds: 20n,
    fields: [{ key: "name", value: Uint8Array.from(Buffer.from(name)) }],
    relations: [],
  });
}
