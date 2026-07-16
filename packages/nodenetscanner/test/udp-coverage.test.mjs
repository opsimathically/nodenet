import assert from "node:assert/strict";
import test from "node:test";

import {
  UDP_COVERAGE_CAPABILITIES,
  UDP_PROBE_CATALOGUE,
} from "../dist/index.js";

test("UDP coverage decisions are final, bounded, and implementation-resolvable", () => {
  assert.equal(UDP_PROBE_CATALOGUE.version, "1.4.1");
  assert.equal(UDP_PROBE_CATALOGUE.variants, 37);
  assert.equal(UDP_COVERAGE_CAPABILITIES.version, "1.1.0");
  assert.deepEqual(UDP_COVERAGE_CAPABILITIES.resources, {
    maximumCandidates: 64,
    maximumCompiledVariants: 256,
    maximumPhysicalQueries: 1_024,
    maximumResponseBytes: 4_096,
    maximumMetadataBytes: 65_536,
    maximumReturnedEndpoints: 1_024,
    maximumStateLifetimeMs: 60_000,
  });
  const entries = UDP_COVERAGE_CAPABILITIES.entries;
  assert.equal(entries.length, 41);
  assert.deepEqual(
    entries.map((entry) => entry.id),
    Array.from({ length: 41 }, (_, index) => index + 1),
  );
  assert.equal(
    new Set(entries.map((entry) => entry.projectId)).size,
    entries.length,
  );
  assert.deepEqual(
    entries
      .filter((entry) => entry.disposition === "implemented")
      .map((entry) => [entry.projectId, entry.implementation]),
    [
      ["asf-rmcp-presence", { kind: "udpProbe", id: 7 }],
      ["ripv1-routing-table", { kind: "discoveryOperation", id: 10 }],
      ["quake2-status", { kind: "udpProbe", id: 35 }],
      ["quake3-info", { kind: "udpProbe", id: 36 }],
      ["mumble-extended-ping", { kind: "udpProbe", id: 37 }],
    ],
  );
  assert.equal(
    entries.filter((entry) => entry.disposition === "noGo").length,
    32,
  );
  const exclusions = entries.filter(
    (entry) => entry.disposition === "excluded",
  );
  assert.equal(exclusions.length, 4);
  assert.ok(
    exclusions.every(
      (entry) =>
        entry.implementation === undefined &&
        entry.risks.includes("threatSignature"),
    ),
  );
  for (const entry of entries.filter(
    (candidate) => candidate.disposition === "implemented",
  )) {
    if (entry.projectId === "asf-rmcp-presence")
      assert.deepEqual(entry.requiredConsents, []);
    else
      assert.deepEqual(entry.requiredConsents, [
        "highAmplification",
        "sensitiveRead",
      ]);
  }
  assert.ok(
    entries.every(
      (entry) =>
        ![entry.projectId, entry.family, entry.rationale]
          .join(" ")
          .toLowerCase()
          .includes(["n", "map"].join("")),
    ),
  );
});
