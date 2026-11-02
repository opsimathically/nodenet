import assert from "node:assert/strict";
import test from "node:test";

import {
  bootstrapCpuReduction,
  bootstrapThroughputRatio,
  percentile,
  summarize,
} from "./phase25-statistics.mjs";

test("Phase 25 bootstrap intervals are deterministic and preserve clear thresholds", () => {
  const baseline = [100, 101, 99, 100, 102, 98, 101, 99, 100, 100];
  const faster = baseline.map((sample) => sample * 1.6);
  const ratio = bootstrapThroughputRatio(baseline, faster);
  assert.ok(ratio.lower95 >= 1.5);
  assert.ok(ratio.upper95 <= 1.61);

  const lowerCpu = baseline.map((sample) => sample * 0.65);
  const reduction = bootstrapCpuReduction(baseline, lowerCpu);
  assert.ok(reduction.lower95 >= 0.3);
  assert.ok(reduction.upper95 <= 0.36);
});

test("Phase 25 summaries interpolate tail percentiles without mutating input", () => {
  const samples = [4, 1, 3, 2];
  assert.equal(percentile(samples, 0.5), 2.5);
  assert.deepEqual(samples, [4, 1, 3, 2]);
  assert.deepEqual(summarize(samples), {
    mean: 2.5,
    p50: 2.5,
    p95: 3.8499999999999996,
    p99: 3.9699999999999998,
    minimum: 1,
    maximum: 4,
  });
  assert.equal(percentile([-2, -1, 4, 8], 0.5), 1.5);
});

test("Phase 25 statistics reject unqualified sample sets", () => {
  assert.throws(() => percentile([1], 0.5), TypeError);
  assert.throws(
    () => bootstrapThroughputRatio([1, 2], [1, Number.NaN]),
    TypeError,
  );
  assert.throws(() => bootstrapCpuReduction([1, 2], [1, 2, 3]), RangeError);
});
