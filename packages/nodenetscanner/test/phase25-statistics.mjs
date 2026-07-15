const DEFAULT_RESAMPLES = 20_000;

function assertSamples(samples, name) {
  if (!Array.isArray(samples) || samples.length < 2)
    throw new TypeError(`${name} requires at least two samples`);
  if (samples.some((sample) => !Number.isFinite(sample)))
    throw new TypeError(`${name} samples must be finite`);
}

function randomGenerator(initialSeed) {
  let state = initialSeed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

export function mean(samples) {
  assertSamples(samples, "mean");
  return samples.reduce((total, sample) => total + sample, 0) / samples.length;
}

export function percentile(samples, probability) {
  assertSamples(samples, "percentile");
  if (!Number.isFinite(probability) || probability < 0 || probability > 1)
    throw new RangeError("probability must be from zero through one");
  const sorted = samples.toSorted((left, right) => left - right);
  const position = (sorted.length - 1) * probability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

function bootstrapPaired(
  baseline,
  candidate,
  statistic,
  { resamples = DEFAULT_RESAMPLES, seed = 0x4e_52_25 } = {},
) {
  assertSamples(baseline, "baseline");
  assertSamples(candidate, "candidate");
  if (
    baseline.some((sample) => sample <= 0) ||
    candidate.some((sample) => sample <= 0)
  )
    throw new RangeError("paired samples must be positive");
  if (baseline.length !== candidate.length)
    throw new RangeError("paired samples must have equal length");
  if (!Number.isSafeInteger(resamples) || resamples < 1_000)
    throw new RangeError("resamples must be a safe integer of at least 1000");
  const random = randomGenerator(seed);
  const distribution = new Array(resamples);
  for (let repetition = 0; repetition < resamples; repetition += 1) {
    let baselineTotal = 0;
    let candidateTotal = 0;
    let draws = 0;
    while (draws < baseline.length) {
      const selected = Math.floor(random() * baseline.length);
      baselineTotal += baseline[selected];
      candidateTotal += candidate[selected];
      draws += 1;
    }
    distribution[repetition] = statistic(
      baselineTotal / baseline.length,
      candidateTotal / candidate.length,
    );
  }
  return {
    estimate: statistic(mean(baseline), mean(candidate)),
    lower95: percentile(distribution, 0.025),
    upper95: percentile(distribution, 0.975),
    resamples,
  };
}

export function bootstrapThroughputRatio(baseline, candidate, options) {
  return bootstrapPaired(
    baseline,
    candidate,
    (baselineMean, candidateMean) => candidateMean / baselineMean,
    options,
  );
}

export function bootstrapCpuReduction(baseline, candidate, options) {
  return bootstrapPaired(
    baseline,
    candidate,
    (baselineMean, candidateMean) =>
      (baselineMean - candidateMean) / baselineMean,
    options,
  );
}

export function summarize(samples) {
  return {
    mean: mean(samples),
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
    p99: percentile(samples, 0.99),
    minimum: Math.min(...samples),
    maximum: Math.max(...samples),
  };
}
