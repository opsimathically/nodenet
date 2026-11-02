import { execFileSync } from "node:child_process";
import { cpus, totalmem } from "node:os";

import { createScanner, inspectNetworkContext } from "../dist/index.js";

const context = await inspectNetworkContext();
const scanner = await createScanner();
const workloads = [
  ["packet-build+tx-rx+correlation", 1],
  ["scheduling+batching+napi", 1024],
];
const results = [];
for (const [name, ports] of workloads) {
  const started = process.hrtime.bigint();
  const session = await scanner.start({
    targets: [{ cidr: "127.0.0.1/32" }],
    probes: [
      {
        kind: "tcpSyn",
        ports: ports === 1 ? [9] : [{ start: 20_000, end: 20_000 + ports - 1 }],
      },
    ],
    deadlineMs: 20_000,
    timing: { timeoutMs: 500, retries: 0 },
    rate: { packetsPerSecond: 100_000, burst: ports, maxOutstanding: ports },
  });
  const summary = await session.summary();
  let batches = 0;
  while ((await session.nextBatch({ maxResults: 4096 })) !== null) batches += 1;
  const elapsed = process.hrtime.bigint() - started;
  results.push({
    name,
    logicalProbes: summary.logicalProbes.toString(),
    elapsedNanoseconds: elapsed.toString(),
    probesPerSecond:
      Number(summary.logicalProbes) / (Number(elapsed) / 1_000_000_000),
    batches,
  });
  await session.close();
}
await scanner.close();
console.log(
  JSON.stringify(
    {
      schemaVersion: 1,
      timestamp: new Date().toISOString(),
      node: process.version,
      architecture: process.arch,
      cpu: cpus()[0]?.model,
      cpuCount: cpus().length,
      memoryBytes: totalmem(),
      kernel: execFileSync("uname", ["-sr"], { encoding: "utf8" }).trim(),
      interfaces: context.interfaces.map(({ index, name, linkKind, mtu }) => ({
        index,
        name,
        linkKind,
        mtu,
      })),
      configuration: { namespace: true, rate: 100_000, timeoutMs: 500 },
      results,
    },
    null,
    2,
  ),
);
