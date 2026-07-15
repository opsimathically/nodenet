import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import test from "node:test";
import { promisify } from "node:util";

import { ScannerError, createScanner } from "../dist/index.js";

const enabled = process.env.NODENETSCANNER_PHASE24_TESTS === "1";
const execute = promisify(execFile);

test(
  "context fault injection terminates without stranded descriptors or promises",
  { skip: !enabled, timeout: 30_000 },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.0/24" }],
      exclude: [{ cidr: "192.0.2.1/32" }],
      probes: [{ kind: "icmpEcho", family: "ipv4" }],
      deadlineMs: 4_000,
      interface: "scan0",
      sourceAddress: "192.0.2.1",
      timing: { timeoutMs: 500, retries: 0 },
      rate: { packetsPerSecond: 20, burst: 1, maxOutstanding: 8 },
    });
    await execute("ip", ["link", "set", "scan0", "down"]);
    await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
    await execute("ip", ["link", "set", "scan0", "up"]);
    const summary = await session.summary();
    assert.ok(["completed", "failed"].includes(summary.state));
    if (summary.error !== undefined)
      assert.ok(summary.error instanceof ScannerError);
    let drained = 0;
    while (true) {
      const batch = await session.nextBatch({ maxResults: 4096 });
      if (batch === null) break;
      drained += batch.length;
    }
    assert.equal(BigInt(drained), summary.results);
    await session.close();
    await scanner.close();
  },
);

test(
  "four sessions remain fair while compact completion batches are retained",
  { skip: !enabled, timeout: 30_000 },
  async () => {
    const scanner = await createScanner();
    const sessions = await Promise.all(
      Array.from({ length: 4 }, (_, index) =>
        scanner.start({
          targets: [{ cidr: "127.0.0.1/32" }],
          probes: [
            {
              kind: "tcpSyn",
              ports: [{ start: 20_000 + index * 64, end: 20_063 + index * 64 }],
            },
          ],
          deadlineMs: 10_000,
          timing: { timeoutMs: 500, retries: 0 },
          rate: { packetsPerSecond: 10_000, burst: 64, maxOutstanding: 64 },
        }),
      ),
    );
    const summaries = await Promise.all(
      sessions.map((session) => session.summary()),
    );
    assert.ok(summaries.every((summary) => summary.results === 64n));
    assert.ok(summaries.every((summary) => summary.progress.sent === 64n));
    await Promise.all(sessions.map((session) => session.close()));
    await scanner.close();
  },
);

test(
  "mixed subnet scans preserve neighbor setup across prefix deferral",
  { skip: !enabled, timeout: 30_000 },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.0/24" }],
      exclude: [{ cidr: "192.0.2.1/32" }],
      probes: [
        { kind: "arp" },
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "tcpSyn", ports: [{ start: 20, end: 24 }] },
      ],
      deadlineMs: 10_000,
      interface: "scan0",
      sourceAddress: "192.0.2.1",
      timing: { timeoutMs: 200, retries: 0 },
      rate: { packetsPerSecond: 20_000, burst: 256, maxOutstanding: 2_048 },
    });
    const summary = await session.summary();
    assert.equal(summary.state, "completed");
    assert.equal(summary.logicalProbes, 1_785n);
    assert.equal(summary.results, summary.logicalProbes);
    assert.equal(summary.error, undefined);
    let drained = 0;
    while (true) {
      const batch = await session.nextBatch({ maxResults: 4_096 });
      if (batch === null) break;
      drained += batch.length;
    }
    assert.equal(BigInt(drained), summary.results);
    await session.close();
    await scanner.close();
  },
);
