import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import test from "node:test";
import { Worker } from "node:worker_threads";

const enabled = process.env.NODENETSCANNER_STRESS_TESTS === "1";

test(
  "repeated Worker teardown leaves scanner descriptors and memory bounded",
  { skip: !enabled, timeout: 120_000 },
  async (context) => {
    const baselineFds = await descriptorCount();
    const baselineRss = process.memoryUsage.rss();
    const moduleUrl = new globalThis.URL("../dist/index.js", import.meta.url)
      .href;
    for (let index = 0; index < 64; index += 1) {
      const worker = new Worker(
        `import { parentPort, workerData } from "node:worker_threads";
         const api = await import(workerData);
         const scanner = await api.createScanner();
         if (${String(index % 2 === 0)}) await scanner.close();
         parentPort.postMessage("ready");
         setInterval(() => {}, 1000);`,
        { eval: true, type: "module", workerData: moduleUrl },
      );
      await new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      });
      await worker.terminate();
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
    const fdDelta = (await descriptorCount()) - baselineFds;
    const rssDelta = process.memoryUsage.rss() - baselineRss;
    context.diagnostic(`fd delta ${fdDelta}; RSS delta ${rssDelta}`);
    assert.ok(fdDelta <= 8, `descriptor growth ${fdDelta}`);
    assert.ok(rssDelta <= 96 * 1024 * 1024, `RSS growth ${rssDelta}`);
  },
);

async function descriptorCount() {
  return (await readdir("/proc/self/fd")).length;
}
