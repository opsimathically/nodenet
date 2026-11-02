import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { memoryUsage, stdout } from "node:process";
import { setImmediate } from "node:timers/promises";

import { RawSocket, interfaceIndex } from "../dist/index.js";

const ITERATIONS = 256;
const loopback = interfaceIndex("lo");

async function cycle(index) {
  const socket = await RawSocket.open({
    family: "packet",
    mode: "raw",
    protocol: 0x88b8,
  });
  try {
    await socket.bind({
      family: "packet",
      interfaceIndex: loopback,
      protocol: 0x88b8,
    });
    await socket.configurePacketRing({
      blockSize: 4096,
      blockCount: 2,
      frameSize: 2048,
      retireTimeoutMs: 16,
    });
    if (index % 16 === 0) {
      const controller = new globalThis.AbortController();
      const pending = socket.receiveRingFrame({ signal: controller.signal });
      controller.abort();
      await assert.rejects(pending, { code: "ERR_ABORTED" });
    }
  } finally {
    await socket.close();
  }
}

// Warm the environment reactor before capturing its stable descriptor baseline.
await cycle(-1);
await setImmediate();
const descriptorsBefore = readdirSync("/proc/self/fd").length;
const rssBefore = memoryUsage.rss();

for (let index = 0; index < ITERATIONS; index += 1) await cycle(index);
await setImmediate();

const descriptorsAfter = readdirSync("/proc/self/fd").length;
const rssAfter = memoryUsage.rss();
assert.equal(descriptorsAfter, descriptorsBefore);
assert.ok(rssAfter - rssBefore < 32 * 1024 * 1024);

stdout.write(
  `${JSON.stringify({
    iterations: ITERATIONS,
    descriptorsBefore,
    descriptorsAfter,
    rssDeltaBytes: rssAfter - rssBefore,
  })}\n`,
);
