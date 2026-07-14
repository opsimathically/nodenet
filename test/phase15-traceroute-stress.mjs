import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { memoryUsage, stdout } from "node:process";
import { setImmediate } from "node:timers/promises";

import {
  IPPROTO_ICMP,
  RawSocket,
  RawSocketEventEmitter,
  traceIcmpRoute,
} from "../dist/index.js";

const ITERATIONS = 256;

async function cycle() {
  const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
  try {
    const controller = new globalThis.AbortController();
    const pending = traceIcmpRoute(
      socket,
      { family: "ipv4", address: "127.0.0.1" },
      {
        maxHops: 1,
        probesPerHop: 1,
        timeoutMilliseconds: 1_000,
        overallTimeoutMilliseconds: 1_000,
        signal: controller.signal,
      },
    );
    controller.abort();
    await assert.rejects(pending, { code: "ERR_ABORTED" });

    // A successful new claim proves traceroute released the normal lane while
    // leaving the caller-owned socket open.
    const source = new RawSocketEventEmitter(socket);
    assert.equal(await source.detach(), socket);
    assert.equal(socket.status, "open");
  } finally {
    await socket.close();
  }
}

// Warm the shared reactor before capturing its stable descriptor baseline.
await cycle();
await setImmediate();
const descriptorsBefore = readdirSync("/proc/self/fd").length;
const rssBefore = memoryUsage.rss();

for (let index = 0; index < ITERATIONS; index += 1) await cycle();
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
