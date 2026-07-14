import { performance } from "node:perf_hooks";
import { Buffer } from "node:buffer";
import { stdout } from "node:process";

import { RawSocket } from "../dist/index.js";

const MESSAGE_COUNT = 256;
const BATCH_SIZE = 32;

function echoRequest(sequence) {
  const packet = Buffer.alloc(8);
  packet[0] = 8;
  packet.writeUInt16BE(0x4e52, 4);
  packet.writeUInt16BE(sequence & 0xffff, 6);
  let sum = 0;
  for (let index = 0; index < packet.length; index += 2)
    sum += packet.readUInt16BE(index);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  packet.writeUInt16BE(~sum & 0xffff, 2);
  return packet;
}

function elapsed(start) {
  return performance.now() - start;
}

async function timeSequential(socket) {
  const start = performance.now();
  for (let index = 0; index < MESSAGE_COUNT; index += 1)
    await socket.sendMessage({
      data: echoRequest(index),
      destination: { family: "ipv4", address: "127.0.0.1" },
    });
  return elapsed(start);
}

async function timeBatches(socket) {
  const start = performance.now();
  for (let offset = 0; offset < MESSAGE_COUNT; offset += BATCH_SIZE) {
    const result = await socket.sendBatch(
      Array.from({ length: BATCH_SIZE }, (_, index) => ({
        data: echoRequest(offset + index),
        destination: { family: "ipv4", address: "127.0.0.1" },
      })),
    );
    if (result.completed !== BATCH_SIZE)
      throw new Error(`partial benchmark batch: ${String(result.completed)}`);
  }
  return elapsed(start);
}

async function timeControlParsing() {
  const socket = await RawSocket.open({ protocol: 1 });
  try {
    await socket.bind("127.0.0.1");
    await socket.setOption("receivePacketInfo", true);
    await socket.setOption("receiveTimestampNanoseconds", true);
    await socket.sendBatch(
      Array.from({ length: 64 }, (_, index) => ({
        data: echoRequest(index),
        destination: { family: "ipv4", address: "127.0.0.1" },
      })),
    );
    const start = performance.now();
    for (let index = 0; index < 64; index += 1) {
      const message = await socket.receiveMessage();
      if (message.control.length === 0)
        throw new Error("control benchmark received no ancillary data");
    }
    return elapsed(start);
  } finally {
    await socket.close();
  }
}

async function main() {
  const first = await RawSocket.open({ protocol: 1 });
  const second = await RawSocket.open({ protocol: 1 });
  try {
    await first.bind("127.0.0.1");
    await second.bind("127.0.0.1");
    const sequentialMs = await timeSequential(first);
    const batchMs = await timeBatches(first);

    const fairnessStart = performance.now();
    const [firstMs, secondMs] = await Promise.all([
      timeBatches(first),
      timeBatches(second),
    ]);
    const fairnessTotalMs = elapsed(fairnessStart);

    const copySource = Buffer.alloc(1024 * 1024, 0x5a);
    const copyStart = performance.now();
    for (let index = 0; index < 64; index += 1) Buffer.from(copySource);
    const copyMs = elapsed(copyStart);
    const controlParsingMs = await timeControlParsing();

    stdout.write(
      JSON.stringify(
        {
          messages: MESSAGE_COUNT,
          batchSize: BATCH_SIZE,
          sequentialMs,
          batchMs,
          speedup: sequentialMs / batchMs,
          twoHotSockets: {
            totalMs: fairnessTotalMs,
            firstMs,
            secondMs,
            completionSkewMs: Math.abs(firstMs - secondMs),
          },
          copyMiBPerSecond: 64 / (copyMs / 1000),
          controlParsing: {
            messages: 64,
            elapsedMs: controlParsingMs,
            messagesPerSecond: 64 / (controlParsingMs / 1000),
          },
        },
        null,
        2,
      ) + "\n",
    );
  } finally {
    await second.close();
    await first.close();
  }
}

await main();
