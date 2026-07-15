import { execFileSync } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import { cpus, totalmem } from "node:os";
import { setTimeout as delay } from "node:timers/promises";

import { RawSocket, interfaceIndex } from "../../nodenetraw/dist/index.js";
import { createScanner, inspectNetworkContext } from "../dist/index.js";
import {
  bootstrapCpuReduction,
  bootstrapThroughputRatio,
  summarize,
} from "./phase25-statistics.mjs";

const PREREGISTRATION = Object.freeze({
  schemaVersion: 1,
  warmupRepetitions: 2,
  measuredRepetitions: 10,
  scannerLogicalProbes: 1_024,
  scannerRates: [10_000, 50_000, 100_000],
  scannerTimeoutMs: 500,
  scannerQuiescenceMs: 250,
  frameCount: 640,
  frameBatchSize: 64,
  ringReceiveBatchSize: 16,
  frameBytes: 96,
  bootstrapResamples: 20_000,
  selection: {
    throughputRatio: 1.5,
    cpuReduction: 0.3,
    confidence: 0.95,
  },
});

const traceEnabled = process.env.NODENETSCANNER_PHASE25_TRACE === "1";

function trace(message) {
  if (traceEnabled) process.stderr.write(`[phase25] ${message}\n`);
}

function optionalCommand(command, arguments_) {
  try {
    return execFileSync(command, arguments_, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return undefined;
  }
}

function optionalRead(path) {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return undefined;
  }
}

function directoryNames(path) {
  try {
    return readdirSync(path).toSorted();
  } catch {
    return [];
  }
}

function driverName(name) {
  const path = `/sys/class/net/${name}/device/driver`;
  try {
    return basename(realpathSync(path));
  } catch {
    return undefined;
  }
}

function interfaceInventory() {
  const parsed = JSON.parse(
    optionalCommand("ip", ["-j", "-details", "link"]) ?? "[]",
  );
  return parsed.map((entry) => {
    const name = String(entry.ifname);
    const queues = directoryNames(`/sys/class/net/${name}/queues`);
    const driver = driverName(name);
    const driverInformation = optionalCommand("ethtool", ["-i", name]);
    return {
      index: entry.ifindex,
      name,
      mtu: entry.mtu,
      operationalState: entry.operstate,
      linkType: entry.link_type,
      queueCount: queues.length,
      queues,
      ...(driver === undefined ? {} : { driver }),
      ...(driverInformation === undefined ? {} : { driverInformation }),
    };
  });
}

function powercapDomains() {
  const root = "/sys/class/powercap";
  if (!existsSync(root)) return [];
  const results = [];
  const pending = [root];
  const visited = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    let canonicalCurrent;
    try {
      canonicalCurrent = realpathSync(current);
    } catch {
      continue;
    }
    if (visited.has(canonicalCurrent)) continue;
    visited.add(canonicalCurrent);
    for (const name of directoryNames(current)) {
      const path = join(current, name);
      let information;
      try {
        information = statSync(path);
      } catch {
        continue;
      }
      if (!information.isDirectory()) continue;
      let canonicalPath;
      try {
        canonicalPath = realpathSync(path);
      } catch {
        continue;
      }
      if (!visited.has(canonicalPath)) pending.push(canonicalPath);
      const energy = optionalRead(join(path, "energy_uj"));
      if (energy !== undefined) {
        results.push({
          path,
          name: optionalRead(join(path, "name")) ?? name,
          energyMicrojoules: energy,
          maximumEnergyRangeMicrojoules: optionalRead(
            join(path, "max_energy_range_uj"),
          ),
        });
      }
    }
  }
  return results;
}

function collectInventory() {
  return {
    timestamp: new Date().toISOString(),
    node: process.version,
    architecture: process.arch,
    kernel: optionalCommand("uname", ["-srvmo"]),
    cpu: cpus()[0]?.model,
    logicalCpuCount: cpus().length,
    totalMemoryBytes: totalmem(),
    cpuTopology: optionalCommand("lscpu", ["--json"]),
    numaOnline: optionalRead("/sys/devices/system/node/online"),
    interfaces: interfaceInventory(),
    powercapDomains: powercapDomains(),
    processAffinity: optionalCommand("taskset", ["-pc", String(process.pid)]),
  };
}

function cpuMeasurement(started, elapsedNanoseconds) {
  const usage = process.cpuUsage(started);
  const cpuMicroseconds = usage.user + usage.system;
  return {
    userMicroseconds: usage.user,
    systemMicroseconds: usage.system,
    totalMicroseconds: cpuMicroseconds,
    averageCores:
      cpuMicroseconds / (Number(elapsedNanoseconds) / Number(1_000n)),
  };
}

async function runScannerOnce(rate, portStart) {
  const scanner = await createScanner();
  try {
    const cpuStarted = process.cpuUsage();
    const started = process.hrtime.bigint();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.2/32" }],
      probes: [
        {
          kind: "tcpSyn",
          ports: [
            {
              start: portStart,
              end: portStart + PREREGISTRATION.scannerLogicalProbes - 1,
            },
          ],
        },
      ],
      deadlineMs: 20_000,
      timing: { timeoutMs: PREREGISTRATION.scannerTimeoutMs, retries: 0 },
      rate: {
        packetsPerSecond: rate,
        burst: PREREGISTRATION.scannerLogicalProbes,
        maxOutstanding: PREREGISTRATION.scannerLogicalProbes,
      },
    });
    const summary = await session.summary();
    const rttNanoseconds = [];
    let decodedResults = 0;
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 4_096 });
      if (batch === null) break;
      decodedResults += batch.length;
      for (const result of batch) {
        if (result.rttNanoseconds !== undefined)
          rttNanoseconds.push(Number(result.rttNanoseconds));
      }
    }
    const elapsedNanoseconds = process.hrtime.bigint() - started;
    await session.close();
    return {
      elapsedNanoseconds: elapsedNanoseconds.toString(),
      logicalProbes: summary.logicalProbes.toString(),
      results: summary.results.toString(),
      decodedResults,
      matched: summary.progress.matched.toString(),
      timedOut: summary.progress.timedOut.toString(),
      kernelDropped: summary.kernelDropped.toString(),
      applicationBackpressured:
        summary.progress.applicationBackpressured.toString(),
      forgedOrUnrelated: summary.forgedOrUnrelated.toString(),
      accuracyTradeoff: summary.accuracyTradeoff,
      configuredPacketsPerSecond: rate,
      probesPerSecond:
        Number(summary.logicalProbes) /
        (Number(elapsedNanoseconds) / 1_000_000_000),
      cpu: cpuMeasurement(cpuStarted, elapsedNanoseconds),
      ...(rttNanoseconds.length === 0
        ? { rttNanoseconds: null }
        : { rttNanoseconds: summarize(rttNanoseconds) }),
    };
  } finally {
    await scanner.close();
  }
}

function packetRequest(sequence, interfaceIndex_, destination) {
  const data = Buffer.alloc(PREREGISTRATION.frameBytes, 0x5a);
  data.writeUInt32BE(sequence >>> 0, 0);
  return {
    data,
    destination: {
      family: "packet",
      interfaceIndex: interfaceIndex_,
      protocol: 0x88b7,
      address: destination,
    },
  };
}

function echoRequest(sequence) {
  const packet = Buffer.alloc(PREREGISTRATION.frameBytes, 0x5a);
  packet[0] = 8;
  packet[1] = 0;
  packet.writeUInt16BE(0, 2);
  packet.writeUInt16BE(0x4e52, 4);
  packet.writeUInt16BE(sequence & 0xffff, 6);
  let sum = 0;
  for (let index = 0; index < packet.length; index += 2)
    sum += packet.readUInt16BE(index);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  packet.writeUInt16BE(~sum & 0xffff, 2);
  return {
    data: packet,
    destination: { family: "ipv4", address: "127.0.0.1" },
  };
}

async function withMmsgSocket(operation) {
  const socket = await RawSocket.open({ protocol: 1 });
  try {
    await socket.bind("127.0.0.1");
    return await operation(socket);
  } finally {
    await socket.close();
  }
}

async function withPacketSockets(receiverMode, operation) {
  const senderIndex = interfaceIndex("bench0");
  const receiverIndex = interfaceIndex("bench1");
  const receiver = await RawSocket.open({
    family: "packet",
    mode: "raw",
    protocol: 0x88b7,
  });
  const sender = await RawSocket.open({
    family: "packet",
    mode: "cooked",
    protocol: 0x88b7,
  });
  try {
    await receiver.bind({
      family: "packet",
      interfaceIndex: receiverIndex,
      protocol: 0x88b7,
    });
    await sender.bind({
      family: "packet",
      interfaceIndex: senderIndex,
      protocol: 0x88b7,
    });
    if (receiverMode === "ring") {
      const sanityReceive = receiver.receiveMessage({
        signal: globalThis.AbortSignal.timeout(2_000),
      });
      await sender.sendMessage(
        packetRequest(
          0xffff_fffe,
          senderIndex,
          Uint8Array.of(0x02, 0x00, 0x00, 0x00, 0x25, 0x02),
        ),
      );
      await sanityReceive;
      await receiver.configurePacketRing({
        blockSize: 4_096,
        blockCount: 2,
        frameSize: 2_048,
        retireTimeoutMs: 16,
      });
    }
    return await operation({ receiver, sender, senderIndex });
  } finally {
    await sender.close();
    await receiver.close();
  }
}

async function receiveMmsg(receiver, count) {
  let received = 0;
  while (received < count) {
    const result = await receiver.receiveBatch({
      count: Math.min(PREREGISTRATION.frameBatchSize, count - received),
      dataCapacity: 256,
      signal: globalThis.AbortSignal.timeout(2_000),
    });
    received += result.completed;
  }
  return received;
}

async function runMmsgOnce(socket, sequenceBase) {
  const cpuStarted = process.cpuUsage();
  const started = process.hrtime.bigint();
  let matched = 0;
  for (
    let offset = 0;
    offset < PREREGISTRATION.frameCount;
    offset += PREREGISTRATION.frameBatchSize
  ) {
    const count = Math.min(
      PREREGISTRATION.frameBatchSize,
      PREREGISTRATION.frameCount - offset,
    );
    const receiving = receiveMmsg(socket, count);
    const sent = await socket.sendBatch(
      Array.from({ length: count }, (_, index) =>
        echoRequest(sequenceBase + offset + index),
      ),
    );
    if (sent.completed !== count)
      throw new Error(`partial mmsg send: ${sent.completed}/${count}`);
    matched += await receiving;
  }
  const elapsedNanoseconds = process.hrtime.bigint() - started;
  return {
    elapsedNanoseconds: elapsedNanoseconds.toString(),
    matchedFrames: matched,
    framesPerSecond: matched / (Number(elapsedNanoseconds) / 1_000_000_000),
    loss: PREREGISTRATION.frameCount - matched,
    cpu: cpuMeasurement(cpuStarted, elapsedNanoseconds),
  };
}

async function runRingOnce(sockets, sequenceBase) {
  const cpuStarted = process.cpuUsage();
  const started = process.hrtime.bigint();
  let matched = 0;
  for (
    let offset = 0;
    offset < PREREGISTRATION.frameCount;
    offset += PREREGISTRATION.ringReceiveBatchSize
  ) {
    const count = Math.min(
      PREREGISTRATION.ringReceiveBatchSize,
      PREREGISTRATION.frameCount - offset,
    );
    const receiving = Array.from({ length: count }, () =>
      sockets.receiver.receiveRingFrame({
        signal: globalThis.AbortSignal.timeout(2_000),
      }),
    );
    const sent = await sockets.sender.sendBatch(
      Array.from({ length: count }, (_, index) =>
        packetRequest(
          sequenceBase + offset + index,
          sockets.senderIndex,
          Uint8Array.of(0x02, 0x00, 0x00, 0x00, 0x25, 0x02),
        ),
      ),
    );
    if (sent.completed !== count)
      throw new Error(`partial ring send: ${sent.completed}/${count}`);
    const leases = await Promise.all(receiving);
    for (const lease of leases) {
      const frame = lease.read();
      if (frame.length >= 14 + PREREGISTRATION.frameBytes) matched += 1;
      lease.release();
    }
  }
  const elapsedNanoseconds = process.hrtime.bigint() - started;
  return {
    elapsedNanoseconds: elapsedNanoseconds.toString(),
    matchedFrames: matched,
    framesPerSecond: matched / (Number(elapsedNanoseconds) / 1_000_000_000),
    loss: PREREGISTRATION.frameCount - matched,
    cpu: cpuMeasurement(cpuStarted, elapsedNanoseconds),
  };
}

async function repeated(name, callback, settleMilliseconds = 0) {
  trace(`${name}: starting warmups`);
  for (let index = 0; index < PREREGISTRATION.warmupRepetitions; index += 1) {
    await callback(-(index + 1) * 10_000_000);
    if (settleMilliseconds > 0) await delay(settleMilliseconds);
    trace(`${name}: warmup ${index + 1} complete`);
  }
  const runs = [];
  for (let index = 0; index < PREREGISTRATION.measuredRepetitions; index += 1) {
    runs.push(await callback(index * 10_000_000));
    if (settleMilliseconds > 0) await delay(settleMilliseconds);
    trace(`${name}: measured repetition ${index + 1} complete`);
  }
  return {
    name,
    runs,
    throughput: summarize(
      runs.map((run) => run.probesPerSecond ?? run.framesPerSecond),
    ),
    averageCores: summarize(runs.map((run) => run.cpu.averageCores)),
    elapsedMilliseconds: summarize(
      runs.map((run) => Number(run.elapsedNanoseconds) / 1_000_000),
    ),
  };
}

async function main() {
  if (process.argv.includes("--inventory")) {
    console.log(JSON.stringify(collectInventory()));
    return;
  }
  const namespaceContext = await inspectNetworkContext();
  const ringOnly = process.env.NODENETSCANNER_PHASE25_RING_ONLY === "1";
  const scanner = [];
  if (!ringOnly) {
    let scannerRepetition = 0;
    for (const rate of PREREGISTRATION.scannerRates) {
      scanner.push(
        await repeated(
          `portable-scanner-${rate}pps`,
          () => {
            const portStart =
              10_000 + scannerRepetition * PREREGISTRATION.scannerLogicalProbes;
            scannerRepetition += 1;
            return runScannerOnce(rate, portStart);
          },
          PREREGISTRATION.scannerQuiescenceMs,
        ),
      );
    }
  }
  const mmsg = ringOnly
    ? null
    : await withMmsgSocket((socket) =>
        repeated("sendmmsg+recvmmsg", (sequence) =>
          runMmsgOnce(socket, sequence),
        ),
      );
  const packetMmapRx = await withPacketSockets("ring", (sockets) =>
    repeated("sendmmsg+TPACKET_V3-RX", (sequence) =>
      runRingOnce(sockets, sequence),
    ),
  );
  const backendLab = [
    JSON.parse(
      execFileSync(
        "target/debug/examples/phase25_backend_lab",
        ["packet-mmap", "txlab0", "02:00:00:00:25:12", "640"],
        { encoding: "utf8" },
      ),
    ),
    JSON.parse(
      execFileSync(
        "target/debug/examples/phase25_backend_lab",
        ["af-xdp", "txlab0"],
        { encoding: "utf8" },
      ),
    ),
  ];
  const hostInventoryEncoded =
    process.env.NODENETSCANNER_PHASE25_HOST_INVENTORY;
  const hostInventory =
    hostInventoryEncoded === undefined
      ? null
      : JSON.parse(
          Buffer.from(hostInventoryEncoded, "base64").toString("utf8"),
        );
  const portableRateAnalysis = scanner.slice(1).map((candidate) => ({
    baseline: scanner[0].name,
    comparison: candidate.name,
    throughputRatio: bootstrapThroughputRatio(
      scanner[0].runs.map((run) => run.probesPerSecond),
      candidate.runs.map((run) => run.probesPerSecond),
    ),
    cpuReduction: bootstrapCpuReduction(
      scanner[0].runs.map((run) => run.cpu.averageCores),
      candidate.runs.map((run) => run.cpu.averageCores),
    ),
  }));
  const evidence = JSON.stringify(
    {
      schemaVersion: 1,
      timestamp: new Date().toISOString(),
      preregistration: PREREGISTRATION,
      inventory: {
        host: hostInventory,
        namespace: collectInventory(),
        scannerContext: namespaceContext.interfaces.map(
          ({ index, name, linkKind, mtu }) => ({
            index,
            name,
            linkKind,
            mtu,
          }),
        ),
      },
      workloads: { scannerRateSweep: scanner, mmsg, packetMmapRx },
      backendLab,
      analysis: {
        portableRateAnalysis,
        backendSelection: {
          outcome: "no-go",
          thresholdEvaluated: false,
          reason:
            "no candidate completed an identical end-to-end matched-result scanner workload",
        },
      },
      candidateEligibility: {
        mmsg: {
          eligibleAsExtremeBackend: false,
          reason:
            "control path only; ordinary bounded mmsg remains a portable optimization",
        },
        packetMmap: {
          eligibleAsExtremeBackend: false,
          reason:
            "disjoint TX and RX controls are not a matched-result scanner backend and cannot qualify ownership or parity",
        },
        afXdp: {
          eligibleAsExtremeBackend: false,
          reason:
            "no benchmark-owned XDP program/XSKMAP and no qualified zero-copy hardware fixture",
        },
      },
    },
    null,
    2,
  );
  const outputPath = process.env.NODENETSCANNER_PHASE25_OUTPUT;
  if (outputPath !== undefined && outputPath.length > 0)
    writeFileSync(outputPath, `${evidence}\n`);
  console.log(evidence);
}

await main();
