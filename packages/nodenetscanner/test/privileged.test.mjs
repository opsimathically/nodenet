import assert from "node:assert/strict";
import test from "node:test";

import { createScanner } from "../dist/index.js";

const enabled = process.env.NODENETSCANNER_PRIVILEGED_TESTS === "1";
const matrix = process.env.NODENETSCANNER_NAMESPACE_MATRIX === "1";

test(
  "portable engine scans IPv4 loopback with ICMP and TCP",
  { skip: !enabled },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "tcpSyn", ports: [9] },
      ],
      deadlineMs: 5_000,
      timing: { timeoutMs: 500, retries: 0 },
      rate: { packetsPerSecond: 100, burst: 2, maxOutstanding: 2 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.results, 2n);
    assert.ok(summary.progress.sent >= 2n);
    assert.ok(summary.progress.matched >= 2n);
    assertResult(results, "127.0.0.1", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "127.0.0.1", "tcpSyn", 9, "closed");
    await session.close();
    await scanner.close();
  },
);

test(
  "terminal compact pulls scale with batches instead of probe rows",
  { skip: !enabled },
  async (context) => {
    const cpuStart = process.cpuUsage();
    const wallStart = globalThis.performance.now();
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [{ kind: "tcpSyn", ports: [{ start: 20_000, end: 20_255 }] }],
      deadlineMs: 10_000,
      timing: { timeoutMs: 500, retries: 0 },
      rate: {
        packetsPerSecond: 10_000,
        burst: 256,
        maxOutstanding: 256,
      },
    });
    const summary = await session.summary();
    assert.equal(summary.results, 256n);
    let batches = 0;
    let rows = 0;
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 64 });
      if (batch === null) break;
      batches += 1;
      rows += batch.length;
    }
    assert.equal(rows, 256);
    assert.equal(batches, 4);
    const cpu = process.cpuUsage(cpuStart);
    context.diagnostic(
      `256 rows / ${String(batches)} N-API pulls; ${(
        globalThis.performance.now() - wallStart
      ).toFixed(2)} ms wall; ${String(cpu.user + cpu.system)} µs process CPU`,
    );
    await session.close();
    await scanner.close();
  },
);

test(
  "portable engine covers dual-stack discovery and transport evidence",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
      probes: [
        { kind: "arp" },
        { kind: "ndp" },
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "icmpEcho", family: "ipv6" },
        { kind: "tcpSyn", ports: [18080, 18081] },
        {
          kind: "udp",
          ports: [18082, 18083, 18084],
          policy: { mode: "empty" },
        },
      ],
      deadlineMs: 10_000,
      timing: { timeoutMs: 1_000, retries: 0 },
      rate: { packetsPerSecond: 500, burst: 16, maxOutstanding: 16 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.error, undefined, formatValue(summary));
    assert.ok(summary.progress.sent >= summary.results);
    assert.ok(summary.progress.received > 0n);
    assert.ok(summary.progress.matched > 0n);
    assertResult(results, "192.0.2.2", "arp", undefined, "up");
    assertResult(results, "2001:db8:22::2", "ndp", undefined, "up");
    assertResult(results, "192.0.2.2", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "2001:db8:22::2", "icmpEchoIpv6", undefined, "up");
    assertResult(results, "192.0.2.2", "tcpSyn", 18080, "open");
    assertResult(results, "2001:db8:22::2", "tcpSyn", 18081, "closed");
    assertResult(results, "192.0.2.2", "udp", 18082, "open");
    assertResult(results, "2001:db8:22::2", "udp", 18083, "closed");
    assertResult(results, "2001:db8:22::2", "udp", 18084, "open");
    await session.close();
    await scanner.close();
  },
);

test(
  "discovery executes bounded dual-stack rpcbind-derived NFS child work",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.startDiscovery({
      scope: {
        kind: "targets",
        targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
        families: ["ipv4", "ipv6"],
      },
      operations: [{ operation: "rpcbindGetAddress", followUp: true }],
      allowRisks: ["sensitiveRead"],
      deadlineMs: 5_000,
    });
    const results = [];
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 2 });
      if (batch === null) break;
      results.push(...batch);
    }
    assert.equal(results.length, 4);
    const parents = new Map(
      results
        .filter((row) => row.derivationKind === undefined)
        .map((row) => [row.entityId, row]),
    );
    const children = results.filter(
      (row) => row.derivationKind === "rpcbindGetAddress",
    );
    assert.equal(parents.size, 2);
    assert.equal(children.length, 2);
    for (const child of children) {
      assert.equal(child.kind, "derivedService");
      assert.ok(child.parentEntityId !== undefined);
      assert.ok(parents.has(child.parentEntityId));
      assert.equal(
        parents.get(child.parentEntityId)?.responder,
        child.responder,
      );
    }
    const summary = await session.summary();
    assert.equal(summary.state, "completed");
    assert.equal(summary.results, 4n);
    assert.equal(summary.progress.sent, 4n);
    await session.close();
    await scanner.close();
  },
);

test(
  "link discovery attributes and merges dual-stack multicast evidence",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.startDiscovery({
      scope: {
        kind: "links",
        interfaces: ["scan0"],
        families: ["ipv4", "ipv6"],
      },
      operations: [
        { operation: "mdnsDnsSdLegacy", receiveMode: "legacyUnicast" },
        { operation: "wsDiscoveryProbe" },
        { operation: "llmnrQuery", query: "fixture.local." },
      ],
      allowRisks: ["multicastOrBroadcast", "sensitiveRead"],
      deadlineMs: 5_000,
    });
    const results = [];
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 2 });
      if (batch === null) break;
      results.push(...batch);
    }
    assert.deepEqual(
      Object.fromEntries(
        ["mdns-dns-sd-legacy", "ws-discovery-probe", "llmnr-query"].map(
          (protocol) => [
            protocol,
            results.filter((row) => row.protocol === protocol).length,
          ],
        ),
      ),
      {
        "mdns-dns-sd-legacy": 2,
        "ws-discovery-probe": 2,
        "llmnr-query": 2,
      },
    );
    for (const result of results) {
      assert.ok(result.interfaceIndex !== undefined);
    }
    for (const result of results.filter(
      (row) => row.protocol === "mdns-dns-sd-legacy",
    ))
      assert.deepEqual(result.addresses, ["192.0.2.2", "2001:db8::2"]);
    assert.deepEqual(
      results
        .filter((row) => row.protocol === "llmnr-query")
        .flatMap((row) => row.addresses)
        .sort(),
      ["192.0.2.2", "2001:db8:22::2"],
    );
    const summary = await session.summary();
    assert.equal(summary.state, "completed");
    assert.equal(summary.results, 6n);
    assert.equal(summary.progress.sent, 16n);
    assert.equal(summary.progress.duplicate, 8n);
    assert.deepEqual(summary.receiveModes, ["legacyUnicast"]);
    await session.close();
    await scanner.close();
  },
);

test(
  "portable engine sends and receives an explicit VLAN path",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "198.51.100.2/32" }],
      probes: [
        { kind: "arp" },
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "tcpSyn", ports: [18080] },
        { kind: "udp", ports: [18082], policy: { mode: "empty" } },
      ],
      deadlineMs: 10_000,
      interface: "scan0",
      sourceAddress: "198.51.100.1",
      vlan: { identifier: 42 },
      timing: { timeoutMs: 1_000, retries: 0 },
      rate: { packetsPerSecond: 200, burst: 4, maxOutstanding: 4 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.error, undefined, formatValue(summary));
    assert.ok(summary.progress.sent >= summary.results);
    assertResult(results, "198.51.100.2", "arp", undefined, "up");
    assertResult(results, "198.51.100.2", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "198.51.100.2", "tcpSyn", 18080, "open");
    assertResult(results, "198.51.100.2", "udp", 18082, "open");
    await session.close();
    await scanner.close();
  },
);

test(
  "omitted UDP policy sends the safe DNS probe and emits schema 2 service evidence",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
      probes: [{ kind: "udp", ports: [53] }],
      deadlineMs: 5_000,
      timing: { timeoutMs: 1_000, retries: 0 },
      rate: { packetsPerSecond: 100, burst: 1, maxOutstanding: 1 },
    });
    const results = [];
    let sawDnsEvidence = false;
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 16 });
      if (batch === null) break;
      assert.equal(batch.schemaVersion, 2);
      const columns = batch.columns;
      assert.ok("terminalUdpProbeIds" in columns);
      const ids = new DataView(
        columns.terminalUdpProbeIds.buffer,
        columns.terminalUdpProbeIds.byteOffset,
        columns.terminalUdpProbeIds.byteLength,
      );
      const families = new DataView(
        columns.udpServiceFamilies.buffer,
        columns.udpServiceFamilies.byteOffset,
        columns.udpServiceFamilies.byteLength,
      );
      for (let row = 0; row < batch.length; row += 1) {
        if (
          ids.getUint16(row * 2, true) === 1 &&
          families.getUint16(row * 2, true) === 1 &&
          columns.udpServiceConfidences[row] === 3
        ) {
          sawDnsEvidence = true;
        }
      }
      results.push(...batch.results);
    }
    assertResult(results, "192.0.2.2", "udp", 53, "open");
    assertResult(results, "2001:db8:22::2", "udp", 53, "open");
    assert.equal(sawDnsEvidence, true);
    assert.equal((await session.summary()).schemaVersion, 2);
    await session.close();
    await scanner.close();
  },
);

test(
  "comprehensive UDP risks admit only consented Phase 30 probes and parse every responder",
  { skip: !matrix },
  async () => {
    const probes = new Map([
      [137, [10, 10, 3]],
      [2049, [11, 11, 3]],
      [5060, [12, 12, 3]],
      [1900, [13, 13, 2]],
      [1701, [14, 14, 3]],
      [161, [15, 15, 3]],
      [11211, [16, 8, 3]],
    ]);
    const expected = new Map();
    for (const [port, evidence] of probes) {
      expected.set(`192.0.2.2/${String(port)}`, [...evidence, "open"]);
      expected.set(
        `2001:db8:22::2/${String(port)}`,
        port === 137 ? [0, 0, 0, "open|filtered"] : [...evidence, "open"],
      );
    }
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
      probes: [
        {
          kind: "udp",
          ports: [...probes.keys()],
          policy: {
            mode: "protocol",
            profile: "comprehensive",
            intensity: 7,
            strategy: "exhaustive",
            emptyFallback: "never",
            allowRisks: [
              "highAmplification",
              "statefulHandshake",
              "authenticationAttempt",
              "sensitiveRead",
            ],
          },
        },
      ],
      deadlineMs: 10_000,
      timing: {
        timeoutMs: 1_000,
        maximumTimeoutMs: 10_000,
        retries: 0,
      },
      rate: { packetsPerSecond: 500, burst: 8, maxOutstanding: 8 },
    });
    const found = new Map();
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 16 });
      if (batch === null) break;
      assert.equal(batch.schemaVersion, 2);
      const ids = new DataView(
        batch.columns.terminalUdpProbeIds.buffer,
        batch.columns.terminalUdpProbeIds.byteOffset,
        batch.columns.terminalUdpProbeIds.byteLength,
      );
      const families = new DataView(
        batch.columns.udpServiceFamilies.buffer,
        batch.columns.udpServiceFamilies.byteOffset,
        batch.columns.udpServiceFamilies.byteLength,
      );
      for (let row = 0; row < batch.length; row += 1) {
        const result = batch.results[row];
        found.set(`${result.target}/${String(result.port)}`, [
          ids.getUint16(row * 2, true),
          families.getUint16(row * 2, true),
          batch.columns.udpServiceConfidences[row],
          result.state,
        ]);
      }
    }
    for (const [endpoint, evidence] of expected) {
      assert.deepEqual(found.get(endpoint), evidence, endpoint);
    }
    assert.equal((await session.summary()).error, undefined);
    await session.close();
    await scanner.close();
  },
);

test(
  "adaptive UDP preserves DNS service recall while reducing physical requests",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const samples = { exhaustive: [], adaptive: [] };
    for (const strategy of ["exhaustive", "adaptive"]) {
      for (let repetition = 0; repetition < 10; repetition += 1) {
        const session = await scanner.start({
          targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
          probes: [
            {
              kind: "udp",
              ports: [53],
              policy: {
                mode: "protocol",
                profile: "legacy",
                intensity: 9,
                strategy,
                emptyFallback: "never",
                allowRisks: ["highAmplification", "sensitiveRead"],
              },
            },
          ],
          deadlineMs: 3_000,
          timing: {
            timeoutMs: 500,
            minimumTimeoutMs: 500,
            maximumTimeoutMs: 500,
            retries: 0,
          },
          rate: { packetsPerSecond: 1_000, burst: 4, maxOutstanding: 4 },
        });
        const results = [];
        for (;;) {
          const batch = await session.nextBatch({ maxResults: 4 });
          if (batch === null) break;
          results.push(...batch.results.materialize());
        }
        assert.equal(results.length, 2);
        assert.ok(results.every((result) => result.state === "open"));
        assert.ok(results.every((result) => result.udpServiceFamily === 1));
        assert.equal(results[0].transmissions, results[1].transmissions);
        const summary = await session.summary();
        assert.equal(summary.udp.policy.strategy, strategy);
        assert.equal(summary.udp.catalogue.version, "1.3.0");
        assert.ok(summary.progress.sent >= BigInt(results[0].transmissions));
        samples[strategy].push(results[0].transmissions);
        await session.close();
      }
    }
    samples.exhaustive.sort((left, right) => left - right);
    samples.adaptive.sort((left, right) => left - right);
    assert.equal(samples.exhaustive[5], 2);
    assert.equal(samples.adaptive[5], 1);
    await scanner.close();
  },
);

test(
  "UDP exact and explicit prefix policies preserve their captured wire payloads",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    for (const [port, policy] of [
      [
        18085,
        {
          mode: "custom",
          payload: Uint8Array.from([0, 0xff, 1, 2]),
          correlation: "tuple",
        },
      ],
      [
        18086,
        {
          mode: "custom",
          payload: Uint8Array.from([1, 2, 3]),
          correlation: "prefixToken",
        },
      ],
    ]) {
      const session = await scanner.start({
        targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
        probes: [{ kind: "udp", ports: [port], policy }],
        deadlineMs: 5_000,
        timing: { timeoutMs: 1_000, retries: 0 },
        rate: { packetsPerSecond: 100, burst: 2, maxOutstanding: 2 },
      });
      const results = await drain(session);
      assertResult(results, "192.0.2.2", "udp", port, "open");
      assertResult(results, "2001:db8:22::2", "udp", port, "open");
      await session.close();
    }
    await scanner.close();
  },
);

async function drain(session) {
  const results = [];
  for (;;) {
    const batch = await session.nextBatch({ maxResults: 64 });
    if (batch === null) return results;
    assert.ok(batch.schemaVersion === 1 || batch.schemaVersion === 2);
    assert.equal(batch.byteOrder, "little-endian");
    assert.ok(batch.length > 0 && batch.length <= 64);
    assert.ok(
      Array.from(batch).every(
        (result) => typeof result.timestampNanoseconds === "bigint",
      ),
    );
    results.push(...batch.results);
  }
}

function assertResult(results, target, probe, port, state) {
  assert.ok(
    results.some(
      (result) =>
        result.target === target &&
        result.probe === probe &&
        result.port === port &&
        result.state === state,
    ),
    `missing ${target} ${probe} ${String(port)} ${state}: ${formatValue(results.map((result) => result.materialize()))}`,
  );
}

function formatValue(value) {
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item,
  );
}
