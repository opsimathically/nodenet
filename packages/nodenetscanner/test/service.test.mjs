import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import net from "node:net";
import test from "node:test";

import { ScannerError, createScanner } from "../dist/index.js";

async function listen(port, handler) {
  const server = net.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  return server;
}

async function close(server) {
  await new Promise((resolve, reject) =>
    server.close((error) => (error === undefined ? resolve() : reject(error))),
  );
}

function serverPort(server) {
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  return address.port;
}

test("bounded TCP conversations handle segmented HTTP and exact Redis requests", async () => {
  let httpRequest = "";
  const http = await listen(0, (socket) => {
    socket.on("data", (chunk) => {
      httpRequest += chunk.toString("ascii");
      if (httpRequest.endsWith("\r\n\r\n")) {
        socket.write("HTTP/1.1 200 OK\r\nSer");
        globalThis.setTimeout(() => {
          socket.end("ver: fixture\r\nContent-Type: text/plain\r\n\r\n");
        }, 5);
      }
    });
  });
  let redisRequest = "";
  const redis = await listen(0, (socket) => {
    socket.on("data", (chunk) => {
      redisRequest += chunk.toString("ascii");
      if (redisRequest === "*1\r\n$4\r\nPING\r\n") {
        socket.write("+PO");
        globalThis.setTimeout(() => socket.end("NG\r\n"), 5);
      }
    });
  });
  const scanner = await createScanner();
  try {
    const httpRun = await scanner.identifyService({
      capabilityId: "http-head",
      target: "127.0.0.1",
      port: serverPort(http),
      deadlineMs: 1_000,
      allowRisks: ["clientNegotiation"],
    });
    assert.equal(httpRun.outcome, "identified");
    assert.equal(httpRun.protocol, "http");
    assert.match(httpRequest, /^HEAD \/ HTTP\/1\.1\r\nHost: 127\.0\.0\.1\r\n/);
    assert.equal(
      Buffer.from(
        httpRun.fields.find((field) => field.key === "server")?.value ?? [],
      ).toString(),
      "fixture",
    );
    const redisRun = await scanner.identifyService({
      capabilityId: "redis-ping",
      target: "127.0.0.1",
      port: serverPort(redis),
      deadlineMs: 1_000,
      allowRisks: ["clientNegotiation"],
    });
    assert.equal(redisRun.outcome, "identified");
    assert.equal(redisRun.protocol, "redis");
    assert.equal(redisRequest, "*1\r\n$4\r\nPING\r\n");
  } finally {
    await scanner.close();
    await Promise.all([close(http), close(redis)]);
  }
});

test("server-first identity and PostgreSQL negotiation remain credential-free", async () => {
  const cases = [
    ["ssh-identification", "SSH-2.0-fixture\r\n", "ssh"],
    ["ftp-greeting", "220 fixture FTP\r\n", "ftp"],
    ["smtp-greeting", "220 fixture ESMTP\r\n", "smtp"],
    ["pop3-greeting", "+OK fixture\r\n", "pop3"],
    ["imap-greeting", "* OK fixture\r\n", "imap"],
  ];
  const scanner = await createScanner();
  try {
    for (const [capabilityId, response, protocol] of cases) {
      let received = 0;
      const server = await listen(0, (socket) => {
        socket.on("data", (chunk) => {
          received += chunk.length;
        });
        socket.write(response.slice(0, 3));
        globalThis.setTimeout(() => socket.end(response.slice(3)), 2);
      });
      const run = await scanner.identifyService({
        capabilityId,
        target: "127.0.0.1",
        port: serverPort(server),
        deadlineMs: 1_000,
        allowRisks: ["serverFirst"],
      });
      assert.equal(run.outcome, "identified");
      assert.equal(run.protocol, protocol);
      assert.equal(run.requestBytes, 0);
      assert.equal(received, 0);
      await close(server);
    }
    const postgres = await listen(0, (socket) => {
      socket.once("data", (chunk) => {
        assert.deepEqual(chunk, Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]));
        socket.end("S");
      });
    });
    const run = await scanner.identifyService({
      capabilityId: "postgresql-ssl-request",
      target: "127.0.0.1",
      port: serverPort(postgres),
      deadlineMs: 1_000,
      allowRisks: ["clientNegotiation"],
    });
    assert.equal(run.outcome, "identified");
    assert.equal(run.protocol, "postgresql");
    assert.equal(run.confidence, "tlsSupported");
    await close(postgres);
  } finally {
    await scanner.close();
  }
});

test("segmented MySQL handshakes remain incomplete until the declared packet arrives", async () => {
  const body = Buffer.concat([
    Buffer.from([10]),
    Buffer.from("8.4.0\0", "ascii"),
    Buffer.from([1, 0, 0, 0]),
  ]);
  const packet = Buffer.concat([Buffer.from([body.length, 0, 0, 0]), body]);
  const server = await listen(0, (socket) => {
    socket.write(packet.subarray(0, 6));
    globalThis.setTimeout(() => socket.end(packet.subarray(6)), 5);
  });
  const scanner = await createScanner();
  try {
    const run = await scanner.identifyService({
      capabilityId: "mysql-initial-handshake",
      target: "127.0.0.1",
      port: serverPort(server),
      deadlineMs: 1_000,
      allowRisks: ["serverFirst"],
    });
    assert.equal(run.outcome, "identified");
    assert.equal(run.protocol, "mysql");
  } finally {
    await scanner.close();
    await close(server);
  }
});

test("TCP conversation bounds distinguish parser failure, overflow, refusal, and cancellation", async () => {
  const malformed = await listen(0, (socket) => {
    socket.end("not-http\r\n\r\n");
    socket.resume();
  });
  const oversized = await listen(0, (socket) => {
    socket.once("data", () => socket.end(Buffer.alloc(4_096, 0x41)));
  });
  const slow = await listen(0, (socket) => socket.resume());
  const malformedPort = serverPort(malformed);
  const scanner = await createScanner();
  try {
    assert.equal(
      (
        await scanner.identifyService({
          capabilityId: "http-head",
          target: "127.0.0.1",
          port: malformedPort,
          deadlineMs: 1_000,
          allowRisks: ["clientNegotiation"],
        })
      ).outcome,
      "parserRejected",
    );
    assert.equal(
      (
        await scanner.identifyService({
          capabilityId: "redis-ping",
          target: "127.0.0.1",
          port: serverPort(oversized),
          deadlineMs: 1_000,
          allowRisks: ["clientNegotiation"],
        })
      ).outcome,
      "responseLimit",
    );
    await close(malformed);
    assert.equal(
      (
        await scanner.identifyService({
          capabilityId: "http-head",
          target: "127.0.0.1",
          port: malformedPort,
          deadlineMs: 1_000,
          allowRisks: ["clientNegotiation"],
        })
      ).outcome,
      "connectRefused",
    );
    const controller = new globalThis.AbortController();
    const running = scanner.identifyService(
      {
        capabilityId: "http-head",
        target: "127.0.0.1",
        port: serverPort(slow),
        deadlineMs: 30_000,
        allowRisks: ["clientNegotiation"],
      },
      { signal: controller.signal },
    );
    globalThis.setTimeout(() => controller.abort(), 25);
    const cancelled = await running;
    assert.equal(cancelled.state, "cancelled");
    assert.equal(cancelled.outcome, "cancelled");
  } finally {
    await scanner.close();
    if (malformed.listening) await close(malformed);
    await Promise.all([close(oversized), close(slow)]);
  }
});

test("service capability and risk policy fail before TCP I/O", async () => {
  const scanner = await createScanner();
  try {
    for (const plan of [
      {
        capabilityId: "tls-client-hello",
        target: "127.0.0.1",
        port: 443,
        deadlineMs: 100,
        allowRisks: ["statefulHandshake"],
      },
      {
        capabilityId: "redis-ping",
        target: "127.0.0.1",
        port: 6379,
        deadlineMs: 100,
        allowRisks: [],
      },
    ]) {
      await assert.rejects(
        scanner.identifyService(plan),
        (error) =>
          error instanceof ScannerError && error.kind === "invalidPlan",
      );
    }
  } finally {
    await scanner.close();
  }
});

test("service conversations share the exact four-session admission ceiling", async () => {
  const server = await listen(0, (socket) => socket.resume());
  const scanner = await createScanner();
  const controllers = Array.from(
    { length: 4 },
    () => new globalThis.AbortController(),
  );
  const plan = {
    capabilityId: "http-head",
    target: "127.0.0.1",
    port: serverPort(server),
    deadlineMs: 30_000,
    allowRisks: ["clientNegotiation"],
  };
  try {
    const running = controllers.map((controller) =>
      scanner.identifyService(plan, { signal: controller.signal }),
    );
    await assert.rejects(
      scanner.identifyService(plan),
      (error) =>
        error instanceof ScannerError && error.kind === "resourceLimit",
    );
    for (const controller of controllers) controller.abort();
    assert.ok(
      (await Promise.all(running)).every((run) => run.state === "cancelled"),
    );
    const replacementController = new globalThis.AbortController();
    const replacement = scanner.identifyService(plan, {
      signal: replacementController.signal,
    });
    replacementController.abort();
    assert.equal((await replacement).state, "cancelled");
  } finally {
    for (const controller of controllers) controller.abort();
    await scanner.close();
    await close(server);
  }
});
