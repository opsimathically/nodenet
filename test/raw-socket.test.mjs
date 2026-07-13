import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { URL } from "node:url";
import { Worker } from "node:worker_threads";

import {
  RawSocket,
  RawSocketError,
  interfaceIndex,
  interfaceName,
} from "../dist/index.js";

test("rejects malformed open options at the public boundary", async () => {
  const invalidOptions = [
    null,
    {},
    { protocol: 0 },
    { protocol: 1.5 },
    { protocol: 256 },
    { protocol: Number.NaN },
    { protocol: "1" },
    { family: "packet", protocol: 1 },
    { family: "packet", mode: "other", protocol: 1 },
    { family: "packet", mode: "raw", protocol: 0 },
    { family: "packet", mode: "cooked", protocol: 65_536 },
  ];

  for (const options of invalidOptions) {
    await assert.rejects(RawSocket.open(options), (error) => {
      assert.ok(error instanceof RawSocketError);
      assert.equal(error.code, "ERR_INVALID_ARGUMENT");
      assert.equal(error.kind, "invalidArgument");
      assert.equal(error.errno, undefined);
      return true;
    });
  }
});

test("validates interface lookup and packet socket permissions", async () => {
  const loopback = interfaceIndex("lo");
  assert.ok(loopback > 0);
  assert.equal(interfaceName(loopback), "lo");
  assert.throws(() => interfaceIndex(""), { code: "ERR_INVALID_ARGUMENT" });
  assert.throws(() => interfaceName(0), { code: "ERR_INVALID_ARGUMENT" });

  let socket;
  try {
    socket = await RawSocket.open({
      family: "packet",
      mode: "cooked",
      protocol: 3,
    });
  } catch (error) {
    assert.ok(error instanceof RawSocketError);
    assert.equal(error.code, "ERR_SYSTEM");
    assert.equal(error.operation, "createPacketSocket");
    return;
  }
  assert.equal(socket.family, "packet");
  assert.equal(socket.packetMode, "cooked");
  await assert.rejects(
    socket.bind({ family: "packet", interfaceIndex: 0, protocol: 3 }),
    {
      code: "ERR_INVALID_ARGUMENT",
    },
  );
  await assert.rejects(socket.setOption("bindToDevice", "lo"), {
    code: "ERR_UNSUPPORTED",
  });
  await assert.rejects(socket.disconnect(), {
    code: "ERR_UNSUPPORTED",
    operation: "disconnect",
  });
  await assert.rejects(
    socket.configurePacketRing({ blockSize: 4097, frameSize: 256 }),
    { code: "ERR_INVALID_ARGUMENT" },
  );
  await socket.close();
});

test("creates and tears down an independent worker environment reactor", async () => {
  const worker = new Worker(
    new URL("./fixtures/worker-open.mjs", import.meta.url),
  );
  const exit = once(worker, "exit");
  const [result] = await once(worker, "message");

  assert.equal(result.completed, true);
  assert.equal((await exit)[0], 0);
});

test("preserves Linux permission errors or safely closes an available socket", async () => {
  let socket;
  try {
    socket = await RawSocket.open({ protocol: 1 });
  } catch (error) {
    assert.ok(error instanceof RawSocketError);
    assert.equal(error.code, "ERR_SYSTEM");
    assert.equal(error.kind, "system");
    assert.equal(error.operation, "createRawIpv4Socket");
    assert.equal(typeof error.errno, "number");
    assert.equal(typeof error.errnoName, "string");
    return;
  }

  assert.equal(socket.status, "open");
  await assert.rejects(socket.bind("localhost"), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "bind",
  });
  await assert.rejects(socket.getOption("unsupported"), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "getOption",
  });
  await assert.rejects(socket.setOption("ipTtl", 0), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "setOption",
  });
  await assert.rejects(socket.setOption("broadcast", 1), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "setOption",
  });
  await assert.rejects(socket.setOption("ipv6Only", true), {
    code: "ERR_INVALID_ARGUMENT",
  });
  await assert.rejects(socket.setOption("bindToDevice", ""), {
    code: "ERR_INVALID_ARGUMENT",
  });
  const socketType = await socket.getSocketOption(1, 3, 4);
  assert.equal(socketType.byteLength, 4);
  await assert.rejects(socket.getSocketOption(1, 26, 16), {
    code: "ERR_UNSUPPORTED",
  });
  await assert.rejects(
    socket.attachClassicFilter([
      { code: 0x05, jumpTrue: 0, jumpFalse: 0, value: 99 },
    ]),
    { code: "ERR_INVALID_ARGUMENT" },
  );
  await assert.rejects(socket.attachEbpfFilter(-1), {
    code: "ERR_INVALID_ARGUMENT",
  });
  await assert.rejects(socket.sendBatch([]), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "sendBatch",
  });
  await assert.rejects(socket.receiveBatch({ count: 0 }), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "receiveBatch",
  });
  await assert.rejects(socket.receiveBatch({ count: 64 }), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "receiveBatch",
  });
  await assert.rejects(socket.configurePacketRing(), {
    code: "ERR_INVALID_ARGUMENT",
    operation: "configurePacketRing",
  });
  await assert.rejects(
    socket.sendMessage({
      data: Uint8Array.of(8),
      destination: { family: "ipv4", address: "not-an-address" },
    }),
    { code: "ERR_INVALID_ARGUMENT", operation: "sendMessage" },
  );
  await assert.rejects(socket.receiveMessage({ controlCapacity: 65_537 }), {
    code: "ERR_INVALID_ARGUMENT",
  });
  const controller = new globalThis.AbortController();
  controller.abort();
  await assert.rejects(socket.receive(64, { signal: controller.signal }), {
    code: "ERR_ABORTED",
    kind: "aborted",
  });
  await socket.close();
  assert.equal(socket.status, "closed");
  await socket.close();
  await assert.rejects(socket.receive(), { code: "ERR_SOCKET_CLOSED" });
  await assert.rejects(socket.send(Uint8Array.of(8), "127.0.0.1"), {
    code: "ERR_SOCKET_CLOSED",
  });
  await assert.rejects(socket.localAddress(), {
    code: "ERR_SOCKET_CLOSED",
  });
  await assert.rejects(socket.getOption("ipTtl"), {
    code: "ERR_SOCKET_CLOSED",
  });
});

test("preserves IPv6 permission errors or exposes the family safely", async () => {
  let socket;
  try {
    socket = await RawSocket.open({ family: "ipv6", protocol: 58 });
  } catch (error) {
    assert.ok(error instanceof RawSocketError);
    assert.equal(error.code, "ERR_SYSTEM");
    assert.equal(error.operation, "createRawIpv6Socket");
    return;
  }
  assert.equal(socket.family, "ipv6");
  await assert.rejects(socket.bind({ family: "ipv4", address: "127.0.0.1" }), {
    code: "ERR_INVALID_ARGUMENT",
  });
  await assert.rejects(socket.setOption("broadcast", true), {
    code: "ERR_INVALID_ARGUMENT",
  });
  await socket.close();
});
