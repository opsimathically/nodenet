import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter, errorMonitor } from "node:events";
import test from "node:test";
import { URL, fileURLToPath } from "node:url";

import { EventReceiveController } from "../dist/internal/event-controller.js";
import { createInternalFinalizers } from "../dist/internal/finalizers.js";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function controllerHarness(overrides = {}) {
  const receives = [];
  const events = [];
  const close = deferred();
  let active = 0;
  let maximumActive = 0;
  let releases = 0;
  let removals = 0;

  const driver = {
    receive(signal) {
      const operation = deferred();
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      operation.promise.then(
        () => {
          active -= 1;
        },
        () => {
          active -= 1;
        },
      );
      signal.addEventListener(
        "abort",
        () => {
          operation.reject({ kind: "aborted" });
        },
        { once: true },
      );
      receives.push(operation);
      return operation.promise;
    },
    close() {
      return close.promise;
    },
    releaseClaim() {
      releases += 1;
    },
    removeCloseObserver() {
      removals += 1;
    },
    detachValue() {
      return "socket";
    },
    dispatchMessage(message) {
      events.push(["message", message]);
    },
    dispatchError(error) {
      events.push(["error", error]);
    },
    dispatchClose() {
      events.push(["close"]);
    },
    invalidState(operation) {
      return Object.assign(new Error(`invalid ${operation}`), {
        code: "ERR_INVALID_STATE",
      });
    },
    socketClosed(operation) {
      return Object.assign(new Error(`closed ${operation}`), {
        code: "ERR_SOCKET_CLOSED",
      });
    },
    isAborted(error) {
      return error?.kind === "aborted";
    },
    isSocketClosed(error) {
      return error?.kind === "socketClosed";
    },
    isReactorClosed(error) {
      return error?.kind === "reactorClosed";
    },
    ...overrides,
  };
  const controller = new EventReceiveController(driver);
  return {
    controller,
    receives,
    events,
    close,
    get maximumActive() {
      return maximumActive;
    },
    get releases() {
      return releases;
    },
    get removals() {
      return removals;
    },
  };
}

async function flushMicrotasks(count = 4) {
  for (let index = 0; index < count; index += 1) await Promise.resolve();
}

test("runs internal finalizers once, in order, with fault isolation", () => {
  const finalizers = createInternalFinalizers();
  const order = [];
  finalizers.add(() => order.push(1));
  finalizers.add(() => {
    order.push(2);
    throw new Error("injected cleanup fault");
  });
  finalizers.add(() => order.push(3));
  finalizers.run();
  finalizers.run();
  assert.deepEqual(order, [1, 2, 3]);
  assert.throws(() => finalizers.add(() => undefined), /after settlement/);
});

test("rearms exactly one receive after synchronous message dispatch", async () => {
  const harness = controllerHarness();
  harness.controller.start();
  assert.equal(harness.controller.status, "running");
  await flushMicrotasks();
  assert.equal(harness.receives.length, 1);

  harness.receives[0].resolve("one");
  await flushMicrotasks(6);
  assert.deepEqual(harness.events, [["message", "one"]]);
  assert.equal(harness.receives.length, 2);
  assert.equal(harness.maximumActive, 1);

  await harness.controller.pause();
  assert.equal(harness.controller.status, "paused");
  assert.equal(harness.receives.length, 2);
});

test("delivers a fulfilled turn before the pause boundary", async () => {
  const harness = controllerHarness();
  harness.controller.start();
  await flushMicrotasks();
  harness.receives[0].resolve("won");
  const pause = harness.controller.pause();
  assert.equal(harness.controller.status, "pausing");
  await pause;
  assert.deepEqual(harness.events, [["message", "won"]]);
  assert.equal(harness.controller.status, "paused");
  assert.equal(harness.receives.length, 1);
});

test("allows synchronous resume from a nonterminal error listener", async () => {
  let controller;
  const harness = controllerHarness({
    dispatchError(error) {
      harness.events.push(["error", error]);
      controller.resume();
    },
  });
  controller = harness.controller;
  controller.start();
  await flushMicrotasks();
  harness.receives[0].reject({ kind: "system" });
  await flushMicrotasks(8);
  assert.equal(controller.status, "running");
  assert.equal(harness.receives.length, 2);
  assert.equal(harness.maximumActive, 1);
  await controller.pause();
});

test("waits for error dispatch before listener-reentrant detach releases", async () => {
  let controller;
  let detach;
  const harness = controllerHarness({
    dispatchError(error) {
      harness.events.push(["error", error]);
      detach = controller.detach();
      assert.equal(harness.releases, 0);
      assert.equal(controller.status, "detaching");
    },
  });
  controller = harness.controller;
  controller.start();
  await flushMicrotasks();
  harness.receives[0].reject({ kind: "system" });
  await flushMicrotasks(6);
  assert.equal(await detach, "socket");
  assert.equal(controller.status, "detached");
  assert.equal(harness.releases, 1);
  assert.equal(harness.removals, 1);
});

test("closes after a winning message and preserves cached promise identity", async () => {
  const harness = controllerHarness();
  harness.controller.start();
  await flushMicrotasks();
  harness.receives[0].resolve("last");
  const first = harness.controller.close();
  const second = harness.controller.close();
  assert.equal(first, second);
  harness.close.resolve();
  await first;
  assert.equal(harness.controller.status, "closed");
  assert.deepEqual(harness.events, [["message", "last"], ["close"]]);
  assert.equal(harness.releases, 1);
  assert.equal(harness.removals, 1);
});

test("reactor loss emits error, terminalizes raw close, then emits close", async () => {
  const harness = controllerHarness();
  harness.controller.start();
  await flushMicrotasks();
  const reactorError = { kind: "reactorClosed" };
  harness.receives[0].reject(reactorError);
  await flushMicrotasks(5);
  assert.deepEqual(harness.events, [["error", reactorError]]);
  harness.close.reject(reactorError);
  await assert.rejects(harness.controller.close(), (error) => {
    assert.equal(error, reactorError);
    return true;
  });
  assert.deepEqual(harness.events, [["error", reactorError], ["close"]]);
  assert.equal(harness.controller.status, "closed");
});

test("external close stops a scheduled pump before admission", async () => {
  const harness = controllerHarness();
  harness.controller.start();
  harness.controller.notifyClosing();
  harness.controller.notifyCloseOutcome();
  await harness.controller.close();
  assert.equal(harness.receives.length, 0);
  assert.deepEqual(harness.events, [["close"]]);
});

test("implements idle, paused, detached, and terminal method contracts", async () => {
  const paused = controllerHarness();
  const firstPause = paused.controller.pause();
  const secondPause = paused.controller.pause();
  assert.equal(firstPause, secondPause);
  await firstPause;
  assert.equal(paused.controller.status, "paused");
  assert.throws(() => paused.controller.start(), {
    code: "ERR_INVALID_STATE",
  });
  assert.equal(paused.controller.resume(), paused.controller);
  await paused.controller.pause();

  const detached = controllerHarness();
  const firstDetach = detached.controller.detach();
  const secondDetach = detached.controller.detach();
  assert.equal(firstDetach, secondDetach);
  assert.equal(detached.controller.status, "detached");
  assert.equal(await firstDetach, "socket");
  assert.equal(detached.releases, 1);
  assert.equal(detached.removals, 1);
  assert.throws(() => detached.controller.start(), {
    code: "ERR_INVALID_STATE",
  });
  await assert.rejects(detached.controller.close(), {
    code: "ERR_INVALID_STATE",
  });

  const closed = controllerHarness();
  const close = closed.controller.close();
  closed.close.resolve();
  await close;
  assert.throws(() => closed.controller.resume(), {
    code: "ERR_SOCKET_CLOSED",
  });
  await assert.rejects(closed.controller.detach(), {
    code: "ERR_SOCKET_CLOSED",
  });
});

test("close preempts pause and detach without losing their boundaries", async () => {
  const pausing = controllerHarness();
  pausing.controller.start();
  await flushMicrotasks();
  const pause = pausing.controller.pause();
  const closeAfterPause = pausing.controller.close();
  pausing.close.resolve();
  await pause;
  await closeAfterPause;
  assert.equal(pausing.controller.status, "closed");

  const detaching = controllerHarness();
  detaching.controller.start();
  await flushMicrotasks();
  const detach = detaching.controller.detach();
  const closeAfterDetach = detaching.controller.close();
  detaching.close.resolve();
  assert.equal(await detach, "socket");
  await closeAfterDetach;
  assert.equal(detaching.controller.status, "closed");
  assert.equal(detaching.releases, 1);
  assert.equal(detaching.removals, 1);
});

test("preserves EventEmitter ordering, meta-events, monitoring, and synthetic isolation", async () => {
  const emitter = new EventEmitter();
  const observed = [];
  emitter.on("newListener", (name) => observed.push(["new", name]));
  emitter.on("removeListener", (name) => observed.push(["remove", name]));
  const second = (message) => observed.push(["second", message]);
  emitter.on("message", (message) => {
    observed.push(["first", message]);
    emitter.removeListener("message", second);
  });
  emitter.on("message", second);
  emitter.on(errorMonitor, (error) => observed.push(["monitor", error]));
  emitter.on("error", (error) => observed.push(["error", error]));

  const harness = controllerHarness({
    dispatchMessage(message) {
      emitter.emit("message", message);
    },
    dispatchError(error) {
      emitter.emit("error", error);
    },
  });
  assert.equal(emitter.emit("message", "synthetic"), true);
  assert.equal(harness.controller.status, "idle");
  harness.controller.start();
  await flushMicrotasks();
  harness.receives[0].resolve("native");
  await flushMicrotasks(6);
  await harness.controller.pause();

  const failure = { marker: "failure" };
  emitter.emit("error", failure);
  assert.ok(
    observed.some((entry) => entry[0] === "monitor" && entry[1] === failure),
  );
  assert.ok(
    observed.some((entry) => entry[0] === "error" && entry[1] === failure),
  );
  assert.deepEqual(
    observed.filter((entry) => entry[0] === "second"),
    [["second", "synthetic"]],
  );
  assert.ok(observed.some((entry) => entry[0] === "remove"));
});

test("listener exceptions and rejection capture retain Node process channels", async () => {
  const expected = {
    "message-throw": ["uncaughtException", "running", "listener-threw"],
    "missing-error": ["uncaughtException", "paused", "receive-failure"],
    "default-rejection": ["unhandledRejection", "running", "listener-rejected"],
    "captured-rejection": ["error", "running", "captured-listener-rejection"],
  };
  for (const [mode, outcome] of Object.entries(expected)) {
    const result = await runExceptionFixture(mode);
    assert.deepEqual(
      [result.channel, result.status, result.value],
      outcome,
      mode,
    );
  }
});

test("two hot sources remain fair through thousands of nonrecursive turns", async () => {
  const counts = [0, 0];
  const completions = [deferred(), deferred()];
  const controllers = [0, 1].map((sourceIndex) => {
    let sequence = 0;
    let controller;
    const driver = {
      receive() {
        sequence += 1;
        return Promise.resolve(sequence);
      },
      close() {
        return Promise.resolve();
      },
      releaseClaim() {
        return undefined;
      },
      removeCloseObserver() {
        return undefined;
      },
      detachValue() {
        return sourceIndex;
      },
      dispatchMessage() {
        counts[sourceIndex] += 1;
        if (counts[sourceIndex] === 1_000) {
          void controller
            .pause()
            .then(() => completions[sourceIndex].resolve());
        }
      },
      dispatchError(error) {
        completions[sourceIndex].reject(error);
      },
      dispatchClose() {
        return undefined;
      },
      invalidState(operation) {
        return new Error(`invalid ${operation}`);
      },
      socketClosed(operation) {
        return new Error(`closed ${operation}`);
      },
      isAborted() {
        return false;
      },
      isSocketClosed() {
        return false;
      },
      isReactorClosed() {
        return false;
      },
    };
    controller = new EventReceiveController(driver);
    return controller;
  });
  controllers[0].start();
  controllers[1].start();
  await Promise.all(completions.map((completion) => completion.promise));
  assert.deepEqual(counts, [1_000, 1_000]);
  assert.deepEqual(
    controllers.map((controller) => controller.status),
    ["paused", "paused"],
  );
});

async function runExceptionFixture(mode) {
  const fixture = fileURLToPath(
    new URL("./fixtures/event-controller-process.mjs", import.meta.url),
  );
  const child = spawn(process.execPath, [fixture, mode], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  assert.equal(code, 0, `${mode}: ${stderr}`);
  return JSON.parse(stdout.trim());
}
