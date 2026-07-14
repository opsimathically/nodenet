import { parentPort } from "node:worker_threads";

import { RawSocket } from "../../dist/index.js";

try {
  const socket = await RawSocket.open({ protocol: 1 });
  await socket.close();
} catch {
  // An unprivileged worker is expected to receive EPERM. The purpose of this
  // fixture is to exercise environment-specific reactor startup and teardown.
}

parentPort?.postMessage({ completed: true });
