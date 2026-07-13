import { parentPort } from "node:worker_threads";

import {
  IPPROTO_RAW,
  RawSocket,
  RawSocketEventEmitter,
} from "../../dist/index.js";

if (parentPort === null) throw new Error("worker must have a parent port");

const socket = await RawSocket.open({ protocol: IPPROTO_RAW });
const source = new RawSocketEventEmitter(socket);
source.on("error", (error) => {
  parentPort.postMessage({ error: String(error) });
});
source.start();
parentPort.postMessage({ ready: true });
parentPort.once("message", async (message) => {
  if (message !== "close") return;
  try {
    await source.close();
    parentPort.postMessage({ closed: true });
    parentPort.close();
  } catch (error) {
    parentPort.postMessage({ error: String(error) });
  }
});
