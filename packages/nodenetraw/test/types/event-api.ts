import {
  RawSocketEventEmitter,
  type RawSocket,
  type RawSocketEventEmitterOptions,
  type RawSocketEventEmitterStatus,
  type ReceivedMessage,
} from "@opsimathically/nodenetraw";

declare const socket: RawSocket;
declare const message: ReceivedMessage;

const options: RawSocketEventEmitterOptions = {
  dataCapacity: 4096,
  controlCapacity: 1024,
  errorQueue: false,
};
const emitter = new RawSocketEventEmitter(socket, options);
const status: RawSocketEventEmitterStatus = emitter.status;
void status;

emitter.on("message", (received) => {
  received.data.subarray(0, 1);
});
emitter.on("error", (error) => {
  if (error instanceof Error) void error.message;
});
emitter.once("close", () => {});
emitter.emit("message", message);
emitter.emit("close");
emitter.emit("application-event", 1, "two");

// @ts-expect-error known message events require a ReceivedMessage payload.
emitter.emit("message");
// @ts-expect-error close has no payload.
emitter.emit("close", message);
// @ts-expect-error error listeners must narrow unknown values.
emitter.on("error", (error) => error.message);
// @ts-expect-error the wrapped socket property is readonly.
emitter.socket = socket;
// @ts-expect-error construction options are readonly.
options.dataCapacity = 1;

// @ts-expect-error internal claim types are not exported.
import type { RawSocketReceiveClaim } from "@opsimathically/nodenetraw";
declare const hidden: RawSocketReceiveClaim;
void hidden;
