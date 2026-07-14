import { Buffer } from "node:buffer";

import {
  ICMP_EXC_TTL,
  IcmpInputError,
  matchIcmpEchoQuoteInternal,
  snapshotByteInputInternal,
  type IcmpDestinationUnreachableCode,
  type IcmpParameterProblemCode,
  type IcmpRedirectCode,
  type ParsedIcmpExtensionObject,
  type ParsedIcmpPacket,
  type ParsedIpv4Header,
} from "./icmp.js";

export const MAX_ICMP_TRACEROUTE_PAYLOAD_LENGTH = 4_096;
export const MAX_ICMP_TRACEROUTE_TOKEN_LENGTH = 64;
export const MAX_ICMP_TRACEROUTE_PROBES_PER_HOP = 10;
export const MAX_ICMP_TRACEROUTE_RESULTS = 2_550;

export interface IcmpTracerouteIpv4Destination {
  readonly family: "ipv4";
  readonly address: string;
}

export interface IcmpTracerouteProbeOptions {
  readonly destination: IcmpTracerouteIpv4Destination;
  readonly identifier: number;
  readonly sequence: number;
  readonly token: Uint8Array;
  readonly payload?: Uint8Array;
  readonly ttl: number;
  readonly sentAt: bigint;
}

export interface IcmpTracerouteProbe {
  readonly destination: IcmpTracerouteIpv4Destination;
  readonly identifier: number;
  readonly sequence: number;
  readonly token: Buffer;
  readonly payload: Buffer;
  readonly data: Buffer;
  readonly ttl: number;
  readonly sentAt: bigint;
}

export type IcmpTracerouteMatchStrength = "strong" | "weak";

export interface IcmpTracerouteExtensionSummary {
  readonly classNumber: number;
  readonly cType: number;
  readonly dataLength: number;
}

interface IcmpTracerouteMatchedBase {
  readonly matched: true;
  readonly responderAddress: string;
  readonly roundTripNanoseconds: bigint;
  readonly matchStrength: IcmpTracerouteMatchStrength;
}

export type IcmpTracerouteMatch =
  | { readonly matched: false }
  | (IcmpTracerouteMatchedBase & { readonly kind: "hop" })
  | (IcmpTracerouteMatchedBase & { readonly kind: "destination" })
  | (IcmpTracerouteMatchedBase & {
      readonly kind: "unreachable";
      readonly code: IcmpDestinationUnreachableCode;
      readonly nextHopMtu: number | undefined;
      readonly extensions: readonly IcmpTracerouteExtensionSummary[];
    })
  | (IcmpTracerouteMatchedBase & {
      readonly kind: "parameterProblem";
      readonly code: IcmpParameterProblemCode;
      readonly pointer: number;
      readonly extensions: readonly IcmpTracerouteExtensionSummary[];
    })
  | (IcmpTracerouteMatchedBase & {
      readonly kind: "redirect";
      readonly code: IcmpRedirectCode;
      readonly gatewayAddress: string;
    });

export type IcmpTracerouteTimeoutKind = "probe" | "overall";

interface IcmpTracerouteProbeResultBase {
  readonly hop: number;
  readonly ordinal: number;
  readonly sequence: number;
}

export type IcmpTracerouteProbeResult =
  | (IcmpTracerouteProbeResultBase & {
      readonly kind: "timeout";
      readonly timeoutKind: IcmpTracerouteTimeoutKind;
    })
  | (IcmpTracerouteProbeResultBase &
      Exclude<IcmpTracerouteMatch, { readonly matched: false }>);

export interface IcmpTracerouteHopResult {
  readonly hop: number;
  readonly probes: readonly IcmpTracerouteProbeResult[];
}

export type IcmpTracerouteTermination =
  "destination" | "unreachable" | "maxHops" | "overallTimeout";

export interface IcmpTracerouteResult {
  readonly destination: IcmpTracerouteIpv4Destination;
  readonly identifier: number;
  readonly termination: IcmpTracerouteTermination;
  readonly startedAt: bigint;
  readonly finishedAt: bigint;
  readonly elapsedNanoseconds: bigint;
  readonly hops: readonly IcmpTracerouteHopResult[];
  readonly ignoredResponses: number;
  readonly invalidResponses: number;
}

export interface IcmpTracerouteProgress {
  readonly result: IcmpTracerouteProbeResult;
}

export interface TraceIcmpRouteOptions {
  readonly firstHop?: number;
  readonly maxHops?: number;
  readonly probesPerHop?: number;
  readonly timeoutMilliseconds?: number;
  readonly overallTimeoutMilliseconds?: number;
  readonly payload?: Uint8Array;
  readonly token?: Uint8Array;
  readonly identifier?: number;
  readonly initialSequence?: number;
  readonly maxInFlight?: number;
  readonly stopOnUnreachable?: boolean;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: IcmpTracerouteProgress) => void;
}

export type IcmpTracerouteReceived =
  | {
      readonly ok: true;
      readonly ipv4: ParsedIpv4Header;
      readonly packet: ParsedIcmpPacket;
      readonly incomplete: boolean;
    }
  | { readonly ok: false };

export interface NormalizedTraceIcmpRouteOptions {
  readonly destination: IcmpTracerouteIpv4Destination;
  readonly firstHop: number;
  readonly maxHops: number;
  readonly probesPerHop: number;
  readonly timeoutNanoseconds: bigint;
  readonly overallTimeoutNanoseconds: bigint;
  readonly payload: Buffer;
  readonly token: Buffer;
  readonly identifier: number;
  readonly initialSequence: number;
  readonly maxInFlight: number;
  readonly stopOnUnreachable: boolean;
  readonly signal: AbortSignal | undefined;
  readonly onProgress: ((progress: IcmpTracerouteProgress) => void) | undefined;
}

export interface IcmpTracerouteAttachmentCallbacks {
  readonly message: (received: IcmpTracerouteReceived) => void;
  readonly error: (error: unknown) => void;
  readonly close: () => void;
}

export interface IcmpTracerouteAttachment {
  start(): void;
  detach(): Promise<void>;
}

export interface IcmpTracerouteDriver {
  now(): bigint;
  send(probe: IcmpTracerouteProbe, signal: AbortSignal): Promise<void>;
  attach(
    callbacks: IcmpTracerouteAttachmentCallbacks,
  ): IcmpTracerouteAttachment;
  setTimer(callback: () => void, milliseconds: number): unknown;
  clearTimer(timer: unknown): void;
  abortedError(): unknown;
  socketClosedError(): unknown;
}

interface Deferred {
  readonly promise: Promise<void>;
  resolve(): void;
}

interface PendingProbe {
  readonly hop: number;
  readonly ordinal: number;
  readonly probe: IcmpTracerouteProbe;
  readonly deadline: bigint;
  readonly deferred: Deferred;
  timer: unknown;
}

function createDeferred(): Deferred {
  let resolvePromise!: () => void;
  const result: Deferred = {
    promise: new Promise<void>((resolve) => {
      resolvePromise = resolve;
    }),
    resolve(): void {
      resolvePromise();
    },
  };
  return result;
}

export function createIcmpTracerouteProbeInternal(
  options: IcmpTracerouteProbeOptions,
): IcmpTracerouteProbe {
  const destination = { ...options.destination };
  const token = Buffer.from(options.token);
  const payload = Buffer.from(options.payload ?? new Uint8Array());
  return {
    destination,
    identifier: options.identifier,
    sequence: options.sequence,
    token,
    payload,
    data: Buffer.concat([token, payload]),
    ttl: options.ttl,
    sentAt: options.sentAt,
  };
}

export function classifyIcmpTracerouteResponseInternal(
  probe: IcmpTracerouteProbe,
  received: IcmpTracerouteReceived,
  receivedAt: bigint,
): IcmpTracerouteMatch {
  if (
    !received.ok ||
    received.incomplete ||
    received.packet.incomplete ||
    received.packet.checksumStatus !== "valid"
  ) {
    return { matched: false };
  }
  const roundTripNanoseconds = receivedAt - probe.sentAt;
  const message = received.packet.message;
  const responderAddress = received.ipv4.sourceAddress;
  if (message.kind === "echoReply") {
    if (
      responderAddress !== probe.destination.address ||
      message.identifier !== probe.identifier ||
      message.sequence !== probe.sequence ||
      !startsWith(message.data, probe.token)
    ) {
      return { matched: false };
    }
    return {
      matched: true,
      kind: "destination",
      responderAddress,
      roundTripNanoseconds,
      matchStrength: "strong",
    };
  }

  if (
    message.kind !== "timeExceeded" &&
    message.kind !== "destinationUnreachable" &&
    message.kind !== "parameterProblem" &&
    message.kind !== "redirect"
  ) {
    return { matched: false };
  }
  if (message.kind === "timeExceeded" && message.code !== ICMP_EXC_TTL) {
    return { matched: false };
  }
  const quoteMatch = matchIcmpEchoQuoteInternal(message.quote, {
    expectedDestinationAddress: probe.destination.address,
    identifier: probe.identifier,
    sequence: probe.sequence,
    token: probe.token,
  });
  if (!quoteMatch.matched) return { matched: false };
  const matchStrength = quoteMatch.strength;
  if (
    matchStrength !== "strong" &&
    (message.kind === "parameterProblem" || message.kind === "redirect")
  ) {
    return { matched: false };
  }
  if (message.kind === "timeExceeded") {
    return {
      matched: true,
      kind: "hop",
      responderAddress,
      roundTripNanoseconds,
      matchStrength,
    };
  }
  if (message.kind === "destinationUnreachable") {
    return {
      matched: true,
      kind: "unreachable",
      responderAddress,
      roundTripNanoseconds,
      matchStrength,
      code: message.code,
      nextHopMtu: message.nextHopMtu,
      extensions: summarizeExtensions(message.extensions?.objects),
    };
  }
  if (message.kind === "parameterProblem") {
    return {
      matched: true,
      kind: "parameterProblem",
      responderAddress,
      roundTripNanoseconds,
      matchStrength,
      code: message.code,
      pointer: message.pointer,
      extensions: summarizeExtensions(message.extensions?.objects),
    };
  }
  return {
    matched: true,
    kind: "redirect",
    responderAddress,
    roundTripNanoseconds,
    matchStrength,
    code: message.code,
    gatewayAddress: message.gatewayAddress,
  };
}

export async function traceIcmpRouteInternal(
  options: NormalizedTraceIcmpRouteOptions,
  driver: IcmpTracerouteDriver,
): Promise<IcmpTracerouteResult> {
  return new IcmpTracerouteSession(options, driver).run();
}

class IcmpTracerouteSession {
  readonly #options: NormalizedTraceIcmpRouteOptions;
  readonly #driver: IcmpTracerouteDriver;
  readonly #pending = new Map<number, PendingProbe>();
  readonly #results: IcmpTracerouteProbeResult[] = [];
  readonly #activeSends = new Set<Promise<void>>();
  readonly #sendAbort = new AbortController();
  readonly #startedAt: bigint;
  readonly #overallDeadline: bigint;
  #attachment: IcmpTracerouteAttachment | undefined;
  #detachPromise: Promise<void> | undefined;
  #overallTimer: unknown;
  #terminal = false;
  #termination: IcmpTracerouteTermination | undefined;
  #failure: unknown;
  #admittedCount = 0;
  #ignoredResponses = 0;
  #invalidResponses = 0;

  constructor(
    options: NormalizedTraceIcmpRouteOptions,
    driver: IcmpTracerouteDriver,
  ) {
    this.#options = options;
    this.#driver = driver;
    this.#startedAt = driver.now();
    this.#overallDeadline = this.#startedAt + options.overallTimeoutNanoseconds;
  }

  async run(): Promise<IcmpTracerouteResult> {
    const signal = this.#options.signal;
    const abort = (): void => {
      this.#beginFailure(this.#driver.abortedError());
    };
    try {
      if (signal?.aborted === true) throw this.#driver.abortedError();
      this.#attachment = this.#driver.attach({
        message: (received) => {
          this.#receive(received);
        },
        error: (error) => {
          this.#beginFailure(error);
        },
        close: () => {
          this.#beginFailure(this.#driver.socketClosedError());
        },
      });
      signal?.addEventListener("abort", abort, { once: true });
      if (!this.#isTerminal()) {
        this.#attachment.start();
        this.#armOverallTimer();
        await this.#admitAllHops();
        if (!this.#isTerminal()) this.#beginSuccess("maxHops");
      }
    } catch (error) {
      this.#beginFailure(error);
    }

    await this.#finish();
    signal?.removeEventListener("abort", abort);
    if (this.#failure !== undefined) throw this.#failure;
    const termination = this.#termination;
    if (termination === undefined) {
      throw new Error("traceroute completed without a termination reason");
    }
    const finishedAt = this.#driver.now();
    return {
      destination: { ...this.#options.destination },
      identifier: this.#options.identifier,
      termination,
      startedAt: this.#startedAt,
      finishedAt,
      elapsedNanoseconds: finishedAt - this.#startedAt,
      hops: groupResults(this.#results),
      ignoredResponses: this.#ignoredResponses,
      invalidResponses: this.#invalidResponses,
    };
  }

  async #admitAllHops(): Promise<void> {
    for (
      let hop = this.#options.firstHop;
      hop <= this.#options.maxHops && !this.#isTerminal();
      hop += 1
    ) {
      const active = new Set<Promise<void>>();
      let ordinal = 0;
      while (
        (ordinal < this.#options.probesPerHop || active.size > 0) &&
        !this.#isTerminal()
      ) {
        while (
          ordinal < this.#options.probesPerHop &&
          active.size < this.#options.maxInFlight &&
          !this.#isTerminal()
        ) {
          if (this.#driver.now() >= this.#overallDeadline) {
            this.#expireOverall();
            break;
          }
          const promise = this.#admitProbe(hop, ordinal);
          active.add(promise);
          void promise.then(() => {
            active.delete(promise);
          });
          ordinal += 1;
        }
        if (active.size > 0) await Promise.race(active);
      }
    }
  }

  #admitProbe(hop: number, ordinal: number): Promise<void> {
    const sentAt = this.#driver.now();
    if (sentAt >= this.#overallDeadline) {
      this.#expireOverall();
      return Promise.resolve();
    }
    const sequence =
      (this.#options.initialSequence + this.#admittedCount) & 0xffff;
    this.#admittedCount += 1;
    const probe = createIcmpTracerouteProbeInternal({
      destination: this.#options.destination,
      identifier: this.#options.identifier,
      sequence,
      token: this.#options.token,
      payload: this.#options.payload,
      ttl: hop,
      sentAt,
    });
    const deferred = createDeferred();
    const deadline = minimumBigint(
      sentAt + this.#options.timeoutNanoseconds,
      this.#overallDeadline,
    );
    const pending: PendingProbe = {
      hop,
      ordinal,
      probe,
      deadline,
      deferred,
      timer: undefined,
    };
    this.#pending.set(sequence, pending);
    this.#armProbeTimer(pending);
    let send: Promise<void>;
    try {
      send = this.#driver.send(probe, this.#sendAbort.signal);
    } catch (error) {
      this.#beginFailure(error);
      return deferred.promise;
    }
    const observed = send.then(
      () => undefined,
      (error: unknown) => {
        if (this.#pending.get(sequence) === pending && !this.#terminal) {
          this.#beginFailure(error);
        }
      },
    );
    this.#activeSends.add(observed);
    void observed.then(() => {
      this.#activeSends.delete(observed);
    });
    return deferred.promise;
  }

  #receive(received: IcmpTracerouteReceived): void {
    if (this.#terminal) return;
    const receivedAt = this.#driver.now();
    if (receivedAt >= this.#overallDeadline) {
      this.#expireOverall();
      return;
    }
    if (
      !received.ok ||
      received.incomplete ||
      received.packet.incomplete ||
      received.packet.checksumStatus !== "valid"
    ) {
      this.#invalidResponses = saturatingIncrement(this.#invalidResponses);
      return;
    }
    for (const pending of [...this.#pending.values()]) {
      if (receivedAt >= pending.deadline) {
        this.#settleTimeout(pending, "probe");
        if (this.#isTerminal()) return;
        continue;
      }
      const match = classifyIcmpTracerouteResponseInternal(
        pending.probe,
        received,
        receivedAt,
      );
      if (!match.matched) continue;
      this.#settleMatch(pending, match);
      return;
    }
    this.#ignoredResponses = saturatingIncrement(this.#ignoredResponses);
  }

  #settleMatch(
    pending: PendingProbe,
    match: Exclude<IcmpTracerouteMatch, { readonly matched: false }>,
  ): void {
    if (!this.#takePending(pending)) return;
    const result: IcmpTracerouteProbeResult = {
      hop: pending.hop,
      ordinal: pending.ordinal,
      sequence: pending.probe.sequence,
      ...match,
    };
    this.#recordResult(result);
    pending.deferred.resolve();
    if (this.#failure !== undefined) return;
    if (match.kind === "destination") this.#beginSuccess("destination");
    else if (match.kind === "unreachable" && this.#options.stopOnUnreachable) {
      this.#beginSuccess("unreachable");
    }
  }

  #settleTimeout(
    pending: PendingProbe,
    timeoutKind: IcmpTracerouteTimeoutKind,
  ): void {
    if (!this.#takePending(pending)) return;
    const result: IcmpTracerouteProbeResult = {
      kind: "timeout",
      hop: pending.hop,
      ordinal: pending.ordinal,
      sequence: pending.probe.sequence,
      timeoutKind,
    };
    this.#recordResult(result);
    pending.deferred.resolve();
  }

  #recordResult(result: IcmpTracerouteProbeResult): void {
    if (this.#results.length >= MAX_ICMP_TRACEROUTE_RESULTS) {
      this.#recordFailure(new Error("traceroute result bound exceeded"));
      return;
    }
    this.#results.push(result);
    if (this.#options.onProgress !== undefined && this.#failure === undefined) {
      try {
        this.#options.onProgress({ result: copyProbeResult(result) });
      } catch (error) {
        this.#recordFailure(error);
      }
    }
  }

  #takePending(pending: PendingProbe): boolean {
    if (this.#pending.get(pending.probe.sequence) !== pending) return false;
    this.#pending.delete(pending.probe.sequence);
    if (pending.timer !== undefined) this.#driver.clearTimer(pending.timer);
    pending.timer = undefined;
    return true;
  }

  #armProbeTimer(pending: PendingProbe): void {
    pending.timer = this.#driver.setTimer(
      () => {
        if (this.#pending.get(pending.probe.sequence) !== pending) return;
        const now = this.#driver.now();
        if (now >= this.#overallDeadline) {
          this.#expireOverall();
        } else if (now >= pending.deadline) {
          this.#settleTimeout(pending, "probe");
        } else {
          this.#armProbeTimer(pending);
        }
      },
      delayMilliseconds(this.#driver.now(), pending.deadline),
    );
  }

  #armOverallTimer(): void {
    if (this.#terminal) return;
    this.#overallTimer = this.#driver.setTimer(
      () => {
        const now = this.#driver.now();
        if (now >= this.#overallDeadline) this.#expireOverall();
        else this.#armOverallTimer();
      },
      delayMilliseconds(this.#driver.now(), this.#overallDeadline),
    );
  }

  #expireOverall(): void {
    if (this.#terminal) return;
    this.#terminal = true;
    this.#termination = "overallTimeout";
    this.#clearOverallTimer();
    for (const pending of [...this.#pending.values()]) {
      this.#settleTimeout(pending, "overall");
    }
    this.#stopIo();
  }

  #beginSuccess(termination: IcmpTracerouteTermination): void {
    if (this.#terminal) return;
    this.#terminal = true;
    this.#termination = termination;
    this.#clearOverallTimer();
    this.#releasePending();
    this.#stopIo();
  }

  #beginFailure(error: unknown): void {
    if (this.#terminal) return;
    if (this.#failure === undefined) this.#failure = error;
    this.#terminal = true;
    this.#clearOverallTimer();
    this.#releasePending();
    this.#stopIo();
  }

  #recordFailure(error: unknown): void {
    if (this.#terminal) {
      if (this.#failure === undefined) this.#failure = error;
      return;
    }
    this.#beginFailure(error);
  }

  #releasePending(): void {
    for (const pending of [...this.#pending.values()]) {
      if (!this.#takePending(pending)) continue;
      pending.deferred.resolve();
    }
  }

  #stopIo(): void {
    this.#sendAbort.abort();
    if (this.#attachment === undefined || this.#detachPromise !== undefined) {
      return;
    }
    try {
      this.#detachPromise = this.#attachment.detach();
    } catch (error) {
      this.#detachPromise = Promise.reject(error);
    }
  }

  #clearOverallTimer(): void {
    if (this.#overallTimer === undefined) return;
    this.#driver.clearTimer(this.#overallTimer);
    this.#overallTimer = undefined;
  }

  #isTerminal(): boolean {
    return this.#terminal;
  }

  async #finish(): Promise<void> {
    this.#clearOverallTimer();
    this.#releasePending();
    this.#stopIo();
    await Promise.allSettled([...this.#activeSends]);
    if (this.#detachPromise === undefined) return;
    try {
      await this.#detachPromise;
    } catch (error) {
      if (this.#failure === undefined) this.#failure = error;
    }
  }
}

function startsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  if (prefix.byteLength > data.byteLength) return false;
  for (let index = 0; index < prefix.byteLength; index += 1) {
    if (data[index] !== prefix[index]) return false;
  }
  return true;
}

function summarizeExtensions(
  objects: readonly ParsedIcmpExtensionObject[] | undefined,
): readonly IcmpTracerouteExtensionSummary[] {
  if (objects === undefined) return [];
  const count = objects.length;
  if (!Number.isSafeInteger(count) || count < 1 || count > 142) {
    throw new IcmpInputError(
      "parsed ICMP extension object count exceeds its bound",
    );
  }
  const summaries: IcmpTracerouteExtensionSummary[] = [];
  for (let index = 0; index < count; index += 1) {
    const object = objects[index];
    if (object === undefined) {
      throw new IcmpInputError("parsed ICMP extension object is missing");
    }
    if (
      !Number.isInteger(object.classNumber) ||
      object.classNumber < 0 ||
      object.classNumber > 0xff ||
      !Number.isInteger(object.cType) ||
      object.cType < 0 ||
      object.cType > 0xff
    ) {
      throw new IcmpInputError(
        "parsed ICMP extension object fields are invalid",
      );
    }
    summaries.push({
      classNumber: object.classNumber,
      cType: object.cType,
      dataLength: snapshotByteInputInternal(
        object.data,
        576,
        "parsed extension data",
      ).byteLength,
    });
  }
  return summaries;
}

function groupResults(
  rawResults: readonly IcmpTracerouteProbeResult[],
): readonly IcmpTracerouteHopResult[] {
  const results = [...rawResults].sort(
    (left, right) => left.hop - right.hop || left.ordinal - right.ordinal,
  );
  const grouped: {
    readonly hop: number;
    readonly probes: IcmpTracerouteProbeResult[];
  }[] = [];
  for (const result of results) {
    const previous = grouped.at(-1);
    if (previous?.hop === result.hop) {
      previous.probes.push(result);
    } else {
      grouped.push({ hop: result.hop, probes: [result] });
    }
  }
  return grouped;
}

function copyProbeResult(
  result: IcmpTracerouteProbeResult,
): IcmpTracerouteProbeResult {
  if (result.kind === "unreachable" || result.kind === "parameterProblem") {
    return {
      ...result,
      extensions: result.extensions.map((extension) => ({ ...extension })),
    };
  }
  return { ...result };
}

function delayMilliseconds(now: bigint, deadline: bigint): number {
  const remaining = deadline - now;
  if (remaining <= 0n) return 0;
  return Number((remaining + 999_999n) / 1_000_000n);
}

function minimumBigint(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}

function saturatingIncrement(value: number): number {
  return value < 0xffff_ffff ? value + 1 : value;
}
