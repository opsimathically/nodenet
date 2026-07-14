import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

import {
  ETH_P_8021AD,
  ETH_P_8021Q,
  ETH_P_ALL,
  ETH_P_ARP,
  ETH_P_IP,
  ETH_P_IPV6,
  IPPROTO_AH,
  IPPROTO_ESP,
  IPPROTO_GRE,
  IPPROTO_ICMP,
  IPPROTO_ICMPV6,
  IPPROTO_IGMP,
  IPPROTO_IPIP,
  IPPROTO_IPV6,
  IPPROTO_RAW,
  IPPROTO_SCTP,
  IPPROTO_TCP,
  IPPROTO_UDP,
  IPPROTO_UDPLITE,
  RawSocketEventEmitter,
  classifyIcmpTracerouteResponse,
  createIcmpTracerouteProbe,
  nativeSmokeTest,
  traceIcmpRoute,
} from "../dist/index.js";

test("calls the native smoke export through ESM", () => {
  assert.equal(nativeSmokeTest(), "nodenetraw:napi-ok");
});

test("loads the synchronous ESM public entry point through require", () => {
  const require = createRequire(import.meta.url);
  const requiredPackage = require("../dist/index.js");

  assert.equal(requiredPackage.nativeSmokeTest(), "nodenetraw:napi-ok");
  assert.equal(requiredPackage.IPPROTO_ICMP, IPPROTO_ICMP);
  assert.equal(requiredPackage.ETH_P_IP, ETH_P_IP);
  assert.equal(requiredPackage.RawSocketEventEmitter, RawSocketEventEmitter);
  assert.equal(
    requiredPackage.createIcmpTracerouteProbe,
    createIcmpTracerouteProbe,
  );
  assert.equal(
    requiredPackage.classifyIcmpTracerouteResponse,
    classifyIcmpTracerouteResponse,
  );
  assert.equal(requiredPackage.traceIcmpRoute, traceIcmpRoute);
});

test("exports the ICMP traceroute API", () => {
  assert.equal(typeof createIcmpTracerouteProbe, "function");
  assert.equal(typeof classifyIcmpTracerouteResponse, "function");
  assert.equal(typeof traceIcmpRoute, "function");
});

test("keeps event controller internals outside package exports", async () => {
  await assert.rejects(
    import("@opsimathically/nodenetraw/internal/event-controller.js"),
    {
      code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
    },
  );
});

test("exports common Linux protocol constants", () => {
  assert.deepEqual(
    {
      IPPROTO_ICMP,
      IPPROTO_IGMP,
      IPPROTO_IPIP,
      IPPROTO_TCP,
      IPPROTO_UDP,
      IPPROTO_IPV6,
      IPPROTO_GRE,
      IPPROTO_ESP,
      IPPROTO_AH,
      IPPROTO_ICMPV6,
      IPPROTO_SCTP,
      IPPROTO_UDPLITE,
      IPPROTO_RAW,
    },
    {
      IPPROTO_ICMP: 1,
      IPPROTO_IGMP: 2,
      IPPROTO_IPIP: 4,
      IPPROTO_TCP: 6,
      IPPROTO_UDP: 17,
      IPPROTO_IPV6: 41,
      IPPROTO_GRE: 47,
      IPPROTO_ESP: 50,
      IPPROTO_AH: 51,
      IPPROTO_ICMPV6: 58,
      IPPROTO_SCTP: 132,
      IPPROTO_UDPLITE: 136,
      IPPROTO_RAW: 255,
    },
  );
  assert.deepEqual(
    { ETH_P_ALL, ETH_P_IP, ETH_P_ARP, ETH_P_8021Q, ETH_P_IPV6, ETH_P_8021AD },
    {
      ETH_P_ALL: 0x0003,
      ETH_P_IP: 0x0800,
      ETH_P_ARP: 0x0806,
      ETH_P_8021Q: 0x8100,
      ETH_P_IPV6: 0x86dd,
      ETH_P_8021AD: 0x88a8,
    },
  );
});
