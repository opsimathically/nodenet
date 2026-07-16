import dgram from "node:dgram";
import net from "node:net";
import { Buffer } from "node:buffer";
import {
  IPPROTO_ICMPV6,
  RawSocket,
  interfaceIndex,
} from "@opsimathically/nodenetraw";

const tcpPort = Number(process.env.NODENETSCANNER_TCP_PORT ?? "18080");
const udp4Port = Number(process.env.NODENETSCANNER_UDP4_PORT ?? "18082");
const udp6Port = Number(process.env.NODENETSCANNER_UDP6_PORT ?? "18084");
const udpExactPort = Number(
  process.env.NODENETSCANNER_UDP_EXACT_PORT ?? "18085",
);
const udpPrefixPort = Number(
  process.env.NODENETSCANNER_UDP_PREFIX_PORT ?? "18086",
);

const servers = [];
const rawSockets = [];
const rawIntervals = [];
const rawAbort = new globalThis.AbortController();

async function startRouterAdvertisementResponder() {
  const socket = await RawSocket.open({
    family: "ipv6",
    protocol: IPPROTO_ICMPV6,
  });
  rawSockets.push(socket);
  await socket.setOption("bindToDevice", "target0");
  await socket.setOption("ipv6MulticastHops", 255);
  await socket.setOption("receiveHopLimit", true);
  await socket.bind({ family: "ipv6", address: "::" });
  const scopeId = await interfaceIndex("target0");
  const response = Buffer.alloc(48);
  response[0] = 134;
  response[4] = 64;
  response.writeUInt16BE(1_800, 6);
  response[16] = 3;
  response[17] = 4;
  response[18] = 64;
  response[19] = 0xc0;
  response.writeUInt32BE(3_600, 20);
  response.writeUInt32BE(1_800, 24);
  Buffer.from("20010db8002200000000000000000000", "hex").copy(response, 32);
  const advertise = (address) =>
    socket.sendMessage({
      data: response,
      destination: { family: "ipv6", address, scopeId },
      control: [{ kind: "ipv6HopLimit", value: 255 }],
    });
  const interval = globalThis.setInterval(() => {
    void advertise("ff02::1").catch((error) => console.error(error));
  }, 100);
  rawIntervals.push(interval);
  void (async () => {
    while (!rawAbort.signal.aborted) {
      try {
        const message = await socket.receiveMessage({
          dataCapacity: 2_048,
          controlCapacity: 512,
          signal: rawAbort.signal,
        });
        if (message.data[0] !== 133 || message.source?.family !== "ipv6")
          continue;
        // A Router Advertisement must use a link-local source. Sending the
        // solicited response to all-nodes lets Linux select target0's
        // link-local address even when the solicitation used a global source.
        await advertise("ff02::1");
      } catch (error) {
        if (!rawAbort.signal.aborted) console.error(error);
      }
    }
  })();
}

function netbiosResponse(message) {
  const header = Buffer.alloc(12);
  message.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8500, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  const record = Buffer.alloc(2 + 10 + 65);
  record.writeUInt16BE(0xc00c, 0);
  record.writeUInt16BE(0x21, 2);
  record.writeUInt16BE(1, 4);
  record.writeUInt32BE(0, 6);
  record.writeUInt16BE(65, 10);
  record[12] = 1;
  Buffer.from("FIXTURE        ").copy(record, 13);
  record[28] = 0;
  record.writeUInt16BE(0x0400, 29);
  return Buffer.concat([header, message.subarray(12), record]);
}

function rpcAccepted(message) {
  const response = Buffer.alloc(24);
  message.copy(response, 0, 0, 4);
  response.writeUInt32BE(1, 4);
  response.writeUInt32BE(0, 8);
  response.writeUInt32BE(0, 12);
  response.writeUInt32BE(0, 16);
  response.writeUInt32BE(0, 20);
  return response;
}

function rpcbindGetAddressResponse(message, universalAddress) {
  const address = Buffer.from(universalAddress, "ascii");
  const paddedLength = (address.length + 3) & ~3;
  const response = Buffer.alloc(28 + paddedLength);
  message.copy(response, 0, 0, 4);
  response.writeUInt32BE(1, 4);
  response.writeUInt32BE(0, 8);
  response.writeUInt32BE(0, 12);
  response.writeUInt32BE(0, 16);
  response.writeUInt32BE(0, 20);
  response.writeUInt32BE(address.length, 24);
  address.copy(response, 28);
  return response;
}

function sipResponse(message) {
  const request = message.toString("ascii");
  const callId = /^Call-ID:\s*(.+)$/im.exec(request)?.[1]?.trim();
  if (callId === undefined) return Buffer.alloc(0);
  return Buffer.from(
    `SIP/2.0 200 OK\r\nCall-ID: ${callId}\r\nCSeq: 1 OPTIONS\r\nServer: nodenet-fixture/1\r\nContent-Length: 0\r\n\r\n`,
    "ascii",
  );
}

function ssdpResponse() {
  return Buffer.from(
    "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:nodenet-fixture::upnp:rootdevice\r\nSERVER: Linux/fixture UPnP/1.1 nodenet/1\r\nLOCATION: http://192.0.2.2/device.xml\r\n\r\n",
    "ascii",
  );
}

function l2tpAvp(attribute, value) {
  const output = Buffer.alloc(6 + value.length);
  output.writeUInt16BE(0x8000 | output.length, 0);
  output.writeUInt16BE(0, 2);
  output.writeUInt16BE(attribute, 4);
  value.copy(output, 6);
  return output;
}

function l2tpResponse(message) {
  let assigned;
  for (let offset = 12; offset + 6 <= message.length;) {
    const length = message.readUInt16BE(offset) & 0x03ff;
    if (length < 6 || offset + length > message.length) return Buffer.alloc(0);
    if (message.readUInt16BE(offset + 4) === 9 && length === 8)
      assigned = message.readUInt16BE(offset + 6);
    offset += length;
  }
  if (assigned === undefined) return Buffer.alloc(0);
  const u16 = (value) => {
    const bytes = Buffer.alloc(2);
    bytes.writeUInt16BE(value);
    return bytes;
  };
  const u32 = (value) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32BE(value);
    return bytes;
  };
  const avps = [
    l2tpAvp(0, u16(2)),
    l2tpAvp(2, Buffer.from([1, 0])),
    l2tpAvp(7, Buffer.from("fixture", "ascii")),
    l2tpAvp(3, u32(3)),
    l2tpAvp(9, u16(0x4242)),
  ];
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0xc802, 0);
  header.writeUInt16BE(
    12 + avps.reduce((sum, value) => sum + value.length, 0),
    2,
  );
  header.writeUInt16BE(assigned, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(1, 10);
  return Buffer.concat([header, ...avps]);
}

function snmpV1Response(message) {
  const response = Buffer.from(message);
  const pdu = response.indexOf(0xa0);
  if (pdu < 0) return Buffer.alloc(0);
  response[pdu] = 0xa2;
  return response;
}

function memcachedStatsResponse(message) {
  return Buffer.concat([
    message.subarray(0, 8),
    Buffer.from("STAT version 1.6.fixture\r\nEND\r\n", "ascii"),
  ]);
}

function ripV1Response(address, metric) {
  const response = Buffer.alloc(24);
  response[0] = 2;
  response[1] = 1;
  response.writeUInt16BE(2, 4);
  Buffer.from(address).copy(response, 8);
  response.writeUInt32BE(metric, 20);
  return response;
}

function ripV1Responses() {
  return [
    ripV1Response([192, 0, 2, 0], 1),
    ripV1Response([198, 51, 100, 0], 2),
  ];
}

function quake2StatusResponse() {
  return Buffer.from(
    "ffffffff7072696e740a5c686f73746e616d655c6e6f64656e65742d666978747572655c6d61706e616d655c716564325f62617365315c76657273696f6e5c666978747572652d312e300a302030205c5c666978747572652d706c617965725c5c0a",
    "hex",
  );
}

function quake3InfoResponse(message) {
  const prefix = Buffer.from([
    0xff,
    0xff,
    0xff,
    0xff,
    ...Buffer.from("getinfo "),
  ]);
  const challenge = message.subarray(prefix.length).toString("ascii");
  return Buffer.from(
    `\xff\xff\xff\xffinfoResponse\n\\challenge\\${challenge}\\hostname\\nodenet-fixture\\mapname\\q3dm1\\protocol\\68\\clients\\1\\sv_maxclients\\8`,
    "latin1",
  );
}

function mumbleExtendedPingResponse(message) {
  const response = Buffer.alloc(24);
  response.writeUInt32BE(0x0001_0500, 0);
  message.copy(response, 4, 4, 12);
  response.writeUInt32BE(1, 12);
  response.writeUInt32BE(16, 16);
  response.writeUInt32BE(72_000, 20);
  return response;
}

function dnsName(value) {
  const labels = value.replace(/\.$/, "").split(".");
  return Buffer.concat([
    ...labels.map((label) => {
      const bytes = Buffer.from(label, "utf8");
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    }),
    Buffer.from([0]),
  ]);
}

function dnsQuestion(message) {
  const labels = [];
  let offset = 12;
  while (offset < message.length) {
    const length = message[offset++];
    if (length === 0) break;
    labels.push(message.subarray(offset, offset + length).toString("utf8"));
    offset += length;
  }
  return {
    name: `${labels.join(".")}.`,
    type: message.readUInt16BE(offset),
  };
}

function mdnsRecordResponse(message) {
  const question = dnsQuestion(message);
  const owner = dnsName(question.name);
  let recordType;
  let rdata;
  if (
    question.name === "_services._dns-sd._udp.local." &&
    question.type === 12
  ) {
    recordType = 12;
    rdata = dnsName("_http._tcp.local.");
  } else if (question.name === "_http._tcp.local." && question.type === 12) {
    recordType = 12;
    rdata = dnsName("Fixture._http._tcp.local.");
  } else if (
    question.name === "Fixture._http._tcp.local." &&
    question.type === 33
  ) {
    recordType = 33;
    rdata = Buffer.concat([
      Buffer.from([0, 0, 0, 0, 0x1f, 0x90]),
      dnsName("fixture.local."),
    ]);
  } else if (
    question.name === "Fixture._http._tcp.local." &&
    question.type === 16
  ) {
    recordType = 16;
    const text = Buffer.from("path=/fixture", "utf8");
    rdata = Buffer.concat([Buffer.from([text.length]), text]);
  } else if (question.name === "fixture.local." && question.type === 1) {
    recordType = 1;
    rdata = Buffer.from([192, 0, 2, 2]);
  } else if (question.name === "fixture.local." && question.type === 28) {
    recordType = 28;
    rdata = Buffer.from("20010db8000000000000000000000002", "hex");
  } else {
    return Buffer.alloc(0);
  }
  const header = Buffer.alloc(12);
  message.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8400, 2);
  header.writeUInt16BE(1, 6);
  const record = Buffer.alloc(owner.length + 10 + rdata.length);
  let offset = 0;
  owner.copy(record, offset);
  offset += owner.length;
  record.writeUInt16BE(recordType, offset);
  record.writeUInt16BE(1, offset + 2);
  record.writeUInt32BE(120, offset + 4);
  record.writeUInt16BE(rdata.length, offset + 8);
  rdata.copy(record, offset + 10);
  return Buffer.concat([header, record]);
}

function llmnrAddressResponse(message, address) {
  const response = Buffer.from(message);
  response.writeUInt16BE(0x8000, 2);
  response.writeUInt16BE(1, 6);
  const record = Buffer.alloc(12 + address.length);
  record.writeUInt16BE(0xc00c, 0);
  record.writeUInt16BE(address.length === 4 ? 1 : 28, 2);
  record.writeUInt16BE(1, 4);
  record.writeUInt32BE(30, 6);
  record.writeUInt16BE(address.length, 10);
  address.copy(record, 12);
  return Buffer.concat([response, record]);
}

function wsDiscoveryResponse(message) {
  const request = message.toString("utf8");
  const requestId = /<a:MessageID>([^<]+)<\/a:MessageID>/.exec(request)?.[1];
  if (requestId === undefined) return Buffer.alloc(0);
  return Buffer.from(
    `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"><s:Header><a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/ProbeMatches</a:Action><a:MessageID>urn:uuid:nodenet-response</a:MessageID><a:RelatesTo>${requestId}</a:RelatesTo><a:To>http://www.w3.org/2005/08/addressing/anonymous</a:To><d:AppSequence InstanceId="1" MessageNumber="1"/></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:nodenet-fixture</a:Address></a:EndpointReference><d:Types>dn:Device</d:Types><d:Scopes>nodenet://fixture</d:Scopes><d:XAddrs>http://192.0.2.2/device</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>`,
    "utf8",
  );
}

async function multicastResponder({ type, port, group, membership, respond }) {
  const socket = dgram.createSocket({ type, reuseAddr: true });
  socket.on("message", (message, remote) => {
    const response = respond(message);
    if (response.length > 0) socket.send(response, remote.port, remote.address);
  });
  servers.push(socket);
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(port, type === "udp4" ? "0.0.0.0" : "::", () => {
      try {
        socket.addMembership(group, membership);
        resolve();
      } catch (error) {
        error.message = `${error.message} for ${group} on ${membership}`;
        reject(error);
      }
    });
  });
}

for (const options of [
  { host: "0.0.0.0", ipv6Only: false },
  { host: "::", ipv6Only: true },
]) {
  const server = net.createServer((socket) => socket.end());
  servers.push(server);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port: tcpPort, ...options }, resolve);
  });
}

for (const { type, port, accepts = () => true, respond } of [
  {
    type: "udp4",
    port: 53,
    accepts: (message) =>
      message.length === 128 &&
      message[2] === 0 &&
      message[3] === 0 &&
      message[12] === 0,
    respond: (message) => {
      const response = Buffer.from(message);
      response[2] = 0x80;
      return response;
    },
  },
  {
    type: "udp6",
    port: 53,
    accepts: (message) =>
      message.length === 128 &&
      message[2] === 0 &&
      message[3] === 0 &&
      message[12] === 0,
    respond: (message) => {
      const response = Buffer.from(message);
      response[2] = 0x80;
      return response;
    },
  },
  {
    type: "udp4",
    port: 137,
    accepts: (message) =>
      message.length === 50 && message.readUInt16BE(46) === 0x21,
    respond: netbiosResponse,
  },
  {
    type: "udp4",
    port: 111,
    accepts: (message) =>
      message.length >= 48 &&
      message.readUInt32BE(12) === 100000 &&
      message.readUInt32BE(16) === 4 &&
      message.readUInt32BE(20) === 3,
    respond: (message) => rpcbindGetAddressResponse(message, "192.0.2.2.8.1"),
  },
  {
    type: "udp6",
    port: 111,
    accepts: (message) =>
      message.length >= 48 &&
      message.readUInt32BE(12) === 100000 &&
      message.readUInt32BE(16) === 4 &&
      message.readUInt32BE(20) === 3,
    respond: (message) =>
      rpcbindGetAddressResponse(message, "2001:db8:22::2.8.1"),
  },
  {
    type: "udp4",
    port: 2049,
    accepts: (message) =>
      message.length === 40 &&
      message.readUInt32BE(12) === 100003 &&
      message.readUInt32BE(16) === 3 &&
      message.readUInt32BE(20) === 0,
    respond: rpcAccepted,
  },
  {
    type: "udp6",
    port: 2049,
    accepts: (message) =>
      message.length === 40 &&
      message.readUInt32BE(12) === 100003 &&
      message.readUInt32BE(16) === 3 &&
      message.readUInt32BE(20) === 0,
    respond: rpcAccepted,
  },
  {
    type: "udp4",
    port: 5060,
    accepts: (message) =>
      message.subarray(0, 8).toString("ascii") === "OPTIONS ",
    respond: sipResponse,
  },
  {
    type: "udp6",
    port: 5060,
    accepts: (message) =>
      message.subarray(0, 8).toString("ascii") === "OPTIONS ",
    respond: sipResponse,
  },
  {
    type: "udp4",
    port: 1900,
    accepts: (message) =>
      message.subarray(0, 9).toString("ascii") === "M-SEARCH ",
    respond: ssdpResponse,
  },
  {
    type: "udp6",
    port: 1900,
    accepts: (message) =>
      message.subarray(0, 9).toString("ascii") === "M-SEARCH ",
    respond: ssdpResponse,
  },
  {
    type: "udp4",
    port: 1701,
    accepts: (message) =>
      message.length >= 20 && message.readUInt16BE(0) === 0xc802,
    respond: l2tpResponse,
  },
  {
    type: "udp6",
    port: 1701,
    accepts: (message) =>
      message.length >= 20 && message.readUInt16BE(0) === 0xc802,
    respond: l2tpResponse,
  },
  {
    type: "udp4",
    port: 161,
    accepts: (message) => message.includes(Buffer.from("public", "ascii")),
    respond: snmpV1Response,
  },
  {
    type: "udp6",
    port: 161,
    accepts: (message) => message.includes(Buffer.from("public", "ascii")),
    respond: snmpV1Response,
  },
  {
    type: "udp4",
    port: 11211,
    accepts: (message) => message.subarray(8).equals(Buffer.from("stats\r\n")),
    respond: memcachedStatsResponse,
  },
  {
    type: "udp6",
    port: 11211,
    accepts: (message) => message.subarray(8).equals(Buffer.from("stats\r\n")),
    respond: memcachedStatsResponse,
  },
  {
    type: "udp4",
    port: 520,
    accepts: (message) =>
      message.length === 24 &&
      message.subarray(0, 4).equals(Buffer.from([1, 1, 0, 0])) &&
      message.readUInt32BE(20) === 16,
    respond: ripV1Responses,
  },
  ...["udp4", "udp6"].flatMap((type) => [
    {
      type,
      port: 27_910,
      accepts: (message) =>
        message.equals(Buffer.from("ffffffff737461747573", "hex")),
      respond: quake2StatusResponse,
    },
    {
      type,
      port: 27_960,
      accepts: (message) =>
        message.length === 28 &&
        message
          .subarray(0, 12)
          .equals(Buffer.from("ffffffff676574696e666f20", "hex")),
      respond: quake3InfoResponse,
    },
    {
      type,
      port: 64_738,
      accepts: (message) =>
        message.length === 12 && message.subarray(0, 4).equals(Buffer.alloc(4)),
      respond: mumbleExtendedPingResponse,
    },
  ]),
  { type: "udp4", port: udp4Port },
  { type: "udp6", port: udp6Port },
  {
    type: "udp4",
    port: udpExactPort,
    accepts: (message) =>
      message.length === 4 &&
      message[0] === 0 &&
      message[1] === 0xff &&
      message[2] === 1 &&
      message[3] === 2,
  },
  {
    type: "udp6",
    port: udpExactPort,
    accepts: (message) =>
      message.length === 4 &&
      message[0] === 0 &&
      message[1] === 0xff &&
      message[2] === 1 &&
      message[3] === 2,
  },
  {
    type: "udp4",
    port: udpPrefixPort,
    accepts: (message) =>
      message.length === 19 &&
      message[16] === 1 &&
      message[17] === 2 &&
      message[18] === 3,
  },
  {
    type: "udp6",
    port: udpPrefixPort,
    accepts: (message) =>
      message.length === 19 &&
      message[16] === 1 &&
      message[17] === 2 &&
      message[18] === 3,
  },
].map((value) => ({ respond: (message) => message, ...value }))) {
  const socket = dgram.createSocket({
    type,
    ipv6Only: type === "udp6",
  });
  socket.on("message", (message, remote) => {
    if (accepts(message)) {
      const responses = respond(message);
      for (const response of Array.isArray(responses) ? responses : [responses])
        socket.send(response, remote.port, remote.address);
    }
  });
  servers.push(socket);
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(
      {
        port,
        address: type === "udp4" ? "0.0.0.0" : "::",
      },
      resolve,
    );
  });
}

await multicastResponder({
  type: "udp4",
  port: 5353,
  group: "224.0.0.251",
  membership: "192.0.2.2",
  respond: mdnsRecordResponse,
});
await multicastResponder({
  type: "udp6",
  port: 5353,
  group: "ff02::fb",
  membership: "::%target0",
  respond: mdnsRecordResponse,
});
await multicastResponder({
  type: "udp4",
  port: 3702,
  group: "239.255.255.250",
  membership: "192.0.2.2",
  respond: wsDiscoveryResponse,
});
await multicastResponder({
  type: "udp6",
  port: 3702,
  group: "ff02::c",
  membership: "::%target0",
  respond: wsDiscoveryResponse,
});
await multicastResponder({
  type: "udp4",
  port: 5355,
  group: "224.0.0.252",
  membership: "192.0.2.2",
  respond: (message) =>
    llmnrAddressResponse(message, Buffer.from([192, 0, 2, 2])),
});
await multicastResponder({
  type: "udp6",
  port: 5355,
  group: "ff02::1:3",
  membership: "::%target0",
  respond: (message) =>
    llmnrAddressResponse(
      message,
      Buffer.from([
        0x20, 0x01, 0x0d, 0xb8, 0, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
      ]),
    ),
});

await startRouterAdvertisementResponder();

console.log("READY");

const close = () => {
  rawAbort.abort();
  for (const interval of rawIntervals) globalThis.clearInterval(interval);
  for (const server of servers) server.close();
  for (const socket of rawSockets) void socket.close();
};
process.once("SIGTERM", close);
process.once("SIGINT", close);
