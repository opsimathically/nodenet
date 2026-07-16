import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const registryRegions = [
  {
    path: "crates/nodenet-protocols/src/udp_catalogue.rs",
    start: "pub static UDP_PROBE_CATALOGUE",
    end: "/// Validates descriptor bounds",
  },
  {
    path: "crates/nodenet-protocols/src/udp_capability.rs",
    start: "pub static UDP_CAPABILITY_LEDGER",
    end: "/// Validates unique project dispositions",
  },
  {
    path: "crates/nodenet-protocols/src/udp_coverage.rs",
    start: "pub static UDP_COVERAGE_REGISTRY",
    end: "/// Validates final dispositions",
  },
  { path: "packages/nodenetscanner/release-policy.json" },
];
const fixtureRoots = ["packages/nodenetscanner/test/fixtures"];
const optionalArtifactRoots = ["packages/nodenetscanner/release/stage"];
const forbiddenInputs = [
  "nmap-service-probes",
  "/nmap_source/",
  "\\nmap_source\\",
];
const forbiddenComparisonName = /\bnmap\b/i;

function checkedRegion(value, descriptor) {
  if (descriptor.start === undefined) return value;
  const start = value.indexOf(descriptor.start);
  const end = value.indexOf(descriptor.end, start);
  if (start === -1 || end === -1 || end <= start)
    throw new Error(`${descriptor.path} registry boundary was not found`);
  return value.slice(start, end);
}

function assertNoInputPaths(path, value) {
  const lower = value.toLowerCase();
  for (const input of forbiddenInputs) {
    if (lower.includes(input))
      throw new Error(`${path} contains a prohibited comparison input path`);
  }
}

function assertIndependentData(path, value) {
  assertNoInputPaths(path, value);
  if (forbiddenComparisonName.test(value))
    throw new Error(
      `${path} embeds an external scanner name in shippable data`,
    );
}

async function filesBelow(path) {
  let metadata;
  try {
    metadata = await stat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  if (metadata.isFile()) return [path];
  const files = [];
  for (const entry of await readdir(path))
    files.push(...(await filesBelow(join(path, entry))));
  return files;
}

for (const descriptor of registryRegions) {
  const value = await readFile(descriptor.path, "utf8");
  assertIndependentData(descriptor.path, checkedRegion(value, descriptor));
}

let fixtureCount = 0;
for (const root of fixtureRoots) {
  for (const path of await filesBelow(root)) {
    assertIndependentData(path, await readFile(path, "utf8"));
    fixtureCount += 1;
  }
}

let artifactCount = 0;
for (const root of optionalArtifactRoots) {
  for (const path of await filesBelow(root)) {
    // Staged documentation may discuss comparative history, but build inputs and
    // local source paths must never leak into a publishable artifact.
    assertNoInputPaths(path, await readFile(path, "utf8"));
    artifactCount += 1;
  }
}

console.log(
  `checked ${String(registryRegions.length)} shippable UDP registries, ${String(fixtureCount)} project fixtures, and ${String(artifactCount)} staged artifacts`,
);
