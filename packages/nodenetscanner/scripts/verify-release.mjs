import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const manifests = [
  join(repositoryRoot, "crates/nodenetscanner-native/Cargo.toml"),
  join(repositoryRoot, "crates/nodenetscanner-engine/Cargo.toml"),
  join(repositoryRoot, "crates/nodenet-linux-context/Cargo.toml"),
  join(repositoryRoot, "crates/nodenet-protocols/Cargo.toml"),
  join(repositoryRoot, "crates/nodenetscanner-engine/fuzz/Cargo.toml"),
  join(repositoryRoot, "crates/nodenet-protocols/fuzz/Cargo.toml"),
];
const packageJson = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
);
const policy = JSON.parse(
  readFileSync(join(packageRoot, "release-policy.json"), "utf8"),
);
function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}
requireCondition(packageJson.version === policy.release, "version drift");
requireCondition(packageJson.private !== true, "scanner must be publishable");
requireCondition(
  packageJson.dependencies === undefined,
  "runtime dependencies forbidden",
);
requireCondition(packageJson.engines.node === ">=26.0.0", "Node floor drift");
requireCondition(packageJson.os?.join() === "linux", "Linux-only policy drift");
requireCondition(packageJson.libc?.join() === "glibc", "glibc policy drift");
requireCondition(policy.artifacts.length === 3, "artifact matrix incomplete");
requireCondition(policy.schemaVersion === 2, "release policy schema drift");
requireCondition(
  policy.resultBatchSchema?.emittedVersion === 2 &&
    policy.resultBatchSchema?.acceptedVersions?.join() === "1,2",
  "result batch schema policy drift",
);
requireCondition(
  policy.udpProbeCatalogue?.version === "1.3.0" &&
    policy.udpProbeCatalogue?.protocolVariants === 33 &&
    policy.udpProbeCatalogue?.safeVariants === 9 &&
    policy.udpProbeCatalogue?.blockedCapabilities === 13,
  "UDP catalogue policy drift",
);
const nativeCargo = readFileSync(manifests[0], "utf8");
requireCondition(
  nativeCargo.includes(`version = "${packageJson.version}"`),
  "native/npm versions differ",
);
for (const target of ["linux-x64-gnu", "linux-arm64-gnu"]) {
  const targetManifest = JSON.parse(
    readFileSync(join(packageRoot, "npm", target, "package.json"), "utf8"),
  );
  requireCondition(
    targetManifest.version === packageJson.version,
    `${target} version drift`,
  );
  requireCondition(targetManifest.os?.join() === "linux", `${target} OS drift`);
  requireCondition(
    targetManifest.libc?.join() === "glibc",
    `${target} libc drift`,
  );
  requireCondition(
    targetManifest.scripts === undefined,
    `${target} has scripts`,
  );
}
const packages = new Map();
for (const manifest of manifests) {
  const metadata = spawnSync(
    "cargo",
    [
      "metadata",
      "--manifest-path",
      manifest,
      "--locked",
      "--format-version",
      "1",
    ],
    { encoding: "utf8" },
  );
  requireCondition(
    metadata.status === 0,
    metadata.stderr || `cargo metadata failed for ${manifest}`,
  );
  for (const dependency of JSON.parse(metadata.stdout).packages)
    packages.set(`${dependency.name}@${dependency.version}`, dependency);
}
const licenses = [
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unicode-3.0",
];
for (const dependency of packages.values())
  requireCondition(
    dependency.license &&
      licenses.some((term) => dependency.license.includes(term)),
    `unreviewed Rust license for ${dependency.name}: ${dependency.license}`,
  );
const audit = spawnSync("npm", ["audit", "--omit=dev", "--audit-level=high"], {
  cwd: repositoryRoot,
  stdio: "inherit",
});
requireCondition(audit.status === 0, "npm production audit failed");
console.log(
  `scanner release policy verified; ${packages.size} Rust packages reviewed`,
);
