import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const binary = `build/native/nodenetraw.linux-${process.arch}-gnu.node`;
const targetDirectories = [
  resolve("release/repro-one"),
  resolve("release/repro-two"),
];

function buildAndHash(targetDirectory) {
  rmSync(targetDirectory, { force: true, recursive: true });
  const result = spawnSync("npm", ["run", "build:native:release"], {
    env: {
      ...process.env,
      CARGO_INCREMENTAL: "0",
      CARGO_TARGET_DIR: targetDirectory,
      SOURCE_DATE_EPOCH: process.env.SOURCE_DATE_EPOCH ?? "1783843200",
    },
    stdio: "inherit",
  });
  if (result.status !== 0) throw new Error("release native build failed");
  return createHash("sha256").update(readFileSync(binary)).digest("hex");
}

try {
  const first = buildAndHash(targetDirectories[0]);
  const second = buildAndHash(targetDirectories[1]);
  if (first !== second)
    throw new Error(`non-reproducible native binary: ${first} != ${second}`);
  console.log(`reproducible clean native binary ${first}`);
} finally {
  for (const directory of targetDirectories)
    rmSync(directory, { force: true, recursive: true });
}
