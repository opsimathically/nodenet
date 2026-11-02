import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = resolve(
  packageRoot,
  `build/native/nodenetscanner.linux-${process.arch}-gnu.node`,
);
const directories = ["scanner-repro-one", "scanner-repro-two"].map((name) =>
  resolve(packageRoot, "release", name),
);
function build(directory) {
  rmSync(directory, { force: true, recursive: true });
  const result = spawnSync("npm", ["run", "build:native:release"], {
    cwd: packageRoot,
    env: {
      ...process.env,
      CARGO_INCREMENTAL: "0",
      CARGO_TARGET_DIR: directory,
      SOURCE_DATE_EPOCH: process.env.SOURCE_DATE_EPOCH ?? "1783843200",
    },
    stdio: "inherit",
  });
  if (result.status !== 0) throw new Error("release native build failed");
  return createHash("sha256").update(readFileSync(binary)).digest("hex");
}
try {
  const [first, second] = directories.map(build);
  if (first !== second)
    throw new Error(`non-reproducible native binary: ${first} != ${second}`);
  console.log(`reproducible scanner binary ${first}`);
} finally {
  for (const directory of directories)
    rmSync(directory, { force: true, recursive: true });
}
