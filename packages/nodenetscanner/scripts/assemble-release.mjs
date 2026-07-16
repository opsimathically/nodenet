import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const release = join(packageRoot, "release");
const stage = join(release, "stage");
const manifest = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
);
const targets = {
  "linux-x64-gnu": "nodenetscanner.linux-x64-gnu.node",
  "linux-arm64-gnu": "nodenetscanner.linux-arm64-gnu.node",
};
const option = process.argv.indexOf("--target");
const target =
  option === -1 ? `linux-${process.arch}-gnu` : process.argv[option + 1];
if (!(target in targets)) throw new Error(`unsupported target: ${target}`);

function checkedCommand(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    ...options,
  });
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(
      result.error?.message ||
        result.stderr.trim() ||
        result.stdout.trim() ||
        `${command} ${arguments_.join(" ")} failed`,
    );
  }
  return result.stdout.trim();
}

const sourceStatus = checkedCommand("git", [
  "status",
  "--porcelain=v1",
  "--untracked-files=all",
]);
if (sourceStatus !== "") {
  throw new Error(
    "release assembly requires a clean Git worktree so sourceCommit identifies the exact packaged source",
  );
}
const sourceCommit = checkedCommand("git", ["rev-parse", "--verify", "HEAD"]);
const rustc = checkedCommand("rustc", ["--version", "--verbose"]);

rmSync(stage, { force: true, recursive: true });
const rootStage = join(stage, "nodenetscanner");
mkdirSync(join(rootStage, "build", "native"), { recursive: true });
for (const item of ["dist", "README.md", "CHANGELOG.md", "release-policy.json"])
  cpSync(join(packageRoot, item), join(rootStage, item), { recursive: true });
cpSync(join(repositoryRoot, "LICENSE"), join(rootStage, "LICENSE"));
cpSync(
  join(packageRoot, "build", "native", "binding.cjs"),
  join(rootStage, "build", "native", "binding.cjs"),
);
const rootManifest = {
  ...manifest,
  files: [
    "build/native/binding.cjs",
    "dist",
    "LICENSE",
    "README.md",
    "CHANGELOG.md",
    "release-policy.json",
  ],
  optionalDependencies: Object.fromEntries(
    Object.keys(targets).map((name) => [
      `@opsimathically/nodenetscanner-${name}`,
      manifest.version,
    ]),
  ),
};
delete rootManifest.scripts;
delete rootManifest.devDependencies;
delete rootManifest.napi;
writeFileSync(
  join(rootStage, "package.json"),
  `${JSON.stringify(rootManifest, null, 2)}\n`,
);

const targetStage = join(stage, `nodenetscanner-${target}`);
mkdirSync(targetStage, { recursive: true });
cpSync(join(repositoryRoot, "LICENSE"), join(targetStage, "LICENSE"));
cpSync(join(packageRoot, "README.md"), join(targetStage, "README.md"));
cpSync(
  join(packageRoot, "npm", target, "package.json"),
  join(targetStage, "package.json"),
);
const binary = targets[target];
const binaryPath = join(packageRoot, "build", "native", binary);
const verification = spawnSync(
  process.execPath,
  [
    join(packageRoot, "scripts", "verify-native-artifact.mjs"),
    binaryPath,
    target,
  ],
  { encoding: "utf8" },
);
if (verification.status !== 0)
  throw new Error(verification.stderr || verification.stdout);
process.stdout.write(verification.stdout);
const description = spawnSync("file", [binaryPath], { encoding: "utf8" });
if (
  description.status !== 0 ||
  !description.stdout.includes("stripped") ||
  description.stdout.includes("not stripped")
)
  throw new Error("release assembly requires a stripped native addon");
cpSync(binaryPath, join(targetStage, binary));

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}
const provenance = {
  schemaVersion: 1,
  packageVersion: manifest.version,
  target,
  node: process.version,
  rustc,
  sourceCommit,
  sourceDateEpoch: process.env.SOURCE_DATE_EPOCH ?? null,
  cargoLockSha256: createHash("sha256")
    .update(readFileSync(join(repositoryRoot, "Cargo.lock")))
    .digest("hex"),
  files: [...files(rootStage), ...files(targetStage)].sort().map((path) => ({
    path: relative(stage, path),
    bytes: statSync(path).size,
    sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
  })),
};
mkdirSync(release, { recursive: true });
writeFileSync(
  join(release, `provenance-${target}.json`),
  `${JSON.stringify(provenance, null, 2)}\n`,
);
console.log(`assembled scanner root and ${target} packages`);
