import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const inferredTarget = `linux-${process.arch}-gnu`;
const binary =
  process.argv[2] ?? `build/native/nodenetraw.linux-${process.arch}-gnu.node`;
const target = process.argv[3] ?? inferredTarget;
const expectedMachines = {
  "linux-x64-gnu": /Advanced Micro Devices X86-64|X86-64/i,
  "linux-arm64-gnu": /AArch64/i,
};
const maximumGlibc = [2, 28];

function fail(message) {
  throw new Error(`native artifact rejected: ${message}`);
}

function run(command, arguments_) {
  const result = spawnSync(command, arguments_, { encoding: "utf8" });
  if (result.status !== 0)
    fail(result.stderr.trim() || `${command} failed for ${binary}`);
  return result.stdout;
}

function compareVersion(left, right) {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

if (!existsSync(binary)) fail(`missing binary ${binary}`);
const expectedMachine = expectedMachines[target];
if (expectedMachine === undefined) fail(`unsupported target ${target}`);

const header = run("readelf", ["--file-header", binary]);
const machine = /^\s*Machine:\s*(.+)$/mu.exec(header)?.[1];
if (machine === undefined || !expectedMachine.test(machine))
  fail(`target ${target} does not match ELF machine ${machine ?? "unknown"}`);

const versions = run("readelf", ["--version-info", binary]);
const required = [
  ...versions.matchAll(/\bGLIBC_(\d+)\.(\d+)(?:\.(\d+))?\b/gu),
].map((match) => match.slice(1).map((part) => Number(part ?? 0)));
if (required.length === 0)
  fail("ELF contains no inspectable GLIBC requirements");
required.sort(compareVersion);
const highest = required.at(-1);
if (compareVersion(highest, maximumGlibc) > 0)
  fail(
    `requires GLIBC_${highest.join(".")}, above the declared GLIBC_${maximumGlibc.join(".")} baseline`,
  );

console.log(
  `verified ${target} ELF architecture and GLIBC requirement <= ${maximumGlibc.join(".")} (highest ${highest.join(".")})`,
);
