import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const target = process.argv[3] ?? `linux-${process.arch}-gnu`;
const binary =
  process.argv[2] ??
  `build/native/nodenetscanner.linux-${process.arch}-gnu.node`;
const machines = {
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
function compare(left, right) {
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

if (!existsSync(binary)) fail(`missing binary ${binary}`);
const expected = machines[target];
if (expected === undefined) fail(`unsupported target ${target}`);
const machine = /^\s*Machine:\s*(.+)$/mu.exec(
  run("readelf", ["--file-header", binary]),
)?.[1];
if (machine === undefined || !expected.test(machine))
  fail(`target ${target} does not match ELF machine ${machine ?? "unknown"}`);
const requirements = [
  ...run("readelf", ["--version-info", binary]).matchAll(
    /\bGLIBC_(\d+)\.(\d+)(?:\.(\d+))?\b/gu,
  ),
].map((match) => match.slice(1).map((part) => Number(part ?? 0)));
if (requirements.length === 0) fail("ELF contains no GLIBC requirements");
requirements.sort(compare);
const highest = requirements.at(-1);
if (compare(highest, maximumGlibc) > 0)
  fail(`requires GLIBC_${highest.join(".")}, above GLIBC_2.28 baseline`);
console.log(
  `verified ${target} ELF architecture and GLIBC requirement <= 2.28 (highest ${highest.join(".")})`,
);
