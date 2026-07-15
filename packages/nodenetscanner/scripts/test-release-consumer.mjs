import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    encoding: "utf8",
    stdio: "inherit",
    ...options,
  });
  if (result.status !== 0)
    throw new Error(`${command} ${arguments_.join(" ")} failed`);
}
run("npm", ["run", "build:native:release"], { cwd: packageRoot });
run(process.execPath, ["scripts/assemble-release.mjs"], { cwd: packageRoot });
const target = `linux-${process.arch}-gnu`;
const tarballs = join(packageRoot, "release", "tarballs");
rmSync(tarballs, { force: true, recursive: true });
mkdirSync(tarballs, { recursive: true });
for (const stage of [`nodenetscanner-${target}`, "nodenetscanner"])
  run("npm", ["pack", "--pack-destination", "../../tarballs"], {
    cwd: join(packageRoot, "release", "stage", stage),
  });
const version = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
).version;
const consumer = mkdtempSync(join(tmpdir(), "nodenetscanner-consumer-"));
try {
  run("npm", ["init", "--yes"], { cwd: consumer });
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(
        tarballs,
        `opsimathically-nodenetscanner-linux-${process.arch}-gnu-${version}.tgz`,
      ),
      join(tarballs, `opsimathically-nodenetscanner-${version}.tgz`),
    ],
    { cwd: consumer },
  );
  const assertion =
    "const m=await import('@opsimathically/nodenetscanner'); if(typeof m.createScanner!=='function'||typeof m.inspectNetworkContext!=='function'||m.RESULT_BATCH_SCHEMA_VERSION!==2||m.SUPPORTED_RESULT_BATCH_SCHEMA_VERSIONS.join(',')!=='1,2'||m.SUPPORTED_SCAN_PROBES.length!==6||m.UDP_PROBE_CATALOGUE.version!=='1.3.0'||m.UDP_PROBE_CATALOGUE.variants!==33)process.exit(1); const s=await m.createScanner(); await s.close()";
  run(process.execPath, ["--input-type=module", "--eval", assertion], {
    cwd: consumer,
  });
  run(
    process.execPath,
    [
      "--eval",
      "const m=require('@opsimathically/nodenetscanner'); if(typeof m.createScanner!=='function')process.exit(1); m.createScanner().then(s=>s.close())",
    ],
    { cwd: consumer },
  );
  console.log(`clean consumer passed for ${version} on ${target}`);
} finally {
  rmSync(consumer, { force: true, recursive: true });
}
