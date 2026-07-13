import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

import { nativeSmokeTest } from "../dist/index.js";

test("calls the native smoke export through ESM", () => {
  assert.equal(nativeSmokeTest(), "nodenetraw:napi-ok");
});

test("loads the synchronous ESM public entry point through require", () => {
  const require = createRequire(import.meta.url);
  const requiredPackage = require("../dist/index.js");

  assert.equal(requiredPackage.nativeSmokeTest(), "nodenetraw:napi-ok");
});
