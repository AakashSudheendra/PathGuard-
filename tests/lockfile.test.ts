import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readNpmLockfile } from "../apps/scanner/src/lockfile.js";

test("reads v3 lockfile and skips root package", async () => {
  const deps = await readNpmLockfile(fileURLToPath(new URL("./fixtures/vulnerable-package-lock.json", import.meta.url)));
  assert.deepEqual(deps, [{ name: "lodash", version: "4.17.20" }]);
});

test("reads a legacy v1 dependency tree", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pathguard-lock-"));
  try {
    const path = join(dir, "package-lock.json");
    await writeFile(path, JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } }));
    assert.deepEqual(await readNpmLockfile(path), [{ name: "a", version: "1.0.0" }, { name: "b", version: "2.0.0" }]);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("reports invalid JSON with useful context", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pathguard-lock-"));
  try {
    const path = join(dir, "package-lock.json");
    await writeFile(path, "{");
    await assert.rejects(() => readNpmLockfile(path), /Invalid JSON in lockfile/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
