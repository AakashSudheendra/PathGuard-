import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeSourceUsage, summarizeSourceEvidence } from "../apps/scanner/src/reachability.js";

async function withProject(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "pathguard-source-"));
  try { await run(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test("detects named import and a call reference", async () => withProject(async (root) => {
  await writeFile(join(root, "app.ts"), 'import { parse } from "lodash";\nparse("text");\n');
  const evidence = await analyzeSourceUsage(root, new Set(["lodash"]));
  assert.ok(evidence.some((x) => x.packageName === "lodash" && x.evidenceType === "static-import"));
  assert.ok(evidence.some((x) => x.packageName === "lodash" && x.evidenceType === "static-call-reference" && x.expression === "parse"));
  assert.ok(evidence.every((x) => x.reachabilityStatus === "not-proven"));
}));

test("detects scoped package names and namespace method references", async () => withProject(async (root) => {
  await writeFile(join(root, "app.ts"), 'import * as client from "@scope/pkg";\nclient.makeRequest();\n');
  const evidence = await analyzeSourceUsage(root, new Set(["@scope/pkg"]));
  assert.ok(evidence.some((x) => x.packageName === "@scope/pkg" && x.evidenceType === "static-import"));
  assert.ok(evidence.some((x) => x.packageName === "@scope/pkg" && x.expression === "client.makeRequest"));
}));

test("detects CommonJS require and ignores local imports", async () => withProject(async (root) => {
  await writeFile(join(root, "app.js"), 'const lodash = require("lodash");\nlodash.get(obj, "a");\nimport local from "./local.js";\n');
  await writeFile(join(root, "local.js"), "export default {};\n");
  const evidence = await analyzeSourceUsage(root);
  assert.ok(evidence.some((x) => x.packageName === "lodash" && x.evidenceType === "static-import"));
  assert.ok(evidence.some((x) => x.packageName === "lodash" && x.evidenceType === "static-call-reference"));
  assert.ok(!evidence.some((x) => x.packageName === "./local.js"));
}));

test("filters call references to packages not present in the lockfile", async () => withProject(async (root) => {
  await writeFile(join(root, "app.ts"), 'import * as ts from "typescript";\nts.createSourceFile("x.ts", "", ts.ScriptTarget.Latest);\n');
  const evidence = await analyzeSourceUsage(root, new Set(["lodash"]));
  assert.equal(evidence.length, 0);
}));

test("summary never overstates runtime reachability", () => {
  assert.equal(summarizeSourceEvidence([{ packageName: "x", file: "a.ts", line: 1, evidenceType: "static-import", reachabilityStatus: "not-proven" }]).reachabilityProvenCount, 0);
});
