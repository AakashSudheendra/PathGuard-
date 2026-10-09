import test from "node:test";
import assert from "node:assert/strict";
import { attachEpssScores, extractCveAliases, summarizeFindings, type EpssScore, type PackageFinding } from "../apps/scanner/src/report.js";

test("extracts and deduplicates CVE aliases", () => {
  assert.deepEqual(extractCveAliases({ id: "CVE-2024-12345", aliases: ["CVE-2024-12345", "GHSA-abcd-efgh-ijkl"] }), ["CVE-2024-12345"]);
});

test("attaches a separate EPSS result to every CVE alias and null for missing scores", () => {
  const epss = new Map<string, EpssScore>([["CVE-2024-12345", { cve: "CVE-2024-12345", score: 0.2, percentile: 0.9 }]]);
  const [record] = attachEpssScores([{ id: "GHSA-test-test-test", aliases: ["CVE-2024-12345", "CVE-2025-54321"] }], epss);
  assert.deepEqual(record?.epssByCve.map((item) => item.score?.score ?? null), [0.2, null]);
});

test("counts unique CVEs across duplicate advisory records", () => {
  const findings: PackageFinding[] = [
    { name: "lodash", version: "4.17.20", vulnerability: { id: "GHSA-a", aliases: ["CVE-2024-12345"] } },
    { name: "lodash", version: "4.17.20", vulnerability: { id: "GHSA-b", aliases: ["CVE-2024-12345"] } }
  ];
  assert.equal(summarizeFindings(1, findings).uniqueCves, 1);
  assert.equal(summarizeFindings(1, findings).packageCvePairs, 1);
});

test("counts same CVE separately for distinct package versions", () => {
  const findings: PackageFinding[] = [
    { name: "lodash", version: "4.17.20", vulnerability: { aliases: ["CVE-2024-12345"] } },
    { name: "lodash", version: "4.17.21", vulnerability: { aliases: ["CVE-2024-12345"] } }
  ];
  assert.equal(summarizeFindings(2, findings).packageCvePairs, 2);
});

test("handles advisories with no CVE identifiers", () => {
  assert.deepEqual(extractCveAliases({ id: "GHSA-abcd-efgh-ijkl", aliases: [] }), []);
});
