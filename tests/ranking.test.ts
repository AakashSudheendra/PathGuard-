import test from "node:test";
import assert from "node:assert/strict";
import { extractCvssBaseScore, rankFinding } from "../apps/scanner/src/ranking.js";
import type { EnrichedVulnerability } from "../apps/scanner/src/report.js";
import type { SourceEvidence } from "../apps/scanner/src/reachability.js";

test("parses numeric CVSS scores", () => {
  assert.equal(extractCvssBaseScore({ severity: [{ score: "7.5" }] }), 7.5);
});

test("calculates the CVSS v3.1 base score from a vector", () => {
  assert.equal(extractCvssBaseScore({
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
  }), 9.8);
});

test("leaves unsupported or absent CVSS values unknown", () => {
  assert.equal(extractCvssBaseScore({ severity: [{ score: "CVSS:4.0/AV:N" }] }), null);
  assert.equal(extractCvssBaseScore({}), null);
});

test("ranking is explainable and rewards matching vulnerable-symbol evidence", () => {
  const vulnerability: EnrichedVulnerability = {
    id: "GHSA-example-example-example",
    severity: [{ score: "7.5" }],
    epssByCve: [{ cve: "CVE-2024-12345", score: { cve: "CVE-2024-12345", score: 0.2, percentile: 0.7 } }]
  };
  const evidence: SourceEvidence[] = [{
    packageName: "lodash",
    file: "src/index.js",
    line: 2,
    evidenceType: "static-call-reference",
    importedSymbol: "template",
    expression: "lodash.template",
    reachabilityStatus: "not-proven"
  }];
  const baseline = rankFinding(vulnerability, evidence, {
    status: "no-matching-symbol-evidence",
    matchedCve: "CVE-2021-23337",
    mappedPackage: "lodash",
    mappedSymbols: ["template"],
    matchingEvidence: [],
    rationale: "No matching call reference found."
  });
  const matched = rankFinding(vulnerability, evidence, {
    status: "vulnerable-symbol-observed",
    matchedCve: "CVE-2021-23337",
    mappedPackage: "lodash",
    mappedSymbols: ["template"],
    matchingEvidence: evidence,
    rationale: "Static match only."
  });
  assert.equal(matched.priorityScore - baseline.priorityScore, 12);
  assert.equal(matched.formulaVersion, "pathguard-v1");
  assert.equal(matched.cvssContribution, 26.25);
  assert.equal(matched.epssContribution, 7);
});

test("missing EPSS and CVSS stay explicitly null and do not produce NaN", () => {
  const result = rankFinding({ epssByCve: [] }, [], {
    status: "no-curated-symbol-mapping",
    matchedCve: null,
    mappedPackage: null,
    mappedSymbols: [],
    matchingEvidence: [],
    rationale: "Unknown."
  });
  assert.equal(result.cvssBaseScore, null);
  assert.equal(result.epssProbability, null);
  assert.equal(result.priorityScore, 0);
  assert.ok(Number.isFinite(result.priorityScore));
});
