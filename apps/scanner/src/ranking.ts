import type { EnrichedVulnerability } from "./report.js";
import type { SourceEvidenceAssessment } from "./vulnerability-evidence.js";
import type { SourceEvidence } from "./reachability.js";

export interface RankingFactors {
  cvssBaseScore: number | null;
  epssProbability: number | null;
  sourceEvidenceLevel: "vulnerable-symbol-observed" | "static-call-reference" | "static-import" | "none-or-unknown";
  cvssContribution: number;
  epssContribution: number;
  sourceContribution: number;
  priorityScore: number;
  formulaVersion: "pathguard-v1";
}

/** Parse a numeric CVSS score or calculate the CVSS v3.x base score from its vector. */
export function extractCvssBaseScore(vulnerability: EnrichedVulnerability | { severity?: Array<{type?: string; score?: string}> }): number | null {
  for (const item of vulnerability.severity ?? []) {
    if (!item.score) continue;
    const numeric = Number(item.score);
    if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 10) return numeric;
    const parsed = cvssV3BaseScore(item.score);
    if (parsed !== null) return parsed;
  }
  return null;
}

function cvssV3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics = new Map(vector.split("/").slice(1).map((part) => {
    const split = part.split(":");
    return [split[0]!, split[1]!] as const;
  }));
  const av: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const ac: Record<string, number> = { L: 0.77, H: 0.44 };
  const ui: Record<string, number> = { N: 0.85, R: 0.62 };
  const impactMetric: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const AV = av[metrics.get("AV") ?? ""];
  const AC = ac[metrics.get("AC") ?? ""];
  const UI = ui[metrics.get("UI") ?? ""];
  const S = metrics.get("S");
  const C = impactMetric[metrics.get("C") ?? ""];
  const I = impactMetric[metrics.get("I") ?? ""];
  const A = impactMetric[metrics.get("A") ?? ""];
  const PRmap: Record<string, number> = S === "C"
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 };
  const PR = PRmap[metrics.get("PR") ?? ""];
  if ([AV, AC, UI, C, I, A, PR].some((x) => x === undefined) || (S !== "U" && S !== "C")) return null;
  const isc = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = S === "U"
    ? 6.42 * isc
    : 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  const raw = S === "U"
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);
  return Math.ceil(raw * 10 - 1e-10) / 10;
}

export function rankFinding(
  vulnerability: EnrichedVulnerability,
  sourceEvidence: SourceEvidence[],
  assessment: SourceEvidenceAssessment
): RankingFactors {
  const cvssBaseScore = extractCvssBaseScore(vulnerability);
  const scores = vulnerability.epssByCve.flatMap((entry) =>
    entry.score && Number.isFinite(entry.score.score) ? [entry.score.score] : []
  );
  const epssProbability = scores.length ? Math.max(...scores) : null;
  const packageEvidence = sourceEvidence.filter((item) =>
    item.packageName && item.evidenceType === "static-call-reference"
  );
  let sourceEvidenceLevel: RankingFactors["sourceEvidenceLevel"] = "none-or-unknown";
  let sourceContribution = 0;
  if (assessment.status === "vulnerable-symbol-observed") {
    sourceEvidenceLevel = "vulnerable-symbol-observed";
    sourceContribution = 30;
  } else if (packageEvidence.length > 0) {
    sourceEvidenceLevel = "static-call-reference";
    sourceContribution = 18;
  } else if (sourceEvidence.some((item) => item.evidenceType === "static-import")) {
    sourceEvidenceLevel = "static-import";
    sourceContribution = 8;
  }

  // Fixed, versioned heuristic for experiments: CVSS 35%, EPSS probability 35%,
  // and source evidence up to 30 points. Missing CVSS/EPSS contributes zero and
  // remains explicitly missing in the report; this is a ranking policy, not a probability.
  const cvssContribution = cvssBaseScore === null ? 0 : cvssBaseScore * 3.5;
  const epssContribution = epssProbability === null ? 0 : Math.max(0, Math.min(1, epssProbability)) * 35;
  const priorityScore = Math.round((cvssContribution + epssContribution + sourceContribution) * 100) / 100;
  return {
    cvssBaseScore,
    epssProbability,
    sourceEvidenceLevel,
    cvssContribution: Math.round(cvssContribution * 100) / 100,
    epssContribution: Math.round(epssContribution * 100) / 100,
    sourceContribution,
    priorityScore,
    formulaVersion: "pathguard-v1"
  };
}
