import { createHash } from "node:crypto";
import { readFile, writeFile, readdir } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { extractCvssBaseScore } from "../apps/scanner/src/ranking.js";

interface Evidence {
  packageName?: string;
  file?: string;
  line?: number;
  evidenceType?: string;
  importedSymbol?: string;
  expression?: string;
}
interface Advisory {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  references?: Array<{type?: string; url?: string}>;
  severity?: Array<{type?: string; score?: string}>;
}
interface Finding {
  name?: string;
  version?: string;
  vulnerability?: Advisory & { epssByCve?: Array<{cve: string; score: {date?: string; score: number} | null}> };
  sourceEvidenceAssessment?: { status?: string; matchedCve?: string | null; mappedSymbols?: string[] };
  ranking?: { cvssBaseScore?: number | null; epssProbability?: number | null; priorityScore?: number };
}
interface PathGuardReport {
  schemaVersion?: string;
  generatedAt?: string;
  findings?: Finding[];
  sourceEvidence?: Evidence[];
  input?: { repositoryUrl?: string; repositoryCommit?: string };
}
interface OsvScannerReport {
  results?: Array<{ packages?: Array<{ package?: { name?: string; version?: string; ecosystem?: string }; vulnerabilities?: Advisory[] }> }>;
}
interface Metadata { repositoryUrl?: string; repositoryCommit?: string; toolVersion?: string; exitCode?: number; }
interface Candidate {
  repositoryUrl: string;
  commitSha: string;
  packageName: string;
  installedVersion: string;
  ids: Set<string>;
  sources: Set<string>;
  sourceEvidence: Set<string>;
  mappingHints: Set<string>;
  references: Set<string>;
  notes: Set<string>;
  advisorySummary: string;
  cvssScore: string;
  epssScore: string;
  pathguardScore: string;
  sourceAssessment: string;
  sourceDate: string;
  epssDate: string;
}
const headers = [
  "case_id", "repository_url", "commit_sha", "ecosystem", "package_name",
  "installed_version", "osv_ids", "cve_ids", "advisory_summary", "advisory_references",
  "vulnerable_function", "mapping_hint_symbols", "source_evidence", "cvss_score",
  "epss_score", "pathguard_score", "source_assessment", "label", "reviewer_1",
  "reviewer_1_label", "reviewer_2", "reviewer_2_label", "disagreement_notes",
  "source_date", "epss_date", "discovery_source", "notes",
];
function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function parseArgs(args: string[]): { reportsDir: string; externalReportsDir?: string; out: string } {
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (!["--reports-dir", "--external-reports-dir", "--out"].includes(arg)) throw new Error(`Unknown argument: ${arg}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg, value);
  }
  const reportsDir = values.get("--reports-dir");
  const externalReportsDir = values.get("--external-reports-dir");
  const out = values.get("--out");
  if (!reportsDir || !out) {
    throw new Error("Usage: npm run build:candidates -- --reports-dir <PathGuard-report-dir> [--external-reports-dir <OSV-Scanner-report-dir>] --out <candidate.csv>");
  }
  return { reportsDir: resolve(reportsDir), ...(externalReportsDir && { externalReportsDir: resolve(externalReportsDir) }), out: resolve(out) };
}
function getIds(vulnerability: Advisory | undefined): Set<string> {
  return new Set([vulnerability?.id, ...(vulnerability?.aliases ?? [])]
    .map((value) => value?.trim().toUpperCase()).filter((value): value is string => Boolean(value)));
}
function validateMetadata(file: string, metadata: Metadata): { repositoryUrl: string; commitSha: string } {
  const repositoryUrl = metadata.repositoryUrl?.trim();
  const commitSha = metadata.repositoryCommit?.trim();
  if (!repositoryUrl || !/^https?:\/\//i.test(repositoryUrl) || !commitSha || !/^[a-f0-9]{40}$/i.test(commitSha)) {
    throw new Error(`${file}: metadata must contain repositoryUrl and a full 40-character repositoryCommit SHA`);
  }
  return { repositoryUrl, commitSha: commitSha.toLowerCase() };
}
function addCandidate(candidates: Candidate[], input: {
  repositoryUrl: string; commitSha: string; packageName: string; installedVersion: string;
  ids: Set<string>; source: string; evidence?: string[]; mappingHints?: string[];
  references?: string[]; summary?: string; cvssScore?: number | null; epssScore?: number | null;
  pathguardScore?: number | null; sourceAssessment?: string; sourceDate?: string; epssDate?: string; note: string;
}) {
  if (!input.ids.size) return;
  const existing = candidates.find((candidate) =>
    candidate.repositoryUrl === input.repositoryUrl &&
    candidate.commitSha.toLowerCase() === input.commitSha.toLowerCase() &&
    candidate.packageName === input.packageName &&
    candidate.installedVersion === input.installedVersion &&
    [...candidate.ids].some((id) => input.ids.has(id))
  );
  const candidate = existing ?? {
    repositoryUrl: input.repositoryUrl,
    commitSha: input.commitSha.toLowerCase(),
    packageName: input.packageName,
    installedVersion: input.installedVersion,
    ids: new Set<string>(), sources: new Set<string>(), sourceEvidence: new Set<string>(),
    mappingHints: new Set<string>(), references: new Set<string>(), notes: new Set<string>(),
    advisorySummary: "", cvssScore: "", epssScore: "", pathguardScore: "",
    sourceAssessment: "", sourceDate: "", epssDate: "",
  };
  for (const id of input.ids) candidate.ids.add(id);
  candidate.sources.add(input.source);
  for (const item of input.evidence ?? []) candidate.sourceEvidence.add(item);
  for (const item of input.mappingHints ?? []) candidate.mappingHints.add(item);
  for (const item of input.references ?? []) candidate.references.add(item);
  if (!candidate.advisorySummary && input.summary) candidate.advisorySummary = input.summary;
  if (!candidate.cvssScore && input.cvssScore !== null && input.cvssScore !== undefined) candidate.cvssScore = String(input.cvssScore);
  if (!candidate.epssScore && input.epssScore !== null && input.epssScore !== undefined) candidate.epssScore = String(input.epssScore);
  if (!candidate.pathguardScore && input.pathguardScore !== null && input.pathguardScore !== undefined) candidate.pathguardScore = String(input.pathguardScore);
  if (!candidate.sourceAssessment && input.sourceAssessment) candidate.sourceAssessment = input.sourceAssessment;
  if (!candidate.sourceDate && input.sourceDate) candidate.sourceDate = input.sourceDate;
  if (!candidate.epssDate && input.epssDate) candidate.epssDate = input.epssDate;
  candidate.notes.add(input.note);
  if (!existing) candidates.push(candidate);
}
async function main() {
  const { reportsDir, externalReportsDir, out } = parseArgs(process.argv.slice(2));
  const candidates: Candidate[] = [];
  const files = (await readdir(reportsDir)).filter((name) => name.toLowerCase().endsWith(".json")).sort();
  if (!files.length) throw new Error(`No JSON PathGuard scan reports found in ${reportsDir}`);
  for (const file of files) {
    const report = JSON.parse(await readFile(resolve(reportsDir, file), "utf8")) as PathGuardReport;
    if (report.schemaVersion !== "1.1") throw new Error(`${file}: expected PathGuard report schemaVersion 1.1`);
    const { repositoryUrl, commitSha } = validateMetadata(file, {
      repositoryUrl: report.input?.repositoryUrl, repositoryCommit: report.input?.repositoryCommit,
    });
    for (const finding of report.findings ?? []) {
      const vuln = finding.vulnerability;
      if (!finding.name || !finding.version || !vuln) continue;
      const evidence = (report.sourceEvidence ?? [])
        .filter((item) => item.packageName === finding.name && item.file && item.line)
        .slice(0, 8)
        .map((item) => `${item.file}:${item.line}:${item.expression ?? item.importedSymbol ?? item.evidenceType ?? "source-reference"}`);
      const epssScores = (vuln.epssByCve ?? []).flatMap((item) => item.score && Number.isFinite(item.score.score) ? [item.score] : []);
      addCandidate(candidates, {
        repositoryUrl, commitSha, packageName: finding.name, installedVersion: finding.version,
        ids: getIds(vuln), source: "PathGuard", evidence,
        mappingHints: finding.sourceEvidenceAssessment?.mappedSymbols ?? [],
        references: (vuln.references ?? []).flatMap((ref) => ref.url ? [ref.url] : []),
        summary: vuln.summary,
        cvssScore: finding.ranking?.cvssBaseScore ?? extractCvssBaseScore(vuln),
        epssScore: finding.ranking?.epssProbability ?? null,
        pathguardScore: finding.ranking?.priorityScore ?? null,
        sourceAssessment: finding.sourceEvidenceAssessment?.status ?? "unknown",
        sourceDate: report.generatedAt,
        epssDate: epssScores.map((item) => item.date).filter((x): x is string => Boolean(x)).sort().at(-1),
        note: `UNREVIEWED candidate from PathGuard report ${basename(file)}; independently verify advisory, vulnerable function, and application call path before assigning a label.`,
      });
    }
  }
  let externalFiles = 0;
  if (externalReportsDir) {
    const names = (await readdir(externalReportsDir)).filter((name) => name.endsWith(".osv.json")).sort();
    if (!names.length) throw new Error(`No *.osv.json OSV-Scanner reports found in ${externalReportsDir}`);
    for (const file of names) {
      const metadataFile = file.replace(/\.osv\.json$/, ".meta.json");
      const metadata = JSON.parse(await readFile(resolve(externalReportsDir, metadataFile), "utf8")) as Metadata;
      const { repositoryUrl, commitSha } = validateMetadata(metadataFile, metadata);
      const report = JSON.parse(await readFile(resolve(externalReportsDir, file), "utf8")) as OsvScannerReport;
      externalFiles++;
      for (const result of report.results ?? []) {
        for (const pkg of result.packages ?? []) {
          const name = pkg.package?.name;
          const version = pkg.package?.version;
          if (!name || !version) continue;
          for (const vuln of pkg.vulnerabilities ?? []) {
            addCandidate(candidates, {
              repositoryUrl, commitSha, packageName: name, installedVersion: version,
              ids: getIds(vuln), source: "OSV-Scanner",
              references: (vuln.references ?? []).flatMap((ref) => ref.url ? [ref.url] : []),
              summary: vuln.summary,
              cvssScore: extractCvssBaseScore(vuln),
              note: `UNREVIEWED candidate from OSV-Scanner report ${basename(file)}; independently verify advisory and application reachability.`,
            });
          }
        }
      }
    }
  }
  if (!candidates.length) throw new Error("No candidate cases with package, version, and advisory identifiers were found.");
  const rows = candidates.map((candidate) => {
    const allIds = [...candidate.ids].sort();
    const cves = allIds.filter((id) => /^CVE-\d{4}-\d+$/i.test(id));
    const otherIds = allIds.filter((id) => !/^CVE-\d{4}-\d+$/i.test(id));
    const primaryId = cves[0] ?? allIds[0]!;
    const stableKey = [candidate.repositoryUrl, candidate.commitSha, candidate.packageName, candidate.installedVersion, primaryId].join("|");
    const caseId = `pg-${createHash("sha256").update(stableKey).digest("hex").slice(0, 16)}`;
    const values: Record<string, string> = {
      case_id: caseId,
      repository_url: candidate.repositoryUrl,
      commit_sha: candidate.commitSha,
      ecosystem: "npm",
      package_name: candidate.packageName,
      installed_version: candidate.installedVersion,
      osv_ids: otherIds.join(";"),
      cve_ids: cves.join(";"),
      advisory_summary: candidate.advisorySummary,
      advisory_references: [...candidate.references].sort().join(";"),
      vulnerable_function: "",
      mapping_hint_symbols: [...candidate.mappingHints].sort().join(";"),
      source_evidence: [...candidate.sourceEvidence].join(" | "),
      cvss_score: candidate.cvssScore,
      epss_score: candidate.epssScore,
      pathguard_score: candidate.pathguardScore,
      source_assessment: candidate.sourceAssessment,
      label: "",
      reviewer_1: "",
      reviewer_1_label: "",
      reviewer_2: "",
      reviewer_2_label: "",
      disagreement_notes: "",
      source_date: candidate.sourceDate,
      epss_date: candidate.epssDate,
      discovery_source: [...candidate.sources].sort().join(";"),
      notes: [...candidate.notes].join(" "),
    };
    return headers.map((header) => values[header] ?? "");
  });
  await writeFile(out, [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n", "utf8");
  process.stdout.write(`Candidate manifest written: ${out}\nPathGuard reports processed: ${files.length}\nOSV-Scanner reports processed: ${externalFiles}\nUnion candidate cases: ${rows.length}\nLabels assigned: 0 (all cases require independent review)\n`);
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
