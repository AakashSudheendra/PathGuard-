import { readFile, writeFile, readdir } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { extractCvssBaseScore } from "../apps/scanner/src/ranking.js";

interface CandidateRow {
  case_id: string;
  repository_url: string;
  commit_sha: string;
  package_name: string;
  installed_version: string;
  osv_ids: string;
  cve_ids: string;
  [key: string]: string;
}
interface OsvVulnerability { id?: string; aliases?: string[]; severity?: Array<{type?: string; score?: string}>; }
interface OsvScannerReport {
  results?: Array<{ packages?: Array<{ package?: { name?: string; version?: string; ecosystem?: string }; vulnerabilities?: OsvVulnerability[] }> }>;
}
interface Metadata { repositoryUrl?: string; repositoryCommit?: string; toolVersion?: string; exitCode?: number; }
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field.length === 0) quoted = true;
    else if (ch === ",") { row.push(field); field = ""; }
    else if (ch === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
    else field += ch;
  }
  if (field.length || row.length) { row.push(field.replace(/\r$/, "")); rows.push(row); }
  return rows.filter((r) => r.some((v) => v.trim() !== ""));
}
function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function parseArgs(args: string[]) {
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (!["--candidates", "--reports-dir", "--out"].includes(arg)) throw new Error(`Unknown argument: ${arg}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg, value);
  }
  const candidates = values.get("--candidates"), reportsDir = values.get("--reports-dir"), out = values.get("--out");
  if (!candidates || !reportsDir || !out) throw new Error("Usage: npm run build:osv-scores -- --candidates <candidate.csv> --reports-dir <OSV-Scanner-reports> --out <scores.csv>");
  return { candidates: resolve(candidates), reportsDir: resolve(reportsDir), out: resolve(out) };
}
function splitIds(value: string): Set<string> {
  return new Set(value.toUpperCase().split(/[;,|\s]+/).map((x) => x.trim()).filter(Boolean));
}
function vulnIds(vuln: OsvVulnerability): Set<string> {
  return new Set([vuln.id, ...(vuln.aliases ?? [])].map((x) => x?.toUpperCase().trim()).filter((x): x is string => Boolean(x)));
}
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const candidateCsv = parseCsv(await readFile(args.candidates, "utf8"));
  const headers = candidateCsv.shift()?.map((x) => x.trim()) ?? [];
  const required = ["case_id", "repository_url", "commit_sha", "package_name", "installed_version", "osv_ids", "cve_ids"];
  for (const header of required) if (!headers.includes(header)) throw new Error(`Candidate CSV missing required column: ${header}`);
  const candidates = candidateCsv.map((values) => Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])) as CandidateRow);
  const names = (await readdir(args.reportsDir)).filter((name) => name.endsWith(".osv.json")).sort();
  if (!names.length) throw new Error(`No *.osv.json OSV-Scanner reports found in ${args.reportsDir}`);
  const records: Array<{ metadata: Metadata; report: OsvScannerReport }> = [];
  for (const file of names) {
    const metaFile = file.replace(/\.osv\.json$/, ".meta.json");
    const metadata = JSON.parse(await readFile(resolve(args.reportsDir, metaFile), "utf8")) as Metadata;
    if (!metadata.repositoryUrl || !/^[a-f0-9]{40}$/i.test(metadata.repositoryCommit ?? "")) {
      throw new Error(`${metaFile}: repositoryUrl and full repositoryCommit are required`);
    }
    if (metadata.exitCode !== 0 && metadata.exitCode !== 1) {
      throw new Error(`${metaFile}: unexpected OSV-Scanner exit code; baseline report may be incomplete`);
    }
    records.push({ metadata, report: JSON.parse(await readFile(resolve(args.reportsDir, file), "utf8")) as OsvScannerReport });
  }
  const output = [["case_id", "score", "flagged", "matched_advisory_ids", "score_source"]];
  let flaggedCount = 0;
  for (const candidate of candidates) {
    const wanted = new Set([...splitIds(candidate.osv_ids), ...splitIds(candidate.cve_ids)]);
    const repoReports = records.filter(({metadata}) =>
      metadata.repositoryUrl === candidate.repository_url &&
      metadata.repositoryCommit?.toLowerCase() === candidate.commit_sha.toLowerCase()
    );
    const matches: OsvVulnerability[] = [];
    for (const {report} of repoReports) {
      for (const result of report.results ?? []) {
        for (const pkg of result.packages ?? []) {
          if (pkg.package?.name !== candidate.package_name || pkg.package?.version !== candidate.installed_version) continue;
          for (const vuln of pkg.vulnerabilities ?? []) {
            if ([...vulnIds(vuln)].some((id) => wanted.has(id))) matches.push(vuln);
          }
        }
      }
    }
    const scores = matches.map((vuln) => extractCvssBaseScore(vuln)).filter((score): score is number => score !== null);
    const score = scores.length ? Math.max(...scores) : 0;
    if (matches.length) flaggedCount++;
    const matchedIds = [...new Set(matches.flatMap((vuln) => [...vulnIds(vuln)]))].sort().join(";");
    const source = matches.length ? (scores.length ? "OSV-Scanner CVSS severity" : "flagged; CVSS unavailable; fallback 0") : "not flagged by OSV-Scanner; score 0";
    output.push([candidate.case_id, String(score), matches.length ? "1" : "0", matchedIds, source]);
  }
  await writeFile(args.out, output.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n", "utf8");
  process.stdout.write(`OSV-Scanner score CSV written: ${args.out}\nCandidate cases: ${candidates.length}\nCases flagged by OSV-Scanner: ${flaggedCount}\nScores use the maximum OSV-Scanner-reported CVSS base score; unflagged cases receive 0. This is a detection-plus-severity baseline, not an intrinsic scanner priority score.\n`);
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
