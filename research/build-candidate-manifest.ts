import { createHash } from "node:crypto";
import { readFile, writeFile, readdir } from "node:fs/promises";
import { basename, resolve } from "node:path";

interface Finding {
  name?: string;
  version?: string;
  vulnerability?: { id?: string; aliases?: string[] };
}
interface ScanReport {
  schemaVersion?: string;
  generatedAt?: string;
  findings?: Finding[];
  input?: { repositoryUrl?: string; repositoryCommit?: string };
}
const headers = [
  "case_id", "repository_url", "commit_sha", "ecosystem", "package_name",
  "installed_version", "osv_ids", "cve_ids", "vulnerable_function",
  "source_evidence", "label", "reviewer_1", "reviewer_1_label",
  "reviewer_2", "reviewer_2_label", "disagreement_notes", "source_date",
  "epss_date", "notes",
];
function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function parseArgs(args: string[]): { reportsDir: string; out: string } {
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (!["--reports-dir", "--out"].includes(arg)) throw new Error(`Unknown argument: ${arg}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg, value);
  }
  const reportsDir = values.get("--reports-dir");
  const out = values.get("--out");
  if (!reportsDir || !out) {
    throw new Error("Usage: npm run build:candidates -- --reports-dir <directory> --out <candidate.csv>");
  }
  return { reportsDir: resolve(reportsDir), out: resolve(out) };
}
async function main() {
  const { reportsDir, out } = parseArgs(process.argv.slice(2));
  const files = (await readdir(reportsDir)).filter((name) => name.toLowerCase().endsWith(".json")).sort();
  if (!files.length) throw new Error(`No JSON scan reports found in ${reportsDir}`);
  const seen = new Set<string>();
  const rows: string[][] = [];
  for (const file of files) {
    const report = JSON.parse(await readFile(resolve(reportsDir, file), "utf8")) as ScanReport;
    if (report.schemaVersion !== "1.1") throw new Error(`${file}: expected report schemaVersion 1.1`);
    const repositoryUrl = report.input?.repositoryUrl?.trim();
    const commitSha = report.input?.repositoryCommit?.trim();
    if (!repositoryUrl || !/^https?:\/\//i.test(repositoryUrl) || !commitSha || !/^[a-f0-9]{40}$/i.test(commitSha)) {
      throw new Error(`${file}: report must contain repositoryUrl and a full 40-character repositoryCommit SHA`);
    }
    for (const finding of report.findings ?? []) {
      if (!finding.name || !finding.version || !finding.vulnerability) continue;
      const identifiers = [...new Set([finding.vulnerability.id, ...(finding.vulnerability.aliases ?? [])]
        .map((value) => value?.trim().toUpperCase()).filter((value): value is string => Boolean(value)))].sort();
      if (!identifiers.length) continue;
      const cves = identifiers.filter((id) => /^CVE-\d{4}-\d+$/i.test(id));
      const otherIds = identifiers.filter((id) => !/^CVE-\d{4}-\d+$/i.test(id));
      const stableKey = [repositoryUrl, commitSha.toLowerCase(), finding.name, finding.version, ...identifiers].join("|");
      if (seen.has(stableKey)) continue;
      seen.add(stableKey);
      const caseId = `pg-${createHash("sha256").update(stableKey).digest("hex").slice(0, 16)}`;
      const values: Record<string, string> = {
        case_id: caseId,
        repository_url: repositoryUrl,
        commit_sha: commitSha.toLowerCase(),
        ecosystem: "npm",
        package_name: finding.name,
        installed_version: finding.version,
        osv_ids: otherIds.join(";"),
        cve_ids: cves.join(";"),
        vulnerable_function: "",
        source_evidence: "",
        label: "",
        reviewer_1: "",
        reviewer_1_label: "",
        reviewer_2: "",
        reviewer_2_label: "",
        disagreement_notes: "",
        source_date: "",
        epss_date: "",
        notes: `UNREVIEWED candidate from ${basename(file)}; independently verify advisory, vulnerable function, and application call path before assigning a label.`,
      };
      rows.push(headers.map((header) => values[header] ?? ""));
    }
  }
  if (!rows.length) throw new Error("No findings with package, version, and advisory identifiers were found.");
  await writeFile(out, [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n", "utf8");
  process.stdout.write(`Candidate manifest written: ${out}\nReports processed: ${files.length}\nUnlabeled candidate cases: ${rows.length}\nLabels assigned: 0 (all cases require independent review)\n`);
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
