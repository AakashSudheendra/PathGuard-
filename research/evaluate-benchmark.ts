import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

type Label = "reachable" | "not_reachable" | "unknown";
interface LabelRow {
  case_id: string;
  package_name: string;
  installed_version: string;
  osv_ids: string;
  cve_ids: string;
  label: Label;
  [key: string]: string;
}
interface Finding {
  name: string;
  version: string;
  vulnerability: { id?: string; aliases?: string[]; severity?: Array<{score?: string}>; epssByCve?: Array<{cve: string; score: {score: number} | null}> };
  ranking?: { cvssBaseScore: number | null; epssProbability: number | null; priorityScore: number; formulaVersion: string };
}
interface ScanReport { findings: Finding[]; generatedAt?: string; tool?: {name?: string; version?: string}; }
interface CaseResult { caseId: string; label: Exclude<Label, "unknown">; scores: Record<"cvss-only" | "epss-only" | "pathguard-v1", number>; }
interface MetricResult {
  method: string;
  evaluatedCases: number;
  positiveCases: number;
  precisionAtK: number | null;
  recallAtK: number | null;
  ndcgAtK: number | null;
  ndcgAtKBootstrap95CI: [number, number] | null;
}

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
    else if (ch === "\n") {
      row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = "";
    } else field += ch;
  }
  if (field.length || row.length) { row.push(field.replace(/\r$/, "")); rows.push(row); }
  return rows.filter((r) => r.some((v) => v.trim() !== ""));
}
function parseLabels(text: string): LabelRow[] {
  const rows = parseCsv(text);
  const headers = rows.shift()?.map((x) => x.trim()) ?? [];
  const required = ["case_id", "package_name", "installed_version", "osv_ids", "cve_ids", "label"];
  for (const name of required) if (!headers.includes(name)) throw new Error(`Labels CSV missing required column: ${name}`);
  return rows.map((values, index) => {
    const record = Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])) as LabelRow;
    record.label = record.label.trim().toLowerCase() as Label;
    if (!record.case_id || !record.package_name || !record.installed_version) throw new Error(`Labels CSV row ${index + 2} is missing case_id, package_name, or installed_version.`);
    if (!["reachable", "not_reachable", "unknown"].includes(record.label)) throw new Error(`Invalid label on CSV row ${index + 2}: ${record.label}`);
    return record;
  });
}
function ids(value: string): Set<string> {
  return new Set(value.toUpperCase().split(/[;,|\s]+/).map((x) => x.trim()).filter(Boolean));
}
function findingIds(finding: Finding): Set<string> {
  return new Set([finding.vulnerability.id ?? "", ...(finding.vulnerability.aliases ?? [])].map((x) => x.toUpperCase()).filter(Boolean));
}
function scoreFor(label: LabelRow, findings: Finding[]): CaseResult | null {
  const wanted = new Set([...ids(label.osv_ids), ...ids(label.cve_ids)]);
  if (!wanted.size) return null;
  const matches = findings.filter((finding) =>
    finding.name === label.package_name &&
    finding.version === label.installed_version &&
    [...findingIds(finding)].some((id) => wanted.has(id))
  );
  if (!matches.length) return null;
  const max = (values: Array<number | null | undefined>) => {
    const known = values.filter((x): x is number => typeof x === "number" && Number.isFinite(x));
    return known.length ? Math.max(...known) : 0;
  };
  return {
    caseId: label.case_id,
    label: label.label as Exclude<Label, "unknown">,
    scores: {
      "cvss-only": max(matches.map((x) => x.ranking?.cvssBaseScore)),
      "epss-only": max(matches.map((x) => x.ranking?.epssProbability)),
      "pathguard-v1": max(matches.map((x) => x.ranking?.priorityScore))
    }
  };
}
function dcg(relevances: number[]): number {
  return relevances.reduce((sum, relevance, i) => sum + (Math.pow(2, relevance) - 1) / Math.log2(i + 2), 0);
}
function ndcgAtK(rows: CaseResult[], method: keyof CaseResult["scores"], k: number): number | null {
  if (!rows.length) return null;
  const ranked = [...rows].sort((a,b) => b.scores[method] - a.scores[method] || a.caseId.localeCompare(b.caseId));
  const observed = dcg(ranked.slice(0,k).map((x) => x.label === "reachable" ? 1 : 0));
  const ideal = dcg([...rows].map((x) => x.label === "reachable" ? 1 : 0).sort((a,b) => b-a).slice(0,k));
  return ideal === 0 ? null : observed / ideal;
}
function metrics(rows: CaseResult[], method: keyof CaseResult["scores"], k: number): MetricResult {
  const ranked = [...rows].sort((a,b) => b.scores[method] - a.scores[method] || a.caseId.localeCompare(b.caseId));
  const top = ranked.slice(0, Math.min(k, ranked.length));
  const positives = rows.filter((x) => x.label === "reachable").length;
  const hits = top.filter((x) => x.label === "reachable").length;
  return {
    method,
    evaluatedCases: rows.length,
    positiveCases: positives,
    precisionAtK: top.length ? hits / top.length : null,
    recallAtK: positives ? hits / positives : null,
    ndcgAtK: ndcgAtK(rows, method, k),
    ndcgAtKBootstrap95CI: bootstrapNdcg(rows, method, k)
  };
}
function bootstrapNdcg(rows: CaseResult[], method: keyof CaseResult["scores"], k: number): [number, number] | null {
  if (rows.length < 2 || !rows.some((x) => x.label === "reachable")) return null;
  let seed = 20261009;
  const random = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  const values: number[] = [];
  for (let b = 0; b < 1000; b++) {
    const sample = Array.from({length: rows.length}, () => rows[Math.floor(random() * rows.length)]!);
    const value = ndcgAtK(sample, method, k);
    if (value !== null) values.push(value);
  }
  values.sort((a,b) => a-b);
  if (!values.length) return null;
  return [values[Math.floor(0.025 * (values.length - 1))]!, values[Math.floor(0.975 * (values.length - 1))]!];
}
function parseArgs(argv: string[]) {
  const args: Record<string,string> = {};
  for (let i=0;i<argv.length;i++) {
    const key = argv[i]!;
    if (!key.startsWith("--") || !argv[i+1] || argv[i+1]!.startsWith("--")) throw new Error(`Expected --option value, got ${key}`);
    args[key.slice(2)] = argv[++i]!;
  }
  if (!args.report || !args.labels) throw new Error("Usage: npm run evaluate:benchmark -- --report <scan-report.json> --labels <labels.csv> [--out <metrics.json>] [--k 5]");
  const k = args.k === undefined ? 5 : Number(args.k);
  if (!Number.isInteger(k) || k < 1) throw new Error("--k must be a positive integer.");
  return {report:resolve(args.report),labels:resolve(args.labels),out:args.out ? resolve(args.out) : undefined,k};
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = JSON.parse(await readFile(args.report,"utf8")) as ScanReport;
  const labels = parseLabels(await readFile(args.labels,"utf8"));
  const results = labels.map((label) => ({label, result:scoreFor(label, report.findings ?? [])}));
  const matched = results.filter((x) => x.result !== null);
  const evaluable = matched.filter((x) => x.label.label !== "unknown" && x.result !== null)
    .map((x) => x.result!) as CaseResult[];
  const methods: Array<keyof CaseResult["scores"]> = ["cvss-only","epss-only","pathguard-v1"];
  const output = {
    schemaVersion: "1.0",
    evaluator: "PathGuard benchmark evaluator",
    generatedAt: new Date().toISOString(),
    input: {report:args.report,labels:args.labels,scanGeneratedAt:report.generatedAt ?? null,scanTool:report.tool ?? null,k:args.k},
    protocol: {
      relevantLabel: "reachable",
      negativeLabel: "not_reachable",
      unknownLabel: "unknown (excluded from ranking metrics)",
      unmatchedCasesExcludedFromRankingMetrics: true,
      missingCvssOrEpssScore: "0 for baseline ordering only; the report keeps the original value null",
      tieBreak: "case_id ascending",
      bootstrap: "1000 deterministic case-level resamples; percentile 95% interval for nDCG@k"
    },
    coverage: {
      labelRows: labels.length,
      matchedRows: matched.length,
      unmatchedRows: labels.length - matched.length,
      matchedCoverage: labels.length ? matched.length / labels.length : 0,
      unknownMatchedRows: matched.filter((x) => x.label.label === "unknown").length,
      evaluableMatchedRows: evaluable.length
    },
    metrics: methods.map((method) => metrics(evaluable,method,args.k)),
    unmatchedCaseIds: results.filter((x) => x.result === null).map((x) => x.label.case_id)
  };
  const json = JSON.stringify(output,null,2) + "\n";
  if (args.out) {
    await mkdir(dirname(args.out),{recursive:true});
    await writeFile(args.out,json,"utf8");
  }
  console.log(JSON.stringify(output,null,2));
  if (args.out) console.log(`Metrics report: ${args.out}`);
}
main().catch((error: unknown) => {
  console.error(`Benchmark evaluation failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
