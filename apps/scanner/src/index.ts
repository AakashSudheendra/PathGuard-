import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { readNpmLockfile, type LockedDependency } from "./lockfile.js";
import { attachEpssScores, summarizeFindings, type EpssScore, type PackageFinding, type VulnerabilityRecord } from "./report.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const USER_AGENT = "PathGuard/0.1.0 (research prototype)";

interface OsvBatchResult { vulns?: Array<{ id: string }>; }
interface OsvBatchResponse { results?: OsvBatchResult[]; }
interface OsvVulnerability extends VulnerabilityRecord { id: string; }

interface ScanReport {
  schemaVersion: "1.0";
  tool: { name: "PathGuard"; version: "0.1.0" };
  generatedAt: string;
  input: { lockfile: string; ecosystem: "npm" };
  sources: { osv: string; epss: string };
  summary: ReturnType<typeof summarizeFindings>;
  dependencies: LockedDependency[];
  findings: Array<PackageFinding & {
    epss: Array<{ cve: string; score: EpssScore | null }>;
    maxEpssScore: number | null;
  }>;
  warnings: string[];
}

function parseArgs(argv: string[]): { lockfile: string; out: string; limit: number } {
  let lockfile = "package-lock.json";
  let out = "pathguard-results.json";
  let limit = 500;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--lockfile" && next) { lockfile = next; i++; }
    else if (arg === "--out" && next) { out = next; i++; }
    else if (arg === "--limit" && next) {
      const parsed = Number(next);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 5000) throw new Error("--limit must be an integer from 1 to 5000.");
      limit = parsed; i++;
    } else if (arg === "--help" || arg === "-h") {
      console.log("PathGuard npm dependency scanner\n\nUsage: npm run scan -- --lockfile <path> [--out <path>] [--limit <count>]\nDefaults: package-lock.json, pathguard-results.json, limit=500");
      process.exit(0);
    } else {
      throw new Error(`Unknown or incomplete argument: ${arg}. Use --help.`);
    }
  }
  return { lockfile: resolve(lockfile), out: resolve(out), limit };
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { "content-type": "application/json", "user-agent": USER_AGENT, ...init?.headers },
    signal: AbortSignal.timeout(25_000)
  });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}: ${(await response.text()).slice(0, 300)}`);
  return await response.json() as T;
}

async function queryOsv(dependencies: LockedDependency[], warnings: string[]): Promise<Map<string, OsvVulnerability[]>> {
  const result = new Map<string, OsvVulnerability[]>();
  // OSV batch query supports many queries, but use small chunks to keep requests predictable.
  const batchSize = 100;
  for (let start = 0; start < dependencies.length; start += batchSize) {
    const chunk = dependencies.slice(start, start + batchSize);
    const body = {
      queries: chunk.map((dependency) => ({
        version: dependency.version,
        package: { name: dependency.name, ecosystem: "npm" }
      }))
    };
    let batch: OsvBatchResponse;
    try {
      batch = await fetchJson<OsvBatchResponse>(OSV_BATCH_URL, { method: "POST", body: JSON.stringify(body) });
    } catch (error) {
      warnings.push(`OSV batch failed for dependencies ${start + 1}-${start + chunk.length}: ${String(error)}`);
      continue;
    }

    const results = batch.results ?? [];
    for (let i = 0; i < chunk.length; i++) {
      const advisoryIds = results[i]?.vulns?.map((v) => v.id) ?? [];
      const records: OsvVulnerability[] = [];
      for (const advisoryId of [...new Set(advisoryIds)]) {
        try {
          records.push(await fetchJson<OsvVulnerability>(OSV_VULN_URL + encodeURIComponent(advisoryId)));
        } catch (error) {
          warnings.push(`Could not retrieve OSV advisory ${advisoryId}: ${String(error)}`);
          records.push({ id: advisoryId, summary: "OSV advisory detail unavailable" });
        }
      }
      result.set(`${chunk[i]!.name}@${chunk[i]!.version}`, records);
    }
  }
  return result;
}

async function queryEpss(cves: string[], warnings: string[]): Promise<Map<string, EpssScore>> {
  const scores = new Map<string, EpssScore>();
  // FIRST EPSS accepts comma-separated CVEs; constrain URL size using chunks.
  for (let start = 0; start < cves.length; start += 80) {
    const ids = cves.slice(start, start + 80);
    const url = new URL(EPSS_URL);
    url.searchParams.set("cve", ids.join(","));
    try {
      const response = await fetchJson<{ data?: Array<{ cve: string; epss: string; percentile: string; date?: string }> }>(url.toString());
      for (const item of response.data ?? []) {
        const score = Number(item.epss);
        const percentile = Number(item.percentile);
        if (!item.cve || !Number.isFinite(score) || !Number.isFinite(percentile)) continue;
        scores.set(item.cve.toUpperCase(), { cve: item.cve.toUpperCase(), score, percentile, ...(item.date && { date: item.date }) });
      }
    } catch (error) {
      warnings.push(`EPSS lookup failed for CVEs ${start + 1}-${start + ids.length}: ${String(error)}`);
    }
  }
  return scores;
}

async function run(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const warnings: string[] = [];
  const dependencies = await readNpmLockfile(args.lockfile);
  if (dependencies.length > args.limit) {
    warnings.push(`Dependency count (${dependencies.length}) exceeds scan limit (${args.limit}); scanning only the first ${args.limit} alphabetically sorted dependencies.`);
  }
  const scanned = dependencies.slice(0, args.limit);
  console.log(`PathGuard: scanning ${scanned.length} of ${dependencies.length} dependencies...`);
  const osvByPackage = await queryOsv(scanned, warnings);

  const rawFindings: PackageFinding[] = [];
  for (const dependency of scanned) {
    for (const vulnerability of osvByPackage.get(`${dependency.name}@${dependency.version}`) ?? []) {
      rawFindings.push({ ...dependency, vulnerability });
    }
  }

  const cves = [...new Set(rawFindings.flatMap((finding) =>
    [finding.vulnerability.id, ...(finding.vulnerability.aliases ?? [])]
      .filter((id): id is string => typeof id === "string")
      .map((id) => id.toUpperCase())
      .filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id))
  ))].sort();
  const epssByCve = await queryEpss(cves, warnings);
  const findings = rawFindings.map((finding) => {
    const [vulnerability] = attachEpssScores([finding.vulnerability], epssByCve);
    const epss = vulnerability!.epssByCve;
    const presentScores = epss.flatMap((entry) => entry.score ? [entry.score.score] : []);
    return {
      ...finding,
      vulnerability: vulnerability!,
      epss,
      maxEpssScore: presentScores.length ? Math.max(...presentScores) : null
    };
  });

  // High EPSS is an evidence dimension, not proof of application reachability.
  findings.sort((a, b) => (b.maxEpssScore ?? -1) - (a.maxEpssScore ?? -1) ||
    a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  const report: ScanReport = {
    schemaVersion: "1.0",
    tool: { name: "PathGuard", version: "0.1.0" },
    generatedAt: new Date().toISOString(),
    input: { lockfile: args.lockfile, ecosystem: "npm" },
    sources: { osv: OSV_BATCH_URL, epss: EPSS_URL },
    summary: summarizeFindings(scanned.length, findings),
    dependencies: scanned,
    findings,
    warnings
  };
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(report, null, 2) + "\n", "utf8");

  console.log(`Dependencies checked: ${report.summary.dependenciesChecked}`);
  console.log(`Packages with known vulnerabilities: ${report.summary.vulnerablePackages}`);
  console.log(`OSV advisory records: ${report.summary.advisoryRecords}`);
  console.log(`Unique CVEs: ${report.summary.uniqueCves}`);
  console.log(`Package-CVE pairs: ${report.summary.packageCvePairs}`);
  console.log(`Warnings: ${warnings.length}`);
  console.log(`Report: ${args.out}`);
  if (warnings.length) {
    console.warn("Some external queries failed. Inspect the report warnings; the scan may be incomplete.");
  }
}

run().catch((error: unknown) => {
  console.error(`PathGuard scan failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
