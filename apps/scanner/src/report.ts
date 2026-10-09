export interface EpssScore {
  cve: string;
  score: number;
  percentile: number;
  date?: string;
}

export interface VulnerabilityRecord {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  affected?: unknown[];
}

export interface EnrichedVulnerability extends VulnerabilityRecord {
  epssByCve: Array<{ cve: string; score: EpssScore | null }>;
}

export interface PackageFinding {
  name: string;
  version: string;
  vulnerability: EnrichedVulnerability;
}

export interface FindingSummary {
  dependenciesChecked: number;
  vulnerablePackages: number;
  advisoryRecords: number;
  uniqueCves: number;
  packageCvePairs: number;
}

export function extractCveAliases(record: VulnerabilityRecord): string[] {
  const values = [record.id, ...(record.aliases ?? [])]
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.toUpperCase().trim());
  return [...new Set(values.filter((value) => /^CVE-\d{4}-\d{4,}$/.test(value)))].sort();
}

export function attachEpssScores(
  records: VulnerabilityRecord[],
  epssByCve: Map<string, EpssScore>
): EnrichedVulnerability[] {
  return records.map((record) => ({
    ...record,
    epssByCve: extractCveAliases(record).map((cve) => ({
      cve,
      score: epssByCve.get(cve) ?? null
    }))
  }));
}

export function summarizeFindings(
  dependenciesChecked: number,
  findings: PackageFinding[]
): FindingSummary {
  const packagePairs = new Set<string>();
  const cves = new Set<string>();
  const packages = new Set<string>();
  for (const finding of findings) {
    packages.add(`${finding.name}@${finding.version}`);
    for (const cve of extractCveAliases(finding.vulnerability)) {
      cves.add(cve);
      packagePairs.add(`${finding.name}@${finding.version}::${cve}`);
    }
  }
  return {
    dependenciesChecked,
    vulnerablePackages: packages.size,
    advisoryRecords: findings.length,
    uniqueCves: cves.size,
    packageCvePairs: packagePairs.size
  };
}
