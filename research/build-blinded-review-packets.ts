import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

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
    if (!["--candidates", "--out-dir"].includes(arg)) throw new Error(`Unknown argument: ${arg}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg, value);
  }
  const candidates = values.get("--candidates"), outDir = values.get("--out-dir");
  if (!candidates || !outDir) throw new Error("Usage: npm run build:review-packets -- --candidates <candidate.csv> --out-dir <directory>");
  return { candidates: resolve(candidates), outDir: resolve(outDir) };
}
async function main() {
  const { candidates: candidatePath, outDir } = parseArgs(process.argv.slice(2));
  const rows = parseCsv(await readFile(candidatePath, "utf8"));
  const headers = rows.shift()?.map((x) => x.trim()) ?? [];
  const required = ["case_id", "repository_url", "commit_sha", "ecosystem", "package_name", "installed_version", "osv_ids", "cve_ids", "advisory_summary", "advisory_references"];
  for (const header of required) if (!headers.includes(header)) throw new Error(`Candidate CSV missing required column: ${header}`);
  const input = rows.map((values) => Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])));
  const reviewHeaders = [
    "case_id", "repository_url", "commit_sha", "ecosystem", "package_name",
    "installed_version", "osv_ids", "cve_ids", "advisory_summary", "advisory_references",
    "vulnerable_function", "reviewer_label", "reviewer_name", "review_notes",
  ];
  const reviewRows = input.map((row) => reviewHeaders.map((header) => String(row[header] ?? "")));
  const csv = [reviewHeaders, ...reviewRows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
  await mkdir(outDir, { recursive: true });
  await writeFile(resolve(outDir, "reviewer-1-blinded.csv"), csv, "utf8");
  await writeFile(resolve(outDir, "reviewer-2-blinded.csv"), csv, "utf8");
  const guide = `# Independent benchmark review instructions

These two CSV files are identical blank copies for independent reviewers. Give one file to each reviewer. Do not share either reviewer's decisions until both copies are complete.

## Blinding

The review packets intentionally omit PathGuard priority scores, CVSS/EPSS scores, source analyzer output, discovery-source flags, and system source-assessment statuses. Do not add those fields while reviewing. The reviewer should determine the label from the pinned source and advisory evidence, not from either tool's score.

## Required label

For each case, enter exactly one value in `reviewer_label`:

- `reachable`: source evidence and relevant configuration support a plausible path to the advisory's vulnerable function and its preconditions.
- `not_reachable`: positive evidence supports that the vulnerable functionality cannot be reached in the evaluated configuration. Absence of an import or failed text search alone is insufficient.
- `unknown`: the source path, vulnerable function, or relevant preconditions cannot be determined confidently.

Record the vulnerable function and concise rationale in `vulnerable_function` and `review_notes`. Include file paths and line numbers at the pinned commit. Use advisory references in the row, and verify affected package versions independently.

## After independent review

Keep both original files unchanged as raw review records. Adjudicate disagreements separately, document the rationale, and merge the two reviewer labels plus adjudicated label into the full candidate manifest only after both reviews are complete. Do not treat candidate discovery by either scanner as proof of reachability or ground truth.
`;
  await writeFile(resolve(outDir, "REVIEW_INSTRUCTIONS.md"), guide, "utf8");
  process.stdout.write(`Blinded review packets written to ${outDir}\nCases per reviewer: ${reviewRows.length}\nTool-specific scores and source-analysis fields omitted.\n`);
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
