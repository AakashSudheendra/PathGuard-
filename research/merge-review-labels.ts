import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

type Label = "reachable" | "not_reachable" | "unknown";
type Row = Record<string, string>;
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
function readRows(text: string, name: string): Row[] {
  const rows = parseCsv(text);
  const headers = rows.shift()?.map((x) => x.trim()) ?? [];
  if (!headers.includes("case_id")) throw new Error(`${name}: missing case_id column`);
  return rows.map((values, index) => {
    const row = Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])) as Row;
    if (!row.case_id.trim()) throw new Error(`${name}: blank case_id at row ${index + 2}`);
    return row;
  });
}
function uniqueMap(rows: Row[], name: string): Map<string, Row> {
  const result = new Map<string, Row>();
  for (const row of rows) {
    if (result.has(row.case_id)) throw new Error(`${name}: duplicate case_id ${row.case_id}`);
    result.set(row.case_id, row);
  }
  return result;
}
function validLabel(value: string, context: string): Label {
  const label = value.trim().toLowerCase();
  if (!["reachable", "not_reachable", "unknown"].includes(label)) {
    throw new Error(`${context}: label must be reachable, not_reachable, or unknown; got "${value}"`);
  }
  return label as Label;
}
function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function parseArgs(args: string[]) {
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (!["--candidates", "--reviewer-1", "--reviewer-2", "--adjudication", "--out"].includes(arg)) {
      throw new Error(`Unknown argument: ${arg}`);
    }
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
    values.set(arg, value);
  }
  const candidates = values.get("--candidates"), reviewer1 = values.get("--reviewer-1"),
    reviewer2 = values.get("--reviewer-2"), adjudication = values.get("--adjudication"), out = values.get("--out");
  if (!candidates || !reviewer1 || !reviewer2 || !adjudication || !out) {
    throw new Error("Usage: npm run merge:review-labels -- --candidates <full-candidates.csv> --reviewer-1 <reviewer1.csv> --reviewer-2 <reviewer2.csv> --adjudication <adjudication.csv> --out <labeled-cases.csv>");
  }
  return { candidates: resolve(candidates), reviewer1: resolve(reviewer1), reviewer2: resolve(reviewer2), adjudication: resolve(adjudication), out: resolve(out) };
}
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const candidateRows = readRows(await readFile(args.candidates, "utf8"), "candidates");
  const reviewer1Rows = uniqueMap(readRows(await readFile(args.reviewer1, "utf8"), "reviewer 1"), "reviewer 1");
  const reviewer2Rows = uniqueMap(readRows(await readFile(args.reviewer2, "utf8"), "reviewer 2"), "reviewer 2");
  const adjudicationRows = uniqueMap(readRows(await readFile(args.adjudication, "utf8"), "adjudication"), "adjudication");
  const candidateIds = new Set(candidateRows.map((row) => row.case_id));
  for (const [name, map] of [["reviewer 1", reviewer1Rows], ["reviewer 2", reviewer2Rows], ["adjudication", adjudicationRows]] as const) {
    const missing = [...candidateIds].filter((id) => !map.has(id));
    const extra = [...map.keys()].filter((id) => !candidateIds.has(id));
    if (missing.length || extra.length) {
      throw new Error(`${name}: case IDs must exactly match the candidate manifest. Missing ${missing.length}; unknown ${extra.length}.`);
    }
  }
  const outputHeaders = [...Object.keys(candidateRows[0] ?? {}), "reviewer_1_notes", "reviewer_2_notes", "adjudication_notes"];
  if (!candidateRows.length) throw new Error("Candidate manifest contains no cases.");
  const output: string[][] = [];
  let disagreements = 0;
  for (const candidate of candidateRows) {
    const id = candidate.case_id;
    const r1 = reviewer1Rows.get(id)!;
    const r2 = reviewer2Rows.get(id)!;
    const adj = adjudicationRows.get(id)!;
    const label1 = validLabel(r1.reviewer_label ?? "", `reviewer 1 case ${id}`);
    const label2 = validLabel(r2.reviewer_label ?? "", `reviewer 2 case ${id}`);
    const finalLabel = validLabel(adj.label ?? "", `adjudication case ${id}`);
    const note = (adj.disagreement_notes ?? "").trim();
    if ((label1 !== label2 || finalLabel !== label1 || finalLabel !== label2) && !note) {
      throw new Error(`Case ${id}: reviewer/adjudicated labels disagree but disagreement_notes is blank.`);
    }
    if (label1 !== label2 || finalLabel !== label1 || finalLabel !== label2) disagreements++;
    const row: Row = {
      ...candidate,
      label: finalLabel,
      reviewer_1: (r1.reviewer_name ?? "").trim(),
      reviewer_1_label: label1,
      reviewer_2: (r2.reviewer_name ?? "").trim(),
      reviewer_2_label: label2,
      disagreement_notes: note,
    };
    output.push([...Object.keys(candidate).map((key) => row[key] ?? ""), (r1.review_notes ?? "").trim(), (r2.review_notes ?? "").trim(), note]);
  }
  await writeFile(args.out, [outputHeaders, ...output].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n", "utf8");
  process.stdout.write(`Labeled benchmark CSV written: ${args.out}\nCases merged: ${output.length}\nCases requiring disagreement documentation: ${disagreements}\n`);
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
