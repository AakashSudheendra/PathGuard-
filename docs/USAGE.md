# Usage

## Scan an npm lockfile

From the repository root:

```powershell
npm ci
npm run build
npm test
npm run scan -- --lockfile "C:\\path\\to\\project\\package-lock.json" --source "C:\\path\\to\\project" --out ".\\pathguard-results.json"
```

Use `npm run scan -- --help` for command usage. `--source` points to the application source directory; if omitted, PathGuard scans the directory containing the lockfile. The JSON report includes source evidence globally and alongside each matching package finding. Findings include `ranking` factors and the `pathguard-v1` priority score. Check `warnings` before interpreting a scan as complete. Network/API errors are recorded as warnings and can cause missed findings.

## Source evidence limitations

The TypeScript syntax-tree analyzer currently recognizes static ECMAScript import declarations and simple CommonJS `require("package")` variable assignments plus direct calls through those local bindings. It excludes local/relative imports and marks every item `reachabilityStatus: "not-proven"`. It is not a whole-program call-graph engine, does not resolve arbitrary aliases or dynamic imports, and does not prove path conditions.

The current priority score is a fixed heuristic: CVSS contributes up to 35 points, EPSS probability contributes up to 35 points, and source evidence contributes up to 30 points for a curated vulnerable-symbol match (18 for a general call reference, 8 for import-only evidence). Missing CVSS/EPSS values remain null in the report; the score is not a calibrated probability. The formula is versioned as `pathguard-v1`.

Every source evidence record currently uses `reachabilityStatus: "not-proven"`. A static import or call reference indicates potential source usage only; it does not establish that the vulnerable function is reachable at runtime or that an exploit condition is satisfied. Missing evidence must not be interpreted as proof that a dependency is safe. Each finding also has `sourceEvidenceAssessment.status`: `vulnerable-symbol-observed` means a call reference matches a reviewed mapping; `no-matching-symbol-evidence` means the current analyzer did not find that symbol; `no-curated-symbol-mapping` means the symbol-level status is unknown. None of these statuses proves runtime reachability or exploitability.

## Reproducible benchmark scans

For each benchmark repository, scan its pinned commit and include metadata used by the evaluator:

```powershell
npm run scan -- --lockfile ".\\benchmarks\\repo-a\\package-lock.json" --source ".\\benchmarks\\repo-a" --repo-url "https://github.com/OWNER/REPOSITORY" --commit "FULL_40_CHARACTER_COMMIT_SHA" --out ".\\research\\scan-reports\\repo-a.json"
```

Use the repository URL and commit recorded in the label CSV exactly. Store one report per repository commit.

## Generate a candidate manifest

Once real scan reports exist, produce a review queue:

```powershell
npm run build:candidates -- --reports-dir ".\\research\\scan-reports" --out ".\\research\\benchmark-candidates.csv"
```

The generator validates schema version 1.1 and immutable repository metadata, deduplicates stable case keys, and creates deterministic case IDs. It intentionally leaves all labels blank. Reviewers must verify each advisory and vulnerable function against the pinned source, preserve reviewer decisions and disagreement notes, and assign the final adjudicated label. Candidate rows are not ground truth.

## Evaluate the completed labels

```powershell
npm run evaluate:benchmark -- --reports-dir ".\\research\\scan-reports" --labels ".\\research\\labeled-cases.csv" --out ".\\research\\metrics.json" --k 5
```

The evaluator requires repository URL and commit metadata and will not match a case against a report from another repository/commit. For an external scanner comparison, also pass `--external-ranking` and `--external-name`; the external CSV must include every label case and give score zero to cases the tool did not flag.
