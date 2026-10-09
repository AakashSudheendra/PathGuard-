# Usage

## Scan an npm lockfile

From the repository root:

```powershell
npm install
npm run build
npm test
npm run scan -- --lockfile "C:\\path\\to\\project\\package-lock.json" --source "C:\\path\\to\\project" --out ".\\pathguard-results.json"
```

Use `npm run scan -- --help` for command usage. `--source` points to the application source directory; if omitted, PathGuard scans the directory containing the lockfile. The JSON report includes source evidence globally and alongside each matching package finding. Findings include `ranking` factors and the `pathguard-v1` priority score. Check `warnings` before interpreting a scan as complete. Network/API errors are recorded as warnings and can cause missed findings.

## Source evidence milestone

The TypeScript syntax-tree analyzer currently recognizes static ECMAScript import declarations and simple CommonJS `require("package")` variable assignments plus direct calls through those local bindings. It excludes local/relative imports and marks every item `reachabilityStatus: "not-proven"`. It is not a whole-program call-graph engine, does not resolve arbitrary aliases or dynamic imports, and does not prove path conditions.


The current priority score is a fixed heuristic: CVSS contributes up to 35 points, EPSS probability contributes up to 35 points, and source evidence contributes up to 30 points for a curated vulnerable-symbol match (18 for a general call reference, 8 for import-only evidence). Missing CVSS/EPSS values remain null in the report; the score is not a calibrated probability. The formula is versioned as `pathguard-v1`.

Every source evidence record currently uses `reachabilityStatus: "not-proven"`. A static import or call reference indicates potential source usage only; it does not establish that the vulnerable function is reachable at runtime or that an exploit condition is satisfied. Missing evidence must not be interpreted as proof that a dependency is safe. Each finding also has `sourceEvidenceAssessment.status`: `vulnerable-symbol-observed` means a call reference matches a reviewed mapping; `no-matching-symbol-evidence` means the current analyzer did not find that symbol; `no-curated-symbol-mapping` means the symbol-level status is unknown. None of these statuses proves runtime reachability or exploitability. The initial mapping is deliberately small and must be expanded only with cited, reviewed advisory-to-symbol evidence.
