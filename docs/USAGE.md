# Usage

## Scan an npm lockfile

From the repository root:

```powershell
npm install
npm run build
npm test
npm run scan -- --lockfile "C:\\path\\to\\project\\package-lock.json" --source "C:\\path\\to\\project" --out ".\\pathguard-results.json"
```

Use `npm run scan -- --help` for command usage. `--source` points to the application source directory; if omitted, PathGuard scans the directory containing the lockfile. The JSON report includes source evidence globally and alongside each matching package finding. Check `warnings` before interpreting a scan as complete. Network/API errors are recorded as warnings and can cause missed findings.

## Source evidence milestone

The TypeScript syntax-tree analyzer currently recognizes static ECMAScript import declarations and simple CommonJS `require("package")` variable assignments plus direct calls through those local bindings. It excludes local/relative imports and marks every item `reachabilityStatus: "not-proven"`. It is not a whole-program call-graph engine, does not resolve arbitrary aliases or dynamic imports, and does not prove path conditions.


Every source evidence record currently uses `reachabilityStatus: "not-proven"`. A static import or call reference indicates potential source usage only; it does not establish that the vulnerable function is reachable at runtime or that an exploit condition is satisfied. Missing evidence must not be interpreted as proof that a dependency is safe.
