# Usage

## Scan an npm lockfile

From the repository root:

```powershell
npm install
npm run build
npm test
npm run scan -- --lockfile "C:\\path\\to\\project\\package-lock.json" --out ".\\pathguard-results.json"
```

Use `npm run scan -- --help` for command usage. Output is JSON; check `warnings` before interpreting a scan as complete. Network/API errors are recorded as warnings and can cause missed findings.

## Source evidence milestone

The TypeScript syntax-tree analyzer currently recognizes static ECMAScript import declarations and simple CommonJS `require("package")` variable assignments plus direct calls through those local bindings. It excludes local/relative imports and marks every item `reachabilityStatus: "not-proven"`. It is not a whole-program call-graph engine, does not resolve arbitrary aliases or dynamic imports, and does not prove path conditions.
