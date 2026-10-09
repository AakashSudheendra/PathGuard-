# PathGuard

**Reachability-aware and evidence-guided prioritization of third-party software vulnerabilities.**

PathGuard analyzes npm lockfiles, enriches findings with OSV advisory data and EPSS exploit-likelihood scores, and adds source-level evidence when dependencies appear to be used by application code. The goal is to support more informed triage than severity-only ranking.

> Research integrity: source imports and call references are evidence of possible use, not proof that a vulnerable function is reachable at runtime. Reachability claims and performance improvements must be validated by appropriate static analysis and experiments.

## Project status

This repository starts with a reproducible npm scanner foundation. The scanner, tests, and research methodology are developed in phases. Do not interpret roadmap items as implemented functionality.

- [x] TypeScript scanner foundation
- [x] OSV advisory queries for npm lockfiles
- [x] CVE alias enrichment and EPSS lookup
- [x] Finding summaries and automated unit tests
- [x] Source usage evidence integrated into findings
- [ ] Dashboard
- [ ] Language-aware call graph / reachability engine
- [ ] Independently labeled benchmark and comparative evaluation

## Requirements

- Node.js 20 or newer (Node.js 24 recommended)
- npm 10 or newer
- Network access for OSV and FIRST EPSS APIs

## Quick start (PowerShell)

```powershell
git clone https://github.com/AakashSudheendra/PathGuard-.git
cd PathGuard-
npm install
npm run build
npm test
npm run scan:fixture
```

Scan a project containing `package-lock.json`:

```powershell
npm run scan -- --lockfile "C:\path\to\your\project\package-lock.json" --out "pathguard-results.json"
```

The output path is relative to the current directory unless you provide an absolute path. The scanner sends package names and versions to OSV and sends discovered CVE identifiers to FIRST EPSS. Review your organization's data-handling requirements before scanning private projects.

## Workspace

- `apps/scanner`: TypeScript command-line scanner.
- `tests`: unit tests and a small, intentionally vulnerable lockfile fixture.
- `research`: benchmark protocol, label template, and experiment guidance.
- `docs`: architecture and research limitations.

## Research protocol

Evaluation should compare at least CVSS-only, EPSS-only, existing scanner output, and PathGuard ranking on the same package/version cases. Define labels before looking at model rankings; separate reachable, not-reachable, and unknown/insufficient-evidence cases. Report precision/recall and ranking metrics with confidence intervals where appropriate, along with API failures, runtime, and coverage. Avoid treating missing evidence as proof of safety.

## Data sources

- OSV: https://osv.dev/
- FIRST EPSS: https://www.first.org/epss/
- OSV-Scanner: https://github.com/google/osv-scanner
- OWASP Benchmark: https://owasp.org/www-project-benchmark/

## License

MIT. See [LICENSE](LICENSE).
