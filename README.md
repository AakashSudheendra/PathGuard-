# PathGuard

**Reachability-aware and evidence-guided prioritization of third-party software vulnerabilities.**

PathGuard analyzes npm lockfiles, enriches findings with OSV advisory data and EPSS exploit-likelihood scores, and adds source-level evidence when dependencies appear to be used by application code. The research question is whether these signals improve triage over severity-only and exploitation-likelihood-only ranking; improvement has not yet been established.

> **Research integrity:** source imports and call references are evidence of possible use, not proof of runtime reachability or exploitability. Performance claims require an independently labeled benchmark and reproducible comparative experiments.

## Project status

### Implemented
- [x] TypeScript scanner foundation for npm lockfiles v1/v2/v3
- [x] OSV advisory queries and CVE alias enrichment
- [x] FIRST EPSS enrichment with missing-data handling
- [x] Static TypeScript source evidence for selected imports, CommonJS bindings, and direct call references
- [x] Advisory-specific vulnerable-symbol evidence with documented provisional lodash mappings
- [x] Versioned explainable `pathguard-v1` ranking and CVSS v3.x vector parsing
- [x] Benchmark evaluator for CVSS-only, EPSS-only, PathGuard, and optional external ranking scores
- [x] Repository/commit-specific matching, label validation, coverage reporting, and ranking metrics
- [x] CI build, unit tests, and synthetic evaluator smoke test

### Not yet implemented or validated
- [ ] Whole-program, language-aware call graph or runtime reachability analysis
- [ ] Broad independently reviewed advisory-to-vulnerable-symbol corpus
- [ ] Real independently labeled benchmark and comparative evaluation
- [ ] Dashboard

The CI benchmark data are synthetic fixtures used to test the evaluator only; they are not empirical evidence.

## Requirements

- Node.js 20 or newer (Node.js 22 is used in CI)
- npm 10 or newer
- Network access for OSV and FIRST EPSS APIs

## Quick start (PowerShell)

```powershell
git clone https://github.com/AakashSudheendra/PathGuard-.git
cd PathGuard-
npm ci
npm run build
npm test
npm run scan:fixture
```

Scan a project containing `package-lock.json`:

```powershell
npm run scan -- --lockfile "C:\path\to\your\project\package-lock.json" --out "pathguard-results.json"
```

For a reproducible benchmark scan, include the repository URL and the full 40-character commit SHA:

```powershell
npm run scan -- --lockfile "C:\path\to\project\package-lock.json" --repo-url "https://github.com/owner/repository" --commit "FULL_40_CHARACTER_COMMIT_SHA" --out ".\research\scan-reports\repository.json"
```

The output path is relative to the current directory unless you provide an absolute path. Each finding includes `ranking` with CVSS, EPSS, source-evidence contributions, total priority score, and formula version. The scanner sends package names and versions to OSV and sends discovered CVE identifiers to FIRST EPSS. Review your organization's data-handling requirements before scanning private projects.

## Workspace

- `apps/scanner`: TypeScript command-line scanner.
- `tests`: unit tests and a small intentionally vulnerable lockfile fixture.
- `research`: benchmark evaluator, label template, experiment guidance, and manuscript draft.
- [Research manuscript draft](research/PAPER_DRAFT.md): empirical results remain placeholders until experiments are completed.
- [Publication checklist](research/PUBLICATION_CHECKLIST.md): separates completed engineering from required empirical work.
- [Benchmark protocol](docs/BENCHMARK_PROTOCOL.md): case selection, independent labels, baselines, metrics, and reproducibility.
- [Research workspace](research/README.md): dataset and evaluation guidance.
- [Research limitations](docs/RESEARCH_LIMITATIONS.md): scope and claims the current implementation cannot support.

## Benchmark evaluation

Save one scan JSON report per pinned repository commit in `research/scan-reports`. Use `--repo-url` and `--commit` during each scan so the evaluator joins cases by repository, immutable commit, package/version, and advisory identifiers.

To evaluate independently reviewed labels and an external baseline:

```powershell
npm run evaluate:benchmark -- --reports-dir ".\research\scan-reports" --labels ".\research\labeled-cases.csv" --external-ranking ".\research\external-scores.csv" --external-name "OSV-Scanner" --out ".\research\metrics.json" --k 5
```

The label template is empty by design. The external score CSV must include every labeled case, assigning score `0` to cases not flagged by the external tool. See the [benchmark protocol](docs/BENCHMARK_PROTOCOL.md). Never present the synthetic CI fixture as empirical evidence.

## Data sources

- OSV: https://osv.dev/
- FIRST EPSS: https://www.first.org/epss/
- OSV-Scanner: https://github.com/google/osv-scanner
- OWASP Benchmark: https://owasp.org/www-project-benchmark/

## License

MIT. See [LICENSE](LICENSE).
