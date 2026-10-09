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
- [x] Advisory-specific vulnerable-symbol evidence with provisional lodash and Busboy mappings
- [x] Versioned explainable `pathguard-v1` ranking and CVSS v3.x vector parsing
- [x] Benchmark evaluator for CVSS-only, EPSS-only, PathGuard, and optional external ranking scores
- [x] Repository/commit-specific matching, label validation, coverage reporting, and ranking metrics
- [x] Unlabeled benchmark-candidate generator that can merge PathGuard and OSV-Scanner discovery
- [x] CI build, unit tests, and synthetic evaluator/candidate-generator smoke tests

### Not yet implemented or validated
- [ ] Whole-program, language-aware call graph or runtime reachability analysis
- [ ] Broad independently reviewed advisory-to-vulnerable-symbol corpus
- [ ] Real independently labeled benchmark and comparative evaluation
- [ ] Dashboard

The CI benchmark data are synthetic fixtures used to test the tooling only; they are not empirical evidence.

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

For a reproducible benchmark scan, include the repository URL and full 40-character commit SHA:

```powershell
npm run scan -- --lockfile "C:\path\to\project\package-lock.json" --repo-url "https://github.com/owner/repository" --commit "FULL_40_CHARACTER_COMMIT_SHA" --out ".\research\scan-reports\repository.json"
```

The output path is relative to the current directory unless you provide an absolute path. Each finding includes `ranking` with CVSS, EPSS, source-evidence contributions, total priority score, and formula version. The scanner sends package names and versions to OSV and sends discovered CVE identifiers to FIRST EPSS. Review your organization's data-handling requirements before scanning private projects.

## Workspace

- `apps/scanner`: TypeScript command-line scanner.
- `tests`: unit tests and a small intentionally vulnerable lockfile fixture.
- `research`: benchmark evaluator, candidate generator, label template, experiment guidance, and manuscript draft.
- [Research manuscript draft](research/PAPER_DRAFT.md): empirical results remain placeholders until experiments are completed.
- [Publication checklist](research/PUBLICATION_CHECKLIST.md): separates completed engineering from required empirical work.
- [Benchmark protocol](docs/BENCHMARK_PROTOCOL.md): case selection, independent labels, baselines, metrics, and reproducibility.
- [Research workspace](research/README.md): dataset and evaluation guidance.
- [Research limitations](docs/RESEARCH_LIMITATIONS.md): scope and claims the current implementation cannot support.

## Collect and prepare benchmark candidates

The [public benchmark cohort](research/PUBLIC_BENCHMARK_COHORT.md) documents five pinned repositories and the workflow that scans them with PathGuard and OSV-Scanner v2.6.0. The workflow uploads immutable scan reports, OSV-Scanner outputs, a union candidate CSV, an OSV-Scanner CVSS baseline score CSV, a reproducibility manifest, and two blinded review packets as a GitHub Actions artifact. The initial cohort is a seed convenience sample, not a representative benchmark.

For your own reports, generate a candidate CSV for independent review:

```powershell
npm run build:candidates -- --reports-dir ".\research\scan-reports" --external-reports-dir ".\research\osv-scanner-reports" --out ".\research\benchmark-candidates.csv"
```

This command merges package/version/advisory cases discovered by PathGuard and OSV-Scanner, deduplicates matching advisory identifiers, and creates stable IDs. It deliberately leaves all labels blank. Reviewers must verify the advisory, vulnerable function, source evidence, and call path, then independently assign labels and record adjudication. Generated candidates are not ground truth and must not be passed to the evaluator until they have been reviewed and completed. For a candidate CSV produced by the cohort workflow, the accompanying `osv-scanner-scores.csv` uses OSV-Scanner's reported CVSS severity for flagged cases and zero for unflagged cases; this is a detection-plus-severity baseline, not an intrinsic scanner priority score.

## Benchmark evaluation

After review, evaluate the labeled CSV and optionally include an external baseline:

```powershell
npm run evaluate:benchmark -- --reports-dir ".\research\scan-reports" --labels ".\research\labeled-cases.csv" --external-ranking ".\research\external-scores.csv" --external-name "OSV-Scanner" --out ".\research\metrics.json" --k 5
```

The label template is empty by design. The two blinded reviewer packets intentionally omit system scores and source-analysis output; give one to each independent reviewer and do not share decisions until both are complete. After adjudication, merge the completed files with `npm run merge:review-labels -- --candidates ".\\research\\benchmark-candidates.csv" --reviewer-1 ".\\research\\reviewer-1-blinded.csv" --reviewer-2 ".\\research\\reviewer-2-blinded.csv" --adjudication ".\\research\\adjudication.csv" --out ".\\research\\labeled-cases.csv"`. The adjudication CSV must contain `case_id,label,disagreement_notes` for every candidate. The external score CSV must include every labeled case, assigning score `0` to cases not flagged by the external tool. See the [benchmark protocol](docs/BENCHMARK_PROTOCOL.md). Never present the synthetic CI fixture as empirical evidence.

## Data sources

- OSV: https://osv.dev/
- FIRST EPSS: https://www.first.org/epss/
- OSV-Scanner: https://github.com/google/osv-scanner
- OWASP Benchmark: https://owasp.org/www-project-benchmark/

## License

MIT. See [LICENSE](LICENSE).
