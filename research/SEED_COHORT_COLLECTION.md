# Initial seed-cohort collection report

**Collection date:** 2026-10-09  
**Status:** candidate discovery only; not an empirical ranking evaluation and not publication-ready ground truth.

## Reproducibility

- PathGuard commit: `0598e26c81aecba8c3e776c33e7ed73b89e6e983`
- Node.js: `v22.23.3`
- npm: `10.9.9`
- OSV-Scanner: `v2.6.0`, downloaded from its release and checksum-verified
- Source repositories: seven pinned commits documented in [PUBLIC_BENCHMARK_COHORT.md](PUBLIC_BENCHMARK_COHORT.md)
- GitHub Actions run and artifacts: [run 37917518663](https://github.com/AakashSudheendra/PathGuard-/actions/runs/37917518663)
- Artifact contents: PathGuard JSON reports, OSV-Scanner JSON reports and logs, union candidate CSV, OSV-Scanner CVSS score CSV, blinded reviewer CSVs, adjudication template, and experiment manifest.

## Scan inventory

| Repository | Dependency entries checked | PathGuard advisory findings | PathGuard warnings |
|---|---:|---:|---:|
| Axios | 670 | 4 | 0 |
| Marked | 626 | 17 | 0 |
| Node-RED | 941 | 22 | 0 |
| npm CLI | 999 | 70 | 0 |
| Parse Server | 1,552 | 64 | 0 |
| Undici | 695 | 3 | 0 |
| Yargs | 492 | 29 | 0 |
| **Total** | **5,975** | **209** | **0** |

The evaluator's union candidate manifest contains **208 unique package/version/advisory cases** after identifier-based deduplication. The sum of per-report advisory findings is larger because one advisory can have multiple identifiers/aliases and duplicate records are collapsed into a single case.

## Baseline and source-evidence observations

- PathGuard and OSV-Scanner each flagged all 208 candidate cases in this seed cohort; neither produced exclusive candidate cases in this run.
- OSV-Scanner supplied a parseable CVSS base score for 162 cases. For the other 46 cases, the baseline records a score of zero and marks the fallback explicitly.
- Three cases have `vulnerable-symbol-observed` status under the provisional advisory-to-symbol mappings; two mapped cases have `no-matching-symbol-evidence`; the remaining 203 cases have no curated symbol mapping.
- All 208 adjudicated-label fields are blank. Both blinded reviewer packets and the adjudication template contain 208 case rows.

These are descriptive collection and coverage statistics only. They are **not** precision, recall, nDCG, accuracy, or evidence of a PathGuard improvement.

## Interpretation and next steps

This seven-repository cohort is a convenience seed, not a representative sample. Because both scanners found the same cases, it does not demonstrate a retrieval advantage for either tool. The OSV-Scanner score file is a constructed detection-plus-CVSS baseline, not a native OSV-Scanner priority score. The sparse vulnerable-symbol mapping coverage also shows that the source-evidence component needs broader, independently reviewed advisory mappings.

Before making research claims, broaden and freeze the cohort, have two independent reviewers complete the blinded packets, adjudicate disagreements, merge the labels using `npm run merge:review-labels`, and evaluate the labeled cases with predeclared metrics and error analysis. Do not fill manuscript result placeholders using these unlabelled scan counts.
