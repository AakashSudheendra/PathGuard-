# Expanded nine-repository cohort collection report

**Collection date:** 2026-10-09  
**Status:** successful candidate discovery and baseline collection; labels remain unreviewed; not an empirical ranking evaluation or publication-ready ground truth.

## Reproducibility

- PathGuard commit: `4cdcd0aa9fbb2c3c2a20a9f61b3485fd6f43a0ea`
- GitHub Actions collection run: [37923613246](https://github.com/AakashSudheendra/PathGuard-/actions/runs/37923613246)
- Artifact: `pathguard-public-benchmark-candidates` (run artifact ID 11612424880)
- Node.js: `v22.23.3`
- npm: `10.9.9`
- OSV-Scanner: `v2.6.0`, downloaded from its release and checksum-verified
- All nine repository HEADs were verified against immutable commit SHAs before scanning.
- The artifact contains nine PathGuard JSON reports, OSV-Scanner raw reports/logs, the union candidate CSV, the OSV-Scanner CVSS score CSV, two blinded reviewer packets, an adjudication template, instructions, and the experiment manifest.

## Scan inventory

| Repository | Dependency entries checked | PathGuard advisory findings | Warnings |
|---|---:|---:|---:|
| Axios | 670 | 4 | 0 |
| Marked | 626 | 17 | 0 |
| NestJS | 1,479 | 81 | 0 |
| Node-RED | 941 | 22 | 0 |
| npm CLI | 999 | 70 | 0 |
| Parse Server | 1,552 | 64 | 0 |
| Socket.IO | 1,205 | 140 | 0 |
| Undici | 695 | 3 | 0 |
| Yargs | 492 | 29 | 0 |
| **Total** | **8,659** | **430** | **0** |

The union candidate manifest contains **427 unique cases** after deduplication. The raw finding count (430) is higher than the unique case count because findings can overlap across identifiers/aliases. The cases cover nine pinned repositories and are keyed to repository URL, immutable commit SHA, package, installed version, and advisory identifiers.

## Baseline and source-evidence observations

- All **427 candidate cases** were discovered by both PathGuard and OSV-Scanner in this cohort; neither tool contributed exclusive cases. This run therefore does not demonstrate a detection-recall advantage for either tool.
- OSV-Scanner supplied a parseable CVSS severity score for **334 cases**. For the other **93**, the exported baseline uses score 0 and explicitly marks the missing-CVSS fallback. This is a constructed detection-plus-CVSS baseline, not a native OSV-Scanner priority score.
- The union candidate CSV has **427 rows**. Both blinded reviewer packets contain 427 rows, and all adjudicated-label fields remain blank.
- The provisional curated mapping inventory yields **3** `vulnerable-symbol-observed` cases, **3** `no-matching-symbol-evidence` cases, and **421** `no-curated-symbol-mapping` cases. These are source-assessment statuses, not adjudicated reachability labels.
- The source analysis records static imports and call references, but it does not prove runtime reachability or exploitability. Mapping coverage remains sparse.

## Interpretation and limitations

This expanded nine-repository cohort is still a convenience sample, not a representative sample of the npm ecosystem. The candidates are unreviewed and are not ground truth. Because the candidate set is the union of two scanners, vulnerabilities missed by both tools remain outside the candidate pool. Repository diversity and dependency counts do not remove selection bias.

Do **not** report precision, recall, nDCG, accuracy, or an improvement claim from these collection counts. Before submission, broaden or justify the frozen cohort, obtain two independent blinded labels per case where feasible, adjudicate disagreements with notes, merge labels using `npm run merge:review-labels`, and run the predeclared evaluator against PathGuard and baseline rankings. Include confidence intervals, error analysis, mapping coverage, and limitations in the final manuscript.
