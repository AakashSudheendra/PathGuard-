# PathGuard — Review Brief

**Project title:** PathGuard: A Reachability-Aware and Evidence-Guided Framework for Prioritizing Third-Party Software Vulnerabilities  
**Review status:** working prototype + expanded data-collection pipeline completed; independent-label evaluation is pending.  
**Latest collection run:** [GitHub Actions run 37923613246](https://github.com/AakashSudheendra/PathGuard-/actions/runs/37923613246)  
**Reproducible collection report:** [EXPANDED_COHORT_COLLECTION.md](EXPANDED_COHORT_COLLECTION.md)  
**Analysis notebook:** [PathGuard_Benchmark_Analysis.ipynb](PathGuard_Benchmark_Analysis.ipynb)

## 1. Problem statement

Software composition analysis (SCA) tools identify dependency versions associated with known vulnerabilities. However, package-level presence and severity alone do not tell a developer whether an application's source appears to use a vulnerable API, how likely the CVE is to be exploited in the wild, or which finding should be reviewed first. PathGuard investigates whether combining severity, exploitation-likelihood, and conservative source-level evidence can support more useful triage.

## 2. What the prototype does

1. Reads npm package-lock files and inventories installed package/version pairs.
2. Queries OSV for package-version advisory matches and retains advisory identifiers and references.
3. Enriches CVE-linked advisories with FIRST EPSS scores when available.
4. Parses selected JavaScript/TypeScript source patterns to record static import, simple CommonJS require, and direct-call evidence.
5. Applies a versioned heuristic ranking called `pathguard-v1`.
6. Produces machine-readable JSON reports, source-evidence assessments, warning records, and benchmark candidate exports.
7. Runs a reproducible comparison collection against OSV-Scanner v2.6.0 on the same pinned repository lockfiles.
8. Generates blinded reviewer packets, an adjudication template, and a benchmark evaluator for use after labels are independently reviewed.

## 3. Ranking rule

`pathguard-v1` is a heuristic score on a 0–100 scale:

`Score = 3.5 × CVSS + 35 × EPSS + U`

- CVSS base score: 0–10; contribution up to 35.
- EPSS probability: 0–1; contribution up to 35.
- Source evidence contribution (U): curated vulnerable-symbol match = 30; general static call reference = 18; import-only = 8; no observed source evidence = 0.

The weights are hand-set and not trained or calibrated. The score is **not** a probability of exploitation. Static imports/calls and a curated symbol match are evidence hints, not proof of runtime reachability, exploitability, or satisfying all advisory preconditions.

## 4. Expanded collection: observed facts

| Item | Observed result |
|---|---:|
| Public repositories, each pinned to a full commit SHA | 9 |
| Dependency entries checked | 8,659 |
| Raw PathGuard advisory findings | 430 |
| Unique candidate cases after deduplication | 427 |
| PathGuard warnings in the nine scan reports | 0 |
| Cases found by PathGuard and OSV-Scanner in the union candidate set | 427 / 427 |
| Cases with parseable CVSS score | 334 / 427 (78.2%) |
| Cases without parseable CVSS score | 93 / 427 (21.8%) |
| Cases with EPSS score | 412 / 427 (96.5%) |
| Cases without EPSS score | 15 / 427 (3.5%) |
| Provisional vulnerable-symbol match | 3 |
| Mapped cases with no matching symbol evidence | 3 |
| Cases with no curated symbol mapping | 421 |
| Independently adjudicated labels currently present | 0 / 427 |

Repositories: Axios, Marked, NestJS, Node-RED, npm CLI, Parse Server, Socket.IO, Undici, and Yargs. The per-repository raw scan counts are documented in the expanded collection report.

### What these results do and do not mean

- They show the collection workflow runs on nine immutable repository snapshots and produced reproducible candidate artifacts.
- Both scanners found the same 427 candidate cases in this run. This does **not** show a detection advantage for PathGuard.
- The OSV-Scanner score export is a constructed detection-plus-CVSS baseline, not an intrinsic OSV-Scanner priority score. Flagged cases with missing CVSS receive a zero fallback, explicitly marked in the CSV.
- The candidate pool is the union of two scanners; issues missed by both are absent.
- The cohort is a convenience sample, not a representative sample of all npm applications.
- No precision, recall, nDCG, accuracy, or comparative improvement claim is available because no independent ground-truth labels have been assigned.

## 5. Suggested 60-second project explanation

“PathGuard is a research prototype for prioritizing third-party npm vulnerabilities using more than package severity alone. It combines OSV advisory matching, EPSS exploitation-likelihood signals, and conservative static source evidence in a versioned ranking heuristic. We built a reproducible collection pipeline that scans pinned repository snapshots with PathGuard and OSV-Scanner and generates blinded review packets. Our expanded collection covers nine repositories, 8,659 dependency entries, and 427 unique candidate cases. The current result is a validated data-collection pipeline—not yet a validated ranking improvement. The next experiment requires independent reviewers to label whether vulnerable functionality is reachable, followed by a predeclared comparison of CVSS-only, EPSS-only, PathGuard, and the documented scanner baseline.”

## 6. Likely review questions and defensible answers

**Q: What is novel about the project?**  
A: The research hypothesis is an evidence-guided prioritization workflow that combines CVSS, EPSS, and advisory-specific source hints while preserving unknown/not-proven states, plus a reproducible evaluation protocol. Novelty relative to prior work must be confirmed with a systematic literature review; it is not claimed solely from implementation.

**Q: Does the system prove a vulnerability is exploitable?**  
A: No. It records static source evidence and explicitly marks runtime reachability as not proven. Exploitability depends on call paths, inputs, configuration, and advisory-specific preconditions.

**Q: What is the current result?**  
A: Nine pinned repositories, 8,659 dependency entries, 430 raw findings, 427 unique cases, zero scan warnings, and 334/427 cases with parseable CVSS. Both scanners found the same candidate cases. Ranking metrics are not yet available because labels remain blank.

**Q: Why use EPSS?**  
A: CVSS describes severity, while EPSS estimates the probability that a CVE will be exploited in the wild over the next 30 days. They represent different dimensions; EPSS may be unavailable for advisories without a CVE.

**Q: Why is Google Colab involved?**  
A: Colab is the reproducible analysis environment for reading the exported benchmark ZIP, calculating descriptive coverage statistics, plotting distributions, and later calculating exploratory ranking metrics once reviewed labels exist. It does not replace the scanner or create labels. The notebook is in the repository.

**Q: Can you claim PathGuard is better than OSV-Scanner?**  
A: Not from current results. Both found the same cases in this candidate set, and the candidate pool is a union of both scanners. Independent labels and a fair, predeclared ranking comparison are still required.

**Q: What is the main limitation?**  
A: Source-evidence mapping is sparse, the sample is a convenience cohort, and independently reviewed reachability labels are not yet available. These limitations are documented rather than hidden.

## 7. Immediate post-review research steps

1. Have two reviewers independently label the blinded candidate packets using `reachable`, `not_reachable`, or `unknown`, recording source/advisory evidence.
2. Adjudicate disagreements and preserve notes.
3. Merge labels using `npm run merge:review-labels`.
4. Run the canonical evaluator for CVSS-only, EPSS-only, PathGuard v1, and the documented external baseline.
5. Report precision@k, recall@k, nDCG@k with bootstrap intervals where appropriate, coverage, unmatched cases, runtime, and error analysis.
6. Expand the cohort if feasible and revise the manuscript only with measured, reproducible results.

## 8. Files to show during the review

- [Paper draft](PAPER_DRAFT.md)
- [Expanded collection report](EXPANDED_COHORT_COLLECTION.md)
- [Public cohort and pinned commits](PUBLIC_BENCHMARK_COHORT.md)
- [Benchmark protocol](../docs/BENCHMARK_PROTOCOL.md)
- [Google Colab analysis notebook](PathGuard_Benchmark_Analysis.ipynb)
- [Publication checklist](PUBLICATION_CHECKLIST.md)
