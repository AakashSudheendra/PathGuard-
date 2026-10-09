# Evidence-Guided Prioritization of Vulnerable npm Dependencies: PathGuard Prototype and Evaluation Protocol

> **Manuscript status: draft / not ready for submission.** The implementation and evaluator exist, but the empirical benchmark, independent labels, full baseline runs, and measured results are not yet available. Replace every `[TO FILL]` item with results from a reproducible experiment. Do not submit with placeholders or claim an improvement without evidence.

## Abstract

Third-party dependency scanners can identify package versions associated with known advisories, but package-level presence alone does not establish whether an application's source uses a vulnerable function. This paper presents PathGuard, a research prototype that combines npm lockfile inventory, OSV advisory matching, FIRST EPSS enrichment, and syntax-tree evidence of source-level dependency usage. A versioned heuristic combines CVSS base severity, EPSS probability, and source evidence, while an explicit advisory-to-symbol mapping records whether a call reference matches a reviewed vulnerable-symbol hint. The implementation preserves unknown states and does not equate static references with runtime reachability or exploitability. We provide a reproducible benchmark protocol and evaluator for comparing CVSS-only, EPSS-only, and PathGuard rankings using precision@k, recall@k, nDCG@k, coverage, and bootstrap intervals. The central empirical question is whether source-level evidence improves prioritization on independently reviewed npm vulnerability cases. Evaluation on [TO FILL] cases yielded [TO FILL]. Until that evaluation is complete, PathGuard should be considered a prototype and experimental framework rather than a validated prioritization method.

**Keywords:** software supply-chain security, npm, dependency vulnerabilities, vulnerability prioritization, EPSS, static analysis, reachability, reproducibility.

## 1. Introduction

Modern JavaScript applications depend on large package ecosystems. A lockfile can identify exact installed package versions, and vulnerability databases can associate versions with public advisories. However, an installed vulnerable package does not necessarily imply that the vulnerable functionality is used by an application, and a source-level call reference does not itself establish runtime execution or exploitability.

Severity and exploitation likelihood represent different risk dimensions. CVSS characterizes vulnerability severity, while FIRST's Exploit Prediction Scoring System estimates the probability that a published CVE will be exploited in the wild in the next 30 days [1]. Research on npm dependency networks has also shown that dependency resolution and transitive propagation are important to understanding ecosystem risk [2]. These signals do not by themselves answer whether a particular application uses an advisory's vulnerable function.

PathGuard investigates a narrow, testable question: **does adding explicitly documented source-level evidence to conventional severity and exploitation-likelihood signals improve the ranking of npm dependency vulnerability cases under independent review?**

This work contributes:
1. An npm lockfile scanning pipeline that queries OSV and enriches CVE aliases with EPSS.
2. A source analyzer that records static import and direct call-reference evidence without claiming that it proves reachability.
3. A small curated advisory-to-symbol mechanism that makes symbol-specific evidence auditable.
4. A transparent, versioned ranking heuristic and a benchmark evaluator for CVSS-only, EPSS-only, and PathGuard rankings.
5. A labeling and reproducibility protocol designed to reduce leakage between system output and ground-truth decisions.

These are implementation contributions; empirical superiority is not claimed.

## 2. Research questions and hypotheses

- **RQ1:** How often does source-level evidence distinguish package presence from observed use of an advisory-mapped vulnerable symbol?
- **RQ2:** Does PathGuard v1 improve top-k ranking quality over CVSS-only and EPSS-only baselines on independently labeled cases?
- **RQ3:** What coverage and error modes arise from incomplete advisory-to-symbol mappings and limited syntax-tree analysis?

Pre-register the following hypotheses before the final benchmark is labeled or rankings are inspected:

- **H1:** PathGuard v1 achieves higher nDCG@k than CVSS-only and EPSS-only on the same evaluable cases.
- **H2:** PathGuard's symbol-specific evidence has non-zero coverage on the benchmark, with coverage reported explicitly.
- **H3:** The ranking benefit, if any, varies with mapping coverage and analyzer limitations.

H1 is a hypothesis, not a result.

## 3. System design

### 3.1 Dependency inventory and advisory matching

PathGuard reads npm package-lock formats v1, v2, and v3, deduplicates package/version pairs, and submits package names and versions to OSV. Advisory detail records are retrieved to collect identifiers and aliases. CVE aliases are used to query FIRST EPSS. API errors are recorded as warnings; an incomplete scan must not be interpreted as a clean scan.

### 3.2 Source-level evidence

The current analyzer uses the TypeScript compiler API to recognize selected static ECMAScript imports, simple CommonJS `require` bindings, and direct call references through those bindings. Evidence records include package, file, line, expression/symbol, and `reachabilityStatus: not-proven`.

This analysis is not a whole-program call graph. It does not comprehensively resolve aliases, dynamic imports, reflection, framework routing, or runtime configuration. It cannot prove that a call executes, that attacker-controlled input reaches it, or that exploit preconditions hold.

### 3.3 Advisory-to-symbol evidence

The prototype currently contains eight provisional advisory-to-symbol mappings: four lodash mappings for CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, and CVE-2019-10744 [5]–[8], three @fastify/busboy mappings for CVE-2026-19484, CVE-2026-19481, and CVE-2026-74866 [9]–[11], and one @graphql-tools/utils mapping for CVE-2026-104852 [13]. Each mapping includes an advisory reference and rationale. The Busboy mappings treat the default-import parser invocation in Parse Server's multipart router at a pinned commit as an entry-point hint [12]; advisory-specific vulnerable branches and downstream conditions are not proven. A match means that a detected call reference matches a provisional symbol hint, not that runtime reachability or exploitability is established. These mappings require independent review before being used as benchmark ground truth.

#### Illustrative code/advisory alignment (not a benchmark label)

At the pinned Parse Server commit, the lockfile resolves `@fastify/busboy` to version 3.2.0. Its `FunctionsRouter.js` multipart middleware checks for `multipart/form-data` and passes `req.headers` to the default-imported `Busboy` parser at line 220 [12]. The CVE-2026-19484 advisory describes an event-loop denial of service caused by a crafted multipart boundary in affected versions before 3.2.1 [9]. This is a concrete reason to map the parser entry point to the advisory, rather than treating package presence alone as usage. It is still not proof that a deployed instance is exposed, that the vulnerable branch executes for a given request, or that every exploit precondition holds. The case remains subject to independent benchmark review.


### 3.4 PathGuard v1 score

The prototype computes a transparent heuristic with a maximum of 100 points:

\[
S_{PG}=3.5C+35E+U
\]

where:
- \(C\) is the CVSS base score on the 0–10 scale (contribution up to 35);
- \(E\) is EPSS probability on the 0–1 scale (contribution up to 35);
- \(U\) is source evidence: 30 for a curated vulnerable-symbol match, 18 for a general static call reference, 8 for import-only evidence, or 0 when no source evidence is observed.

The formula is versioned as `pathguard-v1`. Missing CVSS or EPSS values remain null in the scan report; the current evaluator uses zero only as a documented deterministic ordering fallback for baseline comparison. The score is a heuristic, not a probability, and its weights have not been learned or empirically calibrated. Because source evidence is coarse, an observed symbol match must not be described as proof of exploitation risk.

## 4. Evaluation methodology

### 4.1 Case selection

The initial reproducible seed cohort comprises seven public npm repositories with pinned commits: Axios, Undici, npm CLI, Marked, Yargs, Node-RED, and Parse Server. It is a convenience sample selected for root npm lockfiles and inspectable source directories, not a representative sample of npm applications. The collection workflow runs PathGuard and OSV-Scanner v2.6.0 against the same pinned lockfiles and forms a union of detected cases. Broaden the cohort and disclose selection bias before making general claims. Select public repositories and vulnerable package/version cases using inclusion criteria fixed before looking at PathGuard rankings. Pin every repository to an immutable commit. Avoid selecting cases solely because the prototype already detects them. Deduplicate cases by repository commit, ecosystem, package/version, and advisory identifier.

### 4.2 Independent labels

Two reviewers should independently assign:
- `reachable`: documented source path and relevant conditions support reachability of the vulnerable functionality;
- `not_reachable`: sufficient positive evidence supports non-reachability in the evaluated configuration;
- `unknown`: evidence is insufficient or contradictory.

A missing import, a failed text search, or a missing curated mapping is not sufficient to assign `not_reachable`. Reviewers must not derive labels from PathGuard's score. Preserve disagreements and record evidence, source locations, and resolution rationale.

### 4.3 Baselines

Compare CVSS-only, EPSS-only, and PathGuard v1 on the same case set. Add OSV-Scanner or another established scanner where versions, invocation, configuration, and outputs can be preserved. Report mismatched or unsupported cases rather than silently dropping them.

### 4.4 Metrics and statistical reporting

Report coverage, precision@k, recall@k, nDCG@k, runtime, API failures, and unmatched cases. Report deterministic bootstrap percentile intervals for nDCG@k where sample size permits. The evaluator excludes `unknown` from primary ranking metrics and reports unknown cases separately. A labeled reachable/not-reachable case missing from the scan output receives score zero for all ranking methods and remains in the denominator, so metrics include retrieval misses as well as ordering quality. Report matched coverage, unmatched case IDs, the value of k, and the exact evaluable denominator. If the sample is too small to support stable inference, describe the results as exploratory.

### 4.5 Results

**Do not fill this table with synthetic CI data.** Run the evaluation on independently labeled cases and preserve the JSON outputs.

| Method | Cases evaluated | Coverage | Precision@k | Recall@k | nDCG@k (95% bootstrap CI) |
|---|---:|---:|---:|---:|---:|
| CVSS-only | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] |
| EPSS-only | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] |
| PathGuard v1 | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] |
| Established scanner (if included) | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] | [TO FILL] |

### 4.6 Error analysis

Manually inspect cases where:
- PathGuard ranks a `not_reachable` case above a `reachable` case;
- CVSS-only or EPSS-only outperforms PathGuard;
- advisory-to-symbol mappings are absent or incorrect;
- source analysis misses an import/call due to aliasing or dynamic loading;
- OSV or EPSS data is missing, stale, or inconsistent;
- duplicate advisories or CVE aliases change the ranking.

## 5. Threats to validity

**Construct validity:** Source call-reference evidence is only a proxy for application use. The labels and the prototype's symbol mappings may not capture all advisory-specific preconditions.

**Internal validity:** Fixed score weights are heuristic and may bias ranking. Reviewer decisions can be subjective. Duplicate advisory records and missing data can distort comparisons.

**External validity:** The prototype supports npm lockfiles and a limited JavaScript/TypeScript syntax subset. Findings may not generalize to other ecosystems, languages, frameworks, or dynamic execution patterns.

**Reproducibility:** OSV advisory records and EPSS scores change over time. Record retrieval dates, pinned source commits, tool versions, raw reports, warnings, and label versions.

**Baseline validity:** Baselines must use the same cases and information cutoff. An established scanner may implement call analysis for some ecosystems but not necessarily the same JavaScript/TypeScript semantics; describe configuration and capability differences.

## 6. Conclusion

PathGuard is an inspectable prototype for combining dependency vulnerability data with limited, advisory-specific source evidence. Its current implementation establishes a runnable pipeline and a reproducible evaluation scaffold, but not a demonstrated improvement in vulnerability prioritization. The principal next step is an independently labeled benchmark with broader reviewed mappings, fair baselines, and transparent error analysis. Any conclusion about effectiveness must follow those measurements.

## References

[1] J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid, and M. Roytman, “Exploit Prediction Scoring System (EPSS),” *Digital Threats: Research and Practice*, vol. 2, no. 3, 2021. doi: [10.1145/3436242](https://doi.org/10.1145/3436242).

[2] C. Liu, S. Chen, L. Fan, B. Chen, Y. Liu, and X. Peng, “Demystifying the Vulnerability Propagation and Its Evolution via Dependency Trees in the NPM Ecosystem,” arXiv:2201.03981, 2022. [https://arxiv.org/abs/2201.03981](https://arxiv.org/abs/2201.03981).

[3] Google, “OSV-Scanner: Usage and Source Scanning,” official documentation. [https://google.github.io/osv-scanner/usage/](https://google.github.io/osv-scanner/usage/).

[4] FIRST, “Exploit Prediction Scoring System (EPSS),” official documentation and API resources. [https://www.first.org/epss/](https://www.first.org/epss/).

[5] National Vulnerability Database, “CVE-2021-23337 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337).

[6] National Vulnerability Database, “CVE-2020-8203 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203).

[7] National Vulnerability Database, “CVE-2020-28500 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2020-28500](https://nvd.nist.gov/vuln/detail/CVE-2020-28500).

[8] National Vulnerability Database, “CVE-2019-10744 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2019-10744](https://nvd.nist.gov/vuln/detail/CVE-2019-10744).

[9] National Vulnerability Database, “CVE-2026-19484 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2026-19484](https://nvd.nist.gov/vuln/detail/CVE-2026-19484).

[10] National Vulnerability Database, “CVE-2026-19481 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2026-19481](https://nvd.nist.gov/vuln/detail/CVE-2026-19481).

[11] National Vulnerability Database, “CVE-2026-74866 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2026-74866](https://nvd.nist.gov/vuln/detail/CVE-2026-74866).

[12] Parse Server, `src/Routers/FunctionsRouter.js`, pinned commit `304c1a5d4e752958c7c9b41425fe1ee546111fc6`, line 220. [Source at pinned commit](https://github.com/parse-community/parse-server/blob/304c1a5d4e752958c7c9b41425fe1ee546111fc6/src/Routers/FunctionsRouter.js#L220).

[13] National Vulnerability Database, “CVE-2026-104852 Detail.” [https://nvd.nist.gov/vuln/detail/CVE-2026-104852](https://nvd.nist.gov/vuln/detail/CVE-2026-104852).

## Artifact availability

Source code, tests, benchmark evaluator, and protocol: [PathGuard repository](https://github.com/AakashSudheendra/PathGuard-). The repository should be tagged with a release commit after the benchmark implementation and all tests pass. Preserve a release archive and exact evaluation inputs before submission.
