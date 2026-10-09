# PathGuard benchmark protocol

## Research question

Does adding application-level source evidence to CVSS/EPSS signals improve prioritization of vulnerable npm package/version cases whose vulnerable functionality is independently assessed as reachable?

This is a question to test, not a claim that PathGuard already improves prioritization.

## Unit of analysis

A benchmark case is a unique tuple of repository URL, immutable repository commit, ecosystem, package name, installed version, and vulnerability/advisory identifier. Do not treat duplicate advisory records for the same package/version/vulnerability as independent cases. Record exact commit hashes and the dates of all external data retrievals.

## Case selection and leakage control

Define inclusion and exclusion rules before inspecting PathGuard's scores. Include public repositories with a reproducible lockfile and source code at the pinned commit. Sample across repository sizes and application types where feasible, and document exclusions such as missing lockfiles, generated-only source, unsupported module patterns, or unavailable advisory metadata. Avoid selecting cases solely because PathGuard detects a matching symbol. Record all candidate cases and reasons for exclusion to make selection bias auditable.

Freeze the repository commit, lockfile, PathGuard commit, and advisory references for every included case. Do not use PathGuard's own output as the ground truth. If a mapping is used to identify candidate cases, reviewers must independently verify the vulnerable function and application call path, and the selection process must disclose that enrichment.

## Labeling protocol

Use the labels in the CSV template:

- `reachable`: reviewers find evidence that application code can reach the vulnerable functionality under a documented call path and the advisory's relevant preconditions are plausible.
- `not_reachable`: reviewers have sufficient positive evidence that the vulnerable functionality cannot be reached in the evaluated application configuration. Absence of a simple import or grep match is not sufficient.
- `unknown`: evidence is insufficient, contradictory, or the advisory's vulnerable function/preconditions cannot be mapped confidently.

Reviewers should use advisory references, source code at the pinned commit, dependency resolution, call sites, and relevant configuration. Record a short rationale and source locations in `notes` or a linked annotation. Have two reviewers label cases independently where feasible; preserve disagreement rather than silently resolving it. The final `label` must not be derived from PathGuard's score or its own output. Preserve both reviewers' original labels and document adjudication.

## Methods to compare

1. **CVSS-only:** rank by CVSS base score. Missing scores are retained as missing in the scan report and receive zero only as the evaluator's explicit deterministic ordering fallback.
2. **EPSS-only:** rank by the EPSS probability associated with the case's CVE aliases. Missing scores use the same documented fallback.
3. **PathGuard v1:** rank by the versioned heuristic score in each report.
4. **External scanner ranking:** optionally pass a complete `case_id,score` CSV using `--external-ranking` and `--external-name`. Higher scores rank first. Every label row must be present; use score zero for cases the external tool did not flag. Document the score construction and do not present a manually constructed score as an intrinsic scanner score.
5. **Established scanner:** include OSV-Scanner or another established tool when its version, command, configuration, and output can be preserved. Run it on the same pinned repositories and package/version cases. Do not compare mismatched case sets without reporting the difference.

The current `pathguard-v1` heuristic has a maximum of 100 points: CVSS contributes up to 35 points, EPSS probability up to 35, and source evidence up to 30. A curated vulnerable-symbol match contributes 30, a general static call reference 18, import-only evidence 8, and no observed evidence 0. This is a transparent research heuristic, not a calibrated probability. The symbol mappings are provisional, manually curated hypotheses and require independent review before they can support ground-truth labels.

## Metrics

For each method, report:

- coverage: labeled cases matched to scanner output / all label rows;
- precision@k and recall@k, with `reachable` as the positive class;
- nDCG@k for ranking quality;
- deterministic bootstrap percentile 95% interval for nDCG@k when the sample and positive count justify it;
- runtime, API failure count, and skipped/unmatched cases.

The evaluator excludes `unknown` from ranking metrics and reports it separately. A labeled `reachable` or `not_reachable` case absent from the scan report receives score zero for PathGuard-derived methods and remains in the ranking denominator, reflecting end-to-end detection plus prioritization. Report matched coverage and unmatched case IDs separately. If there are no positive reachable cases, recall and nDCG are undefined and must not be reported as zero performance.

Predeclare the values of k and the primary metric. Report all methods on the same evaluable case set, alongside the end-to-end coverage result. Avoid interpreting overlapping uncertainty intervals as a formal significance test; use a paired comparison or appropriate statistical analysis if making inferential claims. Report negative and inconclusive results.

## Reproducibility

For multi-repository runs, pass one report JSON per repository commit to the evaluator with `--reports-dir`. Each report must include `input.repositoryUrl` and `input.repositoryCommit`, recorded by passing `--repo-url` and a full `--commit` SHA to the scanner. The evaluator joins on both values as well as package version and vulnerability identifiers to avoid accidental cross-repository matches.

For each run, preserve:

- PathGuard commit SHA and Node/npm versions;
- immutable source repository commit hashes;
- lockfiles and relevant package manifests;
- scan JSON outputs and all warnings;
- OSV retrieval timestamp and advisory IDs;
- EPSS scores and dates as returned by FIRST EPSS;
- label CSV version, reviewer decisions, and disagreement notes;
- baseline tool version and full invocation;
- evaluator arguments, output JSON, and the value of k.

Do not commit private application source or datasets without permission. Do not report synthetic CI fixtures as empirical results. Freeze inclusion criteria and the label procedure before inspecting ranking results. Report missing-data rates, API failures, and cases where PathGuard's score disagrees with reviewers.

## Current limitations

The source analyzer uses syntax-tree evidence for a limited set of static imports, simple CommonJS bindings, and direct call references. The prototype currently contains seven provisional mappings: four lodash mappings (CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, CVE-2019-10744) and three @fastify/busboy parser-entry mappings (CVE-2026-19484, CVE-2026-19481, CVE-2026-74866). The Busboy mappings are supported by advisory descriptions and a direct default-import invocation in Parse Server's multipart router at the pinned cohort commit, but do not prove the vulnerable branch or exploit preconditions. All mappings need independent review and are not ground truth. Neither a call-reference match nor the PathGuard v1 score proves runtime reachability or exploitability. A publication claiming improvement requires a sufficiently diverse, independently labeled benchmark and a fair baseline comparison.
