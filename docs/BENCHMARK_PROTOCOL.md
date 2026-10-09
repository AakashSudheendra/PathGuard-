# PathGuard benchmark protocol

## Research question

Does adding application-level source evidence to CVSS/EPSS signals improve prioritization of vulnerable npm package/version cases whose vulnerable functionality is independently assessed as reachable?

This is a question to test, not a claim that PathGuard already improves prioritization.

## Unit of analysis

A benchmark case is a unique tuple of repository URL, immutable repository commit, ecosystem, package name, installed version, and vulnerability/advisory identifier. Do not treat duplicate advisory records for the same package/version/vulnerability as independent cases. Record exact commit hashes and the dates of all external data retrievals.

## Labeling protocol

Use the labels in the CSV template:

- `reachable`: reviewers find evidence that application code can reach the vulnerable functionality under a documented call path and the advisory's relevant preconditions are plausible.
- `not_reachable`: reviewers have sufficient positive evidence that the vulnerable functionality cannot be reached in the evaluated application configuration. Absence of a simple import or grep match is not sufficient.
- `unknown`: evidence is insufficient, contradictory, or the advisory's vulnerable function/preconditions cannot be mapped confidently.

Reviewers should use advisory references, source code at the pinned commit, dependency resolution, call sites, and relevant configuration. Record a short rationale and source locations in `notes` or a linked annotation. Have two reviewers label cases independently where feasible; preserve disagreement rather than silently resolving it. The label must not be derived from PathGuard's score or its own output.

## Methods to compare

1. **CVSS-only**: rank by CVSS base score. Missing scores are retained as missing in the scan report and receive zero only as the evaluator's explicit deterministic ordering fallback.
2. **EPSS-only**: rank by the maximum EPSS probability among CVE aliases for the package/advisory case. Missing scores use the same documented fallback.
3. **PathGuard v1**: rank by the versioned heuristic score in each report.
4. **External scanner score**: optionally pass a complete `case_id,score` CSV using `--external-ranking` and `--external-name`. Higher scores rank first. Every label row must be present; use score zero for cases the external tool did not flag. This enables a common-case comparison, but the external score construction must be documented and must not be presented as an intrinsic scanner score if it was manually assigned. The current score has a maximum of 100: CVSS contributes up to 35 points, EPSS probability up to 35, and source evidence up to 30. A curated vulnerable-symbol match contributes 30, a general static call reference 18, and import-only evidence 8. This is a research heuristic, not a calibrated probability.
5. **Optional established scanner**: include OSV-Scanner or another tool when its version, command, configuration, and output can be preserved. Run it on the same pinned repositories and package/version cases. Do not compare on mismatched case sets without reporting the difference.

## Metrics

For each method, report:

- coverage: labeled cases that can be matched to scanner output / all label rows;
- precision@k and recall@k, with `reachable` as the positive class;
- nDCG@k for ranking quality;
- deterministic bootstrap percentile 95% interval for nDCG@k where enough labeled cases and positive cases exist;
- runtime, API failure count, and any skipped or unmatched cases.

The evaluator excludes `unknown` from ranking metrics and reports it separately. A labeled `reachable` or `not_reachable` case absent from the scan report receives score zero for all methods and remains in the ranking denominator; this makes ranking metrics reflect end-to-end detection plus prioritization. Report matched coverage and unmatched case IDs separately. If there are no positive reachable cases, recall and nDCG are undefined and must not be reported as zero performance.

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

Do not commit private application source or datasets without permission. Do not report synthetic CI fixtures as empirical results. Freeze the inclusion criteria and label procedure before inspecting ranking results. Report negative findings, missing-data rates, API failures, and cases where PathGuard's score disagrees with reviewers.

## Current limitations

The current source analyzer uses syntax-tree evidence for a limited set of static imports, simple CommonJS bindings, and direct call references. The curated advisory-to-symbol corpus currently contains one lodash mapping. Neither call-reference detection nor the PathGuard v1 score proves runtime reachability or exploitability. A publication claiming improvement requires a substantially broader, independently labeled benchmark and a fair baseline comparison.
