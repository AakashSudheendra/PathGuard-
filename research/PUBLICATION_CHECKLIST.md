# Publication readiness checklist

This checklist distinguishes software completion from evidence needed to support a research claim. Statuses must be updated from actual artifacts, not intentions.

## Software and artifact

- [x] npm lockfile inventory for lockfile v1/v2/v3 with unit tests.
- [x] OSV advisory matching and CVE alias extraction.
- [x] FIRST EPSS enrichment with missing-score handling.
- [x] Static import/call-reference evidence with explicit `not-proven` status.
- [x] Curated advisory-to-symbol assessment with reference and rationale.
- [x] Versioned, explainable `pathguard-v1` ranking factors.
- [x] Benchmark evaluator for CVSS-only, EPSS-only, PathGuard, and optional external scores.
- [x] Label validation for unique IDs, identifiers, allowed labels, and reviewer disagreement notes.
- [x] Deterministic unlabeled candidate-manifest generator that merges PathGuard and OSV-Scanner discoveries.
- [x] Blinded independent-review packet generator that omits system scores and source-analysis outputs.
- [x] Reviewer/adjudication merge tool with distinct-reviewer, complete-case, and disagreement-note validation.
- [x] Pinned nine-repository collection workflow with checksum-verified OSV-Scanner baseline and reproducibility manifest; expanded scan must complete and be checked.
- [x] CI build, unit tests, evaluator/candidate/review-packet/label-merge smoke tests.
- [x] Research protocol and manuscript draft with explicit placeholders.

## Empirical work required before submission

- [ ] Define and freeze case-selection criteria before examining final rankings.
- [ ] Expand the original seven-repository convenience seed to nine pinned repositories (Socket.IO and NestJS added); assess whether this is sufficiently large and diverse, continue cohort expansion if needed, and document selection bias.
- [ ] Generate candidate cases from real scans and manually verify the package/advisory/function mapping.
- [ ] Expand advisory-to-symbol mappings using cited sources and independent review.
- [ ] Complete both blinded reviewer CSVs and adjudication template; independently label cases as `reachable`, `not_reachable`, or `unknown`, preserving raw decisions and adjudication rationale.
- [x] Collect initial seed-cohort PathGuard reports with pinned repository commits and API warning records.
- [ ] Run PathGuard on the final expanded, frozen, independently labeled cohort and archive reports, warnings, retrieval dates, tool commit, Node/npm versions, and EPSS dates.
- [ ] Run CVSS-only and EPSS-only baselines on the same cases.
- [x] Run OSV-Scanner v2.6.0 on the initial seed cohort and preserve raw JSON outputs plus a documented CVSS-based score export.
- [ ] Re-run the established scanner baseline on the final independently labeled cohort with pinned version/configuration and documented case matching.
- [ ] Create complete external ranking score CSVs with explicit zero scores for cases not flagged by the external tool.
- [ ] Evaluate using predeclared k values and metrics; report coverage, precision@k, recall@k, nDCG@k, uncertainty intervals where justified, runtime, and API failures.
- [ ] Conduct error analysis, including cases where PathGuard ranks a non-reachable case above a reachable case.
- [ ] Replace every `[TO FILL]` manuscript placeholder with measured results or remove unsupported claims.
- [ ] Audit references, license constraints, dataset permissions, and artifact availability.
- [ ] Tag the exact evaluated Git commit and archive the inputs and outputs used in the paper.
- [ ] Have the manuscript reviewed by a supervisor/co-author before submission.

## Stop conditions

Do not claim improved prioritization if the results do not support it. Do not call the project publication-ready while empirical checkboxes remain unchecked. A negative or inconclusive result can still support a useful paper if the protocol is rigorous, the sample is appropriate, and limitations are reported honestly.
