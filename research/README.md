# Research workspace

This folder contains the benchmark evaluator, label template, experimental protocol, and manuscript artifacts.

## Required evaluation before research claims

1. Select repositories and vulnerable package/version cases before inspecting PathGuard ranking.
2. Record OSV advisory IDs, CVE identifiers, package/version, source repository commit, scanner version, API retrieval date, and EPSS publication date.
3. Obtain labels from documented evidence. Use `reachable`, `not_reachable`, and `unknown`; use two reviewers independently where feasible and report disagreement.
4. Do not label a finding not-reachable merely because a simple text search found no import.
5. Compare CVSS-only, EPSS-only, an established scanner such as OSV-Scanner, and PathGuard under the same case set.
6. Report precision@k, recall@k, nDCG@k, coverage, runtime, failed queries, and uncertainty estimates where the sample size supports them.
7. Keep raw third-party datasets out of Git where licensing or size makes that inappropriate; document download and version steps.

## Evaluator

`evaluate-benchmark.ts` accepts one report or a directory of reports and joins cases by repository URL, immutable commit SHA, package/version, and vulnerability identifiers. It reports label coverage, precision@k, recall@k, nDCG@k, and a deterministic bootstrap percentile interval for nDCG@k. It supports CVSS-only, EPSS-only, PathGuard v1, and an optional external ranking CSV. The external CSV must include every label case, including explicit score-zero rows for cases not flagged by the external tool.

The synthetic fixtures in `research/fixtures` are used only to smoke-test the evaluator in CI. They are not empirical data and must never be cited as a result.

## Advisory-specific source evidence

The current prototype includes four provisional, manually curated lodash mappings for CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, and CVE-2019-10744, each linked to an NVD reference. This is intentionally narrow: unlisted advisories remain unknown, and matching a call reference is not proof of runtime reachability or exploitability. Expand this mapping only with a cited reference, rationale, and independent review record.

## Label template and reviewer procedure

`benchmark-label-template.csv` includes repository URL and commit SHA, package/version, advisory identifiers, reviewer 1 and reviewer 2 labels, final adjudicated label, and disagreement notes. Keep the raw reviewer labels rather than overwriting them with the final adjudication. Any disagreement should have a documented rationale.

## Publication status

The software pipeline and synthetic CI smoke test are implemented. The empirical work is not complete: real pinned repositories, independently reviewed labels, complete baseline outputs, measured results, and error analysis are still required. See [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md) and [PAPER_DRAFT.md](PAPER_DRAFT.md).
