# Research workspace

This folder contains the benchmark evaluator, candidate generator, label template, experimental protocol, and manuscript artifacts.

## Required evaluation before research claims

1. Select repositories and vulnerable package/version cases before inspecting PathGuard ranking.
2. Record OSV advisory IDs, CVE identifiers, package/version, source repository commit, scanner version, API retrieval date, and EPSS publication date.
3. Obtain labels from documented evidence. Use `reachable`, `not_reachable`, and `unknown`; use two reviewers independently where feasible and report disagreement.
4. Do not label a finding not-reachable merely because a simple text search found no import.
5. Compare CVSS-only, EPSS-only, an established scanner such as OSV-Scanner, and PathGuard under the same case set.
6. Report precision@k, recall@k, nDCG@k, coverage, runtime, failed queries, and uncertainty estimates where the sample size supports them.
7. Keep raw third-party datasets out of Git where licensing or size makes that inappropriate; document download and version steps.

## Initial public cohort

[PUBLIC_BENCHMARK_COHORT.md](PUBLIC_BENCHMARK_COHORT.md) documents the initial five-repository seed cohort and the workflow that scans each repository at a pinned commit. This is a convenience sample, not a representative benchmark. The workflow uploads scan reports and an unlabeled candidate CSV as an artifact; candidates require independent review and are not ground truth.

## Evaluator

`evaluate-benchmark.ts` accepts one report or a directory of reports and joins cases by repository URL, immutable commit SHA, package/version, and vulnerability identifiers. It reports label coverage, precision@k, recall@k, nDCG@k, and a deterministic bootstrap percentile interval for nDCG@k. It supports CVSS-only, EPSS-only, PathGuard v1, and an optional external ranking CSV. The external CSV must include every label case, including explicit score-zero rows for cases not flagged by the external tool.

`build-candidate-manifest.ts` creates stable case IDs from real schema 1.1 scan reports, deduplicates findings, and leaves all labels blank. It refuses reports without repository URL and a full immutable commit SHA.

The synthetic fixtures in `research/fixtures` are used only to smoke-test the tooling in CI. They are not empirical data and must never be cited as a result.

## Advisory-specific source evidence

The current prototype contains seven provisional mappings: four lodash mappings for CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, and CVE-2019-10744, plus three @fastify/busboy parser-entry mappings for CVE-2026-19484, CVE-2026-19481, and CVE-2026-74866. Each has an NVD reference and rationale. The Busboy mappings are supported by advisory descriptions and a direct parser invocation in Parse Server's multipart router, but do not prove vulnerable-branch execution or exploit preconditions. Unlisted advisories remain unknown; matching a call reference is not proof of runtime reachability or exploitability. All mappings need independent review before benchmark labels rely on them.

## Label template and reviewer procedure

`benchmark-label-template.csv` includes repository URL and commit SHA, package/version, advisory identifiers, reviewer 1 and reviewer 2 labels, final adjudicated label, and disagreement notes. Keep the raw reviewer labels rather than overwriting them with the final adjudication. Any disagreement should have a documented rationale.

## Publication status

The software pipeline and synthetic CI smoke test are implemented. The empirical work is not complete: real pinned repositories, independently reviewed labels, complete baseline outputs, measured results, and error analysis are still required. See [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md) and [PAPER_DRAFT.md](PAPER_DRAFT.md).
