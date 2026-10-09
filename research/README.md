# Research workspace

This folder is the home for benchmark protocols, dataset documentation, and reproducible experiments.

## Required evaluation before research claims

1. Select repositories and vulnerable package/version cases before inspecting PathGuard ranking.
2. Record OSV advisory IDs, CVE identifiers, package/version, source repository commit, scanner version, API retrieval date, and EPSS publication date.
3. Obtain labels from documented evidence. Use at least `reachable`, `not_reachable`, and `unknown`; use two reviewers when feasible and report disagreement.
4. Do not label a finding not-reachable merely because a simple text search found no import.
5. Compare CVSS-only, EPSS-only, OSV-Scanner or another established baseline, and PathGuard under the same case set.
6. Report precision@k, recall@k, nDCG@k, coverage, runtime, failed queries, and confidence intervals where sample size supports them.
7. Keep raw third-party datasets out of Git where licensing or size makes that inappropriate; document download and version steps.

Current source-level import/call evidence is preliminary. A syntax-tree match is not call-graph reachability, and neither establishes execution of a vulnerable path condition.

## Advisory-specific source evidence

PathGuard uses an explicitly curated mapping from a CVE and package to a vulnerable symbol when such a mapping has been reviewed. The current prototype includes one lodash mapping for CVE-2021-23337, with the NVD advisory as its reference. This is intentionally narrow: unlisted advisories remain unknown, and matching a call reference is not proof of runtime reachability or exploitability. Expand this mapping only with documented, independently reviewed evidence.
