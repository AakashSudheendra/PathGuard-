# Initial public npm repository cohort

**Status:** collection seed only; not yet a labeled benchmark and not claimed to be representative.

The GitHub Actions workflow `.github/workflows/collect-benchmark.yml` scans each repository's root `package-lock.json` and a bounded source directory. Full immutable commit hashes are pinned in the workflow and passed into each PathGuard report. The workflow checks out each repository's named branch and verifies that its HEAD equals the pinned SHA before scanning; it fails closed if a branch has moved, rather than silently scanning a different revision. This is a convenience sample selected for npm lockfiles and inspectable JavaScript/TypeScript source; any paper must discuss selection bias and broaden it before making general claims.

| Repository | Pinned commit | Source directory | Lockfile |
|---|---|---|---|
| [axios/axios](https://github.com/axios/axios) | `1a94bdbdf0518f3adbeada510b747aff80847ed7` | `lib` | root `package-lock.json` |
| [nodejs/undici](https://github.com/nodejs/undici) | `e960331c83346ce770a7a58d7cfb6afb4aec0ccf` | `lib` | root `package-lock.json` |
| [npm/cli](https://github.com/npm/cli) | `b317f16c80df02ea3628cfa77170d5ae9b59720c` | `lib` | root `package-lock.json` |
| [markedjs/marked](https://github.com/markedjs/marked) | `eaa1fffb30fa334cc11ab93f1e5aaa1d2b916e7c` | `src` | root `package-lock.json` |
| [yargs/yargs](https://github.com/yargs/yargs) | `b2dbcc538062829bd720f8cbfb6b4765bae6b4b8` | `lib` | root `package-lock.json` |
| [node-red/node-red](https://github.com/node-red/node-red) | `935b8d3e12ec8be064f3a72ac6547131f778a7b1` | `packages` | root `package-lock.json` |
| [parse-community/parse-server](https://github.com/parse-community/parse-server) | `304c1a5d4e752958c7c9b41425fe1ee546111fc6` | `src` | root `package-lock.json` |

## Reproduce collection

Open the [Collect Public Benchmark Candidates workflow](https://github.com/AakashSudheendra/PathGuard-/actions/workflows/collect-benchmark.yml) and run **Run workflow**, or push a change to that workflow file. The workflow builds PathGuard, checks out each repository at its pinned commit, runs PathGuard and the checksum-verified OSV-Scanner v2.6.0 against the same lockfiles, merges cases discovered by either tool, and uploads raw scan reports, an unlabeled union candidate CSV, an OSV-Scanner CVSS baseline score CSV, two blinded reviewer packets, review instructions, and an experiment manifest as the `pathguard-public-benchmark-candidates` artifact.

The OSV-Scanner score CSV uses the maximum CVSS base score reported by OSV-Scanner for a matched advisory; cases not flagged receive score 0. This is a **detection-plus-severity baseline**, not an intrinsic priority score emitted by OSV-Scanner. Flagged cases without a parseable CVSS score also receive 0 and are identified in the CSV's `score_source` field. Report that limitation in any analysis.

The manifest records the collection time, PathGuard commit, Node/npm versions, OSV-Scanner version, pinned source commits, and the fact that labels remain unreviewed. Individual PathGuard reports record their generation time, source commit, and API warnings; EPSS dates are preserved where returned.

## Important interpretation limits

- This is a seed set, not a representative sample of npm applications.
- Candidate rows are generated from the union of scanner findings and are **unreviewed**. They are not ground truth.
- Labels must be assigned from the pinned source, advisory details, vulnerable function, relevant call paths, and configuration—not from PathGuard scores.
- Use two independent reviewers where feasible and retain disagreement notes.
- Cases discovered by either scanner remain in the union candidate set, including cases not found by PathGuard. This helps reduce but does not eliminate selection bias; vulnerabilities missed by both tools remain outside this candidate pool.
- A source-level import or call reference is not proof of runtime reachability or exploitability.
- Do not report precision/recall or ranking results as publication findings until the case set, labels, and baseline outputs are complete and independently checked.
