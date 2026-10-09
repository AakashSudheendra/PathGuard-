# Research limitations and claims policy

PathGuard is a research prototype. Initial results from a fixture demonstrate execution of the scanner pipeline, not a generalized improvement in vulnerability prioritization.

Do not claim:
- that a vulnerability is exploitable merely because a package is installed;
- that it is unreachable merely because no static import was found;
- that import/call references prove runtime reachability;
- that PathGuard outperforms an established tool without a predeclared benchmark and fair baseline comparison;
- that a benchmark is independent if labels were assigned using PathGuard's own score.

Any published evaluation should specify inclusion criteria, ground-truth procedure, API snapshots or retrieval dates, comparison methods, repeated runs where appropriate, limitations, and error analysis.

## Advisory-to-symbol matching

PathGuard now has a small manually curated advisory-to-symbol mapping and reports whether source-level call evidence matches it. This is a triage hint, not a general vulnerability-function database. The mapping must include a reference and rationale, and should be reviewed before use in research. `vulnerable-symbol-observed` means a syntax-tree call reference matches the curated symbol; it does not prove runtime reachability, attacker-controlled input, or exploitability. `no-matching-symbol-evidence` is not proof of non-reachability. `no-curated-symbol-mapping` must be treated as unknown.
