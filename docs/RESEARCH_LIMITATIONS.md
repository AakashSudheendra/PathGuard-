# Research limitations and claims policy

PathGuard is a research prototype. Initial results from a fixture demonstrate execution of the scanner pipeline, not a generalized improvement in vulnerability prioritization.

Do not claim:
- that a vulnerability is exploitable merely because a package is installed;
- that it is unreachable merely because no static import was found;
- that import/call references prove runtime reachability;
- that PathGuard outperforms an established tool without a predeclared benchmark and fair baseline comparison;
- that a benchmark is independent if labels were assigned using PathGuard's own score.

Any published evaluation should specify inclusion criteria, ground-truth procedure, API snapshots or retrieval dates, comparison methods, repeated runs where appropriate, limitations, and error analysis.
