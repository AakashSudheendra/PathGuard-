# Architecture

## Current data flow

1. Parse npm package-lock v1/v2/v3 into unique name/version pairs.
2. Submit package/version pairs to the OSV batch query API.
3. Fetch OSV advisory details and resolve CVE aliases.
4. Query FIRST EPSS for each discovered CVE.
5. Match source call references against manually curated advisory-to-symbol knowledge.
6. Compute a versioned, explainable priority score from CVSS (35 points maximum), EPSS probability (35 points maximum), and source evidence (up to 30 points).
7. Write a JSON report with summary, finding records, timestamps, evidence assessments, ranking contributions, and source metadata.

## Reliability rules

- A network failure should be visible and should not be represented as a clean scan.
- A missing EPSS score is unknown, not zero in the report. The baseline ranking evaluator uses zero only as a deterministic ordering fallback and documents this choice.
- The PathGuard v1 score is a heuristic, not a calibrated probability or empirically validated model.
- A package/advisory result is distinct from a unique CVE and from a package-version/CVE pair.
- Duplicate package versions should be deduplicated at parsing time.
- Source-level imports or symbol references are preliminary evidence only. The current milestone does not prove dynamic runtime reachability.

## Planned components

- SourceEvidence analyzer using the TypeScript compiler API.
- A scoring module with documented, configurable factors and missing-data behavior.
- Dashboard consuming stable report JSON.
- Experimental harness for baselines, labels, and confidence intervals.
