# PyDepGraph: research design and reviewer notes

Working title: An Automated Framework for Organization-Wide Python Dependency Intelligence
and Software Supply-Chain Risk Analysis.

## Problem

Organizations collect heterogeneous manifests but need traceable answers about which
repositories and teams reference which Python distributions and versions. A declaration,
locked record, and installed observation have different evidentiary strength. Conflating
them can overstate vulnerability exposure. This prototype establishes a inspectable
catalog foundation. Security intelligence and research novelty remain future work.

## Current method and rationale

Adapters preserve scope and source hashes rather than flattening every input into one
package/version pair. PyPA packaging implements requirement/version semantics; TOML and
INI use standard-library parsers. Three-state marker/matching results retain uncertainty.
The graph is a simple evidence graph, sufficient to trace catalog findings to teams and
source records. It is not a call graph. Graph construction and source parsing are roughly
linear in input records/bytes; matching currently iterates records × advisories and should
be indexed by package for large advisory feeds. Hashing is currently per record and can
be cached per file. Timings should not be extrapolated to dense enterprise repositories.

## Data and experiment

80 generated repositories, eight repeating schema/scenario families, fixed seed 17.
Fictional demo-lib has versions 1.0 and 2.0; SYNTH-001 affects versions below 2.0.
Range-only requirements have an indeterminate expected result. The generator produces
expected.json from the configured scenarios, independent of scanner execution. However,
the same implementation author designed both; this is not independent ground-truth review.
Unit tests add marker, malformed input, inclusion cycle, constraint, normalization and
scope edge cases. These do not constitute comprehensive format conformance testing.

Scaling uses 10/100/1000 one-dependency repositories, three seeds and three timed scans per
seed after one warm-up. Generation, import, output serialization, chart rendering and
network are excluded. All runs are local and network-free. Each output timing is measured
with perf_counter. Figures show medians and observed min/max, not confidence intervals.
No memory or cold-cache benchmark was performed. See raw results for machine metadata.

## Reviewer-facing contribution to investigate next

Question: Does reconciling declarations, lockfiles and installed snapshots with explicit
environment context improve affected-environment identification over manifest-only analysis?

Needed before a full paper:
1. Define reconciliation rules, evidence freshness, environment identity, and abstentions.
2. Add actual versioned lock schema support and installed metadata; validate transitive edges.
3. Integrate frozen real advisory snapshots with source dates and alias handling.
4. Use independently reviewed fixtures and diverse public repositories at fixed commits.
5. Compare with relevant existing tools on identical supported inputs and advisory snapshots.
6. Run ablations for environment handling and evidence reconciliation; report false positives,
   false negatives, indeterminate rate, runtime, and memory. Unknown truth is not a negative.
7. Evaluate upgrade recommendations using a real resolver and isolated tests if implemented.
8. Add related-work review, reproducibility archive, licensing and limitations.

## References for implementation and related work

- PyPA dependency specification: https://packaging.python.org/en/latest/specifications/dependency-specifiers/
- PyPA packaging: https://packaging.pypa.io/
- pip-audit: https://github.com/pypa/pip-audit
- Dependency-Track: https://docs.dependencytrack.org/

These existing tools already cover substantial inventory/security capabilities. A dashboard
or graph representation alone is not a demonstrated novel contribution. No AI model is
used here. No invented production results, security advisories, or improvement percentages
should be presented as real-world findings. Synthetic records must remain labeled.
