# PyDepGraph 0.1 — reproducible research prototype

An automated Python dependency evidence catalog and synthetic advisory-matching demo.
Independent implementation using generated inputs only. No workplace code or data.

## Run

Requires Python 3.11 or newer. From this directory:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python pydepgraph.py synthetic_repositories --advisories advisories.synthetic.json --out my-catalog.json
```

The archive includes generated data and measured results. `python demo.py` generates them
in a fresh source copy with no `synthetic_repositories` or `results` directory; it refuses
to overwrite an existing run. To rerun benchmarks, copy the source files into a new directory.
All synthetic dependencies are parsed as text; do not install the generated repositories.

## What works

- Recursive per-repository collection from requirements, standard pyproject declarations,
  Poetry lock inventory, Pipfile/Pipfile.lock, setup.cfg and tox.ini.
- Requirements includes and constraints, exact pins, canonical package names, scope labels.
- Marker evaluation only when target variables are supplied; otherwise indeterminate.
- Source paths and SHA-256 evidence provenance; explicit parse/unsupported diagnostics.
- Offline matching against a simple JSON advisory schema, with three possible classifications.
- Team→repository→evidence→package graph exported in catalog.json.
- JSON/CSV catalog, reproducible synthetic inputs, raw timings, PNG/SVG figures, unit tests.

Each immediate directory under the scan root is a repository. Optional `pydepgraph.json`
provides `team` and an `environment` mapping. Missing owners remain UNKNOWN.

## Meaning of results

`affected` means an exact version in a source record matches a supplied advisory range
and its recorded marker is applicable. It does NOT prove installation, deployment,
selected extras, exploitation, or production exposure. Scope labels must be retained.
`not_affected` means that version does not match that specific advisory's range.
No finding is not a clean bill of health. `indeterminate` preserves unresolved versions
or unknown marker context. Optional/test/lock inventory records are not production findings.

All shipped advisory records have SYNTH identifiers and are fictional. This is not yet
a live vulnerability scanner. The simple affected-range matcher is not an OSV schema parser.
No advisory freshness, alias deduplication, or real CVE coverage claims are made.

## Deliberate limits

This milestone does not resolve transitive paths, install environments, reconcile lock
freshness, prove conflicts, calculate exploitability, or suggest validated upgrades.
Poetry parsing inventories package records only: group/extra/per-edge applicability is
not resolved. Legacy tool.poetry declarations, uv.lock, arbitrary INI files, dynamic
dependencies, VCS requirements, tox substitutions/factors and group includes are not
fully supported. Unsupported inputs yield diagnostics where detected; those diagnostics
must be reviewed. Repository metadata errors can stop a scan. Only trusted local inputs
should be used; this is not hardened against resource-exhaustion input or symlink races.

Multiple source records for the same package are preserved rather than treated as multiple
deployed installations. Constraints are not treated as evidence of usage. Requirement
ranges are not resolved to invented versions. No code in scanned repositories is executed.

## Reproducibility and paper readiness

See RESEARCH_NOTES.md and results/summary.json. Current small fixtures are smoke-test
evidence only, not independent validation or evidence of superiority to existing tools.
The benchmark uses one dependency per repository and warm local filesystem reads.

## Open-source release

The repository includes an Apache-2.0 license. The environment-analysis extension is an unreleased research preview.

## Environment analysis research preview — 0.2.0a1

The new command retains separate declaration evidence and installed observations:

```sh
python environment_analysis.py REPOSITORY_ROOT --profiles profiles.json --advisories advisories.synthetic.json --out analysis.json
python -m unittest discover -s tests -v
python research/benchmark.py research/results
```

A profiles file is a JSON list such as:

```json
[{"id":"linux312-web","environment":{"sys_platform":"linux","python_version":"3.12"},"extras":["web"],"groups":[]}]
```

An omitted extras/groups key means selection is unknown; an empty list means none selected. Unknown platform or marker variables are not filled from the analysis host. Lock-only and development scopes remain unresolved. The implementation is an applicability analyzer, not a resolver.

Optionally pass `--snapshots snapshots.json`, a mapping from profile IDs to repository names to `pip inspect` JSON paths (relative to the mapping file). The report must match every provided target environment field. Snapshot inventories are supplied observations; their authenticity, completeness and selected extras are not independently verified. Source declarations and observations are never silently fused.

The benchmark uses 16 generated profiles and 96 applicability decisions. These deliberately selected cases are functional validation, not a representative accuracy estimate. See research/PROTOCOL.md for the still-pending real-repository study.
