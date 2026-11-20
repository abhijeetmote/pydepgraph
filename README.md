# PyDepGraph — dependency evidence and environment analysis

An offline Python dependency evidence catalog with explicit target profiles and
comparison against supplied installed-package inventories. The current code includes
the **0.2.0a1 research preview** and retains the original v0.1 scanner CLI.
Shipped benchmark inputs and advisories are synthetic. No workplace code or data
is included. Merged code does not imply a published release or a completed
real-repository vulnerability evaluation.

## Install and run the original catalog

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

## Original catalog capabilities

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

## Original catalog result semantics

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

The tools do not resolve transitive paths, install environments, reconcile lockfile
freshness, establish resolver-level conflicts, calculate exploitability, or suggest
validated upgrades. The environment command can report an observed installed version
that violates an individual source declaration; this does not prove an installation
is unsatisfiable.
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

The original catalog experiment is documented in [RESEARCH_NOTES.md](RESEARCH_NOTES.md)
and [results/summary.json](results/summary.json); it uses one dependency per repository
and warm local filesystem reads. The newer environment experiments are separate and
are described below. Both use controlled fixtures, not independent evidence of
superiority to existing scanners.

## Open-source release

The repository includes an Apache-2.0 license. The environment-analysis extension is an unreleased research preview.

## Environment analysis research preview — 0.2.0a1

The environment command evaluates declarations under named profiles and retains
separate declaration findings, installed observations, and comparison records.
Create `profiles.json` using the example below, then replace `REPOSITORY_ROOT`
with a directory whose immediate subdirectories are repositories:

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

To collect a report, run the following **inside the target environment you intend
to compare**, using a pip version that supports `inspect`:

```sh
python -m pip inspect > inspect.json
```

For a repository directory named `app`, create `snapshots.json` alongside that report:

```json
{"linux312-web":{"app":"inspect.json"}}
```

Then analyze the supplied inventory:

```sh
python environment_analysis.py REPOSITORY_ROOT --profiles profiles.json --snapshots snapshots.json --advisories advisories.synthetic.json --out analysis.json
```

The profile's environment values must describe the collected environment. The sample
Linux profile will be rejected against a macOS or Windows report. Selecting extras
in a profile does not install them or prove that they were requested during installation.
Omit `--advisories` to obtain declaration/inventory comparisons without advisory findings.

Each entry in `results` contains:

| Field | Meaning |
| --- | --- |
| `profile` | Supplied target environment and selection context |
| `evidence` | Source records with true, false, or unknown applicability and a reason |
| `findings` | Source advisory matches: affected, not_affected, not_applicable, or indeterminate |
| `observations` | Advisory matches against the supplied installed inventory, including absent packages |
| `comparisons` | Per-declaration inventory relations and inventory-only packages |

Top-level `diagnostics` retain extraction warnings; `limitations` describe interpretation
boundaries. Empty findings do not establish that an installation is secure.

### Declaration and inventory reconciliation

Each profile result now includes `comparisons`, independent of advisory input.
A record can be `satisfies_declaration`, `violates_declaration`, `active_absent`,
`inactive_present`, `inactive_absent`, `unresolved_applicability`,
`present_version_unconstrained`, or `inventory_only`. These are per-declaration
relations; inactive presence may be explained by another active declaration.
Constraint membership includes observed prereleases and does not reproduce
installer candidate selection. Direct-reference artifact identity is not checked.
Contradictory declarations are retained separately. Snapshot associations must
reference known profiles and existing non-symlink repository directories, including
repositories for which no supported declaration was extracted.

Run the additional controlled fixture with:

```sh
python research/reconciliation_benchmark.py research/results
```

This fixture uses a hand-authored snapshot and no real advisories or installations.


### Recorded validation

| Check | Recorded result | Interpretation |
| --- | --- | --- |
| Unit tests | 31 passed: 12 original and 19 extension tests | Regression checks for supported behavior |
| Applicability fixture | 96/96 expected labels across 16 profiles | Controlled platform, interpreter, extra, and group cases |
| v0.1 active-field comparison | 80/96 labels agree | The 16 differences are deliberately selected extra/group cases |
| Reconciliation fixture | 8/8 expected relations | Hand-authored inventory; independent of advisory input |

Recorded with Python 3.12.14 and packaging 26.3. These counts do not estimate
real-world vulnerability precision, recall, or false-positive reduction. The original
scanner retains scope labels; the active-field comparison measures added selection
semantics, not a complete comparison of deployment scanners.

See [applicability results](research/results/summary.json),
[reconciliation results](research/results/reconciliation.json), and the
[real-repository evaluation protocol](research/PROTOCOL.md). A real-repository study,
raw advisory-feed integration, and independent scanner comparisons remain pending.
