# Environment-aware evaluation protocol

Status: prospective protocol. The real-repository study has not been run.

## Primary question
Does explicit deployment-context selection reduce incorrect applicability assignments relative to the v0.1 source-evidence inventory, without converting unknown cases into negative findings?

## Contribution boundary
The baseline is public commit f45e96e. It already implements basic marker evaluation. Marker evaluation alone is not novel. The proposed contribution is an evidence-preserving evaluation of explicit context selection and observed-environment discrepancies. Novelty remains to be established by a fuller literature review.

## Proposed sample
Select public, appropriately licensed Python projects using predeclared repository activity and packaging-format inclusion criteria. Freeze repository commits and record exclusions, installation failures and selection bias. Stratify by optional dependencies, marker use, and available lock formats. Select sample size after a feasibility pilot, before viewing comparative outcomes. Deduplicate forks and avoid treating multiple environments from one project as independent projects.

## Ground truth
Use disposable, isolated environments with no user credentials for installations. Record exact interpreter, platform, selected extras/groups, installer version, package index snapshot and resolved artifacts. Do not claim to test Windows by setting a marker on macOS: label such cases simulated unless a genuine platform runner supplies an observation. Capture pip inspect immediately after installation. Preserve failures. A package inventory establishes presence, not reachability or exploitability.

## Advisories
Use a dated, archived public advisory snapshot. The current implementation accepts a simplified schema and has no OSV adapter. Implement and validate handling of ecosystem ranges, withdrawn advisories, aliases and missing versions before using real advisories. Separate advisory interpretation errors from dependency applicability errors.

## Comparators and ablations
1. Existing v0.1 with the same explicit environment fields.
2. Environment extension with optional selection disabled.
3. Full extension.
4. Established scanners, pinned versions and matched advisory data where possible; report unavoidable feed differences separately.

## Outcomes
Per source record: true/false/unknown applicability. Per installed package/advisory: affected, unaffected or absent. Report unresolved rate, false active and false inactive rates, presence mismatches, complete inventories, parsing exclusions and runtime distributions. Never equate an omitted finding with a negative. Report source and installed evidence separately when they conflict. Aggregate primarily by project and provide uncertainty intervals that account for repeated environments.

## Reproducibility and release
Archive commands, input hashes, outputs, package versions, hardware details and the code commit. Preserve v0.1 and use a new prerelease for the extension. Include an explicit comparison to prior work and coauthor contribution statements. No results may be inferred from the prospective protocol.
