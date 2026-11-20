# Changelog

## 0.2.0a1 — unreleased research preview

- Add environment_analysis.py with named target profiles and explicit extras/groups.
- Preserve unknown applicability for missing target inputs and unsupported scopes.
- Import pip inspect v1 observations with environment matching and content hashes.
- Keep declared and installed findings separate; no deployment or exploitability claim.
- Add 13 regression tests, a 96-decision controlled benchmark and a snapshot integration check.
- Retain the original v0.1 CLI and behavior.

This preview extends Git baseline f45e96e. No real-repository comparative evaluation or real advisory adapter is included.

### Research preview review updates
- Add advisory-independent, per-declaration installed inventory comparisons.
- Preserve contradictory source constraints in separate comparison records.
- Reject unknown snapshot profiles/repositories and invalid profile fields.
- Retain snapshot-only evidence for repositories without supported declarations.
- Add six regression tests (31 total) and eight hand-labeled reconciliation cases.
