"""Explicit target profiles and observed-installation comparison for PyDepGraph.

Offline analysis only. Declared applicability, package presence and exploitability
are distinct. Unknown scope or marker inputs remain unresolved.
"""
import argparse
import hashlib
import json
from pathlib import Path
from packaging.markers import Marker, Variable, default_environment
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from pydepgraph import scan

VERSION = '0.2.0a1'


def marker_variables(node):
    """Read parsed variables, never variable-like words inside quoted strings.

    packaging's parsed marker tree is private; compatibility is covered by tests
    and the repository pins packaging. No custom marker comparison semantics.
    """
    if isinstance(node, Variable):
        return {node.value}
    if isinstance(node, (list, tuple)):
        return set().union(*(marker_variables(item) for item in node))
    return set()


def validate_profile(profile):
    if not isinstance(profile, dict):
        raise ValueError('profile must be an object')
    if not isinstance(profile.get('id'), str) or not profile['id']:
        raise ValueError('profile requires a non-empty id')
    env = profile.get('environment')
    if not isinstance(env, dict) or any(not isinstance(v, str) for v in env.values()):
        raise ValueError('environment must map names to strings')
    if any(k in env for k in ('extra', 'extras', 'dependency_groups')):
        raise ValueError('select extras and groups through profile fields, not environment')
    if set(env) - default_environment().keys():
        raise ValueError('unknown environment field')
    for name in ('extras', 'groups'):
        if name in profile and (not isinstance(profile[name], list) or
                any(not isinstance(x, str) or not x.strip() for x in profile[name])):
            raise ValueError(name + ' must be a list of names; omit for unknown selection')
    if 'python_version' in env and 'python_full_version' in env:
        full = Version(env['python_full_version'])
        if env['python_version'] != '.'.join(map(str, full.release[:2])):
            raise ValueError('python_version conflicts with python_full_version')


def applicability(row, profile):
    scope = row['scope']
    if scope == 'constraint':
        return False, 'constraint_is_not_usage'
    if scope.startswith(('optional:', 'group:')):
        field = 'extras' if scope.startswith('optional:') else 'groups'
        if field not in profile:
            return None, 'unknown_' + field + '_selection'
        selected = {canonicalize_name(x) for x in profile[field]}
        if canonicalize_name(scope.split(':', 1)[1]) not in selected:
            return False, 'scope_not_selected'
    elif scope != 'runtime':
        return None, 'unsupported_scope_' + scope
    if not row['marker']:
        return True, 'selected_unconditional_declaration'
    marker = Marker(row['marker'])
    variables = marker_variables(marker._markers)
    env = profile['environment']
    missing = variables - env.keys() - {'extra'}
    if missing:
        return None, 'missing_marker_variables:' + ','.join(sorted(missing))
    if 'extra' in variables and 'extras' not in profile:
        return None, 'unknown_extras_selection'
    contexts = [''] + profile.get('extras', []) if 'extra' in variables else ['']
    try:
        active = any(marker.evaluate(environment={**env, 'extra': extra}, context='requirement')
                     for extra in contexts)
    except Exception as exc:
        return None, 'marker_evaluation_error:' + type(exc).__name__
    return active, 'marker_true' if active else 'marker_false'


def inspect_snapshot(path, profile):
    path = Path(path)
    raw = path.read_bytes()
    data = json.loads(raw)
    if data.get('version') != '1' or not isinstance(data.get('installed'), list):
        raise ValueError('expected pip inspect schema version 1')
    observed_env = data.get('environment', {})
    for key, value in profile['environment'].items():
        if observed_env.get(key) != value:
            raise ValueError('snapshot does not match target environment: ' + key)
    inventory = {}
    for entry in data['installed']:
        meta = entry['metadata']; name = canonicalize_name(meta['name'])
        version = str(Version(meta['version']))
        if name in inventory and inventory[name] != version:
            raise ValueError('conflicting installed versions: ' + name)
        inventory[name] = version
    return inventory, hashlib.sha256(raw).hexdigest()


def reconcile(evidence, inventory, repo, profile_id, digest):
    """Compare each declaration independently; never merge contradictory evidence.

    A range match means constraint compatibility, not dependency resolution.
    Inventory-only packages may be transitive or tooling; they are not errors.
    """
    records = []
    declarations = [r for r in evidence if r['repository'] == repo and r['scope'] != 'constraint']
    for row in declarations:
        version = inventory.get(row['package'])
        if row['active'] is None:
            status = 'unresolved_applicability'
        elif row['active'] is False:
            status = 'inactive_present' if version is not None else 'inactive_absent'
        elif version is None:
            status = 'active_absent'
        elif not row['constraint']:
            status = 'present_version_unconstrained'
        else:
            compatible = SpecifierSet(row['constraint']).contains(Version(version), prereleases=True)
            status = 'satisfies_declaration' if compatible else 'violates_declaration'
        records.append(dict(repository=repo, profile_id=profile_id, package=row['package'],
            source=row['source'], source_sha256=row['source_sha256'], scope=row['scope'],
            constraint=row['constraint'], active=row['active'], installed_version=version,
            relation=status, snapshot_sha256=digest))
    declared_names = {r['package'] for r in declarations}
    for name in sorted(inventory.keys() - declared_names):
        records.append(dict(repository=repo, profile_id=profile_id, package=name,
            installed_version=inventory[name], relation='inventory_only', snapshot_sha256=digest))
    return records


def analyze(root, profiles, advisories=(), snapshots=None):
    ids = []
    for profile in profiles:
        validate_profile(profile); ids.append(profile['id'])
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate profile id')
    snapshots = {} if snapshots is None else snapshots
    if not isinstance(snapshots, dict) or set(snapshots) - set(ids):
        raise ValueError('snapshot mappings must reference known profile IDs')
    repos = {p.name for p in Path(root).iterdir() if p.is_dir() and not p.is_symlink()}
    for mapping in snapshots.values():
        if not isinstance(mapping, dict) or set(mapping) - repos:
            raise ValueError('snapshot mapping must reference repository directories')
    catalog = scan(root)
    results = []
    for profile in profiles:
        evidence = []
        for row in catalog['rows']:
            active, reason = applicability(row, profile)
            evidence.append({**row, 'environment': profile['environment'],
                             'profile_id': profile['id'], 'active': active, 'reason': reason})
        findings = []
        for row in evidence:
            for advisory in advisories:
                if canonicalize_name(advisory['package']) != row['package']:
                    continue
                if row['active'] is False:
                    status = 'not_applicable'
                elif row['active'] is None or row['version'] is None:
                    status = 'indeterminate'
                else:
                    status = 'affected' if Version(row['version']) in SpecifierSet(advisory['affected']) else 'not_affected'
                findings.append({**row, 'advisory': advisory['id'], 'status': status,
                                 'basis': 'source_evidence', 'synthetic_advisory': advisory.get('synthetic', False)})
        observations = []
        comparisons = []
        for repo, path in (snapshots or {}).get(profile['id'], {}).items():
            inventory, digest = inspect_snapshot(path, profile)
            comparisons.extend(reconcile(evidence, inventory, repo, profile['id'], digest))
            for advisory in advisories:
                name = canonicalize_name(advisory['package']); version = inventory.get(name)
                status = 'absent' if version is None else ('affected' if Version(version) in SpecifierSet(advisory['affected']) else 'not_affected')
                declarations = [r for r in evidence if r['repository'] == repo and r['package'] == name]
                observations.append(dict(repository=repo, profile_id=profile['id'], package=name,
                    version=version, advisory=advisory['id'], status=status, basis='installed_snapshot',
                    synthetic_advisory=advisory.get('synthetic', False), snapshot_sha256=digest,
                    declaration_versions=sorted({r['version'] for r in declarations if r['version']}),
                    declared_applicability=[r['active'] for r in declarations]))
        results.append(dict(profile=profile, evidence=evidence, findings=findings, observations=observations,
                            comparisons=comparisons))
    return dict(schema_version='0.2', tool_version=VERSION, results=results,
                diagnostics=catalog['diagnostics'], limitations=[
                    'Source evidence does not prove installation or exploitability.',
                    'Snapshot inventories are supplied observations, not independently authenticated.',
                    'No transitive resolution or deployment verification.',
                    'Advisories use the existing simplified schema, not raw OSV.',
                    'Unsupported lock and development scopes remain indeterminate.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--profiles', type=Path, required=True)
    parser.add_argument('--advisories', type=Path)
    parser.add_argument('--snapshots', type=Path, help='JSON mapping profile ID to repository name to pip inspect path')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    snapshots = json.loads(args.snapshots.read_text()) if args.snapshots else {}
    if args.snapshots:
        snapshots = {p: {r: str((args.snapshots.parent / path).resolve()) for r, path in repos.items()} for p, repos in snapshots.items()}
    result = analyze(args.root, json.loads(args.profiles.read_text()),
                     json.loads(args.advisories.read_text()) if args.advisories else [], snapshots)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
