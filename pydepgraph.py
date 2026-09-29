"""Offline dependency evidence catalog. Python 3.11+. No repository code execution."""
import argparse
import configparser
import hashlib
import json
import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from packaging.specifiers import SpecifierSet


def scan(root, advisories=()):
    root = Path(root).resolve()
    rows, diagnostics = [], []

    def warn(repo, path, message):
        diagnostics.append(dict(repository=repo.name, source=str(path.relative_to(repo)), message=message))

    for repo in sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink()):
        meta_path = repo / 'pydepgraph.json'
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        env = meta.get('environment', {})
        team = meta.get('team', 'UNKNOWN')
        visited = set()

        def add(path, raw, scope='runtime', kind='declared', version=None, marker=None):
            try:
                req = Requirement(raw)
                marker_obj = req.marker
                if marker:
                    from packaging.markers import Marker
                    marker_obj = Marker(marker)
                marker_text = str(marker_obj) if marker_obj else None
                active = True
                if marker_obj:
                    # Avoid packaging's implicit host-environment defaults.
                    variables = set(re.findall(r'\b(?:python_version|python_full_version|os_name|sys_platform|platform_release|platform_system|platform_version|platform_machine|platform_python_implementation|implementation_name|implementation_version|extra|extras|dependency_groups)\b', marker_text))
                    active = marker_obj.evaluate(environment=env) if variables <= env.keys() else None
                exact = version
                specs = list(req.specifier)
                if exact is None and len(specs) == 1 and specs[0].operator == '==' and '*' not in specs[0].version:
                    exact = specs[0].version
                if exact is not None:
                    exact = str(Version(exact))
                rows.append(dict(repository=repo.name, team=team, environment=env,
                    package=canonicalize_name(req.name), constraint=str(req.specifier),
                    version=exact, scope=scope, evidence=kind, marker=marker_text,
                    active=active, source=str(path.relative_to(repo)), raw=raw,
                    source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            except Exception as exc:
                warn(repo, path, f'Unsupported or invalid requirement {raw!r}: {exc}')

        def requirements(path, scope='runtime'):
            key = (path.resolve(), scope)
            if key in visited:
                return
            visited.add(key)
            if path.is_symlink() or not path.resolve().is_relative_to(repo.resolve()):
                warn(repo, path, 'Include outside repository or symlink rejected')
                return
            if not path.exists():
                warn(repo, path, 'Missing included requirements file')
                return
            content = path.read_text().replace('\\\n', '')
            for line in content.splitlines():
                line = re.split(r'\s+#', line, maxsplit=1)[0].strip()
                if not line or line.startswith('#'):
                    continue
                include = re.match(r'^(?:-r\s*|--requirement(?:=|\s+))(.+)$', line)
                constraint = re.match(r'^(?:-c\s*|--constraint(?:=|\s+))(.+)$', line)
                if include or constraint:
                    match = include or constraint
                    requirements(path.parent / match[1].strip(), 'constraint' if constraint else scope)
                elif line.startswith('-'):
                    warn(repo, path, f'Unsupported option: {line}')
                else:
                    add(path, re.split(r'\s+--hash=', line)[0], scope)

        for path in sorted(repo.rglob('*')):
            if not path.is_file() or path.is_symlink() or any(p.startswith('.') for p in path.relative_to(repo).parts):
                continue
            try:
                if path.name.startswith('requirements') and path.suffix == '.txt':
                    requirements(path, 'dev' if any(x in path.stem for x in ('dev', 'test')) else 'runtime')
                elif path.name == 'pyproject.toml':
                    data = tomllib.loads(path.read_text())
                    project = data.get('project', {})
                    for raw in project.get('dependencies', []):
                        add(path, raw)
                    for group, deps in project.get('optional-dependencies', {}).items():
                        for raw in deps:
                            add(path, raw, 'optional:' + group)
                    for group, deps in data.get('dependency-groups', {}).items():
                        for raw in deps:
                            if isinstance(raw, str):
                                add(path, raw, 'group:' + group)
                            else:
                                warn(repo, path, 'Dependency group includes unsupported')
                    if data.get('tool', {}).get('poetry'):
                        warn(repo, path, 'Legacy tool.poetry declarations unsupported; use poetry.lock or PEP 621')
                    if 'dependencies' in project.get('dynamic', []):
                        warn(repo, path, 'Dynamic dependencies not executed')
                elif path.name == 'poetry.lock':
                    data = tomllib.loads(path.read_text())
                    for pkg in data.get('package', []):
                        add(path, pkg['name'], 'lock', 'locked', pkg['version'], pkg.get('markers'))
                    warn(repo, path, 'Poetry lock inventory only: extras, groups, per-edge applicability and transitive paths not resolved')
                elif path.name in ('Pipfile', 'Pipfile.lock'):
                    locked = path.name.endswith('.lock')
                    data = json.loads(path.read_text()) if locked else tomllib.loads(path.read_text())
                    for section, scope in [('default' if locked else 'packages', 'runtime'), ('develop' if locked else 'dev-packages', 'dev')]:
                        for name, value in data.get(section, {}).items():
                            detail = value if isinstance(value, dict) else {'version': value}
                            spec = detail.get('version', '*')
                            if any(k in detail for k in ('git', 'path', 'file')):
                                warn(repo, path, f'Non-index dependency unsupported: {name}')
                                continue
                            add(path, name + ('' if spec == '*' else spec), scope,
                                'locked' if locked else 'declared', marker=detail.get('markers'))
                elif path.name in ('setup.cfg', 'tox.ini'):
                    cfg = configparser.ConfigParser(interpolation=None)
                    cfg.read_string(path.read_text())
                    for section in cfg.sections():
                        if section == 'options' and cfg.has_option(section, 'install_requires'):
                            for raw in cfg[section]['install_requires'].splitlines():
                                if raw.strip():
                                    add(path, raw.strip())
                        elif section == 'options.extras_require':
                            for group, deps in cfg[section].items():
                                for raw in deps.splitlines():
                                    if raw.strip():
                                        add(path, raw.strip(), 'optional:' + group)
                        elif section.startswith('testenv') and cfg.has_option(section, 'deps'):
                            for raw in cfg[section]['deps'].splitlines():
                                if raw.strip():
                                    add(path, raw.strip(), section)
                elif path.suffix in ('.ini', '.lock'):
                    warn(repo, path, 'Unsupported schema')
            except Exception as exc:
                warn(repo, path, f'Parse failure: {exc}')

    unique = {json.dumps(r, sort_keys=True): r for r in rows}
    rows = list(unique.values())
    findings = []
    for row in rows:
        if row['scope'] == 'constraint' or row['active'] is False:
            continue
        for advisory in advisories:
            if canonicalize_name(advisory['package']) != row['package']:
                continue
            status = 'indeterminate'
            if row['version'] is not None and row['active'] is True:
                status = 'affected' if Version(row['version']) in SpecifierSet(advisory['affected']) else 'not_affected'
            findings.append({**row, 'advisory': advisory['id'], 'synthetic_advisory': advisory.get('synthetic', False), 'status': status})
    # Evidence graph, not a runtime call graph or reconstructed transitive graph.
    nodes, edges = {}, []
    for i, row in enumerate(rows):
        rid = 'repo:' + row['repository']
        tid = 'team:' + row['team']
        eid = 'evidence:' + str(i)
        pid = 'package:' + row['package']
        for node, typ, label in [(rid, 'repository', row['repository']), (tid, 'team', row['team']), (eid, 'evidence', row['version'] or row['constraint'] or 'unresolved'), (pid, 'package', row['package'])]:
            nodes[node] = dict(id=node, type=typ, label=label)
        edges.extend([dict(source=tid, target=rid), dict(source=rid, target=eid), dict(source=eid, target=pid)])
    return dict(schema_version='0.1', rows=rows, findings=findings, diagnostics=diagnostics,
                graph=dict(nodes=list(nodes.values()), edges=list({(e['source'], e['target']): e for e in edges}.values())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--advisories', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    advisories = json.loads(args.advisories.read_text()) if args.advisories else []
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(scan(args.root, advisories), indent=2) + '\n')


if __name__ == '__main__':
    main()
