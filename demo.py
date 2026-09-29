"""Generate synthetic repositories, run scanner, measure and plot. No downloads."""
import csv
import json
import platform
import random
import statistics
import tempfile
import time
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pydepgraph import scan

BASE = Path(__file__).resolve().parent
ADVISORIES = [{'id': 'SYNTH-001', 'package': 'demo-lib', 'affected': '<2', 'synthetic': True,
               'description': 'Fictional test advisory; not a public vulnerability record.'}]


def generate(root, count, seed=17):
    """Balanced schema families with independently specified expected classifications."""
    rng = random.Random(seed)
    expected = []
    for i in range(count):
        repo = root / f'service-{i:04d}'
        repo.mkdir(parents=True, exist_ok=False)
        family = i % 8
        version = rng.choice(['1.0', '2.0'])
        status = 'affected' if version == '1.0' else 'not_affected'
        meta = {'synthetic': True, 'team': ['Data', 'Platform', 'Applications', 'UNKNOWN'][i % 4],
                'environment': {'sys_platform': 'linux', 'python_version': '3.11'}}
        (repo / 'pydepgraph.json').write_text(json.dumps(meta, indent=2))
        if family == 0:
            name, content = 'requirements.txt', f'demo-lib=={version}\n'
        elif family == 1:
            name, content = 'pyproject.toml', f'[project]\nname="synthetic-service"\nversion="0.1"\ndependencies=["demo-lib=={version}"]\n'
        elif family == 2:
            name, content = 'poetry.lock', f'[[package]]\nname="demo-lib"\nversion="{version}"\n'
        elif family == 3:
            name, content = 'Pipfile.lock', json.dumps({'default': {'demo-lib': {'version': '==' + version}}})
        elif family == 4:
            name, content = 'Pipfile', f'[packages]\ndemo-lib="=={version}"\n'
        elif family == 5:
            name, content = 'setup.cfg', f'[options]\ninstall_requires =\n demo-lib=={version}\n'
        elif family == 6:
            name, content = 'tox.ini', f'[testenv]\ndeps =\n demo-lib=={version}\n'
        else:
            name, content = 'requirements.txt', 'demo-lib>=1\n'
            status = 'indeterminate'
        (repo / name).write_text(content)
        expected.append({'repository': repo.name, 'status': status})
    return expected


def main():
    # Refuse to overwrite any existing generated dataset or results.
    dataset, output = BASE / 'synthetic_repositories', BASE / 'results'
    if dataset.exists() or output.exists():
        raise SystemExit('Outputs already exist. Run a fresh copy to regenerate without overwriting.')
    dataset.mkdir()
    output.mkdir()
    truth = generate(dataset, 80)
    (BASE / 'advisories.synthetic.json').write_text(json.dumps(ADVISORIES, indent=2))
    (BASE / 'expected.json').write_text(json.dumps(truth, indent=2))
    result = scan(dataset, ADVISORIES)
    (output / 'catalog.json').write_text(json.dumps(result, indent=2))
    actual = {f['repository']: f['status'] for f in result['findings']}
    matched = sum(actual.get(x['repository']) == x['status'] for x in truth)
    if matched != len(truth):
        raise AssertionError('Generated benchmark differs from expected classifications')
    with (output / 'catalog.csv').open('w', newline='') as f:
        fields = ['repository', 'team', 'package', 'version', 'constraint', 'scope', 'evidence', 'active', 'source']
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(result['rows'])
    timings = []
    for count in (10, 100, 1000):
        for seed in (17, 29, 43):
            with tempfile.TemporaryDirectory() as tmp:
                generate(Path(tmp), count, seed)
                scan(tmp, ADVISORIES)  # warm-up; excluded
                for repeat in range(3):
                    start = time.perf_counter()
                    scan(tmp, ADVISORIES)
                    timings.append({'repositories': count, 'seed': seed, 'repeat': repeat,
                                    'seconds': time.perf_counter() - start})
    (output / 'timings.json').write_text(json.dumps(timings, indent=2))
    counts = Counter(f['status'] for f in result['findings'])
    summary = {'synthetic': True, 'repositories': 80, 'evidence_rows': len(result['rows']),
               'fixture_classifications_matched': matched, 'fixture_classifications_total': len(truth),
               'advisory_status_counts': counts, 'diagnostics': len(result['diagnostics']),
               'python': platform.python_version(), 'platform': platform.platform(),
               'timing_scope': 'Warm filesystem scan plus matching plus graph, excludes generation, imports, plotting, network and serialization',
               'timing_median_seconds': {str(n): statistics.median(x['seconds'] for x in timings if x['repositories'] == n) for n in (10, 100, 1000)}}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2))
    plt.rcParams.update({'font.size': 11, 'axes.spines.top': False, 'axes.spines.right': False})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    labels = ['affected', 'not_affected', 'indeterminate']
    bars = axes[0].bar(['Affected', 'Not affected', 'Indeterminate'], [counts[x] for x in labels], color=['#b64f57', '#398675', '#9b853a'])
    axes[0].bar_label(bars, padding=3)
    axes[0].set_ylim(0, max(counts.values()) * 1.25)
    axes[0].set_ylabel('Dependency evidence records')
    axes[0].set_title('Fictional advisory: measured classifications')
    ns = (10, 100, 1000)
    medians = [summary['timing_median_seconds'][str(n)] for n in ns]
    lows = [min(x['seconds'] for x in timings if x['repositories'] == n) for n in ns]
    highs = [max(x['seconds'] for x in timings if x['repositories'] == n) for n in ns]
    axes[1].errorbar(ns, medians, yerr=[[m-l for m,l in zip(medians,lows)], [h-m for m,h in zip(medians,highs)]], fmt='o-', color='#326493', capsize=5)
    axes[1].set_xscale('log')
    axes[1].set_xticks(ns, [str(n) for n in ns])
    axes[1].set_xlabel('Synthetic repositories (one dependency each)')
    axes[1].set_ylabel('Elapsed seconds')
    axes[1].set_title('Warm scans: median and observed range')
    fig.suptitle('PyDepGraph 0.1 — actual execution on synthetic inputs', fontsize=15, fontweight='bold')
    fig.text(.5, .015, 'Synthetic packages and advisories • 9 timed runs per scale • No production-security or comparative-performance claims', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .07, 1, .94))
    fig.savefig(output / 'benchmark.png', dpi=180)
    fig.savefig(output / 'benchmark.svg')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
