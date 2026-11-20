"""Controlled applicability benchmark; generated data, not real-repository validation."""
import itertools,json,sys,tempfile,time,platform
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from environment_analysis import analyze
from pydepgraph import scan
import packaging


def main():
    output=Path(sys.argv[1]); output.mkdir(parents=True,exist_ok=True)
    profiles=[]; expected={}
    for os_name,py,extra,group in itertools.product(['linux','win32'],['3.10','3.12'],[False,True],[False,True]):
        ident=f'{os_name}-{py}-web{int(extra)}-test{int(group)}'
        profiles.append(dict(id=ident,environment={'sys_platform':os_name,'python_version':py},extras=['web'] if extra else [],groups=['test'] if group else []))
        # Independent truth table: no marker evaluator used to compute labels.
        expected[ident]={'always':True,'windows':os_name=='win32','oldpy':py=='3.10','webdep':extra,'testdep':group,'mixed':os_name=='linux' and py=='3.12'}
    with tempfile.TemporaryDirectory() as tmp:
        repo=Path(tmp)/'app';repo.mkdir()
        (repo/'pyproject.toml').write_text('''[project]
name="benchmark-app"
version="1"
dependencies=["always==1", "windows==1; sys_platform == 'win32'", "oldpy==1; python_version < '3.11'", "mixed==1; sys_platform == 'linux' and python_version >= '3.12'"]
[project.optional-dependencies]
web=["webdep==1"]
[dependency-groups]
test=["testdep==1"]
''')
        advisories=[dict(id='SYNTH-'+name,package=name,affected='<2',synthetic=True) for name in expected[profiles[0]['id']]]
        started=time.perf_counter();result=analyze(tmp,profiles,advisories);elapsed=time.perf_counter()-started
        records=[]
        for p,result_row in zip(profiles,result['results']):
            (repo/'pydepgraph.json').write_text(json.dumps({'environment':p['environment']}))
            baseline=scan(tmp,advisories)
            for e in result_row['evidence']:
                b=next(r for r in baseline['rows'] if r['package']==e['package'])
                truth=expected[p['id']][e['package']]
                records.append(dict(profile=p['id'],package=e['package'],expected_active=truth,extension_active=e['active'],baseline_active=b['active']))
        summary=dict(design='controlled factorial fixtures; no real CVEs or installations',profiles=len(profiles),decisions=len(records),
            extension_correct=sum(r['expected_active']==r['extension_active'] for r in records),
            baseline_correct=sum(r['expected_active']==r['baseline_active'] for r in records),
            baseline_false_active=sum(not r['expected_active'] and r['baseline_active'] is True for r in records),
            elapsed_seconds=elapsed,python=platform.python_version(),packaging=packaging.__version__,baseline_commit='f45e96e',
            warning='Fixtures deliberately exercise optional selection. Counts do not estimate real-world accuracy or superiority.')
        (output/'records.json').write_text(json.dumps(records,indent=2)+'\n');(output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        (output/'profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
        print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
