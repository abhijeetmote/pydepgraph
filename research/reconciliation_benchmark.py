"""Hand-labeled reconciliation fixture, independent of advisory matching."""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment_analysis import analyze

def main():
    output = Path(sys.argv[1]); output.mkdir(parents=True, exist_ok=True)
    expected = {'compatible':'satisfies_declaration','conflict':'violates_declaration',
        'missing':'active_absent','offpresent':'inactive_present','offabsent':'inactive_absent',
        'unknown':'unresolved_applicability','free':'present_version_unconstrained',
        'tool':'inventory_only'}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)/'repos'; repo=root/'app'; repo.mkdir(parents=True)
        (repo/'requirements.txt').write_text('''compatible>=1,<3
conflict==1
missing==1
offpresent==1; sys_platform == "win32"
offabsent==1; sys_platform == "win32"
unknown==1; platform_machine == "arm64"
free
''')
        profile = dict(id='linux', environment={'sys_platform':'linux'}, extras=[], groups=[])
        snap = Path(tmp)/'inspect.json'
        snap.write_text(json.dumps(dict(version='1',environment=profile['environment'],installed=[
            dict(metadata={'name':name,'version':'2'}) for name in ['compatible','conflict','offpresent','free','tool']])))
        result=analyze(root,[profile],snapshots={'linux':{'app':str(snap)}})['results'][0]
        records=[dict(package=r['package'], expected=expected[r['package']], actual=r['relation']) for r in result['comparisons']]
        summary=dict(design='hand-authored snapshot fixture, not an actual installation',
            decisions=len(records),correct=sum(r['expected']==r['actual'] for r in records),records=records)
        (output/'reconciliation.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary,indent=2))
        if summary['correct'] != len(expected): raise SystemExit('reconciliation mismatch')
if __name__=='__main__': main()
