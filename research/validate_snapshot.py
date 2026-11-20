"""Read an existing pip inspect observation; write only aggregate smoke-test results."""
import json,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from environment_analysis import analyze
raw=Path(sys.argv[1]);data=json.loads(raw.read_text())
item=next(x['metadata'] for x in data['installed'] if x['metadata']['name'].lower()=='packaging')
p=dict(id='observed-host',environment=data['environment'],extras=[],groups=[])
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)/'repos';repo=root/'app';repo.mkdir(parents=True)
    (repo/'requirements.txt').write_text('packaging=='+item['version'])
    result=analyze(root,[p],[dict(id='SYNTH-SNAPSHOT',package='packaging',affected='=='+item['version'],synthetic=True)],{p['id']:{'app':str(raw)}})
    obs=result['results'][0]['observations'][0]
    assert obs['status']=='affected' and obs['version']==item['version']
    output=dict(test='pip inspect integration smoke check',package='packaging',version=item['version'],
                observation_matches=True,synthetic_advisory=True,
                limitation='One existing host environment; not independent installation or vulnerability validation.')
    Path(sys.argv[2]).write_text(json.dumps(output,indent=2)+'\n');print(json.dumps(output))
