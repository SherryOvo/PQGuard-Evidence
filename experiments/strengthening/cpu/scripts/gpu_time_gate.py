import datetime,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
g=json.loads((ROOT/'config/experiment.json').read_text())['gpu']
assert datetime.datetime.now(datetime.timezone.utc)>=datetime.datetime.fromisoformat(g['not_before_utc']),'Before 14:30 CST'
assert json.loads((ROOT/'evidence/CPU_DONE.json').read_text()).get('passed'),'CPU work has not passed'
r=subprocess.run(['nvidia-smi','--query-gpu=name,memory.total','--format=csv,noheader,nounits'],capture_output=True,text=True);assert r.returncode==0 and 'A800' in r.stdout and int(r.stdout.split(',')[-1].strip())>75000,'A800 80GB not available'
print('TIME_AND_RESOURCE_GATE_PASS')
