"""Pure-module smoke suite for build environments without Flask/Semgrep.

It tests local parsers and orchestrator with a mocked Semgrep result.
Run full pytest with Flask/Semgrep on the Kali VM.
"""
import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
pkg=types.ModuleType('hunterqa')
pkg.__path__=[str(ROOT/'hunterqa')]
sys.modules['hunterqa']=pkg
sys.path.insert(0,str(ROOT))
from hunterqa.research import normalize_research_report, get_crash_signal
from hunterqa.evidence import correlate_evidence
from hunterqa.engines.config_audit import audit_project
from hunterqa.engines.openapi import audit_openapi
from hunterqa.engines.dependencies import inventory
from hunterqa.engines.sanitizers import parse_sanitizer_log
from hunterqa.orchestrator import scan_local_source
import hunterqa.orchestrator as orch

checks=0
def check(condition, name):
    global checks
    if not condition: raise AssertionError(name)
    checks+=1
    print('[PASS]', name)

legacy={'findings':[{'crash':{'filename':'legacy','return_code':-6,'signal':6},'ai_analysis':{'cwe':'CWE-121','zero_day_confirmed':True}}]}
result=normalize_research_report(legacy)
check(result['findings'][0]['signal']==6,'legacy report imports')
check(not result['findings'][0]['zero_day_confirmed'],'no AI-confirmed zero-days')

flat={'project':'ZeroScope AI','findings':[{'filename':'id:000000','input_size':12,'sha256':'a'*64,'attempts':[{'return_code':-6,'signal':6}],'reproducible':True}],
      'sanitizer_evidence':[{'category':'heap-use-after-free','cwe_candidate':'CWE-416','evidence_confirmed':True}]}
result=normalize_research_report(flat)
check(result['findings'][0]['signal']==6 and result['findings'][0]['input_size']==12,'flat report crash metadata')
check(result['findings'][0]['matched_diagnostics_count']==0,'unrelated sanitizer evidence remains separate')
check(result['project']=='HunterQA AI','new branding')

matched=correlate_evidence([{'sha256':'a'*64,'binary_sha256':'b'*64}], [{'input_sha256':'a'*64,'binary_sha256':'b'*64}])
check(len(matched[0]['matched_diagnostics'])==1,'two-hash provenance matching')
check(correlate_evidence([{'sha256':'a'*64}], [{'input_sha256':'a'*64}])[0]['matched_diagnostics']==[],'input alone not sufficient')

with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    (root/'Dockerfile').write_text('FROM alpine:latest\nUSER root\n')
    (root/'requirements.txt').write_text('demo==1.2.3\n')
    (root/'openapi.json').write_text(json.dumps({'openapi':'3.0.0','paths':{'/x':{'post':{}}}}))
    (root/'main.py').write_text('eval(input())\n')
    rules=ROOT/'hunterqa'/'rules'/'semgrep.yml'
    check(len(audit_project(root))>=2,'config audit')
    check(len(audit_openapi(root))==1,'offline OpenAPI audit')
    check(len(inventory(root))==1,'dependency inventory')
    original=orch.subprocess.run
    class Completed:
        returncode=0
        stderr=''
        stdout=json.dumps({'results':[{'path':str(root/'main.py'), 'check_id':'hunterqa.python.eval','start':{'line':1},'end':{'line':1},'extra':{'severity':'ERROR','metadata':{'cwe':'CWE-95'},'message':'review eval'}}]})
    orch.subprocess.run=lambda *a,**k: Completed()
    try: scan=scan_local_source(root,rules)
    finally: orch.subprocess.run=original
    check(len(scan['findings'])>=4,'unified scan combines engines')
    check(len(scan['dependencies'])==1,'unified scan inventory recorded')

log='ERROR: AddressSanitizer: heap-use-after-free\nSUMMARY: AddressSanitizer: heap-use-after-free /tmp/uaf_test.c:14:27 in main'
check(parse_sanitizer_log(log)['cwe_candidate']=='CWE-416','ASan evidence parser')
check(parse_sanitizer_log('Aborted')['cwe_candidate'] is None,'SIGABRT not memory corruption')

import yaml
r=yaml.safe_load((ROOT/'hunterqa'/'rules'/'semgrep.yml').read_text())
check(isinstance(r.get('rules'),list) and len(r['rules'])>=10,'offline Semgrep rule file parses')
from jinja2 import Environment
engine=Environment()
for f in (ROOT/'hunterqa'/'templates').glob('*.html'):
    engine.parse(f.read_text())
check(True,'Jinja templates parse')
print(f'Passed {checks} offline smoke checks')
