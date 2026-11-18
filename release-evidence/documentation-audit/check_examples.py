from pathlib import Path
import json,re,subprocess,threading,urllib.request,datetime,tempfile,os,sys
from scanner.workbench.server import Server
r=Path('/workspace/work/candidates/hf-model-provenance-scanner');out=Path('/workspace/work/doc-reconciliation/hf-model-provenance-scanner');checks=[];env={**os.environ,'PYTHONPATH':str(r),'PYTHONDONTWRITEBYTECODE':'1'}
for n in subprocess.check_output(['git','ls-files'],cwd=r,text=True).splitlines()+['docs/DOCUMENTATION_AUDIT.md']:
 p=r/n
 if p.suffix!='.md':continue
 for lang,body in re.findall(r'^```([^\n]*)\n(.*?)^```',p.read_text(),re.M|re.S):
  if lang.strip() in ['sh','bash']:
   p1=subprocess.run(['bash','-n'],input=body,text=True,capture_output=True);checks.append({'document':n,'check':'Bash syntax only; not command execution','exit_code':p1.returncode,'error':p1.stderr});assert p1.returncode==0,(n,p1.stderr)
  elif lang.strip()=='json':json.loads(body);checks.append({'document':n,'check':'JSON syntax','exit_code':0})
for name,args in [('cli-version',['--version']),('cli-help',['--help'])]:
 p=subprocess.run([sys.executable,'-m','scanner.cli',*args],cwd=r,env=env,capture_output=True,text=True);(out/(name+'.txt')).write_text(p.stdout+p.stderr);assert p.returncode==0;checks.append({'check':name,'command':[sys.executable,'-m','scanner.cli',*args],'exit_code':0})
assert 'hf-scanner 0.3.0' in (out/'cli-version.txt').read_text()
with tempfile.TemporaryDirectory(prefix='hf-doc-example-') as td:
 target=Path(td)/'synthetic.py';target.write_text('weights = [1, 2, 3]\n')
 for fmt in ['json','sarif']:
  cmd=[sys.executable,'-m','scanner.cli',str(target),'--mode','local','--no-network','--format',fmt,'--fail-on','high','--enforce'];p=subprocess.run(cmd,cwd=r,env=env,capture_output=True,text=True,timeout=20);(out/('actual-cli-'+fmt+'.log')).write_text(p.stdout+p.stderr);assert p.returncode==0,(fmt,p.stdout,p.stderr);doc=json.loads(p.stdout)
  if fmt=='json':assert doc['scanner_version']=='0.3.0' and doc['completeness']=='COMPLETE' and doc['files_scanned']==1
  else:assert doc['version']=='2.1.0' and doc['runs'][0]['tool']['driver']['name']=='hf-scanner'
  checks.append({'check':'Actual benign localCLI '+fmt,'command':cmd,'exit_code':0,'scope':'Real static scan of controlled source; no model execution/network; SARIF shape only, not officialschema certification'})
server=Server(('127.0.0.1',0));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();base='http://127.0.0.1:'+str(server.server_port)
try:
 with urllib.request.urlopen(base+'/api/health',timeout=2) as response:health=json.load(response)
 text=(r/'docs/API_VERSIONING.md').read_text();payload=json.loads(re.search(r'^```json\n(.*?)^```',text,re.M|re.S).group(1));request=urllib.request.Request(base+'/api/inspect',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Inspector-Token':health['csrf_token']})
 with urllib.request.urlopen(request,timeout=15) as response:report=json.load(response)
 assert report['result']['files'][0]['status']=='NO_PATTERN_FOUND' and report['result']['files'][0]['name']=='synthetic.pkl';assert report['source']['version']=='0.3.0';(out/'actual-api-example.json').write_text(json.dumps(report,indent=2)+'\n');checks.append({'check':'Actual documented localAPI envelope through fresh loopback server + bounded staticworker','exit_code':0,'observed_status':report['result']['files'][0]['status'],'source_commit_observed':report['source']['commit'],'source_status_observed':report['source']['source_state'],'nonce_saved':False})
finally:server.shutdown();server.server_close();thread.join(2)
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Documentation checks, syntax versus actual benign CLI/API clearly separated; no independentsecurityclosure orfullsuiteclaim','checks':checks};(out/'example-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('Documentation checks:',len(checks),'passed')
