from pathlib import Path
import subprocess,json,struct,time,hashlib,datetime,urllib.request,tempfile,os
from playwright.sync_api import sync_playwright,expect
root=Path('/workspace/work/candidates/hf-model-provenance-scanner');out=Path('/workspace/work/evidence/hf-model-provenance-scanner/final/browser-binary');out.mkdir(parents=True,exist_ok=True);source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();start=now();port=18769;client=urllib.request.build_opener(urllib.request.ProxyHandler({}));process=subprocess.Popen(['/workspace/work/envs/hf/bin/python','-m','scanner.workbench.server','--port',str(port)],cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
def weights(value,revision):
 header=json.dumps({'__metadata__':{'origin':'SYNTHETIC local format fixture','revision':revision},'weight':{'dtype':'F32','shape':[1],'data_offsets':[0,4]}},separators=(',',':')).encode();return struct.pack('<Q',len(header))+header+struct.pack('<f',value)
try:
 for _ in range(80):
  try:
   health=json.load(client.open(f'http://127.0.0.1:{port}/api/health',timeout=1));break
  except OSError:time.sleep(.1)
 else:raise RuntimeError('Startup deadline')
 assert health['source']['commit']==source and health['source']['source_state']=='CLEAN'
 with tempfile.TemporaryDirectory(prefix='hf-benign-binary-') as directory,sync_playwright() as pw:
  paths=[Path(directory)/'operator-left.safetensors',Path(directory)/'operator-right.safetensors'];values=[weights(1.0,'first'),weights(2.0,'second')]
  for p,data in zip(paths,values):p.write_bytes(data)
  browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox']);page=browser.new_page(accept_downloads=True,viewport={'width':1440,'height':1000});errors=[];page.on('pageerror',lambda error:errors.append(str(error)));page.goto(f'http://127.0.0.1:{port}');expect(page.locator('#version')).to_contain_text(source[:12]);page.locator('#first').set_input_files(paths[0]);page.locator('#second').set_input_files(paths[1]);page.locator('#inspect').click();expect(page.locator('#status')).to_contain_text('Completed',timeout=15000);report=json.loads(page.locator('#report').text_content());assert report['comparison']['bytes_equal'] is False and report['comparison']['metadata_equal'] is False and report['comparison']['structures_equal'] is False
  for file,data in zip(report['result']['files'],values):assert file['format']=='safetensors' and file['sha256']==hashlib.sha256(data).hexdigest() and file['structures']['fingerprint']['tensor_count']==1
  with page.expect_download() as downloaded:page.locator('#download').click()
  downloaded.value.save_as(out/'changed-weights-report.json');bundle=json.loads((out/'changed-weights-report.json').read_text());canonical=page.evaluate("JSON.stringify(JSON.parse(document.getElementById('report').textContent),null,2)");assert bundle['manifest']['report_sha256']==hashlib.sha256(canonical.encode()).hexdigest();page.screenshot(path=str(out/'binary-compare.png'),full_page=True)
  identical=Path(directory)/'operator-identical.safetensors';identical.write_bytes(values[0]);page.locator('#second').set_input_files(identical);expect(page.locator('#output')).to_be_hidden();page.locator('#inspect').click();expect(page.locator('#status')).to_contain_text('Completed',timeout=15000);equal=json.loads(page.locator('#report').text_content());assert equal['comparison']['bytes_equal'] is True and equal['comparison']['metadata_equal'] is True and equal['comparison']['structures_equal'] is True
  (out/'identical-renamed-report.json').write_text(json.dumps(equal,indent=2)+'\n');assert not errors;result={'source_commit':source,'utc_start':start,'utc_end':now(),'browser':browser.version,'checks':['actual two valid binary SafeTensors uploads','canonical tensor fingerprint and exact file hashes','changed weights/metadata/structures compare unequal','actual downloaded bundle checksum','rerun identical bytes under different filenames compares equal','no uncaught page errors'],'result':'PASS','fixture_scope':'Operator-created synthetic valid binary-format fixtures, not trained models or field detection measurements','page_errors':errors};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(result);browser.close()
finally:
 process.terminate();process.wait(timeout=10)
