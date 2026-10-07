"""Publish verified assets to this private repository; never change visibility."""
import hashlib,json,os,urllib.request,urllib.error,urllib.parse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPO='reliable-ly0411/SpaceSniffer-zh-cn';BASE='https://api.github.com/repos/'+REPO

def api(method,path,payload=None,data=None,content_type='application/json'):
 if payload is not None:data=json.dumps(payload).encode()
 headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':content_type}
 with urllib.request.urlopen(urllib.request.Request(path if path.startswith('https://') else BASE+path,data=data,headers=headers,method=method),timeout=120) as response:
  body=response.read();return json.loads(body) if body else None

def status(state,description):
 api('POST','/statuses/'+os.environ['GITHUB_SHA'],{'state':state,'context':'localization/releases','description':description[:140],'target_url':'https://github.com/'+REPO+'/actions/runs/'+os.environ['GITHUB_RUN_ID']})
def publish():
 assert os.environ['GITHUB_REPOSITORY']==REPO
 assert api('GET','/git/ref/heads/main')['object']['sha']==os.environ['GITHUB_SHA'],'superseded build'
 assert api('GET','')['private'] is True,'This workflow only publishes to the private repository.'
 rows=json.loads((ROOT/'upstream/releases.json').read_text());runtime=json.loads((ROOT/'tests/runtime-results.json').read_text());evidence={x['version']:x for x in runtime['results']}
 assert len(rows)==len(evidence)==19
 results=[]
 for row in rows:
  version=row['version'];out=ROOT/'dist'/version;exe=ROOT/'build'/version/'SpaceSniffer.exe';test=evidence[version]
  assert test['alive'] and test['chinese'] and hashlib.sha256(exe.read_bytes()).hexdigest()==test['exe_sha256'],'runtime evidence does not match '+version
  tag='v'+version+'-zh1';body=(out/'release.md').read_text();files=sorted(p for p in out.iterdir() if p.name!='release.md')
  try:release=api('GET','/releases/tags/'+tag)
  except urllib.error.HTTPError as e:
   if e.code!=404:raise
   release=api('POST','/releases',{'tag_name':tag,'target_commitish':os.environ['GITHUB_SHA'],'name':'SpaceSniffer '+version+' 简体中文资源汉化 zh1','body':body,'draft':True,'prerelease':False})
  existing={a['name']:a for a in release['assets']}
  for file in files:
   raw=file.read_bytes();expected='sha256:'+hashlib.sha256(raw).hexdigest()
   if file.name in existing:
    assert existing[file.name].get('digest')==expected,'existing asset differs; refusing overwrite: '+file.name
    continue
   assert release['draft'],'cannot mutate an already published release'
   asset=api('POST',release['upload_url'].split('{')[0]+'?name='+urllib.parse.quote(file.name),data=raw,content_type='application/octet-stream')
   assert asset['size']==len(raw) and asset.get('digest')==expected,'uploaded asset verification failed'
  release=api('GET','/releases/'+str(release['id']))
  assert {a['name'] for a in release['assets']}=={p.name for p in files}
  if release['draft']:release=api('PATCH','/releases/'+str(release['id']),{'draft':False,'make_latest':'true' if version=='2.2.0.27' else 'false'})
  assert not release['draft'];results.append({'version':version,'url':release['html_url'],'assets':len(release['assets'])});print(version,release['html_url'],flush=True)
 (ROOT/'dist/published.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n');status('success','Published and verified 19 releases / 114 assets')
if __name__=='__main__':
 import sys
 if len(sys.argv)>1:status(sys.argv[1],sys.argv[2])
 else:publish()
