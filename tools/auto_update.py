"""Discover, build, validate and publish compatible official releases; fail closed."""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
from html.parser import HTMLParser
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import build as builder
from localize import patch_dfm
from resource_audit import PE, DFM
from publish import api, publish_one, status

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'automation'
PAGE = 'https://www.uderzo.it/main_products/space_sniffer/download_alt.html'
CONTEXT = 'localization/auto-update'
REPO = 'reliable-ly0411/SpaceSniffer-zh-cn'

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def version_key(version):
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version):
        raise ValueError('Unrecognized version format')
    return tuple(map(int, version.split('.')))

def official_url(url):
    p = urllib.parse.urlsplit(url)
    if (p.scheme != 'https' or p.netloc != 'www.uderzo.it' or
        not p.path.startswith('/main_products/space_sniffer/') or p.query or p.fragment or
        any(x in p.path for x in ('..', '%', '\\'))):
        raise ValueError('Unexpected official URL: '+url)
    return url

class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch_official(url, limit=64*1024*1024):
    url = official_url(url)
    with urllib.request.build_opener(OfficialRedirect()).open(url, timeout=60) as response:
        official_url(response.url)
        data = response.read(limit+1)
    if len(data)>limit:
        raise ValueError('Official response exceeds size limit')
    return data

class ReleaseTable(HTMLParser):
    def __init__(self):
        super().__init__(); self.rows=[]; self.row=None; self.cell=None
    def handle_starttag(self, tag, attrs):
        if tag=='tr': self.row=[]
        elif tag in ('td','th') and self.row is not None: self.cell={'text':'','links':[]}
        elif tag=='a' and self.cell is not None:
            href=dict(attrs).get('href')
            if href:self.cell['links'].append(href)
    def handle_data(self, data):
        if self.cell is not None:self.cell['text']+=data
    def handle_endtag(self, tag):
        if tag in ('td','th') and self.cell is not None:
            self.row.append(self.cell);self.cell=None
        elif tag=='tr' and self.row is not None:
            self.rows.append(self.row);self.row=None;self.cell=None

def parse_latest(html):
    parser=ReleaseTable();parser.feed(html);releases=[]
    for cells in parser.rows:
        if not cells or not re.search(r'SpaceSniffer\s+v',cells[0]['text'],re.I):continue
        if len(cells)!=5:raise ValueError('Official release table schema changed')
        m=re.fullmatch(r'\s*SpaceSniffer\s+v(\d+\.\d+\.\d+\.\d+)(?:\s+(x64|x86))?\s*',cells[0]['text'],re.I)
        if not m:raise ValueError('Unknown version/architecture label')
        version,arch=m.group(1),m.group(2) or 'x86'
        if len(cells[0]['links'])!=1:raise ValueError('Ambiguous archive link')
        url=official_url(urllib.parse.urljoin(PAGE,cells[0]['links'][0]))
        if not re.fullmatch(r'/main_products/space_sniffer/files/spacesniffer_'+version.replace('.','_')+r'(?:_x64|_x86)?\.zip',urllib.parse.urlsplit(url).path):
            raise ValueError('Archive filename/version mismatch')
        date=re.search(r'\b(\d{2}/\d{2}/\d{4})\b',cells[2]['text'])
        if not date:raise ValueError('Missing official date')
        md5,sha1=(cells[i]['text'].strip().lower() for i in (3,4))
        if not re.fullmatch('[0-9a-f]{32}',md5) or not re.fullmatch('[0-9a-f]{40}',sha1):raise ValueError('Missing official hashes')
        notes=official_url(urllib.parse.urljoin(PAGE,cells[2]['links'][0])) if cells[2]['links'] else PAGE.replace('download_alt','release_notes')
        releases.append(dict(version=version,architecture=arch.lower(),official_date=dt.datetime.strptime(date.group(1),'%d/%m/%Y').date().isoformat(),download_url=url,official_md5=md5,official_sha1=sha1,release_notes_url=notes))
    if not releases:raise ValueError('No official releases found')
    if len({r['version'] for r in releases})!=len(releases):raise ValueError('Duplicate/ambiguous official version')
    return max(releases,key=lambda r:version_key(r['version']))

def decide(row, known, release, verify_existing=False):
    previous=next((x for x in known if x['version']==row['version']),None)
    if previous:
        for key in ('architecture','official_date','official_md5','official_sha1','download_url'):
            if row[key]!=previous[key]:raise ValueError('Known upstream release changed: '+key)
    elif version_key(row['version'])<=max(version_key(x['version']) for x in known):
        raise ValueError('Official latest is older than repository history')
    published=release is not None and not release['draft']
    if published and previous is None:raise ValueError('Published release has no pinned source record')
    return bool(verify_existing or not published),not published

def release_for(version):
    try:return api('GET','/releases/tags/v'+version+'-zh1')
    except urllib.error.HTTPError as e:
        if e.code!=404:raise
        return None

def inspect_archive(row, data):
    for alg in ('md5','sha1'):
        if hashlib.new(alg,data).hexdigest()!=row['official_'+alg]:raise ValueError('Official archive checksum mismatch: '+alg)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos=z.infolist();names=[x.filename for x in infos]
        if len(names)!=len(set(names)) or sum(x.file_size for x in infos)>128*1024*1024:raise ValueError('Unsafe archive structure')
        for name in names:
            p=PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:raise ValueError('Unsafe archive path')
        if names.count('SpaceSniffer.exe')!=1 or 'Disclaimer.txt' not in names or 'Release Notes.txt' not in names:
            raise ValueError('Official package layout changed')
        exe=z.read('SpaceSniffer.exe');pe=PE(exe)
        if pe.machine!={'x64':0x8664,'x86':0x14c}[row['architecture']]:raise ValueError('PE architecture mismatch')
        versions=[]
        for res in pe.resources:
            if res['path'][0]==16:
                raw=exe[res['offset']:res['offset']+res['size']];pos=raw.find(b'\xbd\x04\xef\xfe')
                if pos<0:raise ValueError('Missing fixed file version')
                ms,ls=struct.unpack_from('<II',raw,pos+8);versions.append((ms>>16,ms&65535,ls>>16,ls&65535))
        if not versions or any(v!=version_key(row['version']) for v in versions):raise ValueError('Embedded file version mismatch')
        notes=z.read('Release Notes.txt')
        if not re.search(rb'v\s*'+re.escape(row['version'].encode())+rb'\s',notes):raise ValueError('Release notes do not describe this version')
    pinned=dict(row,archive_sha256=builder.digest(data),exe_member='SpaceSniffer.exe',exe_sha256=builder.digest(exe),availability='verified')
    return pinned,exe

def resource_review(exe):
    pe=PE(exe);translations=read(ROOT/'translations/zh-CN.json');forms=[]
    for res in pe.resources:
        raw=exe[res['offset']:res['offset']+res['size']]
        if raw.startswith(b'TPF0'):
            _,changes,unmapped=patch_dfm(raw,translations)
            parsed=DFM(raw);parsed.obj()
            forms.append({'resource':res['path'],'classes':sorted({o['cls'] for o in parsed.objects}),'translated':len(changes),'unmapped':unmapped})
    return forms

def output(**values):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f:
            for key,value in values.items():f.write(f'{key}={str(value).lower()}\n')
    print(values,flush=True)

def prepare(verify_existing=False, offline=False):
    WORK.mkdir(exist_ok=True)
    row=parse_latest(fetch_official(PAGE,2*1024*1024).decode('iso-8859-1'))
    known=read(ROOT/'upstream/releases.json')
    release={'draft':False} if offline else release_for(row['version'])
    needed,publish=decide(row,known,release,verify_existing)
    save(WORK/'discovery.json',{'official_latest':row,'build':needed,'publish':publish})
    output(build=needed,version=row['version'])
    if not needed:
        print('Already published; no build or release changes.');return
    archive=ROOT/'.cache'/row['download_url'].rsplit('/',1)[-1]
    data=archive.read_bytes() if archive.exists() else fetch_official(row['download_url'])
    pinned,exe=inspect_archive(row,data)
    previous=next((x for x in known if x['version']==row['version']),None)
    if previous:
        builder.verify(data,previous)
        if pinned['exe_sha256']!=previous['exe_sha256']:raise ValueError('Known executable hash changed')
        pinned=previous
    forms=resource_review(exe);save(WORK/'resource-review.json',forms)
    baseline=read(ROOT/'upstream/auto-compatibility.json')
    if sorted(f['resource'][1] for f in forms)!=baseline['forms'] or sorted({c for f in forms for c in f['classes']})!=baseline['classes']:
        raise ValueError('New form/component structure requires review; see resource-review.json')
    if any(f['unmapped'] for f in forms):raise ValueError('New visible strings require translation; see resource-review.json')
    archive.parent.mkdir(exist_ok=True);archive.write_bytes(data)
    builder.build(pinned)
    state={'row':pinned,'publish':publish and not offline,'source_sha':os.environ.get('GITHUB_SHA','local-check')}
    save(WORK/'state.json',state)
    shutil.copytree(ROOT/'dist'/row['version'],WORK/'dist'/row['version'],dirs_exist_ok=True)
    smoke=WORK/'smoke'/row['version'];smoke.mkdir(parents=True,exist_ok=True);(smoke/'SpaceSniffer.exe').write_bytes((ROOT/'build'/row['version']/'SpaceSniffer.exe').read_bytes())
    verify_candidate(state)

def verify_candidate(state):
    row=state['row'];out=WORK/'dist'/row['version'];checks=read(out/'checksums.json')
    original_name=row['download_url'].rsplit('/',1)[-1];zh=f"SpaceSniffer-{row['version']}-{row['architecture']}-zh-CN-zh1.zip"
    if set(checks)!={original_name,zh}:raise ValueError('Unexpected candidate archives')
    for name,hashes in checks.items():
        for alg in ('md5','sha1','sha256'):
            if builder.digest((out/name).read_bytes(),alg)!=hashes[alg]:raise ValueError('Candidate archive changed')
    original=(out/original_name).read_bytes();builder.verify(original,row)
    with zipfile.ZipFile(io.BytesIO(original)) as a,zipfile.ZipFile(out/zh) as b:
        for name in a.namelist():
            if name!=row['exe_member'] and a.read(name)!=b.read(name):raise ValueError('Original document changed')
        exe=b.read(row['exe_member']);coverage=json.loads(b.read('localization-coverage.json'))
        if coverage['dfm_unmapped'] or coverage['output_sha256']!=builder.digest(exe):raise ValueError('Invalid localization coverage')
        if 'https://github.com/'+REPO not in b.read('COPYRIGHT-zh-CN.txt').decode('utf-8-sig'):raise ValueError('Missing copyright/repository information')
        source_pe,localized_pe=PE(a.read(row['exe_member'])),PE(exe)
        if source_pe.machine!=localized_pe.machine:raise ValueError('Localized architecture changed')
        for s in source_pe.sections:
            if exe[s['offset']:s['offset']+s['size']]!=a.read(row['exe_member'])[s['offset']:s['offset']+s['size']]:raise ValueError('Original PE section changed')
    if (WORK/'smoke'/row['version']/'SpaceSniffer.exe').read_bytes()!=exe:raise ValueError('Runtime input differs from packaged executable')
    return exe

def check_runtime(state, evidence, exe):
    row=state['row']
    if len(evidence)!=1:raise ValueError('Expected exactly one runtime result')
    test=evidence[0]
    if test['version']!=row['version'] or not test['alive'] or not test['chinese'] or not test.get('menus_ok') or test['exe_sha256']!=builder.digest(exe):
        raise ValueError('Windows runtime evidence does not match candidate')
    return test

def commit_metadata(row,test):
    parent=os.environ['GITHUB_SHA']
    if api('GET','/git/ref/heads/main')['object']['sha']!=parent:raise ValueError('Superseded workflow; retry against current main')
    rows=read(ROOT/'upstream/releases.json');old=next((x for x in rows if x['version']==row['version']),None)
    if old and old!=row:raise ValueError('Refusing to replace pinned upstream metadata')
    if not old:rows.append(row)
    rows.sort(key=lambda r:version_key(r['version']),reverse=True)
    runtime=read(ROOT/'tests/runtime-results.json');runtime['results']=[x for x in runtime['results'] if x['version']!=row['version']]+[test]
    runtime['scope']='Per-version startup and Chinese menus; each automatic record identifies its Windows runner. Not full interactive/scan/DPI validation.'
    tree_base=api('GET','/git/commits/'+parent)['tree']['sha']
    tree=api('POST','/git/trees',{'base_tree':tree_base,'tree':[{'path':path,'mode':'100644','type':'blob','content':json.dumps(value,ensure_ascii=False,indent=2)+'\n'} for path,value in [('upstream/releases.json',rows),('tests/runtime-results.json',runtime)]]})
    commit=api('POST','/git/commits',{'message':'Record verified automatic localization '+row['version'],'tree':tree['sha'],'parents':[parent]})
    api('PATCH','/git/refs/heads/main',{'sha':commit['sha'],'force':False})
    return commit['sha']

def finalize():
    state=read(WORK/'state.json');exe=verify_candidate(state);test=check_runtime(state,read(WORK/'runtime.json'),exe)
    if state['source_sha']!=os.environ['GITHUB_SHA']:raise ValueError('Artifact belongs to another source revision')
    if not state['publish']:
        print('Existing-version validation passed; no release/metadata writes.');return
    if os.environ['GITHUB_REPOSITORY']!=REPO or not api('GET','')['private']:raise ValueError('Only the private target repository is allowed')
    current=parse_latest(fetch_official(PAGE,2*1024*1024).decode('iso-8859-1'))
    for key in ('version','official_md5','official_sha1','official_date'):
        if current[key]!=state['row'][key]:raise ValueError('Official latest changed during the build')
    existing=release_for(current['version'])
    if existing and not existing['draft']:raise ValueError('Release already published; refusing overwrite')
    target=commit_metadata(state['row'],test)
    row=state['row'];shutil.copytree(WORK/'dist'/row['version'],ROOT/'dist'/row['version'],dirs_exist_ok=True)
    dest=ROOT/'build'/row['version'];dest.mkdir(parents=True,exist_ok=True);(dest/'SpaceSniffer.exe').write_bytes(exe)
    result=publish_one(row,test,target,make_latest=True)
    save(WORK/'published.json',result)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['prepare','finalize','status']);p.add_argument('--verify-existing',action='store_true');p.add_argument('--offline',action='store_true');p.add_argument('--state',default='pending');p.add_argument('--description',default='Checking official release')
    a=p.parse_args()
    if a.command=='prepare':prepare(a.verify_existing,a.offline)
    elif a.command=='finalize':finalize()
    else:status(a.state,a.description,context=CONTEXT)
