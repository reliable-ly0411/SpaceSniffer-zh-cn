import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import auto_update as auto

ROW=dict(version='2.2.0.27',architecture='x64',official_date='2026-03-25',download_url=auto.PAGE.replace('download_alt.html','files/spacesniffer_2_2_0_27_x64.zip'),official_md5='a'*32,official_sha1='b'*40,release_notes_url=auto.PAGE.replace('download_alt','release_notes'))
def html(version='2.2.0.27'):
    return f'<table><tr><td><a href="files/spacesniffer_{version.replace(".","_")}_x64.zip">SpaceSniffer v{version} x64</a></td><td>1 KB</td><td><a href="release_notes.html">Release notes - 25/03/2026</a></td><td>{"a"*32}</td><td>{"b"*40}</td></tr></table>'

def fake_archive(extra=None):
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as z:
        z.writestr('SpaceSniffer.exe',struct.pack('<6I',0xfeef04bd,0x10000,0x20002,27,0x20002,27))
        z.writestr('Disclaimer.txt','original disclaimer')
        z.writestr('Release Notes.txt','v 2.2.0.27\n---\nExample')
        if extra:z.writestr(extra,'unsafe')
    data=buffer.getvalue();row=dict(ROW,official_md5=hashlib.md5(data).hexdigest(),official_sha1=hashlib.sha1(data).hexdigest())
    return row,data

class DiscoveryTests(unittest.TestCase):
    def test_official_metadata(self):self.assertEqual(auto.parse_latest(html()),ROW)
    def test_numeric_version_order_not_lexical_or_table_order(self):
        self.assertEqual(auto.parse_latest(html('2.9.0.0')+html('2.10.0.0'))['version'],'2.10.0.0')
    def test_schema_and_missing_hash_fail(self):
        for page in ('<html>maintenance</html>',html().replace('a'*32,'abc'),html().replace('25/03/2026','broken'),html()+html(),html().replace('x64</a>','arm64</a>')):
            with self.subTest(page=page[:60]),self.assertRaises(ValueError):auto.parse_latest(page)
    def test_external_and_traversal_links_fail(self):
        for url in ('https://evil.example/file.zip','http://www.uderzo.it/main_products/space_sniffer/file.zip','https://www.uderzo.it/main_products/space_sniffer/../bad.zip'):
            with self.subTest(url=url),self.assertRaises(ValueError):auto.official_url(url)
        with self.assertRaises(ValueError):auto.parse_latest(html().replace('href="files/','href="https://evil.example/'))
    def test_filename_must_match_label(self):
        with self.assertRaises(ValueError):auto.parse_latest(html().replace('spacesniffer_2_2','spacesniffer_3_2'))
    def test_already_published_is_noop(self):
        self.assertEqual(auto.decide(ROW,[ROW],{'draft':False}),(False,False))
        self.assertEqual(auto.decide(ROW,[ROW],{'draft':False},True),(True,False))
    def test_new_version_and_draft_retry(self):
        older=dict(ROW,version='2.1.0.21')
        self.assertEqual(auto.decide(ROW,[older],None),(True,True))
        self.assertEqual(auto.decide(ROW,[ROW],{'draft':True}),(True,True))
    def test_repacked_or_rolled_back_official_release_fails(self):
        with self.assertRaises(ValueError):auto.decide(dict(ROW,official_md5='c'*32),[ROW],None)
        with self.assertRaises(ValueError):auto.decide(dict(ROW,version='1.0.0.0'),[ROW],None)
        with self.assertRaises(ValueError):auto.decide(ROW,[dict(ROW,version='2.1.0.21')],{'draft':False})

class ValidationTests(unittest.TestCase):
    def test_archive_hash_version_and_architecture_guards(self):
        row,data=fake_archive();pe=SimpleNamespace(machine=0x8664,resources=[dict(path=[16,1,0],offset=0,size=24)])
        with patch.object(auto,'PE',return_value=pe):
            pinned,exe=auto.inspect_archive(row,data)
            self.assertEqual(pinned['archive_sha256'],hashlib.sha256(data).hexdigest())
            with self.assertRaises(ValueError):auto.inspect_archive(dict(row,version='2.3.0.0'),data)
            with self.assertRaises(ValueError):auto.inspect_archive(dict(row,architecture='x86'),data)
        with self.assertRaises(ValueError):auto.inspect_archive(row,data+b'x')
    def test_unsafe_zip_path_fails_before_pe_parsing(self):
        row,data=fake_archive('../escape.exe')
        with self.assertRaisesRegex(ValueError,'Unsafe archive path'):auto.inspect_archive(row,data)
    def test_runtime_must_match_version_hash_and_four_menus(self):
        exe=b'candidate';test=dict(version=ROW['version'],alive=True,chinese=True,menus_ok=True,exe_sha256=hashlib.sha256(exe).hexdigest())
        self.assertEqual(auto.check_runtime({'row':ROW},[test],exe),test)
        for key,value in [('version','1.0.0.0'),('alive',False),('chinese',False),('menus_ok',False),('exe_sha256','0'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):auto.check_runtime({'row':ROW},[dict(test,**{key:value})],exe)
        with self.assertRaises(ValueError):auto.check_runtime({'row':ROW},[],exe)
    def test_changed_zip_blocks_finalize(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(auto,'WORK',Path(tmp)):
            row=ROW;out=Path(tmp)/'dist'/row['version'];out.mkdir(parents=True)
            names=[row['download_url'].rsplit('/',1)[-1],f"SpaceSniffer-{row['version']}-x64-zh-CN-zh1.zip"]
            checks={n:{a:'0'*{'md5':32,'sha1':40,'sha256':64}[a] for a in ('md5','sha1','sha256')} for n in names}
            for n in names:(out/n).write_bytes(b'changed')
            auto.save(out/'checksums.json',checks)
            with self.assertRaisesRegex(ValueError,'Candidate archive changed'):auto.verify_candidate({'row':row})
    def test_existing_validation_has_no_remote_side_effect(self):
        state={'row':ROW,'publish':False,'source_sha':'abc'}
        with patch.dict(os.environ,GITHUB_SHA='abc'),patch.object(auto,'read',side_effect=[state,[{}]]),patch.object(auto,'verify_candidate',return_value=b'exe'),patch.object(auto,'check_runtime',return_value={}),patch.object(auto,'api') as api:
            auto.finalize();api.assert_not_called()
    def test_stale_source_rejected_before_remote_mutation(self):
        with patch.dict(os.environ,GITHUB_SHA='abc'),patch.object(auto,'api',return_value={'object':{'sha':'newer'}}) as api:
            with self.assertRaisesRegex(ValueError,'Superseded'):auto.commit_metadata(ROW,{})
            self.assertEqual(api.call_count,1)
    def test_metadata_commit_preserves_other_versions(self):
        rows=[dict(ROW,version='2.1.0.21')];runtime={'results':[{'version':'2.1.0.21'}]};calls=[]
        def api(method,path,payload=None):
            calls.append((method,path,payload))
            if path=='/git/ref/heads/main':return {'object':{'sha':'abc'}}
            if path=='/git/commits/abc':return {'tree':{'sha':'base'}}
            if path=='/git/trees':return {'sha':'tree'}
            if path=='/git/commits':return {'sha':'new'}
            if path=='/git/refs/heads/main':return {}
            raise AssertionError(path)
        with patch.dict(os.environ,GITHUB_SHA='abc'),patch.object(auto,'api',side_effect=api),patch.object(auto,'read',side_effect=[rows,runtime]):
            self.assertEqual(auto.commit_metadata(ROW,{'version':ROW['version']}),'new')
        tree=next(p for m,u,p in calls if u=='/git/trees')
        self.assertEqual(tree['base_tree'],'base')
        saved=json.loads(tree['tree'][0]['content']);self.assertEqual([r['version'] for r in saved],['2.2.0.27','2.1.0.21'])
        self.assertFalse(calls[-1][2]['force'])

class PublicationTests(unittest.TestCase):
    def test_upload_digest_and_draft_transition(self):
        import publish
        import urllib.error
        with tempfile.TemporaryDirectory() as tmp,patch.object(publish,'ROOT',Path(tmp)):
            out=Path(tmp)/'dist'/ROW['version'];out.mkdir(parents=True)
            exe=Path(tmp)/'build'/ROW['version']/'SpaceSniffer.exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'executable')
            (out/'release.md').write_text('body');(out/'asset.zip').write_bytes(b'archive')
            asset={'name':'asset.zip','size':7,'digest':'sha256:'+hashlib.sha256(b'archive').hexdigest()}
            calls=[]
            def api(method,path,payload=None,**kw):
                calls.append((method,path,payload))
                if '/releases/tags/' in path:raise urllib.error.HTTPError(path,404,'not found',{},None)
                if path=='/releases':
                    self.assertEqual(payload['target_commitish'],'tested-commit');self.assertTrue(payload['draft'])
                    return {'id':1,'assets':[],'draft':True,'upload_url':'https://uploads.github.com/example{?name}'}
                if path.startswith('https://uploads.github.com/'):return asset
                if method=='GET':return {'id':1,'assets':[asset],'draft':True}
                return {'draft':False,'assets':[asset],'html_url':'https://github.com/example/release'}
            test=dict(alive=True,chinese=True,exe_sha256=hashlib.sha256(b'executable').hexdigest())
            with patch.object(publish,'api',side_effect=api):
                result=publish.publish_one(ROW,test,'tested-commit',True)
            self.assertEqual(result['assets'],1)
            self.assertEqual(calls[-1][2],{'draft':False,'make_latest':'true'})
    def test_published_asset_is_never_overwritten(self):
        import publish
        with tempfile.TemporaryDirectory() as tmp,patch.object(publish,'ROOT',Path(tmp)):
            out=Path(tmp)/'dist'/ROW['version'];out.mkdir(parents=True)
            exe=Path(tmp)/'build'/ROW['version']/'SpaceSniffer.exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'exe')
            (out/'release.md').write_text('body');(out/'asset.zip').write_bytes(b'new bytes')
            test=dict(alive=True,chinese=True,exe_sha256=hashlib.sha256(b'exe').hexdigest())
            with patch.object(publish,'api',return_value={'draft':False,'assets':[{'name':'asset.zip','digest':'sha256:old'}]}) as api:
                with self.assertRaisesRegex(AssertionError,'refusing overwrite'):publish.publish_one(ROW,test,'commit')
                self.assertEqual(api.call_count,1)

if __name__=='__main__':unittest.main()
