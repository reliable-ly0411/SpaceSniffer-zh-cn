import hashlib,json,sys,unittest,zipfile,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from build import verify,build
from resource_audit import PE
class BuildTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.rows=json.loads((ROOT/'upstream/releases.json').read_text())
 def test_all_archives_and_documents(self):
  self.assertGreaterEqual(len(self.rows),19)
  for row in self.rows:
   with self.subTest(version=row['version']):
    out=ROOT/'dist'/row['version'];original=out/row['download_url'].rsplit('/',1)[-1];verify(original.read_bytes(),row)
    zh=next(out.glob('*-zh-CN-zh1.zip'))
    with zipfile.ZipFile(original) as a,zipfile.ZipFile(zh) as b:
     for name in a.namelist():
      if name!=row['exe_member']:self.assertEqual(a.read(name),b.read(name),name)
     self.assertIn(b'https://github.com/reliable-ly0411/SpaceSniffer-zh-cn',b.read('COPYRIGHT-zh-CN.txt'))
     self.assertIn(b'https://github.com/reliable-ly0411/SpaceSniffer-zh-cn',b.read('LOCALIZATION-REPOSITORY.txt'))
     report=json.loads(b.read('localization-coverage.json'));self.assertEqual(report['dfm_unmapped'],0)
     data=b.read(row['exe_member']);pe=PE(data)
     base=(ROOT/'build'/row['version']/'unlocalized.exe').read_bytes();bp=PE(base)
     for s in bp.sections:
      if s['name']!='.idata':self.assertEqual(data[s['offset']:s['offset']+s['size']],base[s['offset']:s['offset']+s['size']])
     start=pe.offset(pe.directories[1][0]);count=0
     while any(data[start:start+20]):
      oft,ts,chain,n,iat=struct.unpack_from('<5I',data,start);off=pe.offset(n);name=data[off:data.index(b'\0',off)]
      self.assertTrue(name and iat,(row['version'],name,iat));start+=20;count+=1
      self.assertLess(count,100)
    checks=json.loads((out/'checksums.json').read_text())
    self.assertEqual(len(checks),2)
    for name,sums in checks.items():
     for alg,expected in sums.items():self.assertEqual(hashlib.new(alg,(out/name).read_bytes()).hexdigest(),expected)
 def test_reject_corrupt_archive(self):
  row=self.rows[0];data=bytearray((ROOT/'.cache'/row['download_url'].rsplit('/',1)[-1]).read_bytes());data[-1]^=1
  with self.assertRaises(ValueError):verify(data,row)
 def test_reproducible_zip(self):
  row=self.rows[0];out=ROOT/'dist'/row['version'];p=next(out.glob('*-zh-CN-zh1.zip'));before=p.read_bytes();build(row);self.assertEqual(p.read_bytes(),before)
if __name__=='__main__':unittest.main()
