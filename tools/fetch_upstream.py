"""Download pinned official archives without modifying their contents."""
import concurrent.futures
import hashlib
import json
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def fetch(row):
    name=row['download_url'].rsplit('/',1)[-1]
    target=ROOT/'.cache'/name
    for attempt in range(3):
        try:
            data=target.read_bytes() if target.exists() else urllib.request.urlopen(row['download_url'],timeout=45).read()
            for algorithm in ('md5','sha1'):
                if hashlib.new(algorithm,data).hexdigest()!=row['official_'+algorithm]:
                    raise ValueError(f"{row['version']}: official {algorithm} mismatch")
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
            row['archive_sha256']=hashlib.sha256(data).hexdigest()
            with zipfile.ZipFile(target) as z:
                names=[n for n in z.namelist() if n.lower().endswith('spacesniffer.exe')]
                assert len(names)==1,names
                exe=z.read(names[0])
                row['exe_member']=names[0]
                row['exe_sha256']=hashlib.sha256(exe).hexdigest()
            row.pop('download_error',None)
            row['availability']='verified'
            print(row['version'],'verified',len(data),flush=True)
            return row
        except Exception:
            if attempt==2:raise
            time.sleep(2)

if __name__=='__main__':
    path=ROOT/'upstream/releases.json'
    rows=json.loads(path.read_text())
    def try_fetch(row):
        try:return fetch(row)
        except Exception as e:
            row['availability']='unavailable'
            row['download_error']=str(e)
            print(row['version'],'unavailable:',e,flush=True)
            return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: rows=list(pool.map(try_fetch,rows))
    path.write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
