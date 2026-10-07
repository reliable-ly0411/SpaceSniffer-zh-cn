"""Extract and, where needed, UPX-unpack working copies. Originals stay intact."""
import contextlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from resource_audit import PE,audit

ROOT=Path(__file__).resolve().parents[1]
if __name__=='__main__':
    for row in json.loads((ROOT/'upstream/releases.json').read_text()):
        archive=ROOT/'.cache'/row['download_url'].rsplit('/',1)[-1]
        if not archive.exists():continue
        with zipfile.ZipFile(archive) as z:
            name=next(n for n in z.namelist() if n.lower().endswith('spacesniffer.exe'))
            data=z.read(name)
        root=ROOT/'.cache'/row['version'];root.mkdir(exist_ok=True)
        exe=root/'SpaceSniffer.exe';exe.write_bytes(data)
        unpacked=b'UPX0' in data[:1024]
        if unpacked:
            subprocess.run([str(ROOT/'.cache/upx'),'-d',str(exe)],capture_output=True,check=True)
        with contextlib.redirect_stdout(io.StringIO()):audit(exe,root/'audit')
        summary=json.loads((root/'audit/summary.json').read_text())
        print(row['version'],'UPX',unpacked,'forms',summary['dfm_forms'],'errors',summary['dfm_errors'],flush=True)
