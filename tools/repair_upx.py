"""Repair UPX reconstruction of overlapping import-name storage in 1.1.3.x/1.1.4.0.
Only .idata is changed. IAT addresses, functions and machine code stay untouched.
The final four empty descriptors have no IAT and are removed. Names of the thirteen
active descriptors follow their existing imported API sets (recorded in tests).
"""
import hashlib,json,struct
from pathlib import Path
from resource_audit import PE
NAMES=['KERNEL32.DLL','ADVAPI32.DLL','COMCTL32.DLL','COMDLG32.DLL','GDI32.DLL','MSIMG32.DLL','OLE32.DLL','OLEAUT32.DLL','SHELL32.DLL','USER32.DLL','VERSION.DLL','WINMM.DLL','WINSPOOL.DRV']
def repair(data,version):
 pins=json.loads((Path(__file__).resolve().parents[1]/'upstream/upx-repair.json').read_text())
 if version not in pins:return data,False
 assert hashlib.sha256(data).hexdigest()==pins[version], 'unrecognized UPX output'
 pe=PE(data);section=next(s for s in pe.sections if s['name']=='.idata');start=pe.offset(pe.directories[1][0]);out=bytearray(data)
 descriptors=[struct.unpack_from('<5I',data,start+20*i) for i in range(18)]
 assert all(d[4] for d in descriptors[:13]) and all(not d[4] and d[3] for d in descriptors[13:17]) and not any(descriptors[17])
 storage=section['offset']+pe.directories[1][1]
 names=b''.join(n.encode()+b'\0' for n in NAMES)
 assert storage+len(names)<=section['offset']+section['size'] and not any(data[storage:storage+len(names)])
 out[storage:storage+len(names)]=names;pos=storage
 for i,name in enumerate(NAMES):
  struct.pack_into('<I',out,start+20*i+12,section['rva']+pos-section['offset']);pos+=len(name)+1
 out[start+260:start+340]=b'\0'*80
 for s in pe.sections:
  if s['name']!='.idata':assert out[s['offset']:s['offset']+s['size']]==data[s['offset']:s['offset']+s['size']]
 return bytes(out),True
