"""Version-pinned, resource-only PE localization. Does not patch machine code."""
import hashlib
import json
import re
import struct
from pathlib import Path
from resource_audit import PE, DFM, visible_properties

ROOT=Path(__file__).resolve().parents[1]
VISIBLE={'caption','hint','text','title','filter','textlabel','displaylabel','editlabel.caption'}

def ustring(value):
    raw=value.encode('utf-8')
    return b'\x14'+struct.pack('<I',len(raw))+raw

def patch_dfm(raw, translations):
    dfm=DFM(raw);dfm.obj()
    assert dfm.p==len(raw)
    edits=[];translated=[];unmapped=[]
    for p in dfm.properties:
        key=p['property'].lower();value=p['value'];replacement=None
        visible=key in VISIBLE or key.endswith(('.caption','.hint'))
        if visible and isinstance(value,str):
            if value in translations:
                replacement=ustring(translations[value]);translated.append({'object':p['object'],'property':p['property'],'source':value,'translation':translations[value]})
            elif value and not (value.startswith(('<%','{','Copyright ','TinyXML ','UPX ','Featuring UPX ')) or value in ('SpaceSniffer','www.uderzo.it',':::progress:::') or value==p['object'].rsplit('/',1)[-1] or re.fullmatch(r'[-\d]+',value)):
                unmapped.append({'object':p['object'],'property':p['property'],'source':value})
        elif key.endswith('.strings') and isinstance(value,list):
            assert all(isinstance(x,str) for x in value)
            new=[translations.get(x,x) for x in value]
            if new!=value:
                replacement=b'\x01'+b''.join(ustring(x) for x in new)+b'\0'
                translated.extend({'object':p['object'],'property':p['property']+f'[{i}]','source':x,'translation':y} for i,(x,y) in enumerate(zip(value,new)) if x!=y)
            unmapped.extend({'object':p['object'],'property':p['property']+f'[{i}]','source':x} for i,x in enumerate(value) if x and x not in translations)
        elif key=='font.name' and value in ('Tahoma','MS Sans Serif','Arial'):
            replacement=ustring('Microsoft YaHei')
        elif key=='font.charset' and value=='ANSI_CHARSET':
            s=b'DEFAULT_CHARSET';replacement=b'\x07'+bytes([len(s)])+s
        if replacement is not None:edits.append((p['offset'],p['size'],replacement))
    result=raw
    for offset,size,replacement in sorted(edits,reverse=True):result=result[:offset]+replacement+result[offset+size:]
    check=DFM(result);check.obj();assert check.p==len(result)
    before={(o['path'],o['cls']) for o in dfm.objects};after={(o['path'],o['cls']) for o in check.objects}
    assert before==after,'component hierarchy changed'
    return result,translated,unmapped

def patch_stringtable(raw, translations):
    pos=0;result=bytearray();changes=[]
    for i in range(16):
        n=struct.unpack_from('<H',raw,pos)[0];pos+=2
        text=raw[pos:pos+n*2].decode('utf-16le');pos+=n*2
        new=translations.get(text,text)
        encoded=new.encode('utf-16le')
        result+=struct.pack('<H',len(encoded)//2)+encoded
        if new!=text:changes.append({'index':i,'source':text,'translation':new})
    assert not any(raw[pos:])
    return bytes(result),changes

def align(n,a):return (n+a-1)//a*a

def resource_blob(resources, new_rva):
    tree={}
    for path,payload,codepage in resources:
        node=tree
        for key in path[:-1]:node=node.setdefault(key,{})
        assert path[-1] not in node
        node[path[-1]]=(payload,codepage)
    result=bytearray()
    def alloc(size,alignment=4):
        n=align(len(result),alignment);result.extend(b'\0'*(n+size-len(result)));return n
    def write_dir(node):
        keys=sorted(node,key=lambda k:(0,k) if isinstance(k,str) else (1,k))
        offset=alloc(16+8*len(keys))
        named=sum(isinstance(k,str) for k in keys)
        struct.pack_into('<HH',result,offset+12,named,len(keys)-named)
        for i,key in enumerate(keys):
            if isinstance(key,str):
                encoded=key.encode('utf-16le');name=alloc(2+len(encoded),2)
                struct.pack_into('<H',result,name,len(encoded)//2);result[name+2:name+2+len(encoded)]=encoded
                name|=0x80000000
            else:name=key
            item=node[key]
            if isinstance(item,dict):target=write_dir(item)|0x80000000
            else:
                payload,codepage=item;target=alloc(16);p=alloc(len(payload))
                result[p:p+len(payload)]=payload
                struct.pack_into('<IIII',result,target,new_rva+p,len(payload),codepage,0)
            struct.pack_into('<II',result,offset+16+i*8,name,target)
        return offset
    assert write_dir(tree)==0
    return bytes(result)

def replace_resources(original, resources):
    pe=PE(original);h=pe.u32(0x3c);opt=h+24;n=pe.u16(h+6);optsize=pe.u16(h+20)
    assert not pe.directories[4][0],'signed inputs need explicit signature handling'
    header=opt+optsize+n*40
    first_raw=min(s['offset'] for s in pe.sections if s['size'])
    assert header+40<=first_raw and not any(original[header:header+40]),'no spare section header'
    sa,fa=struct.unpack_from('<II',original,opt+32)
    rva=align(max(s['rva']+max(s['virtual_size'],s['size']) for s in pe.sections),sa)
    raw_offset=align(len(original),fa)
    payload=resource_blob(resources,rva);raw_size=align(len(payload),fa)
    out=bytearray(original);out.extend(b'\0'*(raw_offset-len(out)));out+=payload;out.extend(b'\0'*(raw_size-len(payload)))
    struct.pack_into('<HH',out,h+4,pe.machine,n+1)
    struct.pack_into('<8sIIIIIIHHI',out,header,b'.zhres\0\0',len(payload),rva,raw_size,raw_offset,0,0,0,0,0x40000040)
    struct.pack_into('<I',out,opt+56,align(rva+len(payload),sa))
    struct.pack_into('<I',out,opt+8,pe.u32(opt+8)+raw_size)
    dirs=opt+(112 if pe.magic==0x20b else 96)
    struct.pack_into('<II',out,dirs+16,rva,len(payload))
    struct.pack_into('<I',out,opt+64,0)
    result=bytes(out);check=PE(result)
    assert check.machine==pe.machine and check.imagebase==pe.imagebase
    assert pe.u32(opt+16)==check.u32(opt+16)
    assert all(pe.directories[i]==check.directories[i] for i in range(16) if i!=2)
    for s in pe.sections:
        assert result[s['offset']:s['offset']+s['size']]==original[s['offset']:s['offset']+s['size']],s['name']
    expected={tuple(path):hashlib.sha256(payload).hexdigest() for path,payload,cp in resources}
    assert {tuple(x['path']):x['sha256'] for x in check.resources}==expected
    return result

def localize(data,translations):
    pe=PE(data);resources=[];report={'forms':[],'stringtable_changes':[],'scope':'窗体资源及常用通用对话框汉化；内嵌状态、错误、帮助和原版 PDF 未修改。'}
    for r in pe.resources:
        raw=data[r['offset']:r['offset']+r['size']]
        if raw.startswith(b'TPF0'):
            raw,changes,unmapped=patch_dfm(raw,translations)
            report['forms'].append({'resource':r['path'],'changes':changes,'unmapped':unmapped})
        elif r['path'][0]==6:
            raw,changes=patch_stringtable(raw,translations)
            report['stringtable_changes'].extend(dict(c,resource=r['path']) for c in changes)
        resources.append((r['path'],raw,r['codepage']))
    report['dfm_translated']=sum(len(f['changes']) for f in report['forms'])
    report['dfm_unmapped']=sum(len(f['unmapped']) for f in report['forms'])
    assert report['dfm_translated']>40,'suspiciously few translations'
    assert report['dfm_unmapped']==0,[(f['resource'],f['unmapped']) for f in report['forms'] if f['unmapped']]
    result=replace_resources(data,resources)
    report['input_sha256']=hashlib.sha256(data).hexdigest();report['output_sha256']=hashlib.sha256(result).hexdigest()
    return result,report
