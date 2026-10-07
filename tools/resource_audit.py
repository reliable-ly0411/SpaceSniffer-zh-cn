"""Read-only PE/DFM inventory. Does not execute or modify the input executable."""
import collections
import hashlib
import json
import re
import struct
import sys
from pathlib import Path


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


class PE:
    def __init__(self, data):
        self.data = data
        h = self.u32(0x3c)
        assert data[h:h+4] == b'PE\0\0'
        self.machine, count = struct.unpack_from('<HH', data, h+4)
        optional_size = self.u16(h+20)
        opt = h+24
        self.magic = self.u16(opt)
        assert self.magic in (0x10b,0x20b)
        self.imagebase = struct.unpack_from('<Q' if self.magic==0x20b else '<I', data, opt+(24 if self.magic==0x20b else 28))[0]
        directory_offset=112 if self.magic==0x20b else 96
        self.directories = [struct.unpack_from('<II', data, opt+directory_offset+i*8) for i in range(16)]
        self.sections = []
        for i in range(count):
            p = opt+optional_size+i*40
            name = data[p:p+8].rstrip(b'\0').decode()
            vs, rva, size, offset = struct.unpack_from('<IIII', data, p+8)
            self.sections.append(dict(name=name, virtual_size=vs, rva=rva, size=size, offset=offset))
        self.resources = []
        base = self.offset(self.directories[2][0])
        def walk(rel, path):
            p = base+rel
            n = self.u16(p+12)+self.u16(p+14)
            for i in range(n):
                name, target = struct.unpack_from('<II', data, p+16+i*8)
                if name & 0x80000000:
                    q = base+(name & 0x7fffffff)
                    name = data[q+2:q+2+self.u16(q)*2].decode('utf-16le')
                if target & 0x80000000:
                    walk(target & 0x7fffffff, path+[name])
                else:
                    rva, size, codepage, _ = struct.unpack_from('<IIII', data, base+target)
                    offset = self.offset(rva)
                    payload = data[offset:offset+size]
                    assert len(payload) == size
                    self.resources.append(dict(path=path+[name], rva=rva, offset=offset, size=size,
                                               codepage=codepage, sha256=hashlib.sha256(payload).hexdigest()))
        walk(0, [])

    def u16(self, p): return struct.unpack_from('<H', self.data, p)[0]
    def u32(self, p): return struct.unpack_from('<I', self.data, p)[0]
    def offset(self, rva):
        for s in self.sections:
            if s['rva'] <= rva < s['rva']+max(s['size'], s['virtual_size']):
                return s['offset']+rva-s['rva']
        raise ValueError(f'unmapped RVA {rva:x}')


class DFM:
    def __init__(self, data):
        assert data[:4] == b'TPF0'
        self.b, self.p = data, 4
        self.objects = []
        self.properties = []

    def take(self, n):
        assert 0 <= n <= len(self.b)-self.p, (self.p, n, len(self.b))
        b = self.b[self.p:self.p+n]
        self.p += n
        return b

    def num(self, fmt): return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]
    def short(self): return self.take(self.num('<B')).decode('cp1252')

    def value(self):
        t = self.num('<B')
        if t in (0, 13): return None
        if t in (8, 9): return t == 9
        if t in (2, 3, 4, 15, 16, 17, 19, 21):
            return self.num({2:'<b',3:'<h',4:'<i',15:'<f',16:'<q',17:'<d',19:'<q',21:'<d'}[t])
        if t == 5: return {'extended_hex':self.take(10).hex()}
        if t in (6, 7): return self.short()
        if t in (12, 18, 20):
            n = self.num('<I')
            return self.take(n*(2 if t == 18 else 1)).decode({12:'cp1252',18:'utf-16le',20:'utf-8'}[t])
        if t == 10:
            b = self.take(self.num('<I'))
            return {'binary_size':len(b), 'sha256':hashlib.sha256(b).hexdigest()}
        if t == 11:
            out = []
            while self.b[self.p]: out.append(self.short())
            self.p += 1
            return {'set':out}
        if t == 1:
            out = []
            while self.b[self.p]: out.append(self.value())
            self.p += 1
            return out
        if t == 14:
            out = []
            while self.b[self.p]:
                if self.b[self.p] in (2,3,4): self.value()
                assert self.num('<B') == 1
                item = {}
                while self.b[self.p]:
                    key = self.short()
                    item[key] = self.value()
                self.p += 1
                out.append(item)
            self.p += 1
            return out
        raise ValueError(f'unknown DFM value type {t} at {self.p-1}')

    def obj(self, parent=''):
        flags = 0
        if self.b[self.p] & 0xf0 == 0xf0:
            flags = self.num('<B') & 0xf
            if flags & 2: self.value()
        cls, name = self.short(), self.short()
        path = parent+'/'+name
        props = {}
        while self.b[self.p]:
            prop = self.short()
            start = self.p
            value = self.value()
            props[prop] = value
            self.properties.append(dict(object=path, cls=cls, property=prop, value=value,
                                        offset=start, size=self.p-start, type=self.b[start]))
        self.p += 1
        self.objects.append(dict(path=path, cls=cls, flags=flags, properties=props))
        while self.b[self.p]: self.obj(path)
        self.p += 1


VISIBLE = {'caption','hint','text','title','filter','textlabel','displaylabel','editlabel.caption'}
def visible_properties(props):
    out = []
    for p in props:
        name, value = p['property'].lower(), p['value']
        if isinstance(value, str) and value and (name in VISIBLE or name.endswith('.caption') or name.endswith('.hint')):
            out.append(p)
        if isinstance(value, list):
            for i, v in enumerate(value):
                if isinstance(v, str) and v and name.endswith('.strings'):
                    out.append(dict(p, property=f"{p['property']}[{i}]", value=v))
                if isinstance(v, dict):
                    for k, s in v.items():
                        if isinstance(s, str) and s and k.lower() in VISIBLE:
                            out.append(dict(p, property=f"{p['property']}[{i}].{k}", value=s))
    return out


def audit(exe, out):
    out.mkdir(exist_ok=True, parents=True)
    b = exe.read_bytes()
    pe = PE(b)
    forms, strings, errors = [], [], []
    for r in pe.resources:
        raw = b[r['offset']:r['offset']+r['size']]
        if raw.startswith(b'TPF0'):
            parser = DFM(raw)
            try:
                parser.obj()
                assert parser.p == len(raw), (parser.p, len(raw))
                forms.append(dict(resource=r['path'], size=len(raw), objects=parser.objects,
                                  properties=parser.properties, visible=visible_properties(parser.properties)))
            except Exception as e:
                errors.append(dict(resource=r['path'], error=str(e), position=parser.p, size=len(raw)))
        if r['path'][0] == 6:
            p = 0
            for i in range(16):
                n = struct.unpack_from('<H', raw, p)[0]; p += 2
                value = raw[p:p+n*2].decode('utf-16le'); p += n*2
                if value:
                    strings.append(dict(id=(r['path'][1]-1)*16+i, language=r['path'][2], value=value))
            assert not any(raw[p:]), 'unexpected nonzero stringtable trailing bytes'
    literals = []
    for s in pe.sections:
        if s['name'] not in ('.rodata', '.rdata', '.data'): continue
        data = b[s['offset']:s['offset']+s['size']]
        patterns = [('ascii', rb'[\x20-\x7e\t\r\n]{4,}'), ('utf16le', rb'(?:[\x20-\x7e\t\r\n]\x00){4,}')]
        for enc, pat in patterns:
            for m in re.finditer(pat, data):
                value = m[0].decode('utf-16le' if enc == 'utf16le' else 'ascii')
                if re.search(r'[A-Za-z]{3}', value):
                    literals.append(dict(section=s['name'], offset=s['offset']+m.start(),
                                         rva=s['rva']+m.start(), encoding=enc, value=value))
    summary = dict(exe=str(exe), sha256=hashlib.sha256(b).hexdigest(), bytes=len(b),
                   machine=hex(pe.machine), authenticode_directory=pe.directories[4], sections=pe.sections,
                   resource_types=dict(collections.Counter(str(r['path'][0]) for r in pe.resources)),
                   resource_languages=dict(collections.Counter(str(r['path'][2]) for r in pe.resources)),
                   resource_count=len(pe.resources), dfm_forms=len(forms), dfm_errors=errors,
                   dfm_objects=sum(len(f['objects']) for f in forms),
                   dfm_visible_occurrences=sum(len(f['visible']) for f in forms),
                   dfm_visible_unique=len(set(p['value'] for f in forms for p in f['visible'])),
                   stringtable_entries=len(strings), stringtable_unique=len(set(p['value'] for p in strings)),
                   nonresource_literal_count=len(literals))
    for name, data in [('summary',summary), ('resources',pe.resources), ('forms',forms),
                       ('stringtable',strings), ('literals',literals)]:
        save(out/(name+'.json'),data)
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__ == '__main__':
    audit(Path(sys.argv[1]),Path(sys.argv[2]))
