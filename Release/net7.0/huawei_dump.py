import argparse
import hashlib
import json
import mmap
import re
import struct
from pathlib import Path

VERSION = '39e002f6aeb2379a57acc3a7dd56c2b6a610588c528b40c0848309a8654e6a0e'
BASE = 0x1AE2540
IMAGES = BASE + 0x7E10
STRINGS = BASE + 0xC004
TYPES = BASE + 0x11E8074
METHODS = BASE + 0x7533B4
FIELDS = BASE + 0xD4AD84
PARAMS = BASE + 0xE8979C
MODULES = 0xC0CFC70
OFFSETS = 0xC303F68
COUNTS = (469, 35082, 194036, 108121, 175456)
PROPERTIES = BASE + 0x68AE28
PROPERTY_COUNT = 41031

KIND = {
    1: 'void', 2: 'bool', 3: 'char', 4: 'sbyte', 5: 'byte', 6: 'short', 7: 'ushort',
    8: 'int', 9: 'uint', 10: 'long', 11: 'ulong', 12: 'float', 13: 'double',
    14: 'string', 22: 'TypedReference', 24: 'IntPtr', 25: 'UIntPtr', 28: 'object'
}

class Elf:
    def __init__(self, fn):
        self.f = open(fn, 'rb')
        self.b = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.b[:5] != b'\x7fELF\x02' or self.b[5] != 1:
            raise ValueError('Expected little-endian ELF64')
        self.ld = []
        pos = self.u64f(0x20)
        size = self.u16f(0x36)
        count = self.u16f(0x38)
        for i in range(count):
            t, flags, off, va, pa, fs, ms, align = struct.unpack_from('<IIQQQQQQ', self.b, pos + i * size)
            if t == 1:
                self.ld.append((va, off, fs, flags))
        rela = 0
        relasz = 0
        for i in range(count):
            t, flags, off, va, pa, fs, ms, align = struct.unpack_from('<IIQQQQQQ', self.b, pos + i * size)
            if t == 2:
                for j in range(0, fs, 16):
                    tag, value = struct.unpack_from('<QQ', self.b, off + j)
                    if tag == 7:
                        rela = value
                    if tag == 8:
                        relasz = value
                    if tag == 0:
                        break
        self.rd = {}
        if rela and relasz:
            foff = self.off(rela, relasz)
            for at, kind, add in struct.iter_unpack('<QQQ', self.b[foff:foff + relasz]):
                if kind & 0xffffffff == 1027:
                    self.rd[at] = add

    def off(self, a, n=1):
        for va, fo, sz, _ in self.ld:
            if va <= a and a + n <= va + sz:
                return fo + a - va
        raise ValueError('unmapped VA 0x%X' % a)

    def has(self, a, n=1):
        try:
            self.off(a,n)
            return True
        except ValueError:
            return False

    def u16f(self, a):
        return struct.unpack_from('<H', self.b, a)[0]

    def u64f(self, a):
        return struct.unpack_from('<Q', self.b, a)[0]

    def u16(self, a):
        return self.u16f(self.off(a,2))

    def i32(self, a):
        return struct.unpack_from('<i', self.b, self.off(a,4))[0]

    def u32(self, a):
        return struct.unpack_from('<I', self.b, self.off(a,4))[0]

    def u64(self, a):
        return struct.unpack_from('<Q', self.b, self.off(a,8))[0]

    def ptr(self, a):
        return self.rd[a] if a in self.rd else self.u64(a)

    def cstr(self, a, cap=2048):
        off = self.off(a)
        end = self.b.find(b'\0',off,off+cap)
        if end < 0:
            raise ValueError('unterminated string at 0x%X' % a)
        return self.b[off:end].decode('utf-8','replace')

    def code(self, a):
        return any(va <= a < va + sz and (fl & 1) for va,fo,sz,fl in self.ld)

    def close(self):
        self.b.close()
        self.f.close()

class Dump:
    def __init__(self, e):
        self.e = e
        self.strings = {}
        self.typenames = {}
        self.addrnames = {}
        self.failedtypes = set()
        self.gparams = {}
        self.typedefs = []
        self.images = []
        self.mods = {}
        self.methods = 0
        self.fields = 0
        self.rv_count = 0
        self.field_count = 0
        self.tybase = e.ptr(0xBA70CA0)
        if e.ptr(0xBA70CB8) != OFFSETS:
            raise ValueError('Invalid Huawei field offset table')
        if e.u32(0xBA70CF8) != COUNTS[1]:
            raise ValueError('Invalid type count')

    def text(self, index):
        if index < 0:
            return ''
        if index not in self.strings:
            if index > 0x3000000:
                raise ValueError('Invalid string index: %d' % index)
            self.strings[index] = self.e.cstr(STRINGS+index)
        return self.strings[index]

    def setup(self):
        e=self.e
        for i in range(COUNTS[0]):
            a=IMAGES+i*36
            start=e.u16(a+12)
            count=e.u32(a+18)
            self.images.append((self.text(e.u32(a+14)),start,count))
        if sum(v[2] for v in self.images)!=COUNTS[1]:
            raise ValueError('Image TypeDefinition ranges do not match')
        for i in range(COUNTS[1]):
            a=TYPES+i*82
            token=e.u32(a)
            if token>>24!=2:
                raise ValueError('Invalid TypeDefinition token at %d' % i)
            self.typedefs.append({
                'name':self.text(e.u32(a+60)),
                'ns':self.text(e.u32(a+68)),
                'token':token,
                'flags':e.u32(a+44),
                'bitfield':e.u32(a+36),
                'fs':e.i32(a+26),'fc':e.u16(a+24),
                'ms':e.i32(a+10),'mc':e.u16(a+78),
                'gc':e.u16(a+20),
                'pc':e.u16(a+76), 'ps':e.u32(a+32),
                'parent':e.u32(a+52), 'declaringType':e.u32(a+64)
            })
        for i, t in enumerate(self.typedefs):
            ti = t['declaringType']
            t['declaring'] = -1
            if ti < 101730:
                ptr = e.ptr(self.tybase + ti*8)
                if e.has(ptr, 12):
                    kind = ((e.u32(ptr+8) >> 16) & 255) >> 2
                    parent = e.ptr(ptr)
                    if kind in (0x11, 0x12) and parent < COUNTS[1] and parent != i:
                        t['declaring'] = parent
        if sum(x['mc'] for x in self.typedefs)!=COUNTS[2] or sum(x['fc'] for x in self.typedefs)!=COUNTS[3]:
            raise ValueError('Field/Method ownership mismatch')
        if sum(x['pc'] for x in self.typedefs) != PROPERTY_COUNT:
            raise ValueError('PropertyDefinition count mismatch')
        pp = BASE + 0x3719D0
        for i in range(5790):
            a = pp + i * 14
            num = e.u16(a + 2)
            owner = e.u16(a + 12)
            if owner >= 4110 or num > 128:
                raise ValueError('Generic metadata mismatch')
            self.gparams.setdefault(owner, []).append((num, self.text(e.u32(a + 6))))
        for k in self.gparams:
            self.gparams[k] = [v for _, v in sorted(self.gparams[k])]
        for i in range(COUNTS[0]):
            p=e.ptr(MODULES+i*8)
            if not p or not e.has(p+0x70,8):
                continue
            try:
                name=e.cstr(e.ptr(p+0x48))
                if name.endswith('.dll'):
                    self.mods[name]=(e.ptr(p),e.ptr(p+0x70))
            except (ValueError,UnicodeError):
                pass
        if len(self.mods)<450:
            raise ValueError('CodeGenModules table validation failed')

    def typefullname(self, idx, depth=0):
        if idx < 0 or idx >= len(self.typedefs):
            return 'Il2CppUnknown'
        t = self.typedefs[idx]
        simple = t['name']
        owner = t.get('declaring', -1)
        if depth < 16 and owner >= 0:
            return self.typefullname(owner, depth+1) + '.' + simple
        return ((t['ns'] + '.') if t['ns'] else '') + simple

    def typename(self, idx, level=0):
        if idx < 0:
            return 'void'
        if idx in self.typenames:
            return self.typenames[idx]
        if idx >= 101730:
            return 'Il2CppType_%X' % idx
        a = self.e.ptr(self.tybase + idx * 8)
        value = self.typename_addr(a, level)
        self.typenames[idx] = value
        return value

    def typename_addr(self, addr, level=0):
        if addr in self.addrnames:
            return self.addrnames[addr]
        if level > 16 or not addr or not self.e.has(addr, 12):
            self.failedtypes.add(addr)
            return 'Il2CppUnknown'
        e = self.e
        data = e.ptr(addr)
        bits = e.u32(addr + 8)
        kind = ((bits >> 16) & 255) >> 2
        if kind in KIND:
            result = KIND[kind]
        elif kind in (0x11, 0x12):
            if 0 <= data < len(self.typedefs):
                t = self.typedefs[data]
                result = self.typefullname(data)
            else:
                self.failedtypes.add(addr)
                result = 'Il2CppUnknown'
        elif kind == 0x0f:
            result = self.typename_addr(data, level + 1) + '*'
        elif kind == 0x10:
            result = self.typename_addr(data, level + 1) + '&'
        elif kind == 0x1d:
            result = self.typename_addr(data, level + 1) + '[]'
        elif kind == 0x14:
            if e.has(data, 16):
                el = e.ptr(data + 16)
                rank = (e.u32(data + 32) >> 8) & 255
                result = self.typename_addr(el, level + 1) + '[' + ',' * (max(1, min(rank, 32)) - 1) + ']'
            else:
                self.failedtypes.add(addr)
                result = 'Il2CppUnknown[]'
        elif kind == 0x15:
            if e.has(data, 32):
                base = e.ptr(data + 24)
                inst = e.ptr(data + 8)
                result = self.typename_addr(base, level + 1)
                result = re.sub(r'`[0-9]+$', '', result)
                if e.has(inst, 16):
                    count = e.u32(inst)
                    args = e.ptr(inst + 8)
                    if 0 < count <= 128 and e.has(args, count * 8):
                        names = [self.typename_addr(e.ptr(args + j * 8), level + 1) for j in range(count)]
                        result = result + '<' + ', '.join(names) + '>'
                    else:
                        self.failedtypes.add(addr)
                else:
                    self.failedtypes.add(addr)
            else:
                self.failedtypes.add(addr)
                result = 'Il2CppUnknown'
        elif kind in (0x13, 0x1e):
            result = self.text(e.u32(BASE + 0x3719D0 + data * 14 + 6)) if data < 5790 else 'Il2CppUnknown'
        elif kind == 0x1b:
            result = 'IntPtr'
        else:
            self.failedtypes.add(addr)
            result = 'Il2CppUnknown'
        if bits & 0x20000000:
            result += '&'
        self.addrnames[addr] = result
        return result

    def fieldoffset(self, ti, ix, count):
        if count==0:
            return None
        e=self.e
        p=e.ptr(OFFSETS+ti*8)
        if not p or not e.has(p+4*count,1):
            return None
        n=e.i32(p+4*ix)
        if n<0 or n>0x1000000:
            return None
        self.field_count+=1
        return n

    def method(self, i, mod, record_stats=True):
        e=self.e
        a=METHODS+i*32
        token=e.u32(a+14)
        if token>>24!=6:
            raise ValueError('Invalid MethodDefinition token at %d'%i)
        rid=token&0xffffff
        rv=0
        if mod is not None:
            base,method_count=mod
            if 0<rid<=method_count:
                rv=e.ptr(base+(rid-1)*8) if base and e.has(base+(rid-1)*8,8) else 0
                if not e.code(rv):
                    rv=0
        if rv and record_stats:
            self.rv_count+=1
        start=e.i32(a+6)
        n=e.u16(a)
        if start<0 and n!=0 or start+n>COUNTS[4]:
            raise ValueError('Method parameters out of range')
        parms=[]
        for k in range(n):
            pa=PARAMS+(start+k)*12
            pt=e.u32(pa+8)
            pn=self.text(e.u32(pa+4))
            parms.append((self.typename(pt),pn or 'p'+str(k)))
        return {
            'name':self.text(e.u32(a+10)),
            'token':token,
            'rtype':self.typename(e.u32(a+2)),
            'params':parms,
            'flags':e.u16(a+22),
            'gc':e.u16(a+24),
            'rva':rv,
            'offset':e.off(rv) if rv else 0
        }

    def property(self, typeinfo, index):
        e=self.e
        a=PROPERTIES+index*20
        setter=e.i32(a)
        name=self.text(e.u32(a+4))
        attrs=e.u32(a+8)
        getter=e.i32(a+12)
        token=e.u32(a+16)
        if token>>24 != 0x17:
            raise ValueError('Invalid PropertyDefinition token at %d'%index)
        if getter < -1 or getter >= typeinfo['mc']:
            raise ValueError('Invalid property getter index at %d'%index)
        if setter < -1 or setter >= typeinfo['mc']:
            raise ValueError('Invalid property setter index at %d'%index)
        return {'name':name,'get':getter,'set':setter,'flags':attrs,'token':token}

    def struct_header(self, out):
        e = self.e
        num = 0
        def ident(s):
            s = re.sub(r'[^a-zA-Z0-9_]', '_', s)
            return ('_' + s if s and s[0].isdigit() else s) or '_'
        with (out / 'il2cpp.h').open('w', encoding='utf-8', newline='\n') as w:
            w.write('#pragma once\n#include <stdint.h>\n#pragma pack(push,1)\n')
            for i, t in enumerate(self.typedefs):
                if not t['fc']:
                    continue
                members = []
                for j in range(t['fc']):
                    idx = t['fs'] + j
                    if idx < 0 or idx >= COUNTS[3]:
                        continue
                    ofs = self.fieldoffset_read(i,j,t['fc'])
                    if ofs is None or ofs < (0 if t['bitfield'] & 1 else 16) or ofs > 0x20000:
                        continue
                    a = FIELDS + 12 * idx
                    members.append((ofs,self.text(e.u32(a))))
                if not members:
                    continue
                members.sort(key=lambda x:(x[0],x[1]))
                u=[]
                seen=set()
                for ofs,name in members:
                    if ofs not in seen:
                        u.append((ofs,name))
                        seen.add(ofs)
                w.write('struct ' + ident(t['ns']+'_'+t['name'])+'_'+str(i)+' {\n')
                current=0
                for j,(ofs,name) in enumerate(u):
                    if ofs>current:
                        w.write('    uint8_t pad_'+format(current,'X')+'['+str(ofs-current)+'];\n')
                    nxt = u[j+1][0] if j+1<len(u) else ofs+8
                    width=max(1, nxt-ofs)
                    w.write('    uint8_t '+ident(name)+'_'+format(ofs,'X')+'['+str(width)+'];\n')
                    current=ofs+width
                w.write('};\n')
                num+=1
            w.write('#pragma pack(pop)\n')
        return num

    def fieldoffset_read(self, ti, ix, count):
        if count == 0:
            return None
        e = self.e
        p = e.ptr(OFFSETS + ti*8)
        if not p or not e.has(p + 4*count,1):
            return None
        v = e.i32(p+4*ix)
        return v if 0<=v<=0x1000000 else None

    def run(self,out,binary, header=False, wm=None, manifest=False):
        self.setup()
        print('[Huawei] metadata and CodeGenModules validated', flush=True)
        out.mkdir(parents=True,exist_ok=True)
        e=self.e
        fp=out/'dump.cs'
        sp=out/'script.json'
        cur=0
        scripts=0
        mf = (out / 'huawei.manifest.jsonl').open('w', encoding='utf-8', newline='\n') if manifest else None
        with fp.open('w',encoding='utf-8',newline='\n') as w, sp.open('w',encoding='utf-8',newline='\n') as sj:
            sj.write('{"ScriptMethod":[')
            if wm and wm.get('Fingerprint'):
                w.write('// '+wm.get('Brand','axent.cc')+' | '+wm['Fingerprint'].replace('-','')[:8]+'\n')
            for i,(name,start,count) in enumerate(self.images):
                w.write(f'// Image {i}: {name} - {start}\n')
            for image_num,(im,start,count) in enumerate(self.images):
                if image_num % 50 == 0:
                    print(f'[Huawei] image {image_num+1}/{len(self.images)}, methods={self.methods}, fields={self.fields}', flush=True)
                if mf:
                    mf.write(json.dumps({'image': im}, ensure_ascii=False, separators=(',', ':')) + '\n')
                mod=self.mods.get(im)
                for tid in range(start,start+count):
                    t=self.typedefs[tid]
                    w.write('\n// Namespace: '+t['ns']+'\n')
                    f=t['flags']
                    public='public ' if f&7 in (1,2) else 'internal '
                    typ='interface' if f&0x20 else 'enum' if t['bitfield']&2 else 'struct' if t['bitfield']&1 else 'class'
                    gcname = self.gparams.get(t['gc'], []) if t['gc'] != 65535 else []
                    nested = t.get('declaring', -1)
                    rootname = self.typefullname(nested).split('.')[-1] + '.' if nested >= 0 else ''
                    cn = rootname + re.sub(r'`[0-9]+$', '', t['name'])
                    if gcname:
                        cn += '<' + ', '.join(gcname) + '>'
                    parent = None if t['parent'] == 0xFFFFFFFF else self.typename(t['parent'])
                    ancestor = (' : '+parent) if parent and parent not in ('object','System.ValueType','System.Enum') and typ=='class' else ''
                    w.write(f"{public}{typ} {cn}{ancestor} // TypeDefIndex: {tid}\n{{\n")
                    dfields = [] if mf else None
                    dmethods = [] if mf else None
                    dproperties = [] if mf else None
                    props=[]
                    if t['pc']:
                        if t['ps'] + t['pc'] > PROPERTY_COUNT:
                            raise ValueError('PropertyDefinition index out of range')
                        props = [self.property(t, t['ps']+ix) for ix in range(t['pc'])]
                    w.write('\t// Fields\n')
                    for ix in range(t['fc']):
                        idx=t['fs']+ix
                        a=FIELDS+idx*12
                        if idx>=COUNTS[3] or idx<0:
                            raise ValueError('FieldDefinition index out of range')
                        type_index=e.u32(a+4)
                        ty=self.typename(type_index)
                        tb=e.ptr(self.tybase+type_index*8) if type_index<101730 else 0
                        attrs=e.u32(tb+8)&65535 if tb else 0
                        access='public ' if attrs&7==6 else 'protected ' if attrs&7 in (4,5) else 'private '
                        mods=('static ' if attrs&0x10 else '')+('readonly ' if attrs&0x20 else '')
                        name=self.text(e.u32(a))
                        off=self.fieldoffset(tid,ix,t['fc'])
                        suffix=f' // 0x{off:X}' if off is not None else ' // Offset: unavailable'
                        w.write(f'\t{access}{mods}{ty} {name};{suffix}\n')
                        self.fields+=1
                        if mf:
                            dfields.append({'name': name, 'type': ty, 'flags': attrs, 'offset': off})
                    if props:
                        w.write('\n\t// Properties\n')
                        for prop in props:
                            gi=prop['get']
                            si=prop['set']
                            if gi >= 0:
                                getter=self.method(t['ms']+gi, mod, False)
                                ptype=getter['rtype']
                            elif si >= 0:
                                setter=self.method(t['ms']+si, mod, False)
                                ptype=setter['params'][0][0] if setter['params'] else 'object'
                            else:
                                ptype='object'
                            tags=(' get;' if gi >= 0 else '')+(' set;' if si >= 0 else '')
                            w.write(f"\t{ptype} {prop['name']} {{{tags} }}\n")
                            if mf:
                                dproperties.append(dict(prop))
                    w.write('\n\t// Methods\n')
                    for ix in range(t['mc']):
                        method=self.method(t['ms']+ix,mod)
                        mname = method['name']
                        gcname = self.gparams.get(method['gc'], []) if method['gc'] != 65535 else []
                        if gcname:
                            mname += '<' + ', '.join(gcname) + '>'
                        attr = method['flags']
                        access = 'public ' if attr & 7 == 6 else 'protected ' if attr & 7 in (4, 5) else 'internal ' if attr & 7 == 3 else 'private '
                        modtext = 'static ' if attr & 0x10 else 'abstract ' if attr & 0x400 else 'virtual ' if attr & 0x40 else ''
                        sig = access + modtext + method['rtype'] + ' ' + mname + '(' + ', '.join(a+' '+b for a,b in method['params']) + ')'
                        addr=method['rva']
                        off=method['offset']
                        w.write(f'\n\t// RVA: 0x{addr:X} Offset: 0x{off:X} VA: 0x{addr:X}\n\t{sig} {{ }}\n')
                        if addr:
                            fullname=(t['ns']+'.' if t['ns'] else '')+t['name']+'$$'+method['name']
                            js={'Address':addr,'Name':fullname,'Signature':sig,'TypeSignature':''}
                            if scripts:
                                sj.write(',')
                            sj.write(json.dumps(js,ensure_ascii=False,separators=(',',':')))
                            scripts+=1
                        self.methods+=1
                        if mf:
                            g = method['gc']
                            dmethods.append({'name': method['name'], 'return': method['rtype'], 'params': method['params'], 'flags': method['flags'], 'generic': self.gparams.get(g, []) if g != 65535 else []})
                    w.write('}\n')
                    if mf:
                        g = t['gc']
                        obj = {'type': {'index': tid, 'namespace': t['ns'], 'name': t['name'], 'flags': t['flags'], 'bitfield': t['bitfield'], 'base': parent, 'fullName': self.typefullname(tid), 'declaring': nested, 'declaringFullName': self.typefullname(nested) if nested >= 0 else None, 'generic': self.gparams.get(g, []) if g != 65535 else []}, 'fields': dfields, 'methods': dmethods, 'properties': dproperties}
                        mf.write(json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n')
            sj.write('],"ScriptString":[],"ScriptMetadata":[],"ScriptMetadataMethod":[],"Addresses":[]')
            if wm:
                sj.write(',"Watermark":'+json.dumps(wm,ensure_ascii=False,separators=(',',':')))
            sj.write('}\n')
        if mf:
            mf.close()
        print('[Huawei] dump.cs/script.json written', flush=True)
        structs=self.struct_header(out) if header else 0
        if header: print('[Huawei] il2cpp.h written', flush=True)
        meta={
            'source':str(binary.name),
            'sha256':VERSION,
            'images':len(self.images),
            'types':len(self.typedefs),
            'methods':self.methods,
            'methodsWithRva':self.rv_count,
            'fields':self.fields,
            'fieldsWithRuntimeOffset':self.field_count,
            'scriptMethods':scripts,
            'properties':PROPERTY_COUNT,
            'typeNameFallbacks':len(self.failedtypes),
            'dummyDll':False,
            'structs':structs,
            'source':'Runtime field offset table and CodeGenModules from ELF'
        }
        (out/'dump.info.json').write_text(json.dumps(meta,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        return meta

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('lib',type=Path)
    ap.add_argument('-o','--out',type=Path,required=True)
    ap.add_argument('--structs',action='store_true')
    ap.add_argument('--dummy-manifest',action='store_true')
    ap.add_argument('--wm',type=Path)
    args=ap.parse_args()
    sha=hashlib.sha256()
    with args.lib.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):
            sha.update(b)
    got=sha.hexdigest()
    if got!=VERSION:
        raise ValueError('Huawei build not supported: '+got)
    print('[Huawei] sha256 verified', flush=True)
    elf=Elf(args.lib)
    try:
        wm=json.loads(args.wm.read_text(encoding='utf-8')) if args.wm else None
        o=Dump(elf).run(args.out,args.lib,args.structs,wm,args.dummy_manifest)
        print(json.dumps(o,ensure_ascii=False))
    finally:
        elf.close()

if __name__=='__main__':
    main()
