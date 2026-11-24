"""Automatic layout recovery for protected IL2CPP v31 libunity.so builds.

Nothing in this module is tied to a particular build.  Every address, header
field position, record field permutation and runtime structure permutation is
recovered from the binary itself:

* roots (metadata blob, CodeRegistration, MetadataRegistration) are followed
  through code cross references starting at the "global-metadata.dat" string;
* the shuffled metadata header is decoded by tiling its offset/size fields;
* every metadata record layout is solved from column semantics (string heap
  indices, tokens, range tables that tile their target tables, ...);
* runtime structures are solved from pointer semantics.
"""
from __future__ import annotations

import itertools
import struct
from typing import Optional

import numpy as np


class ProfileError(ValueError):
    pass


# ---------------------------------------------------------------------------
# AArch64 helpers
# ---------------------------------------------------------------------------

def _sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def decode(insn: int, pc: int):
    """Decode the handful of AArch64 forms used by the runtime accessors."""
    if (insn & 0x9F000000) == 0x90000000:
        imm = _sx((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21) << 12
        return ('adrp', insn & 31, (pc & ~0xFFF) + imm)
    if (insn & 0x9F000000) == 0x10000000:
        imm = _sx((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21)
        return ('adr', insn & 31, pc + imm)
    if (insn & 0x7F800000) == 0x11000000 and not (insn >> 29) & 1:
        imm = (insn >> 10) & 0xFFF
        if (insn >> 22) & 1:
            imm <<= 12
        return ('addi', insn & 31, (insn >> 5) & 31, imm)
    if (insn & 0x7FE0FFE0) == 0x2A0003E0:
        return ('mov', insn & 31, (insn >> 16) & 31)
    if (insn & 0xFC000000) == 0x94000000:
        return ('bl', pc + (_sx(insn & 0x3FFFFFF, 26) << 2))
    if (insn & 0xFC000000) == 0x14000000:
        return ('b', pc + (_sx(insn & 0x3FFFFFF, 26) << 2))
    if insn == 0xD65F03C0:
        return ('ret',)
    if (insn & 0x3B000000) == 0x39000000 and not (insn >> 26) & 1:
        size = insn >> 30
        opc = (insn >> 22) & 3
        imm = ((insn >> 10) & 0xFFF) << size
        rt, rn = insn & 31, (insn >> 5) & 31
        if opc == 0:
            return ('str', rt, rn, imm, 1 << size)
        return ('ldr', rt, rn, imm, 1 << size, opc >= 2)
    if (insn & 0x3B200C00) == 0x38000000 and not (insn >> 26) & 1:
        size = insn >> 30
        opc = (insn >> 22) & 3
        imm = _sx((insn >> 12) & 0x1FF, 9)
        rt, rn = insn & 31, (insn >> 5) & 31
        if opc == 0:
            return ('str', rt, rn, imm, 1 << size)
        return ('ldr', rt, rn, imm, 1 << size, opc >= 2)
    if (insn & 0x7FC00000) == 0x29400000:
        size = 8 if insn >> 31 else 4
        imm = _sx((insn >> 15) & 0x7F, 7) * size
        return ('ldp', insn & 31, (insn >> 10) & 31, (insn >> 5) & 31, imm, size)
    if (insn & 0x7FE0FC00) == 0x1AC00C00:
        return ('sdiv', insn & 31, (insn >> 5) & 31, (insn >> 16) & 31)
    if (insn & 0x7F800000) == 0x53000000:
        immr, imms = (insn >> 16) & 0x3F, (insn >> 10) & 0x3F
        if imms >= immr:
            return ('ubfx', insn & 31, (insn >> 5) & 31, immr, imms - immr + 1)
    return None


class Code:
    def __init__(self, elf):
        self.elf = elf
        self.segments = []
        for vaddr, off, filesz, _, flags in elf.loads:
            if flags & 1 and filesz:
                words = np.frombuffer(elf.data, dtype='<u4', count=filesz // 4, offset=off)
                self.segments.append((vaddr, words))

    def insn(self, pc: int) -> int:
        return self.elf.u32(pc)

    def window(self, pc: int, count: int):
        for i in range(count):
            yield pc + i * 4, decode(self.insn(pc + i * 4), pc + i * 4)

    def adrp_add_refs(self, target: int) -> list[int]:
        out = []
        page = target & ~0xFFF
        lo = target & 0xFFF
        for vaddr, w in self.segments:
            idx = np.nonzero((w & 0x9F000000) == 0x90000000)[0]
            if not len(idx):
                continue
            ins = w[idx].astype(np.int64)
            imm = (((ins >> 5) & 0x7FFFF) << 2) | ((ins >> 29) & 3)
            imm = np.where(imm & (1 << 20), imm - (1 << 21), imm) << 12
            pcs = vaddr + idx.astype(np.int64) * 4
            hit = idx[((pcs & ~0xFFF) + imm) == page]
            for i in hit:
                rd = int(w[i]) & 31
                for j in range(1, 4):
                    if i + j >= len(w):
                        break
                    d = decode(int(w[i + j]), vaddr + (i + j) * 4)
                    if d and d[0] == 'addi' and d[2] == rd and d[3] == lo:
                        out.append(vaddr + int(i) * 4)
                        break
        return out

    def branch_refs(self, target: int) -> list[int]:
        out = []
        for vaddr, w in self.segments:
            op = w >> 26
            idx = np.nonzero((op == 0x25) | (op == 0x05))[0]
            imm = (w[idx] & 0x3FFFFFF).astype(np.int64)
            imm = np.where(imm & (1 << 25), imm - (1 << 26), imm)
            pcs = vaddr + idx.astype(np.int64) * 4
            out.extend(int(x) for x in pcs[pcs + imm * 4 == target])
        return out

    def stores_to(self, target: int, reg: int) -> list[int]:
        """Sites of `adrp xN, page ... str <reg>, [xN, #lo]`."""
        out = []
        lo = target & 0xFFF
        if lo % 8:
            return out
        for vaddr, w in self.segments:
            want = 0xF9000000 | ((lo // 8) << 10) | reg
            idx = np.nonzero((w & 0xFFFFFC1F) == want)[0]
            for i in idx:
                rn = (int(w[i]) >> 5) & 31
                for j in range(1, 8):
                    if i - j < 0:
                        break
                    d = decode(int(w[i - j]), vaddr + (i - j) * 4)
                    if d and d[0] == 'adrp' and d[1] == rn:
                        if d[2] == target & ~0xFFF:
                            out.append(vaddr + int(i) * 4)
                        break
        return out

    def function_start(self, pc: int, limit: int = 4096) -> int:
        for i in range(1, limit):
            d = decode(self.insn(pc - i * 4), pc - i * 4)
            if d and d[0] in ('ret', 'b'):
                return pc - (i - 1) * 4
        return pc


class Emu:
    """Straight-line symbolic register tracker."""

    def __init__(self, elf):
        self.elf = elf
        self.regs: dict[int, tuple] = {}

    def get(self, r):
        return self.regs.get(r)

    def step(self, d):
        if d is None:
            return
        op = d[0]
        if op == 'adrp' or op == 'adr':
            self.regs[d[1]] = ('const', d[2])
        elif op == 'addi':
            src = self.regs.get(d[2])
            if src and src[0] == 'const':
                self.regs[d[1]] = ('const', src[1] + d[3])
            else:
                self.regs.pop(d[1], None)
        elif op == 'mov':
            if d[2] == 31:
                self.regs[d[1]] = ('const', 0)
            elif d[2] in self.regs:
                self.regs[d[1]] = self.regs[d[2]]
            else:
                self.regs.pop(d[1], None)
        elif op == 'ldr':
            _, rt, rn, imm, size, _signed = d
            base = self.regs.get(rn)
            if base and base[0] == 'const' and size == 8:
                self.regs[rt] = ('global', base[1] + imm)
            elif base:
                self.regs[rt] = ('field', base, imm, size)
            else:
                self.regs.pop(rt, None)
        elif op == 'ldp':
            _, rt, rt2, rn, imm, size = d
            base = self.regs.get(rn)
            for r, o in ((rt, imm), (rt2, imm + size)):
                if base:
                    self.regs[r] = ('field', base, o, size)
                else:
                    self.regs.pop(r, None)
        elif op == 'sdiv':
            a, b = self.regs.get(d[2]), self.regs.get(d[3])
            self.regs[d[1]] = ('div', a, b) if a and b else None
        elif op == 'ubfx':
            src = self.regs.get(d[2])
            self.regs[d[1]] = ('bits', src, d[3], d[4]) if src else None
        elif op in ('bl',):
            for r in range(0, 19):
                self.regs.pop(r, None)
            self.regs[0] = ('ret', d[1])


# ---------------------------------------------------------------------------
# Roots
# ---------------------------------------------------------------------------

def _find_cstring_vas(elf, needle: bytes) -> list[int]:
    out = []
    start = 0
    while True:
        off = elf.data.find(needle, start)
        if off < 0:
            return out
        for vaddr, poff, filesz, _, _ in elf.loads:
            if poff <= off < poff + filesz:
                out.append(vaddr + off - poff)
        start = off + 1


def _resolve_loader(elf, code: Code, func: int) -> Optional[int]:
    emu = Emu(elf)
    for pc, d in code.window(func, 24):
        if d and d[0] == 'ldr' and d[1] == 0 and d[4] == 8:
            base = emu.get(d[2])
            if base and base[0] == 'const':
                return elf.u64(base[1] + d[3])
        if d and d[0] == 'ret':
            reg = emu.get(0)
            if reg and reg[0] == 'global':
                return elf.u64(reg[1])
            return None
        emu.step(d)
    return None


def _trace_initialize(elf, code: Code, site: int) -> dict:
    """Follow GlobalMetadata::Initialize from its string reference."""
    emu = Emu(elf)
    info = {'site': site, 'header_reads': [], 'calls': [], 'globals': {}}
    loader = None
    callbacks = []
    for pc, d in code.window(site, 160):
        if d is None:
            continue
        if d[0] == 'bl' and loader is None:
            loader = d[1]
            emu.step(d)
            emu.regs[0] = ('hdr',)
            continue
        if d[0] == 'str' and d[4] == 8 and loader is not None:
            src = emu.get(d[1])
            base = emu.get(d[2])
            if src == ('hdr',) and base and base[0] == 'const':
                info['globals'].setdefault('header', []).append(base[1] + d[3])
        if d[0] == 'ldr' and loader is not None:
            base = emu.get(d[2])
            if base and base[0] == 'const' and d[4] == 8 and base[1] + d[3] in info['globals'].get('header', ()):
                emu.regs[d[1]] = ('hdr',)
                continue
            if base == ('hdr',) and d[4] == 4:
                info['header_reads'].append((pc, d[3]))
        if d[0] == 'bl' and loader is not None:
            args = [emu.get(r) for r in range(3)]
            info['calls'].append((pc, d[1], args))
        if d[0] == 'adr':
            callbacks.append(d[2])
        emu.step(d)
        if d[0] == 'ret':
            break
    info['loader'] = loader
    info['callbacks'] = callbacks
    return info


def find_roots(elf, code: Optional[Code] = None) -> dict:
    code = code or Code(elf)
    strings = _find_cstring_vas(elf, b'global-metadata.dat\0')
    if not strings:
        raise ProfileError('"global-metadata.dat" string is missing')
    refs = [r for s in strings for r in code.adrp_add_refs(s)]
    if not refs:
        raise ProfileError('No code reference to "global-metadata.dat"')
    for ref in refs:
        init = _trace_initialize(elf, code, ref)
        if not init['loader']:
            continue
        base = _resolve_loader(elf, code, init['loader'])
        if base is None:
            continue
        mr_global = None
        width_func = None
        for pc, target, args in init['calls']:
            a0 = args[0]
            if a0 and a0[0] == 'field' and a0[1] and a0[1][0] == 'global':
                mr_global = a0[1][1]
                width_func = target
                init['mr_types_count_field'] = a0[2]
                break
        if mr_global is None:
            continue
        init['width_func'] = width_func
        init['width_args'] = [args[0] for pc, t, args in init['calls'] if t == width_func]
        roots = {'metadata_va': base, 'initialize': init, 'mr_global': mr_global}
        roots.update(_find_registrations(elf, code, mr_global))
        return roots
    raise ProfileError('Unable to follow GlobalMetadata::Initialize')


def _find_registrations(elf, code: Code, mr_global: int) -> dict:
    for store in code.stores_to(mr_global, 1):
        func = code.function_start(store)
        cr_global = None
        for pc, d in code.window(func, (store - func) // 4 + 8):
            if d and d[0] == 'str' and d[1] == 0 and d[4] == 8:
                prev = Emu(elf)
                for ppc, pd in code.window(max(func, pc - 32), (pc - max(func, pc - 32)) // 4):
                    prev.step(pd)
                base = prev.get(d[2])
                if base and base[0] == 'const':
                    cr_global = base[1] + d[3]
        found = _resolve_register_args(elf, code, func, depth=0, seen=set())
        if found:
            cr, mr = found
            return {'code_registration': cr, 'metadata_registration': mr,
                    'register_func': func, 'cr_global': cr_global}
    raise ProfileError('Unable to locate il2cpp_codegen_register call')


def _resolve_register_args(elf, code: Code, func: int, depth: int, seen: set):
    if depth > 6 or func in seen:
        return None
    seen.add(func)
    for site in code.branch_refs(func):
        start = max(site - 48, 0)
        emu = Emu(elf)
        for pc, d in code.window(start, (site - start) // 4):
            emu.step(d)
        x0, x1 = emu.get(0), emu.get(1)

        def value(reg):
            if reg and reg[0] == 'const':
                return reg[1]
            if reg and reg[0] == 'global':
                return elf.u64(reg[1])
            return None

        cr, mr = value(x0), value(x1)
        if cr and mr:
            return cr, mr
        caller = code.function_start(site)
        found = _resolve_register_args(elf, code, caller, depth + 1, seen)
        if found:
            return found
    return None


def _trace_handle_callback(elf, code: Code, func: int, header_globals) -> Optional[dict]:
    """InitializeTypeHandle / InitializeGenericParameterHandle: offset+size/count*index."""
    emu = Emu(elf)
    result = {}
    for pc, d in code.window(func, 32):
        if d is None:
            continue
        if d[0] == 'ldr':
            base = emu.get(d[2])
            if base and base[0] == 'const' and d[4] == 8 and base[1] + d[3] in header_globals:
                emu.regs[d[1]] = ('hdr',)
                continue
            if base == ('hdr',) and d[4] == 4 and d[5]:
                result['offset'] = d[3]
        if d[0] == 'sdiv':
            a, b = emu.get(d[2]), emu.get(d[3])
            if a and b and a[0] == 'field' and b[0] == 'field' and a[1] == ('hdr',) and b[1] == ('hdr',):
                result['size'] = a[2]
                result['count'] = b[2]
        emu.step(d)
        if d[0] == 'ret':
            break
    return result if len(result) == 3 else None


def _trace_process_types(elf, code: Code, func: int, mr_global: int) -> dict:
    """ProcessIl2CppTypeDefinitions: MR.types/typesCount and the Il2CppType kind bitfield."""
    emu = Emu(elf)
    out = {}
    pending = None
    for pc, d in code.window(func, 64):
        if d is None:
            continue
        if d[0] == 'ldr':
            base = emu.get(d[2])
            if base == ('global', mr_global):
                if d[4] == 4:
                    out.setdefault('types_count_field', d[3])
                elif d[4] == 8:
                    out.setdefault('types_field', d[3])
            elif pending is None and 'types_field' in out and d[2] == 0 and d[4] in (1, 2, 4):
                pending = (d[1], d[3], d[4])
                out['kind'] = (d[3], 0, 8 * d[4]) if d[4] == 1 else None
        elif d[0] == 'ubfx' and pending and d[2] == pending[0]:
            out['kind'] = (pending[1], d[3], d[4])
            break
        elif pending and out.get('kind'):
            break
        emu.step(d)
    if 'kind' not in out or out['kind'] is None:
        raise ProfileError('Unable to recover Il2CppType kind bitfield from ProcessIl2CppTypeDefinitions')
    return out


def code_anchors(elf, code: Code, roots: dict) -> dict:
    init = roots['initialize']
    hdr_globals = set(init['globals'].get('header', ()))
    out = {}
    process = None
    cbs = []
    for pc, target, args in init['calls']:
        if args[0] and args[0][0] == 'const' and args[1] and args[1][0] == 'const':
            process = target
            cbs = [args[0][1], args[1][1]]
    if process is None:
        raise ProfileError('ProcessIl2CppTypeDefinitions call not found')
    out['type_definitions'] = _trace_handle_callback(elf, code, cbs[0], hdr_globals)
    out['generic_parameters'] = _trace_handle_callback(elf, code, cbs[1], hdr_globals)
    out.update(_trace_process_types(elf, code, process, roots['mr_global']))
    reads = [off for _, off in init['header_reads']]
    out['images_count_field'] = reads[0] if reads else None
    out['width_count_fields'] = [a[2] if a and a[0] == 'field' else None for a in init['width_args']]
    return out


# ---------------------------------------------------------------------------
# Header: section tiling
# ---------------------------------------------------------------------------

STRIDES = (1, 2, 4, 8, 12, 14, 16, 20, 24, 28, 32, 36, 40, 48, 64, 82)
MAX_BLOB = 0x10000000


def _header_size(values: dict[int, int]) -> int:
    for v in sorted(set(values.values())):
        if 0x40 <= v <= 0x800 and v % 4 == 0 and any(p < v for p, x in values.items() if x == v):
            return v
    raise ProfileError('Unable to determine protected metadata header size')


def solve_header_sections(elf, base: int, probe: int = 0x800) -> dict:
    raw = elf.read(base, probe)
    first = {i: struct.unpack_from('<I', raw, i)[0] for i in range(0, probe, 4)}
    hsize = _header_size(first)
    values = {p: v for p, v in first.items() if p < hsize}
    byval: dict[int, list[int]] = {}
    for p, v in values.items():
        byval.setdefault(v, []).append(p)
    nodes = sorted(v for v in byval if hsize <= v < MAX_BLOB)
    index = {v: i for i, v in enumerate(nodes)}
    edges: list[list[tuple]] = [[] for _ in nodes]
    for i, o in enumerate(nodes):
        for j in range(i + 1, len(nodes)):
            d = nodes[j] - o
            for pad in range(8):
                s = d - pad
                if s <= 0:
                    break
                for p in byval.get(s, ()):
                    edges[i].append((j, (3.0 if pad < 4 else 2.0) - pad * 0.01, ('size', p, s, pad)))
                for st in STRIDES[1:]:
                    if s % st == 0:
                        for p in byval.get(s // st, ()):
                            edges[i].append((j, (2.0 if pad == 0 else 0.5) - pad * 0.01, ('count', p, s // st, st, pad)))
        if i + 1 < len(nodes):
            edges[i].append((i + 1, -5.0, ('gap',)))
    start = index.get(hsize)
    if start is None:
        raise ProfileError('Header does not reference its first section')
    banned: set[int] = set()
    for _ in range(64):
        best = [(0.0, None, None)] * len(nodes)
        for i in range(len(nodes) - 1, -1, -1):
            b = (0.0, None, None)
            for j, w, info in edges[i]:
                if info[0] != 'gap' and info[1] in banned:
                    continue
                score = best[j][0] + w
                if score > b[0]:
                    b = (score, j, info)
            best[i] = b
        path = []
        i = start
        while i is not None:
            path.append(i)
            i = best[i][1]
        offset_positions = {p for i in path for p in byval[nodes[i]]}
        conflicts = {best[i][2][1] for i in path
                     if best[i][2] and best[i][2][0] != 'gap' and best[i][2][1] in offset_positions
                     and len(byval[nodes[i]]) and best[i][2][1] not in byval[nodes[i]]}
        if not conflicts - banned:
            break
        banned |= conflicts
    sections = []
    i = start
    while i is not None:
        _, j, info = best[i]
        sec = {'start': nodes[i], 'offset_fields': list(byval[nodes[i]]),
               'end': nodes[j] if j is not None else None, 'link': info}
        if info and info[0] == 'size':
            sec['size'] = info[2]
            sec['size_field'] = info[1]
        elif info and info[0] == 'count':
            sec['size'] = info[2] * info[3]
            sec['count_field'] = info[1]
            sec['stride'] = info[3]
        sections.append(sec)
        i = j
    used = set()
    for sec in sections:
        for k in ('size_field', 'count_field'):
            if k in sec:
                used.add(sec[k])
    for sec in sections:
        if len(sec['offset_fields']) > 1:
            free = [p for p in sec['offset_fields'] if p not in used]
            sec['offset_fields'] = free or sec['offset_fields']
        sec['offset_field'] = sec['offset_fields'][0]
        used.add(sec['offset_field'])
    return {'header_size': hsize, 'values': values, 'sections': sections, 'used': used}


# ---------------------------------------------------------------------------
# Record column solver
# ---------------------------------------------------------------------------

def index_width(count: int) -> int:
    return 1 if count < 0x100 else 2 if count < 0x10000 else 4


class Tbl:
    def __init__(self, raw: bytes, stride: int):
        self.S = stride
        self.n = len(raw) // stride
        self.b = np.frombuffer(raw, np.uint8, count=self.n * stride).reshape(self.n, stride)
        self._cache = {}

    def u(self, off: int, w: int) -> np.ndarray:
        key = (off, w)
        v = self._cache.get(key)
        if v is None:
            cols = self.b[:, off:off + w].astype(np.int64)
            v = np.zeros(self.n, np.int64)
            for k in range(w):
                v |= cols[:, k] << (8 * k)
            self._cache[key] = v
        return v

    def s(self, off: int, w: int) -> np.ndarray:
        v = self.u(off, w)
        if w == 4:
            return np.where(v >= 1 << 31, v - (1 << 32), v)
        return np.where(v == (1 << (8 * w)) - 1, -1, v)

    def cols(self, w: int):
        return range(0, self.S - w + 1)


def frac(mask) -> float:
    return float(np.mean(mask)) if len(mask) else 0.0


def tiles(start: np.ndarray, count: np.ndarray, total: Optional[int] = None) -> bool:
    m = count > 0
    if not m.any():
        return total == 0
    s, c = start[m], count[m]
    t = int(c.sum())
    if total is not None and t != total:
        return False
    if s.min() != 0 or int((s + c).max()) != t:
        return False
    o = np.argsort(s, kind='stable')
    s, c = s[o], c[o]
    return bool(np.all(s[1:] == s[:-1] + c[:-1]))


def range_pairs(t: Tbl, start_ws=(4,), count_ws=(2, 4), min_total: int = 1) -> list[tuple]:
    out = []
    for cw in count_ws:
        for co in t.cols(cw):
            c = t.u(co, cw)
            if cw == 4 and c.max() >= 1 << 24:
                continue
            total = int(c.sum())
            if total < min_total:
                continue
            for sw in start_ws:
                for so in t.cols(sw):
                    if so < co + cw and co < so + sw:
                        continue
                    s = t.s(so, sw)
                    m = c > 0
                    if not m.any() or s[m].min() != 0 or int((s[m] + c[m]).max()) != total:
                        continue
                    if tiles(s, c, total):
                        out.append((so, sw, co, cw, total))
    return out


def assign(S: int, fields: dict[str, list[tuple]], required: bool = True, fixed_mask: int = 0) -> dict:
    """Pick one (score, off, w) candidate per field: no overlap, full coverage."""
    fields = {k: sorted((c for c in v if not fixed_mask & (((1 << c[2]) - 1) << c[1])), reverse=True)
              for k, v in fields.items()}
    names = sorted(fields, key=lambda k: len(fields[k]))
    full = (1 << S) - 1
    best = {'score': -1.0, 'pick': None}
    upper = [0.0] * (len(names) + 1)
    for i in range(len(names) - 1, -1, -1):
        upper[i] = upper[i + 1] + (max(c[0] for c in fields[names[i]]) if fields[names[i]] else 0)

    def rec(i, used, score, pick):
        if score + upper[i] <= best['score'] + 1e-9:
            return
        if i == len(names):
            if not required or used == full:
                best['score'] = score
                best['pick'] = dict(pick)
            return
        for sc, off, w in fields[names[i]]:
            mask = ((1 << w) - 1) << off
            if used & mask:
                continue
            pick[names[i]] = (off, w)
            rec(i + 1, used | mask, score + sc, pick)
            del pick[names[i]]

    rec(0, fixed_mask, 0.0, {})
    if best['pick'] is None:
        raise ProfileError('No consistent field layout: ' + ', '.join(f'{k}:{len(v)}' for k, v in fields.items()))
    return best['pick']


def pick_pairs(pairs: list[tuple], want: int) -> list[tuple]:
    """Choose `want` non-overlapping start/count pairs (each pair = two columns)."""
    def mask(p):
        so, sw, co, cw, _ = p
        return (((1 << sw) - 1) << so) | (((1 << cw) - 1) << co)
    uniq = {}
    for p in pairs:
        uniq.setdefault(mask(p), p)
    pairs = list(uniq.values())
    best = []

    def rec(i, used, chosen):
        nonlocal best
        if len(chosen) == want:
            best = list(chosen)
            return True
        if i == len(pairs) or len(chosen) + len(pairs) - i < want:
            return False
        m = mask(pairs[i])
        if not used & m:
            chosen.append(pairs[i])
            if rec(i + 1, used | m, chosen):
                return True
            chosen.pop()
        return rec(i + 1, used, chosen)

    if not rec(0, 0, []):
        raise ProfileError(f'Unable to choose {want} disjoint range pairs from {len(pairs)}')
    return best


def pairs_mask(pairs) -> int:
    m = 0
    for so, sw, co, cw, _ in pairs:
        m |= (((1 << sw) - 1) << so) | (((1 << cw) - 1) << co)
    return m


def cand(t: Tbl, w: int, scorer, threshold: float = 0.9, limit: int = 64, fixed: int = 0) -> list[tuple]:
    out = []
    for off in t.cols(w):
        if fixed & (((1 << w) - 1) << off):
            continue
        sc = scorer(off)
        if sc >= threshold:
            out.append((sc, off, w))
    out.sort(reverse=True)
    return out[:limit]


def anywhere(t: Tbl, w: int, scorer=None, fixed: int = 0) -> list[tuple]:
    out = [((scorer(off) if scorer else 0.0), off, w) for off in t.cols(w)
           if not fixed & (((1 << w) - 1) << off)]
    out.sort(reverse=True)
    return out


# ---------------------------------------------------------------------------
# Metadata solver
# ---------------------------------------------------------------------------

BITFIELDS = (('attrs', 16), ('type', 8), ('num_mods', 5), ('byref', 1), ('pinned', 1), ('valuetype', 1))


class MetadataSolver:
    def __init__(self, elf, roots: dict, anchors: dict, header: dict):
        self.elf = elf
        self.base = roots['metadata_va']
        self.mr = roots['metadata_registration']
        self.anchors = anchors
        self.header = header
        self.vals = header['values']
        self.sections = header['sections']
        self.assigned: dict[int, str] = {}
        self.records: dict[str, dict] = {}
        self.blobs: dict[str, dict] = {}
        wf = anchors['width_count_fields']
        self.types_count = elf.u32(self.mr + anchors['types_count_field'])
        self.types_ptr = elf.u64(self.mr + anchors['types_field'])
        self.typedef_count = self.vals[wf[1]]
        self.gc_count = self.vals[wf[2]]
        self.params_count = self.vals[wf[3]]
        self.W_t = index_width(self.types_count)
        self.W_td = index_width(self.typedef_count)
        self.W_gc = index_width(self.gc_count)
        self.W_p = index_width(self.params_count)
        self._load_types()

    # -- primitives -------------------------------------------------------
    def _load_types(self):
        e = self.elf
        koff, lsb, width = self.anchors['kind']
        self.desc_off = koff & ~3
        self.kind_shift = (koff & 3) * 8 + lsb
        self.kind_width = width
        self.data_off = 8 if self.desc_off < 8 else 0
        n = self.types_count
        desc = np.zeros(n, np.int64)
        data = np.zeros(n, np.int64)
        ptrs = np.zeros(n, np.int64)
        for i in range(n):
            p = e.u64(self.types_ptr + i * 8)
            ptrs[i] = p
            try:
                desc[i] = e.u32(p + self.desc_off)
                data[i] = e.u64(p + self.data_off)
            except Exception:
                desc[i] = -1
        self.type_ptrs, self.type_desc, self.type_data = ptrs, desc, data
        self.type_kind = (desc >> self.kind_shift) & ((1 << width) - 1)

    def size_of(self, sec) -> Optional[int]:
        if sec.get('size') is not None:
            return sec['size']
        if sec.get('end') is not None:
            return sec['end'] - sec['start']
        return None

    def raw(self, start: int, size: int) -> bytes:
        return self.elf.read(self.base + start, size)

    def section_at(self, start: int):
        for sec in self.sections:
            if sec['start'] == start:
                return sec
        raise ProfileError(f'No metadata section starts at 0x{start:X}')

    def free_sections(self):
        return [s for s in self.sections if s['start'] not in self.assigned]

    def find_section(self, count: int, strides=STRIDES, slack: int = 4, allow_open: bool = False):
        out = []
        for sec in self.free_sections():
            size = self.size_of(sec)
            for st in strides:
                if size is None:
                    if allow_open and count * st <= self._readable_size(sec['start']):
                        out.append((sec, st))
                elif 0 <= size - count * st < slack:
                    out.append((sec, st))
        return out

    def claim(self, name: str, sec: dict, stride: int, count: int, fields: dict, **extra):
        self.assigned[sec['start']] = name
        self.records[name] = dict(offset=sec['start'], offset_field=sec['offset_field'],
                                  size=self.size_of(sec), stride=stride, count=count,
                                  fields=fields, **extra)

    def claim_blob(self, name: str, sec: dict, size: Optional[int]):
        self.assigned[sec['start']] = name
        self.blobs[name] = dict(offset=sec['start'], offset_field=sec['offset_field'], size=size)

    def table(self, sec, stride, count) -> Tbl:
        return Tbl(self.raw(sec['start'], stride * count), stride)

    # string heap helpers
    def is_str(self, v: np.ndarray) -> np.ndarray:
        ok = (v >= 0) & (v < len(self.heap))
        idx = np.where(ok, v, 0)
        return ok & self.heap_starts[idx]

    def str_score(self, t: Tbl, off: int) -> float:
        return frac(self.is_str(t.s(off, 4)))

    def str_prefix(self, v: np.ndarray, prefix: bytes) -> np.ndarray:
        ok = (v >= 0) & (v + len(prefix) < len(self.heap))
        idx = np.where(ok, v, 0)
        for k, ch in enumerate(prefix):
            ok &= self.heap[idx + k] == ch
        return ok

    def str_suffix_dll(self, v: np.ndarray) -> np.ndarray:
        out = np.zeros(len(v), bool)
        for i, x in enumerate(v):
            if 0 <= x < len(self.heap):
                end = self.heap_bytes.find(b'\0', int(x))
                out[i] = self.heap_bytes[int(x):end].lower().endswith(b'.dll')
        return out

    @staticmethod
    def tok(t: Tbl, off: int, prefix: int) -> float:
        v = t.u(off, 4)
        return frac(((v >> 24) == prefix) & ((v & 0xFFFFFF) > 0))

    def type_ref_score(self, v: np.ndarray, kinds) -> float:
        ok = (v >= 0) & (v < self.types_count)
        k = self.type_kind[np.where(ok, v, 0)]
        return frac((v == -1) | (ok & np.isin(k, kinds)))

    def valid_type(self, v: np.ndarray, allow_neg=True) -> np.ndarray:
        m = (v >= 0) & (v < self.types_count)
        return m | (v == -1) if allow_neg else m

    # -- string heap / literals -------------------------------------------
    def solve_strings(self):
        best = None
        for sec in self.sections:
            size = self.size_of(sec)
            if size is None:
                size = self._readable_size(sec['start'])
            if size < 64:
                continue
            head = self.raw(sec['start'], min(size, 1 << 20))
            if b'mscorlib.dll\0' not in head and b'<Module>\0' not in head:
                continue
            nul = head.count(0) / len(head)
            score = (0.05 < nul < 0.4) + (b'<Module>\0' in head)
            if best is None or score > best[0]:
                best = (score, sec, size)
        if best is None:
            raise ProfileError('String heap not found')
        _, sec, size = best
        self.claim_blob('string', sec, self.size_of(sec))
        self.heap_bytes = self.raw(sec['start'], size)
        self.heap = np.frombuffer(self.heap_bytes, np.uint8)
        starts = np.zeros(len(self.heap) + 1, bool)
        starts[0] = True
        starts[1:] = self.heap == 0
        self.heap_starts = starts[:-1]

        lit = None
        for sec in self.free_sections():
            size = self.size_of(sec)
            if not size or size < 8 or size % 4 > 3:
                continue
            n = size // 4
            v = np.frombuffer(self.raw(sec['start'], n * 4), '<u4').astype(np.int64)
            if v[0] == 0 and np.all(v[1:] >= v[:-1]) and v[-1] > 0:
                if lit is None or n > lit[1]:
                    lit = (sec, n, v)
        if lit is None:
            raise ProfileError('String literal offset table not found')
        sec, n, v = lit
        data_size = int(v[-1])
        self.claim('string_literal_offsets', sec, 4, n, {})
        self.records['string_literal_offsets']['count_value'] = n
        best = None
        for s in self.free_sections():
            size = self.size_of(s)
            if size is None or size < data_size or size - data_size > 8:
                continue
            raw = self.raw(s['start'], min(data_size, 4096))
            printable = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13)) / max(len(raw), 1)
            if best is None or printable > best[0]:
                best = (printable, s)
        if best is None:
            raise ProfileError('String literal data not found')
        self.claim_blob('string_literal_data', best[1], data_size)

    def _readable_size(self, start: int) -> int:
        cache = self.__dict__.setdefault('_readable', {})
        if start in cache:
            return cache[start]
        cache[start] = self._probe_size(start)
        return cache[start]

    def _probe_size(self, start: int) -> int:
        lo, hi = 0, 1 << 26
        while lo < hi:
            mid = (lo + hi + 1) // 2
            try:
                self.elf.read(self.base + start, mid)
                lo = mid
            except Exception:
                hi = mid - 1
        return lo

    # -- type definitions -------------------------------------------------
    def solve_typedefs(self):
        a = self.anchors['type_definitions']
        if not a:
            raise ProfileError('TypeDefinition accessor not recovered')
        sec = self.section_at(self.vals[a['offset']])
        count = self.vals[a['count']]
        stride = self.vals[a['size']] // count
        t = self.table(sec, stride, count)
        pairs = [p for p in range_pairs(t, (4,), (2,)) if self.find_section(p[4], (32, 12, 20, 24, 8, 4))]
        pairs += self._empty_pairs(t, (4,), (2,), pairs)
        chosen = pick_pairs(pairs, 8)
        fixed = pairs_mask(chosen)
        idx = np.arange(count)
        kinds_byval = {}

        def byval(off):
            v = t.s(off, self.W_t)
            ok = (v >= 0) & (v < self.types_count)
            vv = np.where(ok, v, 0)
            kinds_byval[off] = vv
            return frac(ok & (self.type_data[vv] == idx) & np.isin(self.type_kind[vv], (0x11, 0x12)))

        def distinct(off):
            v = t.u(off, 4)
            return len(np.unique(v)) / count

        W = self.W_t
        strong = {
            'name': [(sc * (0.5 + 0.5 * distinct(o)), o, w) for sc, o, w in cand(t, 4, lambda o: self.str_score(t, o), 0.95)],
            'namespace': [(sc * (1.0 - 0.5 * distinct(o)), o, w) for sc, o, w in cand(t, 4, lambda o: self.str_score(t, o), 0.95)],
            'token': cand(t, 4, lambda o: self.tok(t, o, 0x02), 0.98),
            'byval_type': cand(t, W, byval, 0.9),
        }
        pick = assign(stride, strong, required=False, fixed_mask=fixed)
        for off, w in pick.values():
            fixed |= ((1 << w) - 1) << off
        bv = t.s(*pick['byval_type'])
        is_vt = self.type_kind[np.where(bv >= 0, bv, 0)] == 0x11
        bits = cand(t, 4, lambda o: frac((t.u(o, 4) & 1) == is_vt), 0.97)
        bits = [c for c in bits if not fixed & (15 << c[1])]
        if not bits:
            raise ProfileError('TypeDefinition bitfield not found')
        pick['bitfield'] = bits[0][1:]
        fixed |= 15 << bits[0][1]
        parent_kinds = (0x12, 0x15, 0x1C) + tuple(range(2, 0x0F)) + (0x18, 0x19)
        rest = {
            'parent': cand(t, W, lambda o: self.type_ref_score(t.s(o, W), parent_kinds) * (1 - frac(t.s(o, W) == -1)), 0.5),
            'declaring_type': cand(t, W, lambda o: self.type_ref_score(t.s(o, W), (0x11, 0x12)) * (0.5 + 0.5 * frac(t.s(o, W) == -1)), 0.5),
            'generic_container': cand(t, self.W_gc, lambda o: frac((t.s(o, self.W_gc) == -1) | (t.u(o, self.W_gc) < self.gc_count)), 0.99),
            'flags': anywhere(t, 4),
        }
        pick.update(assign(stride, rest, fixed_mask=fixed))
        self.td = t
        self.td_pick = pick
        self.td_pairs = chosen
        self.claim('type_definitions', sec, stride, count, pick, count_field=a['count'], size_field=a['size'])
        self._name_typedef_pairs()

    def _empty_pairs(self, t: Tbl, start_ws, count_ws, found):
        out = []
        for cw in count_ws:
            for co in t.cols(cw):
                if t.u(co, cw).any():
                    continue
                for sw in start_ws:
                    for so in t.cols(sw):
                        if not (so < co + cw and co < so + sw) and np.all(t.s(so, sw) == -1):
                            out.append((so, sw, co, cw, 0))
        return out

    def _name_typedef_pairs(self):
        t, pick = self.td, self.td_pick
        decl = t.s(*pick['declaring_type'])
        nested_total = int(np.sum(decl != -1))
        names = {}
        quad = []
        for p in self.td_pairs:
            total = p[4]
            if total == 0:
                continue
            hits = self.find_section(total, (32, 12, 20, 24, 8, 4))
            if not hits:
                raise ProfileError(f'No section matches TypeDefinition range total {total}')
            sec, st = hits[0]
            name = {32: 'methods', 12: 'fields', 20: 'properties', 24: 'events', 8: 'interface_offsets'}.get(st)
            if st == 4:
                if total == nested_total:
                    name = 'nested_types'
                else:
                    quad.append((p, sec))
                    continue
            names[name] = (p, sec, st)
        for p, sec in quad:
            v = np.frombuffer(self.raw(sec['start'], p[4] * 4), '<u4').astype(np.int64)
            tagged = frac(((v >> 29) & 7) > 0)
            names['vtable_methods' if tagged > 0.5 else 'interfaces'] = (p, sec, 4)
        for name in ('methods', 'fields', 'properties', 'events', 'nested_types',
                     'interfaces', 'vtable_methods', 'interface_offsets'):
            if name not in names:
                names[name] = None
        self.td_ranges = {}
        for name, item in names.items():
            if item is None:
                continue
            p, sec, st = item
            so, sw, co, cw, total = p
            self.td_ranges[name] = dict(start=(so, sw), count=(co, cw), total=total, section=sec, stride=st)
            self.td_pick[name + '_start'] = (so, sw)
            self.td_pick[name + '_count'] = (co, cw)
            if name in ('nested_types', 'interfaces', 'vtable_methods', 'interface_offsets'):
                self.claim(name, sec, st, total, {})

    def owners(self, name: str) -> np.ndarray:
        r = self.td_ranges[name]
        s = self.td.s(*r['start'])
        c = self.td.u(*r['count'])
        out = np.full(r['total'], -1, np.int64)
        for i in np.nonzero(c > 0)[0]:
            out[s[i]:s[i] + c[i]] = i
        return out

    # -- images -----------------------------------------------------------
    def solve_images(self):
        count = self.vals[self.anchors['images_count_field']]
        for sec, st in self.find_section(count, range(20, 64)):
            t = self.table(sec, st, count)
            name = cand(t, 4, lambda o: frac(self.is_str(t.s(o, 4))) * frac(self.str_suffix_dll(t.s(o, 4))), 0.9)
            if not name:
                continue
            tp = [p for p in range_pairs(t, (self.W_td,), (4,)) if p[4] == self.typedef_count]
            if not tp:
                continue
            type_pair = tp[0]
            fixed = pairs_mask([type_pair])
            ca = [p for p in range_pairs(t, (4,), (4,)) if not pairs_mask([p]) & fixed]
            ca += self._empty_pairs(t, (4,), (4,), ca)
            ca = [p for p in ca if not pairs_mask([p]) & fixed]
            ca.sort(key=lambda p: -p[4])
            if not ca:
                continue
            ca_pair = ca[0]
            fixed |= pairs_mask([ca_pair])
            ar = np.arange(count)
            fields = {
                'name': name,
                'assembly_index': cand(t, 4, lambda o: frac(t.s(o, 4) == ar), 0.5),
                'entry_point_index': anywhere(t, 4, lambda o: frac(t.s(o, 4) == -1)),
                'exported_type_count': anywhere(t, 4, lambda o: frac(t.s(o, 4) == 0) * 0.5),
                'token': anywhere(t, 4, lambda o: 0.1 * frac(t.s(o, 4) > 0)),
                'exported_type_start': anywhere(t, self.W_td, lambda o: frac(t.s(o, self.W_td) == -1)),
            }
            pick = assign(st, fields, fixed_mask=fixed)
            pick['type_start'] = type_pair[0:2]
            pick['type_count'] = type_pair[2:4]
            pick['custom_attribute_start'] = ca_pair[0:2]
            pick['custom_attribute_count'] = ca_pair[2:4]
            self.img = t
            self.img_pick = pick
            self.attribute_count = ca_pair[4]
            self.claim('images', sec, st, count, pick)
            return
        raise ProfileError('ImageDefinition table not found')

    # -- generics ---------------------------------------------------------
    def solve_generic_parameters(self):
        a = self.anchors['generic_parameters']
        sec = self.section_at(self.vals[a['offset']])
        count = self.vals[a['count']]
        stride = self.vals[a['size']] // count
        self.gp_count = count
        self.gp_sec = (sec, stride)

    def solve_generic_containers(self):
        count = self.gc_count
        for sec, st in self.find_section(count, (16, 12, 14, 20, 24)):
            t = self.table(sec, st, count)
            pairs = [p for p in range_pairs(t, (4,), (4,)) if p[4] == self.gp_count]
            if not pairs:
                continue
            fixed = pairs_mask(pairs[:1])
            fields = {
                'is_method': cand(t, 4, lambda o: frac((t.u(o, 4) == 0) | (t.u(o, 4) == 1)), 0.99),
                'owner_index': anywhere(t, 4, lambda o: frac(t.s(o, 4) >= 0) * 0.1),
            }
            pick = assign(st, fields, fixed_mask=fixed)
            pick['generic_parameter_start'] = pairs[0][0:2]
            pick['type_argc'] = pairs[0][2:4]
            self.gc = t
            self.gc_pick = pick
            self.claim('generic_containers', sec, st, count, pick)
            return
        raise ProfileError('GenericContainer table not found')

    def solve_generic_parameter_records(self):
        sec, st = self.gp_sec
        count = self.gp_count
        t = self.table(sec, st, count)
        start = self.gc.s(*self.gc_pick['generic_parameter_start'])
        argc = self.gc.u(*self.gc_pick['type_argc'])
        owner = np.full(count, -1, np.int64)
        num = np.full(count, -1, np.int64)
        for c in np.nonzero(argc > 0)[0]:
            owner[start[c]:start[c] + argc[c]] = c
            num[start[c]:start[c] + argc[c]] = np.arange(argc[c])
        Wg = self.W_gc
        strong = {
            'name': cand(t, 4, lambda o: self.str_score(t, o), 0.95),
            'owner_index': cand(t, Wg, lambda o: frac(t.s(o, Wg) == owner), 0.98),
            'num': cand(t, 2, lambda o: frac(t.u(o, 2) == num), 0.98),
        }
        pick = assign(st, strong, required=False)
        fixed = 0
        for off, w in pick.values():
            fixed |= ((1 << w) - 1) << off
        pairs = [p for p in range_pairs(t, (2,), (2,)) if not pairs_mask([p]) & fixed]
        pairs += [p for p in self._empty_pairs(t, (2,), (2,), pairs) if not pairs_mask([p]) & fixed]
        hits = [p for p in pairs if p[4] == 0 or self.find_section(p[4], (self.W_t,))]
        if not hits:
            raise ProfileError('GenericParameter constraint range not found')
        p = max(hits, key=lambda x: x[4])
        fixed |= pairs_mask([p])
        pick.update(assign(st, {'flags': anywhere(t, 2)}, fixed_mask=fixed))
        pick['constraints_start'] = p[0:2]
        pick['constraints_count'] = p[2:4]
        self.gp = t
        self.gp_pick = pick
        self.claim('generic_parameters', sec, st, count, pick)
        if p[4]:
            csec, cst = self.find_section(p[4], (self.W_t,))[0]
            self.claim('generic_constraints', csec, cst, p[4], {})

    # -- methods / fields / params ---------------------------------------
    def solve_methods(self):
        r = self.td_ranges['methods']
        sec, st, count = r['section'], r['stride'], r['total']
        t = self.table(sec, st, count)
        owner = self.owners('methods')
        gc_owner = self.gc.s(*self.gc_pick['owner_index'])
        gc_is_method = self.gc.u(*self.gc_pick['is_method'])
        idx = np.arange(count)
        pairs = [p for p in range_pairs(t, (self.W_p,), (2,)) if self.find_section(p[4], (12, 8, 16))]
        if not pairs:
            raise ProfileError('MethodDefinition parameter range not found')
        p = pairs[0]
        fixed = pairs_mask([p])

        def gc_score(o):
            v = t.s(o, self.W_gc)
            ok = (v >= 0) & (v < self.gc_count)
            vv = np.where(ok, v, 0)
            good = (v == -1) | (ok & (gc_owner[vv] == idx) & (gc_is_method[vv] == 1))
            return frac(good) if ok.any() else 0.0

        W = self.W_t
        fields = {
            'name': cand(t, 4, lambda o: self.str_score(t, o), 0.95),
            'token': cand(t, 4, lambda o: self.tok(t, o, 0x06), 0.98),
            'declaring_type': cand(t, self.W_td, lambda o: frac(t.s(o, self.W_td) == owner), 0.98),
            'generic_container': cand(t, self.W_gc, gc_score, 0.99),
            'return_type': cand(t, W, lambda o: frac(self.valid_type(t.s(o, W), False)), 0.98),
            'return_parameter_token': anywhere(t, 4, lambda o: frac((t.u(o, 4) >> 24) == 0x08)),
            'flags': anywhere(t, 2, lambda o: frac(((t.u(o, 2) & 7) >= 1) & ((t.u(o, 2) & 7) <= 6))),
            'iflags': anywhere(t, 2, lambda o: frac(t.u(o, 2) == 0)),
            'slot': anywhere(t, 2, lambda o: frac(t.u(o, 2) == 0xFFFF)),
        }
        pick = assign(st, fields, fixed_mask=fixed)
        pick['parameter_start'] = p[0:2]
        pick['parameter_count'] = p[2:4]
        self.md = t
        self.md_pick = pick
        self.claim('methods', sec, st, count, pick)
        psec, pst = self.find_section(p[4], (12, 8, 16))[0]
        self.param_sec = (psec, pst, p[4])

    def _simple(self, name, sec, st, count, token_prefix):
        t = self.table(sec, st, count)
        W = self.W_t
        fields = {
            'name': cand(t, 4, lambda o: self.str_score(t, o), 0.95),
            'token': cand(t, 4, lambda o: self.tok(t, o, token_prefix), 0.98),
            'type': cand(t, W, lambda o: frac(self.valid_type(t.s(o, W), False)), 0.98),
        }
        pick = assign(st, fields)
        self.claim(name, sec, st, count, pick)
        return t, pick

    def solve_fields(self):
        r = self.td_ranges['fields']
        self.fd, self.fd_pick = self._simple('fields', r['section'], r['stride'], r['total'], 0x04)

    def solve_parameters(self):
        sec, st, count = self.param_sec
        self.pd, self.pd_pick = self._simple('parameters', sec, st, count, 0x08)

    def method_name_prefix(self, prefix: bytes) -> np.ndarray:
        return self.str_prefix(self.md.s(*self.md_pick['name']), prefix)

    def _accessor_score(self, t, off, owner, prefix_mask):
        v = t.s(off, 4)
        mstart = self.td.s(*self.td_pick['methods_start'])
        mcount = self.td.u(*self.td_pick['methods_count'])
        own = np.where(owner >= 0, owner, 0)
        ok = (v >= 0) & (v < mcount[own])
        g = np.where(ok, mstart[own] + v, 0)
        hit = ok & prefix_mask[np.clip(g, 0, len(prefix_mask) - 1)]
        used = frac(ok)
        return frac(hit[ok]) if ok.any() else 0.0, used, frac((v == -1) | ok)

    def solve_properties(self):
        r = self.td_ranges.get('properties')
        if not r:
            return
        sec, st, count = r['section'], r['stride'], r['total']
        t = self.table(sec, st, count)
        owner = self.owners('properties')
        getm, setm = self.method_name_prefix(b'get_'), self.method_name_prefix(b'set_')
        fields = {
            'name': cand(t, 4, lambda o: self.str_score(t, o), 0.95),
            'token': cand(t, 4, lambda o: self.tok(t, o, 0x17), 0.98),
            'get': anywhere(t, 4, lambda o: self._accessor_score(t, o, owner, getm)[0]),
            'set': anywhere(t, 4, lambda o: self._accessor_score(t, o, owner, setm)[0]),
            'attrs': anywhere(t, 4, lambda o: frac(t.u(o, 4) == 0)),
        }
        pick = assign(st, fields)
        self.claim('properties', sec, st, count, pick)

    def solve_events(self):
        r = self.td_ranges.get('events')
        if not r:
            return
        sec, st, count = r['section'], r['stride'], r['total']
        t = self.table(sec, st, count)
        owner = self.owners('events')
        W = self.W_t
        addm = self.method_name_prefix(b'add_')
        remm = self.method_name_prefix(b'remove_')
        fields = {
            'name': cand(t, 4, lambda o: self.str_score(t, o), 0.95),
            'token': cand(t, 4, lambda o: self.tok(t, o, 0x14), 0.98),
            'type': cand(t, W, lambda o: frac(self.valid_type(t.s(o, W), False)), 0.98),
            'add': anywhere(t, 4, lambda o: self._accessor_score(t, o, owner, addm)[0]),
            'remove': anywhere(t, 4, lambda o: self._accessor_score(t, o, owner, remm)[0]),
            'raise': anywhere(t, 4, lambda o: frac(t.s(o, 4) == -1)),
        }
        pick = assign(st, fields)
        self.claim('events', sec, st, count, pick)

    # -- Il2CppType bitfield ----------------------------------------------
    def solve_type_bits(self):
        desc = self.type_desc
        ok = desc >= 0
        kind = self.type_kind
        byval = self.td.s(*self.td_pick['byval_type'])
        byval = byval[(byval >= 0) & (byval < self.types_count)]
        ftypes = self.fd.s(*self.fd_pick['type'])
        ftypes = ftypes[(ftypes >= 0) & (ftypes < self.types_count)]
        ptypes = self.pd.s(*self.pd_pick['type'])
        ptypes = ptypes[(ptypes >= 0) & (ptypes < self.types_count)]
        cls = ok & np.isin(kind, (0x11, 0x12))
        best = None
        others = [f for f in BITFIELDS if f[0] != 'type']
        for order in itertools.permutations(others):
            for kpos in range(len(order) + 1):
                seq = list(order[:kpos]) + [('type', self.kind_width)] + list(order[kpos:])
                pos, layout = 0, {}
                for name, w in seq:
                    layout[name] = (pos, w)
                    pos += w
                if layout['type'][0] != self.kind_shift:
                    continue

                def get(name, sel=None):
                    p, w = layout[name]
                    v = desc if sel is None else desc[sel]
                    return (v >> p) & ((1 << w) - 1)

                score = frac(get('valuetype')[cls] == (kind[cls] == 0x11)) * 4
                score += frac(get('attrs', byval) == 0) + frac(get('byref', byval) == 0)
                score += frac(get('attrs', ftypes) != 0) * 2
                score += frac(get('byref', ftypes) == 0)
                score += frac(get('num_mods')[ok] == 0) + frac(get('pinned')[ok] == 0)
                score += 0.5 * (get('byref', ptypes).any())
                if best is None or score > best[0]:
                    best = (score, layout)
        self.type_bits = best[1]
        self.type_attrs = (desc >> self.type_bits['attrs'][0]) & 0xFFFF

    def attrs_of(self, type_index: np.ndarray) -> np.ndarray:
        ok = (type_index >= 0) & (type_index < self.types_count)
        return np.where(ok, self.type_attrs[np.where(ok, type_index, 0)], 0)

    # -- default values ---------------------------------------------------
    def solve_defaults(self):
        ftype = self.fd.s(*self.fd_pick['type'])
        ptype = self.pd.s(*self.pd_pick['type'])
        targets = (('field_default_values', self.records['fields']['count'], ftype, 0x8000),
                   ('parameter_default_values', self.records['parameters']['count'], ptype, 0x1000))
        for name, n_owner, owner_type, flag in targets:
            best = None
            for sec in self.free_sections():
                size = self.size_of(sec)
                if not size or size % 12 > 3 or size < 12:
                    continue
                count = size // 12
                t = self.table(sec, 12, count)
                for io in (0, 4, 8):
                    v = t.s(io, 4)
                    if not np.all((v >= 0) & (v < n_owner)) or not np.all(v[1:] > v[:-1]):
                        continue
                    score = frac(self.attrs_of(owner_type[v]) & flag != 0)
                    if score > 0.9 and (best is None or score > best[0]):
                        best = (score, sec, count, io, t)
            if best is None:
                continue
            _, sec, count, io, t = best
            rest = [o for o in (0, 4, 8) if o != io]
            tscore = [frac(self.valid_type(t.s(o, 4), False)) * (1 - len(np.unique(t.u(o, 4))) / count) for o in rest]
            to = rest[int(np.argmax(tscore))]
            do = [o for o in rest if o != to][0]
            owner_key = 'field_index' if name.startswith('field') else 'parameter_index'
            self.claim(name, sec, 12, count, {owner_key: (io, 4), 'type': (to, 4), 'data': (do, 4)})
        data_max = 0
        for name in ('field_default_values', 'parameter_default_values'):
            rec = self.records.get(name)
            if rec:
                t = self.table(self.section_at(rec['offset']), 12, rec['count'])
                v = t.s(*rec['fields']['data'])
                if (v >= 0).any():
                    data_max = max(data_max, int(v[v >= 0].max()) + 1)
        return data_max

    # -- custom attributes ------------------------------------------------
    def solve_attributes(self):
        count = self.attribute_count
        for sec, st in self.find_section(count, (8,), slack=12, allow_open=True):
            t = self.table(sec, 8, count)
            for to, so in ((0, 4), (4, 0)):
                tok = t.u(to, 4) >> 24
                start = t.u(so, 4)
                if frac(np.isin(tok, (0x02, 0x04, 0x06, 0x08, 0x14, 0x17, 0x20))) < 0.99:
                    continue
                if start[0] != 0 or not np.all(start[1:] >= start[:-1]):
                    continue
                self.claim('attribute_data_ranges', sec, 8, count, {'token': (to, 4), 'start': (so, 4)})
                last = int(start[-1])
                best = None
                for s2 in self.free_sections():
                    size = self.size_of(s2)
                    if size is None or size < last:
                        continue
                    if best is None or size < best[0]:
                        best = (size, s2)
                if best is None:
                    raise ProfileError('Custom attribute blob not found')
                self.claim_blob('attribute_data', best[1], best[0])
                return
        raise ProfileError('Custom attribute ranges not found')

    def solve_default_data(self, data_max: int):
        if not data_max:
            return
        best = None
        for sec in self.free_sections():
            size = self.size_of(sec)
            if size is None or size < data_max:
                continue
            if best is None or size < best[0]:
                best = (size, sec)
        if best is None:
            raise ProfileError('Default value blob not found')
        self.claim_blob('field_and_parameter_default_value_data', best[1], best[0])

    # -- field references / interface offsets ------------------------------
    def solve_field_refs(self):
        fcount = self.td.u(*self.td_pick['fields_count'])
        kind_ok = (0x11, 0x12, 0x15)
        best = None
        for sec in self.free_sections():
            size = self.size_of(sec)
            if not size or size % 8 > 3 or size < 8 or sec.get('stride') not in (None, 8):
                continue
            count = size // 8
            t = self.table(sec, 8, count)
            for to, fo in ((0, 4), (4, 0)):
                ti = t.s(to, 4)
                fi = t.s(fo, 4)
                ok = (ti >= 0) & (ti < self.types_count)
                if frac(ok) < 0.99:
                    continue
                k = self.type_kind[np.where(ok, ti, 0)]
                d = self.type_data[np.where(ok, ti, 0)]
                direct = np.isin(k, (0x11, 0x12)) & (d >= 0) & (d < self.typedef_count)
                lim = np.where(direct, fcount[np.clip(d, 0, self.typedef_count - 1)], 1 << 16)
                score = frac(np.isin(k, kind_ok)) * frac((fi >= 0) & (fi < lim))
                if score > 0.97 and (best is None or score > best[0]):
                    best = (score, sec, count, to, fo)
        if best:
            _, sec, count, to, fo = best
            self.claim('field_refs', sec, 8, count, {'type': (to, 4), 'field': (fo, 4)})

    def solve_interface_offsets(self):
        rec = self.records.get('interface_offsets')
        if not rec:
            return
        st = rec['stride']
        t = self.table(self.section_at(rec['offset']), st, rec['count'])
        W = self.W_t
        best = None
        for to in t.cols(W):
            oo = [o for o in t.cols(4) if o >= to + W or o + 4 <= to]
            for o in oo:
                score = self.type_ref_score(t.s(to, W), (0x12, 0x15)) + frac((t.s(o, 4) >= 0) & (t.s(o, 4) < 0x10000))
                if best is None or score > best[0]:
                    best = (score, to, o)
        rec['fields'] = {'type': (best[1], W), 'offset': (best[2], 4)}

    def solve(self) -> dict:
        self.solve_strings()
        self.solve_typedefs()
        self.solve_images()
        self.solve_generic_parameters()
        self.solve_generic_containers()
        self.solve_generic_parameter_records()
        self.solve_methods()
        self.solve_fields()
        self.solve_parameters()
        self.solve_properties()
        self.solve_events()
        self.solve_type_bits()
        data_max = self.solve_defaults()
        self.solve_attributes()
        self.solve_default_data(data_max)
        self.solve_field_refs()
        self.solve_interface_offsets()
        for name in ('nested_types', 'interfaces', 'vtable_methods', 'generic_constraints'):
            rec = self.records.get(name)
            if rec:
                rec['fields'] = {'value': (0, rec['stride'])}
        return {
            'metadata_va': self.base,
            'header_size': self.header['header_size'],
            'records': self.records,
            'blobs': self.blobs,
            'widths': {'type_index': self.W_t, 'type_definition': self.W_td,
                       'generic_container': self.W_gc, 'parameter': self.W_p},
            'counts': {'types': self.types_count, 'type_definitions': self.typedef_count,
                       'generic_containers': self.gc_count, 'generic_parameters': self.gp_count,
                       'parameters': self.params_count, 'attributes': self.attribute_count},
            'il2cpp_type': {'descriptor_offset': self.desc_off, 'data_offset': self.data_off,
                            'bits': self.type_bits},
            'unclaimed_sections': [hex(s['start']) for s in self.free_sections()],
        }


# ---------------------------------------------------------------------------
# Runtime structures (CodeRegistration / MetadataRegistration / modules)
# ---------------------------------------------------------------------------

class RuntimeSolver:
    def __init__(self, elf, roots: dict, anchors: dict, md: MetadataSolver):
        self.elf = elf
        self.cr = roots['code_registration']
        self.mr = roots['metadata_registration']
        self.anchors = anchors
        self.md = md
        self.exec_ranges = [(v, v + fs) for v, _, fs, _, fl in elf.loads if fl & 1]
        self.type_set = set(int(x) for x in md.type_ptrs if x)
        self.images_count = md.records['images']['count']
        self.methods_count = md.records['methods']['count']
        nidx = md.img.s(*md.img_pick['name'])
        self.image_names = set()
        for x in nidx:
            end = md.heap_bytes.find(b'\0', int(x))
            self.image_names.add(md.heap_bytes[int(x):end])

    # -- memory helpers ---------------------------------------------------
    def q(self, va: int) -> int:
        e = self.elf
        v = e.relocated_u64.get(va)
        if v is not None:
            return v
        try:
            return e.u64(va)
        except Exception:
            for start, _, _, memsz, _ in e.loads:
                if start <= va and va + 8 <= start + memsz:
                    return 0
            raise

    def d(self, va: int) -> int:
        try:
            return self.elf.u32(va)
        except Exception:
            return 0

    def is_ptr_slot(self, va: int) -> bool:
        return va in self.elf.relocated_u64

    def is_exec(self, v: int) -> bool:
        return any(a <= v < b for a, b in self.exec_ranges)

    def mapped(self, v: int, size: int = 8) -> bool:
        return any(s <= v and v + size <= s + m for s, _, _, m, _ in self.elf.loads)

    def cstr(self, v: int) -> Optional[bytes]:
        try:
            off = self.elf.va_to_off(v)
        except Exception:
            return None
        end = self.elf.data.find(b'\0', off, off + 300)
        return self.elf.data[off:end] if end > off else None

    def region(self, base: int, size: int):
        """Split a registration struct into pointer slots and u32 count slots."""
        ptrs, counts = {}, {}
        for off in range(0, size, 8):
            if self.is_ptr_slot(base + off):
                ptrs[off] = self.q(base + off)
            else:
                v = self.q(base + off)
                counts[off] = v & 0xFFFFFFFF
                counts[off + 4] = v >> 32
        return ptrs, counts

    def exec_run(self, ptr: int, limit: int) -> int:
        n = 0
        while n < limit:
            try:
                v = self.q(ptr + n * 8)
            except Exception:
                break
            if v and v != 0xFFFFFFFFFFFFFFFF and not self.is_exec(v) and not (self.mapped(v) and self.is_ptr_slot(ptr + n * 8)):
                break
            n += 1
        return n

    def exec_frac(self, ptr: int, count: int) -> float:
        if count <= 0:
            return 0.0
        idx = sorted(set([0, count - 1] + [count * i // 64 for i in range(64)]))
        good = 0
        for i in idx:
            try:
                v = self.q(ptr + i * 8)
            except Exception:
                continue
            good += bool(v) and self.is_exec(v)
        return good / len(idx)

    # -- MetadataRegistration --------------------------------------------
    def solve_metadata_registration(self) -> dict:
        md = self.md
        a = self.anchors
        size = 0x80
        ptrs, counts = self.region(self.mr, size)
        out = {'types': (a['types_field'], a['types_count_field'])}
        ptrs.pop(a['types_field'], None)
        # Generic instantiations: {argc, argv} records whose argv points at type pointers.
        insts = None
        for off, p in ptrs.items():
            ok, layout = self._generic_inst_layout(p)
            if ok:
                insts = (off, p, layout)
                break
        if insts is None:
            raise ProfileError('MetadataRegistration genericInsts not found')
        ptrs.pop(insts[0])
        inst_run = self._run(insts[1], lambda v: self._generic_inst_layout_one(v, insts[2]))
        used_counts = {a['types_count_field']}
        inst_count = self._pick_count(counts, used_counts, inst_run)
        out['generic_insts'] = (insts[0], inst_count[0])
        used_counts.add(inst_count[0])
        self.inst_layout = insts[2]
        self.inst_set = set(self.q(insts[1] + i * 8) for i in range(inst_count[1]))
        self.generic_insts_count = inst_count[1]

        classes = None
        for off, p in ptrs.items():
            layout = self._generic_class_layout(p)
            if layout:
                classes = (off, p, layout)
                break
        if classes is None:
            raise ProfileError('MetadataRegistration genericClasses not found')
        ptrs.pop(classes[0])
        run = self._run(classes[1], lambda v: self._generic_class_one(v, classes[2]))
        cc = self._pick_count(counts, used_counts, run)
        used_counts.add(cc[0])
        out['generic_classes'] = (classes[0], cc[0])
        self.class_layout = classes[2]

        tdc = md.typedef_count
        tdc_slots = [o for o, v in counts.items() if v == tdc]
        field_count = md.td.u(*md.td_pick['fields_count'])
        per_type = []
        for off, p in ptrs.items():
            try:
                first = [self.q(p + i * 8) for i in range(min(tdc, 64))]
            except Exception:
                continue
            if not all(v == 0 or self.mapped(v, 4) for v in first):
                continue
            try:
                vals = np.array([self.q(p + i * 8) for i in range(tdc)], np.int64)
            except Exception:
                continue
            if not np.all((vals == 0) | np.array([self.mapped(int(v), 4) if v else True for v in vals[:2048]] +
                                                [True] * max(0, tdc - 2048))):
                continue
            nulls = vals == 0
            per_type.append((off, frac(nulls == (field_count == 0)), frac(nulls)))
        per_type.sort(key=lambda x: -x[1])
        if len(per_type) < 2 or len(tdc_slots) < 2:
            raise ProfileError('MetadataRegistration fieldOffsets/typeDefinitionsSizes not found')
        fo = max(per_type, key=lambda x: x[1] - x[2] * 0 + (x[2] > 0))
        sizes = [x for x in per_type if x[0] != fo[0]]
        sizes = min(sizes, key=lambda x: x[2])
        out['field_offsets'] = (fo[0], tdc_slots[0])
        out['type_definition_sizes'] = (sizes[0], tdc_slots[1])
        for k in (fo[0], sizes[0]):
            ptrs.pop(k)
        used_counts |= set(tdc_slots[:2])

        # Inline tables: MethodSpec (12 bytes) and GenericMethodFunctionsDefinitions (16 bytes).
        tables = []
        for off, p in ptrs.items():
            for stride in (12, 16):
                n = self._int_rows_run(p, stride, 1 << 21)
                if n >= 16:
                    tables.append((off, p, stride, n))
        spec = max((t for t in tables if t[2] == 12), key=lambda t: t[3], default=None)
        gmt = max((t for t in tables if t[2] == 16 and t[0] != (spec[0] if spec else None)), key=lambda t: t[3], default=None)
        if not spec or not gmt:
            raise ProfileError('MetadataRegistration methodSpecs/genericMethodTable not found')
        sc = self._pick_count(counts, used_counts, spec[3])
        used_counts.add(sc[0])
        gc = self._pick_count(counts, used_counts, gmt[3])
        used_counts.add(gc[0])
        out['method_specs'] = (spec[0], sc[0])
        out['generic_method_table'] = (gmt[0], gc[0])
        self.mr_fields = out
        self.mr_counts = counts
        self.spec_layout = self._method_spec_layout(spec[1], sc[1])
        self.gmt_layout = self._gmt_layout(gmt[1], gc[1])
        return out

    def _run(self, ptr: int, check, limit: int = 1 << 21) -> int:
        n = 0
        while n < limit:
            try:
                v = self.q(ptr + n * 8)
            except Exception:
                break
            if not v or not check(v):
                break
            n += 1
        return n

    @staticmethod
    def _pick_count(counts: dict, used: set, run: int) -> tuple[int, int]:
        best = None
        for off, v in counts.items():
            if off in used or not 0 < v <= run:
                continue
            if best is None or v > best[1]:
                best = (off, v)
        if best is None:
            raise ProfileError(f'No registration count matches a table of {run} entries')
        return best

    def _generic_inst_layout_one(self, inst: int, layout) -> bool:
        argc_off, argv_off = layout
        try:
            argc = self.q(inst + argc_off)
            argv = self.q(inst + argv_off)
        except Exception:
            return False
        return 0 < argc <= 64 and self.is_ptr_slot(inst + argv_off) and self.q(argv) in self.type_set

    def _generic_inst_layout(self, p: int):
        for layout in ((0, 8), (8, 0)):
            good = 0
            for i in range(16):
                try:
                    v = self.q(p + i * 8)
                except Exception:
                    break
                good += bool(v) and self._generic_inst_layout_one(v, layout)
            if good == 16:
                return True, layout
        return False, None

    def _generic_class_layout(self, p: int):
        for type_off in (0, 8, 16, 24):
            for inst_off in (0, 8, 16, 24):
                if inst_off == type_off:
                    continue
                if all(self._generic_class_one(self.q(p + i * 8), (type_off, inst_off)) for i in range(16)):
                    return (type_off, inst_off)
        return None

    def _generic_class_one(self, gc: int, layout) -> bool:
        type_off, inst_off = layout
        try:
            return self.q(gc + type_off) in self.type_set and self.q(gc + inst_off) in self.inst_set
        except Exception:
            return False

    def _int_rows_run(self, p: int, stride: int, limit: int) -> int:
        if self.is_ptr_slot(p):
            return 0
        try:
            off = self.elf.va_to_off(p)
        except Exception:
            return 0
        n = min(limit, (len(self.elf.data) - off) // stride)
        raw = np.frombuffer(self.elf.data, '<i4', count=n * stride // 4, offset=off).reshape(n, stride // 4)
        bad = np.nonzero(~np.all((raw >= -1) & (raw < (1 << 22)), axis=1))[0]
        return int(bad[0]) if len(bad) else n

    def _rows(self, p: int, stride: int, count: int) -> np.ndarray:
        off = self.elf.va_to_off(p, stride * count)
        return np.frombuffer(self.elf.data, '<i4', count=count * stride // 4, offset=off).reshape(count, stride // 4).astype(np.int64)

    def _method_spec_layout(self, p: int, count: int) -> dict:
        rows = self._rows(p, 12, count)
        gcm = self.md.md.s(*self.md.md_pick['generic_container'])
        best = None
        for perm in itertools.permutations(range(3)):
            m, ci, mi = (rows[:, k] for k in perm)
            ok = (m >= 0) & (m < self.methods_count)
            if not ok.all():
                continue
            mm = np.where(ok, m, 0)
            score = frac((mi != -1) == (gcm[mm] != -1)) + frac((ci >= -1) & (ci < self.generic_insts_count)) \
                + frac((mi >= -1) & (mi < self.generic_insts_count))
            if best is None or score > best[0]:
                best = (score, perm)
        if best is None:
            raise ProfileError('MethodSpec layout not recovered')
        perm = best[1]
        return {'method_definition': perm[0] * 4, 'class_inst': perm[1] * 4, 'method_inst': perm[2] * 4}

    def _gmt_layout(self, p: int, count: int) -> dict:
        rows = self._rows(p, 16, count)
        cols = list(range(4))
        neg = [frac(rows[:, k] == -1) for k in cols]
        adj = int(np.argmax(neg))
        rest = [k for k in cols if k != adj]
        distinct = {k: len(np.unique(rows[:, k])) for k in rest}
        inv = min(rest, key=lambda k: distinct[k])
        rest.remove(inv)
        gen = max(rest, key=lambda k: distinct[k])
        meth = [k for k in rest if k != gen][0]
        return {'generic_method_index': gen * 4, 'method_index': meth * 4,
                'invoker_index': inv * 4, 'adjustor_thunk_index': adj * 4,
                'max_method_index': int(rows[:, meth].max()), 'max_invoker_index': int(rows[:, inv].max()),
                'max_adjustor_thunk_index': int(rows[:, adj].max())}

    # -- CodeRegistration -------------------------------------------------
    def solve_code_registration(self) -> dict:
        size = 0x80
        if 0 < self.mr - self.cr < size:
            size = self.mr - self.cr
        ptrs, counts = self.region(self.cr, size)
        self.cr_all_ptrs = dict(ptrs)
        out = {}
        used = set()
        # codeGenModules
        mod = None
        for off, p in ptrs.items():
            try:
                if all(self._module_name_off(self.q(p + i * 8)) is not None for i in range(self.images_count)):
                    mod = off
                    break
            except Exception:
                continue
        if mod is None:
            raise ProfileError('CodeRegistration codeGenModules not found')
        cslot = [o for o, v in counts.items() if v == self.images_count]
        if not cslot:
            raise ProfileError('codeGenModulesCount not found')
        out['codegen_modules'] = (mod, cslot[0])
        used.add(cslot[0])
        self.modules_ptr = ptrs.pop(mod)

        # interopData: array of structs that reference Il2CppType pointers.
        interop = None
        for off, p in ptrs.items():
            for stride in (0x38, 0x30, 0x40):
                for toff in range(0, stride, 8):
                    try:
                        if all(self.q(p + i * stride + toff) in self.type_set for i in range(8)):
                            interop = (off, p, stride)
                    except Exception:
                        pass
                if interop:
                    break
            if interop:
                break
        if interop:
            ptrs.pop(interop[0])
            n = 0
            while True:
                try:
                    ok = any(self.q(interop[1] + n * interop[2] + t) in self.type_set for t in range(0, interop[2], 8))
                except Exception:
                    ok = False
                if not ok:
                    break
                n += 1
            ic = self._pick_count(counts, used, n)
            used.add(ic[0])
            out['interop'] = (interop[0], ic[0])

        # executable pointer arrays
        gmt = self.gmt_layout
        gmp_need = gmt['max_method_index'] + 1
        inv_need = gmt['max_invoker_index'] + 1
        runs = {off: self.exec_run(p, 1 << 21) for off, p in ptrs.items()}

        def exact_count(need):
            cands = [(v, o) for o, v in counts.items() if o not in used and v >= need]
            if not cands:
                raise ProfileError(f'No CodeRegistration count >= {need}')
            return min(cands)[1]

        targets = set(ptrs.values())

        def choose(count, exclude):
            best = None
            for off, p in ptrs.items():
                if off in exclude or runs[off] < min(count, 4096):
                    continue
                score = self.exec_frac(p, count) + (1.0 if p + count * 8 in targets else 0.0)
                if best is None or score > best[0]:
                    best = (score, off)
            if best is None:
                raise ProfileError(f'No executable array of {count} entries in CodeRegistration')
            return best[1]

        islot = exact_count(inv_need)
        used.add(islot)
        inv_off = choose(counts[islot], ())
        out['invoker_pointers'] = (inv_off, islot)
        gslot = exact_count(gmp_need)
        used.add(gslot)
        gmp_off = choose(counts[gslot], (inv_off,))
        out['generic_method_pointers'] = (gmp_off, gslot)
        remaining = {off: p for off, p in ptrs.items() if off not in (inv_off, gmp_off)}
        self.cr_counts = counts
        self.cr_remaining = remaining
        self.cr_used = used
        self.cr_fields = out
        return out

    def _covers(self, p: int, count: int) -> bool:
        try:
            self.q(p + (count - 1) * 8)
            return True
        except Exception:
            return False

    def _adjustor_shaped(self, p: int, count: int) -> float:
        good = total = 0
        for i in range(min(count, 32)):
            try:
                f = self.q(p + i * 8)
            except Exception:
                continue
            if not f:
                continue
            total += 1
            try:
                d0 = decode(self.elf.u32(f), f)
                d1 = decode(self.elf.u32(f + 4), f + 4)
            except Exception:
                continue
            good += bool(d0 and d0[0] == 'addi' and d0[1] == 0 and d0[2] == 0 and d1 and d1[0] in ('b', 'mov', 'addi'))
        return good / total if total else 0.0

    def finish_code_registration(self, reverse_total: int):
        out, counts, used = self.cr_fields, self.cr_counts, self.cr_used
        remaining = dict(self.cr_remaining)
        gcount = self.gmt_layout['max_adjustor_thunk_index'] + 1
        adj = [(self._adjustor_shaped(p, gcount), off) for off, p in remaining.items()] if gcount > 0 else []
        adj = [x for x in adj if x[0] > 0.5]
        if adj:
            off = max(adj)[1]
            out['generic_adjustor_thunks'] = (off, None)
            remaining.pop(off)
        # unresolved virtual/instance/static call arrays: three arrays of one shared count.
        targets = set(self.cr_all_ptrs.values())
        best = None
        for co, v in counts.items():
            if co in used or v <= 0:
                continue
            members = {off for off, p in remaining.items() if p + v * 8 in targets}
            if len(members) >= 2 and (best is None or len(members) > len(best[1])):
                best = (co, members, v)
        if best:
            co, members, v = best
            ordered = sorted(members, key=lambda o: remaining[o])
            virt, rest = ordered[0], ordered[1:]
            out['unresolved_virtual'] = (virt, co)
            if len(rest) >= 1:
                out['unresolved_instance'] = (rest[0], None)
            if len(rest) >= 2:
                out['unresolved_static'] = (rest[1], None)
            used.add(co)
            for o in members:
                remaining.pop(o)
        if reverse_total:
            rslot = [o for o, v in counts.items() if o not in used and v == reverse_total]
            cand_r = [(self.exec_frac(p, reverse_total), off) for off, p in remaining.items()]
            if rslot and cand_r:
                fr, off = max(cand_r)
                if fr > 0.5:
                    out['reverse_pinvoke'] = (off, rslot[0])
                    used.add(rslot[0])
                    remaining.pop(off)
        return out

    # -- CodeGenModule ----------------------------------------------------
    def _module_name_off(self, mod: int) -> Optional[int]:
        for off in range(0, 0x88, 8):
            if not self.is_ptr_slot(mod + off):
                continue
            s = self.cstr(self.q(mod + off))
            if s and (s in self.image_names or s.lower().endswith(b'.dll')):
                return off
        return None

    def solve_modules(self) -> dict:
        md = self.md
        mods = [self.q(self.modules_ptr + i * 8) for i in range(self.images_count)]
        name_off = self._module_name_off(mods[0])
        names = [self.cstr(self.q(m + name_off)).decode('utf-8', 'replace') for m in mods]
        img = md.img
        img_names = {}
        nidx = md.img.s(*md.img_pick['name'])
        for i in range(self.images_count):
            end = md.heap_bytes.find(b'\0', int(nidx[i]))
            img_names[md.heap_bytes[int(nidx[i]):end].decode('utf-8', 'replace')] = i
        tstart = img.s(*md.img_pick['type_start'])
        tcount = img.u(*md.img_pick['type_count'])
        mcount = md.td.u(*md.td_pick['methods_count'])
        expect = []
        for n in names:
            i = img_names.get(n)
            if i is None:
                raise ProfileError(f'CodeGenModule {n} has no ImageDefinition')
            expect.append(int(mcount[tstart[i]:tstart[i] + tcount[i]].sum()) if tcount[i] else 0)
        size = 0x88
        slots = list(range(0, size, 4))

        def u32(m, off):
            return self.d(m + off)

        ptr_slots = [o for o in range(0, size, 8) if sum(self.is_ptr_slot(m + o) or self.q(m + o) == 0 for m in mods) == len(mods)
                     and any(self.is_ptr_slot(m + o) for m in mods)]
        count_slot = None
        for o in slots:
            if all(u32(m, o) == e for m, e in zip(mods, expect)) and o not in ptr_slots and o - 4 not in ptr_slots:
                count_slot = o
                break
        if count_slot is None:
            raise ProfileError('CodeGenModule.methodPointerCount not found')
        out = {'name': name_off, 'method_pointer_count': count_slot}
        taken = {name_off}

        def best_ptr(check, exclude):
            best = None
            for o in ptr_slots:
                if o in exclude:
                    continue
                good = total = 0
                for m, e in zip(mods, expect):
                    if not e:
                        continue
                    total += 1
                    try:
                        good += check(self.q(m + o), e)
                    except Exception:
                        pass
                if total and (best is None or good / total > best[0]):
                    best = (good / total, o)
            return best

        mp = best_ptr(lambda p, e: p != 0 and self.exec_frac(p, e) > 0.3, taken)
        out['method_pointers'] = mp[1]
        taken.add(mp[1])
        inv_limit = self.cr_counts[self.cr_fields['invoker_pointers'][1]]

        def inv_check(p, e):
            if not p:
                return False
            off = self.elf.va_to_off(p, e * 4)
            v = np.frombuffer(self.elf.data, '<i4', count=e, offset=off)
            return bool(np.all((v >= -1) & (v < inv_limit)))

        ii = best_ptr(inv_check, taken)
        out['invoker_indices'] = ii[1]
        taken.add(ii[1])

        # (count, pointer, layout) groups validated over all modules.
        count_slots = [o for o in slots if o not in out.values() and not any(o in (p, p + 4) for p in ptr_slots)]
        for kind, stride, validator in (('adjustor_thunks', 16, self._thunk_layout),
                                        ('reverse_pinvoke', 24, self._reverse_layout),
                                        ('rgctx_ranges', 12, self._range_layout),
                                        ('rgctxs', 16, self._rgctx_layout)):
            best = None
            for co in count_slots:
                counts = [u32(m, co) for m in mods]
                if not any(counts) or max(counts) > 1 << 20:
                    continue
                for po in ptr_slots:
                    if po in taken:
                        continue
                    layout = validator([(self.q(m + po), c) for m, c in zip(mods, counts) if c])
                    if layout is not None:
                        score = sum(1 for c in counts if c)
                        if best is None or score > best[0]:
                            best = (score, co, po, layout)
            if best:
                _, co, po, layout = best
                out[kind] = {'count': co, 'pointer': po, 'layout': layout}
                taken.add(po)
                count_slots.remove(co)
        self.module_layout = out
        self.module_reverse_total = sum(u32(m, out['reverse_pinvoke']['count']) for m in mods) if 'reverse_pinvoke' in out else 0
        return out

    def _thunk_layout(self, items):
        for fn_off, tok_off in ((0, 8), (8, 0)):
            ok = True
            for p, c in items[:64]:
                for i in (0, c - 1):
                    try:
                        fn = self.q(p + i * 16 + fn_off)
                        tok = self.q(p + i * 16 + tok_off)
                    except Exception:
                        ok = False
                        break
                    if not self.is_exec(fn) or tok >> 24 != 0x06 or tok > 0xFFFFFFFF:
                        ok = False
                        break
                if not ok:
                    break
            if ok and items:
                return {'method': fn_off, 'token': tok_off}
        return None

    def _reverse_layout(self, items):
        for ptr_off in (0, 8, 16):
            dw = [o for o in range(0, 24, 4) if o not in (ptr_off, ptr_off + 4)]
            for tok_off in dw:
                ok = True
                for p, c in items[:64]:
                    for i in (0, c - 1):
                        try:
                            tok = self.d(p + i * 24 + tok_off)
                            fn = self.q(p + i * 24 + ptr_off)
                        except Exception:
                            ok = False
                            break
                        if tok >> 24 != 0x06 or not (fn == 0 or self.mapped(fn)):
                            ok = False
                            break
                    if not ok:
                        break
                if ok and items:
                    others = [o for o in dw if o != tok_off]
                    idx_vals = {o: [self.d(p + i * 24 + o) for p, c in items for i in range(c)] for o in others}
                    index_off = max(others, key=lambda o: len(set(idx_vals[o])))
                    others.remove(index_off)
                    gmi = max(others, key=lambda o: sum(v != 0 for v in idx_vals[o]))
                    return {'method': ptr_off, 'token': tok_off, 'index': index_off, 'generic_method_index': gmi}
        return None

    def _range_layout(self, items):
        for tok_off in (0, 4, 8):
            rest = [o for o in (0, 4, 8) if o != tok_off]
            ok = True
            mins = {o: 1 << 30 for o in rest}
            for p, c in items[:128]:
                try:
                    rows = [(self.d(p + i * 12 + tok_off), self.elf.i32(p + i * 12 + rest[0]),
                             self.elf.i32(p + i * 12 + rest[1])) for i in range(min(c, 64))]
                except Exception:
                    ok = False
                    break
                if not all((t >> 24) in (0x02, 0x06) for t, _, _ in rows):
                    ok = False
                    break
                if not all(0 <= x < 1 << 20 and 0 <= y < 1 << 20 for _, x, y in rows):
                    ok = False
                    break
                mins[rest[0]] = min(mins[rest[0]], min(x for _, x, _ in rows))
                mins[rest[1]] = min(mins[rest[1]], min(y for _, _, y in rows))
            if ok and items:
                so = min(rest, key=lambda o: mins[o])
                lo = [o for o in rest if o != so][0]
                return {'token': tok_off, 'start': so, 'length': lo}
        return None

    def _rgctx_layout(self, items):
        for kind_off in (0, 8):
            ok = True
            for p, c in items[:64]:
                for i in (0, c - 1):
                    try:
                        k = self.q(p + i * 16 + kind_off)
                    except Exception:
                        ok = False
                        break
                    if not 1 <= k <= 8:
                        ok = False
                        break
                if not ok:
                    break
            if ok and items:
                return {'type': kind_off, 'data': 8 - kind_off}
        return None

    def solve(self) -> dict:
        mr = self.solve_metadata_registration()
        cr = self.solve_code_registration()
        mods = self.solve_modules()
        cr = self.finish_code_registration(self.module_reverse_total)
        return {
            'metadata_registration': mr, 'code_registration': cr, 'codegen_module': mods,
            'generic_inst': {'type_argc': self.inst_layout[0], 'type_argv': self.inst_layout[1]},
            'generic_class': {'type': self.class_layout[0], 'class_inst': self.class_layout[1]},
            'method_spec': self.spec_layout, 'generic_method_table': self.gmt_layout,
        }


def build_profile(elf) -> dict:
    code = Code(elf)
    roots = find_roots(elf, code)
    anchors = code_anchors(elf, code, roots)
    header = solve_header_sections(elf, roots['metadata_va'])
    md = MetadataSolver(elf, roots, anchors, header)
    profile = md.solve()
    rt = RuntimeSolver(elf, roots, anchors, md)
    profile['runtime'] = rt.solve()
    profile['code_registration_va'] = roots['code_registration']
    profile['metadata_registration_va'] = roots['metadata_registration']
    profile['solver'] = md
    return profile
