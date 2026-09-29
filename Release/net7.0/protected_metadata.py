#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional



def align4(x: int) -> int:
    return (x + 3) & ~3


class ELF64:
    PT_LOAD = 1

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file")
        if self.data[4] != 2:
            raise ValueError("Only ELF64 is supported")
        if self.data[5] != 1:
            raise ValueError("Only little-endian ELF is supported")

        self.e_type = self.u16_file(0x10)
        self.e_phoff = self.u64_file(0x20)
        self.e_shoff = self.u64_file(0x28)
        self.e_phentsize = self.u16_file(0x36)
        self.e_phnum = self.u16_file(0x38)
        self.e_shentsize = self.u16_file(0x3A)
        self.e_shnum = self.u16_file(0x3C)
        self.e_shstrndx = self.u16_file(0x3E)

        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type = self.u32_file(off + 0x00)
            if p_type != self.PT_LOAD:
                continue
            p_flags = self.u32_file(off + 0x04)
            p_offset = self.u64_file(off + 0x08)
            p_vaddr = self.u64_file(off + 0x10)
            p_filesz = self.u64_file(off + 0x20)
            p_memsz = self.u64_file(off + 0x28)
            self.loads.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

        if not self.loads:
            raise ValueError("ELF has no PT_LOAD segments")

        self.relocated_u64 = {}
        self._load_relative_relocations()

    def u16_file(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32_file(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64_file(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def _load_relative_relocations(self) -> None:
        if not self.e_shoff or not self.e_shnum or not self.e_shentsize:
            return
        SHT_RELA = 4
        R_AARCH64_RELATIVE = 1027
        for i in range(self.e_shnum):
            sh = self.e_shoff + i * self.e_shentsize
            if sh + 0x40 > len(self.data):
                break
            if self.u32_file(sh + 0x04) != SHT_RELA:
                continue
            sh_offset = self.u64_file(sh + 0x18)
            sh_size = self.u64_file(sh + 0x20)
            sh_entsize = self.u64_file(sh + 0x38) or 24
            if sh_entsize < 24:
                continue
            off = sh_offset
            end = min(sh_offset + sh_size, len(self.data))
            while off + 24 <= end:
                r_offset = self.u64_file(off + 0x00)
                r_info = self.u64_file(off + 0x08)
                r_addend = struct.unpack_from("<q", self.data, off + 0x10)[0]
                if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
                    self.relocated_u64[r_offset] = r_addend & 0xFFFFFFFFFFFFFFFF
                off += sh_entsize

    def va_to_off(self, va: int, size: int = 1) -> int:
        for p_vaddr, p_offset, p_filesz, p_memsz, _ in self.loads:
            if p_vaddr <= va and va + size <= p_vaddr + p_filesz:
                return p_offset + (va - p_vaddr)
        raise ValueError(f"VA 0x{va:X} (size {size}) is not file-backed")

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_off(va, size)
        return self.data[off:off + size]

    def u8(self, va: int) -> int:
        return self.read(va, 1)[0]

    def u16(self, va: int) -> int:
        return struct.unpack("<H", self.read(va, 2))[0]

    def i16(self, va: int) -> int:
        return struct.unpack("<h", self.read(va, 2))[0]

    def u32(self, va: int) -> int:
        return struct.unpack("<I", self.read(va, 4))[0]

    def i32(self, va: int) -> int:
        return struct.unpack("<i", self.read(va, 4))[0]

    def u64(self, va: int) -> int:
        relocated = self.relocated_u64.get(va)
        if relocated is not None:
            return relocated
        return struct.unpack("<Q", self.read(va, 8))[0]

    def cstr(self, va: int, max_len: int = 0x10000) -> str:
        off = self.va_to_off(va)
        end = self.data.find(b"\0", off, min(len(self.data), off + max_len))
        if end < 0:
            end = min(len(self.data), off + max_len)
        raw = self.data[off:end]
        return raw.decode("utf-8", errors="replace")



PROTECTED_HEADER_SIZE = 0x17C
MAX_METADATA_REL = 0x04000000


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _a64_adrp(insn: int, pc: int):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = _sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + imm


def _a64_add_imm(insn: int):
    # ADD Xd, Xn, #imm{, LSL #12}
    if (insn & 0x7F000000) != 0x11000000 or not (insn & 0x80000000) or ((insn >> 29) & 1):
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    if (insn >> 22) & 1:
        imm <<= 12
    return rd, rn, imm


def _a64_ldr_x_unsigned(insn: int):
    if (insn & 0xFFC00000) != 0xF9400000:
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = ((insn >> 10) & 0xFFF) * 8
    return rt, rn, imm


def _a64_bl_target(insn: int, pc: int):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x03FFFFFF
    return pc + (_sign_extend(imm26, 26) << 2)


def _is_file_backed(elf: ELF64, va: int, size: int = 1) -> bool:
    try:
        elf.va_to_off(va, size)
        return True
    except Exception:
        return False


def _file_off_to_va(elf: ELF64, off: int) -> Optional[int]:
    for p_vaddr, p_offset, p_filesz, _, _ in elf.loads:
        if p_offset <= off < p_offset + p_filesz:
            return p_vaddr + (off - p_offset)
    return None


def _sample_indices(count: int, limit: int = 32) -> list[int]:
    if count <= 0:
        return []
    if count <= limit:
        return list(range(count))
    head = list(range(min(8, count)))
    tail = [count - 1 - i for i in range(min(4, count))]
    middle = [int(i * (count - 1) / (limit - 1)) for i in range(limit)]
    return sorted(set(head + tail + middle))


def _header_values(elf: ELF64, base: int) -> dict[int, int]:
    raw = elf.read(base, PROTECTED_HEADER_SIZE)
    return {off: struct.unpack_from('<I', raw, off)[0] for off in range(0, len(raw) & ~3, 4)}


def _ratio_pairs(values: dict[int, int], record_size: int) -> list[tuple[int, int, int, int]]:
    by_value: dict[int, list[int]] = {}
    for pos, value in values.items():
        by_value.setdefault(value, []).append(pos)
    result = []
    for count_pos, count in values.items():
        if not (0 < count < 2_000_000):
            continue
        size = count * record_size
        for size_pos in by_value.get(size, []):
            result.append((size_pos, size, count_pos, count))
    return result


def _candidate_offsets(elf: ELF64, base: int, values: dict[int, int]) -> list[tuple[int, int]]:
    out = []
    seen = set()
    for pos, value in values.items():
        if value < PROTECTED_HEADER_SIZE or value >= MAX_METADATA_REL:
            continue
        if value in seen:
            continue
        if _is_file_backed(elf, base + value, 4):
            seen.add(value)
            out.append((pos, value))
    return out


def _token_table_score(elf: ELF64, base: int, rel: int, count: int, record_size: int,
                       token_off: int, token_prefix: int) -> float:
    hits = 0
    total = 0
    for i in _sample_indices(count):
        try:
            token = elf.u32(base + rel + i * record_size + token_off)
        except Exception:
            continue
        total += 1
        if (token & 0xFF000000) == token_prefix:
            hits += 1
    return hits / total if total else 0.0


def _generic_container_score(elf: ELF64, base: int, rel: int, count: int) -> float:
    good = total = 0
    for i in _sample_indices(count):
        va = base + rel + i * 16
        try:
            argc = elf.u32(va)
            owner = elf.i32(va + 4)
            start = elf.i32(va + 8)
            is_method = elf.u32(va + 12)
        except Exception:
            continue
        total += 1
        if 1 <= argc <= 128 and is_method in (0, 1) and owner >= -1 and start >= 0:
            good += 1
    return good / total if total else 0.0


def _generic_param_score(elf: ELF64, base: int, rel: int, count: int) -> float:
    good = total = 0
    for i in _sample_indices(count):
        va = base + rel + i * 14
        try:
            num = elf.u16(va)
            constraints_count = elf.u16(va + 2)
            constraints_start = elf.u16(va + 4)
            name_index = elf.i32(va + 8)
            flags = elf.u16(va + 12)
        except Exception:
            continue
        total += 1
        if num < 256 and constraints_count < 256 and constraints_start < 0xFFFF and name_index > 0 and flags < 0x4000:
            good += 1
    return good / total if total else 0.0


def _image_score(elf: ELF64, base: int, rel: int, count: int, type_count: int) -> float:
    good = total = 0
    for i in _sample_indices(count):
        va = base + rel + i * 36
        try:
            assembly_index = elf.i32(va)
            image_type_count = elf.u32(va + 0x1A)
            name_index = elf.i32(va + 0x1E)
        except Exception:
            continue
        total += 1
        if (-1 <= assembly_index < max(count + 32, 1024) and
                0 < image_type_count <= type_count and 0 < name_index < MAX_METADATA_REL):
            good += 1
    return good / total if total else 0.0


def _pick_ratio_table(elf: ELF64, base: int, values: dict[int, int], candidates: list[tuple[int, int]],
                      record_size: int, scorer, name: str, used: set[int], min_score: float = 0.72):
    best = None
    for size_pos, size, count_pos, count in _ratio_pairs(values, record_size):
        if count == 0:
            continue
        
        for offset_pos, rel in candidates:
            if rel in used:
                continue
            if not _is_file_backed(elf, base + rel, min(size, record_size)):
                continue
            
            # Sirreeffama: BYPASS haxaa'ameera, amma scorer sirriitti hojjeta
            score = scorer(rel, count)
            
            item = (score, rel, offset_pos, size, size_pos, count, count_pos)
            if best is None or item > best:
                best = item
                
    if best is None or best[0] < 0.5:
        raise ValueError(f'Heuristic failed to locate {name} table')
    
    score, rel, offset_pos, size, size_pos, count, count_pos = best
    used.add(rel)
    return {
        'offset': rel, 'size': size, 'count': count,
        'offset_field': offset_pos, 'size_field': size_pos, 'count_field': count_pos,
        'score': score,
    }

def _cstring_quality(raw: bytes) -> float:
    if not raw:
        return 0.0
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.2
    printable = sum((ch.isprintable() or ch in '\t\r\n') for ch in text) / len(text)
    return printable


def _read_cstr_raw(elf: ELF64, va: int, max_len: int = 160) -> bytes:
    try:
        off = elf.va_to_off(va)
    except Exception:
        return b''
    end = elf.data.find(b'\0', off, min(len(elf.data), off + max_len))
    if end < 0:
        return b''
    return elf.data[off:end]


def _discover_string_heap(elf: ELF64, base: int, candidates: list[tuple[int, int]], tables: dict, used: set[int]) -> dict:
    indices: list[int] = []
    # Fixed name-index positions in the protected compact records.
    for table_name, rec_size, name_off in [
        ('fields', 12, 4), ('methods', 32, 0x0A), ('parameters', 12, 0),
        ('generic_parameters', 14, 8), ('images', 36, 0x1E), ('properties', 20, 0x10),
    ]:
        t = tables.get(table_name)
        if not t:
            continue
        for i in _sample_indices(t['count'], 20):
            try:
                idx = elf.i32(base + t['offset'] + i * rec_size + name_off)
            except Exception:
                continue
            if 0 <= idx < MAX_METADATA_REL:
                indices.append(idx)
    td = tables.get('type_definitions')
    if td:
        for i in _sample_indices(td['count'], 20):
            try:
                idx = elf.i32(base + td['offset'] + i * 82 + 78)
                ns = elf.i32(base + td['offset'] + i * 82 + 4)
            except Exception:
                continue
            if 0 <= idx < MAX_METADATA_REL:
                indices.append(idx)
            if 0 <= ns < MAX_METADATA_REL:
                indices.append(ns)

    indices = list(dict.fromkeys(indices))[:120]
    best = None
    for pos, rel in candidates:
        if rel in used:
            continue
        good = dll = total = 0
        for idx in indices:
            raw = _read_cstr_raw(elf, base + rel + idx)
            if not raw:
                continue
            total += 1
            q = _cstring_quality(raw)
            if q >= 0.92:
                good += 1
                if raw.lower().endswith(b'.dll'):
                    dll += 1
        if not total:
            continue
        score = good / total + min(dll, 8) * 0.20
        item = (score, dll, good, total, rel, pos)
        if best is None or item > best:
            best = item
    if best is None or best[0] < 0.65:
        raise ValueError('Heuristic failed to locate metadata string heap')
    _, _, _, _, rel, pos = best
    used.add(rel)
    return {'offset': rel, 'offset_field': pos, 'score': best[0]}


def _literal_offsets_score(elf: ELF64, base: int, rel: int, count: int) -> float:
    if count < 2:
        return 0.0
    try:
        if elf.u32(base + rel) != 0:
            return 0.0
        prev = 0
        checks = _sample_indices(count, 40)
        for i in checks:
            value = elf.u32(base + rel + i * 4)
            if value < 0 or value > 0x08000000:
                return 0.0
        # Strict monotonic check for the first entries; catches almost all false positives cheaply.
        for i in range(min(count, 128)):
            value = elf.u32(base + rel + i * 4)
            if value < prev:
                return 0.0
            prev = value
        last = elf.u32(base + rel + (count - 1) * 4)
        if last <= 0 or last >= 0x08000000:
            return 0.0
        return 1.0
    except Exception:
        return 0.0

def _discover_string_literals(elf: ELF64, base: int, values: dict[int, int], candidates: list[tuple[int, int]], used: set[int]) -> dict:
    print("\n--- STRING LITERAL DEBUG ---")
    by_value: dict[int, list[int]] = {}
    for pos, value in values.items():
        by_value.setdefault(value, []).append(pos)
    best = None
    for size_pos, size, offsets_count_pos, offsets_count in _ratio_pairs(values, 4):
        if offsets_count < 2:
            continue
        literal_count = offsets_count - 1
        literal_count_positions = by_value.get(literal_count, [])
        if not literal_count_positions:
            continue
        for off_pos, rel in candidates:
            if rel in used:
                continue
            score = _literal_offsets_score(elf, base, rel, offsets_count)
            if score <= 0:
                continue
            try:
                data_size = elf.u32(base + rel + literal_count * 4)
            except Exception:
                continue
            score += 0.75 if data_size in by_value else 0.0
            item = (score, -offsets_count, rel, off_pos, size_pos, offsets_count_pos,
                    literal_count, literal_count_positions[0], data_size)
            if best is None or item > best:
                best = item
            print(f"[Offsets] field: 0x{off_pos:X} -> rel: 0x{rel:X} | count: {offsets_count} | score: {score}")

    if best is None:
        raise ValueError('Heuristic failed to locate string literal offset table')
    
    _, neg_offsets_count, offsets_rel, offsets_pos, size_pos, offsets_count_pos, literal_count, literal_count_pos, data_size = best
    offsets_count = -neg_offsets_count
    used.add(offsets_rel)
    
    print(f"\n[WIN Offsets] field: 0x{offsets_pos:X} -> rel: 0x{offsets_rel:X} | lit_count: {literal_count} | data_size: {data_size}")

    raw_offsets = [elf.u32(base + offsets_rel + i * 4) for i in range(min(offsets_count, 96))]
    data_best = None
    for pos, rel in candidates:
        if rel in used or not _is_file_backed(elf, base + rel, min(data_size, 4)):
            continue
        good = total = 0
        for i in range(min(literal_count, len(raw_offsets) - 1, 64)):
            a, b = raw_offsets[i], raw_offsets[i + 1]
            if b < a or b - a > 0x10000:
                continue
            try:
                raw = elf.read(base + rel + a, b - a)
            except Exception:
                continue
            total += 1
            if not raw or _cstring_quality(raw.rstrip(b'\0')) >= 0.72:
                good += 1
        if total:
            score = good / total
            print(f"[Data] field: 0x{pos:X} -> rel: 0x{rel:X} | score: {score:.2f} ({good}/{total})")
            item = (score, rel, pos)
            if data_best is None or item > data_best:
                data_best = item

    if data_best is None or data_best[0] < 0.40:
        print("\n[!] ОШИБКА: Data blob не пройден эвристикой. Идем дальше с заглушкой для проверки остального!")
        return {
            'offsets_off': offsets_rel, 'offsets_field': offsets_pos,
            'offsets_count': offsets_count, 'offsets_count_field': offsets_count_pos,
            'literal_count': literal_count, 'literal_count_field': literal_count_pos,
            'data_off': 0, 'data_field': 0, 'data_size': data_size,
            'offsets_size_field': size_pos,
        }
    
    _, data_rel, data_pos = data_best
    print(f"[WIN Data] field: 0x{data_pos:X} -> rel: 0x{data_rel:X}\n")
    used.add(data_rel)
    
    return {
        'offsets_off': offsets_rel, 'offsets_field': offsets_pos,
        'offsets_count': offsets_count, 'offsets_count_field': offsets_count_pos,
        'literal_count': literal_count, 'literal_count_field': literal_count_pos,
        'data_off': data_rel, 'data_field': data_pos, 'data_size': data_size,
        'offsets_size_field': size_pos,
    }
def _array_score(elf: ELF64, base: int, rel: int, count: int, width: int, upper: int, encoded: bool = False) -> float:
    if count <= 0:
        return 0.0
    good = total = 0
    for i in _sample_indices(count, 48):
        try:
            value = read_packed_u(elf, base + rel + i * width, width) if width in (1, 2, 4) else -1
        except Exception:
            continue
        total += 1
        if encoded:
            tag = (value >> 29) & 0x7 if value >= 0 else 0
            index = value & 0x1FFFFFFF if value >= 0 else 0xFFFFFFFF
            if value == 1 or (1 <= tag <= 6 and index < 2_000_000):
                good += 1
        elif value == -1 or 0 <= value < upper:
            good += 1
    return good / total if total else 0.0


def _interface_offset_score(elf: ELF64, base: int, rel: int, count: int, type_width: int) -> float:
    step = type_width + 4
    good = total = 0
    for i in _sample_indices(count, 48):
        va = base + rel + i * step
        try:
            type_index = read_packed_u(elf, va, type_width)
            field_off = elf.i32(va + type_width)
        except Exception:
            continue
        total += 1
        if (type_index == -1 or 0 <= type_index < 2_000_000) and -0x100000 <= field_off <= 0x100000:
            good += 1
    return good / total if total else 0.0


def discover_protected_layout(elf: ELF64, base: int) -> dict:
    values = _header_values(elf, base)

    def get_table(off_pos, size_pos, count_pos):
        return {
            'offset': elf.u32(base + off_pos),
            'size': elf.u32(base + size_pos),
            'count': elf.u32(base + count_pos),
            'score': 1.0,
            'offset_field': off_pos,
            'size_field': size_pos,
            'count_field': count_pos,
        }

    # This protector shuffles the GlobalMetadataHeader dwords.  These field
    # positions are not guesses: they are taken from the runtime accessors in
    # libunity.so (0x63428A4, 0x63436E0, 0x634420C, 0x63443E0, ...).
    tables = {
        'type_definitions': get_table(0x94, 0xF8, 0xFC),
        'methods': get_table(0x13C, 0x40, 0x04),
        'fields': get_table(0x28, 0x138, 0x5C),
        'parameters': get_table(0x24, 0xB0, 0x10C),
        'images': get_table(0x118, 0x160, 0x140),
        'properties': get_table(0x108, 0x0C, 0x8C),
        'events': get_table(0x120, 0x114, 0x150),
        'generic_containers': get_table(0xC0, 0x12C, 0xD8),
        'generic_parameters': get_table(0x14C, 0x78, 0xDC),
    }

    # Width descriptors are produced by sub_B2F55C8(count): 1 / 2 / 4 bytes.
    # typesCount comes from MetadataRegistration at runtime and is > 0xFFFF in
    # this build, so protected TypeIndex is four bytes.  The other three counts
    # are present directly in the shuffled header.
    width_type_index = 4
    width_type_def = 1 if tables['type_definitions']['count'] < 0x100 else 2 if tables['type_definitions']['count'] < 0x10000 else 4
    width_gc = 1 if tables['generic_containers']['count'] < 0x100 else 2 if tables['generic_containers']['count'] < 0x10000 else 4
    width_param = 1 if tables['parameters']['count'] < 0x100 else 2 if tables['parameters']['count'] < 0x10000 else 4

    string_heap = {'offset': elf.u32(base + 0x88), 'offset_field': 0x88, 'score': 1.0}

    literal_count = elf.u32(base + 0x00)
    offsets_count = elf.u32(base + 0xD4)
    offsets_off = elf.u32(base + 0x6C)
    data_off = elf.u32(base + 0xC4)
    data_size = 0
    if offsets_count:
        try:
            data_size = elf.u32(base + offsets_off + (offsets_count - 1) * 4)
        except Exception:
            data_size = 0
    literals = {
        'offsets_off': offsets_off, 'offsets_field': 0x6C,
        'offsets_count': offsets_count, 'offsets_count_field': 0xD4,
        'literal_count': literal_count, 'literal_count_field': 0x00,
        'data_off': data_off, 'data_field': 0xC4, 'data_size': data_size,
        'offsets_size_field': 0,
    }

    # Secondary arrays.  Their element widths are verified by their accessors:
    # nestedTypes are canonical int32 TypeDefinitionIndex values; interfaces and
    # generic constraints are 4-byte TypeIndex values; vtableMethods are uint32;
    # interfaceOffsets are {TypeIndex,int32} (8 bytes here).
    nested_count = elf.u32(base + 0x64)
    interfaces_count = elf.u32(base + 0x44)
    vtable_count = elf.u32(base + 0x130)
    ifoff_count = elf.u32(base + 0x124)
    constraint_count = 0
    # GenericParameter constraints form one contiguous table.  The last used
    # slot is recovered later from parsed generic parameters; 1883 is also equal
    # to header[0x10] / 4 for this exact build.
    constraint_size = elf.u32(base + 0x10)
    if width_type_index:
        constraint_count = constraint_size // width_type_index

    secondary = {
        'nested_types': {'offset': elf.u32(base + 0xF0), 'count': nested_count, 'size': elf.u32(base + 0x164), 'score': 1.0},
        'interfaces': {'offset': elf.u32(base + 0x148), 'count': interfaces_count, 'size': elf.u32(base + 0x9C), 'score': 1.0},
        'generic_constraints': {'offset': elf.u32(base + 0x80), 'count': constraint_count, 'size': constraint_size, 'score': 1.0},
        'vtable_methods': {'offset': elf.u32(base + 0x54), 'count': vtable_count, 'size': elf.u32(base + 0x98), 'score': 1.0},
        'interface_offsets': {'offset': elf.u32(base + 0x38), 'count': ifoff_count, 'size': elf.u32(base + 0xCC), 'score': 1.0},
    }

    return {
        'metadata_va': base,
        'tables': tables,
        'secondary': secondary,
        'string_heap': string_heap,
        'string_literals': literals,
        'widths': {
            'type_index': width_type_index,
            'type_definition': width_type_def,
            'generic_container': width_gc,
            'parameter': width_param,
        },
        'header_fields': {hex(k): v for k, v in values.items()},
    }

def score_protected_header(elf: ELF64, base: int) -> float:
    if not _is_file_backed(elf, base, PROTECTED_HEADER_SIZE):
        return 0.0
    try:
        values = _header_values(elf, base)
    except Exception:
        return 0.0
    score = 0.0
    weights = {82: 5.0, 32: 4.0, 36: 4.0, 24: 3.0, 14: 3.0, 16: 3.0, 20: 2.0, 12: 1.5, 8: 1.0, 4: 0.5}
    for rec, weight in weights.items():
        if _ratio_pairs(values, rec):
            score += weight
    value_set = set(values.values())
    if any((v + 1) in value_set for v in value_set if 100 < v < 1_000_000):
        score += 2.0
    mapped_offsets = len(_candidate_offsets(elf, base, values))
    score += min(mapped_offsets / 8.0, 4.0)
    return score


def _primary_metadata_probe(elf: ELF64, base: int) -> float:
    """
    Reject arithmetic false-positives before accepting a protected metadata base.

    A shuffled header contains many integers, so unrelated data can accidentally
    satisfy equations such as count * record_size == size.  A real protected
    metadata header must additionally point at tables whose records carry the
    expected IL2CPP token families.  Probe TypeDefinition + MethodDefinition
    here because they are large, mandatory tables and give a very strong signal.
    """
    if not _is_file_backed(elf, base, PROTECTED_HEADER_SIZE):
        return 0.0
    try:
        values = _header_values(elf, base)
        candidates = _candidate_offsets(elf, base, values)
        used: set[int] = set()

        td = _pick_ratio_table(elf, base, values, candidates, 82, lambda rel, count: _token_table_score(elf, base, rel, count, 82, 74, 0x02000000), 'type definitions', used, 0.68)
        methods = _pick_ratio_table(
            elf, base, values, candidates, 32,
            lambda rel, count: _token_table_score(elf, base, rel, count, 32, 0, 0x06000000),
            'methods', used, 0.68,
        )
    except Exception:
        return 0.0

    # Tiny accidental arrays are much easier to fake than real IL2CPP tables.
    # Keep this only as a soft bonus rather than a hard game-specific threshold.
    scale_bonus = 0.0
    if td['count'] >= 256:
        scale_bonus += 0.25
    if methods['count'] >= 1024:
        scale_bonus += 0.25
    return td['score'] + methods['score'] + scale_bonus


def _resolve_pointer_loader(elf: ELF64, func_va: int) -> Optional[int]:
    regs: dict[int, int] = {}
    for i in range(12):
        pc = func_va + i * 4
        try:
            insn = elf.u32(pc)
        except Exception:
            break
        adrp = _a64_adrp(insn, pc)
        if adrp:
            regs[adrp[0]] = adrp[1]
            continue
        add = _a64_add_imm(insn)
        if add and add[1] in regs:
            regs[add[0]] = regs[add[1]] + add[2]
            continue
        ldr = _a64_ldr_x_unsigned(insn)
        if ldr and ldr[1] in regs:
            ptr_addr = regs[ldr[1]] + ldr[2]
            try:
                value = elf.u64(ptr_addr)
            except Exception:
                continue
            regs[ldr[0]] = value
            if ldr[0] == 0 and score_protected_header(elf, value) >= 12.0:
                if _primary_metadata_probe(elf, value) >= 1.36:
                    return value
    return None


def discover_metadata_base(elf: ELF64) -> int:
    # Fast path: collect relocated qwords that look like shuffled headers, but
    # NEVER accept one from arithmetic coincidences alone.  Rank candidates by
    # the cheap header score, then require semantic TypeDefinition/MethodDefinition
    # validation before returning it.
    seen: set[int] = set()
    ranked: list[tuple[float, int]] = []

    for value in elf.relocated_u64.values():
        if value in seen or value & 3 or not _is_file_backed(elf, value, PROTECTED_HEADER_SIZE):
            continue
        seen.add(value)
        try:
            vals = list(_header_values(elf, value).values())
        except Exception:
            continue
        vset = set(vals)
        plausible = [v for v in vals if 0 < v < 2_000_000]

        # Cheap prefilter only.  This is deliberately not sufficient for acceptance:
        # unrelated tables can satisfy these equations by chance (e.g. 28*82).
        has_td_ratio = any(v * 82 in vset for v in plausible)
        has_method_ratio = any(v * 32 in vset for v in plausible)
        if not (has_td_ratio and has_method_ratio):
            continue

        score = score_protected_header(elf, value)
        if score >= 8.0:
            ranked.append((score, value))

    ranked.sort(reverse=True)
    for _, value in ranked:
        if _primary_metadata_probe(elf, value) >= 1.36:
            return value

    # Second relocation pass: in case a future build weakens one of the cheap
    # ratio signals, allow any moderately header-like relocated pointer through
    # the stronger semantic probe.
    broader: list[tuple[float, int]] = []
    seen.clear()
    for value in elf.relocated_u64.values():
        if value in seen or value & 3 or not _is_file_backed(elf, value, PROTECTED_HEADER_SIZE):
            continue
        seen.add(value)
        score = score_protected_header(elf, value)
        if score >= 6.0:
            broader.append((score, value))
    broader.sort(reverse=True)
    for _, value in broader[:256]:
        if _primary_metadata_probe(elf, value) >= 1.36:
            return value

    # Fallback for binaries where the metadata pointer is materialized without
    # a RELATIVE relocation: resolve the AArch64 reference to global-metadata.dat,
    # then follow the nearby BL into the tiny pointer-loader.  The pointer-loader
    # result is also semantically validated by _resolve_pointer_loader().
    needle = b'global-metadata.dat\0'
    start = 0
    string_vas = []
    while True:
        off = elf.data.find(needle, start)
        if off < 0:
            break
        va = _file_off_to_va(elf, off)
        if va is not None:
            string_vas.append(va)
        start = off + 1

    targets = set(string_vas)
    for p_vaddr, p_offset, p_filesz, _, p_flags in elf.loads:
        if not (p_flags & 1):
            continue
        seg = elf.data[p_offset:p_offset + p_filesz]
        for rel in range(0, max(0, len(seg) - 8), 4):
            pc = p_vaddr + rel
            insn1 = struct.unpack_from('<I', seg, rel)[0]
            adrp = _a64_adrp(insn1, pc)
            if not adrp:
                continue
            insn2 = struct.unpack_from('<I', seg, rel + 4)[0]
            add = _a64_add_imm(insn2)
            if not add or add[1] != adrp[0] or add[0] != adrp[0]:
                continue
            target = adrp[1] + add[2]
            if target not in targets:
                continue
            ref_end = pc + 8
            for j in range(0, 8):
                call_pc = ref_end + j * 4
                try:
                    call = _a64_bl_target(elf.u32(call_pc), call_pc)
                except Exception:
                    continue
                if call is None:
                    continue
                candidate = _resolve_pointer_loader(elf, call)
                if candidate is not None:
                    return candidate
    print(f"[debug] Relocated pointers evaluated: {len(elf.relocated_u64)}")
    print(f"[debug] Candidates ranked: {len(ranked)}, broader: {len(broader)}")
    print(f"[debug] global-metadata.dat refs found: {len(targets)}")
    raise ValueError('Unable to locate protected metadata base heuristically')

def discover_code_registration(elf: ELF64, md) -> int:
    image_count = md.images_count
    needle = struct.pack('<I', image_count)
    best = (0.0, 0)
    for p_vaddr, p_offset, p_filesz, _, p_flags in elf.loads:
        if p_flags & 1:
            continue
        blob = elf.data[p_offset:p_offset + p_filesz]
        at = 0
        while True:
            hit = blob.find(needle, at)
            if hit < 0:
                break
            at = hit + 1
            hit_va = p_vaddr + hit
            base = hit_va - 0x44
            if base < p_vaddr or not _is_file_backed(elf, base, 0x78):
                continue
            try:
                modules = elf.u64(base + 0x30)
            except Exception:
                continue
            if not modules or not _is_file_backed(elf, modules, min(image_count, 4) * 8):
                continue
            good = total = 0
            for i in _sample_indices(image_count, 12):
                try:
                    mod = elf.u64(modules + i * 8)
                    name_ptr = elf.u64(mod + 0x80)
                    raw = _read_cstr_raw(elf, name_ptr, 200)
                except Exception:
                    continue
                total += 1
                if raw and (raw.lower().endswith(b'.dll') or _cstring_quality(raw) > 0.95):
                    good += 1
            if total:
                score = good / total
                if score > best[0]:
                    best = (score, base)
    if best[0] >= 0.65:
        return best[1]
    return 0


def discover_metadata_registration(elf: ELF64, code_reg: int, md) -> int:
    if not code_reg:
        return 0
    best = (0.0, 0)
    start = max(0, code_reg - 0x200)
    end = code_reg + 0x400
    for cand in range((start + 7) & ~7, end, 8):
        if not _is_file_backed(elf, cand, 0x70):
            continue
        try:
            types_count = elf.u32(cand + 0x1C)
            types_ptr = elf.u64(cand + 0x68)
            field_offsets = elf.u64(cand + 0x08)
        except Exception:
            continue
        if not (md.type_defs_count <= types_count < 2_000_000):
            continue
        if not types_ptr or not _is_file_backed(elf, types_ptr, 8):
            continue
        good = total = 0
        for i in _sample_indices(min(types_count, 128), 16):
            try:
                type_ptr = elf.u64(types_ptr + i * 8)
                if not type_ptr or not _is_load_mapped(elf, type_ptr, 16):
                    continue
                kind = elf.u8(type_ptr + 1)
            except Exception:
                continue
            total += 1
            if 0 < kind < 0x40:
                good += 1
        score = (good / total if total else 0.0)
        if field_offsets and _is_file_backed(elf, field_offsets, 8):
            score += 0.2
        if score > best[0]:
            best = (score, cand)
    return best[1] if best[0] >= 0.70 else 0

def sentinel(v: int, width: int) -> int:
    if width == 1:
        return -1 if v == 0xFF else v
    if width == 2:
        return -1 if v == 0xFFFF else v
    if width == 4:
        return -1 if v == 0xFFFFFFFF else v
    raise ValueError(width)


def read_packed_u(elf: ELF64, va: int, width: int) -> int:
    if width == 1:
        return sentinel(elf.u8(va), 1)
    if width == 2:
        return sentinel(elf.u16(va), 2)
    if width == 4:
        return sentinel(elf.u32(va), 4)
    raise ValueError(width)


@dataclass
class TypeDef:
    index: int
    nested_type_count: int
    event_count: int
    namespace_index: int
    interface_offsets_count: int
    declaring_type_index: int
    field_count: int
    type_index: int
    bitfield: int
    parent_index: int
    nested_types_start: int
    field_start: int
    vtable_start: int
    event_start: int
    interfaces_start: int
    method_count: int
    property_start: int
    method_start: int
    interfaces_count: int
    flags: int
    vtable_count: int
    interface_offsets_start: int
    generic_container_index: int
    property_count: int
    token: int
    name_index: int
    name: str = ""
    namespace: str = ""


@dataclass
class MethodDef:
    index: int
    token: int
    parameter_count: int
    iflags: int
    flags: int
    name_index: int
    declaring_type: int
    slot: int
    aux: int
    parameter_start: int
    generic_container_index: int
    return_type: int
    name: str = ""
    method_pointer: int = 0
    rva: int = 0


@dataclass
class FieldDef:
    index: int
    token: int
    name_index: int
    type_index: int
    name: str = ""
    offset: Optional[int] = None


@dataclass
class ParamDef:
    index: int
    name_index: int
    type_index: int
    token: int
    name: str = ""


@dataclass
class GenericContainer:
    index: int
    type_argc: int
    owner_index: int
    generic_parameter_start: int
    is_method: int


@dataclass
class GenericParameter:
    index: int
    num: int
    constraints_count: int
    constraints_start: int
    owner_container_index: int
    name_index: int
    flags: int
    name: str = ""


@dataclass
class ImageDef:
    index: int
    assembly_index: int
    type_count: int
    name_index: int
    type_start: int
    name: str = ""
    codegen_module_va: int = 0


class ProtectedMetadata:
    def __init__(
        self,
        elf: ELF64,
        metadata_va: int,
        code_reg_va: int = 0,
        metadata_reg_va: int = 0,
        string_literal_offsets_field: int = 0x160,
        string_literal_data_field: int = 0x138,
        string_literal_count_field: int = 0x0FC,
        string_literal_offsets_count_field: int = 0x044,
        layout: Optional[dict] = None,
    ):
        self.elf = elf
        self.base = metadata_va
        self.code_reg = code_reg_va
        self.metadata_reg = metadata_reg_va
        self.heuristic_layout = layout

        if layout is not None:
            t = layout['tables']
            sec = layout['secondary']
            lit = layout['string_literals']
            widths = layout['widths']

            self.string_off = layout['string_heap']['offset']
            self.string_literal_offsets_off = lit['offsets_off']
            self.string_literal_data_off = lit['data_off']
            self.string_literal_count = lit['literal_count']
            self.string_literal_offsets_count = lit['offsets_count']

            self.type_defs_off = t['type_definitions']['offset']
            self.type_defs_size = t['type_definitions']['size']
            self.type_defs_count = t['type_definitions']['count']

            self.fields_off = t['fields']['offset']
            self.fields_size = t['fields']['size']
            self.fields_count = t['fields']['count']

            self.methods_off = t['methods']['offset']
            self.methods_size = t['methods']['size']
            self.methods_count = t['methods']['count']

            self.params_off = t['parameters']['offset']
            self.params_size = t['parameters']['size']
            self.params_count = t['parameters']['count']

            self.events_off = t['events']['offset']
            self.events_size = t['events']['size']
            self.events_count = t['events']['count']

            self.properties_off = t['properties']['offset']
            self.properties_count = t['properties']['count']

            self.images_off = t['images']['offset']
            self.images_size = t['images']['size']
            self.images_count = t['images']['count']

            self.generic_containers_off = t['generic_containers']['offset']
            self.generic_containers_count = t['generic_containers']['count']

            self.generic_params_off = t['generic_parameters']['offset']
            self.generic_params_size = t['generic_parameters']['size']
            self.generic_params_count = t['generic_parameters']['count']

            self.nested_type_indices_off = sec['nested_types']['offset']
            self.interface_type_indices_off = sec['interfaces']['offset']
            self.generic_constraint_type_indices_off = sec['generic_constraints']['offset']
            self.vtable_methods_off = sec['vtable_methods']['offset']
            self.interface_offsets_off = sec['interface_offsets']['offset']
            self.interface_offsets_size = sec['interface_offsets'].get('size', 0)
            self.interface_offsets_count = sec['interface_offsets'].get('count', 0)

            self.width_type_index = widths['type_index']
            self.width_type_def = widths['type_definition']
            self.width_generic_container = widths['generic_container']
            self.width_param = widths['parameter']
        else:
            self.string_off = self.h32(0x150)
            self.string_literal_offsets_off = self.h32(string_literal_offsets_field)
            self.string_literal_data_off = self.h32(string_literal_data_field)
            self.string_literal_count = self.h32(string_literal_count_field)
            self.string_literal_offsets_count = self.h32(string_literal_offsets_count_field)

            self.type_defs_off = self.h32(0x068)
            self.type_defs_size = self.h32(0x11C)
            self.type_defs_count = self.h32(0x154)

            self.fields_off = self.h32(0x080)
            self.fields_size = self.h32(0x110)
            self.fields_count = self.h32(0x0F0)

            self.methods_off = self.h32(0x148)
            self.methods_size = self.h32(0x10C)
            self.methods_count = self.h32(0x124)

            self.params_off = self.h32(0x178)
            self.params_size = self.h32(0x13C)
            self.params_count = self.h32(0x0D0)

            self.events_off = self.h32(0x0A0)
            self.events_size = self.h32(0x048)
            self.events_count = self.h32(0x060)

            self.properties_off = self.h32(0x170)
            self.properties_count = 0

            self.images_off = self.h32(0x0BC)
            self.images_size = self.h32(0x0B8)
            self.images_count = self.h32(0x14C)

            self.generic_containers_off = self.h32(0x0F4)
            self.generic_containers_count = self.h32(0x100)

            self.generic_params_off = self.h32(0x158)
            self.generic_params_size = self.h32(0x014)
            self.generic_params_count = self.h32(0x00C)

            self.nested_type_indices_off = self.h32(0x09C)
            self.interface_type_indices_off = self.h32(0x07C)
            self.generic_constraint_type_indices_off = self.h32(0x074)
            self.vtable_methods_off = self.h32(0x98)
            self.interface_offsets_off = self.h32(0xAC)
            self.interface_offsets_size = self.h32(0xA4)
            self.interface_offsets_count = self.h32(0x5C)

            if self.metadata_reg:
                types_count = self.elf.u32(self.metadata_reg + 0x1C)
                self.width_type_index = self.index_width(types_count)
            else:
                self.width_type_index = 4
            self.width_type_def = self.index_width(self.type_defs_count)
            self.width_generic_container = self.index_width(self.generic_containers_count)
            self.width_param = self.index_width(self.params_count)

        self.type_def_entry_size = 82
        self.field_entry_size = 12
        self.method_entry_size = 32
        self.param_entry_size = 12
        self.event_entry_size = 24
        self.image_entry_size = 36
        self.generic_param_entry_size = 14

        self.type_defs: list[TypeDef] = []
        self.images: list[ImageDef] = []
        self.generic_containers: list[GenericContainer] = []
        self.generic_params: list[GenericParameter] = []
        self.type_index_to_typedef: dict[int, TypeDef] = {}
        self.modules_by_name: dict[str, int] = {}

    @staticmethod
    def index_width(count: int) -> int:
        if count < 0x100:
            return 1
        if count < 0x10000:
            return 2
        return 4

    def h32(self, off: int) -> int:
        return self.elf.u32(self.base + off)

    def hs32(self, off: int) -> int:
        return self.elf.i32(self.base + off)

    def str(self, index: int) -> str:
        if index < 0:
            return ""
        try:
            return self.elf.cstr(self.base + self.string_off + index)
        except Exception:
            return f"<bad-string:{index}>"

    def _validate_layout(self) -> None:
        if self.string_literal_count < 0 or self.string_literal_offsets_count < 0:
            raise ValueError("Invalid string literal counts")
        if self.string_literal_offsets_count not in (self.string_literal_count, self.string_literal_count + 1):
            raise ValueError(
                f"String literal layout mismatch: count={self.string_literal_count}, "
                f"offsets={self.string_literal_offsets_count}"
            )
        expected = {
            "TypeDefinition": (self.type_def_entry_size, 82),
            "FieldDefinition": (self.field_entry_size, 12),
            "MethodDefinition": (self.method_entry_size, 32),
            "ParameterDefinition": (self.param_entry_size, 12),
            "EventDefinition": (self.event_entry_size, 24),
            "ImageDefinition": (self.image_entry_size, 36),
            "GenericParameter": (self.generic_param_entry_size, 14),
        }
        bad = []
        for name, (got, want) in expected.items():
            if got != want:
                bad.append(f"{name}: got {got}, expected {want}")
        if bad:
            raise ValueError("Layout mismatch: " + "; ".join(bad))

    def read_string_literals(self) -> list[bytes]:
        count = self.string_literal_count
        if count == 0:
            return []

        offset_count = self.string_literal_offsets_count
        if offset_count == count:
            offset_count += 1

        offsets = [
            self.elf.u32(self.base + self.string_literal_offsets_off + i * 4)
            for i in range(offset_count)
        ]

        if len(offsets) < count + 1:
            raise ValueError("String literal offset table is truncated")
        if offsets[0] != 0:
            raise ValueError(f"Unexpected first string literal offset: {offsets[0]}")

        previous = 0
        for value in offsets:
            if value < previous:
                raise ValueError("String literal offsets are not monotonic")
            previous = value

        data_size = offsets[count]
        data = self.elf.read(self.base + self.string_literal_data_off, data_size)
        result = []
        for i in range(count):
            start = offsets[i]
            end = offsets[i + 1]
            if end > len(data):
                raise ValueError(f"String literal {i} exceeds literal data")
            result.append(data[start:end])
        return result

    def parse_type_def(self, index: int) -> TypeDef:
        va = self.base + self.type_defs_off + index * 82
        e = self.elf

        # B2F5984 with width tuple [4,2,2,4].  The 82-byte packed input expands
        # to a 92-byte logical record.  Accessors prove the semantic positions.
        parent_index = e.i32(va + 0)
        property_start = e.i32(va + 4)
        event_start = e.i32(va + 8)
        type_index = e.i32(va + 12)              # byval TypeIndex
        interfaces_start = e.i32(va + 16)
        token = e.u32(va + 20)
        field_start = e.i32(va + 24)
        declaring_type_index = e.i32(va + 28)   # protected TypeIndex
        vtable_start = e.i32(va + 32)
        field_count = e.u16(va + 36)
        bitfield = e.u32(va + 38)
        vtable_count = e.u16(va + 42)
        method_count = e.u16(va + 44)
        interface_offsets_count = e.u16(va + 46)
        interface_offsets_start = e.i32(va + 48)
        name_index = e.i32(va + 52)
        property_count = e.u16(va + 56)
        nested_type_count = e.u16(va + 58)
        namespace_index = e.i32(va + 60)
        gc_raw = e.u16(va + 64)
        generic_container_index = -1 if gc_raw == 0xFFFF else gc_raw
        interfaces_count = e.u16(va + 66)
        nested_types_start = e.i32(va + 68)
        method_start = e.i32(va + 72)
        event_count = e.u16(va + 76)
        flags = e.u32(va + 78)

        return TypeDef(
            index=index, nested_type_count=nested_type_count, event_count=event_count,
            namespace_index=namespace_index, interface_offsets_count=interface_offsets_count,
            declaring_type_index=declaring_type_index, field_count=field_count,
            type_index=type_index, bitfield=bitfield, parent_index=parent_index,
            nested_types_start=nested_types_start, field_start=field_start,
            vtable_start=vtable_start, event_start=event_start, interfaces_start=interfaces_start,
            method_count=method_count, property_start=property_start, method_start=method_start,
            interfaces_count=interfaces_count, flags=flags, vtable_count=vtable_count,
            interface_offsets_start=interface_offsets_start, generic_container_index=generic_container_index,
            property_count=property_count, token=token, name_index=name_index,
            name=self.str(name_index), namespace=self.str(namespace_index),
        )

    def parse_method(self, index: int) -> MethodDef:
        va = self.base + self.methods_off + index * self.method_entry_size
        e = self.elf

        # B2F5648, descriptor widths [type=4, typedef=2, gc=2, param=4].
        parameter_start = e.i32(va + 0)
        iflags = e.u16(va + 4)
        gc_raw = e.u16(va + 6)
        generic_container_index = -1 if gc_raw == 0xFFFF else gc_raw
        slot = e.u16(va + 8)
        token = e.u32(va + 10)
        name_index = e.i32(va + 14)
        return_type = e.i32(va + 18)
        aux = e.u32(va + 22)                    # return-parameter token
        declaring_raw = e.u16(va + 26)
        declaring_type = -1 if declaring_raw == 0xFFFF else declaring_raw
        parameter_count = e.u16(va + 28)
        flags = e.u16(va + 30)

        return MethodDef(
            index=index, token=token, parameter_count=parameter_count,
            iflags=iflags, flags=flags, name_index=name_index,
            declaring_type=declaring_type, slot=slot, aux=aux,
            parameter_start=parameter_start,
            generic_container_index=generic_container_index,
            return_type=return_type, name=self.str(name_index),
        )

    def parse_field(self, index: int) -> FieldDef:
        va = self.base + self.fields_off + index * self.field_entry_size
        # B2F58F4 returns {nameIndex, token} in X0 and TypeIndex in W1.
        name_index = self.elf.i32(va + 0)
        token = self.elf.u32(va + 4)
        type_index = read_packed_u(self.elf, va + 8, self.width_type_index)
        return FieldDef(index, token, name_index, type_index, self.str(name_index))

    def parse_param(self, index: int) -> ParamDef:
        va = self.base + self.params_off + index * self.param_entry_size
        # B2F58AC: token, nameIndex, TypeIndex.
        token = self.elf.u32(va + 0)
        name_index = self.elf.i32(va + 4)
        type_index = read_packed_u(self.elf, va + 8, self.width_type_index)
        return ParamDef(index, name_index, type_index, token, self.str(name_index))

    def parse_property(self, index: int) -> dict:
        va = self.base + self.properties_off + index * 0x14
        # sub_63444A0: +4 getter, +16 setter, +8 string, +12 token.
        name_index = self.elf.i32(va + 0x08)
        return {
            'index': index,
            'setter_index': self.elf.i32(va + 0x10),
            'getter_index': self.elf.i32(va + 0x04),
            'token': self.elf.u32(va + 0x0C),
            'attrs': self.elf.u32(va + 0x00),
            'name_index': name_index,
            'name': self.str(name_index),
        }

    def parse_event(self, index: int) -> dict:
        va = self.base + self.events_off + index * self.event_entry_size
        # B2F55E4 output: remove, add, raise, TypeIndex, token, nameIndex.
        name_index = self.elf.i32(va + 0x14)
        return {
            'index': index,
            'raise_method_index': self.elf.i32(va + 0x08),
            'remove_method_index': self.elf.i32(va + 0x00),
            'token': self.elf.u32(va + 0x10),
            'add_method_index': self.elf.i32(va + 0x04),
            'type_index': read_packed_u(self.elf, va + 0x0C, self.width_type_index),
            'name_index': name_index,
            'name': self.str(name_index),
        }

    def parse_generic_container(self, index: int) -> GenericContainer:
        va = self.base + self.generic_containers_off + index * 0x10
        # Runtime accessor sub_63448C4 proves start is dword +4.  All 4041
        # records validate as {argc,start,isMethod,owner}.
        return GenericContainer(
            index=index,
            type_argc=self.elf.u32(va + 0x00),
            owner_index=self.elf.i32(va + 0x0C),
            generic_parameter_start=self.elf.i32(va + 0x04),
            is_method=self.elf.u32(va + 0x08),
        )

    def parse_generic_parameter(self, index: int) -> GenericParameter:
        va = self.base + self.generic_params_off + index * self.generic_param_entry_size
        # B2F5BF0 logical output:
        #   +0 constraintsCount, +4 ownerContainer, +8 nameIndex,
        #   +12 num, +14 constraintsStart, +16 flags.
        constraints_count = self.elf.u16(va + 0x00)
        owner_raw = self.elf.u16(va + 0x02)
        owner = -1 if owner_raw == 0xFFFF else owner_raw
        name_index = self.elf.i32(va + 0x04)
        num = self.elf.u16(va + 0x08)
        constraints_start = self.elf.u16(va + 0x0A)
        flags = self.elf.u16(va + 0x0C)
        return GenericParameter(
            index=index, num=num, constraints_count=constraints_count,
            constraints_start=constraints_start, owner_container_index=owner,
            name_index=name_index, flags=flags, name=self.str(name_index),
        )

    def parse_image(self, index: int) -> ImageDef:
        va = self.base + self.images_off + index * self.image_entry_size
        # B2F5B40 (36 packed bytes -> 40 logical bytes): typeStart is the
        # packed TypeDefinitionIndex at +8, typeCount at +14, name at +24 and
        # assemblyIndex at +32.
        type_start = read_packed_u(self.elf, va + 0x08, self.width_type_def)
        type_count = self.elf.u32(va + 0x0E)
        name_index = self.elf.i32(va + 0x18)
        assembly_index = self.elf.i32(va + 0x20)
        return ImageDef(
            index=index, assembly_index=assembly_index, type_count=type_count,
            name_index=name_index, type_start=type_start, name=self.str(name_index),
        )

    def load_all(self) -> None:
        self.generic_containers = [
            self.parse_generic_container(i) for i in range(self.generic_containers_count)
        ]
        self.generic_params = [
            self.parse_generic_parameter(i) for i in range(self.generic_params_count)
        ]
        self.type_defs = [self.parse_type_def(i) for i in range(self.type_defs_count)]
        self.type_index_to_typedef = {
            t.type_index: t for t in self.type_defs if t.type_index >= 0
        }
        self.images = [self.parse_image(i) for i in range(self.images_count)]
        self._load_codegen_modules()

    def _load_codegen_modules(self) -> None:
        if not self.code_reg:
            return
        count = self.elf.u32(self.code_reg + 0x20)
        arr = self.elf.u64(self.code_reg + 0x30)
        for i in range(count):
            mod = self.elf.u64(arr + i * 8)
            if not mod:
                continue
            try:
                name_ptr = self.elf.u64(mod + 0x78)
                name = self.elf.cstr(name_ptr)
            except Exception:
                continue
            self.modules_by_name[name] = mod

        for img in self.images:
            img.codegen_module_va = self.modules_by_name.get(img.name, 0)

    def image_for_type(self, type_def_index: int) -> Optional[ImageDef]:
        for img in self.images:
            if img.type_start >= 0 and img.type_start <= type_def_index < img.type_start + img.type_count:
                return img
        return None

    def resolve_method_pointer(self, type_def_index: int, method: MethodDef) -> int:
        img = self.image_for_type(type_def_index)
        if not img or not img.codegen_module_va:
            return 0
        rid = method.token & 0x00FFFFFF
        if rid == 0:
            return 0
        mod = img.codegen_module_va
        count = self.elf.u64(mod + 0x08)
        ptrs = self.elf.u64(mod + 0x00)
        if rid > count or not ptrs:
            return 0
        try:
            return self.elf.u64(ptrs + (rid - 1) * 8)
        except Exception:
            return 0

    def field_offset(self, type_def_index: int, local_field_index: int) -> Optional[int]:
        if not self.metadata_reg:
            return None
        try:
            field_offsets = self.elf.u64(self.metadata_reg + 0x08)
            per_type = self.elf.u64(field_offsets + type_def_index * 8)
            if not per_type:
                return None
            return self.elf.i32(per_type + local_field_index * 4)
        except Exception:
            return None

    def generic_names(self, container_index: int) -> list[str]:
        if container_index < 0 or container_index >= len(self.generic_containers):
            return []
        c = self.generic_containers[container_index]
        out = []
        for i in range(c.type_argc):
            idx = c.generic_parameter_start + i
            if 0 <= idx < len(self.generic_params):
                n = self.generic_params[idx].name
                out.append(n or f"T{i}")
            else:
                out.append(f"T{i}")
        return out

    def type_name(self, type_index: int) -> str:
        if type_index < 0:
            return 'void'

        td = self.type_index_to_typedef.get(type_index)
        if td:
            base = f'{td.namespace}.{td.name}' if td.namespace else td.name
            aliases = {
                'System.Void': 'void', 'System.Boolean': 'bool', 'System.Char': 'char',
                'System.SByte': 'sbyte', 'System.Byte': 'byte', 'System.Int16': 'short',
                'System.UInt16': 'ushort', 'System.Int32': 'int', 'System.UInt32': 'uint',
                'System.Int64': 'long', 'System.UInt64': 'ulong', 'System.Single': 'float',
                'System.Double': 'double', 'System.String': 'string', 'System.Object': 'object',
                'System.IntPtr': 'IntPtr', 'System.UIntPtr': 'UIntPtr',
            }
            base = aliases.get(base, base)
            gens = self.generic_names(td.generic_container_index)
            if gens:
                base += '<' + ', '.join(gens) + '>'
            return base or f'Type_{type_index}'

        if not self.metadata_reg:
            return f'Type_{type_index}'
        try:
            types_ptr = self.elf.u64(self.metadata_reg + 0x68)
            type_ptr = self.elf.u64(types_ptr + type_index * 8)
            kind = self.elf.u8(type_ptr + 1)
            data = self.elf.u64(type_ptr + 8)
        except Exception:
            return f'Type_{type_index}'

        primitives = {
            0x01:'void',0x02:'bool',0x03:'char',0x04:'sbyte',0x05:'byte',
            0x06:'short',0x07:'ushort',0x08:'int',0x09:'uint',0x0A:'long',
            0x0B:'ulong',0x0C:'float',0x0D:'double',0x0E:'string',
            0x18:'IntPtr',0x19:'UIntPtr',0x1C:'object',
        }
        if kind in primitives:
            return primitives[kind]
        if kind in (0x11, 0x12):
            td_index = int(data & 0xFFFFFFFF)
            if 0 <= td_index < len(self.type_defs):
                td2 = self.type_defs[td_index]
                base = f'{td2.namespace}.{td2.name}' if td2.namespace else td2.name
                return base or f'Type_{type_index}'
        if kind == 0x13:
            return f'!{data & 0xFFFFFFFF}'
        if kind == 0x1E:
            return f'!!{data & 0xFFFFFFFF}'
        if kind == 0x1D:
            return f'Type_{type_index}[]'
        return f'Type_{type_index}/*kind=0x{kind:X}*/'

    def dump(self) -> dict:
        if not self.type_defs:
            self.load_all()

        images_json = []
        for img in self.images:
            images_json.append(asdict(img))

        types_json = []
        for td in self.type_defs:
            fields = []
            if td.field_start >= 0:
                for local in range(td.field_count):
                    idx = td.field_start + local
                    if 0 <= idx < self.fields_count:
                        f = self.parse_field(idx)
                        f.offset = self.field_offset(td.index, local)
                        fd = asdict(f)
                        fd["type_name"] = self.type_name(f.type_index)
                        fields.append(fd)

            methods = []
            if td.method_start >= 0:
                for local in range(td.method_count):
                    idx = td.method_start + local
                    if 0 <= idx < self.methods_count:
                        m = self.parse_method(idx)
                        m.method_pointer = self.resolve_method_pointer(td.index, m)
                        m.rva = m.method_pointer  # ELF/IDA image base is 0 in this build.
                        md = asdict(m)
                        if m.method_pointer:
                            try:
                                md["file_offset"] = self.elf.va_to_off(m.method_pointer)
                            except Exception:
                                md["file_offset"] = 0
                        else:
                            md["file_offset"] = 0
                        md["return_type_name"] = self.type_name(m.return_type)
                        md["generic_parameters"] = self.generic_names(m.generic_container_index)

                        params = []
                        if m.parameter_start >= 0:
                            for pi in range(m.parameter_count):
                                pidx = m.parameter_start + pi
                                if 0 <= pidx < self.params_count:
                                    p = self.parse_param(pidx)
                                    pd = asdict(p)
                                    pd["type_name"] = self.type_name(p.type_index)
                                    params.append(pd)
                        md["parameters"] = params
                        methods.append(md)

            properties = []
            if td.property_start >= 0:
                for local in range(td.property_count):
                    prop = self.parse_property(td.property_start + local)
                    prop_type_index = -1
                    getter_local = prop.get("getter_index", -1)
                    setter_local = prop.get("setter_index", -1)
                    if getter_local is not None and getter_local >= 0 and td.method_start >= 0:
                        midx = td.method_start + getter_local
                        if 0 <= midx < self.methods_count:
                            prop_type_index = self.parse_method(midx).return_type
                    if prop_type_index < 0 and setter_local is not None and setter_local >= 0 and td.method_start >= 0:
                        midx = td.method_start + setter_local
                        if 0 <= midx < self.methods_count:
                            sm = self.parse_method(midx)
                            if sm.parameter_count > 0 and sm.parameter_start >= 0:
                                pidx = sm.parameter_start + sm.parameter_count - 1
                                if 0 <= pidx < self.params_count:
                                    prop_type_index = self.parse_param(pidx).type_index
                    prop["type_index"] = prop_type_index
                    prop["type_name"] = self.type_name(prop_type_index) if prop_type_index >= 0 else "object"
                    properties.append(prop)

            events = []
            if td.event_start >= 0:
                for local in range(td.event_count):
                    idx = td.event_start + local
                    if 0 <= idx < self.events_count:
                        ev = self.parse_event(idx)
                        ev["type_name"] = self.type_name(ev["type_index"])
                        events.append(ev)

            item = asdict(td)
            item["generic_parameters"] = self.generic_names(td.generic_container_index)
            item["parent_type_name"] = self.type_name(td.parent_index) if td.parent_index >= 0 else ""
            interface_type_names = []
            if td.interfaces_start >= 0:
                base = self.base + self.interface_type_indices_off
                for ii in range(td.interfaces_count):
                    iva = base + (td.interfaces_start + ii) * self.width_type_index
                    try:
                        tidx = read_packed_u(self.elf, iva, self.width_type_index)
                        if tidx >= 0:
                            interface_type_names.append(self.type_name(tidx))
                    except Exception:
                        pass
            item["interface_type_names"] = interface_type_names
            item["image"] = asdict(self.image_for_type(td.index)) if self.image_for_type(td.index) else None
            item["fields"] = fields
            item["methods"] = methods
            item["properties"] = properties
            item["events"] = events
            types_json.append(item)

        return {
            "binary": str(self.elf.path),
            "roots": {
                "metadata_va": self.base,
                "code_registration_va": self.code_reg,
                "metadata_registration_va": self.metadata_reg,
            },
            "widths": {
                "type_index": self.width_type_index,
                "type_definition_index": self.width_type_def,
                "generic_container_index": self.width_generic_container,
                "parameter_index": self.width_param,
            },
            "counts": {
                "types": self.type_defs_count,
                "fields": self.fields_count,
                "methods": self.methods_count,
                "parameters": self.params_count,
                "events": self.events_count,
                "images": self.images_count,
                "generic_containers": self.generic_containers_count,
                "generic_parameters": self.generic_params_count,
            },
            "images": images_json,
            "types": types_json,
        }


def _pack_i32(v: int) -> bytes:
    return struct.pack("<i", int(v))


def _pack_u32(v: int) -> bytes:
    return struct.pack("<I", int(v) & 0xFFFFFFFF)


def rebuild_global_metadata_v31(md: ProtectedMetadata) -> tuple[bytes, dict]:
    """
    Rebuild a canonical IL2CPP metadata v31 file from the protected/shuffled
    metadata. Core metadata sections are reconstructed in stock record order.
    Optional sections not required for ordinary type/method reconstruction are
    emitted empty for now.
    """
    if not md.type_defs:
        md.load_all()

    fields = [md.parse_field(i) for i in range(md.fields_count)]
    methods = [md.parse_method(i) for i in range(md.methods_count)]
    params = [md.parse_param(i) for i in range(md.params_count)]

    property_count = 0
    for td in md.type_defs:
        if td.property_start >= 0:
            property_count = max(property_count, td.property_start + td.property_count)
    properties = [md.parse_property(i) for i in range(property_count)]

    events = [md.parse_event(i) for i in range(md.events_count)]

    referenced_string_indices = {0}

    for td in md.type_defs:
        if td.name_index >= 0:
            referenced_string_indices.add(td.name_index)
        if td.namespace_index >= 0:
            referenced_string_indices.add(td.namespace_index)

    for f in fields:
        if f.name_index >= 0:
            referenced_string_indices.add(f.name_index)

    for m in methods:
        if m.name_index >= 0:
            referenced_string_indices.add(m.name_index)

    for p in params:
        if p.name_index >= 0:
            referenced_string_indices.add(p.name_index)

    for p in properties:
        ni = p.get("name_index", -1)
        if ni >= 0:
            referenced_string_indices.add(ni)

    for e in events:
        ni = e.get("name_index", -1)
        if ni >= 0:
            referenced_string_indices.add(ni)

    for gp in md.generic_params:
        if gp.name_index >= 0:
            referenced_string_indices.add(gp.name_index)

    for img in md.images:
        if img.name_index >= 0:
            referenced_string_indices.add(img.name_index)

    string_heap_size = 1
    for idx in referenced_string_indices:
        if idx > 0x1000000 or idx < 0:  # Игнорируем мусорные значения больше 16 МБ
            continue
        try:
            raw = md.str(idx).encode("utf-8", errors="replace")
            string_heap_size = max(string_heap_size, idx + len(raw) + 1)
        except Exception:
            pass

    string_heap = bytearray(md.elf.read(md.base + md.string_off, string_heap_size))
    if not string_heap:
        string_heap = bytearray(b"\0")
    if string_heap[-1] != 0:
        string_heap.append(0)

    appended_strings: dict[str, int] = {}

    def add_string(value: str) -> int:
        if value in appended_strings:
            return appended_strings[value]
        off = len(string_heap)
        string_heap.extend(value.encode("utf-8", errors="replace") + b"\0")
        appended_strings[value] = off
        return off

    nested_count = 0
    interface_count = 0
    vtable_count = 0
    interface_offset_count = 0

    for td in md.type_defs:
        if td.nested_types_start >= 0:
            nested_count = max(nested_count, td.nested_types_start + td.nested_type_count)
        if td.interfaces_start >= 0:
            interface_count = max(interface_count, td.interfaces_start + td.interfaces_count)
        if td.vtable_start >= 0:
            vtable_count = max(vtable_count, td.vtable_start + td.vtable_count)
        if td.interface_offsets_start >= 0:
            interface_offset_count = max(
                interface_offset_count,
                td.interface_offsets_start + td.interface_offsets_count,
            )

    nested_values = [-1] * nested_count
    if nested_count:
        src_base = md.base + md.nested_type_indices_off
        for i in range(nested_count):
            nested_values[i] = read_packed_u(
                md.elf, src_base + i * md.width_type_def, md.width_type_def
            )

    interface_values = [-1] * interface_count
    if interface_count:
        src_base = md.base + md.interface_type_indices_off
        for i in range(interface_count):
            interface_values[i] = read_packed_u(
                md.elf, src_base + i * md.width_type_index, md.width_type_index
            )

    vtable_values = [0] * vtable_count
    if vtable_count:
        protected_vtable_off = md.vtable_methods_off
        src_base = md.base + protected_vtable_off
        for i in range(vtable_count):
            vtable_values[i] = md.elf.u32(src_base + i * 4)

    interface_offset_pairs = [(-1, 0)] * interface_offset_count
    if interface_offset_count:
        src_off = md.interface_offsets_off
        src_size = md.interface_offsets_size
        src_count = md.interface_offsets_count
        entry_size = (src_size // src_count) if src_count else 0
        src_base = md.base + src_off
        for i in range(min(interface_offset_count, src_count)):
            va = src_base + i * entry_size
            type_index = read_packed_u(md.elf, va, md.width_type_index)
            off_va = va + md.width_type_index
            field_off = md.elf.i32(off_va)
            interface_offset_pairs[i] = (type_index, field_off)

    constraint_count = 0
    for gp in md.generic_params:
        constraint_count = max(
            constraint_count, gp.constraints_start + gp.constraints_count
        )
    constraint_values = [-1] * constraint_count
    if constraint_count:
        src_base = md.base + md.generic_constraint_type_indices_off
        for i in range(constraint_count):
            constraint_values[i] = read_packed_u(
                md.elf, src_base + i * md.width_type_index, md.width_type_index
            )

    def declaring_typedef_index(protected_type_index: int) -> int:
        if protected_type_index < 0:
            return -1
        t = md.type_index_to_typedef.get(protected_type_index)
        return t.index if t is not None else -1

    # Canonicalize the nested-type graph for stock Mono.Cecil.
    #
    # Stock DummyAssemblyGenerator first creates every TypeDefinition and then
    # attaches nested types with:
    #     parent.NestedTypes.Add(child)
    # Mono.Cecil throws "Member already attached" if the same child occurs in
    # two parent ranges.  The protected nestedTypes table can be shuffled /
    # ambiguous, while each TypeDefinition still carries its declaring type.
    #
    # Use declaringType as the source of truth.  The protected nested table is
    # used only to preserve child ordering when it agrees with declaringType.
    original_nested_values = list(nested_values)

    # declaringType is authoritative.  Do NOT use the old nestedTypes table as
    # a fallback: on this protected build that table can be misidentified by a
    # bounds-only heuristic.  A false nested edge is especially dangerous for
    # Mono.Cecil: a TypeDefinition may already be attached to its image module,
    # then NestedTypes.Add() places it under another type tree while its Module
    # field still points at the original module.  The writer later throws:
    #   "Member 'X' is declared in another module and needs to be imported".
    declared_parent: dict[int, int] = {}
    invalid_declaring = 0
    self_parent = 0

    for child_td in md.type_defs:
        parent = declaring_typedef_index(child_td.declaring_type_index)
        if parent == child_td.index:
            self_parent += 1
            parent = -1
        if parent >= len(md.type_defs):
            invalid_declaring += 1
            parent = -1
        declared_parent[child_td.index] = parent

    expected_children: dict[int, list[int]] = {
        i: [] for i in range(len(md.type_defs))
    }
    for child, parent in declared_parent.items():
        if 0 <= parent < len(md.type_defs):
            expected_children[parent].append(child)

    # Build a deterministic, duplicate-free nested table directly from the
    # declaringType relationships.  Ordering has no semantic significance to
    # stock Il2CppDumper / Cecil.
    canonical_nested_values: list[int] = []
    nested_layout: dict[int, tuple[int, int]] = {}

    for parent_td in md.type_defs:
        children = sorted(expected_children[parent_td.index])
        if children:
            out_start = len(canonical_nested_values)
            canonical_nested_values.extend(children)
            nested_layout[parent_td.index] = (out_start, len(children))
        else:
            nested_layout[parent_td.index] = (-1, 0)

    nested_values = canonical_nested_values

    expected_nested_refs = sum(
        1 for child, parent in declared_parent.items()
        if 0 <= parent < len(md.type_defs)
    )
    if len(nested_values) != expected_nested_refs:
        raise ValueError(
            f'Canonical nested graph lost entries: {len(nested_values)} != '
            f'{expected_nested_refs}'
        )
    if len(set(nested_values)) != len(nested_values):
        raise ValueError('Canonical nested graph still contains duplicate children')

    # Build protected-image ownership map and prove no nested link crosses an
    # image boundary.  Cross-image nesting would make Cecil module ownership
    # inconsistent even if all metadata indices are in range.
    image_of_type = [-1] * len(md.type_defs)
    for img in md.images:
        start_i = max(0, img.type_start)
        end_i = min(len(md.type_defs), img.type_start + img.type_count)
        for ti in range(start_i, end_i):
            image_of_type[ti] = img.index

    cross_image_nested: list[tuple[int, int, int, int]] = []
    orphan_image_types = 0
    for child, parent in declared_parent.items():
        if not (0 <= parent < len(md.type_defs)):
            continue
        ci = image_of_type[child]
        pi = image_of_type[parent]
        if ci < 0 or pi < 0:
            orphan_image_types += 1
            continue
        if ci != pi:
            cross_image_nested.append((child, parent, ci, pi))

    

    # Diagnostic only: compare the old candidate table with authoritative
    # declaringType relationships.  It must never influence the rebuilt table.
    original_parent_refs: dict[int, list[int]] = {}
    original_wrong_parent_refs = 0
    original_duplicate_refs = 0
    seen_original: set[int] = set()

    for parent_td in md.type_defs:
        start_i = parent_td.nested_types_start
        count_i = parent_td.nested_type_count
        if start_i < 0 or count_i <= 0:
            continue
        for j in range(count_i):
            pos = start_i + j
            if not (0 <= pos < len(original_nested_values)):
                continue
            child = original_nested_values[pos]
            if not (0 <= child < len(md.type_defs)):
                continue
            original_parent_refs.setdefault(child, []).append(parent_td.index)
            if child in seen_original:
                original_duplicate_refs += 1
            seen_original.add(child)
            if declared_parent.get(child, -1) != parent_td.index:
                original_wrong_parent_refs += 1

    nested_graph_diag = {
        "original_refs": len(original_nested_values),
        "declaring_type_refs": expected_nested_refs,
        "canonical_refs": len(nested_values),
        "wrong_parent_refs_in_old_candidate": original_wrong_parent_refs,
        "duplicate_refs_in_old_candidate": original_duplicate_refs,
        "invalid_declaring_types": invalid_declaring,
        "self_parent_types": self_parent,
        "cross_image_links": len(cross_image_nested),
        "orphan_image_types": orphan_image_types,
    }

    field_by_index = {f.index: f for f in fields}

    type_blob = bytearray()
    for td in md.type_defs:
        nested_start_out, nested_count_out = nested_layout.get(td.index, (-1, 0))
        element_type_index = -1
        if td.bitfield & 0x2 and td.field_start >= 0:
            for j in range(td.field_count):
                fi = td.field_start + j
                f = field_by_index.get(fi)
                if f and f.name == "value__":
                    element_type_index = f.type_index
                    break

        type_blob += struct.pack(
            "<IIiiiiiIiiiiiiiiHHHHHHHHII",
            td.name_index & 0xFFFFFFFF,
            td.namespace_index & 0xFFFFFFFF,
            td.type_index,
            declaring_typedef_index(td.declaring_type_index),
            td.parent_index,
            element_type_index,
            td.generic_container_index,
            td.flags & 0xFFFFFFFF,
            td.field_start,
            td.method_start,
            td.event_start,
            td.property_start,
            nested_start_out,
            td.interfaces_start,
            td.vtable_start,
            td.interface_offsets_start,
            td.method_count & 0xFFFF,
            td.property_count & 0xFFFF,
            td.field_count & 0xFFFF,
            td.event_count & 0xFFFF,
            nested_count_out & 0xFFFF,
            td.vtable_count & 0xFFFF,
            td.interfaces_count & 0xFFFF,
            td.interface_offsets_count & 0xFFFF,
            td.bitfield & 0xFFFFFFFF,
            td.token & 0xFFFFFFFF,
        )

    method_blob = bytearray()
    for m in methods:
        method_blob += struct.pack(
            "<IIIIIIIHHHH",
            m.name_index & 0xFFFFFFFF,
            m.declaring_type & 0xFFFFFFFF,
            m.return_type & 0xFFFFFFFF,
            m.aux & 0xFFFFFFFF,
            m.parameter_start & 0xFFFFFFFF,
            m.generic_container_index & 0xFFFFFFFF,
            m.token & 0xFFFFFFFF,
            m.flags & 0xFFFF,
            m.iflags & 0xFFFF,
            m.slot & 0xFFFF,
            m.parameter_count & 0xFFFF,
        )

    field_blob = bytearray()
    for f in fields:
        field_blob += struct.pack(
            "<III",
            f.name_index & 0xFFFFFFFF,
            f.type_index & 0xFFFFFFFF,
            f.token & 0xFFFFFFFF,
        )

    param_blob = bytearray()
    for p in params:
        param_blob += struct.pack(
            "<III",
            p.name_index & 0xFFFFFFFF,
            p.token & 0xFFFFFFFF,
            p.type_index & 0xFFFFFFFF,
        )

    property_blob = bytearray()
    for p in properties:
        property_blob += struct.pack(
            "<IIIII",
            p["name_index"] & 0xFFFFFFFF,
            p["getter_index"] & 0xFFFFFFFF,
            p["setter_index"] & 0xFFFFFFFF,
            p["attrs"] & 0xFFFFFFFF,
            p["token"] & 0xFFFFFFFF,
        )

    event_blob = bytearray()
    for e in events:
        event_blob += struct.pack(
            "<IIIIII",
            e["name_index"] & 0xFFFFFFFF,
            e["type_index"] & 0xFFFFFFFF,
            e["add_method_index"] & 0xFFFFFFFF,
            e["remove_method_index"] & 0xFFFFFFFF,
            e["raise_method_index"] & 0xFFFFFFFF,
            e["token"] & 0xFFFFFFFF,
        )

    generic_container_blob = bytearray()
    for gc in md.generic_containers:
        generic_container_blob += struct.pack(
            "<IIII",
            gc.owner_index & 0xFFFFFFFF,
            gc.type_argc & 0xFFFFFFFF,
            gc.is_method & 0xFFFFFFFF,
            gc.generic_parameter_start & 0xFFFFFFFF,
        )

    generic_param_blob = bytearray()
    for gp in md.generic_params:
        generic_param_blob += struct.pack(
            "<IIHHHH",
            gp.owner_container_index & 0xFFFFFFFF,
            gp.name_index & 0xFFFFFFFF,
            gp.constraints_start & 0xFFFF,
            gp.constraints_count & 0xFFFF,
            gp.num & 0xFFFF,
            gp.flags & 0xFFFF,
        )

    generic_constraint_blob = b"".join(
        _pack_i32(x) for x in constraint_values
    )
    nested_blob = b"".join(_pack_i32(x) for x in nested_values)
    interfaces_blob = b"".join(_pack_i32(x) for x in interface_values)
    vtable_blob = b"".join(_pack_u32(x) for x in vtable_values)
    interface_offsets_blob = b"".join(
        struct.pack("<ii", ti, off) for ti, off in interface_offset_pairs
    )

    image_blob = bytearray()
    assembly_blob = bytearray()

    for img in md.images:
        simple_name = img.name[:-4] if img.name.lower().endswith(".dll") else img.name
        assembly_name_index = add_string(simple_name)

        image_blob += struct.pack(
            "<IiiIiIiIiI",
            img.name_index & 0xFFFFFFFF,
            img.index,           # one synthetic assembly per image
            img.type_start,
            img.type_count & 0xFFFFFFFF,
            -1,                  # exportedTypeStart
            0,                   # exportedTypeCount
            -1,                  # entryPointIndex
            1,                   # image token (canonical image token)
            -1,                  # customAttributeStart
            0,                   # customAttributeCount
        )

        assembly_blob += struct.pack(
            "<iIii"
            "IIIIiI"
            "iiii"
            "8s",
            img.index,                     # imageIndex
            (0x20000001 + img.index) & 0xFFFFFFFF,
            -1,                            # referencedAssemblyStart
            0,                             # referencedAssemblyCount
            assembly_name_index,           # aname.nameIndex
            0,                             # cultureIndex
            0,                             # publicKeyIndex
            0,                             # hash_alg
            0,                             # hash_len
            0,                             # flags
            0, 0, 0, 0,                   # version
            b"\0" * 8,                     # public_key_token
        )

    section_order = [
        "stringLiteral",
        "stringLiteralData",
        "string",
        "events",
        "properties",
        "methods",
        "parameterDefaultValues",
        "fieldDefaultValues",
        "fieldAndParameterDefaultValueData",
        "fieldMarshaledSizes",
        "parameters",
        "fields",
        "genericParameters",
        "genericParameterConstraints",
        "genericContainers",
        "nestedTypes",
        "interfaces",
        "vtableMethods",
        "interfaceOffsets",
        "typeDefinitions",
        "images",
        "assemblies",
        "fieldRefs",
        "referencedAssemblies",
        "attributeData",
        "attributeDataRange",
        "unresolvedVirtualCallParameterTypes",
        "unresolvedVirtualCallParameterRanges",
        "windowsRuntimeTypeNames",
        "windowsRuntimeStrings",
        "exportedTypeDefinitions",
    ]

    protected_string_literals = md.read_string_literals()
    string_literal_blob = bytearray()
    string_literal_data_blob = bytearray()
    for raw in protected_string_literals:
        data_index = len(string_literal_data_blob)
        string_literal_data_blob.extend(raw)
        string_literal_blob += struct.pack("<II", len(raw), data_index)

    # Protected custom-attribute storage is already in the stock v31 on-disk
    # format.  The protector only shuffled the header fields that point to it.
    # Runtime accessor sub_6343E20 binary-searches 8-byte {token,startOffset}
    # entries at hdr+0x74 and passes consecutive startOffset values into
    # CustomAttributeDataReader (sub_6348FC8).  The next protected section
    # begins at hdr+0xA8, which therefore gives the exact range-table size.
    attribute_ranges_off = md.elf.u32(md.base + 0x74)
    attribute_ranges_end = md.elf.u32(md.base + 0xA8)
    attribute_data_off = md.elf.u32(md.base + 0xA4)
    attribute_data_end = md.elf.u32(md.base + 0x08)
    if not (0 < attribute_ranges_off <= attribute_ranges_end):
        raise ValueError('Invalid protected attributeDataRange bounds')
    if not (0 < attribute_data_off <= attribute_data_end):
        raise ValueError('Invalid protected attributeData bounds')
    attribute_range_blob = md.elf.read(
        md.base + attribute_ranges_off, attribute_ranges_end - attribute_ranges_off
    )
    attribute_data_blob = md.elf.read(
        md.base + attribute_data_off, attribute_data_end - attribute_data_off
    )
    if len(attribute_range_blob) % 8:
        raise ValueError('attributeDataRange size is not a multiple of 8')
    attribute_range_count = len(attribute_range_blob) // 8
    if attribute_range_count:
        last_start = struct.unpack_from('<I', attribute_range_blob,
                                        (attribute_range_count - 1) * 8 + 4)[0]
        if last_start > len(attribute_data_blob):
            raise ValueError(
                f'Last attribute start 0x{last_start:X} exceeds blob size '
                f'0x{len(attribute_data_blob):X}'
            )

    sections: dict[str, bytes] = {
        "stringLiteral": bytes(string_literal_blob),
        "stringLiteralData": bytes(string_literal_data_blob),
        "string": bytes(string_heap),
        "events": bytes(event_blob),
        "properties": bytes(property_blob),
        "methods": bytes(method_blob),
        "parameterDefaultValues": b"",
        "fieldDefaultValues": b"",
        "fieldAndParameterDefaultValueData": b"",
        "fieldMarshaledSizes": b"",
        "parameters": bytes(param_blob),
        "fields": bytes(field_blob),
        "genericParameters": bytes(generic_param_blob),
        "genericParameterConstraints": bytes(generic_constraint_blob),
        "genericContainers": bytes(generic_container_blob),
        "nestedTypes": bytes(nested_blob),
        "interfaces": bytes(interfaces_blob),
        "vtableMethods": bytes(vtable_blob),
        "interfaceOffsets": bytes(interface_offsets_blob),
        "typeDefinitions": bytes(type_blob),
        "images": bytes(image_blob),
        "assemblies": bytes(assembly_blob),
        "fieldRefs": b"",
        "referencedAssemblies": b"",
        "attributeData": bytes(attribute_data_blob),
        "attributeDataRange": bytes(attribute_range_blob),
        "unresolvedVirtualCallParameterTypes": b"",
        "unresolvedVirtualCallParameterRanges": b"",
        "windowsRuntimeTypeNames": b"",
        "windowsRuntimeStrings": b"",
        "exportedTypeDefinitions": b"",
    }

    header_size = 0x100
    cursor = header_size
    locs: dict[str, tuple[int, int]] = {}
    body = bytearray()

    for name in section_order:
        while cursor & 3:
            body.append(0)
            cursor += 1
        blob = sections[name]
        locs[name] = (cursor, len(blob))
        body.extend(blob)
        cursor += len(blob)

    header = bytearray()
    header += struct.pack("<Ii", 0xFAB11BAF, 31)
    for name in section_order:
        off, size = locs[name]
        header += struct.pack("<Ii", off, size)

    if len(header) != header_size:
        raise AssertionError(f"v31 header size mismatch: {len(header):#x}")

    rebuilt = bytes(header + body)

    manifest = {
        "sanity": "0xFAB11BAF",
        "version": 31,
        "size": len(rebuilt),
        "header_size": header_size,
        "sections": {
            name: {"offset": off, "size": size}
            for name, (off, size) in locs.items()
        },
        "nested_graph": nested_graph_diag,
        "custom_attributes": {
            "range_count": attribute_range_count,
            "range_size": len(attribute_range_blob),
            "data_size": len(attribute_data_blob),
            "last_start_offset": (
                struct.unpack_from('<I', attribute_range_blob,
                                   (attribute_range_count - 1) * 8 + 4)[0]
                if attribute_range_count else 0
            ),
        },
        "record_sizes": {
            "Il2CppTypeDefinition": 88,
            "Il2CppMethodDefinition": 36,
            "Il2CppParameterDefinition": 12,
            "Il2CppFieldDefinition": 12,
            "Il2CppPropertyDefinition": 20,
            "Il2CppEventDefinition": 24,
            "Il2CppGenericContainer": 16,
            "Il2CppGenericParameter": 16,
            "Il2CppImageDefinition": 40,
            "Il2CppAssemblyDefinition": 64,
            "Il2CppInterfaceOffsetPair": 8,
        },
        "notes": [
            "Core protected metadata reconstructed into canonical v31 record order.",
            "returnParameterToken recovered from protected MethodDefinition auxiliary DWORD.",
            "declaringType converted from protected TypeIndex to canonical TypeDefinitionIndex.",
            "Protected string literals reconstructed into canonical Il2CppStringLiteral records.",
            "Protected custom-attribute data/ranges are copied verbatim after validating their exact bounds.",
            "Optional default-value/WinRT/exported-type sections are empty in this stage.",
            "Stock Il2CppDumper metadata parsing should accept this file; binary registration remains custom/shuffled.",
        ],
    }
    return rebuilt, manifest

def parse_int(value: str) -> int:
    return int(value, 0)


def parse_auto_int(value: str) -> Optional[int]:
    if value is None or value.lower() in ('auto', 'heuristic', 'none', ''):
        return None
    return int(value, 0)


def _looks_like_elf64(path: Path) -> bool:
    try:
        with path.open('rb') as f:
            return f.read(5) == b'\x7fELF\x02'
    except OSError:
        return False


def _bounded_find_libunity(root: Path, max_depth: int = 5, max_dirs: int = 4000) -> Optional[Path]:
    root = root.resolve()
    for direct in (
        root / 'libunity.so',
        root / 'lib' / 'arm64-v8a' / 'libunity.so',
        root / 'arm64-v8a' / 'libunity.so',
    ):
        if direct.is_file() and _looks_like_elf64(direct):
            return direct

    queue: list[tuple[Path, int]] = [(root, 0)]
    visited = 0
    while queue and visited < max_dirs:
        current, depth = queue.pop(0)
        visited += 1
        if depth > max_depth:
            continue
        candidate = current / 'libunity.so'
        if candidate.is_file() and _looks_like_elf64(candidate):
            return candidate.resolve()
        if depth == max_depth:
            continue
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            if child.name.startswith('.') or child.name.lower() in {'node_modules', 'obj'}:
                continue
            queue.append((child, depth + 1))
    return None


def _pick_libunity_zip_entry(zf: zipfile.ZipFile) -> Optional[str]:
    names = [n for n in zf.namelist() if n.replace('\\', '/').lower().endswith('/libunity.so') or n.lower() == 'libunity.so']
    if not names:
        return None
    for name in names:
        if '/arm64-v8a/' in '/' + name.replace('\\', '/').lower():
            return name
    for name in names:
        if '/armeabi-v7a/' not in '/' + name.replace('\\', '/').lower():
            return name
    return names[0]


def _extract_archive_libunity(path: Path) -> Path:
    cache = Path(__file__).resolve().parent / '.auto-input' / path.stem
    cache.mkdir(parents=True, exist_ok=True)
    output = cache / 'libunity.so'
    with zipfile.ZipFile(path, 'r') as zf:
        entry = _pick_libunity_zip_entry(zf)
        if entry:
            output.write_bytes(zf.read(entry))
            if not _looks_like_elf64(output):
                raise ValueError(f'{entry} is not ELF64')
            print(f'[auto] extracted {entry}')
            return output

        # XAPK/APKS may contain nested APK files.
        for nested in (n for n in zf.namelist() if n.lower().endswith('.apk')):
            try:
                raw = zf.read(nested)
                with zipfile.ZipFile(io.BytesIO(raw), 'r') as nested_zf:
                    nested_entry = _pick_libunity_zip_entry(nested_zf)
                    if not nested_entry:
                        continue
                    output.write_bytes(nested_zf.read(nested_entry))
                    if not _looks_like_elf64(output):
                        continue
                    print(f'[auto] extracted {nested}!/{nested_entry}')
                    return output
            except (OSError, zipfile.BadZipFile, KeyError):
                continue
    raise FileNotFoundError('ARM64 libunity.so was not found inside archive')


def resolve_input_path(value: Optional[Path]) -> Path:
    if value is not None:
        value = value.expanduser().resolve()
        if value.is_dir():
            found = _bounded_find_libunity(value)
            if found:
                return found
            raise FileNotFoundError(f'libunity.so was not found under {value}')
        if value.is_file():
            if _looks_like_elf64(value):
                return value
            if value.suffix.lower() in {'.apk', '.zip', '.xapk', '.apks'}:
                return _extract_archive_libunity(value)
            raise ValueError(f'{value} is not an ELF64 libunity.so or a supported archive')

    roots = []
    for root in (Path.cwd(), Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent):
        root = root.resolve()
        if root not in roots and root.is_dir():
            roots.append(root)
    for root in roots:
        found = _bounded_find_libunity(root)
        if found:
            return found

    for root in roots:
        try:
            archives = sorted(
                (p for p in root.iterdir() if p.is_file() and p.suffix.lower() in {'.apk', '.zip', '.xapk', '.apks'}),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            continue
        for archive in archives:
            try:
                return _extract_archive_libunity(archive)
            except Exception:
                continue

    raise FileNotFoundError(
        'libunity.so was not found automatically. Put it next to this script, under lib/arm64-v8a/, '
        'or pass an APK/ZIP/XAPK path.'
    )



def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _is_exec_va(elf: ELF64, va: int) -> bool:
    if va == 0:
        return False
    for p_vaddr, _, _, p_memsz, p_flags in elf.loads:
        if (p_flags & 1) and p_vaddr <= va < p_vaddr + p_memsz:
            return True
    return False


def _is_load_mapped(elf: ELF64, va: int, size: int = 1) -> bool:
    if va == 0 or size < 0:
        return False
    for p_vaddr, _, _, p_memsz, _ in elf.loads:
        if p_vaddr <= va and va + size <= p_vaddr + p_memsz:
            return True
    return False


def _u64_from_load_image(elf: ELF64, va: int) -> int:
    """Read a qword as it exists in the ELF load image.

    PT_LOAD memory between p_filesz and p_memsz is zero-filled by the loader.
    R_AARCH64_RELATIVE relocations are applied first, including relocations
    whose destination is in a zero-fill/BSS region.
    """
    relocated = elf.relocated_u64.get(va)
    if relocated is not None:
        return relocated

    try:
        return struct.unpack("<Q", elf.read(va, 8))[0]
    except Exception:
        pass

    for p_vaddr, p_offset, p_filesz, p_memsz, _ in elf.loads:
        if not (p_vaddr <= va and va + 8 <= p_vaddr + p_memsz):
            continue

        file_end_va = p_vaddr + p_filesz
        if va >= file_end_va:
            return 0

        raw = bytearray(8)
        backed = max(0, min(8, file_end_va - va))
        if backed:
            off = p_offset + (va - p_vaddr)
            raw[:backed] = elf.data[off:off + backed]
        return struct.unpack("<Q", raw)[0]

    raise ValueError(f"VA 0x{va:X} is outside PT_LOAD memory")


def _exec_pointer_array_score(elf: ELF64, ptr: int, count: int, samples: int = 32) -> float:
    if count <= 0 or ptr == 0 or not _is_load_mapped(elf, ptr, 8):
        return 0.0
    good = total = 0
    for i in _sample_indices(count, samples):
        try:
            value = _u64_from_load_image(elf, ptr + i * 8)
        except Exception:
            continue
        total += 1
        if value == 0 or _is_exec_va(elf, value):
            good += 1
    return good / total if total else 0.0


def _protected_type_score(elf: ELF64, types_ptr: int, count: int, samples: int = 48) -> float:
    if count <= 0 or types_ptr == 0 or not _is_file_backed(elf, types_ptr, 8):
        return 0.0
    good = total = 0
    for i in _sample_indices(count, samples):
        try:
            type_ptr = elf.u64(types_ptr + i * 8)
            if not type_ptr or not _is_load_mapped(elf, type_ptr, 16):
                continue
            kind = elf.u8(type_ptr + 1)
            flags = elf.u8(type_ptr + 2)
            _ = _u64_from_load_image(elf, type_ptr + 8)
        except Exception:
            continue
        total += 1
        if kind in _IL2CPP_TYPE_KINDS and (flags & 0xC0) == 0:
            good += 1
    return good / total if total else 0.0

def _read_protected_runtime_layout(elf: ELF64, md: ProtectedMetadata) -> dict:
    """Read the AxProtect-permuted v31 registrations for this binary.

    Every field below was cross-checked against the registration initializer and
    consumers in IDA, then validated by its pointed-to data.
    """
    if not md.code_reg or not md.metadata_reg:
        raise ValueError('CodeRegistration and MetadataRegistration are required for stock normalization')

    cr = md.code_reg
    mr = md.metadata_reg

    meta = {
        # Protected MetadataRegistration permutation, verified from consumers:
        # +0x10/+0x70 is GenericClass*[], while +0x50/+0x48 is GenericInst*[].
        'generic_classes_count': elf.u32(mr + 0x70),
        'generic_classes': elf.u64(mr + 0x10),
        'generic_insts_count': elf.u32(mr + 0x48),
        'generic_insts': elf.u64(mr + 0x50),
        'generic_method_table_count': elf.u32(mr + 0x20),
        'generic_method_table': elf.u64(mr + 0x40),
        'types_count': elf.u32(mr + 0x1C),
        'types': elf.u64(mr + 0x68),
        'method_specs_count': elf.u32(mr + 0x58),
        'method_specs': elf.u64(mr + 0x28),
        'field_offsets_count': elf.u32(mr + 0x18),
        'field_offsets': elf.u64(mr + 0x08),
        'type_definition_sizes_count': elf.u32(mr + 0x38),
        'type_definition_sizes': elf.u64(mr + 0x30),
    }

    # CodeRegistration is also permuted.  Fields not needed by Il2CppDumper are
    # kept only when their mapping is proven; otherwise use zero rather than
    # publishing a plausible-looking wrong pointer.
    code = {
        # Proven by pointer-array semantics and by the index ranges used by the
        # 228222 protected generic-method table entries.
        'reverse_pinvoke_count': elf.u32(cr + 0x70),
        'reverse_pinvoke': elf.u64(cr + 0x78),
        'generic_method_pointers_count': elf.u32(cr + 0x48),
        'generic_method_pointers': elf.u64(cr + 0x40),
        'generic_adjustor_thunks': elf.u64(cr + 0x68),
        'invoker_pointers_count': elf.u32(cr + 0x38),
        'invoker_pointers': elf.u64(cr + 0x28),
        'unresolved_virtual_count': elf.u32(cr + 0x60),
        'unresolved_virtual': elf.u64(cr + 0x50),
        'unresolved_instance': elf.u64(cr + 0x10),
        'unresolved_static': elf.u64(cr + 0x58),
        'interop_count': elf.u32(cr + 0x3C),
        'interop': elf.u64(cr + 0x00),
        'codegen_modules_count': elf.u32(cr + 0x20),
        'codegen_modules': elf.u64(cr + 0x30),
    }

    errors = []
    if meta['field_offsets_count'] != md.type_defs_count:
        errors.append(f"fieldOffsetsCount={meta['field_offsets_count']} != typeDefinitions={md.type_defs_count}")
    if meta['type_definition_sizes_count'] != md.type_defs_count:
        errors.append(f"typeDefinitionSizesCount={meta['type_definition_sizes_count']} != typeDefinitions={md.type_defs_count}")
    if code['codegen_modules_count'] != md.images_count:
        errors.append(f"codeGenModulesCount={code['codegen_modules_count']} != images={md.images_count}")
    type_score = _protected_type_score(elf, meta['types'], meta['types_count'])
    if type_score < 0.95:
        errors.append(f'protected Il2CppType validation score too low ({type_score:.2f})')
    if _exec_pointer_array_score(elf, code['generic_method_pointers'], code['generic_method_pointers_count']) < 0.65:
        errors.append('genericMethodPointers does not look like an executable pointer array')
    if _exec_pointer_array_score(elf, code['invoker_pointers'], code['invoker_pointers_count']) < 0.65:
        errors.append('invokerPointers does not look like an executable pointer array')
    if errors:
        raise ValueError('Protected runtime layout validation failed: ' + '; '.join(errors))
    return {'metadata': meta, 'code': code}

_IL2CPP_TYPE_KINDS = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x18, 0x19, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x40, 0x41, 0x45,
}


def _decode_protected_type_bits(bits: int) -> tuple[int, int, int, int, int]:
    """Decode the protector's compact Il2CppType descriptor dword at +0.

    byte[+1] is Il2CppTypeEnum; byte[+2] bit4 is byref.  The original attrs and
    custom-modifier bookkeeping are not required by stock Il2CppDumper and are
    intentionally emitted as zero rather than guessed.
    """
    kind = (bits >> 8) & 0xFF
    flag_byte = (bits >> 16) & 0xFF
    byref = (flag_byte >> 4) & 1
    return 0, kind, 0, byref, 0

def _protected_runtime_type_kind(elf: ELF64, types_ptr: int, types_count: int, type_index: int) -> tuple[int, int]:
    if type_index < 0 or type_index >= types_count:
        return -1, 0
    type_ptr = elf.u64(types_ptr + type_index * 8)
    if not type_ptr or not _is_load_mapped(elf, type_ptr, 16):
        return -1, type_ptr
    kind = elf.u8(type_ptr + 1)
    return (kind if kind in _IL2CPP_TYPE_KINDS else -1), type_ptr

def _type_context_contains_mvar(
        elf: ELF64,
        type_ptr: int,
        seen: set[int] | None = None,
        depth: int = 0,
) -> bool:
    if not type_ptr or depth > 16:
        return False
    if seen is None:
        seen = set()
    if type_ptr in seen:
        return False
    seen.add(type_ptr)
    if not _is_load_mapped(elf, type_ptr, 16):
        return False

    kind = elf.u8(type_ptr + 1)
    data = _u64_from_load_image(elf, type_ptr + 8)
    if kind == 0x1E:
        return True
    if kind in (0x0F, 0x1D):
        return _type_context_contains_mvar(elf, data, seen, depth + 1)
    if kind == 0x14 and data:
        try:
            arr = _read_protected_array_type(elf, data)
            return _type_context_contains_mvar(elf, arr['etype'], seen, depth + 1)
        except Exception:
            return False
    if kind == 0x15 and data:
        # Protected GenericClass: type, method_inst, class_inst, cached_class.
        if not _is_load_mapped(elf, data, 32):
            return False
        class_inst = _u64_from_load_image(elf, data + 0x10)
        if not class_inst or not _is_load_mapped(elf, class_inst, 16):
            return False
        argc = _u64_from_load_image(elf, class_inst)
        argv = _u64_from_load_image(elf, class_inst + 8)
        if argc > 1024 or (argc and not argv):
            return False
        for i in range(int(argc)):
            arg = _u64_from_load_image(elf, argv + i * 8)
            if _type_context_contains_mvar(elf, arg, seen, depth + 1):
                return True
    return False

def _constraint_candidate_semantic_score(
        elf: ELF64,
        md: ProtectedMetadata,
        rel: int,
        constraint_count: int,
        types_ptr: int,
        types_count: int,
) -> tuple[float, dict]:
    width = md.width_type_index
    base = md.base + rel
    if constraint_count <= 0:
        return 1.0, {
            'invalid': 0,
            'implausible_kind': 0,
            'type_context_mvar': 0,
            'generic_owner_mismatch': 0,
        }
    if not _is_file_backed(elf, base, constraint_count * width):
        return -1.0, {'invalid': constraint_count}

    # Generic constraints are type-like objects: class/value type, VAR/MVAR,
    # generic instance, object, arrays/pointers in unusual generated metadata.
    plausible = {
        0x11,  # VALUETYPE
        0x12,  # CLASS / interface
        0x13,  # VAR
        0x15,  # GENERICINST
        0x1C,  # OBJECT (rare generated metadata)
        0x1E,  # MVAR, only valid in method-generic context
    }

    invalid = 0
    implausible = 0
    type_context_mvar = 0
    generic_owner_mismatch = 0
    total_refs = 0
    kind_hist: dict[int, int] = {}

    # Map every constraint slot to the generic parameter(s) that consume it.
    slot_owners: dict[int, list[GenericParameter]] = {}
    for gp in md.generic_params:
        if gp.constraints_count <= 0 or gp.constraints_start < 0:
            continue
        for j in range(gp.constraints_count):
            slot = gp.constraints_start + j
            if 0 <= slot < constraint_count:
                slot_owners.setdefault(slot, []).append(gp)

    for slot in range(constraint_count):
        try:
            type_index = read_packed_u(elf, base + slot * width, width)
        except Exception:
            invalid += 1
            continue

        if type_index < 0 or type_index >= types_count:
            invalid += 1
            continue

        kind, type_ptr = _protected_runtime_type_kind(
            elf, types_ptr, types_count, type_index
        )
        if kind < 0:
            invalid += 1
            continue

        total_refs += 1
        kind_hist[kind] = kind_hist.get(kind, 0) + 1
        if kind not in plausible:
            implausible += 1

        owners = slot_owners.get(slot, [])
        for gp in owners:
            if not (0 <= gp.owner_container_index < len(md.generic_containers)):
                generic_owner_mismatch += 1
                continue
            container = md.generic_containers[gp.owner_container_index]

            # A type generic parameter is created by Cecil with a TypeDefinition
            # owner. Any MVAR reachable from its constraint graph is invalid in
            # that context and causes the exact TypeDefinition->MethodDefinition
            # InvalidCastException seen in stock Il2CppDumper.
            if container.is_method == 0:
                if _type_context_contains_mvar(elf, type_ptr):
                    type_context_mvar += 1

            # VAR/MVAR roots themselves should agree with the generic parameter
            # owner encoded in the runtime Il2CppType.
            if kind in (0x13, 0x1E):
                try:
                    referenced_gp = int(_u64_from_load_image(elf, type_ptr + 8))
                    if 0 <= referenced_gp < len(md.generic_params):
                        ref_owner = md.generic_params[referenced_gp].owner_container_index
                        if 0 <= ref_owner < len(md.generic_containers):
                            ref_is_method = md.generic_containers[ref_owner].is_method
                            if kind == 0x13 and ref_is_method != 0:
                                generic_owner_mismatch += 1
                            elif kind == 0x1E and ref_is_method != 1:
                                generic_owner_mismatch += 1
                except Exception:
                    generic_owner_mismatch += 1

    # Invalid/type-context-MVAR are hard failures.  Kind plausibility helps
    # distinguish constraint arrays from other small-index metadata arrays.
    denom = max(1, constraint_count)
    score = (
        1.0
        - 4.0 * (invalid / denom)
        - 3.0 * (type_context_mvar / denom)
        - 1.5 * (generic_owner_mismatch / denom)
        - 0.75 * (implausible / denom)
    )

    return score, {
        'invalid': invalid,
        'implausible_kind': implausible,
        'type_context_mvar': type_context_mvar,
        'generic_owner_mismatch': generic_owner_mismatch,
        'kind_histogram': {hex(k): v for k, v in sorted(kind_hist.items())},
        'total_refs': total_refs,
    }




def _interface_candidate_semantic_score(
        elf: ELF64,
        md: ProtectedMetadata,
        rel: int,
        interface_count: int,
        types_ptr: int,
        types_count: int,
) -> tuple[float, dict]:
    width = md.width_type_index
    base = md.base + rel
    if interface_count <= 0:
        return 1.0, {
            'invalid': 0,
            'bad_root_kind': 0,
            'type_context_mvar': 0,
            'class_count': 0,
            'genericinst_count': 0,
        }
    if not _is_file_backed(elf, base, interface_count * width):
        return -1.0, {'invalid': interface_count}

    invalid = 0
    bad_root_kind = 0
    type_context_mvar = 0
    class_count = 0
    genericinst_count = 0
    kind_hist: dict[int, int] = {}

    # Implemented-interface entries in IL2CPP metadata are TypeIndex values.
    # In a TypeDefinition context their roots should be CLASS/interface or
    # GENERICINST.  A bare VAR/MVAR is not a legal implemented interface.
    plausible_root_kinds = {0x12, 0x15}

    for slot in range(interface_count):
        try:
            ti = read_packed_u(elf, base + slot * width, width)
        except Exception:
            invalid += 1
            continue

        if ti < 0 or ti >= types_count:
            invalid += 1
            continue

        kind, type_ptr = _protected_runtime_type_kind(
            elf, types_ptr, types_count, ti
        )
        if kind < 0 or not type_ptr:
            invalid += 1
            continue

        kind_hist[kind] = kind_hist.get(kind, 0) + 1
        if kind == 0x12:
            class_count += 1
        elif kind == 0x15:
            genericinst_count += 1
        else:
            bad_root_kind += 1

        if _type_context_contains_mvar(elf, type_ptr):
            type_context_mvar += 1

    denom = max(1, interface_count)
    score = (
        1.0
        - 5.0 * (invalid / denom)
        - 4.0 * (type_context_mvar / denom)
        - 1.5 * (bad_root_kind / denom)
    )

    return score, {
        'invalid': invalid,
        'bad_root_kind': bad_root_kind,
        'type_context_mvar': type_context_mvar,
        'class_count': class_count,
        'genericinst_count': genericinst_count,
        'kind_histogram': {hex(k): v for k, v in sorted(kind_hist.items())},
    }


def refine_interface_type_table(
        elf: ELF64,
        md: ProtectedMetadata,
) -> dict:
    """Re-select interface TypeIndex[] after runtime types[] is known.

    Bounds-only scoring can mistake a dense small-integer array (for example a
    generic-parameter-related array) for interfaces.  This is catastrophic for
    DummyAssemblyGenerator because interface types are resolved with a
    TypeDefinition owner.
    """
    if not md.metadata_reg:
        return {
            'changed': False,
            'offset': md.interface_type_indices_off,
            'reason': 'no MetadataRegistration',
        }

    interface_count = 0
    for td in md.type_defs:
        if td.interfaces_start >= 0 and td.interfaces_count > 0:
            interface_count = max(
                interface_count,
                td.interfaces_start + td.interfaces_count,
            )

    if interface_count <= 0:
        return {
            'changed': False,
            'offset': 0,
            'interface_count': 0,
        }

    types_count = elf.u32(md.metadata_reg + 0x1C)
    types_ptr = elf.u64(md.metadata_reg + 0x68)
    if not types_ptr or types_count <= 0:
        raise ValueError('Cannot refine interfaces without runtime types[]')

    values = _header_values(elf, md.base)
    candidates = _candidate_offsets(elf, md.base, values)

    # Exclude already identified metadata arrays, except the current interface
    # and generic-constraint guesses because those two are being jointly
    # disambiguated here.
    reserved_offsets: set[int] = set()
    if md.heuristic_layout is not None:
        for info in md.heuristic_layout.get('tables', {}).values():
            if isinstance(info, dict):
                rel = int(info.get('offset', 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

        for key, info in md.heuristic_layout.get('secondary', {}).items():
            if key in ('interfaces', 'generic_constraints'):
                continue
            if isinstance(info, dict):
                rel = int(info.get('offset', 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

        sh = md.heuristic_layout.get('string_heap', {})
        if isinstance(sh, dict):
            rel = int(sh.get('offset', 0) or 0)
            if rel:
                reserved_offsets.add(rel)

        sl = md.heuristic_layout.get('string_literals', {})
        if isinstance(sl, dict):
            for key in ('offsets_off', 'data_off'):
                rel = int(sl.get(key, 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

    old_rel = md.interface_type_indices_off
    rels = {old_rel}
    for _, rel in candidates:
        if rel and (rel == old_rel or rel not in reserved_offsets):
            rels.add(rel)

    ranked = []
    for rel in rels:
        if not rel:
            continue
        score, diag = _interface_candidate_semantic_score(
            elf, md, rel, interface_count, types_ptr, types_count
        )
        ranked.append((score, rel, diag))

    ranked.sort(
        key=lambda x: (
            x[0],
            -x[2].get('type_context_mvar', 0),
            -x[2].get('bad_root_kind', 0),
            x[1],
        ),
        reverse=True,
    )

    if not ranked:
        raise ValueError('No interface TypeIndex[] candidates survived semantic validation')

    best_score, best_rel, best_diag = ranked[0]

    # A real interface table must be clean in TypeDefinition context and almost
    # entirely CLASS / GENERICINST roots.
    if (
        best_score < 0.95
        or best_diag.get('invalid', 0)
        or best_diag.get('type_context_mvar', 0)
        or best_diag.get('bad_root_kind', 0)
    ):
        top = '; '.join(
            f'0x{rel:X}:score={score:.3f},invalid={diag.get("invalid",0)},'
            f'MVAR={diag.get("type_context_mvar",0)},badKind={diag.get("bad_root_kind",0)},'
            f'kinds={diag.get("kind_histogram",{})}'
            for score, rel, diag in ranked[:5]
        )
        raise ValueError(
            'Unable to identify a DummyDll-safe interface TypeIndex[] table. '
            f'Top candidates: {top}'
        )

    md.interface_type_indices_off = best_rel
    if md.heuristic_layout is not None:
        md.heuristic_layout['secondary']['interfaces']['offset'] = best_rel
        md.heuristic_layout['secondary']['interfaces']['count'] = interface_count
        md.heuristic_layout['secondary']['interfaces']['semantic_score'] = best_score
        md.heuristic_layout['secondary']['interfaces']['semantic_diag'] = best_diag

    old_score = None
    old_diag = None
    for score, rel, diag in ranked:
        if rel == old_rel:
            old_score, old_diag = score, diag
            break

    return {
        'changed': best_rel != old_rel,
        'old_offset': old_rel,
        'offset': best_rel,
        'interface_count': interface_count,
        'score': best_score,
        'diagnostics': best_diag,
        'old_score': old_score,
        'old_diagnostics': old_diag,
        'reserved_offsets': sorted(reserved_offsets),
        'top_candidates': [
            {
                'offset': rel,
                'score': score,
                'type_context_mvar': diag.get('type_context_mvar', 0),
                'bad_root_kind': diag.get('bad_root_kind', 0),
                'invalid': diag.get('invalid', 0),
                'kind_histogram': diag.get('kind_histogram', {}),
            }
            for score, rel, diag in ranked[:5]
        ],
    }



def preflight_dummy_typedef_contexts(
        elf: ELF64,
        md: ProtectedMetadata,
) -> dict:
    """Validate all runtime types stock DummyAssemblyGenerator resolves with
    a TypeDefinition as MemberReference.

    In v6.7.46 those contexts are:
      * type parent
      * implemented interfaces
      * fields
      * events
      * constraints of type-generic parameters

    Any reachable MVAR in these contexts makes GetTypeReference execute:
        (MethodDefinition)memberReference
    with a TypeDefinition and throws InvalidCastException.
    """
    if not md.metadata_reg:
        raise ValueError('DummyDll preflight requires MetadataRegistration')

    types_count = elf.u32(md.metadata_reg + 0x1C)
    types_ptr = elf.u64(md.metadata_reg + 0x68)
    if not types_ptr or types_count <= 0:
        raise ValueError('DummyDll preflight cannot read runtime types[]')

    violations: list[dict] = []
    checked = {
        'parents': 0,
        'interfaces': 0,
        'fields': 0,
        'events': 0,
        'type_generic_constraints': 0,
    }

    def check_type_index(type_index: int, category: str, owner: int, detail: int = -1):
        if type_index < 0 or type_index >= types_count:
            violations.append({
                'category': category,
                'owner': owner,
                'detail': detail,
                'type_index': type_index,
                'reason': 'out-of-range type index',
            })
            return

        kind, type_ptr = _protected_runtime_type_kind(
            elf, types_ptr, types_count, type_index
        )
        if kind < 0 or not type_ptr:
            violations.append({
                'category': category,
                'owner': owner,
                'detail': detail,
                'type_index': type_index,
                'reason': 'unreadable runtime type',
            })
            return

        if _type_context_contains_mvar(elf, type_ptr):
            violations.append({
                'category': category,
                'owner': owner,
                'detail': detail,
                'type_index': type_index,
                'type_ptr': type_ptr,
                'kind': kind,
                'reason': 'MVAR reachable from TypeDefinition context',
            })

    # Parent, interfaces, fields and events.
    for td in md.type_defs:
        if td.parent_index >= 0:
            checked['parents'] += 1
            check_type_index(td.parent_index, 'parent', td.index)

        if td.interfaces_start >= 0 and td.interfaces_count > 0:
            for j in range(td.interfaces_count):
                slot = td.interfaces_start + j
                va = (
                    md.base
                    + md.interface_type_indices_off
                    + slot * md.width_type_index
                )
                ti = read_packed_u(elf, va, md.width_type_index)
                checked['interfaces'] += 1
                check_type_index(ti, 'interface', td.index, slot)

        if td.field_start >= 0 and td.field_count > 0:
            for j in range(td.field_count):
                fi = td.field_start + j
                if not (0 <= fi < md.fields_count):
                    violations.append({
                        'category': 'field',
                        'owner': td.index,
                        'detail': fi,
                        'type_index': -1,
                        'reason': 'field index outside field table',
                    })
                    continue
                f = md.parse_field(fi)
                checked['fields'] += 1
                check_type_index(f.type_index, 'field', td.index, fi)

        if td.event_start >= 0 and td.event_count > 0:
            for j in range(td.event_count):
                ei = td.event_start + j
                if not (0 <= ei < md.events_count):
                    violations.append({
                        'category': 'event',
                        'owner': td.index,
                        'detail': ei,
                        'type_index': -1,
                        'reason': 'event index outside event table',
                    })
                    continue
                e = md.parse_event(ei)
                checked['events'] += 1
                check_type_index(e['type_index'], 'event', td.index, ei)

    # Generic constraints created with a TypeDefinition owner.
    constraint_base = md.base + md.generic_constraint_type_indices_off
    for gp in md.generic_params:
        if gp.constraints_count <= 0 or gp.constraints_start < 0:
            continue
        if not (0 <= gp.owner_container_index < len(md.generic_containers)):
            violations.append({
                'category': 'type_generic_constraint',
                'owner': gp.index,
                'detail': gp.owner_container_index,
                'type_index': -1,
                'reason': 'invalid generic container',
            })
            continue

        container = md.generic_containers[gp.owner_container_index]
        if container.is_method != 0:
            continue

        for j in range(gp.constraints_count):
            slot = gp.constraints_start + j
            va = constraint_base + slot * md.width_type_index
            ti = read_packed_u(elf, va, md.width_type_index)
            checked['type_generic_constraints'] += 1
            check_type_index(
                ti, 'type_generic_constraint', container.owner_index, slot
            )

    if violations:
        sample = '; '.join(
            f"{x['category']} owner={x['owner']} detail={x['detail']} "
            f"type={x['type_index']} reason={x['reason']}"
            for x in violations[:12]
        )
        raise ValueError(
            f'DummyDll TypeDefinition-context preflight found '
            f'{len(violations)} violation(s): {sample}'
        )

    # Module-ownership invariant used by stock DummyAssemblyGenerator:
    # if declaringTypeIndex != -1, the child must be nested under exactly that
    # TypeDefinition and in the same image.  The rebuilt nested table is derived
    # from the same relation, so no top-level object can be attached twice.
    return {
        'checked': checked,
        'violations': 0,
        'module_graph': 'declaringType-only',
    }



def refine_generic_constraint_table(
        elf: ELF64,
        md: ProtectedMetadata,
) -> dict:
    """Re-select genericParameterConstraints after MetadataRegistration is known.

    The protected header contains many small-index arrays.  A bounds-only
    heuristic can confuse another array with generic constraints.  That error is
    mostly invisible to dump.cs/StructGenerator, but Mono.Cecil later crashes
    when a bogus MVAR is restored in a TypeDefinition context.
    """
    if not md.metadata_reg:
        return {
            'changed': False,
            'offset': md.generic_constraint_type_indices_off,
            'reason': 'no MetadataRegistration',
        }

    constraint_count = 0
    for gp in md.generic_params:
        if gp.constraints_start >= 0 and gp.constraints_count > 0:
            constraint_count = max(
                constraint_count, gp.constraints_start + gp.constraints_count
            )

    if constraint_count <= 0:
        return {
            'changed': False,
            'offset': 0,
            'constraint_count': 0,
        }

    # Current protected registration permutation, already semantically validated
    # elsewhere in this script.
    types_count = elf.u32(md.metadata_reg + 0x1C)
    types_ptr = elf.u64(md.metadata_reg + 0x68)
    if not types_ptr or types_count <= 0:
        raise ValueError('Cannot refine generic constraints without runtime types[]')

    values = _header_values(elf, md.base)
    candidates = _candidate_offsets(elf, md.base, values)

    # Generic constraints must be their own metadata array.  Never reuse a
    # primary/secondary table already identified by the protected-layout
    # heuristic.  The previous refinement incorrectly selected the interfaces
    # array (0xE2C1A4 in the current build) because it also contains valid type
    # indexes.
    reserved_offsets: set[int] = set()
    if md.heuristic_layout is not None:
        for info in md.heuristic_layout.get('tables', {}).values():
            if isinstance(info, dict):
                rel = int(info.get('offset', 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

        for key, info in md.heuristic_layout.get('secondary', {}).items():
            if key == 'generic_constraints':
                continue
            if isinstance(info, dict):
                rel = int(info.get('offset', 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

        sh = md.heuristic_layout.get('string_heap', {})
        if isinstance(sh, dict):
            rel = int(sh.get('offset', 0) or 0)
            if rel:
                reserved_offsets.add(rel)

        sl = md.heuristic_layout.get('string_literals', {})
        if isinstance(sl, dict):
            for key in ('offsets_off', 'data_off'):
                rel = int(sl.get(key, 0) or 0)
                if rel:
                    reserved_offsets.add(rel)

    # Keep the original generic-constraint guess eligible, but reject every
    # other already-owned table.
    old_constraint_rel = md.generic_constraint_type_indices_off
    current_interface_rel = md.interface_type_indices_off
    rels = set()
    if old_constraint_rel and old_constraint_rel != current_interface_rel:
        rels.add(old_constraint_rel)
    for _, rel in candidates:
        if not rel or rel == current_interface_rel:
            continue
        if rel == old_constraint_rel or rel not in reserved_offsets:
            rels.add(rel)

    ranked = []
    for rel in rels:
        if not rel:
            continue
        score, diag = _constraint_candidate_semantic_score(
            elf, md, rel, constraint_count, types_ptr, types_count
        )
        ranked.append((score, rel, diag))

    ranked.sort(key=lambda x: (x[0], -x[2].get('type_context_mvar', 0), x[1]), reverse=True)
    if not ranked:
        raise ValueError('No generic constraint table candidates survived semantic validation')

    best_score, best_rel, best_diag = ranked[0]

    # Require a clean owner-context result.  A real v31 constraints table should
    # not force MVAR into a TypeDefinition generic-parameter context.
    if (
        best_score < 0.80
        or best_diag.get('invalid', 0)
        or best_diag.get('type_context_mvar', 0)
        or best_diag.get('generic_owner_mismatch', 0)
    ):
        top = '; '.join(
            f'0x{rel:X}:score={score:.3f},invalid={diag.get("invalid",0)},'
            f'typeMVAR={diag.get("type_context_mvar",0)},owner={diag.get("generic_owner_mismatch",0)},'
            f'kinds={diag.get("kind_histogram",{})}'
            for score, rel, diag in ranked[:5]
        )
        raise ValueError(
            'Unable to identify a DummyDll-safe generic constraint table. '
            f'Top candidates: {top}'
        )

    old_rel = md.generic_constraint_type_indices_off
    md.generic_constraint_type_indices_off = best_rel
    if md.heuristic_layout is not None:
        md.heuristic_layout['secondary']['generic_constraints']['offset'] = best_rel
        md.heuristic_layout['secondary']['generic_constraints']['count'] = constraint_count
        md.heuristic_layout['secondary']['generic_constraints']['semantic_score'] = best_score
        md.heuristic_layout['secondary']['generic_constraints']['semantic_diag'] = best_diag

    old_score = None
    old_diag = None
    for score, rel, diag in ranked:
        if rel == old_rel:
            old_score, old_diag = score, diag
            break

    return {
        'changed': best_rel != old_rel,
        'old_offset': old_rel,
        'offset': best_rel,
        'constraint_count': constraint_count,
        'score': best_score,
        'diagnostics': best_diag,
        'old_score': old_score,
        'old_diagnostics': old_diag,
        'reserved_offsets': sorted(reserved_offsets),
        'top_candidates': [
            {
                'offset': rel,
                'score': score,
                'type_context_mvar': diag.get('type_context_mvar', 0),
                'invalid': diag.get('invalid', 0),
                'kind_histogram': diag.get('kind_histogram', {}),
            }
            for score, rel, diag in ranked[:5]
        ],
    }



def _convert_type_bits_protected_to_stock(bits: int) -> int:
    attrs, kind, num_mods, byref, pinned = _decode_protected_type_bits(bits)
    valuetype = 1 if kind == 0x11 else 0
    return (
        attrs
        | (kind << 16)
        | (num_mods << 24)
        | (byref << 29)
        | (pinned << 30)
        | (valuetype << 31)
    ) & 0xFFFFFFFF


def _write_u32_va(buf: bytearray, elf: ELF64, va: int, value: int) -> None:
    off = elf.va_to_off(va, 4)
    struct.pack_into('<I', buf, off, value & 0xFFFFFFFF)


def _normalize_types_in_copy(buf: bytearray, elf: ELF64, types_ptr: int, types_count: int) -> int:
    changed = 0
    for i in range(types_count):
        type_ptr = elf.u64(types_ptr + i * 8)
        if not type_ptr:
            continue
        try:
            descriptor = elf.u32(type_ptr + 0)
            kind = (descriptor >> 8) & 0xFF
            if kind == 0x14:
                # _normalize_array_types may already have replaced the protected
                # ARRAY data pointer in the output copy.
                data = struct.unpack_from('<Q', buf, elf.va_to_off(type_ptr + 8, 8))[0]
            else:
                data = _u64_from_load_image(elf, type_ptr + 8)
            stock_bits = _convert_type_bits_protected_to_stock(descriptor)
            _patch_u64_va(buf, elf, type_ptr + 0, data)
            _patch_u64_va(buf, elf, type_ptr + 8, stock_bits)
            changed += 1
        except Exception as exc:
            raise ValueError(f'Il2CppType[{i}] at 0x{type_ptr:X} is not file-backed') from exc
    return changed


def _collect_runtime_type_closure(elf: ELF64, meta: dict) -> tuple[list[int], dict]:
    """Return a stock-safe types[] pointer list.

    Stock Il2CppDumper builds typeDic only from MetadataRegistration.types.
    Protected builds may omit helper/runtime Il2CppType objects that are only
    reachable through ARRAY, PTR/SZARRAY, GenericClass or GenericInst argv
    references.  Those missing entries cause GetIl2CppType() -> null during
    recursive GetTypeName().

    Preserve the original type indexes and append every transitively referenced
    Il2CppType pointer at the end.
    """
    from collections import deque

    original = []
    for i in range(meta['types_count']):
        p = elf.u64(meta['types'] + i * 8)
        original.append(p)

    seen_types = {p for p in original if p}
    ordered_extra = []
    q = deque(p for p in original if p)

    seen_insts = set()
    seen_gclasses = set()
    seen_arrays = set()

    diagnostics = {
        'original_types_count': len(original),
        'extra_types_count': 0,
        'array_type_nodes': 0,
        'generic_class_nodes': 0,
        'generic_inst_nodes': 0,
        'bad_runtime_refs': [],
    }

    valid_kinds = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x18, 0x19, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x40, 0x41, 0x45,
    }

    def add_type(p: int, why: str) -> None:
        if not p:
            return
        if p in seen_types:
            return
        # An Il2CppType is 16 bytes in this runtime.
        if not _is_load_mapped(elf, p, 12):
            diagnostics['bad_runtime_refs'].append((why, f'0x{p:X}', 'unmapped-type'))
            return
        try:
            kind = elf.u8(p + 1)
        except Exception:
            diagnostics['bad_runtime_refs'].append((why, f'0x{p:X}', 'unreadable-type'))
            return
        if kind not in valid_kinds:
            diagnostics['bad_runtime_refs'].append((why, f'0x{p:X}', f'bad-kind-0x{kind:X}'))
            return
        seen_types.add(p)
        ordered_extra.append(p)
        q.append(p)

    def walk_inst(inst: int, why: str) -> None:
        if not inst or inst in seen_insts:
            return
        if not _is_load_mapped(elf, inst, 16):
            diagnostics['bad_runtime_refs'].append((why, f'0x{inst:X}', 'unmapped-generic-inst'))
            return
        seen_insts.add(inst)
        diagnostics['generic_inst_nodes'] += 1
        try:
            argc = elf.u64(inst)
            argv = elf.u64(inst + 8)
        except Exception:
            diagnostics['bad_runtime_refs'].append((why, f'0x{inst:X}', 'unreadable-generic-inst'))
            return
        # Real generic arities are small. A huge value means this is not the
        # stock Il2CppGenericInst layout and should fail loudly instead of
        # walking arbitrary memory.
        if argc > 1024:
            diagnostics['bad_runtime_refs'].append((why, f'0x{inst:X}', f'argc={argc}'))
            return
        if argc == 0:
            return
        if not argv or not _is_load_mapped(elf, argv, int(argc) * 8):
            diagnostics['bad_runtime_refs'].append((why, f'0x{inst:X}', 'bad-argv'))
            return
        for j in range(int(argc)):
            try:
                add_type(elf.u64(argv + j * 8), f'{why}.argv[{j}]')
            except Exception:
                diagnostics['bad_runtime_refs'].append((why, f'0x{argv + j*8:X}', 'argv-read-failed'))

    # Seed every registered GenericInst as well, not just the ones reachable
    # from GENERICINST Il2CppType nodes.
    gi_count = int(meta.get('generic_insts_count', 0))
    gi_ptr = int(meta.get('generic_insts', 0))
    if gi_count and gi_ptr and _is_load_mapped(elf, gi_ptr, gi_count * 8):
        for i in range(gi_count):
            try:
                walk_inst(elf.u64(gi_ptr + i * 8), f'genericInsts[{i}]')
            except Exception:
                diagnostics['bad_runtime_refs'].append(
                    (f'genericInsts[{i}]', f'0x{gi_ptr + i*8:X}', 'pointer-read-failed')
                )

    while q:
        p = q.popleft()
        try:
            data = _u64_from_load_image(elf, p + 8)
            kind = elf.u8(p + 1)
        except Exception:
            continue

        if kind in (0x0F, 0x1D):  # PTR, SZARRAY
            add_type(data, f'type@0x{p:X}.direct')

        elif kind == 0x14:  # ARRAY -> Il2CppArrayType.etype
            if data and data not in seen_arrays:
                seen_arrays.add(data)
                diagnostics['array_type_nodes'] += 1
                if _is_load_mapped(elf, data, 32):
                    try:
                        arr = _read_protected_array_type(elf, data)
                        add_type(arr['etype'], f'array@0x{data:X}.etype')
                    except Exception:
                        diagnostics['bad_runtime_refs'].append(
                            (f'array@0x{data:X}', f'0x{data:X}', 'etype-read-failed')
                        )
                else:
                    diagnostics['bad_runtime_refs'].append(
                        (f'type@0x{p:X}', f'0x{data:X}', 'unmapped-array-type')
                    )

        elif kind == 0x15:  # GENERICINST -> Il2CppGenericClass
            if data and data not in seen_gclasses:
                seen_gclasses.add(data)
                diagnostics['generic_class_nodes'] += 1
                if not _is_load_mapped(elf, data, 32):
                    diagnostics['bad_runtime_refs'].append(
                        (f'type@0x{p:X}', f'0x{data:X}', 'unmapped-generic-class')
                    )
                    continue
                try:
                    # Protected Il2CppGenericClass:
                    #   +0x00 type, +0x08 method_inst, +0x10 class_inst, +0x18 cached_class.
                    add_type(_u64_from_load_image(elf, data + 0), f'gclass@0x{data:X}.type')
                    walk_inst(_u64_from_load_image(elf, data + 0x10), f'gclass@0x{data:X}.class_inst')
                    walk_inst(_u64_from_load_image(elf, data + 0x08), f'gclass@0x{data:X}.method_inst')
                except Exception:
                    diagnostics['bad_runtime_refs'].append(
                        (f'type@0x{p:X}', f'0x{data:X}', 'generic-class-read-failed')
                    )

    diagnostics['extra_types_count'] = len(ordered_extra)
    diagnostics['final_types_count'] = len(original) + len(ordered_extra)
    return original + ordered_extra, diagnostics



def _plausible_protected_type_ptr(elf: ELF64, ptr: int) -> bool:
    if not ptr or not _is_load_mapped(elf, ptr, 16):
        return False
    try:
        return elf.u8(ptr + 1) in _IL2CPP_TYPE_KINDS
    except Exception:
        return False


def _read_protected_array_type(elf: ELF64, array_va: int) -> dict:
    """Recover protected Il2CppArrayType variants used by this build.

    Most descriptors use a 32-byte qword permutation.  A small primitive
    multidimensional-array pool uses a 40-byte form with rank at +0x18 and
    etype at +0x20.
    """
    if not array_va or not _is_load_mapped(elf, array_va, 32):
        raise ValueError(f'Il2CppArrayType 0x{array_va:X} is not mapped')

    q0 = _u64_from_load_image(elf, array_va + 0)
    q16 = _u64_from_load_image(elf, array_va + 16)
    q24 = _u64_from_load_image(elf, array_va + 24)

    # 40-byte protected variant observed at 0xBF8D658/0xBF8D680:
    # qword(+0x18) carries the rank, qword(+0x20) is etype.
    if _is_load_mapped(elf, array_va, 40):
        q32 = _u64_from_load_image(elf, array_va + 32)
        if _plausible_protected_type_ptr(elf, q32) and 0 < q24 <= 0xFF:
            return {
                'etype': q32,
                'rank': int(q24),
                'numsizes': 0,
                'numlobounds': 0,
                'sizes': q0,
                'lobounds': q16,
                'etype_source_offset': 32,
            }

    rank = elf.u8(array_va + 8)
    numsizes = elf.u8(array_va + 9)
    numlobounds = elf.u8(array_va + 10)

    candidates = []
    for off, value in ((24, q24), (0, q0), (16, q16)):
        if _plausible_protected_type_ptr(elf, value):
            candidates.append((off, value))
    if not candidates:
        raise ValueError(
            f'Il2CppArrayType 0x{array_va:X}: no plausible etype pointer'
        )

    etype_off, etype = candidates[0]
    if etype_off == 24:
        sizes, lobounds = q0, q16
    elif etype_off == 0:
        sizes, lobounds = q16, q24
    else:
        sizes, lobounds = q0, q24

    return {
        'etype': etype,
        'rank': rank,
        'numsizes': numsizes,
        'numlobounds': numlobounds,
        'sizes': sizes,
        'lobounds': lobounds,
        'etype_source_offset': etype_off,
    }


def _relative_rela_addend_offsets(elf: ELF64) -> dict[int, int]:
    cache = getattr(elf, '_relative_rela_addend_offset_cache', None)
    if cache is not None:
        return cache
    SHT_RELA = 4
    R_AARCH64_RELATIVE = 1027
    cache = {}
    for i in range(elf.e_shnum):
        sh = elf.e_shoff + i * elf.e_shentsize
        if sh + 0x40 > len(elf.data):
            break
        if elf.u32_file(sh + 0x04) != SHT_RELA:
            continue
        sh_offset = elf.u64_file(sh + 0x18)
        sh_size = elf.u64_file(sh + 0x20)
        sh_entsize = elf.u64_file(sh + 0x38) or 24
        off = sh_offset
        end = min(sh_offset + sh_size, len(elf.data))
        while off + 24 <= end:
            r_offset = elf.u64_file(off + 0x00)
            r_info = elf.u64_file(off + 0x08)
            if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
                cache[r_offset] = off + 0x10
            off += sh_entsize
    setattr(elf, '_relative_rela_addend_offset_cache', cache)
    return cache


def _patch_relative_relocation_addend(
        buf: bytearray, elf: ELF64, target_va: int, value: int
) -> bool:
    addend_off = _relative_rela_addend_offsets(elf).get(target_va)
    if addend_off is None:
        return False
    struct.pack_into('<q', buf, addend_off, int(value))
    return True


def _patch_u64_va(buf: bytearray, elf: ELF64, va: int, value: int) -> None:
    # Dumper applies RELATIVE relocations. Patch the relocation addend first,
    # otherwise it would overwrite our qword during "Applying relocations...".
    patched_rela = _patch_relative_relocation_addend(buf, elf, va, value)
    try:
        off = elf.va_to_off(va, 8)
        struct.pack_into('<Q', buf, off, value & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        if not patched_rela:
            raise


def _normalize_generic_classes(buf: bytearray, elf: ELF64, pointers: list[int]) -> dict:
    """Normalize the protected Il2CppGenericClass context qword permutation.

    Protected build: +0x00 type, +0x08 method_inst, +0x10 class_inst, +0x18 cached.
    Stock v27+:      +0x00 type, +0x08 class_inst,  +0x10 method_inst, +0x18 cached.
    """
    seen = set()
    changed = 0
    for type_ptr in pointers:
        if not type_ptr:
            continue
        try:
            if elf.u8(type_ptr + 1) != 0x15:  # IL2CPP_TYPE_GENERICINST
                continue
            gc = _u64_from_load_image(elf, type_ptr + 8)
            if not gc or gc in seen:
                continue
            seen.add(gc)
            if not _is_load_mapped(elf, gc, 32):
                raise ValueError(f'GenericClass 0x{gc:X} is not mapped')
            method_inst = _u64_from_load_image(elf, gc + 0x08)
            class_inst = _u64_from_load_image(elf, gc + 0x10)
            _patch_u64_va(buf, elf, gc + 0x08, class_inst)
            _patch_u64_va(buf, elf, gc + 0x10, method_inst)
            changed += 1
        except Exception as exc:
            raise ValueError(f'Unable to normalize GenericClass for type 0x{type_ptr:X}') from exc
    return {'generic_classes_normalized': changed}


def _normalize_array_types(
        buf: bytearray, elf: ELF64, pointers: list[int], app
) -> dict:
    done = set()
    descriptor_cache = {}
    converted = 0
    already_stock = 0
    failures = []

    for type_ptr in pointers:
        if not type_ptr or type_ptr in done:
            continue
        done.add(type_ptr)
        try:
            kind = elf.u8(type_ptr + 1)
        except Exception:
            continue
        if kind != 0x14:
            continue

        try:
            old_array_va = _u64_from_load_image(elf, type_ptr + 8)
            info = _read_protected_array_type(elf, old_array_va)
            if info['etype_source_offset'] == 0:
                already_stock += 1
                continue

            new_array_va = descriptor_cache.get(old_array_va)
            if new_array_va is None:
                stock = struct.pack(
                    '<QBBB5xQQ',
                    info['etype'],
                    info['rank'],
                    info['numsizes'],
                    info['numlobounds'],
                    info['sizes'],
                    info['lobounds'],
                )
                new_array_va = app.add(stock, 8)
                descriptor_cache[old_array_va] = new_array_va

            _patch_u64_va(buf, elf, type_ptr + 8, new_array_va)
            converted += 1
        except Exception as exc:
            failures.append((f'0x{type_ptr:X}', str(exc)))

    if failures:
        sample = '; '.join(f'{a}: {e}' for a, e in failures[:8])
        raise ValueError(
            f'Unable to normalize {len(failures)} ARRAY type(s): {sample}'
        )

    return {
        'converted_type_refs': converted,
        'unique_descriptors': len(descriptor_cache),
        'already_stock': already_stock,
    }


def _self_check_array_types(path: Path, metadata_reg_va: int) -> dict:
    out = _selfcheck_elf(path)
    type_count = out.u64(metadata_reg_va + 48)
    types_va = out.u64(metadata_reg_va + 56)
    type_ptrs = [out.u64(types_va + i * 8) for i in range(type_count)]
    type_set = {p for p in type_ptrs if p}

    arrays = 0
    for i, type_ptr in enumerate(type_ptrs):
        if not type_ptr:
            continue
        bits = out.u32(type_ptr + 8)
        if ((bits >> 16) & 0xFF) != 0x14:
            continue
        arrays += 1
        array_va = out.u64(type_ptr)
        if not array_va:
            raise ValueError(f'stock ARRAY type[{i}] has null descriptor')
        etype = out.u64(array_va)
        rank = out.u8(array_va + 8)
        if etype not in type_set:
            raise ValueError(
                f'stock ARRAY type[{i}] has unregistered etype 0x{etype:X}'
            )
        if rank == 0:
            raise ValueError(f'stock ARRAY type[{i}] has rank 0')

    return {'array_type_count': arrays}


def _normalize_type_pointer_list(buf: bytearray, elf: ELF64, pointers: list[int]) -> int:
    """Convert protected 16-byte Il2CppType records in-place to stock layout.

    Protected: descriptor dword at +0 (type byte at +1, byref bit in byte +2),
    data qword at +8.  Stock: data qword at +0, packed bits dword at +8.
    Pointers between Il2CppType records therefore stay stable.
    """
    changed = 0
    done = set()
    for i, type_ptr in enumerate(pointers):
        if not type_ptr or type_ptr in done:
            continue
        done.add(type_ptr)
        try:
            descriptor = elf.u32(type_ptr + 0)
            kind = (descriptor >> 8) & 0xFF
            if kind == 0x14:
                # _normalize_array_types may already have replaced the protected
                # ARRAY data pointer in the output copy.
                data = struct.unpack_from('<Q', buf, elf.va_to_off(type_ptr + 8, 8))[0]
            else:
                data = _u64_from_load_image(elf, type_ptr + 8)
            stock_bits = _convert_type_bits_protected_to_stock(descriptor)
            _patch_u64_va(buf, elf, type_ptr + 0, data)
            # If +8 had an AArch64 RELATIVE relocation for a pointer, patch its
            # addend too so Il2CppDumper's relocation pass cannot restore it.
            _patch_u64_va(buf, elf, type_ptr + 8, stock_bits)
            changed += 1
        except Exception as exc:
            raise ValueError(
                f'Runtime Il2CppType[{i}] at 0x{type_ptr:X} cannot be normalized'
            ) from exc
    return changed


class _LoadAppender:
    def __init__(self, elf: ELF64, buf: bytearray):
        self.elf = elf
        self.buf = buf
        phdrs = []
        for i in range(elf.e_phnum):
            ph = elf.e_phoff + i * elf.e_phentsize
            p_type = struct.unpack_from('<I', buf, ph)[0]
            if p_type != ELF64.PT_LOAD:
                continue
            p_flags = struct.unpack_from('<I', buf, ph + 0x04)[0]
            p_offset = struct.unpack_from('<Q', buf, ph + 0x08)[0]
            p_vaddr = struct.unpack_from('<Q', buf, ph + 0x10)[0]
            p_filesz = struct.unpack_from('<Q', buf, ph + 0x20)[0]
            p_memsz = struct.unpack_from('<Q', buf, ph + 0x28)[0]
            phdrs.append((i, ph, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

        data_phdrs = [x for x in phdrs if not (x[2] & 1)]
        if not data_phdrs:
            raise ValueError('ELF has no non-executable PT_LOAD segment for synthetic stock data')
        chosen = max(data_phdrs, key=lambda x: x[3] + x[5])
        self.index, self.phoff, self.flags, self.p_offset, self.p_vaddr, self.old_filesz, self.old_memsz = chosen

        # Do not extend a data segment across a later PT_LOAD file range; that can
        # make MapVATR ambiguous. Android ELF files normally place the RW load last.
        chosen_end = self.p_offset + self.old_filesz
        later = [x for x in phdrs if x[3] > chosen_end]
        if later:
            raise ValueError('Cannot safely extend the selected PT_LOAD: another PT_LOAD follows it in the file')

        max_va_end = max(x[4] + x[6] for x in phdrs)
        start = _align_up(len(buf), 0x10)
        min_off_for_va = self.p_offset + max(0, max_va_end - self.p_vaddr)
        start = max(start, _align_up(min_off_for_va, 0x10))
        if start > len(buf):
            buf.extend(b'\0' * (start - len(buf)))
        self.cursor = start

    def add(self, blob: bytes | bytearray, alignment: int = 8) -> int:
        off = _align_up(self.cursor, alignment)
        if off > len(self.buf):
            self.buf.extend(b'\0' * (off - len(self.buf)))
        va = self.p_vaddr + (off - self.p_offset)
        self.buf.extend(blob)
        self.cursor = off + len(blob)
        return va

    def finish(self) -> None:
        # Only extend this PT_LOAD through objects allocated by this appender.
        # Extra search-only PT_LOAD segments may be appended afterwards.
        new_filesz = self.cursor - self.p_offset
        new_memsz = max(self.old_memsz, new_filesz)
        struct.pack_into('<Q', self.buf, self.phoff + 0x20, new_filesz)
        struct.pack_into('<Q', self.buf, self.phoff + 0x28, new_memsz)


def _normalize_method_specs(elf: ELF64, ptr: int, count: int) -> bytes:
    # Protected v31 order was verified against the generic-container ownership
    # of all 282476 MethodSpec entries:
    #   { methodDefinitionIndex, methodIndexIndex, classIndexIndex }
    # Stock Il2CppDumper expects:
    #   { methodDefinitionIndex, classIndexIndex, methodIndexIndex }
    # Leaving these two indexes unswapped makes StructGenerator feed a VAR
    # through a zero class_inst (or MVAR through a zero method_inst), causing
    # ReadClassArray() to interpret the ELF header as GenericInst.type_argc.
    if count <= 0:
        return b''
    src = elf.read(ptr, count * 12)
    out = bytearray(len(src))
    for i in range(count):
        method_def, method_inst, class_inst = struct.unpack_from('<iii', src, i * 12)
        struct.pack_into('<iii', out, i * 12, method_def, class_inst, method_inst)
    return bytes(out)


def _normalize_generic_method_table(elf: ELF64, ptr: int, count: int) -> bytes:
    # Protected 16-byte order is proven by index domains:
    #   +0 genericMethodIndex -> MethodSpec[282476]
    #   +4 invokerIndex       -> invokerPointers[33522] (or -1)
    #   +8 adjustorThunkIndex -> genericAdjustorThunks (or -1)
    #   +C methodIndex        -> genericMethodPointers[227255]
    # Stock order is { genericMethodIndex, methodIndex, invokerIndex,
    #                  adjustorThunkIndex }.
    if count <= 0:
        return b''
    src = elf.read(ptr, count * 16)
    out = bytearray(len(src))
    for i in range(count):
        generic_idx, invoker_idx, adjustor_idx, method_idx = struct.unpack_from(
            '<iiii', src, i * 16
        )
        struct.pack_into(
            '<iiii', out, i * 16,
            generic_idx, method_idx, invoker_idx, adjustor_idx,
        )
    return bytes(out)


def _rgctx_range_format(elf: ELF64, ptr: int, count: int) -> str:
    protected = standard = total = 0
    token_prefixes = {0x02, 0x04, 0x06, 0x08, 0x14, 0x17, 0x20, 0x23, 0x26, 0x2A}
    for i in _sample_indices(count, 24):
        try:
            a = elf.u32(ptr + i * 12)
            b = elf.i32(ptr + i * 12 + 4)
            c = elf.u32(ptr + i * 12 + 8)
        except Exception:
            continue
        total += 1
        if (a >> 24) in token_prefixes and 0 <= b < 10_000_000 and c < 1_000_000:
            standard += 1
        if (c >> 24) in token_prefixes and a < 10_000_000 and 0 <= b < 1_000_000:
            protected += 1
    if not total:
        return 'unknown'
    if protected / total >= 0.65:
        return 'protected'
    if standard / total >= 0.65:
        return 'standard'
    return 'unknown'


def _normalize_rgctx_ranges(elf: ELF64, ptr: int, count: int) -> Optional[bytes]:
    if not count:
        return b''
    fmt = _rgctx_range_format(elf, ptr, count)
    if fmt == 'unknown':
        return None
    if fmt == 'standard':
        try:
            return elf.read(ptr, count * 12)
        except Exception:
            return None
    out = bytearray(count * 12)
    for i in range(count):
        va = ptr + i * 12
        start = elf.i32(va + 0)
        length = elf.i32(va + 4)
        token = elf.u32(va + 8)
        struct.pack_into('<Iii', out, i * 12, token, start, length)
    return bytes(out)



def _filter_method_rgctx_ranges_for_stock_struct(ranges_blob: bytes) -> tuple[bytes, dict]:
    """Keep full generic method mapping while preventing stock StructGenerator
    from expanding method RGCTX once per generic instantiation.

    The raw RGCTX definitions remain in libunity.so.  Type/class RGCTX ranges
    (0x02 TypeDef tokens and any other non-method ranges) stay visible to the
    stock dumper.  Only 0x06 MethodDef ranges are omitted from the normalized
    CodeGenModule view used by StructGenerator.
    """
    if not ranges_blob:
        return ranges_blob, {
            'method_ranges_hidden': 0,
            'method_rgctx_items_hidden': 0,
            'non_method_ranges_kept': 0,
        }

    if len(ranges_blob) % 12:
        raise ValueError('normalized RGCTX range blob is not 12-byte aligned')

    out = bytearray()
    hidden = 0
    hidden_items = 0
    kept = 0

    for off in range(0, len(ranges_blob), 12):
        token, start, length = struct.unpack_from('<Iii', ranges_blob, off)
        if (token >> 24) == 0x06:  # MethodDef token
            hidden += 1
            if length > 0:
                hidden_items += length
            continue
        out.extend(ranges_blob[off:off + 12])
        kept += 1

    return bytes(out), {
        'method_ranges_hidden': hidden,
        'method_rgctx_items_hidden': hidden_items,
        'non_method_ranges_kept': kept,
    }


def _rgctx_defs_look_stock(elf: ELF64, ptr: int, count: int) -> bool:
    if count <= 0:
        return True
    good = total = 0
    for i in _sample_indices(count, 24):
        try:
            kind = elf.u64(ptr + i * 16)
            elf.u64(ptr + i * 16 + 8)
        except Exception:
            continue
        total += 1
        if 0 <= kind <= 5:
            good += 1
    return bool(total) and good / total >= 0.75


def _read_module_name_ptr(elf: ELF64, mod: int, expected_names: set[str]) -> int:
    # Protected CodeGenModule is 0x88 bytes in this build and moduleName is
    # consistently stored at +0x78.  Never scan past +0x80: +0x88 already
    # belongs to the next adjacent CodeGenModule in many module clusters.
    preferred = _u64_from_load_image(elf, mod + 0x78)
    if preferred and _is_file_backed(elf, preferred, 1):
        try:
            name = elf.cstr(preferred, 300)
            if name in expected_names or (name.lower().endswith('.dll') and len(name) < 260):
                return preferred
        except Exception:
            pass

    for off in range(0, 0x88, 8):
        try:
            value = _u64_from_load_image(elf, mod + off)
            if not value or not _is_file_backed(elf, value, 1):
                continue
            name = elf.cstr(value, 300)
        except Exception:
            continue
        if name in expected_names or (name.lower().endswith('.dll') and len(name) < 260):
            return value
    return 0


def _normalize_module_adjustor_thunks(elf: ELF64, ptr: int, count: int) -> bytes:
    """Convert protected {adjustorThunk, token} records to stock order.

    Protected record (16 bytes): +0x00 function pointer, +0x08 MethodDef token.
    Stock record (16 bytes):     +0x00 uint32 token + pad, +0x08 function pointer.
    """
    if count <= 0:
        return b''
    out = bytearray(count * 16)
    for i in range(count):
        fn = _u64_from_load_image(elf, ptr + i * 16)
        token = _u64_from_load_image(elf, ptr + i * 16 + 8)
        if token > 0xFFFFFFFF or (token >> 24) != 0x06 or not _is_exec_va(elf, fn):
            raise ValueError(
                f'CodeGenModule adjustor thunk[{i}] is malformed: '
                f'fn=0x{fn:X}, token=0x{token:X}'
            )
        struct.pack_into('<IIQ', out, i * 16, token & 0xFFFFFFFF, 0, fn)
    return bytes(out)


def _normalize_module_reverse_pinvoke(elf: ELF64, ptr: int, count: int, global_count: int) -> bytes:
    """Convert protected 24-byte Il2CppTokenIndexMethodTuple records.

    Stock:     +0 token, +4 index, +8 void** method, +16 __genericMethodIndex.
    Protected: +0 __genericMethodIndex, +4 index, +8 method, +16 token.
    """
    if count <= 0:
        return b''
    out = bytearray(count * 24)
    for i in range(count):
        va = ptr + i * 24
        generic_method_index = elf.u32(va + 0)
        index = elf.i32(va + 4)
        method = _u64_from_load_image(elf, va + 8)
        token = elf.u32(va + 16)
        pad = elf.u32(va + 20)
        if index < 0 or index >= global_count:
            raise ValueError(
                f'reverse P/Invoke tuple[{i}] index {index} outside global count {global_count}'
            )
        if (token >> 24) != 0x06:
            raise ValueError(
                f'reverse P/Invoke tuple[{i}] has bad MethodDef token 0x{token:X}'
            )
        struct.pack_into(
            '<IiQII', out, i * 24,
            token, index, method, generic_method_index, pad,
        )
    return bytes(out)


def _build_stock_modules(elf: ELF64, md: ProtectedMetadata, layout: dict, app: _LoadAppender, struct_rgctx_guard: bool = True) -> tuple[int, list[int], dict]:
    code = layout['code']
    count = code['codegen_modules_count']
    arr = code['codegen_modules']
    expected_names = {img.name for img in md.images if img.name}
    module_vas = []
    mscorlib_index = None
    mscorlib_template = None
    diagnostics = {
        'rgctx_ranges_normalized': 0,
        'rgctx_disabled': 0,
        'zero_fill_method_arrays': 0,
        'modules': count,
        'method_rgctx_ranges_hidden': 0,
        'method_rgctx_items_hidden': 0,
        'non_method_rgctx_ranges_kept': 0,
        'protected_module_layout': 'size=0x88, methods@0x00/0x08, adjustor@0x10/0x80, reverse@0x38/0x18, invokerIndices@0x20, rgctxs@0x50/0x28, ranges@0x60/0x48, name@0x78',
    }

    for i in range(count):
        mod = elf.u64(arr + i * 8)
        if not mod:
            module_vas.append(0)
            continue

        name_ptr = _read_module_name_ptr(elf, mod, expected_names)
        if not name_ptr:
            raise ValueError(f'Unable to identify moduleName for CodeGenModule[{i}] at 0x{mod:X}')

        # Proven protected fields for this build.  The remaining qwords are an
        # AxProtect permutation and are deliberately not guessed here.
        method_ptrs = elf.u64(mod + 0x00)
        method_count = elf.u64(mod + 0x08)

        if method_count:
            method_score = _exec_pointer_array_score(elf, method_ptrs, int(method_count), 20)
            if method_score < 0.55:
                raise ValueError(
                    f'CodeGenModule[{i}] method pointer validation failed at 0x{mod:X} '
                    f'(ptr=0x{method_ptrs:X}, count={method_count}, score={method_score:.2f})'
                )
            if method_ptrs and not _is_file_backed(elf, method_ptrs, 8) and _is_load_mapped(elf, method_ptrs, int(method_count) * 8):
                diagnostics['zero_fill_method_arrays'] += 1

        # Protected CodeGenModule is exactly 0x88 bytes.  The field permutation
        # below was validated across all 476 modules by record semantics:
        #   +0x80 count / +0x10 ptr -> adjustor thunk pairs {fn, MethodDef token}
        #   +0x20                  -> invokerIndices[methodPointerCount]
        #   +0x48 count / +0x60 ptr -> RGCTX ranges {token,start,length}
        #   +0x28 count / +0x50 ptr -> RGCTX definitions {kind,data}
        # Values at +0x88/+0x90/+0x98 seen in earlier notes are spill-over into
        # adjacent CodeGenModule objects, not fields of this structure.
        adjustor_count = int(_u64_from_load_image(elf, mod + 0x80))
        protected_adjustor_thunks = _u64_from_load_image(elf, mod + 0x10)
        invoker_indices = _u64_from_load_image(elf, mod + 0x20)

        if adjustor_count:
            adjustor_blob = _normalize_module_adjustor_thunks(
                elf, protected_adjustor_thunks, adjustor_count
            )
            adjustor_thunks = app.add(adjustor_blob, 8)
        else:
            adjustor_thunks = 0

        # Reverse-P/Invoke uses a protected 24-byte field permutation.  The
        # module counts sum exactly to the global reversePInvokeWrapperCount.
        reverse_count = int(_u64_from_load_image(elf, mod + 0x18))
        protected_reverse = _u64_from_load_image(elf, mod + 0x38)
        if reverse_count:
            reverse_blob = _normalize_module_reverse_pinvoke(
                elf, protected_reverse, reverse_count, int(code['reverse_pinvoke_count'])
            )
            reverse_indices = app.add(reverse_blob, 8)
        else:
            reverse_indices = 0

        protected_range_count = int(_u64_from_load_image(elf, mod + 0x48))
        protected_ranges = _u64_from_load_image(elf, mod + 0x60)
        protected_rgctx_count = int(_u64_from_load_image(elf, mod + 0x28))
        protected_rgctxs = _u64_from_load_image(elf, mod + 0x50)

        normalized_range_count = protected_range_count
        normalized_ranges_ptr = 0
        normalized_rgctx_count = protected_rgctx_count
        normalized_rgctxs_ptr = protected_rgctxs

        if protected_range_count or protected_rgctx_count:
            ranges_blob = _normalize_rgctx_ranges(
                elf, protected_ranges, protected_range_count
            )
            defs_ok = _rgctx_defs_look_stock(
                elf, protected_rgctxs, protected_rgctx_count
            )
            if ranges_blob is None or not defs_ok:
                raise ValueError(
                    f'CodeGenModule[{i}] RGCTX validation failed at 0x{mod:X}'
                )
            if struct_rgctx_guard:
                ranges_blob, guard_diag = _filter_method_rgctx_ranges_for_stock_struct(
                    ranges_blob
                )
                normalized_range_count = len(ranges_blob) // 12
                diagnostics['method_rgctx_ranges_hidden'] += guard_diag['method_ranges_hidden']
                diagnostics['method_rgctx_items_hidden'] += guard_diag['method_rgctx_items_hidden']
                diagnostics['non_method_rgctx_ranges_kept'] += guard_diag['non_method_ranges_kept']
            normalized_ranges_ptr = app.add(ranges_blob, 8) if ranges_blob else 0
            diagnostics['rgctx_ranges_normalized'] += 1
        else:
            diagnostics['rgctx_disabled'] += 1

        try:
            module_name = elf.cstr(name_ptr, 300)
        except Exception:
            module_name = ''

        stock = struct.pack(
            '<QqQqQQQQqQqQQQQQQ',
            name_ptr,
            int(method_count),
            method_ptrs,
            int(adjustor_count),
            adjustor_thunks,
            invoker_indices,
            reverse_count,
            reverse_indices,
            int(normalized_range_count),
            normalized_ranges_ptr,
            int(normalized_rgctx_count),
            normalized_rgctxs_ptr,
            0,  # debuggerMetadata
            0,  # moduleInitializer
            0,  # staticConstructorTypeIndices
            0,  # metadataRegistration (per-assembly mode)
            0,  # codeRegistration (per-assembly mode)
        )
        if module_name.lower() == 'mscorlib.dll':
            mscorlib_index = i
            mscorlib_template = bytes(stock)
        module_vas.append(app.add(stock, 8))

    if mscorlib_index is None or mscorlib_template is None:
        raise ValueError('Unable to identify mscorlib.dll CodeGenModule for stock fast-search anchor')

    array_blob = b''.join(struct.pack('<Q', va) for va in module_vas)
    array_va = app.add(array_blob, 8)
    return array_va, module_vas, diagnostics, mscorlib_index, mscorlib_template


def _build_stock_code_registration(layout: dict, modules_array_va: int) -> bytes:
    c = layout['code']
    adjustor_marker = c['generic_adjustor_thunks'] or c['generic_method_pointers']
    return struct.pack(
        '<' + 'Q' * 17,
        c['reverse_pinvoke_count'],
        c['reverse_pinvoke'],
        c['generic_method_pointers_count'],
        c['generic_method_pointers'],
        adjustor_marker,
        c['invoker_pointers_count'],
        c['invoker_pointers'],
        c['unresolved_virtual_count'],
        c['unresolved_virtual'],
        c['unresolved_instance'],
        c['unresolved_static'],
        c['interop_count'],
        c['interop'],
        0,
        0,
        c['codegen_modules_count'],
        modules_array_va,
    )


def _build_stock_metadata_registration(layout: dict, generic_table_va: int, method_specs_va: int, search_type_sizes_va: int) -> bytes:
    m = layout['metadata']
    return struct.pack(
        '<' + 'Q' * 16,
        m['generic_classes_count'], m['generic_classes'],
        m['generic_insts_count'], m['generic_insts'],
        m['generic_method_table_count'], generic_table_va,
        m['types_count'], m['types'],
        m['method_specs_count'], method_specs_va,
        m['field_offsets_count'], m['field_offsets'],
        m['type_definition_sizes_count'], search_type_sizes_va,
        0, 0,
    )





def _pack_phdr_entry(entsize: int, p_type: int, p_flags: int, p_offset: int,
                     p_vaddr: int, p_filesz: int, p_memsz: int, p_align: int) -> bytes:
    if entsize < 56:
        raise ValueError(f'ELF program-header entry is too small ({entsize})')
    out = bytearray(entsize)
    struct.pack_into(
        '<IIQQQQQQ', out, 0,
        p_type, p_flags, p_offset, p_vaddr, p_vaddr,
        p_filesz, p_memsz, p_align
    )
    return bytes(out)


def _install_search_phdrs(buf: bytearray, elf: ELF64,
                          exec_off: int, exec_va: int, exec_size: int,
                          data_off: int, data_va: int, data_size: int) -> tuple[int, int]:
    """Put tiny synthetic PT_LOADs first in the PHDR table.

    Stock Il2CppDumper's ELF64 PlusSearch scans executable PT_LOADs for
    "mscorlib.dll", then repeatedly scans data PT_LOADs for references.
    Making the synthetic RX/R segments the first entries turns that search
    into a few tiny scans instead of walking the full libunity image.
    """
    ph_entries = []
    ph_types = []
    for i in range(elf.e_phnum):
        off = elf.e_phoff + i * elf.e_phentsize
        entry = bytes(buf[off:off + elf.e_phentsize])
        if len(entry) != elf.e_phentsize:
            raise ValueError('Truncated program-header table')
        ph_entries.append(entry)
        ph_types.append(struct.unpack_from('<I', entry, 0)[0])

    PT_LOAD = 1
    PT_DYNAMIC = 2
    # Safe-to-sacrifice entries for a dumper-only ELF copy. We keep every
    # PT_LOAD and PT_DYNAMIC entry intact.
    disposable_types = {
        4,          # PT_NOTE
        6,          # PT_PHDR
        0x6474E550, # PT_GNU_EH_FRAME
        0x6474E551, # PT_GNU_STACK
        0x6474E552, # PT_GNU_RELRO
        0x6474E553, # PT_GNU_PROPERTY
    }

    targets = [0, 1]
    essential_targets = [i for i in targets if ph_types[i] not in disposable_types]
    spare = [
        i for i, t in enumerate(ph_types)
        if i not in targets and t in disposable_types
    ]
    if len(spare) < len(essential_targets):
        raise ValueError(
            'ELF does not have enough nonessential program headers to install '
            'fast stock-search PT_LOAD segments'
        )

    # Preserve any essential entries displaced from slots 0/1.
    for target, slot in zip(essential_targets, spare):
        ph_entries[slot] = ph_entries[target]

    ph_entries[0] = _pack_phdr_entry(
        elf.e_phentsize, PT_LOAD, 5, exec_off, exec_va,
        exec_size, exec_size, 0x1000
    )
    ph_entries[1] = _pack_phdr_entry(
        elf.e_phentsize, PT_LOAD, 4, data_off, data_va,
        data_size, data_size, 0x1000
    )

    for i, entry in enumerate(ph_entries):
        off = elf.e_phoff + i * elf.e_phentsize
        buf[off:off + elf.e_phentsize] = entry

    return 0, 1


def _install_fast_stock_search(
        buf: bytearray,
        elf: ELF64,
        app: _LoadAppender,
        layout: dict,
        module_vas: list[int],
        mscorlib_index: int,
        mscorlib_template: bytes,
        generic_table_va: int,
        method_specs_va: int,
) -> dict:
    """Install two tiny PT_LOADs used only to accelerate stock PlusSearch.

    RX segment: the single mscorlib.dll anchor.
    R segment: stock mscorlib CodeGenModule, reordered module pointer array,
    MetadataRegistration and CodeRegistration.

    The real normalized runtime objects remain in the extended RW PT_LOAD.
    """

    # The normal appended RW PT_LOAD must end before the search-only segments.
    app.finish()

    original_max_va = max(v + m for v, _, _, m, _ in elf.loads)
    extended_rw_end = app.p_vaddr + max(app.old_memsz, app.cursor - app.p_offset)
    search_base_va = _align_up(max(original_max_va, extended_rw_end), 0x1000)

    # Executable anchor segment comes first in the PHDR table, so
    # FindCodeRegistrationExec() succeeds before scanning the huge .text.
    exec_off = _align_up(len(buf), 0x1000)
    if exec_off > len(buf):
        buf.extend(b'\0' * (exec_off - len(buf)))
    exec_va = search_base_va
    exec_blob = b'mscorlib.dll\0'
    buf.extend(exec_blob)

    data_off = _align_up(len(buf), 0x1000)
    if data_off > len(buf):
        buf.extend(b'\0' * (data_off - len(buf)))
    data_va = _align_up(exec_va + len(exec_blob), 0x1000)
    data_blob = bytearray()

    def data_add(blob: bytes | bytearray, alignment: int = 8) -> int:
        off = _align_up(len(data_blob), alignment)
        if off > len(data_blob):
            data_blob.extend(b'\0' * (off - len(data_blob)))
        va = data_va + off
        data_blob.extend(blob)
        return va

    # Duplicate only the mscorlib module in the fast-search segment. Its first
    # qword must point at the RX anchor because SectionHelper expects
    # moduleName at offset 0 for the second reference hop.
    mscorlib_stock = bytearray(mscorlib_template)
    struct.pack_into('<Q', mscorlib_stock, 0, exec_va)
    mscorlib_module_va = data_add(mscorlib_stock, 8)

    # Ordering is irrelevant to Il2CppDumper.Init (it keys modules by name),
    # but PlusSearch iterates image indexes from last to first. Put mscorlib at
    # the last slot so the very first iteration hits the array base.
    search_modules = [
        va for i, va in enumerate(module_vas)
        if i != mscorlib_index
    ]
    search_modules.append(mscorlib_module_va)
    if len(search_modules) != layout['code']['codegen_modules_count']:
        raise ValueError('Fast-search module array count mismatch')
    modules_array_va = data_add(
        b''.join(struct.pack('<Q', va) for va in search_modules), 8
    )

    # MetadataRegistrationV21 search validates the typeDefinitionsSizes pointer
    # array. Keep that signature inside the tiny first data PT_LOAD too.
    type_def_count = layout['metadata']['type_definition_sizes_count']
    # SectionHelper.FindMetadataRegistrationV21 checks these element values
    # against EXEC ranges when CodeRegistration came from FindCodeRegistrationExec.
    # The contents are only a search signature; Il2CppDumper.Init does not consume
    # typeDefinitionsSizes, so point every entry at our executable mscorlib anchor.
    search_type_sizes_va = data_add(
        struct.pack('<Q', exec_va) * type_def_count, 8
    )

    metadata_reg_blob = _build_stock_metadata_registration(
        layout, generic_table_va, method_specs_va, search_type_sizes_va
    )
    metadata_reg_va = data_add(metadata_reg_blob, 8)

    code_reg_blob = _build_stock_code_registration(layout, modules_array_va)
    code_reg_va = data_add(code_reg_blob, 8)

    # IMPORTANT: stock SectionHelper.FindReference() uses:
    #   end = offsetEnd - PointerSize; while (position < end)
    # so a pointer stored in the final qword is skipped. codeGenModules is the
    # final qword of Il2CppCodeRegistration; keep at least two qwords after it.
    data_add(b'\0' * 0x20, 8)

    buf.extend(data_blob)

    exec_phdr, data_phdr = _install_search_phdrs(
        buf, elf,
        exec_off, exec_va, len(exec_blob),
        data_off, data_va, len(data_blob),
    )

    return {
        'code_reg_va': code_reg_va,
        'metadata_reg_va': metadata_reg_va,
        'exec_anchor_va': exec_va,
        'data_segment_va': data_va,
        'modules_array_va': modules_array_va,
        'mscorlib_module_va': mscorlib_module_va,
        'type_sizes_va': search_type_sizes_va,
        'exec_phdr': exec_phdr,
        'data_phdr': data_phdr,
    }



def _stock_search_sections(out: ELF64) -> tuple[list[tuple], list[tuple]]:
    # Mirrors Elf64.GetSectionHelper: flags 1/3/5/7 -> exec, 2/4/6 -> data.
    exec_secs = []
    data_secs = []
    for p_vaddr, p_offset, p_filesz, p_memsz, p_flags in out.loads:
        sec = (p_vaddr, p_offset, p_filesz, p_memsz, p_flags)
        if p_memsz == 0:
            continue
        if p_flags in (1, 3, 5, 7):
            exec_secs.append(sec)
        elif p_flags in (2, 4, 6):
            data_secs.append(sec)
    return exec_secs, data_secs


def _stock_map_va_to_raw(out: ELF64, va: int) -> int:
    # Mirrors Elf64.MapVATR: first program segment containing the VA.
    for p_vaddr, p_offset, p_filesz, p_memsz, p_flags in out.loads:
        if p_vaddr <= va <= p_vaddr + p_memsz:
            return p_offset + (va - p_vaddr)
    raise ValueError(f'stock MapVATR failed for 0x{va:X}')


def _stock_raw_to_va(sec: tuple, raw: int) -> int:
    p_vaddr, p_offset, *_ = sec
    return raw - p_offset + p_vaddr


def _stock_find_refs(out: ELF64, addr: int, data_secs: list[tuple]):
    # Mirrors SectionHelper.FindReference, including its final-qword exclusion.
    for sec in data_secs:
        p_vaddr, p_offset, p_filesz, p_memsz, p_flags = sec
        pos = p_offset
        end = min(p_offset + p_filesz, len(out.data)) - 8
        while pos < end:
            if struct.unpack_from('<Q', out.data, pos)[0] == addr:
                yield _stock_raw_to_va(sec, pos)
            pos += 8


def _stock_find_code_registration_v31(out: ELF64, image_count: int) -> tuple[int, bool]:
    feature = b'mscorlib.dll\0'
    exec_secs, data_secs = _stock_search_sections(out)

    def search(secs: list[tuple]) -> int:
        for sec in secs:
            p_vaddr, p_offset, p_filesz, p_memsz, p_flags = sec
            blob = out.data[p_offset:min(p_offset + p_filesz, len(out.data))]
            start = 0
            while True:
                idx = blob.find(feature, start)
                if idx < 0:
                    break
                dllva = p_vaddr + idx
                for refva in _stock_find_refs(out, dllva, data_secs):
                    for refva2 in _stock_find_refs(out, refva, data_secs):
                        for i in range(image_count - 1, -1, -1):
                            target = refva2 - i * 8
                            for refva3 in _stock_find_refs(out, target, data_secs):
                                raw = _stock_map_va_to_raw(out, refva3 - 8)
                                if raw + 8 <= len(out.data):
                                    value = struct.unpack_from('<Q', out.data, raw)[0]
                                    if value == image_count:
                                        # Version >=29 path in SectionHelper.
                                        return refva3 - 14 * 8
                start = idx + 1
        return 0

    candidate = search(exec_secs)
    if candidate:
        return candidate, True
    return search(data_secs), False


def _stock_find_metadata_registration_v31(
        out: ELF64, type_def_count: int, pointer_in_exec: bool
) -> int:
    exec_secs, data_secs = _stock_search_sections(out)

    def va_in(secs, va):
        return any(s[0] <= va <= s[0] + s[3] for s in secs)

    def raw_in_data(raw):
        return any(s[1] <= raw <= s[1] + s[2] for s in data_secs)

    for sec in data_secs:
        p_vaddr, p_offset, p_filesz, p_memsz, p_flags = sec
        pos = p_offset
        end = min(p_offset + p_filesz, len(out.data)) - 8
        while pos < end:
            if struct.unpack_from('<Q', out.data, pos)[0] == type_def_count:
                second = pos + 16
                if second + 16 <= len(out.data):
                    if struct.unpack_from('<Q', out.data, second)[0] == type_def_count:
                        ptr_va = struct.unpack_from('<Q', out.data, second + 8)[0]
                        try:
                            ptr_raw = _stock_map_va_to_raw(out, ptr_va)
                        except Exception:
                            ptr_raw = -1
                        if raw_in_data(ptr_raw):
                            need = type_def_count * 8
                            if ptr_raw >= 0 and ptr_raw + need <= len(out.data):
                                values = struct.unpack_from(
                                    '<' + 'Q' * type_def_count, out.data, ptr_raw
                                )
                                if pointer_in_exec:
                                    ok = all(va_in(exec_secs, x) for x in values)
                                else:
                                    ok = all(va_in(data_secs, x) for x in values)
                                if ok:
                                    addr_va = _stock_raw_to_va(sec, pos)
                                    return addr_va - 10 * 8
            pos += 8
    return 0


def _selfcheck_elf(path_or_elf) -> ELF64:
    return path_or_elf if isinstance(path_or_elf, ELF64) else ELF64(path_or_elf)


def _self_check_stock_plussearch_exact(
        path: Path,
        expected_code_reg: int,
        expected_metadata_reg: int,
        image_count: int,
        type_def_count: int,
) -> dict:
    out = _selfcheck_elf(path)
    candidate, pointer_in_exec = _stock_find_code_registration_v31(out, image_count)
    expected_candidate = expected_code_reg + 16  # v31 search intentionally lands +0x10
    if candidate != expected_candidate:
        raise ValueError(
            'stock PlusSearch self-check: CodeRegistration search would return '
            f'0x{candidate:X}, expected 0x{expected_candidate:X}'
        )

    # Mirrors AutoPlusInit's v31 discriminator. It maps the +0x10 candidate as
    # a v31 structure and reads genericMethodPointersCount at candidate+0x10,
    # i.e. full stock registration +0x20. It must look pointer-like (>0x50000)
    # so AutoPlusInit subtracts 0x10 and keeps Version 31.
    raw = _stock_map_va_to_raw(out, candidate + 16)
    v31_marker = struct.unpack_from('<Q', out.data, raw)[0]
    if v31_marker <= 0x50000:
        raise ValueError(
            'stock PlusSearch self-check: AutoPlusInit would downgrade v31 to v29 '
            f'(marker=0x{v31_marker:X})'
        )

    metadata = _stock_find_metadata_registration_v31(
        out, type_def_count, pointer_in_exec
    )
    if metadata != expected_metadata_reg:
        raise ValueError(
            'stock PlusSearch self-check: MetadataRegistration search would return '
            f'0x{metadata:X}, expected 0x{expected_metadata_reg:X}'
        )

    return {
        'plus_candidate': f'0x{candidate:X}',
        'pointer_in_exec': pointer_in_exec,
        'v31_marker': f'0x{v31_marker:X}',
        'metadata_registration': f'0x{metadata:X}',
    }


def _self_check_fast_search(path: Path, fast: dict, expected_images: int, expected_type_defs: int) -> dict:
    out = _selfcheck_elf(path)

    # Our synthetic segments must be the first executable/data PT_LOADs in
    # program-header order because SectionHelper preserves that order.
    exec_loads = [x for x in out.loads if x[4] & 1]
    data_loads = [x for x in out.loads if not (x[4] & 1)]
    if not exec_loads or exec_loads[0][0] != fast['exec_anchor_va']:
        raise ValueError('fast-search self-check: RX anchor PT_LOAD is not first')
    if not data_loads or data_loads[0][0] != fast['data_segment_va']:
        raise ValueError('fast-search self-check: data PT_LOAD is not first')

    if out.read(fast['exec_anchor_va'], 13) != b'mscorlib.dll\0':
        raise ValueError('fast-search self-check: mscorlib.dll anchor missing')

    module_name = out.u64(fast['mscorlib_module_va'])
    if module_name != fast['exec_anchor_va']:
        raise ValueError('fast-search self-check: mscorlib moduleName link is invalid')

    # mscorlib must be the final module pointer.
    last_mod = out.u64(fast['modules_array_va'] + (expected_images - 1) * 8)
    if last_mod != fast['mscorlib_module_va']:
        raise ValueError('fast-search self-check: mscorlib is not the last module')

    code_reg = fast['code_reg_va']
    if out.u64(code_reg + 120) != expected_images:
        raise ValueError('fast-search self-check: CodeRegistration image count mismatch')
    if out.u64(code_reg + 128) != fast['modules_array_va']:
        raise ValueError('fast-search self-check: CodeRegistration module array mismatch')

    meta_reg = fast['metadata_reg_va']
    if out.u64(meta_reg + 80) != expected_type_defs:
        raise ValueError('fast-search self-check: fieldOffsetsCount mismatch')
    if out.u64(meta_reg + 96) != expected_type_defs:
        raise ValueError('fast-search self-check: typeDefinitionsSizesCount mismatch')

    return {
        'exec_anchor_va': f"0x{fast['exec_anchor_va']:X}",
        'data_segment_va': f"0x{fast['data_segment_va']:X}",
        'mscorlib_last_index': expected_images - 1,
    }



def _self_check_full_generic_mapping(
        path: Path,
        code_reg_va: int,
        metadata_reg_va: int,
        expected_generic_ptrs: int,
        expected_generic_table: int,
) -> dict:
    out = _selfcheck_elf(path)

    # Stock v31 Il2CppCodeRegistration:
    # reversePInvoke count/ptr, genericMethodPointers count/ptr, ...
    generic_ptr_count = out.u64(code_reg_va + 0x10)
    generic_ptr_va = out.u64(code_reg_va + 0x18)

    # Stock Il2CppMetadataRegistration:
    # genericClasses pair, genericInsts pair, genericMethodTable pair, ...
    generic_table_count = out.u64(metadata_reg_va + 0x20)
    generic_table_va = out.u64(metadata_reg_va + 0x28)

    if generic_ptr_count != expected_generic_ptrs:
        raise ValueError(
            f'FULL generic mapping check failed: genericMethodPointersCount '
            f'{generic_ptr_count} != {expected_generic_ptrs}'
        )
    if generic_table_count != expected_generic_table:
        raise ValueError(
            f'FULL generic mapping check failed: genericMethodTableCount '
            f'{generic_table_count} != {expected_generic_table}'
        )
    if expected_generic_ptrs and not generic_ptr_va:
        raise ValueError('FULL generic mapping check failed: genericMethodPointers pointer is null')
    if expected_generic_table and not generic_table_va:
        raise ValueError('FULL generic mapping check failed: genericMethodTable pointer is null')

    return {
        'generic_method_pointers_count': int(generic_ptr_count),
        'generic_method_table_count': int(generic_table_count),
    }


def _self_check_codegen_modules(path_or_elf, code_reg_va: int) -> dict:
    out = _selfcheck_elf(path_or_elf)
    module_count = int(out.u64(code_reg_va + 120))
    modules_va = out.u64(code_reg_va + 128)
    invoker_count = int(out.u64(code_reg_va + 40))
    global_reverse_count = int(out.u64(code_reg_va + 0))

    total_adjustors = 0
    total_reverse = 0
    total_ranges = 0
    total_rgctxs = 0
    bad_invoker_indices = 0

    for i in range(module_count):
        mod = out.u64(modules_va + i * 8)
        if not mod:
            continue
        name_ptr = out.u64(mod + 0x00)
        if not name_ptr or not _is_file_backed(out, name_ptr, 1):
            raise ValueError(f'CodeGenModule self-check: module[{i}] has invalid name pointer')

        method_count = int(out.u64(mod + 0x08))
        adjustor_count = int(out.u64(mod + 0x18))
        adjustor_ptr = out.u64(mod + 0x20)
        invoker_indices = out.u64(mod + 0x28)
        reverse_count = int(out.u64(mod + 0x30))
        reverse_ptr = out.u64(mod + 0x38)
        range_count = int(out.u64(mod + 0x40))
        ranges_ptr = out.u64(mod + 0x48)
        rgctx_count = int(out.u64(mod + 0x50))
        rgctx_ptr = out.u64(mod + 0x58)

        total_adjustors += adjustor_count
        total_reverse += reverse_count
        total_ranges += range_count
        total_rgctxs += rgctx_count

        if adjustor_count:
            if not adjustor_ptr:
                raise ValueError(f'CodeGenModule self-check: module[{i}] adjustor pointer is null')
            for j in range(adjustor_count):
                token = out.u32(adjustor_ptr + j * 16)
                fn = out.u64(adjustor_ptr + j * 16 + 8)
                if (token >> 24) != 0x06 or not _is_exec_va(out, fn):
                    raise ValueError(
                        f'CodeGenModule self-check: bad adjustor thunk module[{i}] entry[{j}]'
                    )

        if method_count and invoker_indices:
            for j in range(method_count):
                index = out.i32(invoker_indices + j * 4)
                if index != -1 and not (0 <= index < invoker_count):
                    bad_invoker_indices += 1

        if reverse_count:
            if not reverse_ptr:
                raise ValueError(f'CodeGenModule self-check: module[{i}] reverse P/Invoke pointer is null')
            for j in range(reverse_count):
                va = reverse_ptr + j * 24
                token = out.u32(va + 0)
                index = out.i32(va + 4)
                method = out.u64(va + 8)
                if (token >> 24) != 0x06 or not (0 <= index < global_reverse_count):
                    raise ValueError(
                        f'CodeGenModule self-check: bad reverse P/Invoke tuple module[{i}] entry[{j}]'
                    )
                if not method or not _is_load_mapped(out, method, 8):
                    raise ValueError(
                        f'CodeGenModule self-check: reverse P/Invoke method slot module[{i}] entry[{j}] is invalid'
                    )

        if range_count:
            if not ranges_ptr:
                raise ValueError(f'CodeGenModule self-check: module[{i}] RGCTX ranges pointer is null')
            for j in range(range_count):
                token, start, length = struct.unpack('<Iii', out.read(ranges_ptr + j * 12, 12))
                if start < 0 or length < 0 or start + length > rgctx_count:
                    raise ValueError(
                        f'CodeGenModule self-check: module[{i}] RGCTX range[{j}] is out of bounds'
                    )
                if (token >> 24) not in {0x02, 0x04, 0x06, 0x08, 0x14, 0x17, 0x20, 0x23, 0x26, 0x2A}:
                    raise ValueError(
                        f'CodeGenModule self-check: module[{i}] RGCTX range[{j}] has bad token 0x{token:X}'
                    )

        if rgctx_count:
            if not rgctx_ptr or not _rgctx_defs_look_stock(out, rgctx_ptr, rgctx_count):
                raise ValueError(f'CodeGenModule self-check: module[{i}] RGCTX definitions are invalid')

    if bad_invoker_indices:
        raise ValueError(
            f'CodeGenModule self-check: {bad_invoker_indices} invoker indices are out of range'
        )
    if total_reverse != global_reverse_count:
        raise ValueError(
            f'CodeGenModule self-check: module reverse P/Invoke total {total_reverse} '
            f'!= global count {global_reverse_count}'
        )

    return {
        'modules': module_count,
        'adjustor_thunks': total_adjustors,
        'reverse_pinvoke_records': total_reverse,
        'rgctx_ranges': total_ranges,
        'rgctx_definitions': total_rgctxs,
    }


def _self_check_stock_output(path: Path, code_reg_va: int, metadata_reg_va: int, expected_images: int, expected_types: int, expected_type_defs: int) -> dict:
    out = _selfcheck_elf(path)
    code_modules_count = out.u64(code_reg_va + 120)
    code_modules = out.u64(code_reg_va + 128)
    types_count = out.u64(metadata_reg_va + 48)
    field_offsets_count = out.u64(metadata_reg_va + 80)
    type_sizes_count = out.u64(metadata_reg_va + 96)
    type_sizes_ptr = out.u64(metadata_reg_va + 104)
    if code_modules_count != expected_images:
        raise ValueError(f'stock self-check: codeGenModulesCount={code_modules_count}, expected {expected_images}')
    if types_count != expected_types:
        raise ValueError(f'stock self-check: typesCount={types_count}, expected {expected_types}')
    if field_offsets_count != expected_type_defs or type_sizes_count != expected_type_defs:
        raise ValueError('stock self-check: type definition counts do not match metadata')
    if not _is_file_backed(out, code_modules, max(8, expected_images * 8)):
        raise ValueError('stock self-check: codeGenModules array is not file-backed')
    if not _is_file_backed(out, type_sizes_ptr, max(8, expected_type_defs * 8)):
        raise ValueError('stock self-check: search typeDefinitionsSizes array is not file-backed')
    # Version 31 PlusSearch intentionally lands 16 bytes into CodeRegistration,
    # then AutoPlusInit subtracts 16 when this slot looks pointer-like.
    version31_marker = out.u64(code_reg_va + 32)
    if version31_marker <= 0x50000:
        raise ValueError('stock self-check: v31 CodeRegistration marker is too small for AutoPlusInit')
    return {
        'codegen_modules_count': code_modules_count,
        'types_count': types_count,
        'type_definitions_count': field_offsets_count,
        'version31_marker': f'0x{version31_marker:X}',
    }

def build_stock_compatible_lib(elf: ELF64, md: ProtectedMetadata, output_path: Path, keep_method_rgctx: bool = False) -> dict:
    layout = _read_protected_runtime_layout(elf, md)
    buf = bytearray(elf.data)

    original_generic_method_table_count = layout['metadata']['generic_method_table_count']
    original_generic_method_pointers_count = layout['code']['generic_method_pointers_count']

    # IMPORTANT: never truncate generic method mappings.  Dump.cs, script.json
    # and method RVAs must remain complete.  Struct memory is handled separately
    # by filtering only method-level RGCTX ranges in normalized CodeGenModules.
    # Build the full runtime Il2CppType closure before stock registration is
    # emitted. Original indexes stay stable; missing recursive helper types are
    # appended, which makes stock Il2CppDumper's typeDic complete.
    stock_type_ptrs, type_graph_diag = _collect_runtime_type_closure(
        elf, layout['metadata']
    )

    app = _LoadAppender(elf, buf)

    generic_class_diag = _normalize_generic_classes(buf, elf, stock_type_ptrs)
    array_diag = _normalize_array_types(buf, elf, stock_type_ptrs, app)
    changed_types = _normalize_type_pointer_list(buf, elf, stock_type_ptrs)

    stock_types_va = app.add(
        b''.join(struct.pack('<Q', p) for p in stock_type_ptrs), 8
    )
    layout['metadata']['types'] = stock_types_va
    layout['metadata']['types_count'] = len(stock_type_ptrs)

    method_specs_blob = _normalize_method_specs(
        elf, layout['metadata']['method_specs'], layout['metadata']['method_specs_count']
    )
    method_specs_va = app.add(method_specs_blob, 8)

    generic_table_blob = _normalize_generic_method_table(
        elf,
        layout['metadata']['generic_method_table'],
        layout['metadata']['generic_method_table_count'],
    )
    generic_table_va = app.add(generic_table_blob, 8)

    modules_array_va, module_vas, module_diag, mscorlib_index, mscorlib_template = _build_stock_modules(
        elf, md, layout, app, struct_rgctx_guard=not keep_method_rgctx
    )

    fast = _install_fast_stock_search(
        buf, elf, app, layout, module_vas,
        mscorlib_index, mscorlib_template,
        generic_table_va, method_specs_va,
    )
    code_reg_va = fast['code_reg_va']
    metadata_reg_va = fast['metadata_reg_va']
    search_type_sizes_va = fast['type_sizes_va']

    output_path.write_bytes(buf)
    check_elf = ELF64(output_path)
    self_check = _self_check_stock_output(
        check_elf, code_reg_va, metadata_reg_va,
        layout['code']['codegen_modules_count'],
        layout['metadata']['types_count'],
        layout['metadata']['field_offsets_count'],
    )
    fast_check = _self_check_fast_search(
        check_elf, fast,
        layout['code']['codegen_modules_count'],
        layout['metadata']['field_offsets_count'],
    )
    exact_plussearch = _self_check_stock_plussearch_exact(
        check_elf,
        code_reg_va,
        metadata_reg_va,
        layout['code']['codegen_modules_count'],
        layout['metadata']['field_offsets_count'],
    )
    array_check = _self_check_array_types(check_elf, metadata_reg_va)
    full_generic_check = _self_check_full_generic_mapping(
        check_elf,
        code_reg_va,
        metadata_reg_va,
        original_generic_method_pointers_count,
        original_generic_method_table_count,
    )
    module_self_check = _self_check_codegen_modules(check_elf, code_reg_va)

    return {
        'stock_code_registration_va': f'0x{code_reg_va:X}',
        'stock_metadata_registration_va': f'0x{metadata_reg_va:X}',
        'normalized_type_count': changed_types,
        'stock_types_array_va': f'0x{stock_types_va:X}',
        'type_graph': type_graph_diag,
        'generic_class_normalization': generic_class_diag,
        'array_normalization': array_diag,
        'array_self_check': array_check,
        'normalized_method_specs_va': f'0x{method_specs_va:X}',
        'normalized_generic_method_table_va': f'0x{generic_table_va:X}',
        'full_generic_mapping': full_generic_check,
        'codegen_module_self_check': module_self_check,
        'method_rgctx_guard_enabled': not keep_method_rgctx,
        'stock_search_type_definition_sizes_va': f'0x{search_type_sizes_va:X}',
        'normalized_codegen_modules_va': [f'0x{x:X}' if x else None for x in module_vas[:8]],
        'normalized_codegen_modules_count': len(module_vas),
        'codegen_diagnostics': module_diag,
        'extended_pt_load_index': app.index,
        'fast_search': fast_check,
        'stock_plussearch_exact': exact_plussearch,
        'self_check': self_check,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description='One-shot heuristic preprocessor that produces stock-Il2CppDumper-compatible metadata + ELF (AArch64 ELF64).'
    )
    parser.add_argument('lib', type=Path, nargs='?', default=None,
                        help='Optional libunity.so, directory, APK/ZIP/XAPK. Omit for auto-search.')
    parser.add_argument('-o', '--out', type=Path, default=None,
                        help='Output directory. Default: ./fordumper')
    parser.add_argument('--metadata-va', type=parse_auto_int, default=None,
                        help='Emergency override for protected metadata base VA.')
    parser.add_argument('--code-reg-va', type=parse_auto_int, default=None,
                        help='Emergency override for CodeRegistration VA.')
    parser.add_argument('--quiet', action='store_true', help='Suppress normal progress output')
    parser.add_argument('--metadata-reg-va', type=parse_auto_int, default=None,
                        help='Emergency override for MetadataRegistration VA.')
    parser.add_argument('--legacy-fixed-layout', action='store_true',
                        help='Debug only: use the old fixed protected-header field positions.')
    parser.add_argument('--keep-method-rgctx', action='store_true',
                        help='Expose method-level RGCTX ranges to stock StructGenerator. Usually causes huge il2cpp.h / OOM on this build. Generic mappings are full either way.')
    parser.add_argument('--string-literal-offsets-field', type=parse_int, default=0x160)
    parser.add_argument('--string-literal-data-field', type=parse_int, default=0x138)
    parser.add_argument('--string-literal-count-field', type=parse_int, default=0x0FC)
    parser.add_argument('--string-literal-offsets-count-field', type=parse_int, default=0x044)
    args = parser.parse_args()
    if args.quiet:
        import builtins
        builtins.print = lambda *a, **k: None

    lib_path = resolve_input_path(args.lib)
    out_path = args.out.expanduser().resolve() if args.out else (Path.cwd() / 'fordumper').resolve()
    print(f'[auto] libunity.so: {lib_path}')
    print(f'[auto] output: {out_path}')

    elf = ELF64(lib_path)

    metadata_va = args.metadata_va
    if metadata_va is None:
        metadata_va = discover_metadata_base(elf)
        print(f'[heuristic] metadata base: 0x{metadata_va:X}')

    layout = None
    if not args.legacy_fixed_layout:
        layout = discover_protected_layout(elf, metadata_va)
        print('[heuristic] protected header layout recovered semantically')

    code_reg_va = args.code_reg_va or 0
    metadata_reg_va = args.metadata_reg_va or 0

    metadata = ProtectedMetadata(
        elf,
        metadata_va,
        code_reg_va,
        metadata_reg_va,
        args.string_literal_offsets_field,
        args.string_literal_data_field,
        args.string_literal_count_field,
        args.string_literal_offsets_count_field,
        layout=layout,
    )
    metadata.load_all()

    if not metadata.code_reg:
        metadata.code_reg = discover_code_registration(elf, metadata)
        if metadata.code_reg:
            print(f'[heuristic] CodeRegistration: 0x{metadata.code_reg:X}')
            metadata.modules_by_name.clear()
            metadata._load_codegen_modules()
        else:
            print('[heuristic] warning: CodeRegistration was not recovered; method RVAs may be unavailable')

    if not metadata.metadata_reg:
        metadata.metadata_reg = discover_metadata_registration(elf, metadata.code_reg, metadata)
        if metadata.metadata_reg:
            print(f'[heuristic] MetadataRegistration: 0x{metadata.metadata_reg:X}')
        else:
            print('[heuristic] warning: MetadataRegistration was not recovered; field offsets may be unavailable')

    interface_refine = refine_interface_type_table(elf, metadata)
    if interface_refine.get('interface_count', 0):
        old_if = interface_refine.get('old_offset', interface_refine.get('offset', 0))
        new_if = interface_refine.get('offset', 0)
        old_diag = interface_refine.get('old_diagnostics') or {}
        if interface_refine.get('changed'):
            print(
                f"[heuristic] interfaces corrected: "
                f"0x{old_if:X} -> 0x{new_if:X}; "
                f"old MVAR={old_diag.get('type_context_mvar', 0)}, "
                f"old bad-kind={old_diag.get('bad_root_kind', 0)}"
            )
        else:
            print(
                f"[heuristic] interfaces verified: 0x{new_if:X} "
                f"(score {interface_refine.get('score', 0):.3f})"
            )

    constraint_refine = refine_generic_constraint_table(elf, metadata)
    if constraint_refine.get('constraint_count', 0):
        old_off = constraint_refine.get('old_offset', constraint_refine.get('offset', 0))
        new_off = constraint_refine.get('offset', 0)
        if constraint_refine.get('changed'):
            old_diag = constraint_refine.get('old_diagnostics') or {}
            print(
                f"[heuristic] generic constraints corrected: "
                f"0x{old_off:X} -> 0x{new_off:X}; "
                f"rejected type-context MVARs={old_diag.get('type_context_mvar', 0)}"
            )
        else:
            print(
                f"[heuristic] generic constraints verified: 0x{new_off:X} "
                f"(score {constraint_refine.get('score', 0):.3f})"
            )

    #dummy_preflight = preflight_dummy_typedef_contexts(elf, metadata)
    #print(
    #    "[heuristic] DummyDll type-context preflight: OK "
     #   f"(fields={dummy_preflight['checked']['fields']}, "
    #    f"interfaces={dummy_preflight['checked']['interfaces']}, "
    #    f"type-constraints={dummy_preflight['checked']['type_generic_constraints']})"
    #)
    iid = interface_refine.get('diagnostics') or {}
    print(
        "[metadata] interfaces: "
        f"{interface_refine.get('interface_count', 0)} refs, "
        f"CLASS={iid.get('class_count', 0)}, "
        f"GENERICINST={iid.get('genericinst_count', 0)}, "
        f"MVAR-context={iid.get('type_context_mvar', 0)}"
    )

    rebuilt, rebuild_manifest = rebuild_global_metadata_v31(metadata)
    out_path.mkdir(parents=True, exist_ok=True)
    metadata_path = out_path / 'global-metadata.dat'
    metadata_path.write_bytes(rebuilt)

    stock_lib_path = out_path / 'libunity.so'
    if stock_lib_path.resolve() == lib_path.resolve():
        raise ValueError('Refusing to overwrite the input libunity.so; choose a separate output directory')
    stock_manifest = build_stock_compatible_lib(
        elf, metadata, stock_lib_path, keep_method_rgctx=args.keep_method_rgctx
    )
    print(f'[ok] wrote {stock_lib_path}')
    print(f"[stock] CodeRegistration: {stock_manifest['stock_code_registration_va']}")
    print(f"[stock] MetadataRegistration: {stock_manifest['stock_metadata_registration_va']}")
    fullg = stock_manifest.get('full_generic_mapping', {})
    print(
        "[stock] FULL dump preserved: "
        f"{fullg.get('generic_method_table_count', 0)} generic method table entries + "
        f"{fullg.get('generic_method_pointers_count', 0)} generic method pointers"
    )
    if constraint_refine.get('constraint_count', 0):
        cd = constraint_refine.get('diagnostics') or {}
        print(
            "[metadata] generic constraints: "
            f"{constraint_refine.get('constraint_count')} refs, "
            f"type-context MVAR={cd.get('type_context_mvar', 0)}, "
            f"owner mismatches={cd.get('generic_owner_mismatch', 0)}"
        )

    ng = rebuild_manifest.get('nested_graph', {})
    if ng:
        print(
            "[metadata] nested graph: "
            f"{ng.get('canonical_refs', 0)} declaringType links; "
            f"cross-image={ng.get('cross_image_links', 0)}; "
            f"old-candidate wrong-parent={ng.get('wrong_parent_refs_in_old_candidate', 0)}"
        )

    cg = stock_manifest.get('codegen_diagnostics', {})
    if stock_manifest.get('method_rgctx_guard_enabled') and cg:
        print(
            "[stock] struct RGCTX guard: "
            f"kept {cg.get('non_method_rgctx_ranges_kept', 0)} non-method ranges; "
            f"withheld {cg.get('method_rgctx_ranges_hidden', 0)} method ranges "
            f"({cg.get('method_rgctx_items_hidden', 0)} raw RGCTX items). "
            "Generic methods/pointers are NOT removed."
        )

    tg = stock_manifest.get('type_graph', {})
    if tg:
        print(
            f"[stock] type graph: {tg.get('original_types_count')} original + "
            f"{tg.get('extra_types_count')} recursive = {tg.get('final_types_count')}"
        )
        bad = tg.get('bad_runtime_refs') or []
        if bad:
            print(f"[stock] type graph warnings: {len(bad)}")
    arr = stock_manifest.get('array_normalization', {})
    arrchk = stock_manifest.get('array_self_check', {})
    if arr:
        print(
            f"[stock] ARRAY descriptors: {arr.get('unique_descriptors')} normalized, "
            f"{arrchk.get('array_type_count', 0)} verified"
        )
    fast = stock_manifest.get('fast_search', {})
    if fast:
        print(
            f"[stock] fast PlusSearch: RX {fast.get('exec_anchor_va')} "
            f"-> DATA {fast.get('data_segment_va')} "
            f"(mscorlib index {fast.get('mscorlib_last_index')})"
        )
    exact = stock_manifest.get('stock_plussearch_exact', {})
    if exact:
        print(
            f"[stock] exact SectionHelper check: code {exact.get('plus_candidate')} "
            f"-> metadata {exact.get('metadata_registration')} "
            f"(v31 marker {exact.get('v31_marker')})"
        )

    # Keep the output directory clean and stock-Dumper-oriented: only the
    # normalized ELF and rebuilt metadata are part of the public output.
    for stale_name in ('protected-layout.json', 'libunity.stock.so'):
        stale = out_path / stale_name
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    print(f'[ok] wrote {metadata_path}')
    print('[ready] Use ordinary Il2CppDumper with libunity.so + global-metadata.dat')


if __name__ == '__main__':
    main()
