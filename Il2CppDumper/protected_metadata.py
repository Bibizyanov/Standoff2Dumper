#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import sys
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from autoprofile import Tbl, build_profile



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


def _sample_indices(count: int, limit: int = 32) -> list[int]:
    if count <= 0:
        return []
    if count <= limit:
        return list(range(count))
    head = list(range(min(8, count)))
    tail = [count - 1 - i for i in range(min(4, count))]
    middle = [int(i * (count - 1) / (limit - 1)) for i in range(limit)]
    return sorted(set(head + tail + middle))



def _is_file_backed(elf: ELF64, va: int, size: int = 1) -> bool:
    try:
        elf.va_to_off(va, size)
        return True
    except Exception:
        return False



# ---------------------------------------------------------------------------
# Protected metadata reader driven by the automatically recovered profile
# ---------------------------------------------------------------------------

@dataclass
class TypeDef:
    index: int
    name_index: int
    namespace_index: int
    type_index: int
    declaring_type_index: int
    parent_index: int
    generic_container_index: int
    flags: int
    bitfield: int
    token: int
    field_start: int
    field_count: int
    method_start: int
    method_count: int
    event_start: int
    event_count: int
    property_start: int
    property_count: int
    nested_types_start: int
    nested_type_count: int
    interfaces_start: int
    interfaces_count: int
    vtable_start: int
    vtable_count: int
    interface_offsets_start: int
    interface_offsets_count: int
    name: str = ""
    namespace: str = ""


@dataclass
class MethodDef:
    index: int
    name_index: int
    declaring_type: int
    return_type: int
    aux: int
    parameter_start: int
    parameter_count: int
    generic_container_index: int
    token: int
    flags: int
    iflags: int
    slot: int
    name: str = ""


@dataclass
class FieldDef:
    index: int
    name_index: int
    type_index: int
    token: int
    name: str = ""


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
    owner_index: int
    type_argc: int
    is_method: int
    generic_parameter_start: int


@dataclass
class GenericParameter:
    index: int
    owner_container_index: int
    name_index: int
    constraints_start: int
    constraints_count: int
    num: int
    flags: int
    name: str = ""


@dataclass
class ImageDef:
    index: int
    name_index: int
    assembly_index: int
    type_start: int
    type_count: int
    exported_type_start: int
    exported_type_count: int
    entry_point_index: int
    token: int
    custom_attribute_start: int
    custom_attribute_count: int
    name: str = ""


TYPEDEF_FIELDS = {
    'name_index': 'name', 'namespace_index': 'namespace', 'type_index': 'byval_type',
    'declaring_type_index': 'declaring_type', 'parent_index': 'parent',
    'generic_container_index': 'generic_container', 'flags': 'flags', 'bitfield': 'bitfield',
    'token': 'token',
    'field_start': 'fields_start', 'field_count': 'fields_count',
    'method_start': 'methods_start', 'method_count': 'methods_count',
    'event_start': 'events_start', 'event_count': 'events_count',
    'property_start': 'properties_start', 'property_count': 'properties_count',
    'nested_types_start': 'nested_types_start', 'nested_type_count': 'nested_types_count',
    'interfaces_start': 'interfaces_start', 'interfaces_count': 'interfaces_count',
    'vtable_start': 'vtable_methods_start', 'vtable_count': 'vtable_methods_count',
    'interface_offsets_start': 'interface_offsets_start', 'interface_offsets_count': 'interface_offsets_count',
}
METHOD_FIELDS = {
    'name_index': 'name', 'declaring_type': 'declaring_type', 'return_type': 'return_type',
    'aux': 'return_parameter_token', 'parameter_start': 'parameter_start',
    'parameter_count': 'parameter_count', 'generic_container_index': 'generic_container',
    'token': 'token', 'flags': 'flags', 'iflags': 'iflags', 'slot': 'slot',
}
FIELD_FIELDS = {'name_index': 'name', 'type_index': 'type', 'token': 'token'}
GC_FIELDS = {'owner_index': 'owner_index', 'type_argc': 'type_argc', 'is_method': 'is_method',
             'generic_parameter_start': 'generic_parameter_start'}
GP_FIELDS = {'owner_container_index': 'owner_index', 'name_index': 'name',
             'constraints_start': 'constraints_start', 'constraints_count': 'constraints_count',
             'num': 'num', 'flags': 'flags'}
IMAGE_FIELDS = {
    'name_index': 'name', 'assembly_index': 'assembly_index', 'type_start': 'type_start',
    'type_count': 'type_count', 'exported_type_start': 'exported_type_start',
    'exported_type_count': 'exported_type_count', 'entry_point_index': 'entry_point_index',
    'token': 'token', 'custom_attribute_start': 'custom_attribute_start',
    'custom_attribute_count': 'custom_attribute_count',
}


class ProtectedMetadata:
    def __init__(self, elf: ELF64, profile: dict):
        self.elf = elf
        self.profile = profile
        self.base = profile['metadata_va']
        self.records = profile['records']
        self.blobs = profile['blobs']
        heap = self.blobs['string']
        self.string_off = heap['offset']
        size = heap['size'] or len(profile['solver'].heap_bytes)
        self.heap = profile['solver'].heap_bytes[:size] if heap['size'] else profile['solver'].heap_bytes
        self.type_defs: list[TypeDef] = []
        self.images: list[ImageDef] = []
        self.generic_containers: list[GenericContainer] = []
        self.generic_params: list[GenericParameter] = []
        self.type_index_to_typedef: dict[int, TypeDef] = {}

    # -- primitives -------------------------------------------------------
    def str(self, index: int) -> str:
        if index < 0 or index >= len(self.heap):
            return ""
        end = self.heap.find(b'\0', index)
        return self.heap[index:end if end >= 0 else len(self.heap)].decode('utf-8', errors='replace')

    def count(self, name: str) -> int:
        rec = self.records.get(name)
        return rec['count'] if rec else 0

    def columns(self, name: str, mapping: dict) -> dict[str, list[int]]:
        rec = self.records.get(name)
        if not rec or not rec['count']:
            return {k: [] for k in mapping}
        raw = self.elf.read(self.base + rec['offset'], rec['stride'] * rec['count'])
        t = Tbl(raw, rec['stride'])
        out = {}
        for attr, field in mapping.items():
            off, w = rec['fields'][field]
            out[attr] = t.s(off, w).tolist()
        return out

    def rows(self, cls, name: str, mapping: dict, with_names: bool = False) -> list:
        cols = self.columns(name, mapping)
        n = self.count(name)
        keys = list(mapping)
        out = []
        for i in range(n):
            kw = {k: cols[k][i] for k in keys}
            obj = cls(index=i, **kw)
            if with_names:
                obj.name = self.str(kw['name_index'])
            out.append(obj)
        return out

    def values(self, name: str) -> list[int]:
        rec = self.records.get(name)
        if not rec or not rec['count']:
            return []
        raw = self.elf.read(self.base + rec['offset'], rec['stride'] * rec['count'])
        t = Tbl(raw, rec['stride'])
        return t.s(*rec['fields']['value']).tolist()

    def blob(self, name: str) -> bytes:
        b = self.blobs.get(name)
        if not b or not b['size']:
            return b''
        return self.elf.read(self.base + b['offset'], b['size'])

    # -- loading ----------------------------------------------------------
    def load_all(self) -> None:
        self.generic_containers = self.rows(GenericContainer, 'generic_containers', GC_FIELDS)
        self.generic_params = self.rows(GenericParameter, 'generic_parameters', GP_FIELDS, True)
        self.type_defs = self.rows(TypeDef, 'type_definitions', TYPEDEF_FIELDS, False)
        for td in self.type_defs:
            td.name = self.str(td.name_index)
            td.namespace = self.str(td.namespace_index)
        self.type_index_to_typedef = {t.type_index: t for t in self.type_defs if t.type_index >= 0}
        self.images = self.rows(ImageDef, 'images', IMAGE_FIELDS, True)
        self.methods = self.rows(MethodDef, 'methods', METHOD_FIELDS, True)
        self.fields = self.rows(FieldDef, 'fields', FIELD_FIELDS, True)
        self.params = self.rows(ParamDef, 'parameters', FIELD_FIELDS, True)
        self.properties = []
        cols = self.columns('properties', {'name_index': 'name', 'getter_index': 'get', 'setter_index': 'set',
                                           'attrs': 'attrs', 'token': 'token'})
        for i in range(self.count('properties')):
            self.properties.append({k: cols[k][i] for k in cols} | {'index': i})
        self.events = []
        cols = self.columns('events', {'name_index': 'name', 'type_index': 'type', 'add_method_index': 'add',
                                       'remove_method_index': 'remove', 'raise_method_index': 'raise',
                                       'token': 'token'})
        for i in range(self.count('events')):
            self.events.append({k: cols[k][i] for k in cols} | {'index': i})
        self.nested_values = self.values('nested_types')
        self.interface_values = self.values('interfaces')
        self.vtable_values = [v & 0xFFFFFFFF for v in self.values('vtable_methods')]
        self.constraint_values = self.values('generic_constraints')
        cols = self.columns('interface_offsets', {'type': 'type', 'offset': 'offset'})
        self.interface_offset_pairs = list(zip(cols['type'], cols['offset']))
        self._validate()

    def _validate(self) -> None:
        checks = (
            ('fields', 'field_start', 'field_count'), ('methods', 'method_start', 'method_count'),
            ('events', 'event_start', 'event_count'), ('properties', 'property_start', 'property_count'),
            ('interfaces', 'interfaces_start', 'interfaces_count'),
            ('vtable_methods', 'vtable_start', 'vtable_count'),
            ('interface_offsets', 'interface_offsets_start', 'interface_offsets_count'),
        )
        for table, start, count in checks:
            upper = self.count(table)
            for td in self.type_defs:
                c = getattr(td, count)
                s = getattr(td, start)
                if c and (s < 0 or s + c > upper):
                    raise ValueError(f'TypeDefinition[{td.index}] {table} range {s}+{c} exceeds {upper}')
        for m in self.methods:
            if m.parameter_count and (m.parameter_start < 0 or m.parameter_start + m.parameter_count > len(self.params)):
                raise ValueError(f'MethodDefinition[{m.index}] parameter range invalid')
        if len(self.images) != len(set(img.name for img in self.images)):
            raise ValueError('Duplicate image names: image table layout is wrong')

    def read_string_literals(self) -> list[bytes]:
        rec = self.records['string_literal_offsets']
        n = rec['count']
        offsets = struct.unpack_from(f'<{n}I', self.elf.read(self.base + rec['offset'], n * 4))
        data = self.blob('string_literal_data')
        if offsets[0] != 0 or any(offsets[i + 1] < offsets[i] for i in range(n - 1)) or offsets[-1] > len(data):
            raise ValueError('String literal offset table is inconsistent')
        return [data[offsets[i]:offsets[i + 1]] for i in range(n - 1)]

    def attribute_tables(self) -> tuple[bytes, bytes]:
        rec = self.records.get('attribute_data_ranges')
        if not rec:
            return b'', b''
        cols = self.columns('attribute_data_ranges', {'token': 'token', 'start': 'start'})
        out = bytearray()
        for tok, start in zip(cols['token'], cols['start']):
            out += struct.pack('<II', tok & 0xFFFFFFFF, start & 0xFFFFFFFF)
        return bytes(out), self.blob('attribute_data')

    def default_tables(self) -> tuple[bytes, bytes, bytes]:
        fblob = bytearray()
        cols = self.columns('field_default_values', {'o': 'field_index', 't': 'type', 'd': 'data'})
        for o, t, d in zip(cols['o'], cols['t'], cols['d']):
            fblob += struct.pack('<iii', o, t, d)
        pblob = bytearray()
        cols = self.columns('parameter_default_values', {'o': 'parameter_index', 't': 'type', 'd': 'data'})
        for o, t, d in zip(cols['o'], cols['t'], cols['d']):
            pblob += struct.pack('<iii', o, t, d)
        return bytes(fblob), bytes(pblob), self.blob('field_and_parameter_default_value_data')

    def field_ref_table(self) -> bytes:
        cols = self.columns('field_refs', {'t': 'type', 'f': 'field'})
        return b''.join(struct.pack('<ii', t, f) for t, f in zip(cols['t'], cols['f']))


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

    fields = md.fields
    methods = md.methods
    params = md.params
    properties = md.properties
    events = md.events

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

    for prop in properties:
        replacement_name = prop.get('_replacement_name')
        if replacement_name is not None:
            prop['name_index'] = add_string(replacement_name)

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

    nested_values = list(md.nested_values[:nested_count])
    interface_values = list(md.interface_values[:interface_count])
    vtable_values = list(md.vtable_values[:vtable_count])
    interface_offset_pairs = list(md.interface_offset_pairs[:interface_offset_count])
    constraint_count = 0
    for gp in md.generic_params:
        constraint_count = max(constraint_count, gp.constraints_start + gp.constraints_count)
    constraint_values = list(md.constraint_values[:constraint_count])

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
            img.assembly_index,
            img.type_start,
            img.type_count & 0xFFFFFFFF,
            img.exported_type_start,
            img.exported_type_count & 0xFFFFFFFF,
            img.entry_point_index,
            img.token & 0xFFFFFFFF,
            img.custom_attribute_start,
            img.custom_attribute_count & 0xFFFFFFFF,
        )

        assembly_blob += struct.pack(
            "<iIii"
            "IIIIiI"
            "iiii"
            "8s",
            img.index,                     # imageIndex (one assembly record per image)
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

    attribute_range_blob, attribute_data_blob = md.attribute_tables()
    attribute_range_count = len(attribute_range_blob) // 8
    if attribute_range_count:
        last_start = struct.unpack_from('<I', attribute_range_blob, (attribute_range_count - 1) * 8 + 4)[0]
        if last_start > len(attribute_data_blob):
            raise ValueError('Last attribute start exceeds attribute blob size')
    # Stock Il2CppDumper reads attributeDataRanges[i + 1] for the end of each payload.
    attribute_range_blob += struct.pack('<II', 0, len(attribute_data_blob))

    field_default_blob, param_default_blob, default_value_data_blob = md.default_tables()
    field_default_count = len(field_default_blob) // 12
    param_default_count = len(param_default_blob) // 12
    field_ref_blob = md.field_ref_table()

    sections: dict[str, bytes] = {
        "stringLiteral": bytes(string_literal_blob),
        "stringLiteralData": bytes(string_literal_data_blob),
        "string": bytes(string_heap),
        "events": bytes(event_blob),
        "properties": bytes(property_blob),
        "methods": bytes(method_blob),
        "parameterDefaultValues": bytes(param_default_blob),
        "fieldDefaultValues": bytes(field_default_blob),
        "fieldAndParameterDefaultValueData": bytes(default_value_data_blob),
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
        "fieldRefs": bytes(field_ref_blob),
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
        "default_values": {
            "field_count": field_default_count,
            "field_table_size": len(field_default_blob),
            "parameter_count": param_default_count,
            "parameter_table_size": len(param_default_blob),
            "data_size": len(default_value_data_blob),
        },
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
            "Image customAttributeStart/customAttributeCount and exported-type ranges are restored from protected ImageDefinition records.",
            "Field and parameter default-value tables/data are restored from the protected metadata.",
            "FieldRef records are restored and reordered to stock {typeIndex, fieldIndex} layout.",
            "WinRT/exported-type sections remain empty when they are not required by this title.",
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


def _self_check_codegen_modules(path_or_elf, code_reg_va: int,
                                require_file_backed_method_arrays: bool = False) -> dict:
    out = _selfcheck_elf(path_or_elf)
    module_count = int(out.u64(code_reg_va + 120))
    modules_va = out.u64(code_reg_va + 128)
    invoker_count = int(out.u64(code_reg_va + 40))
    global_reverse_count = int(out.u64(code_reg_va + 0))
    global_reverse_ptr = out.u64(code_reg_va + 8)

    # The global reverse P/Invoke wrapper array is independent of the
    # optional per-CodeGenModule reversePInvokeWrapperIndices array.
    # Google 2026 carries 1,622 global wrappers but does not expose module
    # tuples. Validate the actual global array instead of requiring the
    # module-local count sum to equal the global wrapper count.
    if global_reverse_count:
        if not global_reverse_ptr or not _is_load_mapped(out, global_reverse_ptr, global_reverse_count * 8):
            raise ValueError('CodeRegistration reverse P/Invoke wrapper array is not mapped')
        for i in range(global_reverse_count):
            ptr = _u64_from_load_image(out, global_reverse_ptr + i * 8)
            if ptr and not _is_exec_va(out, ptr):
                raise ValueError(
                    f'CodeRegistration reverse P/Invoke wrapper[{i}] '
                    f'has non-executable pointer 0x{ptr:X}'
                )

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
        if require_file_backed_method_arrays and method_count:
            method_array = out.u64(mod + 0x10)
            if not _is_file_backed(out, method_array, method_count * 8):
                raise ValueError(
                    f'CodeGenModule self-check: module[{i}] method pointer array '
                    'is not fully file-backed'
                )
            for j in range(method_count):
                fn = out.u64(method_array + j * 8)
                if fn and not _is_exec_va(out, fn):
                    raise ValueError(
                        f'CodeGenModule self-check: module[{i}] method pointer '
                        f'[{j}] is not executable (0x{fn:X})'
                    )
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
    # Module-local entries may be absent even when the global wrapper table
    # is populated. They describe different mappings; their counts need not
    # match. Each present module entry is already validated above.

    return {
        'modules': module_count,
        'adjustor_thunks': total_adjustors,
        'reverse_pinvoke_records': total_reverse,
        'global_reverse_pinvoke_wrappers': global_reverse_count,
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



# ---------------------------------------------------------------------------
# Stock-compatible libunity.so, driven by the recovered runtime profile
# ---------------------------------------------------------------------------

IL2CPP_TYPE_PTR, IL2CPP_TYPE_BYREF = 0x0F, 0x10
IL2CPP_TYPE_ARRAY, IL2CPP_TYPE_GENERICINST, IL2CPP_TYPE_SZARRAY = 0x14, 0x15, 0x1D


def _runtime_layout(elf: ELF64, profile: dict) -> dict:
    rt = profile['runtime']
    cr = profile['code_registration_va']
    mr = profile['metadata_registration_va']

    def ptr(base, slot):
        return _u64_from_load_image(elf, base + slot) if slot is not None else 0

    def cnt(base, slot):
        return elf.u32(base + slot) if slot is not None else 0

    meta = {}
    for key, (p, c) in rt['metadata_registration'].items():
        meta[key] = ptr(mr, p)
        meta[key + '_count'] = cnt(mr, c)
    code = {}
    for key in ('reverse_pinvoke', 'generic_method_pointers', 'generic_adjustor_thunks', 'invoker_pointers',
                'unresolved_virtual', 'unresolved_instance', 'unresolved_static', 'interop', 'codegen_modules'):
        p, c = rt['code_registration'].get(key, (None, None))
        code[key] = ptr(cr, p)
        code[key + '_count'] = cnt(cr, c)
    if meta['field_offsets_count'] != profile['counts']['type_definitions']:
        raise ValueError('fieldOffsetsCount does not match TypeDefinition count')
    if code['codegen_modules_count'] != profile['records']['images']['count']:
        raise ValueError('codeGenModulesCount does not match ImageDefinition count')
    return {'metadata': meta, 'code': code}


class _TypeCodec:
    def __init__(self, elf: ELF64, profile: dict):
        spec = profile['il2cpp_type']
        self.elf = elf
        self.desc_off = spec['descriptor_offset']
        self.data_off = spec['data_offset']
        self.bits = spec['bits']

    def field(self, desc: int, name: str) -> int:
        pos, width = self.bits[name]
        return (desc >> pos) & ((1 << width) - 1)

    def read(self, ptr: int) -> tuple[int, int, int]:
        desc = self.elf.u32(ptr + self.desc_off)
        data = _u64_from_load_image(self.elf, ptr + self.data_off)
        return desc, self.field(desc, 'type'), data

    def stock_bits(self, desc: int) -> int:
        f = self.field
        return (f(desc, 'attrs') | f(desc, 'type') << 16 | f(desc, 'num_mods') << 24 |
                f(desc, 'byref') << 29 | f(desc, 'pinned') << 30 | f(desc, 'valuetype') << 31)


def _collect_types(elf: ELF64, codec: _TypeCodec, layout: dict, rt: dict) -> list[int]:
    meta = layout['metadata']
    types = [_u64_from_load_image(elf, meta['types'] + i * 8) for i in range(meta['types_count'])]
    known = set(types)
    extra = []
    gi, gc = rt['generic_inst'], rt['generic_class']
    work = list(types)
    while work:
        ptr = work.pop()
        if not ptr:
            continue
        _, kind, data = codec.read(ptr)
        refs = []
        if kind in (IL2CPP_TYPE_PTR, IL2CPP_TYPE_BYREF, IL2CPP_TYPE_SZARRAY) and data:
            refs.append(data)
        elif kind == IL2CPP_TYPE_ARRAY and data:
            refs.append(_array_etype(elf, data, known)[0])
        elif kind == IL2CPP_TYPE_GENERICINST and data:
            refs.append(_u64_from_load_image(elf, data + gc['type']))
            inst = _u64_from_load_image(elf, data + gc['class_inst'])
            if inst:
                argc = _u64_from_load_image(elf, inst + gi['type_argc'])
                argv = _u64_from_load_image(elf, inst + gi['type_argv'])
                refs.extend(_u64_from_load_image(elf, argv + k * 8) for k in range(min(argc, 128)))
        for r in refs:
            if r and r not in known and _is_load_mapped(elf, r, 16):
                known.add(r)
                extra.append(r)
                work.append(r)
    return types + extra


def _array_etype(elf: ELF64, desc_va: int, known: set) -> tuple[int, int, int]:
    """Return (etype, rank, etype_offset) for a protected Il2CppArrayType."""
    etype = None
    rank = 0
    for off in range(0, 40, 8):
        if not _is_load_mapped(elf, desc_va + off, 8):
            break
        q = _u64_from_load_image(elf, desc_va + off)
        if (desc_va + off) in elf.relocated_u64 or q in known:
            if etype is None and q in known:
                etype = (q, off)
            continue
        for k in range(8):
            b = (q >> (8 * k)) & 0xFF
            if 1 <= b <= 32:
                rank = max(rank, b)
    if etype is None:
        raise ValueError(f'Il2CppArrayType 0x{desc_va:X} has no element type')
    return etype[0], rank, etype[1]


def _normalize_types(buf: bytearray, elf: ELF64, codec: _TypeCodec, type_ptrs: list[int], app) -> dict:
    known = set(type_ptrs)
    decoded = {}
    for ptr in known:
        if ptr:
            decoded[ptr] = codec.read(ptr)
    arrays = {}
    for ptr, (desc, kind, data) in decoded.items():
        if kind == IL2CPP_TYPE_ARRAY and data:
            new = arrays.get(data)
            if new is None:
                etype, rank, _ = _array_etype(elf, data, known)
                if not rank:
                    raise ValueError(f'Il2CppArrayType 0x{data:X} has no rank')
                new = app.add(struct.pack('<QBBB5xQQ', etype, rank, 0, 0, 0, 0), 8)
                arrays[data] = new
            data = new
        _patch_u64_va(buf, elf, ptr, data)
        _patch_u64_va(buf, elf, ptr + 8, codec.stock_bits(desc))
    return {'types': len(decoded), 'arrays': len(arrays)}


def _normalize_generic_objects(buf: bytearray, elf: ELF64, layout: dict, rt: dict) -> dict:
    meta = layout['metadata']
    gi, gc = rt['generic_inst'], rt['generic_class']
    insts = set()
    for i in range(meta['generic_insts_count']):
        inst = _u64_from_load_image(elf, meta['generic_insts'] + i * 8)
        argc = _u64_from_load_image(elf, inst + gi['type_argc'])
        argv = _u64_from_load_image(elf, inst + gi['type_argv'])
        if not 0 < argc <= 128 or not _is_load_mapped(elf, argv, argc * 8):
            raise ValueError(f'GenericInst[{i}] is malformed')
        insts.add((inst, argc, argv))
    for inst, argc, argv in insts:
        _patch_u64_va(buf, elf, inst, argc)
        _patch_u64_va(buf, elf, inst + 8, argv)
    classes = set()
    for i in range(meta['generic_classes_count']):
        cls = _u64_from_load_image(elf, meta['generic_classes'] + i * 8)
        classes.add((cls, _u64_from_load_image(elf, cls + gc['type']),
                     _u64_from_load_image(elf, cls + gc['class_inst'])))
    for cls, typ, inst in classes:
        _patch_u64_va(buf, elf, cls, typ)
        _patch_u64_va(buf, elf, cls + 8, inst)
        _patch_u64_va(buf, elf, cls + 16, 0)
        _patch_u64_va(buf, elf, cls + 24, 0)
    return {'generic_insts': len(insts), 'generic_classes': len(classes)}


def _int_table(elf: ELF64, ptr: int, count: int, stride: int, order: list[int]) -> bytes:
    raw = elf.read(ptr, count * stride)
    out = bytearray()
    for i in range(count):
        out += b''.join(raw[i * stride + o:i * stride + o + 4] for o in order)
    return bytes(out)


def _materialize_pointers(elf: ELF64, ptr: int, count: int, app, executable_only: bool = True) -> tuple[int, dict]:
    stats = {'slots': count, 'executable': 0, 'dropped': 0}
    out = bytearray(count * 8)
    for i in range(count):
        v = _u64_from_load_image(elf, ptr + i * 8) if ptr else 0
        if v and (not executable_only or _is_exec_va(elf, v)):
            struct.pack_into('<Q', out, i * 8, v)
            stats['executable'] += 1
        elif v:
            stats['dropped'] += 1
    return (app.add(out, 8) if count else 0), stats


def _build_stock_modules_auto(elf: ELF64, layout: dict, rt: dict, app, struct_rgctx_guard: bool) -> tuple:
    code = layout['code']
    m = rt['codegen_module']
    modules, diag = [], {'method_slots': 0, 'method_rgctx_ranges_hidden': 0,
                         'method_rgctx_items_hidden': 0, 'non_method_rgctx_ranges_kept': 0}
    mscorlib_index, mscorlib_template = -1, None

    def u32(base, off):
        return elf.u32(base + off)

    for i in range(code['codegen_modules_count']):
        mod = _u64_from_load_image(elf, code['codegen_modules'] + i * 8)
        name_ptr = _u64_from_load_image(elf, mod + m['name'])
        name = elf.cstr(name_ptr, 300)
        method_count = u32(mod, m['method_pointer_count'])
        method_ptrs, _ = _materialize_pointers(elf, _u64_from_load_image(elf, mod + m['method_pointers']), method_count, app)
        diag['method_slots'] += method_count
        inv = _u64_from_load_image(elf, mod + m['invoker_indices'])
        if method_count and inv and not _is_file_backed(elf, inv, method_count * 4):
            inv = app.add(bytes(method_count * 4), 8)

        thunk_count, thunks = 0, 0
        spec = m.get('adjustor_thunks')
        if spec:
            thunk_count = u32(mod, spec['count'])
            src = _u64_from_load_image(elf, mod + spec['pointer'])
            blob = bytearray()
            for k in range(thunk_count):
                tok = _u64_from_load_image(elf, src + k * 16 + spec['layout']['token']) & 0xFFFFFFFF
                fn = _u64_from_load_image(elf, src + k * 16 + spec['layout']['method'])
                blob += struct.pack('<IIQ', tok, 0, fn)
            thunks = app.add(blob, 8) if blob else 0

        rev_count, rev = 0, 0
        spec = m.get('reverse_pinvoke')
        if spec:
            rev_count = u32(mod, spec['count'])
            src = _u64_from_load_image(elf, mod + spec['pointer'])
            lay = spec['layout']
            blob = bytearray()
            for k in range(rev_count):
                va = src + k * 24
                blob += struct.pack('<IiQII', elf.u32(va + lay['token']), elf.i32(va + lay['index']),
                                    _u64_from_load_image(elf, va + lay['method']),
                                    elf.u32(va + lay['generic_method_index']), 0)
            rev = app.add(blob, 8) if blob else 0

        range_count, ranges = 0, 0
        spec = m.get('rgctx_ranges')
        if spec:
            n = u32(mod, spec['count'])
            src = _u64_from_load_image(elf, mod + spec['pointer'])
            lay = spec['layout']
            blob = b''.join(struct.pack('<Iii', elf.u32(src + k * 12 + lay['token']),
                                        elf.i32(src + k * 12 + lay['start']),
                                        elf.i32(src + k * 12 + lay['length'])) for k in range(n))
            if struct_rgctx_guard and blob:
                blob, g = _filter_method_rgctx_ranges_for_stock_struct(blob)
                diag['method_rgctx_ranges_hidden'] += g['method_ranges_hidden']
                diag['method_rgctx_items_hidden'] += g['method_rgctx_items_hidden']
                diag['non_method_rgctx_ranges_kept'] += g['non_method_ranges_kept']
            range_count = len(blob) // 12
            ranges = app.add(blob, 8) if blob else 0

        rgctx_count, rgctxs = 0, 0
        spec = m.get('rgctxs')
        if spec:
            rgctx_count = u32(mod, spec['count'])
            src = _u64_from_load_image(elf, mod + spec['pointer'])
            lay = spec['layout']
            if lay['type'] == 0 and (not rgctx_count or _is_file_backed(elf, src, rgctx_count * 16)):
                rgctxs = src
            elif rgctx_count:
                rgctxs = app.add(b''.join(struct.pack('<QQ', _u64_from_load_image(elf, src + k * 16 + lay['type']),
                                                      _u64_from_load_image(elf, src + k * 16 + lay['data']))
                                          for k in range(rgctx_count)), 8)

        stock = struct.pack('<QqQqQQqQqQqQQQQQQ', name_ptr, method_count, method_ptrs, thunk_count, thunks,
                            inv, rev_count, rev, range_count, ranges, rgctx_count, rgctxs, 0, 0, 0, 0, 0)
        modules.append(app.add(stock, 8))
        if name.lower() == 'mscorlib.dll':
            mscorlib_index, mscorlib_template = i, stock
    if mscorlib_template is None:
        raise ValueError('mscorlib.dll CodeGenModule missing')
    array = app.add(b''.join(struct.pack('<Q', p) for p in modules), 8)
    return array, modules, diag, mscorlib_index, mscorlib_template


def build_stock_compatible_lib(elf: ELF64, md: ProtectedMetadata, output_path: Path,
                               keep_method_rgctx: bool = False) -> dict:
    profile = md.profile
    rt = profile['runtime']
    layout = _runtime_layout(elf, profile)
    codec = _TypeCodec(elf, profile)
    buf = bytearray(elf.data)
    app = _LoadAppender(elf, buf)

    type_ptrs = _collect_types(elf, codec, layout, rt)
    original_types = layout['metadata']['types_count']
    generic_diag = _normalize_generic_objects(buf, elf, layout, rt)
    type_diag = _normalize_types(buf, elf, codec, type_ptrs, app)
    layout['metadata']['types'] = app.add(b''.join(struct.pack('<Q', p) for p in type_ptrs), 8)
    layout['metadata']['types_count'] = len(type_ptrs)

    spec = rt['method_spec']
    method_specs_va = app.add(_int_table(
        elf, layout['metadata']['method_specs'], layout['metadata']['method_specs_count'], 12,
        [spec['method_definition'], spec['class_inst'], spec['method_inst']]), 8)
    gmt = rt['generic_method_table']
    generic_table_va = app.add(_int_table(
        elf, layout['metadata']['generic_method_table'], layout['metadata']['generic_method_table_count'], 16,
        [gmt['generic_method_index'], gmt['method_index'], gmt['invoker_index'], gmt['adjustor_thunk_index']]), 8)

    code = layout['code']
    pointer_diag = {}
    for key in ('generic_method_pointers', 'invoker_pointers', 'reverse_pinvoke', 'unresolved_virtual'):
        if code.get(key) and code.get(key + '_count'):
            code[key], pointer_diag[key] = _materialize_pointers(elf, code[key], code[key + '_count'], app)

    modules_array_va, module_vas, module_diag, mscorlib_index, mscorlib_template = _build_stock_modules_auto(
        elf, layout, rt, app, struct_rgctx_guard=not keep_method_rgctx)
    if module_diag['method_slots'] != md.count('methods'):
        raise ValueError(f"CodeGenModule method slots {module_diag['method_slots']} != {md.count('methods')}")

    fast = _install_fast_stock_search(buf, elf, app, layout, module_vas, mscorlib_index, mscorlib_template,
                                      generic_table_va, method_specs_va)
    code_reg_va, metadata_reg_va = fast['code_reg_va'], fast['metadata_reg_va']
    output_path.write_bytes(buf)

    check_elf = ELF64(output_path)
    self_check = _self_check_stock_output(check_elf, code_reg_va, metadata_reg_va, code['codegen_modules_count'],
                                          layout['metadata']['types_count'], layout['metadata']['field_offsets_count'])
    fast_check = _self_check_fast_search(check_elf, fast, code['codegen_modules_count'],
                                         layout['metadata']['field_offsets_count'])
    exact = _self_check_stock_plussearch_exact(check_elf, code_reg_va, metadata_reg_va,
                                               code['codegen_modules_count'], layout['metadata']['field_offsets_count'])
    array_check = _self_check_array_types(check_elf, metadata_reg_va)
    full_generic = _self_check_full_generic_mapping(check_elf, code_reg_va, metadata_reg_va,
                                                    code['generic_method_pointers_count'],
                                                    layout['metadata']['generic_method_table_count'])
    module_check = _self_check_codegen_modules(check_elf, code_reg_va, require_file_backed_method_arrays=True)
    return {
        'stock_code_registration_va': f'0x{code_reg_va:X}',
        'stock_metadata_registration_va': f'0x{metadata_reg_va:X}',
        'type_graph': {'original_types_count': original_types, 'extra_types_count': len(type_ptrs) - original_types,
                       'final_types_count': len(type_ptrs)},
        'type_normalization': type_diag, 'generic_objects': generic_diag,
        'pointer_arrays': pointer_diag, 'codegen_diagnostics': module_diag,
        'method_rgctx_guard_enabled': not keep_method_rgctx,
        'array_self_check': array_check, 'full_generic_mapping': full_generic,
        'codegen_module_self_check': module_check, 'fast_search': fast_check,
        'stock_plussearch_exact': exact, 'self_check': self_check,
    }


def _profile_summary(profile: dict) -> dict:
    out = {k: v for k, v in profile.items() if k not in ('solver',)}
    return json.loads(json.dumps(out, default=lambda o: o if isinstance(o, (int, str)) else str(o)))


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Self-updating preprocessor: recovers every protected IL2CPP v31 layout from libunity.so '
                    'and emits stock-Il2CppDumper-compatible global-metadata.dat + libunity.so.')
    parser.add_argument('lib', type=Path, nargs='?', default=None,
                        help='libunity.so, directory, APK/ZIP/XAPK. Omit for auto-search.')
    parser.add_argument('-o', '--out', type=Path, default=None, help='Output directory. Default: ./fordumper')
    parser.add_argument('--quiet', action='store_true', help='Suppress normal progress output')
    parser.add_argument('--progress', action='store_true', help='Emit machine-readable progress on stderr')
    parser.add_argument('--keep-method-rgctx', action='store_true',
                        help='Expose method-level RGCTX ranges to stock StructGenerator (large il2cpp.h).')
    parser.add_argument('--profile-only', action='store_true', help='Recover and print the layout profile, then exit')
    args = parser.parse_args()
    if args.quiet:
        import builtins
        builtins.print = lambda *a, **k: None

    def progress(stage: str) -> None:
        if args.progress:
            sys.stderr.write(f'PROGRESS|{stage}\n')
            sys.stderr.flush()

    lib_path = resolve_input_path(args.lib)
    out_path = args.out.expanduser().resolve() if args.out else (Path.cwd() / 'fordumper').resolve()
    print(f'[auto] libunity.so: {lib_path}')
    progress('Reading ELF and relocations')
    elf = ELF64(lib_path)
    progress('Recovering protected layout')
    profile = build_profile(elf)
    summary = _profile_summary(profile)
    print(f"[auto] metadata 0x{profile['metadata_va']:X}, CodeRegistration 0x{profile['code_registration_va']:X}, "
          f"MetadataRegistration 0x{profile['metadata_registration_va']:X}")
    for name, rec in profile['records'].items():
        print(f"[auto] {name}: header+0x{rec['offset_field']:X} -> +0x{rec['offset']:X}, "
              f"{rec['count']} x {rec['stride']} {rec['fields'] if rec['fields'] else ''}")
    if args.profile_only:
        print(json.dumps(summary, indent=1))
        return

    out_path.mkdir(parents=True, exist_ok=True)
    progress('Parsing protected metadata')
    md = ProtectedMetadata(elf, profile)
    md.load_all()
    progress(f'Metadata loaded: {len(md.type_defs):,} classes')
    rebuilt, manifest = rebuild_global_metadata_v31(md)
    metadata_path = out_path / 'global-metadata.dat'
    metadata_path.write_bytes(rebuilt)

    stock_lib_path = out_path / 'libunity.so'
    if stock_lib_path.resolve() == lib_path.resolve():
        raise ValueError('Refusing to overwrite the input libunity.so; choose a separate output directory')
    progress('Normalizing runtime structures')
    stock = build_stock_compatible_lib(elf, md, stock_lib_path, keep_method_rgctx=args.keep_method_rgctx)
    (out_path / 'profile.json').write_text(json.dumps(summary, indent=1), encoding='utf-8')
    print(f"[stock] CodeRegistration: {stock['stock_code_registration_va']}")
    print(f"[stock] MetadataRegistration: {stock['stock_metadata_registration_va']}")
    print(f"[stock] types: {stock['type_graph']}")
    print(f'[ok] wrote {stock_lib_path}')
    print(f'[ok] wrote {metadata_path}')


if __name__ == '__main__':
    main()
