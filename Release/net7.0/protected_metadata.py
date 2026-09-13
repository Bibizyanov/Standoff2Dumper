#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_METADATA_VA = 0x01B60480
DEFAULT_CODE_REG_VA = 0x0B7C32E0
DEFAULT_METADATA_REG_VA = 0x0B7C3358


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
        code_reg_va: int,
        metadata_reg_va: int,
        string_literal_offsets_field: int = 0x160,
        string_literal_data_field: int = 0x138,
        string_literal_count_field: int = 0x0FC,
        string_literal_offsets_count_field: int = 0x044,
    ):
        self.elf = elf
        self.base = metadata_va
        self.code_reg = code_reg_va
        self.metadata_reg = metadata_reg_va

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

        types_count = self.elf.u32(self.metadata_reg + 0x30)
        self.width_type_index = self.index_width(types_count)
        self.width_type_def = self.index_width(self.type_defs_count)
        self.width_generic_container = self.index_width(self.generic_containers_count)
        self.width_param = self.index_width(self.params_count)

        self.type_def_entry_size = self.type_defs_size // self.type_defs_count
        self.field_entry_size = self.fields_size // self.fields_count
        self.method_entry_size = self.methods_size // self.methods_count
        self.param_entry_size = self.params_size // self.params_count
        self.event_entry_size = self.events_size // self.events_count
        self.image_entry_size = self.images_size // self.images_count
        self.generic_param_entry_size = self.generic_params_size // self.generic_params_count

        self._validate_layout()

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
        va = self.base + self.type_defs_off + index * self.type_def_entry_size
        e = self.elf
        packed_counts = e.u32(va + 0x00)
        nested_count = packed_counts & 0xFFFF
        event_count = packed_counts >> 16

        namespace_index = e.i32(va + 0x04)
        interface_offsets_count = e.u16(va + 0x08)

        p = va + 0x0A
        declaring_type_index = read_packed_u(e, p, self.width_type_index)
        p += self.width_type_index

        field_count = e.u16(p)
        p += 2

        type_index = e.i32(p)
        bitfield = e.u32(p + 4)
        p += 8

        parent_index = read_packed_u(e, p, self.width_type_index)
        p += self.width_type_index

        nested_types_start = e.i32(p + 0x00)
        field_start = e.i32(p + 0x04)
        vtable_start = e.i32(p + 0x08)
        event_start = e.i32(p + 0x0C)
        interfaces_start = e.i32(p + 0x10)
        method_count = e.u16(p + 0x14)
        property_start = e.i32(p + 0x16)
        method_start = e.i32(p + 0x1A)
        interfaces_count = e.u16(p + 0x1E)
        flags = e.u32(p + 0x20)
        vtable_count = e.u16(p + 0x24)
        interface_offsets_start = e.i32(p + 0x26)

        gc_va = p + 0x2A
        generic_container_index = read_packed_u(e, gc_va, self.width_generic_container)
        p2 = gc_va + self.width_generic_container

        property_count = e.u16(p2)
        token = e.u32(p2 + 2)
        name_index = e.i32(p2 + 6)

        td = TypeDef(
            index=index,
            nested_type_count=nested_count,
            event_count=event_count,
            namespace_index=namespace_index,
            interface_offsets_count=interface_offsets_count,
            declaring_type_index=declaring_type_index,
            field_count=field_count,
            type_index=type_index,
            bitfield=bitfield,
            parent_index=parent_index,
            nested_types_start=nested_types_start,
            field_start=field_start,
            vtable_start=vtable_start,
            event_start=event_start,
            interfaces_start=interfaces_start,
            method_count=method_count,
            property_start=property_start,
            method_start=method_start,
            interfaces_count=interfaces_count,
            flags=flags,
            vtable_count=vtable_count,
            interface_offsets_start=interface_offsets_start,
            generic_container_index=generic_container_index,
            property_count=property_count,
            token=token,
            name_index=name_index,
            name=self.str(name_index),
            namespace=self.str(namespace_index),
        )
        return td

    def parse_method(self, index: int) -> MethodDef:
        va = self.base + self.methods_off + index * self.method_entry_size
        e = self.elf

        token = e.u32(va + 0x00)
        parameter_count = e.u16(va + 0x04)
        iflags = e.u16(va + 0x06)
        flags = e.u16(va + 0x08)
        name_index = e.i32(va + 0x0A)

        p = va + 0x0E
        declaring_type = read_packed_u(e, p, self.width_type_def)
        p += self.width_type_def

        slot = e.u16(p)
        aux = e.u32(p + 2)
        p += 6

        parameter_start = read_packed_u(e, p, self.width_param)
        p += self.width_param

        generic_container_index = read_packed_u(e, p, self.width_generic_container)
        p += self.width_generic_container

        return_type = read_packed_u(e, p, self.width_type_index)

        return MethodDef(
            index=index,
            token=token,
            parameter_count=parameter_count,
            iflags=iflags,
            flags=flags,
            name_index=name_index,
            declaring_type=declaring_type,
            slot=slot,
            aux=aux,
            parameter_start=parameter_start,
            generic_container_index=generic_container_index,
            return_type=return_type,
            name=self.str(name_index),
        )

    def parse_field(self, index: int) -> FieldDef:
        va = self.base + self.fields_off + index * self.field_entry_size
        token = self.elf.u32(va)
        name_index = self.elf.u32(va + 4)
        type_index = self.elf.u32(va + 8)
        return FieldDef(index, token, name_index, type_index, self.str(name_index))

    def parse_param(self, index: int) -> ParamDef:
        va = self.base + self.params_off + index * self.param_entry_size
        name_index = self.elf.u32(va)
        type_index = self.elf.u32(va + 4)
        token = self.elf.u32(va + 8)
        return ParamDef(index, name_index, type_index, token, self.str(name_index))

    def parse_property(self, index: int) -> dict:
        va = self.base + self.properties_off + index * 0x14
        return {
            "index": index,
            "setter_index": self.elf.i32(va + 0x00),
            "getter_index": self.elf.i32(va + 0x04),
            "token": self.elf.u32(va + 0x08),
            "attrs": self.elf.u32(va + 0x0C),
            "name_index": self.elf.u32(va + 0x10),
            "name": self.str(self.elf.u32(va + 0x10)),
        }

    def parse_event(self, index: int) -> dict:
        va = self.base + self.events_off + index * self.event_entry_size
        return {
            "index": index,
            "raise_method_index": self.elf.i32(va + 0x00),
            "remove_method_index": self.elf.i32(va + 0x04),
            "token": self.elf.u32(va + 0x08),
            "add_method_index": self.elf.i32(va + 0x0C),
            "type_index": self.elf.u32(va + 0x10),
            "name_index": self.elf.u32(va + 0x14),
            "name": self.str(self.elf.u32(va + 0x14)),
        }

    def parse_generic_container(self, index: int) -> GenericContainer:
        va = self.base + self.generic_containers_off + index * 0x10
        return GenericContainer(
            index=index,
            type_argc=self.elf.u32(va + 0x00),
            owner_index=self.elf.i32(va + 0x04),
            generic_parameter_start=self.elf.i32(va + 0x08),
            is_method=self.elf.u32(va + 0x0C),
        )

    def parse_generic_parameter(self, index: int) -> GenericParameter:
        va = self.base + self.generic_params_off + index * self.generic_param_entry_size
        num = self.elf.u16(va + 0x00)
        constraints_count = self.elf.u16(va + 0x02)
        constraints_start = self.elf.u16(va + 0x04)
        owner = read_packed_u(self.elf, va + 0x06, self.width_generic_container)
        name_index = self.elf.i32(va + 0x08)
        flags = self.elf.u16(va + 0x0C)
        return GenericParameter(
            index=index,
            num=num,
            constraints_count=constraints_count,
            constraints_start=constraints_start,
            owner_container_index=owner,
            name_index=name_index,
            flags=flags,
            name=self.str(name_index),
        )

    def parse_image(self, index: int) -> ImageDef:
        va = self.base + self.images_off + index * self.image_entry_size
        assembly_index = self.elf.i32(va + 0x00)
        type_count = self.elf.u32(va + 0x1A)
        name_index = self.elf.i32(va + 0x1E)
        type_start = read_packed_u(self.elf, va + 0x22, self.width_type_def)
        return ImageDef(
            index=index,
            assembly_index=assembly_index,
            type_count=type_count,
            name_index=name_index,
            type_start=type_start,
            name=self.str(name_index),
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
        count = self.elf.u32(self.code_reg + 0x44)
        arr = self.elf.u64(self.code_reg + 0x30)
        for i in range(count):
            mod = self.elf.u64(arr + i * 8)
            if not mod:
                continue
            try:
                name_ptr = self.elf.u64(mod + 0x80)
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
        ptrs = self.elf.u64(mod + 0x30)
        if rid > count or not ptrs:
            return 0
        try:
            return self.elf.u64(ptrs + (rid - 1) * 8)
        except Exception:
            return 0

    def field_offset(self, type_def_index: int, local_field_index: int) -> Optional[int]:
        try:
            field_offsets = self.elf.u64(self.metadata_reg + 0x68)
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
            return "void"

        td = self.type_index_to_typedef.get(type_index)
        if td:
            base = f"{td.namespace}.{td.name}" if td.namespace else td.name
            aliases = {
                "System.Void": "void", "System.Boolean": "bool", "System.Char": "char",
                "System.SByte": "sbyte", "System.Byte": "byte", "System.Int16": "short",
                "System.UInt16": "ushort", "System.Int32": "int", "System.UInt32": "uint",
                "System.Int64": "long", "System.UInt64": "ulong", "System.Single": "float",
                "System.Double": "double", "System.String": "string", "System.Object": "object",
                "System.IntPtr": "IntPtr", "System.UIntPtr": "UIntPtr",
            }
            base = aliases.get(base, base)
            gens = self.generic_names(td.generic_container_index)
            if gens:
                base += "<" + ", ".join(gens) + ">"
            return base or f"Type_{type_index}"

        try:
            types_ptr = self.elf.u64(self.metadata_reg + 0x48)
            type_ptr = self.elf.u64(types_ptr + type_index * 8)
            bits = self.elf.u32(type_ptr + 8)
            kind = (bits >> 18) & 0xFF
        except Exception:
            return f"Type_{type_index}"

        primitives = {
            0x01: "void",
            0x02: "bool",
            0x03: "char",
            0x04: "sbyte",
            0x05: "byte",
            0x06: "short",
            0x07: "ushort",
            0x08: "int",
            0x09: "uint",
            0x0A: "long",
            0x0B: "ulong",
            0x0C: "float",
            0x0D: "double",
            0x0E: "string",
            0x18: "IntPtr",
            0x19: "UIntPtr",
            0x1C: "object",
        }
        if kind in primitives:
            return primitives[kind]

        if kind in (0x11, 0x12):
            try:
                td_index = int(self.elf.u64(type_ptr + 0x00) & 0xFFFFFFFF)
                if 0 <= td_index < len(self.type_defs):
                    td2 = self.type_defs[td_index]
                    base = f"{td2.namespace}.{td2.name}" if td2.namespace else td2.name
                    aliases = {
                        "System.Void": "void", "System.Boolean": "bool", "System.Char": "char",
                        "System.SByte": "sbyte", "System.Byte": "byte", "System.Int16": "short",
                        "System.UInt16": "ushort", "System.Int32": "int", "System.UInt32": "uint",
                        "System.Int64": "long", "System.UInt64": "ulong", "System.Single": "float",
                        "System.Double": "double", "System.String": "string", "System.Object": "object",
                        "System.IntPtr": "IntPtr", "System.UIntPtr": "UIntPtr",
                    }
                    base = aliases.get(base, base)
                    gens = self.generic_names(td2.generic_container_index)
                    if gens:
                        base += "<" + ", ".join(gens) + ">"
                    return base or f"Type_{type_index}"
            except Exception:
                pass

        if kind == 0x13:
            return f"!{type_index}"
        if kind == 0x1E:
            return f"!!{type_index}"
        if kind == 0x1D:
            return f"Type_{type_index}[]"
        return f"Type_{type_index}/*kind=0x{kind:X}*/"

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
        protected_vtable_off = md.h32(0x98)
        src_base = md.base + protected_vtable_off
        for i in range(vtable_count):
            vtable_values[i] = md.elf.u32(src_base + i * 4)

    interface_offset_pairs = [(-1, 0)] * interface_offset_count
    if interface_offset_count:
        src_off = md.h32(0xAC)
        src_size = md.h32(0xA4)
        src_count = md.h32(0x5C)
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

    field_by_index = {f.index: f for f in fields}

    type_blob = bytearray()
    for td in md.type_defs:
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
            td.nested_types_start,
            td.interfaces_start,
            td.vtable_start,
            td.interface_offsets_start,
            td.method_count & 0xFFFF,
            td.property_count & 0xFFFF,
            td.field_count & 0xFFFF,
            td.event_count & 0xFFFF,
            td.nested_type_count & 0xFFFF,
            td.vtable_count & 0xFFFF,
            td.interfaces_count & 0xFFFF,
            td.interface_offsets_count & 0xFFFF,
            td.bitfield & 0xFFFFFFFF,
            td.token & 0xFFFFFFFF,
        )

    method_blob = bytearray()
    for m in methods:
        method_blob += struct.pack(
            "<IiiiiiIHHHH",
            m.name_index & 0xFFFFFFFF,
            m.declaring_type,
            m.return_type,
            m.aux,
            m.parameter_start,
            m.generic_container_index,
            m.token & 0xFFFFFFFF,
            m.flags & 0xFFFF,
            m.iflags & 0xFFFF,
            m.slot & 0xFFFF,
            m.parameter_count & 0xFFFF,
        )

    field_blob = bytearray()
    for f in fields:
        field_blob += struct.pack(
            "<IiI",
            f.name_index & 0xFFFFFFFF,
            f.type_index,
            f.token & 0xFFFFFFFF,
        )

    param_blob = bytearray()
    for p in params:
        param_blob += struct.pack(
            "<IIi",
            p.name_index & 0xFFFFFFFF,
            p.token & 0xFFFFFFFF,
            p.type_index,
        )

    property_blob = bytearray()
    for p in properties:
        property_blob += struct.pack(
            "<IiiII",
            p["name_index"] & 0xFFFFFFFF,
            p["getter_index"],
            p["setter_index"],
            p["attrs"] & 0xFFFFFFFF,
            p["token"] & 0xFFFFFFFF,
        )

    event_blob = bytearray()
    for e in events:
        event_blob += struct.pack(
            "<IiiiiI",
            e["name_index"] & 0xFFFFFFFF,
            e["type_index"],
            e["add_method_index"],
            e["remove_method_index"],
            e["raise_method_index"],
            e["token"] & 0xFFFFFFFF,
        )

    generic_container_blob = bytearray()
    for gc in md.generic_containers:
        generic_container_blob += struct.pack(
            "<iiii",
            gc.owner_index,
            gc.type_argc,
            gc.is_method,
            gc.generic_parameter_start,
        )

    generic_param_blob = bytearray()
    for gp in md.generic_params:
        generic_param_blob += struct.pack(
            "<iIhhHH",
            gp.owner_container_index,
            gp.name_index & 0xFFFFFFFF,
            gp.constraints_start,
            gp.constraints_count,
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
        "attributeData": b"",
        "attributeDataRange": b"",
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
            "Optional default-value/custom-attribute/WinRT/exported-type sections are empty in this stage.",
            "Stock Il2CppDumper metadata parsing should accept this file; binary registration remains custom/shuffled.",
        ],
    }
    return rebuilt, manifest

def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lib", type=Path)
    parser.add_argument("-o", "--out", type=Path, required=True)
    parser.add_argument("--metadata-va", type=parse_int, default=DEFAULT_METADATA_VA)
    parser.add_argument("--code-reg-va", type=parse_int, default=DEFAULT_CODE_REG_VA)
    parser.add_argument("--metadata-reg-va", type=parse_int, default=DEFAULT_METADATA_REG_VA)
    parser.add_argument("--string-literal-offsets-field", type=parse_int, default=0x160)
    parser.add_argument("--string-literal-data-field", type=parse_int, default=0x138)
    parser.add_argument("--string-literal-count-field", type=parse_int, default=0x0FC)
    parser.add_argument("--string-literal-offsets-count-field", type=parse_int, default=0x044)
    args = parser.parse_args()

    elf = ELF64(args.lib)
    metadata = ProtectedMetadata(
        elf,
        args.metadata_va,
        args.code_reg_va,
        args.metadata_reg_va,
        args.string_literal_offsets_field,
        args.string_literal_data_field,
        args.string_literal_count_field,
        args.string_literal_offsets_count_field,
    )
    metadata.load_all()
    rebuilt, _ = rebuild_global_metadata_v31(metadata)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "global-metadata.dat").write_bytes(rebuilt)


if __name__ == "__main__":
    main()
