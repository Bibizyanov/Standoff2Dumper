import os
import struct
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import autoprofile as ap  # noqa: E402


class FakeElf:
    def __init__(self, blob: bytes):
        self.blob = blob

    def read(self, va, size):
        if va + size > len(self.blob):
            raise ValueError('not file-backed')
        return self.blob[va:va + size]


def test_header_tiling_recovers_shuffled_sections():
    hsize = 0x40
    values = [0] * (hsize // 4)
    values[3], values[6] = hsize, 0x130
    values[1], values[5] = hsize + 0x130, 0x244
    values[7], values[9] = hsize + 0x376, 0x1B8
    blob = struct.pack(f'<{len(values)}I', *values) + bytes(0x800)
    h = ap.solve_header_sections(FakeElf(blob), 0, probe=hsize)
    got = [(s['start'], s['offset_field'], s.get('size')) for s in h['sections']]
    assert got[0] == (hsize, 12, 0x130)
    assert got[1] == (hsize + 0x130, 4, 0x244)
    assert got[2][:2] == (hsize + 0x376, 28)


def test_range_pairs_find_start_count_columns_that_tile():
    counts = np.array([2, 0, 3, 1], np.int64)
    starts = np.array([0, -1, 3, 2], np.int64)
    raw = b''.join(struct.pack('<HiH', 0xAAAA, int(s), int(c)) for s, c in zip(starts, counts))
    t = ap.Tbl(raw, 8)
    assert (2, 4, 6, 2, 6) in ap.range_pairs(t, (4,), (2,))
    assert ap.tiles(starts, counts, 6)
    assert not ap.tiles(np.array([0, -1, 2, 2]), counts, 6)


def test_assign_requires_full_non_overlapping_cover():
    fields = {'a': [(1.0, 0, 4), (0.5, 2, 4)], 'b': [(1.0, 4, 2), (0.9, 0, 2)]}
    assert ap.assign(6, fields) == {'a': (0, 4), 'b': (4, 2)}
    with pytest.raises(ap.ProfileError):
        ap.assign(8, fields)


def test_decode_aarch64_forms():
    assert ap.decode(0xF9400A60, 0) == ('ldr', 0, 19, 0x10, 8, False)
    assert ap.decode(0x53087D08, 0)[0] == 'ubfx'
    assert ap.decode(0x94000004, 0x100) == ('bl', 0x110)


LIBS = [p for p in os.environ.get('SO2_LIBS', '').split(os.pathsep) if p]


@pytest.mark.skipif(not LIBS, reason='set SO2_LIBS to real libunity.so paths')
@pytest.mark.parametrize('lib', LIBS)
def test_real_library_profile(lib):
    from protected_metadata import ELF64, ProtectedMetadata
    elf = ELF64(Path(lib))
    profile = ap.build_profile(elf)
    md = ProtectedMetadata(elf, profile)
    md.load_all()
    assert len(md.type_defs) == profile['counts']['type_definitions']
    assert sum(img.type_count for img in md.images) == len(md.type_defs)
    assert {'generic_method_pointers', 'invoker_pointers', 'codegen_modules'} <= set(profile['runtime']['code_registration'])
