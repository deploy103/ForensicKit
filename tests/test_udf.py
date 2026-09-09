from __future__ import annotations

import binascii
import hashlib
import io
from pathlib import Path

from forensickit.engine import AnalysisEngine
from forensickit.config import ForensicKitConfig
from forensickit.evidence import EvidenceManager
from forensickit.extraction import ExtractionManager
from forensickit.identification import IdentificationEngine
from forensickit.models import AnalysisMode, Artifact
from forensickit.profiles import ProfileEngine
from forensickit.triage import GenericTriageEngine
from forensickit.udf import UdfObservationEngine
from forensickit.workspace import CaseWorkspace
from tests.test_engine_pipeline import _iso9660_with_root_file


_BLOCK_SIZE = 2_048


def _artifact(path: Path) -> Artifact:
    payload = path.read_bytes()
    return Artifact(
        id="artifact-udf",
        case_id="case-udf",
        path=str(path),
        logical_name=path.name,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def _values(observations):
    return {item.key: item.value for item in observations}


def _dstring(text: str, length: int) -> bytes:
    encoded = b"\x08" + text.encode("latin-1")
    assert len(encoded) <= length - 1
    result = bytearray(length)
    result[:len(encoded)] = encoded
    result[-1] = len(encoded)
    return bytes(result)


def _entity_identifier(identifier: str) -> bytes:
    encoded = identifier.encode("ascii")
    assert len(encoded) <= 23
    result = bytearray(32)
    result[1:1 + len(encoded)] = encoded
    return bytes(result)


def _character_set() -> bytes:
    name = b"OSTA Compressed Unicode"
    result = bytearray(64)
    result[1:1 + len(name)] = name
    return bytes(result)


def _extent(length: int, location: int) -> bytes:
    return length.to_bytes(4, "little") + location.to_bytes(4, "little")


def _long_ad(
    length: int,
    logical_block_number: int,
    partition_reference: int,
) -> bytes:
    return (
        length.to_bytes(4, "little")
        + logical_block_number.to_bytes(4, "little")
        + partition_reference.to_bytes(2, "little")
        + b"\x00" * 6
    )


def _tag_descriptor(
    raw: bytearray,
    identifier: int,
    location: int,
    crc_length: int,
) -> bytes:
    raw[0:2] = identifier.to_bytes(2, "little")
    raw[2:4] = (2).to_bytes(2, "little")
    raw[5] = 0
    raw[6:8] = (1).to_bytes(2, "little")
    raw[10:12] = crc_length.to_bytes(2, "little")
    raw[12:16] = location.to_bytes(4, "little")
    raw[8:10] = binascii.crc_hqx(
        bytes(raw[16:16 + crc_length]), 0,
    ).to_bytes(2, "little")
    raw[4] = (sum(raw[0:4]) + sum(raw[5:16])) & 0xFF
    return bytes(raw)


def _primary_volume(location: int) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[16:20] = (1).to_bytes(4, "little")
    raw[20:24] = (0).to_bytes(4, "little")
    raw[24:56] = _dstring("FORENSICKIT", 32)
    raw[56:58] = (1).to_bytes(2, "little")
    raw[58:60] = (1).to_bytes(2, "little")
    raw[60:62] = (2).to_bytes(2, "little")
    raw[62:64] = (3).to_bytes(2, "little")
    raw[64:68] = (1).to_bytes(4, "little")
    raw[68:72] = (1).to_bytes(4, "little")
    raw[72:200] = _dstring("FORENSICKIT-SET", 128)
    raw[200:264] = _character_set()
    raw[264:328] = _character_set()
    return _tag_descriptor(raw, 1, location, 496)


def _partition(location: int, *, access_type: int = 1) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[16:20] = (2).to_bytes(4, "little")
    raw[20:22] = (0).to_bytes(2, "little")
    raw[22:24] = (0).to_bytes(2, "little")
    raw[24:56] = _entity_identifier("+NSR03")
    raw[184:188] = access_type.to_bytes(4, "little")
    raw[188:192] = (400).to_bytes(4, "little")
    raw[192:196] = (100).to_bytes(4, "little")
    return _tag_descriptor(raw, 5, location, 496)


def _logical_volume(location: int) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[16:20] = (3).to_bytes(4, "little")
    raw[20:84] = _character_set()
    raw[84:212] = _dstring("FORENSICKIT-UDF", 128)
    raw[212:216] = _BLOCK_SIZE.to_bytes(4, "little")
    raw[216:248] = _entity_identifier("*OSTA UDF Compliant")
    raw[248:264] = _long_ad(_BLOCK_SIZE, 0, 0)
    raw[264:268] = (6).to_bytes(4, "little")
    raw[268:272] = (1).to_bytes(4, "little")
    raw[272:304] = _entity_identifier("*ForensicKit")
    raw[432:440] = _extent(_BLOCK_SIZE, 350)
    raw[440:446] = b"\x01\x06\x01\x00\x00\x00"
    return _tag_descriptor(raw, 6, location, 430)


def _terminator(location: int) -> bytes:
    return _tag_descriptor(bytearray(_BLOCK_SIZE), 8, location, 496)


def _anchor(location: int, main: int, reserve: int) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[16:24] = _extent(4 * _BLOCK_SIZE, main)
    raw[24:32] = _extent(4 * _BLOCK_SIZE, reserve)
    return _tag_descriptor(raw, 2, location, 496)


def _file_set_descriptor(location: int = 0) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[28:30] = (3).to_bytes(2, "little")
    raw[30:32] = (3).to_bytes(2, "little")
    raw[32:36] = (1).to_bytes(4, "little")
    raw[36:40] = (1).to_bytes(4, "little")
    raw[40:44] = (0).to_bytes(4, "little")
    raw[44:48] = (0).to_bytes(4, "little")
    raw[48:112] = _character_set()
    raw[112:240] = _dstring("FORENSICKIT-UDF", 128)
    raw[240:304] = _character_set()
    raw[304:336] = _dstring("FORENSICKIT-FILESET", 32)
    raw[400:416] = _long_ad(_BLOCK_SIZE, 1, 0)
    raw[416:448] = _entity_identifier("*OSTA UDF Compliant")
    return _tag_descriptor(raw, 0x0100, location, 496)


def _root_file_entry(
    information_length: int,
    location: int = 1,
    *,
    file_type: int = 4,
    allocation_descriptor_type: int = 0,
    allocation_extent_location: int | None = None,
) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[20:22] = (4).to_bytes(2, "little")
    raw[24:26] = (1).to_bytes(2, "little")
    raw[27] = file_type
    raw[28:32] = location.to_bytes(4, "little")
    raw[32:34] = (0).to_bytes(2, "little")
    raw[34:36] = allocation_descriptor_type.to_bytes(2, "little")
    raw[36:40] = (1000).to_bytes(4, "little")
    raw[40:44] = (1000).to_bytes(4, "little")
    raw[44:48] = (0x14A5).to_bytes(4, "little")
    raw[48:50] = (1).to_bytes(2, "little")
    raw[56:64] = information_length.to_bytes(8, "little")
    raw[64:72] = (1).to_bytes(8, "little")
    raw[108:112] = (1).to_bytes(4, "little")
    raw[128:160] = _entity_identifier("*ForensicKit")
    raw[160:168] = (42).to_bytes(8, "little")
    raw[168:172] = (0).to_bytes(4, "little")
    if allocation_extent_location is not None:
        assert allocation_descriptor_type == 0
        allocation_descriptor = (
            (0xC0000000 | _BLOCK_SIZE).to_bytes(4, "little")
            + allocation_extent_location.to_bytes(4, "little")
        )
    else:
        allocation_descriptor = (
            _BLOCK_SIZE.to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            if allocation_descriptor_type == 0
            else _long_ad(_BLOCK_SIZE, 2, 0)
        )
    raw[172:176] = len(allocation_descriptor).to_bytes(4, "little")
    raw[176:176 + len(allocation_descriptor)] = allocation_descriptor
    return _tag_descriptor(
        raw, 0x0105, location, 160 + len(allocation_descriptor),
    )


def _file_identifier(
    location: int,
    icb_location: int,
    *,
    name: str | None = None,
    parent: bool = False,
    directory: bool = False,
    padding_byte: int = 0,
    deleted: bool = False,
    zero_icb: bool = False,
) -> bytes:
    encoded_name = b"" if name is None else b"\x08" + name.encode("latin-1")
    record_length = (38 + len(encoded_name) + 3) & ~3
    raw = bytearray(record_length)
    raw[16:18] = (1).to_bytes(2, "little")
    raw[18] = (
        (0x08 if parent else 0)
        | (0x02 if directory else 0)
        | (0x04 if deleted else 0)
    )
    raw[19] = len(encoded_name)
    raw[20:36] = _long_ad(
        0 if zero_icb else _BLOCK_SIZE,
        0 if zero_icb else icb_location,
        0,
    )
    raw[36:38] = (0).to_bytes(2, "little")
    raw[38:38 + len(encoded_name)] = encoded_name
    if padding_byte:
        raw[-1] = padding_byte
    return _tag_descriptor(raw, 0x0101, location, record_length - 16)


def _root_directory(
    *,
    parent_icb_location: int = 1,
    child_tag_location: int = 2,
    child_name: str = "README.TXT",
    child_padding_byte: int = 0,
    include_allocation_extent_file: bool = False,
) -> bytes:
    records = [
        _file_identifier(
            2,
            parent_icb_location,
            parent=True,
            directory=True,
        ),
        _file_identifier(
            child_tag_location,
            3,
            name=child_name,
            padding_byte=child_padding_byte,
        ),
        _file_identifier(2, 5, name="SUBDIR", directory=True),
        _file_identifier(2, 9, name="SPARSE.BIN"),
        _file_identifier(2, 11, name="INLINE.TXT"),
        _file_identifier(2, 13, name="EXTENDED.BIN"),
        _file_identifier(2, 15, name="EXT-SPARSE.BIN"),
    ]
    if include_allocation_extent_file:
        records.append(_file_identifier(2, 17, name="CHAINED.BIN"))
    return b"".join(records)


def _subdirectory(
    *,
    parent_icb_location: int = 1,
    include_root_cycle: bool = False,
) -> bytes:
    records = [
        _file_identifier(
            6,
            parent_icb_location,
            parent=True,
            directory=True,
        ),
        _file_identifier(6, 7, name="NESTED.TXT"),
        _file_identifier(
            6, 0, deleted=True, zero_icb=True,
        ),
    ]
    if include_root_cycle:
        records.append(_file_identifier(
            6, 1, name="ROOT-LOOP", directory=True,
        ))
    return b"".join(records)


def _child_file_entry(
    data_length: int,
    location: int = 3,
    *,
    file_type: int = 5,
    data_location: int = 4,
    extended: bool = False,
    allocation_descriptor_type: int = 0,
    embedded_data: bytes | None = None,
) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[20:22] = (4).to_bytes(2, "little")
    raw[24:26] = (1).to_bytes(2, "little")
    raw[27] = file_type
    raw[28:32] = (1).to_bytes(4, "little")
    raw[32:34] = (0).to_bytes(2, "little")
    raw[34:36] = allocation_descriptor_type.to_bytes(2, "little")
    raw[36:40] = (1000).to_bytes(4, "little")
    raw[40:44] = (1000).to_bytes(4, "little")
    raw[44:48] = (0x14A5).to_bytes(4, "little")
    raw[48:50] = (1).to_bytes(2, "little")
    raw[56:64] = data_length.to_bytes(8, "little")
    if extended:
        raw[64:72] = data_length.to_bytes(8, "little")
        raw[72:80] = (
            0 if allocation_descriptor_type == 3
            else (1 if data_length else 0)
        ).to_bytes(8, "little")
        raw[128:132] = (1).to_bytes(4, "little")
        raw[168:200] = _entity_identifier("*ForensicKit")
        raw[200:208] = (43).to_bytes(8, "little")
        allocation_length_offset = 212
        allocation_offset = 216
        identifier = 0x010A
        crc_base_length = 200
    else:
        raw[64:72] = (
            0 if allocation_descriptor_type == 3
            else (1 if data_length else 0)
        ).to_bytes(8, "little")
        raw[108:112] = (1).to_bytes(4, "little")
        raw[128:160] = _entity_identifier("*ForensicKit")
        raw[160:168] = (43).to_bytes(8, "little")
        allocation_length_offset = 172
        allocation_offset = 176
        identifier = 0x0105
        crc_base_length = 160
    if not data_length:
        allocation_descriptor = b""
    elif allocation_descriptor_type == 0:
        allocation_descriptor = (
            data_length.to_bytes(4, "little")
            + data_location.to_bytes(4, "little")
        )
    elif allocation_descriptor_type == 1:
        allocation_descriptor = _long_ad(data_length, data_location, 0)
    elif allocation_descriptor_type == 2:
        allocation_descriptor = (
            data_length.to_bytes(4, "little")
            + data_length.to_bytes(4, "little")
            + data_length.to_bytes(4, "little")
            + data_location.to_bytes(4, "little")
            + b"\x00" * 4
        )
    else:
        assert allocation_descriptor_type == 3
        allocation_descriptor = (
            embedded_data if embedded_data is not None
            else b"E" * data_length
        )
        assert len(allocation_descriptor) == data_length
    raw[
        allocation_length_offset:allocation_length_offset + 4
    ] = len(allocation_descriptor).to_bytes(4, "little")
    raw[
        allocation_offset:allocation_offset + len(allocation_descriptor)
    ] = allocation_descriptor
    return _tag_descriptor(
        raw, identifier, location, crc_base_length + len(allocation_descriptor),
    )


def _sparse_file_entry(location: int = 9) -> bytes:
    raw = bytearray(_child_file_entry(
        2 * _BLOCK_SIZE,
        location=location,
        data_location=10,
    ))
    raw[64:72] = (1).to_bytes(8, "little")
    allocation_descriptors = (
        _BLOCK_SIZE.to_bytes(4, "little")
        + (10).to_bytes(4, "little")
        + (0x80000000 | _BLOCK_SIZE).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )
    raw[172:176] = len(allocation_descriptors).to_bytes(4, "little")
    raw[176:192] = allocation_descriptors
    return _tag_descriptor(raw, 0x0105, location, 176)


def _compressed_extended_file_entry(
    information_length: int,
    recorded_length: int,
    location: int = 13,
) -> bytes:
    raw = bytearray(_child_file_entry(
        information_length,
        location=location,
        data_location=14,
        allocation_descriptor_type=2,
    ))
    raw[176:180] = recorded_length.to_bytes(4, "little")
    raw[180:184] = recorded_length.to_bytes(4, "little")
    raw[184:188] = information_length.to_bytes(4, "little")
    return _tag_descriptor(raw, 0x0105, location, 180)


def _sparse_extended_file_entry(location: int = 15) -> bytes:
    raw = bytearray(_child_file_entry(
        2 * _BLOCK_SIZE,
        location=location,
        data_location=16,
        allocation_descriptor_type=2,
    ))
    raw[64:72] = (1).to_bytes(8, "little")
    allocation_descriptors = (
        _BLOCK_SIZE.to_bytes(4, "little")
        + _BLOCK_SIZE.to_bytes(4, "little")
        + _BLOCK_SIZE.to_bytes(4, "little")
        + (16).to_bytes(4, "little")
        + b"\x00" * 4
        + (0x80000000 | _BLOCK_SIZE).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + _BLOCK_SIZE.to_bytes(4, "little")
        + b"\x00" * 8
    )
    raw[172:176] = len(allocation_descriptors).to_bytes(4, "little")
    raw[176:216] = allocation_descriptors
    return _tag_descriptor(raw, 0x0105, location, 200)


def _allocation_extent_descriptor(
    location: int,
    previous_location: int,
    allocation_descriptors: bytes,
    *,
    tag_location: int | None = None,
    identifier: int = 0x0102,
) -> bytes:
    raw = bytearray(_BLOCK_SIZE)
    raw[16:20] = previous_location.to_bytes(4, "little")
    raw[20:24] = len(allocation_descriptors).to_bytes(4, "little")
    raw[24:24 + len(allocation_descriptors)] = allocation_descriptors
    return _tag_descriptor(
        raw,
        identifier,
        location if tag_location is None else tag_location,
        8 + len(allocation_descriptors),
    )


def _allocation_ad(
    descriptor_type: int,
    extent_type: int,
    length: int,
    logical_block_number: int,
) -> bytes:
    raw_length = (extent_type << 30) | length
    if descriptor_type == 0:
        return (
            raw_length.to_bytes(4, "little")
            + logical_block_number.to_bytes(4, "little")
        )
    if descriptor_type == 1:
        return _long_ad(raw_length, logical_block_number, 0)
    assert descriptor_type == 2
    recorded_length = length if extent_type == 0 else 0
    information_length = length if extent_type != 3 else 0
    return (
        raw_length.to_bytes(4, "little")
        + recorded_length.to_bytes(4, "little")
        + information_length.to_bytes(4, "little")
        + logical_block_number.to_bytes(4, "little")
        + b"\x00" * 4
    )


def _chained_file_entry(
    location: int = 17,
    allocation_descriptor_type: int = 0,
) -> bytes:
    raw = bytearray(_child_file_entry(
        3 * _BLOCK_SIZE,
        location=location,
        data_location=18,
        allocation_descriptor_type=allocation_descriptor_type,
    ))
    raw[64:72] = (2).to_bytes(8, "little")
    allocation_descriptors = (
        _allocation_ad(allocation_descriptor_type, 0, _BLOCK_SIZE, 18)
        + _allocation_ad(allocation_descriptor_type, 3, _BLOCK_SIZE, 20)
    )
    raw[172:176] = len(allocation_descriptors).to_bytes(4, "little")
    raw[176:176 + len(allocation_descriptors)] = allocation_descriptors
    return _tag_descriptor(
        raw, 0x0105, location, 160 + len(allocation_descriptors),
    )


def _chained_directory_entry(
    data_length: int,
    location: int,
    allocation_extent_location: int,
) -> bytes:
    raw = bytearray(_child_file_entry(
        data_length,
        location=location,
        file_type=4,
        data_location=6,
    ))
    descriptor = _allocation_ad(
        0, 3, _BLOCK_SIZE, allocation_extent_location,
    )
    raw[172:176] = len(descriptor).to_bytes(4, "little")
    raw[176:184] = descriptor
    return _tag_descriptor(raw, 0x0105, location, 160 + len(descriptor))


def _vrs(identifier: bytes) -> bytes:
    assert len(identifier) == 5
    raw = bytearray(_BLOCK_SIZE)
    raw[1:6] = identifier
    raw[6] = 1
    return bytes(raw)


def _udf_image(
    *,
    reserve_access_type: int = 1,
    omit_terminating_vrs: bool = False,
    corrupt_main_lvd_crc: bool = False,
    corrupt_main_pvd_checksum: bool = False,
    short_main_pvd_crc: bool = False,
    vrs_start: int = 16,
    corrupt_file_set_crc: bool = False,
    root_file_type: int = 4,
    root_allocation_descriptor_type: int = 0,
    corrupt_root_fid_crc: bool = False,
    parent_icb_location: int = 1,
    child_fid_tag_location: int = 2,
    child_fid_name: str = "README.TXT",
    child_fid_padding_byte: int = 0,
    child_icb_file_type: int = 5,
    corrupt_child_icb_crc: bool = False,
    child_icb_extended: bool = False,
    child_allocation_descriptor_type: int = 0,
    subdirectory_parent_icb_location: int = 1,
    include_root_directory_cycle: bool = False,
    compressed_extended_file: bool = False,
    include_allocation_extent_file: bool = False,
    allocation_extent_fault: str | None = None,
    root_directory_allocation_extent: bool = False,
    subdirectory_allocation_extent: bool = False,
    allocation_extent_descriptor_type: int = 0,
) -> bytes:
    image = bytearray(600 * _BLOCK_SIZE)
    image[vrs_start * _BLOCK_SIZE:(vrs_start + 1) * _BLOCK_SIZE] = (
        _vrs(b"BEA01")
    )
    image[(vrs_start + 1) * _BLOCK_SIZE:(vrs_start + 2) * _BLOCK_SIZE] = (
        _vrs(b"NSR03")
    )
    if not omit_terminating_vrs:
        image[
            (vrs_start + 2) * _BLOCK_SIZE:(vrs_start + 3) * _BLOCK_SIZE
        ] = _vrs(b"TEA01")
    image[256 * _BLOCK_SIZE:257 * _BLOCK_SIZE] = _anchor(256, 257, 300)
    for start, access_type in ((257, 1), (300, reserve_access_type)):
        image[start * _BLOCK_SIZE:(start + 1) * _BLOCK_SIZE] = (
            _primary_volume(start)
        )
        image[(start + 1) * _BLOCK_SIZE:(start + 2) * _BLOCK_SIZE] = (
            _partition(start + 1, access_type=access_type)
        )
        image[(start + 2) * _BLOCK_SIZE:(start + 3) * _BLOCK_SIZE] = (
            _logical_volume(start + 2)
        )
        image[(start + 3) * _BLOCK_SIZE:(start + 4) * _BLOCK_SIZE] = (
            _terminator(start + 3)
        )
    directory = _root_directory(
        parent_icb_location=parent_icb_location,
        child_tag_location=child_fid_tag_location,
        child_name=child_fid_name,
        child_padding_byte=child_fid_padding_byte,
        include_allocation_extent_file=include_allocation_extent_file,
    )
    image[400 * _BLOCK_SIZE:401 * _BLOCK_SIZE] = _file_set_descriptor()
    image[401 * _BLOCK_SIZE:402 * _BLOCK_SIZE] = _root_file_entry(
        len(directory),
        file_type=root_file_type,
        allocation_descriptor_type=root_allocation_descriptor_type,
        allocation_extent_location=(
            23 if root_directory_allocation_extent else None
        ),
    )
    image[
        402 * _BLOCK_SIZE:402 * _BLOCK_SIZE + len(directory)
    ] = directory
    child_data = b"ForensicKit UDF child metadata only\n"
    image[403 * _BLOCK_SIZE:404 * _BLOCK_SIZE] = _child_file_entry(
        len(child_data),
        file_type=child_icb_file_type,
        extended=child_icb_extended,
        allocation_descriptor_type=child_allocation_descriptor_type,
        embedded_data=child_data,
    )
    image[
        404 * _BLOCK_SIZE:404 * _BLOCK_SIZE + len(child_data)
    ] = child_data
    subdirectory = _subdirectory(
        parent_icb_location=subdirectory_parent_icb_location,
        include_root_cycle=include_root_directory_cycle,
    )
    image[405 * _BLOCK_SIZE:406 * _BLOCK_SIZE] = (
        _chained_directory_entry(len(subdirectory), 5, 24)
        if subdirectory_allocation_extent
        else _child_file_entry(
            len(subdirectory),
            location=5,
            file_type=4,
            data_location=6,
        )
    )
    image[
        406 * _BLOCK_SIZE:406 * _BLOCK_SIZE + len(subdirectory)
    ] = subdirectory
    nested_data = b"Nested UDF metadata remains unmaterialized\n"
    image[407 * _BLOCK_SIZE:408 * _BLOCK_SIZE] = _child_file_entry(
        len(nested_data),
        location=7,
        data_location=8,
    )
    image[
        408 * _BLOCK_SIZE:408 * _BLOCK_SIZE + len(nested_data)
    ] = nested_data
    image[409 * _BLOCK_SIZE:410 * _BLOCK_SIZE] = _sparse_file_entry()
    sparse_recorded = b"SPARSE-RECORDED" + b"\xA5" * (
        _BLOCK_SIZE - len(b"SPARSE-RECORDED")
    )
    image[410 * _BLOCK_SIZE:411 * _BLOCK_SIZE] = sparse_recorded
    embedded_data = b"INLINE-UDF-DATA"
    image[411 * _BLOCK_SIZE:412 * _BLOCK_SIZE] = _child_file_entry(
        len(embedded_data),
        location=11,
        allocation_descriptor_type=3,
        embedded_data=embedded_data,
    )
    extended_data = b"EXTENDED-AD-DATA"
    if compressed_extended_file:
        image[413 * _BLOCK_SIZE:414 * _BLOCK_SIZE] = (
            _compressed_extended_file_entry(
                len(extended_data), 8,
            )
        )
    else:
        image[413 * _BLOCK_SIZE:414 * _BLOCK_SIZE] = _child_file_entry(
            len(extended_data),
            location=13,
            data_location=14,
            allocation_descriptor_type=2,
        )
    image[
        414 * _BLOCK_SIZE:414 * _BLOCK_SIZE + len(extended_data)
    ] = extended_data
    image[415 * _BLOCK_SIZE:416 * _BLOCK_SIZE] = (
        _sparse_extended_file_entry()
    )
    image[416 * _BLOCK_SIZE:417 * _BLOCK_SIZE] = b"X" * _BLOCK_SIZE
    if include_allocation_extent_file:
        image[417 * _BLOCK_SIZE:418 * _BLOCK_SIZE] = _chained_file_entry(
            allocation_descriptor_type=allocation_extent_descriptor_type,
        )
        image[418 * _BLOCK_SIZE:419 * _BLOCK_SIZE] = b"A" * _BLOCK_SIZE
        image[419 * _BLOCK_SIZE:420 * _BLOCK_SIZE] = b"B" * _BLOCK_SIZE
        if allocation_extent_fault == "limit":
            for logical_location in range(20, 52):
                next_descriptor = (
                    _allocation_ad(
                        allocation_extent_descriptor_type,
                        3,
                        _BLOCK_SIZE,
                        logical_location + 1,
                    )
                )
                image[
                    (400 + logical_location) * _BLOCK_SIZE:
                    (401 + logical_location) * _BLOCK_SIZE
                ] = _allocation_extent_descriptor(
                    logical_location,
                    0 if logical_location == 20 else logical_location - 1,
                    next_descriptor,
                )
        else:
            first_aed_descriptors = (
                _allocation_ad(
                    allocation_extent_descriptor_type, 0, _BLOCK_SIZE, 19,
                )
                + _allocation_ad(
                    allocation_extent_descriptor_type,
                    3,
                    _BLOCK_SIZE,
                    21 if allocation_extent_fault != "cycle" else 20,
                )
            )
            first_aed = _allocation_extent_descriptor(
                20,
                1 if allocation_extent_fault == "previous_pointer" else 0,
                first_aed_descriptors,
                tag_location=(
                    19 if allocation_extent_fault == "tag_location" else None
                ),
                identifier=(
                    0x0103
                    if allocation_extent_fault == "identifier" else 0x0102
                ),
            )
            image[420 * _BLOCK_SIZE:421 * _BLOCK_SIZE] = first_aed
            final_aed_descriptors = (
                _allocation_ad(
                    allocation_extent_descriptor_type, 2, _BLOCK_SIZE, 0,
                )
            )
            image[421 * _BLOCK_SIZE:422 * _BLOCK_SIZE] = (
                _allocation_extent_descriptor(
                    21,
                    20,
                    final_aed_descriptors,
                )
            )
            if allocation_extent_fault == "checksum":
                image[420 * _BLOCK_SIZE + 4] ^= 0x01
            elif allocation_extent_fault == "crc":
                image[420 * _BLOCK_SIZE + 24] ^= 0x01
            elif allocation_extent_fault == "incomplete":
                image[420 * _BLOCK_SIZE:421 * _BLOCK_SIZE] = (
                    b"\x00" * _BLOCK_SIZE
                )
    if root_directory_allocation_extent:
        root_aed_descriptors = (
            _BLOCK_SIZE.to_bytes(4, "little")
            + (2).to_bytes(4, "little")
        )
        image[423 * _BLOCK_SIZE:424 * _BLOCK_SIZE] = (
            _allocation_extent_descriptor(23, 0, root_aed_descriptors)
        )
    if subdirectory_allocation_extent:
        subdirectory_aed_descriptors = (
            _BLOCK_SIZE.to_bytes(4, "little")
            + (6).to_bytes(4, "little")
        )
        image[424 * _BLOCK_SIZE:425 * _BLOCK_SIZE] = (
            _allocation_extent_descriptor(
                24, 0, subdirectory_aed_descriptors,
            )
        )
    if corrupt_main_lvd_crc:
        image[259 * _BLOCK_SIZE + 100] ^= 0x01
    if corrupt_main_pvd_checksum:
        image[257 * _BLOCK_SIZE + 4] ^= 0x01
    if short_main_pvd_crc:
        start = 257 * _BLOCK_SIZE
        image[start:start + _BLOCK_SIZE] = _tag_descriptor(
            bytearray(image[start:start + _BLOCK_SIZE]), 1, 257, 32,
        )
    if corrupt_file_set_crc:
        image[400 * _BLOCK_SIZE + 310] ^= 0x01
    if corrupt_root_fid_crc:
        image[402 * _BLOCK_SIZE + 80] ^= 0x01
    if corrupt_child_icb_crc:
        image[403 * _BLOCK_SIZE + 100] ^= 0x01
    return bytes(image)


def test_udf_vrs_anchor_and_volume_descriptor_copies_validate(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence.udf"
    evidence.write_bytes(_udf_image())
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)

    assert identified.format == "udf"
    assert artifact.artifact_type == "archive"
    assert values["triage.detected_header_format"] == "udf"
    assert values["archive.container_kind"] == "udf"
    assert values["archive.udf.detected"] is True
    assert values["archive.udf.valid"] is True
    assert values["archive.udf.revision_identifier"] == "NSR03"
    vrs = values["archive.udf.volume_recognition_sequence"]
    assert vrs["valid"] is True
    assert vrs["recognized"] is True
    assert [item["standard_identifier"] for item in vrs["records"]] == [
        "BEA01", "NSR03", "TEA01",
    ]
    active_anchor = values["archive.udf.active_anchor"]
    assert active_anchor["block_size"] == _BLOCK_SIZE
    assert active_anchor["logical_sector"] == 256
    assert active_anchor["tag"]["checksum_valid"] is True
    assert active_anchor["tag"]["crc_valid"] is True
    assert active_anchor["tag"]["location_valid"] is True
    assert active_anchor["main_volume_descriptor_sequence"]["location"] == 257
    assert active_anchor["reserve_volume_descriptor_sequence"]["location"] == 300
    main = values["archive.udf.main_volume_descriptor_sequence"]
    reserve = values["archive.udf.reserve_volume_descriptor_sequence"]
    assert main["valid"] is True
    assert reserve["valid"] is True
    assert [item["type"] for item in main["descriptors"]] == [
        "primary_volume", "partition", "logical_volume", "terminating",
    ]
    assert main["descriptors"][0]["expected_crc_length"] == 496
    assert main["descriptors"][2]["expected_crc_length"] == 430
    assert all(
        item["tag"]["checksum_valid"] is True
        and item["tag"]["crc_valid"] is True
        and item["crc_coverage_valid"] is True
        for item in main["descriptors"]
    )
    partition = main["partitions"][0]
    assert partition["partition_number"] == 0
    assert partition["partition_contents"]["identifier"] == "+NSR03"
    assert partition["offset"] == 400 * _BLOCK_SIZE
    assert partition["length"] == 100 * _BLOCK_SIZE
    logical_volume = main["logical_volumes"][0]
    assert logical_volume["logical_block_size"] == _BLOCK_SIZE
    assert logical_volume["domain_identifier"]["identifier"] == (
        "*OSTA UDF Compliant"
    )
    assert logical_volume["partition_maps"][0]["partition_number"] == 0
    assert logical_volume["file_set_descriptor_address"] == {
        "raw_hex": _long_ad(_BLOCK_SIZE, 0, 0).hex(),
        "raw_length": _BLOCK_SIZE,
        "extent_type": 0,
        "length": _BLOCK_SIZE,
        "logical_block_number": 0,
        "partition_reference_number": 0,
        "implementation_use_raw_hex": "000000000000",
        "implementation_use_flags": 0,
        "valid": True,
    }
    comparison = values["archive.udf.volume_descriptor_comparison"]
    assert comparison["performed"] is True
    assert comparison["consistent"] is True
    assert comparison["failed_checks"] == []
    file_set = values["archive.udf.file_set"]
    assert file_set["valid"] is True
    assert file_set["offset"] == 400 * _BLOCK_SIZE
    assert file_set["tag"]["identifier"] == 0x0100
    assert file_set["tag"]["checksum_valid"] is True
    assert file_set["tag"]["crc_valid"] is True
    assert file_set["tag"]["crc_length"] == 496
    assert file_set["file_set_identifier"]["text"] == (
        "FORENSICKIT-FILESET"
    )
    assert file_set["logical_volume_identifier"]["text"] == (
        "FORENSICKIT-UDF"
    )
    assert file_set["resolved_file_set"]["partition_number"] == 0
    assert file_set["resolved_root_directory_icb"]["offset"] == (
        401 * _BLOCK_SIZE
    )
    root_icb = file_set["root_icb"]
    assert root_icb["valid"] is True
    assert root_icb["tag"]["identifier"] == 0x0105
    assert root_icb["tag"]["crc_length"] == 168
    assert root_icb["descriptor_kind"] == "file_entry"
    assert root_icb["file_type_name"] == "directory"
    assert root_icb["allocation_descriptor_type"] == 0
    assert root_icb["allocation_descriptor_raw_hex"] == (
        _BLOCK_SIZE.to_bytes(4, "little")
        + (2).to_bytes(4, "little")
    ).hex()
    root_directory = file_set["root_directory"]
    assert root_directory["valid"] is True
    assert root_directory["allocation_descriptor_kind"] == "short_ad"
    assert root_directory["information_length"] == len(_root_directory())
    assert root_directory["allocated_length"] == _BLOCK_SIZE
    assert root_directory["bytes_read"] == len(_root_directory())
    assert root_directory["parent_record_valid"] is True
    assert root_directory["entry_count"] == 7
    (
        parent,
        child,
        subdirectory_fid,
        sparse_fid,
        inline_fid,
        extended_fid,
        extended_sparse_fid,
    ) = root_directory["entries"]
    assert parent["parent"] is True
    assert parent["directory"] is True
    assert parent["file_identifier"]["text"] == ".."
    assert parent["tag"]["crc_length"] == parent["record_length"] - 16
    assert parent["tag"]["location"] == 2
    assert parent["source_segments"][0]["offset"] == 402 * _BLOCK_SIZE
    assert child["file_identifier"] == {
        "text": "README.TXT",
        "compression_id": 8,
        "raw_hex": (b"\x08README.TXT").hex(),
        "path_safe": True,
        "valid": True,
    }
    assert child["resolved_icb"]["offset"] == 403 * _BLOCK_SIZE
    assert child["padding_raw_hex"] == "000000"
    assert subdirectory_fid["file_identifier"]["text"] == "SUBDIR"
    assert subdirectory_fid["directory"] is True
    assert sparse_fid["file_identifier"]["text"] == "SPARSE.BIN"
    assert inline_fid["file_identifier"]["text"] == "INLINE.TXT"
    assert extended_fid["file_identifier"]["text"] == "EXTENDED.BIN"
    assert extended_sparse_fid["file_identifier"]["text"] == (
        "EXT-SPARSE.BIN"
    )
    child_inventory = root_directory["child_icbs"]
    assert child_inventory["valid"] is True
    assert child_inventory["unique_icb_count"] == 6
    assert child_inventory["active_fid_count"] == 6
    child_icb = child_inventory["children"][0]
    assert child_icb["valid"] is True
    assert child_icb["fid_indices"] == [1]
    assert child_icb["relationships"][0]["valid"] is True
    assert child_icb["icb"]["file_type_name"] == "regular_file"
    assert child_icb["icb"]["tag"]["crc_length"] == 168
    child_allocation = child_icb["icb"][
        "allocation_descriptor_metadata"
    ]
    assert child_allocation["valid"] is True
    assert child_allocation["kind"] == "short_ad"
    assert child_allocation["descriptor_count"] == 1
    assert child_allocation["descriptors"][0]["resolved"]["offset"] == (
        404 * _BLOCK_SIZE
    )
    assert root_directory["directory_count"] == 2
    assert root_directory["tree_entry_count"] == 10
    assert root_directory["tree_bytes_read"] == (
        len(_root_directory()) + len(_subdirectory())
    )
    assert root_directory["tree_errors"] == []
    parsed_subdirectory = root_directory["subdirectories"][0]
    assert parsed_subdirectory["valid"] is True
    assert parsed_subdirectory["directory_index"] == 1
    assert parsed_subdirectory["parent_directory_index"] == 0
    assert parsed_subdirectory["path_components"] == ["SUBDIR"]
    assert parsed_subdirectory["parent_record_valid"] is True
    assert parsed_subdirectory["parent_record"]["icb_address"][
        "logical_block_number"
    ] == 1
    nested_fid = parsed_subdirectory["entries"][1]
    assert nested_fid["file_identifier"]["text"] == "NESTED.TXT"
    assert nested_fid["source_segments"][0]["offset"] > 406 * _BLOCK_SIZE
    nested_icb = parsed_subdirectory["child_icbs"]["children"][0]
    assert nested_icb["icb"]["tag"]["location"] == 7
    assert nested_icb["icb"]["file_type_name"] == "regular_file"
    deleted_fid = parsed_subdirectory["entries"][2]
    assert deleted_fid["valid"] is True
    assert deleted_fid["deleted"] is True
    assert deleted_fid["icb_address"]["valid"] is False
    assert deleted_fid["child_icb_status"] == "deleted_not_followed"
    assert parsed_subdirectory["child_icbs"][
        "deleted_fids_not_followed"
    ] == 1
    sparse_icb = child_inventory["children"][2]["icb"]
    sparse_allocation = sparse_icb["allocation_descriptor_metadata"]
    assert sparse_allocation["valid"] is True
    assert [
        item["address"]["extent_type"]
        for item in sparse_allocation["descriptors"]
    ] == [0, 2]
    inline_icb = child_inventory["children"][3]["icb"]
    assert inline_icb["allocation_descriptor_metadata"]["kind"] == (
        "embedded_data"
    )
    assert inline_icb["allocation_descriptor_metadata"][
        "embedded_sha256"
    ] == hashlib.sha256(b"INLINE-UDF-DATA").hexdigest()
    extended_icb = child_inventory["children"][4]["icb"]
    extended_allocation = extended_icb["allocation_descriptor_metadata"]
    assert extended_allocation["kind"] == "extended_ad"
    assert extended_allocation["valid"] is True
    assert extended_allocation["descriptors"][0]["address"][
        "recorded_length"
    ] == len(b"EXTENDED-AD-DATA")
    extended_sparse_allocation = child_inventory["children"][5]["icb"][
        "allocation_descriptor_metadata"
    ]
    assert extended_sparse_allocation["valid"] is True
    assert [
        (
            item["address"]["extent_type"],
            item["address"]["recorded_length"],
            item["address"]["information_length"],
        )
        for item in extended_sparse_allocation["descriptors"]
    ] == [
        (0, _BLOCK_SIZE, _BLOCK_SIZE),
        (2, 0, _BLOCK_SIZE),
    ]
    assert values["archive.udf.file_set_errors"] == []
    assert values["archive.udf.errors"] == []
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(
        item.category == "archive_udf_metadata"
        and item.severity == "info"
        for item in profile.findings
    )
    assert any(
        item.category == "archive_udf_file_set_metadata"
        and item.severity == "info"
        for item in profile.findings
    )

    long_ad_evidence = tmp_path / "long-ad-root.udf"
    long_ad_evidence.write_bytes(_udf_image(
        root_allocation_descriptor_type=1,
    ))
    long_ad_values = _values(GenericTriageEngine().analyze(
        _artifact(long_ad_evidence), long_ad_evidence,
    ))
    assert long_ad_values["archive.udf.valid"] is True
    assert long_ad_values["archive.udf.file_set"]["root_directory"][
        "allocation_descriptor_kind"
    ] == "long_ad"

    bounded_values = _values(UdfObservationEngine(
        max_directory_entries=8,
    ).analyze(artifact, evidence))
    bounded_root = bounded_values["archive.udf.file_set"]["root_directory"]
    assert bounded_values["archive.udf.valid"] is False
    assert bounded_root["tree_entry_count"] == 8
    assert "directory_tree_entry_limit" in bounded_root[
        "subdirectories"
    ][0]["failed_checks"]

    extended_child_evidence = tmp_path / "extended-child-icb.udf"
    extended_child_evidence.write_bytes(_udf_image(child_icb_extended=True))
    extended_child_values = _values(GenericTriageEngine().analyze(
        _artifact(extended_child_evidence), extended_child_evidence,
    ))
    extended_child = extended_child_values[
        "archive.udf.file_set"
    ]["root_directory"]["child_icbs"]["children"][0]
    assert extended_child_values["archive.udf.valid"] is True
    assert extended_child["icb"]["descriptor_kind"] == "extended_file_entry"
    assert extended_child["icb"]["object_size"] == len(
        b"ForensicKit UDF child metadata only\n"
    )
    assert extended_child["icb"]["tag"]["crc_length"] == 208

    for descriptor_type, expected_kind in (
        (1, "long_ad"),
        (2, "extended_ad"),
        (3, "embedded_data"),
    ):
        allocation_evidence = tmp_path / f"child-{expected_kind}.udf"
        allocation_evidence.write_bytes(_udf_image(
            child_allocation_descriptor_type=descriptor_type,
        ))
        allocation_values = _values(GenericTriageEngine().analyze(
            _artifact(allocation_evidence), allocation_evidence,
        ))
        allocation_child = allocation_values[
            "archive.udf.file_set"
        ]["root_directory"]["child_icbs"]["children"][0]
        assert allocation_values["archive.udf.valid"] is True
        assert allocation_child["icb"][
            "allocation_descriptor_metadata"
        ]["kind"] == expected_kind


def test_udf_crc_corruption_and_reserve_semantic_divergence_are_anomalies(
    tmp_path: Path,
) -> None:
    corrupt = tmp_path / "bad-crc.udf"
    corrupt.write_bytes(_udf_image(corrupt_main_lvd_crc=True))
    corrupt_artifact = _artifact(corrupt)
    corrupt_observations = GenericTriageEngine().analyze(
        corrupt_artifact, corrupt,
    )
    corrupt_values = _values(corrupt_observations)
    main_lvd = corrupt_values[
        "archive.udf.main_volume_descriptor_sequence"
    ]["descriptors"][2]
    assert corrupt_values["archive.udf.detected"] is True
    assert corrupt_values["archive.udf.valid"] is False
    assert main_lvd["tag"]["checksum_valid"] is True
    assert main_lvd["tag"]["crc_valid"] is False
    corrupt_profile = ProfileEngine().evaluate(
        corrupt_artifact, corrupt_observations,
    )
    assert any(
        item.category == "udf_structure_anomaly"
        and "invalid_descriptor_tag" in " ".join(item.supporting_evidence)
        for item in corrupt_profile.findings
    )

    bad_checksum = tmp_path / "bad-tag-checksum.udf"
    bad_checksum.write_bytes(_udf_image(corrupt_main_pvd_checksum=True))
    bad_checksum_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_checksum), bad_checksum,
    ))
    bad_pvd = bad_checksum_values[
        "archive.udf.main_volume_descriptor_sequence"
    ]["descriptors"][0]
    assert bad_pvd["tag"]["checksum_valid"] is False
    assert bad_pvd["tag"]["crc_valid"] is True
    assert bad_checksum_values["archive.udf.valid"] is False

    short_crc = tmp_path / "short-crc-coverage.udf"
    short_crc.write_bytes(_udf_image(short_main_pvd_crc=True))
    short_crc_values = _values(GenericTriageEngine().analyze(
        _artifact(short_crc), short_crc,
    ))
    short_pvd = short_crc_values[
        "archive.udf.main_volume_descriptor_sequence"
    ]["descriptors"][0]
    assert short_pvd["tag"]["checksum_valid"] is True
    assert short_pvd["tag"]["crc_valid"] is True
    assert short_pvd["expected_crc_length"] == 496
    assert short_pvd["crc_coverage_valid"] is False
    assert short_crc_values["archive.udf.valid"] is False

    bad_file_set = tmp_path / "bad-file-set-crc.udf"
    bad_file_set.write_bytes(_udf_image(corrupt_file_set_crc=True))
    bad_file_set_artifact = _artifact(bad_file_set)
    bad_file_set_observations = GenericTriageEngine().analyze(
        bad_file_set_artifact, bad_file_set,
    )
    bad_file_set_values = _values(bad_file_set_observations)
    assert bad_file_set_values[
        "archive.udf.main_volume_descriptor_sequence"
    ]["valid"] is True
    assert bad_file_set_values["archive.udf.file_set"]["valid"] is False
    assert bad_file_set_values["archive.udf.file_set"]["tag"][
        "crc_valid"
    ] is False
    assert bad_file_set_values["archive.udf.valid"] is False
    assert any(
        item["reason"] == "invalid_file_set_descriptor_tag"
        for item in bad_file_set_values["archive.udf.file_set_errors"]
    )

    bad_root = tmp_path / "root-is-regular-file.udf"
    bad_root.write_bytes(_udf_image(root_file_type=5))
    bad_root_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_root), bad_root,
    ))
    assert bad_root_values["archive.udf.file_set"]["valid"] is False
    assert bad_root_values["archive.udf.file_set"]["root_icb"]["tag"][
        "crc_valid"
    ] is True
    assert any(
        item["reason"] == "root_icb_not_directory"
        for item in bad_root_values["archive.udf.file_set_errors"]
    )

    bad_fid = tmp_path / "bad-root-fid-crc.udf"
    bad_fid.write_bytes(_udf_image(corrupt_root_fid_crc=True))
    bad_fid_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_fid), bad_fid,
    ))
    bad_directory = bad_fid_values["archive.udf.file_set"]["root_directory"]
    assert bad_fid_values["archive.udf.valid"] is False
    assert bad_directory["valid"] is False
    assert bad_directory["entries"][1]["tag"]["crc_valid"] is False
    assert "descriptor_tag" in bad_directory["entries"][1][
        "failed_checks"
    ]

    bad_parent = tmp_path / "bad-root-parent-fid.udf"
    bad_parent.write_bytes(_udf_image(parent_icb_location=5))
    bad_parent_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_parent), bad_parent,
    ))
    bad_parent_directory = bad_parent_values[
        "archive.udf.file_set"
    ]["root_directory"]
    assert bad_parent_values["archive.udf.valid"] is False
    assert bad_parent_directory["parent_record_valid"] is False
    assert "parent_icb_address" in bad_parent_directory["entries"][0][
        "failed_checks"
    ]

    bad_location = tmp_path / "bad-fid-tag-location.udf"
    bad_location.write_bytes(_udf_image(child_fid_tag_location=3))
    bad_location_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_location), bad_location,
    ))
    bad_location_entry = bad_location_values[
        "archive.udf.file_set"
    ]["root_directory"]["entries"][1]
    assert bad_location_values["archive.udf.valid"] is False
    assert bad_location_entry["tag"]["checksum_valid"] is True
    assert bad_location_entry["tag"]["crc_valid"] is True
    assert bad_location_entry["tag"]["location_valid"] is False

    bad_padding = tmp_path / "bad-fid-padding.udf"
    bad_padding.write_bytes(_udf_image(child_fid_padding_byte=0xA5))
    bad_padding_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_padding), bad_padding,
    ))
    bad_padding_entry = bad_padding_values[
        "archive.udf.file_set"
    ]["root_directory"]["entries"][1]
    assert bad_padding_entry["tag"]["valid"] is True
    assert "descriptor_padding" in bad_padding_entry["failed_checks"]
    assert bad_padding_values["archive.udf.valid"] is False

    unsafe_name = tmp_path / "unsafe-fid-name.udf"
    unsafe_name.write_bytes(_udf_image(child_fid_name="../README.TXT"))
    unsafe_name_values = _values(GenericTriageEngine().analyze(
        _artifact(unsafe_name), unsafe_name,
    ))
    unsafe_name_entry = unsafe_name_values[
        "archive.udf.file_set"
    ]["root_directory"]["entries"][1]
    assert unsafe_name_entry["tag"]["valid"] is True
    assert unsafe_name_entry["file_identifier"]["path_safe"] is False
    assert "file_identifier" in unsafe_name_entry["failed_checks"]
    assert unsafe_name_values["archive.udf.valid"] is False

    bad_child_crc = tmp_path / "bad-child-icb-crc.udf"
    bad_child_crc.write_bytes(_udf_image(corrupt_child_icb_crc=True))
    bad_child_crc_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_child_crc), bad_child_crc,
    ))
    bad_child = bad_child_crc_values[
        "archive.udf.file_set"
    ]["root_directory"]["child_icbs"]["children"][0]
    assert bad_child_crc_values["archive.udf.valid"] is False
    assert bad_child["icb"]["tag"]["checksum_valid"] is True
    assert bad_child["icb"]["tag"]["crc_valid"] is False
    assert any(
        item["reason"] == "invalid_icb_descriptor_tag"
        for item in bad_child["errors"]
    )

    child_type_mismatch = tmp_path / "child-type-mismatch.udf"
    child_type_mismatch.write_bytes(_udf_image(child_icb_file_type=4))
    child_type_values = _values(GenericTriageEngine().analyze(
        _artifact(child_type_mismatch), child_type_mismatch,
    ))
    child_type = child_type_values[
        "archive.udf.file_set"
    ]["root_directory"]["child_icbs"]["children"][0]
    assert child_type["icb"]["tag"]["valid"] is True
    assert child_type["relationships"][0]["valid"] is False
    assert "directory_file_type" in child_type["relationships"][0][
        "failed_checks"
    ]
    assert child_type_values["archive.udf.valid"] is False

    bad_subdirectory_parent = tmp_path / "bad-subdirectory-parent.udf"
    bad_subdirectory_parent.write_bytes(_udf_image(
        subdirectory_parent_icb_location=5,
    ))
    bad_subdirectory_parent_values = _values(GenericTriageEngine().analyze(
        _artifact(bad_subdirectory_parent), bad_subdirectory_parent,
    ))
    bad_subdirectory = bad_subdirectory_parent_values[
        "archive.udf.file_set"
    ]["root_directory"]["subdirectories"][0]
    assert bad_subdirectory_parent_values["archive.udf.valid"] is False
    assert bad_subdirectory["parent_record_valid"] is False
    assert "parent_icb_address" in bad_subdirectory["entries"][0][
        "failed_checks"
    ]

    root_cycle = tmp_path / "root-directory-cycle.udf"
    root_cycle.write_bytes(_udf_image(include_root_directory_cycle=True))
    root_cycle_values = _values(GenericTriageEngine().analyze(
        _artifact(root_cycle), root_cycle,
    ))
    root_cycle_directory = root_cycle_values[
        "archive.udf.file_set"
    ]["root_directory"]
    assert root_cycle_values["archive.udf.valid"] is False
    assert any(
        item["reason"] == "shared_or_cyclic_directory_icb"
        for item in root_cycle_directory["tree_errors"]
    )

    divergent = tmp_path / "divergent-reserve.udf"
    divergent.write_bytes(_udf_image(reserve_access_type=2))
    divergent_artifact = _artifact(divergent)
    divergent_observations = GenericTriageEngine().analyze(
        divergent_artifact, divergent,
    )
    divergent_values = _values(divergent_observations)
    comparison = divergent_values["archive.udf.volume_descriptor_comparison"]
    assert divergent_values["archive.udf.valid"] is False
    assert divergent_values[
        "archive.udf.main_volume_descriptor_sequence"
    ]["valid"] is True
    assert divergent_values[
        "archive.udf.reserve_volume_descriptor_sequence"
    ]["valid"] is True
    assert comparison["consistent"] is False
    assert "descriptor_bodies" in comparison["failed_checks"]
    assert "partitions" in comparison["failed_checks"]
    assert any(
        item["reason"] == "main_reserve_volume_descriptor_mismatch"
        for item in divergent_values["archive.udf.errors"]
    )


def test_udf_partial_vrs_is_recognized_and_engine_report_retains_metadata(
    tmp_path: Path,
) -> None:
    incomplete = tmp_path / "incomplete-vrs.udf"
    incomplete.write_bytes(_udf_image(omit_terminating_vrs=True))
    incomplete_artifact = _artifact(incomplete)
    incomplete_observations = GenericTriageEngine().analyze(
        incomplete_artifact, incomplete,
    )
    incomplete_values = _values(incomplete_observations)
    assert incomplete_values["triage.detected_header_format"] == "udf"
    assert incomplete_values["archive.udf.detected"] is True
    assert incomplete_values["archive.udf.valid"] is False
    assert any(
        item["reason"] == "tea01_not_found"
        for item in incomplete_values["archive.udf.errors"]
    )

    evidence = tmp_path / "engine.udf"
    evidence.write_bytes(_udf_image())
    result = AnalysisEngine().analyze(
        evidence,
        tmp_path / "udf-cases",
        mode=AnalysisMode.AUTO,
        execute=False,
    )
    assert [item.logical_name for item in result.artifacts] == [
        "engine.udf",
        "README.TXT",
        "SPARSE.BIN",
        "INLINE.TXT",
        "EXTENDED.BIN",
        "EXT-SPARSE.BIN",
        "SUBDIR/NESTED.TXT",
    ]
    assert result.artifacts[0].artifact_type == "archive"
    case_root = next((tmp_path / "udf-cases").glob("*/case.db")).parent
    assert (case_root / result.artifacts[1].path).read_bytes() == (
        b"ForensicKit UDF child metadata only\n"
    )
    sparse_payload = (case_root / result.artifacts[2].path).read_bytes()
    assert sparse_payload[:len(b"SPARSE-RECORDED")] == b"SPARSE-RECORDED"
    assert sparse_payload[len(b"SPARSE-RECORDED"):_BLOCK_SIZE] == (
        b"\xA5" * (_BLOCK_SIZE - len(b"SPARSE-RECORDED"))
    )
    assert sparse_payload[_BLOCK_SIZE:] == b"\x00" * _BLOCK_SIZE
    assert (case_root / result.artifacts[3].path).read_bytes() == (
        b"INLINE-UDF-DATA"
    )
    assert (case_root / result.artifacts[4].path).read_bytes() == (
        b"EXTENDED-AD-DATA"
    )
    extended_sparse_payload = (
        case_root / result.artifacts[5].path
    ).read_bytes()
    assert extended_sparse_payload == (
        b"X" * _BLOCK_SIZE + b"\x00" * _BLOCK_SIZE
    )
    assert (case_root / result.artifacts[6].path).read_bytes() == (
        b"Nested UDF metadata remains unmaterialized\n"
    )
    assert any(
        item.category == "archive_udf_metadata"
        and item.source == "profile:archive"
        for item in result.findings
    )
    assert any(
        item.category == "archive_udf_file_set_metadata"
        and item.source == "profile:archive"
        for item in result.findings
    )
    assert any(
        item.category == "archive_udf_extraction"
        and item.source == "builtin_udf_extractor"
        and "fid_source_segments" in item.supporting_evidence[0]
        and any("'kind': 'zero'" in value for value in item.supporting_evidence)
        and any("'kind': 'embedded'" in value for value in item.supporting_evidence)
        for item in result.findings
    )
    report = next(
        (tmp_path / "udf-cases").glob("*/reports/report.json")
    ).read_text(encoding="utf-8")
    assert '"archive.udf.active_anchor"' in report
    assert '"archive.udf.volume_descriptor_comparison"' in report
    assert '"archive_udf_metadata"' in report
    assert '"archive_udf_file_set_metadata"' in report
    assert '"archive_udf_extraction"' in report
    assert "FORENSICKIT-UDF" in report
    assert "README.TXT" in report
    assert "SPARSE.BIN" in report
    assert "INLINE.TXT" in report
    assert "EXTENDED.BIN" in report
    assert "EXT-SPARSE.BIN" in report
    assert "NESTED.TXT" in report


def test_hybrid_iso_udf_keeps_iso_primary_and_validates_udf_metadata(
    tmp_path: Path,
) -> None:
    image = bytearray(_udf_image(vrs_start=24))
    iso = _iso9660_with_root_file(b"FLAG.TXT;1", b"hybrid")
    image[:len(iso)] = iso
    evidence = tmp_path / "hybrid.iso"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)

    assert identified.format == "iso9660"
    assert values["triage.detected_header_format"] == "iso9660"
    assert values["archive.container_kind"] == "iso9660"
    assert values["archive.iso9660.signature"] is True
    assert values["archive.udf.detected"] is True
    assert values["archive.udf.valid"] is True
    assert values["archive.udf.volume_recognition_sequence"][
        "begin_index"
    ] == 8
    assert any(
        item.category == "archive_udf_metadata"
        for item in ProfileEngine().evaluate(artifact, observations).findings
    )


def test_udf_extractor_rejects_changed_source_extent(tmp_path: Path) -> None:
    evidence = tmp_path / "immutable.udf"
    evidence.write_bytes(_udf_image())
    config = ForensicKitConfig()
    with CaseWorkspace.create(
        tmp_path / "cases", "udf-immutable", config,
    ) as workspace:
        artifact = EvidenceManager(workspace).ingest(evidence)
        stored = workspace.resolve_stored_path(artifact.path)
        observations = GenericTriageEngine(config.limits).analyze(
            artifact, stored,
        )
        workspace.database.add_observations(observations)
        stored.chmod(0o644)
        with stored.open("r+b") as stream:
            stream.seek(404 * _BLOCK_SIZE)
            original = stream.read(1)
            stream.seek(404 * _BLOCK_SIZE)
            stream.write(bytes([original[0] ^ 0x01]))
        stored.chmod(0o444)

        extracted = ExtractionManager(
            workspace, config.limits,
        ).extract_udf(artifact)

        assert extracted.artifacts == []
        assert extracted.findings == []
        assert extracted.errors == [
            "UDF source hash no longer matches artifact provenance"
        ]


def test_udf_extended_ad_compression_is_metadata_only(tmp_path: Path) -> None:
    evidence = tmp_path / "compressed-extended.udf"
    evidence.write_bytes(_udf_image(compressed_extended_file=True))
    config = ForensicKitConfig()
    with CaseWorkspace.create(
        tmp_path / "cases", "udf-compressed-extended", config,
    ) as workspace:
        artifact = EvidenceManager(workspace).ingest(evidence)
        stored = workspace.resolve_stored_path(artifact.path)
        observations = GenericTriageEngine(config.limits).analyze(
            artifact, stored,
        )
        values = _values(observations)
        workspace.database.add_observations(observations)

        extended_icb = values["archive.udf.file_set"][
            "root_directory"
        ]["child_icbs"]["children"][4]["icb"]
        extended_address = extended_icb[
            "allocation_descriptor_metadata"
        ]["descriptors"][0]["address"]
        assert values["archive.udf.valid"] is True
        assert extended_address["recorded_length"] == 8
        assert extended_address["information_length"] == len(
            b"EXTENDED-AD-DATA"
        )

        extracted = ExtractionManager(
            workspace, config.limits,
        ).extract_udf(artifact)

        assert [item.logical_name for item in extracted.artifacts] == [
            "README.TXT",
            "SPARSE.BIN",
            "INLINE.TXT",
            "EXT-SPARSE.BIN",
            "SUBDIR/NESTED.TXT",
        ]
        assert any(
            "EXTENDED.BIN" in error
            and "extended_recorded_information_length" in error
            for error in extracted.errors
        )


def test_udf_allocation_extent_chain_has_exact_provenance_and_engine_extracts(
    tmp_path: Path,
) -> None:
    payload = _udf_image(include_allocation_extent_file=True)
    evidence = tmp_path / "allocation-chain.udf"
    evidence.write_bytes(payload)
    artifact = _artifact(evidence)
    values = _values(GenericTriageEngine().analyze(artifact, evidence))

    assert values["archive.udf.valid"] is True
    root = values["archive.udf.file_set"]["root_directory"]
    chained = root["child_icbs"]["children"][6]
    allocation = chained["icb"]["allocation_descriptor_metadata"]
    assert allocation["valid"] is True
    assert allocation["chain_complete"] is True
    assert allocation["descriptor_count"] == 3
    assert allocation["total_descriptor_count"] == 5
    assert allocation["continuation_descriptor_count"] == 2
    assert allocation["allocation_extent_count"] == 2
    assert [
        (item["source_kind"], item["source_extent_index"])
        for item in allocation["descriptors"]
    ] == [("icb", None), ("allocation_extent", 0), ("allocation_extent", 1)]
    assert [
        item["address"]["logical_block_number"]
        for item in allocation["descriptors"]
    ] == [18, 19, 0]
    first, second = allocation["allocation_extents"]
    assert first["offset"] == 420 * _BLOCK_SIZE
    assert first["length"] == _BLOCK_SIZE
    assert first["raw_sha256"] == hashlib.sha256(
        payload[420 * _BLOCK_SIZE:421 * _BLOCK_SIZE]
    ).hexdigest()
    assert first["tag"]["identifier"] == 0x0102
    assert first["tag"]["checksum_valid"] is True
    assert first["tag"]["crc_valid"] is True
    assert first["tag"]["location_valid"] is True
    assert first["tag"]["crc_length"] == 24
    assert first["previous_allocation_extent_location"] == 0
    assert first["expected_previous_allocation_extent_location"] == 0
    assert second["previous_allocation_extent_location"] == 20
    assert second["expected_previous_allocation_extent_location"] == 20
    assert second["tag"]["crc_length"] == 16

    result = AnalysisEngine().analyze(
        evidence,
        tmp_path / "engine-chain-cases",
        mode=AnalysisMode.AUTO,
        execute=False,
    )
    chained_artifact = next(
        item for item in result.artifacts
        if item.logical_name == "CHAINED.BIN"
    )
    case_root = next(
        (tmp_path / "engine-chain-cases").glob("*/case.db")
    ).parent
    assert (case_root / chained_artifact.path).read_bytes() == (
        b"A" * _BLOCK_SIZE
        + b"B" * _BLOCK_SIZE
        + b"\x00" * _BLOCK_SIZE
    )
    finding = next(
        item for item in result.findings
        if item.category == "archive_udf_extraction"
    )
    assert any(
        "CHAINED.BIN" in item and "allocation_extents" in item
        for item in finding.supporting_evidence
    )
    for descriptor_type, expected_kind, descriptor_size in (
        (1, "long_ad", 16),
        (2, "extended_ad", 20),
    ):
        alternate = tmp_path / f"allocation-chain-{expected_kind}.udf"
        alternate.write_bytes(_udf_image(
            include_allocation_extent_file=True,
            allocation_extent_descriptor_type=descriptor_type,
        ))
        alternate_values = _values(GenericTriageEngine().analyze(
            _artifact(alternate), alternate,
        ))
        alternate_allocation = alternate_values[
            "archive.udf.file_set"
        ]["root_directory"]["child_icbs"]["children"][6]["icb"][
            "allocation_descriptor_metadata"
        ]
        assert alternate_values["archive.udf.valid"] is True
        assert alternate_allocation["valid"] is True
        assert alternate_allocation["kind"] == expected_kind
        assert alternate_allocation["descriptor_size"] == descriptor_size
        assert alternate_allocation["continuation_descriptor_count"] == 2
        assert alternate_allocation["allocation_extent_count"] == 2
        alternate_case_root_parent = (
            tmp_path / f"engine-chain-{expected_kind}-cases"
        )
        alternate_result = AnalysisEngine().analyze(
            alternate,
            alternate_case_root_parent,
            mode=AnalysisMode.AUTO,
            execute=False,
        )
        alternate_child = next(
            item for item in alternate_result.artifacts
            if item.logical_name == "CHAINED.BIN"
        )
        alternate_case_root = next(
            alternate_case_root_parent.glob("*/case.db")
        ).parent
        assert (alternate_case_root / alternate_child.path).read_bytes() == (
            b"A" * _BLOCK_SIZE
            + b"B" * _BLOCK_SIZE
            + b"\x00" * _BLOCK_SIZE
        )


def test_udf_allocation_extent_chain_full_range_is_immutably_revalidated(
    tmp_path: Path,
) -> None:
    payload = _udf_image(include_allocation_extent_file=True)
    evidence = tmp_path / "allocation-chain-revalidation.udf"
    evidence.write_bytes(payload)
    artifact = _artifact(evidence)
    values = _values(GenericTriageEngine().analyze(artifact, evidence))
    config = ForensicKitConfig()
    with CaseWorkspace.create(
        tmp_path / "revalidation-cases", "udf-aed-revalidation", config,
    ) as workspace:
        manager = ExtractionManager(workspace, config.limits)
        file_set = values["archive.udf.file_set"]
        metadata_ranges = manager._udf_metadata_ranges(values, file_set)
        candidate = next(
            item for item in manager._udf_regular_file_candidates(
                file_set, metadata_ranges, len(payload),
            )
            if item["logical_name"] == "CHAINED.BIN"
        )
        assert candidate["extraction_eligible"] is True
        manager._revalidate_udf_candidate(io.BytesIO(payload), candidate)

        changed = bytearray(payload)
        changed[420 * _BLOCK_SIZE + 128] = 0xA5
        try:
            manager._revalidate_udf_candidate(io.BytesIO(changed), candidate)
        except RuntimeError as exc:
            assert str(exc) == (
                "allocation extent no longer matches triage provenance"
            )
        else:
            raise AssertionError("mutated AED slack passed immutable revalidation")


def test_udf_directory_allocation_extent_chain_drives_tree_traversal(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "directory-allocation-chain.udf"
    evidence.write_bytes(_udf_image(
        root_directory_allocation_extent=True,
        subdirectory_allocation_extent=True,
    ))
    values = _values(GenericTriageEngine().analyze(
        _artifact(evidence), evidence,
    ))

    assert values["archive.udf.valid"] is True
    directory = values["archive.udf.file_set"]["root_directory"]
    chain = directory["allocation_descriptor_chain"]
    assert directory["valid"] is True
    assert directory["entry_count"] == 7
    assert chain["valid"] is True
    assert chain["chain_complete"] is True
    assert chain["continuation_descriptor_count"] == 1
    assert chain["allocation_extent_count"] == 1
    assert chain["allocation_extents"][0]["offset"] == 423 * _BLOCK_SIZE
    assert directory["extents"][0]["source_kind"] == "allocation_extent"
    assert directory["extents"][0]["source_extent_index"] == 0
    assert directory["entries"][1]["file_identifier"]["text"] == (
        "README.TXT"
    )
    assert directory["tree_allocation_extent_count"] == 2
    assert directory["tree_allocation_extent_bytes_read"] == 2 * _BLOCK_SIZE
    subdirectory = directory["subdirectories"][0]
    assert subdirectory["valid"] is True
    assert subdirectory["allocation_descriptor_chain"][
        "allocation_extent_count"
    ] == 1
    assert subdirectory["extents"][0]["source_kind"] == (
        "allocation_extent"
    )
    assert subdirectory["extents"][0]["source_extent_index"] == 0


def test_udf_malformed_allocation_extent_chains_remain_metadata_only(
    tmp_path: Path,
) -> None:
    for fault, expected_check in (
        ("identifier", "allocation_extent_descriptor_identifier"),
        ("checksum", "allocation_extent_descriptor_tag"),
        ("crc", "allocation_extent_descriptor_tag"),
        ("tag_location", "allocation_extent_descriptor_tag"),
        ("previous_pointer", "previous_allocation_extent_location"),
        ("cycle", "allocation_extent_cycle"),
        ("incomplete", "allocation_extent_descriptor_tag"),
        ("limit", "allocation_extent_limit"),
    ):
        evidence = tmp_path / f"allocation-chain-{fault}.udf"
        evidence.write_bytes(_udf_image(
            include_allocation_extent_file=True,
            allocation_extent_fault=fault,
        ))
        values = _values(GenericTriageEngine().analyze(
            _artifact(evidence), evidence,
        ))
        allocation = values["archive.udf.file_set"]["root_directory"][
            "child_icbs"
        ]["children"][6]["icb"]["allocation_descriptor_metadata"]
        retained_checks = list(allocation["failed_checks"])
        for extent in allocation["allocation_extents"]:
            retained_checks.extend(extent["failed_checks"])
        for descriptor in allocation["continuation_descriptors"]:
            retained_checks.extend(descriptor["failed_checks"])
        assert values["archive.udf.valid"] is False
        assert allocation["valid"] is False
        assert allocation["chain_complete"] is False
        assert expected_check in retained_checks
        assert allocation["continuation_descriptor_count"] >= 1

    engine_evidence = tmp_path / "allocation-chain-engine-malformed.udf"
    engine_evidence.write_bytes(_udf_image(
        include_allocation_extent_file=True,
        allocation_extent_fault="crc",
    ))
    result = AnalysisEngine().analyze(
        engine_evidence,
        tmp_path / "malformed-chain-cases",
        mode=AnalysisMode.AUTO,
        execute=False,
    )
    assert [item.logical_name for item in result.artifacts] == [
        "allocation-chain-engine-malformed.udf"
    ]
    report = next(
        (tmp_path / "malformed-chain-cases").glob("*/reports/report.json")
    ).read_text(encoding="utf-8")
    assert "CHAINED.BIN" in report
    assert "allocation_extent_descriptor_tag" in report
