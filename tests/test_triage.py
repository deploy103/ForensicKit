from __future__ import annotations

import binascii
import hashlib
import struct
import zipfile
import tarfile
import io
import plistlib
import sqlite3
import uuid
import zlib
from pathlib import Path

from forensickit.config import AnalysisLimits
from forensickit.engine import AnalysisEngine
from forensickit.identification import IdentificationEngine
from forensickit.models import AnalysisMode, Artifact
from forensickit.profiles import ProfileEngine
from forensickit.tools import parse_output
from forensickit.triage import GenericTriageEngine


def _artifact(path: Path, *, logical_name: str | None = None) -> Artifact:
    data = path.read_bytes()
    return Artifact(
        id="artifact-1",
        case_id="case-1",
        path=str(path),
        logical_name=logical_name or path.name,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def _values(observations):
    return {observation.key: observation.value for observation in observations}


def _png(chunks: list[tuple[bytes, bytes]]) -> bytes:
    result = bytearray(b"\x89PNG\r\n\x1a\n")
    for kind, payload in chunks:
        result.extend(struct.pack(">I", len(payload)))
        result.extend(kind)
        result.extend(payload)
        result.extend(struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF))
    return bytes(result)


def _cpio_newc_member(
    name: str,
    data: bytes = b"",
    *,
    mode: int = 0o100644,
    inode: int = 1,
    magic: bytes = b"070701",
    checksum: int | None = None,
) -> bytes:
    raw_name = name.encode("utf-8") + b"\x00"
    stored_checksum = (
        sum(data) & 0xFFFFFFFF if magic == b"070702" and checksum is None
        else 0 if checksum is None
        else checksum
    )
    fields = (
        inode, mode, 1000, 1000, 1, 1_700_000_000, len(data),
        0, 0, 0, 0, len(raw_name), stored_checksum,
    )
    header = magic + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    assert len(header) == 110
    result = bytearray(header)
    result.extend(raw_name)
    result.extend(b"\x00" * ((-len(result)) % 4))
    result.extend(data)
    result.extend(b"\x00" * ((-len(result)) % 4))
    return bytes(result)


def _cpio_newc_archive(*members: bytes, magic: bytes = b"070701") -> bytes:
    trailer = _cpio_newc_member(
        "TRAILER!!!", mode=0, inode=len(members) + 1, magic=magic,
    )
    return b"".join((*members, trailer))


def _cpio_odc_member(
    name: str,
    data: bytes = b"",
    *,
    mode: int = 0o100644,
    inode: int = 1,
    device: int = 0o12,
    rdevice: int = 0,
) -> bytes:
    raw_name = name.encode("utf-8") + b"\x00"
    header = (
        b"070707"
        + f"{device:06o}{inode:06o}{mode:06o}{1000:06o}{1000:06o}{1:06o}{rdevice:06o}"
        f"{1_700_000_000:011o}{len(raw_name):06o}{len(data):011o}".encode("ascii")
    )
    assert len(header) == 76
    result = bytearray(header)
    result.extend(raw_name)
    result.extend(b"\x00" * ((-len(result)) % 2))
    result.extend(data)
    result.extend(b"\x00" * ((-len(result)) % 2))
    return bytes(result)


def test_png_appended_zip_is_observed_and_classified(tmp_path: Path) -> None:
    zip_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("flag.txt", "Q1RGe2RldGVybWluaXN0aWN9")
    clean_png = _png(
        [
            (b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)),
            (b"IDAT", b""),
            (b"IEND", b""),
        ]
    )
    evidence = tmp_path / "challenge.dat"
    evidence.write_bytes(clean_png + zip_path.read_bytes())
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    result = IdentificationEngine().identify(artifact, observations)

    assert values["artifact.size"] == evidence.stat().st_size
    assert values["png.iend_found"] is True
    assert values["png.bytes_after_iend"] == zip_path.stat().st_size
    assert values["embedded.pk_signature"] is True
    assert values["embedded.zip.offsets"][0] == len(clean_png)
    assert values["extension.mismatch"] is True
    assert result.format == "png"
    assert artifact.artifact_type == "image"
    assert [item.artifact_type for item in result.classifications] == [
        "image",
        "archive",
        "steganography",
    ]
    assert "archive" in result.profiles
    assert "steganography" in result.profiles


def test_strings_entropy_scope_and_offsets_are_bounded(tmp_path: Path) -> None:
    evidence = tmp_path / "strings.bin"
    data = (
        b"\x00\x01HELLO_ASCII\x00"
        + "HELLO_UTF16_LE".encode("utf-16-le")
        + b"\xff\xfe"
        + "HELLO_UTF16_BE".encode("utf-16-be")
        + bytes(range(256)) * 16
    )
    evidence.write_bytes(data)
    artifact = _artifact(evidence)
    limits = AnalysisLimits(max_string_scan_bytes=1024, signature_scan_bytes=1024)

    values = _values(
        GenericTriageEngine(limits, entropy_scan_bytes=512).analyze(artifact, evidence)
    )

    assert values["entropy.scope"] == "sample"
    assert values["entropy.bytes_sampled"] <= 512
    assert values["strings.scope"] == "sample"
    assert values["strings.bytes_scanned"] <= 1024
    assert values["strings.ascii.count"] >= 1
    all_string_samples = (
        values["strings.ascii.samples"]
        + values["strings.utf16le.samples"]
        + values["strings.utf16be.samples"]
    )
    assert all(isinstance(item["offset"], int) for item in all_string_samples)
    assert any("HELLO" in item["text"] for item in all_string_samples)


def test_ooxml_container_identification_uses_entry_structure(tmp_path: Path) -> None:
    evidence = tmp_path / "renamed.bin"
    with zipfile.ZipFile(evidence, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr("word/document.xml", "<document />")
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().triage(artifact, evidence)
    values = _values(observations)
    result = IdentificationEngine().classify(artifact, observations)

    assert values["archive.zip.ooxml_kind"] == "docx"
    assert values["archive.container_kind"] == "docx"
    assert values["embedded.pk_signature"] is False
    assert result.format == "docx"
    assert result.primary.artifact_type == "office"
    assert artifact.mime.endswith("wordprocessingml.document")
    assert [item.artifact_type for item in result.classifications] == [
        "office",
        "archive",
    ]
    normalized = _values(result.observations)
    assert normalized["artifact.format"] == "docx"
    assert normalized["artifact.profile"] == "office"
    assert normalized["artifact.profiles"] == ["generic", "office", "archive"]


def test_jpeg_eoi_trailer_and_extension_mismatch(tmp_path: Path) -> None:
    evidence = tmp_path / "photo.png"
    jpeg = b"\xff\xd8\xff\xe0" + b"JFIF\x00" + b"payload" + b"\xff\xd9"
    evidence.write_bytes(jpeg + b"TRAILER")
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    result = IdentificationEngine().identify(artifact, observations)

    assert values["jpeg.eoi_found"] is True
    assert values["jpeg.bytes_after_eoi"] == len(b"TRAILER")
    assert values["extension.mismatch"] is True
    assert result.format == "jpeg"
    assert "steganography" in [item.artifact_type for item in result.classifications]


def test_valid_pe_requires_pe_signature_not_only_mz(tmp_path: Path) -> None:
    evidence = tmp_path / "program.exe"
    body = bytearray(512)
    body[:2] = b"MZ"
    body[0x3C:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\x00\x00"
    evidence.write_bytes(body)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    result = IdentificationEngine().identify(artifact, observations)

    assert values["executable.pe.valid_signature"] is True
    assert result.format == "pe"
    assert result.primary.artifact_type == "executable"


def test_invalid_mz_offset_remains_unknown_binary(tmp_path: Path) -> None:
    evidence = tmp_path / "not-really.exe"
    body = bytearray(b"MZ" + b"\x00" * 126)
    body[0x3C:0x40] = (0x7FFFFFFF).to_bytes(4, "little")
    evidence.write_bytes(body)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    result = IdentificationEngine().identify(artifact, observations)

    assert values["triage.detected_header_format"] == "unknown"
    assert values["executable.pe.valid_signature"] is False
    assert result.format == "unknown_binary"


def test_registry_root_value_inventory_uses_vk_flags_and_never_reads_value_data(tmp_path: Path) -> None:
    """A minimal allocated REGF layout exposes VK metadata at bounded offsets."""
    hive = bytearray(8192)
    hive[:4] = b"regf"
    hive[4:8] = (7).to_bytes(4, "little")
    hive[8:12] = (7).to_bytes(4, "little")
    hive[36:40] = (0x20).to_bytes(4, "little")
    hive[40:44] = (4096).to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4100:4104] = (0).to_bytes(4, "little")
    hive[4104:4108] = (4096).to_bytes(4, "little")

    root = 4096 + 0x20
    hive[root:root + 4] = (-88).to_bytes(4, "little", signed=True)
    hive[root + 4:root + 6] = b"nk"
    hive[root + 6:root + 8] = (0x20).to_bytes(2, "little")  # compressed key name
    hive[root + 24:root + 28] = (1).to_bytes(4, "little")
    hive[root + 32:root + 36] = (0xC0).to_bytes(4, "little")
    hive[root + 40:root + 44] = (1).to_bytes(4, "little")
    hive[root + 44:root + 48] = (0x80).to_bytes(4, "little")
    hive[root + 76:root + 78] = (4).to_bytes(2, "little")
    hive[root + 80:root + 84] = b"ROOT"

    value_list = 4096 + 0x80
    hive[value_list:value_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[value_list + 4:value_list + 8] = (0xA0).to_bytes(4, "little")
    value = 4096 + 0xA0
    hive[value:value + 4] = (-32).to_bytes(4, "little", signed=True)
    hive[value + 4:value + 6] = b"vk"
    hive[value + 6:value + 8] = (3).to_bytes(2, "little")
    hive[value + 8:value + 12] = (12).to_bytes(4, "little")
    hive[value + 12:value + 16] = (0xFFFFFF00).to_bytes(4, "little")  # deliberately untrusted data pointer
    hive[value + 16:value + 20] = (1).to_bytes(4, "little")  # REG_SZ
    hive[value + 20:value + 22] = (1).to_bytes(2, "little")  # compressed name flag
    hive[value + 24:value + 27] = b"Run"

    subkey_list = 4096 + 0xC0
    hive[subkey_list:subkey_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[subkey_list + 4:subkey_list + 6] = b"li"
    hive[subkey_list + 6:subkey_list + 8] = (1).to_bytes(2, "little")
    hive[subkey_list + 8:subkey_list + 12] = (0xE0).to_bytes(4, "little")
    child = 4096 + 0xE0
    hive[child:child + 4] = (-96).to_bytes(4, "little", signed=True)
    hive[child + 4:child + 6] = b"nk"
    hive[child + 6:child + 8] = (0x20).to_bytes(2, "little")
    hive[child + 24:child + 28] = (2).to_bytes(4, "little")
    hive[child + 40:child + 44] = (3).to_bytes(4, "little")
    hive[child + 76:child + 78] = (3).to_bytes(2, "little")
    hive[child + 80:child + 83] = b"Run"

    evidence = tmp_path / "fixture.regf"
    evidence.write_bytes(hive)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["registry.root_value_names"] == ["Run"]
    assert values["registry.root_subkey_names"] == ["Run"]
    assert values["registry.root_subkeys"] == [{
        "name": "Run", "offset": 0xE0, "last_write_time": None,
        "subkey_count": 2, "subkey_list_offset": 0, "value_count": 3, "value_list_offset": 0,
    }]
    assert values["registry.root_value_list_error"] is None
    assert values["registry.root_values"] == [{
        "name": "Run", "type": "REG_SZ", "type_code": 1,
        "data_size": 12, "data_inline": False,
    }]


def test_minidump_system_and_module_metadata_are_boundedly_recovered(tmp_path: Path) -> None:
    dump = bytearray(512)
    dump[:4] = b"MDMP"
    dump[8:12] = (2).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 7, 32, 64)  # SystemInfoStream
    dump[44:56] = struct.pack("<III", 4, 112, 96)  # ModuleListStream
    dump[64:66] = (9).to_bytes(2, "little")  # AMD64
    dump[70] = 4
    dump[71] = 1
    dump[72:76] = (10).to_bytes(4, "little")
    dump[76:80] = (0).to_bytes(4, "little")
    dump[80:84] = (19045).to_bytes(4, "little")
    dump[84:88] = (2).to_bytes(4, "little")
    dump[88:92] = (208).to_bytes(4, "little")
    dump[96:100] = (1).to_bytes(4, "little")
    module = 100
    dump[module:module + 8] = (0x7FF600000000).to_bytes(8, "little")
    dump[module + 8:module + 12] = (0x123000).to_bytes(4, "little")
    dump[module + 16:module + 20] = (123456789).to_bytes(4, "little")
    dump[module + 24:module + 28] = (220).to_bytes(4, "little")
    dump[208:212] = (6).to_bytes(4, "little")
    dump[212:218] = "SP0".encode("utf-16le")
    module_name = r"C:\\Windows\\System32\\kernel32.dll".encode("utf-16le")
    dump[220:224] = len(module_name).to_bytes(4, "little")
    dump[224:224 + len(module_name)] = module_name
    evidence = tmp_path / "sample.dmp"
    evidence.write_bytes(dump)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["memory.minidump_valid"] is True
    assert values["memory.minidump.system_info"]["architecture"] == "x64"
    assert values["memory.minidump.system_info"]["build_number"] == 19045
    assert values["memory.minidump.system_info"]["service_pack"] == "SP0"
    assert values["memory.minidump.modules"] == [{
        "base_address": "0x7ff600000000", "image_size": 0x123000,
        "timestamp": 123456789, "name": r"C:\\Windows\\System32\\kernel32.dll",
    }]


def test_minidump_thread_and_memory_range_descriptors_are_bounded(tmp_path: Path) -> None:
    dump = bytearray(256)
    dump[:4] = b"MDMP"
    dump[8:12] = (2).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 3, 52, 64)  # ThreadListStream
    dump[44:56] = struct.pack("<III", 5, 20, 116)  # MemoryListStream
    dump[64:68] = (1).to_bytes(4, "little")
    thread = 68
    dump[thread:thread + 4] = (1337).to_bytes(4, "little")
    dump[thread + 4:thread + 8] = (2).to_bytes(4, "little")
    dump[thread + 8:thread + 12] = (8).to_bytes(4, "little")
    dump[thread + 12:thread + 16] = (-1).to_bytes(4, "little", signed=True)
    dump[thread + 16:thread + 24] = (0x7FFDE000).to_bytes(8, "little")
    dump[thread + 24:thread + 32] = (0x100000).to_bytes(8, "little")
    dump[thread + 32:thread + 36] = (16).to_bytes(4, "little")
    dump[thread + 36:thread + 40] = (160).to_bytes(4, "little")
    dump[thread + 40:thread + 44] = (8).to_bytes(4, "little")
    dump[thread + 44:thread + 48] = (176).to_bytes(4, "little")
    dump[116:120] = (1).to_bytes(4, "little")
    dump[120:128] = (0x400000).to_bytes(8, "little")
    dump[128:132] = (12).to_bytes(4, "little")
    dump[132:136] = (192).to_bytes(4, "little")
    evidence = tmp_path / "threads.dmp"
    evidence.write_bytes(dump)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["memory.minidump.thread_count"] == 1
    assert values["memory.minidump.threads"] == [{
        "thread_id": 1337, "suspend_count": 2, "priority_class": 8, "priority": -1,
        "teb": "0x7ffde000", "stack_start": "0x100000", "stack_size": 16,
        "stack_rva": 160, "stack_within_image": True, "context_size": 8,
        "context_rva": 176, "context_within_image": True,
    }]
    assert values["memory.minidump.memory_ranges"] == [{
        "start": "0x400000", "size": 12, "rva": 192, "within_image": True,
    }]


def test_minidump_exception_and_memory64_descriptors_are_bounded(tmp_path: Path) -> None:
    dump = bytearray(512)
    dump[:4] = b"MDMP"
    dump[8:12] = (2).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 6, 168, 64)  # ExceptionStream
    dump[44:56] = struct.pack("<III", 9, 32, 240)  # Memory64ListStream
    dump[64:68] = (4242).to_bytes(4, "little")
    dump[72:76] = (0xC0000005).to_bytes(4, "little")
    dump[76:80] = (1).to_bytes(4, "little")
    dump[88:96] = (0x7FF612341000).to_bytes(8, "little")
    dump[96:100] = (2).to_bytes(4, "little")
    dump[224:228] = (16).to_bytes(4, "little")
    dump[228:232] = (480).to_bytes(4, "little")
    dump[240:248] = (1).to_bytes(8, "little")
    dump[248:256] = (400).to_bytes(8, "little")
    dump[256:264] = (0x1400000).to_bytes(8, "little")
    dump[264:272] = (12).to_bytes(8, "little")
    evidence = tmp_path / "exception-memory64.dmp"
    evidence.write_bytes(dump)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["memory.minidump.exception"] == {
        "thread_id": 4242, "code": "0xc0000005", "name": "access_violation",
        "flags": 1, "address": "0x7ff612341000", "parameter_count": 2,
        "context_size": 16, "context_rva": 480, "context_within_image": True,
    }
    assert values["memory.minidump.memory64_ranges"] == [{
        "start": "0x1400000", "size": 12, "rva": 400, "within_image": True,
    }]


def test_minidump_memory_info_protection_metadata_reaches_memory_profile(tmp_path: Path) -> None:
    dump = bytearray(256)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 16, 64, 64)  # MemoryInfoListStream
    dump[64:68] = (16).to_bytes(4, "little")
    dump[68:72] = (48).to_bytes(4, "little")
    dump[72:80] = (1).to_bytes(8, "little")
    entry = 80
    dump[entry:entry + 8] = (0x7FF600000000).to_bytes(8, "little")
    dump[entry + 8:entry + 16] = (0x7FF600000000).to_bytes(8, "little")
    dump[entry + 24:entry + 32] = (0x2000).to_bytes(8, "little")
    dump[entry + 32:entry + 36] = (0x1000).to_bytes(4, "little")
    dump[entry + 36:entry + 40] = (0x40).to_bytes(4, "little")
    dump[entry + 40:entry + 44] = (0x2000000).to_bytes(4, "little")
    evidence = tmp_path / "memory-info.dmp"
    evidence.write_bytes(dump)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["memory.minidump.memory_info_ranges"] == [{
        "base_address": "0x7ff600000000", "allocation_base": "0x7ff600000000",
        "size": 0x2000, "state": "commit", "protect": "execute_readwrite", "type": "private",
    }]
    assert any(finding.category == "memory_rwx_lead" for finding in profile.findings)


def test_minidump_handle_and_unloaded_module_metadata_are_bounded(tmp_path: Path) -> None:
    dump = bytearray(1024)
    dump[:4] = b"MDMP"
    dump[8:12] = (2).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 12, 48, 64)  # HandleDataStream
    dump[44:56] = struct.pack("<III", 14, 32, 160)  # UnloadedModuleListStream
    dump[64:80] = struct.pack("<IIII", 16, 32, 1, 0)
    dump[80:88] = (0xABC).to_bytes(8, "little")
    dump[88:92] = (256).to_bytes(4, "little")
    dump[92:96] = (288).to_bytes(4, "little")
    dump[96:100] = (2).to_bytes(4, "little")
    dump[100:104] = (0x12019F).to_bytes(4, "little")
    dump[104:108] = (1).to_bytes(4, "little")
    dump[108:112] = (2).to_bytes(4, "little")
    dump[160:168] = struct.pack("<II", 1, 24)
    dump[168:176] = (0x7FF60000).to_bytes(8, "little")
    dump[176:180] = (0x4000).to_bytes(4, "little")
    dump[180:184] = (0xAABBCCDD).to_bytes(4, "little")
    dump[184:188] = (1_700_000_000).to_bytes(4, "little")
    dump[188:192] = (384).to_bytes(4, "little")
    for rva, text in {
        256: "File",
        288: r"C:\\Users\\ctf\\Downloads\\payload.dll",
        384: r"C:\\Users\\ctf\\AppData\\Local\\Temp\\removed.dll",
    }.items():
        encoded = text.encode("utf-16le")
        dump[rva:rva + 4] = len(encoded).to_bytes(4, "little")
        dump[rva + 4:rva + 4 + len(encoded)] = encoded
    evidence = tmp_path / "handles.dmp"
    evidence.write_bytes(dump)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["memory.minidump.handles"] == [{
        "handle": "0xabc", "type_name": "File", "object_name": r"C:\\Users\\ctf\\Downloads\\payload.dll",
        "attributes": "0x00000002", "granted_access": "0x0012019f", "handle_count": 1, "pointer_count": 2,
    }]
    assert values["memory.minidump.unloaded_modules"] == [{
        "base_address": "0x7ff60000", "image_size": 0x4000, "checksum": "0xaabbccdd",
        "timestamp": 1_700_000_000, "name": r"C:\\Users\\ctf\\AppData\\Local\\Temp\\removed.dll",
    }]
    categories = {finding.category for finding in profile.findings}
    assert {"memory_handle_lead", "memory_unloaded_module_lead"} <= categories


def test_minidump_misc_process_metadata_reaches_memory_profile(tmp_path: Path) -> None:
    dump = bytearray(128)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = struct.pack("<III", 15, 24, 64)  # MiscInfoStream
    dump[64:68] = (24).to_bytes(4, "little")
    dump[68:72] = (1).to_bytes(4, "little")
    dump[72:76] = (4242).to_bytes(4, "little")
    dump[76:80] = (1_700_000_000).to_bytes(4, "little")
    dump[80:84] = (3).to_bytes(4, "little")
    dump[84:88] = (4).to_bytes(4, "little")
    evidence = tmp_path / "misc.dmp"
    evidence.write_bytes(dump)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["memory.minidump.misc_info"] == {
        "size": 24, "flags": "0x00000001", "process_id": 4242,
        "process_create_time": "2023-11-14T22:13:20+00:00",
        "process_user_time_seconds": 3, "process_kernel_time_seconds": 4, "size_valid": True,
    }
    assert any(finding.category == "memory_minidump_process_metadata" for finding in profile.findings)


def test_ios_backup_info_plist_is_parsed_and_classified_without_extension_trust(tmp_path: Path) -> None:
    evidence = tmp_path / "Info.bin"
    evidence.write_bytes(plistlib.dumps({
        "Product Version": "17.5",
        "Unique Identifier": "offline-device-id",
        "Device Name": "CTF iPhone",
        "Last Backup Date": "2026-08-26",
    }, fmt=plistlib.FMT_BINARY))
    artifact = _artifact(evidence, logical_name="Info.plist")

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)

    assert values["plist.parsed"] is True
    assert values["mobile.ios_backup_info_plist"] is True
    assert values["plist.scalar_metadata"]["Device Name"] == "CTF iPhone"
    assert identified.format == "ios_backup_info"
    assert artifact.artifact_type == "ios"


def test_ios_manifest_files_are_sampled_with_fixed_readonly_columns(tmp_path: Path) -> None:
    evidence = tmp_path / "Manifest.db"
    connection = sqlite3.connect(evidence)
    try:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        connection.execute("CREATE TABLE Properties (key TEXT, value BLOB)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
            ("a" * 40, "HomeDomain", "Library/Preferences/com.ctf.flag.plist", 1, b"opaque"),
        )
        connection.commit()
    finally:
        connection.close()
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)

    assert values["mobile.ios_manifest_detected"] is True
    assert values["mobile.ios_manifest_domain_counts"] == [{"domain": "HomeDomain", "sample_count": 1}]
    assert values["mobile.ios_manifest_file_samples"] == [{
        "file_id": "a" * 40, "domain": "HomeDomain",
        "relative_path": "Library/Preferences/com.ctf.flag.plist", "flags": "1",
    }]
    assert identified.format == "ios_backup_manifest"


def test_apk_structure_routes_to_android_decompiler_plan(tmp_path: Path) -> None:
    evidence = tmp_path / "challenge.bin"
    with zipfile.ZipFile(evidence, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        archive.writestr("classes.dex", b"dex\n035\x00")
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert identified.format == "apk"
    assert artifact.artifact_type == "android"
    recommendations = {item.tool: item for item in profile.recommendations}
    assert set(recommendations) >= {"jadx", "apktool"}
    assert recommendations["jadx"].allows("auto")
    assert recommendations["apktool"].allows("deep")


def test_plaintext_apk_manifest_permission_metadata_reaches_mobile_profile(tmp_path: Path) -> None:
    evidence = tmp_path / "manifest.apk"
    with zipfile.ZipFile(evidence, "w") as archive:
        archive.writestr("AndroidManifest.xml", """<?xml version='1.0'?>
            <manifest xmlns:android='http://schemas.android.com/apk/res/android'
             package='org.ctf.challenge' android:versionName='1.2' android:versionCode='12'>
              <uses-sdk android:minSdkVersion='23' android:targetSdkVersion='34'/>
              <uses-permission android:name='android.permission.SEND_SMS'/>
              <uses-permission android:name='android.permission.INTERNET'/>
            </manifest>""")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/payload.so", b"\x7fELF")
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["android.apk.manifest_format"] == "xml"
    assert values["android.apk.package_name"] == "org.ctf.challenge"
    assert values["android.apk.sdk"] == {"min_sdk": "23", "target_sdk": "34"}
    assert values["android.apk.suspicious_permissions"] == ["android.permission.SEND_SMS"]
    assert values["android.apk.native_libraries"] == ["lib/arm64-v8a/payload.so"]
    assert {finding.category for finding in profile.findings} >= {
        "android_apk_metadata", "android_apk_permission_lead",
    }


def test_qpdf_parser_normalizes_structural_check_failure() -> None:
    parsed = parse_output(
        "qpdf", artifact_id="artifact-1", tool="qpdf", exit_code=2,
        stdout="checking broken.pdf\nWARNING: file is damaged\n",
        stderr="qpdf: operation succeeded with errors\n",
    )
    values = _values(parsed.observations)

    assert values["pdf.qpdf.check_status"] == "error"
    assert [finding.category for finding in parsed.findings] == ["pdf_structure_anomaly"]


def test_fsstat_parser_normalizes_filesystem_type_and_metadata() -> None:
    parsed = parse_output(
        "sleuthkit_fsstat", artifact_id="artifact-1", tool="sleuthkit_fsstat",
        stdout="FILE SYSTEM INFORMATION\nFile System Type: NTFS\nVolume Serial Number: 1234-ABCD\n",
    )
    values = _values(parsed.observations)

    assert values["filesystem.fsstat.type"] == "NTFS"
    assert values["filesystem.fsstat.metadata"]["volume serial number"] == "1234-ABCD"


def test_ewfinfo_parser_normalizes_media_size_and_segments() -> None:
    parsed = parse_output(
        "ewfinfo", artifact_id="artifact-1", tool="ewfinfo",
        stdout="""EWF information
Media information:
        Media size: 1.0 GiB (1073741824 bytes)
        Number of segments: 3
""",
    )
    values = _values(parsed.observations)

    assert values["disk.ewf.media_size_bytes"] == 1_073_741_824
    assert values["disk.ewf.segment_count"] == 3


def test_readelf_parser_normalizes_loader_metadata_and_relative_runpath() -> None:
    parsed = parse_output(
        "readelf", artifact_id="artifact-1", tool="readelf",
        stdout="""Dynamic section at offset 0x2 contains 2 entries:
 0x0000000000000001 (NEEDED)             Shared library: [libcurl.so.4]
 0x000000000000001d (RUNPATH)            Library runpath: [.:/opt/ctf/lib]
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RWE 0x10
""",
    )
    values = _values(parsed.observations)

    assert values["executable.readelf.needed_libraries"] == ["libcurl.so.4"]
    assert values["executable.readelf.search_paths"] == [".:/opt/ctf/lib"]
    assert values["executable.readelf.interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert values["executable.readelf.executable_stack"] is True
    assert [finding.category for finding in parsed.findings] == ["executable_loader_path_lead"]


def test_vhd_footer_and_qcow2_header_route_to_virtual_disk_triage(tmp_path: Path) -> None:
    vhd = bytearray(1024)
    footer = memoryview(vhd)[512:]
    footer[:8] = b"conectix"
    footer[8:12] = (2).to_bytes(4, "big")
    footer[12:16] = (0x00010000).to_bytes(4, "big")
    footer[16:24] = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    footer[40:48] = (4096).to_bytes(8, "big")
    footer[48:56] = (4096).to_bytes(8, "big")
    footer[60:64] = (2).to_bytes(4, "big")
    footer[68:84] = b"\x01" * 16
    checksum_bytes = bytearray(footer)
    checksum_bytes[64:68] = b"\x00" * 4
    footer[64:68] = ((~sum(checksum_bytes)) & 0xFFFFFFFF).to_bytes(4, "big")
    vhd_path = tmp_path / "disk.vhd"
    vhd_path.write_bytes(vhd)
    vhd_observations = GenericTriageEngine().analyze(_artifact(vhd_path), vhd_path)
    vhd_values = _values(vhd_observations)
    assert vhd_values["disk.vhd.footer"]["valid"] is True
    assert IdentificationEngine().identify(_artifact(vhd_path), vhd_observations).format == "vhd"

    qcow = bytearray(512)
    qcow[:4] = b"QFI\xfb"
    qcow[4:8] = (3).to_bytes(4, "big")
    qcow[20:24] = (16).to_bytes(4, "big")
    qcow[24:32] = (16 * 1024 * 1024).to_bytes(8, "big")
    qcow[36:40] = (1).to_bytes(4, "big")
    qcow[40:48] = (72).to_bytes(8, "big")
    qcow_path = tmp_path / "disk.qcow2"
    qcow_path.write_bytes(qcow)
    qcow_observations = GenericTriageEngine().analyze(_artifact(qcow_path), qcow_path)
    qcow_values = _values(qcow_observations)
    assert qcow_values["disk.qcow2.header"]["valid"] is True
    assert IdentificationEngine().identify(_artifact(qcow_path), qcow_observations).format == "qcow2"


def test_isobmff_atom_and_movie_header_inventory(tmp_path: Path) -> None:
    ftyp = struct.pack(">I4s4sI4s", 20, b"ftyp", b"isom", 0, b"isom")
    mvhd_body = b"\x00\x00\x00\x00" + b"\x00" * 8 + (1000).to_bytes(4, "big") + (2500).to_bytes(4, "big")
    mvhd = struct.pack(">I4s", 8 + len(mvhd_body), b"mvhd") + mvhd_body
    moov = struct.pack(">I4s", 8 + len(mvhd), b"moov") + mvhd
    evidence = tmp_path / "movie.bin"
    evidence.write_bytes(ftyp + moov)

    observations = GenericTriageEngine().analyze(_artifact(evidence), evidence)
    values = _values(observations)

    assert values["media.format"] == "isobmff"
    assert values["media.isobmff.atom_types"] == ["ftyp", "moov"]
    assert values["media.isobmff.structure_valid"] is True
    assert values["media.isobmff.movie_header"] == {
        "version": 0, "valid": True, "timescale": 1000,
        "duration_units": 2500, "duration_seconds": 2.5,
    }


def test_wav_riff_info_metadata_is_boundedly_recovered(tmp_path: Path) -> None:
    fmt = b"fmt " + (16).to_bytes(4, "little") + struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    comment = b"CTF metadata\x00"
    info_payload = b"INFO" + b"ICMT" + len(comment).to_bytes(4, "little") + comment
    info_payload += b"\x00" if len(comment) & 1 else b""
    info = b"LIST" + len(info_payload).to_bytes(4, "little") + info_payload
    body = b"WAVE" + fmt + info
    evidence = tmp_path / "audio.bin"
    evidence.write_bytes(b"RIFF" + len(body).to_bytes(4, "little") + body)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert values["media.format"] == "wav"
    assert values["media.wav.structure_valid"] is True
    assert values["media.wav.info_tags"] == {"ICMT": "CTF metadata"}
    assert any(finding.title == "WAV LIST/INFO metadata recovered" for finding in profile.findings)


def test_matroska_ebml_info_metadata_is_boundedly_recovered(tmp_path: Path) -> None:
    def element(identifier: bytes, payload: bytes) -> bytes:
        assert len(payload) < 127
        return identifier + bytes([0x80 | len(payload)]) + payload

    info = (
        element(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big"))
        + element(b"\x44\x89", struct.pack(">d", 3.5))
        + element(b"\x7b\xa9", b"CTF movie")
        + element(b"\x4d\x80", b"offline-muxer")
    )
    segment = element(b"\x18\x53\x80\x67", element(b"\x15\x49\xa9\x66", info))
    evidence = tmp_path / "movie.bin"
    evidence.write_bytes(element(b"\x1a\x45\xdf\xa3", b"") + segment)

    observations = GenericTriageEngine().analyze(_artifact(evidence), evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(_artifact(evidence), observations)
    profile = ProfileEngine().evaluate(_artifact(evidence), [*observations, *identified.observations])

    assert values["media.format"] == "matroska"
    assert values["media.matroska.structure_valid"] is True
    assert values["media.matroska.info"] == {
        "timecode_scale": 1_000_000, "duration": 3.5, "title": "CTF movie",
        "muxing_app": "offline-muxer", "duration_seconds": 0.0035,
    }
    assert any(finding.category == "media_metadata" for finding in profile.findings)


def test_avi_riff_main_header_and_structure_are_boundedly_recovered(tmp_path: Path) -> None:
    avih = bytearray(56)
    avih[0:4] = (40_000).to_bytes(4, "little")
    avih[4:8] = (1_000_000).to_bytes(4, "little")
    avih[12:16] = (0x10).to_bytes(4, "little")
    avih[16:20] = (250).to_bytes(4, "little")
    avih[24:28] = (2).to_bytes(4, "little")
    avih[32:36] = (640).to_bytes(4, "little")
    avih[36:40] = (480).to_bytes(4, "little")
    avih_chunk = b"avih" + len(avih).to_bytes(4, "little") + bytes(avih)
    hdrl = b"LIST" + (4 + len(avih_chunk)).to_bytes(4, "little") + b"hdrl" + avih_chunk
    evidence = tmp_path / "movie.bin"
    evidence.write_bytes(b"RIFF" + (4 + len(hdrl)).to_bytes(4, "little") + b"AVI " + hdrl)

    observations = GenericTriageEngine().analyze(_artifact(evidence), evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(_artifact(evidence), observations)
    profile = ProfileEngine().evaluate(_artifact(evidence), [*observations, *identified.observations])

    assert values["media.format"] == "avi"
    assert values["media.avi.size_matches"] is True
    assert values["media.avi.structure_valid"] is True
    assert values["media.avi.main_header"] == {
        "microseconds_per_frame": 40_000, "max_bytes_per_second": 1_000_000,
        "flags": "0x00000010", "total_frames": 250, "stream_count": 2,
        "width": 640, "height": 480,
    }
    assert any(finding.category == "media_metadata" for finding in profile.findings)


def test_elf_program_headers_expose_interpreter_and_permission_leads(tmp_path: Path) -> None:
    elf = bytearray(512)
    elf[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    elf[16:64] = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    interpreter = b"/lib64/ld-linux-x86-64.so.2\x00"
    elf[64:120] = struct.pack("<IIQQQQQQ", 1, 7, 0x100, 0x400000, 0, 16, 16, 0x1000)
    elf[120:176] = struct.pack("<IIQQQQQQ", 3, 4, 0x120, 0, 0, len(interpreter), len(interpreter), 1)
    elf[176:232] = struct.pack("<IIQQQQQQ", 0x6474E551, 7, 0, 0, 0, 0, 0, 16)
    elf[0x120:0x120 + len(interpreter)] = interpreter
    evidence = tmp_path / "sample.elf"
    evidence.write_bytes(elf)

    observations = GenericTriageEngine().analyze(_artifact(evidence), evidence)
    values = _values(observations)

    assert values["executable.elf.header_valid"] is True
    assert values["executable.elf.interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert values["executable.elf.program_headers"][0]["writable"] is True
    assert values["executable.elf.program_headers"][2]["type"] == "gnu_stack"


def test_png_crc_failure_is_observed_natively(tmp_path: Path) -> None:
    data = bytearray(_png([
        (b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)),
        (b"IEND", b""),
    ]))
    data[-1] ^= 0x01
    evidence = tmp_path / "corrupt.png"
    evidence.write_bytes(data)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["png.crc_checked_chunk_count"] == 2
    assert values["png.crc_valid"] is False
    assert values["png.crc_failures"][0]["type"] == "IEND"


def test_gzip_optional_filename_and_comment_are_boundedly_observed(tmp_path: Path) -> None:
    evidence = tmp_path / "payload.gz"
    evidence.write_bytes(
        b"\x1f\x8b\x08\x18" + (1234).to_bytes(4, "little") + b"\x00\x03"
        + b"payload.tar\x00ctf archive\x00" + b"not-a-complete-deflate-stream"
    )
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["archive.gzip.original_name"] == "payload.tar"
    assert values["archive.gzip.comment"] == "ctf archive"
    assert values["archive.gzip.os"] == "unix"
    assert values["archive.gzip.header_complete"] is True


def test_jpeg_comment_and_app_marker_inventory(tmp_path: Path) -> None:
    comment = b"CTF{jpeg_comment}"
    jpeg = (
        b"\xff\xd8"
        + b"\xff\xe0\x00\x04JF"
        + b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment
        + b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x11\x00"
        + b"\xff\xd9"
    )
    evidence = tmp_path / "comment.jpg"
    evidence.write_bytes(jpeg)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["jpeg.comments"] == ["CTF{jpeg_comment}"]
    assert values["jpeg.app_marker_counts"] == {"APP0": 1}
    assert values["image.width"] == 1


def test_jpeg_app_segment_inventory_preserves_exif_xmp_icc_and_photoshop_provenance(tmp_path: Path) -> None:
    segments = [
        (0xE1, b"Exif\x00\x00II*\x00"),
        (0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta/>"),
        (0xE2, b"ICC_PROFILE\x00\x01\x01profile"),
        (0xED, b"Photoshop 3.0\x00resource"),
    ]
    jpeg = b"\xff\xd8" + b"".join(
        b"\xff" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload
        for marker, payload in segments
    ) + b"\xff\xd9"
    evidence = tmp_path / "metadata.jpg"
    evidence.write_bytes(jpeg)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert [item["kind"] for item in values["jpeg.app_segments"]] == ["exif", "xmp", "icc_profile", "photoshop_irb"]
    assert [item["offset"] for item in values["jpeg.app_segments"]] == [2, 16, 61, 86]
    assert values["jpeg.xmp_packets"] == [{"offset": 16, "text": "<x:xmpmeta/>"}]
    assert values["jpeg.icc_profile_chunks"] == [{"offset": 61, "sequence": 1, "count": 1, "payload_length": 7}]
    assert values["jpeg.icc_profile_valid"] is True


def test_jpeg_icc_chunk_sequence_validation_is_bounded() -> None:
    assert GenericTriageEngine._jpeg_icc_profile_error([
        {"offset": 2, "sequence": 1, "count": 2, "payload_length": 1},
        {"offset": 20, "sequence": 2, "count": 2, "payload_length": 1},
    ]) is None
    assert GenericTriageEngine._jpeg_icc_profile_error([
        {"offset": 2, "sequence": 1, "count": 2, "payload_length": 1},
        {"offset": 20, "sequence": 1, "count": 2, "payload_length": 1},
    ]) == "ICC_PROFILE contains duplicate chunk sequence numbers"


def test_jpeg_exif_tiff_scalar_metadata_is_bounded() -> None:
    tiff = bytearray(64)
    tiff[:2] = b"II"
    tiff[2:4] = (42).to_bytes(2, "little")
    tiff[4:8] = (8).to_bytes(4, "little")
    tiff[8:10] = (2).to_bytes(2, "little")
    tiff[10:12] = (0x0112).to_bytes(2, "little")
    tiff[12:14] = (3).to_bytes(2, "little")
    tiff[14:18] = (1).to_bytes(4, "little")
    tiff[18:20] = (6).to_bytes(2, "little")
    tiff[22:24] = (0x010F).to_bytes(2, "little")
    tiff[24:26] = (2).to_bytes(2, "little")
    tiff[26:30] = (4).to_bytes(4, "little")
    tiff[30:34] = b"CTF\x00"

    tags, error = GenericTriageEngine._jpeg_exif_tiff_tags(bytes(tiff))

    assert error is None
    assert tags == {"orientation": 6, "make": "CTF"}


def test_evtx_chunk_headers_are_inventoried_without_event_decoding(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[36:38] = (1).to_bytes(2, "little")
    data[38:40] = (3).to_bytes(2, "little")
    data[40:42] = (4096).to_bytes(2, "little")
    data[42:44] = (1).to_bytes(2, "little")
    chunk = 4096
    data[chunk:chunk + 8] = b"ElfChnk\x00"
    data[chunk + 8:chunk + 16] = (10).to_bytes(8, "little")
    data[chunk + 16:chunk + 24] = (12).to_bytes(8, "little")
    data[chunk + 24:chunk + 32] = (100).to_bytes(8, "little")
    data[chunk + 32:chunk + 40] = (102).to_bytes(8, "little")
    data[chunk + 40:chunk + 44] = (512).to_bytes(4, "little")
    data[chunk + 44:chunk + 48] = (544).to_bytes(4, "little")
    data[chunk + 48:chunk + 52] = (4096).to_bytes(4, "little")
    record = chunk + 512
    data[record:record + 4] = b"**\x00\x00"
    data[record + 4:record + 8] = (32).to_bytes(4, "little")
    data[record + 8:record + 16] = (101).to_bytes(8, "little")
    data[record + 16:record + 24] = (132271296000000000).to_bytes(8, "little")
    data[record + 28:record + 32] = (32).to_bytes(4, "little")
    evidence = tmp_path / "events.evtx"
    evidence.write_bytes(data)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["evtx.chunks_inspected"] == 1
    assert values["evtx.chunk_headers"] == [{
        "index": 0, "offset": 4096, "first_event_record_number": 10,
        "last_event_record_number": 12, "first_event_record_id": 100,
        "last_event_record_id": 102, "header_size": 512,
        "last_record_offset": 544, "free_space_offset": 4096, "layout_valid": True,
    }]
    assert values["evtx.record_headers"] == [{"chunk_index": 0, "offset": 4608, "size": 32, "record_id": 101, "timestamp": "2020-02-25T18:40:00+00:00"}]


def test_evtx_record_size_mirror_mismatch_isolated(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[40:42] = (4096).to_bytes(2, "little")
    data[42:44] = (1).to_bytes(2, "little")
    chunk = 4096
    data[chunk:chunk + 8] = b"ElfChnk\x00"
    data[chunk + 40:chunk + 44] = (512).to_bytes(4, "little")
    data[chunk + 44:chunk + 48] = (544).to_bytes(4, "little")
    data[chunk + 48:chunk + 52] = (4096).to_bytes(4, "little")
    record = chunk + 512
    data[record:record + 4] = b"**\x00\x00"
    data[record + 4:record + 8] = (32).to_bytes(4, "little")
    data[record + 28:record + 32] = (31).to_bytes(4, "little")
    evidence = tmp_path / "bad-record.evtx"
    evidence.write_bytes(data)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))
    assert values["evtx.record_headers"] == []
    assert values["evtx.record_header_errors"] == ["chunk 0: record size mirror mismatch at 512"]


def test_evtx_record_id_gap_is_boundedly_observed(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[40:42] = (4096).to_bytes(2, "little")
    data[42:44] = (1).to_bytes(2, "little")
    chunk = 4096
    data[chunk:chunk + 8] = b"ElfChnk\x00"
    data[chunk + 40:chunk + 44] = (512).to_bytes(4, "little")
    data[chunk + 44:chunk + 48] = (576).to_bytes(4, "little")
    data[chunk + 48:chunk + 52] = (4096).to_bytes(4, "little")
    for offset, record_id in ((512, 10), (544, 12)):
        record = chunk + offset
        data[record:record + 4] = b"**\x00\x00"
        data[record + 4:record + 8] = (32).to_bytes(4, "little")
        data[record + 8:record + 16] = record_id.to_bytes(8, "little")
        data[record + 28:record + 32] = (32).to_bytes(4, "little")
    evidence = tmp_path / "gap.evtx"
    evidence.write_bytes(data)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))
    assert values["evtx.record_id_gaps"] == [{"previous_record_id": 10, "record_id": 12, "previous_offset": 4608, "offset": 4640}]


def test_prefetch_header_size_and_hash_are_boundedly_recovered(tmp_path: Path) -> None:
    data = bytearray(0xE0)
    data[:4] = (30).to_bytes(4, "little")
    data[4:8] = b"SCCA"
    data[16:76] = "FLAGTOOL.EXE".encode("utf-16le").ljust(60, b"\x00")
    data[12:16] = len(data).to_bytes(4, "little")
    data[76:80] = (0xA1B2C3D4).to_bytes(4, "little")
    data[0xD0:0xD4] = (7).to_bytes(4, "little")
    evidence = tmp_path / "FLAGTOOL-12345678.pf"
    evidence.write_bytes(data)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))
    assert values["prefetch.declared_file_size"] == len(data)
    assert values["prefetch.size_matches_evidence"] is True
    assert values["prefetch.executable_hash"] == "A1B2C3D4"
    assert values["prefetch.run_count"] == 7


def test_tar_header_inventory_validates_member_checksum(tmp_path: Path) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("nested/flag.txt")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"flag"))
    evidence = tmp_path / "archive.tar"
    evidence.write_bytes(output.getvalue())
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["archive.tar.entries_inspected"] == 1
    assert values["archive.tar.entries"][0]["name"] == "nested/flag.txt"
    assert values["archive.tar.entries"][0]["checksum_valid"] is True
    assert values["archive.tar.invalid_checksums"] == []


def test_cpio_crc_entries_preserve_ranges_checksums_types_and_unsafe_paths(tmp_path: Path) -> None:
    magic = b"070702"
    directory = _cpio_newc_member("nested", mode=0o040755, inode=1, magic=magic)
    payload = b"CTF{cpio_triage}"
    regular = _cpio_newc_member(
        "nested/flag.txt", payload, mode=0o100640, inode=2, magic=magic,
    )
    symlink = _cpio_newc_member(
        "nested/link", b"../flag.txt", mode=0o120777, inode=3, magic=magic,
    )
    unsafe = _cpio_newc_member(
        "../escape.txt", b"unsafe", mode=0o100600, inode=4, magic=magic,
    )
    evidence = tmp_path / "initramfs.cpio"
    evidence.write_bytes(_cpio_newc_archive(
        directory, regular, symlink, unsafe, magic=magic,
    ))
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    identified = IdentificationEngine().identify(artifact, observations)

    assert identified.format == "cpio"
    assert artifact.artifact_type == "archive"
    assert values["archive.container_kind"] == "cpio"
    assert values["archive.cpio.formats"] == ["crc"]
    assert values["archive.cpio.format_consistent"] is True
    assert values["archive.cpio.entry_count"] == 4
    assert values["archive.cpio.trailer_found"] is True
    assert values["archive.cpio.trailer"]["valid_zero_length"] is True
    assert values["archive.cpio.complete"] is True
    assert values["archive.cpio.scan_truncated"] is False
    assert values["archive.cpio.structure_error"] is None
    assert values["archive.cpio.invalid_checksums"] == []
    entries = values["archive.cpio.entries"]
    assert [item["file_type"] for item in entries] == [
        "directory", "regular", "symlink", "regular",
    ]
    assert entries[1]["header_offset"] == len(directory)
    assert entries[1]["name_offset"] == len(directory) + 110
    assert entries[1]["data_offset"] % 4 == 0
    assert entries[1]["data_length"] == len(payload)
    assert entries[1]["permissions"] == "0o0640"
    assert entries[1]["stored_checksum"] == sum(payload)
    assert entries[1]["calculated_checksum"] == sum(payload)
    assert entries[1]["checksum_valid"] is True
    assert entries[1]["checksum_verification"] == "complete"
    assert entries[1]["path_safe"] is True
    assert entries[3]["path_safe"] is False
    assert values["archive.cpio.checksum_bytes_read"] == (
        len(payload) + len(b"../flag.txt") + len(b"unsafe")
    )

    profile = ProfileEngine().evaluate(artifact, observations)
    unsafe_finding = next(
        item for item in profile.findings
        if item.category == "archive_unsafe_member_path"
    )
    assert "../escape.txt" in unsafe_finding.supporting_evidence[0]
    assert not any(
        item.category == "archive_structure_anomaly"
        for item in profile.findings
    )

    bad_crc = tmp_path / "bad-crc.cpio"
    bad_crc.write_bytes(_cpio_newc_archive(
        _cpio_newc_member(
            "bad.bin", b"checksum", magic=magic, checksum=0,
        ),
        magic=magic,
    ))
    bad_artifact = _artifact(bad_crc)
    bad_observations = GenericTriageEngine().analyze(bad_artifact, bad_crc)
    bad_values = _values(bad_observations)
    assert bad_values["archive.cpio.entries"][0]["checksum_valid"] is False
    assert len(bad_values["archive.cpio.invalid_checksums"]) == 1
    bad_profile = ProfileEngine().evaluate(bad_artifact, bad_observations)
    anomaly = next(
        item for item in bad_profile.findings
        if item.category == "archive_structure_anomaly"
    )
    assert "'checksum_valid': False" in anomaly.supporting_evidence[0]

    newc = tmp_path / "plain-newc.cpio"
    newc.write_bytes(_cpio_newc_archive(
        _cpio_newc_member("plain.txt", b"newc", inode=1),
    ))
    newc_artifact = _artifact(newc)
    newc_observations = GenericTriageEngine().analyze(newc_artifact, newc)
    newc_values = _values(newc_observations)
    assert newc_values["archive.cpio.formats"] == ["newc"]
    assert newc_values["archive.cpio.complete"] is True
    assert newc_values["archive.cpio.entries"][0]["checksum_field_zero"] is True
    assert newc_values["archive.cpio.entries"][0]["checksum_valid"] is None
    assert newc_values["archive.cpio.entries"][0]["checksum_verification"] == "not_applicable"

    nonzero_newc = tmp_path / "nonzero-newc-check.cpio"
    nonzero_newc.write_bytes(_cpio_newc_archive(
        _cpio_newc_member("plain.txt", b"newc", inode=1, checksum=1),
    ))
    nonzero_artifact = _artifact(nonzero_newc)
    nonzero_observations = GenericTriageEngine().analyze(
        nonzero_artifact, nonzero_newc,
    )
    nonzero_values = _values(nonzero_observations)
    assert nonzero_values["archive.cpio.entries"][0]["checksum_field_zero"] is False
    nonzero_profile = ProfileEngine().evaluate(nonzero_artifact, nonzero_observations)
    assert any(
        item.category == "archive_structure_anomaly"
        for item in nonzero_profile.findings
    )

    odc_member = _cpio_odc_member(
        "ab", b"xyz", mode=0o100604, inode=7, device=0o12, rdevice=0o34,
    )
    odc = tmp_path / "portable-ascii.cpio"
    odc.write_bytes(odc_member + _cpio_odc_member(
        "TRAILER!!!", mode=0, inode=8,
    ))
    odc_artifact = _artifact(odc)
    odc_observations = GenericTriageEngine().analyze(odc_artifact, odc)
    odc_values = _values(odc_observations)
    assert IdentificationEngine().identify(odc_artifact, odc_observations).format == "cpio"
    assert odc_values["archive.cpio.formats"] == ["odc"]
    assert odc_values["archive.cpio.complete"] is True
    odc_record = odc_values["archive.cpio.entries"][0]
    assert odc_record["magic"] == "070707"
    assert odc_record["header_length"] == 76
    assert odc_record["numeric_encoding"] == "octal"
    assert odc_record["alignment"] == 2
    assert odc_record["name_offset"] == 76
    assert odc_record["name_padding_length"] == 1
    assert odc_record["data_offset"] == 80
    assert odc_record["data_length"] == 3
    assert odc_record["data_padding_length"] == 1
    assert odc_record["next_header_offset"] == len(odc_member)
    assert odc_record["inode"] == 7
    assert odc_record["permissions"] == "0o0604"
    assert odc_record["legacy_device"] == 0o12
    assert odc_record["legacy_rdevice"] == 0o34
    assert odc_record["device_major"] is None
    assert odc_record["stored_checksum"] is None
    assert odc_record["checksum_verification"] == "not_applicable"


def test_ntfs_mft_zero_fixed_header_is_observed_at_boot_geometry_offset(tmp_path: Path) -> None:
    image = bytearray(2048)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[64] = 0xF6  # -10 => 1024-byte file record
    image[510:512] = b"\x55\xaa"
    mft = 512
    image[mft:mft + 4] = b"FILE"
    image[mft + 4:mft + 6] = (48).to_bytes(2, "little")
    image[mft + 6:mft + 8] = (3).to_bytes(2, "little")
    image[mft + 16:mft + 18] = (1).to_bytes(2, "little")
    image[mft + 18:mft + 20] = (1).to_bytes(2, "little")
    image[mft + 20:mft + 22] = (56).to_bytes(2, "little")
    image[mft + 22:mft + 24] = (1).to_bytes(2, "little")
    image[mft + 24:mft + 28] = (512).to_bytes(4, "little")
    image[mft + 28:mft + 32] = (1024).to_bytes(4, "little")
    evidence = tmp_path / "volume.raw"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ntfs.mft0_offset"] == 512
    assert values["filesystem.ntfs.mft0_valid_signature"] is True
    assert values["filesystem.ntfs.mft0_bounds_valid"] is True


def test_ntfs_mft0_usa_fixup_and_nonresident_ads_data_run_are_bounded(tmp_path: Path) -> None:
    image = bytearray(2048)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[64] = 0xF6
    image[510:512] = b"\x55\xaa"
    mft = 512
    image[mft:mft + 4] = b"FILE"
    image[mft + 4:mft + 6] = (48).to_bytes(2, "little")
    image[mft + 6:mft + 8] = (3).to_bytes(2, "little")
    image[mft + 16:mft + 18] = (1).to_bytes(2, "little")
    image[mft + 18:mft + 20] = (1).to_bytes(2, "little")
    image[mft + 20:mft + 22] = (56).to_bytes(2, "little")
    image[mft + 22:mft + 24] = (1).to_bytes(2, "little")
    image[mft + 24:mft + 28] = (140).to_bytes(4, "little")
    image[mft + 28:mft + 32] = (1024).to_bytes(4, "little")
    image[mft + 48:mft + 50] = b"\xaa\xbb"
    image[mft + 50:mft + 52] = b"\x11\x22"
    image[mft + 52:mft + 54] = b"\x33\x44"
    image[mft + 510:mft + 512] = b"\xaa\xbb"
    image[mft + 1022:mft + 1024] = b"\xaa\xbb"
    attribute = mft + 56
    image[attribute:attribute + 4] = (0x80).to_bytes(4, "little")
    image[attribute + 4:attribute + 8] = (80).to_bytes(4, "little")
    image[attribute + 8] = 1
    image[attribute + 9] = 3
    image[attribute + 10:attribute + 12] = (64).to_bytes(2, "little")
    image[attribute + 14:attribute + 16] = (2).to_bytes(2, "little")
    image[attribute + 24:attribute + 32] = (1).to_bytes(8, "little")
    image[attribute + 32:attribute + 34] = (70).to_bytes(2, "little")
    image[attribute + 40:attribute + 48] = (1024).to_bytes(8, "little")
    image[attribute + 48:attribute + 56] = (900).to_bytes(8, "little")
    image[attribute + 64:attribute + 70] = "ads".encode("utf-16le")
    image[attribute + 70:attribute + 74] = b"\x11\x02\x05\x00"
    image[attribute + 80:attribute + 84] = (0xFFFFFFFF).to_bytes(4, "little")
    evidence = tmp_path / "ntfs.raw"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))
    assert values["filesystem.ntfs.mft0_usa_fixup_valid"] is True
    assert values["filesystem.ntfs.mft0_attributes"] == [{
        "offset": 56, "type": "0x80", "type_name": "data", "length": 80, "nonresident": True,
        "name": "ads", "attribute_id": 2, "attribute_flags": 0, "lowest_vcn": 0, "highest_vcn": 1,
        "allocated_size": 1024, "real_size": 900, "initialized_size": 0,
        "data_runs": [{"vcn": 0, "cluster_count": 2, "lcn": 5}],
    }]


def test_ntfs_data_run_parser_preserves_partial_metadata_and_reports_bad_bounds() -> None:
    attribute = bytearray(72)
    attribute[64:68] = b"\x11\x02\x05\xFF"  # valid run then an overlong truncated descriptor

    runs, error = GenericTriageEngine._ntfs_data_runs(bytes(attribute), 64)

    assert runs == [{"vcn": 0, "cluster_count": 2, "lcn": 5}]
    assert error == "invalid data-run header or truncated descriptor"


def test_ntfs_resident_data_inventory_keeps_fixed_value_bytes_and_offset() -> None:
    record = bytearray(96)
    first = 56
    record[first:first + 4] = (0x80).to_bytes(4, "little")
    record[first + 4:first + 8] = (32).to_bytes(4, "little")
    record[first + 14:first + 16] = (7).to_bytes(2, "little")
    record[first + 16:first + 20] = (4).to_bytes(4, "little")
    record[first + 20:first + 22] = (24).to_bytes(2, "little")
    record[first + 24:first + 28] = b"FLAG"
    record[first + 32:first + 36] = (0xFFFFFFFF).to_bytes(4, "little")

    attributes, errors = GenericTriageEngine._ntfs_attribute_inventory(
        bytes(record), first, first + 36, True,
    )

    assert errors == []
    assert attributes == [{
        "offset": 56,
        "type": "0x80",
        "type_name": "data",
        "length": 32,
        "nonresident": False,
        "name": None,
        "attribute_id": 7,
        "value_length": 4,
        "value_bounds_valid": True,
        "resident_value_offset": 80,
        "resident_data_hex": "464c4147",
    }]


def test_ntfs_resident_standard_information_and_file_name_timestamps_are_compared() -> None:
    record = bytearray(256)
    first = 56
    standard_time = 132271296000000000
    changed_file_name_time = standard_time + 10_000_000
    record[first:first + 4] = (0x10).to_bytes(4, "little")
    record[first + 4:first + 8] = (56).to_bytes(4, "little")
    record[first + 16:first + 20] = (32).to_bytes(4, "little")
    record[first + 20:first + 22] = (24).to_bytes(2, "little")
    for offset in range(first + 24, first + 56, 8):
        record[offset:offset + 8] = standard_time.to_bytes(8, "little")
    file_name = first + 56
    record[file_name:file_name + 4] = (0x30).to_bytes(4, "little")
    record[file_name + 4:file_name + 8] = (96).to_bytes(4, "little")
    record[file_name + 16:file_name + 20] = (68).to_bytes(4, "little")
    record[file_name + 20:file_name + 22] = (24).to_bytes(2, "little")
    value = file_name + 24
    record[value:value + 8] = (5).to_bytes(8, "little")
    for offset in range(value + 8, value + 40, 8):
        record[offset:offset + 8] = standard_time.to_bytes(8, "little")
    record[value + 32:value + 40] = changed_file_name_time.to_bytes(8, "little")
    record[value + 64] = 1
    record[value + 65] = 1
    record[value + 66:value + 68] = "M".encode("utf-16le")
    record[file_name + 96:file_name + 100] = (0xFFFFFFFF).to_bytes(4, "little")

    attributes, errors = GenericTriageEngine._ntfs_attribute_inventory(bytes(record), first, file_name + 100, True)
    mismatches = GenericTriageEngine._ntfs_timestamp_mismatches(attributes)

    assert errors == []
    assert attributes[0]["timestamps"]["created"] == "2020-02-25T18:40:00+00:00"
    assert attributes[1]["file_name"] == "M"
    assert mismatches == [{
        "field": "accessed", "standard_information": "2020-02-25T18:40:00+00:00",
        "file_name": "M", "file_name_timestamp": "2020-02-25T18:40:01+00:00",
    }]


def test_ntfs_standard_information_recovers_fixed_attribute_and_security_metadata() -> None:
    value = bytearray(72)
    value[32:36] = (0x0002 | 0x0400 | 0x4000).to_bytes(4, "little")
    value[36:40] = (2).to_bytes(4, "little")
    value[40:44] = (7).to_bytes(4, "little")
    value[44:48] = (9).to_bytes(4, "little")
    value[48:52] = (1001).to_bytes(4, "little")
    value[52:56] = (42).to_bytes(4, "little")
    value[56:64] = (4096).to_bytes(8, "little")
    value[64:72] = (99).to_bytes(8, "little")

    metadata, error = GenericTriageEngine._ntfs_standard_information_timestamps(bytes(value))

    assert error is None
    assert metadata["file_attributes"] == 0x4402
    assert metadata["file_attribute_names"] == ["hidden", "reparse_point", "encrypted"]
    assert metadata["owner_id"] == 1001
    assert metadata["security_id"] == 42
    assert metadata["quota_charged"] == 4096
    assert metadata["update_sequence_number"] == 99


def test_ntfs_resident_attribute_list_inventory_is_bounded() -> None:
    value = bytearray(60)
    value[0:4] = (0x80).to_bytes(4, "little")
    value[4:6] = (32).to_bytes(2, "little")
    value[6] = 3
    value[7] = 26
    value[8:16] = (4).to_bytes(8, "little")
    value[16:24] = ((7 << 48) | 42).to_bytes(8, "little")
    value[24:26] = (9).to_bytes(2, "little")
    value[26:32] = "ads".encode("utf-16le")
    value[32:36] = (0x30).to_bytes(4, "little")
    value[36:38] = (28).to_bytes(2, "little")
    value[48:56] = (5).to_bytes(8, "little")
    value[56:58] = (2).to_bytes(2, "little")

    entries, error = GenericTriageEngine._ntfs_attribute_list_entries(bytes(value))

    assert error is None
    assert entries == [
        {"offset": 0, "type": "0x80", "type_name": "data", "length": 32, "lowest_vcn": 4,
         "record_number": 42, "sequence_number": 7, "attribute_id": 9, "name": "ads"},
        {"offset": 32, "type": "0x30", "type_name": "file_name", "length": 28, "lowest_vcn": 0,
         "record_number": 5, "sequence_number": 0, "attribute_id": 2, "name": None},
    ]


def test_ntfs_attribute_list_links_stay_within_sample_and_check_sequence() -> None:
    links = GenericTriageEngine._ntfs_sample_attribute_list_links([
        {"record_number": 1, "signature_valid": True, "sequence_number": 3, "attribute_list_references": []},
        {"record_number": 2, "signature_valid": True, "sequence_number": 4, "attribute_list_references": [
            {"type_name": "data", "name": "ads", "lowest_vcn": 4, "attribute_id": 9, "record_number": 1, "sequence_number": 3},
            {"type_name": "data", "name": None, "lowest_vcn": 0, "attribute_id": 2, "record_number": 1, "sequence_number": 2},
            {"type_name": "file_name", "name": None, "lowest_vcn": 0, "attribute_id": 1, "record_number": 99, "sequence_number": 1},
        ]},
    ])

    assert links == [
        {"source_record_number": 2, "type_name": "data", "name": "ads", "lowest_vcn": 4, "attribute_id": 9,
         "target_record_number": 1, "target_sequence_number": 3, "target_sampled": True, "target_sequence_matches": True},
        {"source_record_number": 2, "type_name": "data", "name": None, "lowest_vcn": 0, "attribute_id": 2,
         "target_record_number": 1, "target_sequence_number": 2, "target_sampled": True, "target_sequence_matches": False},
        {"source_record_number": 2, "type_name": "file_name", "name": None, "lowest_vcn": 0, "attribute_id": 1,
         "target_record_number": 99, "target_sequence_number": 1, "target_sampled": False, "target_sequence_matches": None},
    ]


def test_ntfs_mft_data_run_sample_preserves_deleted_record_filename_metadata(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[64] = 0xF6
    image[510:512] = b"\x55\xaa"
    mft = 512
    image[mft:mft + 4] = b"FILE"
    image[mft + 4:mft + 6] = (48).to_bytes(2, "little")
    image[mft + 6:mft + 8] = (3).to_bytes(2, "little")
    image[mft + 20:mft + 22] = (56).to_bytes(2, "little")
    image[mft + 22:mft + 24] = (1).to_bytes(2, "little")
    image[mft + 24:mft + 28] = (132).to_bytes(4, "little")
    image[mft + 28:mft + 32] = (1024).to_bytes(4, "little")
    image[mft + 48:mft + 50] = b"\xaa\xbb"
    image[mft + 50:mft + 52] = b"\x11\x22"
    image[mft + 52:mft + 54] = b"\x33\x44"
    image[mft + 510:mft + 512] = b"\xaa\xbb"
    image[mft + 1022:mft + 1024] = b"\xaa\xbb"
    attribute = mft + 56
    image[attribute:attribute + 4] = (0x80).to_bytes(4, "little")
    image[attribute + 4:attribute + 8] = (72).to_bytes(4, "little")
    image[attribute + 8] = 1
    image[attribute + 24:attribute + 32] = (7).to_bytes(8, "little")
    image[attribute + 32:attribute + 34] = (64).to_bytes(2, "little")
    image[attribute + 40:attribute + 48] = (4096).to_bytes(8, "little")
    image[attribute + 48:attribute + 56] = (2048).to_bytes(8, "little")
    image[attribute + 64:attribute + 68] = b"\x11\x08\x01\x00"
    image[attribute + 72:attribute + 76] = (0xFFFFFFFF).to_bytes(4, "little")
    deleted = mft + 1024
    image[deleted:deleted + 4] = b"FILE"
    image[deleted + 4:deleted + 6] = (48).to_bytes(2, "little")
    image[deleted + 6:deleted + 8] = (3).to_bytes(2, "little")
    image[deleted + 16:deleted + 18] = (5).to_bytes(2, "little")
    image[deleted + 20:deleted + 22] = (56).to_bytes(2, "little")
    image[deleted + 24:deleted + 28] = (172).to_bytes(4, "little")
    image[deleted + 28:deleted + 32] = (1024).to_bytes(4, "little")
    image[deleted + 48:deleted + 50] = b"\xcc\xdd"
    image[deleted + 50:deleted + 52] = b"\x44\x55"
    image[deleted + 52:deleted + 54] = b"\x66\x77"
    image[deleted + 510:deleted + 512] = b"\xcc\xdd"
    image[deleted + 1022:deleted + 1024] = b"\xcc\xdd"
    name_attribute = deleted + 56
    image[name_attribute:name_attribute + 4] = (0x30).to_bytes(4, "little")
    image[name_attribute + 4:name_attribute + 8] = (112).to_bytes(4, "little")
    image[name_attribute + 16:name_attribute + 20] = (82).to_bytes(4, "little")
    image[name_attribute + 20:name_attribute + 22] = (24).to_bytes(2, "little")
    value = name_attribute + 24
    image[value:value + 8] = (5).to_bytes(8, "little")
    image[value + 64] = 8
    image[value + 65] = 1
    image[value + 66:value + 82] = "gone.txt".encode("utf-16le")
    image[name_attribute + 112:name_attribute + 116] = (0xFFFFFFFF).to_bytes(4, "little")
    evidence = tmp_path / "ntfs-deleted.raw"
    evidence.write_bytes(image)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ntfs.mft_sample_records"] == [{
        "record_number": 1, "physical_segments": [{"logical_offset": 1024, "physical_offset": 1536, "length": 1024}], "signature_valid": True, "bounds_valid": True,
        "usa_fixup_valid": True, "usa_fixup_error": None, "sequence_number": 5, "in_use": False,
        "directory": False, "deleted": True, "file_names": ["gone.txt"],
        "file_name_references": [{"file_name": "gone.txt", "parent_record_number": 5, "parent_sequence_number": 0}],
        "standard_information": [],
        "attribute_list_references": [],
        "index_root_entries": [],
        "attribute_errors": [],
    }]
    assert values["filesystem.ntfs.mft_sample_errors"] == []
    assert values["filesystem.ntfs.mft_sample_parent_links"] == [{
        "child_record_number": 1, "file_name": "gone.txt", "parent_record_number": 5,
        "parent_sequence_number": 0, "parent_sampled": False, "parent_sequence_matches": None,
    }]
    assert values["filesystem.ntfs.mft_sample_attribute_list_links"] == []


def test_ntfs_mft_mirror_is_independently_fixed_and_logical_difference_reported(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[56:64] = (5).to_bytes(8, "little")
    image[64] = 0xF6
    image[510:512] = b"\x55\xaa"
    primary = bytearray(1024)
    primary[:4] = b"FILE"
    primary[4:6] = (48).to_bytes(2, "little")
    primary[6:8] = (3).to_bytes(2, "little")
    primary[16:18] = (1).to_bytes(2, "little")
    primary[20:22] = (56).to_bytes(2, "little")
    primary[22:24] = (1).to_bytes(2, "little")
    primary[24:28] = (60).to_bytes(4, "little")
    primary[28:32] = (1024).to_bytes(4, "little")
    primary[48:54] = b"\xaa\xbb\x11\x22\x33\x44"
    primary[56:60] = (0xFFFFFFFF).to_bytes(4, "little")
    primary[510:512] = b"\xaa\xbb"
    primary[1022:1024] = b"\xaa\xbb"
    image[512:1536] = primary
    mirror = bytearray(primary)
    mirror[16:18] = (2).to_bytes(2, "little")
    image[5 * 512:7 * 512] = mirror
    evidence = tmp_path / "ntfs-mirror.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["filesystem.ntfs.mft_mirror.available"] is True
    assert values["filesystem.ntfs.mft_mirror.offset"] == 2560
    assert values["filesystem.ntfs.mft_mirror.signature_valid"] is True
    assert values["filesystem.ntfs.mft_mirror.bounds_valid"] is True
    assert values["filesystem.ntfs.mft_mirror.usa_fixup_valid"] is True
    assert values["filesystem.ntfs.mft_mirror.primary_match"] is False
    assert values["filesystem.ntfs.mft_mirror.first_difference_offset"] == 16
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(item for item in profile.findings if item.category == "ntfs_mft_mirror_mismatch")
    assert "first_difference=16" in finding.supporting_evidence[0]


def test_ntfs_backup_boot_sector_validates_and_reports_first_difference(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[64] = 0xF6
    image[510:512] = b"\x55\xaa"
    image[-512:] = image[:512]
    image[-512 + 72] = 0xA5
    evidence = tmp_path / "ntfs-backup-boot.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["filesystem.ntfs.backup_boot.available"] is True
    assert values["filesystem.ntfs.backup_boot.offset"] == 3584
    assert values["filesystem.ntfs.backup_boot.signature_valid"] is True
    assert values["filesystem.ntfs.backup_boot.end_marker_valid"] is True
    assert values["filesystem.ntfs.backup_boot.primary_match"] is False
    assert values["filesystem.ntfs.backup_boot.first_difference_offset"] == 72
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(item for item in profile.findings if item.category == "ntfs_backup_boot_mismatch")
    assert "backup_offset=3584" in finding.supporting_evidence[0]
    assert "first_difference=72" in finding.supporting_evidence[0]


def test_fat32_root_deleted_short_entry_keeps_unknown_name_and_offset(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (8).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    entry = 1024
    image[entry:entry + 11] = b"\xe5LAG    TXT"
    image[entry + 11] = 0x20
    image[entry + 13] = 50
    fat_date = ((2026 - 1980) << 9) | (9 << 5) | 3
    fat_time = (12 << 11) | (34 << 5) | 28
    image[entry + 14:entry + 16] = fat_time.to_bytes(2, "little")
    image[entry + 16:entry + 18] = fat_date.to_bytes(2, "little")
    image[entry + 18:entry + 20] = fat_date.to_bytes(2, "little")
    image[entry + 22:entry + 24] = fat_time.to_bytes(2, "little")
    image[entry + 24:entry + 26] = fat_date.to_bytes(2, "little")
    image[entry + 26:entry + 28] = (5).to_bytes(2, "little")
    image[entry + 28:entry + 32] = (123).to_bytes(4, "little")
    evidence = tmp_path / "fat32.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["filesystem.fat.root.offset"] == 1024
    assert values["filesystem.fat.deleted_short_entries"] == [{
        "entry_index": 0, "offset": 1024, "short_name": "?LAG.TXT",
        "first_character_unknown": True, "attributes": "0x20",
        "first_cluster": 5, "cluster_field_raw": "0x00000005",
        "fat32_cluster_high_reserved": 0, "size": 123,
        "created": "2026-09-03T12:34:56.500000",
        "accessed": "2026-09-03T00:00:00",
        "modified": "2026-09-03T12:34:56",
        "raw_hex": bytes(image[entry:entry + 32]).hex(),
    }]
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(item for item in profile.findings if item.category == "fat_deleted_directory_entry")
    assert "?LAG.TXT" in finding.supporting_evidence[0]


def test_fat32_fsinfo_and_backup_sectors_keep_signature_hint_and_divergence_provenance(tmp_path: Path) -> None:
    sector_size = 512
    reserved = 8
    fat_size = 600
    total_sectors = 70_000
    first_data_sector = reserved + fat_size
    image = bytearray((first_data_sector + 2) * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = reserved.to_bytes(2, "little")
    image[16] = 1
    image[32:36] = total_sectors.to_bytes(4, "little")
    image[36:40] = fat_size.to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[48:50] = (1).to_bytes(2, "little")
    image[50:52] = (6).to_bytes(2, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    image[reserved * sector_size + 8:reserved * sector_size + 12] = (0x0FFFFFFF).to_bytes(4, "little")

    def fsinfo(sector: int, free_count: int, next_free: int) -> None:
        offset = sector * sector_size
        image[offset:offset + 4] = b"RRaA"
        image[offset + 484:offset + 488] = b"rrAa"
        image[offset + 488:offset + 492] = free_count.to_bytes(4, "little")
        image[offset + 492:offset + 496] = next_free.to_bytes(4, "little")
        image[offset + 508:offset + 512] = b"\x00\x00\x55\xaa"

    fsinfo(1, 100, 5)
    image[6 * sector_size:7 * sector_size] = image[:sector_size]
    image[6 * sector_size + 67] ^= 0x5A
    fsinfo(7, 101, 5)
    evidence = tmp_path / "fat32-metadata.raw"
    evidence.write_bytes(image)

    observations = GenericTriageEngine().analyze(_artifact(evidence), evidence)
    values = _values(observations)

    assert values["filesystem.fat32.cluster_count"] == total_sectors - first_data_sector
    assert values["filesystem.fat32.fat_entry_capacity"] == fat_size * sector_size // 4
    primary = values["filesystem.fat32.fsinfo"]
    assert primary["available"] is True and primary["valid"] is True
    assert primary["offset"] == sector_size
    assert primary["free_cluster_count"] == 100
    assert primary["free_cluster_count_in_range"] is True
    assert primary["next_free_cluster"] == 5
    assert primary["next_free_cluster_in_range"] is True
    backup_boot = values["filesystem.fat32.backup_boot"]
    assert backup_boot["available"] is True
    assert backup_boot["signature_valid"] is True
    assert backup_boot["fat32_label_valid"] is True
    assert backup_boot["primary_match"] is False
    assert backup_boot["first_difference_offset"] == 67
    backup_fsinfo = values["filesystem.fat32.backup_fsinfo"]
    assert backup_fsinfo["available"] is True and backup_fsinfo["valid"] is True
    assert backup_fsinfo["offset"] == 7 * sector_size
    assert backup_fsinfo["primary_match"] is False
    assert backup_fsinfo["first_difference_offset"] == 488
    profile = ProfileEngine().evaluate(_artifact(evidence), observations)
    categories = {item.category for item in profile.findings}
    assert "fat32_fsinfo_inventory" in categories
    assert "fat32_backup_boot_mismatch" in categories
    assert "fat32_backup_fsinfo_mismatch" in categories

    invalid_hints = bytearray(image)
    invalid_hints[sector_size + 488:sector_size + 492] = (70_000).to_bytes(4, "little")
    invalid_hints[sector_size + 492:sector_size + 496] = (1).to_bytes(4, "little")
    invalid = tmp_path / "fat32-invalid-fsinfo.raw"
    invalid.write_bytes(invalid_hints)
    invalid_observations = GenericTriageEngine().analyze(_artifact(invalid), invalid)
    invalid_values = _values(invalid_observations)
    assert invalid_values["filesystem.fat32.fsinfo"]["free_cluster_count_in_range"] is False
    assert invalid_values["filesystem.fat32.fsinfo"]["next_free_cluster_in_range"] is False
    invalid_profile = ProfileEngine().evaluate(_artifact(invalid), invalid_observations)
    assert any(item.category == "fat32_fsinfo_anomaly" for item in invalid_profile.findings)


def test_fat12_and_fat16_duplicate_tables_preserve_match_divergence_and_truncation(tmp_path: Path) -> None:
    sector_size = 512
    fat12_image = bytearray(4 * sector_size)
    fat12_image[11:13] = sector_size.to_bytes(2, "little")
    fat12_image[13] = 1
    fat12_image[14:16] = (1).to_bytes(2, "little")
    fat12_image[16] = 2
    fat12_image[17:19] = (16).to_bytes(2, "little")
    fat12_image[19:21] = (100).to_bytes(2, "little")
    fat12_image[21] = 0xF0
    fat12_image[22:24] = (1).to_bytes(2, "little")
    fat12_image[54:62] = b"FAT12   "
    fat12_image[510:512] = b"\x55\xaa"
    reference_table_data = bytearray((index * 17) & 0xFF for index in range(sector_size))
    reference_table_data[:3] = b"\xf0\xff\xff"
    reference_table = bytes(reference_table_data)
    fat12_image[sector_size:2 * sector_size] = reference_table
    fat12_image[2 * sector_size:3 * sector_size] = reference_table
    matching_path = tmp_path / "fat12-matching-copies.raw"
    matching_path.write_bytes(fat12_image)

    matching_observations = GenericTriageEngine().analyze(_artifact(matching_path), matching_path)
    matching = _values(matching_observations)["filesystem.fat12.fat_copies"]
    assert matching["available"] is True
    assert matching["authoritative_copy_selected"] is False
    assert matching["all_copies_match"] is True
    assert [
        (
            item["index"], item["offset"], item["end_offset"], item["length"],
            item["within_declared_volume"], item["within_supplied_image"], item["available"],
        )
        for item in matching["copies"]
    ] == [
        (0, sector_size, 2 * sector_size, sector_size, True, True, True),
        (1, 2 * sector_size, 3 * sector_size, sector_size, True, True, True),
    ]
    assert matching["comparisons"] == [{
        "reference_index": 0, "compared_index": 1, "available": True,
        "compared_bytes": sector_size, "full_table_compared": True,
        "match": True, "first_difference": None,
    }]
    assert matching["copies"][0]["reserved_entries"] == {
        "available": True, "raw_hex": "f0ffff", "entry0_offset": sector_size,
        "entry1_packed_offset": sector_size + 1, "entry0": "0xFF0", "entry1": "0xFFF",
        "entry0_media_matches": True, "entry0_reserved_bits_valid": True,
        "entry1_eoc_valid": True, "valid": True,
    }
    matching_profile = ProfileEngine().evaluate(_artifact(matching_path), matching_observations)
    matching_categories = {item.category for item in matching_profile.findings}
    assert "fat12_fat_copy_inventory" in matching_categories
    assert "fat12_fat_copy_anomaly" not in matching_categories

    divergent_image = bytearray(fat12_image)
    divergent_image[2 * sector_size + 19] ^= 0x5A
    divergent_path = tmp_path / "fat12-divergent-copies.raw"
    divergent_path.write_bytes(divergent_image)
    divergent_observations = GenericTriageEngine().analyze(_artifact(divergent_path), divergent_path)
    divergent = _values(divergent_observations)["filesystem.fat12.fat_copies"]
    comparison = divergent["comparisons"][0]
    assert divergent["all_copies_match"] is False
    assert comparison["match"] is False
    assert comparison["full_table_compared"] is False
    assert comparison["compared_bytes"] == 20
    assert comparison["first_difference"] == {
        "relative_offset": 19,
        "reference_absolute_offset": sector_size + 19,
        "compared_absolute_offset": 2 * sector_size + 19,
        "reference_byte": f"0x{reference_table[19]:02X}",
        "compared_byte": f"0x{divergent_image[2 * sector_size + 19]:02X}",
    }
    divergent_profile = ProfileEngine().evaluate(_artifact(divergent_path), divergent_observations)
    assert any(item.category == "fat12_fat_copy_anomaly" for item in divergent_profile.findings)

    fat16_fat_sectors = 16
    second_fat_offset = (1 + fat16_fat_sectors) * sector_size
    truncated_fat16 = bytearray(second_fat_offset + 100)
    truncated_fat16[11:13] = sector_size.to_bytes(2, "little")
    truncated_fat16[13] = 1
    truncated_fat16[14:16] = (1).to_bytes(2, "little")
    truncated_fat16[16] = 2
    truncated_fat16[17:19] = (16).to_bytes(2, "little")
    truncated_fat16[19:21] = (4_119).to_bytes(2, "little")
    truncated_fat16[21] = 0xF8
    truncated_fat16[22:24] = fat16_fat_sectors.to_bytes(2, "little")
    truncated_fat16[54:62] = b"FAT16   "
    truncated_fat16[510:512] = b"\x55\xaa"
    truncated_fat16[sector_size:sector_size + 4] = b"\xf8\xff\xff\x3f"
    truncated_path = tmp_path / "fat16-truncated-second-copy.raw"
    truncated_path.write_bytes(truncated_fat16)
    truncated_observations = GenericTriageEngine().analyze(_artifact(truncated_path), truncated_path)
    truncated = _values(truncated_observations)["filesystem.fat16.fat_copies"]
    assert truncated["available"] is True
    assert truncated["all_copies_match"] is None
    assert truncated["copies"][0]["available"] is True
    assert truncated["copies"][0]["reserved_entries"]["valid"] is True
    assert truncated["copies"][0]["reserved_entries"]["entry1"] == "0x3FFF"
    assert truncated["copies"][0]["reserved_entries"]["entry1_clean_shutdown"] is False
    assert truncated["copies"][0]["reserved_entries"]["entry1_no_io_errors"] is False
    assert truncated["copies"][1]["available"] is False
    assert truncated["copies"][1]["offset"] == second_fat_offset
    assert truncated["copies"][1]["reason"] == "declared FAT range exceeds supplied image"
    assert truncated["comparisons"][0]["available"] is False
    assert truncated["comparisons"][0]["match"] is None
    truncated_profile = ProfileEngine().evaluate(_artifact(truncated_path), truncated_observations)
    assert any(item.category == "fat16_fat_copy_anomaly" for item in truncated_profile.findings)


def test_fat_bpb_relationship_validation_is_variant_specific_and_image_length_neutral(tmp_path: Path) -> None:
    sector_size = 512
    fixtures: list[tuple[int, bytearray]] = []

    fat12 = bytearray(4 * sector_size)
    fat12[:3] = b"\xeb\x3c\x90"
    fat12[11:13] = sector_size.to_bytes(2, "little")
    fat12[13] = 1
    fat12[14:16] = (1).to_bytes(2, "little")
    fat12[16] = 1
    fat12[17:19] = (16).to_bytes(2, "little")
    fat12[19:21] = (100).to_bytes(2, "little")
    fat12[21] = 0xF0
    fat12[22:24] = (1).to_bytes(2, "little")
    fat12[54:62] = b"FAT12   "
    fat12[510:512] = b"\x55\xaa"
    fat12[sector_size:sector_size + 3] = b"\xf0\xff\xff"
    fixtures.append((12, fat12))

    fat16_size = 17
    fat16 = bytearray(20 * sector_size)
    fat16[:3] = b"\xeb\x3c\x90"
    fat16[11:13] = sector_size.to_bytes(2, "little")
    fat16[13] = 1
    fat16[14:16] = (1).to_bytes(2, "little")
    fat16[16] = 1
    fat16[17:19] = (16).to_bytes(2, "little")
    fat16[19:21] = (4_119).to_bytes(2, "little")
    fat16[21] = 0xF8
    fat16[22:24] = fat16_size.to_bytes(2, "little")
    fat16[54:62] = b"FAT16   "
    fat16[510:512] = b"\x55\xaa"
    fat16[sector_size:sector_size + 4] = b"\xf8\xff\xff\xff"
    fixtures.append((16, fat16))

    fat32_size = 600
    first_data_sector = 1 + fat32_size
    fat32 = bytearray((first_data_sector + 1) * sector_size)
    fat32[:3] = b"\xeb\x58\x90"
    fat32[11:13] = sector_size.to_bytes(2, "little")
    fat32[13] = 1
    fat32[14:16] = (1).to_bytes(2, "little")
    fat32[16] = 1
    fat32[21] = 0xF8
    fat32[32:36] = (70_000).to_bytes(4, "little")
    fat32[36:40] = fat32_size.to_bytes(4, "little")
    fat32[44:48] = (2).to_bytes(4, "little")
    fat32[82:90] = b"FAT32   "
    fat32[510:512] = b"\x55\xaa"
    fat32[sector_size:sector_size + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    fat32[sector_size + 8:sector_size + 12] = (0x0FFFFFFF).to_bytes(4, "little")
    fixtures.append((32, fat32))

    for fat_bits, image in fixtures:
        path = tmp_path / f"fat{fat_bits}-valid-bpb.raw"
        path.write_bytes(image)
        artifact = _artifact(path)
        observations = GenericTriageEngine().analyze(artifact, path)
        validation = _values(observations)["filesystem.fat.bpb_validation"]
        assert validation["fat_bits"] == fat_bits
        assert validation["valid"] is True
        assert validation["failed_checks"] == []
        assert validation["declared_volume_within_supplied_image"] is False
        profile = ProfileEngine().evaluate(artifact, observations)
        assert not any(item.category == "fat_bpb_structure_anomaly" for item in profile.findings)

    malformed = bytearray(fat32)
    malformed[:3] = b"\xeb\x01\x00"
    malformed[17:19] = (16).to_bytes(2, "little")
    malformed[19:21] = (10).to_bytes(2, "little")
    malformed[22:24] = (1).to_bytes(2, "little")
    malformed[42:44] = (1).to_bytes(2, "little")
    malformed[52] = 1
    malformed_path = tmp_path / "fat32-invalid-bpb.raw"
    malformed_path.write_bytes(malformed)
    malformed_artifact = _artifact(malformed_path)
    malformed_observations = GenericTriageEngine().analyze(malformed_artifact, malformed_path)
    malformed_validation = _values(malformed_observations)["filesystem.fat.bpb_validation"]
    assert malformed_validation["valid"] is False
    assert {
        "jump_instruction_valid", "total_sector_fields_valid", "fat_size_fields_valid",
        "root_entry_count_valid", "cluster_count_matches_variant",
        "fat32_fs_version_valid", "fat32_reserved_bpb_bytes_zero",
    } <= set(malformed_validation["failed_checks"])
    malformed_profile = ProfileEngine().evaluate(malformed_artifact, malformed_observations)
    finding = next(
        item for item in malformed_profile.findings
        if item.category == "fat_bpb_structure_anomaly"
    )
    assert "jump_instruction_valid" in finding.supporting_evidence[0]
    assert "fat32_reserved_bpb_bytes_zero" in finding.supporting_evidence[0]


def test_fat_variant_is_derived_without_a_label_and_label_conflicts_are_preserved(tmp_path: Path) -> None:
    sector_size = 512

    def boot_image(fat_bits: int) -> bytearray:
        if fat_bits == 12:
            image = bytearray(4 * sector_size)
            fat_size, total_sectors, root_entries = 1, 100, 16
        elif fat_bits == 16:
            image = bytearray(20 * sector_size)
            fat_size, total_sectors, root_entries = 17, 4_119, 16
        else:
            fat_size, total_sectors, root_entries = 600, 70_000, 0
            image = bytearray((1 + fat_size + 1) * sector_size)
        image[:3] = b"\xeb\x3c\x90"
        image[11:13] = sector_size.to_bytes(2, "little")
        image[13] = 1
        image[14:16] = (1).to_bytes(2, "little")
        image[16] = 1
        image[17:19] = root_entries.to_bytes(2, "little")
        image[21] = 0xF8
        if fat_bits == 32:
            image[32:36] = total_sectors.to_bytes(4, "little")
            image[36:40] = fat_size.to_bytes(4, "little")
            image[44:48] = (2).to_bytes(4, "little")
            image[sector_size:sector_size + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
            image[sector_size + 8:sector_size + 12] = (0x0FFFFFFF).to_bytes(4, "little")
        else:
            image[19:21] = total_sectors.to_bytes(2, "little")
            image[22:24] = fat_size.to_bytes(2, "little")
            image[sector_size:sector_size + (3 if fat_bits == 12 else 4)] = (
                b"\xf8\xff\xff" if fat_bits == 12 else b"\xf8\xff\xff\xff"
            )
        image[510:512] = b"\x55\xaa"
        return image

    for fat_bits in (12, 16, 32):
        path = tmp_path / f"fat{fat_bits}-without-label.raw"
        path.write_bytes(boot_image(fat_bits))
        artifact = _artifact(path)
        observations = GenericTriageEngine().analyze(artifact, path)
        values = _values(observations)
        assert values["filesystem.fat.label_signature"] is False
        assert values["filesystem.fat_signature"] is True
        assert values["filesystem.type"] == "fat"
        assert values["filesystem.fat.variant"] == f"fat{fat_bits}"
        assert values["filesystem.fat.variant_evidence"] == {
            "text_label_records": [],
            "text_label_fat_bits": None,
            "text_label_ambiguous": False,
            "bpb_cluster_count_fat_bits": fat_bits,
            "bpb_structure_recognized": True,
            "label_structure_agree": None,
            "selected_fat_bits": fat_bits,
            "selection_basis": "bpb_cluster_count",
        }
        assert values["filesystem.fat.bpb_validation"]["valid"] is True
        assert values["filesystem.fat.bpb_validation"]["checks"]["fat_entry_capacity_sufficient"] is True
        root_key = (
            "filesystem.fat.root.available"
            if fat_bits == 32 else f"filesystem.fat{fat_bits}.root.available"
        )
        assert values[root_key] is True
        identified = IdentificationEngine().identify(artifact, observations)
        assert identified.format == "filesystem"
        assert artifact.artifact_type == "filesystem"

    conflict = boot_image(12)
    conflict[54:62] = b"FAT16   "
    conflict_path = tmp_path / "fat12-with-conflicting-fat16-label.raw"
    conflict_path.write_bytes(conflict)
    conflict_artifact = _artifact(conflict_path)
    conflict_observations = GenericTriageEngine().analyze(conflict_artifact, conflict_path)
    conflict_values = _values(conflict_observations)
    variant = conflict_values["filesystem.fat.variant_evidence"]
    assert conflict_values["filesystem.fat.variant"] == "fat12"
    assert variant["text_label_fat_bits"] == 16
    assert variant["bpb_cluster_count_fat_bits"] == 12
    assert variant["label_structure_agree"] is False
    assert variant["selection_basis"] == "bpb_cluster_count"
    assert variant["text_label_records"][0]["offset"] == 54
    assert conflict_values["filesystem.fat12.root.available"] is True
    conflict_profile = ProfileEngine().evaluate(conflict_artifact, conflict_observations)
    mismatch = next(
        item for item in conflict_profile.findings
        if item.category == "fat_variant_label_mismatch"
    )
    assert "'offset': 54" in mismatch.supporting_evidence[0]
    assert not any(
        item.category == "fat_bpb_structure_anomaly"
        for item in conflict_profile.findings
    )

    false_candidate = bytearray(sector_size)
    false_candidate[:3] = b"\xeb\x3c\x90"
    false_candidate[11:13] = sector_size.to_bytes(2, "little")
    false_candidate[510:512] = b"\x55\xaa"
    false_path = tmp_path / "not-a-fat-volume.raw"
    false_path.write_bytes(false_candidate)
    false_values = _values(GenericTriageEngine().analyze(_artifact(false_path), false_path))
    assert false_values["filesystem.fat_signature"] is False


def test_mbr_partition_boot_filesystems_are_offset_validated_without_trusting_type_codes(tmp_path: Path) -> None:
    sector_size = 512
    image = bytearray(11 * sector_size)
    first_entry = 446
    image[first_entry + 4] = 0x06
    image[first_entry + 8:first_entry + 12] = (1).to_bytes(4, "little")
    image[first_entry + 12:first_entry + 16] = (4).to_bytes(4, "little")
    second_entry = first_entry + 16
    image[second_entry + 4] = 0x07
    image[second_entry + 8:second_entry + 12] = (5).to_bytes(4, "little")
    image[second_entry + 12:second_entry + 16] = (5).to_bytes(4, "little")
    third_entry = second_entry + 16
    image[third_entry + 4] = 0x07
    image[third_entry + 8:third_entry + 12] = (10).to_bytes(4, "little")
    image[third_entry + 12:third_entry + 16] = (100).to_bytes(4, "little")
    image[510:512] = b"\x55\xaa"

    fat = sector_size
    image[fat:fat + 3] = b"\xeb\x3c\x90"
    image[fat + 11:fat + 13] = sector_size.to_bytes(2, "little")
    image[fat + 13] = 1
    image[fat + 14:fat + 16] = (1).to_bytes(2, "little")
    image[fat + 16] = 1
    image[fat + 17:fat + 19] = (16).to_bytes(2, "little")
    image[fat + 19:fat + 21] = (100).to_bytes(2, "little")
    image[fat + 21] = 0xF8
    image[fat + 22:fat + 24] = (1).to_bytes(2, "little")
    image[fat + 28:fat + 32] = (1).to_bytes(4, "little")
    image[fat + 510:fat + 512] = b"\x55\xaa"

    ntfs = 5 * sector_size
    image[ntfs:ntfs + 3] = b"\xeb\x52\x90"
    image[ntfs + 3:ntfs + 11] = b"NTFS    "
    image[ntfs + 11:ntfs + 13] = sector_size.to_bytes(2, "little")
    image[ntfs + 13] = 1
    image[ntfs + 21] = 0xF8
    image[ntfs + 28:ntfs + 32] = (5).to_bytes(4, "little")
    image[ntfs + 40:ntfs + 48] = (5).to_bytes(8, "little")
    image[ntfs + 48:ntfs + 56] = (1).to_bytes(8, "little")
    image[ntfs + 56:ntfs + 64] = (2).to_bytes(8, "little")
    image[ntfs + 64] = 0xF6
    image[ntfs + 68] = 0xF6
    image[ntfs + 510:ntfs + 512] = b"\x55\xaa"

    exfat = 10 * sector_size
    image[exfat:exfat + 3] = b"\xeb\x76\x90"
    image[exfat + 3:exfat + 11] = b"EXFAT   "
    image[exfat + 64:exfat + 72] = (10).to_bytes(8, "little")
    image[exfat + 72:exfat + 80] = (100).to_bytes(8, "little")
    image[exfat + 80:exfat + 84] = (24).to_bytes(4, "little")
    image[exfat + 84:exfat + 88] = (1).to_bytes(4, "little")
    image[exfat + 88:exfat + 92] = (25).to_bytes(4, "little")
    image[exfat + 92:exfat + 96] = (75).to_bytes(4, "little")
    image[exfat + 96:exfat + 100] = (2).to_bytes(4, "little")
    image[exfat + 104:exfat + 106] = (0x0100).to_bytes(2, "little")
    image[exfat + 108] = 9
    image[exfat + 109] = 0
    image[exfat + 110] = 1
    image[exfat + 112] = 0
    image[exfat + 510:exfat + 512] = b"\x55\xaa"

    evidence = tmp_path / "mbr-partition-filesystems.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    partitions = values["disk.mbr.partition_filesystems"]
    assert len(partitions) == 3
    assert partitions[0]["partition_offset"] == sector_size
    assert partitions[0]["boot_sector_offset"] == sector_size
    assert partitions[0]["filesystem_candidate"] == "fat12"
    assert partitions[0]["detected_filesystem"] == "fat12"
    assert partitions[0]["detection_basis"] == "fat_bpb_cluster_count"
    assert partitions[0]["expected_filesystems_from_type_code"] == ["fat16"]
    assert partitions[0]["partition_type_matches_detected"] is False
    assert partitions[0]["validation"]["valid"] is True
    assert partitions[0]["validation"]["declared_volume_within_partition"] is False
    assert partitions[0]["boot_declared_start_lba"] == 1
    assert partitions[0]["boot_declared_start_lba_field_offset"] == fat + 28
    assert partitions[0]["boot_declared_start_lba_matches_mbr"] is True
    assert partitions[0]["boot_declared_volume_field_offset"] == fat + 19
    assert partitions[0]["boot_declared_volume_field_width"] == 2
    assert partitions[0]["boot_declared_volume_matches_partition"] is False
    assert partitions[1]["partition_offset"] == ntfs
    assert partitions[1]["filesystem_candidate"] == "ntfs"
    assert partitions[1]["detected_filesystem"] == "ntfs"
    assert partitions[1]["expected_filesystems_from_type_code"] == ["ntfs", "exfat"]
    assert partitions[1]["partition_type_matches_detected"] is True
    assert partitions[1]["validation"]["failed_checks"] == []
    assert partitions[1]["boot_declared_start_lba"] == 5
    assert partitions[1]["boot_declared_volume_field_offset"] == ntfs + 40
    assert partitions[1]["boot_declared_volume_matches_partition"] is True
    assert partitions[2]["partition_offset"] == exfat
    assert partitions[2]["filesystem_candidate"] == "exfat"
    assert partitions[2]["detected_filesystem"] == "exfat"
    assert partitions[2]["partition_type_matches_detected"] is True
    assert partitions[2]["validation"]["failed_checks"] == []
    assert partitions[2]["boot_declared_start_lba_field_offset"] == exfat + 64
    assert partitions[2]["boot_declared_volume_field_offset"] == exfat + 72
    assert partitions[2]["boot_declared_volume_matches_partition"] is True

    profile = ProfileEngine().evaluate(artifact, observations)
    inventory = next(
        item for item in profile.findings
        if item.category == "mbr_partition_filesystem_inventory"
    )
    mismatch = next(
        item for item in profile.findings
        if item.category == "partition_type_filesystem_mismatch"
    )
    geometry_mismatch = next(
        item for item in profile.findings
        if item.category == "partition_boot_geometry_mismatch"
    )
    assert "'partition_offset': 512" in inventory.supporting_evidence[0]
    assert "'expected_filesystems_from_type_code': ['fat16']" in mismatch.supporting_evidence[0]
    assert "'boot_declared_volume_matches_partition': False" in geometry_mismatch.supporting_evidence[0]

    malformed = bytearray(image)
    malformed[ntfs + 510:ntfs + 512] = b"\x00\x00"
    malformed_path = tmp_path / "mbr-malformed-ntfs-partition.raw"
    malformed_path.write_bytes(malformed)
    malformed_artifact = _artifact(malformed_path)
    malformed_observations = GenericTriageEngine().analyze(malformed_artifact, malformed_path)
    malformed_partitions = _values(malformed_observations)["disk.mbr.partition_filesystems"]
    assert malformed_partitions[1]["filesystem_candidate"] == "ntfs"
    assert malformed_partitions[1]["detected_filesystem"] is None
    assert "end_marker_valid" in malformed_partitions[1]["validation"]["failed_checks"]
    malformed_profile = ProfileEngine().evaluate(malformed_artifact, malformed_observations)
    boot_anomaly = next(
        item for item in malformed_profile.findings
        if item.category == "partition_filesystem_boot_anomaly"
    )
    assert "'boot_sector_offset': 2560" in boot_anomaly.supporting_evidence[0]


def test_partition_extent_conflicts_preserve_pair_provenance_and_mark_every_owner(tmp_path: Path) -> None:
    duplicate_entries = [
        {
            "slot": slot,
            "entry_valid": True,
            "entry_offset": 446 + (slot - 1) * 16,
            "type_code": "0x01",
            "type": "FAT12",
            "start_lba": 10,
            "sector_count": 4,
            "within_image": True,
        }
        for slot in (1, 2)
    ]
    duplicate_summary = GenericTriageEngine._partition_extent_conflicts(
        duplicate_entries, [], [],
    )
    assert duplicate_summary["conflict_count"] == 1
    assert duplicate_summary["ambiguous_candidate_identities"] == [
        "mbr_primary:1", "mbr_primary:2",
    ]
    assert duplicate_summary["records"][0]["relation"] == "exact_duplicate"
    assert duplicate_summary["records"][0]["overlap_start_lba"] == 10
    assert duplicate_summary["records"][0]["overlap_end_lba"] == 13
    assert all(item["partition_extent_ambiguous"] is True for item in duplicate_entries)

    sector_size = 512
    image = bytearray(7 * sector_size)
    for slot, start_lba in ((0, 1), (1, 3)):
        entry = 446 + slot * 16
        image[entry + 4] = 0x01
        image[entry + 8:entry + 12] = start_lba.to_bytes(4, "little")
        image[entry + 12:entry + 16] = (4).to_bytes(4, "little")
        boot = start_lba * sector_size
        image[boot:boot + 3] = b"\xeb\x3c\x90"
        image[boot + 11:boot + 13] = sector_size.to_bytes(2, "little")
        image[boot + 13] = 1
        image[boot + 14:boot + 16] = (1).to_bytes(2, "little")
        image[boot + 16] = 1
        image[boot + 17:boot + 19] = (16).to_bytes(2, "little")
        image[boot + 19:boot + 21] = (4).to_bytes(2, "little")
        image[boot + 21] = 0xF8
        image[boot + 22:boot + 24] = (1).to_bytes(2, "little")
        image[boot + 28:boot + 32] = start_lba.to_bytes(4, "little")
        image[boot + 510:boot + 512] = b"\x55\xaa"
    image[510:512] = b"\x55\xaa"
    evidence = tmp_path / "overlapping-primary-partitions.dd"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    conflicts = values["disk.partition_extent_conflicts"]
    assert conflicts["candidate_count"] == 2
    assert conflicts["conflict_count"] == 1
    assert conflicts["ambiguous_candidate_count"] == 2
    assert conflicts["records"][0]["relation"] == "partial_overlap"
    assert conflicts["records"][0]["overlap_start_lba"] == 3
    assert conflicts["records"][0]["overlap_end_lba"] == 4
    assert conflicts["records"][0]["overlap_offset"] == 3 * sector_size
    assert conflicts["records"][0]["overlap_length"] == 2 * sector_size
    filesystems = values["disk.mbr.partition_filesystems"]
    assert [item["detected_filesystem"] for item in filesystems] == ["fat12", "fat12"]
    assert [item["partition_extent_identity"] for item in filesystems] == [
        "mbr_primary:1", "mbr_primary:2",
    ]
    assert all(item["partition_extent_ambiguous"] is True for item in filesystems)
    assert all(item["partition_extent_conflict_count"] == 1 for item in filesystems)

    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(
        item for item in profile.findings
        if item.category == "partition_extent_conflict"
    )
    assert finding.severity == "medium"
    assert "'overlap_start_lba': 3" in finding.supporting_evidence[0]
    assert "'identity': 'mbr_primary:1'" in finding.supporting_evidence[0]


def test_ebr_logical_partitions_use_current_and_extended_base_relative_offsets(tmp_path: Path) -> None:
    sector_size = 512
    image = bytearray(20 * sector_size)
    image[446 + 4] = 0x0F
    image[446 + 8:446 + 12] = (1).to_bytes(4, "little")
    image[446 + 12:446 + 16] = (15).to_bytes(4, "little")
    image[510:512] = b"\x55\xaa"

    first_ebr = sector_size
    image[first_ebr + 446 + 4] = 0x06
    image[first_ebr + 446 + 8:first_ebr + 446 + 12] = (1).to_bytes(4, "little")
    image[first_ebr + 446 + 12:first_ebr + 446 + 16] = (4).to_bytes(4, "little")
    image[first_ebr + 462 + 4] = 0x0F
    image[first_ebr + 462 + 8:first_ebr + 462 + 12] = (6).to_bytes(4, "little")
    image[first_ebr + 462 + 12:first_ebr + 462 + 16] = (9).to_bytes(4, "little")
    image[first_ebr + 510:first_ebr + 512] = b"\x55\xaa"

    second_ebr = 7 * sector_size
    image[second_ebr + 446 + 4] = 0x07
    image[second_ebr + 446 + 8:second_ebr + 446 + 12] = (1).to_bytes(4, "little")
    image[second_ebr + 446 + 12:second_ebr + 446 + 16] = (4).to_bytes(4, "little")
    image[second_ebr + 510:second_ebr + 512] = b"\x55\xaa"

    fat = 2 * sector_size
    image[fat:fat + 3] = b"\xeb\x3c\x90"
    image[fat + 11:fat + 13] = sector_size.to_bytes(2, "little")
    image[fat + 13] = 1
    image[fat + 14:fat + 16] = (1).to_bytes(2, "little")
    image[fat + 16] = 1
    image[fat + 17:fat + 19] = (16).to_bytes(2, "little")
    image[fat + 19:fat + 21] = (100).to_bytes(2, "little")
    image[fat + 21] = 0xF8
    image[fat + 22:fat + 24] = (1).to_bytes(2, "little")
    image[fat + 28:fat + 32] = (2).to_bytes(4, "little")
    image[fat + 510:fat + 512] = b"\x55\xaa"

    ntfs = 8 * sector_size
    image[ntfs:ntfs + 3] = b"\xeb\x52\x90"
    image[ntfs + 3:ntfs + 11] = b"NTFS    "
    image[ntfs + 11:ntfs + 13] = sector_size.to_bytes(2, "little")
    image[ntfs + 13] = 1
    image[ntfs + 21] = 0xF8
    image[ntfs + 28:ntfs + 32] = (8).to_bytes(4, "little")
    image[ntfs + 40:ntfs + 48] = (4).to_bytes(8, "little")
    image[ntfs + 48:ntfs + 56] = (1).to_bytes(8, "little")
    image[ntfs + 56:ntfs + 64] = (2).to_bytes(8, "little")
    image[ntfs + 64] = 0xF6
    image[ntfs + 68] = 0xF6
    image[ntfs + 510:ntfs + 512] = b"\x55\xaa"

    evidence = tmp_path / "ebr-logical-filesystems.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    chains = values["disk.mbr.ebr_chains"]
    assert len(chains) == 1
    assert chains[0]["termination"] == "end"
    assert chains[0]["errors"] == []
    assert chains[0]["extended_base_lba"] == 1
    assert chains[0]["ebr_records"][0]["logical_entry_relative_to"] == "current_ebr_lba"
    assert chains[0]["ebr_records"][0]["link_entry_relative_to"] == "extended_base_lba"
    assert chains[0]["ebr_records"][0]["link_entry"]["absolute_ebr_lba"] == 7
    logical = values["disk.mbr.logical_partitions"]
    assert [item["start_lba"] for item in logical] == [2, 8]
    assert [item["ebr_lba"] for item in logical] == [1, 7]
    assert logical[0]["entry_offset"] == first_ebr + 446
    assert logical[1]["entry_offset"] == second_ebr + 446
    extent_conflicts = values["disk.partition_extent_conflicts"]
    assert extent_conflicts["candidate_count"] == 2
    assert extent_conflicts["excluded_semantic_container_count"] == 1
    assert extent_conflicts["excluded_semantic_containers"][0]["identity"] == "mbr_primary:1"
    assert extent_conflicts["excluded_semantic_containers"][0]["partition_extent_role"] == "extended_container"
    assert extent_conflicts["excluded_semantic_containers"][0]["partition_length"] == 15 * sector_size
    assert extent_conflicts["conflict_count"] == 0
    assert logical[0]["partition_extent_identity"] == "mbr_logical:1"
    assert logical[0]["partition_extent_ambiguous"] is False

    filesystems = values["disk.mbr.logical_partition_filesystems"]
    assert [item["detected_filesystem"] for item in filesystems] == ["fat12", "ntfs"]
    assert filesystems[0]["partition_table"] == "mbr_logical"
    assert filesystems[0]["extended_base_lba"] == 1
    assert filesystems[0]["ebr_offset"] == first_ebr
    assert filesystems[0]["logical_entry_offset"] == first_ebr + 446
    assert filesystems[0]["boot_sector_offset"] == fat
    assert filesystems[0]["boot_declared_start_lba_matches_logical_entry"] is True
    assert filesystems[0]["partition_type_matches_detected"] is False
    assert filesystems[1]["ebr_offset"] == second_ebr
    assert filesystems[1]["boot_sector_offset"] == ntfs
    assert filesystems[1]["partition_type_matches_detected"] is True

    profile = ProfileEngine().evaluate(artifact, observations)
    logical_inventory = next(
        item for item in profile.findings
        if item.category == "mbr_logical_partition_filesystem_inventory"
    )
    assert "'logical_entry_offset': 958" in logical_inventory.supporting_evidence[0]
    assert not any(item.category == "ebr_chain_anomaly" for item in profile.findings)

    cyclic = bytearray(image)
    cyclic[second_ebr + 462 + 4] = 0x0F
    cyclic[second_ebr + 462 + 8:second_ebr + 462 + 12] = (6).to_bytes(4, "little")
    cyclic[second_ebr + 462 + 12:second_ebr + 462 + 16] = (9).to_bytes(4, "little")
    cyclic_path = tmp_path / "ebr-cycle.raw"
    cyclic_path.write_bytes(cyclic)
    cyclic_artifact = _artifact(cyclic_path)
    cyclic_observations = GenericTriageEngine().analyze(cyclic_artifact, cyclic_path)
    cyclic_chain = _values(cyclic_observations)["disk.mbr.ebr_chains"][0]
    assert cyclic_chain["termination"] == "cycle"
    assert cyclic_chain["errors"] == ["EBR chain cycles at LBA 7"]
    cyclic_profile = ProfileEngine().evaluate(cyclic_artifact, cyclic_observations)
    anomaly = next(
        item for item in cyclic_profile.findings if item.category == "ebr_chain_anomaly"
    )
    assert "'ebr_lba': 7" in anomaly.supporting_evidence[0]


def test_gpt_partition_filesystems_require_crc_validated_entries_and_keep_guid_provenance(tmp_path: Path) -> None:
    sector_size = 512
    image = bytearray(40 * sector_size)
    image[446 + 4] = 0xEE
    image[446 + 8:446 + 12] = (1).to_bytes(4, "little")
    image[446 + 12:446 + 16] = (39).to_bytes(4, "little")
    image[510:512] = b"\x55\xaa"

    esp_guid = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    entries = bytearray(256)
    for index, first_lba, last_lba, name in (
        (0, 4, 9, "EFI FAT"),
        (1, 10, 14, "MISLABELED NTFS"),
    ):
        offset = index * 128
        entries[offset:offset + 16] = esp_guid.bytes_le
        entries[offset + 16:offset + 32] = uuid.UUID(int=index + 1).bytes_le
        entries[offset + 32:offset + 40] = first_lba.to_bytes(8, "little")
        entries[offset + 40:offset + 48] = last_lba.to_bytes(8, "little")
        encoded_name = name.encode("utf-16le")
        entries[offset + 56:offset + 56 + len(encoded_name)] = encoded_name
    image[2 * sector_size:2 * sector_size + len(entries)] = entries

    header = bytearray(sector_size)
    header[:8] = b"EFI PART"
    header[8:12] = (0x00010000).to_bytes(4, "little")
    header[12:16] = (92).to_bytes(4, "little")
    header[24:32] = (1).to_bytes(8, "little")
    header[32:40] = (39).to_bytes(8, "little")
    header[40:48] = (4).to_bytes(8, "little")
    header[48:56] = (37).to_bytes(8, "little")
    header[56:72] = uuid.UUID(int=100).bytes_le
    header[72:80] = (2).to_bytes(8, "little")
    header[80:84] = (2).to_bytes(4, "little")
    header[84:88] = (128).to_bytes(4, "little")
    header[88:92] = (zlib.crc32(entries) & 0xFFFFFFFF).to_bytes(4, "little")
    crc_input = bytearray(header[:92])
    crc_input[16:20] = b"\x00" * 4
    header[16:20] = (zlib.crc32(crc_input) & 0xFFFFFFFF).to_bytes(4, "little")
    image[sector_size:2 * sector_size] = header
    image[38 * sector_size:38 * sector_size + len(entries)] = entries
    backup_header = bytearray(header)
    backup_header[16:20] = b"\x00" * 4
    backup_header[24:32] = (39).to_bytes(8, "little")
    backup_header[32:40] = (1).to_bytes(8, "little")
    backup_header[72:80] = (38).to_bytes(8, "little")
    backup_crc_input = bytearray(backup_header[:92])
    backup_crc_input[16:20] = b"\x00" * 4
    backup_header[16:20] = (
        zlib.crc32(backup_crc_input) & 0xFFFFFFFF
    ).to_bytes(4, "little")
    image[39 * sector_size:40 * sector_size] = backup_header

    fat = 4 * sector_size
    image[fat:fat + 3] = b"\xeb\x3c\x90"
    image[fat + 11:fat + 13] = sector_size.to_bytes(2, "little")
    image[fat + 13] = 1
    image[fat + 14:fat + 16] = (1).to_bytes(2, "little")
    image[fat + 16] = 1
    image[fat + 17:fat + 19] = (16).to_bytes(2, "little")
    image[fat + 19:fat + 21] = (100).to_bytes(2, "little")
    image[fat + 21] = 0xF8
    image[fat + 22:fat + 24] = (1).to_bytes(2, "little")
    image[fat + 28:fat + 32] = (4).to_bytes(4, "little")
    image[fat + 510:fat + 512] = b"\x55\xaa"

    ntfs = 10 * sector_size
    image[ntfs:ntfs + 3] = b"\xeb\x52\x90"
    image[ntfs + 3:ntfs + 11] = b"NTFS    "
    image[ntfs + 11:ntfs + 13] = sector_size.to_bytes(2, "little")
    image[ntfs + 13] = 1
    image[ntfs + 21] = 0xF8
    image[ntfs + 28:ntfs + 32] = (10).to_bytes(4, "little")
    image[ntfs + 40:ntfs + 48] = (5).to_bytes(8, "little")
    image[ntfs + 48:ntfs + 56] = (1).to_bytes(8, "little")
    image[ntfs + 56:ntfs + 64] = (2).to_bytes(8, "little")
    image[ntfs + 64] = 0xF6
    image[ntfs + 68] = 0xF6
    image[ntfs + 510:ntfs + 512] = b"\x55\xaa"

    evidence = tmp_path / "gpt-partition-filesystems.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    assert values["disk.gpt.header"]["header_crc_valid"] is True
    assert values["disk.gpt.header"]["partition_entry_crc_valid"] is True
    assert values["disk.gpt.header"]["backup"]["valid"] is True
    assert values["disk.gpt.header"]["backup"]["header_offset"] == 39 * sector_size
    assert values["disk.gpt.header"]["backup"]["partition_entry_offset"] == 38 * sector_size
    assert values["disk.gpt.header"]["backup"]["reciprocal_locations_match"] is True
    assert values["disk.gpt.header"]["backup"]["partition_entry_table_matches_primary"] is True
    assert values["disk.gpt.partition_filesystem_validation"]["eligible"] is True
    extent_conflicts = values["disk.partition_extent_conflicts"]
    assert extent_conflicts["candidate_count"] == 2
    assert extent_conflicts["excluded_semantic_container_count"] == 1
    assert extent_conflicts["excluded_semantic_containers"][0]["identity"] == "mbr_primary:1"
    assert extent_conflicts["excluded_semantic_containers"][0]["partition_extent_role"] == "gpt_protective_container"
    assert extent_conflicts["conflict_count"] == 0
    filesystems = values["disk.gpt.partition_filesystems"]
    assert len(filesystems) == 2
    assert filesystems[0]["partition_table"] == "gpt"
    assert filesystems[0]["gpt_partition_index"] == 1
    assert filesystems[0]["partition_type_guid"] == str(esp_guid)
    assert filesystems[0]["partition_unique_guid"] == str(uuid.UUID(int=1))
    assert filesystems[0]["partition_name"] == "EFI FAT"
    assert filesystems[0]["partition_offset"] == fat
    assert filesystems[0]["detected_filesystem"] == "fat12"
    assert filesystems[0]["expected_filesystems_from_type_guid"] == ["fat12", "fat16", "fat32"]
    assert filesystems[0]["partition_type_matches_detected"] is True
    assert filesystems[0]["boot_declared_start_lba_matches_gpt"] is True
    assert filesystems[1]["gpt_partition_index"] == 2
    assert filesystems[1]["partition_offset"] == ntfs
    assert filesystems[1]["detected_filesystem"] == "ntfs"
    assert filesystems[1]["partition_type_matches_detected"] is False
    assert filesystems[1]["boot_declared_volume_matches_partition"] is True

    profile = ProfileEngine().evaluate(artifact, observations)
    inventory = next(
        item for item in profile.findings
        if item.category == "gpt_partition_filesystem_inventory"
    )
    mismatch = next(
        item for item in profile.findings
        if item.category == "partition_type_filesystem_mismatch"
    )
    assert "'gpt_partition_index': 1" in inventory.supporting_evidence[0]
    assert str(esp_guid) in mismatch.supporting_evidence[0]
    assert not any(
        item.category == "gpt_backup_metadata_anomaly" for item in profile.findings
    )

    corrupt = bytearray(image)
    corrupt[2 * sector_size + 56] ^= 1
    corrupt_path = tmp_path / "gpt-corrupt-entry-table.raw"
    corrupt_path.write_bytes(corrupt)
    corrupt_observations = GenericTriageEngine().analyze(_artifact(corrupt_path), corrupt_path)
    corrupt_values = _values(corrupt_observations)
    assert corrupt_values["disk.gpt.header"]["partition_entry_crc_valid"] is False
    assert corrupt_values["disk.gpt.partition_filesystem_validation"]["eligible"] is False
    assert corrupt_values["disk.gpt.partition_filesystems"] == []

    backup_corrupt = bytearray(image)
    backup_corrupt[39 * sector_size + 16] ^= 1
    backup_corrupt_path = tmp_path / "gpt-corrupt-backup-header.raw"
    backup_corrupt_path.write_bytes(backup_corrupt)
    backup_artifact = _artifact(backup_corrupt_path)
    backup_observations = GenericTriageEngine().analyze(
        backup_artifact, backup_corrupt_path,
    )
    backup_values = _values(backup_observations)
    assert backup_values["disk.gpt.partition_filesystem_validation"]["eligible"] is True
    assert backup_values["disk.gpt.header"]["backup"]["header_crc_valid"] is False
    assert backup_values["disk.gpt.header"]["backup"]["valid"] is False
    backup_profile = ProfileEngine().evaluate(backup_artifact, backup_observations)
    backup_anomaly = next(
        item for item in backup_profile.findings
        if item.category == "gpt_backup_metadata_anomaly"
    )
    assert "'header_offset': 19968" in backup_anomaly.supporting_evidence[0]


def test_fat32_extflags_control_copy_consistency_and_active_chain_traversal(tmp_path: Path) -> None:
    sector_size = 512
    reserved = 1
    fat_size = 600
    fat_count = 2
    first_data_sector = reserved + fat_count * fat_size
    total_sectors = 70_000
    image = bytearray((first_data_sector + 6) * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = reserved.to_bytes(2, "little")
    image[16] = fat_count
    image[21] = 0xF8
    image[32:36] = total_sectors.to_bytes(4, "little")
    image[36:40] = fat_size.to_bytes(4, "little")
    image[40:42] = (0x0081).to_bytes(2, "little")  # mirroring disabled, FAT 1 active
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    fat0_offset = reserved * sector_size
    fat1_offset = (reserved + fat_size) * sector_size
    image[fat0_offset:fat0_offset + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    image[fat1_offset:fat1_offset + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    image[fat0_offset + 2 * 4:fat0_offset + 2 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[fat1_offset + 2 * 4:fat1_offset + 2 * 4 + 4] = (5).to_bytes(4, "little")
    image[fat1_offset + 5 * 4:fat1_offset + 5 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    root = first_data_sector * sector_size
    for index in range(sector_size // 32):
        offset = root + index * 32
        image[offset:offset + 11] = b"ACTIVE  TXT"
        image[offset + 11] = 0x20
    second_root_cluster = (first_data_sector + 3) * sector_size
    image[second_root_cluster:second_root_cluster + 11] = b"\xe5LAG    TXT"
    image[second_root_cluster + 11] = 0x20
    image[second_root_cluster + 26:second_root_cluster + 28] = (7).to_bytes(2, "little")
    image[second_root_cluster + 28:second_root_cluster + 32] = (12).to_bytes(4, "little")
    evidence = tmp_path / "fat32-active-copy-one.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    copies = values["filesystem.fat32.fat_copies"]
    assert copies["available"] is True
    assert copies["ext_flags"] == "0x0081"
    assert copies["mirroring_enabled"] is False
    assert copies["copies_expected_to_match"] is False
    assert copies["active_copy_index"] == 1
    assert copies["active_copy_index_valid"] is True
    assert copies["active_copy_available"] is True
    assert copies["selection_basis"] == "bpb_extflags_active_copy"
    assert copies["all_copies_match"] is False
    assert copies["copies"][0]["reserved_entries"]["entry0_masked"] == "0x0FFFFFF8"
    assert copies["copies"][0]["reserved_entries"]["entry1_masked"] == "0x0FFFFFFF"
    assert copies["copies"][0]["reserved_entries"]["entry1_clean_shutdown"] is True
    assert copies["copies"][0]["reserved_entries"]["entry1_no_io_errors"] is True
    assert copies["copies"][0]["reserved_entries"]["valid"] is True
    difference = copies["comparisons"][0]["first_difference"]
    assert difference["relative_offset"] == 8
    assert difference["reference_absolute_offset"] == fat0_offset + 8
    assert difference["compared_absolute_offset"] == fat1_offset + 8
    assert values["filesystem.fat.root.fat_mirroring_enabled"] is False
    assert values["filesystem.fat.root.active_fat_index"] == 1
    assert values["filesystem.fat.root.active_fat_offset"] == fat1_offset
    assert values["filesystem.fat.root.cluster_segments"] == [
        {"cluster": 2, "offset": root, "length": sector_size},
        {"cluster": 5, "offset": second_root_cluster, "length": sector_size},
    ]
    assert values["filesystem.fat.deleted_short_entries"][0]["offset"] == second_root_cluster
    profile = ProfileEngine().evaluate(artifact, observations)
    categories = {item.category for item in profile.findings}
    assert "fat32_fat_copy_inventory" in categories
    assert "fat32_fat_copy_anomaly" not in categories

    mirrored = bytearray(image)
    mirrored[40:42] = (0).to_bytes(2, "little")
    mirrored_path = tmp_path / "fat32-mirrored-divergence.raw"
    mirrored_path.write_bytes(mirrored)
    mirrored_observations = GenericTriageEngine().analyze(_artifact(mirrored_path), mirrored_path)
    mirrored_values = _values(mirrored_observations)
    assert mirrored_values["filesystem.fat32.fat_copies"]["mirroring_enabled"] is True
    assert mirrored_values["filesystem.fat32.fat_copies"]["all_copies_match"] is False
    assert mirrored_values["filesystem.fat.root.active_fat_index"] == 0
    assert mirrored_values["filesystem.fat.root.cluster_segments"] == [
        {"cluster": 2, "offset": root, "length": sector_size},
    ]
    mirrored_profile = ProfileEngine().evaluate(_artifact(mirrored_path), mirrored_observations)
    assert any(item.category == "fat32_fat_copy_anomaly" for item in mirrored_profile.findings)

    invalid_active = bytearray(image)
    invalid_active[40:42] = (0x0083).to_bytes(2, "little")
    invalid_active_path = tmp_path / "fat32-invalid-active-copy.raw"
    invalid_active_path.write_bytes(invalid_active)
    invalid_observations = GenericTriageEngine().analyze(_artifact(invalid_active_path), invalid_active_path)
    invalid_values = _values(invalid_observations)
    assert invalid_values["filesystem.fat32.fat_copies"]["active_copy_index_valid"] is False
    assert invalid_values["filesystem.fat32.fat_copies"]["active_copy_available"] is False
    assert invalid_values["filesystem.fat.root.available"] is False
    invalid_profile = ProfileEngine().evaluate(_artifact(invalid_active_path), invalid_observations)
    assert any(item.category == "fat32_fat_copy_anomaly" for item in invalid_profile.findings)

    malformed_inactive = bytearray(image)
    malformed_inactive[fat1_offset] = 0xF0
    malformed_inactive_path = tmp_path / "fat32-malformed-inactive-header.raw"
    malformed_inactive_path.write_bytes(malformed_inactive)
    malformed_observations = GenericTriageEngine().analyze(
        _artifact(malformed_inactive_path), malformed_inactive_path,
    )
    malformed_values = _values(malformed_observations)
    assert malformed_values["filesystem.fat32.fat_copies"]["copies"][1]["reserved_entries"]["valid"] is False
    malformed_profile = ProfileEngine().evaluate(_artifact(malformed_inactive_path), malformed_observations)
    malformed_categories = {item.category for item in malformed_profile.findings}
    assert "fat32_reserved_fat_entry_anomaly" in malformed_categories
    assert "fat32_fat_copy_anomaly" not in malformed_categories


def test_fat12_lost_chain_inventory_excludes_validated_active_file_chain(tmp_path: Path) -> None:
    sector_size = 512
    first_data_sector = 3
    image = bytearray(12 * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[17:19] = (16).to_bytes(2, "little")
    image[19:21] = (100).to_bytes(2, "little")
    image[21] = 0xF0
    image[22:24] = (1).to_bytes(2, "little")
    image[54:62] = b"FAT12   "
    image[510:512] = b"\x55\xaa"
    image[sector_size:sector_size + 3] = b"\xf0\xff\xff"

    def set_fat12(cluster: int, value: int) -> None:
        offset = sector_size + cluster + cluster // 2
        packed = int.from_bytes(image[offset:offset + 2], "little")
        if cluster & 1:
            packed = (packed & 0x000F) | ((value & 0x0FFF) << 4)
        else:
            packed = (packed & 0xF000) | (value & 0x0FFF)
        image[offset:offset + 2] = packed.to_bytes(2, "little")

    set_fat12(5, 0xFFF)
    set_fat12(7, 8)
    set_fat12(8, 0xFFF)
    root_offset = 2 * sector_size
    image[root_offset:root_offset + 11] = b"ACTIVE  TXT"
    image[root_offset + 11] = 0x20
    image[root_offset + 26:root_offset + 28] = (5).to_bytes(2, "little")
    image[root_offset + 28:root_offset + 32] = (20).to_bytes(4, "little")
    evidence = tmp_path / "fat12-lost-chain.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    inventory = values["filesystem.fat12.lost_chains"]
    assert inventory["available"] is True
    assert inventory["scan_complete_for_volume"] is True
    assert inventory["active_start_clusters"] == [5]
    assert inventory["allocated_cluster_count_in_scan"] == 3
    assert inventory["validated_reference_cluster_count_in_scan"] == 1
    assert inventory["unreferenced_allocated_cluster_count_in_scan"] == 2
    assert inventory["ownership_inferred"] is False
    assert inventory["content_recovered"] is False
    assert inventory["chains_truncated"] is False
    assert inventory["chains"] == [{
        "start_cluster": 7,
        "cluster_chain": [
            {
                "cluster": 7, "fat_entry_offset": sector_size + 10,
                "fat_entry_raw": bytes(image[sector_size + 10:sector_size + 12]).hex(),
                "next_cluster": 8, "data_offset": 8 * sector_size,
                "data_length": sector_size, "data_within_supplied_image": True,
            },
            {
                "cluster": 8, "fat_entry_offset": sector_size + 12,
                "fat_entry_raw": bytes(image[sector_size + 12:sector_size + 14]).hex(),
                "next_cluster": 0xFFF, "data_offset": 9 * sector_size,
                "data_length": sector_size, "data_within_supplied_image": True,
            },
        ],
        "termination": "eoc", "complete_eoc_chain": True,
    }]
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(
        item for item in profile.findings
        if item.category == "fat12_lost_allocation_chain_candidate"
    )
    assert "rather than proof of deletion" in finding.explanation


def test_fat12_subdirectory_invalid_active_and_deleted_lfns_keep_lineage(tmp_path: Path) -> None:
    sector_size = 512
    first_data_sector = 3
    image = bytearray(10 * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[17:19] = (16).to_bytes(2, "little")
    image[19:21] = (100).to_bytes(2, "little")
    image[21] = 0xF0
    image[22:24] = (1).to_bytes(2, "little")
    image[54:62] = b"FAT12   "
    image[510:512] = b"\x55\xaa"
    image[sector_size:sector_size + 3] = b"\xf0\xff\xff"

    def set_fat12(cluster: int, value: int) -> None:
        offset = sector_size + cluster + cluster // 2
        packed = int.from_bytes(image[offset:offset + 2], "little")
        if cluster & 1:
            packed = (packed & 0x000F) | ((value & 0x0FFF) << 4)
        else:
            packed = (packed & 0xF000) | (value & 0x0FFF)
        image[offset:offset + 2] = packed.to_bytes(2, "little")

    for cluster in (4, 5, 7):
        set_fat12(cluster, 0xFFF)
    root_offset = 2 * sector_size
    image[root_offset:root_offset + 11] = b"ACTIVE     "
    image[root_offset + 11] = 0x10
    image[root_offset + 26:root_offset + 28] = (7).to_bytes(2, "little")
    directory_offset = (first_data_sector + 5) * sector_size

    def lfn_slot(long_name: str, short_name: bytes, *, deleted: bool) -> bytearray:
        encoded_name = long_name.encode("utf-16le")
        units = [
            int.from_bytes(encoded_name[offset:offset + 2], "little")
            for offset in range(0, len(encoded_name), 2)
        ]
        units.extend([0, *([0xFFFF] * (12 - len(units)))])
        slot = bytearray(32)
        slot[0] = 0xE5 if deleted else 0x41
        slot[11] = 0x0F
        slot[13] = GenericTriageEngine._fat_short_name_checksum(short_name)
        encoded = b"".join(value.to_bytes(2, "little") for value in units)
        slot[1:11] = encoded[:10]
        slot[14:26] = encoded[10:22]
        slot[28:32] = encoded[22:26]
        return slot

    active_short_name = b"ACTIVE~1TXT"
    active_slot = lfn_slot("Broken.txt", active_short_name, deleted=False)
    active_slot[13] ^= 0xFF
    image[directory_offset:directory_offset + 32] = active_slot
    active_short_offset = directory_offset + 32
    image[active_short_offset:active_short_offset + 11] = active_short_name
    image[active_short_offset + 11] = 0x20
    image[active_short_offset + 26:active_short_offset + 28] = (4).to_bytes(2, "little")
    image[active_short_offset + 28:active_short_offset + 32] = (1).to_bytes(4, "little")

    deleted_short_name = b"DELETE~1TXT"
    deleted_slot_offset = directory_offset + 64
    deleted_slot = lfn_slot("Deleted.txt", deleted_short_name, deleted=True)
    deleted_slot[12] = 1
    image[deleted_slot_offset:deleted_slot_offset + 32] = deleted_slot
    deleted_short_offset = directory_offset + 96
    image[deleted_short_offset:deleted_short_offset + 11] = b"\xe5" + deleted_short_name[1:]
    image[deleted_short_offset + 11] = 0x20
    image[deleted_short_offset + 26:deleted_short_offset + 28] = (5).to_bytes(2, "little")
    image[deleted_short_offset + 28:deleted_short_offset + 32] = (1).to_bytes(4, "little")
    evidence = tmp_path / "fat12-subdirectory-invalid-lfns.raw"
    evidence.write_bytes(image)

    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)
    active_files = values["filesystem.fat12.root.recoverable_regular_files"]
    assert active_files[0]["short_name"] == "ACTIVE~1.TXT"
    assert "long_name" not in active_files[0]
    deleted = values["filesystem.fat12.root.subdirectory_deleted_entries"]
    assert deleted[0]["short_name"] == "?ELETE~1.TXT"
    assert "long_name" not in deleted[0]
    assert values["filesystem.fat12.root.unlinked_lfn_slots"] == [
        {
            "directory_start_cluster": 7,
            "directory_cluster_lineage": [7],
            "directory_source_entry_offset": root_offset,
            "short_entry_index": 1,
            "short_entry_offset": active_short_offset,
            "slot_offsets": [directory_offset],
            "reason": "active LFN checksum does not match the short entry",
            "raw_hex": [active_slot.hex()],
        },
        {
            "directory_start_cluster": 7,
            "directory_cluster_lineage": [7],
            "directory_source_entry_offset": root_offset,
            "short_entry_index": 3,
            "short_entry_offset": deleted_short_offset,
            "slot_offsets": [deleted_slot_offset],
            "reason": "LFN slot type, attributes, or first-cluster field is invalid",
            "raw_hex": [deleted_slot.hex()],
        },
    ]
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "fat12_unlinked_lfn_slots" for item in profile.findings)


def test_active_fat_root_lfn_orphans_keep_exact_slot_provenance(tmp_path: Path) -> None:
    sector_size = 512
    slot = bytearray(32)
    slot[0] = 0x41
    slot[11] = 0x0F
    encoded_name = "Orphan.txt".encode("utf-16le") + b"\x00\x00" + b"\xff\xff" * 3
    slot[1:11] = encoded_name[:10]
    slot[14:26] = encoded_name[10:22]
    slot[28:32] = encoded_name[22:26]

    fixed_variants = (
        (12, 1, 100, b"FAT12   ", b"\xf0\xff\xff", 2 * sector_size),
        (16, 17, 4_119, b"FAT16   ", b"\xf8\xff\xff\xff", 18 * sector_size),
    )
    for fat_bits, fat_size, total_sectors, label, fat_header, root_offset in fixed_variants:
        image = bytearray(root_offset + sector_size)
        image[11:13] = sector_size.to_bytes(2, "little")
        image[13] = 1
        image[14:16] = (1).to_bytes(2, "little")
        image[16] = 1
        image[17:19] = (16).to_bytes(2, "little")
        image[19:21] = total_sectors.to_bytes(2, "little")
        image[21] = 0xF0 if fat_bits == 12 else 0xF8
        image[22:24] = fat_size.to_bytes(2, "little")
        image[54:62] = label
        image[510:512] = b"\x55\xaa"
        image[sector_size:sector_size + len(fat_header)] = fat_header
        image[root_offset:root_offset + 32] = slot
        evidence = tmp_path / f"fat{fat_bits}-root-orphan-lfn.raw"
        evidence.write_bytes(image)

        artifact = _artifact(evidence)
        observations = GenericTriageEngine().analyze(artifact, evidence)
        values = _values(observations)
        assert values[f"filesystem.fat{fat_bits}.root.unlinked_lfn_slots"] == [{
            "short_entry_index": None,
            "short_entry_offset": None,
            "slot_offsets": [root_offset],
            "reason": "LFN slots are not followed by a short entry",
            "raw_hex": [slot.hex()],
        }]
        assert any(
            item.category == f"fat{fat_bits}_unlinked_lfn_slots"
            for item in ProfileEngine().evaluate(artifact, observations).findings
        )

    fat32 = bytearray(4 * sector_size)
    fat32[11:13] = sector_size.to_bytes(2, "little")
    fat32[13] = 1
    fat32[14:16] = (1).to_bytes(2, "little")
    fat32[16] = 1
    fat32[32:36] = (8).to_bytes(4, "little")
    fat32[36:40] = (1).to_bytes(4, "little")
    fat32[44:48] = (2).to_bytes(4, "little")
    fat32[82:90] = b"FAT32   "
    fat32[510:512] = b"\x55\xaa"
    fat32[sector_size:sector_size + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    fat32[sector_size + 8:sector_size + 12] = (0x0FFFFFFF).to_bytes(4, "little")
    fat32_root_offset = 2 * sector_size
    fat32[fat32_root_offset:fat32_root_offset + 32] = slot
    fat32_path = tmp_path / "fat32-root-orphan-lfn.raw"
    fat32_path.write_bytes(fat32)
    fat32_artifact = _artifact(fat32_path)
    fat32_observations = GenericTriageEngine().analyze(fat32_artifact, fat32_path)
    fat32_values = _values(fat32_observations)
    assert fat32_values["filesystem.fat.unlinked_lfn_slots"] == [{
        "short_entry_index": None,
        "short_entry_offset": None,
        "slot_offsets": [fat32_root_offset],
        "reason": "LFN slots are not followed by a short entry",
        "raw_hex": [slot.hex()],
    }]
    assert any(
        item.category == "fat32_unlinked_lfn_slots"
        for item in ProfileEngine().evaluate(fat32_artifact, fat32_observations).findings
    )


def test_active_fat_root_directory_lfns_are_validated_before_inventory(tmp_path: Path) -> None:
    sector_size = 512
    valid_short = b"VALIDD~1   "
    invalid_short = b"BROKEN~1   "

    def lfn_slot(name: str, short_name: bytes) -> bytearray:
        units = [
            int.from_bytes(name.encode("utf-16le")[offset:offset + 2], "little")
            for offset in range(0, len(name.encode("utf-16le")), 2)
        ]
        units.extend([0, *([0xFFFF] * (12 - len(units)))])
        result = bytearray(32)
        result[0] = 0x41
        result[11] = 0x0F
        result[13] = GenericTriageEngine._fat_short_name_checksum(short_name)
        encoded = b"".join(value.to_bytes(2, "little") for value in units)
        result[1:11] = encoded[:10]
        result[14:26] = encoded[10:22]
        result[28:32] = encoded[22:26]
        return result

    valid_slot = lfn_slot("Valid Dir", valid_short)
    invalid_slot = lfn_slot("Broken Dir", invalid_short)
    invalid_slot[13] ^= 0xFF
    nested_valid_short = b"NVALID~1   "
    nested_invalid_short = b"NBROKE~1   "
    nested_valid_slot = lfn_slot("Valid Nested", nested_valid_short)
    nested_invalid_slot = lfn_slot("Broken Nest", nested_invalid_short)
    nested_invalid_slot[13] ^= 0xFF

    def write_root_entries(image: bytearray, root_offset: int, clusters: tuple[int, int]) -> None:
        image[root_offset:root_offset + 32] = valid_slot
        first_short_offset = root_offset + 32
        image[first_short_offset:first_short_offset + 11] = valid_short
        image[first_short_offset + 11] = 0x10
        image[first_short_offset + 26:first_short_offset + 28] = clusters[0].to_bytes(2, "little")
        image[root_offset + 64:root_offset + 96] = invalid_slot
        second_short_offset = root_offset + 96
        image[second_short_offset:second_short_offset + 11] = invalid_short
        image[second_short_offset + 11] = 0x10
        image[second_short_offset + 26:second_short_offset + 28] = clusters[1].to_bytes(2, "little")

    def write_nested_entry(
        image: bytearray, directory_offset: int, short_name: bytes,
        slot_bytes: bytes, child_cluster: int,
    ) -> None:
        image[directory_offset:directory_offset + 32] = slot_bytes
        short_offset = directory_offset + 32
        image[short_offset:short_offset + 11] = short_name
        image[short_offset + 11] = 0x10
        image[short_offset + 26:short_offset + 28] = child_cluster.to_bytes(2, "little")

    def write_deep_file(image: bytearray, directory_offset: int, file_cluster: int) -> None:
        image[directory_offset:directory_offset + 11] = b"DEEP    TXT"
        image[directory_offset + 11] = 0x20
        image[directory_offset + 26:directory_offset + 28] = file_cluster.to_bytes(2, "little")
        image[directory_offset + 28:directory_offset + 32] = (1).to_bytes(4, "little")

    fixed_variants = (
        (12, 1, 100, b"FAT12   ", 2 * sector_size, 3),
        (16, 17, 4_119, b"FAT16   ", 18 * sector_size, 19),
    )
    for fat_bits, fat_size, total_sectors, label, root_offset, first_data_sector in fixed_variants:
        image = bytearray((first_data_sector + 5) * sector_size)
        image[11:13] = sector_size.to_bytes(2, "little")
        image[13] = 1
        image[14:16] = (1).to_bytes(2, "little")
        image[16] = 1
        image[17:19] = (16).to_bytes(2, "little")
        image[19:21] = total_sectors.to_bytes(2, "little")
        image[21] = 0xF0 if fat_bits == 12 else 0xF8
        image[22:24] = fat_size.to_bytes(2, "little")
        image[54:62] = label
        image[510:512] = b"\x55\xaa"
        if fat_bits == 12:
            image[sector_size:sector_size + 3] = b"\xf0\xff\xff"
            for cluster in (2, 3, 4, 5, 6):
                offset = sector_size + cluster + cluster // 2
                packed = int.from_bytes(image[offset:offset + 2], "little")
                if cluster & 1:
                    packed = (packed & 0x000F) | (0xFFF << 4)
                else:
                    packed = (packed & 0xF000) | 0xFFF
                image[offset:offset + 2] = packed.to_bytes(2, "little")
        else:
            image[sector_size:sector_size + 4] = b"\xf8\xff\xff\xff"
            for cluster in (2, 3, 4, 5, 6):
                offset = sector_size + cluster * 2
                image[offset:offset + 2] = (0xFFFF).to_bytes(2, "little")
        write_root_entries(image, root_offset, (2, 3))
        first_directory_offset = first_data_sector * sector_size
        second_directory_offset = (first_data_sector + 1) * sector_size
        write_nested_entry(
            image, first_directory_offset, nested_valid_short, nested_valid_slot, 4,
        )
        write_nested_entry(
            image, second_directory_offset, nested_invalid_short, nested_invalid_slot, 5,
        )
        deep_directory_offset = (first_data_sector + 2) * sector_size
        write_deep_file(image, deep_directory_offset, 6)
        path = tmp_path / f"fat{fat_bits}-root-directory-lfns.raw"
        path.write_bytes(image)
        values = _values(GenericTriageEngine().analyze(_artifact(path), path))
        inventory = values[f"filesystem.fat{fat_bits}.root.subdirectory_inventory"]
        assert inventory[0]["long_name"] == "Valid Dir"
        assert inventory[0]["lfn_slot_offsets"] == [root_offset]
        assert "long_name" not in inventory[1]
        assert inventory[2]["long_name"] == "Valid Nested"
        assert inventory[2]["lfn_slot_offsets"] == [first_directory_offset]
        assert inventory[2]["parent_cluster_lineage"] == [2]
        assert "long_name" not in inventory[3]
        active_files = values[f"filesystem.fat{fat_bits}.root.recoverable_regular_files"]
        deep_file = next(item for item in active_files if item["short_name"] == "DEEP.TXT")
        assert deep_file["directory_identity_lineage"] == [
            {
                "short_name": "VALIDD~1", "long_name": "Valid Dir",
                "source_entry_offset": root_offset + 32,
                "lfn_slot_offsets": [root_offset], "start_cluster": 2,
            },
            {
                "short_name": "NVALID~1", "long_name": "Valid Nested",
                "source_entry_offset": first_directory_offset + 32,
                "lfn_slot_offsets": [first_directory_offset], "start_cluster": 4,
            },
        ]
        assert values[f"filesystem.fat{fat_bits}.root.unlinked_lfn_slots"] == [
            {
                "short_entry_index": 3,
                "short_entry_offset": root_offset + 96,
                "slot_offsets": [root_offset + 64],
                "reason": "active LFN checksum does not match the short entry",
                "raw_hex": [invalid_slot.hex()],
            },
            {
                "directory_start_cluster": 3,
                "directory_cluster_lineage": [3],
                "directory_source_entry_offset": root_offset + 96,
                "short_entry_index": 1,
                "short_entry_offset": second_directory_offset + 32,
                "slot_offsets": [second_directory_offset],
                "reason": "active LFN checksum does not match the short entry",
                "raw_hex": [nested_invalid_slot.hex()],
            },
        ]

    fat32_first_data_sector = 2
    fat32 = bytearray((fat32_first_data_sector + 6) * sector_size)
    fat32[11:13] = sector_size.to_bytes(2, "little")
    fat32[13] = 1
    fat32[14:16] = (1).to_bytes(2, "little")
    fat32[16] = 1
    fat32[32:36] = (8).to_bytes(4, "little")
    fat32[36:40] = (1).to_bytes(4, "little")
    fat32[44:48] = (2).to_bytes(4, "little")
    fat32[82:90] = b"FAT32   "
    fat32[510:512] = b"\x55\xaa"
    fat32[sector_size:sector_size + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    for cluster in (2, 3, 4, 5, 6, 7):
        offset = sector_size + cluster * 4
        fat32[offset:offset + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    fat32_root_offset = fat32_first_data_sector * sector_size
    write_root_entries(fat32, fat32_root_offset, (3, 4))
    fat32_first_directory_offset = (fat32_first_data_sector + 1) * sector_size
    fat32_second_directory_offset = (fat32_first_data_sector + 2) * sector_size
    write_nested_entry(
        fat32, fat32_first_directory_offset, nested_valid_short, nested_valid_slot, 5,
    )
    write_nested_entry(
        fat32, fat32_second_directory_offset, nested_invalid_short, nested_invalid_slot, 6,
    )
    fat32_deep_directory_offset = (fat32_first_data_sector + 3) * sector_size
    write_deep_file(fat32, fat32_deep_directory_offset, 7)
    fat32_path = tmp_path / "fat32-root-directory-lfns.raw"
    fat32_path.write_bytes(fat32)
    fat32_values = _values(GenericTriageEngine().analyze(_artifact(fat32_path), fat32_path))
    fat32_inventory = fat32_values["filesystem.fat.subdirectory_inventory"]
    assert fat32_inventory[0]["long_name"] == "Valid Dir"
    assert fat32_inventory[0]["lfn_slot_offsets"] == [fat32_root_offset]
    assert "long_name" not in fat32_inventory[1]
    assert fat32_inventory[2]["long_name"] == "Valid Nested"
    assert fat32_inventory[2]["lfn_slot_offsets"] == [fat32_first_directory_offset]
    assert fat32_inventory[2]["parent_cluster_lineage"] == [3]
    assert "long_name" not in fat32_inventory[3]
    fat32_active_files = fat32_values["filesystem.fat.root.recoverable_regular_files"]
    fat32_deep_file = next(item for item in fat32_active_files if item["short_name"] == "DEEP.TXT")
    assert fat32_deep_file["directory_identity_lineage"] == [
        {
            "short_name": "VALIDD~1", "long_name": "Valid Dir",
            "source_entry_offset": fat32_root_offset + 32,
            "lfn_slot_offsets": [fat32_root_offset], "start_cluster": 3,
        },
        {
            "short_name": "NVALID~1", "long_name": "Valid Nested",
            "source_entry_offset": fat32_first_directory_offset + 32,
            "lfn_slot_offsets": [fat32_first_directory_offset], "start_cluster": 5,
        },
    ]
    assert fat32_values["filesystem.fat.unlinked_lfn_slots"] == [
        {
            "short_entry_index": 3,
            "short_entry_offset": fat32_root_offset + 96,
            "slot_offsets": [fat32_root_offset + 64],
            "reason": "active LFN checksum does not match the short entry",
            "raw_hex": [invalid_slot.hex()],
        },
        {
            "directory_start_cluster": 4,
            "directory_cluster_lineage": [4],
            "directory_source_entry_offset": fat32_root_offset + 96,
            "short_entry_index": 1,
            "short_entry_offset": fat32_second_directory_offset + 32,
            "slot_offsets": [fat32_second_directory_offset],
            "reason": "active LFN checksum does not match the short entry",
            "raw_hex": [nested_invalid_slot.hex()],
        },
    ]


def test_fat32_deleted_lfn_chain_requires_checksum_and_terminal_validation(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (8).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    short_name = b"VERYL~1 TXT"
    checksum = GenericTriageEngine._fat_short_name_checksum(short_name)
    long_name = "Very Long Flag.txt"
    units = [int.from_bytes(long_name.encode("utf-16le")[i:i + 2], "little") for i in range(0, len(long_name.encode("utf-16le")), 2)]
    units.extend([0, *([0xFFFF] * (26 - len(units) - 1))])
    root = 1024
    for physical_index, chunk_index in enumerate((1, 0)):
        slot = bytearray(32)
        slot[0] = 0xE5
        slot[11] = 0x0F
        slot[13] = checksum
        chunk = units[chunk_index * 13:(chunk_index + 1) * 13]
        encoded = b"".join(value.to_bytes(2, "little") for value in chunk)
        slot[1:11] = encoded[:10]
        slot[14:26] = encoded[10:22]
        slot[28:32] = encoded[22:26]
        image[root + physical_index * 32:root + (physical_index + 1) * 32] = slot
    short_offset = root + 64
    image[short_offset:short_offset + 11] = b"\xe5ERYL~1 TXT"
    image[short_offset + 11] = 0x20
    image[short_offset + 26:short_offset + 28] = (7).to_bytes(2, "little")
    image[short_offset + 28:short_offset + 32] = (321).to_bytes(4, "little")
    # A second two-slot chain has inconsistent checksums and must remain unlinked.
    bad_slot_one = bytearray(image[root:root + 32])
    bad_slot_two = bytearray(image[root + 32:root + 64])
    bad_slot_one[13] ^= 0xFF
    image[root + 96:root + 128] = bad_slot_one
    image[root + 128:root + 160] = bad_slot_two
    image[root + 160:root + 171] = b"\xe5THER~1 TXT"
    image[root + 171] = 0x20
    evidence = tmp_path / "fat32-lfn.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    recovered = values["filesystem.fat.deleted_short_entries"][0]
    assert recovered["long_name"] == long_name
    assert recovered["reconstructed_short_name"] == "VERYL~1.TXT"
    assert recovered["recovered_short_first_byte"] == "0x56"
    assert recovered["lfn_slot_offsets"] == [1024, 1056]
    assert recovered["lfn_ordinal_bytes_destroyed"] is True
    assert recovered["lfn_order_validation"] == "contiguous_deleted_slots_physical_order"
    assert recovered["lfn_terminal_validation"] == "nul_terminator_with_ffff_padding"
    assert len(values["filesystem.fat.unlinked_lfn_slots"]) == 1
    assert "checksum" in values["filesystem.fat.unlinked_lfn_slots"][0]["reason"]
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "fat_deleted_lfn_entry" for item in profile.findings)


def test_fat32_root_chain_reaches_noncontiguous_cluster_and_stops_loop(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (8).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    # Root cluster 2 -> noncontiguous cluster 5 -> cluster 2 loop.
    image[512 + 2 * 4:512 + 2 * 4 + 4] = (5).to_bytes(4, "little")
    image[512 + 5 * 4:512 + 5 * 4 + 4] = (2).to_bytes(4, "little")
    # Avoid an end marker in cluster 2 so parsing reaches the second cluster.
    for index in range(16):
        offset = 1024 + index * 32
        image[offset:offset + 11] = b"ACTIVE  TXT"
        image[offset + 11] = 0x20
    second = 2560
    image[second:second + 11] = b"\xe5ECOND  BIN"
    image[second + 11] = 0x20
    image[second + 26:second + 28] = (9).to_bytes(2, "little")
    image[second + 28:second + 32] = (456).to_bytes(4, "little")
    evidence = tmp_path / "fat32-chain.raw"
    evidence.write_bytes(image)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.fat.root.cluster_segments"] == [
        {"cluster": 2, "offset": 1024, "length": 512},
        {"cluster": 5, "offset": 2560, "length": 512},
    ]
    assert values["filesystem.fat.root.chain_termination"] == "loop"
    assert "loops at cluster 2" in values["filesystem.fat.root.chain_errors"][0]
    recovered = values["filesystem.fat.deleted_short_entries"][0]
    assert recovered["offset"] == 2560
    assert recovered["short_name"] == "?ECOND.BIN"
    assert recovered["first_cluster"] == 9
    assert recovered["size"] == 456


def test_fat32_active_subdirectory_is_bounded_but_deleted_directory_is_not_traversed(tmp_path: Path) -> None:
    image = bytearray(5120)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (10).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    for cluster in (2, 5, 6):
        image[512 + cluster * 4:512 + cluster * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    root = 1024
    image[root:root + 11] = b"ACTIVE     "
    image[root + 11] = 0x10
    image[root + 26:root + 28] = (5).to_bytes(2, "little")
    deleted_dir = root + 32
    image[deleted_dir:deleted_dir + 11] = b"\xe5ELETED    "
    image[deleted_dir + 11] = 0x10
    image[deleted_dir + 26:deleted_dir + 28] = (6).to_bytes(2, "little")
    active_content = 2560
    image[active_content:active_content + 11] = b"\xe5HILD   TXT"
    image[active_content + 11] = 0x20
    image[active_content + 26:active_content + 28] = (8).to_bytes(2, "little")
    image[active_content + 28:active_content + 32] = (77).to_bytes(4, "little")
    deleted_content = 3072
    image[deleted_content:deleted_content + 11] = b"\xe5IDDEN  BIN"
    image[deleted_content + 11] = 0x20
    evidence = tmp_path / "fat32-subdir.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["filesystem.fat.subdirectory_inventory"] == [{
        "name": "ACTIVE", "start_cluster": 5, "source_entry_offset": 1024,
        "parent_cluster_lineage": [],
        "directory_identity_lineage": [{
            "short_name": "ACTIVE", "long_name": None,
            "source_entry_offset": 1024, "lfn_slot_offsets": None,
            "start_cluster": 5,
        }],
        "cluster_chain": [{
            "cluster": 5, "offset": 2560, "length": 512,
            "fat_entry_offset": 532, "fat_entry_raw": "ffffff0f",
            "next_cluster": 0x0FFFFFFF,
        }],
        "termination": "eoc",
    }]
    assert values["filesystem.fat.subdirectory_deleted_entries"] == [{
        "directory_start_cluster": 5, "directory_cluster_lineage": [5],
        "directory_source_entry_offset": 1024,
        "directory_short_name": "ACTIVE", "directory_long_name": None,
        "directory_lfn_slot_offsets": None,
        "directory_identity_lineage": [{
            "short_name": "ACTIVE", "long_name": None,
            "source_entry_offset": 1024, "lfn_slot_offsets": None,
            "start_cluster": 5,
        }],
        "entry_index": 0,
        "offset": 2560, "short_name": "?HILD.TXT", "first_character_unknown": True,
        "attributes": "0x20", "first_cluster": 8,
        "cluster_field_raw": "0x00000008", "fat32_cluster_high_reserved": 0,
        "size": 77,
        "raw_hex": bytes(image[active_content:active_content + 32]).hex(),
    }]
    assert not any(item.get("short_name") == "?IDDEN.BIN" for item in values["filesystem.fat.subdirectory_deleted_entries"])
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(item for item in profile.findings if item.category == "fat_subdirectory_deleted_entry")
    assert "directory_cluster_lineage': [5]" in finding.supporting_evidence[0]


def test_exfat_deleted_root_file_set_requires_restored_checksum(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[3:11] = b"EXFAT   "
    image[80:84] = (1).to_bytes(4, "little")
    image[84:88] = (1).to_bytes(4, "little")
    image[88:92] = (2).to_bytes(4, "little")
    image[92:96] = (6).to_bytes(4, "little")
    image[96:100] = (2).to_bytes(4, "little")
    image[108] = 9
    image[109] = 0
    image[110] = 1
    image[510:512] = b"\x55\xaa"
    image[512 + 2 * 4:512 + 2 * 4 + 4] = (5).to_bytes(4, "little")
    image[512 + 5 * 4:512 + 5 * 4 + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    for root_index in range(16):
        image[1024 + root_index * 32] = 0x81
    primary = bytearray(32)
    primary[0] = 0x85
    primary[1] = 2
    primary[4:6] = (0x20).to_bytes(2, "little")
    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 2
    name = "deleted.txt"
    stream[3] = len(name)
    stream[4:6] = (0x1234).to_bytes(2, "little")
    stream[8:16] = (77).to_bytes(8, "little")
    stream[20:24] = (5).to_bytes(4, "little")
    stream[24:32] = (77).to_bytes(8, "little")
    name_entry = bytearray(32)
    name_entry[0] = 0xC1
    name_entry[2:2 + len(name.encode("utf-16le"))] = name.encode("utf-16le")
    checksum = GenericTriageEngine._exfat_entry_set_checksum([
        bytes(primary), bytes(stream), bytes(name_entry)
    ])
    primary[2:4] = checksum.to_bytes(2, "little")
    primary[0], stream[0], name_entry[0] = 0x05, 0x40, 0x41
    root = 2560
    image[root:root + 32] = primary
    image[root + 32:root + 64] = stream
    image[root + 64:root + 96] = name_entry
    evidence = tmp_path / "exfat.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["triage.detected_header_format"] == "exfat"
    assert values["filesystem.type"] == "exfat"
    assert values["filesystem.exfat.root_offset"] == 1024
    assert values["filesystem.exfat.root_cluster_segments"] == [
        {"cluster": 2, "offset": 1024, "length": 512},
        {"cluster": 5, "offset": 2560, "length": 512},
    ]
    assert values["filesystem.exfat.root_chain_termination"] == "eoc"
    recovered = values["filesystem.exfat.deleted_file_sets"][0]
    assert recovered["name"] == name
    assert recovered["entry_offsets"] == [2560, 2592, 2624]
    assert recovered["first_cluster"] == 5 and recovered["data_length"] == 77
    assert recovered["stored_set_checksum"] == f"0x{checksum:04X}"
    assert recovered["checksum_valid_after_in_use_restore"] is True
    assert recovered["name_hash_validation"] == "not_verified_without_upcase_table"
    identified = IdentificationEngine().identify(artifact, observations)
    assert identified.format == "exfat" and artifact.artifact_type == "filesystem"
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    assert any(item.category == "exfat_deleted_file_entry" for item in profile.findings)


def test_exfat_main_backup_boot_regions_validate_checksums_and_exact_divergence(tmp_path: Path) -> None:
    sector_size = 512
    region_size = 12 * sector_size
    image = bytearray(40 * sector_size)
    image[3:11] = b"EXFAT   "
    image[72:80] = (40).to_bytes(8, "little")
    image[80:84] = (24).to_bytes(4, "little")
    image[84:88] = (1).to_bytes(4, "little")
    image[88:92] = (26).to_bytes(4, "little")
    image[92:96] = (10).to_bytes(4, "little")
    image[96:100] = (2).to_bytes(4, "little")
    image[108], image[109], image[110] = 9, 0, 1
    image[510:512] = b"\x55\xaa"
    for sector in range(1, 9):
        image[(sector + 1) * sector_size - 4:(sector + 1) * sector_size] = b"\x00\x00\x55\xaa"
    image[region_size:2 * region_size] = image[:region_size]
    image[region_size + 100] = 0x44
    main_checksum = GenericTriageEngine._exfat_boot_checksum(bytes(image[:11 * sector_size]))
    backup_checksum = GenericTriageEngine._exfat_boot_checksum(
        bytes(image[region_size:region_size + 11 * sector_size])
    )
    image[11 * sector_size:region_size] = main_checksum.to_bytes(4, "little") * (sector_size // 4)
    image[region_size + 11 * sector_size:2 * region_size] = (
        backup_checksum.to_bytes(4, "little") * (sector_size // 4)
    )
    image[24 * sector_size + 2 * 4:24 * sector_size + 2 * 4 + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    evidence = tmp_path / "exfat-boot-regions.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    main = values["filesystem.exfat.boot_regions.main"]
    backup = values["filesystem.exfat.boot_regions.backup"]
    assert main["checksum_valid"] is True and main["checksum_repeated"] is True
    assert backup["checksum_valid"] is True and backup["extended_boot_signatures_valid"] is True
    assert values["filesystem.exfat.boot_regions.immutable_fields_match"] is False
    assert values["filesystem.exfat.boot_regions.difference_count"] == 1
    assert values["filesystem.exfat.boot_regions.first_immutable_difference"] == {
        "relative_offset": 100, "main_absolute_offset": 100,
        "backup_absolute_offset": region_size + 100,
        "main_byte": "0x00", "backup_byte": "0x44",
    }
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "exfat_backup_boot_mismatch" for item in profile.findings)

    image[11 * sector_size + 4:11 * sector_size + 8] = (main_checksum ^ 1).to_bytes(4, "little")
    corrupt = tmp_path / "exfat-checksum-copy.raw"
    corrupt.write_bytes(image)
    corrupt_artifact = _artifact(corrupt)
    corrupt_observations = GenericTriageEngine().analyze(corrupt_artifact, corrupt)
    corrupt_values = _values(corrupt_observations)
    assert corrupt_values["filesystem.exfat.boot_regions.main"]["checksum_repeated"] is False
    assert corrupt_values["filesystem.exfat.boot_regions.main"]["checksum_valid"] is False
    corrupt_profile = ProfileEngine().evaluate(corrupt_artifact, corrupt_observations)
    assert any(item.category == "exfat_boot_region_anomaly" for item in corrupt_profile.findings)


def test_exfat_bitmap_upcase_validation_rechecks_name_hash_and_warns_on_reuse(tmp_path: Path) -> None:
    image = bytearray(8192)
    image[3:11] = b"EXFAT   "
    image[80:84] = (1).to_bytes(4, "little")
    image[84:88] = (1).to_bytes(4, "little")
    image[88:92] = (2).to_bytes(4, "little")
    image[92:96] = (12).to_bytes(4, "little")
    image[96:100] = (2).to_bytes(4, "little")
    image[108] = 9
    image[109] = 0
    image[110] = 1
    image[510:512] = b"\x55\xaa"
    for cluster, next_cluster in ((2, 5), (3, 0xFFFFFFFF), (4, 0xFFFFFFFF), (5, 0xFFFFFFFF)):
        image[512 + cluster * 4:512 + cluster * 4 + 4] = next_cluster.to_bytes(4, "little")

    bitmap_entry = bytearray(32)
    bitmap_entry[0] = 0x81
    bitmap_entry[20:24] = (3).to_bytes(4, "little")
    bitmap_entry[24:32] = (2).to_bytes(8, "little")
    image[1024:1056] = bitmap_entry

    words = [0xFFFF, 97, *range(65, 91), 0xFFFF, 65_535 - 123, 0xFFFF]
    upcase_data = b"".join(value.to_bytes(2, "little") for value in words)
    mapping = GenericTriageEngine._decode_exfat_upcase_table(upcase_data)
    assert mapping is not None
    upcase_entry = bytearray(32)
    upcase_entry[0] = 0x82
    upcase_entry[4:8] = GenericTriageEngine._exfat_upcase_checksum(upcase_data).to_bytes(4, "little")
    upcase_entry[20:24] = (4).to_bytes(4, "little")
    upcase_entry[24:32] = len(upcase_data).to_bytes(8, "little")
    image[1056:1088] = upcase_entry
    for root_index in range(2, 16):
        image[1024 + root_index * 32] = 0xA0
    image[1536:1538] = b"\x1f\x00"  # root/system clusters plus deleted cluster 6 are allocated now.
    image[2048:2048 + len(upcase_data)] = upcase_data

    name = "deleted.txt"
    raw_name = name.encode("utf-16le")
    primary = bytearray(32)
    primary[0], primary[1] = 0x85, 2
    primary[4:6] = (0x20).to_bytes(2, "little")
    stream = bytearray(32)
    stream[0], stream[1], stream[3] = 0xC0, 0x02, len(name)
    stream[4:6] = GenericTriageEngine._exfat_name_hash(raw_name, mapping).to_bytes(2, "little")
    stream[8:16] = (32).to_bytes(8, "little")
    stream[20:24] = (6).to_bytes(4, "little")
    stream[24:32] = (32).to_bytes(8, "little")
    name_entry = bytearray(32)
    name_entry[0] = 0xC1
    name_entry[2:2 + len(raw_name)] = raw_name
    checksum = GenericTriageEngine._exfat_entry_set_checksum([
        bytes(primary), bytes(stream), bytes(name_entry)
    ])
    primary[2:4] = checksum.to_bytes(2, "little")
    primary[0], stream[0], name_entry[0] = 0x05, 0x40, 0x41
    image[2560:2592] = primary
    image[2592:2624] = stream
    image[2624:2656] = name_entry
    evidence = tmp_path / "exfat-system-files.raw"
    evidence.write_bytes(image)

    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    bitmap = values["filesystem.exfat.allocation_bitmaps"][0]
    assert bitmap["validation"] == "valid"
    assert bitmap["allocated_cluster_count"] == 5
    assert bitmap["system_allocation_consistent"] is True
    upcase = values["filesystem.exfat.upcase_tables"][0]
    assert upcase["checksum_valid"] is True and upcase["mapping_complete"] is True
    deleted = values["filesystem.exfat.deleted_file_sets"][0]
    assert deleted["name_hash_validation"] == "valid"
    assert deleted["calculated_name_hash"] == deleted["name_hash"]
    assert deleted["allocation_bitmap_cluster_states"] == [{"cluster": 6, "allocated": True}]
    assert deleted["allocation_reuse_warning"] is True
    assert deleted["allocation_bitmap_interpretation"] == "current_allocation_state_only_not_deleted_file_ownership"
    profile = ProfileEngine().evaluate(artifact, observations)
    reuse = next(item for item in profile.findings if item.category == "exfat_deleted_cluster_reuse_warning")
    assert "not proof" in reuse.explanation


def test_exfat_active_nofatchain_subdirectory_inventories_deleted_file_set(tmp_path: Path) -> None:
    image = bytearray(5120)
    image[3:11] = b"EXFAT   "
    image[80:84] = (1).to_bytes(4, "little")
    image[84:88] = (1).to_bytes(4, "little")
    image[88:92] = (2).to_bytes(4, "little")
    image[92:96] = (8).to_bytes(4, "little")
    image[96:100] = (2).to_bytes(4, "little")
    image[108], image[109], image[110] = 9, 0, 1
    image[510:512] = b"\x55\xaa"
    image[512 + 2 * 4:512 + 2 * 4 + 4] = (0xFFFFFFFF).to_bytes(4, "little")

    directory_name = "ACTIVE"
    active_primary = bytearray(32)
    active_primary[0], active_primary[1] = 0x85, 2
    active_primary[4:6] = (0x10).to_bytes(2, "little")
    active_stream = bytearray(32)
    active_stream[0], active_stream[1], active_stream[3] = 0xC0, 0x02, len(directory_name)
    active_stream[8:16] = (512).to_bytes(8, "little")
    active_stream[20:24] = (3).to_bytes(4, "little")
    active_stream[24:32] = (512).to_bytes(8, "little")
    active_name = bytearray(32)
    active_name[0] = 0xC1
    active_name[2:2 + len(directory_name.encode("utf-16le"))] = directory_name.encode("utf-16le")
    active_checksum = GenericTriageEngine._exfat_entry_set_checksum([
        bytes(active_primary), bytes(active_stream), bytes(active_name)
    ])
    active_primary[2:4] = active_checksum.to_bytes(2, "little")
    image[1024:1056] = active_primary
    image[1056:1088] = active_stream
    image[1088:1120] = active_name

    child_name = "child.txt"
    child_primary = bytearray(32)
    child_primary[0], child_primary[1] = 0x85, 2
    child_primary[4:6] = (0x20).to_bytes(2, "little")
    child_stream = bytearray(32)
    child_stream[0], child_stream[1], child_stream[3] = 0xC0, 0x02, len(child_name)
    child_stream[8:16] = (24).to_bytes(8, "little")
    child_stream[20:24] = (4).to_bytes(4, "little")
    child_stream[24:32] = (24).to_bytes(8, "little")
    child_name_entry = bytearray(32)
    child_name_entry[0] = 0xC1
    child_name_entry[2:2 + len(child_name.encode("utf-16le"))] = child_name.encode("utf-16le")
    child_checksum = GenericTriageEngine._exfat_entry_set_checksum([
        bytes(child_primary), bytes(child_stream), bytes(child_name_entry)
    ])
    child_primary[2:4] = child_checksum.to_bytes(2, "little")
    child_primary[0], child_stream[0], child_name_entry[0] = 0x05, 0x40, 0x41
    image[1536:1568] = child_primary
    image[1568:1600] = child_stream
    image[1600:1632] = child_name_entry
    evidence = tmp_path / "exfat-subdirectory.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    inventory = values["filesystem.exfat.subdirectory_inventory"]
    assert inventory[0]["name"] == directory_name
    assert inventory[0]["mapping_mode"] == "nofatchain_contiguous"
    assert inventory[0]["cluster_chain"] == [
        {"cluster": 3, "offset": 1536, "length": 512, "data_length": 512}
    ]
    deleted = values["filesystem.exfat.subdirectory_deleted_file_sets"][0]
    assert deleted["name"] == child_name and deleted["offset"] == 1536
    assert deleted["directory_start_cluster"] == 3
    assert deleted["directory_cluster_lineage"] == [3]
    assert deleted["directory_source_entry_offset"] == 1024
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "exfat_deleted_file_entry" for item in profile.findings)
    assert any(item.category == "exfat_active_subdirectory_inventory" for item in profile.findings)


def test_exfat_fat_subdirectory_rejects_shared_and_never_traverses_deleted_directory(tmp_path: Path) -> None:
    image = bytearray(6144)
    image[3:11] = b"EXFAT   "
    image[80:84] = (1).to_bytes(4, "little")
    image[84:88] = (1).to_bytes(4, "little")
    image[88:92] = (2).to_bytes(4, "little")
    image[92:96] = (10).to_bytes(4, "little")
    image[96:100] = (2).to_bytes(4, "little")
    image[108], image[109], image[110] = 9, 0, 1
    image[510:512] = b"\x55\xaa"
    for cluster, next_cluster in ((2, 0xFFFFFFFF), (3, 5), (5, 0xFFFFFFFF)):
        image[512 + cluster * 4:512 + cluster * 4 + 4] = next_cluster.to_bytes(4, "little")

    def file_set(name: str, attributes: int, flags: int, first_cluster: int, length: int, deleted: bool) -> bytes:
        primary = bytearray(32)
        primary[0], primary[1] = 0x85, 2
        primary[4:6] = attributes.to_bytes(2, "little")
        stream = bytearray(32)
        stream[0], stream[1], stream[3] = 0xC0, flags, len(name)
        stream[8:16] = length.to_bytes(8, "little")
        stream[20:24] = first_cluster.to_bytes(4, "little")
        stream[24:32] = length.to_bytes(8, "little")
        name_entry = bytearray(32)
        name_entry[0] = 0xC1
        encoded = name.encode("utf-16le")
        name_entry[2:2 + len(encoded)] = encoded
        primary[2:4] = GenericTriageEngine._exfat_entry_set_checksum([
            bytes(primary), bytes(stream), bytes(name_entry)
        ]).to_bytes(2, "little")
        if deleted:
            primary[0], stream[0], name_entry[0] = 0x05, 0x40, 0x41
        return bytes(primary + stream + name_entry)

    image[1024:1120] = file_set("CHAINED", 0x10, 0, 3, 1024, False)
    for entry_index in range(16):
        image[1536 + entry_index * 32] = 0xA0
    chained_directory = 2560
    image[chained_directory:chained_directory + 96] = file_set("child.txt", 0x20, 2, 7, 24, True)
    image[chained_directory + 96:chained_directory + 192] = file_set("LOOP", 0x10, 2, 5, 512, False)
    image[chained_directory + 192:chained_directory + 288] = file_set("DELETED", 0x10, 2, 6, 512, True)
    image[3072:3168] = file_set("hidden.txt", 0x20, 2, 8, 24, True)
    evidence = tmp_path / "exfat-fat-subdirectory.raw"
    evidence.write_bytes(image)

    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    inventory = values["filesystem.exfat.subdirectory_inventory"]
    assert inventory[0]["mapping_mode"] == "fat_chain_eoc"
    assert [item["cluster"] for item in inventory[0]["cluster_chain"]] == [3, 5]
    assert inventory[0]["cluster_chain"][1]["offset"] == 2560
    deleted_names = [item["name"] for item in values["filesystem.exfat.subdirectory_deleted_file_sets"]]
    assert deleted_names == ["child.txt", "DELETED"]
    assert "hidden.txt" not in deleted_names
    assert any("loop_or_shared_cluster" in error for error in values["filesystem.exfat.subdirectory_errors"])
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "exfat_subdirectory_chain_anomaly" for item in profile.findings)


def test_ext_root_inode_depth0_extent_and_direct_directory_entries(tmp_path: Path) -> None:
    image = bytearray(16 * 1024)
    superblock = 1024
    image[superblock:superblock + 4] = (16).to_bytes(4, "little")
    image[superblock + 4:superblock + 8] = (16).to_bytes(4, "little")
    image[superblock + 20:superblock + 24] = (1).to_bytes(4, "little")
    image[superblock + 24:superblock + 28] = (0).to_bytes(4, "little")
    image[superblock + 32:superblock + 36] = (16).to_bytes(4, "little")
    image[superblock + 40:superblock + 44] = (16).to_bytes(4, "little")
    image[superblock + 56:superblock + 58] = b"\x53\xef"
    image[superblock + 76:superblock + 80] = (1).to_bytes(4, "little")
    image[superblock + 88:superblock + 90] = (128).to_bytes(2, "little")
    image[superblock + 96:superblock + 100] = (0x42).to_bytes(4, "little")
    image[2048 + 8:2048 + 12] = (5).to_bytes(4, "little")
    inode_offset = 5 * 1024 + 128
    image[inode_offset:inode_offset + 2] = (0x41ED).to_bytes(2, "little")
    image[inode_offset + 4:inode_offset + 8] = (1024).to_bytes(4, "little")
    image[inode_offset + 32:inode_offset + 36] = (0x00080000).to_bytes(4, "little")
    extent = inode_offset + 40
    image[extent:extent + 2] = (0xF30A).to_bytes(2, "little")
    image[extent + 2:extent + 4] = (1).to_bytes(2, "little")
    image[extent + 4:extent + 6] = (4).to_bytes(2, "little")
    image[extent + 12:extent + 16] = (0).to_bytes(4, "little")
    image[extent + 16:extent + 18] = (1).to_bytes(2, "little")
    image[extent + 20:extent + 24] = (7).to_bytes(4, "little")
    directory = 7 * 1024
    image[directory:directory + 4] = (2).to_bytes(4, "little")
    image[directory + 4:directory + 6] = (12).to_bytes(2, "little")
    image[directory + 6:directory + 9] = bytes([1, 2]) + b"."
    image[directory + 12:directory + 16] = (2).to_bytes(4, "little")
    image[directory + 16:directory + 18] = (12).to_bytes(2, "little")
    image[directory + 18:directory + 22] = bytes([2, 2]) + b".."
    image[directory + 24:directory + 28] = (12).to_bytes(4, "little")
    image[directory + 28:directory + 30] = (16).to_bytes(2, "little")
    image[directory + 30:directory + 40] = bytes([8, 1]) + b"flag.txt"
    image[directory + 40:directory + 44] = (13).to_bytes(4, "little")
    image[directory + 44:directory + 46] = (16).to_bytes(2, "little")
    image[directory + 46:directory + 51] = bytes([3, 2]) + b"sub"
    image[directory + 56:directory + 60] = (15).to_bytes(4, "little")
    image[directory + 60:directory + 62] = (968).to_bytes(2, "little")
    image[directory + 62:directory + 68] = bytes([4, 2]) + b"loop"
    payload = b"CTF{ext_root_active_file}"
    file_inode_offset = 5 * 1024 + 11 * 128
    image[file_inode_offset:file_inode_offset + 2] = (0x81A4).to_bytes(2, "little")
    image[file_inode_offset + 4:file_inode_offset + 8] = len(payload).to_bytes(4, "little")
    image[file_inode_offset + 26:file_inode_offset + 28] = (1).to_bytes(2, "little")
    image[file_inode_offset + 32:file_inode_offset + 36] = (0x00080000).to_bytes(4, "little")
    file_extent = file_inode_offset + 40
    image[file_extent:file_extent + 2] = (0xF30A).to_bytes(2, "little")
    image[file_extent + 2:file_extent + 4] = (1).to_bytes(2, "little")
    image[file_extent + 4:file_extent + 6] = (4).to_bytes(2, "little")
    image[file_extent + 16:file_extent + 18] = (1).to_bytes(2, "little")
    image[file_extent + 20:file_extent + 24] = (8).to_bytes(4, "little")
    image[8 * 1024:8 * 1024 + len(payload)] = payload
    subdirectory_inode_offset = 5 * 1024 + 12 * 128
    image[subdirectory_inode_offset:subdirectory_inode_offset + 2] = (0x41ED).to_bytes(2, "little")
    image[subdirectory_inode_offset + 4:subdirectory_inode_offset + 8] = (1024).to_bytes(4, "little")
    image[subdirectory_inode_offset + 26:subdirectory_inode_offset + 28] = (2).to_bytes(2, "little")
    image[subdirectory_inode_offset + 32:subdirectory_inode_offset + 36] = (0x00080000).to_bytes(4, "little")
    sub_extent = subdirectory_inode_offset + 40
    image[sub_extent:sub_extent + 2] = (0xF30A).to_bytes(2, "little")
    image[sub_extent + 2:sub_extent + 4] = (1).to_bytes(2, "little")
    image[sub_extent + 4:sub_extent + 6] = (4).to_bytes(2, "little")
    image[sub_extent + 16:sub_extent + 18] = (1).to_bytes(2, "little")
    image[sub_extent + 20:sub_extent + 24] = (9).to_bytes(4, "little")
    subdirectory = 9 * 1024
    for offset, inode_number, record_length, name, file_type in (
        (0, 13, 12, b".", 2), (12, 2, 12, b"..", 2), (24, 14, 1000, b"inner.txt", 1),
    ):
        image[subdirectory + offset:subdirectory + offset + 4] = inode_number.to_bytes(4, "little")
        image[subdirectory + offset + 4:subdirectory + offset + 6] = record_length.to_bytes(2, "little")
        image[subdirectory + offset + 6:subdirectory + offset + 8] = bytes([len(name), file_type])
        image[subdirectory + offset + 8:subdirectory + offset + 8 + len(name)] = name
    inner_payload = b"CTF{ext_subdirectory_child}"
    inner_inode_offset = 5 * 1024 + 13 * 128
    image[inner_inode_offset:inner_inode_offset + 2] = (0x81A4).to_bytes(2, "little")
    image[inner_inode_offset + 4:inner_inode_offset + 8] = len(inner_payload).to_bytes(4, "little")
    image[inner_inode_offset + 26:inner_inode_offset + 28] = (1).to_bytes(2, "little")
    image[inner_inode_offset + 32:inner_inode_offset + 36] = (0x00080000).to_bytes(4, "little")
    inner_extent = inner_inode_offset + 40
    image[inner_extent:inner_extent + 2] = (0xF30A).to_bytes(2, "little")
    image[inner_extent + 2:inner_extent + 4] = (1).to_bytes(2, "little")
    image[inner_extent + 4:inner_extent + 6] = (4).to_bytes(2, "little")
    image[inner_extent + 16:inner_extent + 18] = (1).to_bytes(2, "little")
    image[inner_extent + 20:inner_extent + 24] = (10).to_bytes(4, "little")
    image[10 * 1024:10 * 1024 + len(inner_payload)] = inner_payload
    loop_inode_offset = 5 * 1024 + 14 * 128
    image[loop_inode_offset:loop_inode_offset + 2] = (0x41ED).to_bytes(2, "little")
    image[loop_inode_offset + 4:loop_inode_offset + 8] = (1024).to_bytes(4, "little")
    image[loop_inode_offset + 26:loop_inode_offset + 28] = (2).to_bytes(2, "little")
    image[loop_inode_offset + 32:loop_inode_offset + 36] = (0x00080000).to_bytes(4, "little")
    loop_extent = loop_inode_offset + 40
    image[loop_extent:loop_extent + 2] = (0xF30A).to_bytes(2, "little")
    image[loop_extent + 2:loop_extent + 4] = (1).to_bytes(2, "little")
    image[loop_extent + 4:loop_extent + 6] = (4).to_bytes(2, "little")
    image[loop_extent + 16:loop_extent + 18] = (1).to_bytes(2, "little")
    image[loop_extent + 20:loop_extent + 24] = (9).to_bytes(4, "little")
    evidence = tmp_path / "ext4.raw"
    evidence.write_bytes(image)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["filesystem.ext.root.available"] is True
    assert values["filesystem.ext.root.mapping_mode"] == "ext4_depth0_extents"
    assert values["filesystem.ext.root.inode_offset"] == inode_offset
    assert values["filesystem.ext.root.block_segments"] == [{
        "logical_block": 0, "physical_block": 7,
        "physical_offset": directory, "data_length": 1024,
    }]
    flag_entry = next(item for item in values["filesystem.ext.root.directory_entries"] if item["name"] == "flag.txt")
    assert flag_entry["inode"] == 12 and flag_entry["file_type"] == "regular"
    assert flag_entry["logical_offset"] == 24 and flag_entry["physical_offset"] == directory + 24
    profile = ProfileEngine().evaluate(artifact, observations)
    assert any(item.category == "ext_root_directory_inventory" for item in profile.findings)
    recoverable = values["filesystem.ext.root.recoverable_regular_files"][0]
    assert recoverable["name"] == "flag.txt" and recoverable["inode_offset"] == file_inode_offset
    assert recoverable["data_segments"] == [{
        "logical_offset": 0, "physical_block": 8,
        "physical_offset": 8 * 1024, "length": len(payload),
    }]
    sub_inventory = values["filesystem.ext.root.subdirectory_inventory"]
    assert sub_inventory[0]["inode"] == 13 and sub_inventory[0]["path"] == "/sub"
    assert sub_inventory[0]["inode_lineage"] == [2, 13]
    inner = next(item for item in values["filesystem.ext.root.recoverable_regular_files"] if item["name"] == "inner.txt")
    assert inner["directory_path"] == "/sub"
    assert inner["directory_inode_lineage"] == [2, 13]
    assert inner["directory_block_lineage"] == [9]
    assert inner["data_segments"][0]["physical_offset"] == 10 * 1024
    assert any("loop/shared directory block" in error for error in values["filesystem.ext.root.subdirectory_errors"])
    assert any(item.category == "ext_active_subdirectory_inventory" for item in profile.findings)
    assert any(item.category == "ext_subdirectory_mapping_anomaly" for item in profile.findings)

    direct_image = bytearray(image)
    direct_image[superblock + 96:superblock + 100] = (0).to_bytes(4, "little")
    direct_image[inode_offset + 32:inode_offset + 36] = (0).to_bytes(4, "little")
    direct_image[inode_offset + 40:inode_offset + 100] = b"\x00" * 60
    direct_image[inode_offset + 40:inode_offset + 44] = (7).to_bytes(4, "little")
    direct_image[directory + 7] = 0
    direct_image[directory + 19] = 0
    direct_image[directory + 31] = 0
    direct_image[directory + 47] = 0
    direct_image[directory + 63] = 0
    direct_image[subdirectory + 7] = 0
    direct_image[subdirectory + 19] = 0
    direct_image[subdirectory + 31] = 0
    direct_image[file_inode_offset + 32:file_inode_offset + 36] = (0).to_bytes(4, "little")
    direct_image[file_inode_offset + 40:file_inode_offset + 100] = b"\x00" * 60
    direct_image[file_inode_offset + 40:file_inode_offset + 44] = (8).to_bytes(4, "little")
    direct = tmp_path / "ext2.raw"
    direct.write_bytes(direct_image)
    direct_values = _values(GenericTriageEngine().analyze(_artifact(direct), direct))
    assert direct_values["filesystem.ext.root.mapping_mode"] == "ext2_3_direct_blocks"
    assert any(item["name"] == "flag.txt" for item in direct_values["filesystem.ext.root.directory_entries"])
    assert direct_values["filesystem.ext.root.recoverable_regular_files"][0]["mapping_mode"] == "ext2_3_direct_blocks"


def test_ext4_depth_one_extent_tree_maps_root_and_regular_file_with_leaf_provenance(tmp_path: Path) -> None:
    image = bytearray(16 * 1024)
    superblock = 1024
    image[superblock:superblock + 4] = (16).to_bytes(4, "little")
    image[superblock + 4:superblock + 8] = (16).to_bytes(4, "little")
    image[superblock + 20:superblock + 24] = (1).to_bytes(4, "little")
    image[superblock + 24:superblock + 28] = (0).to_bytes(4, "little")
    image[superblock + 32:superblock + 36] = (16).to_bytes(4, "little")
    image[superblock + 40:superblock + 44] = (16).to_bytes(4, "little")
    image[superblock + 56:superblock + 58] = b"\x53\xef"
    image[superblock + 76:superblock + 80] = (1).to_bytes(4, "little")
    image[superblock + 88:superblock + 90] = (128).to_bytes(2, "little")
    image[superblock + 96:superblock + 100] = (0x42).to_bytes(4, "little")
    image[2048 + 8:2048 + 12] = (3).to_bytes(4, "little")

    def extent_header(offset: int, entries: int, maximum: int, depth: int) -> None:
        image[offset:offset + 2] = (0xF30A).to_bytes(2, "little")
        image[offset + 2:offset + 4] = entries.to_bytes(2, "little")
        image[offset + 4:offset + 6] = maximum.to_bytes(2, "little")
        image[offset + 6:offset + 8] = depth.to_bytes(2, "little")

    def extent_index(offset: int, logical: int, leaf: int) -> None:
        image[offset:offset + 4] = logical.to_bytes(4, "little")
        image[offset + 4:offset + 8] = (leaf & 0xFFFFFFFF).to_bytes(4, "little")
        image[offset + 8:offset + 10] = (leaf >> 32).to_bytes(2, "little")

    def extent(offset: int, logical: int, length: int, physical: int) -> None:
        image[offset:offset + 4] = logical.to_bytes(4, "little")
        image[offset + 4:offset + 6] = length.to_bytes(2, "little")
        image[offset + 6:offset + 8] = (physical >> 32).to_bytes(2, "little")
        image[offset + 8:offset + 12] = (physical & 0xFFFFFFFF).to_bytes(4, "little")

    root_inode = 3 * 1024 + 128
    image[root_inode:root_inode + 2] = (0x41ED).to_bytes(2, "little")
    image[root_inode + 4:root_inode + 8] = (1024).to_bytes(4, "little")
    image[root_inode + 26:root_inode + 28] = (2).to_bytes(2, "little")
    image[root_inode + 32:root_inode + 36] = (0x00080000).to_bytes(4, "little")
    extent_header(root_inode + 40, 1, 4, 1)
    extent_index(root_inode + 52, 0, 6)
    extent_header(6 * 1024, 1, 84, 0)
    extent(6 * 1024 + 12, 0, 1, 7)

    directory = 7 * 1024
    for offset, inode_number, record_length, name, file_type in (
        (0, 2, 12, b".", 2),
        (12, 2, 12, b"..", 2),
        (24, 12, 1000, b"flag.txt", 1),
    ):
        image[directory + offset:directory + offset + 4] = inode_number.to_bytes(4, "little")
        image[directory + offset + 4:directory + offset + 6] = record_length.to_bytes(2, "little")
        image[directory + offset + 6:directory + offset + 8] = bytes([len(name), file_type])
        image[directory + offset + 8:directory + offset + 8 + len(name)] = name

    payload = b"A" * 1024 + b"CTF{ext4_depth_one_leaf}"
    file_inode = 3 * 1024 + 11 * 128
    image[file_inode:file_inode + 2] = (0x81A4).to_bytes(2, "little")
    image[file_inode + 4:file_inode + 8] = len(payload).to_bytes(4, "little")
    image[file_inode + 26:file_inode + 28] = (1).to_bytes(2, "little")
    image[file_inode + 32:file_inode + 36] = (0x00080000).to_bytes(4, "little")
    extent_header(file_inode + 40, 2, 4, 1)
    extent_index(file_inode + 52, 0, 8)
    extent_index(file_inode + 64, 1, 10)
    extent_header(8 * 1024, 1, 84, 0)
    extent(8 * 1024 + 12, 0, 1, 9)
    extent_header(10 * 1024, 1, 84, 0)
    extent(10 * 1024 + 12, 1, 1, 11)
    image[9 * 1024:10 * 1024] = payload[:1024]
    image[11 * 1024:11 * 1024 + len(payload) - 1024] = payload[1024:]

    evidence = tmp_path / "ext4-depth-one.raw"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ext.root.available"] is True
    assert values["filesystem.ext.root.mapping_mode"] == "ext4_depth1_extent_tree"
    assert values["filesystem.ext.root.block_segments"][0]["physical_offset"] == 7 * 1024
    root_mapping = values["filesystem.ext.root.mapping"]
    assert root_mapping[0]["kind"] == "extent_index"
    assert root_mapping[0]["logical_block"] == 0
    assert root_mapping[0]["leaf_block"] == 6
    assert root_mapping[0]["index_entry_offset"] == root_inode + 52
    assert root_mapping[1]["leaf_offset"] == 6 * 1024
    assert root_mapping[2]["leaf_entry_offset"] == 6 * 1024 + 12
    recovered = values["filesystem.ext.root.recoverable_regular_files"][0]
    assert recovered["mapping_mode"] == "ext4_depth1_extent_tree"
    assert recovered["mapping_provenance"][0]["index_entry_offset"] == file_inode + 52
    assert recovered["mapping_provenance"][1]["index_entry_offset"] == file_inode + 64
    assert [
        item["leaf_offset"] for item in recovered["mapping_provenance"]
        if item["kind"] == "extent_leaf"
    ] == [8 * 1024, 10 * 1024]
    assert recovered["data_segments"] == [{
        "logical_offset": 0, "physical_block": 9, "physical_offset": 9 * 1024,
        "length": 1024, "extent_leaf_block": 8,
        "extent_leaf_offset": 8 * 1024, "extent_entry_offset": 8 * 1024 + 12,
        "extent_tree_depth": 1,
    }, {
        "logical_offset": 1024, "physical_block": 11, "physical_offset": 11 * 1024,
        "length": len(payload) - 1024, "extent_leaf_block": 10,
        "extent_leaf_offset": 10 * 1024, "extent_entry_offset": 10 * 1024 + 12,
        "extent_tree_depth": 1,
    }]
    result = AnalysisEngine().analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )
    child = next(item for item in result.artifacts if item.logical_name == "flag.txt")
    assert any(
        item.value == "CTF{ext4_depth_one_leaf}" and item.artifact_id == child.id
        for item in result.flags
    )
    recovery = next(item for item in result.findings if item.category == "ext_root_file_recovery")
    assert "mapping_mode:ext4_depth1_extent_tree" in recovery.supporting_evidence[0]
    assert f"leaf_offset': {8 * 1024}" in recovery.supporting_evidence[0]
    assert f"leaf_offset': {10 * 1024}" in recovery.supporting_evidence[0]

    repeated_leaf = bytearray(image)
    repeated_leaf[root_inode + 42:root_inode + 44] = (2).to_bytes(2, "little")
    extent_index_offset = root_inode + 64
    repeated_leaf[extent_index_offset:extent_index_offset + 4] = (1).to_bytes(4, "little")
    repeated_leaf[extent_index_offset + 4:extent_index_offset + 8] = (6).to_bytes(4, "little")
    invalid = tmp_path / "ext4-repeated-leaf.raw"
    invalid.write_bytes(repeated_leaf)
    invalid_values = _values(GenericTriageEngine().analyze(_artifact(invalid), invalid))
    assert invalid_values["filesystem.ext.root.available"] is False
    assert "repeated extent-tree index" in invalid_values["filesystem.ext.root.error"]


def test_ext4_depth_two_extent_tree_maps_child_and_rejects_index_cycle(tmp_path: Path) -> None:
    image = bytearray(16 * 1024)
    superblock = 1024
    image[superblock:superblock + 4] = (16).to_bytes(4, "little")
    image[superblock + 4:superblock + 8] = (16).to_bytes(4, "little")
    image[superblock + 20:superblock + 24] = (1).to_bytes(4, "little")
    image[superblock + 32:superblock + 36] = (16).to_bytes(4, "little")
    image[superblock + 40:superblock + 44] = (16).to_bytes(4, "little")
    image[superblock + 56:superblock + 58] = b"\x53\xef"
    image[superblock + 76:superblock + 80] = (1).to_bytes(4, "little")
    image[superblock + 88:superblock + 90] = (128).to_bytes(2, "little")
    image[superblock + 96:superblock + 100] = (0x42).to_bytes(4, "little")
    image[2048 + 8:2048 + 12] = (3).to_bytes(4, "little")

    def header(offset: int, depth: int) -> None:
        image[offset:offset + 2] = (0xF30A).to_bytes(2, "little")
        image[offset + 2:offset + 4] = (1).to_bytes(2, "little")
        image[offset + 4:offset + 6] = (4 if offset % 1024 else 84).to_bytes(2, "little")
        image[offset + 6:offset + 8] = depth.to_bytes(2, "little")

    def index(offset: int, logical: int, child: int) -> None:
        image[offset:offset + 12] = b"\x00" * 12
        image[offset:offset + 4] = logical.to_bytes(4, "little")
        image[offset + 4:offset + 8] = child.to_bytes(4, "little")

    def leaf_extent(offset: int, logical: int, physical: int) -> None:
        image[offset:offset + 12] = b"\x00" * 12
        image[offset:offset + 4] = logical.to_bytes(4, "little")
        image[offset + 4:offset + 6] = (1).to_bytes(2, "little")
        image[offset + 8:offset + 12] = physical.to_bytes(4, "little")

    root_inode = 3 * 1024 + 128
    image[root_inode:root_inode + 2] = (0x41ED).to_bytes(2, "little")
    image[root_inode + 4:root_inode + 8] = (1024).to_bytes(4, "little")
    image[root_inode + 26:root_inode + 28] = (2).to_bytes(2, "little")
    image[root_inode + 32:root_inode + 36] = (0x00080000).to_bytes(4, "little")
    header(root_inode + 40, 2)
    index(root_inode + 52, 0, 6)
    header(6 * 1024, 1)
    index(6 * 1024 + 12, 0, 7)
    header(7 * 1024, 0)
    leaf_extent(7 * 1024 + 12, 0, 8)

    directory = 8 * 1024
    for offset, inode_number, record_length, name, file_type in (
        (0, 2, 12, b".", 2),
        (12, 2, 12, b"..", 2),
        (24, 12, 1000, b"deep.txt", 1),
    ):
        image[directory + offset:directory + offset + 4] = inode_number.to_bytes(4, "little")
        image[directory + offset + 4:directory + offset + 6] = record_length.to_bytes(2, "little")
        image[directory + offset + 6:directory + offset + 8] = bytes([len(name), file_type])
        image[directory + offset + 8:directory + offset + 8 + len(name)] = name

    payload = b"CTF{ext4_depth_two_tree}"
    file_inode = 3 * 1024 + 11 * 128
    image[file_inode:file_inode + 2] = (0x81A4).to_bytes(2, "little")
    image[file_inode + 4:file_inode + 8] = len(payload).to_bytes(4, "little")
    image[file_inode + 26:file_inode + 28] = (1).to_bytes(2, "little")
    image[file_inode + 32:file_inode + 36] = (0x00080000).to_bytes(4, "little")
    header(file_inode + 40, 2)
    index(file_inode + 52, 0, 9)
    header(9 * 1024, 1)
    index(9 * 1024 + 12, 0, 10)
    header(10 * 1024, 0)
    leaf_extent(10 * 1024 + 12, 0, 11)
    image[11 * 1024:11 * 1024 + len(payload)] = payload

    evidence = tmp_path / "ext4-depth-two.raw"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ext.root.mapping_mode"] == "ext4_depth2_extent_tree"
    assert values["filesystem.ext.root.block_segments"][0]["physical_offset"] == directory
    root_provenance = values["filesystem.ext.root.mapping"]
    assert [item["kind"] for item in root_provenance] == [
        "extent_index", "extent_index_node", "extent_index", "extent_leaf", "extent",
    ]
    assert root_provenance[0]["index_entry_offset"] == root_inode + 52
    assert root_provenance[1]["index_node_offset"] == 6 * 1024
    assert root_provenance[2]["index_entry_offset"] == 6 * 1024 + 12
    assert root_provenance[3]["leaf_offset"] == 7 * 1024
    recovered = values["filesystem.ext.root.recoverable_regular_files"][0]
    assert recovered["name"] == "deep.txt"
    assert recovered["mapping_mode"] == "ext4_depth2_extent_tree"
    assert recovered["data_segments"][0]["extent_tree_depth"] == 2
    assert recovered["data_segments"][0]["extent_leaf_offset"] == 10 * 1024

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "depth-two-cases", mode=AnalysisMode.AUTO, execute=False,
    )
    child = next(item for item in result.artifacts if item.logical_name == "deep.txt")
    assert any(
        item.value == "CTF{ext4_depth_two_tree}" and item.artifact_id == child.id
        for item in result.flags
    )

    cyclic = bytearray(image)
    cyclic[6 * 1024 + 16:6 * 1024 + 20] = (6).to_bytes(4, "little")
    invalid = tmp_path / "ext4-depth-two-cycle.raw"
    invalid.write_bytes(cyclic)
    invalid_values = _values(GenericTriageEngine().analyze(_artifact(invalid), invalid))
    assert invalid_values["filesystem.ext.root.available"] is False
    assert "repeated extent-tree index" in invalid_values["filesystem.ext.root.error"]


def test_ext2_single_indirect_maps_directory_and_file_with_pointer_provenance(tmp_path: Path) -> None:
    block_size = 1024
    image = bytearray(64 * block_size)
    superblock = 1024
    image[superblock:superblock + 4] = (16).to_bytes(4, "little")
    image[superblock + 4:superblock + 8] = (64).to_bytes(4, "little")
    image[superblock + 20:superblock + 24] = (1).to_bytes(4, "little")
    image[superblock + 32:superblock + 36] = (64).to_bytes(4, "little")
    image[superblock + 40:superblock + 44] = (16).to_bytes(4, "little")
    image[superblock + 56:superblock + 58] = b"\x53\xef"
    image[superblock + 76:superblock + 80] = (1).to_bytes(4, "little")
    image[superblock + 88:superblock + 90] = (128).to_bytes(2, "little")
    image[superblock + 96:superblock + 100] = (0x02).to_bytes(4, "little")
    image[2048 + 8:2048 + 12] = (3).to_bytes(4, "little")

    root_inode = 3 * block_size + 128
    image[root_inode:root_inode + 2] = (0x41ED).to_bytes(2, "little")
    image[root_inode + 4:root_inode + 8] = (13 * block_size).to_bytes(4, "little")
    image[root_inode + 26:root_inode + 28] = (2).to_bytes(2, "little")
    for pointer, physical in enumerate(range(8, 20)):
        image[root_inode + 40 + pointer * 4:root_inode + 44 + pointer * 4] = physical.to_bytes(4, "little")
    image[root_inode + 88:root_inode + 92] = (20).to_bytes(4, "little")
    image[20 * block_size:20 * block_size + 4] = (21).to_bytes(4, "little")

    directory = 8 * block_size
    for offset, inode_number, record_length, name, file_type in (
        (0, 2, 12, b".", 2),
        (12, 2, 12, b"..", 2),
        (24, 12, 1000, b"indirect.bin", 1),
    ):
        image[directory + offset:directory + offset + 4] = inode_number.to_bytes(4, "little")
        image[directory + offset + 4:directory + offset + 6] = record_length.to_bytes(2, "little")
        image[directory + offset + 6:directory + offset + 8] = bytes([len(name), file_type])
        image[directory + offset + 8:directory + offset + 8 + len(name)] = name
    for physical in [*range(9, 20), 21]:
        offset = physical * block_size
        image[offset + 4:offset + 6] = block_size.to_bytes(2, "little")

    payload = b"A" * (12 * block_size) + b"CTF{ext_single_indirect}"
    file_inode = 3 * block_size + 11 * 128
    image[file_inode:file_inode + 2] = (0x81A4).to_bytes(2, "little")
    image[file_inode + 4:file_inode + 8] = len(payload).to_bytes(4, "little")
    image[file_inode + 26:file_inode + 28] = (1).to_bytes(2, "little")
    for pointer, physical in enumerate(range(22, 34)):
        image[file_inode + 40 + pointer * 4:file_inode + 44 + pointer * 4] = physical.to_bytes(4, "little")
        image[physical * block_size:(physical + 1) * block_size] = payload[
            pointer * block_size:(pointer + 1) * block_size
        ]
    image[file_inode + 88:file_inode + 92] = (34).to_bytes(4, "little")
    image[34 * block_size:34 * block_size + 4] = (35).to_bytes(4, "little")
    image[35 * block_size:35 * block_size + len(payload) - 12 * block_size] = payload[12 * block_size:]

    evidence = tmp_path / "ext2-single-indirect.raw"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ext.root.mapping_mode"] == "ext2_3_direct_single_indirect"
    root_mapping = values["filesystem.ext.root.mapping"]
    root_indirect = next(item for item in root_mapping if item.get("kind") == "single_indirect_block")
    assert root_indirect["physical_offset"] == 20 * block_size
    assert root_indirect["inode_pointer_offset"] == root_inode + 88
    root_pointer = next(item for item in root_mapping if item.get("kind") == "indirect_data_pointer")
    assert root_pointer["pointer_offset"] == 20 * block_size
    assert root_pointer["physical_block"] == 21
    recovered = values["filesystem.ext.root.recoverable_regular_files"][0]
    assert recovered["name"] == "indirect.bin"
    assert recovered["mapping_mode"] == "ext2_3_direct_single_indirect"
    assert recovered["data_segments"][-1] == {
        "logical_offset": 12 * block_size, "physical_block": 35,
        "physical_offset": 35 * block_size, "length": len(payload) - 12 * block_size,
        "indirect_block": 34, "indirect_block_offset": 34 * block_size,
        "indirect_pointer_offset": 34 * block_size,
    }

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "indirect-cases", mode=AnalysisMode.AUTO, execute=False,
    )
    child = next(item for item in result.artifacts if item.logical_name == "indirect.bin")
    assert any(
        item.value == "CTF{ext_single_indirect}" and item.artifact_id == child.id
        for item in result.flags
    )

    aliased = bytearray(image)
    aliased[20 * block_size:20 * block_size + 4] = (8).to_bytes(4, "little")
    invalid = tmp_path / "ext2-indirect-alias.raw"
    invalid.write_bytes(aliased)
    invalid_values = _values(GenericTriageEngine().analyze(_artifact(invalid), invalid))
    assert invalid_values["filesystem.ext.root.available"] is False
    assert "repeated, aliased" in invalid_values["filesystem.ext.root.error"]


def test_ntfs_i30_index_root_inventory_is_bounded_and_keeps_entry_provenance() -> None:
    value = bytearray(160)
    value[0:4] = (0x30).to_bytes(4, "little")
    value[16:20] = (16).to_bytes(4, "little")
    value[20:24] = (136).to_bytes(4, "little")
    value[24:28] = (136).to_bytes(4, "little")
    entry = 32
    value[entry:entry + 8] = ((2 << 48) | 42).to_bytes(8, "little")
    value[entry + 8:entry + 10] = (104).to_bytes(2, "little")
    value[entry + 10:entry + 12] = (82).to_bytes(2, "little")
    key = entry + 16
    value[key:key + 8] = (5).to_bytes(8, "little")
    value[key + 64] = 8
    value[key + 65] = 1
    value[key + 66:key + 82] = "flag.txt".encode("utf-16le")
    terminal = entry + 104
    value[terminal + 8:terminal + 10] = (16).to_bytes(2, "little")
    value[terminal + 12:terminal + 14] = (2).to_bytes(2, "little")

    inventory, error = GenericTriageEngine._ntfs_index_root_entries(bytes(value))

    assert error is None
    assert inventory == {
        "indexed_attribute_type": "0x30", "index_flags": 0, "entry_bytes": 136,
        "allocated_entry_bytes": 136, "index_entries": [{
            "offset": 32, "record_number": 42, "sequence_number": 2, "flags": 0,
            "file_name": "flag.txt", "file_name_namespace": 1,
        }],
    }


def test_ntfs_mft_mapping_preserves_noncontiguous_logical_and_physical_segments() -> None:
    image = bytearray(6_000)
    image[1_280:1_536] = b"A" * 256
    image[5_120:5_376] = b"B" * 256
    runs = [
        {"vcn": 0, "cluster_count": 1, "lcn": 2},
        {"vcn": 1, "cluster_count": 1, "lcn": 10},
    ]

    payload, segments, error = GenericTriageEngine._ntfs_read_mapped_range(
        io.BytesIO(image), runs, 512, 256, 512, len(image)
    )

    assert error is None
    assert payload == b"A" * 256 + b"B" * 256
    assert segments == [
        {"logical_offset": 256, "physical_offset": 1280, "length": 256},
        {"logical_offset": 512, "physical_offset": 5120, "length": 256},
    ]


def test_ntfs_parent_linking_stays_within_the_sample_and_checks_sequence() -> None:
    links = GenericTriageEngine._ntfs_sample_parent_links([
        {"record_number": 1, "signature_valid": True, "sequence_number": 3, "file_name_references": []},
        {"record_number": 2, "signature_valid": True, "sequence_number": 4, "file_name_references": [
            {"file_name": "child.txt", "parent_record_number": 1, "parent_sequence_number": 3},
            {"file_name": "stale.txt", "parent_record_number": 1, "parent_sequence_number": 2},
            {"file_name": "outside.txt", "parent_record_number": 99, "parent_sequence_number": 1},
        ]},
    ])

    assert links == [
        {"child_record_number": 2, "file_name": "child.txt", "parent_record_number": 1,
         "parent_sequence_number": 3, "parent_sampled": True, "parent_sequence_matches": True},
        {"child_record_number": 2, "file_name": "stale.txt", "parent_record_number": 1,
         "parent_sequence_number": 2, "parent_sampled": True, "parent_sequence_matches": False},
        {"child_record_number": 2, "file_name": "outside.txt", "parent_record_number": 99,
         "parent_sequence_number": 1, "parent_sampled": False, "parent_sequence_matches": None},
    ]


def test_ntfs_i30_linking_stays_within_sample_and_checks_child_metadata() -> None:
    links = GenericTriageEngine._ntfs_sample_index_links([
        {"record_number": 5, "signature_valid": True, "file_names": ["directory"], "index_root_entries": [
            {"attribute_offset": 56, "record_number": 2, "sequence_number": 4, "file_name": "child.txt"},
            {"attribute_offset": 56, "record_number": 2, "sequence_number": 3, "file_name": "stale.txt"},
            {"attribute_offset": 56, "record_number": 99, "sequence_number": 1, "file_name": "outside.txt"},
        ]},
        {"record_number": 2, "signature_valid": True, "sequence_number": 4, "file_names": ["child.txt"]},
    ])

    assert links == [
        {"directory_record_number": 5, "index_attribute_offset": 56, "file_name": "child.txt",
         "child_record_number": 2, "child_sequence_number": 4, "child_sampled": True,
         "child_sequence_matches": True, "child_file_name_matches": True},
        {"directory_record_number": 5, "index_attribute_offset": 56, "file_name": "stale.txt",
         "child_record_number": 2, "child_sequence_number": 3, "child_sampled": True,
         "child_sequence_matches": False, "child_file_name_matches": False},
        {"directory_record_number": 5, "index_attribute_offset": 56, "file_name": "outside.txt",
         "child_record_number": 99, "child_sequence_number": 1, "child_sampled": False,
         "child_sequence_matches": None, "child_file_name_matches": None},
    ]


def test_ntfs_sample_record_anomalies_are_bounded_and_keep_segments() -> None:
    anomalies = GenericTriageEngine._ntfs_sample_record_anomalies([
        {"record_number": 1, "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True},
        {"record_number": 2, "signature_valid": False, "bounds_valid": True, "usa_fixup_valid": False,
         "usa_fixup_error": "USA sequence mismatch at sector 2", "physical_segments": [{"logical_offset": 2048, "physical_offset": 4096, "length": 1024}]},
    ])

    assert anomalies == [{
        "record_number": 2, "failed_checks": ["signature_valid", "usa_fixup_valid"],
        "usa_fixup_error": "USA sequence mismatch at sector 2",
        "physical_segments": [{"logical_offset": 2048, "physical_offset": 4096, "length": 1024}],
    }]


def test_ntfs_nonresident_index_allocation_retains_run_metadata_without_buffer_reads() -> None:
    record = bytearray(160)
    attribute = 56
    record[attribute:attribute + 4] = (0xA0).to_bytes(4, "little")
    record[attribute + 4:attribute + 8] = (72).to_bytes(4, "little")
    record[attribute + 8] = 1
    record[attribute + 24:attribute + 32] = (1).to_bytes(8, "little")
    record[attribute + 32:attribute + 34] = (64).to_bytes(2, "little")
    record[attribute + 40:attribute + 48] = (1024).to_bytes(8, "little")
    record[attribute + 48:attribute + 56] = (900).to_bytes(8, "little")
    record[attribute + 64:attribute + 68] = b"\x11\x02\x05\x00"
    record[attribute + 72:attribute + 76] = (0xFFFFFFFF).to_bytes(4, "little")

    attributes, errors = GenericTriageEngine._ntfs_attribute_inventory(bytes(record), attribute, attribute + 76, True)

    assert errors == []
    assert attributes[0]["type_name"] == "index_allocation"
    assert attributes[0]["data_runs"] == [{"vcn": 0, "cluster_count": 2, "lcn": 5}]


def test_ntfs_data_run_extent_starts_at_declared_lowest_vcn() -> None:
    attribute = bytearray(72)
    attribute[64:68] = b"\x11\x02\x09\x00"

    runs, error = GenericTriageEngine._ntfs_data_runs(bytes(attribute), 64, 4)

    assert error is None
    assert runs == [{"vcn": 4, "cluster_count": 2, "lcn": 9}]


def test_ntfs_sampled_data_extents_require_exact_list_sequence_and_base_reference() -> None:
    base_stream = {
        "attribute_offset": 120, "attribute_id": 3, "stream_name": "ads",
        "attribute_flags": 0, "lowest_vcn": 0, "highest_vcn": 0,
        "allocated_size": 1024, "real_size": 700, "initialized_size": 700,
        "data_runs": [{"vcn": 0, "cluster_count": 1, "lcn": 5}],
    }
    base = {
        "record_number": 4, "sequence_number": 6,
        "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
        "physical_segments": [{"physical_offset": 4096, "length": 1024}],
        "nonresident_data_attributes": [base_stream],
        "attribute_list_references": [
            {"type_name": "data", "name": "ads", "lowest_vcn": 0,
             "record_number": 4, "sequence_number": 6, "attribute_id": 3},
            {"type_name": "data", "name": "ads", "lowest_vcn": 1,
             "record_number": 8, "sequence_number": 2, "attribute_id": 7},
        ],
    }
    extension = {
        "record_number": 8, "sequence_number": 2, "base_record_number": 4,
        "base_sequence_number": 6,
        "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
        "physical_segments": [{"physical_offset": 8192, "length": 1024}],
        "nonresident_data_attributes": [{
            "attribute_offset": 64, "attribute_id": 7, "stream_name": "ads",
            "attribute_flags": 0, "lowest_vcn": 1, "highest_vcn": 1,
            "allocated_size": 0, "real_size": 0, "initialized_size": 0,
            "data_runs": [{"vcn": 1, "cluster_count": 1, "lcn": 9}],
        }],
    }

    GenericTriageEngine._ntfs_join_sampled_data_extents([base, extension])

    joined = base["joined_nonresident_data_attributes"][0]
    assert joined["data_runs"] == [
        {"vcn": 0, "cluster_count": 1, "lcn": 5},
        {"vcn": 1, "cluster_count": 1, "lcn": 9},
    ]
    assert joined["highest_vcn"] == 1
    assert [item["record_number"] for item in joined["extent_provenance"]] == [4, 8]

    invalid_base = {**base, "joined_nonresident_data_attributes": []}
    invalid_extension = {**extension, "base_sequence_number": 5}
    GenericTriageEngine._ntfs_join_sampled_data_extents([invalid_base, invalid_extension])
    assert invalid_base["joined_nonresident_data_attributes"] == []


def test_ntfs_nonresident_index_allocation_parses_fixed_indx_and_isolates_bad_buffer() -> None:
    image = bytearray(10 * 512)
    buffer = bytearray(1024)
    buffer[:4] = b"INDX"
    buffer[4:6] = (40).to_bytes(2, "little")
    buffer[6:8] = (3).to_bytes(2, "little")
    buffer[16:24] = (7).to_bytes(8, "little")
    buffer[24:28] = (40).to_bytes(4, "little")
    name = "lost.txt"
    key_length = 66 + len(name.encode("utf-16le"))
    entry_length = ((16 + key_length + 7) // 8) * 8
    buffer[28:32] = (40 + entry_length + 16).to_bytes(4, "little")
    buffer[32:36] = (1000).to_bytes(4, "little")
    entry = 64
    buffer[entry:entry + 8] = ((3 << 48) | 42).to_bytes(8, "little")
    buffer[entry + 8:entry + 10] = entry_length.to_bytes(2, "little")
    buffer[entry + 10:entry + 12] = key_length.to_bytes(2, "little")
    key = entry + 16
    buffer[key:key + 8] = ((2 << 48) | 5).to_bytes(8, "little")
    buffer[key + 64] = len(name)
    buffer[key + 65] = 1
    buffer[key + 66:key + 66 + len(name.encode("utf-16le"))] = name.encode("utf-16le")
    terminal = entry + entry_length
    buffer[terminal + 8:terminal + 10] = (16).to_bytes(2, "little")
    buffer[terminal + 12:terminal + 14] = (2).to_bytes(2, "little")
    buffer[40:46] = b"\xaa\xbb\x11\x22\x33\x44"
    buffer[510:512] = b"\xaa\xbb"
    buffer[1022:1024] = b"\xaa\xbb"
    image[5 * 512:7 * 512] = buffer
    attribute = {
        "offset": 128, "attribute_flags": 0, "lowest_vcn": 0,
        "real_size": 2048,
        "data_runs": [{"vcn": 0, "cluster_count": 4, "lcn": 5}],
    }

    slack = 256
    stale_name = "deleted.doc"
    stale_key_length = 66 + len(stale_name.encode("utf-16le"))
    stale_entry_length = ((16 + stale_key_length + 7) // 8) * 8
    buffer[slack:slack + 8] = ((4 << 48) | 88).to_bytes(8, "little")
    buffer[slack + 8:slack + 10] = stale_entry_length.to_bytes(2, "little")
    buffer[slack + 10:slack + 12] = stale_key_length.to_bytes(2, "little")
    stale_key = slack + 16
    buffer[stale_key + 64] = len(stale_name)
    buffer[stale_key + 65] = 1
    buffer[stale_key + 66:stale_key + 66 + len(stale_name.encode("utf-16le"))] = stale_name.encode("utf-16le")
    image[5 * 512:7 * 512] = buffer

    entries, slack_entries, buffers, errors = GenericTriageEngine._ntfs_index_allocation_entries(
        io.BytesIO(image), attribute, 512, 1024, 512, len(image)
    )

    assert len(entries) == 1
    assert entries[0]["file_name"] == "lost.txt"
    assert entries[0]["record_number"] == 42
    assert entries[0]["sequence_number"] == 3
    assert entries[0]["index_buffer"]["index_vcn"] == 7
    assert entries[0]["index_buffer"]["physical_segments"] == [
        {"logical_offset": 0, "physical_offset": 2560, "length": 1024}
    ]
    assert buffers[0]["usa_fixup_valid"] is True
    assert len(slack_entries) == 1
    assert slack_entries[0]["file_name"] == "deleted.doc"
    assert slack_entries[0]["record_number"] == 88
    assert slack_entries[0]["slack_offset"] == 256
    assert slack_entries[0]["confidence"] == 0.72
    assert any("buffer 1: missing INDX signature" in error for error in errors)


def test_ntfs_sampled_directory_maps_nonresident_i30_buffer(tmp_path: Path) -> None:
    image = bytearray(8192)
    image[3:11] = b"NTFS    "
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[48:56] = (1).to_bytes(8, "little")
    image[64] = image[68] = 0xF6  # 1 KiB FILE and INDX records
    image[510:512] = b"\x55\xaa"
    mft = 512
    image[mft:mft + 4] = b"FILE"
    image[mft + 4:mft + 6] = (48).to_bytes(2, "little")
    image[mft + 6:mft + 8] = (3).to_bytes(2, "little")
    image[mft + 20:mft + 22] = (56).to_bytes(2, "little")
    image[mft + 22:mft + 24] = (1).to_bytes(2, "little")
    image[mft + 24:mft + 28] = (132).to_bytes(4, "little")
    image[mft + 28:mft + 32] = (1024).to_bytes(4, "little")
    image[mft + 48:mft + 54] = b"\xaa\xbb\x11\x22\x33\x44"
    image[mft + 510:mft + 512] = b"\xaa\xbb"
    image[mft + 1022:mft + 1024] = b"\xaa\xbb"
    mft_data = mft + 56
    image[mft_data:mft_data + 4] = (0x80).to_bytes(4, "little")
    image[mft_data + 4:mft_data + 8] = (72).to_bytes(4, "little")
    image[mft_data + 8] = 1
    image[mft_data + 24:mft_data + 32] = (3).to_bytes(8, "little")
    image[mft_data + 32:mft_data + 34] = (64).to_bytes(2, "little")
    image[mft_data + 40:mft_data + 48] = (2048).to_bytes(8, "little")
    image[mft_data + 48:mft_data + 56] = (2048).to_bytes(8, "little")
    image[mft_data + 56:mft_data + 64] = (2048).to_bytes(8, "little")
    image[mft_data + 64:mft_data + 68] = b"\x11\x04\x01\x00"
    image[mft_data + 72:mft_data + 76] = (0xFFFFFFFF).to_bytes(4, "little")

    directory = mft + 1024
    image[directory:directory + 4] = b"FILE"
    image[directory + 4:directory + 6] = (48).to_bytes(2, "little")
    image[directory + 6:directory + 8] = (3).to_bytes(2, "little")
    image[directory + 16:directory + 18] = (4).to_bytes(2, "little")
    image[directory + 20:directory + 22] = (56).to_bytes(2, "little")
    image[directory + 22:directory + 24] = (3).to_bytes(2, "little")
    image[directory + 24:directory + 28] = (140).to_bytes(4, "little")
    image[directory + 28:directory + 32] = (1024).to_bytes(4, "little")
    image[directory + 48:directory + 54] = b"\xcc\xdd\x44\x55\x66\x77"
    image[directory + 510:directory + 512] = b"\xcc\xdd"
    image[directory + 1022:directory + 1024] = b"\xcc\xdd"
    allocation = directory + 56
    image[allocation:allocation + 4] = (0xA0).to_bytes(4, "little")
    image[allocation + 4:allocation + 8] = (80).to_bytes(4, "little")
    image[allocation + 8] = 1
    image[allocation + 9] = 4
    image[allocation + 10:allocation + 12] = (64).to_bytes(2, "little")
    image[allocation + 14:allocation + 16] = (6).to_bytes(2, "little")
    image[allocation + 24:allocation + 32] = (1).to_bytes(8, "little")
    image[allocation + 32:allocation + 34] = (72).to_bytes(2, "little")
    image[allocation + 40:allocation + 48] = (1024).to_bytes(8, "little")
    image[allocation + 48:allocation + 56] = (1024).to_bytes(8, "little")
    image[allocation + 56:allocation + 64] = (1024).to_bytes(8, "little")
    image[allocation + 64:allocation + 72] = "$I30".encode("utf-16le")
    image[allocation + 72:allocation + 76] = b"\x11\x02\x0a\x00"
    image[allocation + 80:allocation + 84] = (0xFFFFFFFF).to_bytes(4, "little")

    index = 10 * 512
    image[index:index + 4] = b"INDX"
    image[index + 4:index + 6] = (40).to_bytes(2, "little")
    image[index + 6:index + 8] = (3).to_bytes(2, "little")
    image[index + 24:index + 28] = (40).to_bytes(4, "little")
    name = "orphan.txt"
    key_length = 66 + len(name.encode("utf-16le"))
    entry_length = ((16 + key_length + 7) // 8) * 8
    image[index + 28:index + 32] = (40 + entry_length + 16).to_bytes(4, "little")
    image[index + 32:index + 36] = (1000).to_bytes(4, "little")
    entry = index + 64
    image[entry:entry + 8] = ((9 << 48) | 77).to_bytes(8, "little")
    image[entry + 8:entry + 10] = entry_length.to_bytes(2, "little")
    image[entry + 10:entry + 12] = key_length.to_bytes(2, "little")
    key = entry + 16
    image[key + 64] = len(name)
    image[key + 65] = 1
    image[key + 66:key + 66 + len(name.encode("utf-16le"))] = name.encode("utf-16le")
    terminal = entry + entry_length
    image[terminal + 8:terminal + 10] = (16).to_bytes(2, "little")
    image[terminal + 12:terminal + 14] = (2).to_bytes(2, "little")
    stale = index + 256
    stale_name = "old-name.txt"
    stale_key_length = 66 + len(stale_name.encode("utf-16le"))
    stale_entry_length = ((16 + stale_key_length + 7) // 8) * 8
    image[stale:stale + 8] = ((2 << 48) | 99).to_bytes(8, "little")
    image[stale + 8:stale + 10] = stale_entry_length.to_bytes(2, "little")
    image[stale + 10:stale + 12] = stale_key_length.to_bytes(2, "little")
    stale_key = stale + 16
    image[stale_key + 64] = len(stale_name)
    image[stale_key + 65] = 1
    image[stale_key + 66:stale_key + 66 + len(stale_name.encode("utf-16le"))] = stale_name.encode("utf-16le")
    image[index + 40:index + 46] = b"\xee\xff\x12\x34\x56\x78"
    image[index + 510:index + 512] = b"\xee\xff"
    image[index + 1022:index + 1024] = b"\xee\xff"
    evidence = tmp_path / "ntfs-i30.raw"
    evidence.write_bytes(image)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["filesystem.ntfs.index_record_size"] == 1024
    sample = values["filesystem.ntfs.mft_sample_records"][0]
    assert sample["directory"] is True
    assert sample["index_allocation_entries"][0]["file_name"] == "orphan.txt"
    assert sample["index_allocation_entries"][0]["record_number"] == 77
    assert sample["index_allocation_entries"][0]["index_buffer"]["physical_segments"] == [
        {"logical_offset": 0, "physical_offset": index, "length": 1024}
    ]
    assert sample["index_allocation_slack_entries"][0]["file_name"] == "old-name.txt"
    assert sample["index_allocation_slack_entries"][0]["record_number"] == 99
    assert sample["index_allocation_slack_entries"][0]["slack_candidate"] is True
    assert values["filesystem.ntfs.mft_sample_index_links"][0]["child_sampled"] is False


def test_explicit_ntfs_usn_journal_child_parses_v2_records_and_offsets(tmp_path: Path) -> None:
    name = "flag.txt"
    encoded_name = name.encode("utf-16le")
    record_length = ((60 + len(encoded_name) + 7) // 8) * 8
    record = bytearray(record_length)
    record[0:4] = record_length.to_bytes(4, "little")
    record[4:6] = (2).to_bytes(2, "little")
    record[8:16] = ((3 << 48) | 42).to_bytes(8, "little")
    record[16:24] = ((2 << 48) | 5).to_bytes(8, "little")
    record[24:32] = (12345).to_bytes(8, "little", signed=True)
    filetime = 116444736000000000 + 1_700_000_000 * 10_000_000
    record[32:40] = filetime.to_bytes(8, "little")
    record[40:44] = (0x80001100).to_bytes(4, "little")
    record[48:52] = (7).to_bytes(4, "little")
    record[52:56] = (0x20).to_bytes(4, "little")
    record[56:58] = len(encoded_name).to_bytes(2, "little")
    record[58:60] = (60).to_bytes(2, "little")
    record[60:60 + len(encoded_name)] = encoded_name
    evidence = tmp_path / "journal.bin"
    evidence.write_bytes(record + b"\x18\x00\x00\x00\x03\x00\x00\x00")
    artifact = _artifact(evidence, logical_name="$UsnJrnl:$J")

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["ntfs.usn_journal_detected"] is True
    assert values["ntfs.usn.record_count"] == 1
    assert values["ntfs.usn.records"] == [{
        "offset": 0, "record_length": record_length, "major_version": 2, "minor_version": 0,
        "file_record_number": 42, "file_sequence_number": 3,
        "parent_record_number": 5, "parent_sequence_number": 2,
        "usn": 12345, "timestamp": "2023-11-14T22:13:20+00:00",
        "reason": "0x80001100", "reason_names": ["file_create", "rename_old_name", "close"],
        "source_info": "0x00000000", "security_id": 7,
        "file_attributes": "0x00000020", "file_name": "flag.txt",
    }]
    profile = ProfileEngine().evaluate(artifact, observations)
    finding = next(item for item in profile.findings if item.category == "ntfs_usn_journal_inventory")
    assert "'offset': 0" in finding.supporting_evidence[0]


def test_ntfs_usn_v3_preserves_128_bit_ids_without_frn_coercion(tmp_path: Path) -> None:
    name = "modern.bin"
    encoded_name = name.encode("utf-16le")
    record_length = ((76 + len(encoded_name) + 7) // 8) * 8
    record = bytearray(record_length)
    record[0:4] = record_length.to_bytes(4, "little")
    record[4:6] = (3).to_bytes(2, "little")
    file_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    parent_id = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    record[8:24] = file_id
    record[24:40] = parent_id
    record[40:48] = (2048).to_bytes(8, "little", signed=True)
    record[56:60] = (0x00000200).to_bytes(4, "little")
    record[72:74] = len(encoded_name).to_bytes(2, "little")
    record[74:76] = (76).to_bytes(2, "little")
    record[76:76 + len(encoded_name)] = encoded_name
    evidence = tmp_path / "usn-v3.bin"
    evidence.write_bytes(record)

    values = _values(GenericTriageEngine().analyze(
        _artifact(evidence, logical_name="$UsnJrnl:$J"), evidence
    ))

    parsed = values["ntfs.usn.records"][0]
    assert parsed["major_version"] == 3
    assert parsed["file_id_128"] == file_id.hex()
    assert parsed["parent_file_id_128"] == parent_id.hex()
    assert "file_record_number" not in parsed
    assert parsed["usn"] == 2048
    assert parsed["reason_names"] == ["file_delete"]
    assert parsed["file_name"] == "modern.bin"


def test_ntfs_usn_v4_parses_bounded_range_extents_without_name_or_time(tmp_path: Path) -> None:
    record_length = 96
    record = bytearray(record_length)
    record[0:4] = record_length.to_bytes(4, "little")
    record[4:6] = (4).to_bytes(2, "little")
    record[8:24] = bytes.fromhex("00112233445566778899aabbccddeeff")
    record[24:40] = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    record[40:48] = (4096).to_bytes(8, "little", signed=True)
    record[48:52] = (0x00000002).to_bytes(4, "little")
    record[52:56] = (1).to_bytes(4, "little")
    record[56:60] = (3).to_bytes(4, "little")
    record[60:62] = (2).to_bytes(2, "little")
    record[62:64] = (16).to_bytes(2, "little")
    record[64:72] = (100).to_bytes(8, "little", signed=True)
    record[72:80] = (20).to_bytes(8, "little", signed=True)
    record[80:88] = (500).to_bytes(8, "little", signed=True)
    record[88:96] = (40).to_bytes(8, "little", signed=True)
    evidence = tmp_path / "usn-v4.bin"
    evidence.write_bytes(record)

    values = _values(GenericTriageEngine().analyze(
        _artifact(evidence, logical_name="$UsnJrnl:$J"), evidence
    ))

    parsed = values["ntfs.usn.records"][0]
    assert parsed["major_version"] == 4
    assert parsed["usn"] == 4096
    assert parsed["reason_names"] == ["data_extend"]
    assert parsed["remaining_extents"] == 3
    assert parsed["number_of_extents"] == 2
    assert parsed["extent_size"] == 16
    assert parsed["extents"] == [{"offset": 100, "length": 20}, {"offset": 500, "length": 40}]
    assert "file_name" not in parsed and "timestamp" not in parsed


def test_uimage_header_and_payload_crc_are_validated(tmp_path: Path) -> None:
    payload = b"firmware payload"
    image = bytearray(64 + len(payload))
    image[:4] = b"\x27\x05\x19\x56"
    image[12:16] = len(payload).to_bytes(4, "big")
    image[24:28] = (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")
    image[32:32 + len(b"ctf firmware")] = b"ctf firmware"
    image[64:] = payload
    header_for_crc = bytearray(image[:64])
    header_for_crc[4:8] = b"\x00" * 4
    image[4:8] = (zlib.crc32(header_for_crc) & 0xFFFFFFFF).to_bytes(4, "big")
    evidence = tmp_path / "firmware.uimg"
    evidence.write_bytes(image)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["firmware.uimage_valid"] is True
    assert values["firmware.uimage.header_crc_valid"] is True
    assert values["firmware.uimage.payload_crc_valid"] is True


def test_tiff_first_ifd_geometry_is_classified_as_image(tmp_path: Path) -> None:
    data = bytearray(128)
    data[:8] = b"II\x2a\x00" + (8).to_bytes(4, "little")
    data[8:10] = (2).to_bytes(2, "little")
    data[10:22] = (256).to_bytes(2, "little") + (4).to_bytes(2, "little") + (1).to_bytes(4, "little") + (640).to_bytes(4, "little")
    data[22:34] = (257).to_bytes(2, "little") + (4).to_bytes(2, "little") + (1).to_bytes(4, "little") + (480).to_bytes(4, "little")
    evidence = tmp_path / "image.bin"
    evidence.write_bytes(data)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = _values(observations)

    assert values["tiff.header_valid"] is True
    assert values["tiff.tags"] == {"width": 640, "height": 480}
    assert IdentificationEngine().identify(artifact, observations).format == "tiff"


def test_registry_inline_dword_value_is_recovered_without_cell_dereference(tmp_path: Path) -> None:
    hive = bytearray(8192)
    hive[:4] = b"regf"
    hive[36:40] = (0x20).to_bytes(4, "little")
    hive[40:44] = (4096).to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4104:4108] = (4096).to_bytes(4, "little")
    root = 4096 + 0x20
    hive[root:root + 4] = (-88).to_bytes(4, "little", signed=True)
    hive[root + 4:root + 6] = b"nk"
    hive[root + 6:root + 8] = (0x20).to_bytes(2, "little")
    hive[root + 40:root + 44] = (1).to_bytes(4, "little")
    hive[root + 44:root + 48] = (0x80).to_bytes(4, "little")
    hive[root + 76:root + 78] = (4).to_bytes(2, "little")
    hive[root + 80:root + 84] = b"ROOT"
    value_list = 4096 + 0x80
    hive[value_list:value_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[value_list + 4:value_list + 8] = (0xA0).to_bytes(4, "little")
    value = 4096 + 0xA0
    hive[value:value + 4] = (-32).to_bytes(4, "little", signed=True)
    hive[value + 4:value + 6] = b"vk"
    hive[value + 6:value + 8] = (4).to_bytes(2, "little")
    hive[value + 8:value + 12] = (0x80000004).to_bytes(4, "little")
    hive[value + 12:value + 16] = (0x78563412).to_bytes(4, "little")
    hive[value + 16:value + 20] = (4).to_bytes(4, "little")  # REG_DWORD
    hive[value + 20:value + 22] = (1).to_bytes(2, "little")
    hive[value + 24:value + 28] = b"Test"
    evidence = tmp_path / "inline.regf"
    evidence.write_bytes(hive)

    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["registry.root_values"] == [{
        "name": "Test", "type": "REG_DWORD", "type_code": 4,
        "data_size": 4, "data_inline": True, "inline_data_hex": "12345678",
        "inline_value": 0x78563412,
    }]


def test_windows_recycle_bin_i_record_is_classified_and_profiled(tmp_path: Path) -> None:
    original_path = r"C:\\Users\\CTF\\Desktop\\flag.txt"
    encoded_path = (original_path + "\x00").encode("utf-16le")
    record = bytearray(28 + len(encoded_path))
    record[0:8] = (2).to_bytes(8, "little")
    record[8:16] = (1337).to_bytes(8, "little")
    record[16:24] = (132_223_104_000_000_000).to_bytes(8, "little")
    record[24:28] = (len(original_path) + 1).to_bytes(4, "little")
    record[28:] = encoded_path
    evidence = tmp_path / "$IABC1234"
    evidence.write_bytes(record)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["windows.recycle_bin_valid"] is True
    assert values["windows.recycle_bin_original_size"] == 1337
    assert values["windows.recycle_bin_original_path"] == original_path
    assert identified.format == "recycle_bin"
    assert artifact.artifact_type == "windows"
    assert any(finding.category == "windows_recycle_bin" for finding in profile.findings)


def test_lnk_linkinfo_unicode_local_target_is_boundedly_recovered(tmp_path: Path) -> None:
    base = r"C:\Users\CTF\AppData\Local\Temp"
    suffix = "payload.exe"
    base_bytes = (base + "\x00").encode("utf-16le")
    suffix_bytes = (suffix + "\x00").encode("utf-16le")
    link_info = bytearray(36 + len(base_bytes) + len(suffix_bytes))
    link_info[0:4] = len(link_info).to_bytes(4, "little")
    link_info[4:8] = (36).to_bytes(4, "little")
    link_info[8:12] = (1).to_bytes(4, "little")
    link_info[28:32] = (36).to_bytes(4, "little")
    link_info[32:36] = (36 + len(base_bytes)).to_bytes(4, "little")
    link_info[36:36 + len(base_bytes)] = base_bytes
    link_info[36 + len(base_bytes):] = suffix_bytes
    lnk = bytearray(76 + len(link_info))
    lnk[:4] = (0x4C).to_bytes(4, "little")
    lnk[4:20] = bytes.fromhex("0114020000000000C000000000000046")
    lnk[20:24] = (0x00000082).to_bytes(4, "little")  # LinkInfo + Unicode
    lnk[76:] = link_info
    evidence = tmp_path / "target.lnk"
    evidence.write_bytes(lnk)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["lnk.target_path"] == r"C:\Users\CTF\AppData\Local\Temp\payload.exe"
    assert values["lnk.link_info"]["valid"] is True
    assert any(finding.category == "windows_lnk_target" for finding in profile.findings)


def test_gif_comment_extension_is_structurally_recovered(tmp_path: Path) -> None:
    gif = (
        b"GIF89a" + (1).to_bytes(2, "little") + (1).to_bytes(2, "little") + b"\x00\x00\x00"
        + b"!\xfe\x09CTF{gif!}\x00"
        + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00\x3b"
    )
    evidence = tmp_path / "comment.gif"
    evidence.write_bytes(gif)
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["gif.comments"] == ["CTF{gif!}"]
    assert values["gif.extension_types"] == ["comment"]
    assert values["gif.image_descriptor_count"] == 1
    assert values["gif.trailer_found"] is True
    assert values["gif.structure_error"] is None
    assert any(finding.category == "image_metadata_lead" for finding in profile.findings)


def test_png_text_chunks_are_boundedly_decoded_into_image_findings(tmp_path: Path) -> None:
    evidence = tmp_path / "metadata.png"
    evidence.write_bytes(_png([
        (b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)),
        (b"tEXt", b"Comment\x00CTF{png_text}"),
        (b"zTXt", b"Author\x00\x00" + zlib.compress(b"offline analyst")),
        (b"IEND", b""),
    ]))
    artifact = _artifact(evidence)
    observations = GenericTriageEngine().analyze(artifact, evidence)
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])
    values = _values(observations)

    assert values["png.text_entries"] == [
        {"type": "tEXt", "keyword": "Comment", "text": "CTF{png_text}"},
        {"type": "zTXt", "keyword": "Author", "text": "offline analyst"},
    ]
    assert any(finding.category == "image_metadata_lead" for finding in profile.findings)


def test_registry_direct_run_child_recovers_only_valid_bounded_text_data(tmp_path: Path) -> None:
    """Direct Run-key values may be decoded, but only from one allocated cell."""
    hive = bytearray(8192)
    hive[:4] = b"regf"
    hive[36:40] = (0x20).to_bytes(4, "little")
    hive[40:44] = (4096).to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4104:4108] = (4096).to_bytes(4, "little")

    root = 4096 + 0x20
    hive[root:root + 4] = (-88).to_bytes(4, "little", signed=True)
    hive[root + 4:root + 6] = b"nk"
    hive[root + 6:root + 8] = (0x20).to_bytes(2, "little")
    hive[root + 24:root + 28] = (1).to_bytes(4, "little")
    hive[root + 32:root + 36] = (0xC0).to_bytes(4, "little")
    hive[root + 76:root + 78] = (4).to_bytes(2, "little")
    hive[root + 80:root + 84] = b"ROOT"

    child_list = 4096 + 0xC0
    hive[child_list:child_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[child_list + 4:child_list + 6] = b"li"
    hive[child_list + 6:child_list + 8] = (1).to_bytes(2, "little")
    hive[child_list + 8:child_list + 12] = (0xE0).to_bytes(4, "little")

    child = 4096 + 0xE0
    hive[child:child + 4] = (-96).to_bytes(4, "little", signed=True)
    hive[child + 4:child + 6] = b"nk"
    hive[child + 6:child + 8] = (0x20).to_bytes(2, "little")
    hive[child + 40:child + 44] = (1).to_bytes(4, "little")
    hive[child + 44:child + 48] = (0x140).to_bytes(4, "little")
    hive[child + 76:child + 78] = (3).to_bytes(2, "little")
    hive[child + 80:child + 83] = b"Run"

    value_list = 4096 + 0x140
    hive[value_list:value_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[value_list + 4:value_list + 8] = (0x160).to_bytes(4, "little")
    command = r"C:\\CTF\\runner.exe --quiet".encode("utf-16le") + b"\x00\x00"
    value = 4096 + 0x160
    hive[value:value + 4] = (-64).to_bytes(4, "little", signed=True)
    hive[value + 4:value + 6] = b"vk"
    hive[value + 6:value + 8] = (7).to_bytes(2, "little")
    hive[value + 8:value + 12] = len(command).to_bytes(4, "little")
    hive[value + 12:value + 16] = (0x1B0).to_bytes(4, "little")
    hive[value + 16:value + 20] = (1).to_bytes(4, "little")
    hive[value + 20:value + 22] = (1).to_bytes(2, "little")
    hive[value + 24:value + 31] = b"Updater"
    data_cell = 4096 + 0x1B0
    hive[data_cell:data_cell + 4] = (-(4 + len(command))).to_bytes(4, "little", signed=True)
    hive[data_cell + 4:data_cell + 4 + len(command)] = command

    evidence = tmp_path / "run-child.regf"
    evidence.write_bytes(hive)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["registry.root_child_values"] == [{
        "key": "Run", "name": "Updater", "type": "REG_SZ", "type_code": 1,
        "data_size": len(command), "data_inline": False,
        "data_text": r"C:\\CTF\\runner.exe --quiet",
    }]
    assert values["registry.execution_value_data"] == values["registry.root_child_values"]


def test_registry_allowlisted_nested_run_path_recovers_full_key_provenance(tmp_path: Path) -> None:
    """A real Run key is nested below Software, not normally a root child."""
    hive = bytearray(8192)
    hive[:4] = b"regf"
    hive[36:40] = (0x20).to_bytes(4, "little")
    hive[40:44] = (4096).to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4104:4108] = (4096).to_bytes(4, "little")

    def nk(offset: int, name: str, child_list: int | None = None, value_list: int | None = None) -> None:
        absolute = 4096 + offset
        encoded = name.encode("latin-1")
        hive[absolute:absolute + 4] = (-128).to_bytes(4, "little", signed=True)
        hive[absolute + 4:absolute + 6] = b"nk"
        hive[absolute + 6:absolute + 8] = (0x20).to_bytes(2, "little")
        if child_list is not None:
            hive[absolute + 24:absolute + 28] = (1).to_bytes(4, "little")
            hive[absolute + 32:absolute + 36] = child_list.to_bytes(4, "little")
        if value_list is not None:
            hive[absolute + 40:absolute + 44] = (1).to_bytes(4, "little")
            hive[absolute + 44:absolute + 48] = value_list.to_bytes(4, "little")
        hive[absolute + 76:absolute + 78] = len(encoded).to_bytes(2, "little")
        hive[absolute + 80:absolute + 80 + len(encoded)] = encoded

    def child_list(offset: int, child_offset: int) -> None:
        absolute = 4096 + offset
        hive[absolute:absolute + 4] = (-16).to_bytes(4, "little", signed=True)
        hive[absolute + 4:absolute + 6] = b"li"
        hive[absolute + 6:absolute + 8] = (1).to_bytes(2, "little")
        hive[absolute + 8:absolute + 12] = child_offset.to_bytes(4, "little")

    # Root → Software → Microsoft → Windows → CurrentVersion → Run.
    nk(0x20, "ROOT", 0xC0)
    nk(0x100, "Software", 0x180)
    nk(0x200, "Microsoft", 0x280)
    nk(0x300, "Windows", 0x380)
    nk(0x400, "CurrentVersion", 0x480)
    nk(0x500, "Run", value_list=0x600)
    for list_offset, child_offset in ((0xC0, 0x100), (0x180, 0x200), (0x280, 0x300), (0x380, 0x400), (0x480, 0x500)):
        child_list(list_offset, child_offset)

    value_list = 4096 + 0x600
    hive[value_list:value_list + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[value_list + 4:value_list + 8] = (0x620).to_bytes(4, "little")
    command = r"C:\\CTF\\nested-run.exe".encode("utf-16le") + b"\x00\x00"
    value = 4096 + 0x620
    hive[value:value + 4] = (-64).to_bytes(4, "little", signed=True)
    hive[value + 4:value + 6] = b"vk"
    hive[value + 6:value + 8] = (7).to_bytes(2, "little")
    hive[value + 8:value + 12] = len(command).to_bytes(4, "little")
    hive[value + 12:value + 16] = (0x680).to_bytes(4, "little")
    hive[value + 16:value + 20] = (1).to_bytes(4, "little")
    hive[value + 20:value + 22] = (1).to_bytes(2, "little")
    hive[value + 24:value + 31] = b"Updater"
    data = 4096 + 0x680
    hive[data:data + 4] = (-(4 + len(command))).to_bytes(4, "little", signed=True)
    hive[data + 4:data + 4 + len(command)] = command

    evidence = tmp_path / "nested-run.regf"
    evidence.write_bytes(hive)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["registry.persistence_path_values"] == [{
        "key_path": "software\\microsoft\\windows\\currentversion\\run",
        "key": "Run", "name": "Updater", "type": "REG_SZ", "type_code": 1,
        "data_size": len(command), "data_inline": False,
        "data_text": r"C:\\CTF\\nested-run.exe",
    }]
    assert values["registry.execution_value_data"] == values["registry.persistence_path_values"]


def test_registry_allowlisted_path_cycle_does_not_recurse_indefinitely(tmp_path: Path) -> None:
    hive = bytearray(8192)
    hive[:4] = b"regf"
    hive[36:40] = (0x20).to_bytes(4, "little")
    hive[40:44] = (4096).to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4104:4108] = (4096).to_bytes(4, "little")
    for offset, name, subkey_list in ((0x20, b"ROOT", 0xC0), (0x100, b"Software", 0xC0)):
        absolute = 4096 + offset
        hive[absolute:absolute + 4] = (-128).to_bytes(4, "little", signed=True)
        hive[absolute + 4:absolute + 6] = b"nk"
        hive[absolute + 6:absolute + 8] = (0x20).to_bytes(2, "little")
        hive[absolute + 24:absolute + 28] = (1).to_bytes(4, "little")
        hive[absolute + 32:absolute + 36] = subkey_list.to_bytes(4, "little")
        hive[absolute + 76:absolute + 78] = len(name).to_bytes(2, "little")
        hive[absolute + 80:absolute + 80 + len(name)] = name
    listing = 4096 + 0xC0
    hive[listing:listing + 4] = (-16).to_bytes(4, "little", signed=True)
    hive[listing + 4:listing + 6] = b"li"
    hive[listing + 6:listing + 8] = (1).to_bytes(2, "little")
    hive[listing + 8:listing + 12] = (0x100).to_bytes(4, "little")

    evidence = tmp_path / "cyclic.regf"
    evidence.write_bytes(hive)
    values = _values(GenericTriageEngine().analyze(_artifact(evidence), evidence))

    assert values["registry.persistence_path_values"] == []
    assert values["registry.persistence_path_truncated"] is False
