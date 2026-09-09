from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zlib

from forensickit.config import ForensicKitConfig
from forensickit.engine import AnalysisEngine
from forensickit.extraction import ExtractionManager
from forensickit.identification import IdentificationEngine
from forensickit.models import AnalysisMode, Artifact
from forensickit.profiles import ProfileEngine
from forensickit.triage import GenericTriageEngine
from forensickit.workspace import CaseWorkspace


_END = 0xFFFFFFFE
_FREE = 0xFFFFFFFF
_FAT = 0xFFFFFFFD
_LNK_HEADER = bytes.fromhex(
    "4c0000000114020000000000c000000000000046"
)


def _artifact(path: Path) -> Artifact:
    data = path.read_bytes()
    return Artifact(
        id="artifact-1", case_id="case-1", path=str(path),
        logical_name=path.name, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
    )


class _RegistryHiveBuilder:
    """Create tiny allocated-cell hives for semantic parser fixtures."""

    def __init__(self, hbin_size: int = 65_536) -> None:
        self.hbin_size = hbin_size
        self.data = bytearray(4096 + hbin_size)
        self.cursor = 32

    def cell(self, payload: bytes) -> int:
        total = (4 + len(payload) + 7) & ~7
        if self.cursor + total > self.hbin_size:
            raise AssertionError("fixture hive is full")
        offset = self.cursor
        absolute = 4096 + offset
        self.data[absolute:absolute + 4] = (-total).to_bytes(4, "little", signed=True)
        self.data[absolute + 4:absolute + 4 + len(payload)] = payload
        self.cursor += total
        return offset

    def value(self, name: str, type_code: int, value: str | bytes | int) -> int:
        if isinstance(value, str):
            raw = value.encode("utf-16le") + b"\x00\x00"
        elif isinstance(value, int):
            width = 8 if type_code == 11 else 4
            raw = value.to_bytes(width, "little")
        else:
            raw = value
        data_offset = self.cell(raw)
        raw_name = name.encode("latin-1")
        payload = bytearray(20 + len(raw_name))
        payload[:2] = b"vk"
        payload[2:4] = len(raw_name).to_bytes(2, "little")
        payload[4:8] = len(raw).to_bytes(4, "little")
        payload[8:12] = data_offset.to_bytes(4, "little")
        payload[12:16] = type_code.to_bytes(4, "little")
        payload[16:18] = (1).to_bytes(2, "little")
        payload[20:] = raw_name
        return self.cell(payload)

    def key(
        self,
        name: str,
        *,
        children: tuple[int, ...] = (),
        values: tuple[int, ...] = (),
        last_write_filetime: int = 0,
    ) -> int:
        child_list = 0xFFFFFFFF
        if children:
            listing = b"li" + len(children).to_bytes(2, "little") + b"".join(
                offset.to_bytes(4, "little") for offset in children
            )
            child_list = self.cell(listing)
        value_list = 0xFFFFFFFF
        if values:
            value_list = self.cell(b"".join(offset.to_bytes(4, "little") for offset in values))
        raw_name = name.encode("latin-1")
        payload = bytearray(76 + len(raw_name))
        payload[:2] = b"nk"
        payload[2:4] = (0x20).to_bytes(2, "little")
        payload[4:12] = last_write_filetime.to_bytes(8, "little")
        payload[20:24] = len(children).to_bytes(4, "little")
        payload[28:32] = child_list.to_bytes(4, "little")
        payload[36:40] = len(values).to_bytes(4, "little")
        payload[40:44] = value_list.to_bytes(4, "little")
        payload[72:74] = len(raw_name).to_bytes(2, "little")
        payload[76:] = raw_name
        return self.cell(payload)

    def write(self, path: Path, root_offset: int) -> None:
        self.data[:4] = b"regf"
        self.data[4:8] = (1).to_bytes(4, "little")
        self.data[8:12] = (1).to_bytes(4, "little")
        self.data[36:40] = root_offset.to_bytes(4, "little")
        self.data[40:44] = self.hbin_size.to_bytes(4, "little")
        self.data[4096:4100] = b"hbin"
        self.data[4100:4104] = (0).to_bytes(4, "little")
        self.data[4104:4108] = self.hbin_size.to_bytes(4, "little")
        path.write_bytes(self.data)


def _amcache_hive(path: Path) -> None:
    builder = _RegistryHiveBuilder()
    values = (
        builder.value("Name", 1, "FLAG{AMCACHE_RECORD}"),
        builder.value("Publisher", 1, "CTF Labs"),
        builder.value("LowerCaseLongPath", 1, r"c:\\users\\alice\\downloads\\solve.exe"),
        builder.value("ProgramId", 1, "0000abc"),
        builder.value("Size", 11, 1337),
    )
    app = builder.key(
        "{11111111-2222-3333-4444-555555555555}",
        values=values,
        last_write_filetime=133_700_000_000_000_000,
    )
    inventory = builder.key("InventoryApplicationFile", children=(app,))
    root = builder.key("Root", children=(inventory,))
    builder.write(path, root)


def _shimcache_hive(path: Path, cached_path: str) -> None:
    builder = _RegistryHiveBuilder()
    raw_path = cached_path.encode("utf-16le")
    modified = 133_700_000_000_000_000
    body = len(raw_path).to_bytes(2, "little") + raw_path + modified.to_bytes(8, "little") + (0).to_bytes(4, "little")
    entry = b"10ts" + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little") + len(body).to_bytes(4, "little") + body
    cache_value = builder.value("AppCompatCache", 3, b"\x00" * 48 + entry)
    cache = builder.key("AppCompatCache", values=(cache_value,))
    session = builder.key("Session Manager", children=(cache,))
    control = builder.key("Control", children=(session,))
    control_set = builder.key("ControlSet001", children=(control,))
    root = builder.key("SYSTEM", children=(control_set,))
    builder.write(path, root)


def _directory_entry(name: str, object_type: int, start: int, size: int) -> bytes:
    entry = bytearray(128)
    encoded = name.encode("utf-16le") + b"\x00\x00"
    entry[:len(encoded)] = encoded
    entry[64:66] = len(encoded).to_bytes(2, "little")
    entry[66] = object_type
    entry[67] = 1
    entry[68:80] = _FREE.to_bytes(4, "little") * 3
    entry[116:120] = start.to_bytes(4, "little")
    entry[120:128] = size.to_bytes(8, "little")
    return bytes(entry)


def _automatic_jumplist(path_text: str, embedded: bytes) -> bytes:
    sector_size = 512
    stream_size = 4096
    header = bytearray(sector_size)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header[24:26] = (0x3E).to_bytes(2, "little")
    header[26:28] = (3).to_bytes(2, "little")
    header[28:30] = b"\xfe\xff"
    header[30:32] = (9).to_bytes(2, "little")
    header[32:34] = (6).to_bytes(2, "little")
    header[44:48] = (1).to_bytes(4, "little")
    header[48:52] = (0).to_bytes(4, "little")
    header[56:60] = (4096).to_bytes(4, "little")
    header[60:64] = _END.to_bytes(4, "little")
    header[68:72] = _END.to_bytes(4, "little")
    header[76:80] = (1).to_bytes(4, "little")
    for offset in range(80, 512, 4):
        header[offset:offset + 4] = _FREE.to_bytes(4, "little")

    directory = bytearray(sector_size)
    directory[:128] = _directory_entry("Root Entry", 5, _END, 0)
    directory[128:256] = _directory_entry("DestList", 2, 2, stream_size)
    directory[256:384] = _directory_entry("1", 2, 10, stream_size)

    fat = bytearray(sector_size)
    values = [_END, _FAT]
    values.extend([*range(3, 10), _END])
    values.extend([*range(11, 18), _END])
    values.extend([_FREE] * (sector_size // 4 - len(values)))
    for index, value in enumerate(values):
        fat[index * 4:index * 4 + 4] = value.to_bytes(4, "little")

    raw_path = path_text.encode("utf-16le")
    record = bytearray(130 + len(raw_path))
    record[72:80] = b"CTFHOST\x00"
    record[88:96] = (1).to_bytes(8, "little")
    record[100:108] = (133_700_000_000_000_000).to_bytes(8, "little")
    record[108:112] = _FREE.to_bytes(4, "little")
    record[116:120] = (7).to_bytes(4, "little")
    record[128:130] = (len(path_text)).to_bytes(2, "little")
    record[130:] = raw_path
    destlist = bytearray(stream_size)
    destlist[:4] = (3).to_bytes(4, "little")
    destlist[4:8] = (1).to_bytes(4, "little")
    destlist[16:24] = (1).to_bytes(8, "little")
    destlist[32:32 + len(record)] = record

    shortcut = bytearray(stream_size)
    shortcut[:len(_LNK_HEADER)] = _LNK_HEADER
    shortcut[76:76 + len(embedded)] = embedded
    return bytes(header + directory + fat + destlist + shortcut)


def test_automatic_jumplist_is_structurally_identified_and_parsed(tmp_path: Path) -> None:
    evidence = tmp_path / "1b4dd67f29cb1962.automaticDestinations-ms"
    evidence.write_bytes(_automatic_jumplist(r"C:\\Users\\ctf\\Downloads\\answer.txt", b"marker"))
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = {item.key: item.value for item in observations}
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert values["jumplist.valid"] is True
    assert values["jumplist.kind"] == "automatic_destinations"
    assert values["jumplist.destinations"][0]["path"].endswith("answer.txt")
    assert values["jumplist.destinations"][0]["stream_offset"] == 32
    assert values["jumplist.link_streams"][0]["lnk_header_valid"] is True
    assert identified.format == "jumplist"
    assert any(item.category == "windows_jumplist" for item in profile.findings)


def test_jumplist_embedded_lnk_reenters_common_flag_search(tmp_path: Path) -> None:
    evidence = tmp_path / "1b4dd67f29cb1962.automaticDestinations-ms"
    evidence.write_bytes(_automatic_jumplist("answer.txt", b"FLAG{JUMPLIST_CHILD}"))
    config = ForensicKitConfig()

    result = AnalysisEngine(config).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )

    children = [item for item in result.artifacts if item.parent_id == result.root_artifact.id]
    assert len(children) == 1
    assert children[0].logical_name == "1.lnk"
    candidate = next(item for item in result.flags if item.value == "FLAG{JUMPLIST_CHILD}")
    assert any(location["artifact_id"] == children[0].id for location in candidate.locations)
    assert any(item.category == "windows_jumplist_extraction" for item in result.findings)


def test_custom_jumplist_range_extraction_is_bounded(tmp_path: Path) -> None:
    footer = bytes.fromhex("abfbbfba4c42a7468c01f83a9c654cb3")
    shortcut = _LNK_HEADER + bytes(76 - len(_LNK_HEADER)) + b"CTF{CUSTOM_LINK}"
    evidence = tmp_path / "custom.bin"
    evidence.write_bytes(shortcut + footer)
    artifact = _artifact(evidence)
    artifact.logical_name = "5f7b5f1e01b83767.customDestinations-ms"
    workspace = CaseWorkspace.create(tmp_path / "cases", "custom")
    try:
        stored = workspace.path("evidence", evidence.name)
        stored.write_bytes(evidence.read_bytes())
        artifact.case_id = workspace.case.id
        artifact.path = workspace.relative(stored)
        workspace.database.add_artifact(artifact)
        extraction = ExtractionManager(workspace, ForensicKitConfig().limits)
        extracted = extraction.extract_jumplist_links(artifact)
        assert len(extracted.artifacts) == 1
        assert workspace.resolve_stored_path(extracted.artifacts[0].path).read_bytes() == shortcut
    finally:
        workspace.close()


def test_amcache_fixed_path_records_reach_profile_search_and_timeline(tmp_path: Path) -> None:
    evidence = tmp_path / "opaque-hive.bin"
    _amcache_hive(evidence)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = {item.key: item.value for item in observations}
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert values["registry.amcache.detected"] is True
    assert values["registry.amcache.schema"] == "InventoryApplicationFile"
    record = values["registry.amcache.records"][0]
    assert record["record_kind"] == "application_file"
    assert record["name"] == "FLAG{AMCACHE_RECORD}"
    assert record["path"] == r"c:\\users\\alice\\downloads\\solve.exe"
    assert record["size"] == 1337
    assert record["key_hive_offset"] > 0
    assert record["key_file_offset"] == 4096 + record["key_hive_offset"]
    assert record["value_provenance"][0]["value_file_offset"] == 4096 + record["value_provenance"][0]["value_hive_offset"]
    assert record["value_provenance"][0]["data_file_offset"] > 4096
    assert record["timestamp_basis"].endswith("not an execution timestamp")
    assert any(item.category == "windows_amcache_inventory" for item in profile.findings)

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False,
    )
    candidate = next(item for item in result.flags if item.value == "FLAG{AMCACHE_RECORD}")
    assert any(location.get("source_kind") == "parsed_record" for location in candidate.locations)
    report = json.loads(
        Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    )
    row = next(item for item in report["timeline"] if item.get("category") == "windows_amcache")
    assert row["path"] == r"c:\\users\\alice\\downloads\\solve.exe"
    assert row["timestamp_raw"] == 133_700_000_000_000_000
    assert row["record_offset"] == record["key_file_offset"]
    assert row["record_hive_offset"] == record["key_hive_offset"]


def test_shimcache_10ts_records_preserve_offsets_and_interpretation_limit(tmp_path: Path) -> None:
    evidence = tmp_path / "system-without-extension"
    cached_path = r"C:\\Users\\alice\\Downloads\\payload.exe"
    _shimcache_hive(evidence, cached_path)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = {item.key: item.value for item in observations}
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert values["registry.shimcache.detected"] is True
    assert values["registry.shimcache.formats"] == ["windows_10_or_newer_10ts"]
    record = values["registry.shimcache.records"][0]
    assert record["path"] == cached_path
    assert record["control_set"] == "ControlSet001"
    assert record["entry_offset_in_value"] == 48
    assert record["value_file_offset"] == 4096 + record["value_hive_offset"]
    assert record["entry_file_offset"] == record["value_data_file_offset"] + 48
    assert record["entry_hive_offset"] == record["entry_file_offset"] - 4096
    assert record["checksum_matches_crc32_body"] is True
    assert record["timestamp_basis"].startswith("cached file last-modified FILETIME")
    finding = next(item for item in profile.findings if item.category == "windows_shimcache_inventory")
    assert "do not alone prove execution" in finding.explanation

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "shimcache-cases", mode=AnalysisMode.TRIAGE, execute=False,
    )
    report = json.loads(
        Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    )
    row = next(item for item in report["timeline"] if item.get("category") == "windows_shimcache")
    assert row["path"] == cached_path
    assert row["registry_cache_format"] == "windows_10_or_newer_10ts"
    assert row["record_offset"] == record["entry_file_offset"]
    assert row["record_hive_offset"] == record["entry_hive_offset"]


def test_unrecognized_shimcache_layout_is_reported_as_unsupported(tmp_path: Path) -> None:
    builder = _RegistryHiveBuilder()
    cache_value = builder.value("AppCompatCache", 3, b"unsupported-cache-layout")
    cache = builder.key("AppCompatCache", values=(cache_value,))
    session = builder.key("Session Manager", children=(cache,))
    control = builder.key("Control", children=(session,))
    control_set = builder.key("ControlSet002", children=(control,))
    root = builder.key("SYSTEM", children=(control_set,))
    evidence = tmp_path / "unsupported-system.hive"
    builder.write(evidence, root)
    artifact = _artifact(evidence)

    observations = GenericTriageEngine().analyze(artifact, evidence)
    values = {item.key: item.value for item in observations}
    identified = IdentificationEngine().identify(artifact, observations)
    profile = ProfileEngine().evaluate(artifact, [*observations, *identified.observations])

    assert values["registry.shimcache.detected"] is True
    assert values["registry.shimcache.records"] == []
    assert any("unsupported or unrecognized" in item for item in values["registry.activity_errors"])
    assert any(item.category == "windows_shimcache_unsupported_layout" for item in profile.findings)


def test_amcache_and_shimcache_exact_paths_are_correlated_across_artifacts(tmp_path: Path) -> None:
    amcache = tmp_path / "Amcache.hve"
    system = tmp_path / "SYSTEM"
    _amcache_hive(amcache)
    _shimcache_hive(system, r"C:\\Users\\Alice\\Downloads\\solve.exe")

    result = AnalysisEngine(ForensicKitConfig()).analyze_many(
        [amcache, system], tmp_path / "correlation-cases",
        mode=AnalysisMode.TRIAGE, execute=False,
    )

    correlations = [
        item for item in result.observations
        if item.key == "correlation.windows_exact_path"
    ]
    assert len(correlations) == 2
    link = correlations[0].value[0]
    assert link["canonical_path"] == r"c:\users\alice\downloads\solve.exe"
    assert link["artifact_count"] == 2
    assert {item["artifact_kind"] for item in link["sources"]} == {"amcache", "shimcache"}
    assert all(item["source_observation_id"] for item in link["sources"])
    assert all(item["record_locator"] is not None for item in link["sources"])
    finding = next(
        item for item in result.findings
        if item.category == "windows_artifact_path_correlation"
    )
    assert "does not by itself prove execution" in finding.explanation
