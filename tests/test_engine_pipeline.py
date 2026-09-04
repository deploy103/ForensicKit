from __future__ import annotations

import base64
import csv
import gzip
import io
import sqlite3
import tarfile
import zlib
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from forensickit.engine import AnalysisEngine
from forensickit.config import ForensicKitConfig
from forensickit.evidence import EvidenceManager
from forensickit.models import AnalysisMode, AnalysisResult, Artifact, Observation
from forensickit.tools import ToolDefinition, ToolRegistry
from forensickit.triage import GenericTriageEngine
from forensickit.workspace import CaseWorkspace


def test_png_appended_zip_recurses_to_base64_flag(tmp_path: Path) -> None:
    archive = BytesIO()
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("flag.txt", base64.b64encode(b"CTF{pipeline_chain}"))
    # Triage only needs structurally valid IEND placement for this chain.
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24 + b"IEND\xaeB`\x82"
    evidence = tmp_path / "challenge.png"
    evidence.write_bytes(png + archive.getvalue())

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    assert [artifact.logical_name for artifact in result.artifacts] == ["challenge.png", "flag.txt"]
    assert any(candidate.value == "CTF{pipeline_chain}" for candidate in result.flags)
    assert any("base64" in candidate.transform_chain for candidate in result.flags)
    assert {"sevenzip", "binwalk3"} <= {item.tool for item in result.plans}


def test_file_parser_reclassifies_and_replans_pcap(tmp_path: Path) -> None:
    executable = tmp_path / "file-parser"
    executable.write_text("#!/bin/sh\nprintf 'pcap capture file, microsecond ts\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    evidence = tmp_path / "opaque.bin"
    evidence.write_bytes(b"\x01\x02\x03\x04")

    engine = AnalysisEngine()
    engine.registry = ToolRegistry(
        [
            ToolDefinition("file", (str(executable),), parser="file", command_templates={"default": ("{executable}", "{evidence}")}),
            ToolDefinition("capinfos", ("missing-capinfos",), parser="capinfos", command_templates={"default": ("{executable}", "{evidence}")}),
            ToolDefinition("tshark", ("missing-tshark",), parser="tshark", command_templates={"default": ("{executable}", "{evidence}")}),
        ]
    )
    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    assert result.root_artifact.artifact_type == "pcap"
    assert {"file", "capinfos", "tshark"} <= {item.tool for item in result.plans}


def test_gzip_recurses_with_artifact_lineage(tmp_path: Path) -> None:
    evidence = tmp_path / "payload.txt.gz"
    with gzip.open(evidence, "wb") as stream:
        stream.write(base64.b64encode(b"CTF{gzip_lineage}"))

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    assert [artifact.logical_name for artifact in result.artifacts] == ["payload.txt.gz", "payload.txt"]
    assert any(candidate.value == "CTF{gzip_lineage}" for candidate in result.flags)


def test_ext_root_regular_file_recurses_to_flag_with_inode_lineage(tmp_path: Path) -> None:
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
    image[2048 + 8:2048 + 12] = (5).to_bytes(4, "little")
    root_inode = 5 * 1024 + 128
    image[root_inode:root_inode + 2] = (0x41ED).to_bytes(2, "little")
    image[root_inode + 4:root_inode + 8] = (1024).to_bytes(4, "little")
    image[root_inode + 40:root_inode + 44] = (7).to_bytes(4, "little")
    directory = 7 * 1024
    for offset, inode, record_length, name in (
        (0, 2, 12, b"."), (12, 2, 12, b".."), (24, 12, 1000, b"flag.txt"),
    ):
        image[directory + offset:directory + offset + 4] = inode.to_bytes(4, "little")
        image[directory + offset + 4:directory + offset + 6] = record_length.to_bytes(2, "little")
        image[directory + offset + 6:directory + offset + 8] = len(name).to_bytes(2, "little")
        image[directory + offset + 8:directory + offset + 8 + len(name)] = name
    payload = b"CTF{ext_engine_lineage}"
    file_inode = 5 * 1024 + 11 * 128
    image[file_inode:file_inode + 2] = (0x81A4).to_bytes(2, "little")
    image[file_inode + 4:file_inode + 8] = len(payload).to_bytes(4, "little")
    image[file_inode + 26:file_inode + 28] = (1).to_bytes(2, "little")
    image[file_inode + 40:file_inode + 44] = (8).to_bytes(4, "little")
    image[8 * 1024:8 * 1024 + len(payload)] = payload
    evidence = tmp_path / "ext2.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    assert [artifact.logical_name for artifact in result.artifacts] == ["ext2.raw", "flag.txt"]
    child = result.artifacts[1]
    assert child.parent_id == result.root_artifact.id
    assert any(candidate.value == "CTF{ext_engine_lineage}" and candidate.artifact_id == child.id for candidate in result.flags)
    recovery = next(item for item in result.findings if item.category == "ext_root_file_recovery")
    assert "inode:12" in recovery.supporting_evidence[0]


def test_multiple_root_evidence_files_share_a_case_and_report(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"CTF{first_root}")
    second.write_bytes(b"FLAG{second_root}")

    result = AnalysisEngine().analyze_many(
        [first, second], tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False,
    )

    roots = [artifact for artifact in result.artifacts if artifact.parent_id is None]
    assert [artifact.logical_name for artifact in roots] == ["first.txt", "second.txt"]
    assert {candidate.value for candidate in result.flags} >= {"CTF{first_root}", "FLAG{second_root}"}
    reports = list((tmp_path / "cases").glob("*/reports/report.json"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert "first.txt" in report and "second.txt" in report


def test_ios_manifest_correlates_explicitly_supplied_file_id_root(tmp_path: Path) -> None:
    manifest = tmp_path / "Manifest.db"
    file_id = "a" * 40
    connection = sqlite3.connect(manifest)
    try:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?)",
            (file_id, "HomeDomain", "Library/Preferences/com.ctf.flag.plist", 1),
        )
        connection.commit()
    finally:
        connection.close()
    payload = tmp_path / file_id
    payload.write_bytes(b"CTF{ios_manifest_payload}")

    result = AnalysisEngine().analyze_many(
        [manifest, payload], tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False,
    )

    assert any(finding.category == "ios_backup_payload_correlation" for finding in result.findings)
    references = [
        observation.value for observation in result.observations
        if observation.key == "mobile.ios_manifest_reference"
    ]
    assert references == [{
        "file_id": file_id, "payload_artifact_id": next(
            artifact.id for artifact in result.artifacts if artifact.logical_name == file_id
        ), "domain": "HomeDomain", "relative_path": "Library/Preferences/com.ctf.flag.plist",
        "manifest_artifact_id": next(
            artifact.id for artifact in result.artifacts if artifact.logical_name == "Manifest.db"
        ),
    }]


def test_ios_backup_directory_preserves_and_correlates_payloads(tmp_path: Path) -> None:
    backup = tmp_path / "ios-backup"
    backup.mkdir()
    manifest = backup / "Manifest.db"
    file_id = "b" * 40
    connection = sqlite3.connect(manifest)
    try:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?)",
            (file_id, "AppDomain-com.ctf", "Documents/flag.txt", 1),
        )
        connection.commit()
    finally:
        connection.close()
    (backup / file_id).write_bytes(base64.b64encode(b"CTF{ios_directory_bundle}"))

    result = AnalysisEngine().analyze(backup, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    roots = [artifact for artifact in result.artifacts if artifact.parent_id is None]
    assert {artifact.logical_name for artifact in roots} == {"Manifest.db", file_id}
    assert any(finding.category == "ios_backup_payload_correlation" for finding in result.findings)
    assert any(candidate.value == "CTF{ios_directory_bundle}" for candidate in result.flags)


def test_ios_manifest_bounded_reference_inventory_links_payload_beyond_summary_sample(tmp_path: Path) -> None:
    backup = tmp_path / "ios-backup"
    backup.mkdir()
    manifest = backup / "Manifest.db"
    target_id = f"{'c' * 39}1"
    connection = sqlite3.connect(manifest)
    try:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        for index in range(201):
            file_id = target_id if index == 200 else f"{index:040x}"
            connection.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?)",
                (file_id, "HomeDomain", f"Library/item-{index}.plist", 1),
            )
        connection.commit()
    finally:
        connection.close()
    (backup / target_id).write_bytes(b"payload")

    result = AnalysisEngine().analyze(backup, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    manifest_artifact = next(artifact for artifact in result.artifacts if artifact.logical_name == "Manifest.db")
    references = next(
        item.value for item in result.observations
        if item.artifact_id == manifest_artifact.id and item.key == "mobile.ios_manifest_file_references"
    )
    assert len(references) == 201
    assert any(item.get("file_id") == target_id for item in references)
    assert any(
        item.key == "mobile.ios_manifest_reference" and item.value["file_id"] == target_id
        for item in result.observations
    )


def test_ios_manifest_semantic_paths_produce_bounded_collection_leads(tmp_path: Path) -> None:
    manifest = tmp_path / "Manifest.db"
    rows = [
        ("1" * 40, "HomeDomain", "Library/SMS/sms.db", 1),
        ("2" * 40, "HomeDomain", "Library/Safari/History.db", 1),
        ("3" * 40, "HomeDomain", "Library/CallHistoryDB/CallHistory.storedata", 1),
        ("4" * 40, "HomeDomain", "Library/Keychains/keychain-2.db", 1),
    ]
    connection = sqlite3.connect(manifest)
    try:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        connection.executemany("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", [(*row, b"opaque metadata") for row in rows])
        connection.commit()
    finally:
        connection.close()

    result = AnalysisEngine().analyze(manifest, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    semantic = next(item.value for item in result.observations if item.key == "mobile.ios_manifest_semantic_paths")
    assert set(semantic) == {"messages", "safari_history", "call_history", "keychain"}
    assert semantic["messages"] == [{
        "file_id": "1" * 40, "domain": "HomeDomain", "relative_path": "Library/SMS/sms.db",
    }]
    categories = {finding.category for finding in result.findings}
    assert {
        "ios_backup_semantic_path_inventory", "ios_backup_messages_lead", "ios_backup_browser_history_lead",
        "ios_backup_call_history_lead", "ios_backup_keychain_lead",
    } <= categories


def test_registry_hive_exactly_matches_supplied_transaction_log_roots(tmp_path: Path) -> None:
    bundle = tmp_path / "registry-bundle"
    bundle.mkdir()
    hive = bytearray(4096)
    hive[:4] = b"regf"
    hive[36:40] = (0xFFFFFFFF).to_bytes(4, "little")
    (bundle / "SYSTEM").write_bytes(hive)
    (bundle / "SYSTEM.LOG1").write_bytes(b"HvLE" + b"one")
    (bundle / "SYSTEM.LOG2").write_bytes(b"HvLE" + b"two")

    result = AnalysisEngine().analyze(bundle, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    system = next(artifact for artifact in result.artifacts if artifact.logical_name == "SYSTEM")
    companions = [
        observation.value for observation in result.observations
        if observation.artifact_id == system.id and observation.key == "registry.transaction_log_companions"
    ]
    assert len(companions) == 1
    assert {item["role"] for item in companions[0]} == {"LOG1", "LOG2"}
    assert any(finding.category == "registry_transaction_log_recovery" for finding in result.findings)


def test_ooxml_embedded_part_recurses_to_encoded_flag(tmp_path: Path) -> None:
    evidence = tmp_path / "challenge.docx"
    with ZipFile(evidence, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", "<w:document/>")
        package.writestr("word/embeddings/oleObject1.bin", base64.b64encode(b"CTF{ooxml_embedded}"))

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    assert result.root_artifact.artifact_type == "office"
    assert any(artifact.logical_name == "word/embeddings/oleObject1.bin" for artifact in result.artifacts)
    assert any(candidate.value == "CTF{ooxml_embedded}" for candidate in result.flags)
    assert any(finding.category == "office_embedded_object" for finding in result.findings)


def test_unencrypted_android_backup_recurses_to_tar_flag(tmp_path: Path) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as package:
        payload = b"CTF{android_backup}"
        info = tarfile.TarInfo("apps/flag.txt")
        info.size = len(payload)
        package.addfile(info, io.BytesIO(payload))
    evidence = tmp_path / "backup.ab"
    evidence.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(archive.getvalue()))

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    assert [artifact.logical_name for artifact in result.artifacts] == ["backup.ab", "backup_payload.tar", "apps/flag.txt"]
    assert any(candidate.value == "CTF{android_backup}" for candidate in result.flags)


def test_tshark_generated_http_object_enters_recursive_engine_pipeline(tmp_path: Path) -> None:
    executable = tmp_path / "tshark"
    executable.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do case \"$arg\" in http,*) output=${arg#http,};; esac; done\n"
        "mkdir -p \"$output\"\n"
        "printf 'Q1RGe3RzaGFya19saW5lYWdlfQ==' > \"$output/object.txt\"\n"
        "printf '  http frames:1 bytes:24\\n'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    # A structurally valid, empty Ethernet PCAP is enough to select PcapProfile.
    evidence = tmp_path / "capture.pcap"
    evidence.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 12 + b"\x01\x00\x00\x00")
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "file", ("missing-file",), parser="file", command_templates={"default": ("{executable}", "{evidence}")},
        ),
        ToolDefinition(
            "tshark", (str(executable),), parser="tshark", generates_files=True,
            command_templates={"default": ("{executable}", "-r", "{evidence}", "--export-objects", "http,{output_dir}")},
        ),
        ToolDefinition(
            "capinfos", ("missing-capinfos",), parser="capinfos", command_templates={"default": ("{executable}", "{evidence}")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    assert any(artifact.logical_name == "object.txt" and artifact.created_by_tool_run_id for artifact in result.artifacts)
    assert any(candidate.value == "CTF{tshark_lineage}" for candidate in result.flags)
    assert any(finding.category == "pcap_exported_object" for finding in result.findings)


def test_pdfdetach_cwd_attachment_output_enters_recursive_engine_pipeline(tmp_path: Path) -> None:
    executable = tmp_path / "pdfdetach"
    executable.write_text(
        "#!/bin/sh\n"
        "printf 'Q1RGe3BkZmRldGFjaF9saW5lYWdlfQ==' > attachment.txt\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    evidence = tmp_path / "attachment.pdf"
    evidence.write_bytes(b"%PDF-1.4\n1 0 obj /EmbeddedFile\nendobj\n%%EOF\n")
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "pdfdetach", (str(executable),), parser="generic", generates_files=True,
            command_templates={"default": ("{executable}", "-saveall", "{evidence}")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    run = next(run for run in result.tool_runs if run.tool == "pdfdetach")
    attachment = next(artifact for artifact in result.artifacts if artifact.logical_name == "attachment.txt")
    inventory = next(
        item.value for item in result.observations if item.key == "pdf.pdfdetach.attachments"
    )
    assert run.command_argv[-2] == "-saveall"
    assert Path(run.command_argv[-1]).name.endswith("_attachment.pdf")
    assert attachment.created_by_tool_run_id == run.id
    assert inventory == [{
        "path": run.generated_files[0], "name": "attachment.txt", "size": len(b"Q1RGe3BkZmRldGFjaF9saW5lYWdlfQ=="),
    }]
    assert any(finding.category == "pdf_attachment_recovery" for finding in result.findings)
    assert any(candidate.value == "CTF{pdfdetach_lineage}" for candidate in result.flags)


def test_pdfimages_prefix_output_enters_recursive_engine_pipeline(tmp_path: Path) -> None:
    executable = tmp_path / "pdfimages"
    executable.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do prefix=$arg; done\n"
        "printf 'Q1RGe3BkZmltYWdlc19saW5lYWdlfQ==' > \"${prefix}-000.ppm\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    evidence = tmp_path / "images.pdf"
    evidence.write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Catalog >>\nendobj\n%%EOF\n")
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "pdfimages", (str(executable),), parser="generic", generates_files=True,
            command_templates={"default": ("{executable}", "-all", "{evidence}", "{output_dir}/image")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    run = next(run for run in result.tool_runs if run.tool == "pdfimages")
    image = next(artifact for artifact in result.artifacts if artifact.logical_name == "image-000.ppm")
    inventory = next(
        item.value for item in result.observations if item.key == "pdf.pdfimages.images"
    )
    assert run.command_argv[-1].endswith("/image")
    assert image.created_by_tool_run_id == run.id
    assert inventory == [{
        "path": run.generated_files[0], "name": "image-000.ppm", "size": len(b"Q1RGe3BkZmltYWdlc19saW5lYWdlfQ=="),
    }]
    assert any(finding.category == "pdf_image_recovery" for finding in result.findings)
    assert any(candidate.value == "CTF{pdfimages_lineage}" for candidate in result.flags)


def test_volatility_filescan_dumpfiles_generated_child_recurses_to_flag(tmp_path: Path) -> None:
    executable = tmp_path / "vol"
    executable.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *windows.filescan.FileScan*) printf 'Offset  Name\\n0x1234  C:\\\\Users\\\\ctf\\\\Temp\\\\payload.bin\\n' ;;\n"
        "  *windows.dumpfiles.DumpFiles*) printf 'Q1RGe3ZvbGF0aWxpdHlfZHVtcGZpbGVzfQ==' > dumped.bin ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    dump = bytearray(128)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = (7).to_bytes(4, "little") + (32).to_bytes(4, "little") + (48).to_bytes(4, "little")
    dump[48:50] = (9).to_bytes(2, "little")  # x64 SystemInfo
    dump[68:72] = (2).to_bytes(4, "little")  # VER_PLATFORM_WIN32_NT
    evidence = tmp_path / "memory.dmp"
    evidence.write_bytes(dump)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "volatility3_windows_filescan", (str(executable),), parser="volatility3",
            command_templates={"default": ("{executable}", "-f", "{evidence}", "windows.filescan.FileScan")},
        ),
        ToolDefinition(
            "volatility3_windows_dumpfiles", (str(executable),), parser="generic", generates_files=True,
            command_templates={"physaddr": ("{executable}", "-f", "{evidence}", "windows.dumpfiles.DumpFiles", "--physaddr", "{file_object_offset}")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    dump_run = next(run for run in result.tool_runs if run.tool == "volatility3_windows_dumpfiles")
    assert dump_run.command_argv[-1] == "0x1234"
    assert any(artifact.logical_name == "dumped.bin" and artifact.created_by_tool_run_id == dump_run.id for artifact in result.artifacts)
    assert any(candidate.value == "CTF{volatility_dumpfiles}" for candidate in result.flags)


def test_volatility_process_correlation_is_persisted_and_reported(tmp_path: Path) -> None:
    executable = tmp_path / "vol"
    executable.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *windows.pslist.PsList*) printf 'Offset  Name  PID  PPID\\n0x1000  hidden.exe  444  4\\n' ;;\n"
        "  *windows.cmdline.CmdLine*) printf 'PID  Process  CommandLine\\n444  hidden.exe  powershell -enc aaa\\n' ;;\n"
        "  *windows.netscan.NetScan*) printf 'Offset  Proto  LocalAddr  ForeignAddr  PID\\n0x2000  TCPv4  10.0.0.2  8.8.8.8  444\\n' ;;\n"
        "  *windows.dlllist.DllList*) printf 'PID  Process  Base  Size  Name  Path\\n444  hidden.exe  0x3000  0x1000  payload.dll  C:\\\\Users\\\\ctf\\\\Temp\\\\payload.dll\\n' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    dump = bytearray(128)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = (7).to_bytes(4, "little") + (32).to_bytes(4, "little") + (48).to_bytes(4, "little")
    dump[48:50] = (9).to_bytes(2, "little")
    dump[68:72] = (2).to_bytes(4, "little")
    evidence = tmp_path / "correlation.dmp"
    evidence.write_bytes(dump)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(name, (str(executable),), parser="volatility3", command_templates={"default": ("{executable}", "-f", "{evidence}", plugin)})
        for name, plugin in (
            ("volatility3_windows_pslist", "windows.pslist.PsList"),
            ("volatility3_windows_cmdline", "windows.cmdline.CmdLine"),
            ("volatility3_windows_netscan", "windows.netscan.NetScan"),
            ("volatility3_windows_dlllist", "windows.dlllist.DllList"),
        )
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    correlations = [item.value for item in result.observations if item.key == "memory.process_correlations"]
    assert correlations and correlations[-1][0]["pid"] == "444"
    assert any(item.category == "memory_process_correlation_lead" for item in result.findings)
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "memory.process_correlations" in report


def test_evtx_and_memory_process_evidence_requires_pid_plus_path_or_ip(tmp_path: Path) -> None:
    evtx = bytearray(4096 + 65536)
    evtx[:8] = b"ElfFile\x00"
    evtx[32:36] = (4096).to_bytes(4, "little")
    evtx[40:42] = (4096).to_bytes(2, "little")
    evtx[42:44] = (1).to_bytes(2, "little")
    chunk = 4096
    evtx[chunk:chunk + 8] = b"ElfChnk\x00"
    evtx[chunk + 40:chunk + 44] = (512).to_bytes(4, "little")
    evtx[chunk + 44:chunk + 48] = (576).to_bytes(4, "little")
    evtx[chunk + 48:chunk + 52] = (4096).to_bytes(4, "little")
    for index, record_id in enumerate((200, 201)):
        record = chunk + 512 + index * 32
        evtx[record:record + 4] = b"**\x00\x00"
        evtx[record + 4:record + 8] = (32).to_bytes(4, "little")
        evtx[record + 8:record + 16] = record_id.to_bytes(8, "little")
        evtx[record + 28:record + 32] = (32).to_bytes(4, "little")
    event_path = tmp_path / "Security.evtx"
    event_path.write_bytes(evtx)

    dump = bytearray(128)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = (7).to_bytes(4, "little") + (32).to_bytes(4, "little") + (48).to_bytes(4, "little")
    dump[48:50] = (9).to_bytes(2, "little")
    dump[68:72] = (2).to_bytes(4, "little")
    memory_path = tmp_path / "memory.dmp"
    memory_path.write_bytes(dump)

    base = r"C:\Temp"
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
    shortcut = bytearray(76 + len(link_info))
    shortcut[:4] = (0x4C).to_bytes(4, "little")
    shortcut[4:20] = bytes.fromhex("0114020000000000C000000000000046")
    shortcut[20:24] = (0x00000082).to_bytes(4, "little")
    shortcut[76:] = link_info
    shortcut_path = tmp_path / "payload.lnk"
    shortcut_path.write_bytes(shortcut)

    def prefetch(name: str) -> bytearray:
        content = bytearray(0xE0)
        content[:4] = (30).to_bytes(4, "little")
        content[4:8] = b"SCCA"
        content[12:16] = len(content).to_bytes(4, "little")
        content[16:76] = name.encode("utf-16le").ljust(60, b"\x00")
        content[76:80] = (0xA1B2C3D4).to_bytes(4, "little")
        content[0xD0:0xD4] = (3).to_bytes(4, "little")
        return content

    prefetch_path = tmp_path / "PAYLOAD-12345678.pf"
    prefetch_path.write_bytes(prefetch("PAYLOAD.EXE"))
    decoy_prefetch_path = tmp_path / "OTHER-12345678.pf"
    decoy_prefetch_path.write_bytes(prefetch("OTHER.EXE"))

    chainsaw_rows = [
        {
            "Event": {
                "System": {"EventID": 4688, "EventRecordID": 200},
                "EventData": {
                    "NewProcessId": "0x1bc",
                    "NewProcessName": r"C:\\Temp\\payload.exe",
                    "IpAddress": "192.0.2.7",
                },
            }
        },
        {
            "Event": {
                "System": {"EventID": 4688, "EventRecordID": 201},
                "EventData": {
                    "NewProcessId": "444",
                    "NewProcessName": r"C:\\Temp\\different.exe",
                    "IpAddress": "203.0.113.9",
                },
            }
        },
    ]
    chainsaw = tmp_path / "chainsaw"
    chainsaw.write_text(
        "#!/usr/bin/env python3\nimport json\n"
        f"rows = {chainsaw_rows!r}\n"
        "for row in rows: print(json.dumps(row))\n",
        encoding="utf-8",
    )
    chainsaw.chmod(0o755)
    volatility = tmp_path / "vol"
    volatility.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *windows.pslist.PsList*) printf 'Offset  Name  PID  PPID\\n0x1000  payload.exe  444  4\\n' ;;\n"
        "  *windows.cmdline.CmdLine*) printf 'PID  Process  CommandLine\\n444  payload.exe  payload.exe -flag\\n' ;;\n"
        "  *windows.netscan.NetScan*) printf 'Offset  Proto  LocalAddr  ForeignAddr  PID\\n0x2000  TCPv4  10.0.0.2:50000  192.0.2.7:443  444\\n' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    volatility.chmod(0o755)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "chainsaw", (str(chainsaw),), parser="event_json",
            command_templates={"default": ("{executable}", "dump", "{evidence}", "--json")},
        ),
        *[
            ToolDefinition(
                name, (str(volatility),), parser="volatility3",
                command_templates={"default": ("{executable}", "-f", "{evidence}", plugin)},
            )
            for name, plugin in (
                ("volatility3_windows_pslist", "windows.pslist.PsList"),
                ("volatility3_windows_cmdline", "windows.cmdline.CmdLine"),
                ("volatility3_windows_netscan", "windows.netscan.NetScan"),
            )
        ],
    ])

    result = engine.analyze_many(
        [event_path, memory_path, shortcut_path, prefetch_path, decoy_prefetch_path],
        tmp_path / "cases", mode=AnalysisMode.DEEP,
    )

    event_artifact = next(item for item in result.artifacts if item.logical_name == "Security.evtx")
    memory_artifact = next(item for item in result.artifacts if item.logical_name == "memory.dmp")
    event_links = next(
        item.value for item in result.observations
        if item.artifact_id == event_artifact.id and item.key == "correlation.evtx_memory_process"
    )
    memory_links = next(
        item.value for item in result.observations
        if item.artifact_id == memory_artifact.id and item.key == "correlation.memory_evtx_process"
    )
    assert len(event_links) == 1
    assert event_links == memory_links
    assert event_links[0]["event_record_id"] == 200
    assert event_links[0]["event_record_offset"] == chunk + 512
    assert event_links[0]["pid"] == 444
    assert event_links[0]["match_basis"] == [
        "exact_pid", "exact_process_basename", "exact_ip_endpoint",
    ]
    assert event_links[0]["matched_process_names"] == ["payload.exe"]
    assert event_links[0]["matched_ip_endpoints"] == ["192.0.2.7"]
    assert event_links[0]["event_source"].startswith("tool:chainsaw:")
    assert event_links[0]["memory_source"].startswith("profile:memory")
    assert any(item.category == "windows_memory_process_correlation" for item in result.findings)
    execution_links = next(
        item.value for item in result.observations
        if item.artifact_id == event_artifact.id and item.key == "correlation.evtx_execution_artifacts"
    )
    assert len(execution_links) == 2
    assert {item["execution_artifact_type"] for item in execution_links} == {
        "lnk_target", "prefetch_executable",
    }
    shortcut_link = next(item for item in execution_links if item["execution_artifact_type"] == "lnk_target")
    prefetch_link = next(item for item in execution_links if item["execution_artifact_type"] == "prefetch_executable")
    assert shortcut_link["match_basis"] == "exact_windows_target_path"
    assert shortcut_link["confidence"] == 0.96
    assert prefetch_link["match_basis"] == "exact_executable_basename"
    assert prefetch_link["execution_metadata"]["run_count"] == 3
    assert all(item["event_record_id"] == 200 for item in execution_links)
    assert not any(item["execution_logical_name"] == decoy_prefetch_path.name for item in execution_links)
    reciprocal_ids = {
        item.artifact_id for item in result.observations
        if item.key == "correlation.execution_artifact_evtx"
    }
    assert reciprocal_ids == {
        item["execution_artifact_id"] for item in execution_links
    }
    assert any(item.category == "windows_execution_artifact_correlation" for item in result.findings)
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "correlation.evtx_memory_process" in report
    assert "exact_process_basename" in report
    assert "correlation.evtx_execution_artifacts" in report


def test_evtx_process_path_correlates_exact_registry_execution_value(tmp_path: Path) -> None:
    for name, content in (
        ("Security.evtx", b"event"),
        ("SYSTEM", b"hive"),
        ("SYSTEM.LOG1", b"log"),
    ):
        (tmp_path / name).write_bytes(content)
    with CaseWorkspace.create(tmp_path / "cases", "registry correlation") as workspace:
        manager = EvidenceManager(workspace)
        event_artifact = manager.ingest(tmp_path / "Security.evtx")
        registry_artifact = manager.ingest(tmp_path / "SYSTEM")
        log_artifact = manager.ingest(tmp_path / "SYSTEM.LOG1")
        workspace.database.add_observations([
            Observation(
                artifact_id=event_artifact.id,
                key="windows.event_hunt.normalized_events",
                value=[{
                    "source_record_index": 0,
                    "event_id": "4688",
                    "event_record_id": 77,
                    "category": "process_creation",
                    "process_id": "0x1bc",
                    "process_path": r"C:\Temp\payload.exe",
                }],
                source="tool:chainsaw:run-1",
            ),
            Observation(
                artifact_id=event_artifact.id,
                key="evtx.normalized_record_correlations",
                value=[{"event_record_id": 77, "record_offset": 4608}],
                source="profile:windows",
            ),
            Observation(
                artifact_id=registry_artifact.id,
                key="windows.registry_signature",
                value=True,
                source="generic_triage",
            ),
            Observation(
                artifact_id=registry_artifact.id,
                key="registry.execution_value_data",
                value=[
                    {
                        "key_path": r"software\microsoft\windows\currentversion\run",
                        "name": "Updater",
                        "type": "REG_SZ",
                        "data_text": r'"C:\Temp\payload.exe" --quiet',
                    },
                    {
                        "key_path": r"software\microsoft\windows\currentversion\runonce",
                        "name": "Unresolved",
                        "type": "REG_EXPAND_SZ",
                        "data_text": r"%TEMP%\payload.exe",
                    },
                ],
                source="generic_triage",
            ),
        ])
        result = AnalysisResult(
            case=workspace.case,
            root_artifact=event_artifact,
            artifacts=[event_artifact, registry_artifact, log_artifact],
        )

        AnalysisEngine._correlate_case_roots(workspace, result)

        links = next(
            item.value for item in result.observations
            if item.artifact_id == event_artifact.id
            and item.key == "correlation.evtx_registry_execution"
        )
        assert len(links) == 1
        assert links[0]["matched_path"] == r"c:\temp\payload.exe"
        assert links[0]["event_record_offset"] == 4608
        assert links[0]["registry_key_path"].endswith(r"windows\currentversion\run")
        assert links[0]["registry_transaction_logs"] == [{
            "role": "LOG1",
            "logical_name": "SYSTEM.LOG1",
            "artifact_id": log_artifact.id,
            "sha256": log_artifact.sha256,
        }]
        assert any(
            item.artifact_id == registry_artifact.id
            and item.key == "correlation.registry_evtx_execution"
            for item in result.observations
        )
        assert any(item.category == "windows_registry_execution_correlation" for item in result.findings)
        assert AnalysisEngine._registry_command_paths(r"payload.exe --quiet") == []
        assert AnalysisEngine._registry_command_paths(r"%TEMP%\payload.exe") == []


def test_volatility_handle_and_dll_path_correlation_is_pid_scoped(tmp_path: Path) -> None:
    executable = tmp_path / "vol"
    executable.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *windows.handles.Handles*) printf 'PID  Offset  HandleValue  Type  Name\\n444  0x2000  0x88  File  C:\\\\Users\\\\ctf\\\\Temp\\\\payload.dll\\n' ;;\n"
        "  *windows.dlllist.DllList*) printf 'PID  Process  Base  Size  Name  Path\\n444  hidden.exe  0x3000  0x1000  payload.dll  C:\\\\Users\\\\ctf\\\\Temp\\\\payload.dll\\n' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    dump = bytearray(128)
    dump[:4] = b"MDMP"
    dump[8:12] = (1).to_bytes(4, "little")
    dump[12:16] = (32).to_bytes(4, "little")
    dump[32:44] = (7).to_bytes(4, "little") + (32).to_bytes(4, "little") + (48).to_bytes(4, "little")
    dump[48:50] = (9).to_bytes(2, "little")
    dump[68:72] = (2).to_bytes(4, "little")
    evidence = tmp_path / "handle-module.dmp"
    evidence.write_bytes(dump)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(name, (str(executable),), parser="volatility3", command_templates={"default": ("{executable}", "-f", "{evidence}", plugin)})
        for name, plugin in (
            ("volatility3_windows_handles", "windows.handles.Handles"),
            ("volatility3_windows_dlllist", "windows.dlllist.DllList"),
        )
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    correlations = [item.value for item in result.observations if item.key == "memory.process_correlations"]
    matched = next(item for batch in correlations for item in batch if item["pid"] == "444")
    assert matched["module_handle_path_matches"] == [{
        "path": r"c:\users\ctf\temp\payload.dll", "handle_type": "file",
        "handle_name": r"C:\Users\ctf\Temp\payload.dll", "module_name": "payload.dll",
        "module_path": r"C:\Users\ctf\Temp\payload.dll",
    }]
    assert any(item.category == "memory_module_handle_correlation_lead" for item in result.findings)


def test_evtx_record_inventory_is_persisted_and_reported(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[36:38] = (1).to_bytes(2, "little")
    data[38:40] = (3).to_bytes(2, "little")
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
    data[record + 8:record + 16] = (77).to_bytes(8, "little")
    data[record + 16:record + 24] = (132271296000000000).to_bytes(8, "little")
    data[record + 28:record + 32] = (32).to_bytes(4, "little")
    evidence = tmp_path / "events.evtx"
    evidence.write_bytes(data)

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    records = next(item.value for item in result.observations if item.key == "evtx.record_headers")
    assert records == [{"chunk_index": 0, "offset": 4608, "size": 32, "record_id": 77, "timestamp": "2020-02-25T18:40:00+00:00"}]
    assert any(item.category == "evtx_record_inventory" for item in result.findings)
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "evtx.record_headers" in report and "record_id" in report


def test_chainsaw_event_record_is_correlated_to_native_evtx_offset(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[36:38] = (1).to_bytes(2, "little")
    data[38:40] = (3).to_bytes(2, "little")
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
    data[record + 8:record + 16] = (77).to_bytes(8, "little")
    data[record + 16:record + 24] = (132271296000000000).to_bytes(8, "little")
    data[record + 28:record + 32] = (32).to_bytes(4, "little")
    evidence = tmp_path / "security.evtx"
    evidence.write_bytes(data)

    executable = tmp_path / "chainsaw"
    executable.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '{\"Event\":{\"System\":{\"EventID\":4688,\"EventRecordID\":77,\"Channel\":\"Security\"},\"EventData\":{\"NewProcessName\":\"C:\\\\\\\\Temp\\\\\\\\payload.exe\"}}}'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([ToolDefinition(
        "chainsaw", (str(executable),), parser="event_json",
        command_templates={"default": ("{executable}", "dump", "{evidence}", "--json")},
    )])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    run = next(item for item in result.tool_runs if item.tool == "chainsaw")
    normalized_observation = next(
        item for item in result.observations
        if item.key == "windows.event_hunt.normalized_events"
    )
    assert normalized_observation.source == f"tool:chainsaw:{run.id}"
    assert normalized_observation.value[0]["process_path"] == r"C:\\Temp\\payload.exe"
    correlations = next(
        item.value for item in result.observations
        if item.key == "evtx.normalized_record_correlations"
    )
    assert correlations[0]["event_record_id"] == 77
    assert correlations[0]["record_offset"] == record
    assert any(item.category == "evtx_record_content_correlation" for item in result.findings)
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "evtx.normalized_record_correlations" in report
    assert '"record_offset": 4608' in report


def test_hayabusa_timeline_record_is_correlated_to_native_evtx_offset(tmp_path: Path) -> None:
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\x00"
    data[32:36] = (4096).to_bytes(4, "little")
    data[40:42] = (4096).to_bytes(2, "little")
    data[42:44] = (1).to_bytes(2, "little")
    chunk = 4096
    data[chunk:chunk + 8] = b"ElfChnk\x00"
    data[chunk + 40:chunk + 44] = (512).to_bytes(4, "little")
    data[chunk + 44:chunk + 48] = (608).to_bytes(4, "little")
    data[chunk + 48:chunk + 52] = (4096).to_bytes(4, "little")
    for index, record_id in enumerate((91, 92, 93)):
        record = chunk + 512 + index * 32
        data[record:record + 4] = b"**\x00\x00"
        data[record + 4:record + 8] = (32).to_bytes(4, "little")
        data[record + 8:record + 16] = record_id.to_bytes(8, "little")
        data[record + 28:record + 32] = (32).to_bytes(4, "little")
    evidence = tmp_path / "system.evtx"
    evidence.write_bytes(data)

    executable = tmp_path / "hayabusa"
    executable.write_text(
        "#!/bin/sh\n"
        "printf 'EventID,EventRecordID,Timestamp,ServiceName,RuleTitle,Image\\n"
        "7045,91,2026-09-03T01:20:00Z,ctfsvc,Service Install,\\n"
        "4688,92,2026-09-03T01:21:00Z,,Process Creation,C:\\\\Temp\\\\payload.exe\\n"
        "1102,93,2026-09-03T01:22:00Z,,Log Cleared,\\n' > \"$5\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([ToolDefinition(
        "hayabusa", (str(executable),), parser="generic", generates_files=True,
        command_templates={"default": (
            "{executable}", "csv-timeline", "-f", "{evidence}", "-o",
            "{output_dir}/timeline.csv", "--no-wizard",
        )},
    )])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    normalized = next(
        item.value for item in result.observations
        if item.key == "windows.event_timeline.normalized_events"
    )
    assert normalized[0]["category"] == "service_install"
    assert normalized[0]["service_name"] == "ctfsvc"
    correlations = next(
        item.value for item in result.observations
        if item.key == "evtx.normalized_record_correlations"
    )
    assert len(correlations) == 3
    assert correlations[0]["event_record_id"] == 91
    assert correlations[0]["record_offset"] == chunk + 512
    clusters = next(
        item.value for item in result.observations
        if item.key == "windows.event_activity_clusters"
    )
    assert clusters[0]["score"] == 16
    assert clusters[0]["level"] == "high"
    assert any(item.category == "windows_event_activity" for item in result.findings)
    assert any(item.category == "windows_event_activity_cluster" for item in result.findings)
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    markdown = Path(result.case.workspace, "reports", "report.md").read_text(encoding="utf-8")
    with Path(result.case.workspace, "reports", "timeline.csv").open(
        encoding="utf-8", newline="",
    ) as stream:
        timeline_rows = list(csv.DictReader(stream))
    assert len(timeline_rows) == 3
    assert timeline_rows[0]["event_record_id"] == "91"
    assert timeline_rows[0]["record_offset"] == str(chunk + 512)
    assert timeline_rows[0]["cluster_score"] == "16"
    assert timeline_rows[0]["sources"].startswith("tool:hayabusa:")
    assert timeline_rows[0]["tool_run_ids"]
    assert timeline_rows[0]["raw_stdout_paths"].startswith("outputs/")
    assert "windows.event_timeline.normalized_events" in report
    assert "service_install" in report
    assert "windows.event_activity_clusters" in report
    assert '"timeline": [' in report
    assert "## Timeline" in markdown


def test_prefetch_declared_size_mismatch_is_persisted_and_reported(tmp_path: Path) -> None:
    data = bytearray(0xE0)
    data[:4] = (30).to_bytes(4, "little")
    data[4:8] = b"SCCA"
    data[12:16] = (0x400).to_bytes(4, "little")
    data[16:76] = "CTFTOOL.EXE".encode("utf-16le").ljust(60, b"\x00")
    data[76:80] = (0xBADC0DE).to_bytes(4, "little")
    data[0xD0:0xD4] = (3).to_bytes(4, "little")
    evidence = tmp_path / "CTFTOOL-12345678.pf"
    evidence.write_bytes(data)

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    assert any(item.key == "prefetch.size_matches_evidence" and item.value is False for item in result.observations)
    assert {"windows_prefetch", "windows_prefetch_structure_anomaly"} <= {item.category for item in result.findings}
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "prefetch.declared_file_size" in report and "windows_prefetch_structure_anomaly" in report


def test_jpeg_xmp_flag_candidate_keeps_app1_segment_provenance(tmp_path: Path) -> None:
    xmp_prefix = b"http://ns.adobe.com/xap/1.0/\x00"
    xmp = b"<x:xmpmeta><flag>CTF{jpeg_xmp}</flag></x:xmpmeta>"
    evidence = tmp_path / "metadata.jpg"
    evidence.write_bytes(
        b"\xff\xd8\xff\xe1" + (len(xmp_prefix) + len(xmp) + 2).to_bytes(2, "big") + xmp_prefix + xmp + b"\xff\xd9"
    )

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    candidate = next(item for item in result.flags if item.value == "CTF{jpeg_xmp}" and item.source == "jpeg_xmp_flag_hunter")
    assert candidate.location == "JPEG APP1 XMP offset 2; character offset 17"
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "jpeg_xmp_flag_hunter" in report and "JPEG APP1 XMP offset 2" in report


def test_jpeg_exif_metadata_and_invalid_app1_are_reported(tmp_path: Path) -> None:
    tiff = bytearray(48)
    tiff[:2] = b"II"
    tiff[2:4] = (42).to_bytes(2, "little")
    tiff[4:8] = (8).to_bytes(4, "little")
    tiff[8:10] = (1).to_bytes(2, "little")
    tiff[10:12] = (0x0112).to_bytes(2, "little")
    tiff[12:14] = (3).to_bytes(2, "little")
    tiff[14:18] = (1).to_bytes(4, "little")
    tiff[18:20] = (6).to_bytes(2, "little")
    valid_app1 = b"Exif\x00\x00" + bytes(tiff)
    invalid_app1 = b"Exif\x00\x00II\x2a\x00\xff\xff\xff\x7f"
    evidence = tmp_path / "exif.jpg"
    evidence.write_bytes(
        b"\xff\xd8"
        + b"\xff\xe1" + (len(valid_app1) + 2).to_bytes(2, "big") + valid_app1
        + b"\xff\xe1" + (len(invalid_app1) + 2).to_bytes(2, "big") + invalid_app1
        + b"\xff\xd9"
    )

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    assert any(item.category == "image_metadata_lead" and "EXIF scalar" in item.title for item in result.findings)
    assert any(item.category == "image_integrity_anomaly" and "EXIF APP1" in item.title for item in result.findings)
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "jpeg.exif_entries" in report and "JPEG EXIF APP1 metadata is structurally inconsistent" in report


def test_ntfs_mft_named_data_attribute_is_reported_without_stream_extraction(tmp_path: Path) -> None:
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

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    assert any(item.category == "ntfs_named_data_attribute" for item in result.findings)
    assert [artifact.logical_name for artifact in result.artifacts] == ["ntfs.raw"]
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "filesystem.ntfs.mft0_attributes" in report and "ntfs_named_data_attribute" in report


def test_deleted_ntfs_resident_data_becomes_recursive_child_with_provenance(tmp_path: Path) -> None:
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
    mft_data = mft + 56
    image[mft_data:mft_data + 4] = (0x80).to_bytes(4, "little")
    image[mft_data + 4:mft_data + 8] = (72).to_bytes(4, "little")
    image[mft_data + 8] = 1
    image[mft_data + 24:mft_data + 32] = (7).to_bytes(8, "little")
    image[mft_data + 32:mft_data + 34] = (64).to_bytes(2, "little")
    image[mft_data + 40:mft_data + 48] = (4096).to_bytes(8, "little")
    image[mft_data + 48:mft_data + 56] = (2048).to_bytes(8, "little")
    image[mft_data + 64:mft_data + 68] = b"\x11\x08\x01\x00"
    image[mft_data + 72:mft_data + 76] = (0xFFFFFFFF).to_bytes(4, "little")

    deleted = mft + 1024
    image[deleted:deleted + 4] = b"FILE"
    image[deleted + 4:deleted + 6] = (48).to_bytes(2, "little")
    image[deleted + 6:deleted + 8] = (3).to_bytes(2, "little")
    image[deleted + 16:deleted + 18] = (5).to_bytes(2, "little")
    image[deleted + 20:deleted + 22] = (56).to_bytes(2, "little")
    image[deleted + 28:deleted + 32] = (1024).to_bytes(4, "little")
    image[deleted + 48:deleted + 50] = b"\xcc\xdd"
    image[deleted + 50:deleted + 52] = b"\x44\x55"
    image[deleted + 52:deleted + 54] = b"\x66\x77"
    image[deleted + 510:deleted + 512] = b"\xcc\xdd"
    image[deleted + 1022:deleted + 1024] = b"\xcc\xdd"
    name = "gone.txt"
    name_value_length = 66 + len(name.encode("utf-16le"))
    name_attribute_length = ((24 + name_value_length + 7) // 8) * 8
    name_attribute = deleted + 56
    image[name_attribute:name_attribute + 4] = (0x30).to_bytes(4, "little")
    image[name_attribute + 4:name_attribute + 8] = name_attribute_length.to_bytes(4, "little")
    image[name_attribute + 16:name_attribute + 20] = name_value_length.to_bytes(4, "little")
    image[name_attribute + 20:name_attribute + 22] = (24).to_bytes(2, "little")
    name_value = name_attribute + 24
    image[name_value:name_value + 8] = (5).to_bytes(8, "little")
    image[name_value + 64] = len(name)
    image[name_value + 65] = 1
    image[name_value + 66:name_value + 66 + len(name.encode("utf-16le"))] = name.encode("utf-16le")

    payload = base64.b64encode(b"CTF{ntfs_resident_child}")
    data_attribute = name_attribute + name_attribute_length
    data_attribute_length = ((24 + len(payload) + 7) // 8) * 8
    image[data_attribute:data_attribute + 4] = (0x80).to_bytes(4, "little")
    image[data_attribute + 4:data_attribute + 8] = data_attribute_length.to_bytes(4, "little")
    image[data_attribute + 14:data_attribute + 16] = (9).to_bytes(2, "little")
    image[data_attribute + 16:data_attribute + 20] = len(payload).to_bytes(4, "little")
    image[data_attribute + 20:data_attribute + 22] = (24).to_bytes(2, "little")
    image[data_attribute + 24:data_attribute + 24 + len(payload)] = payload
    ads_payload = b"FLAG{ntfs_resident_ads}"
    ads_attribute = data_attribute + data_attribute_length
    ads_attribute_length = ((32 + len(ads_payload) + 7) // 8) * 8
    image[ads_attribute:ads_attribute + 4] = (0x80).to_bytes(4, "little")
    image[ads_attribute + 4:ads_attribute + 8] = ads_attribute_length.to_bytes(4, "little")
    image[ads_attribute + 9] = 3
    image[ads_attribute + 10:ads_attribute + 12] = (24).to_bytes(2, "little")
    image[ads_attribute + 14:ads_attribute + 16] = (10).to_bytes(2, "little")
    image[ads_attribute + 16:ads_attribute + 20] = len(ads_payload).to_bytes(4, "little")
    image[ads_attribute + 20:ads_attribute + 22] = (32).to_bytes(2, "little")
    image[ads_attribute + 24:ads_attribute + 30] = "ads".encode("utf-16le")
    image[ads_attribute + 32:ads_attribute + 32 + len(ads_payload)] = ads_payload
    nonresident_payload = b"CTF{ntfs_nonresident_child}"
    nonresident_attribute = ads_attribute + ads_attribute_length
    image[nonresident_attribute:nonresident_attribute + 4] = (0x80).to_bytes(4, "little")
    image[nonresident_attribute + 4:nonresident_attribute + 8] = (80).to_bytes(4, "little")
    image[nonresident_attribute + 8] = 1
    image[nonresident_attribute + 9] = 3
    image[nonresident_attribute + 10:nonresident_attribute + 12] = (64).to_bytes(2, "little")
    image[nonresident_attribute + 14:nonresident_attribute + 16] = (11).to_bytes(2, "little")
    image[nonresident_attribute + 24:nonresident_attribute + 32] = (0).to_bytes(8, "little")
    image[nonresident_attribute + 32:nonresident_attribute + 34] = (72).to_bytes(2, "little")
    image[nonresident_attribute + 40:nonresident_attribute + 48] = (512).to_bytes(8, "little")
    image[nonresident_attribute + 48:nonresident_attribute + 56] = len(nonresident_payload).to_bytes(8, "little")
    image[nonresident_attribute + 56:nonresident_attribute + 64] = len(nonresident_payload).to_bytes(8, "little")
    image[nonresident_attribute + 64:nonresident_attribute + 70] = "raw".encode("utf-16le")
    image[nonresident_attribute + 72:nonresident_attribute + 76] = b"\x11\x01\x07\x00"
    compressed_attribute = nonresident_attribute + 80
    image[compressed_attribute:compressed_attribute + 4] = (0x80).to_bytes(4, "little")
    image[compressed_attribute + 4:compressed_attribute + 8] = (80).to_bytes(4, "little")
    image[compressed_attribute + 8] = 1
    image[compressed_attribute + 9] = 3
    image[compressed_attribute + 10:compressed_attribute + 12] = (64).to_bytes(2, "little")
    image[compressed_attribute + 12:compressed_attribute + 14] = (1).to_bytes(2, "little")
    image[compressed_attribute + 14:compressed_attribute + 16] = (12).to_bytes(2, "little")
    image[compressed_attribute + 32:compressed_attribute + 34] = (72).to_bytes(2, "little")
    image[compressed_attribute + 40:compressed_attribute + 48] = (512).to_bytes(8, "little")
    image[compressed_attribute + 48:compressed_attribute + 56] = len(nonresident_payload).to_bytes(8, "little")
    image[compressed_attribute + 56:compressed_attribute + 64] = len(nonresident_payload).to_bytes(8, "little")
    image[compressed_attribute + 64:compressed_attribute + 70] = "bad".encode("utf-16le")
    image[compressed_attribute + 72:compressed_attribute + 76] = b"\x11\x01\x07\x00"
    terminator = compressed_attribute + 80
    image[terminator:terminator + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    image[deleted + 24:deleted + 28] = (terminator + 4 - deleted).to_bytes(4, "little")
    image[7 * 512:7 * 512 + len(nonresident_payload)] = nonresident_payload
    evidence = tmp_path / "ntfs-resident.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )

    recovered = next(item for item in result.artifacts if item.logical_name == "gone.txt")
    recovered_ads = next(item for item in result.artifacts if item.logical_name == "gone.txt:ads")
    recovered_nonresident = next(item for item in result.artifacts if item.logical_name == "gone.txt:raw")
    assert recovered.parent_id == result.root_artifact.id
    assert recovered.depth == 1
    assert recovered_ads.parent_id == result.root_artifact.id
    assert recovered_nonresident.parent_id == result.root_artifact.id
    sample = next(
        item.value for item in result.observations
        if item.key == "filesystem.ntfs.mft_sample_records"
    )[0]
    assert sample["deleted"] is True
    assert sample["resident_data_attributes"][0]["attribute_id"] == 9
    assert sample["resident_data_attributes"][0]["data_hex"] == payload.hex()
    assert sample["resident_data_attributes"][1]["stream_name"] == "ads"
    assert sample["resident_data_attributes"][1]["data_hex"] == ads_payload.hex()
    assert sample["nonresident_data_attributes"][0] == {
        "attribute_offset": nonresident_attribute - deleted,
        "attribute_id": 11,
        "stream_name": "raw",
        "attribute_flags": 0,
        "lowest_vcn": 0,
        "highest_vcn": 0,
        "allocated_size": 512,
        "real_size": len(nonresident_payload),
        "initialized_size": len(nonresident_payload),
        "data_runs": [{"vcn": 0, "cluster_count": 1, "lcn": 7}],
    }
    assert sample["nonresident_data_attributes"][1]["stream_name"] == "bad"
    assert sample["nonresident_data_attributes"][1]["attribute_flags"] == 1
    assert not any(item.logical_name == "gone.txt:bad" for item in result.artifacts)
    finding = next(item for item in result.findings if item.category == "ntfs_resident_data_recovery")
    assert recovered.id in finding.supporting_evidence[0]
    assert "record:1" in finding.supporting_evidence[0]
    assert "deleted:True" in finding.supporting_evidence[0]
    assert any(recovered_ads.id in item and "stream:ads" in item for item in finding.supporting_evidence)
    nonresident_finding = next(
        item for item in result.findings if item.category == "ntfs_nonresident_data_recovery"
    )
    assert any(
        recovered_nonresident.id in item and "lcn': 7" in item
        for item in nonresident_finding.supporting_evidence
    )
    assert any(
        candidate.artifact_id == recovered.id and candidate.value == "CTF{ntfs_resident_child}"
        for candidate in result.flags
    )
    assert any(
        candidate.artifact_id == recovered_ads.id and candidate.value == "FLAG{ntfs_resident_ads}"
        for candidate in result.flags
    )
    assert any(
        candidate.artifact_id == recovered_nonresident.id
        and candidate.value == "CTF{ntfs_nonresident_child}"
        for candidate in result.flags
    )
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "builtin_ntfs_resident_extractor" in report
    assert "builtin_ntfs_nonresident_extractor" in report
    assert "CTF{ntfs_resident_child}" in report


def test_ntfs_record_after_old_32_record_boundary_is_sampled_and_recovered(tmp_path: Path) -> None:
    image = bytearray(43 * 1024)
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
    mft_data = mft + 56
    image[mft_data:mft_data + 4] = (0x80).to_bytes(4, "little")
    image[mft_data + 4:mft_data + 8] = (72).to_bytes(4, "little")
    image[mft_data + 8] = 1
    image[mft_data + 24:mft_data + 32] = (99).to_bytes(8, "little")
    image[mft_data + 32:mft_data + 34] = (64).to_bytes(2, "little")
    image[mft_data + 40:mft_data + 48] = (100 * 512).to_bytes(8, "little")
    image[mft_data + 48:mft_data + 56] = (41 * 1024).to_bytes(8, "little")
    image[mft_data + 56:mft_data + 64] = (41 * 1024).to_bytes(8, "little")
    image[mft_data + 64:mft_data + 68] = b"\x11\x64\x01\x00"
    image[mft_data + 72:mft_data + 76] = (0xFFFFFFFF).to_bytes(4, "little")

    late = mft + 40 * 1024
    image[late:late + 4] = b"FILE"
    image[late + 4:late + 6] = (48).to_bytes(2, "little")
    image[late + 6:late + 8] = (3).to_bytes(2, "little")
    image[late + 16:late + 18] = (9).to_bytes(2, "little")
    image[late + 20:late + 22] = (56).to_bytes(2, "little")
    image[late + 22:late + 24] = (1).to_bytes(2, "little")
    image[late + 28:late + 32] = (1024).to_bytes(4, "little")
    image[late + 48:late + 50] = b"\xee\xff"
    image[late + 50:late + 52] = b"\x12\x34"
    image[late + 52:late + 54] = b"\x56\x78"
    image[late + 510:late + 512] = b"\xee\xff"
    image[late + 1022:late + 1024] = b"\xee\xff"
    name = "late.txt"
    name_bytes = name.encode("utf-16le")
    name_value_length = 66 + len(name_bytes)
    name_attribute_length = ((24 + name_value_length + 7) // 8) * 8
    name_attribute = late + 56
    image[name_attribute:name_attribute + 4] = (0x30).to_bytes(4, "little")
    image[name_attribute + 4:name_attribute + 8] = name_attribute_length.to_bytes(4, "little")
    image[name_attribute + 16:name_attribute + 20] = name_value_length.to_bytes(4, "little")
    image[name_attribute + 20:name_attribute + 22] = (24).to_bytes(2, "little")
    name_value = name_attribute + 24
    image[name_value:name_value + 8] = (5).to_bytes(8, "little")
    image[name_value + 64] = len(name)
    image[name_value + 65] = 1
    image[name_value + 66:name_value + 66 + len(name_bytes)] = name_bytes
    payload = base64.b64encode(b"CTF{ntfs_late_sample}")
    data_attribute = name_attribute + name_attribute_length
    data_attribute_length = ((24 + len(payload) + 7) // 8) * 8
    image[data_attribute:data_attribute + 4] = (0x80).to_bytes(4, "little")
    image[data_attribute + 4:data_attribute + 8] = data_attribute_length.to_bytes(4, "little")
    image[data_attribute + 14:data_attribute + 16] = (4).to_bytes(2, "little")
    image[data_attribute + 16:data_attribute + 20] = len(payload).to_bytes(4, "little")
    image[data_attribute + 20:data_attribute + 22] = (24).to_bytes(2, "little")
    image[data_attribute + 24:data_attribute + 24 + len(payload)] = payload
    terminator = data_attribute + data_attribute_length
    image[terminator:terminator + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    image[late + 24:late + 28] = (terminator + 4 - late).to_bytes(4, "little")
    evidence = tmp_path / "ntfs-late-record.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )

    sample_limit = next(
        item.value for item in result.observations
        if item.key == "filesystem.ntfs.mft_sample_limit"
    )
    records = next(
        item.value for item in result.observations
        if item.key == "filesystem.ntfs.mft_sample_records"
    )
    assert sample_limit == 256
    assert len(records) == 40
    assert records[-1]["record_number"] == 40
    assert records[-1]["file_names"] == ["late.txt"]
    recovered = next(item for item in result.artifacts if item.logical_name == "late.txt")
    assert recovered.parent_id == result.root_artifact.id
    assert any(
        candidate.artifact_id == recovered.id and candidate.value == "CTF{ntfs_late_sample}"
        for candidate in result.flags
    )


def test_deleted_fat32_single_and_complete_multi_cluster_files_become_recursive_children(tmp_path: Path) -> None:
    image = bytearray(5120)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (8).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    image[512 + 2 * 4:512 + 2 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[512 + 6 * 4:512 + 6 * 4 + 4] = (8).to_bytes(4, "little")
    image[512 + 8 * 4:512 + 8 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[512 + 3 * 4:512 + 3 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[512 + 7 * 4:512 + 7 * 4 + 4] = (9).to_bytes(4, "little")
    image[512 + 9 * 4:512 + 9 * 4 + 4] = (10).to_bytes(4, "little")
    root_entry = 1024
    image[root_entry:root_entry + 11] = b"\xe5LAG    TXT"
    image[root_entry + 11] = 0x20
    image[root_entry + 26:root_entry + 28] = (5).to_bytes(2, "little")
    payload = base64.b64encode(b"CTF{fat32_deleted_child}")
    image[root_entry + 28:root_entry + 32] = len(payload).to_bytes(4, "little")
    oversized_entry = root_entry + 32
    image[oversized_entry:oversized_entry + 11] = b"\xe5ARGE   BIN"
    image[oversized_entry + 11] = 0x20
    image[oversized_entry + 26:oversized_entry + 28] = (7).to_bytes(2, "little")
    image[oversized_entry + 28:oversized_entry + 32] = (513).to_bytes(4, "little")
    multi_entry = root_entry + 64
    image[multi_entry:multi_entry + 11] = b"\xe5ULTI   BIN"
    image[multi_entry + 11] = 0x20
    image[multi_entry + 26:multi_entry + 28] = (6).to_bytes(2, "little")
    multi_payload = b"M" * 512 + base64.b64encode(b"CTF{fat32_multicluster_child}")
    image[multi_entry + 28:multi_entry + 32] = len(multi_payload).to_bytes(4, "little")
    active_directory = root_entry + 96
    image[active_directory:active_directory + 11] = b"ACTIVE     "
    image[active_directory + 11] = 0x10
    image[active_directory + 26:active_directory + 28] = (3).to_bytes(2, "little")
    reserved_high_entry = root_entry + 128
    image[reserved_high_entry:reserved_high_entry + 11] = b"\xe5ESERV  BIN"
    image[reserved_high_entry + 11] = 0x20
    image[reserved_high_entry + 20:reserved_high_entry + 22] = (0x1000).to_bytes(2, "little")
    image[reserved_high_entry + 26:reserved_high_entry + 28] = (5).to_bytes(2, "little")
    image[reserved_high_entry + 28:reserved_high_entry + 32] = len(payload).to_bytes(4, "little")
    sub_entry = 1536
    image[sub_entry:sub_entry + 11] = b"\xe5UBFLAG TXT"
    image[sub_entry + 11] = 0x20
    image[sub_entry + 26:sub_entry + 28] = (4).to_bytes(2, "little")
    sub_payload = base64.b64encode(b"CTF{fat32_subdirectory_child}")
    image[sub_entry + 28:sub_entry + 32] = len(sub_payload).to_bytes(4, "little")
    content_offset = 2560
    image[content_offset:content_offset + len(payload)] = payload
    image[3072:3584] = multi_payload[:512]
    image[4096:4096 + len(multi_payload[512:])] = multi_payload[512:]
    image[2048:2048 + len(sub_payload)] = sub_payload
    evidence = tmp_path / "fat32-deleted.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )

    recovered = next(item for item in result.artifacts if item.logical_name == "?LAG.TXT")
    recovered_multi = next(item for item in result.artifacts if item.logical_name == "?ULTI.BIN")
    recovered_sub = next(item for item in result.artifacts if item.logical_name == "?UBFLAG.TXT")
    assert recovered.parent_id == result.root_artifact.id
    assert recovered.depth == 1
    assert recovered.size == len(payload)
    assert not any(item.logical_name == "?ARGE.BIN" for item in result.artifacts)
    assert not any(item.logical_name == "?ESERV.BIN" for item in result.artifacts)
    assert recovered_multi.size == len(multi_payload)
    assert recovered_multi.parent_id == result.root_artifact.id
    assert recovered_sub.parent_id == result.root_artifact.id
    root_observations = {
        item.key: item.value for item in result.observations
        if item.artifact_id == result.root_artifact.id
    }
    malformed = next(
        item for item in root_observations["filesystem.fat.deleted_short_entries"]
        if item["offset"] == reserved_high_entry
    )
    assert malformed["first_cluster"] == 5
    assert malformed["cluster_field_raw"] == "0x10000005"
    assert malformed["fat32_cluster_high_reserved"] == 1
    assert any(
        item.category == "fat32_directory_cluster_field_anomaly"
        and "0x10000005" in item.supporting_evidence[0]
        for item in result.findings
    )
    finding = next(item for item in result.findings if item.category == "fat_deleted_content_recovery")
    assert recovered.id in finding.supporting_evidence[0]
    assert "entry_offset:1024" in finding.supporting_evidence[0]
    assert "physical_offset:2560" in finding.supporting_evidence[0]
    assert "allocation_state:unknown_deleted_cluster_may_be_reused" in finding.supporting_evidence[0]
    multi_evidence = next(item for item in finding.supporting_evidence if recovered_multi.id in item)
    assert "'cluster': 6" in multi_evidence and "'cluster': 8" in multi_evidence
    assert "chain_validation:complete_fat_chain_eoc" in multi_evidence
    sub_evidence = next(item for item in finding.supporting_evidence if recovered_sub.id in item)
    assert "entry_offset:1536" in sub_evidence
    assert "directory_start_cluster:3" in sub_evidence
    assert "directory_cluster_lineage:[3]" in sub_evidence
    assert "directory_source_entry_offset:1120" in sub_evidence
    assert any(
        candidate.artifact_id == recovered.id and candidate.value == "CTF{fat32_deleted_child}"
        for candidate in result.flags
    )
    assert any(
        candidate.artifact_id == recovered_multi.id
        and candidate.value == "CTF{fat32_multicluster_child}"
        for candidate in result.flags
    )
    assert any(
        candidate.artifact_id == recovered_sub.id
        and candidate.value == "CTF{fat32_subdirectory_child}"
        for candidate in result.flags
    )
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "builtin_fat32_deleted_extractor" in report
    assert "CTF{fat32_deleted_child}" in report


def test_fat16_fixed_root_deleted_lfn_recovers_one_cluster_with_lineage(tmp_path: Path) -> None:
    sector_size = 512
    image = bytearray(27 * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[17:19] = (16).to_bytes(2, "little")
    image[19:21] = (4103).to_bytes(2, "little")
    image[21] = 0xF8
    image[22:24] = (16).to_bytes(2, "little")
    image[54:62] = b"FAT16   "
    image[510:512] = b"\x55\xaa"
    root_offset = 17 * sector_size
    first_data_sector = 18

    short_name = b"VERYL~1 TXT"
    checksum = GenericTriageEngine._fat_short_name_checksum(short_name)
    long_name = "Very Long Flag.txt"
    encoded_name = long_name.encode("utf-16le")
    units = [
        int.from_bytes(encoded_name[offset:offset + 2], "little")
        for offset in range(0, len(encoded_name), 2)
    ]
    units.extend([0, *([0xFFFF] * (26 - len(units) - 1))])
    for physical_index, chunk_index in enumerate((1, 0)):
        slot = bytearray(32)
        slot[0] = 0xE5
        slot[11] = 0x0F
        slot[13] = checksum
        encoded = b"".join(
            value.to_bytes(2, "little")
            for value in units[chunk_index * 13:(chunk_index + 1) * 13]
        )
        slot[1:11] = encoded[:10]
        slot[14:26] = encoded[10:22]
        slot[28:32] = encoded[22:26]
        image[root_offset + physical_index * 32:root_offset + (physical_index + 1) * 32] = slot
    short_offset = root_offset + 64
    image[short_offset:short_offset + 11] = b"\xe5ERYL~1 TXT"
    image[short_offset + 11] = 0x20
    image[short_offset + 26:short_offset + 28] = (5).to_bytes(2, "little")
    payload = b"CTF{fat16_fixed_root}"
    image[short_offset + 28:short_offset + 32] = len(payload).to_bytes(4, "little")
    invalid_high = short_offset + 32
    image[invalid_high:invalid_high + 11] = b"\xe5LIAS   BIN"
    image[invalid_high + 11] = 0x20
    image[invalid_high + 20:invalid_high + 22] = (1).to_bytes(2, "little")
    image[invalid_high + 26:invalid_high + 28] = (7).to_bytes(2, "little")
    image[invalid_high + 28:invalid_high + 32] = (8).to_bytes(4, "little")
    multi_offset = invalid_high + 32
    image[multi_offset:multi_offset + 11] = b"\xe5ULTI   BIN"
    image[multi_offset + 11] = 0x20
    image[multi_offset + 26:multi_offset + 28] = (6).to_bytes(2, "little")
    multi_payload = b"M" * sector_size + b"CTF{fat16_multicluster}"
    image[multi_offset + 28:multi_offset + 32] = len(multi_payload).to_bytes(4, "little")
    image[sector_size + 6 * 2:sector_size + 6 * 2 + 2] = (8).to_bytes(2, "little")
    image[sector_size + 8 * 2:sector_size + 8 * 2 + 2] = (0xFFFF).to_bytes(2, "little")
    active_directory_offset = multi_offset + 32
    image[active_directory_offset:active_directory_offset + 11] = b"ACTIVE     "
    image[active_directory_offset + 11] = 0x10
    image[active_directory_offset + 26:active_directory_offset + 28] = (9).to_bytes(2, "little")
    image[sector_size + 9 * 2:sector_size + 9 * 2 + 2] = (0xFFFF).to_bytes(2, "little")
    content_offset = (first_data_sector + 3) * sector_size
    image[content_offset:content_offset + len(payload)] = payload
    multi_first_offset = (first_data_sector + 4) * sector_size
    multi_second_offset = (first_data_sector + 6) * sector_size
    image[multi_first_offset:multi_first_offset + sector_size] = multi_payload[:sector_size]
    image[multi_second_offset:multi_second_offset + len(multi_payload) - sector_size] = multi_payload[sector_size:]
    subdirectory_offset = (first_data_sector + 7) * sector_size
    sub_entry = subdirectory_offset
    image[sub_entry:sub_entry + 11] = b"\xe5UBFLAG TXT"
    image[sub_entry + 11] = 0x20
    image[sub_entry + 26:sub_entry + 28] = (10).to_bytes(2, "little")
    sub_payload = b"CTF{fat16_subdirectory}"
    image[sub_entry + 28:sub_entry + 32] = len(sub_payload).to_bytes(4, "little")
    sub_content_offset = (first_data_sector + 8) * sector_size
    image[sub_content_offset:sub_content_offset + len(sub_payload)] = sub_payload
    evidence = tmp_path / "fat16-deleted.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat16-cases", mode=AnalysisMode.AUTO, execute=False,
    )

    values = {
        observation.key: observation.value
        for observation in result.observations
        if observation.artifact_id == result.root_artifact.id
    }
    assert values["filesystem.fat.variant"] == "fat16"
    assert values["filesystem.fat16.root.available"] is True
    assert values["filesystem.fat16.root.offset"] == root_offset
    assert values["filesystem.fat16.root.first_data_sector"] == first_data_sector
    assert values["filesystem.fat16.root.fat_entry_capacity"] == 4096
    deleted = values["filesystem.fat16.root.deleted_entries"]
    assert deleted[0]["long_name"] == long_name
    assert deleted[0]["lfn_slot_offsets"] == [root_offset, root_offset + 32]
    assert deleted[0]["first_cluster"] == 5
    assert deleted[0]["fat16_cluster_high_reserved"] == 0
    assert deleted[1]["fat16_cluster_high_reserved"] == 1
    sub_deleted = values["filesystem.fat16.root.subdirectory_deleted_entries"]
    assert sub_deleted[0]["directory_start_cluster"] == 9
    assert sub_deleted[0]["directory_cluster_lineage"] == [9]
    assert sub_deleted[0]["directory_source_entry_offset"] == active_directory_offset
    assert sub_deleted[0]["offset"] == subdirectory_offset
    child = next(item for item in result.artifacts if item.logical_name == long_name)
    multi_child = next(item for item in result.artifacts if item.logical_name == "?ULTI.BIN")
    sub_child = next(item for item in result.artifacts if item.logical_name == "?UBFLAG.TXT")
    assert not any(item.logical_name == "?LIAS.BIN" for item in result.artifacts)
    assert any(
        item.value == "CTF{fat16_fixed_root}" and item.artifact_id == child.id
        for item in result.flags
    )
    assert any(
        item.value == "CTF{fat16_subdirectory}" and item.artifact_id == sub_child.id
        for item in result.flags
    )
    assert any(
        item.value == "CTF{fat16_multicluster}" and item.artifact_id == multi_child.id
        for item in result.flags
    )
    assert any(item.category == "fat16_deleted_directory_entry" for item in result.findings)
    assert any(item.category == "fat16_deleted_lfn_entry" for item in result.findings)
    assert any(item.category == "fat16_subdirectory_deleted_entry" for item in result.findings)
    recovery = next(item for item in result.findings if item.category == "fat16_deleted_content_recovery")
    assert "builtin_fat16_deleted_extractor" in recovery.source
    assert f"entry_offset:{short_offset}" in recovery.supporting_evidence[0]
    assert f"physical_offset:{content_offset}" in recovery.supporting_evidence[0]
    assert "chain_validation:single_cluster_direct" in recovery.supporting_evidence[0]
    multi_evidence = next(item for item in recovery.supporting_evidence if multi_child.id in item)
    assert f"physical_offset:{multi_first_offset}" in multi_evidence
    assert f"'physical_offset': {multi_second_offset}" in multi_evidence
    assert "chain_validation:complete_fat16_chain_eoc" in multi_evidence
    sub_evidence = next(item for item in recovery.supporting_evidence if sub_child.id in item)
    assert f"entry_offset:{subdirectory_offset}" in sub_evidence
    assert "directory_start_cluster:9" in sub_evidence
    assert "directory_cluster_lineage:[9]" in sub_evidence
    assert f"directory_source_entry_offset:{active_directory_offset}" in sub_evidence

    fat12_sized = bytearray(image)
    fat12_sized[19:21] = (100).to_bytes(2, "little")
    invalid = tmp_path / "fat16-label-fat12-geometry.raw"
    invalid.write_bytes(fat12_sized)
    invalid_artifact = Artifact(
        id="fat16-invalid", case_id="case", path=str(invalid), logical_name=invalid.name,
        sha256="0" * 64, size=len(fat12_sized),
    )
    invalid_values = {
        item.key: item.value for item in GenericTriageEngine().analyze(invalid_artifact, invalid)
    }
    assert invalid_values["filesystem.fat16.root.available"] is False
    assert invalid_values["filesystem.fat16.root.error"] == "invalid FAT16 fixed-root geometry"

    non_eoc = bytearray(image)
    non_eoc[sector_size + 8 * 2:sector_size + 8 * 2 + 2] = (9).to_bytes(2, "little")
    incomplete = tmp_path / "fat16-non-eoc-chain.raw"
    incomplete.write_bytes(non_eoc)
    incomplete_result = AnalysisEngine().analyze(
        incomplete, tmp_path / "fat16-incomplete-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert any(item.logical_name == long_name for item in incomplete_result.artifacts)
    assert not any(item.logical_name == "?ULTI.BIN" for item in incomplete_result.artifacts)

    looping_directory = bytearray(image)
    looping_directory[sector_size + 9 * 2:sector_size + 9 * 2 + 2] = (9).to_bytes(2, "little")
    invalid_directory = tmp_path / "fat16-looping-directory.raw"
    invalid_directory.write_bytes(looping_directory)
    invalid_directory_result = AnalysisEngine().analyze(
        invalid_directory, tmp_path / "fat16-directory-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert not any(item.logical_name == "?UBFLAG.TXT" for item in invalid_directory_result.artifacts)
    assert any(
        item.category == "fat16_subdirectory_chain_anomaly"
        for item in invalid_directory_result.findings
    )


def test_fat12_fixed_root_recovers_single_and_exact_packed_multicluster_chain(tmp_path: Path) -> None:
    sector_size = 512
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
    root_offset = 2 * sector_size
    first_data_sector = 3
    entry = root_offset
    image[entry:entry + 11] = b"\xe5LAG    TXT"
    image[entry + 11] = 0x20
    image[entry + 26:entry + 28] = (5).to_bytes(2, "little")
    payload = b"CTF{fat12_single_cluster}"
    image[entry + 28:entry + 32] = len(payload).to_bytes(4, "little")
    multi = entry + 32
    image[multi:multi + 11] = b"\xe5ULTI   BIN"
    image[multi + 11] = 0x20
    image[multi + 26:multi + 28] = (6).to_bytes(2, "little")
    multi_payload = b"M" * sector_size + b"CTF{fat12_packed_chain}"
    image[multi + 28:multi + 32] = len(multi_payload).to_bytes(4, "little")

    def set_fat12(cluster: int, value: int) -> None:
        offset = sector_size + cluster + cluster // 2
        packed = int.from_bytes(image[offset:offset + 2], "little")
        if cluster & 1:
            packed = (packed & 0x000F) | ((value & 0x0FFF) << 4)
        else:
            packed = (packed & 0xF000) | (value & 0x0FFF)
        image[offset:offset + 2] = packed.to_bytes(2, "little")

    set_fat12(6, 8)
    set_fat12(8, 0xFFF)
    active_directory_offset = multi + 32
    image[active_directory_offset:active_directory_offset + 11] = b"ACTIVE     "
    image[active_directory_offset + 11] = 0x10
    image[active_directory_offset + 26:active_directory_offset + 28] = (7).to_bytes(2, "little")
    set_fat12(7, 0xFFF)
    content_offset = (first_data_sector + 3) * sector_size
    image[content_offset:content_offset + len(payload)] = payload
    multi_first_offset = (first_data_sector + 4) * sector_size
    multi_second_offset = (first_data_sector + 6) * sector_size
    image[multi_first_offset:multi_first_offset + sector_size] = multi_payload[:sector_size]
    image[multi_second_offset:multi_second_offset + len(multi_payload) - sector_size] = multi_payload[sector_size:]
    subdirectory_offset = (first_data_sector + 5) * sector_size
    image[subdirectory_offset:subdirectory_offset + 11] = b"\xe5UBFLAG TXT"
    image[subdirectory_offset + 11] = 0x20
    image[subdirectory_offset + 26:subdirectory_offset + 28] = (4).to_bytes(2, "little")
    sub_payload = b"CTF{fat12_subdirectory}"
    image[subdirectory_offset + 28:subdirectory_offset + 32] = len(sub_payload).to_bytes(4, "little")
    sub_content_offset = (first_data_sector + 2) * sector_size
    image[sub_content_offset:sub_content_offset + len(sub_payload)] = sub_payload
    evidence = tmp_path / "fat12-deleted.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat12-cases", mode=AnalysisMode.AUTO, execute=False,
    )

    values = {
        observation.key: observation.value
        for observation in result.observations
        if observation.artifact_id == result.root_artifact.id
    }
    assert values["filesystem.fat.variant"] == "fat12"
    assert values["filesystem.fat12.root.available"] is True
    assert values["filesystem.fat12.root.offset"] == root_offset
    assert values["filesystem.fat12.root.first_data_sector"] == first_data_sector
    assert values["filesystem.fat12.root.cluster_count"] == 97
    assert values["filesystem.fat12.root.fat_entry_capacity"] == 341
    assert values["filesystem.fat12.root.deleted_entries"][0]["fat12_cluster_high_reserved"] == 0
    sub_deleted = values["filesystem.fat12.root.subdirectory_deleted_entries"]
    assert sub_deleted[0]["directory_start_cluster"] == 7
    assert sub_deleted[0]["directory_cluster_lineage"] == [7]
    assert sub_deleted[0]["directory_source_entry_offset"] == active_directory_offset
    assert sub_deleted[0]["offset"] == subdirectory_offset
    child = next(item for item in result.artifacts if item.logical_name == "?LAG.TXT")
    multi_child = next(item for item in result.artifacts if item.logical_name == "?ULTI.BIN")
    sub_child = next(item for item in result.artifacts if item.logical_name == "?UBFLAG.TXT")
    assert any(
        item.value == "CTF{fat12_single_cluster}" and item.artifact_id == child.id
        for item in result.flags
    )
    assert any(
        item.value == "CTF{fat12_packed_chain}" and item.artifact_id == multi_child.id
        for item in result.flags
    )
    assert any(
        item.value == "CTF{fat12_subdirectory}" and item.artifact_id == sub_child.id
        for item in result.flags
    )
    assert any(item.category == "fat12_deleted_directory_entry" for item in result.findings)
    assert any(item.category == "fat12_subdirectory_deleted_entry" for item in result.findings)
    recovery = next(item for item in result.findings if item.category == "fat12_deleted_content_recovery")
    assert f"entry_offset:{root_offset}" in recovery.supporting_evidence[0]
    assert f"physical_offset:{content_offset}" in recovery.supporting_evidence[0]
    assert "chain_validation:single_cluster_direct" in recovery.supporting_evidence[0]
    multi_evidence = next(item for item in recovery.supporting_evidence if multi_child.id in item)
    assert f"physical_offset:{multi_first_offset}" in multi_evidence
    assert f"'physical_offset': {multi_second_offset}" in multi_evidence
    assert "'fat_entry_offset': 521" in multi_evidence
    assert "'fat_entry_raw': '08f0'" in multi_evidence
    assert "'fat_entry_offset': 524" in multi_evidence
    assert "chain_validation:complete_fat12_chain_eoc" in multi_evidence
    sub_evidence = next(item for item in recovery.supporting_evidence if sub_child.id in item)
    assert f"entry_offset:{subdirectory_offset}" in sub_evidence
    assert "directory_start_cluster:7" in sub_evidence
    assert "directory_cluster_lineage:[7]" in sub_evidence
    assert f"directory_source_entry_offset:{active_directory_offset}" in sub_evidence

    fat16_sized = bytearray(image)
    fat16_sized[19:21] = (5000).to_bytes(2, "little")
    invalid = tmp_path / "fat12-label-fat16-geometry.raw"
    invalid.write_bytes(fat16_sized)
    invalid_artifact = Artifact(
        id="fat12-invalid", case_id="case", path=str(invalid), logical_name=invalid.name,
        sha256="0" * 64, size=len(fat16_sized),
    )
    invalid_values = {
        item.key: item.value for item in GenericTriageEngine().analyze(invalid_artifact, invalid)
    }
    assert invalid_values["filesystem.fat12.root.available"] is False
    assert invalid_values["filesystem.fat12.root.error"] == "invalid FAT12 fixed-root geometry"

    non_eoc = bytearray(image)
    packed_offset = sector_size + 8 + 8 // 2
    packed = int.from_bytes(non_eoc[packed_offset:packed_offset + 2], "little")
    non_eoc[packed_offset:packed_offset + 2] = ((packed & 0xF000) | 9).to_bytes(2, "little")
    incomplete = tmp_path / "fat12-non-eoc.raw"
    incomplete.write_bytes(non_eoc)
    incomplete_result = AnalysisEngine().analyze(
        incomplete, tmp_path / "fat12-incomplete-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert any(item.logical_name == "?LAG.TXT" for item in incomplete_result.artifacts)
    assert not any(item.logical_name == "?ULTI.BIN" for item in incomplete_result.artifacts)

    looping_directory = bytearray(image)
    directory_fat_offset = sector_size + 7 + 7 // 2
    packed = int.from_bytes(looping_directory[directory_fat_offset:directory_fat_offset + 2], "little")
    looping_directory[directory_fat_offset:directory_fat_offset + 2] = (
        (packed & 0x000F) | (7 << 4)
    ).to_bytes(2, "little")
    invalid_directory = tmp_path / "fat12-looping-directory.raw"
    invalid_directory.write_bytes(looping_directory)
    invalid_directory_result = AnalysisEngine().analyze(
        invalid_directory, tmp_path / "fat12-directory-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert not any(item.logical_name == "?UBFLAG.TXT" for item in invalid_directory_result.artifacts)
    assert any(
        item.category == "fat12_subdirectory_chain_anomaly"
        for item in invalid_directory_result.findings
    )


def test_fat12_complete_lost_chain_becomes_anonymous_recursive_flag_artifact(tmp_path: Path) -> None:
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
    lost_payload = b"L" * sector_size + b"CTF{fat12_lost_chain_recursive}"
    first_lost_offset = (first_data_sector + 5) * sector_size
    second_lost_offset = (first_data_sector + 6) * sector_size
    image[first_lost_offset:first_lost_offset + sector_size] = lost_payload[:sector_size]
    image[second_lost_offset:second_lost_offset + len(lost_payload) - sector_size] = lost_payload[sector_size:]
    evidence = tmp_path / "fat12-lost-chain.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat12-lost-cases", mode=AnalysisMode.AUTO, execute=False,
    )

    child = next(
        item for item in result.artifacts
        if item.logical_name == "FAT12_LOST_CHAIN_00000007.bin"
    )
    assert child.parent_id == result.root_artifact.id
    assert child.depth == 1
    assert child.size == 2 * sector_size
    assert any(
        item.value == "CTF{fat12_lost_chain_recursive}" and item.artifact_id == child.id
        for item in result.flags
    )
    finding = next(
        item for item in result.findings if item.category == "fat12_lost_chain_recovery"
    )
    assert finding.source == "builtin_fat12_lost_chain_extractor"
    assert f"child:{child.id}" in finding.supporting_evidence[0]
    assert "start_cluster:7" in finding.supporting_evidence[0]
    assert f"'data_offset': {first_lost_offset}" in finding.supporting_evidence[0]
    assert f"'data_offset': {second_lost_offset}" in finding.supporting_evidence[0]
    assert "logical_size:unknown_full_clusters_include_final_cluster_slack" in finding.supporting_evidence[0]
    report = Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "FAT12_LOST_CHAIN_00000007.bin" in report
    assert "CTF{fat12_lost_chain_recursive}" in report


def test_fat12_active_lfn_file_requires_exact_eoc_chain_and_recurses(tmp_path: Path) -> None:
    sector_size = 512
    first_data_sector = 3
    image = bytearray(8 * sector_size)
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
    short_name = b"ACTIVE~1TXT"
    long_name = "Active.txt"
    checksum = GenericTriageEngine._fat_short_name_checksum(short_name)
    units = [
        int.from_bytes(long_name.encode("utf-16le")[offset:offset + 2], "little")
        for offset in range(0, len(long_name.encode("utf-16le")), 2)
    ]
    units.extend([0, *([0xFFFF] * (12 - len(units)))])
    slot = bytearray(32)
    slot[0] = 0x41
    slot[11] = 0x0F
    slot[13] = checksum
    encoded = b"".join(value.to_bytes(2, "little") for value in units)
    slot[1:11] = encoded[:10]
    slot[14:26] = encoded[10:22]
    slot[28:32] = encoded[22:26]
    root_offset = 2 * sector_size
    image[root_offset:root_offset + 32] = slot
    short_offset = root_offset + 32
    image[short_offset:short_offset + 11] = short_name
    image[short_offset + 11] = 0x20
    image[short_offset + 26:short_offset + 28] = (5).to_bytes(2, "little")
    payload = b"CTF{fat12_active_lfn_recursive}"
    image[short_offset + 28:short_offset + 32] = len(payload).to_bytes(4, "little")
    content_offset = (first_data_sector + 3) * sector_size
    image[content_offset:content_offset + len(payload)] = payload
    evidence = tmp_path / "fat12-active-lfn.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat12-active-cases", mode=AnalysisMode.AUTO, execute=False,
    )

    values = {
        observation.key: observation.value
        for observation in result.observations
        if observation.artifact_id == result.root_artifact.id
    }
    active = values["filesystem.fat12.root.recoverable_regular_files"]
    assert active == [{
        "entry_index": 1, "offset": short_offset, "short_name": "ACTIVE~1.TXT",
        "attributes": "0x20", "first_cluster": 5, "cluster_high_reserved": 0,
        "fat12_cluster_high_reserved": 0, "size": len(payload),
        "raw_hex": bytes(image[short_offset:short_offset + 32]).hex(),
        "long_name": long_name, "lfn_slot_offsets": [root_offset],
        "lfn_checksum": f"0x{checksum:02X}",
        "lfn_order_validation": "stored_ordinals_and_terminal_marker",
        "lfn_terminal_validation": "nul_terminator_with_ffff_padding",
    }]
    child = next(item for item in result.artifacts if item.logical_name == long_name)
    assert child.parent_id == result.root_artifact.id and child.size == len(payload)
    assert any(
        item.value == "CTF{fat12_active_lfn_recursive}" and item.artifact_id == child.id
        for item in result.flags
    )
    finding = next(
        item for item in result.findings if item.category == "fat12_active_file_recovery"
    )
    assert finding.source == "builtin_fat12_active_file_extractor"
    assert f"entry_offset:{short_offset}" in finding.supporting_evidence[0]
    assert f"lfn_slot_offsets:[{root_offset}]" in finding.supporting_evidence[0]
    assert f"physical_offset': {content_offset}" in finding.supporting_evidence[0]
    assert "chain_validation:exact_size_required_chain_eoc" in finding.supporting_evidence[0]

    non_eoc = bytearray(image)
    packed_offset = sector_size + 5 + 5 // 2
    packed = int.from_bytes(non_eoc[packed_offset:packed_offset + 2], "little")
    non_eoc[packed_offset:packed_offset + 2] = (
        (packed & 0x000F) | (6 << 4)
    ).to_bytes(2, "little")
    non_eoc_path = tmp_path / "fat12-active-lfn-non-eoc.raw"
    non_eoc_path.write_bytes(non_eoc)
    non_eoc_result = AnalysisEngine().analyze(
        non_eoc_path, tmp_path / "fat12-active-non-eoc-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert not any(item.logical_name == long_name for item in non_eoc_result.artifacts)
    assert not any(
        item.category == "fat12_active_file_recovery" for item in non_eoc_result.findings
    )


def test_fat32_active_file_recovery_uses_extflags_selected_fat(tmp_path: Path) -> None:
    sector_size = 512
    reserved = 1
    fat_size = 600
    fat_count = 2
    first_data_sector = reserved + fat_count * fat_size
    image = bytearray((first_data_sector + 6) * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = reserved.to_bytes(2, "little")
    image[16] = fat_count
    image[21] = 0xF8
    image[32:36] = (70_000).to_bytes(4, "little")
    image[36:40] = fat_size.to_bytes(4, "little")
    image[40:42] = (0x0081).to_bytes(2, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    fat0_offset = reserved * sector_size
    fat1_offset = (reserved + fat_size) * sector_size
    for offset in (fat0_offset, fat1_offset):
        image[offset:offset + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    image[fat0_offset + 2 * 4:fat0_offset + 2 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[fat1_offset + 2 * 4:fat1_offset + 2 * 4 + 4] = (5).to_bytes(4, "little")
    image[fat1_offset + 5 * 4:fat1_offset + 5 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[fat1_offset + 7 * 4:fat1_offset + 7 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    root_offset = first_data_sector * sector_size
    for index in range(sector_size // 32):
        offset = root_offset + index * 32
        image[offset:offset + 11] = b"FILLER  TXT"
        image[offset + 11] = 0x20
    second_root_offset = (first_data_sector + 3) * sector_size
    image[second_root_offset:second_root_offset + 11] = b"ACTIVE  TXT"
    image[second_root_offset + 11] = 0x20
    image[second_root_offset + 26:second_root_offset + 28] = (7).to_bytes(2, "little")
    payload = b"CTF{fat32_extflags_active_file}"
    image[second_root_offset + 28:second_root_offset + 32] = len(payload).to_bytes(4, "little")
    content_offset = (first_data_sector + 5) * sector_size
    image[content_offset:content_offset + len(payload)] = payload
    evidence = tmp_path / "fat32-active-copy-file.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat32-active-cases", mode=AnalysisMode.AUTO, execute=False,
    )

    values = {
        observation.key: observation.value
        for observation in result.observations
        if observation.artifact_id == result.root_artifact.id
    }
    assert values["filesystem.fat.root.active_fat_index"] == 1
    active = values["filesystem.fat.root.recoverable_regular_files"]
    assert active == [{
        "entry_index": 16, "offset": second_root_offset, "short_name": "ACTIVE.TXT",
        "attributes": "0x20", "first_cluster": 7,
        "cluster_field_raw": "0x00000007", "fat32_cluster_high_reserved": 0,
        "size": len(payload), "raw_hex": bytes(image[second_root_offset:second_root_offset + 32]).hex(),
    }]
    child = next(item for item in result.artifacts if item.logical_name == "ACTIVE.TXT")
    assert child.parent_id == result.root_artifact.id and child.size == len(payload)
    assert any(
        item.value == "CTF{fat32_extflags_active_file}" and item.artifact_id == child.id
        for item in result.flags
    )
    finding = next(
        item for item in result.findings if item.category == "fat32_active_file_recovery"
    )
    assert finding.source == "builtin_fat32_active_file_extractor"
    assert f"entry_offset:{second_root_offset}" in finding.supporting_evidence[0]
    assert f"'fat_entry_offset': {fat1_offset + 7 * 4}" in finding.supporting_evidence[0]
    assert f"'physical_offset': {content_offset}" in finding.supporting_evidence[0]
    assert "chain_validation:exact_size_required_chain_eoc" in finding.supporting_evidence[0]


def test_fat32_noncontiguous_subdirectory_lfn_file_keeps_selected_fat_lineage(tmp_path: Path) -> None:
    sector_size = 512
    reserved = 1
    fat_size = 600
    first_data_sector = reserved + 2 * fat_size
    image = bytearray((first_data_sector + 8) * sector_size)
    image[11:13] = sector_size.to_bytes(2, "little")
    image[13] = 1
    image[14:16] = reserved.to_bytes(2, "little")
    image[16] = 2
    image[21] = 0xF8
    image[32:36] = (70_000).to_bytes(4, "little")
    image[36:40] = fat_size.to_bytes(4, "little")
    image[40:42] = (0x0081).to_bytes(2, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    fat0_offset = reserved * sector_size
    fat1_offset = (reserved + fat_size) * sector_size
    for offset in (fat0_offset, fat1_offset):
        image[offset:offset + 8] = b"\xf8\xff\xff\x0f\xff\xff\xff\x0f"
    image[fat0_offset + 2 * 4:fat0_offset + 2 * 4 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
    for cluster, next_cluster in (
        (2, 0x0FFFFFFF), (5, 9), (9, 0x0FFFFFFF),
        (7, 0x0FFFFFFF), (8, 0x0FFFFFFF),
    ):
        offset = fat1_offset + cluster * 4
        image[offset:offset + 4] = next_cluster.to_bytes(4, "little")
    root_offset = first_data_sector * sector_size
    image[root_offset:root_offset + 11] = b"ACTIVE     "
    image[root_offset + 11] = 0x10
    image[root_offset + 26:root_offset + 28] = (5).to_bytes(2, "little")
    first_directory_offset = (first_data_sector + 3) * sector_size
    for index in range(sector_size // 32):
        offset = first_directory_offset + index * 32
        image[offset:offset + 11] = b"FILLER  TXT"
        image[offset + 11] = 0x20
    second_directory_offset = (first_data_sector + 7) * sector_size
    short_name = b"NESTED~1TXT"
    long_name = "Nested.txt"
    checksum = GenericTriageEngine._fat_short_name_checksum(short_name)
    encoded_name = long_name.encode("utf-16le")
    units = [
        int.from_bytes(encoded_name[offset:offset + 2], "little")
        for offset in range(0, len(encoded_name), 2)
    ]
    units.extend([0, *([0xFFFF] * (12 - len(units)))])
    slot = bytearray(32)
    slot[0] = 0x41
    slot[11] = 0x0F
    slot[13] = checksum
    encoded_slot = b"".join(value.to_bytes(2, "little") for value in units)
    slot[1:11] = encoded_slot[:10]
    slot[14:26] = encoded_slot[10:22]
    slot[28:32] = encoded_slot[22:26]
    image[second_directory_offset:second_directory_offset + 32] = slot
    short_offset = second_directory_offset + 32
    image[short_offset:short_offset + 11] = short_name
    image[short_offset + 11] = 0x20
    image[short_offset + 26:short_offset + 28] = (7).to_bytes(2, "little")
    payload = b"CTF{fat32_subdirectory_lfn_active}"
    image[short_offset + 28:short_offset + 32] = len(payload).to_bytes(4, "little")
    content_offset = (first_data_sector + 5) * sector_size
    image[content_offset:content_offset + len(payload)] = payload
    deleted_short_name = b"DELETE~1TXT"
    deleted_long_name = "Deleted.txt"
    deleted_checksum = GenericTriageEngine._fat_short_name_checksum(deleted_short_name)
    deleted_encoded_name = deleted_long_name.encode("utf-16le")
    deleted_units = [
        int.from_bytes(deleted_encoded_name[offset:offset + 2], "little")
        for offset in range(0, len(deleted_encoded_name), 2)
    ]
    deleted_units.extend([0, *([0xFFFF] * (12 - len(deleted_units)))])
    deleted_slot_offset = second_directory_offset + 64
    deleted_slot = bytearray(32)
    deleted_slot[0] = 0xE5
    deleted_slot[11] = 0x0F
    deleted_slot[13] = deleted_checksum
    deleted_encoded_slot = b"".join(value.to_bytes(2, "little") for value in deleted_units)
    deleted_slot[1:11] = deleted_encoded_slot[:10]
    deleted_slot[14:26] = deleted_encoded_slot[10:22]
    deleted_slot[28:32] = deleted_encoded_slot[22:26]
    image[deleted_slot_offset:deleted_slot_offset + 32] = deleted_slot
    deleted_short_offset = deleted_slot_offset + 32
    image[deleted_short_offset:deleted_short_offset + 11] = b"\xe5" + deleted_short_name[1:]
    image[deleted_short_offset + 11] = 0x20
    image[deleted_short_offset + 26:deleted_short_offset + 28] = (8).to_bytes(2, "little")
    deleted_payload = b"CTF{fat32_subdirectory_deleted_lfn}"
    image[deleted_short_offset + 28:deleted_short_offset + 32] = len(deleted_payload).to_bytes(4, "little")
    deleted_content_offset = (first_data_sector + 6) * sector_size
    image[deleted_content_offset:deleted_content_offset + len(deleted_payload)] = deleted_payload
    incompatible_slot_offset = second_directory_offset + 128
    image[incompatible_slot_offset:incompatible_slot_offset + 32] = slot
    volume_label_offset = second_directory_offset + 160
    image[volume_label_offset:volume_label_offset + 11] = b"VOLUME     "
    image[volume_label_offset + 11] = 0x08
    orphan_slot_offset = second_directory_offset + 192
    image[orphan_slot_offset:orphan_slot_offset + 32] = slot
    evidence = tmp_path / "fat32-subdirectory-active-lfn.raw"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(
        evidence, tmp_path / "fat32-subdirectory-active-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )

    child = next(item for item in result.artifacts if item.logical_name == long_name)
    deleted_child = next(item for item in result.artifacts if item.logical_name == deleted_long_name)
    assert child.parent_id == result.root_artifact.id and child.size == len(payload)
    assert deleted_child.parent_id == result.root_artifact.id and deleted_child.size == len(deleted_payload)
    assert any(
        item.value == "CTF{fat32_subdirectory_lfn_active}" and item.artifact_id == child.id
        for item in result.flags
    )
    assert any(
        item.value == "CTF{fat32_subdirectory_deleted_lfn}" and item.artifact_id == deleted_child.id
        for item in result.flags
    )
    inventory = next(
        observation.value for observation in result.observations
        if observation.artifact_id == result.root_artifact.id
        and observation.key == "filesystem.fat.subdirectory_inventory"
    )
    assert inventory == [{
        "name": "ACTIVE", "start_cluster": 5, "source_entry_offset": root_offset,
        "parent_cluster_lineage": [],
        "cluster_chain": [
            {
                "cluster": 5, "offset": first_directory_offset, "length": sector_size,
                "fat_entry_offset": fat1_offset + 5 * 4,
                "fat_entry_raw": (9).to_bytes(4, "little").hex(), "next_cluster": 9,
            },
            {
                "cluster": 9, "offset": second_directory_offset, "length": sector_size,
                "fat_entry_offset": fat1_offset + 9 * 4,
                "fat_entry_raw": (0x0FFFFFFF).to_bytes(4, "little").hex(),
                "next_cluster": 0x0FFFFFFF,
            },
        ],
        "termination": "eoc",
    }]
    finding = next(
        item for item in result.findings if item.category == "fat32_active_file_recovery"
    )
    active_evidence = next(item for item in finding.supporting_evidence if f"child:{child.id}" in item)
    assert f"entry_offset:{short_offset}" in active_evidence
    assert f"lfn_slot_offsets:[{second_directory_offset}]" in active_evidence
    assert "directory_start_cluster:5" in active_evidence
    assert "directory_cluster_lineage:[5, 9]" in active_evidence
    assert f"directory_source_entry_offset:{root_offset}" in active_evidence
    assert f"'fat_entry_offset': {fat1_offset + 7 * 4}" in active_evidence
    assert f"'physical_offset': {content_offset}" in active_evidence
    deleted_finding = next(
        item for item in result.findings if item.category == "fat_deleted_content_recovery"
    )
    deleted_evidence = next(
        item for item in deleted_finding.supporting_evidence if f"child:{deleted_child.id}" in item
    )
    assert f"entry_offset:{deleted_short_offset}" in deleted_evidence
    assert f"lfn_slot_offsets:[{deleted_slot_offset}]" in deleted_evidence
    assert "directory_start_cluster:5" in deleted_evidence
    assert "directory_cluster_lineage:[5, 9]" in deleted_evidence
    assert f"directory_source_entry_offset:{root_offset}" in deleted_evidence
    assert f"physical_offset:{deleted_content_offset}" in deleted_evidence

    bad_lfn = bytearray(image)
    bad_lfn[second_directory_offset + 13] ^= 0xFF
    bad_lfn_path = tmp_path / "fat32-subdirectory-bad-active-lfn.raw"
    bad_lfn_path.write_bytes(bad_lfn)
    bad_result = AnalysisEngine().analyze(
        bad_lfn_path, tmp_path / "fat32-subdirectory-bad-lfn-cases",
        mode=AnalysisMode.AUTO, execute=False,
    )
    assert not any(item.logical_name == long_name for item in bad_result.artifacts)
    assert any(item.logical_name == "NESTED~1.TXT" for item in bad_result.artifacts)
    unlinked = next(
        observation.value for observation in bad_result.observations
        if observation.artifact_id == bad_result.root_artifact.id
        and observation.key == "filesystem.fat.unlinked_lfn_slots"
    )
    assert unlinked == [
        {
            "directory_start_cluster": 5,
            "directory_cluster_lineage": [5, 9],
            "directory_source_entry_offset": root_offset,
            "short_entry_index": 17,
            "short_entry_offset": short_offset,
            "slot_offsets": [second_directory_offset],
            "reason": "active LFN checksum does not match the short entry",
            "raw_hex": [bytes(bad_lfn[second_directory_offset:second_directory_offset + 32]).hex()],
        },
        {
            "directory_start_cluster": 5,
            "directory_cluster_lineage": [5, 9],
            "directory_source_entry_offset": root_offset,
            "short_entry_index": 21,
            "short_entry_offset": volume_label_offset,
            "slot_offsets": [incompatible_slot_offset],
            "reason": "LFN slots are followed by an incompatible volume-label entry",
            "raw_hex": [slot.hex()],
        },
        {
            "directory_start_cluster": 5,
            "directory_cluster_lineage": [5, 9],
            "directory_source_entry_offset": root_offset,
            "short_entry_index": None,
            "short_entry_offset": None,
            "slot_offsets": [orphan_slot_offset],
            "reason": "LFN slots are not followed by a short entry",
            "raw_hex": [slot.hex()],
        },
    ]
    unlinked_finding = next(
        item for item in bad_result.findings
        if item.category == "fat32_unlinked_lfn_slots"
    )
    assert str(short_offset) in unlinked_finding.supporting_evidence[0]
    assert "[5, 9]" in unlinked_finding.supporting_evidence[0]
    assert "active LFN checksum does not match the short entry" in unlinked_finding.supporting_evidence[0]
    report = Path(bad_result.case.workspace, "reports", "report.json").read_text(encoding="utf-8")
    assert "fat32_unlinked_lfn_slots" in report
    assert "active LFN checksum does not match the short entry" in report
    assert "LFN slots are followed by an incompatible volume-label entry" in report
    assert "LFN slots are not followed by a short entry" in report


def test_recycle_bin_exact_supplied_content_pair_is_correlated(tmp_path: Path) -> None:
    bundle = tmp_path / "recycle"
    bundle.mkdir()
    suffix = "ABC123"
    original = r"C:\Users\ctf\Desktop\flag.txt"
    encoded = (original + "\x00").encode("utf-16le")
    metadata = bytearray(28 + len(encoded))
    metadata[:8] = (2).to_bytes(8, "little")
    metadata[8:16] = (123).to_bytes(8, "little")
    metadata[24:28] = (len(original) + 1).to_bytes(4, "little")
    metadata[28:] = encoded
    (bundle / f"$I{suffix}").write_bytes(metadata)
    (bundle / f"$R{suffix}").write_bytes(b"CTF{recycle_content_pair}")

    result = AnalysisEngine().analyze(bundle, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    metadata_artifact = next(item for item in result.artifacts if item.logical_name == f"$I{suffix}")
    linked = next(item.value for item in result.observations if item.artifact_id == metadata_artifact.id and item.key == "windows.recycle_bin_content_companion")
    assert linked["content_logical_name"] == f"$R{suffix}"
    assert any(item.category == "windows_recycle_bin_pair" for item in result.findings)
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "windows.recycle_bin_content_companion" in report and "windows_recycle_bin_pair" in report


def test_invalid_recycle_bin_metadata_is_not_paired_by_filename(tmp_path: Path) -> None:
    bundle = tmp_path / "recycle-invalid"
    bundle.mkdir()
    (bundle / "$IBAD").write_bytes(b"not a valid recycle-bin record")
    (bundle / "$RBAD").write_bytes(b"CTF{unpaired}")

    result = AnalysisEngine().analyze(bundle, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)

    assert not any(item.key.startswith("windows.recycle_bin_") and item.key.endswith("_companion") for item in result.observations)
    assert not any(item.category == "windows_recycle_bin_pair" for item in result.findings)


def test_android_boot_components_are_recursively_analyzed(tmp_path: Path) -> None:
    ramdisk = gzip.compress(base64.b64encode(b"CTF{android_boot_ramdisk}"))
    page_size = 2048
    kernel = b"KERNEL"
    image = bytearray(page_size * 2 + len(ramdisk))
    image[:8] = b"ANDROID!"
    image[8:12] = len(kernel).to_bytes(4, "little")
    image[16:20] = len(ramdisk).to_bytes(4, "little")
    image[36:40] = page_size.to_bytes(4, "little")
    image[page_size:page_size + len(kernel)] = kernel
    image[page_size * 2:page_size * 2 + len(ramdisk)] = ramdisk
    evidence = tmp_path / "boot.img"
    evidence.write_bytes(image)

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    assert {"android_boot_kernel.bin", "android_boot_ramdisk.bin"} <= {artifact.logical_name for artifact in result.artifacts}
    assert any(candidate.value == "CTF{android_boot_ramdisk}" for candidate in result.flags)
    assert any(finding.category == "android_boot_extraction" for finding in result.findings)


def test_truncated_android_backup_zlib_payload_is_not_promoted(tmp_path: Path) -> None:
    evidence = tmp_path / "truncated.ab"
    payload = zlib.compress(b"not-a-full-tar")[:-3]
    evidence.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + payload)

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    assert [artifact.logical_name for artifact in result.artifacts] == ["truncated.ab"]
    assert any("Android backup extraction failed" in error for error in result.errors)


def test_nonfatal_analysis_errors_are_persisted_in_case_report(tmp_path: Path) -> None:
    evidence = tmp_path / "truncated.ab"
    evidence.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(b"not-a-full-tar")[:-3])

    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)

    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    markdown = next((tmp_path / "cases").glob("*/reports/report.md")).read_text(encoding="utf-8")
    assert result.errors
    assert "Android backup extraction failed" in report
    assert "extraction_manager" in report
    assert "## Recommended next steps" in markdown


def test_tool_stdout_is_hunted_as_flag_evidence(tmp_path: Path) -> None:
    executable = tmp_path / "pdftotext"
    executable.write_text("#!/bin/sh\nprintf 'CTF{tool_output_chain}\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    evidence = tmp_path / "input.pdf"
    evidence.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "pdftotext", (str(executable),), parser="pdftotext",
            command_templates={"default": ("{executable}", "{evidence}")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO)

    assert any(
        candidate.value == "CTF{tool_output_chain}"
        and candidate.source.startswith("tool_output_flag_hunter:pdftotext:")
        for candidate in result.flags
    )


def test_explicit_tool_and_category_filters_only_narrow_existing_plan(tmp_path: Path) -> None:
    evidence = tmp_path / "input.pdf"
    evidence.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    config = ForensicKitConfig(tool_allowlist=["pdfinfo"], category_filter=["pdf"])
    engine = AnalysisEngine(config)
    engine.registry = ToolRegistry([
        ToolDefinition("pdfid", ("missing-pdfid",), profiles=("pdf",), parser="pdfid"),
        ToolDefinition("pdfinfo", ("missing-pdfinfo",), profiles=("pdf",), parser="pdfinfo"),
        ToolDefinition("pdftotext", ("missing-pdftotext",), profiles=("pdf",), parser="pdftotext"),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.PLAN, execute=False)

    assert [plan.tool for plan in result.plans] == ["pdfinfo"]


def test_native_partition_offsets_drive_distinct_fls_runs(tmp_path: Path) -> None:
    executable = tmp_path / "fls"
    executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n", encoding="utf-8")
    executable.chmod(0o755)
    image = bytearray(512 * 16)
    image[446 + 4] = 0x83
    image[446 + 8:446 + 12] = (1).to_bytes(4, "little")
    image[446 + 12:446 + 16] = (1).to_bytes(4, "little")
    image[462 + 4] = 0x83
    image[462 + 8:462 + 12] = (3).to_bytes(4, "little")
    image[462 + 12:462 + 16] = (1).to_bytes(4, "little")
    image[510:512] = b"\x55\xaa"
    evidence = tmp_path / "disk.dd"
    evidence.write_bytes(image)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition(
            "sleuthkit_fls", (str(executable),), parser="sleuthkit_fls",
            command_templates={"offset": ("{executable}", "-r", "-p", "-o", "{partition_offset}", "{evidence}")},
        ),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    runs = [run for run in result.tool_runs if run.tool == "sleuthkit_fls"]
    assert len(runs) == 2
    assert {run.command_argv[-2] for run in runs} == {"1", "3"}
    reports = list((tmp_path / "cases").glob("*/reports/report.md"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert "partition_offset=1" in report and "partition_offset=3" in report


def test_mmls_parser_output_drives_followup_offset_fls_run(tmp_path: Path) -> None:
    mmls = tmp_path / "mmls"
    mmls.write_text(
        "#!/bin/sh\nprintf '002:000  4096  8191  4096  Linux (0x83)\\n'\n",
        encoding="utf-8",
    )
    mmls.chmod(0o755)
    fls = tmp_path / "fls"
    fls.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n", encoding="utf-8")
    fls.chmod(0o755)
    fsstat = tmp_path / "fsstat"
    fsstat.write_text(
        "#!/bin/sh\nprintf 'File System Type: NTFS\\nVolume Serial Number: CTF-1234\\n'\n",
        encoding="utf-8",
    )
    fsstat.chmod(0o755)
    evidence = tmp_path / "image.E01"
    evidence.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 4096)
    engine = AnalysisEngine()
    engine.registry = ToolRegistry([
        ToolDefinition("sleuthkit_mmls", (str(mmls),), parser="sleuthkit_mmls", command_templates={"default": ("{executable}", "{evidence}")}),
        ToolDefinition("sleuthkit_fls", (str(fls),), parser="sleuthkit_fls", command_templates={"offset": ("{executable}", "-r", "-p", "-o", "{partition_offset}", "{evidence}")}),
        ToolDefinition("sleuthkit_fsstat", (str(fsstat),), parser="sleuthkit_fsstat", command_templates={"offset": ("{executable}", "-o", "{partition_offset}", "{evidence}")}),
        ToolDefinition("ewfinfo", ("missing-ewfinfo",), parser="generic", command_templates={"default": ("{executable}", "{evidence}")}),
    ])

    result = engine.analyze(evidence, tmp_path / "cases", mode=AnalysisMode.DEEP)

    fls_runs = [run for run in result.tool_runs if run.tool == "sleuthkit_fls"]
    assert len(fls_runs) == 1
    assert fls_runs[0].command_argv[-2] == "4096"
    fsstat_runs = [run for run in result.tool_runs if run.tool == "sleuthkit_fsstat"]
    assert len(fsstat_runs) == 1
    assert fsstat_runs[0].command_argv[-2] == "4096"
    assert any(observation.key == "filesystem.fsstat.type" and observation.value == "NTFS" for observation in result.observations)
