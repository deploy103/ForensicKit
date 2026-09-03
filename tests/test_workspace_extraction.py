from __future__ import annotations

import base64
import io
import zipfile
import hashlib
from pathlib import Path

from forensickit.config import ForensicKitConfig
from forensickit.evidence import EvidenceManager
from forensickit.extraction import ExtractionManager
from forensickit.flags import FlagHunter
from forensickit.models import Observation
from forensickit.models import AnalysisResult
from forensickit.engine import AnalysisEngine
from forensickit.reporting import ReportGenerator
from forensickit.workspace import CaseWorkspace
from forensickit.doctor import Doctor
from forensickit.tools import ToolRegistry
from forensickit.triage import GenericTriageEngine


def _zip(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def test_evidence_is_preserved_and_deduplicated(tmp_path: Path) -> None:
    source = tmp_path / "challenge.bin"
    source.write_bytes(b"immutable source")
    with CaseWorkspace.create(tmp_path / "cases", "dedupe") as workspace:
        manager = EvidenceManager(workspace)
        first = manager.ingest(source)
        second = manager.ingest(source)
        assert first.id == second.id
        stored = workspace.resolve_stored_path(first.path)
        assert stored.read_bytes() == b"immutable source"
        assert stored.stat().st_mode & 0o222 == 0
        assert len(workspace.database.artifacts()) == 1


def test_bounded_zip_extract_flag_and_report(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"CTF{recursive_pipeline}")
    source = tmp_path / "polyglot.png"
    source.write_bytes(b"image-prefix" + _zip({"nested/flag.txt": encoded, "../escape": b"bad"}))
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "pipeline", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        extraction = ExtractionManager(workspace, config.limits).extract_zip(root)
        assert [item.logical_name for item in extraction.artifacts] == ["nested/flag.txt"]
        assert any("unsafe path" in error for error in extraction.errors)
        child = extraction.artifacts[0]
        flags = FlagHunter(config.flag_patterns).scan(workspace.resolve_stored_path(child.path), child)
        assert any(candidate.value == "CTF{recursive_pipeline}" for candidate in flags)
        assert any("base64" in candidate.transform_chain for candidate in flags)
        workspace.database.add_findings(extraction.findings)
        workspace.database.add_flags(flags)
        json_report, markdown_report = ReportGenerator().generate(workspace)
        assert "CTF{recursive_pipeline}" in json_report.read_text(encoding="utf-8")
        assert "CTF{recursive_pipeline}" in markdown_report.read_text(encoding="utf-8")
        assert (workspace.root / "reports" / "timeline.csv").exists()


def test_timeline_report_deduplicates_tool_records_and_preserves_sources() -> None:
    event = {
        "event_id": "4688", "event_record_id": 77,
        "category": "process_creation", "timestamp": "2026-09-03T01:00:00Z",
        "command_line": "=unsafe-spreadsheet-formula",
    }
    report = {
        "artifacts": [{"id": "a", "logical_name": "Security.evtx"}],
        "tool_runs": [
            {"id": "run-c", "stdout_path": "outputs/run-c.stdout"},
            {"id": "run-h", "stdout_path": "outputs/run-h.stdout"},
        ],
        "observations": [
            {
                "id": "obs-c", "artifact_id": "a",
                "key": "windows.event_hunt.normalized_events",
                "value": [event], "source": "tool:chainsaw:run-c",
            },
            {
                "id": "obs-h", "artifact_id": "a",
                "key": "windows.event_timeline.normalized_events",
                "value": [event.copy()], "source": "tool:hayabusa:run-h",
            },
            {
                "id": "obs-o", "artifact_id": "a",
                "key": "evtx.normalized_record_correlations",
                "value": [{"event_record_id": 77, "record_offset": 4608, "record_size": 256}],
                "source": "profile:windows",
            },
        ],
    }

    rows = ReportGenerator._timeline_rows(report)

    assert len(rows) == 1
    assert rows[0]["record_offset"] == 4608
    assert rows[0]["timestamp_utc"] == "2026-09-03T01:00:00+00:00"
    assert rows[0]["sources"] == "tool:chainsaw:run-c;tool:hayabusa:run-h"
    assert rows[0]["tool_run_ids"] == "run-c;run-h"
    assert rows[0]["raw_stdout_paths"] == "outputs/run-c.stdout;outputs/run-h.stdout"
    assert rows[0]["command_line"] == "=unsafe-spreadsheet-formula"
    assert ReportGenerator._csv_safe(rows[0]["command_line"]) == "'=unsafe-spreadsheet-formula"


def test_timeline_report_includes_usn_record_and_journal_provenance() -> None:
    report = {
        "artifacts": [
            {"id": "journal", "logical_name": "$UsnJrnl:$J"},
            {"id": "disk", "logical_name": "disk.raw"},
        ],
        "tool_runs": [],
        "observations": [{
            "id": "obs-usn", "artifact_id": "journal", "key": "ntfs.usn.records",
            "source": "builtin:triage", "value": [{
                "offset": 4096, "record_length": 80, "usn": 123,
                "major_version": 2,
                "timestamp": "2026-09-03T01:02:03+09:00",
                "reason": "0x00002100", "reason_names": ["file_create", "rename_new_name"],
                "file_record_number": 42, "file_sequence_number": 3,
                "parent_record_number": 5, "parent_sequence_number": 2,
                "file_name": "=formula.txt", "file_attributes": "0x00000020",
                "source_info": "0x00000000", "security_id": 7,
            }],
        }, {
            "id": "obs-link", "artifact_id": "journal",
            "key": "correlation.usn_sampled_mft", "source": "usn_mft_correlator",
            "value": [{
                "journal_artifact_id": "journal", "ancestor_artifact_id": "disk",
                "journal_observation_id": "obs-usn", "mft_observation_id": "obs-mft",
                "usn": 123, "journal_offset": 4096,
                "sample_file_names": ["actual.txt"], "sample_deleted": False,
                "sample_physical_segments": [{"physical_offset": 8192, "length": 1024}],
            }],
        }],
    }

    rows = ReportGenerator._timeline_rows(report)

    assert len(rows) == 1
    assert rows[0]["event_id"] == "USN_RECORD_V2"
    assert rows[0]["timestamp_utc"] == "2026-09-02T16:02:03+00:00"
    assert rows[0]["record_offset"] == 4096
    assert rows[0]["record_size"] == 80
    assert rows[0]["file_record_number"] == 42
    assert rows[0]["reason_names"] == "file_create;rename_new_name"
    assert rows[0]["sources"] == "builtin:triage;usn_mft_correlator"
    assert rows[0]["source_observation_ids"] == "obs-usn;obs-link"
    assert rows[0]["mft_artifact_id"] == "disk"
    assert rows[0]["mft_artifact_name"] == "disk.raw"
    assert rows[0]["mft_observation_id"] == "obs-mft"
    assert rows[0]["sample_file_names"] == ["actual.txt"]
    assert rows[0]["sample_physical_segments"][0]["physical_offset"] == 8192
    assert ReportGenerator._csv_safe(rows[0]["file_name"]) == "'=formula.txt"


def test_zip_member_size_limit_is_enforced(tmp_path: Path) -> None:
    source = tmp_path / "large.zip"
    source.write_bytes(_zip({"large.bin": b"A" * 1024}))
    config = ForensicKitConfig()
    config.limits.max_single_artifact_size = 100
    with CaseWorkspace.create(tmp_path / "cases", "limits", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        result = ExtractionManager(workspace, config.limits).extract_zip(root)
        assert not result.artifacts
        assert any("maximum single artifact size" in error for error in result.errors)


def test_ntfs_sparse_and_uninitialized_nonresident_ranges_are_zero_filled(tmp_path: Path) -> None:
    cluster_size = 512
    source = tmp_path / "sparse-ntfs.raw"
    image = bytearray(10 * cluster_size)
    first_cluster = b"CTF{ntfs_sparse_child}" + b"A" * (cluster_size - 22)
    final_cluster = b"B" * cluster_size
    image[5 * cluster_size:6 * cluster_size] = first_cluster
    image[8 * cluster_size:9 * cluster_size] = final_cluster
    source.write_bytes(image)
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "ntfs-sparse", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        common = {
            "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
            "directory": False, "record_number": 9, "file_names": ["sparse.bin"],
            "deleted": True,
        }
        valid_stream = {
            "attribute_id": 4, "stream_name": "zeros", "attribute_flags": 0x8000,
            "lowest_vcn": 0, "highest_vcn": 2,
            "allocated_size": 2 * cluster_size, "real_size": 1300,
            "initialized_size": 1150,
            "data_runs": [
                {"vcn": 0, "cluster_count": 1, "lcn": 5},
                {"vcn": 1, "cluster_count": 1, "lcn": None},
                {"vcn": 2, "cluster_count": 1, "lcn": 8},
            ],
        }
        malformed_stream = {
            **valid_stream, "attribute_id": 5, "stream_name": "gap",
            "data_runs": [
                {"vcn": 0, "cluster_count": 1, "lcn": 5},
                {"vcn": 2, "cluster_count": 1, "lcn": 8},
            ],
        }
        workspace.database.add_observations([
            Observation(root.id, "filesystem.ntfs.bytes_per_sector", 512, "test"),
            Observation(root.id, "filesystem.ntfs.sectors_per_cluster", 1, "test"),
            Observation(
                root.id, "filesystem.ntfs.mft_sample_records",
                [{**common, "nonresident_data_attributes": [valid_stream, malformed_stream]}],
                "test",
            ),
        ])

        result = ExtractionManager(workspace, config.limits).extract_ntfs_nonresident_data(root)

        assert [item.logical_name for item in result.artifacts] == ["sparse.bin:zeros"]
        recovered = workspace.resolve_stored_path(result.artifacts[0].path).read_bytes()
        assert recovered == first_cluster + (b"\x00" * cluster_size) + final_cluster[:126] + (b"\x00" * 150)
        assert len(recovered) == 1300
        evidence = result.findings[0].supporting_evidence[0]
        assert "zero_fill_reason': 'sparse_run'" in evidence
        assert "logical_offset': 512" in evidence
        assert "zero_fill_reason': 'uninitialized_tail'" in evidence
        assert "logical_offset': 1150" in evidence
        assert not any(item.logical_name.endswith(":gap") for item in result.artifacts)
        flags = FlagHunter(config.flag_patterns).scan(
            workspace.resolve_stored_path(result.artifacts[0].path), result.artifacts[0]
        )
        assert any(item.value == "CTF{ntfs_sparse_child}" for item in flags)


def test_ntfs_exact_sampled_attribute_list_extents_become_one_child(tmp_path: Path) -> None:
    source = tmp_path / "extent-ntfs.raw"
    image = bytearray(12 * 512)
    image[5 * 512:6 * 512] = b"A" * 512
    extent_tail = b"CTF{ntfs_extent_child}" + b"B" * (512 - 22)
    image[9 * 512:10 * 512] = extent_tail
    source.write_bytes(image)
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "ntfs-extents", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        base_stream = {
            "attribute_offset": 120, "attribute_id": 3, "stream_name": "joined",
            "attribute_flags": 0, "lowest_vcn": 0, "highest_vcn": 0,
            "allocated_size": 1024, "real_size": 600, "initialized_size": 600,
            "data_runs": [{"vcn": 0, "cluster_count": 1, "lcn": 5}],
        }
        records = [{
            "record_number": 4, "sequence_number": 6, "file_names": ["extent.bin"],
            "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
            "directory": False, "deleted": False, "physical_segments": [],
            "nonresident_data_attributes": [base_stream],
            "attribute_list_references": [
                {"type_name": "data", "name": "joined", "lowest_vcn": 0,
                 "record_number": 4, "sequence_number": 6, "attribute_id": 3},
                {"type_name": "data", "name": "joined", "lowest_vcn": 1,
                 "record_number": 8, "sequence_number": 2, "attribute_id": 7},
            ],
        }, {
            "record_number": 8, "sequence_number": 2, "base_record_number": 4,
            "base_sequence_number": 6,
            "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
            "directory": False, "physical_segments": [],
            "nonresident_data_attributes": [{
                "attribute_offset": 64, "attribute_id": 7, "stream_name": "joined",
                "attribute_flags": 0, "lowest_vcn": 1, "highest_vcn": 1,
                "allocated_size": 0, "real_size": 0, "initialized_size": 0,
                "data_runs": [{"vcn": 1, "cluster_count": 1, "lcn": 9}],
            }],
            "attribute_list_references": [],
        }]
        GenericTriageEngine._ntfs_join_sampled_data_extents(records)
        workspace.database.add_observations([
            Observation(root.id, "filesystem.ntfs.bytes_per_sector", 512, "test"),
            Observation(root.id, "filesystem.ntfs.sectors_per_cluster", 1, "test"),
            Observation(root.id, "filesystem.ntfs.mft_sample_records", records, "test"),
        ])

        result = ExtractionManager(workspace, config.limits).extract_ntfs_nonresident_data(root)

        assert [item.logical_name for item in result.artifacts] == ["extent.bin:joined"]
        recovered_path = workspace.resolve_stored_path(result.artifacts[0].path)
        assert recovered_path.read_bytes() == b"A" * 512 + extent_tail[:88]
        assert "'record_number': 8" in result.findings[0].supporting_evidence[0]
        flags = FlagHunter(config.flag_patterns).scan(recovered_path, result.artifacts[0])
        assert any(item.value == "CTF{ntfs_extent_child}" for item in flags)


def test_usn_child_correlates_to_ancestor_mft_only_by_exact_record_sequence(tmp_path: Path) -> None:
    source = tmp_path / "disk.raw"
    source.write_bytes(b"disk evidence")
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "usn-mft", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        child_path = workspace.path("extracted", root.id, "journal.bin")
        child_path.parent.mkdir(parents=True)
        child_path.write_bytes(b"journal evidence")
        child = ExtractionManager(workspace, config.limits).register_file(
            child_path, root, "$UsnJrnl:$J"
        )
        assert child is not None
        mft_observation = Observation(root.id, "filesystem.ntfs.mft_sample_records", [{
            "record_number": 42, "sequence_number": 3,
            "signature_valid": True, "bounds_valid": True, "usa_fixup_valid": True,
            "file_names": ["actual-name.txt"], "deleted": False,
            "physical_segments": [{"physical_offset": 8192, "length": 1024}],
        }], "test:mft")
        usn_observation = Observation(child.id, "ntfs.usn.records", [{
            "major_version": 2, "file_record_number": 42, "file_sequence_number": 3,
            "file_name": "different-journal-name.txt", "usn": 1000, "offset": 80,
            "timestamp": "2026-09-03T01:00:00+00:00", "reason": "0x00000100",
            "reason_names": ["file_create"],
        }, {
            "major_version": 2, "file_record_number": 42, "file_sequence_number": 4,
            "file_name": "reused-record.txt", "usn": 1080, "offset": 160,
        }], "test:usn")
        workspace.database.add_observations([mft_observation, usn_observation])
        result = AnalysisResult(workspace.case, root, artifacts=[root, child])

        AnalysisEngine._correlate_usn_mft_records(workspace, result, [root, child])

        correlation = next(item for item in result.observations if item.key == "correlation.usn_sampled_mft")
        assert len(correlation.value) == 1
        assert correlation.value[0]["record_number"] == 42
        assert correlation.value[0]["sequence_number"] == 3
        assert correlation.value[0]["journal_file_name"] == "different-journal-name.txt"
        assert correlation.value[0]["sample_file_names"] == ["actual-name.txt"]
        assert correlation.value[0]["journal_observation_id"] == usn_observation.id
        assert correlation.value[0]["mft_observation_id"] == mft_observation.id
        assert correlation.value[0]["sample_physical_segments"][0]["physical_offset"] == 8192
        assert len(result.findings) == 1
        assert result.findings[0].category == "ntfs_usn_mft_correlation"


def test_exfat_deleted_nofatchain_recovery_zero_fills_uninitialized_tail(tmp_path: Path) -> None:
    source = tmp_path / "exfat.raw"
    image = bytearray(4096)
    payload = b"CTF{exfat_deleted_child}"
    physical_offset = 1536
    image[physical_offset:physical_offset + len(payload)] = payload
    image[physical_offset + len(payload):physical_offset + 80] = b"X" * (80 - len(payload))
    source.write_bytes(image)
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "exfat-deleted", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        workspace.database.add_observations([
            Observation(root.id, "filesystem.exfat.bytes_per_sector", 512, "test"),
            Observation(root.id, "filesystem.exfat.sectors_per_cluster", 1, "test"),
            Observation(root.id, "filesystem.exfat.cluster_size", 512, "test"),
            Observation(root.id, "filesystem.exfat.cluster_heap_offset_sectors", 2, "test"),
            Observation(root.id, "filesystem.exfat.fat_offset_sectors", 1, "test"),
            Observation(root.id, "filesystem.exfat.fat_length_sectors", 1, "test"),
            Observation(root.id, "filesystem.exfat.cluster_count", 6, "test"),
            Observation(root.id, "filesystem.exfat.subdirectory_deleted_file_sets", [{
                "entry_index": 0, "offset": 1024, "entry_offsets": [1024, 1056, 1088],
                "name": "deleted.bin", "attributes": "0x0020", "stream_flags": "0x02",
                "first_cluster": 3, "data_length": 80, "valid_data_length": len(payload),
                "stored_set_checksum": "0x1234", "checksum_valid_after_in_use_restore": True,
                "allocation_bitmap_state": "one_or_more_clusters_currently_allocated_possible_reuse",
                "allocation_reuse_warning": True,
                "directory_start_cluster": 7, "directory_cluster_lineage": [7],
                "directory_source_entry_offset": 2560,
            }], "test"),
        ])

        result = ExtractionManager(workspace, config.limits).extract_exfat_deleted_contiguous(root)

        assert [item.logical_name for item in result.artifacts] == ["deleted.bin"]
        child = result.artifacts[0]
        recovered = workspace.resolve_stored_path(child.path).read_bytes()
        assert recovered == payload + b"\x00" * (80 - len(payload))
        assert b"X" not in recovered
        evidence = result.findings[0].supporting_evidence[0]
        assert "physical_offset:1536" in evidence
        assert f"zero_fill_offset:{len(payload)}" in evidence
        assert "allocation_state:one_or_more_clusters_currently_allocated_possible_reuse" in evidence
        assert "allocation_reuse_warning:True" in evidence
        assert "directory_cluster_lineage:[7]" in evidence
        flags = FlagHunter(config.flag_patterns).scan(workspace.resolve_stored_path(child.path), child)
        assert any(item.value == "CTF{exfat_deleted_child}" for item in flags)


def test_exfat_deleted_fat_chain_requires_exact_eoc_and_keeps_segments(tmp_path: Path) -> None:
    source = tmp_path / "exfat-chain.raw"
    image = bytearray(4096)
    image[512 + 3 * 4:512 + 3 * 4 + 4] = (5).to_bytes(4, "little")
    image[512 + 5 * 4:512 + 5 * 4 + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    payload = b"A" * 512 + b"CTF{exfat_fat_chain}"
    image[1536:2048] = payload[:512]
    image[2560:2560 + len(payload[512:])] = payload[512:]
    source.write_bytes(image)
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "exfat-chain", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        observations = [
            Observation(root.id, "filesystem.exfat.bytes_per_sector", 512, "test"),
            Observation(root.id, "filesystem.exfat.sectors_per_cluster", 1, "test"),
            Observation(root.id, "filesystem.exfat.cluster_size", 512, "test"),
            Observation(root.id, "filesystem.exfat.cluster_heap_offset_sectors", 2, "test"),
            Observation(root.id, "filesystem.exfat.fat_offset_sectors", 1, "test"),
            Observation(root.id, "filesystem.exfat.fat_length_sectors", 1, "test"),
            Observation(root.id, "filesystem.exfat.cluster_count", 6, "test"),
            Observation(root.id, "filesystem.exfat.deleted_file_sets", [{
                "entry_index": 0, "offset": 1024, "entry_offsets": [1024, 1056, 1088],
                "name": "chain.bin", "attributes": "0x0020", "stream_flags": "0x00",
                "first_cluster": 3, "data_length": len(payload), "valid_data_length": len(payload),
                "stored_set_checksum": "0x5678", "checksum_valid_after_in_use_restore": True,
            }], "test"),
        ]
        workspace.database.add_observations(observations)

        result = ExtractionManager(workspace, config.limits).extract_exfat_deleted_contiguous(root)

        assert len(result.artifacts) == 1
        assert workspace.resolve_stored_path(result.artifacts[0].path).read_bytes() == payload
        evidence = result.findings[0].supporting_evidence[0]
        assert "mapping_mode:fat_chain_eoc" in evidence
        assert "'cluster': 3" in evidence and "'cluster': 5" in evidence
        flags = FlagHunter(config.flag_patterns).scan(
            workspace.resolve_stored_path(result.artifacts[0].path), result.artifacts[0]
        )
        assert any(item.value == "CTF{exfat_fat_chain}" for item in flags)


def test_ext_root_regular_file_recovery_keeps_inode_and_segment_provenance(tmp_path: Path) -> None:
    source = tmp_path / "ext.raw"
    image = bytearray(4096)
    payload = b"CTF{ext_recursive_child}"
    image[2048:2048 + len(payload)] = payload
    source.write_bytes(image)
    config = ForensicKitConfig()
    with CaseWorkspace.create(tmp_path / "cases", "ext-root", config) as workspace:
        root = EvidenceManager(workspace).ingest(source)
        workspace.database.add_observations([
            Observation(root.id, "filesystem.ext.root.recoverable_regular_files", [{
                "name": "flag.txt", "directory_entry_offset": 1536,
                "inode": 12, "inode_offset": 1408, "inode_mode": "0x81A4",
                "inode_flags": "0x00080000", "link_count": 1,
                "size": len(payload), "mapping_mode": "ext4_depth0_extents",
                "directory_inode": 13, "directory_inode_offset": 1536,
                "directory_path": "/sub", "directory_inode_lineage": [2, 13],
                "directory_source_entry_offset": 1024, "directory_block_lineage": [3],
                "data_segments": [{
                    "logical_offset": 0, "physical_block": 4,
                    "physical_offset": 2048, "length": len(payload),
                }],
            }], "test"),
        ])

        result = ExtractionManager(workspace, config.limits).extract_supported(root)

        assert [item.logical_name for item in result.artifacts] == ["flag.txt"]
        child = result.artifacts[0]
        assert workspace.resolve_stored_path(child.path).read_bytes() == payload
        evidence = result.findings[0].supporting_evidence[0]
        assert "inode:12" in evidence and "inode_offset:1408" in evidence
        assert "physical_offset': 2048" in evidence
        assert "directory_path:/sub" in evidence and "directory_inode_lineage:[2, 13]" in evidence
        flags = FlagHunter(config.flag_patterns).scan(workspace.resolve_stored_path(child.path), child)
        assert any(item.value == "CTF{ext_recursive_child}" for item in flags)


def test_doctor_validates_staged_offline_bundle_hashes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "manifests").mkdir(parents=True)
    (bundle / "wheels").mkdir()
    source = bundle / "forensickit-source.tar.gz"
    wheel = bundle / "wheels" / "forensickit-0.1-py3-none-any.whl"
    source.write_bytes(b"source")
    wheel.write_bytes(b"wheel")
    (bundle / "manifests" / "build-manifest.env").write_text("BUNDLE_FORMAT=forensickit-offline-v1\n", encoding="utf-8")
    entries = [source, wheel, bundle / "manifests" / "build-manifest.env"]
    (bundle / "manifests" / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(bundle)}\n" for path in entries),
        encoding="utf-8",
    )

    checks = Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
    bundle_check = next(check for check in checks if check.name == "Offline bundle")

    assert bundle_check.status == "OK"


def test_doctor_rejects_offline_bundle_checksum_mismatch(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "manifests").mkdir(parents=True)
    (bundle / "wheels").mkdir()
    (bundle / "forensickit-source.tar.gz").write_bytes(b"source")
    (bundle / "wheels" / "forensickit-0.1-py3-none-any.whl").write_bytes(b"wheel")
    (bundle / "manifests" / "build-manifest.env").write_text("BUNDLE_FORMAT=forensickit-offline-v1\n", encoding="utf-8")
    (bundle / "manifests" / "SHA256SUMS").write_text(
        f"{'0' * 64}  ./forensickit-source.tar.gz\n", encoding="utf-8",
    )

    checks = Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
    bundle_check = next(check for check in checks if check.name == "Offline bundle")

    assert bundle_check.status == "BROKEN"
    assert "checksum mismatch" in bundle_check.detail


def test_doctor_warns_when_valid_bundle_targets_other_architecture(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "manifests").mkdir(parents=True)
    (bundle / "wheels").mkdir()
    source = bundle / "forensickit-source.tar.gz"
    wheel = bundle / "wheels" / "forensickit-0.1-py3-none-any.whl"
    source.write_bytes(b"source")
    wheel.write_bytes(b"wheel")
    metadata = bundle / "manifests" / "build-manifest.env"
    metadata.write_text("DISTRO_ID=unknown\nDISTRO_VERSION=unknown\nARCHITECTURE=impossible-arch\n", encoding="utf-8")
    entries = [source, wheel, metadata]
    (bundle / "manifests" / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(bundle)}\n" for path in entries),
        encoding="utf-8",
    )

    checks = Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
    bundle_check = next(check for check in checks if check.name == "Offline bundle")

    assert bundle_check.status == "WARN"
    assert "impossible-arch" in bundle_check.detail
