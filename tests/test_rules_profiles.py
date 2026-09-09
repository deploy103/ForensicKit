from __future__ import annotations

from pathlib import Path

from forensickit.engine import AnalysisEngine
from forensickit.evidence import EvidenceManager
from forensickit.models import (
    AnalysisMode, Artifact, Classification, Finding, Observation, ToolRun, ToolRunStatus,
)
from forensickit.planner import ToolPlanner
from forensickit.profiles import ProfileEngine, ToolRecommendation, merge_recommendations
from forensickit.rules import RuleEngine
from forensickit.tools.registry import ToolDefinition, ToolRegistry
from forensickit.triage import GenericTriageEngine
from forensickit.workspace import CaseWorkspace


ROOT = Path(__file__).resolve().parents[1]


def artifact(
    artifact_type: str = "unknown",
    *,
    mime: str | None = None,
    magic: str | None = None,
    classifications: list[Classification] | None = None,
) -> Artifact:
    return Artifact(
        id="artifact-1",
        case_id="case-1",
        path="evidence/example.bin",
        logical_name="example.bin",
        sha256="0" * 64,
        size=4096,
        mime=mime,
        magic=magic,
        artifact_type=artifact_type,
        classifications=classifications or [],
    )


def observation(key: str, value: object, *, artifact_id: str = "artifact-1") -> Observation:
    return Observation(artifact_id=artifact_id, key=key, value=value, source="test")


def test_example_rules_load_and_explain_png_match() -> None:
    engine = RuleEngine.from_yaml(ROOT / "config" / "rules.example.yaml")
    assert not engine.validation_errors
    assert len(engine.rules) == 4

    result = engine.evaluate(
        artifact("image", mime="image/png"),
        [
            # The shipped rule uses canonical artifact.format while current
            # generic triage deliberately records its derivation in this key.
            observation("triage.detected_header_format", "png"),
            observation("png.bytes_after_iend", 130),
            observation("embedded.pk_signature", True),
        ],
        profiles={"generic", "image", "steganography", "archive"},
    )

    assert result.fired_rule_ids == ["png_appended_payload", "png_appended_zip"]
    assert {finding.category for finding in result.findings} == {
        "structural_anomaly",
        "embedded_archive",
    }
    assert all(finding.artifact_id == "artifact-1" for finding in result.findings)
    assert all(finding.source.startswith("rule:") for finding in result.findings)
    assert "actual 130" in " ".join(result.fired_rules[0].reasons)

    recommendations = {item.tool: item for item in result.recommendations}
    assert set(recommendations) == {"binwalk3", "sevenzip", "zsteg"}
    assert recommendations["binwalk3"].allowed_modes == {
        AnalysisMode.AUTO,
        AnalysisMode.DEEP,
    }
    assert recommendations["zsteg"].allowed_modes == {AnalysisMode.DEEP}
    assert "png_appended_payload" in recommendations["binwalk3"].reason
    assert "png_appended_zip" in recommendations["binwalk3"].reason


def test_rule_operators_nested_any_artifact_type_and_profile() -> None:
    engine = RuleEngine.from_data(
        {
            "rules": [
                {
                    "id": "operators",
                    "profiles": ["image"],
                    "when": {
                        "all": [
                            {"artifact_type": ["image", "png"]},
                            {"profile": "image"},
                            {"observation": "format", "equals": "png"},
                            {"observation": "count", "greater_than": 3},
                            {"observation": "count", "less_than": 10},
                            {"observation": "tags", "contains": "secret"},
                            {"observation": "missing", "exists": False},
                            {"observation": "status", "not_equals": "broken"},
                            {
                                "any": [
                                    {"observation": "never", "equals": True},
                                    {"observation": "marker", "exists": True},
                                ]
                            },
                        ]
                    },
                    "emit": {"recommend": {"auto": ["file"]}},
                }
            ]
        }
    )
    assert not engine.validation_errors

    result = engine.evaluate(
        artifact(
            "png",
            classifications=[Classification("image", 0.99, "signature")],
        ),
        [
            observation("format", "png"),
            observation("count", "7"),
            observation("tags", ["ctf", "secret"]),
            observation("status", "ok"),
            observation("marker", 0),
        ],
        profiles={"image"},
    )
    assert result.fired_rule_ids == ["operators"]
    assert len(result.fired_rules[0].reasons) == 9
    assert result.recommendations[0].tool == "file"


def test_rule_conditions_use_prior_findings_and_tool_results_and_emit_actions() -> None:
    engine = RuleEngine.from_data({"rules": [{
        "id": "verify_then_extract",
        "when": {"all": [
            {"finding": {"category": "embedded_archive", "minimum_confidence": 0.8}, "exists": True},
            {"tool_result": {"tool": "binwalk3", "status": "completed", "exit_code": 0}, "exists": True},
        ]},
        "emit": {
            "observations": [{"key": "archive.verified", "value": True, "confidence": 0.95}],
            "confidence_changes": [{
                "target": "classification:archive", "delta": 0.15,
                "reason": "independent parser confirmation",
            }],
            "parser_actions": [{"parser": "sevenzip", "tool": "sevenzip", "priority": 93}],
            "extractor_actions": [{
                "extractor": "sevenzip", "tool": "sevenzip", "modes": ["deep"],
                "command_mode": "extract", "priority": 88,
            }],
        },
    }]})
    target = artifact(
        "archive",
        classifications=[Classification("archive", 0.9, "validated archive structure")],
    )
    prior_finding = Finding(
        artifact_id=target.id, title="Embedded archive", category="embedded_archive",
        severity="medium", confidence=0.9, explanation="signature", source="test",
    )
    prior_run = ToolRun(
        artifact_id=target.id, tool="binwalk3", command_argv=["binwalk3"], timeout=10,
        status=ToolRunStatus.COMPLETED, exit_code=0,
    )

    result = engine.evaluate(target, findings=[prior_finding], tool_runs=[prior_run])

    assert not engine.validation_errors
    assert result.fired_rule_ids == ["verify_then_extract"]
    assert result.observations[0].key == "archive.verified"
    assert result.observations[0].source == "rule:verify_then_extract"
    assert result.confidence_changes[0].delta == 0.15
    assert result.confidence_changes[0].status == "applied"
    assert result.confidence_changes[0].previous_confidences == (0.9,)
    assert result.confidence_changes[0].updated_confidences == (1.0,)
    assert target.classifications[0].confidence == 1.0
    assert {action.kind for action in result.actions} == {"parser", "extractor"}
    action_audits = [item for item in result.observations if item.key.endswith("_action")]
    assert all(item.value["disposition"] == "tool_recommendation" for item in action_audits)
    recommendations = {(item.tool, item.command_mode): item for item in result.recommendations}
    assert recommendations[("sevenzip", "default")].allows(AnalysisMode.AUTO)
    assert recommendations[("sevenzip", "extract")].allowed_modes == {AnalysisMode.DEEP}
    assert "prior tool result matched" in recommendations[("sevenzip", "extract")].reason


def test_rule_confidence_change_is_bounded_auditable_and_idempotent() -> None:
    engine = RuleEngine.from_data({"rules": [{
        "id": "raise_archive_confidence",
        "when": {"artifact_type": "archive"},
        "emit": {"confidence_changes": [{
            "target": "classification:archive",
            "delta": 0.7,
            "reason": "independent structure validation",
        }]},
    }]})
    target = artifact(
        "archive",
        classifications=[Classification("archive", 0.45, "weak archive signature")],
    )

    first = engine.evaluate(target)
    audit = next(item for item in first.observations if item.key == "rule.confidence_change")
    second = engine.evaluate(target, first.observations)

    assert target.classifications[0].confidence == 1.0
    assert first.confidence_changes[0].status == "applied"
    assert first.confidence_changes[0].previous_confidences == (0.45,)
    assert first.confidence_changes[0].updated_confidences == (1.0,)
    assert audit.value["status"] == "applied"
    assert audit.value["detail"].endswith("clamped to [0, 1]")
    assert second.confidence_changes[0].status == "already_applied"
    assert not any(item.key == "rule.confidence_change" for item in second.observations)


def test_engine_persists_rule_confidence_change_before_planner_scoring(tmp_path: Path) -> None:
    source = tmp_path / "weak.zip"
    source.write_bytes(b"PK\x03\x04payload")
    executable = tmp_path / "verifier"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([ToolDefinition(
        "verifier",
        (str(executable),),
        profiles=("archive",),
        minimum_confidence=0.6,
        command_templates={"default": ("{executable}", "{evidence}")},
    )])
    analysis = AnalysisEngine()
    analysis.profiles = ProfileEngine([])
    analysis.rules = RuleEngine.from_data({"rules": [{
        "id": "confirm_archive",
        "when": {"artifact_type": "archive"},
        "emit": {"confidence_changes": [{
            "target": "classification:archive",
            "delta": 0.25,
            "reason": "validated directory structure",
        }]},
    }]})

    with CaseWorkspace.create(tmp_path / "cases", "confidence-integration") as workspace:
        target = EvidenceManager(workspace).ingest(source)
        target.artifact_type = "archive"
        target.classifications = [Classification("archive", 0.4, "weak signature")]
        workspace.database.update_artifact_identification(target)

        _, rule_result = analysis._decide(workspace, target, [])
        plans = ToolPlanner(workspace, registry).plan(
            target,
            [ToolRecommendation(
                "verifier", frozenset({AnalysisMode.AUTO}), "verify archive", 80,
            )],
            AnalysisMode.AUTO,
        )
        persisted = workspace.database.artifact_by_hash(target.case_id, target.sha256)

    assert rule_result.confidence_changes[0].applied is True
    assert persisted is not None
    assert persisted.classifications[0].confidence == 0.65
    assert plans[0].evidence_confidence == 0.65
    assert plans[0].available is True


def test_rule_confidence_change_without_matching_classification_is_recorded_as_rejected() -> None:
    engine = RuleEngine.from_data({"rules": [{
        "id": "missing_target",
        "when": {"artifact_type": "archive"},
        "emit": {"confidence_changes": [{
            "target": "classification:archive",
            "delta": 0.1,
            "reason": "parser evidence",
        }]},
    }]})

    result = engine.evaluate(artifact("archive"))

    assert result.confidence_changes[0].status == "rejected"
    audit = next(item for item in result.observations if item.key == "rule.confidence_change")
    assert audit.value["status"] == "rejected"
    assert "no classification matching" in audit.value["detail"]


def test_rule_rejects_unsupported_confidence_targets_and_toolless_actions() -> None:
    engine = RuleEngine.from_data({"rules": [
        {
            "id": "unsupported_confidence",
            "when": {"artifact_type": "archive"},
            "emit": {"confidence_changes": [{
                "target": "hypothesis:embedded_archive",
                "delta": 0.1,
                "reason": "not persistently actionable",
            }]},
        },
        {
            "id": "tool_less_actions",
            "when": {"artifact_type": "archive"},
            "emit": {
                "parser_actions": [{"parser": "sevenzip"}],
                "extractor_actions": [{"extractor": "sevenzip"}],
            },
        },
        {
            "id": "valid",
            "when": {"artifact_type": "archive"},
            "emit": {"recommend": {"auto": ["sevenzip"]}},
        },
    ]})

    assert [rule.id for rule in engine.rules] == ["valid"]
    messages = [str(error) for error in engine.validation_errors]
    assert any("classification:<artifact_type>" in message for message in messages)
    assert sum("tool is required" in message for message in messages) == 2


def test_rule_rejects_unbounded_action_parameters() -> None:
    engine = RuleEngine.from_data({"rules": [{
        "id": "too_many_parameters",
        "when": {"artifact_type": "archive"},
        "emit": {"parser_actions": [{
            "parser": "sevenzip",
            "tool": "sevenzip",
            "parameters": {f"value_{index}": index for index in range(17)},
        }]},
    }]})

    assert not engine.rules
    assert any("at most 16" in str(error) for error in engine.validation_errors)


def test_rule_prior_state_exists_false_is_explainable() -> None:
    engine = RuleEngine.from_data({"rules": [{
        "id": "fallback",
        "when": {"tool_result": "sevenzip", "exists": False},
        "emit": {"recommend": {"deep": ["binwalk3"]}},
    }]})
    result = engine.evaluate(artifact())
    assert result.fired_rule_ids == ["fallback"]
    assert "is absent" in result.fired_rules[0].reasons[0]


def test_malformed_rules_are_isolated_from_valid_rules() -> None:
    engine = RuleEngine.from_data(
        {
            "rules": [
                {
                    "id": "bad",
                    "when": {"all": []},
                    "emit": {"recommend": {"auto": "not-a-list"}},
                },
                {
                    "id": "good",
                    "when": {"observation": "present", "exists": True},
                    "emit": {
                        "findings": [{"title": "Present", "category": "test"}],
                        "recommend": {"deep": ["binwalk3"]},
                    },
                },
            ]
        }
    )
    assert [rule.id for rule in engine.rules] == ["good"]
    assert engine.validation_errors

    result = engine.evaluate(artifact(), [observation("present", False)])
    assert result.fired_rule_ids == ["good"]
    assert result.validation_errors == list(engine.validation_errors)
    assert result.findings[0].explanation.startswith("Rule good fired because")


def test_invalid_yaml_becomes_validation_error(tmp_path: Path) -> None:
    rules = tmp_path / "bad.yaml"
    rules.write_text("rules:\n  - id: [unterminated", encoding="utf-8")
    engine = RuleEngine.from_yaml(rules)
    assert not engine.rules
    assert len(engine.validation_errors) == 1
    assert "safely load YAML" in engine.validation_errors[0].message


def test_cyclic_yaml_rule_is_isolated(tmp_path: Path) -> None:
    rules = tmp_path / "cyclic.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: cyclic\n"
        "    when: &condition\n"
        "      all: [*condition]\n"
        "    emit: {}\n"
        "  - id: valid\n"
        "    when: {observation: marker, exists: true}\n"
        "    emit: {recommend: {auto: [file]}}\n",
        encoding="utf-8",
    )
    engine = RuleEngine.from_yaml(rules)
    assert [rule.id for rule in engine.rules] == ["valid"]
    assert engine.validation_errors
    assert engine.evaluate(artifact(), [observation("marker", 0)]).fired_rule_ids == ["valid"]


def test_triage_observations_connect_to_profiles_and_shipped_rules(tmp_path: Path) -> None:
    # The triage parser only needs chunk bounds here; CRC values are retained
    # as opaque bytes and pngcheck is recommended for external verification.
    png = (
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + b"\x00" * 13
        + b"\x00" * 4
        + (0).to_bytes(4, "big")
        + b"IEND"
        + b"\x00" * 4
        + b"PK\x03\x04hidden"
    )
    evidence = tmp_path / "challenge.png"
    evidence.write_bytes(png)
    target = artifact("unknown")
    target.size = len(png)
    target.logical_name = evidence.name

    observations = GenericTriageEngine().analyze(target, evidence)
    profile_result = ProfileEngine().evaluate(target, observations)
    rule_result = RuleEngine.from_yaml(ROOT / "config" / "rules.example.yaml").evaluate(
        target, observations, profiles=profile_result.active_profiles
    )

    assert {"generic", "image", "steganography"} <= profile_result.active_profiles
    assert rule_result.fired_rule_ids == ["png_appended_payload", "png_appended_zip"]
    assert {item.tool for item in rule_result.recommendations} == {
        "binwalk3",
        "sevenzip",
        "zsteg",
    }


def test_profile_engine_generic_image_stego_findings_and_dedupe() -> None:
    result = ProfileEngine().evaluate(
        artifact("image", mime="image/png"),
        [
            observation("artifact.format", "png"),
            observation("png.bytes_after_iend", 42),
            observation("embedded.pk_signature", True),
        ],
    )

    assert result.profiles == ["generic", "image", "steganography"]
    assert "generic triage applies to every artifact" in result.reasons["generic"]
    assert {finding.category for finding in result.findings} == {
        "structural_anomaly",
        "embedded_archive",
    }
    recommendations = {item.tool: item for item in result.recommendations}
    assert {"file", "exiftool", "pngcheck", "binwalk3", "sevenzip", "zsteg"} <= set(
        recommendations
    )
    assert recommendations["binwalk3"].priority == 120
    assert "trailing" in recommendations["binwalk3"].reason
    assert "PK/ZIP" in recommendations["binwalk3"].reason
    assert recommendations["zsteg"].allowed_modes == {AnalysisMode.DEEP}


def test_pdf_embedded_file_marker_adds_safe_attachment_recovery_plan() -> None:
    result = ProfileEngine().evaluate(
        artifact("pdf", mime="application/pdf"),
        [
            observation("artifact.format", "pdf"),
            observation("pdf.embedded_file_marker_count", 1),
        ],
    )
    recommendations = {item.tool: item for item in result.recommendations}
    assert {"pdfid", "pdfinfo", "pdftotext", "qpdf", "pdfdetach", "pdfimages"} <= set(recommendations)
    assert recommendations["pdfdetach"].allowed_modes == {AnalysisMode.DEEP}
    assert recommendations["pdfimages"].allowed_modes == {AnalysisMode.DEEP}


def test_windows_profile_promotes_allowlisted_registry_path_command() -> None:
    result = ProfileEngine().evaluate(
        artifact("registry"),
        [
            observation("windows.registry_signature", True),
            observation("registry.persistence_path_values", [{
                "key_path": "software\\microsoft\\windows\\currentversion\\run",
                "key": "Run", "name": "Updater", "type": "REG_SZ",
                "data_text": r"C:\\CTF\\runner.exe --quiet",
            }]),
            observation("registry.execution_value_data", [{
                "key_path": "software\\microsoft\\windows\\currentversion\\run",
                "key": "Run", "name": "Updater", "type": "REG_SZ",
                "data_text": r"C:\\CTF\\runner.exe --quiet",
            }]),
        ],
    )
    commands = [finding for finding in result.findings if finding.category == "registry_execution_command"]
    assert len(commands) == 1
    assert "software\\microsoft\\windows\\currentversion\\run" in commands[0].supporting_evidence[0]


def test_windows_profile_correlates_normalized_event_record_to_native_offset() -> None:
    result = ProfileEngine().evaluate(
        artifact("evtx"),
        [
            observation("windows.evtx_signature", True),
            observation("evtx.record_headers", [{
                "chunk_index": 2,
                "offset": 0x21000,
                "size": 384,
                "record_id": 77,
                "timestamp": "2026-09-03T01:02:03+00:00",
            }]),
            observation("windows.event_hunt.normalized_events", [{
                "source_record_index": 4,
                "event_id": "4688",
                "event_record_id": 77,
                "category": "process_creation",
                "timestamp": "2026-09-03T01:02:03Z",
            }]),
        ],
    )

    correlations = next(
        item.value for item in result.observations
        if item.key == "evtx.normalized_record_correlations"
    )
    assert correlations == [{
        "event_record_id": 77,
        "event_id": "4688",
        "category": "process_creation",
        "record_offset": 0x21000,
        "record_size": 384,
        "chunk_index": 2,
        "native_timestamp": "2026-09-03T01:02:03+00:00",
        "parser_timestamp": "2026-09-03T01:02:03Z",
        "source_record_index": 4,
    }]
    assert any(item.category == "evtx_record_content_correlation" for item in result.findings)


def test_windows_profile_clusters_and_scores_bounded_event_sequences() -> None:
    headers = [
        {"record_id": record_id, "offset": offset, "size": 64, "chunk_index": 0, "timestamp": None}
        for record_id, offset in ((1, 4608), (2, 4672), (3, 4736), (4, 4800))
    ]
    execution = {
        "source_record_index": 0, "event_id": "4688", "event_record_id": 1,
        "category": "process_creation", "timestamp": "2026-09-03T01:00:00Z",
        "process_path": r"C:\\Temp\\payload.exe",
    }
    result = ProfileEngine().evaluate(
        artifact("evtx"),
        [
            observation("windows.evtx_signature", True),
            observation("evtx.record_headers", headers),
            observation("windows.event_hunt.normalized_events", [
                execution,
                {
                    "source_record_index": 1, "event_id": "7045", "event_record_id": 2,
                    "category": "service_install", "timestamp": "2026-09-03T01:05:00+00:00",
                    "service_name": "ctfsvc",
                },
                {
                    "source_record_index": 2, "event_id": "1102", "event_record_id": 3,
                    "category": "log_cleared", "timestamp": "2026-09-03T01:10:00Z",
                    "user": "analyst",
                },
                {
                    "source_record_index": 3, "event_id": "5007", "event_record_id": 4,
                    "category": "defender_change", "timestamp": "2026-09-03T01:11:00",
                },
            ]),
            # The same record from another parser must not inflate the score.
            observation("windows.event_timeline.normalized_events", [execution.copy()]),
        ],
    )

    clusters = next(
        item.value for item in result.observations
        if item.key == "windows.event_activity_clusters"
    )
    assert len(clusters) == 1
    assert clusters[0]["event_count"] == 3
    assert clusters[0]["category_counts"] == {
        "log_cleared": 1, "process_creation": 1, "service_install": 1,
    }
    assert clusters[0]["score"] == 16
    assert clusters[0]["level"] == "high"
    assert [item["record_offset"] for item in clusters[0]["events"]] == [4608, 4672, 4736]
    finding = next(item for item in result.findings if item.category == "windows_event_activity_cluster")
    assert finding.severity == "high"


def test_archive_pcap_memory_and_disk_profiles_are_signature_driven() -> None:
    archive_result = ProfileEngine().evaluate(
        artifact("unknown"),
        [
            observation("triage.detected_header_format", "zip"),
            observation("archive.zip.encrypted_entries", 1),
        ],
    )
    assert "archive" in archive_result.profiles
    assert any(item.tool == "sevenzip" for item in archive_result.recommendations)
    assert archive_result.findings[0].category == "encrypted_container"

    pcap_result = ProfileEngine().evaluate(
        artifact("unknown", magic="pcap capture file, microsecond ts"),
        [
            observation("pcap.dns.long_labels", True),
            observation("pcap.dns.query_count", 40),
        ],
    )
    assert "pcap" in pcap_result.profiles
    assert {item.tool for item in pcap_result.recommendations} >= {"capinfos", "tshark"}
    assert pcap_result.findings[0].category == "possible_dns_encoding"

    memory_result = ProfileEngine().evaluate(
        artifact("unknown"), [observation("signature.memory_dump", True)]
    )
    assert "memory" in memory_result.profiles
    assert any(item.tool == "volatility3" for item in memory_result.recommendations)

    disk_result = ProfileEngine().evaluate(
        artifact("unknown"), [observation("disk.gpt_signature", True)]
    )
    assert "disk" in disk_result.profiles
    disk_tools = {item.tool: item for item in disk_result.recommendations}
    assert disk_tools["sleuthkit_mmls"].allowed_modes == {
        AnalysisMode.AUTO,
        AnalysisMode.DEEP,
    }
    assert "sleuthkit_fls" not in disk_tools
    assert any(finding.category == "disk_partition_workflow" for finding in disk_result.findings)

    raw_filesystem = ProfileEngine().evaluate(
        artifact("filesystem"), [observation("filesystem.signature_detected", True)]
    )
    raw_tools = {item.tool: item for item in raw_filesystem.recommendations}
    assert raw_tools["sleuthkit_fls"].allowed_modes == {AnalysisMode.DEEP}
    assert raw_tools["sleuthkit_fsstat"].allowed_modes == {AnalysisMode.AUTO, AnalysisMode.DEEP}

    partition_offset_result = ProfileEngine().evaluate(
        artifact("disk"), [
            observation("disk.mbr_signature", True),
            observation("disk.mbr.partitions", [{"start_lba": 2048, "within_image": True}]),
        ],
    )
    offset_fls = [item for item in partition_offset_result.recommendations if item.tool == "sleuthkit_fls"]
    assert len(offset_fls) == 1
    assert offset_fls[0].command_mode == "offset"
    assert offset_fls[0].parameters == {"partition_offset": "2048"}
    offset_fsstat = [item for item in partition_offset_result.recommendations if item.tool == "sleuthkit_fsstat"]
    assert len(offset_fsstat) == 1
    assert offset_fsstat[0].parameters == {"partition_offset": "2048"}

    parser_offset_result = ProfileEngine().evaluate(
        artifact("disk"), [
            observation("disk.partitions", [
                {"slot": "002:000", "start": 4096, "description": "Linux (0x83)"},
                {"slot": "000:000", "start": 0, "description": "Primary Table (#0)"},
                {"slot": "001:000", "start": 34, "description": "Unallocated"},
            ]),
        ],
    )
    parser_fls = [item for item in parser_offset_result.recommendations if item.tool == "sleuthkit_fls"]
    assert len(parser_fls) == 1
    assert parser_fls[0].parameters == {"partition_offset": "4096"}
    parser_fsstat = [item for item in parser_offset_result.recommendations if item.tool == "sleuthkit_fsstat"]
    assert len(parser_fsstat) == 1
    assert parser_fsstat[0].parameters == {"partition_offset": "4096"}


def test_disk_profile_promotes_normalized_ewf_metadata() -> None:
    result = ProfileEngine().evaluate(
        artifact("disk"), [
            observation("disk.ewf_signature", True),
            observation("disk.ewf.media_size_bytes", 1_073_741_824),
            observation("disk.ewf.segment_count", 3),
        ],
    )
    assert any(item.tool == "ewfinfo" for item in result.recommendations)
    metadata = [finding for finding in result.findings if finding.category == "ewf_metadata"]
    assert len(metadata) == 1
    assert "reported_segment_count=3" in metadata[0].supporting_evidence


def test_image_profile_promotes_recognized_jpeg_application_metadata() -> None:
    result = ProfileEngine().evaluate(
        artifact("jpeg"), [
            observation("artifact.format", "jpeg"),
            observation("jpeg.app_segments", [
                {"marker": "APP1", "offset": 2, "length": 10, "kind": "exif", "identifier_hex": "457869660000"},
                {"marker": "APP2", "offset": 16, "length": 20, "kind": "icc_profile", "identifier_hex": "4943435f50524f46494c4500"},
            ]),
            observation("jpeg.icc_profile_valid", False),
            observation("jpeg.icc_profile_error", "ICC_PROFILE chunk sequence is incomplete"),
        ],
    )

    metadata = [item for item in result.findings if item.category == "image_metadata_lead"]
    assert len(metadata) == 1
    assert "icc_profile" in metadata[0].supporting_evidence[1]
    assert any(item.category == "image_integrity_anomaly" for item in result.findings)


def test_image_profile_preserves_bounded_jpeg_exif_metadata_and_errors() -> None:
    valid = ProfileEngine().evaluate(
        artifact("jpeg"), [
            observation("artifact.format", "jpeg"),
            observation("jpeg.exif_entries", [{
                "offset": 2,
                "tags": {"make": "CTF Camera", "model": "Offline", "orientation": 6},
                "error": None,
            }]),
        ],
    )
    metadata = [item for item in valid.findings if item.category == "image_metadata_lead"]
    assert len(metadata) == 1
    assert "CTF Camera" in metadata[0].supporting_evidence[0]

    malformed = ProfileEngine().evaluate(
        artifact("jpeg"), [
            observation("artifact.format", "jpeg"),
            observation("jpeg.exif_entries", [{
                "offset": 2, "tags": {}, "error": "EXIF TIFF first IFD entry bounds are invalid",
            }]),
        ],
    )
    anomalies = [item for item in malformed.findings if item.category == "image_integrity_anomaly"]
    assert len(anomalies) == 1
    assert anomalies[0].supporting_evidence == ["EXIF TIFF first IFD entry bounds are invalid"]


def test_pcap_profile_promotes_tls_alpn_packet_provenance() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [
            observation("pcap.tls.client_hellos", [{
                "server_name": "ctf.example", "alpn_protocols": ["h2", "http/1.1"],
                "packet_index": 1, "source": "10.0.0.1", "destination": "10.0.0.2",
            }]),
        ],
    )
    findings = [item for item in result.findings if item.category == "pcap_tls_alpn"]
    assert len(findings) == 1
    assert "http/1.1" in findings[0].supporting_evidence[0]


def test_pcap_profile_promotes_tls_serverhello_selected_alpn() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [
            observation("pcap.tls.server_hellos", [{
                "selected_alpn": "h2", "cipher_suite": "0x1301", "packet_index": 2,
                "source": "10.0.0.2", "destination": "10.0.0.1",
            }]),
        ],
    )
    findings = [item for item in result.findings if item.category == "pcap_tls_alpn"]
    assert len(findings) == 1
    assert "0x1301" in findings[0].supporting_evidence[0]


def test_pcap_profile_promotes_tls_certificate_inventory_and_structural_errors() -> None:
    valid = ProfileEngine().evaluate(
        artifact("pcap"), [observation("pcap.tls.certificates", [{
            "certificate_count": 2, "certificate_sha256": ["a" * 64, "b" * 64],
            "packet_index": 4, "source": "10.0.0.2", "destination": "10.0.0.1",
        }])],
    )
    inventory = [item for item in valid.findings if item.category == "pcap_tls_certificate_inventory"]
    assert len(inventory) == 1
    assert "packet_index': 4" in inventory[0].supporting_evidence[0]

    malformed = ProfileEngine().evaluate(
        artifact("pcap"), [observation("pcap.tls.certificate_errors", [{"packet_index": 5, "error": "bad list"}])],
    )
    errors = [item for item in malformed.findings if item.category == "pcap_tls_structure_anomaly"]
    assert len(errors) == 1
    assert "bad list" in errors[0].supporting_evidence[0]


def test_pcap_profile_reports_tls_certificate_incomplete_flow() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [observation("pcap.tls.certificate_incomplete_flows", [{
            "packet_indices": [7, 8], "captured_length": 1024, "expected_length": 4096,
        }])],
    )
    findings = [item for item in result.findings if item.title.startswith("TLS Certificate capture ended")]
    assert len(findings) == 1
    assert "expected_length': 4096" in findings[0].supporting_evidence[0]


def test_pcap_profile_promotes_correlated_tls_alpn_offer_selection_mismatch() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [
            observation("pcap.tls.negotiations", [{
                "client_hello_packet_indices": [5], "server_hello_packet_index": 6,
                "server_name": "mismatch.ctf", "offered_alpn": ["h2"],
                "selected_alpn": "http/1.1", "selected_alpn_offered": False,
                "cipher_suite": "0x1301",
            }]),
        ],
    )
    findings = [item for item in result.findings if item.category == "pcap_tls_negotiation_anomaly"]
    assert len(findings) == 1
    assert "server_hello_packet_index': 6" in findings[0].supporting_evidence[0]


def test_pcap_profile_reports_tls_clienthello_flow_state_limit() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [observation("pcap.tls.client_hello_flow_state_truncated", True)]
    )
    findings = [item for item in result.findings if item.category == "pcap_analysis_limit"]
    assert len(findings) == 1
    assert "4,096-flow" in findings[0].explanation


def test_pcap_profile_reports_tls_serverhello_incomplete_flow() -> None:
    result = ProfileEngine().evaluate(
        artifact("pcap"), [observation("pcap.tls.server_hello_incomplete_flows", [{
            "packet_indices": [4], "captured_length": 19, "expected_length": 48,
        }])]
    )
    findings = [item for item in result.findings if item.title.startswith("TLS ServerHello capture ended")]
    assert len(findings) == 1
    assert "expected_length': 48" in findings[0].supporting_evidence[0]


def test_disk_profile_preserves_ntfs_usa_and_named_data_attribute_provenance() -> None:
    result = ProfileEngine().evaluate(
        artifact("filesystem"), [
            observation("filesystem.signature_detected", True),
            observation("filesystem.ntfs.mft0_valid_signature", True),
            observation("filesystem.ntfs.mft0_bounds_valid", True),
            observation("filesystem.ntfs.mft0_usa_fixup_valid", True),
            observation("filesystem.ntfs.mft0_timestamp_mismatches", [{
                "file_name": "$MFT", "field": "accessed",
                "standard_information": "2020-02-25T18:40:00+00:00",
                "file_name_timestamp": "2020-02-25T18:40:01+00:00",
            }]),
            observation("filesystem.ntfs.mft_sample_records", [{
                "record_number": 1, "deleted": True, "file_names": ["gone.txt"],
                "physical_segments": [{"logical_offset": 1024, "physical_offset": 1536, "length": 1024}],
                "standard_information": [{"file_attribute_names": ["hidden", "encrypted"]}],
                "index_root_entries": [{"record_number": 42, "file_name": "flag.txt", "attribute_offset": 56}],
                "index_allocation_entries": [{
                    "record_number": 43, "sequence_number": 2, "file_name": "deleted.txt",
                    "attribute_offset": 168, "entry_offset": 64,
                    "index_buffer": {"index_vcn": 7, "logical_offset": 0,
                                     "physical_segments": [{"physical_offset": 8192, "length": 1024}]},
                }],
                "index_allocation_slack_entries": [{
                    "record_number": 44, "sequence_number": 1, "file_name": "stale.tmp",
                    "slack_offset": 512, "slack_candidate": True, "confidence": 0.72,
                    "index_buffer": {"index_vcn": 7, "logical_offset": 0,
                                     "physical_segments": [{"physical_offset": 8192, "length": 1024}]},
                }],
            }]),
            observation("filesystem.ntfs.mft_sample_errors", ["record 2: mapped physical MFT range exceeds supplied image bounds"]),
            observation("filesystem.ntfs.mft_sample_record_anomalies", [{
                "record_number": 3, "failed_checks": ["usa_fixup_valid"],
                "usa_fixup_error": "USA sequence mismatch at sector 2", "physical_segments": [],
            }]),
            observation("filesystem.ntfs.mft_sample_parent_links", [{
                "child_record_number": 2, "file_name": "stale.txt", "parent_record_number": 1,
                "parent_sequence_number": 2, "parent_sampled": True, "parent_sequence_matches": False,
            }]),
            observation("filesystem.ntfs.mft_sample_index_links", [{
                "directory_record_number": 5, "file_name": "stale.txt", "child_record_number": 2,
                "child_sequence_number": 3, "child_sampled": True, "child_sequence_matches": False,
                "child_file_name_matches": False,
            }]),
            observation("filesystem.ntfs.mft_sample_attribute_list_links", [{
                "source_record_number": 2, "type_name": "data", "target_record_number": 1,
                "target_sequence_number": 2, "target_sampled": True, "target_sequence_matches": False,
            }]),
            observation("filesystem.ntfs.mft0_attributes", [{
                "type_name": "data", "name": "ads", "nonresident": True,
                "real_size": 900, "data_runs": [{"vcn": 0, "cluster_count": 2, "lcn": 5}],
            }, {
                "type_name": "index_allocation", "name": "$I30", "nonresident": True,
                "real_size": 4096, "data_runs": [{"vcn": 0, "cluster_count": 8, "lcn": 20}],
            }, {
                "type_name": "attribute_list", "extent_references": [{
                    "type_name": "data", "record_number": 42, "sequence_number": 7, "attribute_id": 9,
                }],
            }]),
        ],
    )

    named_data = [item for item in result.findings if item.category == "ntfs_named_data_attribute"]
    assert len(named_data) == 1
    assert "name='ads'" in named_data[0].supporting_evidence[0]
    assert "data_runs=[{'vcn': 0, 'cluster_count': 2, 'lcn': 5}]" in named_data[0].supporting_evidence[0]
    assert any(item.category == "ntfs_timestamp_mismatch_lead" for item in result.findings)
    assert any(item.category == "ntfs_deleted_record_lead" for item in result.findings)
    assert any(item.category == "ntfs_directory_index_inventory" for item in result.findings)
    assert any(item.category == "ntfs_index_allocation_inventory" for item in result.findings)
    assert any(item.category == "ntfs_index_slack_entry_lead" for item in result.findings)
    assert any(item.category == "ntfs_parent_reference_mismatch_lead" for item in result.findings)
    assert any(item.category == "ntfs_directory_index_mismatch_lead" for item in result.findings)
    assert any(item.category == "ntfs_index_allocation_metadata" for item in result.findings)
    assert any(item.category == "ntfs_special_file_attribute_lead" for item in result.findings)
    assert any(item.category == "ntfs_attribute_list_inventory" for item in result.findings)
    assert any(item.category == "ntfs_attribute_list_mismatch_lead" for item in result.findings)
    assert sum(item.category == "filesystem_structure_anomaly" for item in result.findings) == 2

    malformed = ProfileEngine().evaluate(
        artifact("filesystem"), [
            observation("filesystem.signature_detected", True),
            observation("filesystem.ntfs.mft0_valid_signature", True),
            observation("filesystem.ntfs.mft0_bounds_valid", True),
            observation("filesystem.ntfs.mft0_usa_fixup_valid", False),
            observation("filesystem.ntfs.mft0_usa_fixup_error", "USA sequence mismatch at sector 2"),
        ],
    )
    anomaly = [item for item in malformed.findings if item.category == "filesystem_structure_anomaly"]
    assert len(anomaly) == 1
    assert "USA sequence mismatch at sector 2" in anomaly[0].supporting_evidence[0]


def test_valid_minidump_metadata_does_not_select_full_system_plugins() -> None:
    result = ProfileEngine().evaluate(
        artifact("memory"), [
            observation("memory.minidump_valid", True),
            observation("memory.minidump.system_info", {"platform_id": 2, "architecture": "x64"}),
        ],
    )
    recommendations = {item.tool for item in result.recommendations}
    assert not recommendations & {
        "volatility3", "volatility3_windows_pslist", "volatility3_windows_cmdline",
        "volatility3_windows_netscan", "volatility3_windows_filescan",
    }
    assert any(item.category == "memory_minidump_scope" for item in result.findings)


def test_full_windows_memory_has_fast_auto_plugins_and_pid_deep_extractors() -> None:
    result = ProfileEngine().evaluate(
        artifact("memory"), [
            observation("memory.windows_crash_signature", True),
            observation("memory.requested_pids", [444]),
        ],
    )
    recommendations = {item.tool: item for item in result.recommendations}
    assert recommendations["volatility3_windows_info"].allows(AnalysisMode.AUTO)
    assert recommendations["volatility3_windows_pslist"].allows(AnalysisMode.AUTO)
    assert recommendations["volatility3_windows_pstree"].allows(AnalysisMode.AUTO)
    assert recommendations["volatility3_windows_cmdline"].allows(AnalysisMode.AUTO)
    assert not recommendations["volatility3_windows_psscan"].allows(AnalysisMode.AUTO)
    memmap = recommendations["volatility3_windows_memmap"]
    assert memmap.command_mode == "pid_dump"
    assert memmap.parameters == {"pid": "444"}


def test_windows_memory_kernel_info_is_exposed_as_cautious_finding() -> None:
    result = ProfileEngine().evaluate(
        artifact("memory"), [
            observation("memory.windows_crash_signature", True),
            observation("memory.volatility.kernel_info", {
                "Kernel Base": "0xf80000000000",
                "NtMajorVersion": "10",
            }),
        ],
    )

    finding = next(item for item in result.findings if item.category == "memory_kernel_info")
    assert "successful layer and symbol resolution" in finding.explanation
    assert "NtMajorVersion=10" in finding.supporting_evidence


def test_memory_parent_rule_reports_evidence_without_malware_verdict() -> None:
    result = ProfileEngine().evaluate(
        artifact("memory"), [
            observation("memory.windows_crash_signature", True),
            observation("memory.volatility.pslist", [
                {"Name": "evilparent.exe", "PID": "333", "PPID": "4"},
                {"Name": "svchost.exe", "PID": "444", "PPID": "333"},
            ]),
        ],
    )
    finding = next(
        item for item in result.findings
        if item.category == "memory_parent_relationship_lead"
    )
    assert "observed_parent" in finding.supporting_evidence[0]
    assert "not a malware verdict" in finding.explanation


def test_windows_profile_pairs_only_adjacent_exact_usn_rename_lineage() -> None:
    old = {
        "offset": 4096, "record_length": 80, "usn": 1000,
        "file_record_number": 42, "file_sequence_number": 3,
        "parent_record_number": 5, "parent_sequence_number": 2,
        "file_name": "old.txt", "timestamp": "2026-09-03T01:00:00+00:00",
        "reason_names": ["rename_old_name"],
    }
    new = {
        "offset": 4176, "record_length": 80, "usn": 1080,
        "file_record_number": 42, "file_sequence_number": 3,
        "parent_record_number": 6, "parent_sequence_number": 4,
        "file_name": "new.txt", "timestamp": "2026-09-03T01:00:01+00:00",
        "reason_names": ["rename_new_name"],
    }
    mismatched = {**new, "offset": 4256, "usn": 1160, "file_sequence_number": 4, "file_name": "wrong.txt"}
    result = ProfileEngine().evaluate(
        artifact("unknown"), [
            observation("ntfs.usn_journal_detected", True),
            observation("ntfs.usn.records", [old, new, mismatched]),
        ],
    )

    rename_observation = next(item for item in result.observations if item.key == "ntfs.usn.rename_pairs")
    assert rename_observation.value == [{
        "file_record_number": 42, "file_sequence_number": 3,
        "old_name": "old.txt", "new_name": "new.txt",
        "old_parent_record_number": 5, "old_parent_sequence_number": 2,
        "new_parent_record_number": 6, "new_parent_sequence_number": 4,
        "old_usn": 1000, "new_usn": 1080, "old_offset": 4096, "new_offset": 4176,
        "old_timestamp": "2026-09-03T01:00:00+00:00",
        "new_timestamp": "2026-09-03T01:00:01+00:00",
    }]
    finding = next(item for item in result.findings if item.category == "ntfs_usn_rename")
    assert "old.txt" in finding.supporting_evidence[0]
    assert "new.txt" in finding.supporting_evidence[0]


def test_elf_profile_selects_readelf_and_reports_parser_loader_path() -> None:
    result = ProfileEngine().evaluate(
        artifact("executable"), [
            observation("artifact.format", "elf"),
            observation("executable.readelf.search_paths", [".:/opt/ctf/lib"]),
        ],
    )
    assert any(item.tool == "readelf" and item.allows("auto") for item in result.recommendations)
    assert any(finding.category == "executable_runtime_metadata" for finding in result.findings)


def test_identification_profile_observations_participate_in_dispatch() -> None:
    target = artifact("unknown")
    result = ProfileEngine().evaluate(
        target,
        [
            observation("artifact.format", "png"),
            observation("artifact.profile", "image"),
            observation("artifact.profiles", ["image", "steganography"]),
        ],
    )
    assert result.active_profiles == {"generic", "image", "steganography"}

    rules = RuleEngine.from_data(
        {
            "rules": [
                {
                    "id": "inferred_profile",
                    "profiles": ["steganography"],
                    "when": {"profile": "steganography"},
                    "emit": {"recommend": {"deep": ["zsteg"]}},
                }
            ]
        }
    )
    rule_result = rules.evaluate(
        target, [observation("artifact.profiles", ["image", "steganography"])]
    )
    assert rule_result.fired_rule_ids == ["inferred_profile"]


def test_recommendation_merge_unions_modes_reasons_and_max_priority() -> None:
    merged = merge_recommendations(
        [
            ToolRecommendation("tshark", frozenset({AnalysisMode.AUTO}), "first reason", 50),
            ToolRecommendation("TSHARK", frozenset({AnalysisMode.DEEP}), "second reason", 90),
        ]
    )
    assert len(merged) == 1
    assert merged[0].allowed_modes == {AnalysisMode.AUTO, AnalysisMode.DEEP}
    assert merged[0].reason == "first reason | second reason"
    assert merged[0].priority == 90
    assert merged[0].allows(AnalysisMode.PLAN)
