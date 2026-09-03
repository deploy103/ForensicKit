from __future__ import annotations

from pathlib import Path

from forensickit.evidence import EvidenceManager
from forensickit.models import AnalysisMode, Classification
from forensickit.planner import ToolPlanner
from forensickit.profiles.base import ToolRecommendation
from forensickit.tools.registry import ToolDefinition, ToolRegistry
from forensickit.workspace import CaseWorkspace


def test_registry_builds_argv_without_shell_interpolation(tmp_path: Path) -> None:
    evidence = tmp_path / "odd name;$(touch nope).bin"
    evidence.write_bytes(b"sample")
    registry = ToolRegistry.default()
    command = registry.build_command("file", evidence)
    assert command[-1] == str(evidence.resolve())
    assert len(command) == 3
    assert "$(touch nope)" in command[-1]
    assert not (tmp_path / "nope").exists()


def test_planner_keeps_reason_when_tool_missing(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    with CaseWorkspace.create(tmp_path / "cases", "planner") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        recommendation = ToolRecommendation(
            "zsteg", frozenset({AnalysisMode.DEEP}), "PNG bit-plane anomaly", 70
        )
        plan = ToolPlanner(workspace, ToolRegistry.default()).plan(
            artifact, [recommendation], AnalysisMode.PLAN
        )
        assert len(plan) == 1
        assert plan[0].tool == "zsteg"
        assert plan[0].reasons == ["PNG bit-plane anomaly"]
        assert plan[0].available is False


def test_parameterized_tool_plan_keeps_partition_offset_as_distinct_argv_value(tmp_path: Path) -> None:
    source = tmp_path / "disk image.dd"
    source.write_bytes(b"disk")
    executable = tmp_path / "fls"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            "sleuthkit_fls", (str(executable),), parser="sleuthkit_fls",
            command_templates={"offset": ("{executable}", "-r", "-p", "-o", "{partition_offset}", "{evidence}")},
        )
    ])
    with CaseWorkspace.create(tmp_path / "cases", "partition-plan") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        recommendations = [
            ToolRecommendation(
                "sleuthkit_fls", frozenset({AnalysisMode.DEEP}), "first validated partition", 80,
                command_mode="offset", parameters={"partition_offset": "2048"},
            ),
            ToolRecommendation(
                "sleuthkit_fls", frozenset({AnalysisMode.DEEP}), "second validated partition", 80,
                command_mode="offset", parameters={"partition_offset": "4096"},
            ),
        ]
        plans = ToolPlanner(workspace, registry).plan(artifact, recommendations, AnalysisMode.DEEP)

    assert len(plans) == 2
    assert {item.parameters["partition_offset"] for item in plans} == {"2048", "4096"}
    assert {tuple(item.command_argv[-3:-1]) for item in plans} == {("-o", "2048"), ("-o", "4096")}


def test_planner_accepts_identified_elf_magic_for_readelf(tmp_path: Path) -> None:
    source = tmp_path / "sample.elf"
    source.write_bytes(b"\x7fELF" + b"\x00" * 128)
    executable = tmp_path / "readelf"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition("readelf", (str(executable),), accepts=("elf",), parser="readelf", command_templates={"default": ("{executable}", "{evidence}")}),
    ])
    with CaseWorkspace.create(tmp_path / "cases", "elf-plan") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        artifact.artifact_type = "executable"
        artifact.magic = "ELF 64-bit LSB pie executable"
        artifact.classifications = [Classification("executable", 0.99, "ELF header")]
        plans = ToolPlanner(workspace, registry).plan(
            artifact, [ToolRecommendation("readelf", frozenset({AnalysisMode.AUTO}), "inspect ELF", 90)], AnalysisMode.AUTO
        )

    assert len(plans) == 1
    assert plans[0].available is True


def test_planner_accepts_identified_android_apk_magic_for_jadx(tmp_path: Path) -> None:
    source = tmp_path / "sample.apk"
    source.write_bytes(b"PK\x03\x04" + b"\x00" * 128)
    executable = tmp_path / "jadx"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition("jadx", (str(executable),), accepts=("apk",), parser="generic", command_templates={"default": ("{executable}", "{evidence}")}),
    ])
    with CaseWorkspace.create(tmp_path / "cases", "apk-plan") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        artifact.artifact_type = "android"
        artifact.magic = "Android APK package"
        artifact.classifications = [Classification("android", 0.99, "APK entries")]
        plans = ToolPlanner(workspace, registry).plan(
            artifact, [ToolRecommendation("jadx", frozenset({AnalysisMode.AUTO}), "inspect APK", 90)], AnalysisMode.AUTO
        )

    assert len(plans) == 1
    assert plans[0].available is True
