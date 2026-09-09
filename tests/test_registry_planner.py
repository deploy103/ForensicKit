from __future__ import annotations

from pathlib import Path

from forensickit.evidence import EvidenceManager
from forensickit.config import AnalysisLimits, ForensicKitConfig
from forensickit.models import AnalysisMode, Classification, Finding, Observation, ToolRun, ToolRunStatus
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


def test_volatility_command_is_forced_offline_json_and_scoped_output(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    output = tmp_path / "vol-output"
    output.mkdir()
    executable = tmp_path / "vol"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            "volatility3_windows_memmap", (str(executable),),
            command_templates={
                "pid_dump": (
                    "{executable}", "-f", "{evidence}", "windows.memmap.Memmap",
                    "--pid", "{pid}", "--dump",
                ),
            },
        )
    ])

    command = registry.build_command(
        "volatility3_windows_memmap", evidence, mode="pid_dump",
        output_directory=output, template_values={"pid": "444"},
    )

    plugin_index = command.index("windows.memmap.Memmap")
    assert command[1:plugin_index] == [
        "--offline", "-q", "-r", "json", "-o", str(output.resolve()),
        "-f", str(evidence.resolve()),
    ]
    assert command[plugin_index + 1:] == ["--pid", "444", "--dump"]


def test_volatility_command_does_not_duplicate_explicit_global_safety_options(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    executable = tmp_path / "vol"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            "volatility3", (str(executable),),
            command_templates={
                "default": (
                    "{executable}", "--offline", "--quiet", "--renderer", "json",
                    "-f", "{evidence}", "banners.Banners",
                ),
            },
        )
    ])

    command = registry.build_command("volatility3", evidence)

    assert command.count("--offline") == 1
    assert command.count("--quiet") == 1
    assert command.count("--renderer") == 1


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


def test_registry_loads_operational_metadata_and_adds_generated_output_contract(tmp_path: Path) -> None:
    catalog = tmp_path / "tools.yaml"
    catalog.write_text(
        "tools:\n"
        "  verifier:\n"
        "    executables: [verifier]\n"
        "    supported_platforms: [linux]\n"
        "    expected_outputs: [stdout, parsed_observations]\n"
        "    dependency_hints: [install from the offline bundle]\n"
        "    prerequisites: [finding:embedded_archive]\n"
        "    expected_value: 92\n"
        "    cpu_cost: 2\n"
        "    estimated_ram_bytes: 536870912\n"
        "    min_artifact_size: 4\n"
        "    max_artifact_size: 4096\n"
        "    minimum_confidence: 0.8\n"
        "    generates_files: true\n",
        encoding="utf-8",
    )
    definition = ToolRegistry.from_yaml(catalog).get("verifier")

    assert definition.supported_platforms == ("linux",)
    assert definition.expected_outputs == ("stdout", "parsed_observations", "generated_files")
    assert definition.dependency_hints == ("install from the offline bundle",)
    assert definition.prerequisites == ("finding:embedded_archive",)
    assert definition.expected_value == 92
    assert definition.cpu_cost == 2
    assert definition.estimated_ram_bytes == 536870912
    assert definition.minimum_confidence == 0.8


def test_planner_blocks_unmet_prior_finding_and_resource_prerequisites(tmp_path: Path) -> None:
    source = tmp_path / "large.bin"
    source.write_bytes(b"sample")
    executable = tmp_path / "verifier"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([ToolDefinition(
        "verifier", (str(executable),), profiles=("archive",),
        prerequisites=("finding:embedded_archive",), expected_value=90,
        cpu_cost=3, estimated_ram_bytes=1024, minimum_confidence=0.9,
        command_templates={"default": ("{executable}", "{evidence}")},
    )])
    config = ForensicKitConfig(limits=AnalysisLimits(
        planner_cpu_units=1, planner_max_ram_bytes=512,
    ))
    with CaseWorkspace.create(tmp_path / "cases", "bounded", config) as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        artifact.classifications = [Classification("archive", 0.7, "weak signature")]
        plans = ToolPlanner(workspace, registry).plan(
            artifact,
            [ToolRecommendation("verifier", frozenset({AnalysisMode.AUTO}), "verify archive", 90)],
            AnalysisMode.AUTO,
        )

    assert len(plans) == 1
    assert plans[0].available is False
    rendered = " | ".join(plans[0].reasons)
    assert "evidence confidence 0.70" in rendered
    assert "CPU cost 3" in rendered
    assert "estimated RAM 1024" in rendered
    assert "finding:embedded_archive" in rendered
    assert plans[0].expected_outputs == ["stdout", "parsed_observations"]


def test_planner_unlocks_tool_and_observation_prerequisites_from_case_history(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    executable = tmp_path / "carver"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([ToolDefinition(
        "carver", (str(executable),), prerequisites=(
            "tool:probe", "observation:probe.valid", "finding:validated_container",
        ),
        command_templates={"default": ("{executable}", "{evidence}")},
    )])
    with CaseWorkspace.create(tmp_path / "cases", "history") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        workspace.database.add_tool_run(ToolRun(
            artifact_id=artifact.id, tool="probe", command_argv=["probe"], timeout=5,
            status=ToolRunStatus.COMPLETED, exit_code=0,
        ))
        workspace.database.add_observations([
            Observation(artifact_id=artifact.id, key="probe.valid", value=True, source="test")
        ])
        workspace.database.add_findings([Finding(
            artifact_id=artifact.id, title="Validated container",
            category="validated_container", severity="info", confidence=0.9,
            explanation="Independent structure validation succeeded.", source="test",
            supporting_evidence=["header and directory agree"],
        )])
        plans = ToolPlanner(workspace, registry).plan(
            artifact,
            [ToolRecommendation("carver", frozenset({AnalysisMode.DEEP}), "validated input", 80)],
            AnalysisMode.DEEP,
        )

    assert plans[0].available is True
    assert plans[0].prerequisites == [
        "tool:probe", "observation:probe.valid", "finding:validated_container",
    ]
    assert plans[0].command_argv[-1].endswith("sample.bin")


def test_planner_scores_expected_value_and_large_artifact_cost_deterministically(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    executable = tmp_path / "inspect"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            "high_value", (str(executable),), cost="high", expected_value=90,
            command_templates={"default": ("{executable}", "{evidence}")},
        ),
        ToolDefinition(
            "low_value", (str(executable),), cost="high", expected_value=20,
            command_templates={"default": ("{executable}", "{evidence}")},
        ),
    ])
    with CaseWorkspace.create(tmp_path / "cases", "scoring") as workspace:
        artifact = EvidenceManager(workspace).ingest(source)
        artifact.size = 512 * 1024 * 1024
        recommendations = [
            ToolRecommendation(name, frozenset({AnalysisMode.DEEP}), "inspect", 80)
            for name in ("low_value", "high_value")
        ]
        plans = ToolPlanner(workspace, registry).plan(
            artifact, recommendations, AnalysisMode.DEEP
        )

    assert [item.tool for item in plans] == ["high_value", "low_value"]
    assert plans[0].priority - plans[1].priority == 14
    assert all("reduce priority by 9" in " ".join(item.reasons) for item in plans)
