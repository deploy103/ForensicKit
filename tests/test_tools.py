from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from forensickit.evidence import EvidenceManager
from forensickit.models import ToolRunStatus
from forensickit.tools import ToolDefinition, ToolRegistry, ToolRunner, parse_output
from forensickit.workspace import CaseWorkspace


def _fake_executable(path: Path) -> Path:
    path.write_text(
        """#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import time

if '--version' in sys.argv:
    print('fake-forensic 1.2.3')
    raise SystemExit(0)
if '--sleep' in sys.argv:
    print('started', flush=True)
    time.sleep(30)
if '--spawn-child' in sys.argv:
    sentinel = pathlib.Path(sys.argv[2]) / 'child-survived'
    subprocess.Popen([
        sys.executable, '-c',
        'import pathlib,sys,time;time.sleep(0.4);pathlib.Path(sys.argv[1]).write_text("alive")',
        str(sentinel),
    ])
    print('child started', flush=True)
    time.sleep(30)
if '--large' in sys.argv:
    sys.stdout.write('X' * 8192)
else:
    print(json.dumps(sys.argv[1:]))
if len(sys.argv) >= 3:
    output_dir = pathlib.Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'generated.txt').write_text('generated', encoding='utf-8')
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _registry(executable: Path) -> ToolRegistry:
    return ToolRegistry(
        [
            ToolDefinition(
                name="fake",
                executable_candidates=(str(executable),),
                parser="generic",
                timeout=2,
                command_templates={
                    "default": ("{executable}", "{evidence}", "{output_dir}"),
                },
                version_probe=("--version",),
                generates_files=True,
            )
        ]
    )


@pytest.fixture
def case_artifact(tmp_path: Path):
    workspace = CaseWorkspace.create(tmp_path / "cases", "tool runner")
    source = tmp_path / "evidence with spaces.bin"
    source.write_bytes(b"evidence")
    artifact = EvidenceManager(workspace).ingest(source)
    try:
        yield workspace, artifact
    finally:
        workspace.close()


def test_registry_loads_seed_builtins_and_builds_safe_argv(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path / "fake tool")
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(
        f"""version: 1
tools:
  custom:
    executables: [{json.dumps(str(executable))}]
    timeout: 7
    parser: generic
    commands:
      default: ["{{executable}}", "--scan", "{{evidence}}"]
    modes:
      deep:
        argv: ["{{executable}}", "--deep", "{{evidence}}", "{{output_dir}}"]
""",
        encoding="utf-8",
    )
    evidence = tmp_path / "sample ; not-a-command.bin"
    evidence.write_bytes(b"x")
    output = tmp_path / "output dir"
    output.mkdir()

    registry = ToolRegistry.from_yaml(catalog)
    definition = registry.get("custom")
    assert definition.timeout == 7
    assert "sqlite3" in registry.names()
    assert "foremost" in registry.names()
    assert "scalpel" in registry.names()
    assert "bulk_extractor" in registry.names()
    assert registry.get("mmls").name == "sleuthkit_mmls"
    availability = registry.detect("custom", probe_version=True)
    assert availability.available is True
    assert availability.version == "fake-forensic 1.2.3"

    argv = registry.build_command(
        "custom",
        evidence,
        mode="deep",
        output_directory=output,
        extra_args=("; touch should-not-run",),
    )
    assert argv == [
        str(executable.resolve()),
        "--deep",
        str(evidence.resolve()),
        str(output.resolve()),
        "; touch should-not-run",
    ]


def test_runner_preserves_exact_argv_logs_and_generated_files(
    tmp_path: Path,
    case_artifact,
) -> None:
    workspace, artifact = case_artifact
    executable = _fake_executable(tmp_path / "fake")
    registry = _registry(executable)
    sentinel = tmp_path / "shell-was-used"
    malicious_argument = f"; touch {sentinel}"

    result = ToolRunner(workspace, registry, preview_bytes=128).run(
        "fake", artifact, extra_args=(malicious_argument,)
    )

    assert result.status is ToolRunStatus.COMPLETED
    assert sentinel.exists() is False
    assert result.run.command_argv[0] == str(executable.resolve())
    assert result.run.command_argv[-1] == malicious_argument
    assert result.run.command_argv[1] == str(workspace.resolve_stored_path(artifact.path))

    stdout_path = workspace.resolve_stored_path(result.run.stdout_path or "")
    stderr_path = workspace.resolve_stored_path(result.run.stderr_path or "")
    observed_argv = json.loads(stdout_path.read_text(encoding="utf-8"))
    assert observed_argv[-1] == malicious_argument
    assert stderr_path.read_bytes() == b""
    assert result.run.generated_files
    generated = workspace.resolve_stored_path(result.run.generated_files[0])
    assert generated.read_text(encoding="utf-8") == "generated"

    persisted = workspace.database.tool_runs(artifact.id)
    assert len(persisted) == 1
    assert persisted[0].command_argv == result.run.command_argv
    assert persisted[0].stdout_path == result.run.stdout_path
    assert persisted[0].status is ToolRunStatus.COMPLETED


def test_runner_times_out_and_keeps_bounded_preview(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = _fake_executable(tmp_path / "slow-fake")
    runner = ToolRunner(workspace, _registry(executable), preview_bytes=32)

    # Leave enough time for the shebang's Python interpreter to start even on a
    # loaded CI host; the fixture still sleeps for 30 seconds, so this remains
    # a real timeout while reliably exercising preservation of flushed output.
    timed_out = runner.run("fake", artifact, timeout=1.0, extra_args=("--sleep",))
    assert timed_out.status is ToolRunStatus.TIMED_OUT
    assert timed_out.run.error and "timeout" in timed_out.run.error
    assert "started" in workspace.resolve_stored_path(timed_out.run.stdout_path or "").read_text()

    child_run = runner.run("fake", artifact, timeout=0.1, extra_args=("--spawn-child",))
    child_sentinel = workspace.resolve_stored_path(child_run.generated_directory or "") / "child-survived"
    time.sleep(0.5)
    assert child_run.status is ToolRunStatus.TIMED_OUT
    assert child_sentinel.exists() is False

    large = runner.run("fake", artifact, extra_args=("--large",))
    stdout_path = workspace.resolve_stored_path(large.run.stdout_path or "")
    assert stdout_path.stat().st_size == 8192
    assert len(large.stdout_preview) < 200
    assert "preview truncated" in large.stdout_preview


def test_runner_clamps_tool_timeout_to_case_limit(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = _fake_executable(tmp_path / "slow-clamped")
    runner = ToolRunner(workspace, _registry(executable), max_timeout=0.1)

    result = runner.run("fake", artifact, timeout=30, extra_args=("--sleep",))

    assert result.status is ToolRunStatus.TIMED_OUT
    assert result.run.timeout == 0.1


def test_missing_tool_is_skipped_and_persisted(case_artifact) -> None:
    workspace, artifact = case_artifact
    registry = ToolRegistry(
        [
            ToolDefinition(
                name="missing",
                executable_candidates=("forensickit-definitely-missing-command",),
                command_templates={"default": ("{executable}", "{evidence}")},
            )
        ]
    )
    result = ToolRunner(workspace, registry).run("missing", artifact)
    assert result.status is ToolRunStatus.SKIPPED
    assert result.run.error and "not found" in result.run.error
    persisted = workspace.database.tool_runs(artifact.id)
    assert len(persisted) == 1
    assert persisted[0].status is ToolRunStatus.SKIPPED
    assert result.observations[0].value is False


def test_core_parsers_return_normalized_observations_and_findings() -> None:
    file_result = parse_output("file", artifact_id="a", stdout="PNG image data, 1 x 1\n")
    assert file_result.observations[0].key == "file.description"

    exif_result = parse_output(
        "exiftool",
        artifact_id="a",
        stdout='[{"[File]FileType":"PNG","[File]MIMEType":"image/png","[ExifTool]Warning":"trailing data"}]',
    )
    assert any(item.key == "exiftool.mime_type" for item in exif_result.observations)
    assert exif_result.findings[0].category == "metadata_anomaly"

    binwalk_result = parse_output(
        "binwalk",
        artifact_id="a",
        stdout="0 0x0 PNG image\n128 0x80 Zip archive data\n",
    )
    assert binwalk_result.findings[0].category == "embedded_data"

    archive_result = parse_output(
        "sevenzip",
        artifact_id="a",
        stdout="Type = zip\n\n----------\nPath = secret.txt\nSize = 3\nEncrypted = +\n",
    )
    assert archive_result.findings[0].category == "encrypted_archive"

    png_result = parse_output(
        "pngcheck", artifact_id="a", stdout="chunk IHDR at offset 0x0000c\nERROR: additional data after IEND\n", exit_code=2
    )
    assert png_result.findings[0].category == "appended_data"

    zsteg_result = parse_output(
        "zsteg", artifact_id="a", stdout='b1,r,lsb,xy .. text: "CTF{demo}"\n'
    )
    assert zsteg_result.findings[0].category == "steganography"

    capinfos_result = parse_output(
        "capinfos", artifact_id="a", stdout="File type: Wireshark/tcpdump\nNumber of packets: 42\n"
    )
    packet_count = next(item for item in capinfos_result.observations if item.key == "pcap.packet_count")
    assert packet_count.value == 42

    tshark_result = parse_output(
        "tshark", artifact_id="a", stdout="  eth frames:10 bytes:800\n    ip frames:9 bytes:700\n"
    )
    protocols = next(item for item in tshark_result.observations if item.key == "pcap.protocols")
    assert protocols.value == ["eth", "ip"]


def test_parser_failure_falls_back_without_raising() -> None:
    result = parse_output("exiftool", artifact_id="a", stdout="not json", stderr="warning")
    assert any(observation.key == "tool.exiftool.parser_error" for observation in result.observations)


def test_nested_event_json_is_normalized_and_jsonl_rows_are_not_dropped() -> None:
    rows = [
        {
            "Event": {
                "System": {
                    "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                    "EventID": 4688,
                    "EventRecordID": 77,
                    "Channel": "Security",
                    "Computer": "ctf-host",
                    "TimeCreated_attributes": {"SystemTime": "2026-09-03T01:02:03Z"},
                },
                "EventData": {"Data": [
                    {"Name": "NewProcessId", "Value": "0x444"},
                    {"Name": "ProcessId", "Value": "0x111"},
                    {"Name": "NewProcessName", "Value": r"C:\\Temp\\payload.exe"},
                    {"Name": "CommandLine", "Value": "payload.exe -flag"},
                ]},
            }
        },
        {
            "Event": {
                "System": {"EventID": {"value": 4625}, "EventRecordID": 78},
                "EventData": {"TargetUserName": "ctf", "IpAddress": "192.0.2.7"},
            }
        },
    ]
    result = parse_output(
        "event_json", artifact_id="a", tool="chainsaw",
        stdout="\n".join(json.dumps(row) for row in rows),
    )

    event_ids = next(item.value for item in result.observations if item.key == "windows.event_hunt.event_ids")
    normalized = next(item.value for item in result.observations if item.key == "windows.event_hunt.normalized_events")
    assert event_ids == {"4688": 1, "4625": 1}
    assert normalized[0] == {
        "source_record_index": 0,
        "event_id": "4688",
        "category": "process_creation",
        "event_record_id": 77,
        "timestamp": "2026-09-03T01:02:03Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "ctf-host",
        "process_id": "0x444",
        "parent_process_id": "0x111",
        "process_path": r"C:\\Temp\\payload.exe",
        "command_line": "payload.exe -flag",
    }
    assert normalized[1]["category"] == "logon_failure"
    assert normalized[1]["target_user"] == "ctf"
    assert normalized[1]["source_ip"] == "192.0.2.7"
    assert {item.category for item in result.findings} == {
        "windows_event_record_inventory", "windows_event_activity",
    }


def test_generated_hayabusa_csv_is_parsed_with_output_provenance(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = tmp_path / "hayabusa"
    executable.write_text(
        "#!/bin/sh\nprintf 'EventID,EventRecordID,RuleTitle,Image,CommandLine\\n4688,77,Suspicious Process,cmd.exe,cmd.exe /c whoami\\n' > \"$5/timeline.csv\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            name="hayabusa", executable_candidates=(str(executable),), parser="generic", generates_files=True,
            command_templates={"default": ("{executable}", "csv-timeline", "-f", "{evidence}", "-o", "{output_dir}")},
        )
    ])

    result = ToolRunner(workspace, registry).run("hayabusa", artifact)

    assert result.run.generated_files
    assert any(item.key == "windows.event_timeline.event_ids" and item.value == {"4688": 1} for item in result.observations)
    normalized = next(item.value for item in result.observations if item.key == "windows.event_timeline.normalized_events")
    assert normalized == [{
        "source_record_index": 0,
        "event_id": "4688",
        "category": "process_creation",
        "event_record_id": 77,
        "process_path": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
    }]
    assert any(item.category == "windows_event_record_inventory" for item in result.findings)
    assert any(item.category == "windows_event_timeline_lead" for item in result.findings)


def test_tshark_exported_http_objects_are_inventoried_before_recursion(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = tmp_path / "tshark"
    executable.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do case \"$arg\" in http,*) output=${arg#http,};; esac; done\n"
        "mkdir -p \"$output\"\n"
        "printf 'CTF{from_tshark}' > \"$output/object.bin\"\n"
        "printf '  http frames:1 bytes:17\\n'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            name="tshark", executable_candidates=(str(executable),), parser="tshark", generates_files=True,
            command_templates={
                "deep": ("{executable}", "-r", "{evidence}", "--export-objects", "http,{output_dir}"),
            },
        )
    ])

    result = ToolRunner(workspace, registry).run("tshark", artifact, mode="deep")
    objects = next(item.value for item in result.observations if item.key == "pcap.tshark.exported_http_objects")

    assert result.status is ToolRunStatus.COMPLETED
    assert objects == [{
        "path": result.run.generated_files[0], "name": "object.bin", "size": len(b"CTF{from_tshark}"),
    }]
    assert any(item.category == "pcap_exported_object" for item in result.findings)
    assert all(item.source.endswith(result.run.id) for item in result.observations if item.key.startswith("pcap.tshark."))


def test_aleapp_generated_json_is_normalized_with_retained_report_path(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = tmp_path / "aleapp"
    executable.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do previous=$current; current=$arg; done\n"
        "mkdir -p \"$current\"\n"
        "printf '[{\"Artifact\":\"SMS\",\"Count\":2}]' > \"$current/mobile.json\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            name="aleapp", executable_candidates=(str(executable),), parser="leapp", generates_files=True,
            command_templates={"default": ("{executable}", "-o", "{output_dir}")},
        )
    ])

    result = ToolRunner(workspace, registry).run("aleapp", artifact)

    assert any(item.key == "mobile.leapp.result_format" and item.value == "json" for item in result.observations)
    assert any(item.key == "mobile.leapp.records" and item.value == [{"Artifact": "SMS", "Count": 2}] for item in result.observations)
    reports = next(item for item in result.observations if item.key == "mobile.aleapp.structured_reports")
    assert reports.value == result.run.generated_files
    assert reports.source.endswith(result.run.id)


def test_bulk_extractor_feature_outputs_are_normalized_with_file_kind(tmp_path: Path, case_artifact) -> None:
    workspace, artifact = case_artifact
    executable = tmp_path / "bulk_extractor"
    executable.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do current=$arg; done\n"
        "mkdir -p \"$current/bulk_extractor\"\n"
        "printf '# comment\\n42\\thttps://example.invalid/flag\\n' > \"$current/bulk_extractor/url.txt\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    registry = ToolRegistry([
        ToolDefinition(
            name="bulk_extractor", executable_candidates=(str(executable),), parser="generic", generates_files=True,
            command_templates={"default": ("{executable}", "-o", "{output_dir}")},
        )
    ])

    result = ToolRunner(workspace, registry).run("bulk_extractor", artifact)

    features = next(item for item in result.observations if item.key == "bulk_extractor.features.url")
    assert features.value == ["https://example.invalid/flag"]
    assert any(item.key == "bulk_extractor.feature_files" and item.value[0]["kind"] == "url" for item in result.observations)
    assert features.source.endswith(result.run.id)


def test_volatility_network_and_command_tables_are_normalized() -> None:
    netscan = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_netscan",
        stdout="Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID\n"
        "0x1000  TCPv4  10.0.0.2  4444  8.8.8.8  443  ESTABLISHED  123\n",
    )
    network = next(item.value for item in netscan.observations if item.key == "memory.volatility.network")
    assert network == [{
        "Offset": "0x1000", "Proto": "TCPv4", "LocalAddr": "10.0.0.2", "LocalPort": "4444",
        "ForeignAddr": "8.8.8.8", "ForeignPort": "443", "State": "ESTABLISHED", "PID": "123",
    }]
    cmdline = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_cmdline",
        stdout="PID  Process  CommandLine\n123  powershell.exe  powershell -enc ZmFrZQ==\n",
    )
    commands = next(item.value for item in cmdline.observations if item.key == "memory.volatility.commands")
    assert commands == [{"PID": "123", "Process": "powershell.exe", "CommandLine": "powershell -enc ZmFrZQ=="}]


def test_volatility_process_scan_handle_and_filescan_tables_are_normalized() -> None:
    psscan = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_psscan",
        stdout="Offset(P)  Name  PID  PPID\n0x1000  hidden.exe  444  4\n",
    )
    scan_rows = next(item.value for item in psscan.observations if item.key == "memory.volatility.psscan")
    assert scan_rows == [{"Offset(P)": "0x1000", "Name": "hidden.exe", "PID": "444", "PPID": "4"}]
    handles = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_handles",
        stdout="PID  Offset  HandleValue  Type  Name\n444  0x2000  0x88  File  C:\\Users\\ctf\\Downloads\\payload.dll\n",
    )
    handle_rows = next(item.value for item in handles.observations if item.key == "memory.volatility.handles")
    assert handle_rows == [{"PID": "444", "Offset": "0x2000", "HandleValue": "0x88", "Type": "File", "Name": r"C:\Users\ctf\Downloads\payload.dll"}]
    files = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_filescan",
        stdout="Offset  Name\n0x3000  C:\\Users\\ctf\\AppData\\Local\\Temp\\dropped.exe\n",
    )
    file_rows = next(item.value for item in files.observations if item.key == "memory.volatility.files")
    assert file_rows == [{"Offset": "0x3000", "Name": r"C:\Users\ctf\AppData\Local\Temp\dropped.exe"}]


def test_volatility_dlllist_and_malfind_tables_are_normalized() -> None:
    modules = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_dlllist",
        stdout="PID  Process  Base  Size  Name  Path\n444  hidden.exe  0x1000  0x2000  payload.dll  C:\\Users\\ctf\\Temp\\payload.dll\n",
    )
    module_rows = next(item.value for item in modules.observations if item.key == "memory.volatility.modules")
    assert module_rows == [{
        "PID": "444", "Process": "hidden.exe", "Base": "0x1000", "Size": "0x2000",
        "Name": "payload.dll", "Path": r"C:\Users\ctf\Temp\payload.dll",
    }]
    malfind = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_malfind",
        stdout="PID  Process  Start VPN  End VPN  Protection\n444  hidden.exe  0x5000  0x6000  PAGE_EXECUTE_READWRITE\n",
    )
    rows = next(item.value for item in malfind.observations if item.key == "memory.volatility.malfind")
    assert rows == [{
        "PID": "444", "Process": "hidden.exe", "Start VPN": "0x5000", "End VPN": "0x6000",
        "Protection": "PAGE_EXECUTE_READWRITE",
    }]


def test_volatility_json_and_jsonl_tables_are_normalized() -> None:
    json_rows = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_windows_netscan",
        stdout=(
            '{"columns": ["PID", "LocalAddr", "ForeignAddr", "State"], '
            '"rows": [["77", "10.0.0.2", "1.1.1.1", "ESTABLISHED"]]}'
        ),
    )
    network = next(item.value for item in json_rows.observations if item.key == "memory.volatility.network")
    assert network == [{
        "PID": "77", "LocalAddr": "10.0.0.2", "ForeignAddr": "1.1.1.1", "State": "ESTABLISHED",
    }]
    jsonl_rows = parse_output(
        "volatility3", artifact_id="a", tool="volatility3_linux_psaux",
        stdout=(
            '{"PID": 12, "PPID": 1, "COMM": "python"}\n'
            '{"PID": 13, "PPID": 12, "COMM": "worker"}\n'
        ),
    )
    processes = next(item.value for item in jsonl_rows.observations if item.key == "memory.volatility.processes")
    assert processes == [
        {"PID": "12", "PPID": "1", "COMM": "python"},
        {"PID": "13", "PPID": "12", "COMM": "worker"},
    ]
