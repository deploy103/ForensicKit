from __future__ import annotations

import json
from pathlib import Path

from forensickit.cli import main
from forensickit.selftest import run_self_test


def test_installed_runtime_self_test_exercises_complete_core_chain() -> None:
    result = run_self_test()

    assert result.healthy, result.errors
    assert len(result.checks) == 6
    assert any("artifact lineage" in item for item in result.checks)
    assert any("finding provenance" in item for item in result.checks)


def test_self_test_cli_returns_success_and_lists_checks(capsys) -> None:
    assert main(["self-test"]) == 0
    output = capsys.readouterr()
    assert "[OK] evidence preservation and SHA-256" in output.out
    assert output.err == ""


def test_self_test_cli_json_is_machine_readable(capsys) -> None:
    assert main(["self-test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is True
    assert len(payload["checks"]) == 6
    assert payload["errors"] == []


def test_cli_reports_missing_evidence_without_a_traceback(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.bin"

    assert main(["analyze", str(missing), "--json"]) == 2
    output = capsys.readouterr()
    payload = json.loads(output.err)
    assert payload["type"] == "ValueError"
    assert str(missing) in payload["error"]
    assert "Traceback" not in output.err
