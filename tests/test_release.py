from __future__ import annotations

import tomllib
from pathlib import Path

import forensickit
from forensickit.cli import build_parser
from forensickit.resources import default_rules_path, default_tool_catalog


ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == "1.0.0"
    assert forensickit.__version__ == "1.0.0"
    assert "ForensicKit v1.0.0" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_packaged_default_resources_exist() -> None:
    catalog = default_tool_catalog()
    rules = default_rules_path()
    assert catalog is not None and catalog.is_file()
    assert rules is not None and rules.is_file()
    assert catalog.parent.name == "data"
    assert rules.parent.name == "data"


def test_cli_release_help_is_actionable() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "forensickit doctor" in help_text
    assert "forensickit analyze EVIDENCE --auto" in help_text
    assert parser.prog == "forensickit"
