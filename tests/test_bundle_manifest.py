from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

from forensickit.bundle_manifest import build_component_manifest, validate_component_manifest
from forensickit.doctor import Doctor
from forensickit.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def _project(root: Path) -> None:
    (root / "config").mkdir(parents=True)
    (root / "src" / "forensickit" / "data").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "forensickit"\nversion = "9.9.9"\nlicense = "MIT"\n',
        encoding="utf-8",
    )
    for relative in (
        "config/rules.example.yaml", "src/forensickit/data/rules.example.yaml",
        "config/tool-catalog.yaml", "src/forensickit/data/tool-catalog.yaml",
    ):
        (root / relative).write_text("version: 1\n", encoding="utf-8")


def _bundle(root: Path) -> None:
    (root / "manifests").mkdir(parents=True)
    (root / "wheels").mkdir()
    (root / "debs").mkdir()
    (root / "tools").mkdir()
    (root / "forensickit-source.tar.gz").write_bytes(b"source archive")
    wheel = root / "wheels" / "forensickit-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "demo-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: forensickit\nVersion: 9.9.9\nLicense-Expression: MIT\nRequires-Python: >=3.12\n",
        )
        archive.writestr(
            "demo-1.2.3.dist-info/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )
    (root / "manifests" / "build-manifest.env").write_text(
        "BUNDLE_FORMAT=forensickit-offline-v2\nDISTRO_ID=unknown\nDISTRO_VERSION=unknown\nARCHITECTURE=unknown\n"
        "SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567\nSOURCE_DIRTY=0\n",
        encoding="utf-8",
    )


def _checksums(bundle: Path) -> None:
    files = [
        item for item in sorted(bundle.rglob("*"), key=lambda value: value.as_posix())
        if item.is_file() and item.name != "SHA256SUMS"
    ]
    (bundle / "manifests" / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(item.read_bytes()).hexdigest()}  ./{item.relative_to(bundle).as_posix()}\n"
            for item in files
        ),
        encoding="utf-8",
    )


def test_component_manifest_records_wheel_rules_versions_hashes_and_support(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    _project(project)
    _bundle(bundle)

    output = build_component_manifest(bundle, project)
    payload = json.loads(output.read_text(encoding="utf-8"))
    validation = validate_component_manifest(bundle, payload)

    assert validation.valid
    assert validation.warnings == ()
    assert {item["kind"] for item in payload["components"]} >= {
        "source_archive", "python_wheel", "rule_pack", "tool_catalog",
    }
    wheel = next(item for item in payload["components"] if item["kind"] == "python_wheel")
    assert wheel["name"] == "forensickit"
    assert wheel["version"] == "9.9.9"
    assert wheel["license"] == "MIT"
    assert wheel["supported_os"] == ["any"]
    assert wheel["architectures"] == ["any"]
    assert len(wheel["sha256"]) == 64
    assert all(item["version"] == "1" for item in payload["components"] if item["kind"] in {"rule_pack", "tool_catalog"})


def test_component_manifest_rejects_source_wheel_version_mismatch(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    _project(project)
    _bundle(bundle)
    output = build_component_manifest(bundle, project)
    payload = json.loads(output.read_text(encoding="utf-8"))
    source = next(item for item in payload["components"] if item["kind"] == "source_archive")
    source["version"] = "9.9.8"

    validation = validate_component_manifest(bundle, payload)

    assert not validation.valid
    assert any("source/wheel version mismatch" in item for item in validation.errors)

    _checksums(bundle)
    check = next(
        item for item in Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
        if item.name == "Offline bundle"
    )
    assert check.status == "OK"
    assert "6 components" in check.detail


def test_prepared_tool_and_symbol_metadata_must_cover_every_staged_file(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    tools = tmp_path / "prepared"
    _project(project)
    _bundle(bundle)
    (tools / "volatility3").mkdir(parents=True)
    (tools / "volatility-symbols").mkdir()
    (tools / "volatility3" / "vol.py").write_bytes(b"offline tool")
    (tools / "volatility-symbols" / "windows.json.xz").write_bytes(b"offline symbols")
    with tarfile.open(bundle / "tools" / "prepared-tools.tar.gz", "w:gz") as archive:
        archive.add(tools, arcname=tools.name)
    metadata = tmp_path / "components.json"
    metadata.write_text(json.dumps({
        "schema_version": 1,
        "components": [
            {
                "kind": "tool", "name": "volatility3", "version": "2.26.2",
                "license": "VSL-1.0", "supported_os": ["linux"],
                "architectures": ["any"], "path": "volatility3", "source": "offline wheel set",
            },
            {
                "kind": "symbols", "name": "volatility-symbols", "version": "2026-09-01",
                "license": "symbol redistribution terms reviewed", "supported_os": ["windows"],
                "architectures": ["amd64"], "path": "volatility-symbols", "source": "prepared cache",
            },
        ],
    }), encoding="utf-8")

    output = build_component_manifest(
        bundle, project, tools_root=tools, components_metadata=metadata,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    validation = validate_component_manifest(bundle, payload)

    assert validation.valid
    assert validation.prepared_component_count == 2
    assert {item["kind"] for item in payload["prepared_components"]} == {"tool", "symbols"}
    assert all(len(item["content_sha256"]) == 64 for item in payload["prepared_components"])
    assert all(item["file_count"] == 1 for item in payload["prepared_components"])

    (tools / "uncovered.bin").write_bytes(b"not described")
    with pytest.raises(ValueError, match="does not cover"):
        build_component_manifest(
            bundle, project, tools_root=tools, components_metadata=metadata,
        )


def test_doctor_rejects_v2_bundle_without_component_manifest(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _bundle(bundle)
    _checksums(bundle)

    check = next(
        item for item in Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
        if item.name == "Offline bundle"
    )

    assert check.status == "BROKEN"
    assert "component-manifest.json" in check.detail


def test_doctor_warns_for_valid_dirty_development_bundle(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    _project(project)
    _bundle(bundle)
    build_component_manifest(bundle, project)
    metadata = bundle / "manifests" / "build-manifest.env"
    metadata.write_text(metadata.read_text(encoding="utf-8").replace("SOURCE_DIRTY=0", "SOURCE_DIRTY=1"), encoding="utf-8")
    _checksums(bundle)

    check = next(
        item for item in Doctor(ToolRegistry([])).run(tmp_path / "cases", bundle).checks
        if item.name == "Offline bundle"
    )

    assert check.status == "WARN"
    assert "dirty development worktree" in check.detail


def _installer_bundle(root: Path, *, unsafe_source: bool = False) -> None:
    (root / "manifests").mkdir(parents=True)
    (root / "wheels").mkdir()
    (root / "debs").mkdir()
    (root / "tools").mkdir()
    wheel = root / "wheels" / "forensickit-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"installer selection fixture")
    with tarfile.open(root / "forensickit-source.tar.gz", "w:gz") as archive:
        payload = tmp_file = root.parent / "README.fixture"
        payload.write_bytes(b"offline source")
        archive.add(tmp_file, arcname="../escape" if unsafe_source else "README.md")
    (root / "manifests" / "build-manifest.env").write_text(
        "BUNDLE_FORMAT=forensickit-offline-v1\n"
        "DISTRO_ID=unknown\nDISTRO_VERSION=unknown\nARCHITECTURE=unknown\n",
        encoding="utf-8",
    )
    _checksums(root)


def test_offline_installer_verify_only_accepts_one_safe_project_wheel(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "bundle verified" in completed.stdout


def test_offline_installer_rejects_ambiguous_project_wheels(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)
    (bundle / "wheels" / "forensickit-9.9.8-py3-none-any.whl").write_bytes(b"stale")
    _checksums(bundle)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "exactly one ForensicKit wheel" in completed.stderr


def test_offline_installer_rejects_archive_path_traversal(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle, unsafe_source=True)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode != 0
    assert "unsafe archive member path" in completed.stderr


def test_offline_installer_rejects_root_and_bundle_containing_prefixes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)

    for prefix, message in (("/", "filesystem root"), (str(bundle / "install"), "must not contain")):
        completed = subprocess.run(
            [
                str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
                "--prefix", prefix, "--verify-only",
            ],
            text=True, capture_output=True, check=False,
        )
        assert completed.returncode == 1
        assert message in completed.stderr


def test_failed_staged_upgrade_preserves_existing_prefix(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    prefix = tmp_path / "installed"
    _installer_bundle(bundle)
    prefix.mkdir()
    sentinel = prefix / "known-good.txt"
    sentinel.write_text("previous installation", encoding="utf-8")

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
            "--prefix", str(prefix), "--no-apt", "--upgrade",
        ],
        text=True, capture_output=True, check=False, timeout=60,
    )

    assert completed.returncode != 0
    assert sentinel.read_text(encoding="utf-8") == "previous installation"
    assert not list(tmp_path.glob("installed.installing.*"))
    assert not list(tmp_path.glob("installed.backup.*"))


def test_bundle_builder_requires_clean_provenance_by_default() -> None:
    script = (ROOT / "scripts" / "build_offline_bundle.sh").read_text(encoding="utf-8")

    assert "--allow-dirty" in script
    assert "git -C \"$PROJECT_ROOT\" archive" in script
    assert "SOURCE_COMMIT=$SOURCE_COMMIT" in script
    assert "SOURCE_DIRTY=$SOURCE_DIRTY" in script
    assert "--exclude='build'" in script
    assert "--exclude='dist'" in script
