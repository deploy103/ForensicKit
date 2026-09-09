from __future__ import annotations

import hashlib
import io
import json
import os
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


def _installer_bundle(
    root: Path, *, unsafe_source: bool = False, fail_final_self_test: bool = False,
) -> None:
    (root / "manifests").mkdir(parents=True)
    (root / "wheels").mkdir()
    (root / "debs").mkdir()
    (root / "tools").mkdir()
    wheel = root / "wheels" / "forensickit-9.9.9-py3-none-any.whl"
    dist_info = "forensickit-9.9.9.dist-info"
    final_self_test_guard = (
        "        if '.installing.' not in sys.executable:\n"
        "            raise SystemExit(23)\n"
        if fail_final_self_test else ""
    )
    wheel_members = {
        "forensickit/__init__.py": '__version__ = "9.9.9"\n',
        "forensickit/cli.py": (
            "def main():\n"
            "    import sys\n"
            "    if sys.argv[1:] == ['--version']:\n"
            "        print('ForensicKit 9.9.9')\n"
            "    elif sys.argv[1:] == ['self-test']:\n"
            f"{final_self_test_guard}"
            "        print('Self-test passed')\n"
            "    else:\n"
            "        raise SystemExit(2)\n"
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\nName: forensickit\nVersion: 9.9.9\n"
            "Provides-Extra: tui\nProvides-Extra: test\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: ForensicKit tests\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": "[console_scripts]\nforensickit = forensickit.cli:main\n",
    }
    wheel_members[f"{dist_info}/RECORD"] = (
        "".join(f"{name},,\n" for name in wheel_members) + f"{dist_info}/RECORD,,\n"
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in wheel_members.items():
            archive.writestr(name, data)
    with tarfile.open(root / "forensickit-source.tar.gz", "w:gz") as archive:
        source_members = {
            "pyproject.toml": b'[project]\nname = "forensickit"\nversion = "9.9.9"\n',
            "src/forensickit/__init__.py": b'__version__ = "9.9.9"\n',
            "README.md": b"offline source\n",
        }
        if unsafe_source:
            source_members = {"../escape": b"unsafe\n"}
        for name, data in source_members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    (root / "manifests" / "build-manifest.env").write_text(
        "BUNDLE_FORMAT=forensickit-offline-v1\n"
        "DISTRO_ID=unknown\nDISTRO_VERSION=unknown\nARCHITECTURE=unknown\n",
        encoding="utf-8",
    )
    _checksums(root)


def _promote_installer_bundle_to_v2(root: Path) -> None:
    wheel = root / "wheels" / "forensickit-9.9.9-py3-none-any.whl"
    (root / "manifests" / "build-manifest.env").write_text(
        "BUNDLE_FORMAT=forensickit-offline-v2\n"
        "DISTRO_ID=unknown\nDISTRO_VERSION=unknown\nARCHITECTURE=unknown\n"
        f"SOURCE_COMMIT={'a' * 40}\nSOURCE_DIRTY=0\nSOURCE_DATE_EPOCH=315532800\n",
        encoding="utf-8",
    )
    (root / "manifests" / "component-manifest.json").write_text(
        json.dumps({
            "schema_version": 1,
            "bundle_format": "forensickit-offline-v2",
            "components": [{
                "kind": "python_wheel",
                "name": "forensickit",
                "version": "9.9.9",
                "license": "NOASSERTION",
                "bundle_path": "wheels/forensickit-9.9.9-py3-none-any.whl",
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "supported_os": ["any"],
                "architectures": ["any"],
            }],
        }),
        encoding="utf-8",
    )
    verifier = root / "verify-wheelhouse.py"
    verifier.write_bytes((ROOT / "scripts" / "wheelhouse_lock.py").read_bytes())
    verifier.chmod(0o755)
    completed = subprocess.run(
        [
            str(verifier), "--wheel-dir", str(root / "wheels"),
            "--lock", str(root / "manifests" / "python-wheel-lock.json"),
            "--write",
        ],
        text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
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


def test_offline_installer_v2_verifies_wheelhouse_dependency_lock(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)
    _promote_installer_bundle_to_v2(bundle)

    accepted = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )
    assert accepted.returncode == 0, accepted.stderr

    lock = bundle / "manifests" / "python-wheel-lock.json"
    payload = json.loads(lock.read_text(encoding="utf-8"))
    payload["wheels"][0]["version"] = "0.0.0"
    lock.write_text(json.dumps(payload), encoding="utf-8")
    _checksums(bundle)
    rejected = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )
    assert rejected.returncode == 1
    assert "does not match its dependency lock" in rejected.stderr


def test_offline_installer_v2_requires_regular_lock_and_verifier(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)
    _promote_installer_bundle_to_v2(bundle)
    (bundle / "manifests" / "python-wheel-lock.json").unlink()
    _checksums(bundle)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "install_offline.sh"), str(bundle), "--verify-only"],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "lacks a regular wheelhouse lock" in completed.stderr


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


def test_offline_installer_rejects_protected_system_prefixes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _installer_bundle(bundle)

    for prefix in ("/etc", "/home", "/opt", "/tmp", "/usr", "/usr/local", "/var"):
        completed = subprocess.run(
            [
                str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
                "--prefix", prefix, "--verify-only",
            ],
            text=True, capture_output=True, check=False,
        )

        assert completed.returncode == 1
        assert "protected system path" in completed.stderr


def test_offline_installer_rejects_symlink_prefix_without_touching_target(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    target = tmp_path / "target"
    prefix = tmp_path / "install-link"
    _installer_bundle(bundle)
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("unrelated", encoding="utf-8")
    prefix.symlink_to(target, target_is_directory=True)

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
            "--prefix", f"{prefix}//", "--no-apt", "--upgrade",
        ],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "symbolic link" in completed.stderr
    assert prefix.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "unrelated"


def test_offline_installer_rejects_forged_marker_without_installed_distribution(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    prefix = tmp_path / "unrelated"
    _installer_bundle(bundle)
    prefix.mkdir()
    sentinel = prefix / "keep.txt"
    sentinel.write_text("unrelated", encoding="utf-8")
    prefix_hash = hashlib.sha256(str(prefix.resolve()).encode()).hexdigest()
    (prefix / ".forensickit-install").write_text(
        "FORENSICKIT_INSTALL_MARKER_V1\n"
        f"prefix_sha256={prefix_hash}\n"
        f"wheel_sha256={'0' * 64}\n"
        "bundle_format=forensickit-offline-v2\n"
        f"source_commit={'0' * 40}\n"
        "source_dirty=0\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
            "--prefix", str(prefix), "--no-apt", "--upgrade",
        ],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "not a recognized ForensicKit installation" in completed.stderr
    assert sentinel.read_text(encoding="utf-8") == "unrelated"


def _legacy_install(prefix: Path, *, nested_source: bool) -> None:
    site_packages = prefix / "venv" / "lib" / "python3.12" / "site-packages"
    package = site_packages / "forensickit"
    dist_info = site_packages / "forensickit-9.9.9.dist-info"
    launcher = prefix / "venv" / "bin" / "forensickit"
    package.mkdir(parents=True)
    dist_info.mkdir()
    launcher.parent.mkdir(parents=True, exist_ok=True)
    (prefix / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    package.joinpath("__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    dist_info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: forensickit\nVersion: 9.9.9\n",
        encoding="utf-8",
    )
    launcher.write_text(
        "#!/usr/bin/python3\nfrom forensickit.cli import main\nmain()\n",
        encoding="utf-8",
    )
    project = prefix / "source" if nested_source else prefix
    project.joinpath("src", "forensickit").mkdir(parents=True, exist_ok=True)
    project.joinpath("src", "forensickit", "__init__.py").write_text(
        '__version__ = "9.9.9"\n', encoding="utf-8",
    )
    project.joinpath("pyproject.toml").write_text(
        '[project]\nname = "forensickit"\nversion = "9.9.9"\n',
        encoding="utf-8",
    )


def test_offline_installer_fresh_install_writes_upgrade_marker(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    prefix = tmp_path / "new-install"
    _installer_bundle(bundle)
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
            "--prefix", str(prefix), "--no-apt",
        ],
        text=True, capture_output=True, check=False, timeout=120, env=clean_env,
    )

    assert completed.returncode == 0, completed.stderr
    assert (prefix / ".forensickit-install").is_file()
    assert (prefix / "venv" / "bin" / "forensickit").is_file()


def test_offline_installer_upgrades_legacy_install_and_writes_bound_marker(
    tmp_path: Path,
) -> None:
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)
    for layout_name, nested_source in (("v1.1-layout", False), ("v1.2-layout", True)):
        scenario = tmp_path / layout_name
        bundle = scenario / "bundle"
        prefix = scenario / "installed"
        _installer_bundle(bundle)
        _legacy_install(prefix, nested_source=nested_source)

        completed = subprocess.run(
            [
                str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
                "--prefix", str(prefix), "--no-apt", "--upgrade",
            ],
            text=True, capture_output=True, check=False, timeout=120, env=clean_env,
        )

        assert completed.returncode == 0, completed.stderr
        marker = prefix / ".forensickit-install"
        marker_text = marker.read_text(encoding="utf-8")
        assert marker_text.startswith("FORENSICKIT_INSTALL_MARKER_V1\n")
        assert f"prefix_sha256={hashlib.sha256(str(prefix.resolve()).encode()).hexdigest()}\n" in marker_text
        assert "bundle_format=forensickit-offline-v1\n" in marker_text
        assert "source_commit=unknown\n" in marker_text
        assert "source_dirty=unknown\n" in marker_text
        assert not list(scenario.glob("installed.installing.*"))
        assert not list(scenario.glob("installed.backup.*"))

        # The newly written marker path, not just the legacy fallback,
        # authorizes a subsequent verified upgrade.
        second = subprocess.run(
            [
                str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
                "--prefix", str(prefix), "--no-apt", "--upgrade",
            ],
            text=True, capture_output=True, check=False, timeout=120, env=clean_env,
        )
        assert second.returncode == 0, second.stderr

        # A marker copied or edited for another prefix is not accepted, even
        # when the surrounding virtual environment is otherwise complete.
        marker.write_text(
            marker.read_text(encoding="utf-8").replace(
                f"prefix_sha256={hashlib.sha256(str(prefix.resolve()).encode()).hexdigest()}",
                f"prefix_sha256={'f' * 64}",
            ),
            encoding="utf-8",
        )
        rejected = subprocess.run(
            [
                str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
                "--prefix", str(prefix), "--no-apt", "--upgrade",
            ],
            text=True, capture_output=True, check=False, timeout=60, env=clean_env,
        )
        assert rejected.returncode == 1
        assert "belongs to a different prefix" in rejected.stderr


def test_upgrade_rejects_unrelated_existing_prefix_without_touching_it(tmp_path: Path) -> None:
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


def test_failed_final_validation_restores_recognized_existing_install(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    prefix = tmp_path / "installed"
    _installer_bundle(bundle, fail_final_self_test=True)
    _legacy_install(prefix, nested_source=True)
    sentinel = prefix / "known-good.txt"
    sentinel.write_text("previous installation", encoding="utf-8")
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "install_offline.sh"), str(bundle),
            "--prefix", str(prefix), "--no-apt", "--upgrade",
        ],
        text=True, capture_output=True, check=False, timeout=120, env=clean_env,
    )

    assert completed.returncode != 0
    assert "final-path validation failed" in completed.stderr
    assert sentinel.read_text(encoding="utf-8") == "previous installation"
    assert not (prefix / ".forensickit-install").exists()
    assert not list(tmp_path.glob("installed.installing.*"))
    assert not list(tmp_path.glob("installed.backup.*"))


def test_bundle_builder_requires_clean_provenance_by_default() -> None:
    script = (ROOT / "scripts" / "build_offline_bundle.sh").read_text(encoding="utf-8")

    assert "--allow-dirty" in script
    assert "git -C \"$PROJECT_ROOT\" archive" in script
    assert "SOURCE_COMMIT=$SOURCE_COMMIT" in script
    assert "SOURCE_DIRTY=$SOURCE_DIRTY" in script
    assert "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" in script
    assert "python-wheel-lock.json" in script
    assert '"$OUTPUT/install_offline.sh"' in script
    assert '"$OUTPUT/verify-wheelhouse.py"' in script
    assert "--exclude='build'" in script
    assert "--exclude='dist'" in script
