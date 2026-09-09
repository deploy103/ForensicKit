from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .tools.registry import ToolRegistry
from .bundle_manifest import validate_component_manifest


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: str
    requirement: str
    detail: str


@dataclass(slots=True)
class DoctorResult:
    checks: list[DoctorCheck]

    @property
    def healthy(self) -> bool:
        return not any(item.requirement == "REQUIRED" and item.status in {"MISSING", "BROKEN"} for item in self.checks)


class Doctor:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def run(self, workspace_base: Path, offline_bundle: Path | None = None) -> DoctorResult:
        checks: list[DoctorCheck] = []
        python_ok = sys.version_info >= (3, 12)
        checks.append(
            DoctorCheck(
                "Python",
                "OK" if python_ok else "BROKEN",
                "REQUIRED",
                sys.version.split()[0] + (" (3.12+ required)" if not python_ok else ""),
            )
        )
        yaml_available = importlib.util.find_spec("yaml") is not None
        checks.append(
            DoctorCheck(
                "PyYAML", "OK" if yaml_available else "MISSING", "REQUIRED",
                "declarative tool/rule catalog loader",
            )
        )
        textual_available = importlib.util.find_spec("textual") is not None
        checks.append(
            DoctorCheck(
                "Textual TUI", "OK" if textual_available else "MISSING", "REQUIRED",
                "standard keyboard-first interface dependency",
            )
        )
        checks.append(self._workspace_check(workspace_base))
        checks.append(self._offline_bundle_check(offline_bundle))
        try:
            usage = shutil.disk_usage(workspace_base.resolve())
            free_gib = usage.free / (1024**3)
            checks.append(
                DoctorCheck(
                    "Free disk",
                    "OK" if free_gib >= 5 else "WARN",
                    "RECOMMENDED",
                    f"{free_gib:.1f} GiB available",
                )
            )
        except OSError as exc:
            checks.append(DoctorCheck("Free disk", "BROKEN", "RECOMMENDED", str(exc)))

        priority_requirement = {"P0": "RECOMMENDED", "P1": "OPTIONAL", "P2": "OPTIONAL"}
        for definition in self.registry.definitions():
            executable = self.registry.resolve_executable(definition)
            checks.append(
                DoctorCheck(
                    definition.name,
                    "OK" if executable else "MISSING",
                    priority_requirement.get(definition.priority.upper(), "OPTIONAL"),
                    executable or f"candidates: {', '.join(definition.executable_candidates)}",
                )
            )
        checks.extend(self._volatility_checks())
        checks.append(
            DoctorCheck(
                "Offline runtime",
                "OK",
                "REQUIRED",
                "core analysis performs no network requests or external API calls",
            )
        )
        return DoctorResult(checks)

    def _volatility_checks(self) -> list[DoctorCheck]:
        checks: list[DoctorCheck] = []
        try:
            availability = self.registry.detect("volatility3", probe_version=True, timeout=3.0)
        except KeyError:
            availability = None
        if availability is None or not availability.available:
            checks.append(DoctorCheck(
                "Volatility version", "MISSING", "RECOMMENDED",
                "stage a tested Volatility 3 `vol` or `vol-offline` executable before competition",
            ))
        else:
            detail = availability.version or availability.error or availability.executable or "version unknown"
            checks.append(DoctorCheck(
                "Volatility version", "OK" if availability.version else "WARN",
                "RECOMMENDED", detail,
            ))
            checks.append(self._volatility_cli_check(Path(availability.executable)))

        candidates: list[Path] = []
        configured = os.environ.get("FORENSIC_VOL_SYMBOLS")
        if configured:
            candidates.append(Path(configured).expanduser())
        candidates.extend((
            Path("/opt/forensic-tools/volatility-symbols"),
            Path.home() / ".cache" / "volatility3",
        ))
        package = importlib.util.find_spec("volatility3")
        if package is not None and package.origin:
            candidates.append(Path(package.origin).resolve().parent / "symbols")
        inventories: list[str] = []
        seen: set[Path] = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved in seen or not resolved.is_dir():
                continue
            seen.add(resolved)
            count = 0
            try:
                for item in resolved.rglob("*"):
                    if item.is_file() and not item.is_symlink():
                        count += 1
                        if count >= 10_000:
                            break
            except OSError:
                continue
            inventories.append(f"{resolved} ({count}{'+' if count >= 10_000 else ''} files)")
        checks.append(DoctorCheck(
            "Volatility symbols/cache",
            "OK" if inventories else "MISSING",
            "RECOMMENDED",
            "; ".join(inventories) if inventories else (
                "no offline symbol/cache directory found; prepare FORENSIC_VOL_SYMBOLS or "
                "/opt/forensic-tools/volatility-symbols while online"
            ),
        ))
        return checks

    @staticmethod
    def _volatility_cli_check(executable: Path) -> DoctorCheck:
        """Verify the exact plugins and extraction arguments ForensicKit uses."""

        required_plugins = (
            "banners.Banners",
            "windows.info.Info",
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.pstree.PsTree",
            "windows.cmdline.CmdLine",
            "windows.netscan.NetScan",
            "windows.handles.Handles",
            "windows.filescan.FileScan",
            "windows.dlllist.DllList",
            "windows.memmap.Memmap",
            "windows.malfind.Malfind",
            "windows.dumpfiles.DumpFiles",
            "linux.pslist.PsList",
            "linux.psaux.PsAux",
            "linux.sockstat.Sockstat",
        )
        argument_checks = {
            "windows.memmap.Memmap": ("--pid", "--dump"),
            "windows.dlllist.DllList": ("--pid", "--dump"),
            "windows.dumpfiles.DumpFiles": ("--physaddr",),
        }

        try:
            global_help = subprocess.run(
                [str(executable), "--help"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                timeout=5.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return DoctorCheck(
                "Volatility plugins/arguments", "BROKEN", "RECOMMENDED",
                f"unable to inspect CLI: {exc}",
            )
        help_text = global_help.stdout[:2 * 1024 * 1024].decode("utf-8", errors="replace")
        missing: list[str] = []
        if global_help.returncode != 0:
            missing.append(f"global help exited {global_help.returncode}")
        for option in ("--offline", "--renderer"):
            if option not in help_text:
                missing.append(option)
        missing.extend(plugin for plugin in required_plugins if plugin not in help_text)

        for plugin, options in argument_checks.items():
            try:
                plugin_help = subprocess.run(
                    [str(executable), plugin, "--help"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    timeout=5.0,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                missing.append(f"{plugin} help ({exc})")
                continue
            plugin_text = plugin_help.stdout[:256 * 1024].decode("utf-8", errors="replace")
            if plugin_help.returncode != 0:
                missing.append(f"{plugin} help exited {plugin_help.returncode}")
                continue
            missing.extend(f"{plugin} {option}" for option in options if option not in plugin_text)

        if missing:
            return DoctorCheck(
                "Volatility plugins/arguments", "BROKEN", "RECOMMENDED",
                "missing or unusable: " + ", ".join(missing),
            )
        return DoctorCheck(
            "Volatility plugins/arguments", "OK", "RECOMMENDED",
            f"{len(required_plugins)} plugins; Windows Info, Memmap/DllList PID dump and DumpFiles physical-address modes verified",
        )

    @staticmethod
    def _workspace_check(workspace_base: Path) -> DoctorCheck:
        try:
            workspace_base.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=workspace_base, prefix=".forensickit-doctor-"):
                pass
            return DoctorCheck("Workspace", "OK", "REQUIRED", str(workspace_base.resolve()))
        except OSError as exc:
            return DoctorCheck("Workspace", "BROKEN", "REQUIRED", str(exc))

    @staticmethod
    def _offline_bundle_check(bundle: Path | None) -> DoctorCheck:
        project_root = Path(__file__).resolve().parents[2]
        builder = project_root / "scripts" / "build_offline_bundle.sh"
        installer = project_root / "scripts" / "install_offline.sh"
        if bundle is None:
            if builder.is_file() and installer.is_file():
                return DoctorCheck(
                    "Offline bundle", "WARN", "RECOMMENDED",
                    "bundle scripts are present; run doctor --bundle BUNDLE to validate staged offline media",
                )
            return DoctorCheck("Offline bundle", "MISSING", "RECOMMENDED", "offline bundle scripts are missing")
        try:
            root = bundle.expanduser().resolve(strict=True)
        except OSError as exc:
            return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", str(exc))
        manifest = root / "manifests" / "SHA256SUMS"
        metadata = root / "manifests" / "build-manifest.env"
        wheels = root / "wheels"
        source = root / "forensickit-source.tar.gz"
        if not root.is_dir() or not manifest.is_file() or not metadata.is_file() or not wheels.is_dir() or not source.is_file():
            return DoctorCheck(
                "Offline bundle", "BROKEN", "RECOMMENDED",
                "requires manifests/SHA256SUMS, manifests/build-manifest.env, wheels/, and forensickit-source.tar.gz",
            )
        if not any(wheels.glob("*.whl")):
            return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", "bundle contains no Python wheels")
        project_wheels = sorted(wheels.glob("forensickit-*.whl"))
        if len(project_wheels) != 1:
            return DoctorCheck(
                "Offline bundle", "BROKEN", "RECOMMENDED",
                f"bundle must contain exactly one ForensicKit wheel; found {len(project_wheels)}",
            )
        try:
            metadata_values: dict[str, str] = {}
            for line in metadata.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    metadata_values[key] = value
            entries = manifest.read_text(encoding="utf-8").splitlines()
            checked = 0
            for line in entries:
                match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
                if not match:
                    return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", "invalid SHA256SUMS entry")
                expected, relative = match.groups()
                candidate = (root / relative.removeprefix("./")).resolve()
                if root not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
                    return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", f"unsafe or missing manifest member: {relative}")
                digest = hashlib.sha256()
                with candidate.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                if digest.hexdigest() != expected.casefold():
                    return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", f"checksum mismatch: {relative}")
                checked += 1
            if checked == 0:
                return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", "SHA256SUMS is empty")
        except OSError as exc:
            return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", str(exc))
        bundle_format = metadata_values.get("BUNDLE_FORMAT", "")
        component_detail = "legacy v1 manifest"
        component_warnings: tuple[str, ...] = ()
        if bundle_format == "forensickit-offline-v2":
            source_commit = metadata_values.get("SOURCE_COMMIT", "")
            source_dirty = metadata_values.get("SOURCE_DIRTY", "")
            if not re.fullmatch(r"[0-9a-fA-F]{40,64}", source_commit):
                return DoctorCheck(
                    "Offline bundle", "BROKEN", "RECOMMENDED",
                    "v2 bundle lacks a valid SOURCE_COMMIT",
                )
            if source_dirty not in {"0", "1"}:
                return DoctorCheck(
                    "Offline bundle", "BROKEN", "RECOMMENDED",
                    "v2 bundle lacks a valid SOURCE_DIRTY marker",
                )
            component_path = root / "manifests" / "component-manifest.json"
            if not component_path.is_file() or component_path.is_symlink():
                return DoctorCheck(
                    "Offline bundle", "BROKEN", "RECOMMENDED",
                    "v2 bundle requires a regular manifests/component-manifest.json",
                )
            try:
                component_payload = json.loads(component_path.read_text(encoding="utf-8"))
                validation = validate_component_manifest(root, component_payload)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return DoctorCheck("Offline bundle", "BROKEN", "RECOMMENDED", f"invalid component manifest: {exc}")
            if not validation.valid:
                return DoctorCheck(
                    "Offline bundle", "BROKEN", "RECOMMENDED",
                    f"component manifest invalid: {validation.errors[0]}",
                )
            component_warnings = validation.warnings
            if source_dirty == "1":
                component_warnings = component_warnings + (
                    "bundle was built from a dirty development worktree",
                )
            component_detail = (
                f"{validation.component_count} components, "
                f"{validation.prepared_component_count} prepared tool/symbol components, "
                f"source={source_commit[:12]}{'-dirty' if source_dirty == '1' else ''}"
            )
        elif bundle_format not in {"", "forensickit-offline-v1"}:
            return DoctorCheck(
                "Offline bundle", "BROKEN", "RECOMMENDED",
                f"unsupported or missing BUNDLE_FORMAT: {bundle_format or 'missing'}",
            )
        target_id = metadata_values.get("DISTRO_ID", "unknown")
        target_version = metadata_values.get("DISTRO_VERSION", "unknown")
        target_arch = metadata_values.get("ARCHITECTURE", "unknown")
        local_id, local_version = "unknown", "unknown"
        try:
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                if line.startswith("ID="):
                    local_id = line.removeprefix("ID=").strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    local_version = line.removeprefix("VERSION_ID=").strip().strip('"')
        except OSError:
            pass
        local_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
        compatible = (
            target_id in {"", "unknown", local_id}
            and target_version in {"", "unknown", local_version}
            and target_arch in {"", "unknown", local_arch}
        )
        detail = (
            f"verified {checked} staged files; target={target_id}/{target_version}/{target_arch}, "
            f"local={local_id}/{local_version}/{local_arch}; {component_detail}"
        )
        if component_warnings:
            detail += "; metadata warnings: " + "; ".join(component_warnings[:3])
        return DoctorCheck(
            "Offline bundle", "OK" if compatible and not component_warnings else "WARN",
            "RECOMMENDED", detail,
        )


__all__ = ["Doctor", "DoctorCheck", "DoctorResult"]
