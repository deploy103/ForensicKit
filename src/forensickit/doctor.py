from __future__ import annotations

import importlib.util
import hashlib
import platform
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .tools.registry import ToolRegistry


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
                "Textual TUI", "OK" if textual_available else "MISSING", "RECOMMENDED",
                "install the offline `forensickit[tui]` extra for `forensickit` / `forensickit tui`",
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
        checks.append(
            DoctorCheck(
                "Offline runtime",
                "OK",
                "REQUIRED",
                "core analysis performs no network requests or external API calls",
            )
        )
        return DoctorResult(checks)

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
            f"local={local_id}/{local_version}/{local_arch}"
        )
        return DoctorCheck("Offline bundle", "OK" if compatible else "WARN", "RECOMMENDED", detail)


__all__ = ["Doctor", "DoctorCheck", "DoctorResult"]
