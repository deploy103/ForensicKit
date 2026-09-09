from __future__ import annotations

"""Build and validate an auditable offline-bundle component manifest."""

from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tomllib
import zipfile


@dataclass(frozen=True, slots=True)
class ComponentManifestValidation:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    component_count: int
    prepared_component_count: int

    @property
    def valid(self) -> bool:
        return not self.errors


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value or "\t" in value:
        raise ValueError("component path must be a nonempty single-line relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe component path: {value}")
    return path


def _resolved_member(root: Path, relative: object) -> Path:
    safe = _safe_relative_path(relative)
    candidate = root.joinpath(*safe.parts)
    current = root
    for part in safe.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"component path traverses a symbolic link: {relative}")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        raise ValueError(f"component path escapes its root: {relative}")
    return resolved


def _tree_identity(path: Path) -> tuple[str, int, int, list[Path]]:
    root = path.resolve(strict=True)
    if root.is_symlink():
        raise ValueError(f"prepared component is a symbolic link: {path}")
    if root.is_file():
        return _sha256(root), 1, root.stat().st_size, [root]
    if not root.is_dir():
        raise ValueError(f"prepared component is not a regular file/directory: {path}")
    files: list[Path] = []
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_symlink():
            raise ValueError(f"prepared component contains symbolic link: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ValueError(f"prepared component contains special file: {candidate}")
        relative = candidate.relative_to(root).as_posix()
        _safe_relative_path(relative)
        files.append(candidate)
    digest = hashlib.sha256()
    total = 0
    for candidate in files:
        relative = candidate.relative_to(root).as_posix()
        size = candidate.stat().st_size
        file_digest = _sha256(candidate)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\x00")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        total += size
    return digest.hexdigest(), len(files), total, files


def _os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("ID", "unknown"), values.get("VERSION_ID", "unknown")


def _project_license(project: dict[str, object]) -> str:
    value = project.get("license")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("text", "file"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return "NOASSERTION"


def _wheel_support(tags: list[str]) -> tuple[list[str], list[str]]:
    lowered = " ".join(tags).casefold()
    systems: list[str] = []
    for marker, name in (("linux", "linux"), ("win", "windows"), ("macosx", "macos")):
        if marker in lowered and name not in systems:
            systems.append(name)
    if "-any" in lowered or not systems:
        systems.append("any")
    architectures: list[str] = []
    for marker, name in (
        ("x86_64", "amd64"), ("amd64", "amd64"), ("aarch64", "arm64"),
        ("arm64", "arm64"), ("i686", "i386"), ("-any", "any"),
    ):
        if marker in lowered and name not in architectures:
            architectures.append(name)
    if not architectures:
        architectures.append("unknown")
    return systems, architectures


def _wheel_component(bundle: Path, wheel: Path) -> tuple[dict[str, object], list[str]]:
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise ValueError("wheel must contain exactly one METADATA and WHEEL file")
            metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8", errors="replace"))
            wheel_metadata = Parser().parsestr(archive.read(wheel_names[0]).decode("utf-8", errors="replace"))
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise ValueError(f"invalid wheel {wheel.name}: {exc}") from exc
    name = metadata.get("Name") or wheel.name
    version = metadata.get("Version") or "unknown"
    license_value = metadata.get("License-Expression") or metadata.get("License")
    if not license_value:
        classifiers = metadata.get_all("Classifier", [])
        license_value = "; ".join(item for item in classifiers if item.startswith("License ::")) or "NOASSERTION"
    if str(license_value).strip().casefold() in {"", "unknown", "noassertion"}:
        warnings.append(f"Python wheel {name} {version} has no asserted license metadata")
        license_value = "NOASSERTION"
    tags = wheel_metadata.get_all("Tag", [])
    supported_os, architectures = _wheel_support(tags)
    return {
        "kind": "python_wheel",
        "name": str(name),
        "version": str(version),
        "license": str(license_value).strip()[:2_000],
        "supported_os": supported_os,
        "architectures": architectures,
        "python_requires": metadata.get("Requires-Python") or "unspecified",
        "wheel_tags": tags[:64],
        "bundle_path": wheel.relative_to(bundle).as_posix(),
        "sha256": _sha256(wheel),
        "size": wheel.stat().st_size,
    }, warnings


def _deb_field(path: Path, field: str) -> str:
    completed = subprocess.run(
        ["dpkg-deb", "-f", str(path), field],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"dpkg-deb could not read {path.name} field {field}: {completed.stderr.strip()[:500]}")
    return completed.stdout.strip()


def _deb_component(bundle: Path, package: Path, distro: str) -> dict[str, object]:
    name = _deb_field(package, "Package")
    version = _deb_field(package, "Version")
    architecture = _deb_field(package, "Architecture")
    return {
        "kind": "debian_package",
        "name": name,
        "version": version,
        "license": f"package copyright: /usr/share/doc/{name}/copyright",
        "supported_os": [distro],
        "architectures": [architecture],
        "section": _deb_field(package, "Section") or "unspecified",
        "homepage": _deb_field(package, "Homepage") or "unspecified",
        "bundle_path": package.relative_to(bundle).as_posix(),
        "sha256": _sha256(package),
        "size": package.stat().st_size,
    }


def _resource_version(path: Path) -> str:
    try:
        match = re.search(r"(?m)^version:\s*['\"]?([^'\"\s#]+)", path.read_text(encoding="utf-8")[:64 * 1024])
    except OSError:
        return "unknown"
    return match.group(1) if match else "unknown"


def _normalized_distribution_name(value: object) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip()).casefold()


def build_component_manifest(
    bundle: Path,
    project_root: Path,
    *,
    tools_root: Path | None = None,
    components_metadata: Path | None = None,
) -> Path:
    bundle = bundle.resolve(strict=True)
    project_root = project_root.resolve(strict=True)
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml has no project table")
    project_name = str(project.get("name") or "forensickit")
    project_version = str(project.get("version") or "unknown")
    project_license = _project_license(project)
    distro, distro_version = _os_release()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    warnings: list[str] = []
    if project_license == "NOASSERTION":
        warnings.append("ForensicKit project license is not declared in pyproject.toml")

    components: list[dict[str, object]] = []
    source = bundle / "forensickit-source.tar.gz"
    components.append({
        "kind": "source_archive", "name": project_name, "version": project_version,
        "license": project_license, "supported_os": ["linux"], "architectures": ["any"],
        "bundle_path": source.relative_to(bundle).as_posix(), "sha256": _sha256(source),
        "size": source.stat().st_size,
    })
    for wheel in sorted((bundle / "wheels").glob("*.whl")):
        component, wheel_warnings = _wheel_component(bundle, wheel)
        components.append(component)
        warnings.extend(wheel_warnings)
    debs = sorted((bundle / "debs").glob("*.deb"))
    if debs and shutil.which("dpkg-deb") is None:
        raise ValueError("dpkg-deb is required to inventory staged Debian packages")
    components.extend(_deb_component(bundle, package, distro) for package in debs)

    resources_dir = bundle / "manifests" / "runtime-resources"
    resources_dir.mkdir(parents=True, exist_ok=True)
    resources = (
        ("rule_pack", project_root / "config" / "rules.example.yaml", "rules-config.yaml"),
        ("rule_pack", project_root / "src" / "forensickit" / "data" / "rules.example.yaml", "rules-packaged.yaml"),
        ("tool_catalog", project_root / "config" / "tool-catalog.yaml", "tool-catalog-config.yaml"),
        ("tool_catalog", project_root / "src" / "forensickit" / "data" / "tool-catalog.yaml", "tool-catalog-packaged.yaml"),
    )
    for kind, source_path, name in resources:
        destination = resources_dir / name
        shutil.copy2(source_path, destination)
        components.append({
            "kind": kind, "name": name, "version": _resource_version(source_path),
            "license": project_license, "supported_os": ["linux"], "architectures": ["any"],
            "bundle_path": destination.relative_to(bundle).as_posix(),
            "sha256": _sha256(destination), "size": destination.stat().st_size,
        })

    prepared: list[dict[str, object]] = []
    if (tools_root is None) != (components_metadata is None):
        raise ValueError("--tools-root and --components-metadata must be supplied together")
    if tools_root is not None and components_metadata is not None:
        tools_root = tools_root.resolve(strict=True)
        metadata_path = components_metadata.resolve(strict=True)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1 or not isinstance(metadata.get("components"), list):
            raise ValueError("prepared component metadata requires schema_version=1 and a components array")
        archive = bundle / "tools" / "prepared-tools.tar.gz"
        if not archive.is_file():
            raise ValueError("prepared-tools.tar.gz is missing")
        covered: set[Path] = set()
        targets: list[Path] = []
        for index, raw in enumerate(metadata["components"]):
            if not isinstance(raw, dict):
                raise ValueError(f"prepared component {index} is not an object")
            for field in ("kind", "name", "version", "license", "path"):
                if not isinstance(raw.get(field), str) or not str(raw[field]).strip():
                    raise ValueError(f"prepared component {index} lacks {field}")
            if raw["kind"] not in {"tool", "symbols", "rule_pack"}:
                raise ValueError(f"prepared component {index} has unsupported kind {raw['kind']!r}")
            for field in ("supported_os", "architectures"):
                if not isinstance(raw.get(field), list) or not raw[field] or not all(isinstance(item, str) and item for item in raw[field]):
                    raise ValueError(f"prepared component {index} requires nonempty {field}")
            safe = _safe_relative_path(raw["path"])
            target = _resolved_member(tools_root, raw["path"])
            digest, file_count, total_bytes, files = _tree_identity(target)
            targets.append(target)
            covered.update(files)
            prepared.append({
                "kind": raw["kind"], "name": raw["name"], "version": raw["version"],
                "license": raw["license"], "supported_os": raw["supported_os"],
                "architectures": raw["architectures"], "source": raw.get("source", "unspecified"),
                "content_path": safe.as_posix(), "content_sha256": digest,
                "file_count": file_count, "total_bytes": total_bytes,
                "bundle_path": archive.relative_to(bundle).as_posix(),
                "bundle_sha256": _sha256(archive),
            })
        _, _, _, all_files = _tree_identity(tools_root)
        uncovered = [item.relative_to(tools_root).as_posix() for item in all_files if item not in covered]
        if uncovered:
            raise ValueError(f"prepared component metadata does not cover {len(uncovered)} file(s), first: {uncovered[0]}")
        copied_metadata = bundle / "manifests" / "prepared-components-input.json"
        shutil.copy2(metadata_path, copied_metadata)
        components.append({
            "kind": "prepared_component_metadata", "name": copied_metadata.name,
            "version": "1", "license": "metadata-only", "supported_os": ["any"],
            "architectures": ["any"], "bundle_path": copied_metadata.relative_to(bundle).as_posix(),
            "sha256": _sha256(copied_metadata), "size": copied_metadata.stat().st_size,
        })

    manifest = {
        "schema_version": 1,
        "bundle_format": "forensickit-offline-v2",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "build_environment": {
            "distro_id": distro, "distro_version": distro_version,
            "architecture": architecture, "python": platform.python_version(),
        },
        "components": components,
        "prepared_components": prepared,
        "warnings": sorted(set(warnings)),
    }
    output = bundle / "manifests" / "component-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output


def validate_component_manifest(bundle: Path, payload: object) -> ComponentManifestValidation:
    bundle = bundle.resolve(strict=True)
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return ComponentManifestValidation(("component manifest schema_version must be 1",), (), 0, 0)
    if payload.get("bundle_format") != "forensickit-offline-v2":
        errors.append("component manifest bundle_format is not forensickit-offline-v2")
    components = payload.get("components")
    prepared = payload.get("prepared_components")
    if not isinstance(components, list) or not components:
        errors.append("component manifest has no components")
        components = []
    if not isinstance(prepared, list):
        errors.append("component manifest prepared_components must be an array")
        prepared = []
    kinds: set[str] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            errors.append(f"component {index} is not an object")
            continue
        kind = str(component.get("kind") or "")
        kinds.add(kind)
        for field in ("kind", "name", "version", "license", "bundle_path", "sha256"):
            if not isinstance(component.get(field), str) or not str(component[field]).strip():
                errors.append(f"component {index} lacks {field}")
        for field in ("supported_os", "architectures"):
            value = component.get(field)
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
                errors.append(f"component {index} requires nonempty {field}")
        if str(component.get("license") or "").casefold() in {"unknown", "noassertion"}:
            warnings.append(f"component {component.get('name', index)} has no asserted license")
        try:
            candidate = _resolved_member(bundle, component.get("bundle_path"))
            if not candidate.is_file():
                raise ValueError("component payload is not a regular file")
            actual = _sha256(candidate)
            expected = str(component.get("sha256") or "").casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
                errors.append(f"component {index} payload checksum mismatch")
            if component.get("size") != candidate.stat().st_size:
                errors.append(f"component {index} payload size mismatch")
        except (OSError, ValueError) as exc:
            errors.append(f"component {index}: {exc}")
    for required in ("source_archive", "python_wheel", "rule_pack", "tool_catalog"):
        if required not in kinds:
            errors.append(f"component manifest lacks {required}")
    source_components = [item for item in components if isinstance(item, dict) and item.get("kind") == "source_archive"]
    if len(source_components) != 1:
        errors.append(f"component manifest requires exactly one source_archive; found {len(source_components)}")
    else:
        source_component = source_components[0]
        project_name = _normalized_distribution_name(source_component.get("name"))
        project_wheels = [
            item for item in components
            if isinstance(item, dict)
            and item.get("kind") == "python_wheel"
            and _normalized_distribution_name(item.get("name")) == project_name
        ]
        if len(project_wheels) != 1:
            errors.append(
                f"component manifest requires exactly one {source_component.get('name')} wheel; "
                f"found {len(project_wheels)}"
            )
        elif project_wheels[0].get("version") != source_component.get("version"):
            errors.append(
                "ForensicKit source/wheel version mismatch: "
                f"{source_component.get('version')} != {project_wheels[0].get('version')}"
            )
    tools_archive = bundle / "tools" / "prepared-tools.tar.gz"
    if tools_archive.is_file() and not prepared:
        errors.append("prepared tool archive has no prepared component metadata")
    for index, component in enumerate(prepared):
        if not isinstance(component, dict):
            errors.append(f"prepared component {index} is not an object")
            continue
        for field in (
            "kind", "name", "version", "license", "content_path",
            "content_sha256", "bundle_path", "bundle_sha256",
        ):
            if not isinstance(component.get(field), str) or not str(component[field]).strip():
                errors.append(f"prepared component {index} lacks {field}")
        for field in ("supported_os", "architectures"):
            value = component.get(field)
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
                errors.append(f"prepared component {index} requires nonempty {field}")
        if str(component.get("license") or "").casefold() in {"unknown", "noassertion"}:
            warnings.append(f"prepared component {component.get('name', index)} has no asserted license")
        try:
            _safe_relative_path(component.get("content_path"))
            archive = _resolved_member(bundle, component.get("bundle_path"))
            expected = str(component.get("bundle_sha256") or "").casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or _sha256(archive) != expected:
                errors.append(f"prepared component {index} archive checksum mismatch")
            content_digest = str(component.get("content_sha256") or "").casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", content_digest):
                errors.append(f"prepared component {index} has invalid content checksum")
        except (OSError, ValueError) as exc:
            errors.append(f"prepared component {index}: {exc}")
    declared_warnings = payload.get("warnings", [])
    if isinstance(declared_warnings, list):
        warnings.extend(str(item)[:2_000] for item in declared_warnings if str(item))
    else:
        errors.append("component manifest warnings must be an array")
    return ComponentManifestValidation(
        tuple(dict.fromkeys(errors)), tuple(dict.fromkeys(warnings)),
        len(components), len(prepared),
    )


__all__ = [
    "ComponentManifestValidation", "build_component_manifest",
    "validate_component_manifest",
]
