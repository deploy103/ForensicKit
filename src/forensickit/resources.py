from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    configured = os.environ.get("FORENSICKIT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    package_path = Path(__file__).resolve()
    packaged_config = package_path.parent / "data"
    if (packaged_config / "tool-catalog.yaml").is_file():
        return package_path.parent
    candidates = [Path.cwd(), *package_path.parents]
    for candidate in candidates:
        if (candidate / "config" / "tool-catalog.yaml").is_file():
            return candidate
    return Path.cwd()


def default_tool_catalog() -> Path | None:
    root = project_root()
    packaged = root / "data" / "tool-catalog.yaml"
    if packaged.is_file():
        return packaged
    path = root / "config" / "tool-catalog.yaml"
    return path if path.is_file() else None


def default_rules_path() -> Path | None:
    root = project_root()
    packaged = root / "data" / "rules.example.yaml"
    if packaged.is_file():
        return packaged
    path = root / "config" / "rules.example.yaml"
    return path if path.is_file() else None
