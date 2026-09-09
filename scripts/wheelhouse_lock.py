#!/usr/bin/env python3
"""Create or verify the immutable Python wheelhouse resolution lock.

The bundle checksum manifest protects bytes, while this lock also records the
resolved distribution names, versions, dependency metadata, and the one-wheel-
per-distribution invariant relied on by offline pip installation.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import compat32
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile


SCHEMA_VERSION = 1


def _normalized_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _wheel_metadata(path: Path) -> tuple[str, str, list[str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = [
                name for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
                and len(Path(name).parts) == 2
            ]
            if len(names) != 1:
                raise ValueError(
                    f"{path.name}: expected exactly one dist-info/METADATA, found {len(names)}"
                )
            metadata = BytesParser(policy=compat32).parsebytes(archive.read(names[0]))
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ValueError(f"{path.name}: cannot read wheel metadata: {exc}") from exc

    name = str(metadata.get("Name", "")).strip()
    version = str(metadata.get("Version", "")).strip()
    if not name or not version:
        raise ValueError(f"{path.name}: wheel metadata lacks Name or Version")
    requirements = sorted(str(item).strip() for item in metadata.get_all("Requires-Dist", []))
    return name, version, requirements


def build_lock(wheel_dir: Path) -> dict[str, object]:
    if not wheel_dir.is_dir():
        raise ValueError(f"wheelhouse is not a directory: {wheel_dir}")
    entries = sorted(wheel_dir.iterdir(), key=lambda item: item.name)
    unexpected = [
        item.name for item in entries
        if item.is_symlink() or not item.is_file() or item.suffix.casefold() != ".whl"
    ]
    if unexpected:
        raise ValueError(
            "wheelhouse contains a symlink, directory, special entry, or non-wheel file: "
            + ", ".join(unexpected)
        )
    wheel_paths = entries
    if not wheel_paths:
        raise ValueError(f"wheelhouse contains no wheels: {wheel_dir}")

    wheels: list[dict[str, object]] = []
    distributions: dict[str, str] = {}
    for path in wheel_paths:
        name, version, requirements = _wheel_metadata(path)
        normalized_name = _normalized_distribution(name)
        previous = distributions.get(normalized_name)
        if previous is not None:
            raise ValueError(
                f"wheelhouse has multiple candidates for distribution {normalized_name}: "
                f"{previous}, {path.name}"
            )
        distributions[normalized_name] = path.name
        wheels.append({
            "filename": path.name,
            "name": name,
            "normalized_name": normalized_name,
            "requires_dist": requirements,
            "sha256": _sha256(path),
            "version": version,
        })

    project_wheels = [item for item in wheels if item["normalized_name"] == "forensickit"]
    if len(project_wheels) != 1:
        raise ValueError(
            "wheelhouse must contain exactly one ForensicKit distribution "
            f"(found {len(project_wheels)})"
        )
    return {
        "install_target": "forensickit[tui,test]",
        "policy": "one immutable wheel candidate per normalized distribution",
        "schema_version": SCHEMA_VERSION,
        "wheels": wheels,
    }


def _render(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify the offline Python wheelhouse lock")
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--lock", dest="lock_path", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="write a new canonical lock instead of verifying one")
    args = parser.parse_args()
    try:
        actual = build_lock(args.wheel_dir)
        rendered = _render(actual)
        if args.write:
            args.lock_path.parent.mkdir(parents=True, exist_ok=True)
            args.lock_path.write_text(rendered, encoding="utf-8", newline="\n")
            print(f"Python wheelhouse locked: {args.lock_path}")
            return 0
        if not args.lock_path.is_file() or args.lock_path.is_symlink():
            raise ValueError(f"wheelhouse lock is missing or unsafe: {args.lock_path}")
        try:
            recorded = json.loads(args.lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read wheelhouse lock: {exc}") from exc
        if recorded != actual:
            raise ValueError("wheelhouse lock does not exactly match the bundled wheel artifacts and metadata")
    except (OSError, ValueError) as exc:
        print(f"wheelhouse lock error: {exc}", file=sys.stderr)
        return 1
    print(f"Python wheelhouse lock verified: {args.lock_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
