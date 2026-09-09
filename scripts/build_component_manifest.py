#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from forensickit.bundle_manifest import build_component_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a version/license/hash inventory for an offline bundle")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--tools-root", type=Path)
    parser.add_argument("--components-metadata", type=Path)
    args = parser.parse_args()
    try:
        output = build_component_manifest(
            args.bundle, args.project_root,
            tools_root=args.tools_root,
            components_metadata=args.components_metadata,
        )
    except (OSError, ValueError) as exc:
        print(f"component manifest error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
