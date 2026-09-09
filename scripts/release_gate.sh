#!/usr/bin/env bash
# Deterministic local release gate.  It performs no network operations.
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${FORENSICKIT_PYTHON:-python3}"
ALLOW_DIRTY=0
BUNDLE=""

usage() {
  cat <<'EOF'
Usage: scripts/release_gate.sh [--bundle DIR] [--allow-dirty]

  --bundle DIR    also validate a staged final offline bundle
  --allow-dirty   run development checks without claiming release readiness

The default release gate refuses uncommitted/untracked files. It performs only
local compile, syntax, full pytest, installed-core self-test, and bundle checks.
Set FORENSICKIT_PYTHON to an offline environment containing the test dependencies.
EOF
}

while (($#)); do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "release Python is unavailable: $PYTHON_BIN" >&2
  exit 1
fi
if ! git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release gate requires Git source provenance" >&2
  exit 1
fi
SOURCE_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
if [[ -n "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal)" ]] && (( ! ALLOW_DIRTY )); then
  echo "release gate failed: source tree is dirty" >&2
  exit 1
fi

cd "$PROJECT_ROOT"
git diff --check
bash -n install_forensics.sh scripts/*.sh
"$PYTHON_BIN" -m compileall -q src tests scripts
PYTHONPATH=src "$PYTHON_BIN" - <<'PY'
import tomllib
from pathlib import Path
import forensickit

root = Path.cwd()
metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
version = metadata["project"]["version"]
readme = (root / "README.md").read_text(encoding="utf-8")
if version != forensickit.__version__:
    raise SystemExit(f"version mismatch: pyproject={version}, package={forensickit.__version__}")
if f"ForensicKit v{version}" not in readme:
    raise SystemExit(f"README does not identify ForensicKit v{version}")
print(f"version consistency: {version}")
PY
PYTHONPATH=src "$PYTHON_BIN" -m pytest
"$PYTHON_BIN" scripts/run_direct_tests.py
PYTHONPATH=src "$PYTHON_BIN" -m forensickit self-test

if [[ -n "$BUNDLE" ]]; then
  BUNDLE="$(realpath -e "$BUNDLE")"
  PYTHONPATH=src "$PYTHON_BIN" -m forensickit doctor --bundle "$BUNDLE"
  scripts/install_offline.sh "$BUNDLE" --verify-only
fi

echo "Release gate passed for $SOURCE_COMMIT"
if (( ALLOW_DIRTY )); then
  echo "Development-only result: dirty source was explicitly allowed"
fi
