#!/usr/bin/env bash
# Deterministic local release gate.  It performs no network operations.
# The repository-root SHA256SUMS is the canonical release-wheel manifest: its
# path field is the wheel basename exactly as it appears below bundle/wheels/.
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
  BUILD_MANIFEST="$BUNDLE/manifests/build-manifest.env"
  SOURCE_ARCHIVE="$BUNDLE/forensickit-source.tar.gz"
  WHEELHOUSE_LOCK="$BUNDLE/manifests/python-wheel-lock.json"
  BUNDLED_INSTALLER="$BUNDLE/install_offline.sh"
  BUNDLED_WHEELHOUSE_VERIFIER="$BUNDLE/verify-wheelhouse.py"
  if [[ ! -f "$BUILD_MANIFEST" || ! -f "$SOURCE_ARCHIVE" || ! -d "$BUNDLE/wheels" || \
        ! -f "$BUNDLED_INSTALLER" || ! -f "$BUNDLED_WHEELHOUSE_VERIFIER" ]]; then
    echo "release bundle is missing its build manifest, source archive, wheelhouse, or standalone installer helpers: $BUNDLE" >&2
    exit 1
  fi
  if ! cmp -s "$PROJECT_ROOT/scripts/install_offline.sh" "$BUNDLED_INSTALLER" || \
     ! cmp -s "$PROJECT_ROOT/scripts/wheelhouse_lock.py" "$BUNDLED_WHEELHOUSE_VERIFIER"; then
    echo "release bundle installer helpers do not exactly match current HEAD" >&2
    exit 1
  fi
  manifest_value() {
    local key="$1"
    awk -F= -v wanted="$key" '
      $1 == wanted { count += 1; sub(/^[^=]*=/, ""); value = $0 }
      END { if (count != 1) exit 1; print value }
    ' "$BUILD_MANIFEST"
  }
  if ! BUNDLE_SOURCE_COMMIT="$(manifest_value SOURCE_COMMIT)"; then
    echo "release bundle must contain exactly one SOURCE_COMMIT value" >&2
    exit 1
  fi
  if ! BUNDLE_SOURCE_DIRTY="$(manifest_value SOURCE_DIRTY)"; then
    echo "release bundle must contain exactly one SOURCE_DIRTY value" >&2
    exit 1
  fi
  if [[ "$BUNDLE_SOURCE_COMMIT" != "$SOURCE_COMMIT" ]]; then
    echo "release bundle source commit does not match current HEAD: bundle=$BUNDLE_SOURCE_COMMIT head=$SOURCE_COMMIT" >&2
    exit 1
  fi
  if [[ "$BUNDLE_SOURCE_DIRTY" != "0" ]]; then
    echo "release bundle must have SOURCE_DIRTY=0 (found ${BUNDLE_SOURCE_DIRTY:-missing})" >&2
    exit 1
  fi

  # Compare the complete uncompressed tar stream, including paths, modes,
  # mtimes, and content, with Git's authoritative archive for current HEAD.
  EXPECTED_SOURCE_TAR_SHA="$(git -C "$PROJECT_ROOT" archive --format=tar "$SOURCE_COMMIT" | sha256sum | awk '{print $1}')"
  if ! BUNDLE_SOURCE_TAR_SHA="$(gzip -dc -- "$SOURCE_ARCHIVE" | sha256sum | awk '{print $1}')"; then
    echo "release bundle source archive is not a readable gzip tar" >&2
    exit 1
  fi
  if [[ "$BUNDLE_SOURCE_TAR_SHA" != "$EXPECTED_SOURCE_TAR_SHA" ]]; then
    echo "release bundle source archive does not exactly match git archive HEAD" >&2
    exit 1
  fi

  mapfile -t BUNDLE_PROJECT_WHEELS < <(find "$BUNDLE/wheels" -maxdepth 1 -type f -name 'forensickit-*.whl' -print | sort)
  if ((${#BUNDLE_PROJECT_WHEELS[@]} != 1)); then
    echo "release bundle must contain exactly one ForensicKit wheel (found ${#BUNDLE_PROJECT_WHEELS[@]})" >&2
    exit 1
  fi
  BUNDLE_PROJECT_WHEEL="${BUNDLE_PROJECT_WHEELS[0]}"
  mapfile -t ROOT_WHEEL_CHECKSUMS < <(awk 'NF && $1 !~ /^#/ { print }' "$PROJECT_ROOT/SHA256SUMS")
  if ((${#ROOT_WHEEL_CHECKSUMS[@]} != 1)); then
    echo "root SHA256SUMS must contain exactly one canonical release-wheel entry" >&2
    exit 1
  fi
  read -r ROOT_WHEEL_SHA ROOT_WHEEL_BASENAME ROOT_WHEEL_EXTRA <<< "${ROOT_WHEEL_CHECKSUMS[0]}"
  ROOT_WHEEL_BASENAME="${ROOT_WHEEL_BASENAME#\*}"
  if [[ -n "${ROOT_WHEEL_EXTRA:-}" || ! "$ROOT_WHEEL_SHA" =~ ^[0-9a-fA-F]{64}$ || \
        -z "$ROOT_WHEEL_BASENAME" || "$ROOT_WHEEL_BASENAME" == */* || \
        "$ROOT_WHEEL_BASENAME" == "." || "$ROOT_WHEEL_BASENAME" == ".." ]]; then
    echo "root SHA256SUMS entry must be: <sha256>  <wheel-basename>" >&2
    exit 1
  fi
  if [[ "$ROOT_WHEEL_BASENAME" != "$(basename "$BUNDLE_PROJECT_WHEEL")" ]]; then
    echo "bundled ForensicKit wheel basename does not match root SHA256SUMS: bundle=$(basename "$BUNDLE_PROJECT_WHEEL") canonical=$ROOT_WHEEL_BASENAME" >&2
    exit 1
  fi
  BUNDLE_PROJECT_WHEEL_SHA="$(sha256sum "$BUNDLE_PROJECT_WHEEL" | awk '{print $1}')"
  if [[ "${ROOT_WHEEL_SHA,,}" != "$BUNDLE_PROJECT_WHEEL_SHA" ]]; then
    echo "bundled ForensicKit wheel hash does not match root SHA256SUMS" >&2
    exit 1
  fi
  "$PYTHON_BIN" scripts/wheelhouse_lock.py \
    --wheel-dir "$BUNDLE/wheels" \
    --lock "$WHEELHOUSE_LOCK"
  PYTHONPATH=src "$PYTHON_BIN" -m forensickit doctor --bundle "$BUNDLE"
  "$BUNDLED_INSTALLER" "$BUNDLE" --verify-only
fi

echo "Release gate passed for $SOURCE_COMMIT"
if (( ALLOW_DIRTY )); then
  echo "Development-only result: dirty source was explicitly allowed"
fi
