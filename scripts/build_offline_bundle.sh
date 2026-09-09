#!/usr/bin/env bash
# Build a same-distro, same-architecture ForensicKit bundle while online.
# The resulting bundle is consumed by scripts/install_offline.sh without any
# network access. It deliberately does not claim cross-distro compatibility.
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$PROJECT_ROOT/forensickit-offline-bundle"
TOOLS_ROOT=""
COMPONENTS_METADATA=""
INCLUDE_APT=1
ALLOW_DIRTY=0
EXTRA_PACKAGES=()

usage() {
  cat <<'EOF'
Usage: scripts/build_offline_bundle.sh [options]

  --output DIR       bundle destination (default: ./forensickit-offline-bundle)
  --tools-root DIR   archive an existing prepared forensic tool/symbol tree
  --components-metadata FILE
                     required JSON version/license/support inventory when --tools-root is used
  --package NAME     add a Debian package to the offline APT set (repeatable)
  --no-apt           create Python/source bundle only
  --allow-dirty      permit a non-release development bundle and record it as dirty
  -h, --help         show this help

Run on an online Ubuntu/Kali/Debian machine that matches the competition
machine's distro release and architecture. Existing output directories are
refused to avoid overwriting an evidence-preparation bundle.
EOF
}

while (($#)); do
  case "$1" in
    --output) OUTPUT="$2"; shift 2 ;;
    --tools-root) TOOLS_ROOT="$2"; shift 2 ;;
    --components-metadata) COMPONENTS_METADATA="$2"; shift 2 ;;
    --package) EXTRA_PACKAGES+=("$2"); shift 2 ;;
    --no-apt) INCLUDE_APT=0; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -f "$PROJECT_ROOT/pyproject.toml" ]]; then
  echo "pyproject.toml not found under $PROJECT_ROOT" >&2
  exit 1
fi

SOURCE_COMMIT="unknown"
SOURCE_DIRTY="unknown"
REPRODUCIBLE_EPOCH="315532800"
if command -v git >/dev/null 2>&1 && git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  SOURCE_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
  if [[ -n "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal)" ]]; then
    SOURCE_DIRTY="1"
    if (( ! ALLOW_DIRTY )); then
      echo "refusing to build a release bundle from a dirty worktree; commit all intended files or use --allow-dirty for a development-only bundle" >&2
      exit 1
    fi
  else
    SOURCE_DIRTY="0"
  fi
  # Derive the wheel timestamp from the latest committed wheel input, not from
  # HEAD. A follow-up commit that only records the release checksum must not
  # perturb dist-info ZIP timestamps and create a checksum cycle.
  REPRODUCIBLE_EPOCH="$(
    git -C "$PROJECT_ROOT" log -1 --format=%ct "$SOURCE_COMMIT" -- \
      pyproject.toml README.md src setup.py setup.cfg MANIFEST.in \
      ':(glob)LICENSE*' ':(glob)COPYING*'
  )"
  if [[ -z "$REPRODUCIBLE_EPOCH" ]]; then
    REPRODUCIBLE_EPOCH="$(git -C "$PROJECT_ROOT" show -s --format=%ct "$SOURCE_COMMIT")"
  fi
elif (( ! ALLOW_DIRTY )); then
  echo "refusing to build a release bundle without Git source provenance; use --allow-dirty for a development-only bundle" >&2
  exit 1
fi
if [[ ! "$REPRODUCIBLE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "could not derive a valid SOURCE_DATE_EPOCH: $REPRODUCIBLE_EPOCH" >&2
  exit 1
fi
# ZIP timestamps cannot represent dates before 1980. This also provides a
# stable fallback for explicitly allowed non-Git development source trees.
if (( REPRODUCIBLE_EPOCH < 315532800 )); then
  REPRODUCIBLE_EPOCH=315532800
fi
export SOURCE_DATE_EPOCH="$REPRODUCIBLE_EPOCH"
OUTPUT="$(realpath -m "$OUTPUT")"
if [[ -e "$OUTPUT" ]]; then
  echo "refusing to overwrite existing bundle: $OUTPUT" >&2
  exit 1
fi
if [[ -n "$TOOLS_ROOT" && -z "$COMPONENTS_METADATA" ]] || [[ -z "$TOOLS_ROOT" && -n "$COMPONENTS_METADATA" ]]; then
  echo "--tools-root and --components-metadata must be supplied together" >&2
  exit 2
fi
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  echo "this bundle builder requires /etc/os-release" >&2
  exit 1
fi

mkdir -p "$OUTPUT"/{debs,wheels,manifests,tools}
mkdir -p "$OUTPUT/debs/partial"
# Keep the bundle directly installable after it is copied to offline media;
# requiring a second checkout merely to locate the installer defeats that
# operational property.  Both helpers are covered by the bundle checksum
# manifest generated below.
install -m 0755 "$PROJECT_ROOT/scripts/install_offline.sh" "$OUTPUT/install_offline.sh"
install -m 0755 "$PROJECT_ROOT/scripts/wheelhouse_lock.py" "$OUTPUT/verify-wheelhouse.py"

APT_PACKAGES=(
  python3 python3-venv python3-pip file
  p7zip-full libimage-exiftool-perl pngcheck
  poppler-utils qpdf sqlite3
  sleuthkit ewf-tools tshark yara
)
APT_PACKAGES+=("${EXTRA_PACKAGES[@]}")
printf '%s\n' "${APT_PACKAGES[@]}" | awk 'NF && !seen[$0]++' | sort > "$OUTPUT/manifests/apt-packages.txt"

python3 -m pip wheel --wheel-dir "$OUTPUT/wheels" --prefer-binary "$PROJECT_ROOT[tui,test]"
python3 "$PROJECT_ROOT/scripts/wheelhouse_lock.py" \
  --wheel-dir "$OUTPUT/wheels" \
  --lock "$OUTPUT/manifests/python-wheel-lock.json" \
  --write

if (( INCLUDE_APT )); then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is unavailable; rerun with --no-apt or on a Debian-family preparer" >&2
    exit 1
  fi
  SUDO=()
  if [[ $EUID -ne 0 ]]; then
    SUDO=(sudo)
  fi
  "${SUDO[@]}" apt-get \
    -o "Dir::Cache::archives=$OUTPUT/debs" \
    -o "Dir::Cache::archives::partial=$OUTPUT/debs/partial" \
    --download-only --reinstall --yes --no-install-recommends install \
    $(tr '\n' ' ' < "$OUTPUT/manifests/apt-packages.txt")
  # apt keeps partial state for its own bookkeeping; it is not an installable
  # payload and should not be shipped as one.
  rm -rf "$OUTPUT/debs/partial"
fi

TAR_EXCLUDES=(
  --exclude='.git'
  --exclude='.agent'
  --exclude='.mypy_cache'
  --exclude='.pytest_cache'
  --exclude='.ruff_cache'
  --exclude='__pycache__'
  --exclude='build'
  --exclude='cases'
  --exclude='dist'
  --exclude='forensickit-offline-bundle'
)
if [[ "$OUTPUT" == "$PROJECT_ROOT"/* ]]; then
  TAR_EXCLUDES+=(--exclude="./${OUTPUT#"$PROJECT_ROOT"/}")
fi
if [[ "$SOURCE_DIRTY" == "0" ]]; then
  # A clean release archive must be an exact snapshot of the recorded commit,
  # independent of ignored build products or workstation-only files.
  git -C "$PROJECT_ROOT" archive \
    --format=tar.gz \
    --output="$OUTPUT/forensickit-source.tar.gz" \
    "$SOURCE_COMMIT"
else
  tar \
    "${TAR_EXCLUDES[@]}" \
    -czf "$OUTPUT/forensickit-source.tar.gz" \
    -C "$PROJECT_ROOT" .
fi

if [[ -n "$TOOLS_ROOT" ]]; then
  TOOLS_ROOT="$(realpath -e "$TOOLS_ROOT")"
  if [[ ! -d "$TOOLS_ROOT" ]]; then
    echo "--tools-root is not a directory: $TOOLS_ROOT" >&2
    exit 1
  fi
  COMPONENTS_METADATA="$(realpath -e "$COMPONENTS_METADATA")"
  if [[ ! -f "$COMPONENTS_METADATA" || -L "$COMPONENTS_METADATA" ]]; then
    echo "--components-metadata must be a regular non-symlink JSON file" >&2
    exit 1
  fi
  UNSAFE_MEMBER="$(find "$TOOLS_ROOT" -mindepth 1 \( -type l -o \( ! -type f ! -type d \) \) -print -quit)"
  if [[ -n "$UNSAFE_MEMBER" ]]; then
    echo "prepared tools contain a symlink or special file: $UNSAFE_MEMBER" >&2
    exit 1
  fi
  tar -czf "$OUTPUT/tools/prepared-tools.tar.gz" -C "$(dirname "$TOOLS_ROOT")" "$(basename "$TOOLS_ROOT")"
fi

cat > "$OUTPUT/manifests/build-manifest.env" <<EOF
BUNDLE_FORMAT=forensickit-offline-v2
DISTRO_ID=${ID:-unknown}
DISTRO_VERSION=${VERSION_ID:-unknown}
ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null || uname -m)
BUILT_AT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PYTHON=$(python3 --version 2>&1)
SOURCE_COMMIT=$SOURCE_COMMIT
SOURCE_DIRTY=$SOURCE_DIRTY
SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
EOF

COMPONENT_COMMAND=(
  python3 "$PROJECT_ROOT/scripts/build_component_manifest.py"
  --bundle "$OUTPUT"
  --project-root "$PROJECT_ROOT"
)
if [[ -n "$TOOLS_ROOT" ]]; then
  COMPONENT_COMMAND+=(--tools-root "$TOOLS_ROOT" --components-metadata "$COMPONENTS_METADATA")
fi
"${COMPONENT_COMMAND[@]}"

(
  cd "$OUTPUT"
  find . -type f ! -path './manifests/SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > manifests/SHA256SUMS
)
echo "Offline bundle created: $OUTPUT"
echo "Copy it to a matching offline machine, then run:"
echo "  $OUTPUT/install_offline.sh $OUTPUT"
