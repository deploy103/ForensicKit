#!/usr/bin/env bash
# Build a same-distro, same-architecture ForensicKit bundle while online.
# The resulting bundle is consumed by scripts/install_offline.sh without any
# network access. It deliberately does not claim cross-distro compatibility.
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$PROJECT_ROOT/forensickit-offline-bundle"
TOOLS_ROOT=""
INCLUDE_APT=1
EXTRA_PACKAGES=()

usage() {
  cat <<'EOF'
Usage: scripts/build_offline_bundle.sh [options]

  --output DIR       bundle destination (default: ./forensickit-offline-bundle)
  --tools-root DIR   archive an existing prepared forensic tool/symbol tree
  --package NAME     add a Debian package to the offline APT set (repeatable)
  --no-apt           create Python/source bundle only
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
    --package) EXTRA_PACKAGES+=("$2"); shift 2 ;;
    --no-apt) INCLUDE_APT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -f "$PROJECT_ROOT/pyproject.toml" ]]; then
  echo "pyproject.toml not found under $PROJECT_ROOT" >&2
  exit 1
fi
if [[ -e "$OUTPUT" ]]; then
  echo "refusing to overwrite existing bundle: $OUTPUT" >&2
  exit 1
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

APT_PACKAGES=(
  python3 python3-venv python3-pip file
  p7zip-full libimage-exiftool-perl pngcheck
  poppler-utils qpdf sqlite3
  sleuthkit ewf-tools tshark yara
)
APT_PACKAGES+=("${EXTRA_PACKAGES[@]}")
printf '%s\n' "${APT_PACKAGES[@]}" | awk 'NF && !seen[$0]++' | sort > "$OUTPUT/manifests/apt-packages.txt"

python3 -m pip wheel --wheel-dir "$OUTPUT/wheels" --prefer-binary "$PROJECT_ROOT[tui,test]"

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

tar \
  --exclude='.git' \
  --exclude='.pytest_cache' \
  --exclude='__pycache__' \
  --exclude='cases' \
  --exclude='forensickit-offline-bundle' \
  -czf "$OUTPUT/forensickit-source.tar.gz" \
  -C "$PROJECT_ROOT" .

if [[ -n "$TOOLS_ROOT" ]]; then
  TOOLS_ROOT="$(realpath -e "$TOOLS_ROOT")"
  if [[ ! -d "$TOOLS_ROOT" ]]; then
    echo "--tools-root is not a directory: $TOOLS_ROOT" >&2
    exit 1
  fi
  tar -czf "$OUTPUT/tools/prepared-tools.tar.gz" -C "$(dirname "$TOOLS_ROOT")" "$(basename "$TOOLS_ROOT")"
fi

cat > "$OUTPUT/manifests/build-manifest.env" <<EOF
BUNDLE_FORMAT=forensickit-offline-v1
DISTRO_ID=${ID:-unknown}
DISTRO_VERSION=${VERSION_ID:-unknown}
ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null || uname -m)
BUILT_AT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PYTHON=$(python3 --version 2>&1)
EOF

(
  cd "$OUTPUT"
  find . -type f ! -path './manifests/SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > manifests/SHA256SUMS
)
echo "Offline bundle created: $OUTPUT"
echo "Copy it to a matching offline machine, then run:"
echo "  scripts/install_offline.sh $OUTPUT"
