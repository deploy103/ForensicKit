#!/usr/bin/env bash
# Install a bundle produced by build_offline_bundle.sh without network access.
set -Eeuo pipefail

BUNDLE=""
PREFIX="/opt/forensickit"
INSTALL_APT=1
LINK_BIN=0
VERIFY_ONLY=0

usage() {
  cat <<'EOF'
Usage: scripts/install_offline.sh BUNDLE [options]

  --prefix DIR       installation prefix (default: /opt/forensickit)
  --no-apt           skip locally bundled Debian packages
  --link-bin         link forensickit into /usr/local/bin (requires root/sudo)
  --verify-only      validate local bundle structure and checksums, then exit
  -h, --help         show this help

The installer uses only local files: pip is invoked with --no-index and APT
is invoked with --no-download. It refuses a bundle with a hash mismatch.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi
BUNDLE="$1"
shift
while (($#)); do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --no-apt) INSTALL_APT=0; shift ;;
    --link-bin) LINK_BIN=1; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

BUNDLE="$(realpath -e "$BUNDLE")"
if [[ ! -f "$BUNDLE/manifests/SHA256SUMS" || ! -f "$BUNDLE/forensickit-source.tar.gz" || ! -d "$BUNDLE/wheels" ]]; then
  echo "not a ForensicKit offline bundle: $BUNDLE" >&2
  exit 1
fi
if ! compgen -G "$BUNDLE/wheels/forensickit-*.whl" >/dev/null; then
  echo "offline bundle has no ForensicKit wheel: $BUNDLE/wheels" >&2
  exit 1
fi
if ! awk '
  NF < 2 { invalid = 1; next }
  { path = $2; sub(/^[*]/, "", path) }
  path ~ /^\// || path ~ /(^|\/)\.\.($|\/)/ { invalid = 1 }
  END { exit invalid }
' "$BUNDLE/manifests/SHA256SUMS"; then
  echo "offline bundle manifest contains an unsafe checksum path" >&2
  exit 1
fi
(
  cd "$BUNDLE"
  sha256sum -c manifests/SHA256SUMS
)

if [[ -r "$BUNDLE/manifests/build-manifest.env" && -r /etc/os-release ]]; then
  # shellcheck disable=SC1090,SC1091
  . "$BUNDLE/manifests/build-manifest.env"
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${DISTRO_ID:-unknown}" != "${ID:-unknown}" || "${DISTRO_VERSION:-unknown}" != "${VERSION_ID:-unknown}" ]]; then
    echo "warning: bundle targets ${DISTRO_ID:-unknown}/${DISTRO_VERSION:-unknown}, local system is ${ID:-unknown}/${VERSION_ID:-unknown}" >&2
  fi
  LOCAL_ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  if [[ "${ARCHITECTURE:-unknown}" != "$LOCAL_ARCH" ]]; then
    echo "warning: bundle targets architecture ${ARCHITECTURE:-unknown}, local system is $LOCAL_ARCH" >&2
  fi
fi

if (( VERIFY_ONLY )); then
  echo "Offline ForensicKit bundle verified: $BUNDLE"
  exit 0
fi

SUDO=()
if [[ $EUID -ne 0 ]]; then
  SUDO=(sudo)
fi
if (( INSTALL_APT )) && compgen -G "$BUNDLE/debs/*.deb" >/dev/null; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is unavailable; use --no-apt only if local prerequisites already exist" >&2
    exit 1
  fi
  "${SUDO[@]}" apt-get --no-download --yes install "$BUNDLE"/debs/*.deb || \
    "${SUDO[@]}" apt-get --no-download --yes -f install
fi

"${SUDO[@]}" mkdir -p "$PREFIX"
"${SUDO[@]}" python3 -m venv "$PREFIX/venv"
"${SUDO[@]}" "$PREFIX/venv/bin/python" -m pip install \
  --no-index --find-links "$BUNDLE/wheels" "forensickit[tui,test]"
"${SUDO[@]}" tar -xzf "$BUNDLE/forensickit-source.tar.gz" -C "$PREFIX"
if [[ -f "$BUNDLE/tools/prepared-tools.tar.gz" ]]; then
  "${SUDO[@]}" tar -xzf "$BUNDLE/tools/prepared-tools.tar.gz" -C "$PREFIX"
fi
if (( LINK_BIN )); then
  "${SUDO[@]}" ln -sf "$PREFIX/venv/bin/forensickit" /usr/local/bin/forensickit
fi

echo "Installed offline ForensicKit at $PREFIX"
echo "Run: $PREFIX/venv/bin/forensickit doctor"
