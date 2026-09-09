#!/usr/bin/env bash
# Install a bundle produced by build_offline_bundle.sh without network access.
set -Eeuo pipefail

BUNDLE=""
PREFIX="/opt/forensickit"
INSTALL_APT=1
LINK_BIN=0
VERIFY_ONLY=0
UPGRADE=0
ALLOW_DIRTY=0

usage() {
  cat <<'EOF'
Usage: scripts/install_offline.sh BUNDLE [options]

  --prefix DIR       installation prefix (default: /opt/forensickit)
  --no-apt           skip locally bundled Debian packages
  --link-bin         link forensickit into /usr/local/bin (requires root/sudo)
  --upgrade          replace an existing prefix with the verified bundled build
  --allow-dirty      permit installation of an explicitly development-only bundle
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
    --upgrade) UPGRADE=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

BUNDLE="$(realpath -e "$BUNDLE")"
PREFIX="$(realpath -m "$PREFIX")"
if [[ "$PREFIX" == "/" ]]; then
  echo "refusing to use the filesystem root as an installation prefix" >&2
  exit 1
fi
if [[ "$PREFIX" == "$BUNDLE" || "$PREFIX" == "$BUNDLE"/* || "$BUNDLE" == "$PREFIX"/* ]]; then
  echo "installation prefix and bundle must not contain one another" >&2
  exit 1
fi
if [[ ! -f "$BUNDLE/manifests/SHA256SUMS" || ! -f "$BUNDLE/manifests/build-manifest.env" || ! -f "$BUNDLE/forensickit-source.tar.gz" || ! -d "$BUNDLE/wheels" ]]; then
  echo "not a ForensicKit offline bundle: $BUNDLE" >&2
  exit 1
fi
mapfile -t FORENSICKIT_WHEELS < <(find "$BUNDLE/wheels" -maxdepth 1 -type f -name 'forensickit-*.whl' -print | sort)
if ((${#FORENSICKIT_WHEELS[@]} != 1)); then
  echo "offline bundle must contain exactly one ForensicKit wheel (found ${#FORENSICKIT_WHEELS[@]}): $BUNDLE/wheels" >&2
  exit 1
fi
FORENSICKIT_WHEEL="${FORENSICKIT_WHEELS[0]}"
if [[ ! -f "$FORENSICKIT_WHEEL" ]]; then
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

manifest_value() {
  awk -F= -v wanted="$1" '$1 == wanted { sub(/^[^=]*=/, ""); print; exit }' "$BUNDLE/manifests/build-manifest.env"
}
BUNDLE_FORMAT_VALUE="$(manifest_value BUNDLE_FORMAT)"
if [[ "$BUNDLE_FORMAT_VALUE" == "forensickit-offline-v2" ]]; then
  if [[ ! -f "$BUNDLE/manifests/component-manifest.json" ]]; then
    echo "v2 bundle lacks manifests/component-manifest.json" >&2
    exit 1
  fi
  python3 - "$BUNDLE/manifests/component-manifest.json" <<'PY'
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest.get("schema_version") != 1 or manifest.get("bundle_format") != "forensickit-offline-v2":
    raise SystemExit("invalid component manifest schema/bundle format")
components = manifest.get("components")
if not isinstance(components, list) or not components:
    raise SystemExit("component manifest has no components")
for index, item in enumerate(components):
    if not isinstance(item, dict):
        raise SystemExit(f"component {index} is not an object")
    for field in ("kind", "name", "version", "license", "bundle_path", "sha256", "supported_os", "architectures"):
        if not item.get(field):
            raise SystemExit(f"component {index} lacks {field}")
PY
  SOURCE_COMMIT_VALUE="$(manifest_value SOURCE_COMMIT)"
  SOURCE_DIRTY_VALUE="$(manifest_value SOURCE_DIRTY)"
  if [[ ! "$SOURCE_COMMIT_VALUE" =~ ^[0-9a-fA-F]{40,64}$ ]] || [[ ! "$SOURCE_DIRTY_VALUE" =~ ^[01]$ ]]; then
    echo "v2 bundle lacks valid source commit/dirty provenance" >&2
    exit 1
  fi
  if [[ "$SOURCE_DIRTY_VALUE" == "1" ]]; then
    echo "warning: bundle was built from dirty development source at $SOURCE_COMMIT_VALUE" >&2
    if (( ! VERIFY_ONLY && ! ALLOW_DIRTY )); then
      echo "refusing to install a dirty development bundle without --allow-dirty" >&2
      exit 1
    fi
  fi
elif [[ "$BUNDLE_FORMAT_VALUE" != "forensickit-offline-v1" ]]; then
  echo "unsupported bundle format: ${BUNDLE_FORMAT_VALUE:-missing}" >&2
  exit 1
else
  echo "warning: legacy v1 bundle has no required component version/license/support manifest" >&2
fi

validate_archive() {
  python3 - "$1" <<'PY'
from pathlib import PurePosixPath
import sys
import tarfile

archive_path = sys.argv[1]
with tarfile.open(archive_path, "r:*") as archive:
    seen = set()
    for member in archive.getmembers():
        name = member.name
        path = PurePosixPath(name)
        if not name or "\x00" in name or path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe archive member path: {name!r}")
        normalized = path.as_posix().removeprefix("./")
        if not normalized and member.isdir():
            continue
        if not normalized or normalized in seen:
            raise SystemExit(f"duplicate or empty archive member path: {name!r}")
        seen.add(normalized)
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"archive contains a link or special member: {name!r}")
PY
}
validate_archive "$BUNDLE/forensickit-source.tar.gz"
if [[ -f "$BUNDLE/tools/prepared-tools.tar.gz" ]]; then
  validate_archive "$BUNDLE/tools/prepared-tools.tar.gz"
fi

if [[ -r /etc/os-release ]]; then
  TARGET_ID="$(manifest_value DISTRO_ID)"
  TARGET_VERSION="$(manifest_value DISTRO_VERSION)"
  TARGET_ARCH="$(manifest_value ARCHITECTURE)"
  LOCAL_ID="$(awk -F= '$1 == "ID" {gsub(/^"|"$/, "", $2); print $2; exit}' /etc/os-release)"
  LOCAL_VERSION="$(awk -F= '$1 == "VERSION_ID" {gsub(/^"|"$/, "", $2); print $2; exit}' /etc/os-release)"
  if [[ "${TARGET_ID:-unknown}" != "${LOCAL_ID:-unknown}" || "${TARGET_VERSION:-unknown}" != "${LOCAL_VERSION:-unknown}" ]]; then
    echo "warning: bundle targets ${TARGET_ID:-unknown}/${TARGET_VERSION:-unknown}, local system is ${LOCAL_ID:-unknown}/${LOCAL_VERSION:-unknown}" >&2
  fi
  LOCAL_ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  if [[ "${TARGET_ARCH:-unknown}" != "$LOCAL_ARCH" ]]; then
    echo "warning: bundle targets architecture ${TARGET_ARCH:-unknown}, local system is $LOCAL_ARCH" >&2
  fi
fi

if (( VERIFY_ONLY )); then
  echo "Offline ForensicKit bundle verified: $BUNDLE"
  exit 0
fi


if [[ -e "$PREFIX" && -n "$(find "$PREFIX" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] && (( ! UPGRADE )); then
  echo "installation prefix is not empty; choose another --prefix or pass --upgrade: $PREFIX" >&2
  exit 1
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

PREFIX_SUDO=("${SUDO[@]}")
PREFIX_PARENT="$PREFIX"
while [[ ! -e "$PREFIX_PARENT" && "$PREFIX_PARENT" != "/" ]]; do
  PREFIX_PARENT="$(dirname "$PREFIX_PARENT")"
done
if [[ -w "$PREFIX_PARENT" ]]; then
  PREFIX_SUDO=()
fi

STAGING="${PREFIX}.installing.$$"
BACKUP="${PREFIX}.backup.$$"
if [[ -e "$STAGING" || -e "$BACKUP" ]]; then
  echo "temporary install path already exists: $STAGING or $BACKUP" >&2
  exit 1
fi
cleanup_install() {
  "${PREFIX_SUDO[@]}" rm -rf -- "$STAGING" 2>/dev/null || true
}
trap cleanup_install EXIT

"${PREFIX_SUDO[@]}" mkdir -p "$(dirname "$PREFIX")" "$STAGING"
"${PREFIX_SUDO[@]}" python3 -m venv "$STAGING/venv"
"${PREFIX_SUDO[@]}" "$STAGING/venv/bin/python" -m pip install \
  --no-index --find-links "$BUNDLE/wheels" --upgrade --force-reinstall \
  "${FORENSICKIT_WHEEL}[tui,test]"
"${PREFIX_SUDO[@]}" mkdir -p "$STAGING/source" "$STAGING/prepared"
"${PREFIX_SUDO[@]}" tar --no-same-owner --no-same-permissions -xzf "$BUNDLE/forensickit-source.tar.gz" -C "$STAGING/source" --overwrite
if [[ -f "$BUNDLE/tools/prepared-tools.tar.gz" ]]; then
  "${PREFIX_SUDO[@]}" tar --no-same-owner --no-same-permissions -xzf "$BUNDLE/tools/prepared-tools.tar.gz" -C "$STAGING/prepared" --overwrite
fi
"${PREFIX_SUDO[@]}" "$STAGING/venv/bin/forensickit" --version
"${PREFIX_SUDO[@]}" "$STAGING/venv/bin/forensickit" self-test

HAD_PREFIX=0
if [[ -e "$PREFIX" ]]; then
  HAD_PREFIX=1
  "${PREFIX_SUDO[@]}" mv -- "$PREFIX" "$BACKUP"
fi
if ! "${PREFIX_SUDO[@]}" mv -- "$STAGING" "$PREFIX"; then
  if (( HAD_PREFIX )) && [[ -e "$BACKUP" ]]; then
    "${PREFIX_SUDO[@]}" mv -- "$BACKUP" "$PREFIX" || true
  fi
  echo "failed to activate the staged installation; previous prefix was restored when possible" >&2
  exit 1
fi
finalize_install() {
  # venv console-script shebangs contain their creation path. Recreate the
  # launchers and reinstall only from the verified wheelhouse at the final
  # prefix, then prove that the final-path executable works before deleting
  # the recoverable previous installation.
  "${PREFIX_SUDO[@]}" python3 -m venv --upgrade "$PREFIX/venv" &&
    "${PREFIX_SUDO[@]}" "$PREFIX/venv/bin/python" -m pip install \
      --no-index --find-links "$BUNDLE/wheels" --upgrade --force-reinstall \
      "${FORENSICKIT_WHEEL}[tui,test]" &&
    "${PREFIX_SUDO[@]}" "$PREFIX/venv/bin/forensickit" --version &&
    "${PREFIX_SUDO[@]}" "$PREFIX/venv/bin/forensickit" self-test
}
if ! finalize_install; then
  "${PREFIX_SUDO[@]}" rm -rf -- "$PREFIX" 2>/dev/null || true
  if (( HAD_PREFIX )) && [[ -e "$BACKUP" ]]; then
    "${PREFIX_SUDO[@]}" mv -- "$BACKUP" "$PREFIX" || true
  fi
  echo "final-path validation failed; previous prefix was restored when possible" >&2
  exit 1
fi
if (( HAD_PREFIX )); then
  "${PREFIX_SUDO[@]}" rm -rf -- "$BACKUP"
fi
trap - EXIT
if (( LINK_BIN )); then
  "${SUDO[@]}" ln -sf "$PREFIX/venv/bin/forensickit" /usr/local/bin/forensickit
fi

echo "Installed offline ForensicKit at $PREFIX"
echo "Run: $PREFIX/venv/bin/forensickit doctor"
