#!/usr/bin/env bash
# Install a bundle produced by build_offline_bundle.sh without network access.
set -Eeuo pipefail

BUNDLE=""
PREFIX="/opt/forensickit"
PREFIX_INPUT=""
INSTALL_APT=1
LINK_BIN=0
VERIFY_ONLY=0
UPGRADE=0
ALLOW_DIRTY=0
INSTALL_MARKER=".forensickit-install"

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

BUNDLE="$(realpath -e -- "$BUNDLE")"
PREFIX_INPUT="$PREFIX"
PREFIX_LEXICAL="$PREFIX_INPUT"
while [[ "$PREFIX_LEXICAL" != "/" && "$PREFIX_LEXICAL" == */ ]]; do
  PREFIX_LEXICAL="${PREFIX_LEXICAL%/}"
done
if [[ -L "$PREFIX_LEXICAL" ]]; then
  echo "refusing to use a symbolic link as an installation prefix: $PREFIX_INPUT" >&2
  exit 1
fi
PREFIX="$(realpath -m -- "$PREFIX_INPUT")"
case "$PREFIX" in
  /)
    echo "refusing to use the filesystem root as an installation prefix" >&2
    exit 1
    ;;
  /bin|/boot|/cdrom|/dev|/etc|/home|/lib|/lib32|/lib64|/libx32|/lost+found|/media|/mnt|/opt|/proc|/root|/run|/sbin|/snap|/srv|/sys|/tmp|/usr|/var|\
  /usr/bin|/usr/include|/usr/lib|/usr/lib32|/usr/lib64|/usr/libx32|/usr/local|/usr/local/bin|/usr/local/lib|/usr/local/sbin|/usr/local/share|/usr/sbin|/usr/share|\
  /var/cache|/var/lib|/var/log|/var/spool|/var/tmp)
    echo "refusing to use a protected system path as an installation prefix: $PREFIX" >&2
    exit 1
    ;;
esac
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
SOURCE_COMMIT_VALUE="unknown"
SOURCE_DIRTY_VALUE="unknown"
if [[ "$BUNDLE_FORMAT_VALUE" == "forensickit-offline-v2" ]]; then
  if [[ ! -f "$BUNDLE/manifests/component-manifest.json" ]]; then
    echo "v2 bundle lacks manifests/component-manifest.json" >&2
    exit 1
  fi
  if [[ ! -f "$BUNDLE/manifests/python-wheel-lock.json" || \
        -L "$BUNDLE/manifests/python-wheel-lock.json" || \
        ! -f "$BUNDLE/verify-wheelhouse.py" || -L "$BUNDLE/verify-wheelhouse.py" ]]; then
    echo "v2 bundle lacks a regular wheelhouse lock or standalone verifier" >&2
    exit 1
  fi
  if ! python3 "$BUNDLE/verify-wheelhouse.py" \
      --wheel-dir "$BUNDLE/wheels" \
      --lock "$BUNDLE/manifests/python-wheel-lock.json"; then
    echo "v2 bundle wheelhouse does not match its dependency lock" >&2
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

validate_existing_install() {
  python3 - "$PREFIX" "$INSTALL_MARKER" <<'PY'
from __future__ import annotations

from email.parser import BytesParser
from pathlib import Path
import hashlib
import re
import sys
import tomllib

prefix = Path(sys.argv[1])
marker = prefix / sys.argv[2]


def regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def regular_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


def fail(reason: str) -> None:
    print(reason)
    raise SystemExit(1)


# A valid environment and installed distribution are required even when a
# marker exists.  This prevents a copied marker alone from authorizing the
# replacement of an unrelated directory.
venv = prefix / "venv"
cli = venv / "bin" / "forensickit"
if not regular_directory(venv) or not regular_file(venv / "pyvenv.cfg") or not regular_file(cli):
    fail("missing the ForensicKit virtual environment or launcher")
try:
    if cli.stat().st_size > 1024 * 1024 or b"from forensickit.cli import main" not in cli.read_bytes():
        fail("the installed launcher is not a ForensicKit console entry point")
except OSError as exc:
    fail(f"cannot inspect the installed launcher: {exc}")

metadata_versions: set[str] = set()
lib = venv / "lib"
if regular_directory(lib):
    for python_dir in lib.iterdir():
        if not python_dir.name.startswith("python") or not regular_directory(python_dir):
            continue
        site_packages = python_dir / "site-packages"
        if not regular_directory(site_packages):
            continue
        package = site_packages / "forensickit"
        if not regular_directory(package) or not regular_file(package / "__init__.py"):
            continue
        for dist_info in site_packages.iterdir():
            if not re.fullmatch(r"forensickit-[^/]+\.dist-info", dist_info.name, re.IGNORECASE):
                continue
            metadata_path = dist_info / "METADATA"
            if not regular_directory(dist_info) or not regular_file(metadata_path):
                continue
            try:
                if metadata_path.stat().st_size > 1024 * 1024:
                    continue
                metadata = BytesParser().parsebytes(metadata_path.read_bytes(), headersonly=True)
            except OSError:
                continue
            if metadata.get("Name", "").strip().lower() == "forensickit" and metadata.get("Version", "").strip():
                metadata_versions.add(metadata["Version"].strip())
if not metadata_versions:
    fail("the virtual environment has no ForensicKit distribution metadata")

if marker.exists() or marker.is_symlink():
    if not regular_file(marker):
        fail("the ForensicKit installation marker is not a regular file")
    try:
        if marker.stat().st_size > 16 * 1024:
            fail("the ForensicKit installation marker is too large")
        lines = marker.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read the ForensicKit installation marker: {exc}")
    if not lines or lines[0] != "FORENSICKIT_INSTALL_MARKER_V1":
        fail("the ForensicKit installation marker has an invalid format")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if "=" not in line:
            fail("the ForensicKit installation marker is malformed")
        key, value = line.split("=", 1)
        if key in values:
            fail("the ForensicKit installation marker has duplicate fields")
        values[key] = value
    expected_keys = {"prefix_sha256", "wheel_sha256", "bundle_format", "source_commit", "source_dirty"}
    if set(values) != expected_keys:
        fail("the ForensicKit installation marker has missing or unknown fields")
    expected_prefix = hashlib.sha256(str(prefix).encode("utf-8")).hexdigest()
    if values["prefix_sha256"] != expected_prefix:
        fail("the ForensicKit installation marker belongs to a different prefix")
    if not re.fullmatch(r"[0-9a-f]{64}", values["wheel_sha256"]):
        fail("the ForensicKit installation marker has an invalid wheel identity")
    if values["bundle_format"] not in {"forensickit-offline-v1", "forensickit-offline-v2"}:
        fail("the ForensicKit installation marker has an invalid bundle format")
    if not (values["source_commit"] == "unknown" or re.fullmatch(r"[0-9a-fA-F]{40,64}", values["source_commit"])):
        fail("the ForensicKit installation marker has invalid source provenance")
    if values["source_dirty"] not in {"0", "1", "unknown"}:
        fail("the ForensicKit installation marker has invalid dirty provenance")
    raise SystemExit(0)

# v1.1 installed source at PREFIX, while v1.2 used PREFIX/source.  Those
# releases predate the marker, so require matching source-project and wheel
# metadata in addition to the complete virtual-environment footprint above.
project_roots = (prefix / "source", prefix)
for project_root in project_roots:
    pyproject = project_root / "pyproject.toml"
    source_init = project_root / "src" / "forensickit" / "__init__.py"
    if not regular_directory(project_root) or not regular_file(pyproject) or not regular_file(source_init):
        continue
    try:
        if pyproject.stat().st_size > 1024 * 1024:
            continue
        project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        continue
    if (
        isinstance(project, dict)
        and str(project.get("name", "")).strip().lower() == "forensickit"
        and str(project.get("version", "")).strip() in metadata_versions
    ):
        raise SystemExit(0)
fail("no valid installation marker or compatible v1.1/v1.2 source layout was found")
PY
}

PREFIX_NONEMPTY=0
inspect_existing_prefix() {
  PREFIX_NONEMPTY=0
  if [[ -L "$PREFIX" ]]; then
    echo "refusing to replace a symbolic-link installation prefix: $PREFIX" >&2
    return 1
  fi
  if [[ ! -e "$PREFIX" ]]; then
    return 0
  fi
  if [[ ! -d "$PREFIX" ]]; then
    echo "installation prefix exists but is not a directory: $PREFIX" >&2
    return 1
  fi
  local first_entry
  if ! first_entry="$(find "$PREFIX" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; then
    echo "cannot safely inspect the existing installation prefix: $PREFIX" >&2
    return 1
  fi
  if [[ -n "$first_entry" ]]; then
    PREFIX_NONEMPTY=1
  fi
}

require_safe_existing_prefix() {
  inspect_existing_prefix || return 1
  if (( ! PREFIX_NONEMPTY )); then
    return 0
  fi
  if (( ! UPGRADE )); then
    echo "installation prefix is not empty; choose another --prefix or pass --upgrade: $PREFIX" >&2
    return 1
  fi
  local reason
  if ! reason="$(validate_existing_install 2>&1)"; then
    echo "refusing --upgrade because the existing prefix is not a recognized ForensicKit installation: ${reason:-identity validation failed}" >&2
    return 1
  fi
}

# Refuse an unrelated target before APT or any other installation side effect.
require_safe_existing_prefix

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
HAD_PREFIX=0
ACTIVATED=0
INSTALL_COMPLETE=0
cleanup_install() {
  "${PREFIX_SUDO[@]}" rm -rf -- "$STAGING" 2>/dev/null || true
  if (( INSTALL_COMPLETE )); then
    return
  fi
  if (( ACTIVATED )) && [[ -e "$PREFIX" ]]; then
    "${PREFIX_SUDO[@]}" rm -rf -- "$PREFIX" 2>/dev/null || true
  fi
  if (( HAD_PREFIX )) && [[ -e "$BACKUP" && ! -e "$PREFIX" ]]; then
    "${PREFIX_SUDO[@]}" mv -- "$BACKUP" "$PREFIX" 2>/dev/null || true
  fi
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
PREFIX_SHA256="$(printf '%s' "$PREFIX" | sha256sum | awk '{print $1}')"
WHEEL_SHA256="$(sha256sum "$FORENSICKIT_WHEEL" | awk '{print $1}')"
write_install_marker() {
  local install_root="$1"
  local marker_tmp="$install_root/${INSTALL_MARKER}.tmp.$$"
  "${PREFIX_SUDO[@]}" rm -f -- "$marker_tmp"
  if ! {
    {
      printf '%s\n' "FORENSICKIT_INSTALL_MARKER_V1"
      printf 'prefix_sha256=%s\n' "$PREFIX_SHA256"
      printf 'wheel_sha256=%s\n' "$WHEEL_SHA256"
      printf 'bundle_format=%s\n' "$BUNDLE_FORMAT_VALUE"
      printf 'source_commit=%s\n' "$SOURCE_COMMIT_VALUE"
      printf 'source_dirty=%s\n' "$SOURCE_DIRTY_VALUE"
    } | "${PREFIX_SUDO[@]}" tee "$marker_tmp" >/dev/null &&
      "${PREFIX_SUDO[@]}" chmod 0644 "$marker_tmp" &&
      "${PREFIX_SUDO[@]}" mv -f -- "$marker_tmp" "$install_root/$INSTALL_MARKER"
  }; then
    "${PREFIX_SUDO[@]}" rm -f -- "$marker_tmp" 2>/dev/null || true
    return 1
  fi
}
"${PREFIX_SUDO[@]}" "$STAGING/venv/bin/forensickit" --version
"${PREFIX_SUDO[@]}" "$STAGING/venv/bin/forensickit" self-test
write_install_marker "$STAGING"

# Revalidate immediately before the destructive rename.  This also detects a
# path that became non-empty or was swapped for a symlink during staging.
require_safe_existing_prefix
if [[ -e "$PREFIX" ]]; then
  HAD_PREFIX=1
  "${PREFIX_SUDO[@]}" mv -- "$PREFIX" "$BACKUP"
fi
if ! "${PREFIX_SUDO[@]}" mv -- "$STAGING" "$PREFIX"; then
  echo "failed to activate the staged installation; previous prefix was restored when possible" >&2
  exit 1
fi
ACTIVATED=1
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
    "${PREFIX_SUDO[@]}" "$PREFIX/venv/bin/forensickit" self-test &&
    write_install_marker "$PREFIX"
}
if ! finalize_install; then
  echo "final-path validation failed; previous prefix was restored when possible" >&2
  exit 1
fi
INSTALL_COMPLETE=1
if (( HAD_PREFIX )); then
  if ! "${PREFIX_SUDO[@]}" rm -rf -- "$BACKUP"; then
    echo "warning: installation succeeded, but the previous backup could not be fully removed: $BACKUP" >&2
  fi
fi
trap - EXIT
if (( LINK_BIN )); then
  "${SUDO[@]}" ln -sf "$PREFIX/venv/bin/forensickit" /usr/local/bin/forensickit
fi

echo "Installed offline ForensicKit at $PREFIX"
echo "Run: $PREFIX/venv/bin/forensickit doctor"
