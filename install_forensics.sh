#!/usr/bin/env bash
# ForensicKit competition workstation bootstrap
# Targets: Kali Linux rolling, Ubuntu 24.04/26.04+, Debian-family systems.
# Purpose: authorized CTF / local forensic artifact analysis.
#
# Default: FULL install
# Usage:
#   bash install_forensics.sh
#   bash install_forensics.sh --core
#   bash install_forensics.sh --full
#   bash install_forensics.sh --doctor
#
# Notes:
# - Run this BEFORE the competition while Internet access is available.
# - The script never needs to execute evidence files.
# - Missing distro packages are skipped instead of aborting the entire install.

set -Eeuo pipefail

MODE="full"
DOCTOR_ONLY=0
TOOLS_ROOT="${TOOLS_ROOT:-/opt/forensic-tools}"
SRC_ROOT="$TOOLS_ROOT/src"
VENV_ROOT="$TOOLS_ROOT/venvs"
BIN_DIR="/usr/local/bin"
LOG_DIR="$TOOLS_ROOT/install-logs"
APT_UPDATED=0

for arg in "$@"; do
  case "$arg" in
    --core) MODE="core" ;;
    --full) MODE="full" ;;
    --doctor) DOCTOR_ONLY=1 ;;
    -h|--help)
      sed -n '1,24p' "$0"
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  echo "[!] /etc/os-release not found" >&2
  exit 1
fi

DISTRO="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
ARCH="$(uname -m)"

if [[ "$ARCH" == "x86_64" ]]; then
  DEB_ARCH="amd64"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  DEB_ARCH="arm64"
else
  DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo "$ARCH")"
fi

if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[SKIP/WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

mkdir_root() {
  $SUDO mkdir -p "$TOOLS_ROOT" "$SRC_ROOT" "$VENV_ROOT" "$LOG_DIR"
  $SUDO chmod 755 "$TOOLS_ROOT" "$SRC_ROOT" "$VENV_ROOT" "$LOG_DIR"
}

apt_update_once() {
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    say "apt update"
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update
    APT_UPDATED=1
  fi
}

apt_has() {
  apt-cache show "$1" >/dev/null 2>&1
}

apt_install_available() {
  local category="$1"; shift
  local available=()
  local missing=()
  local p

  for p in "$@"; do
    if apt_has "$p"; then
      available+=("$p")
    else
      missing+=("$p")
    fi
  done

  if ((${#available[@]})); then
    say "APT [$category] (${#available[@]} packages)"
    if ! $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${available[@]}"; then
      warn "Batch install had an error; retrying package-by-package"
      for p in "${available[@]}"; do
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$p" \
          || warn "apt install failed: $p"
      done
    fi
  fi

  if ((${#missing[@]})); then
    warn "Not in current APT repo: ${missing[*]}"
  fi
}

pip_try() {
  local venv="$1"; shift
  local pkg
  for pkg in "$@"; do
    "$venv/bin/python" -m pip install --upgrade "$pkg" \
      || warn "pip install failed: $pkg"
  done
}

symlink_venv_commands() {
  local venv="$1"; shift
  local cmd
  for cmd in "$@"; do
    if [[ -x "$venv/bin/$cmd" ]]; then
      $SUDO ln -sf "$venv/bin/$cmd" "$BIN_DIR/$cmd"
    fi
  done
}

github_latest_asset_url() {
  local repo="$1"
  local regex="$2"
  curl -fsSL --retry 3 "https://api.github.com/repos/${repo}/releases/latest" \
    | jq -r --arg re "$regex" '.assets[] | select(.name | test($re; "i")) | .browser_download_url' \
    | head -n1
}

download_release_archive() {
  local repo="$1"
  local regex="$2"
  local dest="$3"
  local url tmp

  url="$(github_latest_asset_url "$repo" "$regex" || true)"
  if [[ -z "$url" || "$url" == "null" ]]; then
    warn "No matching GitHub release asset: $repo / $regex"
    return 1
  fi

  tmp="$(mktemp)"
  say "Downloading $repo"
  if ! curl -fL --retry 3 "$url" -o "$tmp"; then
    rm -f "$tmp"
    warn "Download failed: $repo"
    return 1
  fi

  $SUDO rm -rf "$dest"
  $SUDO mkdir -p "$dest"

  case "$url" in
    *.zip)
      $SUDO unzip -q "$tmp" -d "$dest" || {
        rm -f "$tmp"; warn "Unzip failed: $repo"; return 1;
      }
      ;;
    *.tar.gz|*.tgz)
      $SUDO tar -xzf "$tmp" -C "$dest" || {
        rm -f "$tmp"; warn "tar.gz extract failed: $repo"; return 1;
      }
      ;;
    *.tar.xz)
      $SUDO tar -xJf "$tmp" -C "$dest" || {
        rm -f "$tmp"; warn "tar.xz extract failed: $repo"; return 1;
      }
      ;;
    *)
      $SUDO cp "$tmp" "$dest/$(basename "${url%%\?*}")"
      ;;
  esac
  rm -f "$tmp"
  ok "$repo -> $dest"
}

install_hayabusa() {
  local regex
  case "$ARCH" in
    x86_64) regex='hayabusa-.*-lin-x64-gnu\.zip$' ;;
    aarch64|arm64) regex='hayabusa-.*-lin-aarch64-gnu\.zip$' ;;
    *) warn "Hayabusa binary: unsupported arch $ARCH"; return 0 ;;
  esac

  if download_release_archive "Yamato-Security/hayabusa" "$regex" "$TOOLS_ROOT/hayabusa"; then
    local bin
    bin="$(find "$TOOLS_ROOT/hayabusa" -type f -name hayabusa -perm /111 2>/dev/null | head -n1 || true)"
    if [[ -z "$bin" ]]; then
      bin="$(find "$TOOLS_ROOT/hayabusa" -type f -name hayabusa 2>/dev/null | head -n1 || true)"
      [[ -n "$bin" ]] && $SUDO chmod +x "$bin"
    fi
    if [[ -n "$bin" ]]; then
      $SUDO ln -sf "$bin" "$BIN_DIR/hayabusa"
      ok "hayabusa"
    fi
  fi
}

install_chainsaw() {
  local regex
  case "$ARCH" in
    x86_64) regex='chainsaw.*x86_64-unknown-linux-(gnu|musl).*\.(zip|tar\.gz)$' ;;
    aarch64|arm64) regex='chainsaw.*aarch64-unknown-linux-(gnu|musl).*\.(zip|tar\.gz)$' ;;
    *) warn "Chainsaw binary: unsupported arch $ARCH"; return 0 ;;
  esac

  if download_release_archive "WithSecureLabs/chainsaw" "$regex" "$TOOLS_ROOT/chainsaw"; then
    local bin
    bin="$(find "$TOOLS_ROOT/chainsaw" -type f -name chainsaw -perm /111 2>/dev/null | head -n1 || true)"
    if [[ -z "$bin" ]]; then
      bin="$(find "$TOOLS_ROOT/chainsaw" -type f -name chainsaw 2>/dev/null | head -n1 || true)"
      [[ -n "$bin" ]] && $SUDO chmod +x "$bin"
    fi
    if [[ -n "$bin" ]]; then
      $SUDO ln -sf "$bin" "$BIN_DIR/chainsaw"
      ok "chainsaw"
    fi
  fi
}

install_jadx_release() {
  local regex='jadx-.*\.zip$'
  if download_release_archive "skylot/jadx" "$regex" "$TOOLS_ROOT/jadx"; then
    local bin
    bin="$(find "$TOOLS_ROOT/jadx" -type f -path '*/bin/jadx' | head -n1 || true)"
    if [[ -n "$bin" ]]; then
      $SUDO chmod +x "$bin"
      $SUDO ln -sf "$bin" "$BIN_DIR/jadx"
      local guibin
      guibin="$(dirname "$bin")/jadx-gui"
      [[ -f "$guibin" ]] && $SUDO chmod +x "$guibin" && $SUDO ln -sf "$guibin" "$BIN_DIR/jadx-gui"
      ok "jadx"
    fi
  fi
}

install_binwalk3_ubuntu() {
  if command -v binwalk3 >/dev/null 2>&1; then
    ok "binwalk3 already installed"
    return
  fi

  command -v cargo >/dev/null 2>&1 || {
    warn "cargo missing; cannot build Binwalk v3"
    return
  }

  local src="$SRC_ROOT/binwalk3"
  say "Building upstream Binwalk v3 (best effort)"
  $SUDO rm -rf "$src"
  $SUDO git clone --depth 1 https://github.com/ReFirmLabs/binwalk.git "$src" || {
    warn "Binwalk v3 clone failed"; return;
  }
  $SUDO chown -R "$(id -u):$(id -g)" "$src" 2>/dev/null || true

  if (cd "$src" && cargo build --release); then
    $SUDO install -m 0755 "$src/target/release/binwalk" "$BIN_DIR/binwalk3"
    ok "binwalk3"
  else
    warn "Binwalk v3 build failed; legacy binwalk remains available"
  fi
}

install_python_toolbox() {
  local venv="$VENV_ROOT/toolbox"
  say "Python forensic toolbox -> $venv"
  $SUDO rm -rf "$venv"
  $SUDO python3 -m venv "$venv"
  $SUDO chown -R "$(id -u):$(id -g)" "$venv"
  "$venv/bin/python" -m pip install -U pip setuptools wheel

  # Core libraries used by ForensicKit and by standalone forensic scripts.
  pip_try "$venv" \
    "volatility3" \
    "oletools" \
    "pefile" \
    "yara-python" \
    "capstone" \
    "construct" \
    "python-magic" \
    "Pillow" \
    "pypdf" \
    "pycryptodome" \
    "python-registry" \
    "regipy" \
    "python-evtx" \
    "scapy" \
    "dpkt" \
    "pyshark" \
    "lief" \
    "bitstring" \
    "hexdump" \
    "cbor2" \
    "msgpack" \
    "protobuf" \
    "lz4" \
    "zstandard" \
    "PyYAML" \
    "textual"

  if [[ "$MODE" == "full" ]]; then
    pip_try "$venv" \
      "stegoveritas" \
      "uefi_firmware" \
      "ubi-reader" \
      "jefferson" \
      "dissect" \
      "dissect.ntfs" \
      "dissect.esedb" \
      "dissect.cstruct"
  fi

  symlink_venv_commands "$venv" \
    vol vol.py \
    oleid olevba olemeta oleobj oletimes rtfobj \
    regipy-cli evtx_dump

  # Convenience wrapper with an explicit offline symbol path.
  cat > /tmp/vol-offline <<EOF
#!/usr/bin/env bash
exec "$venv/bin/vol" -s "$TOOLS_ROOT/volatility-symbols" "\$@"
EOF
  $SUDO install -m 0755 /tmp/vol-offline "$BIN_DIR/vol-offline"
  rm -f /tmp/vol-offline
}

install_volatility_symbols() {
  [[ "$MODE" == "full" ]] || return 0

  local dest="$TOOLS_ROOT/volatility-symbols"
  $SUDO mkdir -p "$dest"

  say "Preparing Volatility 3 offline symbol packs"
  local json
  json="$(curl -fsSL --retry 3 https://api.github.com/repos/volatilityfoundation/volatility3-test-data/releases/latest || true)"
  if [[ -z "$json" ]]; then
    warn "Could not query volatility3-test-data release; symbols skipped"
    return
  fi

  local name url
  for name in windows.zip mac.zip linux.zip; do
    url="$(printf '%s' "$json" | jq -r --arg n "$name" '.assets[] | select(.name == $n) | .browser_download_url' | head -n1)"
    if [[ -n "$url" && "$url" != "null" ]]; then
      say "Downloading Volatility symbol pack: $name"
      if $SUDO curl -fL --retry 3 "$url" -o "$dest/$name"; then
        ok "$dest/$name"
      else
        warn "Failed: $name"
        $SUDO rm -f "$dest/$name"
      fi
    else
      warn "No release asset found: $name"
    fi
  done

  # Also copy into the Python package symbol directory so plain `vol` sees them.
  local venv="$VENV_ROOT/toolbox"
  if [[ -x "$venv/bin/python" ]]; then
    local pkg_symbols
    pkg_symbols="$("$venv/bin/python" - <<'PY'
import pathlib, volatility3
print(pathlib.Path(volatility3.__file__).resolve().parent / "symbols")
PY
)"
    for name in windows.zip mac.zip linux.zip; do
      if [[ -f "$dest/$name" ]]; then
        $SUDO cp -f "$dest/$name" "$pkg_symbols/$name"
      fi
    done
  fi
}

install_zsteg() {
  if ! command -v gem >/dev/null 2>&1; then
    warn "RubyGems missing; zsteg skipped"
    return
  fi
  say "Installing zsteg"
  $SUDO gem install zsteg --no-document || warn "zsteg gem install failed"
}

install_didier_suite() {
  local src="$SRC_ROOT/DidierStevensSuite"
  say "Installing Didier Stevens Suite"
  $SUDO rm -rf "$src"
  $SUDO git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git "$src" || {
    warn "DidierStevensSuite clone failed"; return;
  }
  $SUDO chown -R "$(id -u):$(id -g)" "$src" 2>/dev/null || true

  local tool
  for tool in \
    pdfid.py pdf-parser.py oledump.py zipdump.py pecheck.py \
    xorsearch.py xor-kpa.py base64dump.py strings.py \
    emldump.py jpegdump.py pngdump.py; do
    if [[ -f "$src/$tool" ]]; then
      $SUDO chmod +x "$src/$tool"
      $SUDO ln -sf "$src/$tool" "$BIN_DIR/$tool"
    fi
  done
  ok "DidierStevensSuite"
}

install_leapp() {
  local name="$1"
  local repo="$2"
  local entry="$3"
  local src="$SRC_ROOT/$name"
  local venv="$VENV_ROOT/$name"

  say "Installing $name"
  $SUDO rm -rf "$src" "$venv"
  $SUDO git clone --depth 1 "https://github.com/$repo.git" "$src" || {
    warn "$name clone failed"; return;
  }
  $SUDO python3 -m venv "$venv"
  $SUDO chown -R "$(id -u):$(id -g)" "$src" "$venv"
  "$venv/bin/python" -m pip install -U pip setuptools wheel
  "$venv/bin/python" -m pip install -r "$src/requirements.txt" || {
    warn "$name dependency install had errors"
  }

  cat > "/tmp/$name" <<EOF
#!/usr/bin/env bash
exec "$venv/bin/python" "$src/$entry" "\$@"
EOF
  $SUDO install -m 0755 "/tmp/$name" "$BIN_DIR/$name"
  rm -f "/tmp/$name"
  ok "$name"
}

clone_rules() {
  [[ "$MODE" == "full" ]] || return 0
  local rules="$TOOLS_ROOT/rules"
  $SUDO mkdir -p "$rules"
  $SUDO chown -R "$(id -u):$(id -g)" "$rules"

  say "Caching offline detection rules"
  rm -rf "$rules/sigma" "$rules/signature-base"
  git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$rules/sigma" \
    || warn "Sigma rules clone failed"
  git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$rules/signature-base" \
    || warn "YARA signature-base clone failed"
}

doctor() {
  say "Forensic tool doctor"
  printf "Distro: %s (%s) | Arch: %s | Mode: %s\n\n" "$DISTRO" "${VERSION_ID:-?}" "$ARCH" "$MODE"

  local commands=(
    file strings xxd exiftool binwalk binwalk3
    7z unzip yara
    foremost scalpel bulk_extractor
    mmls fls fsstat icat tsk_recover ewfinfo ewfmount
    testdisk photorec
    pngcheck steghide stegseek zsteg
    tshark capinfos tcpflow tcpdump
    pdfinfo pdftotext pdfimages pdfdetach qpdf
    pdfid.py pdf-parser.py oledump.py oleid olevba
    sqlite3
    regripper reglookup hivexregedit
    hayabusa chainsaw
    vol vol-offline
    adb apktool jadx
    radare2 rizin readelf objdump gdb
    ffmpeg sox
    aleapp ileapp
  )

  local found=0 missing=0 cmd
  for cmd in "${commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf '\033[32m[OK]\033[0m      %-18s %s\n' "$cmd" "$(command -v "$cmd")"
      ((found+=1))
    else
      printf '\033[33m[MISSING]\033[0m %-18s\n' "$cmd"
      ((missing+=1))
    fi
  done
  printf "\nFound: %d | Missing: %d\n" "$found" "$missing"
  printf "Tool root: %s\n" "$TOOLS_ROOT"
  [[ -d "$TOOLS_ROOT/rules/sigma" ]] && printf "Sigma rules: %s\n" "$TOOLS_ROOT/rules/sigma"
  [[ -d "$TOOLS_ROOT/rules/signature-base" ]] && printf "YARA rules: %s\n" "$TOOLS_ROOT/rules/signature-base"
  [[ -d "$TOOLS_ROOT/volatility-symbols" ]] && printf "Volatility symbols: %s\n" "$TOOLS_ROOT/volatility-symbols"
}

if [[ "$DOCTOR_ONLY" -eq 1 ]]; then
  doctor
  exit 0
fi

mkdir_root
apt_update_once

# Prevent the tshark/wireshark package from asking an interactive capture question.
if command -v debconf-set-selections >/dev/null 2>&1; then
  echo "wireshark-common wireshark-common/install-setuid boolean false" \
    | $SUDO debconf-set-selections || true
fi

# Enable Ubuntu Universe, where many forensic packages live.
if [[ "$DISTRO" == "ubuntu" ]]; then
  apt_install_available "repo helpers" software-properties-common
  if command -v add-apt-repository >/dev/null 2>&1; then
    $SUDO add-apt-repository -y universe >/dev/null 2>&1 || true
    APT_UPDATED=0
    apt_update_once
  fi
fi

# ---------- Base / generic ----------
BASE_PACKAGES=(
  ca-certificates curl wget git jq
  python3 python3-venv python3-pip python3-dev python3-tk pipx
  build-essential pkg-config cmake
  ruby ruby-dev
  default-jre-headless
  file xxd hexedit
  binutils elfutils
  ripgrep jq
  unzip zip 7zip p7zip-full p7zip-rar unar cabextract
  gzip bzip2 xz-utils lzip lz4 lzop zstd
)

GENERIC_FORENSICS=(
  libimage-exiftool-perl exiv2 jhead
  binwalk
  bulk-extractor
  foremost scalpel magicrescue recoverjpeg
  hashdeep md5deep ssdeep
  yara
)

# ---------- Disk / filesystem ----------
DISK_PACKAGES=(
  sleuthkit
  ewf-tools afflib-tools xmount
  testdisk gddrescue dc3dd dcfldd safecopy
  ntfs-3g exfatprogs dosfstools
  btrfs-progs xfsprogs e2fsprogs
  lvm2 mdadm
  squashfs-tools cramfsprogs mtd-utils
  qemu-utils libguestfs-tools
  ext3grep ext4magic extundelete scrounge-ntfs
  libvshadow-utils
)

# ---------- Steganography / image / media ----------
STEGO_PACKAGES=(
  pngcheck pngcrush optipng
  steghide stegseek stegsnow outguess
  imagemagick graphicsmagick
  ffmpeg sox libsox-fmt-all
)

# ---------- PCAP / network artifacts ----------
NETWORK_PACKAGES=(
  tshark wireshark-common
  tcpdump tcpflow tcpick tcpreplay
  ngrep netsniff-ng
  zeek
)

# ---------- Documents / Office / email ----------
DOCUMENT_PACKAGES=(
  poppler-utils qpdf mupdf-tools ghostscript
  antiword catdoc unrtf odt2txt
  pst-utils mdbtools
  python3-olefile
)

# ---------- Windows artifacts ----------
WINDOWS_PACKAGES=(
  regripper reglookup
  libhivex-bin chntpw
  grokevt rifiuti rifiuti2 vinetto
  plaso plaso-tools
  libevt-utils libevtx-utils libregf-utils
  libesedb-utils liblnk-utils libmsiecf-utils
  libpff-tools libscca-utils
)

# ---------- Mobile ----------
MOBILE_PACKAGES=(
  adb
  apktool jadx aapt
  sqlite3 sqlitebrowser
  libimobiledevice-utils ifuse libplist-utils
)

# ---------- Binary / firmware helpers ----------
BINARY_PACKAGES=(
  gdb
  radare2 rizin rizin-cutter readpe
  patchelf nasm
  upx-ucl
  device-tree-compiler u-boot-tools
  rustc cargo libfontconfig1-dev liblzma-dev
)

# ---------- Optional GUI / heavyweight ----------
HEAVY_PACKAGES=(
  autopsy guymager gparted
  ghidra
  imhex
  audacity
  libreoffice
)

# ---------- Local password-protected evidence helpers ----------
CRACK_PACKAGES=(
  john hashcat
  fcrackzip pdfcrack rarcrack bkcrack
)

apt_install_available "base" "${BASE_PACKAGES[@]}"
apt_install_available "generic" "${GENERIC_FORENSICS[@]}"
apt_install_available "disk/filesystem" "${DISK_PACKAGES[@]}"
apt_install_available "stego/media" "${STEGO_PACKAGES[@]}"
apt_install_available "network/pcap" "${NETWORK_PACKAGES[@]}"
apt_install_available "documents" "${DOCUMENT_PACKAGES[@]}"
apt_install_available "windows artifacts" "${WINDOWS_PACKAGES[@]}"
apt_install_available "mobile" "${MOBILE_PACKAGES[@]}"
apt_install_available "binary/firmware" "${BINARY_PACKAGES[@]}"

if [[ "$MODE" == "full" ]]; then
  apt_install_available "heavy/gui" "${HEAVY_PACKAGES[@]}"
  apt_install_available "local evidence password helpers" "${CRACK_PACKAGES[@]}"
fi

# Kali currently maintains a dedicated forensic metapackage. Use it in FULL mode
# to catch forensic packages that may not be in the explicit cross-distro list.
if [[ "$DISTRO" == "kali" && "$MODE" == "full" ]]; then
  apt_install_available "Kali forensic metapackage" kali-tools-forensics
  apt_install_available "Kali extras" binwalk3 kali-tools-crypto-stego
fi

install_python_toolbox
install_zsteg

if [[ "$MODE" == "full" ]]; then
  install_hayabusa
  install_chainsaw
  install_didier_suite

  # JADX apt availability varies by distro/release.
  command -v jadx >/dev/null 2>&1 || install_jadx_release

  # Kali ships binwalk3 directly. Ubuntu usually needs upstream build.
  if [[ "$DISTRO" != "kali" ]]; then
    install_binwalk3_ubuntu
  fi

  install_volatility_symbols

  # Mobile forensic extraction parsers.
  install_leapp "aleapp" "abrignoni/ALEAPP" "aleapp.py"
  install_leapp "ileapp" "abrignoni/iLEAPP" "ileapp.py"

  clone_rules
fi

# Convenience environment file for ForensicKit / shell sessions.
cat > /tmp/forensic-tools-env.sh <<EOF
export FORENSIC_TOOLS_ROOT="$TOOLS_ROOT"
export FORENSIC_SIGMA_RULES="$TOOLS_ROOT/rules/sigma"
export FORENSIC_YARA_RULES="$TOOLS_ROOT/rules/signature-base"
export FORENSIC_VOL_SYMBOLS="$TOOLS_ROOT/volatility-symbols"
EOF
$SUDO install -m 0644 /tmp/forensic-tools-env.sh /etc/profile.d/forensic-tools.sh
rm -f /tmp/forensic-tools-env.sh

doctor

say "Install finished"
echo "Recommended before competition:"
echo "  1) Reboot once if GUI packages were installed."
echo "  2) Run: bash $0 --doctor"
echo "  3) Disable Internet and test real sample files."
echo "  4) Copy $TOOLS_ROOT plus this script and your ForensicKit project to backup media."
