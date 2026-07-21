#!/usr/bin/env bash
# Idempotent Cursor Cloud update script for wrela on Ubuntu.
# Installs Linux stand-ins for the Mac/Homebrew defaults baked into this repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '[wrela-cloud] %s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_apt_packages() {
  local packages=(
    build-essential
    pkg-config
    cmake
    curl
    ca-certificates
    gnupg
    lsb-release
    qemu-system-arm
    qemu-efi-aarch64
    # llvm-sys static link line (Homebrew LLVM pulls these in automatically)
    libzstd-dev
    zlib1g-dev
    libxml2-dev
    libffi-dev
  )
  local missing=()
  local pkg
  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} > 0)); then
    log "installing apt packages: ${missing[*]}"
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  else
    log "apt packages already present"
  fi
}

ensure_polly_22() {
  if [[ -f /usr/lib/llvm-22/lib/libPolly.a ]] && dpkg -s libpolly-22-dev >/dev/null 2>&1; then
    return 0
  fi
  log "installing libpolly-22-dev"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libpolly-22-dev
}

install_llvm_22() {
  if [[ -x /usr/lib/llvm-22/bin/llvm-config ]] && [[ -x /usr/lib/llvm-22/bin/lld-link ]]; then
    local version
    version="$(/usr/lib/llvm-22/bin/llvm-config --version)"
    case "$version" in
      22.1.*)
        log "LLVM $version already installed"
        ensure_polly_22
        return 0
        ;;
    esac
  fi

  log "installing LLVM 22 from apt.llvm.org"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget

  local llvm_sh
  llvm_sh="$(mktemp)"
  curl -fsSL https://apt.llvm.org/llvm.sh -o "$llvm_sh"
  sudo bash "$llvm_sh" 22
  rm -f "$llvm_sh"
  ensure_polly_22

  if [[ ! -x /usr/lib/llvm-22/bin/llvm-config ]]; then
    log "error: llvm-config missing after LLVM 22 install"
    exit 1
  fi
  if [[ ! -f /usr/lib/llvm-22/lib/libPolly.a ]]; then
    log "error: libPolly.a missing after LLVM 22 install"
    exit 1
  fi
}

# Repo defaults point at Homebrew paths (/opt/homebrew/...). On Linux cloud VMs
# we materialize compatible symlinks so .cargo/config.toml and fallbacks work.
install_homebrew_shims() {
  local llvm_prefix=/usr/lib/llvm-22
  local qemu_bin=/usr/bin/qemu-system-aarch64
  local firmware_code=/usr/share/AAVMF/AAVMF_CODE.fd
  local firmware_vars=/usr/share/AAVMF/AAVMF_VARS.fd

  if [[ ! -x "$llvm_prefix/bin/llvm-config" ]]; then
    log "error: expected $llvm_prefix/bin/llvm-config"
    exit 1
  fi
  if [[ ! -x "$qemu_bin" ]]; then
    log "error: expected $qemu_bin"
    exit 1
  fi
  if [[ ! -f "$firmware_code" || ! -f "$firmware_vars" ]]; then
    log "error: expected AAVMF firmware under /usr/share/AAVMF"
    exit 1
  fi

  log "refreshing /opt/homebrew compatibility shims"
  sudo mkdir -p /opt/homebrew/opt /opt/homebrew/bin /opt/homebrew/share/qemu /opt/homebrew/opt/lld/bin
  sudo ln -sfn "$llvm_prefix" /opt/homebrew/opt/llvm
  sudo ln -sfn "$llvm_prefix/bin/lld-link" /opt/homebrew/opt/lld/bin/lld-link
  sudo ln -sfn "$qemu_bin" /opt/homebrew/bin/qemu-system-aarch64
  sudo ln -sfn "$firmware_code" /opt/homebrew/share/qemu/edk2-aarch64-code.fd
  sudo ln -sfn "$firmware_vars" /opt/homebrew/share/qemu/edk2-arm-vars.fd
}

install_env_profile() {
  local profile=/etc/profile.d/wrela-cloud.sh
  local gcc_lib
  gcc_lib="$(dirname "$(g++ -print-file-name=libstdc++.so)")"
  log "writing $profile (gcc lib dir: $gcc_lib)"
  sudo tee "$profile" >/dev/null <<EOF
# Linux overrides for wrela Mac/Homebrew defaults (see AGENTS.md)
export LLVM_SYS_221_PREFIX="\${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}"
export WRELA_LLVM_PREFIX="\${WRELA_LLVM_PREFIX:-/usr/lib/llvm-22}"
export WRELA_LLD_LINK="\${WRELA_LLD_LINK:-/usr/lib/llvm-22/bin/lld-link}"
export WRELA_QEMU="\${WRELA_QEMU:-/usr/bin/qemu-system-aarch64}"
export WRELA_QEMU_FIRMWARE_CODE="\${WRELA_QEMU_FIRMWARE_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}"
export WRELA_QEMU_FIRMWARE_VARS="\${WRELA_QEMU_FIRMWARE_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
# Keep shimmed Homebrew paths on PATH for tools that resolve by name.
export PATH="/opt/homebrew/bin:/usr/lib/llvm-22/bin:\${PATH}"
# rust-lld (used by the Rust driver) does not search GCC's libstdc++ dir by default.
export LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:${gcc_lib}\${LIBRARY_PATH:+:\$LIBRARY_PATH}"
EOF

  # shellcheck disable=SC1090
  source "$profile"
  if [[ -f "${HOME}/.bashrc" ]] && ! grep -q 'wrela-cloud.sh' "${HOME}/.bashrc"; then
    printf '\n# wrela cloud env\nsource /etc/profile.d/wrela-cloud.sh\n' >>"${HOME}/.bashrc"
  fi
}

ensure_rust_toolchain() {
  if ! need_cmd rustup; then
    log "error: rustup is required on the Cursor base image"
    exit 1
  fi
  # rust-toolchain.toml pins 1.95.0; ensure it is present for offline aliases.
  rustup show active-toolchain >/dev/null
  log "active rustc: $(rustc --version)"
}

fetch_cargo_deps() {
  log "cargo fetch --locked"
  cargo fetch --locked
}

verify_native_tools() {
  log "verifying native toolchain resolution"
  /usr/lib/llvm-22/bin/llvm-config --version | grep -E '^22\.1\.' >/dev/null
  test -x /usr/lib/llvm-22/bin/lld-link
  test -f /usr/lib/llvm-22/lib/libPolly.a
  test -x /usr/bin/qemu-system-aarch64
  test -f /usr/share/AAVMF/AAVMF_CODE.fd
  test -f /usr/share/AAVMF/AAVMF_VARS.fd
  test -x /opt/homebrew/opt/llvm/bin/llvm-config
  test -x /opt/homebrew/opt/lld/bin/lld-link
  test -x /opt/homebrew/bin/qemu-system-aarch64
  test -f /opt/homebrew/share/qemu/edk2-aarch64-code.fd
  test -f /opt/homebrew/share/qemu/edk2-arm-vars.fd
  log "native tools ok (LLVM $(/usr/lib/llvm-22/bin/llvm-config --version))"
}

install_apt_packages
install_llvm_22
install_homebrew_shims
install_env_profile
ensure_rust_toolchain
fetch_cargo_deps
verify_native_tools
log "cloud environment update complete"
