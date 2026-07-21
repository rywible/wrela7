# Agent notes for wrela

## Cursor Cloud specific instructions

Cloud agents run on **Ubuntu x86_64**, not macOS. This repo’s developer defaults assume Homebrew under `/opt/homebrew` (see `.cargo/config.toml`, QEMU/firmware fallbacks, and `lld-link` discovery).

`.cursor/install.sh` (run as the environment `install` / update script) sets up Linux equivalents:

| Need | Linux location | Mac-default shim |
| --- | --- | --- |
| LLVM 22.1.x (`llvm-config`) | `/usr/lib/llvm-22` (apt.llvm.org) | `/opt/homebrew/opt/llvm` |
| `lld-link` | `/usr/lib/llvm-22/bin/lld-link` | `/opt/homebrew/opt/lld/bin/lld-link` |
| `qemu-system-aarch64` | `/usr/bin/qemu-system-aarch64` | `/opt/homebrew/bin/qemu-system-aarch64` |
| EDK2 code/vars | `/usr/share/AAVMF/AAVMF_{CODE,VARS}.fd` | `/opt/homebrew/share/qemu/edk2-*.fd` |

Environment overrides are also written to `/etc/profile.d/wrela-cloud.sh`:

```bash
export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
export WRELA_LLVM_PREFIX=/usr/lib/llvm-22
export WRELA_LLD_LINK=/usr/lib/llvm-22/bin/lld-link
export WRELA_QEMU=/usr/bin/qemu-system-aarch64
export WRELA_QEMU_FIRMWARE_CODE=/usr/share/AAVMF/AAVMF_CODE.fd
export WRELA_QEMU_FIRMWARE_VARS=/usr/share/AAVMF/AAVMF_VARS.fd
# rust-lld needs GCC's libstdc++ search path when linking llvm-sys
export LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/usr/lib/gcc/x86_64-linux-gnu/13
```

If a shell does not load profile.d, `source /etc/profile.d/wrela-cloud.sh` before cargo.

Native linking also needs `libpolly-22-dev` and `libzstd-dev` (installed by the script).

### Trustworthy commands

Workspace cargo aliases use `--locked --offline`. Always `cargo fetch --locked` after dependency changes (the install script does this).

Preferred loop:

```bash
cargo xtask slices
cargo xgate semantic
cargo xgate wrela-sema
```

Native / full gates need the system LLVM/LLD (and QEMU+firmware for testing/cli):

```bash
cargo xgate artifact --full
cargo xgate backend --full
```

Non-native gates should pass without `--full` once the install script has run.

### Known host differences

- `cpufeatures` only depends on `libc` on aarch64 (and loongarch64 Linux). The reviewed xtask closure is cfg-gated so x86_64 Linux cloud VMs do not expect that edge.
- Do not use `brew`, Xcode, or Darwin-only paths in cloud sessions.
