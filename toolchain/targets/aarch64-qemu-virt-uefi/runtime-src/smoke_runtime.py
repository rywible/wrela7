#!/usr/bin/env python3
"""Link and boot the real runtime consumer under explicitly authenticated tools."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

import build_runtime


EXPECTED_FRAMES = (
    bytes.fromhex(
        "5752454c545354000100000003000000000000000000000011000000b06d85e7"
        "0300000000000000000000000001000000"
    ),
    bytes.fromhex(
        "5752454c545354000100000003000000010000000000000011000000bf729a25"
        "03000000010000000000000001c0db0000"
    ),
    bytes.fromhex(
        "5752454c545354000100000003000000020000000000000013000000b6d2a16c"
        "03000000020000000000000004c0db00000300"
    ),
    bytes.fromhex(
        "5752454c545354000100000003000000030000000000000015000000ad3072d7"
        "030000000300000000000000060000000001000000"
    ),
)
MAX_SMOKE_IMAGE_BYTES = 16 * 1024 * 1024
MAX_SMOKE_SERIAL_BYTES = 4 * 1024 * 1024


def digest_argument(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(f"--{name}-sha256", required=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "lld-link", "qemu", "firmware-code", "firmware-vars", "runtime-object"):
        parser.add_argument(f"--{name}", required=True)
        digest_argument(parser, name)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser.parse_args()


def authenticated_file(raw: str, expected: str, label: str) -> pathlib.Path:
    path = build_runtime.checked_absolute_file(raw, label)
    expected = expected.lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise build_runtime.BuildError(f"{label} SHA-256 is not canonical lowercase hexadecimal")
    actual = build_runtime.sha256_file(path)
    if actual != expected:
        raise build_runtime.BuildError(
            f"{label} digest mismatch: expected {expected}, measured {actual}"
        )
    return path


def private_root(raw: str) -> pathlib.Path:
    root = pathlib.Path(raw)
    if not root.is_absolute() or root != pathlib.Path(os.path.normpath(raw)):
        raise build_runtime.BuildError("private root must be a normalized absolute path")
    if root.is_symlink() or not root.is_dir():
        raise build_runtime.BuildError("private root must be an existing non-symlink directory")
    return root


def compile_smoke(compiler: pathlib.Path, source: pathlib.Path, output: pathlib.Path, temp: pathlib.Path) -> None:
    command = [
        str(compiler),
        "--target=aarch64-unknown-uefi",
        "-c",
        "-x",
        "assembler",
        "-nostdlib",
        "-nodefaultlibs",
        "-g0",
        "-Werror",
        str(source),
        "-o",
        str(output),
    ]
    result = subprocess.run(
        command,
        cwd=source.parent,
        env={
            "HOME": str(temp),
            "LC_ALL": "C",
            "PATH": "",
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": str(temp),
            "TZ": "UTC",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode or result.stdout or result.stderr:
        raise build_runtime.BuildError(
            "authenticated compiler failed smoke consumer:\n"
            + result.stderr.decode("utf-8", "replace")
        )


def inspect_efi(path: pathlib.Path) -> None:
    image_bytes = path.stat().st_size
    if not 0x100 <= image_bytes <= MAX_SMOKE_IMAGE_BYTES:
        raise build_runtime.BuildError("linked smoke image has an invalid bounded extent")
    data = path.read_bytes()
    if len(data) != image_bytes:
        raise build_runtime.BuildError("linked smoke image changed while it was read")
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise build_runtime.BuildError("linked smoke output is not a PE image")
    pe = struct.unpack_from("<L", data, 0x3C)[0]
    if pe + 4 + 20 + 112 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise build_runtime.BuildError("linked smoke output has an invalid PE header")
    coff = pe + 4
    machine, _, _, _, _, optional_size, _ = struct.unpack_from("<HHLLLHH", data, coff)
    optional = coff + 20
    if machine != build_runtime.MACHINE_ARM64 or optional_size < 160:
        raise build_runtime.BuildError("linked smoke output is not ARM64 PE32+")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise build_runtime.BuildError("linked smoke output is not PE32+")
    if struct.unpack_from("<Q", data, optional + 24)[0] != 0:
        raise build_runtime.BuildError("linked smoke image base is not the UEFI-safe zero base")
    if struct.unpack_from("<H", data, optional + 68)[0] != 10:
        raise build_runtime.BuildError("linked smoke output is not an EFI application")
    relocation_rva, relocation_bytes = struct.unpack_from("<LL", data, optional + 112 + 5 * 8)
    if relocation_rva == 0 or relocation_bytes == 0:
        raise build_runtime.BuildError("linked smoke output has no base relocation directory")


def slip_frames(serial: bytes) -> list[bytes]:
    frames: list[bytes] = []
    current: bytearray | None = None
    index = 0
    while index < len(serial):
        byte = serial[index]
        index += 1
        if byte == 0xC0:
            if current:
                frames.append(bytes(current))
            current = bytearray()
            continue
        if current is None:
            continue
        if byte == 0xDB:
            if index >= len(serial):
                break
            escaped = serial[index]
            index += 1
            if escaped == 0xDC:
                current.append(0xC0)
            elif escaped == 0xDD:
                current.append(0xDB)
            else:
                current = None
        else:
            current.append(byte)
    return frames


def main() -> int:
    args = parse_args()
    try:
        if not 1 <= args.timeout_seconds <= 300:
            raise build_runtime.BuildError("timeout must be between 1 and 300 seconds")
        files: dict[str, pathlib.Path] = {}
        for name in ("compiler", "lld_link", "qemu", "firmware_code", "firmware_vars", "runtime_object"):
            option = name.replace("_", "-")
            files[name] = authenticated_file(
                getattr(args, name), getattr(args, f"{name}_sha256"), option
            )
        build_runtime.inspect_coff(files["runtime_object"])
        root = private_root(args.private_root)
        source = pathlib.Path(__file__).resolve().parent / "smoke.S"
        if source.is_symlink() or not source.is_file():
            raise build_runtime.BuildError("smoke.S must be a non-symlink regular file")
        with tempfile.TemporaryDirectory(prefix="wrela-runtime-smoke-", dir=root) as raw_temp:
            temp = pathlib.Path(raw_temp)
            smoke_object = temp / "smoke.obj"
            image = temp / "BOOTAA64.EFI"
            serial = temp / "serial.bin"
            variables = temp / "QEMU_VARS.fd"
            esp_boot = temp / "esp" / "EFI" / "BOOT"
            esp_boot.mkdir(parents=True)
            compile_smoke(files["compiler"], source, smoke_object, temp)
            link = subprocess.run(
                [
                    str(files["lld_link"]),
                    "-flavor", "link",
                    "/machine:arm64",
                    "/subsystem:efi_application",
                    "/entry:wrela_image_entry",
                    "/nodefaultlib",
                    "/brepro",
                    "/dynamicbase",
                    "/lldignoreenv",
                    "/WX",
                    "/base:0",
                    f"/out:{image}",
                    str(smoke_object),
                    str(files["runtime_object"]),
                ],
                cwd=temp,
                env={"LC_ALL": "C", "PATH": "", "TZ": "UTC"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if link.returncode or link.stdout or link.stderr:
                raise build_runtime.BuildError(
                    "authenticated LLD failed smoke link:\n"
                    + (link.stdout + link.stderr).decode("utf-8", "replace")
                )
            inspect_efi(image)
            shutil.copyfile(image, esp_boot / "BOOTAA64.EFI")
            shutil.copyfile(files["firmware_vars"], variables)
            qemu = subprocess.run(
                [
                    str(files["qemu"]),
                    "-machine", "virt-10.0,gic-version=3,secure=off",
                    "-cpu", "cortex-a57",
                    "-accel", "tcg,thread=single",
                    "-m", "512",
                    "-smp", "1",
                    "-nic", "none",
                    "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={files['firmware_code']}",
                    "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
                    "-drive", f"if=none,format=raw,file=fat:rw:{temp / 'esp'},id=hd0",
                    "-device", "virtio-blk-device,drive=hd0",
                    "-serial", f"file:{serial}",
                    "-monitor", "none",
                    "-display", "none",
                    "-no-reboot",
                ],
                cwd=temp,
                env={
                    "HOME": str(temp),
                    "LC_ALL": "C",
                    "PATH": "",
                    "TMPDIR": str(temp),
                    "TZ": "UTC",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout_seconds,
                check=False,
            )
            if qemu.returncode != 0 or qemu.stdout or qemu.stderr:
                raise build_runtime.BuildError(
                    f"QEMU smoke failed with exit {qemu.returncode}:\n"
                    + (qemu.stdout + qemu.stderr).decode("utf-8", "replace")
                )
            serial_size = serial.stat().st_size
            if serial_size > MAX_SMOKE_SERIAL_BYTES:
                raise build_runtime.BuildError("bounded PL011 smoke output limit was exceeded")
            serial_bytes = serial.read_bytes()
            if len(serial_bytes) != serial_size:
                raise build_runtime.BuildError("PL011 smoke output changed while it was read")
            frames = slip_frames(serial_bytes)
            if frames != list(EXPECTED_FRAMES):
                raise build_runtime.BuildError(
                    "PL011 stream did not contain the exact typed-fatal lifecycle"
                )
            if b"\xdb\xdc" not in serial_bytes or b"\xdb\xdd" not in serial_bytes:
                raise build_runtime.BuildError("PL011 stream did not exercise both canonical SLIP escapes")
            print("qemu_smoke=pass")
            print(
                "frame_stream_sha256="
                + hashlib.sha256(b"".join(EXPECTED_FRAMES)).hexdigest()
            )
            print(f"serial_bytes={len(serial_bytes)}")
        return 0
    except subprocess.TimeoutExpired:
        print("runtime smoke failed: QEMU did not ResetSystem before the bounded timeout", file=sys.stderr)
        return 1
    except (build_runtime.BuildError, OSError, struct.error, UnicodeError) as error:
        print(f"runtime smoke failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
