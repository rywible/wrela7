#!/usr/bin/env python3
"""Reproducibly build and structurally inspect the Wrela ARM64 COFF runtime."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import struct
import subprocess
import sys
import tempfile


MACHINE_ARM64 = 0xAA64
REQUIRED_SYMBOLS = {
    "wrela_rt_v2_image_enter",
    "wrela_rt_v2_image_exit",
    "wrela_rt_v2_fatal",
    "wrela_rt_v2_cpu_idle",
    "wrela_rt_v2_interrupt_mask",
    "wrela_rt_v2_interrupt_restore",
    "wrela_rt_v2_cache_maintain",
    "wrela_rt_v2_record_event",
    "wrela_rt_v2_replay_event",
    "wrela_rt_v2_test_emit",
    "wrela_rt_v2_test_finish",
    "wrela_rt_v2_test_assertion_fail",
}
REQUIRED_SECTIONS = {".text", ".rdata", ".bss"}
IMAGE_REL_ARM64_ADDR64 = 0x000E
IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004
IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
MAX_RUNTIME_OBJECT_BYTES = 16 * 1024 * 1024


class BuildError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def checked_absolute_file(raw: str, label: str) -> pathlib.Path:
    path = pathlib.Path(raw)
    if not path.is_absolute() or path != pathlib.Path(os.path.normpath(raw)):
        raise BuildError(f"{label} must be a normalized absolute path")
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"{label} must name a non-symlink regular file")
    return path


def checked_output(raw: str) -> pathlib.Path:
    path = pathlib.Path(raw)
    if not path.is_absolute() or path != pathlib.Path(os.path.normpath(raw)):
        raise BuildError("output must be a normalized absolute path")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise BuildError("output parent must be an existing non-symlink directory")
    return path


def read_c_string(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= limit:
        raise BuildError("COFF string offset escapes the string table")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise BuildError("unterminated COFF string")
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError("non-UTF-8 COFF string") from error


def inspect_coff(path: pathlib.Path) -> dict[str, object]:
    file_bytes = path.stat().st_size
    if not 20 <= file_bytes <= MAX_RUNTIME_OBJECT_BYTES:
        raise BuildError(
            f"runtime object size {file_bytes} is outside 20..={MAX_RUNTIME_OBJECT_BYTES}"
        )
    data = path.read_bytes()
    if len(data) != file_bytes:
        raise BuildError("runtime object changed while it was read")
    if len(data) < 20:
        raise BuildError("truncated COFF header")
    machine, section_count, timestamp, symbol_offset, symbol_count, optional_size, flags = (
        struct.unpack_from("<HHLLLHH", data, 0)
    )
    if machine != MACHINE_ARM64:
        raise BuildError(f"COFF machine is 0x{machine:04x}, expected ARM64")
    if not 1 <= section_count <= 32:
        raise BuildError("invalid COFF section count")
    if timestamp != 0:
        raise BuildError("COFF timestamp is not reproducible zero")
    if optional_size != 0:
        raise BuildError("object unexpectedly has an optional header")
    if flags != 0:
        raise BuildError("object has unexpected COFF file characteristics")
    section_end = 20 + section_count * 40
    symbol_end = symbol_offset + symbol_count * 18
    if section_end > len(data) or symbol_offset < section_end or symbol_end > len(data):
        raise BuildError("COFF tables escape the object")
    if symbol_end + 4 > len(data):
        raise BuildError("missing COFF string table")
    string_bytes = struct.unpack_from("<L", data, symbol_end)[0]
    if string_bytes < 4 or symbol_end + string_bytes != len(data):
        raise BuildError("COFF string table is not exact-consumption canonical")

    def name_from(raw: bytes) -> str:
        if raw[:4] == b"\0\0\0\0":
            offset = struct.unpack_from("<L", raw, 4)[0]
            if offset < 4:
                raise BuildError("invalid long-name string offset")
            return read_c_string(data, symbol_end + offset, symbol_end + string_bytes)
        try:
            return raw.rstrip(b"\0").decode("ascii")
        except UnicodeDecodeError as error:
            raise BuildError("non-ASCII short COFF symbol name") from error

    sections: list[dict[str, object]] = []
    section_names: set[str] = set()
    relocations: list[tuple[str, int, int, int]] = []
    for index in range(section_count):
        offset = 20 + index * 40
        raw_name = data[offset : offset + 8]
        if raw_name.startswith(b"/"):
            try:
                name_offset = int(raw_name[1:].rstrip(b"\0").decode("ascii"), 10)
            except ValueError as error:
                raise BuildError("invalid section long-name offset") from error
            name = read_c_string(data, symbol_end + name_offset, symbol_end + string_bytes)
        else:
            try:
                name = raw_name.rstrip(b"\0").decode("ascii")
            except UnicodeDecodeError as error:
                raise BuildError("non-ASCII short COFF section name") from error
        if name in section_names:
            raise BuildError(f"duplicate COFF section {name}")
        section_names.add(name)
        virtual_size, virtual_address, raw_size, raw_offset, reloc_offset, _, reloc_count, _, characteristics = struct.unpack_from(
            "<LLLLLLHHL", data, offset + 8
        )
        if raw_size:
            uninitialized = bool(characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            if uninitialized:
                if raw_offset != 0:
                    raise BuildError(f"uninitialized section {name} unexpectedly has raw bytes")
            elif raw_offset < section_end or raw_offset + raw_size > symbol_offset:
                raise BuildError(f"section {name} raw data escapes the object")
        if reloc_count:
            reloc_end = reloc_offset + reloc_count * 10
            if reloc_offset < section_end or reloc_end > symbol_offset:
                raise BuildError(f"section {name} relocations escape the object")
            for relocation in range(reloc_count):
                reloc_at = reloc_offset + relocation * 10
                address, symbol_index, relocation_type = struct.unpack_from("<LLH", data, reloc_at)
                if address >= max(raw_size, virtual_size) or symbol_index >= symbol_count:
                    raise BuildError(f"section {name} has an invalid relocation")
                relocations.append((name, address, symbol_index, relocation_type))
        sections.append(
            {
                "name": name,
                "raw_size": raw_size,
                "virtual_size": virtual_size,
                "relocations": reloc_count,
                "characteristics": characteristics,
            }
        )
    if not REQUIRED_SECTIONS.issubset(section_names):
        missing = sorted(REQUIRED_SECTIONS - section_names)
        raise BuildError(f"missing required COFF sections: {', '.join(missing)}")
    if section_names != {".text", ".data", ".bss", ".rdata"}:
        raise BuildError(f"unexpected COFF section set: {', '.join(sorted(section_names))}")
    by_name = {str(section["name"]): section for section in sections}
    text_flags = int(by_name[".text"]["characteristics"])
    if not (text_flags & IMAGE_SCN_CNT_CODE and text_flags & IMAGE_SCN_MEM_EXECUTE and text_flags & IMAGE_SCN_MEM_READ) or text_flags & IMAGE_SCN_MEM_WRITE:
        raise BuildError(".text does not have canonical read/execute code permissions")
    rdata_flags = int(by_name[".rdata"]["characteristics"])
    if not (rdata_flags & IMAGE_SCN_CNT_INITIALIZED_DATA and rdata_flags & IMAGE_SCN_MEM_READ) or rdata_flags & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE):
        raise BuildError(".rdata does not have canonical read-only data permissions")
    bss_flags = int(by_name[".bss"]["characteristics"])
    if not (bss_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA and bss_flags & IMAGE_SCN_MEM_READ and bss_flags & IMAGE_SCN_MEM_WRITE) or bss_flags & IMAGE_SCN_MEM_EXECUTE:
        raise BuildError(".bss does not have canonical read/write uninitialized permissions")
    if int(by_name[".text"]["raw_size"]) == 0 or int(by_name[".rdata"]["raw_size"]) != 24:
        raise BuildError("runtime code or relocation-anchor extent is invalid")
    if int(by_name[".data"]["raw_size"]) != 0:
        raise BuildError("runtime unexpectedly contains initialized mutable data")
    if int(by_name[".bss"]["raw_size"]) != 73_984:
        raise BuildError("runtime fixed-state extent drifted from 73,984 bytes")

    defined: dict[str, int] = {}
    undefined: set[str] = set()
    principal_symbols: set[int] = set()
    symbol_names: dict[int, str] = {}
    symbol_index = 0
    while symbol_index < symbol_count:
        offset = symbol_offset + symbol_index * 18
        name = name_from(data[offset : offset + 8])
        _, section_number, _, storage_class, auxiliary = struct.unpack_from("<LhHBB", data, offset + 8)
        if symbol_index + auxiliary >= symbol_count:
            raise BuildError("COFF auxiliary symbol records escape the symbol table")
        principal_symbols.add(symbol_index)
        symbol_names[symbol_index] = name
        if storage_class == 2:  # IMAGE_SYM_CLASS_EXTERNAL
            if section_number == 0:
                undefined.add(name)
            elif section_number > 0:
                if name in defined:
                    raise BuildError(f"duplicate external definition {name}")
                defined[name] = section_number
        symbol_index += 1 + auxiliary
    missing_symbols = REQUIRED_SYMBOLS - defined.keys()
    if missing_symbols:
        raise BuildError(f"missing runtime symbols: {', '.join(sorted(missing_symbols))}")
    if undefined:
        raise BuildError(f"runtime has undefined externals: {', '.join(sorted(undefined))}")
    extra_symbols = defined.keys() - REQUIRED_SYMBOLS
    if extra_symbols:
        raise BuildError(f"unexpected external definitions: {', '.join(sorted(extra_symbols))}")
    text_index = next(index + 1 for index, section in enumerate(sections) if section["name"] == ".text")
    if any(section != text_index for section in defined.values()):
        raise BuildError("one or more runtime ABI symbols are not defined in .text")
    allowed_relocations = {
        IMAGE_REL_ARM64_ADDR64,
        IMAGE_REL_ARM64_PAGEBASE_REL21,
        IMAGE_REL_ARM64_PAGEOFFSET_12A,
    }
    for section, _, target, relocation_type in relocations:
        if target not in principal_symbols:
            raise BuildError(f"section {section} relocation targets an auxiliary symbol")
        if relocation_type not in allowed_relocations:
            raise BuildError(f"section {section} has unexpected ARM64 relocation 0x{relocation_type:04x}")
    anchors = [
        relocation
        for relocation in relocations
        if relocation[0] == ".rdata" and relocation[3] == IMAGE_REL_ARM64_ADDR64
    ]
    if len(anchors) != 1 or symbol_names.get(anchors[0][2]) != "wrela_rt_v2_image_enter":
        raise BuildError("runtime lacks its required ARM64 ADDR64 relocation anchor")
    if not relocations:
        raise BuildError("runtime contains no relocations")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sections": sections,
        "defined_runtime_symbols": sorted(REQUIRED_SYMBOLS),
        "undefined_symbols": [],
        "relocation_count": len(relocations),
        "has_addr64_relocation": True,
        "coff_characteristics": flags,
    }


def compile_once(compiler: pathlib.Path, source: pathlib.Path, output: pathlib.Path, temp: pathlib.Path) -> None:
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
    environment = {
        "HOME": str(temp),
        "LC_ALL": "C",
        "PATH": "",
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": str(temp),
        "TZ": "UTC",
    }
    result = subprocess.run(
        command,
        cwd=str(source.parent),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")
        raise BuildError(f"authenticated compiler rejected runtime.S:\n{stderr}")
    if result.stdout or result.stderr:
        raise BuildError("compiler unexpectedly produced diagnostics")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--compiler-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-object-sha256")
    parser.add_argument("--verify-existing", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        compiler = checked_absolute_file(args.compiler, "compiler")
        output = checked_output(args.output)
        expected_compiler = args.compiler_sha256.lower()
        if len(expected_compiler) != 64 or any(c not in "0123456789abcdef" for c in expected_compiler):
            raise BuildError("compiler SHA-256 must be 64 lowercase hexadecimal digits")
        actual_compiler = sha256_file(compiler)
        if actual_compiler != expected_compiler:
            raise BuildError(
                f"compiler digest mismatch: expected {expected_compiler}, measured {actual_compiler}"
            )
        source = pathlib.Path(__file__).resolve().parent / "runtime.S"
        if not source.is_file() or source.is_symlink():
            raise BuildError("runtime.S must be a non-symlink regular file beside this script")
        expected_object = args.expected_object_sha256
        if expected_object is not None:
            expected_object = expected_object.lower()
            if len(expected_object) != 64 or any(
                character not in "0123456789abcdef" for character in expected_object
            ):
                raise BuildError("expected object SHA-256 is not canonical lowercase hexadecimal")
        if args.verify_existing:
            if not output.is_file() or output.is_symlink():
                raise BuildError("existing output must be a non-symlink regular file")
            report = inspect_coff(output)
            if expected_object is not None and report["sha256"] != expected_object:
                raise BuildError(
                    f"object digest mismatch: expected {expected_object}, measured {report['sha256']}"
                )
        else:
            with tempfile.TemporaryDirectory(prefix="wrela-runtime-", dir=str(output.parent)) as raw_temp:
                temp = pathlib.Path(raw_temp)
                first_root = temp / "first"
                second_root = temp / "second"
                first_root.mkdir()
                second_root.mkdir()
                first = first_root / "runtime.obj"
                second = second_root / "runtime.obj"
                compile_once(compiler, source, first, first_root)
                compile_once(compiler, source, second, second_root)
                first_bytes = first.read_bytes()
                second_bytes = second.read_bytes()
                if first_bytes != second_bytes:
                    raise BuildError("two isolated runtime builds were not byte-identical")
                report = inspect_coff(first)
                if expected_object is not None and report["sha256"] != expected_object:
                    raise BuildError(
                        f"object digest mismatch: expected {expected_object}, measured {report['sha256']}"
                    )
                staged = temp / "published.obj"
                staged.write_bytes(first_bytes)
                with staged.open("rb") as artifact:
                    os.fsync(artifact.fileno())
                os.replace(staged, output)
                directory_fd = os.open(output.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        print(f"compiler_sha256={actual_compiler}")
        print(f"source_sha256={sha256_file(source)}")
        print(f"object_sha256={report['sha256']}")
        print(f"object_bytes={report['bytes']}")
        print(f"relocations={report['relocation_count']}")
        print("defined_runtime_symbols=" + ",".join(report["defined_runtime_symbols"]))
        print("undefined_symbols=none")
        return 0
    except (BuildError, OSError, struct.error, UnicodeError) as error:
        print(f"runtime build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
