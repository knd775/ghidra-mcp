"""Framework-mode builds: configure a stub, harvest objects from the build tree.

The linked ELF is the wrong harvest: --gc-sections drops anything the stub's
main.c did not reference. Corpus entries come from per-library .o / .a files.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

ET_REL = 1
EM_ARM = 40
EM_AARCH64 = 183
EM_X86_64 = 62
TARGET_MACHINES = {EM_ARM, EM_AARCH64, EM_X86_64}

HOST_TOOL_DIR_NAMES = frozenset(
    {
        "pioasm",
        "pioasmBuild",
        "elf2uf2",
        "elf2uf2Build",
        "picotool",
        "picotoolBuild",
        "pioasm-install",
    }
)

SUBMODULE_MARKERS = (
    ("/lib/tinyusb/", "tinyusb"),
    ("/tinyusb/src/", "tinyusb"),
    ("/lib/lwip/", "lwip"),
    ("/lib/btstack/", "btstack"),
    ("/lib/mbedtls/", "mbedtls"),
    ("/lib/cyw43-driver/", "cyw43-driver"),
    ("/lib/tinyusb/", "tinyusb"),
)

COMPONENT_RE = re.compile(r"/(hardware_[a-z0-9_]+|pico_[a-z0-9_]+)/")
CMAKE_TARGET_RE = re.compile(r"CMakeFiles/([^/]+)\.dir")

STUB_ENV = "GHIDRA_MCP_STUBS"
DEFAULT_STUBS = Path("/opt/ghidra-builder/stubs")

RunFn = Callable[..., Any]


def stubs_root() -> Path:
    raw = os.environ.get(STUB_ENV, "").strip()
    if raw:
        return Path(raw)
    here = Path(__file__).resolve().parent
    repo_stubs = here.parent / "stubs"
    if repo_stubs.is_dir():
        return repo_stubs
    return DEFAULT_STUBS


def is_stub_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    return (path / "stub.json").is_file() or (path / "CMakeLists.txt").is_file()


def list_stubs(root: Path | None = None) -> list[str]:
    base = root or stubs_root()
    if not base.is_dir():
        return []
    names = []
    for child in sorted(base.iterdir()):
        if is_stub_dir(child):
            names.append(child.name)
    return names


def stub_dir(framework: str, root: Path | None = None) -> Path:
    name = (framework or "").strip()
    available = list_stubs(root)
    if not name:
        raise FrameworkError(
            "framework is required in mode=framework; available: " + str(available),
            status="missing_framework",
            extra={"available": available},
        )
    dest = (root or stubs_root()) / name
    if not is_stub_dir(dest):
        raise FrameworkError(
            f"unknown framework {name!r}; available: {available}",
            status="unknown_framework",
            extra={"available": available, "framework": name},
        )
    return dest


class FrameworkError(Exception):
    def __init__(self, message: str, *, status: str, extra: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


def elf_type_and_machine(path: Path) -> tuple[int, int] | None:
    """Return (e_type, e_machine), or None if the file is not ELF."""
    try:
        with open(path, "rb") as fh:
            ident = fh.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                return None
            ei_class = ident[4]
            ei_data = ident[5]
            endian = "<" if ei_data == 1 else ">"
            header_rest = 36 if ei_class == 1 else 48
            rest = fh.read(header_rest)
            if len(rest) < 4:
                return None
            e_type, machine = struct.unpack_from(endian + "HH", rest, 0)
            return int(e_type), int(machine)
    except OSError:
        return None


def elf_machine(path: Path) -> int | None:
    hdr = elf_type_and_machine(path)
    return None if hdr is None else hdr[1]


def is_target_object(path: Path) -> bool:
    """Relocatable objects for packed targets — never the linked ELF (ET_EXEC)."""
    hdr = elf_type_and_machine(path)
    if hdr is None:
        return False
    e_type, machine = hdr
    return machine in TARGET_MACHINES and e_type == ET_REL


def _under_host_tool(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return bool(parts & HOST_TOOL_DIR_NAMES)


def classify_object(path: Path) -> str | None:
    """Return a corpus library name, or None to skip (stub main, host tools)."""
    posix = path.as_posix()
    lower = posix.lower()
    if _under_host_tool(path):
        return None
    if path.name == "main.c.o" or path.name.startswith("main.c."):
        return None

    for marker, lib in SUBMODULE_MARKERS:
        if marker in lower:
            return lib

    match = COMPONENT_RE.search(posix)
    if match:
        return match.group(1)

    cmake = CMAKE_TARGET_RE.search(posix)
    if cmake:
        target = cmake.group(1)
        if target in {"ghidra_stub", "ghidra_framework_stub"}:
            return None
        if target.startswith("harvest_"):
            return target[len("harvest_") :]
        if target not in HOST_TOOL_DIR_NAMES:
            return target
    return None


def archive_library_name(path: Path) -> str | None:
    if _under_host_tool(path):
        return None
    stem = path.name
    if stem.startswith("lib") and stem.endswith(".a"):
        return stem[3:-2]
    if stem.endswith(".a"):
        return stem[:-2]
    return None


def iter_build_files(build_dir: Path, suffix: str) -> list[Path]:
    found: list[Path] = []
    if not build_dir.is_dir():
        return found
    for p in build_dir.rglob("*" + suffix):
        if p.is_file():
            found.append(p)
    return found


def harvest_groups(build_dir: Path) -> dict[str, list[Path]]:
    """Map library name → target object/archive files. Never includes the ELF."""
    groups: dict[str, list[Path]] = {}

    for obj in iter_build_files(build_dir, ".o"):
        if obj.suffix != ".o":
            continue
        if not is_target_object(obj):
            continue
        lib = classify_object(obj)
        if not lib:
            continue
        groups.setdefault(lib, []).append(obj)

    for archive in iter_build_files(build_dir, ".a"):
        if not is_target_object(archive) and elf_machine(archive) is not None:
            # .a is an archive, not ELF; ar containers have no ELF header.
            pass
        lib = archive_library_name(archive)
        if not lib:
            continue
        if lib in HOST_TOOL_DIR_NAMES:
            continue
        # Prefer already-grouped .o files for this name; use the archive
        # only when the walk found no objects (STATIC libraries).
        if lib not in groups:
            groups[lib] = [archive]
    return groups


def toolchain_tokens(cc: str, cxx: str, identity: str) -> dict[str, str]:
    """Tokens a stub can spend in `toolchain_cache_vars`.

    Derived from the resolved compiler path, so an identity that is not packed
    (unit tests, older images) yields empty values and the stub's variables are
    dropped rather than pointing somewhere wrong.
    """
    path = Path(cc or "")
    parent = path.parent
    bin_dir = str(parent) if str(parent) not in {"", "."} else ""
    name = path.name
    triple = name[: -len("-gcc")] if name.endswith("-gcc") else ""
    if not triple and name.endswith("-clang"):
        triple = name[: -len("-clang")]
    return {
        "toolchain": identity or "",
        "toolchain_bin": bin_dir,
        "toolchain_triple": triple,
        "toolchain_prefix": f"{bin_dir}/{triple}-" if bin_dir and triple else "",
        "cc": cc or "",
        "cxx": cxx or "",
    }


def toolchain_cache_argv(meta: Mapping[str, Any], tokens: Mapping[str, str]) -> list[str]:
    """`-D` flags a stub declares for a framework that resolves its own toolchain.

    pico-sdk ignores CMAKE_C_COMPILER: pico_find_compiler searches PATH, and the
    packed prefixes are deliberately not on PATH. Zephyr
    (ZEPHYR_TOOLCHAIN_VARIANT / CROSS_COMPILE) and ESP-IDF (IDF_TOOLCHAIN) each
    want their own variables, so this stays stub data rather than a special case
    per framework here.

    A template whose tokens do not resolve is dropped, not emitted empty: an
    empty PICO_TOOLCHAIN_PATH searches PATH again and fails further downstream.
    """
    raw = meta.get("toolchain_cache_vars") or {}
    if not isinstance(raw, Mapping):
        return []
    argv: list[str] = []
    for key, template in raw.items():
        name = str(key).strip()
        if not name:
            continue
        value = substitute_tokens([str(template)], tokens)[0]
        if not value or "{" in value:
            continue
        argv.append(f"-D{name}={value}")
    return argv


def cmake_generator(which: Callable[[str], Any] = shutil.which) -> str:
    """Ninja when the image has it, otherwise CMake's default generator.

    Ninja parallelises a pico-sdk build far better and the builder image
    installs ninja-build, but a stale image without it must still build rather
    than fail configure with "CMAKE_MAKE_PROGRAM is not set".
    """
    return "Ninja" if which("ninja") else ""


def cmake_configure_argv(
    *,
    stub: Path,
    build_dir: Path,
    sdk_path: str,
    board: str,
    libraries: list[str],
    opt: str,
    config: Mapping[str, str],
    extra_flags: list[str],
    cc: str,
    cxx: str,
    cache_vars: list[str] | None = None,
    generator: str | None = None,
) -> list[str]:
    cflags = opt
    if extra_flags:
        cflags = opt + " " + " ".join(extra_flags)
    gen = cmake_generator() if generator is None else generator
    argv = [
        "cmake",
        "-S",
        str(stub),
        "-B",
        str(build_dir),
    ]
    if gen:
        argv += ["-G", gen]
    argv += [
        f"-DGHIDRA_SDK_PATH={sdk_path}",
        f"-DGHIDRA_LIBRARIES={';'.join(libraries)}",
        f"-DCMAKE_C_COMPILER={cc}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
        f"-DCMAKE_C_FLAGS={cflags}",
        f"-DCMAKE_CXX_FLAGS={cflags}",
    ]
    argv.extend(cache_vars or [])
    if board:
        argv.append(f"-DGHIDRA_BOARD={board}")
    for key, value in config.items():
        argv.append(f"-D{key}={value}")
    return argv


def cmake_build_argv(build_dir: Path) -> list[str]:
    return ["cmake", "--build", str(build_dir), "-j"]


def checkout_with_submodules(
    git_dir: Path,
    sha: str,
    dest: Path,
    run: RunFn,
    git_fn: Callable[..., Any],
) -> None:
    """Worktree + submodule update. git archive cannot fetch submodules."""
    dest.mkdir(parents=True, exist_ok=True)
    added = git_fn(
        run,
        ["--git-dir", str(git_dir), "worktree", "add", "--detach", str(dest), sha],
    )
    if added.returncode != 0:
        raise FrameworkError(
            f"git worktree add failed for {sha}: {(added.stderr or added.stdout or '').strip()}",
            status="ref_not_found",
            extra={"ref": sha},
        )
    sub = git_fn(
        run,
        ["-C", str(dest), "submodule", "update", "--init", "--recursive"],
    )
    if sub.returncode != 0:
        raise FrameworkError(
            "git submodule update failed: " + (sub.stderr or sub.stdout or "").strip(),
            status="submodule_failed",
        )


def combine_objects(
    files: list[Path],
    dest: Path,
    ld: str,
    run: RunFn,
    env: Mapping[str, str],
) -> list[str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if len(files) == 1 and files[0].suffix == ".a":
        shutil.copy2(files[0], dest)
        return ["cp", str(files[0]), str(dest)]
    if len(files) == 1:
        shutil.copy2(files[0], dest)
        return ["cp", str(files[0]), str(dest)]
    argv = [ld, "-r", "--build-id=none", "-o", str(dest), *[str(p) for p in files]]
    linked = run(argv, env=dict(env), timeout=60)
    if linked.returncode != 0:
        raise FrameworkError(
            f"ld -r failed while combining {len(files)} objects:\n"
            + (linked.stderr or linked.stdout or ""),
            status="compile_failed",
            extra={"command": argv},
        )
    return argv


def load_stub_meta(stub: Path) -> dict[str, Any]:
    meta_path = stub / "stub.json"
    if not meta_path.is_file():
        return {"name": stub.name, "generator": "cmake"}
    return json.loads(meta_path.read_text(encoding="utf-8"))


def substitute_tokens(argv: list[str], mapping: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    for item in argv:
        value = str(item)
        for key, replacement in mapping.items():
            value = value.replace("{" + key + "}", replacement)
        out.append(value)
    return out


def argv_from_meta(meta: Mapping[str, Any], key: str, mapping: Mapping[str, str]) -> list[str]:
    raw = meta.get(key) or []
    if not isinstance(raw, list) or not raw:
        return []
    return substitute_tokens([str(x) for x in raw], mapping)


def harvest_declared(
    meta: Mapping[str, Any],
    snapshot: Path,
    build_dir: Path,
) -> dict[str, list[Path]]:
    """Explicit harvest paths from stub.json, mapped to library names."""
    declared = meta.get("harvest") or []
    if not isinstance(declared, list) or not declared:
        return {}
    groups: dict[str, list[Path]] = {}
    missing: list[str] = []
    for item in declared:
        if isinstance(item, str):
            rel = item
            lib = archive_library_name(Path(item)) or Path(item).stem
        elif isinstance(item, Mapping):
            rel = str(item.get("path") or "").strip()
            lib = str(item.get("library") or "").strip() or (
                archive_library_name(Path(rel)) or Path(rel).stem
            )
        else:
            continue
        if not rel:
            continue
        candidates = [build_dir / rel, snapshot / rel]
        found = next((p for p in candidates if p.is_file()), None)
        if found is None:
            missing.append(rel)
            continue
        groups.setdefault(lib, []).append(found)
    if missing and not groups:
        raise FrameworkError(
            "harvest paths not found: " + ", ".join(missing),
            status="library_not_harvested",
            extra={"missing": missing},
        )
    return groups

