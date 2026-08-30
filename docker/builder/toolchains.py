"""Resolve <compiler><major>-<target> to binaries packed in this image."""

from __future__ import annotations

import os
from pathlib import Path

TOOLCHAINS_ENV = "GHIDRA_MCP_TOOLCHAINS"
DEFAULT_TOOLCHAINS_ROOT = Path("/opt/ghidra-builder/toolchains")


def toolchains_root() -> Path:
    raw = os.environ.get(TOOLCHAINS_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_TOOLCHAINS_ROOT


def list_installed(root: Path | None = None) -> dict[str, Path]:
    base = root or toolchains_root()
    found: dict[str, Path] = {}
    if not base.is_dir():
        return found
    for child in sorted(base.iterdir()):
        cc = child / "bin" / "arm-none-eabi-gcc"
        clang = child / "bin" / "clang"
        if child.is_dir() and (cc.is_file() or clang.is_file()):
            found[child.name] = child
    return found


def resolve_tools(
    identity: str,
    *,
    fallback_cc: str,
    fallback_ld: str,
    fallback_strip: str,
    fallback_nm: str,
    root: Path | None = None,
) -> dict[str, str]:
    """Return cc/ld/strip/nm paths for an identity.

    When packed toolchains are present, the identity must match a directory
    name (gcc10-arm, gcc13-arm). Unit tests without a packed tree fall back
    to the binaries named in the request.
    """
    installed = list_installed(root)
    ident = (identity or "").strip()
    if installed:
        if ident not in installed:
            available = sorted(installed)
            raise KeyError(ident, available)
        prefix = installed[ident]
        cc = prefix / "bin" / "arm-none-eabi-gcc"
        clang = prefix / "bin" / "clang"
        if clang.is_file() and not cc.is_file():
            return {
                "cc": str(clang),
                "ld": str(prefix / "bin" / "ld.lld"),
                "strip": str(prefix / "bin" / "llvm-strip"),
                "nm": str(prefix / "bin" / "llvm-nm"),
                "cxx": str(prefix / "bin" / "clang++"),
            }
        cxx = prefix / "bin" / "arm-none-eabi-g++"
        return {
            "cc": str(cc),
            "ld": str(prefix / "bin" / "arm-none-eabi-ld"),
            "strip": str(prefix / "bin" / "arm-none-eabi-strip"),
            "nm": str(prefix / "bin" / "arm-none-eabi-nm"),
            "cxx": str(cxx) if cxx.is_file() else str(cc),
        }
    return {
        "cc": fallback_cc,
        "ld": fallback_ld,
        "strip": fallback_strip,
        "nm": fallback_nm,
        "cxx": "",
    }
