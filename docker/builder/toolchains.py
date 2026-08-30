"""Resolve <compiler><major>-<target> to binaries packed in this image."""

from __future__ import annotations

import json
import os
from pathlib import Path

TOOLCHAINS_ENV = "GHIDRA_MCP_TOOLCHAINS"
DEFAULT_TOOLCHAINS_ROOT = Path("/opt/ghidra-builder/toolchains")


def toolchains_root() -> Path:
    raw = os.environ.get(TOOLCHAINS_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_TOOLCHAINS_ROOT


def _identity_meta(prefix: Path) -> dict[str, object]:
    meta = prefix / "identity.json"
    if not meta.is_file():
        return {}
    try:
        payload = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _is_packed_prefix(child: Path) -> bool:
    if not child.is_dir():
        return False
    if (child / "bin" / "arm-none-eabi-gcc").is_file():
        return True
    if (child / "bin" / "clang").is_file():
        return True
    meta = _identity_meta(child)
    if str(meta.get("kind") or "").strip() == "native":
        cc = Path(str(meta.get("cc") or ""))
        return cc.is_file()
    return False


def list_installed(root: Path | None = None) -> dict[str, Path]:
    base = root or toolchains_root()
    found: dict[str, Path] = {}
    if not base.is_dir():
        return found
    for child in sorted(base.iterdir()):
        if _is_packed_prefix(child):
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
    name (gcc10-arm, gcc13-arm, gcc13-x86_64). Native identities are described
    by identity.json (kind=native) and point at distro binaries. Unit tests
    without a packed tree fall back to the binaries named in the request.
    """
    installed = list_installed(root)
    ident = (identity or "").strip()
    if installed:
        if ident not in installed:
            available = sorted(installed)
            raise KeyError(ident, available)
        prefix = installed[ident]
        meta = _identity_meta(prefix)
        if str(meta.get("kind") or "").strip() == "native":
            return {
                "cc": str(meta.get("cc") or fallback_cc),
                "cxx": str(meta.get("cxx") or ""),
                "ld": str(meta.get("ld") or fallback_ld),
                "strip": str(meta.get("strip") or fallback_strip),
                "nm": str(meta.get("nm") or fallback_nm),
                "objdump": str(meta.get("objdump") or "objdump"),
            }
        cc = prefix / "bin" / "arm-none-eabi-gcc"
        clang = prefix / "bin" / "clang"
        if clang.is_file() and not cc.is_file():
            return {
                "cc": str(clang),
                "ld": str(prefix / "bin" / "ld.lld"),
                "strip": str(prefix / "bin" / "llvm-strip"),
                "nm": str(prefix / "bin" / "llvm-nm"),
                "cxx": str(prefix / "bin" / "clang++"),
                "objdump": str(prefix / "bin" / "llvm-objdump"),
            }
        cxx = prefix / "bin" / "arm-none-eabi-g++"
        objdump = prefix / "bin" / "arm-none-eabi-objdump"
        return {
            "cc": str(cc),
            "ld": str(prefix / "bin" / "arm-none-eabi-ld"),
            "strip": str(prefix / "bin" / "arm-none-eabi-strip"),
            "nm": str(prefix / "bin" / "arm-none-eabi-nm"),
            "cxx": str(cxx) if cxx.is_file() else str(cc),
            "objdump": str(objdump) if objdump.is_file() else "objdump",
        }
    return {
        "cc": fallback_cc,
        "ld": fallback_ld,
        "strip": fallback_strip,
        "nm": fallback_nm,
        "cxx": "",
        "objdump": "objdump",
    }
