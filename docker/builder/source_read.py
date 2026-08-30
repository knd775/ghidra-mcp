"""Read pinned reference source from the builder's git cache.

The MCP server does not mount /src. This process does: POST /source is a
synchronous read (not a build job) against the bare clone the compile used.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

import toolchains as packed_toolchains

DEFAULT_CONTEXT = 20
DEFAULT_MAX_LINES = 400
HARD_MAX_LINES = 800
TEXT_NM_TYPES = frozenset("TtWw")

RunFn = Callable[..., Any]


class SourceError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


def sanitize_repo_id(repo: str) -> str:
    parsed = urlparse(repo)
    host = parsed.netloc or "git"
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    raw = f"{host}{path}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_") or "repo"


def confine_repo_path(path: str) -> str:
    value = (path or "").strip()
    if not value:
        raise SourceError("path is required", status="invalid_path")
    if "\n" in value or "\r" in value or "\0" in value or ":" in value:
        raise SourceError("path contains illegal characters", status="invalid_path")
    if value.startswith("/") or value.startswith("\\") or value.startswith("-"):
        raise SourceError(
            "path must be repo-relative (no absolute paths)",
            status="path_outside_cache",
        )
    posix = Path(value).as_posix()
    if posix == ".." or posix.startswith("../") or "/../" in f"/{posix}/":
        raise SourceError("path must not contain '..'", status="path_outside_cache")
    if ".." in Path(value).parts:
        raise SourceError("path must not contain '..'", status="path_outside_cache")
    return posix


def strip_debug_prefix(path: str, prefix: str) -> str:
    value = (path or "").strip()
    pref = (prefix or "").rstrip("/")
    if pref and (value == pref or value.startswith(pref + "/")):
        value = value[len(pref) :].lstrip("/")
    return value


def load_sidecar(artifact: Path) -> dict[str, Any]:
    side = artifact.parent / (artifact.name + ".json")
    if not side.is_file():
        raise SourceError(
            f"artifact has no provenance sidecar (expected {side.name}); "
            "rebuild with build_reference",
            status="sidecar_missing",
            extra={"sidecar": str(side), "artifact": str(artifact)},
        )
    try:
        payload = json.loads(side.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceError(
            f"provenance sidecar {side} is unreadable: {exc}",
            status="sidecar_unreadable",
            extra={"sidecar": str(side)},
        ) from exc
    if not isinstance(payload, dict):
        raise SourceError("provenance sidecar is not a JSON object", status="sidecar_unreadable")
    return payload


def git_dir_for(repo: str, src_cache: Path) -> Path:
    dest = src_cache / f"{sanitize_repo_id(repo)}.git"
    if not dest.exists():
        raise SourceError(
            f"source cache has no clone of {repo!r} at {dest}. "
            "Rebuild the artifact (build_reference) so the builder fetches that repo.",
            status="commit_not_cached",
            extra={"repo": repo, "git_dir": str(dest)},
        )
    return dest


def _git(run: RunFn, argv: list[str], timeout: float = 30) -> Any:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return run(["git", *argv], env=env, timeout=timeout)


def require_commit(git_dir: Path, commit: str, run: RunFn) -> None:
    probed = _git(run, ["--git-dir", str(git_dir), "cat-file", "-t", commit])
    kind = (probed.stdout or "").strip()
    if probed.returncode != 0 or kind != "commit":
        raise SourceError(
            f"commit {commit} is not in the builder source cache at {git_dir}. "
            "Rebuild the artifact (build_reference) or fetch that ref into /src.",
            status="commit_not_cached",
            extra={"commit": commit, "git_dir": str(git_dir)},
        )


def git_show(git_dir: Path, commit: str, path: str, run: RunFn) -> str:
    spec = f"{commit}:{path}"
    exists = _git(run, ["--git-dir", str(git_dir), "cat-file", "-e", spec])
    if exists.returncode != 0:
        raise SourceError(
            f"{path} is not in commit {commit} ({git_dir.name})",
            status="path_not_in_commit",
            extra={"commit": commit, "path": path, "git_dir": str(git_dir)},
        )
    shown = _git(run, ["--git-dir", str(git_dir), "show", spec], timeout=30)
    if shown.returncode != 0:
        err = (shown.stderr or shown.stdout or "").strip()
        raise SourceError(
            f"git show {spec} failed: {err}",
            status="path_not_in_commit",
            extra={"commit": commit, "path": path},
        )
    return shown.stdout or ""


def slice_lines(
    text: str,
    start_line: int,
    end_line: int,
    *,
    hard_limit: int = HARD_MAX_LINES,
) -> tuple[list[dict[str, Any]], bool, int, int]:
    all_lines = text.splitlines()
    total = len(all_lines)
    start = max(1, start_line)
    end = total if end_line <= 0 else min(end_line, total)
    if end < start:
        end = start
    span = end - start + 1
    truncated = False
    if span > hard_limit:
        end = start + hard_limit - 1
        truncated = True
    rows = []
    for n in range(start, end + 1):
        if n > total:
            break
        rows.append({"n": n, "text": all_lines[n - 1]})
    return rows, truncated, start, min(end, total)


def parse_nm_symbols(text: str) -> list[tuple[int, str]]:
    symbols: list[tuple[int, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        kind = parts[-2]
        name = parts[-1]
        if kind not in TEXT_NM_TYPES:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        symbols.append((addr, name))
    symbols.sort()
    return symbols


def parse_decodedline(text: str) -> list[tuple[str, int, int]]:
    """Return (file, line, address) rows from objdump --dwarf=decodedline."""
    rows: list[tuple[str, int, int]] = []
    current_cu = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("CU:"):
            current_cu = line[3:].strip().rstrip(":")
            continue
        if not line or line.startswith("File name") or line.startswith("Decoded"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        addr_token = None
        line_token = None
        # Walk from the right: skip trailing 'x' / view, then address, then line.
        idx = len(parts) - 1
        while idx >= 0 and parts[idx] in {"x", "View", "Stmt"}:
            idx -= 1
        if idx < 1:
            continue
        addr_token = parts[idx]
        line_token = parts[idx - 1]
        file_token = " ".join(parts[: idx - 1]) if idx - 1 > 0 else current_cu
        if not line_token.isdigit():
            continue
        addr_s = addr_token[2:] if addr_token.lower().startswith("0x") else addr_token
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        source = file_token or current_cu
        if source:
            rows.append((source, int(line_token), addr))
    return rows


def resolve_function_span(
    function: str,
    symbols: list[tuple[int, str]],
    decoded: list[tuple[str, int, int]],
    context: int,
) -> tuple[str, int, int]:
    want = function.strip()
    if not want:
        raise SourceError("function is required", status="invalid_function")
    match: tuple[int, str] | None = None
    for addr, name in symbols:
        if name == want or name.lstrip("_") == want.lstrip("_"):
            match = (addr, name)
            break
        if name.split("@", 1)[0] == want or name.split("@@", 1)[0] == want:
            match = (addr, name)
            break
    if match is None:
        raise SourceError(
            f"function {want!r} not found in artifact symbols",
            status="function_not_found",
            extra={"function": want},
        )
    start_addr, _ = match
    next_addr = None
    for addr, _name in symbols:
        if addr > start_addr:
            next_addr = addr
            break
    files: dict[str, list[int]] = {}
    for source, line, addr in decoded:
        if addr < start_addr:
            continue
        if next_addr is not None and addr >= next_addr:
            continue
        files.setdefault(source, []).append(line)
    if not files:
        raise SourceError(
            f"function {want!r} has no DWARF line records in this artifact",
            status="function_not_found",
            extra={"function": want},
        )
    source = max(files, key=lambda k: len(files[k]))
    lines = files[source]
    lo = max(1, min(lines) - max(0, context))
    hi = max(lines) + max(0, context)
    return source, lo, hi


def objdump_and_nm(
    artifact: Path,
    toolchain: str,
    run: RunFn,
) -> tuple[str, str]:
    try:
        tools = packed_toolchains.resolve_tools(
            toolchain,
            fallback_cc="gcc",
            fallback_ld="ld",
            fallback_strip="strip",
            fallback_nm="nm",
        )
    except KeyError:
        tools = {"nm": "nm", "objdump": "objdump"}
    nm_bin = tools.get("nm") or "nm"
    dump_bin = tools.get("objdump") or "objdump"
    listed = run([nm_bin, "--defined-only", str(artifact)], timeout=30)
    dumped = run([dump_bin, "--dwarf=decodedline", str(artifact)], timeout=30)
    return listed.stdout or "", dumped.stdout or ""


def handle_source_request(
    req: Mapping[str, Any],
    *,
    run: RunFn,
    src_cache: Path,
    confine_artifact: Callable[[Path], Path],
) -> dict[str, Any]:
    raw_artifact = str(req.get("artifact") or "").strip()
    if not raw_artifact:
        raise SourceError("artifact is required", status="invalid_artifact")
    artifact = confine_artifact(Path(raw_artifact))
    if not artifact.is_file():
        raise SourceError(
            f"artifact not found: {artifact}",
            status="artifact_not_found",
            extra={"artifact": str(artifact)},
        )

    sidecar = load_sidecar(artifact)
    repo = str(sidecar.get("repo") or "").strip()
    commit = str(sidecar.get("commit") or "").strip()
    if not repo or not commit:
        raise SourceError(
            "provenance sidecar is missing repo or commit",
            status="sidecar_unreadable",
            extra={"sidecar": str(artifact) + ".json"},
        )
    prefix = str(sidecar.get("debug_path_prefix") or "").strip()
    git_dir = git_dir_for(repo, src_cache)
    require_commit(git_dir, commit, run)

    function = str(req.get("function") or "").strip()
    rel = str(req.get("path") or "").strip()
    context = int(req.get("context") or DEFAULT_CONTEXT)
    if context < 0:
        context = 0
    start_line = int(req.get("start_line") or 0)
    end_line = int(req.get("end_line") or 0)

    resolved_function = function or None
    if function:
        nm_text, dump_text = objdump_and_nm(
            artifact, str(sidecar.get("toolchain") or ""), run
        )
        source, lo, hi = resolve_function_span(
            function, parse_nm_symbols(nm_text), parse_decodedline(dump_text), context
        )
        rel = confine_repo_path(strip_debug_prefix(source, prefix) or source)
        if start_line <= 0:
            start_line = lo
        if end_line <= 0:
            end_line = hi
    elif rel:
        rel = confine_repo_path(strip_debug_prefix(rel, prefix) or rel)
        if start_line <= 0:
            start_line = 1
        if end_line <= 0:
            end_line = start_line + DEFAULT_MAX_LINES - 1
    else:
        raise SourceError("function or path is required", status="invalid_request")

    if end_line - start_line + 1 > HARD_MAX_LINES:
        end_line = start_line + HARD_MAX_LINES - 1
        truncated_by_request = True
    else:
        truncated_by_request = False

    text = git_show(git_dir, commit, rel, run)
    rows, truncated, start_line, end_line = slice_lines(text, start_line, end_line)
    truncated = truncated or truncated_by_request
    body: dict[str, Any] = {
        "ok": True,
        "artifact": artifact.name,
        "repo": repo,
        "commit": commit,
        "path": rel,
        "debug_path_prefix": prefix,
        "start_line": start_line,
        "end_line": end_line,
        "lines": rows,
        "truncated": truncated,
    }
    if resolved_function:
        body["function"] = resolved_function
    if truncated:
        body["truncation"] = (
            f"stopped at line {end_line} (hard limit {HARD_MAX_LINES})"
        )
    return body
