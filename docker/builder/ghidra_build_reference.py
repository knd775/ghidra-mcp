#!/usr/bin/env python3
"""Compile a pinned-source reference library inside the builder container.

The MCP server never moves object bytes through an agent tool call. This
process clones (or updates) a git ref into the persistent /src cache, compiles
in the container, and writes the object onto the shared volume at /data/uploads
where import_file can see it.

Invocation:
  ghidra-build-reference serve          # long-lived HTTP control plane
  ghidra-build-reference build          # JSON request on stdin, JSON on stdout

A compile failure returns compiler stderr. A missing ref names the ref and
whether the repository was reachable. Zero defined functions is a hard refuse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

_BUILDER_DIR = Path(__file__).resolve().parent
if str(_BUILDER_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILDER_DIR))
import framework_build as fw  # noqa: E402
import jobs as builder_jobs  # noqa: E402
import source_read as src_read  # noqa: E402
import toolchains as packed_toolchains  # noqa: E402

DEFAULT_PORT = 8092
DEFAULT_SRC_CACHE = Path("/src")
DEFAULT_CC = "arm-none-eabi-gcc"
DEFAULT_LD = "arm-none-eabi-ld"
DEFAULT_STRIP = "arm-none-eabi-strip"
DEFAULT_NM = "arm-none-eabi-nm"
DEFAULT_PREPARE_TIMEOUT = 300
MAX_PREPARE_TIMEOUT = 3600
# Java dry_run argv uses this token; we substitute the snapshot path at compile.
SNAPSHOT_PLACEHOLDER = "<snapshot>"
DEBUG_PATH_ROOT = "/ref"

SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
BRANCH_NAMES = frozenset(
    {"HEAD", "head", "main", "master", "develop", "dev", "trunk", "next"}
)
TEXT_NM_TYPES = frozenset("TtWw")

RunFn = Callable[..., subprocess.CompletedProcess[str]]


def debug_path_prefix(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "").strip()) or "unnamed"
    return f"{DEBUG_PATH_ROOT}/{safe}"


def with_debug_maps(flags: list[str], snapshot: Path, name: str) -> list[str]:
    prefix = debug_path_prefix(name)
    snap = str(snapshot)
    out = list(flags)
    if not any(flag == "-g" or flag.startswith("-g") for flag in out):
        out.insert(0, "-g")
    if not any(flag.startswith("-fdebug-prefix-map=") for flag in out):
        out.append(f"-fdebug-prefix-map={snap}={prefix}")
    if not any(flag.startswith("-ffile-prefix-map=") for flag in out):
        out.append(f"-ffile-prefix-map={snap}={prefix}")
    if not any(flag.startswith("-fmacro-prefix-map=") for flag in out):
        out.append(f"-fmacro-prefix-map={snap}={prefix}")
    return out


class BuildError(Exception):
    """Structured failure the HTTP/CLI layer turns into JSON."""

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


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    """SIGKILL the session started by ``start_new_session``, not just ``proc``.

    The shell can exit while a background child still holds the pipes
    (``sleep 60 &`` without ``wait``). ``proc.poll()`` is then non-None,
    but the process group is still alive — always signal the group.
    """
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if proc.poll() is None:
                proc.kill()
    elif proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _default_run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    timeout: float | None = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    # New session so a timeout can kill pipelines, ``make -j``, and
    # backgrounded descendants — subprocess.run only signals /bin/sh.
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=None if env is None else dict(env),
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(proc)
        try:
            leftover_out, leftover_err = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired as leftover:
            leftover_out = leftover.stdout if leftover.stdout is not None else exc.stdout
            leftover_err = leftover.stderr if leftover.stderr is not None else exc.stderr
        raise subprocess.TimeoutExpired(
            argv,
            timeout if timeout is not None else 0,
            output=leftover_out,
            stderr=leftover_err,
        ) from None
    except BaseException:
        _kill_process_group(proc)
        raise
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, argv, stdout, stderr)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def sanitize_repo_id(repo: str) -> str:
    parsed = urlparse(repo)
    host = parsed.netloc or "git"
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    raw = f"{host}{path}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_") or "repo"


def reject_branch_name(ref: str) -> None:
    """Reject names that cannot be a reproducible corpus pin, before git."""
    value = (ref or "").strip()
    if not value:
        raise BuildError("ref is required (a tag or commit SHA, not a branch)", status="invalid_ref")
    if "\n" in value or "\r" in value or "\0" in value:
        raise BuildError("ref contains illegal control characters", status="invalid_ref")
    if value.startswith("-"):
        raise BuildError("ref must not start with '-' (looks like a flag)", status="invalid_ref")
    if value.startswith("refs/heads/") or value in BRANCH_NAMES:
        raise BuildError(
            f"ref {value!r} is a branch name; pin a tag or commit SHA so the "
            "corpus entry can be reproduced",
            status="ref_is_branch",
            extra={"ref": value},
        )
    if "/" in value and not SHA_RE.fullmatch(value):
        # origin/main, feature/foo — tags almost never have slashes here.
        raise BuildError(
            f"ref {value!r} looks like a branch (contains '/'); pin a tag or commit SHA",
            status="ref_is_branch",
            extra={"ref": value},
        )


def _git(
    run: RunFn,
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return run(["git", *argv], cwd=cwd, env=env, timeout=timeout)


def ensure_bare_clone(
    repo: str,
    cache_root: Path,
    run: RunFn,
) -> Path:
    cache_root.mkdir(parents=True, exist_ok=True)
    dest = cache_root / f"{sanitize_repo_id(repo)}.git"
    lock_path = cache_root / f"{sanitize_repo_id(repo)}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a", encoding="utf-8") as lock:
        try:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        if dest.is_dir():
            # Ignore fetch failure: resolve_commit still sees cached tags and
            # names a missing ref specifically instead of "unreachable".
            _git(run, ["fetch", "--tags", "--prune", "origin"], cwd=dest)
            return dest
        cloned = _git(run, ["clone", "--bare", repo, str(dest)], timeout=180)
        if cloned.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise BuildError(
                f"git clone failed for {repo}: {(cloned.stderr or cloned.stdout).strip()}",
                status="repo_unreachable",
                extra={"repo_reachable": False, "ref": None},
            )
        return dest


def resolve_commit(git_dir: Path, ref: str, run: RunFn) -> str:
    """Return the full SHA for a tag or commit. Refuse branch names."""
    reject_branch_name(ref)

    def git_out(args: list[str]) -> subprocess.CompletedProcess[str]:
        return _git(run, ["--git-dir", str(git_dir), *args])

    # Fetch the named ref; a missing tag/SHA is not a network failure once clone worked.
    git_out(["fetch", "--tags", "origin"])
    if SHA_RE.fullmatch(ref):
        peeled = git_out(["rev-parse", "--verify", f"{ref}^{{commit}}"])
        if peeled.returncode != 0:
            fetched = git_out(["fetch", "origin", ref])
            peeled = git_out(["rev-parse", "--verify", f"{ref}^{{commit}}"])
            if peeled.returncode != 0:
                raise BuildError(
                    f"ref {ref!r} not found (repository was reachable)",
                    status="ref_not_found",
                    extra={"ref": ref, "repo_reachable": True},
                )
        return peeled.stdout.strip()

    tag_ok = git_out(["show-ref", "--verify", "--quiet", f"refs/tags/{ref}"])
    if tag_ok.returncode == 0:
        peeled = git_out(["rev-parse", f"{ref}^{{commit}}"])
        if peeled.returncode != 0:
            raise BuildError(
                f"ref {ref!r} not found (repository was reachable)",
                status="ref_not_found",
                extra={"ref": ref, "repo_reachable": True},
            )
        return peeled.stdout.strip()

    branch_ok = git_out(["show-ref", "--verify", "--quiet", f"refs/heads/{ref}"])
    if branch_ok.returncode == 0:
        raise BuildError(
            f"ref {ref!r} is a branch name; pin a tag or commit SHA so the "
            "corpus entry can be reproduced",
            status="ref_is_branch",
            extra={"ref": ref, "repo_reachable": True},
        )

    raise BuildError(
        f"ref {ref!r} not found (repository was reachable)",
        status="ref_not_found",
        extra={"ref": ref, "repo_reachable": True},
    )


def commit_timestamp(git_dir: Path, sha: str, run: RunFn) -> str:
    r = _git(run, ["--git-dir", str(git_dir), "log", "-1", "--format=%ct", sha])
    value = (r.stdout or "").strip()
    return value if r.returncode == 0 and value.isdigit() else "0"


def extract_snapshot_bytes(git_dir: Path, sha: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["GIT_TERMINAL_PROMPT"] = "0"
    archive = subprocess.run(
        ["git", "--git-dir", str(git_dir), "archive", "--format=tar", sha],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if archive.returncode != 0 or not archive.stdout:
        subprocess.run(
            ["git", "--git-dir", str(git_dir), "fetch", "origin", sha],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        archive = subprocess.run(
            ["git", "--git-dir", str(git_dir), "archive", "--format=tar", sha],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    if archive.returncode != 0 or not archive.stdout:
        err = archive.stderr.decode("utf-8", "replace").strip()
        raise BuildError(
            f"git archive failed for {sha}: {err}",
            status="ref_not_found",
            extra={"ref": sha, "repo_reachable": True},
        )
    tar = subprocess.run(
        ["tar", "-x", "-C", str(dest)],
        input=archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if tar.returncode != 0:
        err = tar.stderr.decode("utf-8", "replace").strip()
        raise BuildError(f"tar extract failed: {err}", status="compile_failed")


def _proc_text(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace").strip()
    return str(raw).strip()


def require_prepare(req: Mapping[str, Any], mode: str) -> str:
    """Return the operator-supplied prepare command.

    Taken only from the request (manifest or tool call). Never read a
    prepare script or command from the cloned tree.
    """
    if "prepare" not in req or req.get("prepare") is None:
        return ""
    raw = req.get("prepare")
    if not isinstance(raw, str):
        raise BuildError("prepare must be a string", status="invalid_prepare")
    if "\0" in raw:
        raise BuildError(
            "prepare contains illegal control characters",
            status="invalid_prepare",
        )
    value = raw.strip()
    if not value:
        return ""
    if mode == "framework":
        raise BuildError(
            "prepare is only valid in mode=sources (framework stubs already "
            "have their own prepare/configure/make)",
            status="invalid_prepare",
        )
    return value


def require_prepare_timeout(req: Mapping[str, Any]) -> int:
    raw = req.get("prepare_timeout", DEFAULT_PREPARE_TIMEOUT)
    if raw is None or raw == "":
        return DEFAULT_PREPARE_TIMEOUT
    if isinstance(raw, bool) or (isinstance(raw, float) and not raw.is_integer()):
        raise BuildError(
            f"prepare_timeout must be an integer number of seconds; got {raw!r}",
            status="invalid_prepare_timeout",
        )
    try:
        timeout = int(raw)
    except (TypeError, ValueError) as exc:
        raise BuildError(
            f"prepare_timeout must be an integer number of seconds; got {raw!r}",
            status="invalid_prepare_timeout",
        ) from exc
    if timeout < 1 or timeout > MAX_PREPARE_TIMEOUT:
        raise BuildError(
            f"prepare_timeout must be 1..{MAX_PREPARE_TIMEOUT}; got {timeout}",
            status="invalid_prepare_timeout",
        )
    return timeout


def prepare_argv(prepare: str) -> list[str]:
    return ["/bin/sh", "-c", prepare]


def run_prepare(
    prepare: str,
    timeout: int,
    snapshot: Path,
    run: RunFn,
    env: Mapping[str, str],
) -> list[str]:
    """Run an operator-supplied shell command in the cloned tree."""
    argv = prepare_argv(prepare)
    try:
        stepped = run(argv, cwd=snapshot, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout = _proc_text(exc.stdout)
        stderr = _proc_text(exc.stderr)
        detail = "\n".join(part for part in (stdout, stderr) if part)
        raise BuildError(
            f"prepare timed out after {timeout}s"
            + (f":\n{detail}" if detail else ""),
            status="prepare_failed",
            extra={
                "stdout": stdout,
                "stderr": stderr,
                "command": argv,
                "timeout": timeout,
            },
        ) from exc
    stdout = _proc_text(stepped.stdout)
    stderr = _proc_text(stepped.stderr)
    if stepped.returncode != 0:
        detail = "\n".join(part for part in (stdout, stderr) if part)
        raise BuildError(
            f"prepare failed:\n{detail}" if detail else "prepare failed",
            status="prepare_failed",
            extra={"stdout": stdout, "stderr": stderr, "command": argv},
        )
    return argv


def compile_objects(
    *,
    snapshot: Path,
    sources: list[str],
    cflags: list[str],
    cc: str,
    ld: str,
    workdir: Path,
    output: Path,
    run: RunFn,
    env: Mapping[str, str],
    name: str = "",
) -> tuple[list[list[str]], list[dict[str, Any]]]:
    """Compile sources; return (commands, failed_units).

    A unit that fails to compile is named and skipped so the rest of a
    multi-file reference can still be produced. Zero successful objects
    is still a hard refuse.
    """
    commands: list[list[str]] = []
    objects: list[Path] = []
    failed_units: list[dict[str, Any]] = []
    workdir.mkdir(parents=True, exist_ok=True)
    mapped_base = [flag.replace(SNAPSHOT_PLACEHOLDER, str(snapshot)) for flag in cflags]
    mapped_base = with_debug_maps(mapped_base, snapshot, name or output.stem)
    for index, rel in enumerate(sources):
        src_path = snapshot / rel
        if not src_path.is_file():
            raise BuildError(
                f"source {rel!r} not found in the checked-out tree",
                status="source_not_found",
                extra={"source": rel},
            )
        obj = workdir / f"{index:03d}-{Path(rel).name}.o"
        argv = [cc, "-c"]
        argv.extend(mapped_base)
        argv.extend([rel, "-o", str(obj)])
        commands.append(argv)
        compiled = run(argv, cwd=snapshot, env=env, timeout=120)
        if compiled.returncode != 0:
            stderr = (compiled.stderr or compiled.stdout or "").strip()
            failed_units.append({"source": rel, "stderr": stderr, "command": argv})
            continue
        objects.append(obj)

    if not objects:
        if len(failed_units) == 1:
            fu = failed_units[0]
            raise BuildError(
                f"compile failed for {fu['source']}:\n{fu['stderr']}",
                status="compile_failed",
                extra={
                    "stderr": fu["stderr"],
                    "source": fu["source"],
                    "command": fu["command"],
                    "failed_units": failed_units,
                },
            )
        parts = [f"{fu['source']}:\n{fu['stderr']}" for fu in failed_units]
        raise BuildError(
            "compile failed for all sources:\n" + "\n".join(parts),
            status="compile_failed",
            extra={
                "stderr": "\n".join(fu["stderr"] for fu in failed_units),
                "failed_units": failed_units,
            },
        )

    if len(objects) == 1:
        shutil.copy2(objects[0], output)
        return commands, failed_units

    argv = [ld, "-r", "--build-id=none", "-o", str(output), *[str(p) for p in objects]]
    commands.append(argv)
    linked = run(argv, cwd=snapshot, env=env, timeout=60)
    if linked.returncode != 0:
        stderr = (linked.stderr or linked.stdout or "").strip()
        raise BuildError(
            f"ld -r failed:\n{stderr}",
            status="compile_failed",
            extra={"stderr": stderr, "command": argv, "failed_units": failed_units},
        )
    return commands, failed_units


def strip_debug(strip_bin: str, output: Path, run: RunFn, env: Mapping[str, str]) -> list[str]:
    argv = [strip_bin, "--strip-debug", str(output)]
    stripped = run(argv, env=env, timeout=30)
    if stripped.returncode != 0:
        stderr = (stripped.stderr or stripped.stdout or "").strip()
        raise BuildError(
            f"strip --strip-debug failed:\n{stderr}",
            status="compile_failed",
            extra={"stderr": stderr, "command": argv},
        )
    return argv


def defined_functions(nm_bin: str, output: Path, run: RunFn, env: Mapping[str, str]) -> list[str]:
    listed = run([nm_bin, "--defined-only", str(output)], env=env, timeout=30)
    if listed.returncode != 0:
        stderr = (listed.stderr or listed.stdout or "").strip()
        raise BuildError(
            f"nm --defined-only failed:\n{stderr}",
            status="compile_failed",
            extra={"stderr": stderr},
        )
    names: list[str] = []
    for line in (listed.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        kind = parts[-2]
        name = parts[-1]
        if kind in TEXT_NM_TYPES:
            names.append(name)
    return names


def file_root_from_env() -> Path | None:
    raw = os.environ.get("GHIDRA_MCP_FILE_ROOT", "").strip()
    return Path(raw) if raw else None


def require_output_under_root(output: Path, root: Path | None = None) -> Path:
    """Refuse to write an object anywhere the MCP server cannot import_file it."""
    resolved = output.expanduser().resolve()
    if root is None:
        root = file_root_from_env()
    if root is None:
        return resolved
    root_res = root.expanduser().resolve()
    try:
        resolved.relative_to(root_res)
    except ValueError as exc:
        raise BuildError(
            f"output {resolved} is outside {root_res}",
            status="invalid_output",
        ) from exc
    return resolved


def install_built_object(staging: Path, output: Path) -> None:
    """Copy then rename onto the shared volume.

    ``os.replace`` is ``rename(2)``. Staging is under /tmp (container overlay);
    ``/data`` is the samples bind. Crossing that is EXDEV, so the object
    would never appear for import_file. Write the tempfile next to the
    destination, then replace.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=str(output.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        os.close(fd)
        with open(staging, "rb") as src, open(tmp_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, output)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sidecar_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + ".json")


def remove_installed_artifacts(paths: list[Path]) -> None:
    """Delete objects (and sidecars) written by a harvest that later failed.

    A half-written corpus looks current to build_manifest: the sidecar hash
    matches, the job is skipped, and the caller never learned the paths.
    """
    for dest in paths:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            sidecar_path(dest).unlink(missing_ok=True)
        except OSError:
            pass


def artifact_record(
    *,
    path: str,
    library: str = "",
    bytes_size: int | None = None,
    digest: str | None = None,
    function_count: int | None = None,
    defined_functions: list[str] | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {"path": path, "library": library}
    if bytes_size is not None:
        rec["bytes"] = bytes_size
    if digest is not None:
        rec["sha256"] = digest
    if function_count is not None:
        rec["function_count"] = function_count
    if defined_functions is not None:
        rec["defined_functions"] = defined_functions
    return rec


def result_envelope(
    *,
    status: str,
    mode: str,
    name: str,
    ref: str,
    toolchain: str,
    artifacts: list[dict[str, Any]],
    command: list[list[str]],
    failed: list[Any] | None = None,
    commit_sha: str = "",
    cc_version: str = "",
    framework: str = "",
    board: str = "",
    prepare: str = "",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One response shape for sources and framework, success and dry-run."""
    body: dict[str, Any] = {
        "ok": status in {"success", "would_execute"},
        "status": status,
        "mode": mode,
        "name": name,
        "ref": ref,
        "commit_sha": commit_sha,
        "toolchain": toolchain,
        "cc_version": cc_version,
        "framework": framework,
        "board": board,
        "artifacts": artifacts,
        "failed": list(failed or []),
        "command": command,
        "prepare": prepare,
    }
    if extra:
        body.update(dict(extra))
    return body


def write_text_atomic(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dest.name}.",
        suffix=".tmp",
        dir=str(dest.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        os.close(fd)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def write_provenance_sidecar(
    dest: Path,
    *,
    req: Mapping[str, Any],
    commit: str,
    compiler_version: str,
    function_count: int,
    digest: str,
    extra: Mapping[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "name": str(req.get("name") or dest.stem),
        "artifact": dest.name,
        "sha256": digest,
        "bytes": dest.stat().st_size,
        "function_count": function_count,
        "repo": str(req.get("repo") or ""),
        "ref": str(req.get("ref") or ""),
        "commit": commit,
        "toolchain": str(req.get("toolchain") or ""),
        "compiler_version": compiler_version,
        "mode": str(req.get("mode") or "sources").strip() or "sources",
        "sources": [str(s).strip() for s in (req.get("sources") or []) if str(s).strip()],
        "opt": str(req.get("opt") or ""),
        "defines": [str(d).strip() for d in (req.get("defines") or []) if str(d).strip()],
        "extra_flags": [str(f) for f in (req.get("extra_flags") or [])],
        "prepare": str(req.get("prepare") or "").strip(),
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if extra:
        payload.update(extra)
    if not payload.get("debug_path_prefix"):
        payload["debug_path_prefix"] = debug_path_prefix(str(req.get("name") or dest.stem))
    write_text_atomic(
        sidecar_path(dest),
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
    )


def cc_version(cc: str, run: RunFn) -> str:
    r = run([cc, "--version"], timeout=15)
    line = (r.stdout or r.stderr or "").splitlines()
    return line[0].strip() if line else cc


def cxx_from_cc(cc: str) -> str:
    numbered = re.search(r"gcc-(\d+)$", cc)
    if numbered:
        return re.sub(r"gcc-(\d+)$", r"g++-\1", cc)
    if cc.endswith("-gcc"):
        return cc[: -len("gcc")] + "g++"
    if cc == "gcc":
        return "g++"
    if cc == "clang":
        return "clang++"
    return cc


def tools_for_request(req: Mapping[str, Any]) -> dict[str, str]:
    identity = str(req.get("toolchain") or "").strip()
    try:
        tools = packed_toolchains.resolve_tools(
            identity,
            fallback_cc=str(req.get("cc") or DEFAULT_CC),
            fallback_ld=str(req.get("ld") or DEFAULT_LD),
            fallback_strip=str(req.get("strip") or DEFAULT_STRIP),
            fallback_nm=str(req.get("nm") or DEFAULT_NM),
        )
    except KeyError as exc:
        ident = str(exc.args[0]) if exc.args else identity
        available = list(exc.args[1]) if len(exc.args) > 1 else []
        raise BuildError(
            f"unknown toolchain {ident!r}; installed: {available}",
            status="unknown_toolchain",
            extra={"installed": available, "toolchain": ident},
        ) from exc
    if not tools.get("cxx"):
        tools["cxx"] = cxx_from_cc(tools["cc"])
    return tools


def artifact_filename(
    name: str,
    library: str,
    ref: str,
    toolchain: str,
    opt: str,
    board: str,
) -> str:
    opt_label = opt[1:] if opt.startswith("-") else opt

    def safe(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value)

    parts = [name, library, ref, toolchain, opt_label]
    if board.strip():
        parts.append(board)
    return "-".join(safe(p) for p in parts) + ".o"


def handle_framework_request(
    req: Mapping[str, Any],
    *,
    run: RunFn,
    src_cache: Path,
    extract: Callable[[Path, str, Path], None] | None,
) -> dict[str, Any]:
    repo = str(req.get("repo") or "").strip()
    ref = str(req.get("ref") or "").strip()
    framework = str(req.get("framework") or "").strip()
    libraries = [str(s).strip() for s in (req.get("libraries") or []) if str(s).strip()]
    board = str(req.get("board") or "").strip()
    config_raw = req.get("config") or {}
    config = {str(k): str(v) for k, v in dict(config_raw).items()} if isinstance(config_raw, dict) else {}
    name = str(req.get("name") or "framework").strip() or "framework"
    opt = str(req.get("opt") or "-Os").strip() or "-Os"
    extra_flags = [str(s) for s in (req.get("extra_flags") or [])]
    for d in req.get("defines") or []:
        item = str(d).strip()
        if not item:
            continue
        extra_flags.append(item if item.startswith("-D") else "-D" + item)
    toolchain = str(req.get("toolchain") or "").strip()

    require_prepare(req, "framework")
    if not repo:
        raise BuildError("repo is required", status="invalid_repo")
    if not libraries:
        raise BuildError(
            "libraries is required in mode=framework (linking nothing produces nothing)",
            status="empty_libraries",
        )
    try:
        stub = fw.stub_dir(framework)
    except fw.FrameworkError as exc:
        raise BuildError(str(exc), status=exc.status, extra=exc.extra) from exc

    tools = tools_for_request(req)
    cc = tools["cc"]
    ld = tools["ld"]
    nm_bin = tools["nm"]
    cxx = tools.get("cxx") or cxx_from_cc(cc)
    meta = fw.load_stub_meta(stub)
    generator = str(meta.get("generator") or "cmake")
    extra_flags = with_debug_maps(extra_flags, Path(SNAPSHOT_PLACEHOLDER), name)
    if bool(req.get("dry_run")):
        mapping = {
            "cc": cc,
            "cxx": cxx,
            "opt": opt,
            "cflags": " ".join(extra_flags),
            "snapshot": SNAPSHOT_PLACEHOLDER,
            "build": "<build>",
        }
        if generator == "make":
            commands = []
            for key in ("prepare", "configure", "make"):
                argv = fw.argv_from_meta(meta, key, mapping)
                if argv:
                    commands.append(argv)
            if not commands:
                commands.append(["make", "-j"])
        else:
            configure = fw.cmake_configure_argv(
                stub=stub,
                build_dir=Path("<build>"),
                sdk_path=SNAPSHOT_PLACEHOLDER,
                board=board,
                libraries=libraries,
                opt=opt,
                config=config,
                extra_flags=extra_flags,
                cc=cc,
                cxx=cxx,
                cache_vars=fw.toolchain_cache_argv(
                    meta, fw.toolchain_tokens(cc, cxx, toolchain)),
            )
            commands = [configure, fw.cmake_build_argv(Path("<build>"))]
        raw_dir = str(req.get("output_dir") or "").strip()
        dest_dir = Path(raw_dir) if raw_dir else Path("<uploads>")
        artifacts = [
            artifact_record(
                path=str(dest_dir / artifact_filename(name, lib, ref, toolchain, opt, board)),
                library=lib,
            )
            for lib in libraries
        ]
        return result_envelope(
            status="would_execute",
            mode="framework",
            name=name,
            ref=ref,
            toolchain=toolchain,
            artifacts=artifacts,
            command=commands,
            framework=framework,
            board=board,
            extra={"dry_run": True},
        )

    raw_dir = str(req.get("output_dir") or "").strip()
    if not raw_dir:
        raise BuildError("output_dir is required in mode=framework", status="invalid_output")
    output_dir = require_output_under_root(Path(raw_dir))

    reject_branch_name(ref)
    git_dir = ensure_bare_clone(repo, src_cache, run)
    sha = resolve_commit(git_dir, ref, run)
    epoch = commit_timestamp(git_dir, sha, run)

    work_root = Path(tempfile.mkdtemp(prefix="ghidra-fw-", dir=tempfile.gettempdir()))
    snapshot = work_root / "sdk"
    build_dir = work_root / "build"
    staging_dir = work_root / "harvest"
    worktree_added = False
    try:
        if extract is not None:
            extract(git_dir, sha, snapshot)
        else:
            fw.checkout_with_submodules(git_dir, sha, snapshot, run, _git)
            worktree_added = True
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["TZ"] = "UTC"
        env["SOURCE_DATE_EPOCH"] = epoch
        env["PICO_SDK_PATH"] = str(snapshot)
        extra_flags = [
            flag.replace(SNAPSHOT_PLACEHOLDER, str(snapshot)) for flag in extra_flags
        ]
        extra_flags = with_debug_maps(extra_flags, snapshot, name)
        mapping = {
            "cc": cc,
            "cxx": cxx,
            "opt": opt,
            "cflags": " ".join(extra_flags),
            "snapshot": str(snapshot),
            "build": str(build_dir),
        }
        commands: list[list[str]] = []
        if generator == "make":
            out_of_tree = bool(meta.get("out_of_tree"))
            cwd = build_dir if out_of_tree else snapshot
            if out_of_tree:
                build_dir.mkdir(parents=True, exist_ok=True)
            env["CC"] = cc
            env["CXX"] = cxx
            env["CFLAGS"] = " ".join([opt, *extra_flags])
            env["CXXFLAGS"] = env["CFLAGS"]
            for key, timeout, status in (
                ("prepare", 180, "configure_failed"),
                ("configure", 300, "configure_failed"),
                ("make", 1800, "compile_failed"),
            ):
                argv = fw.argv_from_meta(meta, key, mapping)
                if not argv:
                    if key == "make":
                        argv = ["make", "-j"]
                    else:
                        continue
                commands.append(argv)
                stepped = run(argv, cwd=cwd, env=env, timeout=timeout)
                if stepped.returncode != 0:
                    stderr = (stepped.stderr or stepped.stdout or "").strip()
                    raise BuildError(
                        f"{key} failed:\n{stderr}",
                        status=status,
                        extra={"stderr": stderr, "command": argv},
                    )
            groups = fw.harvest_declared(meta, snapshot, cwd)
            if not groups:
                groups = fw.harvest_groups(build_dir) or fw.harvest_groups(snapshot)
        else:
            env.pop("CC", None)
            env.pop("CXX", None)
            configure = fw.cmake_configure_argv(
                stub=stub,
                build_dir=build_dir,
                sdk_path=str(snapshot),
                board=board,
                libraries=libraries,
                opt=opt,
                config=config,
                extra_flags=extra_flags,
                cc=cc,
                cxx=cxx,
                cache_vars=fw.toolchain_cache_argv(
                    meta, fw.toolchain_tokens(cc, cxx, toolchain)),
            )
            commands = [configure]
            configured = run(configure, env=env, timeout=180)
            if configured.returncode != 0:
                stderr = (configured.stderr or configured.stdout or "").strip()
                raise BuildError(
                    f"cmake configure failed:\n{stderr}",
                    status="configure_failed",
                    extra={"stderr": stderr, "command": configure},
                )
            build = fw.cmake_build_argv(build_dir)
            commands.append(build)
            built = run(build, env=env, timeout=900)
            if built.returncode != 0:
                stderr = (built.stderr or built.stdout or "").strip()
                raise BuildError(
                    f"cmake build failed:\n{stderr}",
                    status="compile_failed",
                    extra={"stderr": stderr, "command": build},
                )
            groups = fw.harvest_groups(build_dir)

        if not groups:
            raise BuildError(
                "refusing to write: 0 defined functions harvested "
                "(0 target objects in the build tree; the linked ELF was not used)",
                status="zero_functions",
                extra={"function_count": 0, "commit_sha": sha},
            )

        missing = [lib for lib in libraries if lib not in groups]
        if missing:
            raise BuildError(
                "library not harvested from the build tree: "
                + ", ".join(missing)
                + f" (found: {sorted(groups)})",
                status="library_not_harvested",
                extra={"missing": missing, "found": sorted(groups)},
            )

        # Requested libraries first, then submodule extras that compiled.
        ordered: list[str] = []
        for lib in libraries:
            if lib not in ordered:
                ordered.append(lib)
        for lib in sorted(groups):
            if lib not in ordered:
                ordered.append(lib)

        staging_dir.mkdir(parents=True, exist_ok=True)
        artifacts: list[dict[str, Any]] = []
        written: list[Path] = []
        total_fns = 0
        compiler_ver = cc_version(cc, run)
        try:
            for lib in ordered:
                filename = artifact_filename(name, lib, ref, toolchain, opt, board)
                staged = staging_dir / filename
                dest = output_dir / filename
                combine_cmd = fw.combine_objects(groups[lib], staged, ld, run, env)
                commands.append(combine_cmd)
                names = defined_functions(nm_bin, staged, run, env)
                if not names:
                    raise BuildError(
                        f"refusing to write: 0 defined functions in harvested {lib} "
                        "(everything was optimised out or the ELF was harvested)",
                        status="zero_functions",
                        extra={"function_count": 0, "library": lib, "commit_sha": sha},
                    )
                install_built_object(staged, dest)
                written.append(dest)
                digest = sha256_file(dest)
                write_provenance_sidecar(
                    dest,
                    req=req,
                    commit=sha,
                    compiler_version=compiler_ver,
                    function_count=len(names),
                    digest=digest,
                    extra={
                        "framework": framework,
                        "library": lib,
                        "board": board,
                        "config": config,
                    },
                )
                total_fns += len(names)
                artifacts.append(
                    artifact_record(
                        path=str(dest),
                        library=lib,
                        bytes_size=dest.stat().st_size,
                        digest=digest,
                        function_count=len(names),
                        defined_functions=names[:200],
                    )
                )
        except Exception:
            remove_installed_artifacts(written)
            raise

        if total_fns == 0:
            remove_installed_artifacts(written)
            raise BuildError(
                "refusing to write: 0 defined functions harvested",
                status="zero_functions",
                extra={"function_count": 0, "commit_sha": sha},
            )

        return result_envelope(
            status="success",
            mode="framework",
            name=name,
            ref=ref,
            toolchain=toolchain,
            artifacts=artifacts,
            command=commands,
            commit_sha=sha,
            cc_version=compiler_ver,
            framework=framework,
            board=board,
        )
    except fw.FrameworkError as exc:
        raise BuildError(str(exc), status=exc.status, extra=exc.extra) from exc
    finally:
        if worktree_added:
            _git(run, ["--git-dir", str(git_dir), "worktree", "remove", "--force", str(snapshot)])
        shutil.rmtree(work_root, ignore_errors=True)


def handle_request(
    req: Mapping[str, Any],
    *,
    run: RunFn = _default_run,
    src_cache: Path = DEFAULT_SRC_CACHE,
    extract: Callable[[Path, str, Path], None] | None = None,
) -> dict[str, Any]:
    mode = str(req.get("mode") or "sources").strip() or "sources"
    if mode == "framework":
        return handle_framework_request(req, run=run, src_cache=src_cache, extract=extract)
    if mode != "sources":
        raise BuildError(
            f"mode must be 'sources' or 'framework'; got {mode!r}",
            status="invalid_mode",
        )
    repo = str(req.get("repo") or "").strip()
    ref = str(req.get("ref") or "").strip()
    sources = [str(s).strip() for s in (req.get("sources") or []) if str(s).strip()]
    cflags = [str(s) for s in (req.get("cflags") or [])]
    do_strip = bool(req.get("strip_debug", False))
    toolchain = str(req.get("toolchain") or "").strip()
    prepare = require_prepare(req, "sources")
    prepare_timeout = require_prepare_timeout(req)

    if not repo:
        raise BuildError("repo is required", status="invalid_repo")
    if not sources:
        raise BuildError("sources is required (e.g. [\"lfs.c\"])", status="invalid_sources")

    reject_branch_name(ref)
    tools = tools_for_request(req)
    cc = tools["cc"]
    ld = tools["ld"]
    strip_bin = tools["strip"]
    nm_bin = tools["nm"]
    for src in sources:
        if src.startswith("/") or src.startswith("-") or ".." in Path(src).parts:
            raise BuildError(
                f"source path {src!r} must be a relative path inside the repo",
                status="invalid_sources",
            )

    if bool(req.get("dry_run")):
        commands: list[list[str]] = []
        if prepare:
            commands.append(prepare_argv(prepare))
        mapped_base = with_debug_maps(list(cflags), Path(SNAPSHOT_PLACEHOLDER), str(req.get("name") or ""))
        objects: list[str] = []
        raw_output = str(req.get("output") or "").strip() or "<output>"
        for index, rel in enumerate(sources):
            obj = f"{index:03d}-{Path(rel).name}.o"
            argv = [cc, "-c", *mapped_base, rel, "-o", obj]
            commands.append(argv)
            objects.append(obj)
        if len(objects) > 1:
            commands.append([ld, "-r", "--build-id=none", "-o", raw_output, *objects])
        if do_strip:
            commands.append([strip_bin, "--strip-debug", raw_output])
        return result_envelope(
            status="would_execute",
            mode="sources",
            name=str(req.get("name") or ""),
            ref=ref,
            toolchain=toolchain,
            artifacts=[artifact_record(path=raw_output, library="")],
            command=commands,
            prepare=prepare,
            extra={"dry_run": True, "prepare_timeout": prepare_timeout},
        )

    raw_output = str(req.get("output") or "").strip()
    if not raw_output:
        raise BuildError("output is required", status="invalid_output")
    output = require_output_under_root(Path(raw_output))

    git_dir = ensure_bare_clone(repo, src_cache, run)
    sha = resolve_commit(git_dir, ref, run)
    epoch = commit_timestamp(git_dir, sha, run)

    work_root = Path(tempfile.mkdtemp(prefix="ghidra-build-", dir=tempfile.gettempdir()))
    snapshot = work_root / "src"
    objdir = work_root / "obj"
    staging = work_root / "out.o"
    try:
        extractor = extract or extract_snapshot_bytes
        extractor(git_dir, sha, snapshot)
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["TZ"] = "UTC"
        env["SOURCE_DATE_EPOCH"] = epoch
        commands = []
        if prepare:
            commands.append(run_prepare(prepare, prepare_timeout, snapshot, run, env))
        compiled_cmds, failed_units = compile_objects(
            snapshot=snapshot,
            sources=sources,
            cflags=cflags,
            cc=cc,
            ld=ld,
            workdir=objdir,
            output=staging,
            run=run,
            env=env,
            name=str(req.get("name") or ""),
        )
        commands.extend(compiled_cmds)
        if do_strip:
            commands.append(strip_debug(strip_bin, staging, run, env))
        names = defined_functions(nm_bin, staging, run, env)
        if not names:
            raise BuildError(
                "refusing to write: 0 defined functions (everything was "
                "optimised out or the wrong file was compiled)",
                status="zero_functions",
                extra={"function_count": 0, "commit_sha": sha},
            )
        written: list[Path] = []
        try:
            install_built_object(staging, output)
            written.append(output)
            compiler_ver = cc_version(cc, run)
            digest = sha256_file(output)
            write_provenance_sidecar(
                output,
                req=req,
                commit=sha,
                compiler_version=compiler_ver,
                function_count=len(names),
                digest=digest,
            )
        except Exception:
            remove_installed_artifacts(written)
            raise
        return result_envelope(
            status="success",
            mode="sources",
            name=str(req.get("name") or ""),
            ref=ref,
            toolchain=toolchain,
            artifacts=[
                artifact_record(
                    path=str(output),
                    library="",
                    bytes_size=output.stat().st_size,
                    digest=digest,
                    function_count=len(names),
                    defined_functions=names[:200],
                )
            ],
            command=commands,
            failed=failed_units,
            commit_sha=sha,
            cc_version=compiler_ver,
            prepare=prepare,
        )
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def error_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, BuildError):
        body = {"ok": False, "error": str(exc), "status": exc.status}
        body.update(exc.extra)
        return body
    return {"ok": False, "error": str(exc), "status": "internal_error"}


def health_payload(run: RunFn = _default_run) -> dict[str, Any]:
    installed = packed_toolchains.list_installed()
    identities = sorted(installed)
    # generators is how a stale image is diagnosable from builder_health:
    # cmake -G Ninja on an image without ninja-build fails configure with
    # "CMAKE_MAKE_PROGRAM is not set", which reads like a stub bug.
    generators = [name for name in ("Ninja", "Unix Makefiles")
                  if shutil.which({"Ninja": "ninja", "Unix Makefiles": "make"}[name])]
    body: dict[str, Any] = {
        "ok": True,
        "identities": identities,
        "uid": os.getuid(),
        "stubs": fw.list_stubs(),
        "generators": generators,
        "cmake_generator": fw.cmake_generator() or "default",
    }
    releases: dict[str, str] = {}
    for ident, prefix in installed.items():
        meta = prefix / "identity.json"
        if not meta.is_file():
            continue
        try:
            payload = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rel = str(payload.get("release") or "").strip()
        if rel:
            releases[ident] = rel
    if releases:
        body["releases"] = releases
    if identities:
        probe = ""
        for ident in identities:
            prefix = installed[ident]
            gcc = prefix / "bin" / "arm-none-eabi-gcc"
            clang = prefix / "bin" / "clang"
            if clang.is_file() and not gcc.is_file():
                probe = str(clang)
                break
            if gcc.is_file():
                probe = str(gcc)
                break
            ident_meta = packed_toolchains._identity_meta(prefix)
            if str(ident_meta.get("kind") or "").strip() == "native":
                cc_path = str(ident_meta.get("cc") or "").strip()
                if cc_path:
                    probe = cc_path
                    break
        if probe:
            body["cc"] = probe
            body["cc_version"] = cc_version(probe, run)
        else:
            cc = os.environ.get("BUILDER_CC", DEFAULT_CC)
            body["cc"] = cc
            body["cc_version"] = cc_version(cc, run)
    else:
        cc = os.environ.get("BUILDER_CC", DEFAULT_CC)
        body["cc"] = cc
        body["cc_version"] = cc_version(cc, run)
    return body


JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
QUEUE = builder_jobs.JobQueue()


class BuilderHandler(BaseHTTPRequestHandler):
    # staticmethod: a plain function stored on the class would bind `self`
    # and pass the handler instance as argv to gcc --version.
    run = staticmethod(_default_run)
    src_cache: Path = DEFAULT_SRC_CACHE

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, indent=None).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    @classmethod
    def ensure_worker(cls) -> None:
        QUEUE.start(
            handle=handle_request,
            error_payload=error_payload,
            run=cls.run,
            src_cache=cls.src_cache,
        )

    def do_GET(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0].rstrip("/") or "/"
        if route in {"/health", "/"}:
            self._send(200, health_payload(self.run))
            return
        if route == "/stubs":
            self._send(200, {"ok": True, "stubs": fw.list_stubs()})
            return
        if route == "/builds":
            listed = QUEUE.list_jobs()
            self._send(200, {"ok": True, "jobs": listed, "count": len(listed)})
            return
        if route.startswith("/build/"):
            job_id = route[len("/build/") :]
            if not JOB_ID_RE.fullmatch(job_id):
                self._send(400, {"ok": False, "error": "invalid job_id", "status": "invalid_job_id"})
                return
            job = QUEUE.get(job_id)
            if job is None:
                self._send(404, {
                    "ok": False,
                    "error": f"no build job '{job_id}'",
                    "status": "job_not_found",
                })
                return
            self._send(200, job.snapshot())
            return
        self._send(404, {"ok": False, "error": "not found", "status": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        route = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 1_000_000:
            self._send(413, {"ok": False, "error": "request too large", "status": "oversized"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send(400, {"ok": False, "error": "malformed JSON", "status": "malformed"})
            return
        if not isinstance(req, dict):
            self._send(400, {"ok": False, "error": "JSON object required", "status": "malformed"})
            return
        if route == "/source":
            try:
                payload = src_read.handle_source_request(
                    req,
                    run=self.run,
                    src_cache=self.src_cache,
                    confine_artifact=require_output_under_root,
                )
                self._send(200, payload)
            except src_read.SourceError as exc:
                body = {"ok": False, "error": str(exc), "status": exc.status}
                body.update(exc.extra)
                code = 404 if exc.status in {
                    "artifact_not_found",
                    "commit_not_cached",
                    "path_not_in_commit",
                    "function_not_found",
                    "sidecar_missing",
                } else 400
                self._send(code, body)
            except BuildError as exc:
                self._send(400, error_payload(exc))
            except Exception as exc:  # noqa: BLE001
                self._send(500, error_payload(exc))
            return
        if route != "/build":
            self._send(404, {"ok": False, "error": "not found", "status": "not_found"})
            return
        self.ensure_worker()
        job = QUEUE.submit(req)
        self._send(202, {"ok": True, "job_id": job.id, "status": "queued"})


def serve(host: str, port: int, src_cache: Path) -> None:
    BuilderHandler.src_cache = src_cache
    BuilderHandler.ensure_worker()
    httpd = ThreadingHTTPServer((host, port), BuilderHandler)
    installed = packed_toolchains.list_installed()
    sys.stderr.write(
        f"ghidra-build-reference listening on {host}:{port} "
        f"identities={sorted(installed) or ['(unpacked)']} uid={os.getuid()}\n"
    )
    httpd.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ghidra-build-reference")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve_p = sub.add_parser("serve", help="HTTP control plane (compose default)")
    serve_p.add_argument("--host", default="0.0.0.0")
    serve_p.add_argument("--port", type=int, default=int(os.environ.get("BUILDER_PORT", DEFAULT_PORT)))
    build_p = sub.add_parser("build", help="Build one request from stdin JSON")
    build_p.add_argument("--src-cache", default=str(DEFAULT_SRC_CACHE))
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        serve(
            args.host,
            args.port,
            Path(os.environ.get("GHIDRA_MCP_SRC_CACHE", str(DEFAULT_SRC_CACHE))),
        )
        return 0

    req = json.load(sys.stdin)
    try:
        payload = handle_request(req, src_cache=Path(args.src_cache))
        json.dump(payload, sys.stdout)
        sys.stdout.write("\n")
        return 0
    except BuildError as exc:
        json.dump(error_payload(exc), sys.stdout)
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
