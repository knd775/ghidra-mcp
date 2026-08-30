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
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

DEFAULT_PORT = 8092
DEFAULT_SRC_CACHE = Path("/src")
DEFAULT_CC = "arm-none-eabi-gcc"
DEFAULT_LD = "arm-none-eabi-ld"
DEFAULT_STRIP = "arm-none-eabi-strip"
DEFAULT_NM = "arm-none-eabi-nm"
# Java dry_run argv uses this token; we substitute the snapshot path at compile.
SNAPSHOT_PLACEHOLDER = "<snapshot>"

SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
BRANCH_NAMES = frozenset(
    {"HEAD", "head", "main", "master", "develop", "dev", "trunk", "next"}
)
TEXT_NM_TYPES = frozenset("TtWw")

RunFn = Callable[..., subprocess.CompletedProcess[str]]


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


def _default_run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    timeout: float | None = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=None if env is None else dict(env),
        check=check,
        timeout=timeout,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


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
) -> tuple[list[list[str]], str]:
    """Compile sources; return (commands, compiler_stderr_from_last_failure)."""
    commands: list[list[str]] = []
    objects: list[Path] = []
    workdir.mkdir(parents=True, exist_ok=True)
    for index, rel in enumerate(sources):
        src_path = snapshot / rel
        if not src_path.is_file():
            raise BuildError(
                f"source {rel!r} not found in the checked-out tree",
                status="source_not_found",
                extra={"source": rel},
            )
        obj = workdir / f"{index:03d}-{Path(rel).name}.o"
        mapped_flags = [flag.replace(SNAPSHOT_PLACEHOLDER, str(snapshot)) for flag in cflags]
        argv = [cc, "-c"]
        if not any(flag.startswith("-ffile-prefix-map=") for flag in mapped_flags):
            argv.append(f"-ffile-prefix-map={snapshot}=.")
        if not any(flag.startswith("-fmacro-prefix-map=") for flag in mapped_flags):
            argv.append(f"-fmacro-prefix-map={snapshot}=.")
        argv.extend(mapped_flags)
        argv.extend([rel, "-o", str(obj)])
        commands.append(argv)
        compiled = run(argv, cwd=snapshot, env=env, timeout=120)
        if compiled.returncode != 0:
            stderr = (compiled.stderr or compiled.stdout or "").strip()
            raise BuildError(
                f"compile failed for {rel}:\n{stderr}",
                status="compile_failed",
                extra={"stderr": stderr, "source": rel, "command": argv},
            )
        objects.append(obj)

    if len(objects) == 1:
        shutil.copy2(objects[0], output)
        return commands, ""

    argv = [ld, "-r", "--build-id=none", "-o", str(output), *[str(p) for p in objects]]
    commands.append(argv)
    linked = run(argv, cwd=snapshot, env=env, timeout=60)
    if linked.returncode != 0:
        stderr = (linked.stderr or linked.stdout or "").strip()
        raise BuildError(
            f"ld -r failed:\n{stderr}",
            status="compile_failed",
            extra={"stderr": stderr, "command": argv},
        )
    return commands, ""


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


def cc_version(cc: str, run: RunFn) -> str:
    r = run([cc, "--version"], timeout=15)
    line = (r.stdout or r.stderr or "").splitlines()
    return line[0].strip() if line else cc


def handle_request(
    req: Mapping[str, Any],
    *,
    run: RunFn = _default_run,
    src_cache: Path = DEFAULT_SRC_CACHE,
    extract: Callable[[Path, str, Path], None] | None = None,
) -> dict[str, Any]:
    repo = str(req.get("repo") or "").strip()
    ref = str(req.get("ref") or "").strip()
    sources = [str(s).strip() for s in (req.get("sources") or []) if str(s).strip()]
    cflags = [str(s) for s in (req.get("cflags") or [])]
    cc = str(req.get("cc") or DEFAULT_CC)
    ld = str(req.get("ld") or DEFAULT_LD)
    strip_bin = str(req.get("strip") or DEFAULT_STRIP)
    nm_bin = str(req.get("nm") or DEFAULT_NM)
    do_strip = bool(req.get("strip_debug", True))

    if not repo:
        raise BuildError("repo is required", status="invalid_repo")
    if not sources:
        raise BuildError("sources is required (e.g. [\"lfs.c\"])", status="invalid_sources")
    raw_output = str(req.get("output") or "").strip()
    if not raw_output:
        raise BuildError("output is required", status="invalid_output")
    output = require_output_under_root(Path(raw_output))

    reject_branch_name(ref)
    for src in sources:
        if src.startswith("/") or src.startswith("-") or ".." in Path(src).parts:
            raise BuildError(
                f"source path {src!r} must be a relative path inside the repo",
                status="invalid_sources",
            )

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
        commands, _ = compile_objects(
            snapshot=snapshot,
            sources=sources,
            cflags=cflags,
            cc=cc,
            ld=ld,
            workdir=objdir,
            output=staging,
            run=run,
            env=env,
        )
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
        install_built_object(staging, output)
        result = {
            "ok": True,
            "path": str(output),
            "bytes": output.stat().st_size,
            "sha256": sha256_file(output),
            "function_count": len(names),
            "defined_functions": names[:200],
            "commit_sha": sha,
            "command": commands,
            "cc_version": cc_version(cc, run),
            "toolchain": os.environ.get("TOOLCHAIN_TAG", ""),
        }
        return result
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def error_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, BuildError):
        body = {"ok": False, "error": str(exc), "status": exc.status}
        body.update(exc.extra)
        return body
    return {"ok": False, "error": str(exc), "status": "internal_error"}


def health_payload(run: RunFn = _default_run) -> dict[str, Any]:
    cc = os.environ.get("BUILDER_CC", DEFAULT_CC)
    tag = os.environ.get("TOOLCHAIN_TAG", "")
    return {
        "ok": True,
        "toolchain": tag,
        "cc": cc,
        "cc_version": cc_version(cc, run),
        "uid": os.getuid(),
    }


class BuilderHandler(BaseHTTPRequestHandler):
    # staticmethod: a plain function stored on the class would bind `self`
    # and pass the handler instance as argv to gcc --version.
    run = staticmethod(_default_run)
    src_cache: Path = DEFAULT_SRC_CACHE
    token: str = ""
    build_lock = threading.Lock()

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _unauthorized(self) -> bool:
        expected = (self.token or "").strip()
        if not expected:
            return False
        got = self.headers.get("Authorization", "")
        return got != f"Bearer {expected}"

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, indent=None).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        # /health is unauthenticated so the image HEALTHCHECK does not put
        # GHIDRA_MCP_AUTH_TOKEN on the process command line. POST /build still
        # requires the token when it is set. No host ports are published.
        if self.path.split("?", 1)[0].rstrip("/") in {"/health", ""}:
            self._send(200, health_payload(self.run))
            return
        if self._unauthorized():
            self._send(401, {"ok": False, "error": "unauthorized", "status": "unauthorized"})
            return
        self._send(404, {"ok": False, "error": "not found", "status": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self._unauthorized():
            self._send(401, {"ok": False, "error": "unauthorized", "status": "unauthorized"})
            return
        if self.path.rstrip("/") != "/build":
            self._send(404, {"ok": False, "error": "not found", "status": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 1_000_000:
            self._send(413, {"ok": False, "error": "request too large", "status": "oversized"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send(400, {"ok": False, "error": "malformed JSON", "status": "malformed"})
            return
        try:
            with self.build_lock:
                payload = handle_request(req, run=self.run, src_cache=self.src_cache)
            self._send(200, payload)
        except BuildError as exc:
            self._send(400, error_payload(exc))
        except Exception as exc:  # pragma: no cover - unexpected
            self._send(500, error_payload(exc))


def serve(host: str, port: int, token: str, src_cache: Path) -> None:
    BuilderHandler.token = token
    BuilderHandler.src_cache = src_cache
    httpd = ThreadingHTTPServer((host, port), BuilderHandler)
    sys.stderr.write(
        f"ghidra-build-reference listening on {host}:{port} "
        f"toolchain={os.environ.get('TOOLCHAIN_TAG', '?')} uid={os.getuid()}\n"
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
            os.environ.get("GHIDRA_MCP_AUTH_TOKEN", ""),
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
