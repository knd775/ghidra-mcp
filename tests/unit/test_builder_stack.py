"""Reference builder stack: compose, image tags, manifest, compile script."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER_PY = REPO_ROOT / "docker" / "builder" / "ghidra_build_reference.py"
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile.builder"
MANIFEST = REPO_ROOT / "docker" / "references.yaml"


def _load_builder():
    spec = importlib.util.spec_from_file_location("ghidra_build_reference", BUILDER_PY)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


gbr = _load_builder()


class TestBuilderCompose(unittest.TestCase):
    def setUp(self):
        self.doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))

    def test_builder_services_exist_and_share_volume(self):
        services = self.doc["services"]
        self.assertIn("builder", services)
        self.assertIn("builder-gcc12", services)
        self.assertIn("builder-gcc10", services)
        self.assertIn("ghidra-mcp", services)
        for name in ("builder", "builder-gcc12", "builder-gcc10"):
            svc = services[name]
            self.assertEqual(svc["user"], "1000:1000")
            self.assertNotIn("ports", svc)
            self.assertIn("ghidra", svc["networks"])
            image = svc["image"]
            self.assertNotIn(":latest", image)
            self.assertTrue(image.startswith("ghidra-builder:gcc"), image)
            self.assertEqual(svc["environment"]["GHIDRA_MCP_FILE_ROOT"], "/data")
            vols = " ".join(str(v) for v in svc["volumes"])
            self.assertIn("SAMPLES_DIR", vols)
            self.assertIn("builder-src-cache:/src", vols)

    def test_ghidra_mcp_points_at_builders_and_shares_samples(self):
        mcp = self.doc["services"]["ghidra-mcp"]
        urls = mcp["environment"]["GHIDRA_MCP_BUILDER_URLS"]
        self.assertIn("ghidra-builder:8092", urls)
        self.assertIn("ghidra-builder-gcc12:8092", urls)
        self.assertIn("ghidra-builder-gcc10:8092", urls)
        self.assertEqual(mcp["environment"]["GHIDRA_MCP_FILE_ROOT"], "/data")
        self.assertIn("builder", mcp["depends_on"])
        self.assertIn("builder-gcc12", mcp["depends_on"])
        self.assertIn("builder-gcc10", mcp["depends_on"])
        volumes = mcp["volumes"]
        self.assertFalse(
            any("docker.sock" in str(v) for v in volumes),
            "ghidra-mcp must not mount docker.sock",
        )

    def test_dockerfile_is_parameterised_and_uid_1000(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("ARG TOOLCHAIN_TAG", text)
        self.assertIn("ARG BASE_IMAGE", text)
        self.assertIn("useradd --uid 1000 --gid 1000", text)
        self.assertIn("getent passwd 1000", text)
        self.assertNotIn(":latest", text.split("FROM", 1)[-1][:80])
        self.assertIn("gcc-arm-none-eabi", text)
        self.assertIn("libnewlib-arm-none-eabi", text)
        self.assertIn('CMD ["serve"]', text)
        self.assertIn("GHIDRA_MCP_FILE_ROOT=/data", text)
        health_lines = [ln for ln in text.splitlines() if "HEALTHCHECK" in ln or "urlopen" in ln]
        self.assertTrue(any("/health" in ln for ln in health_lines))
        self.assertFalse(
            any("Bearer" in ln for ln in health_lines),
            "HEALTHCHECK must not put the auth token on the command line",
        )

    def test_manifest_expands_to_nine(self):
        doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
        entry = doc["references"][0]
        self.assertEqual(entry["name"], "littlefs")
        self.assertEqual(entry["ref"], "v2.9.3")
        self.assertNotIn(entry["ref"], ("main", "master", "HEAD"))
        matrix = entry["matrix"]
        n = len(matrix["toolchain"]) * len(matrix["opt"])
        self.assertEqual(n, 9)
        expected = [
            f"littlefs-v2.9.3-{tc}-{opt.lstrip('-')}.o"
            for tc in matrix["toolchain"]
            for opt in matrix["opt"]
        ]
        self.assertEqual(
            expected,
            [
                "littlefs-v2.9.3-gcc10-Os.o",
                "littlefs-v2.9.3-gcc10-O2.o",
                "littlefs-v2.9.3-gcc10-O3.o",
                "littlefs-v2.9.3-gcc12-Os.o",
                "littlefs-v2.9.3-gcc12-O2.o",
                "littlefs-v2.9.3-gcc12-O3.o",
                "littlefs-v2.9.3-gcc13-Os.o",
                "littlefs-v2.9.3-gcc13-O2.o",
                "littlefs-v2.9.3-gcc13-O3.o",
            ],
        )


class TestBuilderScript(unittest.TestCase):
    def test_rejects_branch_before_git(self):
        with self.assertRaises(gbr.BuildError) as ctx:
            gbr.reject_branch_name("main")
        self.assertEqual(ctx.exception.status, "ref_is_branch")
        with self.assertRaises(gbr.BuildError):
            gbr.reject_branch_name("HEAD")
        gbr.reject_branch_name("v2.9.3")
        gbr.reject_branch_name("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

    def test_defined_functions_counts_text_symbols_only(self):
        nm_out = (
            "00000000 T lfs_bd_read\n"
            "00000010 t lfs_dir_fetchmatch\n"
            "00000020 D g_counter\n"
            "         U memcpy\n"
        )

        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout=nm_out, stderr="")

        names = gbr.defined_functions("arm-none-eabi-nm", Path("/tmp/x.o"), run, {})
        self.assertEqual(names, ["lfs_bd_read", "lfs_dir_fetchmatch"])

    def test_handle_request_compile_failure_returns_stderr(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "src"
            snap_written = {}

            def extract(git_dir, sha, dest):
                dest.mkdir(parents=True, exist_ok=True)
                (dest / "lfs.c").write_text("int lfs_bd_read(void) { return 0; }\n")
                snap_written["yes"] = True

            def run(argv, **kwargs):
                if argv[0] == "git":
                    joined = " ".join(argv)
                    if "clone" in argv:
                        Path(argv[-1]).mkdir(parents=True, exist_ok=True)
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv and "refs/tags/" in argv[-1]:
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv:
                        return subprocess.CompletedProcess(argv, 1, "", "")
                    if "rev-parse" in argv:
                        return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
                    if "log" in argv:
                        return subprocess.CompletedProcess(argv, 0, "1700000000\n", "")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-gcc":
                    return subprocess.CompletedProcess(
                        argv, 1, "", "lfs.c:1: error: boom\n"
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            req = {
                "repo": "https://github.com/littlefs-project/littlefs.git",
                "ref": "v2.9.3",
                "sources": ["lfs.c"],
                "cflags": ["-fno-common"],
                "output": str(Path(td) / "uploads" / "out.o"),
                "strip_debug": True,
            }
            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.handle_request(req, run=run, src_cache=cache, extract=extract)
            self.assertEqual(ctx.exception.status, "compile_failed")
            self.assertIn("boom", str(ctx.exception))

    def test_handle_request_zero_functions_refuses_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "src"
            dest = Path(td) / "uploads" / "out.o"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "lfs.c").write_text("int unused;\n")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    if "clone" in argv:
                        Path(argv[-1]).mkdir(parents=True, exist_ok=True)
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv and "refs/tags/" in argv[-1]:
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv:
                        return subprocess.CompletedProcess(argv, 1, "", "")
                    if "rev-parse" in argv:
                        return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
                    if "log" in argv:
                        return subprocess.CompletedProcess(argv, 0, "1\n", "")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "-c" in argv:
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"ELF")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-strip":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    return subprocess.CompletedProcess(argv, 0, "00000000 D unused\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            req = {
                "repo": "https://github.com/littlefs-project/littlefs.git",
                "ref": "v2.9.3",
                "sources": ["lfs.c"],
                "cflags": ["-fno-common"],
                "output": str(dest),
                "strip_debug": True,
            }
            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.handle_request(req, run=run, src_cache=cache, extract=extract)
            self.assertEqual(ctx.exception.status, "zero_functions")
            self.assertFalse(dest.exists())

    def test_strip_keeps_symtab_argv(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "x.o"
            out.write_bytes(b"obj")
            gbr.strip_debug("arm-none-eabi-strip", out, run, {})
        self.assertEqual(calls[0][1], "--strip-debug")
        self.assertNotIn("--strip-all", calls[0])
        self.assertNotIn("--strip-unneeded", calls[0])

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("nm"), "host gcc/nm not installed")
    def test_two_host_gcc_builds_match_and_keep_symbols(self):
        """Acceptance 3 and 7 against the host compiler (script logic, not ARM)."""
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "snap"
            src.mkdir()
            (src / "lfs.c").write_text("int lfs_bd_read(void) { return 42; }\n")
            hashes = []
            for i in range(2):
                out = Path(td) / f"out{i}.o"
                env = os.environ.copy()
                env["LC_ALL"] = "C"
                env["SOURCE_DATE_EPOCH"] = "0"
                env["TZ"] = "UTC"
                work = Path(td) / f"obj{i}"
                gbr.compile_objects(
                    snapshot=src,
                    sources=["lfs.c"],
                    cflags=["-fno-common", "-ffunction-sections", "-fno-ident", "-frandom-seed=out.o"],
                    cc="gcc",
                    ld="ld",
                    workdir=work,
                    output=out,
                    run=gbr._default_run,
                    env=env,
                )
                strip = shutil.which("strip") or "strip"
                gbr.strip_debug(strip, out, gbr._default_run, env)
                names = gbr.defined_functions("nm", out, gbr._default_run, env)
                self.assertIn("lfs_bd_read", names)
                hashes.append(gbr.sha256_file(out))
            self.assertEqual(hashes[0], hashes[1], "unpinned input leaked into the object")


class TestBuilderInstallAndRefs(unittest.TestCase):
    def test_install_built_object_copies_then_replaces(self):
        with tempfile.TemporaryDirectory() as td:
            staging = Path(td) / "tmp" / "out.o"
            dest = Path(td) / "data" / "uploads" / "out.o"
            staging.parent.mkdir(parents=True)
            staging.write_bytes(b"ELF\x00object")
            gbr.install_built_object(staging, dest)
            self.assertEqual(dest.read_bytes(), b"ELF\x00object")
            self.assertTrue(staging.exists())
            self.assertEqual(list(dest.parent.glob(".out.o.*.tmp")), [])

    def test_output_outside_file_root_refused_before_git(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "data"
            root.mkdir()
            dest = Path(td) / "elsewhere" / "out.o"

            def boom(*_a, **_k):
                self.fail("must not clone or compile")

            with patch.dict(os.environ, {"GHIDRA_MCP_FILE_ROOT": str(root)}):
                with self.assertRaises(gbr.BuildError) as ctx:
                    gbr.handle_request(
                        {
                            "repo": "https://github.com/littlefs-project/littlefs.git",
                            "ref": "v2.9.3",
                            "sources": ["lfs.c"],
                            "output": str(dest),
                        },
                        run=boom,
                        src_cache=Path(td) / "src",
                    )
            self.assertEqual(ctx.exception.status, "invalid_output")

    def test_warm_cache_survives_fetch_failure(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td)
            repo = "https://github.com/littlefs-project/littlefs.git"
            dest = cache / f"{gbr.sanitize_repo_id(repo)}.git"
            dest.mkdir()
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if "clone" in argv:
                    self.fail("must not re-clone when the cache exists")
                if "fetch" in argv:
                    return subprocess.CompletedProcess(argv, 1, "", "network down")
                return subprocess.CompletedProcess(argv, 0, "", "")

            got = gbr.ensure_bare_clone(repo, cache, run)
            self.assertEqual(got, dest)
            self.assertTrue(any("fetch" in argv for argv in calls))

    def test_missing_tag_names_ref_and_reachability(self):
        def run(argv, **kwargs):
            if "show-ref" in argv or "rev-parse" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.resolve_commit(Path(td), "v9.9.9", run)
        self.assertEqual(ctx.exception.status, "ref_not_found")
        self.assertIn("v9.9.9", str(ctx.exception))
        self.assertTrue(ctx.exception.extra.get("repo_reachable"))

    def test_compile_substitutes_snapshot_placeholder(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            Path(argv[argv.index("-o") + 1]).write_bytes(b"x")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            snap = Path(td) / "snap"
            snap.mkdir()
            (snap / "lfs.c").write_text("int x(void) { return 1; }\n")
            gbr.compile_objects(
                snapshot=snap,
                sources=["lfs.c"],
                cflags=[
                    f"-ffile-prefix-map={gbr.SNAPSHOT_PLACEHOLDER}=.",
                    "-fno-common",
                ],
                cc="arm-none-eabi-gcc",
                ld="arm-none-eabi-ld",
                workdir=Path(td) / "obj",
                output=Path(td) / "out.o",
                run=run,
                env=os.environ,
            )
        gcc = calls[0]
        self.assertIn(f"-ffile-prefix-map={snap}=.", gcc)
        self.assertFalse(any(gbr.SNAPSHOT_PLACEHOLDER in flag for flag in gcc))

    def test_successful_build_writes_object_with_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads" / "littlefs-v2.9.3-gcc13-Os.o"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "lfs.c").write_text("int lfs_bd_read(void) { return 0; }\n")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    if "clone" in argv:
                        Path(argv[-1]).mkdir(parents=True, exist_ok=True)
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv and "refs/tags/" in argv[-1]:
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if "show-ref" in argv:
                        return subprocess.CompletedProcess(argv, 1, "", "")
                    if "rev-parse" in argv:
                        return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
                    if "log" in argv:
                        return subprocess.CompletedProcess(argv, 0, "1\n", "")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "-c" in argv:
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"ELF")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-strip":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    return subprocess.CompletedProcess(
                        argv, 0, "00000000 T lfs_bd_read\n", ""
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = gbr.handle_request(
                {
                    "repo": "https://github.com/littlefs-project/littlefs.git",
                    "ref": "v2.9.3",
                    "sources": ["lfs.c"],
                    "cflags": ["-fno-common"],
                    "output": str(dest),
                    "strip_debug": True,
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["function_count"], 1)
            self.assertEqual(result["defined_functions"], ["lfs_bd_read"])
            self.assertEqual(result["commit_sha"], "abc123")
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), b"ELF")
            self.assertTrue(os.access(dest, os.R_OK))


class TestHttpControlPlane(unittest.TestCase):
    def test_run_is_not_bound_as_instance_method(self):
        self.assertIsInstance(gbr.BuilderHandler.__dict__["run"], staticmethod)

    def test_health_is_open_build_requires_token(self):
        def fake_run(argv, **kwargs):
            if "--version" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, "arm-none-eabi-gcc 13.2.1\n", ""
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

        prev_token = gbr.BuilderHandler.token
        gbr.BuilderHandler.run = staticmethod(fake_run)
        gbr.BuilderHandler.token = "secret"
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), gbr.BuilderHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=2
            ) as resp:
                body = json.loads(resp.read().decode())
            self.assertTrue(body["ok"])
            self.assertIn("cc_version", body)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/build",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=2)
            self.assertEqual(ctx.exception.code, 401)
        finally:
            httpd.shutdown()
            httpd.server_close()
            gbr.BuilderHandler.run = staticmethod(gbr._default_run)
            gbr.BuilderHandler.token = prev_token


if __name__ == "__main__":
    unittest.main()
