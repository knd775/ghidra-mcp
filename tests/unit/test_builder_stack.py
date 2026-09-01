"""Reference builder stack: compose, image tags, manifest, compile script."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
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

if str(REPO_ROOT / "docker" / "builder") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "docker" / "builder"))


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

    def test_one_builder_service_and_shared_volume(self):
        services = self.doc["services"]
        self.assertIn("builder", services)
        self.assertNotIn("builder-gcc12", services)
        self.assertNotIn("builder-gcc10", services)
        self.assertIn("ghidra-mcp", services)
        self.assertNotIn("profiles", self.doc)
        self.assertNotIn("profiles", services["builder"])
        svc = services["builder"]
        self.assertEqual(svc["user"], "1000:1000")
        self.assertNotIn("ports", svc)
        self.assertIn("ghidra", svc["networks"])
        self.assertEqual(svc.get("restart"), "unless-stopped")
        image = svc["image"]
        self.assertIn("ghidra-mcp-builder", image)
        self.assertTrue(image.startswith("ghcr.io/"), image)
        self.assertIn("${GHIDRA_MCP_VERSION:-dev}", image)
        self.assertEqual(svc.get("hostname"), "ghidra-builder")
        self.assertEqual(svc.get("container_name"), "ghidra-builder")
        self.assertNotIn(":gcc", image)
        self.assertNotIn("TOOLCHAIN_TAG", svc.get("environment", {}))
        self.assertEqual(svc["environment"]["GHIDRA_MCP_FILE_ROOT"], "/data")
        self.assertEqual(
            svc["environment"]["GHIDRA_MCP_TOOLCHAINS"],
            "/opt/ghidra-builder/toolchains",
        )
        vols = " ".join(str(v) for v in svc["volumes"])
        self.assertIn("SAMPLES_DIR", vols)
        self.assertIn("builder-src-cache:/src", vols)

    def test_local_build_script_tags_the_ghcr_name(self):
        text = (REPO_ROOT / "docker" / "build-builders.sh").read_text(encoding="utf-8")
        self.assertIn("ghidra-mcp-builder", text)
        self.assertNotIn("-t ghidra-builder", text)

    def test_no_docker_sock_in_any_service(self):
        for name, svc in self.doc["services"].items():
            volumes = svc.get("volumes") or []
            self.assertFalse(
                any("docker.sock" in str(v) for v in volumes),
                f"{name} must not mount docker.sock",
            )

    def test_ghidra_mcp_points_at_the_one_builder(self):
        mcp = self.doc["services"]["ghidra-mcp"]
        self.assertEqual(
            mcp["environment"]["GHIDRA_MCP_BUILDER_URL"],
            "http://ghidra-builder:8092",
        )
        self.assertNotIn("GHIDRA_MCP_BUILDER_URLS", mcp["environment"])
        self.assertEqual(mcp["environment"]["GHIDRA_MCP_FILE_ROOT"], "/data")
        self.assertEqual(mcp["environment"]["GHIDRA_MCP_STUBS"], "/opt/ghidra-builder/stubs")
        self.assertIn("builder", mcp["depends_on"])
        self.assertNotIn("builder-gcc12", mcp["depends_on"])
        self.assertNotIn("builder-gcc10", mcp["depends_on"])
        volumes = mcp["volumes"]
        self.assertTrue(any("stubs" in str(v) for v in volumes))
        self.assertTrue(
            any("references.yaml" in str(v) and "userland" not in str(v) for v in volumes)
        )
        self.assertTrue(any("references.userland.yaml" in str(v) for v in volumes))
        self.assertFalse(
            any("docker.sock" in str(v) for v in volumes),
            "ghidra-mcp must not mount docker.sock",
        )

    def test_dockerfile_packs_three_toolchains_uid_1000(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("ghidra-mcp-builder", text)
        self.assertNotIn("ARG TOOLCHAIN_TAG", text)
        self.assertNotIn("ARG BASE_IMAGE", text)
        self.assertNotIn("gcc-arm-none-eabi", text)
        self.assertNotIn("libnewlib-arm-none-eabi", text)
        self.assertIn("useradd --uid 1000 --gid 1000", text)
        self.assertIn("getent passwd 1000", text)
        self.assertIn("cmake", text)
        self.assertIn("ninja-build", text)
        self.assertIn("/opt/ghidra-builder/stubs", text)
        self.assertIn("/usr/local/lib/ghidra-builder", text)
        self.assertIn("GHIDRA_MCP_STUBS", text)
        self.assertIn("GHIDRA_MCP_TOOLCHAINS=/opt/ghidra-builder/toolchains", text)
        self.assertIn("/opt/ghidra-builder/toolchains/gcc10-arm", text)
        self.assertIn("/opt/ghidra-builder/toolchains/gcc12-arm", text)
        self.assertIn("/opt/ghidra-builder/toolchains/gcc13-arm", text)
        self.assertIn("/opt/ghidra-builder/toolchains/gcc13-x86_64", text)
        self.assertIn("gcc-13", text)
        self.assertIn("g++-13", text)
        self.assertNotIn("libc6-dev-i386", text)
        self.assertNotRegex(text, r"apt-get install[^\n]*gcc-multilib")
        self.assertIn("dpkg -l gcc-multilib", text)
        self.assertIn("debian:trixie-slim", text)
        self.assertIn("COPY --from=gcc10 --chown=1000:1000", text)
        self.assertIn("COPY --from=gcc12 --chown=1000:1000", text)
        self.assertIn("COPY --from=gcc13 --chown=1000:1000", text)
        self.assertIn("developer.arm.com", text)
        self.assertIn('org.ghidra-mcp.toolchain.gcc10-arm="10.3-2021.10"', text)
        self.assertIn('org.ghidra-mcp.toolchain.gcc12-arm="12.2.Rel1"', text)
        self.assertIn('org.ghidra-mcp.toolchain.gcc13-arm="13.2.Rel1"', text)
        self.assertIn('org.ghidra-mcp.toolchain.gcc13-x86_64="distro"', text)
        self.assertNotIn("chown -R builder:builder /src /data /home/builder /opt/ghidra-builder", text)
        self.assertNotIn("\nENV CC=", "\n" + text)
        self.assertIn('CMD ["serve"]', text)
        self.assertIn("GHIDRA_MCP_FILE_ROOT=/data", text)
        health_lines = [ln for ln in text.splitlines() if "HEALTHCHECK" in ln or "urlopen" in ln]
        self.assertTrue(any("/health" in ln for ln in health_lines))
        self.assertFalse(
            any("Bearer" in ln for ln in health_lines),
            "HEALTHCHECK must not put the auth token on the command line",
        )

    def test_every_apt_update_clears_lists_in_same_run(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        current: list[str] = []
        in_run = False
        runs: list[str] = []
        for ln in text.splitlines():
            stripped = ln.strip()
            if stripped.startswith("RUN ") or stripped.startswith("RUN\t"):
                if in_run and current:
                    runs.append("\n".join(current))
                current = [stripped]
                in_run = stripped.endswith("\\")
                if not in_run:
                    runs.append("\n".join(current))
                    current = []
                continue
            if in_run:
                current.append(stripped)
                if not stripped.endswith("\\"):
                    runs.append("\n".join(current))
                    current = []
                    in_run = False
        self.assertTrue(runs)
        apt_runs = [r for r in runs if "apt-get update" in r]
        self.assertGreaterEqual(len(apt_runs), 2)
        for r in apt_runs:
            self.assertIn("rm -rf /var/lib/apt/lists/*", r)

    def test_lock_pins_three_arm_releases(self):
        lock = REPO_ROOT / "docker" / "builder" / "toolchains.lock"
        pins = {}
        for ln in lock.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            ident, release, sha256, url = ln.split()
            pins[ident] = (release, sha256, url)
        self.assertEqual(set(pins), {"gcc10-arm", "gcc12-arm", "gcc13-arm"})
        for ident, (release, sha256, url) in pins.items():
            self.assertEqual(len(sha256), 64, ident)
            int(sha256, 16)
            self.assertTrue(url.startswith("https://developer.arm.com/"), ident)
            self.assertTrue(url.endswith(".tar.xz") or url.endswith(".tar.bz2"), ident)
        df = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(f'org.ghidra-mcp.toolchain.gcc10-arm="{pins["gcc10-arm"][0]}"', df)
        self.assertIn(f'org.ghidra-mcp.toolchain.gcc12-arm="{pins["gcc12-arm"][0]}"', df)
        self.assertIn(f'org.ghidra-mcp.toolchain.gcc13-arm="{pins["gcc13-arm"][0]}"', df)

    def test_lock_and_stub_cmakelists_are_tracked(self):
        """*.lock and *.txt in .gitignore silently dropped these from the PR.

        CI then ran against a tree that had neither pin file nor pico-sdk stub.
        """
        must_exist = (
            "docker/builder/toolchains.lock",
            "docker/builder/source_read.py",
            "docker/references.userland.yaml",
            "docker/stubs/pico-sdk/CMakeLists.txt",
            "docker/stubs/musl/stub.json",
            "docker/stubs/glibc/stub.json",
            "docker/stubs/openssl/stub.json",
            "docker/stubs/libsodium/stub.json",
            "docker/stubs/sqlite/stub.json",
        )
        # These were dropped from a PR by a blanket gitignore. Keep asserting
        # they are tracked so a later ignore cannot hide them again.
        must_be_tracked = (
            "docker/builder/toolchains.lock",
            "docker/stubs/pico-sdk/CMakeLists.txt",
        )
        for rel in must_exist:
            ignored = subprocess.run(
                ["git", "check-ignore", "-q", rel],
                cwd=REPO_ROOT,
            )
            self.assertNotEqual(ignored.returncode, 0, f"{rel} is gitignored")
            self.assertTrue((REPO_ROOT / rel).is_file(), f"{rel} is missing")
        for rel in must_be_tracked:
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", rel],
                cwd=REPO_ROOT,
                capture_output=True,
            )
            self.assertEqual(tracked.returncode, 0, f"{rel} is not in git")

    def test_fetch_script_verifies_sha_and_drops_archive(self):
        text = (REPO_ROOT / "docker" / "builder" / "fetch_toolchains.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("sha256sum -c", text)
        self.assertIn("--strip-components=1", text)
        self.assertIn("keep_archive", text)
        self.assertIn("rm -rf \"$cache_dir\"", text)
        self.assertNotIn("v8.1-m.main", text)
        self.assertNotIn("prune_unused_abis", text)

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
                "littlefs-v2.9.3-gcc10-arm-Os.o",
                "littlefs-v2.9.3-gcc10-arm-O2.o",
                "littlefs-v2.9.3-gcc10-arm-O3.o",
                "littlefs-v2.9.3-gcc12-arm-Os.o",
                "littlefs-v2.9.3-gcc12-arm-O2.o",
                "littlefs-v2.9.3-gcc12-arm-O3.o",
                "littlefs-v2.9.3-gcc13-arm-Os.o",
                "littlefs-v2.9.3-gcc13-arm-O2.o",
                "littlefs-v2.9.3-gcc13-arm-O3.o",
            ],
        )

    def test_manifest_includes_pico_sdk_framework_matrix(self):
        doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["references"]), 4)
        self.assertEqual(doc["database"], "postgresql://ghidra-bsim:5432/bsim")
        self.assertEqual(doc["config_template"], "medium_nosize")
        pico = next(entry for entry in doc["references"] if entry["name"] == "pico-sdk")
        self.assertEqual(pico["name"], "pico-sdk")
        self.assertEqual(pico["mode"], "framework")
        self.assertEqual(pico["framework"], "pico-sdk")
        self.assertEqual(pico["ref"], "2.1.0")
        self.assertNotIn(pico["ref"], ("main", "master", "HEAD"))
        self.assertIn("hardware_i2c", pico["libraries"])
        matrix = pico["matrix"]
        n = len(matrix["toolchain"]) * len(matrix["opt"]) * len(matrix["board"])
        self.assertEqual(n, 12)

    def test_userland_manifest_is_separate_and_expands(self):
        path = REPO_ROOT / "docker" / "references.userland.yaml"
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["database"], "postgresql://ghidra-bsim:5432/bsim")
        self.assertEqual(doc["config_template"], "medium_nosize")
        count = 0
        names = []
        for entry in doc["references"]:
            names.append(entry["name"])
            matrix = entry["matrix"]
            n = 1
            for axis in matrix.values():
                n *= len(axis)
            count += n
            self.assertEqual(matrix["toolchain"], ["gcc13-x86_64"])
            self.assertEqual(matrix["opt"], ["-O2", "-Os", "-O0"])
        self.assertEqual(count, 24)
        self.assertEqual(
            names,
            ["musl", "musl", "glibc", "glibc", "zlib", "openssl", "libsodium", "sqlite"],
        )
        embedded = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(len(embedded["references"]), 4)
        self.assertEqual(doc["database"], embedded["database"])

    def test_manifest_includes_frotz_sources_prepare(self):
        doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
        frotz = next(entry for entry in doc["references"] if entry["name"] == "frotz")
        self.assertNotIn("mode", frotz)
        self.assertNotIn("framework", frotz)
        self.assertEqual(frotz["ref"], 2.54 if isinstance(frotz["ref"], float) else "2.54")
        self.assertEqual(frotz["prepare"], "make src/common/defs.h src/common/hash.h")
        self.assertEqual(frotz["extra_flags"], ["-std=gnu11"])
        self.assertIn("src/common/process.c", frotz["sources"])
        self.assertIn("src/common/object.c", frotz["sources"])
        self.assertEqual(frotz["matrix"]["toolchain"], ["gcc13-arm"])
        self.assertEqual(frotz["matrix"]["opt"], ["-O2", "-Os"])
        for src in frotz["sources"]:
            self.assertTrue(src.startswith("src/common/"), src)
            self.assertFalse(src.startswith("src/curses/"), src)
            self.assertFalse(src.startswith("src/sdl/"), src)


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
        self.assertTrue(any(flag.startswith("-fdebug-prefix-map=") for flag in gcc))

    def test_successful_build_writes_object_with_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads" / "littlefs-v2.9.3-gcc13-arm-Os.o"

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
                        return subprocess.CompletedProcess(
                            argv, 0, "9c7e232086f865cff0bb96fe753deb66431d91fd\n", ""
                        )
                    if "log" in argv:
                        return subprocess.CompletedProcess(argv, 0, "1\n", "")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009\n",
                        "",
                    )
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
                    "name": "littlefs",
                    "repo": "https://github.com/littlefs-project/littlefs.git",
                    "ref": "v2.9.3",
                    "sources": ["lfs.c"],
                    "cflags": ["-fno-common"],
                    "opt": "-Os",
                    "defines": ["LFS_NO_MALLOC", "LFS_NO_ASSERT"],
                    "extra_flags": [],
                    "toolchain": "gcc13-arm",
                    "output": str(dest),
                    "strip_debug": True,
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["mode"], "sources")
            self.assertEqual(len(result["artifacts"]), 1)
            art = result["artifacts"][0]
            self.assertEqual(art["function_count"], 1)
            self.assertEqual(art["defined_functions"], ["lfs_bd_read"])
            self.assertEqual(art["library"], "")
            self.assertEqual(art["path"], str(dest))
            self.assertEqual(result["failed"], [])
            self.assertEqual(
                result["commit_sha"], "9c7e232086f865cff0bb96fe753deb66431d91fd"
            )
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), b"ELF")
            self.assertTrue(os.access(dest, os.R_OK))
            side = dest.with_name(dest.name + ".json")
            self.assertTrue(side.is_file(), side)
            meta = json.loads(side.read_text())
            self.assertEqual(meta["name"], "littlefs")
            self.assertEqual(meta["artifact"], dest.name)
            self.assertEqual(meta["sha256"], hashlib.sha256(b"ELF").hexdigest())
            self.assertEqual(meta["bytes"], 3)
            self.assertEqual(meta["function_count"], 1)
            self.assertEqual(meta["ref"], "v2.9.3")
            self.assertEqual(
                meta["commit"], "9c7e232086f865cff0bb96fe753deb66431d91fd"
            )
            self.assertEqual(meta["toolchain"], "gcc13-arm")
            self.assertEqual(
                meta["compiler_version"],
                "arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009",
            )
            self.assertEqual(meta["mode"], "sources")
            self.assertEqual(meta["sources"], ["lfs.c"])
            self.assertEqual(meta["opt"], "-Os")
            self.assertEqual(meta["defines"], ["LFS_NO_MALLOC", "LFS_NO_ASSERT"])
            self.assertEqual(meta["extra_flags"], [])
            self.assertEqual(meta["prepare"], "")
            self.assertTrue(meta["built_at"].endswith("Z"))
            self.assertEqual(meta["debug_path_prefix"], "/ref/littlefs")


def _git_ok(argv):
    if "clone" in argv:
        Path(argv[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(argv, 0, "", "")
    if "show-ref" in argv and "refs/tags/" in argv[-1]:
        return subprocess.CompletedProcess(argv, 0, "", "")
    if "show-ref" in argv:
        return subprocess.CompletedProcess(argv, 1, "", "")
    if "rev-parse" in argv:
        return subprocess.CompletedProcess(argv, 0, "abc123def456\n", "")
    if "log" in argv:
        return subprocess.CompletedProcess(argv, 0, "1\n", "")
    return subprocess.CompletedProcess(argv, 0, "", "")


class TestPrepare(unittest.TestCase):
    def test_prepare_runs_before_compile_and_records_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads" / "frotz-2.54-gcc13-arm-O2.o"
            order = []

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "src" / "common").mkdir(parents=True)
                (dest_dir / "src" / "common" / "process.c").write_text(
                    '#include "defs.h"\nint interpret(void) { return DEF; }\n'
                )

            def run(argv, **kwargs):
                if argv[0] == "git":
                    return _git_ok(argv)
                if argv[:2] == ["/bin/sh", "-c"]:
                    order.append("prepare")
                    snap = Path(kwargs["cwd"])
                    (snap / "src" / "common" / "defs.h").write_text("#define DEF 1\n")
                    return subprocess.CompletedProcess(
                        argv, 0, "generated defs.h\n", ""
                    )
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "-c" in argv:
                    order.append("compile")
                    self.assertTrue(
                        (Path(kwargs["cwd"]) / "src" / "common" / "defs.h").is_file()
                    )
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"ELF")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    return subprocess.CompletedProcess(
                        argv, 0, "00000000 T interpret\n", ""
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = gbr.handle_request(
                {
                    "name": "frotz",
                    "repo": "https://gitlab.com/DavidGriffith/frotz.git",
                    "ref": "2.54",
                    "sources": ["src/common/process.c"],
                    "prepare": "make src/common/defs.h",
                    "prepare_timeout": 300,
                    "cflags": ["-fno-common"],
                    "opt": "-O2",
                    "toolchain": "gcc13-arm",
                    "output": str(dest),
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(order, ["prepare", "compile"])
            self.assertEqual(result["prepare"], "make src/common/defs.h")
            self.assertEqual(result["command"][0], ["/bin/sh", "-c", "make src/common/defs.h"])
            self.assertIn("interpret", result["artifacts"][0]["defined_functions"])
            meta = json.loads((dest.with_name(dest.name + ".json")).read_text())
            self.assertEqual(meta["prepare"], "make src/common/defs.h")
            self.assertNotIn("prepare", meta["sha256"])

    def test_prepare_failure_returns_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as td:
            compiled = {"n": 0}

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "src" / "common").mkdir(parents=True)
                (dest_dir / "src" / "common" / "process.c").write_text("int x;\n")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    return _git_ok(argv)
                if argv[:2] == ["/bin/sh", "-c"]:
                    return subprocess.CompletedProcess(
                        argv,
                        1,
                        "generating defs.h\n",
                        "make: *** No rule to make target 'src/common/defs.h'\n",
                    )
                if argv[0] == "arm-none-eabi-gcc":
                    compiled["n"] += 1
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.handle_request(
                    {
                        "repo": "https://gitlab.com/DavidGriffith/frotz.git",
                        "ref": "2.54",
                        "sources": ["src/common/process.c"],
                        "prepare": "make src/common/defs.h",
                        "output": str(Path(td) / "uploads" / "out.o"),
                    },
                    run=run,
                    src_cache=Path(td) / "src",
                    extract=extract,
                )
            self.assertEqual(ctx.exception.status, "prepare_failed")
            self.assertIn("No rule to make target", str(ctx.exception))
            self.assertIn("generating defs.h", ctx.exception.extra.get("stdout", ""))
            self.assertIn("No rule to make target", ctx.exception.extra.get("stderr", ""))
            self.assertEqual(compiled["n"], 0)

    def test_dry_run_shows_prepare_and_compiles_nothing(self):
        def boom(*_a, **_k):
            self.fail("dry_run must not clone or compile")

        result = gbr.handle_request(
            {
                "name": "frotz",
                "repo": "https://gitlab.com/DavidGriffith/frotz.git",
                "ref": "2.54",
                "sources": ["src/common/process.c"],
                "prepare": "make src/common/defs.h src/common/hash.h",
                "cflags": ["-fno-common"],
                "toolchain": "gcc13-arm",
                "dry_run": True,
            },
            run=boom,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["status"], "would_execute")
        self.assertEqual(result["mode"], "sources")
        self.assertEqual(result["prepare"], "make src/common/defs.h src/common/hash.h")
        self.assertEqual(
            result["command"][0],
            ["/bin/sh", "-c", "make src/common/defs.h src/common/hash.h"],
        )
        self.assertEqual(result["command"][1][0], "arm-none-eabi-gcc")
        self.assertEqual(len(result["artifacts"]), 1)
        self.assertEqual(result["artifacts"][0]["library"], "")
        self.assertEqual(result["failed"], [])

    def test_failed_unit_is_named_and_build_continues(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads" / "out.o"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "good.c").write_text("int interpret(void) { return 1; }\n")
                (dest_dir / "bad.c").write_text("#include <unistd.h>\nint fail(void);\n")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    return _git_ok(argv)
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "-c" in argv:
                    src = argv[-3]
                    if src == "bad.c":
                        return subprocess.CompletedProcess(
                            argv, 1, "", "bad.c:1:10: fatal error: unistd.h: No such file\n"
                        )
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"ELF")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    return subprocess.CompletedProcess(
                        argv, 0, "00000000 T interpret\n", ""
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = gbr.handle_request(
                {
                    "name": "frotz",
                    "repo": "https://gitlab.com/DavidGriffith/frotz.git",
                    "ref": "2.54",
                    "sources": ["good.c", "bad.c"],
                    "output": str(dest),
                    "toolchain": "gcc13-arm",
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["artifacts"][0]["defined_functions"], ["interpret"])
            self.assertEqual(len(result["failed"]), 1)
            self.assertEqual(result["failed"][0]["source"], "bad.c")
            self.assertIn("unistd.h", result["failed"][0]["stderr"])

    def test_prepare_timeout_rejects_bool_and_fractional(self):
        with self.assertRaises(gbr.BuildError) as ctx:
            gbr.require_prepare_timeout({"prepare_timeout": True})
        self.assertEqual(ctx.exception.status, "invalid_prepare_timeout")
        with self.assertRaises(gbr.BuildError) as ctx:
            gbr.require_prepare_timeout({"prepare_timeout": 1.9})
        self.assertEqual(ctx.exception.status, "invalid_prepare_timeout")
        self.assertEqual(gbr.require_prepare_timeout({"prepare_timeout": 300}), 300)
        self.assertEqual(gbr.require_prepare_timeout({"prepare_timeout": 300.0}), 300)
        self.assertEqual(gbr.require_prepare_timeout({"prepare_timeout": "120"}), 120)

    @unittest.skipUnless(os.name == "posix", "process-group kill is POSIX")
    def test_prepare_timeout_kills_descendant_processes(self):
        with tempfile.TemporaryDirectory() as td:
            pid_file = Path(td) / "child.pid"
            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.run_prepare(
                    f"sleep 60 & echo $! > {pid_file}; wait",
                    1,
                    Path(td),
                    gbr._default_run,
                    os.environ,
                )
            self.assertEqual(ctx.exception.status, "prepare_failed")
            self.assertIn("timed out", str(ctx.exception))
            self.assertTrue(pid_file.is_file(), "descendant must start before timeout")
            child_pid = int(pid_file.read_text(encoding="utf-8").strip())
            deadline = time.time() + 2
            alive = True
            while time.time() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    alive = False
                    break
                time.sleep(0.05)
            self.assertFalse(alive, f"descendant {child_pid} survived prepare timeout")

    @unittest.skipUnless(os.name == "posix", "process-group kill is POSIX")
    def test_prepare_timeout_kills_orphaned_background_child(self):
        """Shell exits; sleep keeps the pipes. Cleanup must still killpg."""
        with tempfile.TemporaryDirectory() as td:
            pid_file = Path(td) / "child.pid"
            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.run_prepare(
                    f"sleep 60 & echo $! > {pid_file}",
                    1,
                    Path(td),
                    gbr._default_run,
                    os.environ,
                )
            self.assertEqual(ctx.exception.status, "prepare_failed")
            self.assertIn("timed out", str(ctx.exception))
            self.assertTrue(pid_file.is_file(), "descendant must start before timeout")
            child_pid = int(pid_file.read_text(encoding="utf-8").strip())
            deadline = time.time() + 2
            alive = True
            while time.time() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    alive = False
                    break
                time.sleep(0.05)
            self.assertFalse(alive, f"orphaned child {child_pid} survived prepare timeout")

    def test_prepare_refused_in_framework_mode(self):
        with self.assertRaises(gbr.BuildError) as ctx:
            gbr.handle_request(
                {
                    "mode": "framework",
                    "repo": "https://github.com/raspberrypi/pico-sdk.git",
                    "ref": "2.1.0",
                    "framework": "pico-sdk",
                    "libraries": ["hardware_i2c"],
                    "prepare": "make headers",
                    "output_dir": "/tmp/uploads",
                },
                run=lambda *a, **k: self.fail("must not run"),
            )
        self.assertEqual(ctx.exception.status, "invalid_prepare")

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("nm"), "host gcc/nm not installed")
    def test_host_prepare_generates_header_then_compiles(self):
        with tempfile.TemporaryDirectory() as td:
            snap = Path(td) / "src"
            snap.mkdir()
            (snap / "core.c").write_text(
                '#include "gen.h"\nint interpret(void) { return TOKEN; }\n'
            )
            env = os.environ.copy()
            env["LC_ALL"] = "C"
            env["TZ"] = "UTC"
            env["SOURCE_DATE_EPOCH"] = "0"
            gbr.run_prepare(
                "printf '#define TOKEN 1\\n' > gen.h",
                30,
                snap,
                gbr._default_run,
                env,
            )
            self.assertTrue((snap / "gen.h").is_file())
            out = Path(td) / "out.o"
            commands, failed = gbr.compile_objects(
                snapshot=snap,
                sources=["core.c"],
                cflags=["-fno-common", "-fno-ident"],
                cc="gcc",
                ld="ld",
                workdir=Path(td) / "obj",
                output=out,
                run=gbr._default_run,
                env=env,
            )
            self.assertEqual(failed, [])
            self.assertTrue(commands)
            names = gbr.defined_functions("nm", out, gbr._default_run, env)
            self.assertIn("interpret", names)

    def test_prepare_not_read_from_repository_content(self):
        """A prepare.sh in the tree is ignored unless the request names it."""
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads" / "out.o"
            ran_repo_script = {"n": 0}

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "prepare.sh").write_text("#!/bin/sh\necho from-repo\n")
                (dest_dir / "lfs.c").write_text("int lfs_bd_read(void) { return 0; }\n")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    return _git_ok(argv)
                if argv[:2] == ["/bin/sh", "-c"] and "prepare.sh" in argv[2]:
                    ran_repo_script["n"] += 1
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "-c" in argv:
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"ELF")
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
                    "output": str(dest),
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(ran_repo_script["n"], 0)
            self.assertEqual(result["prepare"], "")


class TestHttpControlPlane(unittest.TestCase):
    def test_run_is_not_bound_as_instance_method(self):
        self.assertIsInstance(gbr.BuilderHandler.__dict__["run"], staticmethod)

    def test_health_is_open_and_post_returns_job_id(self):
        def fake_run(argv, **kwargs):
            if "--version" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, "arm-none-eabi-gcc 13.2.1\n", ""
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

        gbr.BuilderHandler.run = staticmethod(fake_run)
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
            self.assertIn("identities", body)
            self.assertIn("pico-sdk", body.get("stubs", []))
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/build",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                self.assertEqual(resp.status, 202)
                posted = json.loads(resp.read().decode())
            self.assertTrue(posted["ok"])
            job_id = posted["job_id"]
            self.assertTrue(job_id)
            deadline = threading.Event()
            snap = None
            for _ in range(50):
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/build/{job_id}", timeout=2
                ) as resp:
                    snap = json.loads(resp.read().decode())
                if snap.get("status") in {"done", "failed"}:
                    break
                deadline.wait(0.05)
            self.assertIsNotNone(snap)
            self.assertEqual(snap["job_id"], job_id)
            self.assertEqual(snap["status"], "failed")
            self.assertIn("repo", str(snap.get("error") or snap.get("result")))
        finally:
            httpd.shutdown()
            httpd.server_close()
            gbr.BuilderHandler.run = staticmethod(gbr._default_run)

    def test_post_returns_before_compile_and_get_retrieves_result(self):
        started = threading.Event()
        release = threading.Event()

        def slow_handle(req, **kwargs):
            started.set()
            release.wait(timeout=5)
            return {
                "ok": True,
                "path": "/data/uploads/out.o",
                "function_count": 3,
                "sha256": "abc",
            }

        gbr.QUEUE.start(
            handle=slow_handle,
            error_payload=gbr.error_payload,
            run=gbr._default_run,
            src_cache=Path("/tmp"),
        )
        orig_handle = gbr.handle_request
        gbr.handle_request = slow_handle
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), gbr.BuilderHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            begin = time.monotonic()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/build",
                data=json.dumps({"repo": "https://example.invalid/lfs.git"}).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                posted = json.loads(resp.read().decode())
            self.assertLess(time.monotonic() - begin, 1.0)
            job_id = posted["job_id"]
            self.assertTrue(started.wait(timeout=2))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/build/{job_id}", timeout=2
            ) as resp:
                mid = json.loads(resp.read().decode())
            self.assertIn(mid["status"], {"queued", "running"})
            release.set()
            snap = None
            for _ in range(50):
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/build/{job_id}", timeout=2
                ) as resp:
                    snap = json.loads(resp.read().decode())
                if snap.get("status") == "done":
                    break
                time.sleep(0.05)
            self.assertEqual(snap["status"], "done")
            self.assertEqual(snap["result"]["function_count"], 3)
        finally:
            release.set()
            httpd.shutdown()
            httpd.server_close()
            gbr.handle_request = orig_handle
            gbr.QUEUE.start(
                handle=gbr.handle_request,
                error_payload=gbr.error_payload,
                run=gbr._default_run,
                src_cache=gbr.DEFAULT_SRC_CACHE,
            )


class TestPackedToolchains(unittest.TestCase):
    def test_unknown_identity_lists_installed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for ident in ("gcc10-arm", "gcc13-arm"):
                bindir = root / ident / "bin"
                bindir.mkdir(parents=True)
                cc = bindir / "arm-none-eabi-gcc"
                cc.write_text("#!/bin/sh\n")
                cc.chmod(0o755)
            os.environ["GHIDRA_MCP_TOOLCHAINS"] = str(root)
            try:
                installed = gbr.packed_toolchains.list_installed()
                self.assertEqual(set(installed), {"gcc10-arm", "gcc13-arm"})
                tools = gbr.packed_toolchains.resolve_tools(
                    "gcc10-arm",
                    fallback_cc="arm-none-eabi-gcc",
                    fallback_ld="arm-none-eabi-ld",
                    fallback_strip="arm-none-eabi-strip",
                    fallback_nm="arm-none-eabi-nm",
                )
                self.assertTrue(tools["cc"].endswith("gcc10-arm/bin/arm-none-eabi-gcc"))
                with self.assertRaises(KeyError) as ctx:
                    gbr.packed_toolchains.resolve_tools(
                        "gcc99-arm",
                        fallback_cc="arm-none-eabi-gcc",
                        fallback_ld="arm-none-eabi-ld",
                        fallback_strip="arm-none-eabi-strip",
                        fallback_nm="arm-none-eabi-nm",
                    )
                self.assertEqual(ctx.exception.args[0], "gcc99-arm")
                self.assertIn("gcc10-arm", ctx.exception.args[1])
                self.assertIn("gcc13-arm", ctx.exception.args[1])
            finally:
                os.environ.pop("GHIDRA_MCP_TOOLCHAINS", None)

    def test_native_x86_64_identity_uses_identity_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            native = root / "gcc13-x86_64"
            native.mkdir()
            cc = root / "gcc-13"
            cc.write_text("#!/bin/sh\n")
            cc.chmod(0o755)
            (native / "identity.json").write_text(
                json.dumps(
                    {
                        "id": "gcc13-x86_64",
                        "kind": "native",
                        "release": "gcc (Debian) 13.3.0",
                        "cc": str(cc),
                        "cxx": str(cc),
                        "ld": "ld",
                        "strip": "strip",
                        "nm": "nm",
                        "objdump": "objdump",
                    }
                )
            )
            os.environ["GHIDRA_MCP_TOOLCHAINS"] = str(root)
            try:
                installed = gbr.packed_toolchains.list_installed()
                self.assertEqual(set(installed), {"gcc13-x86_64"})
                tools = gbr.packed_toolchains.resolve_tools(
                    "gcc13-x86_64",
                    fallback_cc="gcc",
                    fallback_ld="ld",
                    fallback_strip="strip",
                    fallback_nm="nm",
                )
                self.assertEqual(tools["cc"], str(cc))
                self.assertEqual(tools["objdump"], "objdump")
            finally:
                os.environ.pop("GHIDRA_MCP_TOOLCHAINS", None)


def _arm_elf32(*, e_type: int = 1, machine: int = 40) -> bytes:
    """Minimal ELF32 little-endian header. e_type 1 = ET_REL, 2 = ET_EXEC."""
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
    rest = struct.pack("<HHI", e_type, machine, 1) + bytes(32)
    return ident + rest


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class TestFrameworkToolchainVars(unittest.TestCase):
    """pico-sdk resolves its own compiler; CMAKE_C_COMPILER alone is ignored.

    pico_find_compiler searches PATH, and the packed prefixes are deliberately
    off PATH, so configure died with "Compiler 'arm-none-eabi-gcc' not found".
    The fix is stub-declared cache variables filled from the resolved identity,
    which is also what Zephyr (ZEPHYR_TOOLCHAIN_VARIANT / CROSS_COMPILE) and
    ESP-IDF (IDF_TOOLCHAIN) will need.
    """

    PACKED_CC = "/opt/ghidra-builder/toolchains/gcc13-arm/bin/arm-none-eabi-gcc"

    def test_tokens_come_from_the_resolved_compiler_path(self):
        tokens = gbr.fw.toolchain_tokens(
            self.PACKED_CC,
            "/opt/ghidra-builder/toolchains/gcc13-arm/bin/arm-none-eabi-g++",
            "gcc13-arm",
        )
        self.assertEqual(
            tokens["toolchain_bin"], "/opt/ghidra-builder/toolchains/gcc13-arm/bin"
        )
        self.assertEqual(tokens["toolchain_triple"], "arm-none-eabi")
        self.assertEqual(tokens["toolchain"], "gcc13-arm")
        self.assertEqual(
            tokens["toolchain_prefix"],
            "/opt/ghidra-builder/toolchains/gcc13-arm/bin/arm-none-eabi-",
        )

    def test_bare_compiler_name_yields_no_bin_dir(self):
        """Unit tests and older images fall back to the requested binary name."""
        tokens = gbr.fw.toolchain_tokens("arm-none-eabi-gcc", "", "gcc13-arm")
        self.assertEqual(tokens["toolchain_bin"], "")
        self.assertEqual(tokens["toolchain_triple"], "arm-none-eabi")

    def test_pico_stub_declares_its_own_toolchain_variables(self):
        meta = gbr.fw.load_stub_meta(gbr.fw.stub_dir("pico-sdk"))
        declared = meta.get("toolchain_cache_vars")
        self.assertIsInstance(declared, dict)
        self.assertEqual(declared.get("PICO_TOOLCHAIN_PATH"), "{toolchain_bin}")
        self.assertEqual(declared.get("PICO_GCC_TRIPLE"), "{toolchain_triple}")

    def test_cache_argv_resolves_the_declared_variables(self):
        meta = gbr.fw.load_stub_meta(gbr.fw.stub_dir("pico-sdk"))
        tokens = gbr.fw.toolchain_tokens(self.PACKED_CC, "", "gcc13-arm")
        argv = gbr.fw.toolchain_cache_argv(meta, tokens)
        self.assertIn(
            "-DPICO_TOOLCHAIN_PATH=/opt/ghidra-builder/toolchains/gcc13-arm/bin", argv
        )
        self.assertIn("-DPICO_GCC_TRIPLE=arm-none-eabi", argv)

    def test_unresolved_template_is_dropped_not_emitted_empty(self):
        """An empty PICO_TOOLCHAIN_PATH searches PATH again and fails later."""
        tokens = gbr.fw.toolchain_tokens("arm-none-eabi-gcc", "", "gcc13-arm")
        argv = gbr.fw.toolchain_cache_argv(
            {"toolchain_cache_vars": {"PICO_TOOLCHAIN_PATH": "{toolchain_bin}"}},
            tokens,
        )
        self.assertEqual(argv, [])
        unknown = gbr.fw.toolchain_cache_argv(
            {"toolchain_cache_vars": {"X": "{no_such_token}"}}, tokens
        )
        self.assertEqual(unknown, [])

    def test_configure_argv_carries_cache_vars_and_operator_config_wins(self):
        argv = gbr.fw.cmake_configure_argv(
            stub=Path("/stubs/pico-sdk"),
            build_dir=Path("/build"),
            sdk_path="/sdk",
            board="pico",
            libraries=["pico_stdlib"],
            opt="-O2",
            config={"PICO_TOOLCHAIN_PATH": "/override"},
            extra_flags=[],
            cc=self.PACKED_CC,
            cxx="",
            cache_vars=["-DPICO_TOOLCHAIN_PATH=/opt/x/bin"],
            generator="Ninja",
        )
        self.assertIn("-DPICO_TOOLCHAIN_PATH=/opt/x/bin", argv)
        # config is appended after cache_vars, so a later -D wins in CMake.
        self.assertGreater(
            argv.index("-DPICO_TOOLCHAIN_PATH=/override"),
            argv.index("-DPICO_TOOLCHAIN_PATH=/opt/x/bin"),
        )

    def test_framework_build_passes_stub_toolchain_vars_to_cmake(self):
        """End to end through the request handler, not just the argv helper."""
        seen: list[list[str]] = []

        def run(argv, **kwargs):
            seen.append([str(a) for a in argv])
            return subprocess.CompletedProcess(argv, 0, "", "")

        body = gbr.handle_framework_request(
            {
                "mode": "framework",
                "name": "pico-sdk",
                "repo": "https://example.invalid/pico-sdk.git",
                "ref": "2.1.0",
                "framework": "pico-sdk",
                "libraries": ["pico_stdlib"],
                "board": "pico",
                "opt": "-O2",
                "toolchain": "gcc13-arm",
                "cc": self.PACKED_CC,
                "dry_run": True,
            },
            src_cache=Path("/tmp"),
            run=run,
            extract=None,
        )
        configure = body["command"][0]
        self.assertIn("-DPICO_GCC_TRIPLE=arm-none-eabi", configure)
        path_flag = [a for a in configure if a.startswith("-DPICO_TOOLCHAIN_PATH=")]
        self.assertEqual(
            path_flag, ["-DPICO_TOOLCHAIN_PATH=/opt/ghidra-builder/toolchains/gcc13-arm/bin"]
        )


class TestCmakeGenerator(unittest.TestCase):
    """cmake -G Ninja without ninja installed fails configure outright."""

    def test_ninja_used_when_present(self):
        argv = gbr.fw.cmake_configure_argv(
            stub=Path("/stubs/pico-sdk"),
            build_dir=Path("/build"),
            sdk_path="/sdk",
            board="",
            libraries=["pico_stdlib"],
            opt="-O2",
            config={},
            extra_flags=[],
            cc="cc",
            cxx="c++",
            generator="Ninja",
        )
        self.assertEqual(argv[argv.index("-G") + 1], "Ninja")

    def test_default_generator_when_ninja_is_missing(self):
        self.assertEqual(gbr.fw.cmake_generator(lambda name: None), "")
        self.assertEqual(gbr.fw.cmake_generator(lambda name: "/usr/bin/ninja"), "Ninja")
        argv = gbr.fw.cmake_configure_argv(
            stub=Path("/stubs/pico-sdk"),
            build_dir=Path("/build"),
            sdk_path="/sdk",
            board="",
            libraries=["pico_stdlib"],
            opt="-O2",
            config={},
            extra_flags=[],
            cc="cc",
            cxx="c++",
            generator="",
        )
        self.assertNotIn("-G", argv)

    def test_image_asserts_ninja_and_health_reports_generators(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("ninja-build", text)
        self.assertIn("test -x /usr/bin/ninja", text)
        body = gbr.health_payload(run=lambda argv, **kw: subprocess.CompletedProcess(
            argv, 0, "gcc (test) 13.2.0\n", ""))
        self.assertIn("generators", body)
        self.assertIn("cmake_generator", body)


class TestFrameworkHarvest(unittest.TestCase):
    def test_list_stubs_includes_pico_sdk(self):
        names = gbr.fw.list_stubs()
        self.assertIn("pico-sdk", names)
        stub = gbr.fw.stub_dir("pico-sdk")
        self.assertTrue((stub / "CMakeLists.txt").is_file())
        self.assertTrue((stub / "main.c").is_file())
        main = (stub / "main.c").read_text(encoding="utf-8")
        self.assertNotIn("i2c", main.lower())

    def test_list_stubs_includes_make_frameworks(self):
        names = gbr.fw.list_stubs()
        for stub in ("musl", "glibc", "openssl", "libsodium", "sqlite"):
            self.assertIn(stub, names)
            meta = gbr.fw.load_stub_meta(gbr.fw.stub_dir(stub))
            self.assertEqual(meta.get("generator"), "make")

    def test_harvest_skips_elf_and_keeps_unreferenced_library(self):
        with tempfile.TemporaryDirectory() as td:
            build = Path(td)
            _write(
                build / "CMakeFiles/ghidra_stub.dir/src/rp2_common/hardware_i2c/i2c.c.o",
                _arm_elf32(),
            )
            _write(
                build / "CMakeFiles/ghidra_stub.dir/src/common/pico_stdlib/stdlib.c.o",
                _arm_elf32(),
            )
            _write(build / "CMakeFiles/ghidra_stub.dir/main.c.o", _arm_elf32())
            _write(build / "ghidra_stub.elf", _arm_elf32(e_type=2))
            _write(
                build / "pioasm/CMakeFiles/pioasm.dir/main.cpp.o",
                _arm_elf32(machine=62),
            )
            _write(build / "lib/tinyusb/src/tusb.c.o", _arm_elf32())
            groups = gbr.fw.harvest_groups(build)
            self.assertIn("hardware_i2c", groups)
            self.assertIn("pico_stdlib", groups)
            self.assertIn("tinyusb", groups)
            self.assertNotIn("ghidra_stub", groups)
            self.assertFalse(any(p.name.endswith(".elf") for files in groups.values() for p in files))
            self.assertFalse(any("pioasm" in str(p) for files in groups.values() for p in files))
            self.assertFalse(any(p.name.startswith("main.c") for files in groups.values() for p in files))

    def test_unknown_framework_lists_installed(self):
        with self.assertRaises(gbr.fw.FrameworkError) as ctx:
            gbr.fw.stub_dir("no-such-sdk")
        self.assertEqual(ctx.exception.status, "unknown_framework")
        self.assertIn("pico-sdk", str(ctx.exception))

    def test_empty_libraries_refused_before_cmake(self):
        def run(argv, **kwargs):
            self.fail(f"must not run {argv}")

        with self.assertRaises(gbr.BuildError) as ctx:
            gbr.handle_request(
                {
                    "mode": "framework",
                    "repo": "https://github.com/raspberrypi/pico-sdk.git",
                    "ref": "2.1.0",
                    "framework": "pico-sdk",
                    "libraries": [],
                    "output_dir": "/tmp/uploads",
                },
                run=run,
            )
        self.assertEqual(ctx.exception.status, "empty_libraries")

    def test_dry_run_configures_nothing(self):
        def run(argv, **kwargs):
            self.fail(f"dry_run must not run {argv}")

        result = gbr.handle_request(
            {
                "mode": "framework",
                "name": "pico-sdk",
                "repo": "https://github.com/raspberrypi/pico-sdk.git",
                "ref": "2.1.0",
                "framework": "pico-sdk",
                "libraries": ["hardware_i2c", "pico_stdlib"],
                "board": "pico",
                "toolchain": "gcc13-arm",
                "opt": "-Os",
                "cc": "arm-none-eabi-gcc",
                "dry_run": True,
            },
            run=run,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["status"], "would_execute")
        self.assertEqual(result["mode"], "framework")
        self.assertEqual(result["command"][0][0], "cmake")
        names = [Path(a["path"]).name for a in result["artifacts"]]
        self.assertIn("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o", names)
        self.assertEqual(
            {a["library"] for a in result["artifacts"]},
            {"hardware_i2c", "pico_stdlib"},
        )
        self.assertEqual(result["failed"], [])
        self.assertNotIn("harvest", result)

    def test_zero_harvest_refuses_and_names_elf(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)

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
                if argv[0] in {"cmake", "arm-none-eabi-gcc"}:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.handle_request(
                    {
                        "mode": "framework",
                        "name": "pico-sdk",
                        "repo": "https://github.com/raspberrypi/pico-sdk.git",
                        "ref": "2.1.0",
                        "framework": "pico-sdk",
                        "libraries": ["hardware_i2c"],
                        "board": "pico",
                        "toolchain": "gcc13-arm",
                        "output_dir": str(dest),
                    },
                    run=run,
                    src_cache=Path(td) / "src",
                    extract=extract,
                )
            self.assertEqual(ctx.exception.status, "zero_functions")
            self.assertIn("ELF", str(ctx.exception))

    def test_framework_build_harvests_unreferenced_and_submodule(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "pico_sdk_init.cmake").write_text("# stub\n")

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
                        return subprocess.CompletedProcess(
                            argv, 0, "9c7e232086f865cff0bb96fe753deb66431d91fd\n", ""
                        )
                    if "log" in argv:
                        return subprocess.CompletedProcess(argv, 0, "1\n", "")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "cmake" and "--build" in argv:
                    build_dir = Path(argv[argv.index("--build") + 1])
                    _write(
                        build_dir / "CMakeFiles/ghidra_stub.dir/src/rp2_common/hardware_i2c/i2c.c.o",
                        _arm_elf32(),
                    )
                    _write(
                        build_dir / "CMakeFiles/ghidra_stub.dir/src/common/pico_stdlib/stdlib.c.o",
                        _arm_elf32(),
                    )
                    _write(build_dir / "lib/tinyusb/src/tusb.c.o", _arm_elf32())
                    _write(build_dir / "CMakeFiles/ghidra_stub.dir/main.c.o", _arm_elf32())
                    _write(build_dir / "ghidra_stub.elf", _arm_elf32(e_type=2))
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "cmake":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    obj = argv[-1]
                    if "i2c" in obj:
                        return subprocess.CompletedProcess(
                            argv, 0, "00000000 T hardware_i2c_init\n", ""
                        )
                    if "stdlib" in obj:
                        return subprocess.CompletedProcess(
                            argv, 0, "00000000 T sleep_ms\n", ""
                        )
                    if "tusb" in obj:
                        return subprocess.CompletedProcess(
                            argv, 0, "00000000 T tud_init\n", ""
                        )
                    return subprocess.CompletedProcess(argv, 0, "00000000 T leftover\n", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-ld":
                    Path(argv[argv.index("-o") + 1]).write_bytes(_arm_elf32())
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = gbr.handle_request(
                {
                    "mode": "framework",
                    "name": "pico-sdk",
                    "repo": "https://github.com/raspberrypi/pico-sdk.git",
                    "ref": "2.1.0",
                    "framework": "pico-sdk",
                    "libraries": ["hardware_i2c", "pico_stdlib"],
                    "board": "pico",
                    "toolchain": "gcc13-arm",
                    "opt": "-Os",
                    "cc": "arm-none-eabi-gcc",
                    "ld": "arm-none-eabi-ld",
                    "nm": "arm-none-eabi-nm",
                    "output_dir": str(dest),
                },
                run=run,
                src_cache=Path(td) / "src",
                extract=extract,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["mode"], "framework")
            self.assertEqual(result["failed"], [])
            libs = {a["library"] for a in result["artifacts"]}
            self.assertEqual({"hardware_i2c", "pico_stdlib", "tinyusb"}, libs)
            names = {Path(a["path"]).name for a in result["artifacts"]}
            self.assertIn("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o", names)
            self.assertIn("pico-sdk-tinyusb-2.1.0-gcc13-arm-Os-pico.o", names)
            for art in result["artifacts"]:
                self.assertGreater(art["function_count"], 0)
                self.assertTrue(Path(art["path"]).is_file())
            i2c = next(a for a in result["artifacts"] if a["library"] == "hardware_i2c")
            self.assertIn("hardware_i2c_init", i2c["defined_functions"])
            self.assertEqual(
                result["commit_sha"], "9c7e232086f865cff0bb96fe753deb66431d91fd"
            )
            for art in result["artifacts"]:
                path = Path(art["path"])
                side = path.with_name(path.name + ".json")
                self.assertTrue(side.is_file(), side)
                meta = json.loads(side.read_text())
                self.assertEqual(
                    meta["commit"], "9c7e232086f865cff0bb96fe753deb66431d91fd"
                )
                self.assertEqual(meta["compiler_version"], "gcc 13.2.1")
                self.assertEqual(meta["framework"], "pico-sdk")
                self.assertEqual(meta["library"], art["library"])
                self.assertEqual(meta["board"], "pico")
                self.assertIn("config", meta)
                self.assertEqual(meta["mode"], "framework")
                self.assertEqual(meta["opt"], "-Os")
                self.assertEqual(
                    meta["sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
                )
                self.assertEqual(meta["artifact"], path.name)
                self.assertEqual(meta["debug_path_prefix"], "/ref/pico-sdk")

    def test_failed_harvest_removes_written_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "uploads"

            def extract(git_dir, sha, dest_dir):
                dest_dir.mkdir(parents=True, exist_ok=True)
                (dest_dir / "pico_sdk_init.cmake").write_text("# stub\n")

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
                if argv[0] == "cmake" and "--build" in argv:
                    build_dir = Path(argv[argv.index("--build") + 1])
                    _write(
                        build_dir / "CMakeFiles/ghidra_stub.dir/src/rp2_common/hardware_i2c/i2c.c.o",
                        _arm_elf32(),
                    )
                    _write(
                        build_dir / "CMakeFiles/ghidra_stub.dir/src/common/pico_stdlib/stdlib.c.o",
                        _arm_elf32(),
                    )
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "cmake":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-nm":
                    obj = argv[-1]
                    if "i2c" in obj:
                        return subprocess.CompletedProcess(
                            argv, 0, "00000000 T hardware_i2c_init\n", ""
                        )
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "arm-none-eabi-gcc" and "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "gcc 13.2.1\n", "")
                if argv[0] == "arm-none-eabi-ld":
                    Path(argv[argv.index("-o") + 1]).write_bytes(_arm_elf32())
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with self.assertRaises(gbr.BuildError) as ctx:
                gbr.handle_request(
                    {
                        "mode": "framework",
                        "name": "pico-sdk",
                        "repo": "https://github.com/raspberrypi/pico-sdk.git",
                        "ref": "2.1.0",
                        "framework": "pico-sdk",
                        "libraries": ["hardware_i2c", "pico_stdlib"],
                        "board": "pico",
                        "toolchain": "gcc13-arm",
                        "opt": "-Os",
                        "cc": "arm-none-eabi-gcc",
                        "ld": "arm-none-eabi-ld",
                        "nm": "arm-none-eabi-nm",
                        "output_dir": str(dest),
                    },
                    run=run,
                    src_cache=Path(td) / "src",
                    extract=extract,
                )
            self.assertEqual(ctx.exception.status, "zero_functions")
            leftovers = list(dest.glob("pico-sdk-*")) if dest.is_dir() else []
            self.assertEqual(leftovers, [], leftovers)

    def test_combine_identical_inputs_same_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.o"
            src.write_bytes(_arm_elf32() + b"payload")
            dest1 = Path(td) / "out1.o"
            dest2 = Path(td) / "out2.o"

            def run(argv, **kwargs):
                self.fail("single-file combine must copy, not ld")

            gbr.fw.combine_objects([src], dest1, "arm-none-eabi-ld", run, {})
            gbr.fw.combine_objects([src], dest2, "arm-none-eabi-ld", run, {})
            self.assertEqual(
                hashlib.sha256(dest1.read_bytes()).hexdigest(),
                hashlib.sha256(dest2.read_bytes()).hexdigest(),
            )


class TestSourceRead(unittest.TestCase):
    def test_path_mode_returns_numbered_lines(self):
        import source_read as src

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "uploads" / "littlefs-v2.9.3-gcc13-arm-Os.o"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"ELF")
            (root / "uploads" / (artifact.name + ".json")).write_text(
                json.dumps(
                    {
                        "name": "littlefs",
                        "repo": "https://github.com/littlefs-project/littlefs.git",
                        "commit": "abc1234",
                        "debug_path_prefix": "/ref/littlefs",
                        "toolchain": "gcc13-arm",
                    }
                )
            )
            git_dir = root / "src" / "github.com_littlefs-project_littlefs.git"
            git_dir.mkdir(parents=True)
            file_text = "int a;\n" + "int lfs_bd_read(void) { return 0; }\n" * 3

            def run(argv, **kwargs):
                if argv[:2] == ["git", "--git-dir"] and "cat-file" in argv and argv[-2] == "-t":
                    return subprocess.CompletedProcess(argv, 0, "commit\n", "")
                if argv[:2] == ["git", "--git-dir"] and "cat-file" in argv and argv[-2] == "-e":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[:2] == ["git", "--git-dir"] and "show" in argv:
                    return subprocess.CompletedProcess(argv, 0, file_text, "")
                self.fail(argv)
                return subprocess.CompletedProcess(argv, 1, "", "")

            body = src.handle_source_request(
                {
                    "artifact": str(artifact),
                    "path": "lfs.c",
                    "start_line": 1,
                    "end_line": 2,
                },
                run=run,
                src_cache=root / "src",
                confine_artifact=lambda p: p,
            )
            self.assertTrue(body["ok"])
            self.assertEqual(body["path"], "lfs.c")
            self.assertEqual(body["commit"], "abc1234")
            self.assertEqual(len(body["lines"]), 2)
            self.assertEqual(body["lines"][0]["n"], 1)
            self.assertFalse(body["truncated"])

    def test_rejects_dotdot_and_caps_lines(self):
        import source_read as src

        with self.assertRaises(src.SourceError) as ctx:
            src.confine_repo_path("../secret")
        self.assertEqual(ctx.exception.status, "path_outside_cache")
        with self.assertRaises(src.SourceError):
            src.confine_repo_path("/etc/passwd")
        text = "\n".join(f"line {i}" for i in range(1, 2000))
        rows, truncated, start, end = src.slice_lines(text, 1, 2000)
        self.assertTrue(truncated)
        self.assertEqual(len(rows), src.HARD_MAX_LINES)
        self.assertEqual(end, src.HARD_MAX_LINES)

    def test_missing_commit_is_specific(self):
        import source_read as src

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "obj.o"
            artifact.write_bytes(b"ELF")
            artifact.with_name(artifact.name + ".json").write_text(
                json.dumps(
                    {
                        "repo": "https://example.com/repo.git",
                        "commit": "deadbeef",
                        "debug_path_prefix": "/ref/x",
                    }
                )
            )
            git_dir = root / "src" / "example.com_repo.git"
            git_dir.mkdir(parents=True)

            def run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 1, "", "not a commit")

            with self.assertRaises(src.SourceError) as ctx:
                src.handle_source_request(
                    {"artifact": str(artifact), "path": "lfs.c"},
                    run=run,
                    src_cache=root / "src",
                    confine_artifact=lambda p: p,
                )
            self.assertEqual(ctx.exception.status, "commit_not_cached")
            self.assertIn("deadbeef", str(ctx.exception))

    def test_function_span_from_nm_and_dwarf(self):
        import source_read as src

        nm = "00000000 T lfs_bd_read\n00000100 T lfs_bd_prog\n"
        dump = (
            "CU: /ref/littlefs/lfs.c:\n"
            "File name                            Line number    Starting address    View    Stmt\n"
            "lfs.c                                        40            0x0               x\n"
            "lfs.c                                        50           0x10               x\n"
            "lfs.c                                        80          0x100               x\n"
        )
        source, lo, hi = src.resolve_function_span(
            "lfs_bd_read",
            src.parse_nm_symbols(nm),
            src.parse_decodedline(dump),
            2,
        )
        self.assertIn("lfs.c", source)
        self.assertEqual(lo, 38)
        self.assertEqual(hi, 52)


if __name__ == "__main__":
    unittest.main()
