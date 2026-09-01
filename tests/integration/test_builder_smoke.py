"""One call per builder path, against a real builder, in under two minutes.

Every defect in ``build_reference`` so far was found by hand: `sources`
schema-required so framework mode was uncallable, an envelope shape mismatch,
`PICO_TOOLCHAIN_PATH` unset, ninja missing, the architecture flags dropped by
`-DCMAKE_C_FLAGS=`, and the requested `-O` level silently overridden by the
SDK's Release default. Six deploys for six defects that one run of this file
would have caught. Anything added to the builder gets a case here.

The compile-line assertions are the ones that matter most. A build that fails
is loud; a build that quietly compiles at `-O3` and writes
``pico-sdk-hardware_i2c-2.1.0-gcc13-arm-O2-pico.o`` is a corpus entry that
lies about its own provenance, and nothing downstream can tell. BSim does not
know what flags an object was built with.

Run it::

    GHIDRA_MCP_BUILDER_URL=http://127.0.0.1:18092 \\
    GHIDRA_MCP_BUILDER_DATA=/home/ben/ghidra-bsim-exp/data \\
        pytest tests/integration/test_builder_smoke.py -v

``GHIDRA_MCP_BUILDER_URL`` is the builder's control plane (compose:
``http://ghidra-builder:8092``; no host port in production, so this is
normally a locally started container). ``GHIDRA_MCP_BUILDER_DATA`` is the host
path of that container's ``/data``; without it the ELF-level checks skip and
the HTTP envelope is all that is asserted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import requests

BUILDER_URL = os.environ.get("GHIDRA_MCP_BUILDER_URL", "").rstrip("/")
BUILDER_DATA = os.environ.get("GHIDRA_MCP_BUILDER_DATA", "")
# Where the builder writes; /data is the shared volume import_file reads.
UPLOADS = "/data/uploads"
# Its own subdirectory so a smoke run never overwrites a corpus artifact.
SMOKE_DIR = f"{UPLOADS}/smoke"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        not BUILDER_URL,
        reason="set GHIDRA_MCP_BUILDER_URL to the builder control plane",
    ),
]

ARM_FLAGS = ["-mcpu=cortex-m0plus", "-mthumb"]


def host_path(container_path: str) -> Path | None:
    """Map a path inside the builder onto the host, when /data is visible."""
    if not BUILDER_DATA:
        return None
    rel = Path(container_path)
    try:
        return Path(BUILDER_DATA) / rel.relative_to("/data")
    except ValueError:
        return None


def build(request: dict, *, timeout: float = 300.0) -> dict:
    """POST /build, poll GET /build/{id}, return the result envelope."""
    posted = requests.post(f"{BUILDER_URL}/build", json=request, timeout=30)
    assert posted.status_code == 202, posted.text
    job_id = posted.json()["job_id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        got = requests.get(f"{BUILDER_URL}/build/{job_id}", timeout=30)
        assert got.status_code == 200, got.text
        body = got.json()
        if body["status"] in {"done", "failed"}:
            return body.get("result") or body
        time.sleep(1.0)
    pytest.fail(f"build job {job_id} did not finish within {timeout}s")


def assert_built(result: dict) -> list[dict]:
    assert result.get("ok"), json.dumps(result, indent=2)[:4000]
    assert result["status"] == "success", json.dumps(result, indent=2)[:4000]
    artifacts = result["artifacts"]
    assert artifacts, "success with no artifacts"
    for art in artifacts:
        assert art["function_count"] > 0, art
        sidecar = host_path(art["path"] + ".json")
        if sidecar is not None:
            assert sidecar.is_file(), f"no sidecar beside {art['path']}"
            meta = json.loads(sidecar.read_text(encoding="utf-8"))
            assert meta["sha256"] == art["sha256"]
            assert meta["commit"] == result["commit_sha"]
    return artifacts


def opt_levels(argv: list[str]) -> list[str]:
    return [tok for tok in argv if tok.startswith("-O")]


@pytest.fixture(scope="module")
def health() -> dict:
    r = requests.get(f"{BUILDER_URL}/health", timeout=15)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module", autouse=True)
def smoke_dir() -> None:
    """Artifacts land under /data/uploads/smoke, never on the corpus."""
    host = host_path(SMOKE_DIR)
    if host is not None:
        host.mkdir(parents=True, exist_ok=True)


def littlefs_request(**over) -> dict:
    req = {
        "mode": "sources",
        "name": "smoke-littlefs",
        "repo": "https://github.com/littlefs-project/littlefs.git",
        "ref": "v2.9.3",
        "sources": ["lfs.c"],
        "toolchain": "gcc13-arm",
        "cflags": [*ARM_FLAGS, "-O2", "-DLFS_NO_MALLOC", "-DLFS_NO_ASSERT"],
        "output": f"{SMOKE_DIR}/smoke-littlefs-v2.9.3-gcc13-arm-O2.o",
    }
    req.update(over)
    return req


def frotz_request(**over) -> dict:
    req = {
        "mode": "sources",
        "name": "smoke-frotz",
        "repo": "https://gitlab.com/DavidGriffith/frotz.git",
        "ref": "2.54",
        # defs.h and hash.h are Makefile-generated, not committed. Without
        # prepare every unit fails on a missing header.
        "prepare": "make src/common/defs.h src/common/hash.h",
        "sources": ["src/common/process.c", "src/common/object.c"],
        "toolchain": "gcc13-arm",
        "cflags": [*ARM_FLAGS, "-O2", "-std=gnu11"],
        "output": f"{SMOKE_DIR}/smoke-frotz-2.54-gcc13-arm-O2.o",
    }
    req.update(over)
    return req


def pico_request(**over) -> dict:
    req = {
        "mode": "framework",
        "name": "smoke-pico-sdk",
        "framework": "pico-sdk",
        "repo": "https://github.com/raspberrypi/pico-sdk.git",
        "ref": "2.1.0",
        "libraries": ["hardware_i2c", "pico_stdlib"],
        "board": "pico",
        "opt": "-O2",
        "toolchain": "gcc13-arm",
        "output_dir": SMOKE_DIR,
    }
    req.update(over)
    return req


class TestBuilderHealth:
    def test_health_reports_toolchains_stubs_and_generator(self, health):
        assert health.get("ok") is True, health
        assert "gcc13-arm" in health.get("identities", []), health
        assert "pico-sdk" in health.get("stubs", []), health
        # cmake -G Ninja without ninja fails configure with
        # "CMAKE_MAKE_PROGRAM is not set", which reads like a stub bug.
        assert health.get("cmake_generator") == "Ninja", health


class TestDryRun:
    """dry_run does no clone and no compile; it is also the flag preview."""

    def test_sources_dry_run_compiles_nothing(self):
        result = build(littlefs_request(dry_run=True), timeout=60)
        assert result["status"] == "would_execute"
        assert result["artifacts"][0]["path"].endswith("-gcc13-arm-O2.o")
        compile_line = next(c for c in result["command"] if "-c" in c)
        assert opt_levels(compile_line) == ["-O2"]

    def test_sources_with_prepare_dry_run_shows_the_command(self):
        result = build(frotz_request(dry_run=True), timeout=60)
        assert result["status"] == "would_execute"
        assert result["prepare"] == "make src/common/defs.h src/common/hash.h"

    def test_framework_dry_run_never_assigns_cmake_c_flags(self):
        result = build(pico_request(dry_run=True), timeout=60)
        assert result["status"] == "would_execute"
        configure = result["command"][0]
        # -DCMAKE_C_FLAGS replaces what the pico toolchain file seeded through
        # CMAKE_C_FLAGS_INIT, which is where -mcpu/-mthumb come from.
        assert not [a for a in configure if a.startswith("-DCMAKE_C_FLAGS=")], configure
        assert [a for a in configure if a.startswith("-DGHIDRA_C_FLAGS=-O2 ")], configure
        assert "-DCMAKE_BUILD_TYPE=GhidraRef" in configure, configure
        assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in configure, configure
        paths = {Path(a["path"]).name for a in result["artifacts"]}
        assert "smoke-pico-sdk-hardware_i2c-2.1.0-gcc13-arm-O2-pico.o" in paths


class TestSourcesMode:
    def test_littlefs_builds_and_names_its_functions(self):
        artifacts = assert_built(build(littlefs_request(), timeout=180))
        names = artifacts[0]["defined_functions"]
        assert "lfs_format" in names, names[:40]
        assert "lfs_dir_fetchmatch" in names, names[:40]

    def test_frotz_prepare_generates_headers_then_compiles(self):
        artifacts = assert_built(build(frotz_request(), timeout=240))
        names = artifacts[0]["defined_functions"]
        assert "interpret" in names, names[:40]


class TestFrameworkMode:
    """pico-sdk: the path where both flag defects lived."""

    @pytest.fixture(scope="class")
    def built(self) -> dict:
        return build(pico_request(), timeout=900)

    def test_one_artifact_per_requested_library(self, built):
        artifacts = assert_built(built)
        libs = {a["library"] for a in artifacts}
        assert {"hardware_i2c", "pico_stdlib"} <= libs, sorted(libs)

    def test_hand_named_firmware_functions_are_present(self, built):
        """Already named by hand in the target firmware, so match quality is
        immediately testable against this corpus entry.

        `time_us_32` is not among them: in SDK 2.1.0 it is a `static inline`
        that reads TIMERAWL, so no object defines it and it can only ever
        appear inlined into a caller. `time_us_64` is the real symbol.
        """
        defined = {n for a in built["artifacts"] for n in a["defined_functions"]}
        for name in ("i2c_write_blocking", "gpio_set_function", "time_us_64"):
            assert name in defined, sorted(defined)[:40]

    def test_compile_lines_were_verified_against_the_request(self, built):
        check = built["flag_check"]
        assert check["opt"] == "-O2"
        assert check["compile_lines"] > 0
        # Cortex-M is Thumb-only; without these the assembler rejects `dmb`.
        assert "-mthumb" in check["require_compile_flags"]
        assert "-mcpu=" in check["require_compile_flag_prefixes"]

    def test_objects_are_thumb_for_the_target_cpu(self, built):
        """Ground truth, not the builder's own report. A build that targets the
        wrong ISA poisons the corpus in a way BSim would not reveal. The
        signatures would simply be from the wrong code."""
        readelf = shutil.which("readelf")
        if readelf is None:
            pytest.skip("no readelf on the host")
        path = host_path(built["artifacts"][0]["path"])
        if path is None:
            pytest.skip("set GHIDRA_MCP_BUILDER_DATA to check the object itself")
        assert path.is_file(), path
        attrs = subprocess.run(
            [readelf, "-A", str(path)], capture_output=True, text=True, timeout=60
        ).stdout
        assert "Tag_THUMB_ISA_use" in attrs, attrs[:2000]
        assert "Tag_CPU_arch" in attrs, attrs[:2000]

    def test_a_wrong_optimisation_level_is_refused_not_labelled(self):
        """The guard itself: an -O level the compile lines do not agree with
        must fail the build rather than produce a mislabelled artifact."""
        result = build(
            pico_request(
                libraries=["hardware_i2c"],
                # Appended after ours, so it wins in CMake: exactly the shape
                # the SDK's Release default had.
                config={"CMAKE_C_FLAGS_GHIDRAREF": "-O3"},
            ),
            timeout=900,
        )
        assert result.get("ok") is False, json.dumps(result, indent=2)[:2000]
        assert result["status"] == "flag_mismatch", result
        assert "-O3" in json.dumps(result["violations"])
