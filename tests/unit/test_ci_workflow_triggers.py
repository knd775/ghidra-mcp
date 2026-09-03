"""Guard that CI actually fires on the branches this project works on.

Why this exists
---------------
On 2026-08-04 `dev` was made the working branch AND the repository's default
branch. Both CI workflows still listed only ``main`` (plus a ``develop`` that
nothing pushes to), so every push to the branch where all work now happens ran
**zero tests and zero code scanning**. Nothing failed. Nothing warned. The first
signal would have been a red `main` at merge time, long after the commit that
broke it -- which is the most expensive moment to find out.

A workflow that does not run cannot fail, so the absence of CI is invisible to
CI by construction. That is precisely the shape of bug that needs an offline
test rather than a convention.

What is deliberately NOT asserted
---------------------------------
* The exact branch list. Branches come and go; requiring an exact set makes this
  test a chore that gets edited to match reality instead of checking it.
* Scorecard. It scores the repo's *published* posture and is intentionally
  ``main``-only -- a working branch is not that. Asserting otherwise would
  pressure a future reader into widening it for symmetry.
* Release workflows, which trigger on tags rather than branches.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from tools.docker_image_changes import IMAGES

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Branches that must be covered by the test + code-scanning workflows. `main` is
# the release branch; `dev` is where the work happens and is the default branch,
# so it is the one whose coverage gap is silent.
REQUIRED_BRANCHES = ("main", "dev")

# Workflows that gate correctness and must therefore see every working branch.
GATING_WORKFLOWS = ("tests.yml", "codeql.yml")


def _load(name: str) -> dict:
    path = WORKFLOWS / name
    assert path.is_file(), f"{name} is missing from {WORKFLOWS}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    """Return the workflow's `on:` block.

    YAML 1.1 resolves a bare ``on`` key to the BOOLEAN ``True``, not the string
    ``"on"`` -- so ``doc["on"]`` raises KeyError on a perfectly valid workflow
    and a naive version of this test passes by never checking anything. Accept
    whichever key the parser produced.
    """
    for key in (True, "on", "On", "ON"):
        if key in doc:
            return doc[key]
    raise AssertionError(f"workflow has no `on:` block; keys were {list(doc)}")


@pytest.mark.parametrize("workflow", GATING_WORKFLOWS)
@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("branch", REQUIRED_BRANCHES)
def test_gating_workflow_triggers_on_working_branches(workflow, event, branch):
    """tests.yml and codeql.yml must fire on push AND pull_request for main+dev."""
    on = _triggers(_load(workflow))
    assert event in on, (
        f"{workflow} has no `{event}:` trigger, so changes reaching a branch "
        f"that way are never checked."
    )
    branches = (on[event] or {}).get("branches")
    assert branches, (
        f"{workflow}'s `{event}:` trigger has no `branches:` filter. That is "
        f"not automatically wrong -- an unfiltered trigger fires on every "
        f"branch -- but this project filters deliberately, so an empty filter "
        f"here is far more likely to be an editing accident than a decision."
    )
    assert branch in branches, (
        f"{workflow} does not run on `{branch}` (push/pull_request branches: "
        f"{branches}). Work pushed to `{branch}` would run no {workflow} checks "
        f"at all, and the gap is invisible: a workflow that never runs never "
        f"reports a failure."
    )


def test_build_status_gate_requires_every_blocking_job():
    """The `build-status` summary job must depend on every blocking job.

    `build-status` is what a branch-protection rule keys on. A blocking job left
    out of its `needs:` list still shows in the run, but can fail without
    turning the overall status red -- so protection silently stops protecting.

    Advisory jobs are excluded on purpose: they end in `|| true` and are meant
    to surface drift without blocking.
    """
    doc = _load("tests.yml")
    jobs = doc["jobs"]
    needs = set(jobs["build-status"]["needs"])

    advisory = {
        name for name, spec in jobs.items()
        if "advisory" in str(spec.get("name", "")).lower()
    }
    blocking = set(jobs) - advisory - {"build-status"}

    missing = sorted(blocking - needs)
    assert not missing, (
        f"these blocking jobs are absent from build-status.needs: {missing}. "
        f"A branch-protection rule keyed on build-status would go green while "
        f"they fail."
    )


def test_build_status_script_checks_every_job_it_depends_on():
    """Every job in `needs:` must also be tested in the summary shell script.

    Adding a job to `needs:` alone is not enough -- it makes the job *run* and
    makes `build-status` wait for it, but the reported status comes from an
    explicit `needs.<job>.result` comparison in the run script. A job listed in
    `needs:` but absent from that script is waited on and then ignored, which
    looks exactly like coverage from the outside.
    """
    doc = _load("tests.yml")
    build_status = doc["jobs"]["build-status"]
    script = "\n".join(
        str(step.get("run", "")) for step in build_status.get("steps", [])
    )
    unchecked = sorted(
        job for job in build_status["needs"]
        if f"needs.{job}.result" not in script
    )
    assert not unchecked, (
        f"build-status waits for {unchecked} but never compares "
        f"needs.<job>.result for them, so their failures do not affect the "
        f"reported build status."
    )


def test_python_unit_job_is_ubuntu_312_only():
    """This fork CI-tests the bridge on Ubuntu 3.12, matching the Docker base.

    eclipse-temurin:21-jdk is Ubuntu 24.04 (Python 3.12). A version matrix or a
    Windows pytest job is a different deployment method and is not gated here.
    """
    python_tests = _load("tests.yml")["jobs"]["python-tests"]
    assert python_tests["runs-on"] == "ubuntu-latest"
    assert "matrix" not in python_tests.get("strategy", {})
    script = "\n".join(
        str(step.get("run", "")) for step in python_tests.get("steps", [])
    )
    assert "3.12" in script
    assert "python-tests-windows" not in _load("tests.yml")["jobs"]
    assert "pester-tests" not in _load("tests.yml")["jobs"]


def test_ghcr_workflow_publishes_headless_bridge_builder_and_bsim():
    """GHCR publish must cover every image this stack actually runs."""
    path = WORKFLOWS / "ghcr.yml"
    assert path.is_file(), "ghcr.yml is missing"
    doc = _load("ghcr.yml")
    jobs = doc["jobs"]
    assert "bridge" in jobs
    assert "headless" in jobs
    assert "builder" in jobs
    assert "bsim" in jobs
    text = path.read_text(encoding="utf-8")
    assert "ghidra-mcp-bridge" in text
    assert "ghidra-mcp-headless" in text
    assert "ghidra-mcp-builder" in text
    assert "ghidra-mcp-bsim" in text
    assert "docker/Dockerfile.bridge" in text
    assert "docker/Dockerfile.builder" in text
    assert "docker/Dockerfile.bsim" in text
    assert "packages: write" in text
    on = _triggers(doc)
    assert "pull_request" not in on, (
        "ghcr.yml publishes images; it has no reason to run on pull requests. "
        "A PR trigger shows up as skipped jobs on every matching PR."
    )
    assert "pull_request" not in text, (
        "leftover pull_request guards mean the workflow still thinks PRs exist"
    )


def test_ghcr_jobs_skip_when_image_inputs_did_not_change():
    """A Java-only push must not download ARM tarballs or sparse-clone Ghidra."""
    path = WORKFLOWS / "ghcr.yml"
    doc = _load("ghcr.yml")
    jobs = doc["jobs"]
    text = path.read_text(encoding="utf-8")
    assert "changes" in jobs
    assert "python3 -m tools.docker_image_changes" in text
    assert "--all" in text
    assert "git diff --name-only" in text
    for name in IMAGES:
        job = jobs[name]
        needs = job.get("needs")
        if isinstance(needs, str):
            needs = [needs]
        assert "changes" in needs, f"{name} must wait for the change detector"
        condition = str(job.get("if", ""))
        assert f"needs.changes.outputs.{name}" in condition, (
            f"{name} must skip when its COPY inputs did not change"
        )


def test_tests_workflow_smokes_bsim_postgres_image():
    """Merge gate must build the BSim image and run CREATE EXTENSION / SSL smoke."""
    doc = _load("tests.yml")
    jobs = doc["jobs"]
    assert "bsim-postgres-image" in jobs
    spec = jobs["bsim-postgres-image"]
    script = "\n".join(str(step.get("run", "")) for step in spec.get("steps", []))
    assert "Dockerfile.bsim" in script
    assert "smoke-lshvector.sh" in script
    assert "CREATE EXTENSION" in script or "smoke-lshvector" in script
    assert "bsim-postgres-image" in jobs["build-status"]["needs"]


def test_bridge_dockerfile_is_python_312_and_loopback_oriented():
    text = (REPO_ROOT / "docker" / "Dockerfile.bridge").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in text
    assert "bridge-mcp-ghidra" in text
    assert "8081" in text
    compose = (REPO_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "Dockerfile.bridge" in compose
    assert "network_mode: \"service:ghidra-mcp\"" in compose
    assert "GHIDRA_MCP_URL: http://127.0.0.1:8089" in compose
    assert "ghidra-server:" in compose
    assert "cloudflared:" in compose
    assert "traefik" not in compose.lower()
    assert "13100:13100" in compose
    assert "GHIDRA_MCP_FILE_ROOT: /data" in compose
    assert "ghcr.io/${GHCR_OWNER:-knd775}/ghidra-mcp-builder:${GHIDRA_MCP_VERSION:-dev}" in compose
    assert "ghcr.io/${GHCR_OWNER:-knd775}/ghidra-mcp-bsim:${GHIDRA_MCP_VERSION:-dev}" in compose
    assert "hostname: ghidra-builder" in compose
    assert "hostname: ghidra-bsim" in compose
    assert "ghidra-builder:gcc13-arm" not in compose
    assert "builder-src-cache:/src" in compose
    assert "user: \"1000:1000\"" in compose
    assert "GHIDRA_MCP_BUILDER_URL:" in compose
    assert "GHIDRA_MCP_BUILDER_URLS" not in compose
    assert not any(
        line.strip().startswith("- ") and "docker.sock" in line
        for line in compose.splitlines()
    )
