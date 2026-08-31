"""Cross-build BSim quality check.

Reproduces the failure that motivated the BSim tools: a reference library
build at one GCC / opt-level, queried from a firmware image of the same
library built differently. Distinctive functions should come back as the
top hit with high confidence. Short generic helpers should come back with
low confidence even at high similarity.

There is no littlefs/RP2040 corpus in this repo. Point GHIDRA_BSIM_FIXTURE
at a directory containing:

    db_url.txt          first line is the BSim URL
    distinctive.json    {"function": "FUN_...", "expected_name": "lfs_bd_read",
                         "min_confidence": 20}
    generic.json        {"function": "FUN_...", "max_confidence": 10}

Ghidra MCP must be running with the firmware program open. If this test
cannot be made to pass, BSim is not solving the problem here; do not
bulk-apply names from these tools until it does.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

FIXTURE = os.environ.get("GHIDRA_BSIM_FIXTURE", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("require_server"),
]


@pytest.fixture(scope="module")
def require_server(server_available):
    if not server_available:
        pytest.skip("MCP server is not running")


@pytest.fixture(scope="module")
def fixture_dir():
    if not FIXTURE or not Path(FIXTURE).is_dir():
        pytest.skip(
            "Set GHIDRA_BSIM_FIXTURE to a directory with db_url.txt, "
            "distinctive.json, generic.json"
        )
    return Path(FIXTURE)


def _await_job(http_client, data, deadline_s=1800):
    """Resolve a BSim job ticket to its result.

    BSim tools answer inline when the CLI finishes inside wait_seconds and
    return {"status": "started", "job_id"} otherwise; the embedded result from
    bsim_job_status is identical to the inline payload.
    """
    if data.get("status") != "started" or "job_id" not in data:
        return data
    job_id = data["job_id"]
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        response = http_client.get("/bsim_job_status", params={"job_id": job_id})
        assert response.status_code == 200, response.text
        status = response.json()
        assert "error" not in status, status
        if status.get("state") == "done":
            result = status.get("result")
            assert isinstance(result, dict), status
            return result
        time.sleep(5)
    raise AssertionError(f"BSim job {job_id} did not finish within {deadline_s}s")


def _post(http_client, path, body):
    response = http_client.post(path, json_data=body, timeout=1800)
    assert response.status_code == 200, response.text
    data = _await_job(http_client, response.json())
    assert "error" not in data, data
    return data


def _db_url(fixture_dir: Path) -> str:
    return (fixture_dir / "db_url.txt").read_text(encoding="utf-8").splitlines()[0].strip()


def test_distinctive_function_is_top_hit_with_confidence(http_client, fixture_dir):
    spec = json.loads((fixture_dir / "distinctive.json").read_text(encoding="utf-8"))
    body = {
        "db_url": _db_url(fixture_dir),
        "function": spec["function"],
        "max_matches": 10,
    }
    # Omit thresholds so the server defaults (similarity 0.0, confidence 10.0)
    # have to surface this cross-build match. Passing 0.7 hid it.
    if "similarity_threshold" in spec:
        body["similarity_threshold"] = spec["similarity_threshold"]
    if "confidence_threshold" in spec:
        body["confidence_threshold"] = spec["confidence_threshold"]
    data = _post(http_client, "/bsim_query", body)
    matches = data.get("matches") or []
    assert matches, data
    top = matches[0]
    assert "similarity" in top and "confidence" in top, top
    assert top["name"] == spec["expected_name"], top
    assert top["confidence"] >= spec.get("min_confidence", 20), top
    assert data.get("ambiguous") is False, data


def test_old_similarity_default_returns_nothing(http_client, fixture_dir):
    spec = json.loads((fixture_dir / "distinctive.json").read_text(encoding="utf-8"))
    data = _post(
        http_client,
        "/bsim_query",
        {
            "db_url": _db_url(fixture_dir),
            "function": spec["function"],
            "similarity_threshold": 0.7,
            "max_matches": 10,
        },
    )
    matches = data.get("matches") or []
    assert not matches, (
        "similarity_threshold=0.7 must still drop the cross-build hit that "
        "the new default surfaces: " + json.dumps(data)
    )
    warnings = data.get("warnings") or []
    assert warnings, data


def test_generic_helper_low_confidence(http_client, fixture_dir):
    spec = json.loads((fixture_dir / "generic.json").read_text(encoding="utf-8"))
    data = _post(
        http_client,
        "/bsim_query",
        {
            "db_url": _db_url(fixture_dir),
            "function": spec["function"],
            "similarity_threshold": spec.get("similarity_threshold", 0.5),
            "confidence_threshold": 0.0,
            "max_matches": 10,
        },
    )
    matches = data.get("matches") or []
    if not matches:
        return
    top = matches[0]
    assert "confidence" in top and "similarity" in top, top
    assert top["confidence"] <= spec.get("max_confidence", 10), (
        "generic helper returned high confidence; BSim is not separating "
        "distinctive functions from accessors/thunks: " + json.dumps(top)
    )


def test_apply_dry_run_does_not_rename(http_client, fixture_dir):
    before = http_client.get("/list_functions", params={"limit": "5"})
    assert before.status_code == 200
    data = _post(
        http_client,
        "/bsim_apply_matches",
        {
            "db_url": _db_url(fixture_dir),
            "min_confidence": 1e9,
            "dry_run": True,
        },
    )
    assert data.get("dry_run") is True, data
    assert data.get("renamed") == [], data
    assert "would_rename" in data, data
    counts = data.get("counts") or {}
    assert counts.get("renamed") == 0, data
    assert counts.get("would_rename") == len(data["would_rename"]), data
    for category in (
        "already_named",
        "unidentifiable",
        "below_similarity",
        "below_confidence",
        "ambiguous",
        "no_matches",
        "function_not_found",
        "rename_failed",
    ):
        assert category in counts, data
    after = http_client.get("/list_functions", params={"limit": "5"})
    assert after.status_code == 200
    assert before.text == after.text


def test_corroborate_match_does_not_require_a_reference_program(http_client, fixture_dir):
    """Acceptance: evidence comes from the corpus; only the query program is open."""
    spec_path = fixture_dir / "corroboration.json"
    if not spec_path.is_file():
        pytest.skip("optional corroboration.json not in GHIDRA_BSIM_FIXTURE")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    data = _post(
        http_client,
        "/corroborate_match",
        {
            "db_url": _db_url(fixture_dir),
            "function": spec["function"],
            "ref_executable": spec["ref_executable"],
            "ref_function": spec["ref_function"],
            "string_normalisation": spec.get("string_normalisation", "auto"),
        },
    )
    assert "score" not in data, data
    assert "corroboration_score" not in data, data
    if data.get("status") == "no_evidence":
        assert data.get("reason") in {"not_extracted", "unsupported_backend"}
        return
    assert "shared_constants" in data, data
    assert "shared_strings" in data, data
    assert "notes" in data, data


def test_query_corroborate_preserves_match_order(http_client, fixture_dir):
    spec = json.loads((fixture_dir / "distinctive.json").read_text(encoding="utf-8"))
    plain = _post(
        http_client,
        "/bsim_query",
        {"db_url": _db_url(fixture_dir), "function": spec["function"], "max_matches": 5},
    )
    corroborated = _post(
        http_client,
        "/bsim_query",
        {
            "db_url": _db_url(fixture_dir),
            "function": spec["function"],
            "max_matches": 5,
            "corroborate": True,
            "corroborate_max_candidates": 3,
        },
    )
    names = [m.get("name") for m in (plain.get("matches") or [])]
    names2 = [m.get("name") for m in (corroborated.get("matches") or [])]
    assert names == names2, (names, names2)
    assert "score" not in json.dumps(corroborated)


def test_apply_without_min_confidence_is_an_error(http_client, fixture_dir):
    response = http_client.post(
        "/bsim_apply_matches",
        json_data={"db_url": _db_url(fixture_dir), "dry_run": True},
        timeout=60,
    )
    assert response.status_code == 200
    data = response.json()
    assert "error" in data
    assert "min_confidence" in data["error"]
