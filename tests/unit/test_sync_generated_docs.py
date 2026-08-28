"""Unit tests for tools.sync_generated_docs."""

from __future__ import annotations

import json
from pathlib import Path

from tools.gen_readme_api_reference import BEGIN_MARKER, END_MARKER
from tools.sync_generated_docs import (
    replace_mcp_tool_counts,
    sync_tree,
)


def test_replace_mcp_tool_counts_updates_numbered_mentions():
    text = "Ships **1 MCP tools** and 22 debugger proxies. Also 1 MCP tool."
    out = replace_mcp_tool_counts(text, 255)
    assert out == "Ships **255 MCP tools** and 22 debugger proxies. Also 255 MCP tool."


def test_replace_mcp_tool_counts_is_idempotent():
    text = "255 MCP tools for binary analysis."
    assert replace_mcp_tool_counts(text, 255) == text


def test_replace_mcp_tool_counts_leaves_unnumbered_mentions():
    text = "Apply changes through the MCP tools. Two new MCP tools landed."
    assert replace_mcp_tool_counts(text, 255) == text


def test_sync_tree_rewrites_readme_section_and_counts(tmp_path: Path):
    catalog = {
        "version": "7.0.0",
        "total_endpoints": 2,
        "endpoints": [
            {
                "path": "/alpha",
                "method": "GET",
                "category": "utility",
                "params": [],
                "description": "Alpha tool.",
            },
            {
                "path": "/beta",
                "method": "POST",
                "category": "utility",
                "params": [],
                "description": "Beta tool.",
            },
        ],
    }
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "endpoints.json").write_text(
        json.dumps(catalog), encoding="utf-8"
    )
    (tmp_path / "README.md").write_text(
        "Intro with **1 MCP tools**.\n\n"
        f"{BEGIN_MARKER}\nOLD SECTION\n{END_MARKER}\n",
        encoding="utf-8",
        newline="\n",
    )
    (tmp_path / "CLAUDE.md").write_text(
        "Overview. 1 MCP tools for binary analysis.\n",
        encoding="utf-8",
        newline="\n",
    )

    changed = sync_tree(tmp_path, write=True)
    rels = {p.as_posix() for p in changed}
    assert "README.md" in rels
    assert "CLAUDE.md" in rels

    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    claude = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "**2 MCP tools**" in readme
    assert "2 MCP tools for binary analysis." in claude
    assert "OLD SECTION" not in readme
    assert "`alpha`" in readme
    assert "`beta`" in readme

    assert sync_tree(tmp_path, write=False) == []
