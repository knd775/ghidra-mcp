"""Rewrite derived docs from tests/endpoints.json.

The catalog is the source of truth. Same-repo pull requests get README's
generated API Reference and the user-visible "N MCP tools" counts rewritten
onto the PR branch by the sync-generated-docs job in tests.yml. That happens
before merge, so main never has a commit where those files are stale.

    python -m tools.sync_generated_docs            # print paths that would change
    python -m tools.sync_generated_docs --write    # rewrite in place

Fork PRs cannot receive the bot commit; they must include the rewrite.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools.gen_readme_api_reference import readme_section, render_api_reference

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"

# Same files as test_user_visible_tool_counts_match_endpoint_catalog. The
# regex only rewrites "123 MCP tool(s)"; files that use a different phrasing
# are left alone.
COUNT_PATHS = (
    Path("README.md"),
    Path("CLAUDE.md"),
    Path("AGENTS.md"),
    Path("src/main/resources/extension.properties"),
    Path("src/main/resources/META-INF/MANIFEST.MF"),
)

MCP_TOOL_COUNT = re.compile(r"(\d+)(\s+MCP tools?)", re.IGNORECASE)


def catalog_total(endpoints_json: Path = ENDPOINTS_JSON) -> int:
    data = json.loads(endpoints_json.read_text(encoding="utf-8"))
    return int(data["total_endpoints"])


def replace_mcp_tool_counts(text: str, total: int) -> str:
    return MCP_TOOL_COUNT.sub(lambda m: f"{total}{m.group(2)}", text)


def apply_readme_section(readme_text: str, rendered: str | None = None) -> str:
    if rendered is None:
        rendered = render_api_reference()
    return readme_text.replace(readme_section(readme_text), rendered)


def sync_tree(root: Path, *, write: bool) -> list[Path]:
    """Rewrite derived docs under root. Returns relative paths that differ."""
    total = catalog_total(root / "tests" / "endpoints.json")
    changed: list[Path] = []

    readme_rel = Path("README.md")
    readme_path = root / readme_rel
    readme_text = readme_path.read_text(encoding="utf-8")
    rendered = render_api_reference(root / "tests" / "endpoints.json")
    new_readme = replace_mcp_tool_counts(apply_readme_section(readme_text, rendered), total)
    if new_readme != readme_text:
        changed.append(readme_rel)
        if write:
            readme_path.write_text(new_readme, encoding="utf-8", newline="\n")

    for rel in COUNT_PATHS:
        if rel == readme_rel:
            continue
        path = root / rel
        if not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        updated = replace_mcp_tool_counts(original, total)
        if updated == original:
            continue
        changed.append(rel)
        if write:
            path.write_text(updated, encoding="utf-8", newline="\n")
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="rewrite derived docs in place"
    )
    args = parser.parse_args(argv)

    changed = sync_tree(PROJECT_ROOT, write=args.write)
    if not changed:
        print("Generated docs are up to date.")
        return 0
    for rel in changed:
        print(rel.as_posix())
    if args.write:
        return 0
    print(
        "Generated docs are stale. Same-repo CI rewrites them onto the PR "
        "branch (tests.yml job sync-generated-docs). Fork PRs must include "
        "the rewrite: python -m tools.sync_generated_docs --write",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
