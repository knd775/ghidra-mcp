"""Decide which GHCR images a commit would actually change.

ghcr.yml used to build all four images on every push. The builder fetches
ARM GNU tarballs, headless downloads Ghidra, and bsim sparse-clones it. A
Java-only commit paid for all of that.

Each image's inputs are its Dockerfile plus every repo path its COPY/ADD
instructions read. ``--from`` copies come from another stage, not the
build context. ``.github/workflows/ghcr.yml`` counts as an input for every
image so a tagging or cache change still publishes.

    git diff --name-only "$BEFORE" HEAD | python -m tools.docker_image_changes
    python -m tools.docker_image_changes --all
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Workflow job names, in the order ghcr.yml prints outputs.
IMAGES: dict[str, str] = {
    "bridge": "docker/Dockerfile.bridge",
    "headless": "docker/Dockerfile",
    "builder": "docker/Dockerfile.builder",
    "bsim": "docker/Dockerfile.bsim",
}

WORKFLOW_PATH = ".github/workflows/ghcr.yml"

_FLAGS_TAKING_VALUE = {"--chown", "--chmod", "--exclude"}


def normalize_repo_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def join_continued_lines(text: str) -> list[str]:
    """Join Dockerfile lines that end in a backslash. Drop comments and blanks."""
    joined: list[str] = []
    buf: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buf:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
        if line.endswith("\\"):
            buf.append(line[:-1].rstrip())
            continue
        buf.append(line)
        piece = " ".join(buf).strip()
        buf = []
        if piece and not piece.startswith("#"):
            joined.append(piece)
    if buf:
        piece = " ".join(buf).strip()
        if piece and not piece.startswith("#"):
            joined.append(piece)
    return joined


def copy_sources_from_instruction(instruction: str) -> list[str] | None:
    """Return context paths a COPY/ADD reads, or None if this is not one.

    ``--from`` instructions return an empty list: those bytes come from
    another stage, not the repo context.
    """
    tokens = instruction.split()
    if not tokens or tokens[0].upper() not in {"COPY", "ADD"}:
        return None
    i = 1
    while i < len(tokens) and tokens[i].startswith("--"):
        flag, _, value = tokens[i].partition("=")
        if flag == "--from":
            return []
        if flag in _FLAGS_TAKING_VALUE and not value:
            i += 2
            continue
        i += 1
    remaining = tokens[i:]
    if not remaining:
        return []
    if remaining[0].startswith("["):
        try:
            arr = json.loads(" ".join(remaining))
        except json.JSONDecodeError:
            return []
        if not isinstance(arr, list) or len(arr) < 2:
            return []
        return [normalize_repo_path(str(item)) for item in arr[:-1] if str(item)]
    if len(remaining) < 2:
        return []
    return [normalize_repo_path(src) for src in remaining[:-1] if src]


def copy_sources_from_dockerfile(text: str) -> list[str]:
    sources: list[str] = []
    seen: set[str] = set()
    for instruction in join_continued_lines(text):
        found = copy_sources_from_instruction(instruction)
        if not found:
            continue
        for src in found:
            if src in seen:
                continue
            seen.add(src)
            sources.append(src)
    return sources


def context_paths(repo_root: Path, image: str) -> list[str]:
    dockerfile = IMAGES[image]
    text = (repo_root / dockerfile).read_text(encoding="utf-8")
    paths = [dockerfile]
    paths.extend(copy_sources_from_dockerfile(text))
    return paths


def image_contexts(repo_root: Path) -> dict[str, tuple[str, ...]]:
    return {name: tuple(context_paths(repo_root, name)) for name in IMAGES}


def file_matches_source(changed: str, source: str) -> bool:
    changed = normalize_repo_path(changed)
    source = normalize_repo_path(source)
    if not changed or not source:
        return False
    source_dir = source.rstrip("/")
    if changed == source or changed == source_dir:
        return True
    return changed.startswith(source_dir + "/")


def images_for_files(
    changed_files: Iterable[str], repo_root: Path
) -> dict[str, bool]:
    selected = {name: False for name in IMAGES}
    changed = [normalize_repo_path(path) for path in changed_files]
    changed = [path for path in changed if path]
    if WORKFLOW_PATH in changed:
        return {name: True for name in IMAGES}
    contexts = image_contexts(repo_root)
    for name, sources in contexts.items():
        selected[name] = any(
            file_matches_source(path, source)
            for path in changed
            for source in sources
        )
    return selected


def github_output_lines(selected: dict[str, bool]) -> list[str]:
    return [
        f"{name}={'true' if selected[name] else 'false'}" for name in IMAGES
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        help="select every image (tags, workflow_dispatch, unknown before SHA)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="repository root that holds the Dockerfiles (default: this repo)",
    )
    args = parser.parse_args(argv)
    root = args.repo_root or PROJECT_ROOT
    if args.all:
        selected = {name: True for name in IMAGES}
    else:
        selected = images_for_files(sys.stdin, root)
    building = [name for name, on in selected.items() if on]
    skipped = [name for name, on in selected.items() if not on]
    print(f"building: {', '.join(building) or '(none)'}", file=sys.stderr)
    print(f"skipped: {', '.join(skipped) or '(none)'}", file=sys.stderr)
    for line in github_output_lines(selected):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
