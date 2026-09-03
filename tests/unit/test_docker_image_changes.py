"""GHCR images rebuild only when a file they COPY actually changed."""

from __future__ import annotations

from pathlib import Path

from tools.docker_image_changes import (
    IMAGES,
    WORKFLOW_PATH,
    context_paths,
    copy_sources_from_dockerfile,
    copy_sources_from_instruction,
    file_matches_source,
    github_output_lines,
    ignore_paths,
    image_contexts,
    images_for_files,
    join_continued_lines,
    main,
    normalize_repo_path,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_parser_skips_from_stages_and_keeps_context_copies():
    text = """\
# syntax=docker/dockerfile:1
FROM alpine
COPY pom.xml .
COPY src ./src
COPY --chown=1000:1000 docker/builder/ /opt/builder/
COPY --from=builder /opt/ghidra /opt/ghidra
ADD ["LICENSE", "/out/LICENSE"]
"""
    assert copy_sources_from_dockerfile(text) == [
        "pom.xml",
        "src",
        "docker/builder/",
        "LICENSE",
    ]


def test_parser_handles_flag_values_trailing_slash_and_junk_json():
    assert copy_sources_from_instruction(
        "COPY --chown 1000:1000 src dest"
    ) == ["src"]
    assert copy_sources_from_instruction("COPY --chown=root") == []
    assert copy_sources_from_instruction("COPY only-one-token") == []
    assert copy_sources_from_instruction("COPY [not-json dest") == []
    assert copy_sources_from_instruction('COPY ["only"]') == []
    assert copy_sources_from_instruction("RUN apt-get update") is None
    assert join_continued_lines("COPY src \\\n") == ["COPY src"]
    assert not file_matches_source("", "src")
    assert copy_sources_from_dockerfile(
        "COPY pom.xml .\nCOPY pom.xml /again\n"
    ) == ["pom.xml"]


def test_parser_joins_continued_copy_lines():
    lines = join_continued_lines(
        "COPY pyproject.toml \\\n    README.md \\\n    LICENSE dest/\n"
    )
    assert len(lines) == 1
    assert copy_sources_from_instruction(lines[0]) == [
        "pyproject.toml",
        "README.md",
        "LICENSE",
    ]


def test_normalize_keeps_dot_github_paths():
    # str.lstrip("./") would turn this into github/workflows/ghcr.yml
    # and a workflow-only push would rebuild nothing.
    assert normalize_repo_path("./.github/workflows/ghcr.yml") == WORKFLOW_PATH
    assert normalize_repo_path(".github/workflows/ghcr.yml") == WORKFLOW_PATH


def test_file_match_does_not_treat_dockerfile_as_a_prefix():
    assert file_matches_source("docker/Dockerfile", "docker/Dockerfile")
    assert not file_matches_source(
        "docker/Dockerfile.bridge", "docker/Dockerfile"
    )
    assert file_matches_source("src/main/java/Foo.java", "src")
    assert file_matches_source("python/bridge_mcp_ghidra/cli.py", "python/")
    assert not file_matches_source("docs/prompts/BSIM.md", "python/")


def test_real_dockerfiles_expose_known_copy_inputs():
    ctx = image_contexts(REPO_ROOT)
    assert ctx["headless"][0] == "docker/Dockerfile"
    assert "docker/entrypoint.sh" in ctx["headless"]
    assert "src" in ctx["headless"]
    assert "pom.xml" in ctx["headless"]
    assert "python/" in ctx["bridge"]
    assert "pyproject.toml" in ctx["bridge"]
    assert "docker/builder/" in ctx["builder"]
    assert "docker/stubs/" in ctx["builder"]
    assert "docker/bsim/lshvector.lock" in ctx["bsim"]
    # Runtime mounts, not image bytes.
    for name, sources in ctx.items():
        assert ".dockerignore" in sources
        assert f"{IMAGES[name]}.dockerignore" in sources
        assert "docker/references.yaml" not in sources
        assert "docker/docker-compose.yml" not in sources
        assert "uv.lock" not in sources


def _on(*names: str) -> dict[str, bool]:
    return {name: name in names for name in IMAGES}


def test_java_only_change_rebuilds_headless():
    assert images_for_files(
        ["src/main/java/com/xebyte/GhidraMCPPlugin.java"], REPO_ROOT
    ) == _on("headless")


def test_bridge_package_change_rebuilds_bridge():
    assert images_for_files(
        ["python/bridge_mcp_ghidra/server.py"], REPO_ROOT
    ) == _on("bridge")


def test_stub_change_rebuilds_builder():
    assert images_for_files(
        ["docker/stubs/pico-sdk/CMakeLists.txt"], REPO_ROOT
    ) == _on("builder")


def test_lshvector_lock_rebuilds_bsim():
    assert images_for_files(
        ["docker/bsim/lshvector.lock"], REPO_ROOT
    ) == _on("bsim")


def test_workflow_change_rebuilds_every_image():
    assert images_for_files([WORKFLOW_PATH], REPO_ROOT) == _on(*IMAGES)


def test_root_dockerignore_rebuilds_every_image():
    assert ignore_paths("docker/Dockerfile.bridge") == (
        ".dockerignore",
        "docker/Dockerfile.bridge.dockerignore",
    )
    assert images_for_files([".dockerignore"], REPO_ROOT) == _on(*IMAGES)


def test_dockerfile_specific_dockerignore_rebuilds_only_that_image():
    assert images_for_files(
        ["docker/Dockerfile.bridge.dockerignore"], REPO_ROOT
    ) == _on("bridge")
    assert images_for_files(
        ["docker/Dockerfile.dockerignore"], REPO_ROOT
    ) == _on("headless")
    assert images_for_files(
        ["docker/Dockerfile.builder.dockerignore"], REPO_ROOT
    ) == _on("builder")
    assert images_for_files(
        ["docker/Dockerfile.bsim.dockerignore"], REPO_ROOT
    ) == _on("bsim")


def test_docs_and_compose_do_not_rebuild():
    assert images_for_files(
        [
            "docs/prompts/BSIM.md",
            "docker/README.md",
            "docker/docker-compose.yml",
            "docker/references.yaml",
            "tests/unit/test_docker_image_changes.py",
        ],
        REPO_ROOT,
    ) == _on()


def test_changelog_is_in_the_bridge_image():
    assert images_for_files(["CHANGELOG.md"], REPO_ROOT) == _on("bridge")


def test_all_flag_and_empty_stdin(capsys):
    assert main(["--all"]) == 0
    captured = capsys.readouterr()
    assert github_output_lines(_on(*IMAGES)) == captured.out.splitlines()
    assert "building: bridge, headless, builder, bsim" in captured.err


def test_cli_reads_changed_files_from_stdin(capsys, monkeypatch):
    monkeypatch.setattr(
        "sys.stdin",
        iter(["src/main/java/com/xebyte/GhidraMCPPlugin.java\n", "\n"]),
    )
    assert main([]) == 0
    captured = capsys.readouterr()
    assert github_output_lines(_on("headless")) == captured.out.splitlines()
    assert "skipped: bridge, builder, bsim" in captured.err


def test_context_paths_reads_from_repo_root_override(tmp_path: Path):
    dockerfile = tmp_path / "docker" / "Dockerfile.bridge"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text(
        "FROM scratch\nCOPY only-this.txt /only-this.txt\n", encoding="utf-8"
    )
    # Other images still resolve against the real repo via IMAGES paths
    # that are missing here; only bridge is overridden by writing that file.
    assert context_paths(tmp_path, "bridge") == [
        "docker/Dockerfile.bridge",
        ".dockerignore",
        "docker/Dockerfile.bridge.dockerignore",
        "only-this.txt",
    ]
