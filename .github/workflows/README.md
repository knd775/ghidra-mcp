# GitHub Workflows

This directory contains the maintained CI, release, and live-regression
workflows for GhidraMCP.

## Workflows

| Workflow | Trigger | Runner | Purpose |
|----------|---------|--------|---------|
| `tests.yml` | Push, pull request, and `workflow_dispatch` to `main`/`develop` | GitHub-hosted Ubuntu | Merge-gating Maven build, Python 3.12 unit tests, BSim PostgreSQL image smoke (`CREATE EXTENSION lshvector` + non-SSL reject), and docs checks. Same-repo PRs also rewrite README API Reference and "N MCP tools" counts onto the PR branch (`sync-generated-docs` job) so main never lands stale. |
| `ghcr.yml` | Push to `main`/`dev`/`develop` and version tags; manual dispatch | GitHub-hosted Ubuntu | Build and push `ghidra-mcp-headless`, `ghidra-mcp-bridge`, `ghidra-mcp-builder`, and `ghidra-mcp-bsim` to GHCR when that image's Dockerfile `COPY` inputs or dockerignore files changed. Changing `ghcr.yml` alone does not rebuild. Version tags and manual dispatch build every image. Does not run on pull requests. |
| `build.yml` | Project build triggers | GitHub-hosted | Build-focused CI path. |
| `release-regression.yml` | Manual, reusable workflow call, PR label | Self-hosted Windows | Live Ghidra deploy and benchmark regression. |
| `release.yml` | Version tags or manual dispatch | GitHub-hosted, optional self-hosted regression | Stable release artifact creation. |
| `pre-release.yml` | Manual dispatch | GitHub-hosted, optional self-hosted regression | Pre-release artifact creation. |

## Pull Request Gates

`tests.yml` runs automatically on pull requests and is the default merge gate.
Configure branch protection to require its status checks.

The README API listing and "N MCP tools" counts are a PR check. Same-repo
PRs get them rewritten onto the PR branch by the `sync-generated-docs` job
before merge; pytest will not pass on a stale listing. A GITHUB_TOKEN push
does not start a new `pull_request` run, so that job then
`workflow_dispatch`es Tests on the rewritten commit. Direct pushes to main
with a stale listing fail; they are not auto-fixed. Fork PRs must include
`python -m tools.sync_generated_docs --write`.

The live Ghidra regression is opt-in on pull requests. Add this PR label:

```text
live-ghidra-regression
```

When the label is present, `release-regression.yml` runs on a self-hosted
Windows runner and executes:

```text
python -m tools.setup deploy --ghidra-path <path> --test release
```

This is not enabled for every PR by default because public GitHub-hosted runners
do not have the required active Ghidra project, and external PRs should not hang
waiting for a private self-hosted runner.

## Release Gates

`release.yml` and `pre-release.yml` expose a `run_live_regression` input. Enable
it when a self-hosted Windows runner is available and you want the release job to
wait for the live regression before publishing.

The release regression workflow expects:

- Ghidra installed on the self-hosted runner.
- Java 21, Python 3.13, and Maven.
- Access to the target Ghidra project.
- Any `.env` credentials needed by the project or Ghidra Server.

See [docs/TESTING.md](../../docs/TESTING.md) for the full testing model,
commands, side effects, and runner/container notes.
