# Ghidra MCP - agent guide

## Overview

MCP server bridging Ghidra reverse engineering with AI tools. 268 MCP tools for binary analysis.

- Package `com.xebyte`, **Version**: 7.0.0, Java 21 LTS, Ghidra 12.1.2.
- This is Ben's personal fork. There is no downstream audience or community to design for.
- Prefer the complete fix over a workaround, and ship it with tests. Finished product, not a plan.

The guards and thresholds documented below were calibrated against measured failures; the full narratives are in git history (the pre-2026-08-31 CLAUDE.md). Check there before relaxing a guard.

## Repository scope

This repo is the Ghidra MCP server and its bridge. In scope:

- `src/`, `python/bridge_mcp_ghidra/`: the server and its bridge
- `ghidra_scripts/`: Ghidra scripts that work on any binary
- `tests/`, `tools/`, `docs/`

Out of scope: anything specific to one target binary or corpus (game probes, mod tooling, per-title debugger harnesses, conformance proving). That belongs in the corpus's own repo even when a session here produces it. Sharing a subject is not sharing a codebase; if something needs rescuing and does not fit the list above, move it to the repo where it belongs rather than committing it here.

## Architecture

```
AI Tools <-> MCP Bridge (python/bridge_mcp_ghidra/) <-> Ghidra Plugin (GhidraMCPPlugin.jar)
```

- Plugin: `src/main/java/com/xebyte/GhidraMCPPlugin.java`. HTTP server, delegates to services.
- Bridge: `python/bridge_mcp_ghidra/`, split into focused modules (`config`, `state`, `server`, `validation`, `transport`, `discovery`, `schema`, `dispatch`, `registry`, `static_tools`, `debugger`, `cli`). Dynamic tool registration from `/mcp/schema`, plus static tools: 8 instance/tool-group/import tools (`list_instances`, `connect_instance`, `list_tool_groups`, `load_tool_group`, `unload_tool_group`, `check_tools`, `search_tools`, `import_file`) and 22 debugger proxies gated on `GHIDRA_DEBUGGER_URL`. Ships as the `ghidra-mcp-bridge` wheel with the `bridge-mcp-ghidra` console script. Cross-module calls are module-qualified (`transport.do_request`, `dispatch.dispatch_get`) and mutable runtime state lives in `state.py`, so each function has one canonical mock-patch target.
- Service layer: `src/main/java/com/xebyte/core/`, 16 service classes (~20K lines), `@McpTool`/`@Param` annotated. v5.4.0 added `EmulationService` (P-code emulation) and `DebuggerService` (TraceRmi wrapping, GUI-only). v7.0.0 added `BSimService` (CLI wrap of `support/bsim`; BSim is not on the server classpath) and `ReferenceBuildService` (`build_reference` / `build_manifest` / `build_reference_status` / `builder_health`; one resident `ghidra-builder` compiles pinned source onto the shared `/data` volume, and `builder_health` reports the container's packed identities and stubs).
- Reference builder: `docker/Dockerfile.builder`, GHCR image `ghidra-mcp-builder`, compose DNS `ghidra-builder`. Toolchain identities are `<compiler><major>-<target>` (gcc10-arm / gcc12-arm / gcc13-arm as pinned ARM GNU prefixes, gcc13-x86_64 as distro gcc-13), pinned in `docker/builder/toolchains.lock`. Always-on, uid 1000, no host ports, no docker.sock. Published by `.github/workflows/ghcr.yml`. `POST /build` returns a job id; `GET /build/{id}` is the poll. Corpus definitions: `docker/references.yaml` (ARM) and `docker/references.userland.yaml` (x86-64), both ingesting into `postgresql://ghidra-bsim:5432/bsim` (`medium_nosize`). Framework stubs: `docker/stubs/<framework>/` (pico-sdk, musl, glibc, openssl, libsodium, sqlite). `mode=framework` harvests per-library `.o`/`.a` from the build tree, never the linked ELF. Compiles keep DWARF (`/ref/<name>/` prefix). `source_read` reads the builder source cache.
- BSim PostgreSQL: `docker/Dockerfile.bsim`, GHCR image `ghidra-mcp-bsim`, compose DNS `ghidra-bsim`. Stock `postgres:16` plus Ghidra's `lshvector` C extension (sources from Ghidra 12.1.2, pinned in `docker/bsim/lshvector.lock`; never `support/bsim_ctl`). SSL mandatory (`hostnossl reject`). One database, `bsim` (`medium_nosize`); ARM firmware and x86-64 userland share it so cross-arch matches are queryable, and `bsim_query(arch=...)` constrains to same-arch. Ingest refuses a pointer-size mismatch only against sized templates (`medium_32` / `medium_64`). Published on `BIND_ADDR:5432` (VPN/LAN), not on the Cloudflare tunnel. `GHIDRA_MCP_BSIM_URLS` is a fail-closed allowlist; `file:` URLs still use `GHIDRA_MCP_BSIM_ROOT`. Credentials `GHIDRA_MCP_BSIM_USER`/`PASSWORD` are not the Ghidra Server login. `bsim-backup` runs `pg_dump`. Migration: `docker/bsim/MIGRATION.md`; confirm the live `file:/srv/ghidra/bsim/re` is 32-bit-only before migrating it, and recreate as `medium_nosize` if polluted.
- Debugger (Python): `python/bridge_mcp_ghidra/debugger.py` is a 22-tool proxy forwarding to whatever external debugger server `GHIDRA_DEBUGGER_URL` names, registered only when that variable is set. That server's HTTP API is an external contract; a route or payload change there breaks these proxies with no CI to catch it.
- Headless: `src/main/java/com/xebyte/headless/`, standalone server without GUI, including `HeadlessManagementService` for program/project lifecycle.
- fun-doc: an external consumer of this server's HTTP API. Changes to the response envelope or service endpoints can break it from a distance; no shared CI catches that.
- Annotation scanner: `AnnotationScanner.java` discovers `@McpTool` methods and generates `/mcp/schema`.

Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`.

- FrontEnd mode: `FrontEndProgramProvider` + `DirectThreadingStrategy`
- Headless mode: `HeadlessProgramProvider` + `DirectThreadingStrategy`

## Tool inventory

Do not keep the full tool list in this file.

- Authoritative repo snapshot: `tests/endpoints.json` (264 endpoints, categories, descriptions)
- Authoritative runtime schema: `/mcp/schema` from the running server
- Usage patterns: `docs/prompts/TOOL_USAGE_GUIDE.md`

## Build and deploy

Two backends. Maven is the default used by `tools.setup`; switch with `TOOLS_SETUP_BACKEND=gradle`.

Gradle (fallback / migration path):

```text
./gradlew buildExtension -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew preflight      -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew deploy         -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew startGhidra    -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC

# Same commands through the tools.setup facade
$env:TOOLS_SETUP_BACKEND = "gradle"
python -m tools.setup build
python -m tools.setup preflight --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup deploy    --ghidra-path F:\ghidra_12.1.2_PUBLIC
```

Maven (default):

```text
python -m tools.setup build
python -m tools.setup preflight      --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup ensure-prereqs --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup deploy         --ghidra-path F:\ghidra_12.1.2_PUBLIC
```

- Maven: `C:\Users\benam\tools\apache-maven-3.9.6\bin\mvn.cmd`
- Ghidra install: `F:\ghidra_12.1.2_PUBLIC`
- Deploy handles build, extension install, FrontEndTool.xml patching, and Ghidra restart.
- Migration plan: `docs/project-management/GRADLE_MIGRATION_CHECKLIST.md`

## Releases

`docs/releases/RELEASE_CHECKLIST.md` is the canonical runbook; do not duplicate it here. Floor before tagging or publishing:

```text
python -m tools.setup verify-version
python -m tools.setup build
pytest tests/unit/ -v --no-cov
python -m tools.setup deploy --ghidra-path F:\ghidra_12.1.2_PUBLIC --test release
```

Run UI-touching deploy/regression only after confirming the current Ghidra UI state; modal dialogs may be present.

## Running the MCP server

```bash
uv run bridge-mcp-ghidra                                  # stdio (recommended for AI tools)
uv run bridge-mcp-ghidra --transport streamable-http      # HTTP (web clients, MCP Inspector)
uv run bridge-mcp-ghidra --transport sse                  # SSE (deprecated compat only)
uv run python -m bridge_mcp_ghidra                        # equivalent module form
```

To use the 22 debugger proxy tools, run the external debugger server and point this bridge at it:

```bash
export GHIDRA_DEBUGGER_URL=http://127.0.0.1:8099   # unset => the 22 tools are not registered
```

Ghidra HTTP endpoint: `http://127.0.0.1:8089`

## Adding new endpoints

1. Add an `@McpTool` + `@Param` method in the appropriate service class.
2. AnnotationScanner auto-discovers it; no bridge or registry changes needed.
3. Add an entry to `tests/endpoints.json` with path, method, category, description.

For tools needing bridge-side logic (retries, multi-call orchestration), add a static `@mcp.tool()` in `python/bridge_mcp_ghidra/static_tools.py` (or `debugger.py`) and add the name to `STATIC_TOOL_NAMES` in `config.py`.

## Code conventions

- All endpoints return JSON.
- Transactions must be committed for Ghidra database changes.
- Prefer batch operations over individual calls.
- `@Param(value = "program")` defaults to `ParamSource.QUERY`; POST endpoints must send `program` as a URL query param, not in the JSON body.

## Convention enforcement

Prompt-only discipline did not survive hundreds of thousands of functions, so v5.0 moved RE documentation conventions into the tool layer. When building or modifying tools, wire validation through `NamingConventions` to keep this consistent.

- `NamingConventions.java`: centralized validation; all naming tools route through it.
- Struct fields: auto-prefixed with Hungarian notation on `create_struct`, `add_struct_field`, `modify_struct_field`.
- Function names: `rename_function` warns on non-PascalCase, missing verbs, short names. Module prefixes (`UPPERCASE_`) are accepted and validated separately.
- Globals/labels: `rename_symbol` warns if globals lack `g_` or labels are not snake_case.
- Plate comments: `batch_set_comments` warns on missing Algorithm/Parameters/Returns sections.
- Type changes: `set_variable_type` rejects `undefined` -> `undefined`.
- Completeness scoring: `analyze_function_completeness` returns budgeted scores with log-scaled deductions; structural deductions are fully forgiven in `effective_score`.

## Testing

Three tiers by cost and prerequisites:

1. Unit (`pytest tests/unit/`): pure Python, no Ghidra, no side effects. Under 5s.
2. Offline: Java scanner/parity plus Python regression tests that do not hit Ghidra on 8089. Under 10s.
3. Integration (`pytest tests/` + `mvn test`): requires live Ghidra on port 8089 with a binary open. Slow and stateful.

### What to run per change

Find the file(s) you edited; run everything in that row. Unit + Offline is the floor for every change. Rows marked "invariants below" have a matching subsection after the table.

| Change location | Run |
| --- | --- |
| `src/main/java/com/xebyte/core/*Service.java` (any service class) | Offline (Java) + Integration (Java) + `tests/integration/test_readonly_endpoints.py` |
| `BSimService.java` (`BSimCli`, `BSimJobs`, `BSimUrls`, `BSimDbProbe`, `BSimMatches`, `BSimCliParser`, `CorroborationExtract`, `CorroborationEvidence`, `CorroborationStore`) | Offline: `BSimCliParserTest`, `BSimServiceValidationTest`, `CorroborationTest`. Python: `tests/unit/test_bsim_postgres_stack.py`. Live: `tests/integration/test_bsim_cross_build.py` (skips without `GHIDRA_BSIM_FIXTURE`). Invariants below. |
| `ReferenceBuildService.java` (`ReferenceBuild`, `ReferenceManifest`, `FrameworkBuild`, `BuilderClient`, `ToolchainIdentity`) | Offline: `ReferenceBuildServiceValidationTest`. Python: `tests/unit/test_builder_stack.py`. Invariants below. |
| `AnalysisService.java` `/get_function_pcode` / `/get_language_metadata` | Offline (Java) + `tests/integration/test_readonly_endpoints.py::TestProgramInfo::test_get_language_metadata*` + `::TestFunctionAnalysis::test_get_function_pcode_*` (needs the new JAR deployed) |
| `ServerManager.java` (UDS + TCP port advertising) | Offline: `ServerManagerPortTest`. Live: `tests/integration/test_readonly_endpoints.py::test_mcp_instance_info_on_tcp` |
| `ProgramScriptService.java` `open_program` | Offline: `ProgramOpenFailureMessageTest`. Live round trip: checkout, `open_program`, `close_program`, `undo_checkout` must return `checkout_undone` on the first try with no Ghidra restart. Invariants below. |
| `NamingConventions.java` | Offline: `NamingConventionsTest` (verb-tier rules, token-subset duplicates, global-name validators). Post-deploy: `tests/integration/test_safe_write_endpoints.py` + `tests/integration/test_global_endpoints.py`. Re-run the fun-doc benchmark (`--mock --tier fast --compare`). |
| `DataTypeService.java` (`audit_global`, `set_global`, export gate, interior detection) and the plate-extent helpers in `NamingConventions.java` | Offline: `NamingConventionsTest`. Live: `tests/integration/test_global_endpoints.py` (auto-skips when endpoints are not registered), plus `audit_global` on a named data export and on a known interior address. Invariants below. |
| `SymbolLabelService.java` `rename_symbol` validator hook | Offline: `NamingConventionsTest`. Live: `tests/integration/test_global_endpoints.py` for the structured-rejection round trip |
| Add/modify `@McpTool` / `@Param` | Offline first; `EndpointsJsonParityTest` fails if `tests/endpoints.json` is stale (see Catalog drift). Then Integration (Java). |
| `GhidraMCPPlugin.java` (HTTP routes) | Offline (Java) + `EndpointRegistrationTest` (integration) + `tests/performance/test_http_concurrency.py`. For TCP port-range fallback: manual check with 8089 occupied, expect bind on 8090 and `/mcp/instance_info` reporting the actual port. |
| `src/main/java/com/xebyte/headless/*` | Offline (Java) + `tests/unit/test_setup_ghidra.py` + Integration (Java) headless run |
| `python/bridge_mcp_ghidra/*` | `tests/unit/test_bridge_utils.py tests/unit/test_mcp_tools.py tests/unit/test_mcp_tool_functions.py tests/unit/test_response_schemas.py tests/unit/test_endpoint_catalog.py tests/unit/test_project_consistency.py`. Socket dir scan: `TestGetSocketDirCandidates` + `TestDiscoverInstancesMultiDir`. TCP port scan: `TestTcpPortScan`. Debugger gating: `TestDebuggerEnabled` + `TestDebuggerToolRegistration`. Per-module cap is 800 lines (`test_bridge_modules_stay_focused`). Mock-patch targets are module-qualified; mutable globals live in `bridge_mcp_ghidra.state`. |
| `ListingService.java` `/list_shadowed_globals` | Offline: `EndpointsJsonParityTest`. Python: `tests/performance/test_global_completeness.py`. Live smoke against a binary with known shadowed globals (one corpus binary had 136). Invariants below. |
| `tools/upgrade_project_language.py` | `tests/unit/test_upgrade_project_language.py`, then a live dry run, then `--apply` on one folder before the corpus. Invariants below. |
| `python/bridge_mcp_ghidra/debugger.py` | `tests/unit/test_bridge_utils.py::TestDebuggerEnabled` + `::TestDebuggerToolRegistration`. These gate whether the proxies register at all, which is what stops the bridge advertising 22 tools that point at nothing. |
| `tools/setup/*`, `build.gradle`, `pom.xml` | `tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py tests/unit/test_gradle_tasks.py tests/unit/test_version_bump.py tests/unit/test_project_consistency.py` |
| `tests/endpoints.json` hand-edit | Offline (Java); `EndpointsJsonParityTest` verifies every `@McpTool` is listed and hand-authored descriptions are preserved |
| CLI (`bridge-mcp-ghidra --transport`, `python -m bridge_mcp_ghidra`, `tools.setup` subcommands) | `tests/unit/test_setup_cli.py` + manual invocation |

### BSim invariants

- Every BSim tool answers inside its `wait_seconds` (max 55) or returns a job ticket. CLI-heavy work runs on `BSimJobs`' single worker; `bsim_job_status` serves the result. Blocking past ~60s re-creates the upstream `-32603`.
- Cheap validation (bad `db_url`/`source`, missing credential, no program) stays synchronous so invalid input is an immediate, specific error.
- Never add BSim modules to the server classpath. Query runs `BSim_McpQuery.java` in a helper `analyzeHeadless` JVM. Keep `ghidra_scripts/BSim_McpQuery.java` byte-identical to `src/main/resources/bsim/BSim_McpQuery.java`.
- `bsim_query` defaults: `similarity_threshold=0.0`, `confidence_threshold=10.0`. Filter on confidence; cross-compiler matches sit at 0.2 to 0.4 similarity. Whole-program uses sentinel `ALL`, never `-`. `arch`/`executable`/`compiler`/`exclude_md5` are server-side `BSimFilter` atoms.
- Functions below `min_feature_count` (default 8) return `identifiable=false`; apply skips them unless `apply_unidentifiable`. Default template is `medium_nosize`. `bsim_apply_matches` requires an explicit `min_confidence`.
- Network `postgresql://` URLs must match `GHIDRA_MCP_BSIM_URLS` (fail-closed if unset) and must not embed a password; set `GHIDRA_MCP_BSIM_PASSWORD` (not the Ghidra Server login). The query helper JVM reads it inside `BSim_McpQuery`.
- For `ghidra://` sources the child JVM is stock Ghidra: env-var credentials do nothing there. Pass `--user`, feed the password on stdin, and always close the child's stdin; an open pipe blocks `HeadlessClientAuthenticator`'s prompt for the full 30-minute timeout.
- Dual ingest (`ghidra://` + `postgresql://`) stdin order is BSim database first, then Ghidra Server: `generatesigs --bsim ... --commit` pulls the vector config out of the DB before `SignatureRepository.process` touches the repository. The other order feeds the Ghidra Server password to PostgreSQL and breaks the whole PostgreSQL ingest path (measured live 2026-08-31); `BSimServiceValidationTest` pins the order in both directions.
- Username side of the same trap: `BulkSignatures` applies `--user` to the BSim database too whenever the BSim URL has no userinfo, so with `GHIDRA_MCP_BSIM_USER` unset a `ghidra://` ingest would log into PostgreSQL as the Ghidra Server user. `BSimUrls.ambiguousIngestUser` refuses that combination synchronously.
- The corroboration extract for a `ghidra://` source runs its own `analyzeHeadless` and needs `-p`: without it `allowPasswordPrompt=false` and `HeadlessClientAuthenticator` returns BADPASSWORD without ever reading the pipe.
- `bsim_list_databases` must never report configuration as state. `GHIDRA_MCP_BSIM_URLS` is an allowlist, not an inventory, and the template comes from a sidecar or `GHIDRA_MCP_BSIM_TEMPLATES`, never from the database. Rows carry `configured` (allowlisted) separately from `present` (`BSimDbProbe`'s read-only JDBC probe) and `config_template_source`. `present` is omitted when unknown because the serializer drops nulls; `probe` is the field that always answers, so a missing `present` must not be read as `false`.
- Never `support/bsim_ctl`; the image is `ghidra-mcp-bsim`.
- Never verify a BSim write path with `dry_run=true`. The scanner short-circuits before the handler, so a passing dry run proves nothing about the real path.

### Reference builder invariants

- `dry_run=true` must not `POST /build` (no clone, no compile). It does `GET /health`, and that list is what unknown names quote.
- `docker/references.yaml` expands to eighteen littlefs jobs, twelve pico-sdk framework jobs (gcc10-arm/gcc12-arm/gcc13-arm across opt levels and boards), and two frotz 2.54 sources jobs (gcc13-arm × `-O2`/`-Os`) and names `postgresql://ghidra-bsim:5432/bsim` (`medium_nosize`). `docker/references.userland.yaml` is a separate 24-job x86-64 corpus pointing at the same database.
- `mode=framework` harvests build-tree objects, never the linked ELF.
- `mode=sources` accepts `prepare` (operator-supplied shell command in the cloned tree before compile; never read from the repo). Frotz uses `make src/common/defs.h src/common/hash.h`. Rejected in `mode=framework`.
- Each artifact gets an `<artifact>.json` sidecar (resolved commit, compiler `--version`, sha256, `debug_path_prefix`, `prepare`). Manifest skip is sidecar-hash match plus recorded `prepare`, not filename.
- Compile with `-g`; `strip_debug` defaults false.
- One `builder` service; identity selects binaries inside that image. `POST /build` returns a job id; `wait_seconds` (max 55) then `build_reference_status`. `builder_health` proxies `GET /health`. `source_read` is `POST /source`, not a job.
- Never mount docker.sock into any service.

### open_program invariants

- Release our `DomainObject` consumer in a `finally`, unconditionally. `getDomainObject(tool, ...)` registers `tool` as a consumer and `ProgramManager.openProgram` takes its own; a stray reference makes the DomainFile "in use" forever, `undoCheckout` fails, and `close_program` reports `success: true, released_cache: false` while unable to help.
- Capture `getName()`/`getFunctionCount()` before the release; after it, the ProgramManager's consumer is the only thing keeping the Program alive.
- `describeOpenFailure` must keep pointing language-version refusals at `tools/upgrade_project_language.py` (this endpoint structurally cannot fix them: `okToUpgrade=false`, and an upgrade needs an exclusive checkout). Do not decorate unrelated failures; a test pins the pass-through.

### Globals auditing and eviction invariants

- "Untyped" has one definition that must move everywhere at once: `NamingConventions.isPlaceholderTypeName` here, plus mirrored placeholder sets in the external fun-doc tooling. The set is `undefined*`, `code`, and bare `pointer`/`pointer32`/`pointer64`. A one-sided edit presents as "starting a typing worker does nothing".
- `set_global` must never clear a named global out of existence. `findEvictionVictims` + `NamingConventions.isEvictableSymbolName` gate `clearCodeUnits` and reject with `type_would_evict`, listing the casualties. Clearing auto-generated labels (`DAT_*`, `LAB_*`) stays allowed. `clearCodeUnits` works on whole code units, so a small write inside an existing unit destroys the whole container.
- All three clearing writers route through `evictionRejection`: `set_global`, `apply_data_type`, `apply_data_classification`. Guarding one makes the guard advisory; the next tool in the chain completes the same write.
- The refusal text must never name `allow_evict` (`NamingConventions.evictionSuggestion` is tested for this). The override is for a human who decided the overlap is wrong, not a hint for the agent being refused.
- `plate_extent_mismatch` is MEDIUM and blocks `fully_documented`. Its thresholds are calibration outputs (6,434 live globals, three passes, final flag rate 1.1%). The abstention classes (POINTER, SENTINEL, UNIT-MULTIPLE, STRIDE, SINGULAR) each kill a measured false-positive class and must not be removed; the stride look-behind stays clause-bounded.
- A named data export's name is the ABI contract; never audit it into `g_` form. The exemption is name-only (type and plate checks still fire) and must not become a blanket export rule: ordinal exports (`Ordinal_*`) are the core rename workflow, and `isOrdinalExportName` is the discriminator.
- `audit_global` must keep distinguishing "no data here" from "swallowed by a unit that starts earlier" (`interior_to_data` plus the `container` block). `/list_globals` resolves the containing unit, so without this the damage is invisible to every dashboard read. Severity stays soft on purpose: `untyped` (hard) already fires for every interior global, and the fix needs a human judgement call.

### list_shadowed_globals invariants

- Its symbol gates are identical to `listGlobals` Pass 1 because `isGlobalDataSymbol` is shared, not copied. The two counts render side by side; disagreeing denominators are the exact bug class this endpoint exposes.
- Auto-generated labels are skipped, the same rule the eviction guard uses.
- `formatGlobalSymbol` takes the type from `getDefinedDataAt`, never `symbol.getObject()`; for a label inside a larger unit, `getObject()` returns the containing Data and reports the eater's type at an untyped address.
- `tests/integration/test_readonly_endpoints.py::TestShadowedGlobalsConsistency` pins the subset relation live and discovers a program that actually has shadowed globals rather than skipping on whatever is active.

### upgrade_project_language.py invariants

- A SLEIGH language bump makes older programs open read-only. A minor bump upgrades with a null translator (no re-analysis, documentation safe); a major bump is reported, not performed. The MCP server can never fix this itself: GUI opens pass `okToUpgrade=false` (`FrontEndProgramProvider:452`, `ProgramScriptService:1815`); only `HeadlessProgramProvider` passes `true`.
- `-commit` is load-bearing: without it the checkout is non-exclusive and the run no-ops cleanly. `-noanalysis` is unconditional.
- Known silent no-ops: `ghidra://` sees only versioned files (9 private programs are not covered by it), Git Bash rewrites `--folder` paths, parentheses in a check-in comment kill `analyzeHeadless.bat` before the JVM starts, and GUI-checked-out files are skipped.
- Credentials come from `<ghidra_dir>/.env` (`GHIDRA_SERVER_PASSWORD`); name outranks source.
- Not idempotent: every pass writes a new server version per touched file and the log cannot tell "upgraded" from "re-committed unchanged". A whole-project `--apply` refuses within 24h of a previous one unless `--force`. Never use `--apply` as its own verification.
- `--verify` leaks one exclusive checkout per probed program. Keep `--verify-sample` at 1 or 2; clear leftovers with a Ghidra restart then `--release-checkouts` (which only releases paths the tool recorded creating).
- Parse paths with `(.+?)`, never `\S+`; program file names can contain spaces.

### Commands

Unit (always cheap, run by default):

```text
pytest tests/unit/ --no-cov
```

Offline Java (scanner + endpoints.json parity, ~11 tests, under 1s):

```text
./gradlew test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
mvn test -Dtest='com.xebyte.offline.*Test'
```

Integration (Ghidra running on 8089 with a binary open):

```text
./gradlew test -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC   # or: mvn test
pytest tests/ -m readonly          # safe, no writes
pytest tests/ -m safe_write        # identity writes only
pytest tests/                      # full suite, includes mutating tests
```

### Catalog drift

If `EndpointsJsonParityTest` fails after `@McpTool` edits, regenerate `tests/endpoints.json` (preserves hand-authored descriptions and hand-registered routes):

```text
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

Do that in the PR. CI rewrites the README API Reference and "N MCP tools" counts onto the PR branch (tests.yml job `sync-generated-docs`) so the merge commit is already correct. Main is never patched after merge.

## Key gotchas

- A bare `-32603 Internal Error` with `data: null` and nothing in either container's logs is an upstream timeout, not a server bug. The gateway/tunnel hops abandon responses at ~60-100s while the call keeps running server-side. Check the bridge's `SLOW_TOOL_WARN_SECONDS` warning first. BSim tools return a `job_id` (poll `bsim_job_status`) specifically to stay under this budget.
- A Ghidra upgrade can silently make every program read-only (SLEIGH language bump). Fix: `python tools/upgrade_project_language.py` dry run, then `--apply`. Check this first after any Ghidra version change.
- Ghidra overwrites FrontEndTool.xml on exit; deploy must patch after Ghidra exits.
- Shared-server renames are not persisted by `save_program`; check in to persist.
- Max ~5 shared-server programs open at once; opening 20+ crashes Ghidra.
- `switch_program` matches by name; for multi-version work use the `program` query parameter on individual endpoints instead.
- Plate comment `\n` creates literal text, not newlines; use actual multi-line text.
- GUI operations from HTTP threads must use `SwingUtilities.invokeAndWait()`.
- A `.claude/` hook (`block-community-github-writes.py`) denies write-shaped `gh` commands against other people's PRs and issues (dependabot PRs exempt). If a `gh` call is denied, that hook is why.

## Cross-version doc archive (optional re-kb service)

When explicitly configured, documentation is stored in `re_kb.functions` on a user-selected Postgres instance and exposed through a user-selected re-kb FastAPI service. Source: `re-universe/services/re-kb/`. Six pieces:

1. Schema: `re_kb.functions` with matching keys (`opcode_hash`, `bsim_signature LSHVECTOR`, shape stats), full doc payload (`locals`, `instruction_comments`, `referenced_data_types`, `referenced_globals`, `referenced_labels`, `equates_referenced` JSONB), and metadata. Companion tables: `doc_field_provenance`, `doc_conflict_queue`, `doc_match_log`.
2. REST API: `POST /v1/doc_archive/upsert`, `POST /v1/doc_archive/match`, `GET /v1/doc_archive/{id}/full`, `GET /v1/doc_archive/conflicts`, `POST /v1/doc_archive/conflicts/{id}/resolve`.
3. Heuristics: `app/services/doc_heuristics.py` resolves field-level conflicts without AI cost; 13 per-field strategies.
4. MCP tools: `archive_ingest_function(address, program)` and `archive_ingest_program(program)` in `DocumentationHashService.java`; build payload from current Ghidra state, POST to the upsert endpoint.
5. fun-doc hooks: write hook after `save_program` calls `/archive_ingest_function`; read hook checks `/v1/doc_archive/match` before the LLM and, on Q5-D gate pass (hash exact, or BSim >= 0.9 and score >= 80), applies name + plate via existing MCP tools and skips the LLM. `bus_emit` events for dashboard visibility.
6. AI conflict worker: `re-kb-conflict-worker` container polls `/v1/doc_archive/conflicts`, asks Claude Haiku for structured decisions, POSTs back. Idle when the queue is empty.

Design rationale for Q1-Q6 lives in commit history. Migration `003_function_doc_archive.sql` applies to the selected BSim database. Disabled by default; set `RE_KB_ARCHIVE_URL` (fun-doc) and `GHIDRA_MCP_ARCHIVE_URL` (Java service) to opt in.

BSim signature backfill is a one-shot script, `ghidra_scripts/recovery/Backfill_BSimSignatures.java`, run per binary from CodeBrowser to populate `bsim_signature` and unlock tier-2 LSH matching. Tier 1 (opcode hash) works without it.

## Documentation

- Function workflow: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`
- Tool guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- String labels: `docs/prompts/STRING_LABELING_CONVENTION.md`
- Version history: `CHANGELOG.md`
