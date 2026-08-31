# BSim cross-build matching

The BSim MCP tools wrap Ghidra's `bsim` CLI and the sibling toolchain
container that feeds it. They do not invent a matching algorithm.
Byte/opcode hashes fail across GCC versions. The older fuzzy matcher
produced ranked lists that looked authoritative and were not:
`lfs_fs_traverse_` was the top candidate for three different firmware
functions. BSim matches decompiled P-code structure and returns two
numbers, similarity and confidence. Confidence is what makes a bulk
rename safe.

The CLI is on disk in Ghidra 12.1.2 (`support/bsim`). It is not on the
headless server's module classpath, so these tools spawn `bsim` (and, for
query, `analyzeHeadless`) as a separate JVM. That cannot knock over the
server. Compose stores the corpus in PostgreSQL so GUI clients on the
VPN can use the same database; leftover H2 `file:` databases remain
single-writer and are serialised.

## The tools are not the work

A first query against an empty database returns nothing useful. There is
nothing to download for embedded targets. Build the corpus from pinned
source, on the shared volume, never by moving object bytes through an
agent tool call (a 34 KB object has already arrived with the right length
and the wrong sha256 that way):

```
build_reference(name="littlefs",
                repo="https://github.com/littlefs-project/littlefs.git",
                ref="v2.9.3",          # tag or SHA; branches are refused
                sources=["lfs.c"],
                toolchain="gcc13-arm",
                arch_flags="-mcpu=cortex-m0plus -mthumb",
                opt="-Os",
                defines=["LFS_NO_MALLOC", "LFS_NO_ASSERT"])
```

That writes `/data/uploads/littlefs-v2.9.3-gcc13-arm-Os.o` as uid 1000.
`import_file` can load that path with no copy. Then `bsim_ingest`.

Frameworks (Pico SDK, later Zephyr) cannot be a file list: headers are
generated at configure time. `mode="framework"` builds a stub under
`docker/stubs/<framework>/` and harvests per-library objects:

```
build_reference(name="pico-sdk",
                repo="https://github.com/raspberrypi/pico-sdk.git",
                ref="2.1.0",
                mode="framework",
                framework="pico-sdk",
                libraries=["hardware_i2c", "pico_stdlib"],
                board="pico",
                toolchain="gcc13-arm",
                opt="-Os")
```

That writes `pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o` (and one
file per harvested library, including submodules such as TinyUSB). The
stub's `main.c` must not call those libraries — that is the test that
harvesting did not use the `--gc-sections`'d ELF.

A corpus needs a matrix, not nine hand-written calls.
`docker/references.yaml` is the corpus definition; `build_manifest` expands
it. littlefs × {gcc10-arm, gcc12-arm, gcc13-arm} × {-Os, -O2, -O3} is nine
objects. pico-sdk is a **framework** entry: one stub CMake project
(`docker/stubs/pico-sdk/`) × {gcc10-arm, gcc12-arm, gcc13-arm} × {-Os, -O2}
× {pico, pico_w} is twelve configure/build jobs, each harvesting several
per-library objects. Compiler version is why: every littlefs from v2.4.2 to v2.9.3
produced `lfs_dir_fetchmatch` at 1040–1120 bytes under GCC 13.2, while the
firmware's was 1416. pico-sdk projects are commonly GCC 10–12. One
builder image holds gcc10-arm, gcc12-arm, and gcc13-arm; the identity
`<compiler><major>-<target>` selects the binary. There is no
`:gcc13-arm` service and no Docker socket. Clang later is a layer in
the same image and a matrix axis, not a new tool. Pins live in
`docker/builder/toolchains.lock` (ARM GNU 10.3-2021.10 / 12.2.Rel1 /
13.2.Rel1), not distro `gcc-arm-none-eabi`.

`dry_run=true` returns the gcc or cmake command line and output path. It clones
nothing and compiles nothing. It does ask the builder `GET /health` so the
command line is for an identity the container actually has. Each artifact gets a `<artifact>.json` sidecar
(resolved commit SHA, the compiler's own `--version` line, sha256). `build_manifest`
skips a job when the artifact exists and that sidecar hash still matches; a
missing or mismatched sidecar rebuilds. Compiles that outlive `wait_seconds`
(default 45, max 55) return `{status: started, job_id}`; poll
`build_reference_status`.

Ask the container what it can compile before picking `toolchain` or `framework`:

```
builder_health()
```

- Ingest **with symbols**. Compile keeps DWARF (`-g`). `strip_debug=true`
  runs `strip --strip-debug` and keeps `.symtab` when disk is the
  constraint; the default is false. Framework mode never strips. A
  stripped binary adds signature noise and yields no names.
- Ingest finished analysis too. Each check-in becomes corpus for the next
  target.

Suggested `listexes` names: `<lib>-<version>-<compiler>-<optlevel>`, e.g.
`littlefs-v2.9.3-gcc13-arm-Os`.

Priority for this environment: littlefs, Frotz, pico-sdk, newlib, FreeRTOS.

## Long calls return a job, not an answer

Every BSim call spawns at least one fresh JVM, so even `bsim_list_corpus`
runs tens of seconds and ingest/query run minutes — longer than the
response budget of the HTTP hops in front of the server (an MCP gateway
or Cloudflare tunnel abandons the response around 60–100 s and fabricates
a bare `-32603 Internal Error` while the operation keeps running
invisibly). Each tool therefore takes `wait_seconds` (default 45, max
55): if the CLI finishes inside the wait you get the normal result; if
not you get

```
{"status": "started", "job_id": "bsim-3-1a2b", ...}
```

and the operation continues server-side. Poll:

```
bsim_job_status(job_id)          -> state: queued | running | done
bsim_job_status()                -> every retained job
```

When `state` is `done`, the `result` field holds exactly what the tool
would have returned inline (plus `ok: false` when that result is an
error). Expect the ticket path for every real ingest, query, and apply;
a `dry_run=true` response proves nothing about any of this — it returns
before the CLI runs.

## Tools

### `builder_health`

```
builder_health()
```

Packed identities, ARM GNU releases, and framework stubs from the builder
container (`GET /health`). This is what can be built. `build_reference` and
`build_manifest` refuse unknown names using this same list, not a Java
constant.

### `build_reference`

```
build_reference(name, repo, ref, sources=[], toolchain="gcc13-arm",
                 arch_flags="", opt="-Os",
                 defines=[], extra_flags=[], strip_debug=False,
                 output_name=None, dry_run=False,
                 mode="sources", framework=None, libraries=[],
                 board=None, config={}, wait_seconds=45)
```

`mode="sources"` (default) compiles named `.c` files and writes
`/data/uploads/<name>-<ref>-<toolchain>-<opt>.o`. `mode="framework"`
ignores `sources`, configures `docker/stubs/<framework>/` against the
cloned SDK, and harvests **build-tree** `.o`/`.a` files — never the
linked ELF. Names are
`<name>-<library>-<ref>-<toolchain>-<opt>[-<board>].o`. Returns a list
of artifacts (path, sha256, function_count, library). `libraries` empty
is an error. Zero harvested functions is a refuse (usually means the ELF
was harvested). `strip_debug` is forced false. `toolchain` is
`<compiler><major>-<target>` (gcc13-arm, clang17-arm). Blank `arch_flags`
uses the identity default. `ref` must be a tag or commit; `main` is
refused. Each artifact is written with `<artifact>.json`: resolved
commit SHA, the compiler's `--version` line, sha256. Framework mode
writes one sidecar per harvested library (`library`, `board`, `config`).
`dry_run=true` clones nothing, configures nothing, and compiles
nothing. It does call `builder_health` (GET /health) so an unknown
identity fails before a fake command line. A compile that outlives
`wait_seconds` returns `{status: "started", job_id}` — poll
`build_reference_status`.

### `build_manifest`

```
build_manifest(path="", dry_run=False, wait_seconds=45)
```

Expands `docker/references.yaml` (or a path under FILE_ROOT). Empty
`path` uses `/data/references.yaml` then the copy baked into the JAR.
Jobs whose artifact exists and whose sidecar sha256 still matches are
skipped. Delete the sidecar to force a rebuild. One shared `wait_seconds`
covers the matrix; leftovers are tickets. Userland:
`path="references.userland.yaml"` (mounted at
`/data/references.userland.yaml`). Both manifests ingest into
`postgresql://ghidra-bsim:5432/bsim` (`medium_nosize`). ARM and x86-64
share that database so cross-arch matches are queryable.
`bsim_query(arch=...)` constrains when you want same-arch only.

DWARF paths are `/ref/<name>/...`. In Ghidra, one Source Files transform
covers the corpus: `/ref/` -> `<local checkout root>/`. Sidecars record
`debug_path_prefix`, repo, and commit.

### `source_read`

```
source_read(artifact, function=None, path=None, start_line=0, end_line=0, context=20)
```

Reads pinned source from the builder git cache. `artifact` names the
corpus object; the sidecar supplies repo and commit. `function=` uses
that object's DWARF to pick a file and line range. `path=` reads a
repo-relative file (or a `/ref/<name>/...` DWARF path). Numbered lines,
capped at 800 with an explicit truncation marker. Missing commits name
the cache directory.

### `build_reference_status`

```
build_reference_status(job_id="")
```

Poll a builder job. Blank `job_id` lists retained jobs.

### `bsim_create_db`

```
bsim_create_db(db_url, config_template="medium_nosize", name=None, description=None,
               callgraph=True, wait_seconds=45)
```

`postgresql://ghidra-bsim:5432/bsim` (`medium_nosize`) is the compose
database. ARM firmware and x86-64 userland share it. GUI clients on the
VPN use `postgresql://<BIND_ADDR>:5432/bsim` with
`BSIM_DB_USER` / `BSIM_DB_PASSWORD`. `file:` H2 URLs remain for leftover
local files. Network URLs must be on
`GHIDRA_MCP_BSIM_URLS` (fail-closed). `medium_nosize` is the template for
every database, unconditionally: it beat `medium_32` under compiler and
optimisation drift and gave up nothing on identical builds. `callgraph=True`
is the default because call-graph data is the one thing that actually helped
in the failed littlefs attempt. `dry_run=true` returns `would_execute` and
does not create the database. Writes `<name>.ghidra-mcp.json` (next to an H2
file, or under `GHIDRA_MCP_BSIM_ROOT` for postgres) so `bsim_list_databases`
can report the template. Sized templates (`medium_32` / `medium_64`) still
exist; ingest refuses a pointer-size mismatch against those because Ghidra
will otherwise accept it and silently degrade results.

### `bsim_list_databases`

```
bsim_list_databases()
```

Lists allowlisted `postgresql://` URLs (`GHIDRA_MCP_BSIM_URLS`) and any
leftover H2 files under `GHIDRA_MCP_BSIM_ROOT`, plus the known config
templates. Does not spawn the bsim CLI. Querying a sized template
(`medium_32` / `medium_64`) against the wrong pointer size returns a
warning, not a confusing error. `medium_nosize` does not.

### `bsim_ingest`

```
bsim_ingest(db_url, source, xml_dir=None, commit=True, overwrite=False, wait_seconds=45)
```

`source` is a `ghidra://` server path, a local `ghidra:/` project, a
repository path starting with `/` (needs `GHIDRA_SERVER_HOST`), or the
name of an open program. `program=` is not required — `source` is the
target. A `ghidra://` URL needs `GHIDRA_SERVER_PASSWORD` (the spawned
`bsim` JVM cannot prompt); missing it is a named, immediate error, not a
blank failure. When the credential is present the server passes
`--user` and feeds the password to the child on stdin — the spawned JVM
is stock Ghidra, which never reads this extension's environment
variables, and its `HeadlessClientAuthenticator` falls back to a stdin
prompt when there is no console. An invalid `source` is refused
synchronously with the remedy. A program with no functions is refused. A
pointer-size mismatch against a sized template (`medium_32` / `medium_64`
/ `large_32`) is refused — the CLI would otherwise accept it and degrade
silently. `medium_nosize` accepts mixed sizes. Identical-MD5 re-ingest is
skipped (BSim keys on MD5 but records the throwaway project URL). The
response carries `executable_md5` for the artifact sidecar. A compiler-spec
change on the same bytes (windows → gcc) still collides; that needs a new
database, not a re-ingest. A stripped program is
ingested with a warning. On PostgreSQL, ingest also writes per-function
constants, strings and direct callees into the companion `corroboration`
schema (same database, not BSim's tables). Identical-MD5 skip still writes
that row when the program is open — that is the backfill path. Ingest takes
minutes: expect the job ticket, and
verify by polling `bsim_job_status` and re-running `bsim_list_corpus` —
never by `dry_run`. The staged GZF keeps the program name, so
`bsim_list_corpus` shows `littlefs-v2.9.3-gcc13-arm-Os`, not `"program"`.

### `bsim_query`

```
bsim_query(db_url, program, function=None, similarity_threshold=0.0,
           confidence_threshold=10.0, max_matches=10, arch=None,
           executable=None, compiler=None, exclude_md5=None,
           min_feature_count=8, min_function_size=0, wait_seconds=45,
           corroborate=False, corroborate_max_candidates=3)
```

Filter on confidence, not similarity. Cross-compiler matches
legitimately score 0.2–0.4 similarity; confidence indicates whether that
overlap is meaningful. The old default (`similarity_threshold=0.7`)
returned nothing against a differently-compiled reference. 10.0 is a
starting floor from one littlefs cross-build, not a calibration.

`arch`, `executable`, `compiler`, and `exclude_md5` are server-side
`BSimFilter` atoms (the same types the GUI search dialog uses). They are
not applied after `max_matches`. Whole-program queries pass `ALL`, never
`-` — a bare dash is eaten by `analyzeHeadless` and the threshold falls
back to 0.7.

Functions too small to identify (near-empty feature vectors; measured
stubs matching a 24-byte wrapper at similarity 1.0, confidence 9.2) are
**returned** with `identifiable=false` and a `reason` that names the
measured feature count and the threshold. Query is investigation and
must not hide data.

Every match has `similarity` and `confidence` as separate numbers, plus
the source executable name and architecture. If the top two
differently-named hits are within 0.05 similarity, `ambiguous` is true.
A `similarity_threshold` above 0.5 adds a warning: it will silently
drop the matches this feature exists to find.

A short generic function (an accessor, a thunk) can still score high
similarity. It should come back with **low confidence** and
`identifiable=false` when the vector is too small. That split is
the whole feature.

`bsim_apply_matches` still requires an explicit `min_confidence`. Its
query-time `similarity_threshold` now defaults to 0.0, same as query.
It skips unidentifiable functions unless `apply_unidentifiable=true`.

`corroborate=true` attaches constants/strings/callee evidence to
ambiguous, unidentifiable, or low-confidence hits (best confidence below
20). It never reorders matches. BSim ranking stays BSim's.

### `corroborate_match`

```
corroborate_match(program, function, db_url, ref_executable, ref_function,
                  string_normalisation="auto")
```

The query side is extracted live from the open program. The reference
side comes from the `corroboration` schema written at ingest. **No
reference program is opened.** Returns shared / query-only / ref-only
constants and strings, shared direct callees, and notes. Distinctiveness
is judged at query time from corpus frequency. There is no blended
score.

`string_normalisation`: `off` (exact), `basename` (final path component
when both look like paths), `auto` (exact first, then basename). A
basename match reports both originals — firmware `__FILE__` paths and
`-fdebug-prefix-map` `/ref/…` paths are the same file. Format strings
match exactly.

A lookup miss (executable ingested before this feature, or a leftover
H2 `file:` URL) is `status: no_evidence`, not an error.

### `bsim_apply_matches`

```
bsim_apply_matches(db_url, program, min_confidence=<required>,
                   min_similarity=0.8, skip_named=True, dry_run=True,
                   similarity_threshold=0.0, arch=None, executable=None,
                   compiler=None, exclude_md5=None, min_feature_count=8,
                   apply_unidentifiable=False, wait_seconds=45)
```

`min_confidence` has no default. Pick one from query results on
functions you already trust, after unidentifiable functions are out of
the set — a floor around 10 then becomes meaningful again. `dry_run=True`
is the default and does not call `setName`. `skip_named=True` will not
overwrite an analyst's name. An `ambiguous` result is never applied,
whatever the scores. Unidentifiable functions are skipped and counted
unless `apply_unidentifiable=true`.

Applied names are the BSim hit names as-is (C linkage, not PascalCase).
`lfs_bd_read` is the right name here.

### `bsim_list_corpus`

```
bsim_list_corpus(db_url, arch=None, name=None, limit=100, wait_seconds=45)
```

What is actually in the database. A corpus you cannot inspect is one you
stop trusting.

### `bsim_job_status`

```
bsim_job_status(job_id="")
```

Status and result of a background BSim operation; blank `job_id` lists
every retained job (the last 64). The embedded `result` for a `done` job
is identical to what the originating tool would have returned inline.
Every CLI start/exit and job transition is also logged server-side, so a
call abandoned by an upstream gateway still leaves evidence in the
`ghidra-mcp` container log.

## Deployment

PostgreSQL, one instance, one database (`bsim`). H2 `file:` URLs cannot
be opened from a Ghidra GUI on another machine; the interactive search
dialog needs a network service. A stock `postgres` image will not work —
BSim's schema needs the `lshvector` C extension (image `ghidra-mcp-bsim`,
sources pinned in `docker/bsim/lshvector.lock` to Ghidra 12.1.2). Do not
use `support/bsim_ctl`. SSL is mandatory: Ghidra refuses a non-SSL
connection. The service is on `BIND_ADDR:5432` (VPN/LAN, same posture as
Ghidra Server RMI) and on the compose network as `ghidra-bsim`. It is
not on the Cloudflare tunnel.

```
postgresql://<BIND_ADDR>:5432/bsim   # medium_nosize, ARM and x86-64
```

Login is `BSIM_DB_USER` / `BSIM_DB_PASSWORD` in `docker/.env`. Not the
Ghidra Server account. `GHIDRA_MCP_BSIM_URLS` is the allowlist; a
`db_url` off that list is a specific error, not a silent outbound
connection. Passwords stay in the environment, never in the URL.

`GHIDRA_MCP_BSIM_ROOT=/srv/ghidra/bsim` still confines leftover `file:`
URLs and holds template sidecars. `bsim-backup` runs `pg_dump` of every
user database and tars `ghidra-repos`.

Migration (stand up → `bsim_create_db` → re-ingest artifacts →
`bsim_list_corpus` → retire H2): `docker/bsim/MIGRATION.md`. Do not
convert H2 files.

If `ghidra.cacerts` is already set for Ghidra Server TLS, import
`ghidra-bsim`'s `server.crt` into that store or GUI clients fail PKIX.
The default (unset `ghidra.cacerts`) accepts the self-signed cert.

## What this is not

`find_similar_functions_fuzzy` / `bulk_fuzzy_match` are still there.
They remain a structural heuristic with one score. Do not use them to
name a library inside firmware. Do not treat a BSim ranked list as a
name either: read confidence, and stop when `ambiguous` is set.
