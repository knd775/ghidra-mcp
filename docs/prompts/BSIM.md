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
server. H2 databases are single-writer; the server serialises BSim calls.

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

- Ingest **with symbols**. `strip_debug` keeps `.symtab`. Framework mode never
  strips. A stripped binary adds signature noise and yields no names.
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
                 defines=[], extra_flags=[], strip_debug=True,
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
covers the matrix; leftovers are tickets.

### `build_reference_status`

```
build_reference_status(job_id="")
```

Poll a builder job. Blank `job_id` lists retained jobs.

### `bsim_create_db`

```
bsim_create_db(db_url, config_template="medium_32", name=None, description=None,
               callgraph=True, wait_seconds=45)
```

`file:/srv/ghidra/bsim/littlefs` is an H2 file. No extra service, one
writer. Use PostgreSQL when two processes need to write. `medium_32` is
the template for 32-bit ARM firmware. `callgraph=True` is the default
because call-graph data is the one thing that actually helped in the
failed littlefs attempt. `dry_run=true` returns `would_execute` and does
not create the database.

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
64-bit program into a corpus that is already 32-bit is refused (the CLI
would otherwise accept it and degrade silently). A stripped program is
ingested with a warning. Ingest takes minutes: expect the job ticket, and
verify by polling `bsim_job_status` and re-running `bsim_list_corpus` —
never by `dry_run`.

### `bsim_query`

```
bsim_query(db_url, program, function=None, similarity_threshold=0.0,
           confidence_threshold=10.0, max_matches=10, wait_seconds=45)
```

Filter on confidence, not similarity. Cross-compiler matches
legitimately score 0.2–0.4 similarity; confidence indicates whether that
overlap is meaningful. The old default (`similarity_threshold=0.7`)
returned nothing against a differently-compiled reference. 10.0 is a
starting floor from one littlefs cross-build, not a calibration.

Every match has `similarity` and `confidence` as separate numbers, plus
the source executable name and architecture. If the top two
differently-named hits are within 0.05 similarity, `ambiguous` is true.
A `similarity_threshold` above 0.5 adds a warning: it will silently
drop the matches this feature exists to find.

A short generic function (an accessor, a thunk) can still score high
similarity. It should come back with **low confidence**. That split is
the whole feature. If it does not, BSim is not solving this problem and
the tools should not be used to rename anything.

`bsim_apply_matches` still requires an explicit `min_confidence` and
still queries at `similarity_threshold=0.7` / `min_similarity=0.8`
unless you pass those. Cross-build apply needs the same 0.0 similarity
floor as query; do not copy the apply defaults onto query.

### `bsim_apply_matches`

```
bsim_apply_matches(db_url, program, min_confidence=<required>,
                   min_similarity=0.8, skip_named=True, dry_run=True, wait_seconds=45)
```

`min_confidence` has no default. Pick one from query results on
functions you already trust. `dry_run=True` is the default and does not
call `setName`. `skip_named=True` will not overwrite an analyst's name.
An `ambiguous` result is never applied, whatever the scores.

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

H2 to start:

```
file:/srv/ghidra/bsim/<db>
```

The directory must be writable by uid 1000 and sit on its own volume. It
is not covered by `GHIDRA_MCP_FILE_ROOT`. Compose mounts
`ghidra-bsim:/srv/ghidra/bsim`. Set `GHIDRA_MCP_BSIM_ROOT=/srv/ghidra/bsim`
so a `file:` URL cannot wander.

Back it up. Regenerating a corpus means recompiling everything in it.

PostgreSQL later, via `bsim_ctl`, when more than one writer is needed.

## What this is not

`find_similar_functions_fuzzy` / `bulk_fuzzy_match` are still there.
They remain a structural heuristic with one score. Do not use them to
name a library inside firmware. Do not treat a BSim ranked list as a
name either: read confidence, and stop when `ambiguous` is set.
