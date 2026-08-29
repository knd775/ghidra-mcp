# BSim cross-build matching

Five MCP tools wrap Ghidra's `bsim` CLI. They do not invent a matching
algorithm. Byte/opcode hashes fail across GCC versions. The older fuzzy
matcher produced ranked lists that looked authoritative and were not:
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
nothing to download for embedded targets. Build the corpus:

- Compile the same library at several optimisation levels and compiler
  versions. `-Os`, `-O2`, `-O3` across two or three GCC releases. That
  drift is exactly what defeated hashing.
- Ingest **with symbols**. A stripped binary adds signature noise and
  yields no names. That is the usual way to waste a day.
- Ingest finished analysis too. Each check-in becomes corpus for the next
  target.

Suggested `listexes` names: `<lib>-<version>-<compiler>-<optlevel>`, e.g.
`littlefs-2.9.3-gcc13-Os`.

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
bsim_query(db_url, program, function=None, similarity_threshold=0.7,
           confidence_threshold=0.0, max_matches=10, wait_seconds=45)
```

Every match has `similarity` and `confidence` as separate numbers, plus
the source executable name and architecture. If the top two
differently-named hits are within 0.05 similarity, `ambiguous` is true.

A short generic function (an accessor, a thunk) can still score high
similarity. It should come back with **low confidence**. That split is
the whole feature. If it does not, BSim is not solving this problem and
the tools should not be used to rename anything.

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
