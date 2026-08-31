# H2 → PostgreSQL BSim migration

Signatures are derived data. Do not convert the H2 files. Re-ingest the
artifacts already on `/data` (and their `.json` sidecars). Regenerating
from source is hours of compile work that grows with every corpus entry;
this path reuses what is already on disk.

Ghidra Server does not host or proxy BSim. Analysts on the VPN talk to
PostgreSQL directly. Credentials are `BSIM_DB_USER` / `BSIM_DB_PASSWORD`
in `docker/.env`. They are **not** the Ghidra Server login.

## GUI / MCP URLs

| Database | Template | Contents | URL on the VPN/LAN | URL on the compose network |
|---|---|---|---|---|
| `bsim` | `medium_nosize` | ARM firmware and x86-64 Linux | `postgresql://<BIND_ADDR>:5432/bsim` | `postgresql://ghidra-bsim:5432/bsim` |

One database. Cross-arch matches happen and are useful; constrain a
query with `bsim_query(arch=...)` when you want same-arch only. Sized
templates (`medium_32` / `medium_64`) still exist: Ghidra will silently
accept a pointer-size mismatch there and quietly degrade results, so
ingest refuses it.

Templates are fixed at `createdatabase` time.

Corroboration evidence (`constants`, strings, direct callees) lives in
schema `corroboration` in the same database. `bsim createdatabase` does
not create or drop it. `pg_dump` of `bsim` includes it. Existing corpus
rows ingested before this feature have no extract; a lookup is
`no_evidence`, not an error. Re-ingest of the same MD5 is refused by
BSim, so backfill is: open the program and call `bsim_ingest` again
(the skip path still writes corroboration), or start a fresh database
before the corpus grows.

Same URL in Window → BSim → Manage Servers (or the search dialog) as
the MCP tools use. SSL is required; Ghidra hard-codes `sslmode=require`.
A self-signed cert is enough **unless** `ghidra.cacerts` is already set
for Ghidra Server TLS — then import `ghidra-bsim`'s `server.crt` into
that store too, or the client fails PKIX.

## Steps

1. Set `BSIM_DB_PASSWORD` in `docker/.env` (`openssl rand -hex 24`).
   Stand up the stack so `ghidra-bsim` is healthy:

   ```bash
   docker compose --env-file docker/.env -f docker/docker-compose.yml up -d ghidra-bsim
   docker exec ghidra-bsim psql -U bsim -d postgres -c 'CREATE EXTENSION lshvector;'
   ```

   That last command is acceptance 0. Stop if it fails.

2. Record pre-migration counts from the H2 files (if they still exist).
   **Before migrating `file:/srv/ghidra/bsim/re`**, list its architectures.
   A `medium_32` database named `re` was polluted with 64-bit signatures via
   the Ghidra CLI on a separate stack; the name collides with the live
   database. If `bsim_list_corpus` shows any 64-bit `arch`, do not migrate
   that file — recreate as `medium_nosize` and re-ingest from artifacts.
   A polluted corpus produces quietly wrong confidence, and the template
   is changing to `medium_nosize` anyway.

   ```text
   bsim_list_corpus(db_url="file:/srv/ghidra/bsim/<old>")
   bsim_list_corpus(db_url="file:/srv/ghidra/bsim/re")
   ```

3. Create the PostgreSQL database. `db_url` must be on
   `GHIDRA_MCP_BSIM_URLS` (compose lists compose DNS and `BIND_ADDR`).
   Expect a job ticket; poll `bsim_job_status`.

   ```text
   bsim_create_db(db_url="postgresql://ghidra-bsim:5432/bsim",
                  config_template="medium_nosize", name="bsim")
   ```

4. Re-ingest every reference already imported. Do not rebuild. For each
   program (or folder) that `bsim_list_corpus` showed on H2:

   ```text
   bsim_ingest(db_url="postgresql://ghidra-bsim:5432/bsim",
               source="ghidra://<BIND_ADDR>/.../<program>")
   ```

   Dual stdin is Ghidra Server password, then BSim password; both come
   from the environment. Skip by executable MD5 before calling
   `bsim_ingest` on a re-run: identical bytes plus a throwaway project
   path is "same MD5, different repository", and `overwrite=true` does
   not bypass it. The ingest response carries `executable_md5` for the
   artifact sidecar.

5. Compare counts:

   ```text
   bsim_list_corpus(db_url="postgresql://ghidra-bsim:5432/bsim")
   ```

   They must match the H2 counts from step 2. Then retire the H2 files
   on the `ghidra-bsim` volume (`*.mv.db`). Keep the volume: template
   sidecars (`<name>.ghidra-mcp.json`) still live there.

6. Backup: `bsim-backup` writes `pg_dump -Fc` of every non-template
   database under the `bsim-backups` volume, plus a tar of
   `ghidra-repos` when that mount is present. Restore to a scratch
   database and compare `bsim_list_corpus`:

   ```bash
   docker exec ghidra-bsim createdb -U bsim bsim_scratch
   dump=$(docker exec ghidra-bsim-backup sh -c 'ls -1 /backups/bsim-*.dump | tail -1')
   docker exec -e PGSSLMODE=require ghidra-bsim-backup \
     pg_restore -h ghidra-bsim -U bsim -d bsim_scratch "$dump"
   ```

   Then `bsim_list_corpus` against a temporarily allowlisted scratch URL.
   Counts must match. Dumps live on `ghidra-bsim-backup` at `/backups`,
   not in the Postgres container.

7. GUI: on a workstation on the VPN, add
   `postgresql://<BIND_ADDR>:5432/bsim` with
   `BSIM_DB_USER` / `BSIM_DB_PASSWORD`. Run Find Similar Functions on a
   function the MCP tools already queried; the match list must agree.

8. Confirm SSL is enforced: `PGSSLMODE=disable psql -h <BIND_ADDR> ...`
   must fail. Confirm the Cloudflare tunnel cannot reach 5432.

## Folding `embedded` + `userland` into `bsim`

Compose used to ship two databases (corpus-domain split). They are one
database now. You cannot `pg_restore` two BSim dumps into one database
(sequences and primary keys collide). Re-ingest, or rename the larger
side and ingest the other.

### Rename then ingest (keeps the larger side)

If `embedded` already has the ARM corpus:

1. Disconnect GUI BSim clients. Rename before or immediately after
   deploying the new allowlist (compose lists `bsim` only):

   ```bash
   docker exec ghidra-bsim psql -U bsim -d postgres \
     -c 'ALTER DATABASE embedded RENAME TO bsim;'
   docker exec ghidra-mcp sh -c \
     'test -f /srv/ghidra/bsim/embedded.ghidra-mcp.json && \
      mv /srv/ghidra/bsim/embedded.ghidra-mcp.json \
         /srv/ghidra/bsim/bsim.ghidra-mcp.json || true'
   ```

   Edit the sidecar's `db_url` to `postgresql://ghidra-bsim:5432/bsim`
   if it stores one. `bsim_create_db` will rewrite it on a later call;
   a rename does not.

2. `bsim_ingest` every userland artifact (or `ghidra://` program) into
   `postgresql://ghidra-bsim:5432/bsim`. Skip by executable MD5.

3. `docker exec ghidra-bsim dropdb -U bsim userland`

4. Point GUI bookmarks at `postgresql://<BIND_ADDR>:5432/bsim`.

If `userland` is the larger side, rename that one instead.

### Fresh `bsim`

```text
bsim_create_db(db_url="postgresql://ghidra-bsim:5432/bsim",
               config_template="medium_nosize", name="bsim")
```

Then `bsim_ingest` every artifact from both old corpora. Compare
`bsim_list_corpus` counts to the sum of the old databases. Drop
`embedded` and `userland`.

Do not use `support/bsim_ctl`. The image compiles `lshvector` against
upstream `postgres:16`.
