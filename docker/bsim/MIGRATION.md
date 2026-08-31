# H2 → PostgreSQL BSim migration

Signatures are derived data. Do not convert the H2 files. Re-ingest the
artifacts already on `/data` (and their `.json` sidecars). Regenerating
from source is hours of compile work that grows with every corpus entry;
this path reuses what is already on disk.

Ghidra Server does not host or proxy BSim. Analysts on the VPN talk to
PostgreSQL directly. Credentials are `BSIM_DB_USER` / `BSIM_DB_PASSWORD`
in `docker/.env`. They are **not** the Ghidra Server login.

## GUI / MCP URLs

| Database | Template | Architecture | URL on the VPN/LAN | URL on the compose network |
|---|---|---|---|---|
| `embedded` | `medium_nosize` | ARM Cortex-M firmware | `postgresql://<BIND_ADDR>:5432/embedded` | `postgresql://ghidra-bsim:5432/embedded` |
| `userland` | `medium_nosize` | x86-64 Linux | `postgresql://<BIND_ADDR>:5432/userland` | `postgresql://ghidra-bsim:5432/userland` |

Both databases use `medium_nosize`. The split is corpus domain (firmware vs
userland), not pointer size. Mixing ARM with x86-64 in one `medium_nosize`
database is harmless; keep them separate because native x86-64 references
cannot substitute for ARM ones (`lfs_bd_read` scored 1.24 cross-architecture
against 41.83 same-architecture). `bsim_query(arch=...)` constrains a mixed
database when you want that. Sized templates (`medium_32` / `medium_64`) still
exist: Ghidra will silently accept a pointer-size mismatch there and quietly
degrade results, so ingest refuses it.

Templates are fixed at `createdatabase` time. Querying the wrong *domain*
returns low-confidence cross-architecture hits, not a broken tool.

Same URLs in Window → BSim → Manage Servers (or the search dialog) as
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

3. Create both PostgreSQL databases. `db_url` must be on
   `GHIDRA_MCP_BSIM_URLS` (compose already lists the four host/db
   combinations). Expect a job ticket; poll `bsim_job_status`.

   ```text
   bsim_create_db(db_url="postgresql://ghidra-bsim:5432/embedded",
                  config_template="medium_nosize", name="embedded")
   bsim_create_db(db_url="postgresql://ghidra-bsim:5432/userland",
                  config_template="medium_nosize", name="userland")
   ```

4. Re-ingest every reference already imported. Do not rebuild. For each
   program (or folder) that `bsim_list_corpus` showed on H2:

   ```text
   bsim_ingest(db_url="postgresql://ghidra-bsim:5432/embedded",
               source="ghidra://<BIND_ADDR>/.../<program>")
   ```

   Use `userland` for the x86-64 corpus. Dual stdin is Ghidra Server
   password, then BSim password; both come from the environment.
   Skip by executable MD5 before calling `bsim_ingest` on a re-run:
   identical bytes plus a throwaway project path is "same MD5, different
   repository", and `overwrite=true` does not bypass it. The ingest
   response carries `executable_md5` for the artifact sidecar.

5. Compare counts:

   ```text
   bsim_list_corpus(db_url="postgresql://ghidra-bsim:5432/embedded")
   bsim_list_corpus(db_url="postgresql://ghidra-bsim:5432/userland")
   ```

   They must match the H2 counts from step 2. Then retire the H2 files
   on the `ghidra-bsim` volume (`*.mv.db`). Keep the volume: template
   sidecars (`<name>.ghidra-mcp.json`) still live there.

6. Backup: `bsim-backup` writes `pg_dump -Fc` of `embedded` and
   `userland` under the `bsim-backups` volume, plus a tar of
   `ghidra-repos` when that mount is present. Restore to a scratch
   database and compare `bsim_list_corpus`:

   ```bash
   docker exec ghidra-bsim createdb -U bsim embedded_scratch
   dump=$(docker exec ghidra-bsim-backup sh -c 'ls -1 /backups/embedded-*.dump | tail -1')
   docker exec -e PGSSLMODE=require ghidra-bsim-backup \
     pg_restore -h ghidra-bsim -U bsim -d embedded_scratch "$dump"
   ```

   Then `bsim_list_corpus` against a temporarily allowlisted scratch URL.
   Counts must match. Dumps live on `ghidra-bsim-backup` at `/backups`,
   not in the Postgres container.

7. GUI: on a workstation on the VPN, add
   `postgresql://<BIND_ADDR>:5432/embedded` (or `userland`) with
   `BSIM_DB_USER` / `BSIM_DB_PASSWORD`. Run Find Similar Functions on a
   function the MCP tools already queried; the match list must agree.

8. Confirm SSL is enforced: `PGSSLMODE=disable psql -h <BIND_ADDR> ...`
   must fail. Confirm the Cloudflare tunnel cannot reach 5432.

Do not use `support/bsim_ctl`. The image compiles `lshvector` against
upstream `postgres:16`.
