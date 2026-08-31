# GhidraMCP Headless Server - Docker Deployment

The compose file on this branch is the stack this fork actually runs:
Ghidra Server (RMI) + headless MCP + Python bridge + BSim PostgreSQL +
a Cloudflare Tunnel. There is no Traefik in this file.

> **Security.** The headless server binds `0.0.0.0` inside the container.
> Host publish of 8089/8081 is loopback only. Remote MCP is the tunnel
> (`http://ghidra-mcp:8081` on the compose network). Set
> `GHIDRA_MCP_AUTH_TOKEN` (the process will not start on a non-loopback
> bind without it) and put the tunnel hostname in
> `GHIDRA_MCP_ALLOWED_HOSTS`. The tunnel is not authentication; put an
> Access policy on the origin and leave Access Managed OAuth off.
>
> ```bash
> openssl rand -hex 32   # GHIDRA_MCP_AUTH_TOKEN
> ```
>
> The image runs as uid 1000 (`ghidra`). The bridge shares that namespace
> as uid 1000 (`bridge`).
>
> BSim PostgreSQL is published on `BIND_ADDR:5432` (VPN/LAN, same
> posture as Ghidra Server RMI) and is **not** on the tunnel network.
> A stock `postgres` image will not work; this stack uses
> `ghidra-mcp-bsim` (`lshvector` + SSL).

## Quick Start

```bash
cp docker/.env.template docker/.env   # fill it
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
curl -H "Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN" \
  http://127.0.0.1:8089/check_connection
```

Local MCP is `http://127.0.0.1:8081/mcp`. Ghidra Server RMI is on
`BIND_ADDR:13100-13102` (not loopback, not 0.0.0.0). BSim is on
`BIND_ADDR:5432`.

`docker-compose.multi.yml` is a leftover nginx scale-out sketch. It is
not this stack.

## Building

### Build Docker Image

```bash
# From project root — Java headless server
docker build -t ghcr.io/knd775/ghidra-mcp-headless:dev -f docker/Dockerfile .

# Python MCP bridge (python:3.12-slim)
docker build -t ghcr.io/knd775/ghidra-mcp-bridge:dev -f docker/Dockerfile.bridge .

# Reference builder (ARM GNU prefixes + distro gcc-13). First build
# downloads the pinned tarballs; after that, pull from GHCR.
docker build -t ghcr.io/knd775/ghidra-mcp-builder:dev -f docker/Dockerfile.builder .

# BSim PostgreSQL (lshvector C extension + SSL). Sparse-clones Ghidra
# 12.1.2 for the extension sources; do not use support/bsim_ctl.
docker build -t ghcr.io/knd775/ghidra-mcp-bsim:dev -f docker/Dockerfile.bsim .
```

Or `docker compose -f docker/docker-compose.yml build`.

Images are also published to GHCR on push to `main`/`dev`/`develop`:

```text
ghcr.io/<owner>/ghidra-mcp-headless
ghcr.io/<owner>/ghidra-mcp-bridge
ghcr.io/<owner>/ghidra-mcp-builder
ghcr.io/<owner>/ghidra-mcp-bsim
```

The bridge must share the headless network namespace.
`GHIDRA_MCP_URL=http://127.0.0.1:8089`. Do not use a Docker DNS name.


### Build with Maven

```bash
# Build headless JAR
mvn clean package -P headless -DskipTests

# Build Docker image via Maven
mvn clean package -P docker -DskipTests
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_PORT` | `8089` | Headless HTTP port inside the container |
| `JAVA_OPTS` | `-Xmx8g -XX:+UseG1GC` | JVM options |
| `GHIDRA_MCP_AUTH_TOKEN` | required | Bearer token; required for the 0.0.0.0 bind |
| `GHIDRA_MCP_FILE_ROOT` | `/data` | Samples bind (`SAMPLES_DIR`) |
| `GHIDRA_MCP_STUBS` | `/opt/ghidra-builder/stubs` | Framework stub projects for `mode=framework` |
| `GHIDRA_MCP_BUILDER_URL` | `http://ghidra-builder:8092` | One builder, every identity. Internal network only. |
| `GHIDRA_MCP_BSIM_ROOT` | `/srv/ghidra/bsim` | Confines leftover `file:` BSim URLs and holds template sidecars. Dedicated volume, not under `/data`. |
| `GHIDRA_MCP_BSIM_URLS` | compose DNS + `BIND_ADDR` for `embedded` and `userland` | Allowlist of `postgresql://` BSim URLs. Fail-closed: unset rejects every network `db_url`. |
| `GHIDRA_MCP_BSIM_USER` | `BSIM_DB_USER` | PostgreSQL role. Not the Ghidra Server account. |
| `GHIDRA_MCP_BSIM_PASSWORD` | `BSIM_DB_PASSWORD` | PostgreSQL password. Never put this in `db_url`. |
| `GHIDRA_MCP_BSIM_TEMPLATES` | `embedded:medium_nosize,userland:medium_nosize` | Name → config template when no sidecar exists. |
| `BSIM_DB_USER` / `BSIM_DB_PASSWORD` | `bsim` / required | Postgres role for `ghidra-bsim`. |
| `GHIDRA_SERVER_HOST` | `BIND_ADDR` | RMI address the headless client dials |
| `BIND_ADDR` | required | Host IP for RMI publish, BSim 5432, and `-ip` |
| `GHIDRA_MCP_ALLOWED_HOSTS` | required | Tunnel hostname for the bridge Host check |
| `TUNNEL_TOKEN` | required | Cloudflare dashboard tunnel token |
| `PROGRAM_FILE` | - | Path to binary file to load on startup |
| `PROJECT_PATH` | - | Path to Ghidra project directory |

### Volumes

| Volume / bind | Container Path | Description |
|--------|---------------|-------------|
| `SAMPLES_DIR` (host path) | `/data` | Binaries / `GHIDRA_MCP_FILE_ROOT` |
| `ghidra-repos` | `/repos` | Ghidra Server project history; `bsim-backup` tars this |
| `ghidra-mcp-home` | `/home/ghidra` | `$HOME/.ghidra` settings |
| `ghidra-mcp-projects` | `/projects` | Local (non-repo) project data |
| `ghidra-bsim` | `/srv/ghidra/bsim` | Leftover H2 files and `<db>.ghidra-mcp.json` sidecars. Writable by uid 1000. |
| `ghidra-bsim-pgdata` | `/var/lib/postgresql/data` | PostgreSQL data for `embedded` + `userland`. Hours of ingest; back this up. |
| `ghidra-bsim-certs` | `/var/lib/postgresql/certs` | Self-signed server cert. Key is `0600` `postgres`. |
| `bsim-backups` | `/backups` (backup sidecar) | `pg_dump -Fc` of both databases, plus `ghidra-repos` tars. |
| `builder-src-cache` | `/src` (builder) | Bare git clones for `build_reference`. Persists so a second build of the same ref does not re-clone. |
| `docker/references.yaml` | `/data/references.yaml` | Embedded ARM corpus (`postgresql://ghidra-bsim:5432/embedded`, `medium_nosize`). `build_manifest` with no path reads this. |
| `docker/references.userland.yaml` | `/data/references.userland.yaml` | x86-64 userland corpus (`.../userland`, `medium_nosize`). `build_manifest(path="references.userland.yaml")`. |
| `docker/stubs/` | `/opt/ghidra-builder/stubs` | Framework stub projects (`pico-sdk` shipped). Listed by `mode=framework` validation. |

## BSim PostgreSQL

H2 `file:` databases are local and single-writer. Analysts connected to
Ghidra Server over RMI have no path to a file inside a container, so
interactive "Find Similar Functions" was unavailable. Ghidra Server does
not host or proxy BSim.

`ghidra-bsim` is PostgreSQL 16 with Ghidra's `lshvector` extension
compiled in (`docker/Dockerfile.bsim`, sources fetched from the Ghidra
12.1.2 tag and blob-checked against `docker/bsim/lshvector.lock`). SSL
is on; `hostnossl` is `reject`. Two databases on the one instance:

| Database | Template | Contents |
|---|---|---|
| `embedded` | `medium_nosize` | ARM Cortex-M references |
| `userland` | `medium_nosize` | x86-64 Linux references |

The split is corpus domain, not pointer size. Mixing architectures in one
`medium_nosize` database is harmless; keep them separate because native
x86-64 references cannot substitute for ARM ones. Constraining a mixed
database is `bsim_query(arch=...)`.

GUI URL: `postgresql://<BIND_ADDR>:5432/<database>`. Login is
`BSIM_DB_USER` / `BSIM_DB_PASSWORD`, not the Ghidra Server account.
If `ghidra.cacerts` is already set for Ghidra Server TLS, import
`server.crt` from the certs volume or GUI clients fail PKIX.

Do not use `support/bsim_ctl`. Migration (re-ingest, do not convert H2):
`docker/bsim/MIGRATION.md`. Operator guide: `docs/prompts/BSIM.md`.

## Reference builder

The Ghidra image has no compiler and runs as uid 1000. Reference libraries
are compiled in one always-on `ghidra-builder` container that holds
gcc10-arm, gcc12-arm, gcc13-arm, and gcc13-x86_64 (the identity
`<compiler><major>-<target>` selects the binary; it is not an image tag).
It listens on the compose network only — no host ports, no Docker socket
in any service. `build_reference` POSTs a job and polls; objects land on
the shared `/data/uploads` mount as uid 1000, and `import_file` loads that
path. `SAMPLES_DIR` on the host must be writable by uid 1000 — the same
constraint as ghidra-mcp. There is no auth on the builder: the listener
is not published off the compose network. `GET /health` is what the
image healthcheck probes, and what MCP `builder_health` returns. ARM
identities are pinned GNU tarballs (`docker/builder/toolchains.lock`),
copied from a fetch stage so the download never sits in a final layer.
`gcc13-x86_64` is distro gcc-13 on a Debian trixie runtime (tens of MB,
not another ARM prefix). Distro `gcc-arm-none-eabi` is not used.
Framework builds also need host `gcc`/`g++` (pico-sdk's pioasm is a
nested host compile), `cmake`, and `ninja-build`. Stubs live in
`docker/stubs/<framework>/` (shipped: `pico-sdk`, `musl`, `glibc`,
`openssl`, `libsodium`, `sqlite`) and are copied into the image at
`/opt/ghidra-builder/stubs`. Adding `stubs/zephyr/` is another directory,
not a new MCP parameter. `mode=framework` harvests `.o`/`.a` from the
build tree, never the linked ELF.

Artifacts are compiled with `-g`. DWARF paths are rewritten to
`/ref/<name>/...` (sidecar field `debug_path_prefix`). In Ghidra,
Window -> Source Files and Transforms, one rule covers the corpus:

```
/ref/  ->  <local checkout root>/
```

Clone the repo at the sidecar's commit, or share the builder `/src`
cache read-only. `source_read` does the lookup through the builder.

Portainer (or `docker compose up -d`) pulls `ghidra-mcp-builder` from GHCR
with the rest of the stack. The compose DNS name is still `ghidra-builder`.
Rebuild locally only when you are changing the Dockerfile or prefixes.
Corpus updates are MCP tools: `builder_health`, `build_manifest`,
`build_reference`, `build_reference_status`, `source_read`. No shell on
the Docker host.

`dry_run=true` returns the compiler or cmake command line without cloning
or compiling. `docker/references.yaml` is the ARM corpus (medium_nosize,
`postgresql://ghidra-bsim:5432/embedded`).
`docker/references.userland.yaml` is x86-64 libc and static libs
(medium_nosize, `postgresql://ghidra-bsim:5432/userland`). Do not ingest
x86-64 into `embedded`. Each object gets a JSON sidecar (`<artifact>.json`)
with the resolved commit, compiler `--version`, sha256, and
`debug_path_prefix`. `build_manifest` skips a job when that hash still
matches.

## API Endpoints

The headless server exposes the same REST API as the GUI plugin. Currently implemented:

### Health & Metadata
- `GET /check_connection` - Health check
- `GET /get_version` - Server version
- `GET /get_metadata` - Program metadata

### Listing
- `GET /list_methods` - List function names
- `GET /list_functions` - List functions with addresses
- `GET /list_classes` - List namespaces
- `GET /list_segments` - List memory segments
- `GET /list_imports` - List imports
- `GET /list_exports` - List exports
- `GET /list_data_items` - List defined data
- `GET /list_strings` - List defined strings
- `GET /list_data_types` - List data types

### Analysis
- `GET /decompile_function` - Decompile function
- `GET /disassemble_function` - Disassemble function
- `GET /get_function_by_address` - Get function info
- `GET /get_xrefs_to` - Get cross-references to address
- `GET /get_xrefs_from` - Get cross-references from address
- `GET /search_functions` - Search functions by name

### Modification (POST)
- `POST /rename_function` - Rename function by name
- `POST /rename_function` - Rename function by address
- `POST /rename_symbol` - Rename data label
- `POST /rename_variables` - Rename variable
- `POST /set_comment(type='pre')` - Set PRE_COMMENT
- `POST /set_comment(type='eol')` - Set EOL_COMMENT

### Program Management
- `GET /list_open_programs` - List loaded programs
- `GET /get_current_program_info` - Current program info
- `POST /switch_program` - Switch active program
- `POST /load_program` - Load program from file (headless only)
- `POST /close_program` - Close a program (headless only)

## Testing

### Run Integration Tests

```bash
# Install test requirements
pip install -r tests/requirements.txt

# Run tests against local server
python tests/run_tests.py --integration --server http://localhost:8089

# Run all tests with verbose output
python tests/run_tests.py --all -v
```

### Test Endpoint Coverage

```bash
# Run endpoint registration tests
pytest tests/integration/test_all_endpoints.py -v
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Container                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              GhidraMCPHeadlessServer                    │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐ │ │
│  │  │ HeadlessProgram  │  │ HeadlessEndpointHandler     │ │ │
│  │  │    Provider      │  │   (~200 REST endpoints)      │ │ │
│  │  └──────────────────┘  └─────────────────────────────┘ │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────┐ │ │
│  │  │ DirectThreading  │  │     Ghidra Headless         │ │ │
│  │  │    Strategy      │  │    (Analysis Engine)        │ │ │
│  │  └──────────────────┘  └─────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
│              Port 8089 ─────────────────────────────────────┼──▶ HTTP API
└─────────────────────────────────────────────────────────────┘

Multi-Instance Setup:
┌─────────────┐     ┌─────────────────────────────────────────┐
│   Client    │────▶│  Nginx Load Balancer (Port 8089)        │
└─────────────┘     └──────┬──────────┬──────────┬────────────┘
                           │          │          │
                    ┌──────▼───┐┌─────▼────┐┌────▼─────┐
                    │Instance 1││Instance 2││Instance 3│
                    │ (8089)   ││ (8089)   ││ (8089)   │
                    └──────────┘└──────────┘└──────────┘
```

## Troubleshooting

### Server won't start

1. Check if port 8089 is in use: `netstat -an | grep 8089`
2. Check Docker logs: `docker logs ghidra-mcp`
3. Verify Ghidra home: `docker exec ghidra-mcp ls /opt/ghidra`

### No program loaded

1. Load a program via API: `curl -X POST -d "file=/data/binary.exe" http://localhost:8089/load_program`
2. Or set `PROGRAM_FILE` environment variable

### Memory issues

1. Increase Java heap: `JAVA_OPTS=-Xmx8g`
2. Monitor usage: `docker stats ghidra-mcp`

## License

Apache License 2.0 - See LICENSE file
