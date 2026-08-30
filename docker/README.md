# GhidraMCP Headless Server - Docker Deployment

The compose file on this branch is the stack this fork actually runs:
Ghidra Server (RMI) + headless MCP + Python bridge + a Cloudflare Tunnel.
There is no Traefik in this file.

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

## Quick Start

```bash
cp docker/.env.template docker/.env   # fill it
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
curl -H "Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN" \
  http://127.0.0.1:8089/check_connection
```

Local MCP is `http://127.0.0.1:8081/mcp`. Ghidra Server RMI is on
`BIND_ADDR:13100-13102` (not loopback, not 0.0.0.0).

`docker-compose.multi.yml` is a leftover nginx scale-out sketch. It is
not this stack.

## Building

### Build Docker Image

```bash
# From project root — Java headless server
docker build -t ghcr.io/knd775/ghidra-mcp-headless:dev -f docker/Dockerfile .

# Python MCP bridge (python:3.12-slim)
docker build -t ghcr.io/knd775/ghidra-mcp-bridge:dev -f docker/Dockerfile.bridge .
```

Or `docker compose -f docker/docker-compose.yml build`.

Images are also published to GHCR on push to `main`/`dev`/`develop`:

```text
ghcr.io/<owner>/ghidra-mcp-headless
ghcr.io/<owner>/ghidra-mcp-bridge
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
| `GHIDRA_MCP_BSIM_ROOT` | `/srv/ghidra/bsim` | Confines `file:` BSim URLs. Dedicated volume, not under `/data`. |
| `GHIDRA_SERVER_HOST` | `BIND_ADDR` | RMI address the headless client dials |
| `BIND_ADDR` | required | Host IP for RMI publish and `-ip` |
| `GHIDRA_MCP_ALLOWED_HOSTS` | required | Tunnel hostname for the bridge Host check |
| `TUNNEL_TOKEN` | required | Cloudflare dashboard tunnel token |
| `PROGRAM_FILE` | - | Path to binary file to load on startup |
| `PROJECT_PATH` | - | Path to Ghidra project directory |

### Volumes

| Volume / bind | Container Path | Description |
|--------|---------------|-------------|
| `SAMPLES_DIR` (host path) | `/data` | Binaries / `GHIDRA_MCP_FILE_ROOT` |
| `ghidra-repos` | `/repos` | Ghidra Server project history; back this up |
| `ghidra-mcp-home` | `/home/ghidra` | `$HOME/.ghidra` settings |
| `ghidra-mcp-projects` | `/projects` | Local (non-repo) project data |
| `ghidra-bsim` | `/srv/ghidra/bsim` | H2 BSim databases (`file:/srv/ghidra/bsim/<db>`). Writable by uid 1000. Back this up; regenerating a corpus means recompiling everything in it. |
| `builder-src-cache` | `/src` (builder) | Bare git clones for `build_reference`. Persists so a second build of the same ref does not re-clone. |
| `docker/references.yaml` | `/data/references.yaml` | Embedded ARM corpus. `build_manifest` with no path reads this. |
| `docker/references.userland.yaml` | `/data/references.userland.yaml` | x86-64 userland corpus. `build_manifest(path="references.userland.yaml")`. |
| `docker/stubs/` | `/opt/ghidra-builder/stubs` | Framework stub projects (`pico-sdk` shipped). Listed by `mode=framework` validation. |

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

Portainer (or `docker compose up --build`) starts the builder with the
rest of the stack. Corpus updates are MCP tools: `builder_health`,
`build_manifest`, `build_reference`, `build_reference_status`,
`source_read`. No shell on the Docker host.

`dry_run=true` returns the compiler or cmake command line without cloning
or compiling. `docker/references.yaml` is the ARM corpus (medium_32).
`docker/references.userland.yaml` is x86-64 libc and static libs
(medium_64, `file:/srv/ghidra/bsim/userland`). Leave
`file:/srv/ghidra/bsim/re` as the existing ARM database; do not ingest
x86-64 into it. Each object gets a JSON sidecar (`<artifact>.json`) with
the resolved commit, compiler `--version`, sha256, and
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
