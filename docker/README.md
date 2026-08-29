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
