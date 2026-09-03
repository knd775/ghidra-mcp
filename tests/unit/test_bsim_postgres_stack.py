"""BSim PostgreSQL stack: image, compose posture, allowlist, SSL, lock pin.

H2 file: databases are local and single-writer. GUI clients on the VPN
cannot open a file inside a container, so the corpus lives in PostgreSQL.
A stock postgres image is not enough: BSim needs the lshvector C
extension, and Ghidra refuses a non-SSL connection.
"""

from __future__ import annotations

import pathlib
import subprocess
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile.bsim"
LOCK = REPO_ROOT / "docker" / "bsim" / "lshvector.lock"
FETCH = REPO_ROOT / "docker" / "bsim" / "fetch_lshvector.sh"
HBA = REPO_ROOT / "docker" / "bsim" / "pg_hba.conf"
ENTRYPOINT = REPO_ROOT / "docker" / "bsim" / "entrypoint.sh"
BACKUP = REPO_ROOT / "docker" / "bsim" / "backup.sh"
SMOKE = REPO_ROOT / "docker" / "bsim" / "smoke-lshvector.sh"
MIGRATION = REPO_ROOT / "docker" / "bsim" / "MIGRATION.md"
ENV_TEMPLATE = REPO_ROOT / "docker" / ".env.template"
DB_PROBE = (
    REPO_ROOT
    / "src"
    / "main"
    / "java"
    / "com"
    / "xebyte"
    / "core"
    / "BSimDbProbe.java"
)
PINNED_COMMIT = "c0f584bf229fffba61b36431f3ce30c0c3e4e682"
PINNED_TAG = "Ghidra_12.1.2_build"
PINNED_GHIDRA = "12.1.2"


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


class TestBsimPostgresCompose(unittest.TestCase):
    def setUp(self):
        self.doc = _compose()

    def test_bsim_service_uses_custom_image_and_bind_addr(self):
        services = self.doc["services"]
        self.assertIn("ghidra-bsim", services)
        svc = services["ghidra-bsim"]
        image = svc["image"]
        self.assertIn("ghidra-mcp-bsim", image)
        self.assertTrue(image.startswith("ghcr.io/"), image)
        self.assertIn("${GHIDRA_MCP_VERSION:-dev}", image)
        self.assertEqual(svc.get("hostname"), "ghidra-bsim")
        self.assertEqual(svc.get("container_name"), "ghidra-bsim")
        self.assertEqual(svc.get("restart"), "unless-stopped")
        self.assertIn("ghidra-db", svc["networks"])
        self.assertNotIn("ghidra", svc.get("networks") or [])
        ports = " ".join(str(p) for p in svc["ports"])
        self.assertIn("BIND_ADDR", ports)
        self.assertIn("5432:5432", ports)
        self.assertNotIn("0.0.0.0", ports)
        self.assertNotIn("127.0.0.1:5432", ports)
        vols = " ".join(str(v) for v in svc["volumes"])
        self.assertIn("ghidra-bsim-pgdata", vols)
        env = svc["environment"]
        self.assertIn("BSIM_DB_PASSWORD", str(env["POSTGRES_PASSWORD"]))
        self.assertEqual(env.get("POSTGRES_DB"), "postgres")
        self.assertNotIn("embedded", str(env.get("POSTGRES_DB")))
        df = svc["build"]["dockerfile"]
        self.assertEqual(df, "docker/Dockerfile.bsim")

    def test_cloudflared_cannot_reach_postgres(self):
        services = self.doc["services"]
        tunnel = services["cloudflared"]
        self.assertEqual(tunnel["networks"], ["ghidra"])
        self.assertNotIn("ghidra-db", tunnel["networks"])
        postgres = services["ghidra-bsim"]
        self.assertEqual(postgres["networks"], ["ghidra-db"])
        mcp = services["ghidra-mcp"]
        self.assertIn("ghidra-db", mcp["networks"])
        self.assertIn("ghidra", mcp["networks"])
        self.assertIn("ghidra-bsim", mcp["depends_on"])
        builder = services["builder"]
        self.assertNotIn("ghidra-db", builder.get("networks") or [])

    def test_database_probe_excludes_bsim_synthetic_library_records(self):
        source = DB_PROBE.read_text(encoding="utf-8")
        self.assertIn("md5 NOT ILIKE 'bbbbbbbbaaaaaaaa%'", source)

    def test_mcp_allowlist_and_credentials(self):
        env = self.doc["services"]["ghidra-mcp"]["environment"]
        urls = env["GHIDRA_MCP_BSIM_URLS"]
        self.assertEqual(
            urls,
            "postgresql://ghidra-bsim:5432/bsim,postgresql://${BIND_ADDR}:5432/bsim",
        )
        self.assertIn("BSIM_DB_PASSWORD", str(env["GHIDRA_MCP_BSIM_PASSWORD"]))
        self.assertIn("BSIM_DB_USER", str(env["GHIDRA_MCP_BSIM_USER"]))
        self.assertEqual(env["GHIDRA_MCP_BSIM_TEMPLATES"], "bsim:medium_nosize")
        self.assertEqual(env["GHIDRA_MCP_BSIM_ROOT"], "/srv/ghidra/bsim")

    def test_backup_service_dumps_both_databases_over_ssl(self):
        svc = self.doc["services"]["bsim-backup"]
        self.assertIn("ghidra-mcp-bsim", svc["image"])
        self.assertEqual(svc["networks"], ["ghidra-db"])
        self.assertNotIn("ports", svc)
        env = svc["environment"]
        self.assertEqual(env["PGHOST"], "ghidra-bsim")
        self.assertEqual(env["PGSSLMODE"], "require")
        vols = " ".join(str(v) for v in svc["volumes"])
        self.assertIn("bsim-backups", vols)
        self.assertIn("ghidra-repos", vols)
        entry = svc["entrypoint"]
        self.assertTrue(any("bsim-backup" in str(x) for x in entry))

    def test_no_docker_sock_and_no_bsim_ctl(self):
        text = COMPOSE.read_text(encoding="utf-8")
        self.assertNotIn("bsim_ctl", text)
        self.assertFalse(
            any(
                line.strip().startswith("- ") and "docker.sock" in line
                for line in text.splitlines()
            ),
            "compose must not mount docker.sock",
        )
        for name, svc in self.doc["services"].items():
            volumes = svc.get("volumes") or []
            self.assertFalse(
                any("docker.sock" in str(v) for v in volumes),
                f"{name} must not mount docker.sock",
            )

    def test_env_template_separates_bsim_from_ghidra_server(self):
        text = ENV_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("BSIM_DB_USER=bsim", text)
        self.assertIn("BSIM_DB_PASSWORD=", text)
        self.assertIn("ghidra-mcp-bsim", text)
        self.assertIn("Not Ghidra Server", text)
        self.assertIn("BIND_ADDR:5432", text)


class TestBsimPostgresImage(unittest.TestCase):
    def test_dockerfile_compiles_lshvector_against_stock_postgres(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("FROM postgres:${PG_MAJOR}-bookworm", text)
        self.assertIn("lshvector", text)
        self.assertIn("PG_CONFIG=pg_config", text)
        self.assertIn("postgresql-server-dev-", text)
        self.assertIn("fetch_lshvector.sh", text)
        self.assertIn("lshvector.lock", text)
        self.assertIn(PINNED_COMMIT, text)
        self.assertIn(PINNED_TAG, text)
        self.assertIn("GHIDRA_VERSION=12.1.2", text)
        self.assertIn("Do not use support/bsim_ctl", text.replace("`", ""))
        self.assertNotIn("USER postgres", text)
        self.assertIn("bsim-entrypoint.sh", text)
        self.assertIn("openssl", text)

    def test_lock_pins_ghidra_commit_and_every_blob(self):
        text = LOCK.read_text(encoding="utf-8")
        self.assertIn(f"commit {PINNED_COMMIT}", text)
        self.assertIn(f"tag {PINNED_TAG}", text)
        self.assertIn(f"ghidra {PINNED_GHIDRA}", text)
        required = (
            "Makefile.lshvector",
            "lshvector.control",
            "lshvector--1.0.sql",
            "c/binhash.c",
            "c/crc32.c",
            "c/lsh.c",
            "c/lsh.h",
            "c/weights.c",
        )
        for name in required:
            self.assertIn(name, text)
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split()
            if parts[0] in {"commit", "tag", "ghidra"}:
                continue
            self.assertEqual(len(parts[1]), 40, ln)
            int(parts[1], 16)

    def test_lock_is_tracked_and_not_gitignored(self):
        rel = "docker/bsim/lshvector.lock"
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", rel],
            cwd=REPO_ROOT,
        )
        self.assertNotEqual(ignored.returncode, 0, f"{rel} is gitignored")
        self.assertTrue((REPO_ROOT / rel).is_file(), f"{rel} is missing")
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel],
            cwd=REPO_ROOT,
            capture_output=True,
        )
        self.assertEqual(tracked.returncode, 0, f"{rel} is not in git")

    def test_fetch_script_verifies_head_and_blobs_and_flattens(self):
        text = FETCH.read_text(encoding="utf-8")
        self.assertIn("git hash-object", text)
        self.assertIn("sparse-checkout", text)
        self.assertIn("HEAD", text)
        self.assertIn('cp "$src/c/"*.c', text)
        self.assertIn("NationalSecurityAgency/ghidra.git", text)
        self.assertNotIn("bsim_ctl", text)

    def test_ssl_is_on_and_hostnossl_is_reject(self):
        hba = HBA.read_text(encoding="utf-8")
        self.assertIn("hostssl", hba)
        self.assertIn("hostnossl", hba)
        self.assertIn("reject", hba)
        self.assertNotRegex(hba, r"(?m)^host\s+")
        entry = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn("ssl=on", entry)
        self.assertIn("ssl_cert_file", entry)
        self.assertIn("ssl_key_file", entry)
        self.assertIn("chmod 600", entry)
        self.assertIn("chown postgres:postgres", entry)
        self.assertIn("ssl_min_protocol_version=TLSv1.2", entry)

    def test_smoke_covers_extension_and_non_ssl_reject(self):
        text = SMOKE.read_text(encoding="utf-8")
        self.assertIn("CREATE EXTENSION lshvector", text)
        self.assertIn("sslmode=disable", text)
        self.assertIn("sslmode=require", text)
        self.assertIn("127.0.0.1", text)

    def test_backup_dumps_every_user_database(self):
        text = BACKUP.read_text(encoding="utf-8")
        self.assertIn("pg_dump", text)
        self.assertIn("pg_database", text)
        self.assertIn("datistemplate", text)
        self.assertIn("PGSSLMODE", text)
        self.assertIn("ghidra-repos", text)
        self.assertNotIn("dump_one embedded", text)
        self.assertNotIn("dump_one userland", text)

    def test_migration_doc_is_reingest_not_h2_convert(self):
        self.assertTrue(MIGRATION.is_file())
        text = MIGRATION.read_text(encoding="utf-8")
        self.assertIn("bsim_create_db", text)
        self.assertIn("bsim_ingest", text)
        self.assertIn("bsim_list_corpus", text)
        self.assertIn("pg_restore", text)
        self.assertIn("postgresql://", text)
        self.assertIn("medium_nosize", text)
        self.assertIn("file:/srv/ghidra/bsim/re", text)
        self.assertIn("not the ghidra server", text.lower().replace("*", ""))
        self.assertIn("Do not use `support/bsim_ctl`", text)
        self.assertIn("corroboration", text)
        self.assertIn("createdatabase", text)

    def test_corroboration_schema_is_companion_not_bsim(self):
        sql = (REPO_ROOT / "src" / "main" / "resources" / "bsim" / "corroboration.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE SCHEMA IF NOT EXISTS corroboration", sql)
        self.assertIn("corroboration.functions", sql)
        self.assertIn("USING gin (constants)", sql)
        self.assertIn("USING gin (strings)", sql)
        self.assertNotIn("descriptable", sql)
        self.assertNotIn("exetable", sql)
        # Typed signatures for bsim_apply_matches(apply_signatures=true) live in
        # the same companion table; existing databases get the columns via
        # idempotent ALTERs, never a rebuild of BSim's own tables.
        for column in ("prototype", "calling_convention", "param_count", "has_dwarf", "gdt_path"):
            self.assertIn(column, sql)
            self.assertIn(f"ADD COLUMN IF NOT EXISTS {column}", sql)
        guide = (REPO_ROOT / "docs" / "prompts" / "BSIM.md").read_text(encoding="utf-8")
        self.assertIn("corroborate_match", guide)
        self.assertIn("corroboration", guide)
        self.assertIn("no_evidence", guide)
        self.assertIn("apply_signatures", guide)
        self.assertIn("min_signature_confidence", guide)
        self.assertIn("[bsim-sig]", guide)
        self.assertIn("rename_named", guide)
        self.assertIn("name_exists_elsewhere", guide)
        self.assertIn("/refs/types/", guide)
        self.assertIn("types_fallback_local", guide)
        self.assertIn("type_archive_versioned", guide)
        self.assertIn("relink_types", guide)
        self.assertIn("relink_skipped", guide)
        self.assertIn("sleep_until_callback", guide)

    def test_extract_script_copies_are_identical_and_emit_signatures(self):
        resource = REPO_ROOT / "src" / "main" / "resources" / "bsim" / "BSim_McpExtract.java"
        script = REPO_ROOT / "ghidra_scripts" / "BSim_McpExtract.java"
        a = resource.read_text(encoding="utf-8")
        self.assertEqual(a, script.read_text(encoding="utf-8"))
        # JSON keys appear in Java source as escaped string literals.
        for token in ('\\"prototype\\"', '\\"has_dwarf\\"', '\\"param_count\\"',
                      '\\"gdt_path\\"', "/bsim-sig", "SourceType.IMPORTED",
                      "FileDataTypeManager.createFileArchive"):
            self.assertIn(token, a)

    def test_manifests_point_at_postgres(self):
        arm = yaml.safe_load(
            (REPO_ROOT / "docker" / "references.yaml").read_text(encoding="utf-8")
        )
        userland = yaml.safe_load(
            (REPO_ROOT / "docker" / "references.userland.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(arm["database"], "postgresql://ghidra-bsim:5432/bsim")
        self.assertEqual(arm["config_template"], "medium_nosize")
        self.assertEqual(userland["database"], "postgresql://ghidra-bsim:5432/bsim")
        self.assertEqual(userland["config_template"], "medium_nosize")
        self.assertEqual(arm["database"], userland["database"])
        littlefs = {entry["name"]: entry for entry in arm["references"]}
        self.assertEqual(
            littlefs["littlefs"]["defines"], ["LFS_NO_MALLOC", "LFS_NO_ASSERT"]
        )
        self.assertEqual(littlefs["littlefs-logging"]["defines"], ["LFS_NO_MALLOC"])

    def test_local_build_script_tags_ghcr_name(self):
        path = REPO_ROOT / "docker" / "build-bsim.sh"
        self.assertTrue(path.is_file(), path)
        text = path.read_text(encoding="utf-8")
        self.assertIn("ghidra-mcp-bsim", text)
        self.assertIn("Dockerfile.bsim", text)
        self.assertNotIn("bsim_ctl", text)


if __name__ == "__main__":
    unittest.main()
