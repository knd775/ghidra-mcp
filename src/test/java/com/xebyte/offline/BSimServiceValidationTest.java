package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.BSimCli;
import com.xebyte.core.BSimJobs;
import com.xebyte.core.BSimService;
import com.xebyte.core.BSimTestCredentials;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.Param;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Validation coverage for BSimService that does not spawn Ghidra.
 *
 * <p>The fake runner completes instantly, so with the default inline wait the
 * job layer is invisible here and every call behaves synchronously — which is
 * the compatibility property the wait exists to preserve. The job-ticket path
 * is exercised explicitly with {@code wait_seconds = 0} and a gated runner.
 */
public class BSimServiceValidationTest extends TestCase {

    /** Default inline wait used by tests that expect a synchronous answer. */
    private static final int WAIT = 45;

    private Path tmp;
    private BSimService svc;
    private final List<List<String>> commands = new CopyOnWriteArrayList<>();
    private final List<String> stdins = new CopyOnWriteArrayList<>();

    @Override
    protected void setUp() throws Exception {
        tmp = Files.createTempDirectory("bsim-test-");
        com.xebyte.core.BSimTestEnv.setAllowlist("");
        com.xebyte.core.BSimTestEnv.setRoot("");
        File home = tmp.resolve("ghidra").toFile();
        File support = new File(home, "support");
        assertTrue(support.mkdirs());
        assertTrue(new File(support, "bsim").createNewFile());
        assertTrue(new File(support, "analyzeHeadless").createNewFile());
        BSimCli cli = new BSimCli(new BSimCli.Runner() {
            @Override
            public BSimCli.Result run(List<String> cmd, Duration timeout) {
                return run(cmd, timeout, null);
            }

            @Override
            public BSimCli.Result run(List<String> cmd, Duration timeout, String stdinData) {
                commands.add(List.copyOf(cmd));
                stdins.add(stdinData == null ? "" : stdinData);
                return new BSimCli.Result(0, canned(cmd), cmd);
            }
        }, home);
        ThreadingStrategy ts = new NoopThreadingStrategy();
        svc = new BSimService(ServiceFactory.stubProvider(), ts, cli);
    }

    @Override
    protected void tearDown() throws Exception {
        BSimTestCredentials.clear();
        com.xebyte.core.BSimTestEnv.clear();
        if (tmp != null) {
            deleteRecursively(tmp);
        }
    }

    public void testCreateDbCommandLine() throws Exception {
        Path dbDir = tmp.resolve("bsimdb");
        Response r = svc.createDb("file:" + dbDir.resolve("lfs"), "medium_32", "lfs", "test db",
                true, WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson().contains("medium_32"));
        assertTrue(r.toJson().contains("\"executables\":0"));
        List<String> created = findCommand("createdatabase");
        assertNotNull(created);
        assertTrue(created.contains("medium_32"));
        assertFalse("callgraph=true must not pass --nocallgraph", created.contains("--nocallgraph"));
        assertTrue(created.contains("--name"));
        assertTrue(Files.isDirectory(dbDir));
        Path sidecar = Path.of(dbDir.resolve("lfs").toString() + ".ghidra-mcp.json");
        assertTrue("create writes a template sidecar", Files.isRegularFile(sidecar));
        assertTrue(Files.readString(sidecar).contains("medium_32"));
    }

    public void testCreateDbNocallgraphWhenDisabled() {
        Path dbDir = tmp.resolve("bsimdb2");
        Response r = svc.createDb("file:" + dbDir.resolve("lfs"), "medium_32", "", "", false, WAIT);
        assertFalse(r instanceof Response.Err);
        List<String> created = findCommand("createdatabase");
        assertTrue(created.contains("--nocallgraph"));
    }

    public void testCreateDbRejectsUnknownTemplate() {
        Response r = svc.createDb("file:" + tmp.resolve("x"), "not_a_template", "", "", true, WAIT);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("config_template"));
    }

    public void testListDatabasesReportsTemplates() {
        Response r = svc.listDatabases(false, 3);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("medium_32"));
        assertTrue(json, json.contains("medium_64"));
        assertTrue(json, json.contains("config_templates"));
    }

    public void testListDatabasesIncludesAllowlistedPostgres() {
        com.xebyte.core.BSimTestEnv.setAllowlist(
                "postgresql://ghidra-bsim:5432/embedded,postgresql://ghidra-bsim:5432/userland");
        com.xebyte.core.BSimTestEnv.setTemplates("embedded:medium_32,userland:medium_64");
        Response r = svc.listDatabases(false, 3);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("postgresql://ghidra-bsim:5432/embedded"));
        assertTrue(json, json.contains("postgresql://ghidra-bsim:5432/userland"));
        assertTrue(json, json.contains("medium_32"));
        assertTrue(json, json.contains("medium_64"));
        assertTrue(json, json.contains("\"backend\":\"postgresql\""));
    }

    /**
     * The allowlist says what may be contacted, not what exists. Reporting a
     * configured template as though it were a property of a live database is
     * exactly the reading that sent an operator hunting for two databases that
     * had never been created.
     */
    public void testListDatabasesSeparatesConfigurationFromState() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setTemplates("embedded:medium_32");
        Response r = svc.listDatabases(false, 3);
        String json = r.toJson();
        assertTrue(json, json.contains("\"configured\":true"));
        assertTrue("template must be labelled as configuration",
                json.contains("\"config_template_source\":\"env\""));
        assertFalse("an unprobed network row must not imply presence either way",
                json.contains("\"present\""));
        assertTrue(json, json.contains("\"probe\":\"not_probed\""));
        assertTrue(json, json.contains("\"probed\":false"));
    }

    /**
     * The probe must never invent a presence answer it does not have. Without
     * GHIDRA_MCP_BSIM_PASSWORD there is nothing to connect with, so the row
     * says so rather than defaulting to present or absent.
     */
    public void testListDatabasesProbeWithoutCredentialIsHonest() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setPassword("");
        Response r = svc.listDatabases(true, 3);
        String json = r.toJson();
        assertTrue(json, json.contains("\"probe\":\"no_credential\""));
        assertFalse("no credential means unknown, not absent",
                json.contains("\"present\""));
    }

    public void testProbeStatesComeFromSqlState() {
        assertEquals("no_database", com.xebyte.core.BSimDbProbe.classify(
                new java.sql.SQLException("db missing", "3D000")));
        assertEquals("auth_failed", com.xebyte.core.BSimDbProbe.classify(
                new java.sql.SQLException("nope", "28P01")));
        assertEquals("unreachable", com.xebyte.core.BSimDbProbe.classify(
                new java.sql.SQLException("refused", "08001")));
        // Only a definite "no such database" may claim absence; everything
        // else leaves presence unknown rather than reporting a false negative.
        assertEquals(Boolean.FALSE, com.xebyte.core.BSimDbProbe.presenceFor(
                new java.sql.SQLException("db missing", "3D000")));
        assertNull(com.xebyte.core.BSimDbProbe.presenceFor(
                new java.sql.SQLException("refused", "08001")));
    }

    public void testProbeDetailNeverLeaksThePassword() {
        com.xebyte.core.BSimTestEnv.setPassword("hunter2secret");
        String detail = com.xebyte.core.BSimDbProbe.sanitize(
                new java.sql.SQLException("FATAL: password \"hunter2secret\" rejected", "28P01"));
        assertFalse(detail, detail.contains("hunter2secret"));
        assertTrue(detail, detail.contains("***"));
    }

    public void testNonPostgresNetworkUrlIsReportedUnprobeable() {
        com.xebyte.core.BSimTestEnv.setAllowlist("https://bsim.example/refs");
        Response r = svc.listDatabases(true, 3);
        String json = r.toJson();
        assertTrue(json, json.contains("\"probe\":\"unsupported\""));
        assertFalse("an unprobeable backend must not claim a presence answer",
                json.contains("\"present\""));
    }

    public void testCreateDbPostgresRejectedOffAllowlist() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setPassword("secret");
        Response r = svc.createDb("postgresql://evil.example/other", "medium_32", "", "", true, WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("GHIDRA_MCP_BSIM_URLS"));
        assertTrue(json, json.contains("evil.example") || json.contains("other"));
        assertNull(findCommand("createdatabase"));
    }

    public void testCreateDbPostgresRejectedWithoutAllowlist() {
        com.xebyte.core.BSimTestEnv.setAllowlist("");
        com.xebyte.core.BSimTestEnv.setPassword("secret");
        Response r = svc.createDb("postgresql://ghidra-bsim:5432/embedded", "medium_32", "", "", true, WAIT);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("GHIDRA_MCP_BSIM_URLS"));
        assertNull(findCommand("createdatabase"));
    }

    public void testCreateDbPostgresRejectedWithoutPassword() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setPassword("");
        Response r = svc.createDb("postgresql://ghidra-bsim:5432/embedded", "medium_32", "", "", true, WAIT);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("GHIDRA_MCP_BSIM_PASSWORD"));
        assertNull(findCommand("createdatabase"));
    }

    public void testCreateDbPostgresRunsWhenAllowlisted() throws Exception {
        Path root = tmp.resolve("sidecars");
        Files.createDirectories(root);
        com.xebyte.core.BSimTestEnv.setRoot(root.toString());
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setUser("bsim");
        com.xebyte.core.BSimTestEnv.setPassword("secret");
        Response r = svc.createDb("postgresql://ghidra-bsim:5432/embedded", "medium_32",
                "embedded", "ARM refs", true, WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        List<String> created = findCommand("createdatabase");
        assertNotNull(created);
        assertTrue(created.contains("postgresql://bsim@ghidra-bsim:5432/embedded")
                || created.stream().anyMatch(s -> s.contains("ghidra-bsim") && s.contains("embedded")));
        assertFalse("password must not appear in argv", created.contains("secret"));
        assertTrue("postgres password on stdin", stdins.contains("secret\n"));
        Path sidecar = root.resolve("embedded.ghidra-mcp.json");
        assertTrue("create writes a template sidecar under ROOT", Files.isRegularFile(sidecar));
        assertTrue(Files.readString(sidecar).contains("medium_32"));
    }

    /**
     * Two console prompts read one pipe, so the payload order IS the protocol.
     * {@code generatesigs --bsim <url> --commit} runs
     * {@code BulkSignatures.signatureRepo}, which calls
     * {@code generateSignaturesFromServer(..., configtemplate = null, ...)};
     * with no {@code --config} override that pulls the vector configuration out
     * of the BSim database <em>before</em> {@code SignatureRepository.process}
     * reaches the Ghidra Server. Database first, repository second.
     *
     * <p>The other order is not a degraded mode — it took out the whole
     * PostgreSQL ingest path. The database prompt ate the Ghidra Server
     * password and the CLI died with
     * {@code Password for bsim:ERROR Could not authenticate with database},
     * while {@code bsim_create_db} and {@code bsim_list_corpus} kept working on
     * the same URL because a database-only command has only one prompt to feed.
     * H2 hid it as well: a {@code file:} database never prompts, so the single
     * line reached the repository prompt it was written for, and the failure
     * looked specific to PostgreSQL rather than to having two secrets in flight.
     */
    public void testIngestFeedsDatabasePasswordBeforeGhidraServerPassword() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setUser("bsim");
        com.xebyte.core.BSimTestEnv.setPassword("bsim-secret");
        BSimTestCredentials.install("5n4ck3y", "ghidra-secret");
        Response r = svc.ingest(
                "postgresql://ghidra-bsim:5432/embedded",
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue("BSim database then Ghidra Server on stdin, in that order",
                stdins.contains("bsim-secret\nghidra-secret\n"));
        assertFalse("the reversed order fails BSim database authentication",
                stdins.contains("ghidra-secret\nbsim-secret\n"));
        List<String> gen = findCommand("generatesigs");
        assertNotNull(gen);
        assertFalse(gen.contains("bsim-secret"));
        assertFalse(gen.contains("ghidra-secret"));
    }

    /**
     * Order is a property of {@code stdinForBsimArgs} itself, so pin it there
     * too: BSimService is not the only caller, and a single-credential command
     * must still write exactly one line.
     */
    public void testStdinPayloadOrderAndSingleCredentialCases() {
        com.xebyte.core.BSimTestEnv.setUser("bsim");
        com.xebyte.core.BSimTestEnv.setPassword("bsim-secret");
        BSimTestCredentials.install("5n4ck3y", "ghidra-secret");
        assertEquals("bsim-secret\nghidra-secret\n", BSimCli.stdinForBsimArgs(List.of(
                "generatesigs", "ghidra://host/repo/prog", "/tmp/xml",
                "--bsim", "postgresql://bsim@ghidra-bsim:5432/embedded", "--commit")));
        assertEquals("bsim-secret\n", BSimCli.stdinForBsimArgs(List.of(
                "createdatabase", "postgresql://bsim@ghidra-bsim:5432/embedded",
                "medium_nosize")));
        assertEquals("ghidra-secret\n", BSimCli.stdinForBsimArgs(List.of(
                "generatesigs", "ghidra://host/repo/prog", "/tmp/xml",
                "--bsim", "file:/srv/ghidra/bsim/nosize", "--commit")));
        assertNull("a local project URL and an H2 database need no secrets",
                BSimCli.stdinForBsimArgs(List.of(
                        "generatesigs", "ghidra:/tmp/proj/BSimIngest", "/tmp/xml",
                        "--bsim", "file:/srv/ghidra/bsim/nosize", "--commit")));
    }

    /**
     * Same family as the stdin ordering bug, in the username dimension.
     * {@code BulkSignatures} applies {@code --user} — which a {@code ghidra://}
     * source forces us to pass — to the BSim database as well, whenever the
     * BSim URL carries no userinfo. Measured against the real CLI: with
     * {@code postgresql://bsim@...} it logs "BSim DB server info specifies user
     * 'bsim'. Ignoring user name option", so the userinfo is what saves us, and
     * that userinfo comes from GHIDRA_MCP_BSIM_USER. Unset, the two identities
     * merge and fail as one more "could not authenticate with database".
     */
    public void testIngestRefusesToMergeBsimAndGhidraServerIdentities() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setUser("");
        com.xebyte.core.BSimTestEnv.setPassword("bsim-secret");
        BSimTestCredentials.install("5n4ck3y", "ghidra-secret");
        Response r = svc.ingest(
                "postgresql://ghidra-bsim:5432/embedded",
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertTrue("must refuse before spawning", r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("GHIDRA_MCP_BSIM_USER"));
        assertNull("nothing may be spawned", findCommand("generatesigs"));

        // With the database user configured the URL carries its own userinfo,
        // Ghidra ignores --user for the database, and ingest proceeds.
        com.xebyte.core.BSimTestEnv.setUser("bsim");
        Response ok = svc.ingest(
                "postgresql://ghidra-bsim:5432/embedded",
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertFalse("unexpected error: " + ok.toJson(), ok instanceof Response.Err);
        assertNotNull(findCommand("generatesigs"));
    }

    /**
     * An H2 ingest has one credential and no database login at all, so the
     * identity check must not fire there — H2 is the path that kept working
     * throughout and must keep working.
     */
    public void testH2IngestIsUnaffectedByTheIdentityCheck() {
        com.xebyte.core.BSimTestEnv.setUser("");
        BSimTestCredentials.install("5n4ck3y", "ghidra-secret");
        Response r = svc.ingest(
                "file:" + tmp.resolve("h2db"),
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertNotNull(findCommand("generatesigs"));
        assertTrue("only the repository password goes on the pipe",
                stdins.contains("ghidra-secret\n"));
    }

    /**
     * {@code Could not authenticate with database} is the one message this
     * failure ever produced, and on its own it points at nothing. Keep it
     * explaining which credential is meant and that two prompts share one pipe.
     */
    public void testDatabaseAuthFailureIsExplained() {
        String raw = "INFO  (BSimLaunchable) Password for bsim:ERROR Could not authenticate "
                + "with database (BSimLaunchable)";
        String explained = com.xebyte.core.BSimCliParser.rewriteIngestError(raw);
        assertNotNull(explained);
        assertTrue(explained, explained.contains("GHIDRA_MCP_BSIM_PASSWORD"));
        assertTrue("must say it is not the Ghidra Server login",
                explained.contains("NOT the Ghidra Server login"));
        assertNull(com.xebyte.core.BSimCliParser.databaseAuthError("all fine here"));
    }

    public void testPointerSizeQueryWarningIsAdvisory() {
        assertNotNull(com.xebyte.core.BSimUrls.pointerSizeQueryWarning(64, "medium_32"));
        assertNull(com.xebyte.core.BSimUrls.pointerSizeQueryWarning(32, "medium_32"));
        assertNull(com.xebyte.core.BSimUrls.pointerSizeQueryWarning(64, "medium_64"));
        assertNull(com.xebyte.core.BSimUrls.pointerSizeQueryWarning(64, "medium_nosize"));
        assertNull(com.xebyte.core.BSimUrls.pointerSizeIngestError(32, "ARM:LE:32:Cortex", "medium_nosize"));
        assertNull(com.xebyte.core.BSimUrls.pointerSizeIngestError(64, "x86:LE:64:default", "medium_nosize"));
        String sized = com.xebyte.core.BSimUrls.pointerSizeIngestError(
                64, "x86:LE:64:default", "medium_32");
        assertNotNull(sized);
        assertTrue(sized, sized.contains("medium_32"));
        assertTrue(sized, sized.contains("medium_nosize"));
        Path root = tmp.resolve("bsimroot");
        try {
            Files.createDirectories(root);
            Files.writeString(root.resolve("userland.ghidra-mcp.json"),
                    "{\"db_url\":\"file:" + root.resolve("userland")
                            + "\",\"config_template\":\"medium_64\"}\n");
            var listed = com.xebyte.core.BSimUrls.listFileDatabases(root);
            assertEquals(1, listed.size());
            assertEquals("medium_64", listed.get(0).get("config_template"));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    public void testIngestInvalidSourceIsSpecificError() {
        Response r = svc.ingest("file:" + tmp.resolve("db"), "not-a-url", "", true, false, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("source"));
        assertTrue(json, json.contains("ghidra://") || json.contains("ghidraURL"));
        assertNull(findCommand("generatesigs"));
    }

    public void testIngestServerUrlWithoutPasswordNamesCredential() {
        if (nonBlank(System.getenv("GHIDRA_SERVER_PASSWORD"))
                || nonBlank(System.getenv("GHIDRA_PASS"))) {
            return;
        }
        Response r = svc.ingest(
                "file:" + tmp.resolve("db"),
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("GHIDRA_SERVER_PASSWORD"));
        assertNull(findCommand("generatesigs"));
    }

    public void testIngestServerUrlPassesUserAndFeedsPasswordOnStdin() {
        BSimTestCredentials.install("5n4ck3y", "hunter2secret");
        Response r = svc.ingest(
                "file:" + tmp.resolve("db"),
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        List<String> gen = findCommand("generatesigs");
        assertNotNull(gen);
        int userIdx = gen.indexOf("--user");
        assertTrue("generatesigs against a server URL must pass --user", userIdx >= 0);
        assertEquals("5n4ck3y", gen.get(userIdx + 1));
        assertFalse("the password must never appear in argv", gen.contains("hunter2secret"));
        // The spawned stock-Ghidra JVM cannot read our env vars; the password
        // travels on stdin where HeadlessClientAuthenticator's no-console
        // fallback reads it.
        assertTrue("password must be fed on stdin, newline-terminated",
                stdins.contains("hunter2secret\n"));
    }

    public void testIngestLocalGhidraUrlDoesNotFeedStdin() {
        Path db = tmp.resolve("localdb");
        Response r = svc.ingest(
                "file:" + db, "ghidra:/tmp/bsim-proj/BSimIngest", "", true, false, "", WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        List<String> gen = findCommand("generatesigs");
        assertNotNull(gen);
        assertTrue(gen.contains("ghidra:/tmp/bsim-proj/BSimIngest"));
        assertTrue(gen.contains("--commit"));
        assertTrue(gen.contains("--bsim"));
        assertFalse("local project URLs need no server auth", gen.contains("--user"));
        for (String s : stdins) {
            assertEquals("no stdin data for local URLs", "", s);
        }
    }

    public void testCreateDbDryRunDoesNotRunCli() throws Exception {
        Path db = tmp.resolve("dry-create");
        AnnotationScanner scanner = new AnnotationScanner(
                ServiceFactory.stubProvider(), new Object[] { svc });
        EndpointDef endpoint = null;
        for (EndpointDef ep : scanner.getEndpoints()) {
            if ("/bsim_create_db".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);
        Map<String, String> query = new HashMap<>();
        query.put("dry_run", "true");
        Map<String, Object> body = new HashMap<>();
        body.put("db_url", "file:" + db.resolve("re"));
        body.put("config_template", "medium_32");
        Response r = endpoint.handler().handle(query, body);
        String json = r.toJson();
        assertTrue(json, json.contains("would_execute") || json.contains("\"dry_run\":true"));
        assertTrue(json, json.contains("/bsim_create_db"));
        assertNull("createdatabase must not run on dry_run", findCommand("createdatabase"));
        assertFalse("dry_run must not create the parent directory either",
                Files.isDirectory(db));
    }

    public void testIngestProgramParamIsNotASelector() {
        String schema = new AnnotationScanner(
                ServiceFactory.stubProvider(), new Object[] { svc }).generateSchema();
        assertTrue(schema.contains("\"selector\": false"));
        assertTrue(schema.contains("/bsim_ingest"));
    }

    public void testIngestRepoPathWithoutHostIsSpecificError() {
        if (nonBlank(System.getenv("GHIDRA_SERVER_HOST"))) {
            if (nonBlank(System.getenv("GHIDRA_SERVER_PASSWORD"))
                    || nonBlank(System.getenv("GHIDRA_PASS"))) {
                return;
            }
            Response r = svc.ingest("file:" + tmp.resolve("db"),
                    "/5n4ck3y/nullcog-v2", "", true, false, "", WAIT);
            assertTrue(r instanceof Response.Err);
            assertTrue(r.toJson().contains("GHIDRA_SERVER_PASSWORD"));
            assertNull(findCommand("generatesigs"));
            return;
        }
        Response r = svc.ingest("file:" + tmp.resolve("db"),
                "/5n4ck3y/nullcog-v2", "", true, false, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("GHIDRA_SERVER_HOST") || json.contains("ghidra://"));
        assertNull(findCommand("generatesigs"));
    }

    public void testApplyMatchesDryRunIsInvokedNotShortCircuited() throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(
                ServiceFactory.stubProvider(), new Object[] { svc });
        EndpointDef endpoint = null;
        for (EndpointDef ep : scanner.getEndpoints()) {
            if ("/bsim_apply_matches".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);
        Map<String, String> query = new HashMap<>();
        query.put("dry_run", "true");
        Map<String, Object> body = new HashMap<>();
        body.put("db_url", "file:" + tmp.resolve("db"));
        body.put("min_confidence", 20.0);
        body.put("dry_run", Boolean.TRUE);
        Response r = endpoint.handler().handle(query, body);
        String json = r.toJson();
        assertFalse("apply_matches must run so the preview can list would_rename",
                json.contains("would_execute"));
        assertNull("dry_run apply must not shell out until a program is loaded",
                findCommand("createdatabase"));
    }

    private static boolean nonBlank(String s) {
        return s != null && !s.isBlank();
    }

    public void testApplyRequiresMinConfidence() {
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, false, true, 0.7, 10, "",
                "", "", "", "", 8, false, "none", 5.0, false, 40.0, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("min_confidence"));
        assertFalse("must not invent a default floor", json.contains("\"min_confidence\":0"));
        assertTrue(commands.isEmpty());
    }

    public void testQueryThresholdDefaultsAreConfidenceFirst() throws Exception {
        java.lang.reflect.Method query = BSimService.class.getMethod(
                "query", String.class, String.class, double.class, double.class,
                int.class, String.class, String.class, String.class, String.class,
                String.class, int.class, int.class, int.class, boolean.class, int.class);
        Param corroborate = paramNamed(query, "corroborate");
        assertEquals("false", corroborate.defaultValue());
        Param corrMax = paramNamed(query, "corroborate_max_candidates");
        assertEquals("3", corrMax.defaultValue());
        Param similarity = paramNamed(query, "similarity_threshold");
        Param confidence = paramNamed(query, "confidence_threshold");
        assertEquals("0.0", similarity.defaultValue());
        assertEquals("10.0", confidence.defaultValue());
        Param minFeat = paramNamed(query, "min_feature_count");
        assertEquals("8", minFeat.defaultValue());

        java.lang.reflect.Method apply = BSimService.class.getMethod(
                "applyMatches", String.class, Double.class, double.class, boolean.class,
                boolean.class, boolean.class, double.class, int.class, String.class,
                String.class, String.class, String.class, String.class, int.class,
                boolean.class, String.class, double.class, boolean.class, double.class,
                String.class, int.class);
        Param minConfidence = paramNamed(apply, "min_confidence");
        assertEquals("apply still has no default floor", Param.NO_DEFAULT, minConfidence.defaultValue());
        Param applySim = paramNamed(apply, "similarity_threshold");
        assertEquals("0.0", applySim.defaultValue());
        Param applyUnident = paramNamed(apply, "apply_unidentifiable");
        assertEquals("false", applyUnident.defaultValue());
        Param resolveConflicts = paramNamed(apply, "resolve_conflicts");
        assertEquals("none", resolveConflicts.defaultValue());
        Param conflictMargin = paramNamed(apply, "conflict_min_confidence_margin");
        assertEquals("5.0", conflictMargin.defaultValue());
        Param applySignatures = paramNamed(apply, "apply_signatures");
        assertEquals("signatures are opt-in", "false", applySignatures.defaultValue());
        Param renameNamed = paramNamed(apply, "rename_named");
        assertEquals("rename_named is opt-in", "false", renameNamed.defaultValue());
        Param typeArchiveMode = paramNamed(apply, "type_archive_mode");
        assertEquals("", typeArchiveMode.defaultValue());
        Param sigFloor = paramNamed(apply, "min_signature_confidence");
        assertEquals("40.0", sigFloor.defaultValue());
    }

    private static Param paramNamed(java.lang.reflect.Method method, String name) {
        for (java.lang.annotation.Annotation[] anns : method.getParameterAnnotations()) {
            for (java.lang.annotation.Annotation a : anns) {
                if (a instanceof Param p && name.equals(p.value())) {
                    return p;
                }
            }
        }
        fail("no @Param(\"" + name + "\") on " + method.getName());
        return null;
    }

    public void testQueryRequiresProgram() {
        Response r = svc.query("file:/tmp/db", "FUN_1", 0.7, 0.0, 10, "",
                "", "", "", "", 8, 0, WAIT, false, 3);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("No program loaded"));
    }

    public void testListCorpusParsesZeroExecutables() {
        Response r = svc.listCorpus("file:/tmp/empty", "", "", 100, WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson().contains("\"count\":0"));
        assertTrue(r.toJson().contains("\"executables\":[]") || r.toJson().contains("\"listed\":0"));
    }

    public void testInvalidTypeArchiveModeIsSynchronousAndSpecific() {
        Response r = svc.applyMatches("file:/tmp/db", 15.0, 0.8, true, false, true, 0.7, 10, "",
                "", "", "", "", 8, false, "none", 5.0, false, 40.0, "disassociate", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("project, file, or local"));
        assertTrue(commands.isEmpty());
    }

    public void testDryRunDefaultDoesNotNeedAProgramWhenConfidenceMissing() {
        // The confidence check must run before any write or query.
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, false, false, 0.7, 10, "",
                "", "", "", "", 8, false, "none", 5.0, false, 40.0, "", WAIT);
        assertTrue(r instanceof Response.Err);
        assertTrue(commands.isEmpty());
    }

    /**
     * The gateway-timeout fix: with {@code wait_seconds = 0} and a slow CLI,
     * the tool answers immediately with a job ticket instead of blocking past
     * the HTTP hop's budget, and {@code bsim_job_status} later serves the same
     * result the tool would have returned inline.
     */
    public void testSlowCliReturnsJobTicketAndStatusDeliversResult() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        File home = tmp.resolve("ghidra").toFile();
        BSimCli slowCli = new BSimCli((cmd, timeout) -> {
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new InterruptedException("test gate never released");
            }
            commands.add(List.copyOf(cmd));
            return new BSimCli.Result(0, canned(cmd), cmd);
        }, home);
        BSimService slow = new BSimService(
                ServiceFactory.stubProvider(), new NoopThreadingStrategy(), slowCli);

        Response ticket = slow.listCorpus("file:/tmp/slowdb", "", "", 100, 0);
        String ticketJson = ticket.toJson();
        assertFalse("a slow CLI must not surface as an error", ticket instanceof Response.Err);
        assertTrue(ticketJson, ticketJson.contains("\"status\":\"started\""));
        assertTrue(ticketJson, ticketJson.contains("job_id"));
        assertTrue(ticketJson, ticketJson.contains("bsim_job_status"));

        String jobId = extractJobId(ticketJson);
        Response running = slow.jobStatus(jobId);
        assertTrue(running.toJson(), running.toJson().contains("\"state\":\"queued\"")
                || running.toJson().contains("\"state\":\"running\""));

        release.countDown();
        String statusJson = null;
        for (int i = 0; i < 100; i++) {
            statusJson = slow.jobStatus(jobId).toJson();
            if (statusJson.contains("\"state\":\"done\"")) break;
            Thread.sleep(50);
        }
        assertNotNull(statusJson);
        assertTrue(statusJson, statusJson.contains("\"state\":\"done\""));
        assertTrue(statusJson, statusJson.contains("\"ok\":true"));
        assertTrue("the embedded result must be the tool's normal payload: " + statusJson,
                statusJson.contains("\"executables\""));
    }

    public void testJobStatusUnknownIdIsSpecificError() {
        Response r = svc.jobStatus("bsim-999-nope");
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("bsim-999-nope"));
    }

    public void testJobStatusBlankListsJobs() {
        svc.listCorpus("file:/tmp/listdb", "", "", 100, WAIT);
        Response r = svc.jobStatus("");
        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"jobs\""));
        assertTrue(json, json.contains("bsim_list_corpus"));
    }

    public void testWaitSecondsIsClampedNotRejected() {
        // Out-of-range waits clamp (0..MAX) rather than erroring: the value is
        // a transport-budget knob, not a semantic input.
        Response r = svc.listCorpus("file:/tmp/clampdb", "", "", 100, 9999);
        assertFalse(r instanceof Response.Err);
        assertTrue(r.toJson().contains("\"count\":0"));
        assertTrue(BSimJobs.MAX_WAIT_SECONDS < 60);
    }

    public void testCreateDbBlankTemplateDefaultsToMediumNosize() throws Exception {
        Path dbDir = tmp.resolve("nosize-db");
        Response r = svc.createDb("file:" + dbDir.resolve("lfs"), "", "", "", true, WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("medium_nosize"));
        List<String> created = findCommand("createdatabase");
        assertNotNull(created);
        assertTrue(created.contains("medium_nosize"));
        java.lang.reflect.Method create = BSimService.class.getMethod(
                "createDb", String.class, String.class, String.class, String.class,
                boolean.class, int.class);
        Param template = paramNamed(create, "config_template");
        assertEquals("medium_nosize", template.defaultValue());
    }

    public void testPointerSizeIngestGatesOnTemplateNotCorpus() throws Exception {
        Path db = tmp.resolve("mixdb");
        Files.writeString(Path.of(db.toString() + ".ghidra-mcp.json"),
                "{\"config_template\":\"medium_nosize\"}\n");
        // 32-bit program; listexes reports a 64-bit executable. The old guard
        // compared against corpus contents and refused. medium_nosize must not.
        BSimCli mixCli = new BSimCli((cmd, timeout) -> {
            commands.add(List.copyOf(cmd));
            if (cmd.contains("listexes")) {
                return new BSimCli.Result(0,
                        "ffff0000ffff0000ffff0000ffff0000 userland.o x86:LE:64:default gcc\n"
                                + "1 executables found\n", cmd);
            }
            return new BSimCli.Result(0, canned(cmd), cmd);
        }, tmp.resolve("ghidra").toFile());
        Program program = noClobberProgram("firmware.elf", new java.util.concurrent.CopyOnWriteArrayList<>());
        BSimService mix = new BSimService(providerOf(program), new NoopThreadingStrategy(), mixCli);
        Response r = mix.ingest("file:" + db, "firmware.elf", "", true, false, "", WAIT);
        assertFalse("medium_nosize must accept mixed pointer sizes: " + r.toJson(),
                r instanceof Response.Err);
        assertNotNull(findCommand("generatesigs"));
    }

    public void testPointerSizeIngestRefusesSizedTemplateMismatch() throws Exception {
        Path db = tmp.resolve("sized32");
        Files.writeString(Path.of(db.toString() + ".ghidra-mcp.json"),
                "{\"config_template\":\"medium_32\"}\n");
        Program program = noClobberProgram("userland.elf",
                new java.util.concurrent.CopyOnWriteArrayList<>(), 64);
        BSimService sized = new BSimService(providerOf(program), new NoopThreadingStrategy(),
                recordingCli(false));
        Response r = sized.ingest("file:" + db, "userland.elf", "", true, false, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("medium_32"));
        assertTrue(json, json.contains("64-bit"));
        assertNull(findCommand("generatesigs"));
    }

    public void testIngestSkipsIdenticalMd5() throws Exception {
        Path db = tmp.resolve("dupdb");
        BSimCli skipCli = new BSimCli((cmd, timeout) -> {
            commands.add(List.copyOf(cmd));
            if (cmd.contains("listexes")) {
                return new BSimCli.Result(0,
                        "00112233445566778899aabbccddeeff nullcog.elf ARM:LE:32:Cortex gcc\n"
                                + "1 executables found\n", cmd);
            }
            return new BSimCli.Result(0, canned(cmd), cmd);
        }, tmp.resolve("ghidra").toFile());
        Program program = noClobberProgram("nullcog.elf",
                new java.util.concurrent.CopyOnWriteArrayList<>());
        BSimService skip = new BSimService(providerOf(program), new NoopThreadingStrategy(), skipCli);
        Response r = skip.ingest("file:" + db, "nullcog.elf", "", true, false, "", WAIT);
        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("already_ingested"));
        assertTrue(json, json.contains("00112233445566778899aabbccddeeff"));
        assertNull(findCommand("generatesigs"));
    }

    public void testIngestSameMd5DifferentCompilerIsExplicit() throws Exception {
        Path db = tmp.resolve("compilerdb");
        BSimCli skipCli = new BSimCli((cmd, timeout) -> {
            commands.add(List.copyOf(cmd));
            if (cmd.contains("listexes")) {
                return new BSimCli.Result(0,
                        "00112233445566778899aabbccddeeff nullcog.elf x86:LE:64:default windows\n"
                                + "1 executables found\n", cmd);
            }
            return new BSimCli.Result(0, canned(cmd), cmd);
        }, tmp.resolve("ghidra").toFile());
        Program program = noClobberProgram("nullcog.elf",
                new java.util.concurrent.CopyOnWriteArrayList<>(), 32, "gcc");
        BSimService skip = new BSimService(providerOf(program), new NoopThreadingStrategy(), skipCli);
        Response r = skip.ingest("file:" + db, "nullcog.elf", "", true, false, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("MD5"));
        assertTrue(json, json.contains("windows"));
        assertTrue(json, json.contains("new database"));
        assertNull(findCommand("generatesigs"));
    }

    public void testQueryWholeProgramPassesAllSentinelNotDash() throws Exception {
        List<Path> saved = new java.util.concurrent.CopyOnWriteArrayList<>();
        BSimService qsvc = queryService(saved, true);
        Response r = qsvc.query("file:" + tmp.resolve("qdb"), "", 0.05, 0.0, 10, "",
                "", "", "", "", 8, 0, WAIT, false, 3);
        assertFalse(r instanceof Response.Err);
        List<String> cmd = null;
        for (List<String> c : commands) {
            if (c.contains("-postScript")) cmd = c;
        }
        assertNotNull(cmd);
        int ps = cmd.indexOf("-postScript");
        assertEquals("ALL", cmd.get(ps + 4));
        assertEquals("0.05", cmd.get(ps + 5));
        assertTrue(cmd.contains("min_feature_count=8"));
    }

    public void testQueryPassesServerSideFilters() throws Exception {
        List<Path> saved = new java.util.concurrent.CopyOnWriteArrayList<>();
        BSimService qsvc = queryService(saved, true);
        Response r = qsvc.query("file:" + tmp.resolve("qdb"), "lfs_bd_read", 0.0, 10.0, 10, "",
                "ARM:LE:32:Cortex", "littlefs.o", "gcc", "aabbccddeeff00112233445566778899",
                8, 0, WAIT, false, 3);
        assertFalse("query failed: " + r.toJson(), r instanceof Response.Err);
        List<String> cmd = null;
        for (List<String> c : commands) {
            if (c.contains("-postScript")) cmd = c;
        }
        assertNotNull(cmd);
        assertTrue(cmd.contains("arch=ARM:LE:32:Cortex"));
        assertTrue(cmd.contains("executable=littlefs.o"));
        assertTrue(cmd.contains("compiler=gcc"));
        assertTrue(cmd.contains("exclude_md5=aabbccddeeff00112233445566778899"));
    }

    public void testPackedProgramFileNamePreservesIdentity() {
        assertEquals("littlefs-v2.9.3-gcc13-arm-Os.o.gzf",
                BSimService.packedProgramFileName("littlefs-v2.9.3-gcc13-arm-Os.o"));
        assertEquals("program.gzf", BSimService.packedProgramFileName(""));
        assertEquals("weird_name.gzf", BSimService.packedProgramFileName("weird name"));
    }

    // ------------------------------------------------------------------
    // Temp-file staging: saveToPackedFile refuses to overwrite, so the gzf
    // handed to it must not exist yet. File.createTempFile pre-created it and
    // made every bsim_query fail with "<path> already exists" before anything
    // ran (issue #6). The Program proxies below enforce the same no-clobber
    // rule real Ghidra does, and every run must leave the temp dir clean.
    // ------------------------------------------------------------------

    public void testQueryStagesGzfWithoutPreCreatingIt() throws Exception {
        List<Path> saved = new CopyOnWriteArrayList<>();
        BSimService qsvc = queryService(saved, true);
        Set<String> before = tmpEntries("bsim-query-");

        Response single = qsvc.query("file:" + tmp.resolve("qdb"), "blake2b_compress",
                0.7, 0.0, 10, "", "", "", "", "", 8, 0, WAIT, false, 3);
        Response whole = qsvc.query("file:" + tmp.resolve("qdb"), "",
                0.9, 0.0, 3, "", "", "", "", "", 8, 0, WAIT, false, 3);

        assertFalse("single-function query failed: " + single.toJson(),
                single instanceof Response.Err);
        assertFalse("whole-program query failed: " + whole.toJson(),
                whole instanceof Response.Err);
        assertTrue(single.toJson(), single.toJson().contains("blake2b_compress"));
        assertEquals("both queries must export the program", 2, saved.size());
        for (Path gzf : saved) {
            assertEquals("nullcog.elf.gzf", gzf.getFileName().toString());
            assertFalse("gzf must be cleaned up: " + gzf, Files.exists(gzf));
            assertFalse("query work dir must be cleaned up: " + gzf.getParent(),
                    Files.exists(gzf.getParent()));
        }
        assertEquals("no bsim-query-* entries may remain in the temp dir",
                before, tmpEntries("bsim-query-"));
    }

    public void testQueryFailureStillCleansUpTempWork() throws Exception {
        List<Path> saved = new CopyOnWriteArrayList<>();
        BSimService qsvc = queryService(saved, false); // runner writes no JSON
        Set<String> before = tmpEntries("bsim-query-");

        Response r = qsvc.query("file:" + tmp.resolve("qdb"), "", 0.7, 0.0, 10, "",
                "", "", "", "", 8, 0, WAIT, false, 3);

        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("produced no JSON"));
        assertEquals(1, saved.size());
        assertFalse("gzf must be cleaned up on failure too", Files.exists(saved.get(0)));
        assertEquals(before, tmpEntries("bsim-query-"));
    }

    public void testIngestStagesOpenProgramWithoutPreCreatingGzf() throws Exception {
        List<Path> saved = new CopyOnWriteArrayList<>();
        Program program = noClobberProgram("nullcog.elf", saved);
        BSimService isvc = new BSimService(providerOf(program),
                new NoopThreadingStrategy(), recordingCli(false));
        Set<String> beforeXml = tmpEntries("bsim-xml-");
        Set<String> beforeGzf = tmpEntries("bsim-ingest-");

        Response r = isvc.ingest("file:" + tmp.resolve("idb"), "nullcog.elf",
                "", true, false, "", WAIT);

        assertFalse("ingest of an open program failed: " + r.toJson(),
                r instanceof Response.Err);
        assertEquals("staging must export the program once", 1, saved.size());
        assertEquals("nullcog.elf.gzf", saved.get(0).getFileName().toString());
        assertFalse("staged gzf must be cleaned up", Files.exists(saved.get(0)));
        assertEquals("temp signature-xml dirs must not leak",
                beforeXml, tmpEntries("bsim-xml-"));
        assertEquals("no bsim-ingest-* entries may remain in the temp dir",
                beforeGzf, tmpEntries("bsim-ingest-"));
    }

    /** Service whose provider holds a no-clobber Program and whose fake
     *  analyzeHeadless optionally writes the query-result JSON. */
    private BSimService queryService(List<Path> saved, boolean writeJson) {
        Program program = noClobberProgram("nullcog.elf", saved);
        return new BSimService(providerOf(program),
                new NoopThreadingStrategy(), recordingCli(writeJson));
    }

    private BSimCli recordingCli(boolean writeQueryJson) {
        return new BSimCli(new BSimCli.Runner() {
            @Override
            public BSimCli.Result run(List<String> cmd, Duration timeout) {
                return run(cmd, timeout, null);
            }

            @Override
            public BSimCli.Result run(List<String> cmd, Duration timeout, String stdinData) {
                commands.add(List.copyOf(cmd));
                stdins.add(stdinData == null ? "" : stdinData);
                int ps = cmd.indexOf("-postScript");
                if (writeQueryJson && ps >= 0) {
                    // args after -postScript: scriptName, dbUrl, outJson, func, ...
                    Path outJson = Path.of(cmd.get(ps + 3));
                    boolean wholeProgram = "ALL".equals(cmd.get(ps + 4))
                            || "-".equals(cmd.get(ps + 4));
                    try {
                        Files.writeString(outJson, wholeProgram
                                ? "{\"program\":\"nullcog.elf\",\"results\":["
                                        + SINGLE_FUNCTION_JSON + "]}"
                                : SINGLE_FUNCTION_JSON);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
                return new BSimCli.Result(0, canned(cmd), cmd);
            }
        }, tmp.resolve("ghidra").toFile());
    }

    private static final String SINGLE_FUNCTION_JSON =
            "{\"function\":\"blake2b_compress\",\"address\":\"0x1000\",\"matches\":["
                    + "{\"name\":\"blake2b_compress\",\"similarity\":1.0,\"confidence\":95.0,"
                    + "\"executable\":\"nullcog-v2\",\"arch\":\"x86:LE:32:default\","
                    + "\"md5\":\"ffff\",\"address\":\"0x1000\"}]}";

    private static ProgramProvider providerOf(Program p) {
        return new ProgramProvider() {
            @Override public Program getCurrentProgram() { return p; }
            @Override public Program getProgram(String name) {
                return p.getName().equals(name) ? p : null;
            }
            @Override public Program[] getAllOpenPrograms() { return new Program[] {p}; }
            @Override public void setCurrentProgram(Program program) { }
        };
    }

    private static Program noClobberProgram(String name, List<Path> saved) {
        return noClobberProgram(name, saved, 32, "gcc");
    }

    private static Program noClobberProgram(String name, List<Path> saved, int bits) {
        return noClobberProgram(name, saved, bits, "gcc");
    }

    /** A Program that, like real Ghidra, refuses to saveToPackedFile onto an
     *  existing file — the exact behavior the temp staging must respect. */
    private static Program noClobberProgram(String name, List<Path> saved, int bits, String compiler) {
        return (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(), new Class<?>[] {Program.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "getExecutableMD5" -> "00112233445566778899aabbccddeeff";
                    case "getExecutablePath" -> "";
                    case "getCompilerSpec" -> compilerSpec(compiler);
                    case "getLanguageID" -> languageId(bits);
                    case "saveToPackedFile" -> {
                        File f = (File) args[0];
                        if (f.exists()) {
                            throw new IOException(f.getAbsolutePath() + " already exists");
                        }
                        Files.write(f.toPath(), new byte[] {0x1f, (byte) 0x8b});
                        saved.add(f.toPath());
                        yield null;
                    }
                    case "getFunctionManager" -> emptyFunctionManager();
                    case "getLanguage" -> languageOf(bits);
                    case "getDomainFile" -> localDomainFile();
                    case "toString" -> name;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static FunctionManager emptyFunctionManager() {
        FunctionIterator none = (FunctionIterator) Proxy.newProxyInstance(
                FunctionIterator.class.getClassLoader(),
                new Class<?>[] {FunctionIterator.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "iterator" -> prox;
                    case "hasNext" -> false;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return (FunctionManager) Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getFunctionCount" -> 3;
                    case "getFunctions" -> none;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static Language languageOf(int bits) {
        LanguageDescription desc = (LanguageDescription) Proxy.newProxyInstance(
                LanguageDescription.class.getClassLoader(),
                new Class<?>[] {LanguageDescription.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSize" -> bits;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return (Language) Proxy.newProxyInstance(
                Language.class.getClassLoader(), new Class<?>[] {Language.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getLanguageDescription" -> desc;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static ghidra.program.model.lang.LanguageID languageId(int bits) {
        String id = bits == 64 ? "x86:LE:64:default" : "ARM:LE:32:Cortex";
        return new ghidra.program.model.lang.LanguageID(id);
    }

    private static ghidra.program.model.lang.CompilerSpec compilerSpec(String id) {
        ghidra.program.model.lang.CompilerSpecID specId =
                new ghidra.program.model.lang.CompilerSpecID(id);
        return (ghidra.program.model.lang.CompilerSpec) Proxy.newProxyInstance(
                ghidra.program.model.lang.CompilerSpec.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.lang.CompilerSpec.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getCompilerSpecID" -> specId;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static DomainFile localDomainFile() {
        return (DomainFile) Proxy.newProxyInstance(
                DomainFile.class.getClassLoader(), new Class<?>[] {DomainFile.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSharedProjectURL" -> null;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static Set<String> tmpEntries(String prefix) throws IOException {
        try (var entries = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return entries.map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith(prefix))
                    .collect(Collectors.toSet());
        }
    }

    private static String extractJobId(String json) {
        int at = json.indexOf("\"job_id\":");
        assertTrue("no job_id in: " + json, at >= 0);
        int start = json.indexOf('"', at + 9) + 1;
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    /**
     * The corroboration extract for a {@code ghidra://} source runs its own
     * {@code analyzeHeadless}, and {@code -p} is what makes that JVM pass
     * {@code allowPasswordPrompt = true} into {@code HeadlessClientAuthenticator}.
     * Without it the authenticator logs "not configured to supply required
     * password" and returns its BADPASSWORD sentinel — it never reads the pipe,
     * so the password we do write is irrelevant and the extract cannot
     * authenticate at all. {@code -connect} only names the user.
     */
    public void testCorroborationExtractAgainstServerUrlAllowsThePasswordPrompt() {
        com.xebyte.core.BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        com.xebyte.core.BSimTestEnv.setUser("bsim");
        com.xebyte.core.BSimTestEnv.setPassword("bsim-secret");
        BSimTestCredentials.install("5n4ck3y", "ghidra-secret");
        Response r = svc.ingest(
                "postgresql://ghidra-bsim:5432/embedded",
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
                "", true, false, "", WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        List<String> extract = findCommand("BSim_McpExtract.java");
        assertNotNull("a ghidra:// ingest must still extract corroboration", extract);
        int connect = extract.indexOf("-connect");
        assertTrue("-connect names the Ghidra Server user", connect >= 0);
        assertEquals("5n4ck3y", extract.get(connect + 1));
        assertTrue("-p is what enables the stdin password prompt",
                extract.contains("-p"));
        assertFalse("the password must never appear in argv",
                extract.contains("ghidra-secret"));
    }

    private List<String> findCommand(String verb) {
        for (List<String> cmd : commands) {
            if (cmd.contains(verb)) return cmd;
        }
        return null;
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (root == null || !Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        }
    }

    private static String canned(List<String> cmd) {
        if (cmd.contains("getexecount") || cmd.contains("listexes")) {
            return "Matching executable count: 0\n0 executables found\n";
        }
        return "ok\n";
    }
}
