package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.BSimCli;
import com.xebyte.core.BSimJobs;
import com.xebyte.core.BSimService;
import com.xebyte.core.BSimTestCredentials;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
        if (tmp != null) {
            deleteRecursively(tmp);
        }
    }

    public void testCreateDbCommandLine() {
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
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, true, 0.7, 10, "", WAIT);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("min_confidence"));
        assertFalse("must not invent a default floor", json.contains("\"min_confidence\":0"));
        assertTrue(commands.isEmpty());
    }

    public void testQueryRequiresProgram() {
        Response r = svc.query("file:/tmp/db", "FUN_1", 0.7, 0.0, 10, "", WAIT);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("No program loaded"));
    }

    public void testListCorpusParsesZeroExecutables() {
        Response r = svc.listCorpus("file:/tmp/empty", "", "", 100, WAIT);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson().contains("\"count\":0"));
        assertTrue(r.toJson().contains("\"executables\":[]") || r.toJson().contains("\"listed\":0"));
    }

    public void testDryRunDefaultDoesNotNeedAProgramWhenConfidenceMissing() {
        // The confidence check must run before any write or query.
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, false, 0.7, 10, "", WAIT);
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

    private static String extractJobId(String json) {
        int at = json.indexOf("\"job_id\":");
        assertTrue("no job_id in: " + json, at >= 0);
        int start = json.indexOf('"', at + 9) + 1;
        int end = json.indexOf('"', start);
        return json.substring(start, end);
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
