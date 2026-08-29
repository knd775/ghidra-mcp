package com.xebyte.offline;

import com.xebyte.core.BSimCli;
import com.xebyte.core.BSimService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Validation coverage for BSimService that does not spawn Ghidra.
 */
public class BSimServiceValidationTest extends TestCase {

    private Path tmp;
    private BSimService svc;
    private final List<List<String>> commands = new CopyOnWriteArrayList<>();

    @Override
    protected void setUp() throws Exception {
        tmp = Files.createTempDirectory("bsim-test-");
        File home = tmp.resolve("ghidra").toFile();
        File support = new File(home, "support");
        assertTrue(support.mkdirs());
        assertTrue(new File(support, "bsim").createNewFile());
        assertTrue(new File(support, "analyzeHeadless").createNewFile());
        BSimCli cli = new BSimCli((cmd, timeout) -> {
            commands.add(List.copyOf(cmd));
            String output = canned(cmd);
            return new BSimCli.Result(0, output, cmd);
        }, home);
        ThreadingStrategy ts = new NoopThreadingStrategy();
        svc = new BSimService(ServiceFactory.stubProvider(), ts, cli);
    }

    @Override
    protected void tearDown() throws Exception {
        if (tmp != null) {
            BSimService.deleteRecursively(tmp);
        }
    }

    public void testCreateDbCommandLine() {
        Path dbDir = tmp.resolve("bsimdb");
        Response r = svc.createDb("file:" + dbDir.resolve("lfs"), "medium_32", "lfs", "test db", true);
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
        Response r = svc.createDb("file:" + dbDir.resolve("lfs"), "medium_32", "", "", false);
        assertFalse(r instanceof Response.Err);
        List<String> created = findCommand("createdatabase");
        assertTrue(created.contains("--nocallgraph"));
    }

    public void testCreateDbRejectsUnknownTemplate() {
        Response r = svc.createDb("file:" + tmp.resolve("x"), "not_a_template", "", "", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("config_template"));
    }

    public void testIngestRequiresSource() {
        Response r = svc.ingest("file:" + tmp.resolve("db"), "", "", true, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("source"));
    }

    public void testApplyRequiresMinConfidence() {
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, true, 0.7, 10, "");
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("min_confidence"));
        assertFalse("must not invent a default floor", json.contains("\"min_confidence\":0"));
        assertTrue(commands.isEmpty());
    }

    public void testQueryRequiresProgram() {
        Response r = svc.query("file:/tmp/db", "FUN_1", 0.7, 0.0, 10, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson().contains("No program loaded"));
    }

    public void testListCorpusParsesZeroExecutables() {
        Response r = svc.listCorpus("file:/tmp/empty", "", "", 100);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson().contains("\"count\":0"));
        assertTrue(r.toJson().contains("\"executables\":[]") || r.toJson().contains("\"listed\":0"));
    }

    public void testDryRunDefaultDoesNotNeedAProgramWhenConfidenceMissing() {
        // The confidence check must run before any write or query.
        Response r = svc.applyMatches("file:/tmp/db", null, 0.8, true, false, 0.7, 10, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(commands.isEmpty());
    }

    private List<String> findCommand(String verb) {
        for (List<String> cmd : commands) {
            if (cmd.contains(verb)) return cmd;
        }
        return null;
    }

    private static String canned(List<String> cmd) {
        if (cmd.contains("getexecount") || cmd.contains("listexes")) {
            return "Matching executable count: 0\n0 executables found\n";
        }
        return "ok\n";
    }
}
