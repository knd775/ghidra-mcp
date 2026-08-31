package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pure-reflection tests for {@link AnnotationScanner}.
 *
 * <p>These tests run fully offline — no Ghidra HTTP server, no loaded program.
 * They catch regressions in the annotation layer itself: a method missing
 * {@code @McpTool}, a duplicate path, malformed schema JSON, or the scanner
 * silently dropping an endpoint after a refactor.
 *
 * <p>This is the "Tier 0" of the offline testing strategy from issue #112 —
 * it doesn't need a {@code FixtureProgramProvider} at all, because the
 * scanner never invokes handlers; it only reads annotations.
 */
public class AnnotationScannerOfflineTest extends TestCase {

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    /** Scanner must discover a meaningful number of endpoints — empty means a wiring regression. */
    public void testScannerDiscoversEndpoints() {
        List<EndpointDef> endpoints = scanner.getEndpoints();
        assertNotNull("Scanner returned null endpoint list", endpoints);
        assertFalse("Scanner discovered zero endpoints — all services may have lost their @McpTool annotations",
            endpoints.isEmpty());

        // Sanity floor: v5.3.2 ships ~150+ annotation-scanned tools. Anything
        // well below that indicates an entire service class was dropped.
        assertTrue(
            "Expected at least 100 annotation-scanned endpoints, got " + endpoints.size()
                + ". A service class may have been dropped from ServiceFactory.",
            endpoints.size() >= 100);
    }

    /** Every endpoint path must be well-formed: non-null, leading slash, no whitespace. */
    public void testEndpointPathsAreWellFormed() {
        List<String> bad = new ArrayList<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            String path = ep.path();
            if (path == null || path.isEmpty()) {
                bad.add("<null-or-empty>");
                continue;
            }
            if (!path.startsWith("/")) {
                bad.add(path + " (missing leading slash)");
            }
            if (path.contains(" ") || path.contains("\t")) {
                bad.add(path + " (contains whitespace)");
            }
        }
        assertTrue("Malformed endpoint paths: " + bad, bad.isEmpty());
    }

    /** Paths must be unique — duplicate paths mean {@code createContext} collisions at runtime. */
    public void testNoDuplicatePaths() {
        Set<String> seen = new HashSet<>();
        Set<String> dupes = new HashSet<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            if (!seen.add(ep.path())) {
                dupes.add(ep.path());
            }
        }
        assertTrue(
            "Duplicate @McpTool paths would cause runtime createContext collisions: " + dupes,
            dupes.isEmpty());
    }

    /** Every endpoint must declare a valid HTTP method. */
    public void testEveryEndpointHasValidMethod() {
        List<String> bad = new ArrayList<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            String m = ep.method();
            if (!"GET".equalsIgnoreCase(m) && !"POST".equalsIgnoreCase(m)) {
                bad.add(ep.path() + " -> " + m);
            }
        }
        assertTrue("Endpoints with non-GET/POST method: " + bad, bad.isEmpty());
    }

    /** {@link AnnotationScanner#generateSchema} must produce parseable JSON. */
    public void testGenerateSchemaIsValidJson() {
        String schema = scanner.generateSchema();
        assertNotNull("generateSchema returned null", schema);
        assertFalse("generateSchema returned empty string", schema.isEmpty());

        JsonObject root;
        try {
            root = new Gson().fromJson(schema, JsonObject.class);
        } catch (RuntimeException e) {
            fail("generateSchema() produced invalid JSON: " + e.getMessage()
                + "\nFirst 500 chars: " + schema.substring(0, Math.min(500, schema.length())));
            return;
        }
        assertNotNull("Schema root is null", root);

        // Top-level shape: { "tools": [...], "count": N }
        assertTrue("Schema missing 'tools' array", root.has("tools"));
        assertTrue("Schema missing 'count' field", root.has("count"));

        JsonArray tools = root.getAsJsonArray("tools");
        int count = root.get("count").getAsInt();
        assertEquals("Schema count field disagrees with tools array length",
            tools.size(), count);
    }

    /**
     * Every tool descriptor in the schema must have the fields the Python bridge
     * depends on: path, method, params. Missing any of these breaks dynamic tool
     * registration in {@code bridge_mcp_ghidra.py}.
     */
    public void testSchemaToolDescriptorsHaveRequiredFields() {
        String schema = scanner.generateSchema();
        JsonObject root = new Gson().fromJson(schema, JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");

        List<String> broken = new ArrayList<>();
        for (JsonElement el : tools) {
            JsonObject tool = el.getAsJsonObject();
            String path = tool.has("path") ? tool.get("path").getAsString() : "<no-path>";
            if (!tool.has("path")) broken.add(path + " (missing path)");
            if (!tool.has("method")) broken.add(path + " (missing method)");
            if (!tool.has("params")) broken.add(path + " (missing params)");
            if (tool.has("params") && !tool.get("params").isJsonArray()) {
                broken.add(path + " (params not an array)");
            }
        }
        assertTrue("Schema tool descriptors missing required fields: " + broken, broken.isEmpty());
    }

    /**
     * Every declared param in the schema must itself have a name, type, source,
     * and required flag. The Python bridge uses these to decide query-vs-body
     * encoding and to report the tool's signature to the AI client.
     */
    public void testSchemaParamDescriptorsHaveRequiredFields() {
        String schema = scanner.generateSchema();
        JsonObject root = new Gson().fromJson(schema, JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");

        List<String> broken = new ArrayList<>();
        for (JsonElement el : tools) {
            JsonObject tool = el.getAsJsonObject();
            String path = tool.get("path").getAsString();
            JsonArray params = tool.getAsJsonArray("params");
            for (JsonElement pel : params) {
                JsonObject param = pel.getAsJsonObject();
                String name = param.has("name") ? param.get("name").getAsString() : "<no-name>";
                String where = path + "::" + name;
                if (!param.has("name")) broken.add(where + " (missing name)");
                if (!param.has("type")) broken.add(where + " (missing type)");
                if (!param.has("source")) broken.add(where + " (missing source)");
                if (!param.has("required")) broken.add(where + " (missing required)");
            }
        }
        assertTrue("Schema param descriptors missing required fields: " + broken, broken.isEmpty());
    }

    /**
     * Boxed Integer/Boolean params with {@code defaultValue} must return the
     * parsed default — not {@code null} — when no value is supplied, for both
     * QUERY and BODY sources.
     *
     * <p>This is a regression test for H13: the {@code Integer.class} and
     * {@code Boolean.class} branches in {@code resolveQueryParam} /
     * {@code resolveBodyParam} were ignoring {@code hasDef}/{@code def} and
     * returning {@code null}, unlike the primitive {@code int}/{@code boolean}
     * branches which already honored it.
     */
    public void testBoxedParamHonorsDefaultValue() throws Exception {
        BoxedDefaultFixture fixture = new BoxedDefaultFixture();
        AnnotationScanner fixtureScanner = new AnnotationScanner(fixture);
        List<EndpointDef> endpoints = fixtureScanner.getEndpoints();

        // Find GET (QUERY source) and POST (BODY source) handlers
        EndpointDef getEndpoint = null;
        EndpointDef postEndpoint = null;
        for (EndpointDef ep : endpoints) {
            if ("/test_boxed_query".equals(ep.path())) getEndpoint = ep;
            if ("/test_boxed_body".equals(ep.path()))  postEndpoint = ep;
        }
        assertNotNull("GET fixture endpoint not found", getEndpoint);
        assertNotNull("POST fixture endpoint not found", postEndpoint);

        // Invoke GET handler with no query parameters
        Map<String, String> emptyQuery = Collections.emptyMap();
        Map<String, Object> emptyBody  = Collections.emptyMap();
        getEndpoint.handler().handle(emptyQuery, emptyBody);

        assertEquals("QUERY: boxed Integer with defaultValue=\"0\" and absent value should return 0",
            Integer.valueOf(0), fixture.lastLength);
        assertEquals("QUERY: boxed Boolean with defaultValue=\"true\" and absent value should return Boolean.TRUE",
            Boolean.TRUE, fixture.lastStrict);

        // Invoke POST handler with no body parameters
        postEndpoint.handler().handle(emptyQuery, emptyBody);

        assertEquals("BODY: boxed Integer with defaultValue=\"5\" and absent value should return 5",
            Integer.valueOf(5), fixture.lastBodyLength);
        assertEquals("BODY: boxed Boolean with defaultValue=\"false\" and absent value should return Boolean.FALSE",
            Boolean.FALSE, fixture.lastBodyStrict);
    }

    /**
     * Tiny fixture service scanned by {@link #testBoxedParamHonorsDefaultValue}.
     * The two {@code @McpTool} methods capture their resolved arguments so the test
     * can assert the values without needing to parse the Response JSON.
     */
    static class BoxedDefaultFixture {

        // Captured by the QUERY handler
        volatile Integer lastLength;
        volatile Boolean lastStrict;

        // Captured by the BODY handler
        volatile Integer lastBodyLength;
        volatile Boolean lastBodyStrict;

        @McpTool(path = "/test_boxed_query", method = "GET",
                 description = "Fixture: boxed Integer/Boolean via QUERY source")
        public Response queryBoxed(
                @Param(value = "length", defaultValue = "0") Integer length,
                @Param(value = "strict", defaultValue = "true") Boolean strict) {
            lastLength = length;
            lastStrict = strict;
            return Response.ok("ok");
        }

        @McpTool(path = "/test_boxed_body", method = "POST",
                 description = "Fixture: boxed Integer/Boolean via BODY source")
        public Response bodyBoxed(
                @Param(value = "length", source = ParamSource.BODY, defaultValue = "5") Integer length,
                @Param(value = "strict", source = ParamSource.BODY, defaultValue = "false") Boolean strict) {
            lastBodyLength = length;
            lastBodyStrict = strict;
            return Response.ok("ok");
        }
    }

    /**
     * Regression test for the 2026-08-09 incident: a raw-HTTP caller that follows this
     * project's own "POST params go in the JSON body" convention (CLAUDE.md "Code
     * Conventions") and puts {@code dry_run} in the body got a REAL write with a
     * response that still looked like a preview. Root cause: the dry-run gate at
     * {@code AnnotationScanner.createHandler} checked only {@code query.get("dry_run")},
     * never the parsed body map, so body-supplied dry_run was silently ignored and the
     * rollback-wrapped branch never ran. Confirmed live against /batch_set_comments,
     * where it overwrote a verified-good plate comment before being caught and reverted.
     *
     * <p>A later incident (bsim_create_db, import_program, terminate_checkout) showed
     * the rollback wrapper is not enough: side effects outside a Program transaction
     * still commit. Tools that do not declare {@code dry_run} must not be invoked at
     * all. Tools that declare it are responsible for a read-only preview.
     */
    public void testDryRunWithoutDeclaredParamDoesNotInvoke() throws Exception {
        DryRunWriteFixture fixture = new DryRunWriteFixture();
        Program program = mock(Program.class);
        when(program.startTransaction(org.mockito.ArgumentMatchers.anyString())).thenReturn(42);

        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProgram("Test.dll")).thenReturn(program);
        when(provider.getCurrentProgram()).thenReturn(program);

        AnnotationScanner fixtureScanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef endpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_dry_run_write".equals(ep.path())) endpoint = ep;
        }
        assertNotNull("Fixture endpoint not found", endpoint);

        Map<String, String> query = new HashMap<>();
        query.put("program", "Test.dll");
        Map<String, Object> body = new HashMap<>();
        body.put("dry_run", Boolean.TRUE);
        Response response = endpoint.handler().handle(query, body);

        assertFalse("Undeclared dry_run must not invoke the method (CLI/file side effects cannot roll back)",
            fixture.invoked);
        verify(program, never()).startTransaction(org.mockito.ArgumentMatchers.anyString());
        String json = response.toJson();
        assertTrue(json, json.contains("\"dry_run\":true") || json.contains("\"dry_run\": true"));
        assertTrue(json, json.contains("would_execute"));
        assertTrue(json, json.contains("/test_dry_run_write"));
    }

    public void testDeclaredDryRunIsInvokedWithoutOpeningTransaction() throws Exception {
        DeclaredDryRunFixture fixture = new DeclaredDryRunFixture();
        Program program = mock(Program.class);
        when(program.startTransaction(org.mockito.ArgumentMatchers.anyString())).thenReturn(42);

        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProgram("Test.dll")).thenReturn(program);

        AnnotationScanner fixtureScanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef endpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_declared_dry_run".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);

        Map<String, String> query = new HashMap<>();
        query.put("program", "Test.dll");
        Map<String, Object> body = new HashMap<>();
        body.put("dry_run", Boolean.TRUE);
        endpoint.handler().handle(query, body);

        assertTrue("Declared dry_run must invoke so the method can preview", fixture.invoked);
        verify(program, never()).startTransaction(org.mockito.ArgumentMatchers.anyString());
        verify(program, never()).endTransaction(anyInt(), anyBoolean());
    }

    public void testFailedDeclaredDryRunLeavesNoTransactionForRetry() throws Exception {
        FailOnceDeclaredDryRunFixture fixture = new FailOnceDeclaredDryRunFixture();
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProgram("Test.dll")).thenReturn(program);

        AnnotationScanner fixtureScanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef endpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_fail_once_declared_dry_run".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);

        Map<String, Object> body = new HashMap<>();
        body.put("program", "Test.dll");
        body.put("dry_run", Boolean.TRUE);
        Response first = endpoint.handler().handle(Collections.emptyMap(), body);
        Response second = endpoint.handler().handle(Collections.emptyMap(), body);

        assertTrue(first instanceof Response.Err);
        assertFalse("retry must reach the endpoint after the first failure",
                second instanceof Response.Err);
        assertEquals(2, fixture.calls);
        verify(program, never()).startTransaction(org.mockito.ArgumentMatchers.anyString());
        verify(program, never()).endTransaction(anyInt(), anyBoolean());
    }

    public void testControlWithoutDryRunStillInvokes() throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("program", "Test.dll");
        Program program2 = mock(Program.class);
        ProgramProvider provider2 = mock(ProgramProvider.class);
        when(provider2.getProgram("Test.dll")).thenReturn(program2);
        DryRunWriteFixture fixture2 = new DryRunWriteFixture();
        AnnotationScanner fixtureScanner2 = new AnnotationScanner(provider2, new Object[] { fixture2 });
        EndpointDef endpoint2 = null;
        for (EndpointDef ep : fixtureScanner2.getEndpoints()) {
            if ("/test_dry_run_write".equals(ep.path())) endpoint2 = ep;
        }
        endpoint2.handler().handle(query, Collections.emptyMap());
        assertTrue("Fixture method must be invoked on a real (non-dry-run) call", fixture2.invoked);
        verify(program2, never()).endTransaction(anyInt(), eq(false));
    }

    /**
     * Every POST {@code @McpTool} that does not declare {@code dry_run} must
     * short-circuit. This is the regression net for bsim_create_db /
     * import_program / any future write that forgets the flag: one assertion,
     * every endpoint.
     */
    public void testUndeclaredDryRunShortCircuitsEveryPostEndpoint() throws Exception {
        JsonObject root = new Gson().fromJson(scanner.generateSchema(), JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");
        Map<String, Boolean> declaresDryRun = new HashMap<>();
        int undeclaredPosts = 0;
        for (JsonElement el : tools) {
            JsonObject t = el.getAsJsonObject();
            if (!"POST".equalsIgnoreCase(t.get("method").getAsString())) continue;
            boolean hasDry = false;
            JsonArray params = t.getAsJsonArray("params");
            if (params != null) {
                for (JsonElement p : params) {
                    if ("dry_run".equals(p.getAsJsonObject().get("name").getAsString())) {
                        hasDry = true;
                        break;
                    }
                }
            }
            declaresDryRun.put(t.get("path").getAsString(), hasDry);
            if (!hasDry) undeclaredPosts++;
        }
        assertTrue("expected POST tools without a dry_run param (bsim_create_db, import_program)",
            undeclaredPosts > 0);

        Map<String, EndpointDef> byPath = new HashMap<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            byPath.put(ep.path(), ep);
        }

        List<String> failed = new ArrayList<>();
        int checked = 0;
        for (Map.Entry<String, Boolean> e : declaresDryRun.entrySet()) {
            if (e.getValue()) continue;
            EndpointDef ep = byPath.get(e.getKey());
            if (ep == null) continue; // manual descriptors are not dispatched here
            Map<String, String> query = new HashMap<>();
            query.put("dry_run", "true");
            Response response = ep.handler().handle(query, Collections.emptyMap());
            String json = response.toJson();
            checked++;
            if (!json.contains("would_execute") || !json.contains("\"dry_run\":true")) {
                failed.add(e.getKey() + " -> " + json);
            }
        }
        assertTrue("checked undeclared POST tools, got " + checked, checked > 0);
        assertTrue("dry_run=true must not invoke undeclared POST tools: " + failed, failed.isEmpty());
        assertTrue(declaresDryRun.containsKey("/bsim_create_db")
            && Boolean.FALSE.equals(declaresDryRun.get("/bsim_create_db")));
        assertTrue(declaresDryRun.containsKey("/import_program")
            && Boolean.FALSE.equals(declaresDryRun.get("/import_program")));
        assertTrue(declaresDryRun.containsKey("/bsim_apply_matches")
            && Boolean.TRUE.equals(declaresDryRun.get("/bsim_apply_matches")));
    }

    public void testProgramParamAcceptsJsonBody() throws Exception {
        ProgramBodyFixture fixture = new ProgramBodyFixture();
        AnnotationScanner fixtureScanner = new AnnotationScanner(null, new Object[] { fixture });
        EndpointDef endpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_program_body".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);

        Map<String, Object> body = new HashMap<>();
        body.put("program", "firmware.elf");
        body.put("db_url", "file:/tmp/db");
        endpoint.handler().handle(Collections.emptyMap(), body);
        assertEquals("firmware.elf", fixture.seenProgram);

        fixture.seenProgram = null;
        Map<String, String> query = new HashMap<>();
        query.put("program", "from-query.elf");
        body.put("program", "from-body.elf");
        endpoint.handler().handle(query, body);
        assertEquals("query string wins", "from-query.elf", fixture.seenProgram);
    }

    /** Tiny fixture service scanned by {@link #testDryRunWithoutDeclaredParamDoesNotInvoke}. */
    static class DryRunWriteFixture {
        volatile boolean invoked;

        @McpTool(path = "/test_dry_run_write", method = "POST",
                 description = "Fixture: a write endpoint used to prove dry_run routing")
        public Response write(
                @Param(value = "program", defaultValue = "") String program) {
            invoked = true;
            return Response.ok("wrote");
        }
    }

    /** Fixture whose method declares dry_run and is therefore invoked on preview. */
    static class DeclaredDryRunFixture {
        volatile boolean invoked;

        @McpTool(path = "/test_declared_dry_run", method = "POST",
                 description = "Fixture: declares dry_run so the scanner invokes it")
        public Response write(
                @Param(value = "program", defaultValue = "") String program,
                @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "true")
                        boolean dryRun) {
            invoked = true;
            return Response.ok(java.util.Map.of("dry_run", dryRun, "status", "preview"));
        }
    }

    static class FailOnceDeclaredDryRunFixture {
        int calls;

        @McpTool(path = "/test_fail_once_declared_dry_run", method = "POST",
                 description = "Fixture: first dry-run fails and the retry must remain usable")
        public Response write(
                @Param(value = "program", defaultValue = "") String program,
                @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "true")
                        boolean dryRun) {
            calls++;
            if (calls == 1) throw new IllegalStateException("planned failure");
            return Response.ok(java.util.Map.of("dry_run", dryRun, "status", "preview"));
        }
    }

    static class ProgramBodyFixture {
        volatile String seenProgram;

        @McpTool(path = "/test_program_body", method = "POST",
                 description = "Fixture: QUERY-sourced program must also accept JSON body")
        public Response write(
                @Param(value = "program", defaultValue = "") String program,
                @Param(value = "db_url", source = ParamSource.BODY, defaultValue = "") String dbUrl) {
            seenProgram = program;
            return Response.ok("ok");
        }
    }
}
