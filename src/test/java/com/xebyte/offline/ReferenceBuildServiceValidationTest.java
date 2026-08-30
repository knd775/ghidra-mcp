package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.BuilderClient;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.ReferenceBuild;
import com.xebyte.core.ReferenceBuildService;
import com.xebyte.core.ReferenceManifest;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Offline coverage for build_reference / build_manifest. The builder is never
 * contacted; a recording client would fail the test if dry_run leaked a compile.
 */
public class ReferenceBuildServiceValidationTest extends TestCase {

    private Path tmp;
    private BuilderClient.Recording client;
    private ReferenceBuildService svc;

    @Override
    protected void setUp() throws Exception {
        tmp = Files.createTempDirectory("refbuild-");
        client = new BuilderClient.Recording();
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        ok.put("path", tmp.resolve("uploads/littlefs-v2.9.3-gcc13-Os.o").toString());
        ok.put("bytes", 34_000);
        ok.put("sha256", "abc");
        ok.put("function_count", 12);
        ok.put("defined_functions", List.of("lfs_bd_read"));
        ok.put("commit_sha", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        ok.put("cc_version", "arm-none-eabi-gcc 13.2.1");
        client.setResponse(ok);
        ReferenceBuild.BuilderConfig cfg = new ReferenceBuild.BuilderConfig(
                ReferenceBuild.defaultToolchainUrls(), tmp, "", Duration.ofSeconds(5));
        svc = new ReferenceBuildService(cfg, client);
    }

    @Override
    protected void tearDown() throws Exception {
        if (tmp != null) {
            deleteRecursively(tmp);
        }
    }

    public void testDryRunDoesNotCallBuilder() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "-mcpu=cortex-m0plus -mthumb",
                "-Os",
                List.of("LFS_NO_MALLOC", "LFS_NO_ASSERT"),
                List.of(),
                true,
                "",
                true);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("would_execute") || json.contains("\"dry_run\":true"));
        assertTrue(json, json.contains("arm-none-eabi-gcc"));
        assertTrue(json, json.contains("-fno-common"));
        assertTrue(json, json.contains("-ffunction-sections"));
        assertTrue(json, json.contains("-DLFS_NO_MALLOC"));
        assertTrue(json, json.contains("littlefs-v2.9.3-gcc13-Os.o"));
        assertTrue("dry_run must not clone or compile", client.calls.isEmpty());
    }

    public void testScannerDryRunDoesNotCallBuilder() throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(
                ServiceFactory.stubProvider(), new Object[] { svc });
        EndpointDef endpoint = null;
        for (EndpointDef ep : scanner.getEndpoints()) {
            if ("/build_reference".equals(ep.path())) endpoint = ep;
        }
        assertNotNull(endpoint);
        Map<String, String> query = new HashMap<>();
        query.put("dry_run", "true");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", "littlefs");
        body.put("repo", "https://github.com/littlefs-project/littlefs.git");
        body.put("ref", "v2.9.3");
        body.put("sources", List.of("lfs.c"));
        body.put("dry_run", Boolean.TRUE);
        Response r = endpoint.handler().handle(query, body);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(client.calls.isEmpty());
        assertTrue(r.toJson().contains("arm-none-eabi-gcc"));
    }

    public void testRejectsBranchNameWithoutContactingBuilder() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "main",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("branch"));
        assertTrue(r.toJson(), r.toJson().contains("main"));
        assertTrue(client.calls.isEmpty());
    }

    public void testUnknownToolchainListsAvailable() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc99",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("gcc10"));
        assertTrue(json, json.contains("gcc12"));
        assertTrue(json, json.contains("gcc13"));
        assertTrue(client.calls.isEmpty());
    }

    public void testOutputNameEncodesProvenance() {
        ReferenceBuild.Spec spec = ReferenceBuild.parse(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "-mcpu=cortex-m0plus -mthumb",
                "-Os",
                List.of("LFS_NO_MALLOC"),
                List.of(),
                true,
                "",
                List.of("gcc10", "gcc12", "gcc13"));
        assertEquals("littlefs-v2.9.3-gcc13-Os.o", spec.resolvedOutputName());
        List<List<String>> cmd = spec.commandLines(Path.of("/data/uploads", spec.resolvedOutputName()));
        assertEquals("arm-none-eabi-gcc", cmd.get(0).get(0));
        assertTrue(cmd.get(0).contains("-c"));
        assertTrue(cmd.get(0).contains("-ffile-prefix-map=<snapshot>=."));
        assertTrue(cmd.get(cmd.size() - 1).contains("--strip-debug"));
        assertFalse("must not strip .symtab", cmd.toString().contains("--strip-all"));
        assertFalse(cmd.toString().contains("--strip-unneeded"));
    }

    public void testRealBuildSendsRequestAndReturnsShaAndCount() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of("LFS_NO_ASSERT"),
                List.of(),
                true,
                "",
                false);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertEquals(1, client.calls.size());
        String json = r.toJson();
        assertTrue(json, json.contains("deadbeef"));
        assertTrue(json, json.contains("\"function_count\":12") || json.contains("\"function_count\": 12"));
        assertTrue(json, json.contains("sha256"));
        Map<?, ?> req = (Map<?, ?>) client.calls.get(0).get("request");
        assertEquals("v2.9.3", req.get("ref"));
        assertEquals(Boolean.TRUE, req.get("strip_debug"));
    }

    public void testCompileFailureReturnsStderr() {
        Map<String, Object> fail = new LinkedHashMap<>();
        fail.put("ok", false);
        fail.put("status", "compile_failed");
        fail.put("error", "compile failed for lfs.c");
        fail.put("stderr", "lfs.c:1: error: LFS_NO_MALLOC undeclared");
        client.setResponse(fail);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("LFS_NO_MALLOC undeclared"));
        assertTrue(r.toJson(), r.toJson().contains("compile_failed"));
    }

    public void testRefNotFoundNamesRefAndReachability() {
        Map<String, Object> fail = new LinkedHashMap<>();
        fail.put("ok", false);
        fail.put("status", "ref_not_found");
        fail.put("error", "ref 'v9.9.9' not found (repository was reachable)");
        fail.put("ref", "v9.9.9");
        fail.put("repo_reachable", true);
        client.setResponse(fail);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v9.9.9",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("v9.9.9"));
        assertTrue(r.toJson(), r.toJson().contains("reachable"));
    }

    public void testZeroFunctionsRefused() {
        Map<String, Object> fail = new LinkedHashMap<>();
        fail.put("ok", true);
        fail.put("function_count", 0);
        fail.put("commit_sha", "abc");
        client.setResponse(fail);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("0 defined functions"));
    }

    public void testMissingFunctionCountRefused() {
        Map<String, Object> fail = new LinkedHashMap<>();
        fail.put("ok", true);
        fail.put("sha256", "abc");
        client.setResponse(fail);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("function_count"));
    }

    public void testManifestExpandsToNineLittlefsJobs() throws Exception {
        Path manifest = Path.of("docker", "references.yaml");
        assertTrue("docker/references.yaml must exist", Files.isRegularFile(manifest));
        List<ReferenceBuild.Spec> jobs = ReferenceManifest.load(
                manifest, List.of("gcc10", "gcc12", "gcc13"));
        assertEquals(9, jobs.size());
        assertEquals("littlefs-v2.9.3-gcc10-Os.o", jobs.get(0).resolvedOutputName());
        assertEquals("littlefs-v2.9.3-gcc13-O3.o", jobs.get(8).resolvedOutputName());
        long toolchains = jobs.stream().map(ReferenceBuild.Spec::toolchain).distinct().count();
        long opts = jobs.stream().map(ReferenceBuild.Spec::opt).distinct().count();
        assertEquals(3, toolchains);
        assertEquals(3, opts);
    }

    public void testManifestDryRunDoesNotCallBuilder() throws Exception {
        Files.copy(Path.of("docker", "references.yaml"), tmp.resolve("references.yaml"));
        Response r = svc.buildManifest("", true);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(client.calls.isEmpty());
        String json = r.toJson();
        assertTrue(json, json.contains("\"count\":9") || json.contains("\"count\": 9"));
        assertTrue(json, json.contains("would_execute"));
    }

    public void testIdenticalInputsProduceIdenticalArgv() {
        ReferenceBuild.Spec a = ReferenceBuild.parse(
                "littlefs", "https://github.com/littlefs-project/littlefs.git", "v2.9.3",
                List.of("lfs.c"), "gcc13", "", "-Os", List.of("LFS_NO_ASSERT"),
                List.of(), true, "", List.of("gcc13"));
        ReferenceBuild.Spec b = ReferenceBuild.parse(
                "littlefs", "https://github.com/littlefs-project/littlefs.git", "v2.9.3",
                List.of("lfs.c"), "gcc13", "", "-Os", List.of("LFS_NO_ASSERT"),
                List.of(), true, "", List.of("gcc13"));
        Path out = Path.of("/data/uploads/littlefs-v2.9.3-gcc13-Os.o");
        assertEquals(a.commandLines(out), b.commandLines(out));
        assertEquals(a.cflags(), b.cflags());
    }

    public void testParseToolchainUrlsSplitsOnFirstColon() {
        Map<String, URI> urls = ReferenceBuild.parseToolchainUrls(
                "gcc13:http://ghidra-builder:8092,gcc12:http://ghidra-builder-gcc12:8092");
        assertEquals(URI.create("http://ghidra-builder:8092"), urls.get("gcc13"));
        assertEquals(URI.create("http://ghidra-builder-gcc12:8092"), urls.get("gcc12"));
    }

    public void testRejectsFileRepo() {
        try {
            ReferenceBuild.requireRepo("file:///tmp/littlefs");
            fail("file: repo must be refused");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("file:"));
        }
    }

    private static void deleteRecursively(Path dir) throws Exception {
        if (!Files.exists(dir)) return;
        try (var walk = Files.walk(dir)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                    });
        }
    }
}
