package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.BuilderClient;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.FrameworkBuild;
import com.xebyte.core.ReferenceBuild;
import com.xebyte.core.ReferenceBuildService;
import com.xebyte.core.ReferenceManifest;
import com.xebyte.core.Response;
import com.xebyte.core.ToolchainIdentity;
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
        ok.put("path", tmp.resolve("uploads/littlefs-v2.9.3-gcc13-arm-Os.o").toString());
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
                "gcc13-arm",
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
        assertTrue(json, json.contains("littlefs-v2.9.3-gcc13-arm-Os.o"));
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
                "gcc13-arm",
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
                "gcc99-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("gcc10-arm"));
        assertTrue(json, json.contains("gcc12-arm"));
        assertTrue(json, json.contains("gcc13-arm"));
        assertTrue(client.calls.isEmpty());
        assertEquals("unknown toolchain still asks the container", 1, client.healthCalls.size());
    }

    public void testHealthIdentitiesWinOverJavaDefaults() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("ok", true);
        health.put("identities", List.of("gcc13-arm"));
        health.put("stubs", List.of("pico-sdk"));
        client.setHealthResponse(health);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc10-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("gcc10-arm"));
        assertTrue(json, json.contains("gcc13-arm"));
        assertFalse("Java's DEFAULT_TOOLCHAINS must not pad the error", json.contains("gcc12-arm"));
        assertTrue(client.calls.isEmpty());
    }

    public void testIdentityOnlyOnContainerIsAccepted() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("ok", true);
        health.put("identities", List.of("gcc13-arm", "gcc14-arm"));
        health.put("stubs", List.of("pico-sdk"));
        client.setHealthResponse(health);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc14-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        assertEquals(1, client.calls.size());
        assertEquals("gcc14-arm", client.calls.get(0).get("toolchain"));
        assertEquals("http://ghidra-builder:8092", client.calls.get(0).get("url"));
    }

    public void testBareGcc13IsNotAnIdentity() {
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
                true);
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("compiler") || json.contains("<compiler>"));
        assertTrue(json, json.contains("gcc13-arm"));
        assertTrue(client.calls.isEmpty());
    }

    public void testOutputNameEncodesProvenance() {
        ReferenceBuild.Spec spec = ReferenceBuild.parse(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
                "-mcpu=cortex-m0plus -mthumb",
                "-Os",
                List.of("LFS_NO_MALLOC"),
                List.of(),
                true,
                "",
                List.of("gcc10-arm", "gcc12-arm", "gcc13-arm"));
        assertEquals("littlefs-v2.9.3-gcc13-arm-Os.o", spec.resolvedOutputName());
        List<List<String>> cmd = spec.commandLines(Path.of("/data/uploads", spec.resolvedOutputName()));
        assertEquals("arm-none-eabi-gcc", cmd.get(0).get(0));
        assertTrue(cmd.get(0).contains("-c"));
        assertTrue(cmd.get(0).contains("-mcpu=cortex-m0plus"));
        assertTrue(cmd.get(0).contains("-g"));
        assertTrue(cmd.get(0).contains("-fdebug-prefix-map=<snapshot>=/ref/littlefs"));
        assertTrue(cmd.get(0).contains("-ffile-prefix-map=<snapshot>=/ref/littlefs"));
        assertFalse(cmd.get(0).contains("-ffile-prefix-map=<snapshot>=."));
        assertTrue(cmd.get(cmd.size() - 1).contains("--strip-debug"));
        assertFalse("must not strip .symtab", cmd.toString().contains("--strip-all"));
        assertFalse(cmd.toString().contains("--strip-unneeded"));
    }

    public void testClangArmIdentitySelectsClangAndTargetTriple() {
        ReferenceBuild.Spec spec = ReferenceBuild.parse(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "clang17-arm",
                "",
                "-Os",
                List.of("LFS_NO_ASSERT"),
                List.of(),
                true,
                "",
                List.of("clang17-arm"));
        assertEquals("littlefs-v2.9.3-clang17-arm-Os.o", spec.resolvedOutputName());
        List<String> cc = spec.commandLines(Path.of("/data/uploads", spec.resolvedOutputName())).get(0);
        assertEquals("clang", cc.get(0));
        assertTrue(cc.toString(), cc.contains("--target=thumbv6m-none-eabi"));
        assertFalse(cc.toString(), cc.contains("-mcpu=cortex-m0plus"));
        Map<String, Object> req = spec.toBuilderRequest(Path.of("/data/uploads", spec.resolvedOutputName()));
        assertEquals("clang", req.get("cc"));
        assertEquals("llvm-strip", req.get("strip"));
        assertEquals("llvm-nm", req.get("nm"));
        assertEquals("clang17-arm", req.get("toolchain"));
        assertEquals("littlefs", req.get("name"));
    }

    public void testXtensaAndRiscvIdentitiesNeedNoNewToolParam() {
        ToolchainIdentity xt = ToolchainIdentity.parse("gcc12-xtensa");
        assertEquals("xtensa-esp32-elf-gcc", xt.cc());
        assertTrue(xt.defaultArchFlags().contains("-mlongcalls"));
        ToolchainIdentity rv = ToolchainIdentity.parse("gcc13-riscv");
        assertEquals("riscv32-unknown-elf-gcc", rv.cc());
        assertTrue(rv.defaultArchFlags().contains("rv32"));
        ToolchainIdentity x64 = ToolchainIdentity.parse("gcc13-x86_64");
        assertEquals("gcc-13", x64.cc());
        assertEquals("-m64", x64.defaultArchFlags());
        assertEquals("gcc14-x86_64", ToolchainIdentity.parse("gcc14-x86_64").id());
        assertEquals("gcc-14", ToolchainIdentity.parse("gcc14-x86_64").cc());
    }

    public void testRealBuildSendsRequestAndReturnsShaAndCount() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
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
        assertEquals("littlefs", req.get("name"));
        assertEquals("-Os", req.get("opt"));
        assertEquals("gcc13-arm", req.get("toolchain"));
        assertEquals("sources", req.get("mode"));
        assertEquals(List.of("LFS_NO_ASSERT"), req.get("defines"));
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
                "gcc13-arm",
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
                "gcc13-arm",
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
                "gcc13-arm",
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
                "gcc13-arm",
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

    public void testManifestExpandsLittlefsAndPicoSdk() throws Exception {
        Path manifest = Path.of("docker", "references.yaml");
        assertTrue("docker/references.yaml must exist", Files.isRegularFile(manifest));
        List<ReferenceBuild.Spec> jobs = ReferenceManifest.load(
                manifest, List.of("gcc10-arm", "gcc12-arm", "gcc13-arm"));
        assertEquals(21, jobs.size());
        List<ReferenceBuild.Spec> littlefs = jobs.stream()
                .filter(s -> "littlefs".equals(s.name())).toList();
        List<ReferenceBuild.Spec> pico = jobs.stream()
                .filter(s -> "pico-sdk".equals(s.name())).toList();
        assertEquals(9, littlefs.size());
        assertEquals(12, pico.size());
        assertEquals("littlefs-v2.9.3-gcc10-arm-Os.o", littlefs.get(0).resolvedOutputName());
        assertEquals("littlefs-v2.9.3-gcc13-arm-O3.o", littlefs.get(8).resolvedOutputName());
        assertTrue(pico.get(0).isFramework());
        assertEquals("pico-sdk-pico_stdlib-2.1.0-gcc10-arm-Os-pico.o",
                pico.get(0).artifactName("pico_stdlib"));
        assertEquals("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-O2-pico_w.o",
                pico.get(11).artifactName("hardware_i2c"));
        long toolchains = littlefs.stream().map(ReferenceBuild.Spec::toolchain).distinct().count();
        long opts = littlefs.stream().map(ReferenceBuild.Spec::opt).distinct().count();
        assertEquals(3, toolchains);
        assertEquals(3, opts);
        long boards = pico.stream().map(ReferenceBuild.Spec::board).distinct().count();
        assertEquals(2, boards);
        assertFalse("DWARF is the default", littlefs.get(0).stripDebug());
    }

    public void testUserlandManifestExpandsSeparately() throws Exception {
        Path manifest = Path.of("docker", "references.userland.yaml");
        assertTrue(Files.isRegularFile(manifest));
        List<ReferenceBuild.Spec> jobs = ReferenceManifest.load(
                manifest, List.of("gcc13-x86_64"));
        assertEquals(24, jobs.size());
        assertEquals("file:/srv/ghidra/bsim/userland",
                ReferenceManifest.databaseUrl(Files.readString(manifest)));
        assertTrue(jobs.stream().allMatch(s -> "gcc13-x86_64".equals(s.toolchain())));
        assertTrue(jobs.stream().noneMatch(ReferenceBuild.Spec::stripDebug));
        long musl = jobs.stream().filter(s -> "musl".equals(s.name())).count();
        assertEquals(6, musl);
    }

    public void testSourceReadProxiesBuilderAndRejectsEscape() {
        Map<String, Object> src = new LinkedHashMap<>();
        src.put("ok", true);
        src.put("path", "lfs.c");
        src.put("commit", "abc");
        src.put("lines", List.of(Map.of("n", 1, "text", "int x;")));
        client.setSourceResponse(src);
        Response r = svc.sourceRead(
                "littlefs-v2.9.3-gcc13-arm-Os.o", "lfs_bd_read", "", 0, 0, 20);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertEquals(1, client.sourceCalls.size());
        Map<?, ?> req = (Map<?, ?>) client.sourceCalls.get(0).get("request");
        assertEquals("lfs_bd_read", req.get("function"));
        Response bad = svc.sourceRead("../etc/passwd", "f", "", 0, 0, 20);
        assertTrue(bad instanceof Response.Err);
        assertTrue(bad.toJson().contains(".."));
        assertEquals(1, client.sourceCalls.size());
        Response missing = svc.sourceRead("obj.o", "", "", 0, 0, 20);
        assertTrue(missing instanceof Response.Err);
        assertTrue(missing.toJson().contains("function or path"));
    }

    public void testManifestDryRunDoesNotCallBuilder() throws Exception {
        Files.copy(Path.of("docker", "references.yaml"), tmp.resolve("references.yaml"));
        Response r = svc.buildManifest("", true);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(client.calls.isEmpty());
        assertEquals("one GET /health for the whole matrix", 1, client.healthCalls.size());
        String json = r.toJson();
        assertTrue(json, json.contains("\"count\":21") || json.contains("\"count\": 21"));
        assertTrue(json, json.contains("would_execute"));
    }

    public void testIdenticalInputsProduceIdenticalArgv() {
        ReferenceBuild.Spec a = ReferenceBuild.parse(
                "littlefs", "https://github.com/littlefs-project/littlefs.git", "v2.9.3",
                List.of("lfs.c"), "gcc13-arm", "", "-Os", List.of("LFS_NO_ASSERT"),
                List.of(), true, "", List.of("gcc13-arm"));
        ReferenceBuild.Spec b = ReferenceBuild.parse(
                "littlefs", "https://github.com/littlefs-project/littlefs.git", "v2.9.3",
                List.of("lfs.c"), "gcc13-arm", "", "-Os", List.of("LFS_NO_ASSERT"),
                List.of(), true, "", List.of("gcc13-arm"));
        Path out = Path.of("/data/uploads/littlefs-v2.9.3-gcc13-arm-Os.o");
        assertEquals(a.commandLines(out), b.commandLines(out));
        assertEquals(a.cflags(), b.cflags());
        assertTrue(a.cflags().contains("-mcpu=cortex-m0plus"));
    }

    public void testParseToolchainUrlsSplitsOnFirstColon() {
        Map<String, URI> urls = ReferenceBuild.parseToolchainUrls(
                "gcc13-arm:http://ghidra-builder:8092,gcc12-arm:http://other-builder:8092");
        assertEquals(URI.create("http://ghidra-builder:8092"), urls.get("gcc13-arm"));
        assertEquals(URI.create("http://other-builder:8092"), urls.get("gcc12-arm"));
        assertNull(urls.get("gcc13"));
        assertTrue(ReferenceBuild.defaultToolchainUrls().keySet()
                .containsAll(ReferenceBuild.DEFAULT_TOOLCHAINS));
        URI one = URI.create("http://ghidra-builder:8092");
        assertEquals(one, ReferenceBuild.defaultToolchainUrls().get("gcc10-arm"));
        assertEquals(one, ReferenceBuild.defaultToolchainUrls().get("gcc12-arm"));
        assertEquals(one, ReferenceBuild.defaultToolchainUrls().get("gcc13-arm"));
    }

    public void testWaitTimeoutReturnsTicketWithoutHarvestChecks() {
        Map<String, Object> queued = new LinkedHashMap<>();
        queued.put("ok", true);
        queued.put("job_id", "build-1-aa");
        queued.put("status", "queued");
        client.setResponse(queued);
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false,
                "sources",
                "",
                null,
                "",
                null,
                0);
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"status\":\"started\"") || json.contains("\"status\": \"started\""));
        assertTrue(json, json.contains("build-1-aa"));
        assertTrue(json, json.contains("build_reference_status"));
        assertFalse(json, json.contains("function_count"));
        assertEquals(1, client.calls.size());
    }

    public void testBuildReferenceStatusPollsBuilder() {
        Map<String, Object> snap = new LinkedHashMap<>();
        snap.put("ok", true);
        snap.put("job_id", "build-1-aa");
        snap.put("status", "running");
        client.setStatusResponse(snap);
        Response r = svc.buildReferenceStatus("build-1-aa");
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("running"));
        assertEquals(List.of("build-1-aa"), client.statusCalls);
        Response listed = svc.buildReferenceStatus("");
        assertTrue(listed.toJson(), listed.toJson().contains("jobs") || listed.toJson().contains("count"));
    }

    public void testBuilderHealthReturnsContainerPayload() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("ok", true);
        health.put("identities", List.of("gcc10-arm", "gcc13-arm"));
        health.put("stubs", List.of("pico-sdk"));
        health.put("releases", Map.of("gcc13-arm", "13.2.Rel1"));
        health.put("uid", 1000);
        health.put("_http_status", 200);
        client.setHealthResponse(health);
        Response r = svc.builderHealth();
        assertFalse(r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("gcc10-arm"));
        assertTrue(json, json.contains("pico-sdk"));
        assertTrue(json, json.contains("13.2.Rel1"));
        assertFalse("internal hop status is not part of the tool contract", json.contains("_http_status"));
        assertEquals(1, client.healthCalls.size());
        assertTrue(client.calls.isEmpty());
    }

    public void testBuilderHealthUnreachable() {
        client.setHealthError(new java.io.IOException("connection refused"));
        Response r = svc.builderHealth();
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("connection refused"));
        assertTrue(r.toJson(), r.toJson().contains("builder_unreachable"));
    }

    public void testDryRunDoesNotSubmitWhenBuilderUnreachable() {
        client.setHealthError(new java.io.IOException("connection refused"));
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("builder_unreachable"));
        assertTrue(client.calls.isEmpty());
    }

    public void testUrlForFallsBackToSharedBuilder() {
        ReferenceBuild.BuilderConfig cfg = new ReferenceBuild.BuilderConfig(
                ReferenceBuild.defaultToolchainUrls(), tmp, "", java.time.Duration.ofSeconds(5));
        assertEquals(URI.create("http://ghidra-builder:8092"), cfg.urlFor("gcc14-arm"));
        Map<String, URI> split = ReferenceBuild.parseToolchainUrls(
                "gcc13-arm:http://ghidra-builder:8092,gcc12-arm:http://other-builder:8092");
        ReferenceBuild.BuilderConfig two = new ReferenceBuild.BuilderConfig(
                split, tmp, "", java.time.Duration.ofSeconds(5));
        try {
            two.urlFor("gcc14-arm");
            fail("distinct builder URLs must not guess");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("gcc13-arm"));
        }
    }

    public void testRejectsFileRepo() {
        try {
            ReferenceBuild.requireRepo("file:///tmp/littlefs");
            fail("file: repo must be refused");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("file:"));
        }
    }

    public void testFrameworkDryRunDoesNotCallBuilder() {
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true,
                "framework",
                "pico-sdk",
                List.of("pico_stdlib", "hardware_i2c"),
                "pico",
                Map.of());
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("would_execute") || json.contains("\"dry_run\":true"));
        assertTrue(json, json.contains("cmake"));
        assertTrue(json, json.contains("hardware_i2c"));
        assertTrue(json, json.contains("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o"));
        assertFalse("sources compile must not appear", json.contains("-ffunction-sections"));
        assertTrue("dry_run must not configure or compile", client.calls.isEmpty());
    }

    public void testFrameworkUnknownListsInstalledStubs() {
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true,
                "framework",
                "no-such-sdk",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("unknown framework"));
        assertTrue(json, json.contains("pico-sdk"));
        assertTrue(client.calls.isEmpty());
    }

    public void testHealthStubsWinOverLocalScan() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("ok", true);
        health.put("identities", List.of("gcc13-arm"));
        health.put("stubs", List.of("nrf-sdk"));
        client.setHealthResponse(health);
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true,
                "framework",
                "pico-sdk",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertTrue(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("unknown framework"));
        assertTrue(json, json.contains("nrf-sdk"));
        assertFalse("local docker/stubs/pico-sdk must not pad the error",
                json.contains("available: [pico-sdk]") || json.contains("available:[pico-sdk]"));
        assertTrue(client.calls.isEmpty());
    }

    public void testFrameworkEmptyLibrariesRefused() {
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true,
                "framework",
                "pico-sdk",
                List.of(),
                "pico",
                Map.of());
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("libraries"));
        assertTrue(client.calls.isEmpty());
    }

    public void testFrameworkMissingNameListsStubs() {
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                true,
                "framework",
                "",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("framework is required"));
        assertTrue(r.toJson(), r.toJson().contains("pico-sdk"));
        assertTrue(client.calls.isEmpty());
    }

    public void testFrameworkStripDebugForcedFalseAndReturnsArtifacts() {
        Map<String, Object> art = new LinkedHashMap<>();
        art.put("path", tmp.resolve("uploads/pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o").toString());
        art.put("sha256", "abc");
        art.put("function_count", 7);
        art.put("library", "hardware_i2c");
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        ok.put("artifacts", List.of(art));
        ok.put("function_count", 7);
        ok.put("commit_sha", "cafebabe");
        client.setResponse(ok);
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false,
                "framework",
                "pico-sdk",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertEquals(1, client.calls.size());
        Map<?, ?> req = (Map<?, ?>) client.calls.get(0).get("request");
        assertEquals(Boolean.FALSE, req.get("strip_debug"));
        assertEquals("framework", req.get("mode"));
        assertTrue(r.toJson(), r.toJson().contains("hardware_i2c"));
        assertTrue(r.toJson(), r.toJson().contains("cafebabe"));
    }

    public void testFrameworkZeroFunctionHarvestRefused() {
        Map<String, Object> art = new LinkedHashMap<>();
        art.put("path", "x.o");
        art.put("sha256", "abc");
        art.put("function_count", 0);
        art.put("library", "hardware_i2c");
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        ok.put("artifacts", List.of(art));
        client.setResponse(ok);
        Response r = svc.buildReference(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                false,
                "framework",
                "pico-sdk",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("0 defined functions"));
        assertTrue(r.toJson(), r.toJson().contains("ELF"));
    }

    public void testFrameworkNamingIncludesLibraryAndBoard() {
        ReferenceBuild.Spec spec = ReferenceBuild.parse(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                List.of("gcc13-arm"),
                "framework",
                "pico-sdk",
                List.of("hardware_i2c"),
                "pico",
                Map.of());
        assertEquals(
                "pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o",
                spec.artifactName("hardware_i2c"));
        ReferenceBuild.Spec w = ReferenceBuild.parse(
                "pico-sdk",
                "https://github.com/raspberrypi/pico-sdk.git",
                "2.1.0",
                List.of(),
                "gcc13-arm",
                "",
                "-Os",
                List.of(),
                List.of(),
                true,
                "",
                List.of("gcc13-arm"),
                "framework",
                "pico-sdk",
                List.of("hardware_i2c"),
                "pico_w",
                Map.of());
        assertEquals(
                "pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico_w.o",
                w.artifactName("hardware_i2c"));
        assertFalse(spec.artifactName("hardware_i2c").equals(w.artifactName("hardware_i2c")));
        List<List<String>> cmd = spec.commandLines(Path.of("/data/uploads"));
        assertEquals("cmake", cmd.get(0).get(0));
        assertTrue(cmd.get(0).toString(), cmd.get(0).contains("-DGHIDRA_BOARD=pico"));
        assertFalse(cmd.toString(), cmd.toString().contains("--strip-debug"));
    }

    public void testSourcesModeUnchangedByFrameworkParams() {
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
                "",
                "-Os",
                List.of("LFS_NO_ASSERT"),
                List.of(),
                true,
                "",
                true);
        assertFalse(r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("arm-none-eabi-gcc"));
        assertTrue(json, json.contains("littlefs-v2.9.3-gcc13-arm-Os.o"));
        assertFalse(json, json.contains("cmake"));
        assertTrue(client.calls.isEmpty());
    }

    public void testManifestSkipsWhenSidecarHashMatches() throws Exception {
        String yaml = "references:\n"
                + "  - name: pico-sdk\n"
                + "    mode: framework\n"
                + "    framework: pico-sdk\n"
                + "    repo: https://github.com/raspberrypi/pico-sdk.git\n"
                + "    ref: 2.1.0\n"
                + "    libraries: [hardware_i2c]\n"
                + "    toolchain: gcc13-arm\n"
                + "    opt: -Os\n"
                + "    board: pico\n";
        Files.writeString(tmp.resolve("references.yaml"), yaml);
        Path existing = tmp.resolve("uploads")
                .resolve("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o");
        writeArtifactWithMatchingSidecar(existing, new byte[] {1, 2, 3});
        Response r = svc.buildManifest("", false);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(client.calls.isEmpty());
        assertTrue(r.toJson(), r.toJson().contains("skipped"));
        assertTrue(r.toJson(), r.toJson().contains("sidecar hash matches"));
    }

    public void testManifestRebuildsWhenSidecarMissing() throws Exception {
        String yaml = picoSdkManifestYaml();
        Files.writeString(tmp.resolve("references.yaml"), yaml);
        Path existing = tmp.resolve("uploads")
                .resolve("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o");
        Files.createDirectories(existing.getParent());
        Files.write(existing, new byte[] {1, 2, 3});
        stubFrameworkBuilderResponse(existing);
        Response r = svc.buildManifest("", false);
        assertEquals(1, client.calls.size());
        assertFalse(r.toJson(), r.toJson().contains("\"skipped\":true"));
    }

    public void testManifestRebuildsWhenSidecarHashMismatches() throws Exception {
        String yaml = picoSdkManifestYaml();
        Files.writeString(tmp.resolve("references.yaml"), yaml);
        Path existing = tmp.resolve("uploads")
                .resolve("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o");
        Files.createDirectories(existing.getParent());
        Files.write(existing, new byte[] {1, 2, 3});
        Files.writeString(
                FrameworkBuild.sidecarPath(existing),
                "{\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}\n",
                StandardCharsets.UTF_8);
        stubFrameworkBuilderResponse(existing);
        Response r = svc.buildManifest("", false);
        assertEquals(1, client.calls.size());
        assertFalse(r.toJson(), r.toJson().contains("\"skipped\":true"));
    }

    public void testManifestRebuildsWhenSidecarCorrupt() throws Exception {
        String yaml = picoSdkManifestYaml();
        Files.writeString(tmp.resolve("references.yaml"), yaml);
        Path existing = tmp.resolve("uploads")
                .resolve("pico-sdk-hardware_i2c-2.1.0-gcc13-arm-Os-pico.o");
        Files.createDirectories(existing.getParent());
        Files.write(existing, new byte[] {1, 2, 3});
        Files.writeString(FrameworkBuild.sidecarPath(existing), "{not json\n", StandardCharsets.UTF_8);
        stubFrameworkBuilderResponse(existing);
        Response r = svc.buildManifest("", false);
        assertFalse("corrupt sidecar must not crash", r instanceof Response.Err && r.toJson().contains("Json"));
        assertEquals(1, client.calls.size());
        assertFalse(r.toJson(), r.toJson().contains("\"skipped\":true"));
    }

    public void testSourcesManifestSkipsWhenSidecarMatches() throws Exception {
        String yaml = "references:\n"
                + "  - name: littlefs\n"
                + "    repo: https://github.com/littlefs-project/littlefs.git\n"
                + "    ref: v2.9.3\n"
                + "    sources: [lfs.c]\n"
                + "    toolchain: gcc13-arm\n"
                + "    opt: -Os\n";
        Files.writeString(tmp.resolve("references.yaml"), yaml);
        Path existing = tmp.resolve("uploads").resolve("littlefs-v2.9.3-gcc13-arm-Os.o");
        writeArtifactWithMatchingSidecar(existing, new byte[] {9, 8, 7});
        Response r = svc.buildManifest("", false);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertTrue(client.calls.isEmpty());
        assertTrue(r.toJson(), r.toJson().contains("skipped"));
    }

    public void testArtifactIsCurrentTreatsMissingSidecarAsStale() throws Exception {
        Path artifact = tmp.resolve("uploads").resolve("foo.o");
        Files.createDirectories(artifact.getParent());
        Files.write(artifact, new byte[] {1});
        assertFalse(FrameworkBuild.artifactIsCurrent(artifact));
        writeArtifactWithMatchingSidecar(artifact, new byte[] {1});
        assertTrue(FrameworkBuild.artifactIsCurrent(artifact));
        Files.delete(FrameworkBuild.sidecarPath(artifact));
        assertFalse(FrameworkBuild.artifactIsCurrent(artifact));
    }

    public void testBuildReferenceDoesNotSkipExistingOutput() throws Exception {
        Path existing = tmp.resolve("uploads").resolve("littlefs-v2.9.3-gcc13-arm-Os.o");
        Files.createDirectories(existing.getParent());
        Files.write(existing, new byte[] {1});
        Response r = svc.buildReference(
                "littlefs",
                "https://github.com/littlefs-project/littlefs.git",
                "v2.9.3",
                List.of("lfs.c"),
                "gcc13-arm",
                "",
                "-Os",
                List.of("LFS_NO_ASSERT"),
                List.of(),
                true,
                "",
                false);
        assertFalse(r.toJson(), r instanceof Response.Err);
        assertEquals(1, client.calls.size());
    }

    private static String picoSdkManifestYaml() {
        return "references:\n"
                + "  - name: pico-sdk\n"
                + "    mode: framework\n"
                + "    framework: pico-sdk\n"
                + "    repo: https://github.com/raspberrypi/pico-sdk.git\n"
                + "    ref: 2.1.0\n"
                + "    libraries: [hardware_i2c]\n"
                + "    toolchain: gcc13-arm\n"
                + "    opt: -Os\n"
                + "    board: pico\n";
    }

    private void stubFrameworkBuilderResponse(Path artifact) {
        Map<String, Object> art = new LinkedHashMap<>();
        art.put("path", artifact.toString());
        art.put("bytes", 3);
        art.put("sha256", "abc");
        art.put("function_count", 3);
        art.put("defined_functions", List.of("hardware_i2c_init"));
        art.put("library", "hardware_i2c");
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        ok.put("artifacts", List.of(art));
        ok.put("function_count", 3);
        ok.put("commit_sha", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        ok.put("cc_version", "arm-none-eabi-gcc 13.2.1");
        client.setResponse(ok);
    }

    private static void writeArtifactWithMatchingSidecar(Path artifact, byte[] data) throws Exception {
        Files.createDirectories(artifact.getParent());
        Files.write(artifact, data);
        String hex = FrameworkBuild.sha256Hex(artifact);
        Files.writeString(
                FrameworkBuild.sidecarPath(artifact),
                "{\"sha256\":\"" + hex + "\"}\n",
                StandardCharsets.UTF_8);
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
