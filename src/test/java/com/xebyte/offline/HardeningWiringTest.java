package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Source-level regression tests pinning the v5.17 pre-release hardening in
 * place. These are deliberately grep-style static checks (same rationale as
 * {@link RunGhidraScriptProgramPropagationTest}): the behaviors depend on a
 * live HTTP server, a browser, a Unix domain socket, or a configured
 * {@code GHIDRA_MCP_PROJECT_FOLDER} — none of which stand up cheaply in CI —
 * but a wiring regression (someone deleting a guard during a refactor) is
 * exactly the failure mode that a cheap source assertion catches.
 */
public class HardeningWiringTest extends TestCase {

    private static String read(String... parts) throws IOException {
        Path p = Paths.get("src", "main", "java", "com", "xebyte");
        for (String s : parts) p = p.resolve(s);
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    /** The TCP request wrapper must invoke the cross-origin guard. */
    public void testTcpSafeHandlerCallsCrossOriginGuard() throws IOException {
        String src = read("GhidraMCPPlugin.java");
        assertTrue("safeHandler must call rejectCrossOriginRequest",
                src.contains("rejectCrossOriginRequest("));
    }

    /** The headless request wrapper must invoke the cross-origin guard. */
    public void testHeadlessSafeContextCallsCrossOriginGuard() throws IOException {
        String src = read("headless", "GhidraMCPHeadlessServer.java");
        assertTrue("safeContext must call rejectCrossOriginRequest",
                src.contains("rejectCrossOriginRequest("));
    }

    /**
     * The UDS dispatch loop must enforce the bearer token before invoking the
     * handler — otherwise a configured token silently doesn't apply on the
     * socket transport.
     */
    public void testUdsDispatchEnforcesBearerAuth() throws IOException {
        String src = read("core", "UdsHttpServer.java");
        assertTrue("UDS dispatch must check matchesBearerAuth",
                src.contains("matchesBearerAuth("));
        assertTrue("UDS dispatch must exempt only health paths",
                src.contains("isAuthExemptPath("));
        // The auth check must sit before the handler is invoked, not after.
        int authIdx = src.indexOf("matchesBearerAuth(");
        int handleIdx = src.indexOf("handler.handle(exchange)");
        assertTrue("Bearer check must precede handler.handle()",
                authIdx > 0 && handleIdx > 0 && authIdx < handleIdx);
    }

    /** Destructive project ops must honor the project-scope containment guard. */
    public void testDestructiveOpsEnforceProjectScope() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        String delete = body(src, "/delete_file");
        String create = body(src, "/create_folder");
        assertTrue("deleteFile must call isPathInProjectScope",
                delete.contains("isPathInProjectScope("));
        assertTrue("createFolder must call isPathInProjectScope",
                create.contains("isPathInProjectScope("));
    }

    /**
     * The script-execution gate must live on the sink (the 3-arg
     * runGhidraScript), not only on the callers, so no route can bypass it.
     */
    public void testRunGhidraScriptSinkIsGated() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        int sig = src.indexOf("public Response runGhidraScript(\n"
                + "            @Param(value = \"script_path\"");
        assertTrue("Could not locate 3-arg runGhidraScript", sig >= 0);
        // The areScriptsAllowed() gate must appear early in the method body,
        // before the program is resolved.
        int gate = src.indexOf("areScriptsAllowed()", sig);
        int resolve = src.indexOf("getProgramOrError", sig);
        assertTrue("runGhidraScript sink must check areScriptsAllowed()", gate >= 0);
        assertTrue("Gate must precede program resolution", gate < resolve);
    }

    /** The dead, ungated /run_script route must stay unregistered.
     *  (The old dead EndpointRegistry router was removed in 7.0.0.) */
    public void testRunScriptRouteNotRegistered() throws IOException {
        String plugin = read("GhidraMCPPlugin.java");
        assertFalse("GhidraMCPPlugin must not register the ungated /run_script route",
                plugin.contains("createContext(\"/run_script\""));
    }

    /** Request bodies must be bounded on every transport. */
    public void testRequestBodiesAreBounded() throws IOException {
        assertTrue("JsonHelper.parseBody must bound the read via readNBytes",
                read("core", "JsonHelper.java").contains("readNBytes"));
        assertTrue("TCP parsePostParams must bound the read",
                read("GhidraMCPPlugin.java").contains("readNBytes")
                        && read("GhidraMCPPlugin.java").contains("exceedsMaxBody"));
        assertTrue("UDS must reject oversized Content-Length (413)",
                read("core", "UdsHttpServer.java").contains("MAX_REQUEST_BODY_BYTES"));
        assertTrue("headless safeContext must fast-reject oversized Content-Length",
                read("headless", "GhidraMCPHeadlessServer.java").contains("exceedsMaxBody("));
        assertTrue("JsonHelper must distinguish oversized from malformed",
                read("core", "JsonHelper.java").contains("parseBodyDetailed"));
    }

    /** Passing language must not force BinaryLoader; that path lives in ProgramImporter. */
    public void testLanguageDoesNotForceRawBinaryLoader() throws IOException {
        String importer = read("core", "ProgramImporter.java");
        assertTrue("language-pinned imports must use importByLookingForLcs",
                importer.contains("importByLookingForLcs"));
        assertTrue("format=binary remains the raw opt-in",
                importer.contains("importAsBinary"));
        String load = read("headless", "HeadlessProgramProvider.java");
        assertFalse("HeadlessProgramProvider must not call importAsBinary directly",
                load.contains("AutoImporter.importAsBinary"));
        assertTrue("language mismatch on an existing import must name force_reimport",
                load.contains("force_reimport=true"));
    }

    /** The old stub returned success without adding the file. */
    public void testVersionControlAddIsImplemented() throws IOException {
        assertFalse("GhidraServerManager must not report repository_verified",
                read("headless", "GhidraServerManager.java").contains("repository_verified"));
        assertTrue("ProjectVersionControl must call DomainFile.addToVersionControl",
                read("core", "ProjectVersionControl.java")
                        .contains(".addToVersionControl("));
        assertTrue("ProjectVersionControl must call DomainFile.undoCheckout",
                read("core", "ProjectVersionControl.java")
                        .contains(".undoCheckout("));
        assertFalse("GhidraServerManager must not take RMI checkouts",
                read("headless", "GhidraServerManager.java").contains("repo.checkout("));
        assertFalse("headless terminate_checkout must not default checkout_id to 0",
                read("headless", "GhidraMCPHeadlessServer.java")
                        .contains("checkout_id\", \"0\""));
    }

    public void testDockerfileCreatesExportAndProjectDirs() throws IOException {
        String docker = java.nio.file.Files.readString(
            java.nio.file.Paths.get("docker", "Dockerfile"));
        assertTrue(docker.contains("/data/exports"));
        assertTrue(docker.contains("/data/ghidra_projects"));
    }

    /** Project ops that used to require PluginTool must go through ProgramProvider. */
    public void testProjectOpsAreNotGuiOnly() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        assertFalse("list/create/delete/open/import must not be GUI-only",
                src.contains("requires GUI mode (PluginTool not available)"));
    }

    /**
     * {@code /upload_file} must not refuse based on the scripts gate. Script
     * execution is warned about at startup on its own; uploads stay confined
     * to uploads/.
     */
    public void testUploadFileDoesNotRefuseWhenScriptsAllowed() throws IOException {
        String src = read("headless", "HeadlessManagementService.java");
        String method = body(src, "/upload_file");
        assertTrue("upload_file must write", method.contains("Files.write"));
        assertTrue("upload_file must not hard-block on areScriptsAllowed()",
                method.indexOf("areScriptsAllowed()") < 0);
        assertTrue("upload_file must confine to uploads/",
                method.contains("\"uploads\""));
    }

    /** Startup must log when GHIDRA_MCP_ALLOW_SCRIPTS is enabled. */
    public void testStartupLogsScriptsEnabledAdvisory() throws IOException {
        String headless = read("headless", "GhidraMCPHeadlessServer.java");
        assertTrue("headless start must log scriptsEnabledAdvisory",
                headless.contains("scriptsEnabledAdvisory("));
        String plugin = read("GhidraMCPPlugin.java");
        assertTrue("GUI plugin start must log scriptsEnabledAdvisory",
                plugin.contains("scriptsEnabledAdvisory("));
        String cfg = read("core", "SecurityConfig.java");
        assertTrue("SecurityConfig must define the advisory",
                cfg.contains("scriptsEnabledAdvisory"));
    }

    /** eclipse-temurin:21-jdk already owns uid 1000; reclaim it before groupadd. */
    public void testDockerfileReclaimsUid1000() throws IOException {
        String src = Files.readString(Paths.get("docker", "Dockerfile"));
        assertTrue("Dockerfile must free uid 1000 before groupadd",
                src.contains("getent passwd 1000"));
        assertTrue("Dockerfile must still create ghidra as uid 1000",
                src.contains("useradd --uid 1000 --gid 1000"));
        String builder = Files.readString(Paths.get("docker", "Dockerfile.builder"));
        assertTrue("builder image must free uid 1000",
                builder.contains("getent passwd 1000"));
        assertTrue("builder must run as uid 1000 so uploads are readable by ghidra-mcp",
                builder.contains("useradd --uid 1000 --gid 1000"));
        assertTrue("one image holds every identity prefix",
                builder.contains("/opt/ghidra-builder/toolchains/gcc13-arm"));
        assertTrue("gcc10-arm is packed into the same image",
                builder.contains("/opt/ghidra-builder/toolchains/gcc10-arm"));
        assertTrue("native x86-64 is packed as gcc13-x86_64",
                builder.contains("/opt/ghidra-builder/toolchains/gcc13-x86_64"));
        assertFalse("must not apt-install gcc-multilib",
                builder.contains("install gcc-multilib")
                        || builder.matches("(?m)^\\s*gcc-multilib\\s*$"));
        assertTrue("image build asserts gcc-multilib is absent",
                builder.contains("dpkg -l gcc-multilib"));
        assertFalse("identity is not an image tag / build-arg",
                builder.contains("ARG TOOLCHAIN_TAG"));
        assertTrue("HEALTHCHECK must probe /health",
                builder.contains("/health"));
        assertFalse("HEALTHCHECK must not put the auth token on the command line",
                builder.contains("Bearer"));
        assertTrue("toolchains are pinned ARM tarballs, not distro packages",
                builder.contains("developer.arm.com"));
        assertFalse("distro gcc-arm-none-eabi is not a corpus pin",
                builder.contains("libnewlib-arm-none-eabi"));
    }

    /**
     * Top-level uncaught-exception handlers must not echo raw exception text
     * to the client (path / class-name disclosure). Deliberate per-endpoint
     * validation messages are unaffected.
     */
    public void testTopLevelErrorsAreGeneric() throws IOException {
        String plugin = read("GhidraMCPPlugin.java");
        assertTrue("safeHandler catch must return a generic message",
                plugin.contains("Internal server error. See the Ghidra application log"));
        assertTrue("headless catch must return a generic message",
                read("headless", "GhidraMCPHeadlessServer.java")
                        .contains("Internal server error. See the Ghidra application log"));
        assertTrue("UDS handler catch must return a generic message",
                read("core", "ServerManager.java")
                        .contains("Internal server error. See the Ghidra application log"));
    }

    /** Headless filesystem endpoints must honor GHIDRA_MCP_FILE_ROOT. */
    public void testHeadlessFsEndpointsEnforceFileRoot() throws IOException {
        String src = read("headless", "HeadlessManagementService.java");
        // create_project, export_program, import_program, archive_project all
        // route their path input through the containment helper.
        int helperUses = countOccurrences(src, "resolveWithinRootOrLog(");
        assertTrue("Expected create/export/import/archive to each call "
                + "resolveWithinRootOrLog (>=4 uses incl. helper def), found " + helperUses,
                helperUses >= 5);
    }

    private static int countOccurrences(String s, String sub) {
        int n = 0, i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) { n++; i += sub.length(); }
        return n;
    }

    /** Extract a method body by walking forward from its @McpTool path. */
    private static String body(String src, String mcpPath) {
        int at = src.indexOf("path = \"" + mcpPath + "\"");
        assertTrue("Could not find @McpTool path=\"" + mcpPath + "\"", at >= 0);
        int open = src.indexOf('{', at);
        int depth = 1, j = open + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        return src.substring(open, j);
    }
}
