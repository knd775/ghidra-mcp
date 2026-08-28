package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.SecurityConfig;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Validation + guard coverage for ProgramScriptService (~2.3K LOC, previously only the
 * run-script propagation offline test). Exercises required-param guards, the
 * no-project fail-closed path for project ops (which used to be GUI-only),
 * and the script-execution security gate — all before any program access, so
 * they run offline.
 */
public class ProgramScriptServiceValidationTest extends TestCase {

    private ProgramScriptService scripts;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        scripts = new ProgramScriptService(ServiceFactory.stubProvider(), ts);
    }

    public void testCloseProgramRequiresName() {
        Response r = scripts.closeProgram("", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name or path is required"));
    }

    public void testSwitchProgramRequiresName() {
        Response r = scripts.switchProgram("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name is required"));
    }

    public void testOpenProgramFromProjectRequiresPath() {
        Response r = scripts.openProgramFromProject("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program path is required"));
    }

    public void testImportFileRequiresFilePath() {
        Response r = scripts.importFile("", "/", "", "", "", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("file_path is required"));
    }

    public void testListProjectFilesRequiresOpenProject() {
        Response r = scripts.listProjectFiles("/");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
        assertFalse("must not be a GUI-only guard",
            ((Response.Err) r).message().contains("GUI mode"));
    }

    public void testCreateFolderRequiresOpenProject() {
        Response r = scripts.createFolder("/firmware", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
    }

    public void testDeleteFileRequiresOpenProject() {
        Response r = scripts.deleteFile("/firmware/sample");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
    }

    public void testOpenProgramRequiresOpenProject() {
        Response r = scripts.openProgramFromProject("/sample", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
        assertFalse("must not be a GUI-only guard",
            ((Response.Err) r).message().contains("GUI mode"));
    }

    public void testImportFileRequiresOpenProject() throws Exception {
        java.io.File tmp = java.io.File.createTempFile("import", ".bin");
        tmp.deleteOnExit();
        Response r = scripts.importFile(tmp.getAbsolutePath(), "/", "", "", "", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
        assertFalse("must not be a GUI-only guard",
            ((Response.Err) r).message().contains("GUI mode"));
    }

    public void testRunScriptInlineGatedByDefault() {
        // Security gate: arbitrary-code execution is off unless GHIDRA_MCP_ALLOW_SCRIPTS is set.
        // Assert the gate only in the (default) disabled state so the test is env-independent.
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            Response r = scripts.runScriptInline("System.out.println(1);", "", "");
            assertTrue(r instanceof Response.Err);
            assertTrue(((Response.Err) r).message().contains("Script execution disabled"));
        }
    }
}
