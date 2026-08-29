package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.SecurityConfig;
import com.xebyte.headless.GhidraServerManager;
import com.xebyte.headless.HeadlessManagementService;
import com.xebyte.headless.HeadlessProgramProvider;
import junit.framework.TestCase;

import java.util.Map;

/**
 * Fail-closed coverage for the headless-only management endpoints that used
 * to be stubs or GUI-only. No project is open under a fresh provider, so
 * these never reach Ghidra Server or the filesystem write.
 */
public class HeadlessManagementServiceValidationTest extends TestCase {

    private HeadlessManagementService svc;

    @Override
    protected void setUp() {
        svc = new HeadlessManagementService(
            new HeadlessProgramProvider(), new GhidraServerManager());
    }

    public void testAddToVersionControlRequiresOpenProject() {
        Response r = svc.addToVersionControl("/sample", "initial", false, "", false);
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue(msg, msg.toLowerCase().contains("no project"));
        assertEquals("no_project", ((Response.Err) r).status());
        assertFalse(msg.contains("repository_verified"));
    }

    public void testCheckoutRequiresOpenProject() {
        Map<String, Object> r = new HeadlessProgramProvider()
            .checkoutFile("/sample", true, false);
        assertEquals(Boolean.FALSE, r.get("success"));
        assertEquals("no_project", r.get("status"));
        assertFalse(String.valueOf(r.get("error")).contains("checked_out"));
    }

    public void testUndoCheckoutRequiresOpenProject() {
        Map<String, Object> r = new HeadlessProgramProvider()
            .undoCheckout("/sample", false, true);
        assertEquals(Boolean.FALSE, r.get("success"));
        assertEquals("no_project", r.get("status"));
        assertFalse("dry_run must not invent a success status",
            "would_undo_checkout".equals(r.get("status")));
    }

    public void testRefreshProjectRequiresOpenProject() {
        Response r = svc.refreshProject();
        assertTrue(r instanceof Response.Err);
        assertFalse(r.toJson().contains("\"status\":\"refreshed\""));
    }

    public void testTerminateCheckoutDryRunDoesNotClaimTerminatedWhenDisconnected() {
        GhidraServerManager sm = new GhidraServerManager();
        String json = sm.terminateCheckout("general", "/x", 1L, true);
        assertFalse(json, json.contains("checkout_terminated"));
        assertFalse(json, json.contains("\"status\": \"checked_out\""));
    }

    public void testCheckoutFileDoesNotReportCheckedOut() {
        GhidraServerManager sm = new GhidraServerManager();
        String json = sm.checkoutFile("general", "/x");
        assertTrue(json, json.contains("not_implemented"));
        assertFalse(json, json.contains("\"status\": \"checked_out\""));
        assertFalse(json, json.contains("repository_verified"));
    }

    public void testUploadFileRequiresFileRoot() {
        if (SecurityConfig.getInstance().hasFileRoot()) {
            // FILE_ROOT is set in this process; the fail-closed fixture cannot
            // assert the missing-root error. The call may proceed to a real write.
            return;
        }
        Response r = svc.uploadFile("sample.bin", "AA==", false);
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue(msg, msg.contains("GHIDRA_MCP_FILE_ROOT"));
        assertFalse("scripts must not hard-block upload_file",
            msg.contains("GHIDRA_MCP_ALLOW_SCRIPTS"));
    }

    public void testUploadFileRejectsPathSeparators() {
        if (!SecurityConfig.getInstance().hasFileRoot()) {
            // Filename is checked after the FILE_ROOT gate.
            return;
        }
        Response r = svc.uploadFile("../escape.bin", "AA==", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().toLowerCase().contains("filename"));
    }
}
