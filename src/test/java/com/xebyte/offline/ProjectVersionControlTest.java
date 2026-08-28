package com.xebyte.offline;

import com.xebyte.core.GhidraIdentity;
import com.xebyte.core.ProjectLocks;
import com.xebyte.core.ProjectVersionControl;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * Offline coverage for the DomainFile version-control lift, identity
 * reporting, lock diagnostics, and error status convention.
 */
public class ProjectVersionControlTest extends TestCase {

    public void testAddWithoutProjectIsNotASuccess() {
        Map<String, Object> r = ProjectVersionControl.add(
            null, "/x", "c", false, null, false);
        assertEquals(Boolean.FALSE, r.get("success"));
        assertEquals("no_project", r.get("status"));
        assertFalse("added".equals(r.get("status")));
        assertFalse("repository_verified".equals(r.get("status")));
    }

    public void testDryRunWithoutProjectDoesNotLookLikeWouldAdd() {
        Map<String, Object> r = ProjectVersionControl.add(
            null, "/x", "c", false, null, true);
        assertEquals(Boolean.FALSE, r.get("success"));
        assertEquals("no_project", r.get("status"));
        assertFalse(Boolean.TRUE.equals(r.get("dry_run")));
    }

    public void testCheckoutWithoutProject() {
        Map<String, Object> r = ProjectVersionControl.checkout(
            null, "/x", true, null, false);
        assertEquals("no_project", r.get("status"));
        assertFalse("checked_out".equals(r.get("status")));
    }

    public void testUndoWithoutProject() {
        Map<String, Object> r = ProjectVersionControl.undoCheckout(null, "/x", false, true);
        assertEquals("no_project", r.get("status"));
        assertFalse("checkout_undone".equals(r.get("status")));
        assertFalse("would_undo_checkout".equals(r.get("status")));
    }

    public void testMissingPath() {
        // project null is checked first
        Map<String, Object> r = ProjectVersionControl.listCheckouts(null, "/");
        assertEquals("no_project", r.get("status"));
    }

    public void testIdentityDescribeAlwaysHasJvmUser() {
        Map<String, Object> d = GhidraIdentity.describe();
        assertTrue(d.containsKey("jvm_user"));
        assertTrue(d.containsKey("identity_mismatch"));
        assertNotNull(d.get("jvm_user"));
    }

    public void testResponseErrCarriesStatus() {
        Response r = Response.guiRequired("Import needs PluginTool");
        assertTrue(r instanceof Response.Err);
        assertEquals("gui_required", ((Response.Err) r).status());
        assertTrue(r.toJson().contains("gui_required"));
        Response n = Response.notImplemented("no adapter path");
        assertEquals("not_implemented", ((Response.Err) n).status());
    }

    public void testProjectLocksFindAndDescribe() throws Exception {
        File dir = Files.createTempDirectory("ghidra-mcp-lock").toFile();
        File lock = new File(dir, "project.prp.lock");
        assertTrue(lock.createNewFile());
        File marker = new File(dir.getParentFile(), "proj.gpr");
        List<String> found = ProjectLocks.find(dir, marker);
        assertTrue(found.stream().anyMatch(p -> p.endsWith("project.prp.lock")));
        String msg = ProjectLocks.describeOpenFailure("/data/ghidra_projects/general.gpr",
            new RuntimeException("Project is already in use"), dir, marker);
        assertTrue(msg, msg.contains("Lock files"));
        assertTrue(msg, msg.contains("delete those files"));
        List<String> leftover = ProjectLocks.tryDelete(found);
        assertTrue(leftover.isEmpty());
        assertFalse(lock.exists());
    }
}
