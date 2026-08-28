package com.xebyte.core;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Project-side version control. The GUI plugin already did this correctly
 * against {@link DomainFile}; the headless RMI/{@code RepositoryAdapter}
 * layer did not, and the two views disagreed (server "checked out", project
 * "not under version control").
 *
 * <p>Both providers call this. {@code RepositoryAdapter} is used only to
 * <em>observe</em> server-side checkouts and for admin terminate of other
 * users' checkouts, never to take a checkout that the open project's
 * DomainFile cannot use.
 */
public final class ProjectVersionControl {

    private ProjectVersionControl() {}

    public static Map<String, Object> add(Project project, String filePath, String comment,
            boolean keepCheckedOut, TaskMonitor monitor, boolean dryRun) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        Map<String, Object> blocked = mutationGate();
        if (blocked != null) {
            return blocked;
        }
        if (repositoryOf(project) == null) {
            return fail("Project is not server-bound. Add-to-version-control requires a shared project.",
                "not_shared");
        }
        if (r.file.isVersioned()) {
            return fail("File already under version control: " + r.path, "already_versioned");
        }
        if (r.file.isHijacked()) {
            return fail(hijackedMessage(r.path), "hijacked");
        }
        if (comment == null) {
            comment = "";
        }
        if (dryRun) {
            Map<String, Object> out = ok("would_add");
            out.put("dry_run", true);
            out.put("path", r.path);
            out.put("comment", comment);
            out.put("keep_checked_out", keepCheckedOut);
            return out;
        }
        try {
            r.file.addToVersionControl(comment, keepCheckedOut, monitor);
            Map<String, Object> out = ok("added");
            out.put("path", r.file.getPathname());
            out.put("comment", comment);
            out.put("version", r.file.getVersion());
            out.put("checked_out", r.file.isCheckedOut());
            out.put("keep_checked_out", keepCheckedOut);
            return out;
        } catch (Exception e) {
            return fail("Add to version control failed: " + e.getMessage(), null);
        }
    }

    public static Map<String, Object> checkout(Project project, String filePath, boolean exclusive,
            TaskMonitor monitor, boolean dryRun) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        Map<String, Object> blocked = mutationGate();
        if (blocked != null) {
            return blocked;
        }
        Map<String, Object> association = associationError(r.file, r.path);
        if (association != null) {
            return association;
        }
        if (r.file.isCheckedOut()) {
            Map<String, Object> out = ok("already_checked_out");
            out.put("path", r.path);
            out.put("exclusive", exclusive);
            putCheckoutUser(out, r.file);
            return out;
        }
        if (dryRun) {
            Map<String, Object> out = ok("would_checkout");
            out.put("dry_run", true);
            out.put("path", r.path);
            out.put("exclusive", exclusive);
            return out;
        }
        try {
            boolean success = r.file.checkout(exclusive, monitor);
            Map<String, Object> out = ok(success ? "checked_out" : "checkout_failed");
            out.put("success", success);
            out.put("path", r.path);
            out.put("exclusive", exclusive);
            putCheckoutUser(out, r.file);
            return out;
        } catch (Exception e) {
            return fail("Checkout failed: " + e.getMessage(), null);
        }
    }

    public static Map<String, Object> checkin(Project project, String filePath, String comment,
            boolean keepCheckedOut, TaskMonitor monitor, boolean dryRun) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        Map<String, Object> blocked = mutationGate();
        if (blocked != null) {
            return blocked;
        }
        Map<String, Object> association = associationError(r.file, r.path);
        if (association != null) {
            return association;
        }
        if (!r.file.isCheckedOut()) {
            return fail("File is not checked out: " + r.path, "not_checked_out");
        }
        Map<String, Object> owner = checkoutOwnerError(r.file, r.path);
        if (owner != null) {
            return owner;
        }
        if (comment == null) {
            comment = "";
        }
        if (dryRun) {
            Map<String, Object> out = ok("would_checkin");
            out.put("dry_run", true);
            out.put("path", r.path);
            out.put("comment", comment);
            out.put("keep_checked_out", keepCheckedOut);
            out.put("version", r.file.getVersion());
            return out;
        }
        try {
            final String cmt = comment;
            final boolean keep = keepCheckedOut;
            r.file.checkin(new ghidra.framework.data.CheckinHandler() {
                @Override
                public boolean keepCheckedOut() { return keep; }
                @Override
                public String getComment() { return cmt; }
                @Override
                public boolean createKeepFile() { return false; }
            }, monitor);
            Map<String, Object> out = ok("checked_in");
            out.put("path", r.path);
            out.put("comment", comment);
            out.put("keep_checked_out", keepCheckedOut);
            out.put("version", r.file.getVersion());
            return out;
        } catch (Exception e) {
            return fail("Checkin failed: " + e.getMessage(), null);
        }
    }

    public static Map<String, Object> undoCheckout(Project project, String filePath, boolean keep,
            boolean dryRun) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        Map<String, Object> blocked = mutationGate();
        if (blocked != null) {
            return blocked;
        }
        if (!r.file.isCheckedOut()) {
            return fail("File is not checked out: " + r.path, "not_checked_out");
        }
        if (dryRun) {
            Map<String, Object> out = ok("would_undo_checkout");
            out.put("dry_run", true);
            out.put("path", r.path);
            out.put("kept_copy", keep);
            return out;
        }
        try {
            r.file.undoCheckout(keep);
            Map<String, Object> out = ok("checkout_undone");
            out.put("path", r.path);
            out.put("kept_copy", keep);
            return out;
        } catch (Exception e) {
            return fail("Undo checkout failed: " + e.getMessage(), null);
        }
    }

    public static Map<String, Object> versionHistory(Project project, String filePath) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        try {
            Version[] versions = r.file.getVersionHistory();
            List<Map<String, Object>> list = new ArrayList<>();
            if (versions != null) {
                for (Version v : versions) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("version", v.getVersion());
                    row.put("user", v.getUser());
                    row.put("comment", v.getComment() != null ? v.getComment() : "");
                    row.put("date", String.valueOf(new java.util.Date(v.getCreateTime())));
                    list.add(row);
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("path", r.path);
            out.put("versions", list);
            out.put("count", list.size());
            out.put("source", "project");
            return out;
        } catch (Exception e) {
            return fail("Failed to get version history: " + e.getMessage(), null);
        }
    }

    public static Map<String, Object> listCheckouts(Project project, String folderPath) {
        if (project == null) {
            return fail("No project open", "no_project");
        }
        ProjectData data = project.getProjectData();
        DomainFolder folder;
        if (folderPath == null || folderPath.isEmpty() || folderPath.equals("/")) {
            folder = data.getRootFolder();
        } else {
            folder = data.getFolder(folderPath);
        }
        if (folder == null) {
            return fail("Folder not found: " + folderPath, "not_found");
        }
        RepositoryAdapter repo = repositoryOf(project);
        List<Map<String, Object>> checkouts = new ArrayList<>();
        collectCheckouts(folder, repo, checkouts);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("checkouts", checkouts);
        out.put("count", checkouts.size());
        out.put("source", "project");
        if (repo != null) {
            try {
                out.put("repository", repo.getName());
            } catch (Exception ignored) {
                // name is diagnostic only
            }
        }
        return out;
    }

    /**
     * Force-undo a checkout on a DomainFile in the open project, then fall
     * back to repository terminate for leftover server-side checkouts.
     */
    public static Map<String, Object> terminateFile(Project project, String filePath,
            Long checkoutId, boolean dryRun) {
        Resolved r = resolve(project, filePath);
        if (r.error != null) {
            return r.error;
        }
        if (dryRun) {
            Map<String, Object> out = ok("would_terminate");
            out.put("dry_run", true);
            out.put("path", r.path);
            if (r.file.isCheckedOut()) {
                out.put("method", "undo_checkout_force");
                putCheckoutUser(out, r.file);
            } else {
                out.put("method", "repository_terminate");
            }
            if (checkoutId != null) {
                out.put("checkout_id", checkoutId);
            }
            return out;
        }
        if (r.file.isCheckedOut()) {
            try {
                r.file.undoCheckout(false, true);
                Map<String, Object> out = ok("terminated");
                out.put("path", r.path);
                out.put("method", "undo_checkout_force");
                return out;
            } catch (Exception e) {
                // fall through to repository adapter
            }
        }
        RepositoryAdapter repo = repositoryOf(project);
        if (repo == null) {
            return fail("Cannot terminate checkout: project has no repository connection",
                "not_shared");
        }
        try {
            int lastSlash = r.path.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? r.path.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? r.path.substring(lastSlash + 1) : r.path;
            ItemCheckoutStatus[] checkouts = repo.getCheckouts(parentPath, fileName);
            if (checkouts == null || checkouts.length == 0) {
                return fail("No active checkouts found for: " + r.path, "not_checked_out");
            }
            int terminated = 0;
            for (ItemCheckoutStatus cs : checkouts) {
                if (checkoutId != null && cs.getCheckoutId() != checkoutId) {
                    continue;
                }
                try {
                    repo.terminateCheckout(parentPath, fileName, cs.getCheckoutId(), false);
                    terminated++;
                } catch (Exception ignored) {
                    // continue
                }
            }
            Map<String, Object> out = ok("terminated");
            out.put("path", r.path);
            out.put("method", "repository_terminate");
            out.put("terminated_count", terminated);
            out.put("total_checkouts", checkouts.length);
            return out;
        } catch (Exception e) {
            return fail("Terminate checkout failed: " + e.getMessage(), null);
        }
    }

    /**
     * Walk the open project and report checkout-owner mismatches versus
     * {@code user.name}. Used at open time so the operator does not discover
     * this after a full analysis pass.
     */
    public static List<Map<String, Object>> checkoutIdentityWarnings(Project project) {
        List<Map<String, Object>> warnings = new ArrayList<>();
        if (project == null) {
            return warnings;
        }
        String jvm = GhidraIdentity.jvmUser();
        try {
            collectIdentity(project.getProjectData().getRootFolder(), jvm, warnings);
        } catch (Exception ignored) {
            // best-effort
        }
        return warnings;
    }

    public static Map<String, Object> describeAssociation(DomainFile file) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (file == null) {
            return out;
        }
        out.put("path", file.getPathname());
        out.put("is_versioned", file.isVersioned());
        out.put("is_checked_out", file.isCheckedOut());
        out.put("is_hijacked", file.isHijacked());
        putCheckoutUser(out, file);
        return out;
    }

    public static RepositoryAdapter repositoryOf(Project project) {
        if (project == null) {
            return null;
        }
        try {
            return project.getProjectData().getRepository();
        } catch (Exception e) {
            return null;
        }
    }

    public static String repoNameOf(Project project) {
        RepositoryAdapter repo = repositoryOf(project);
        if (repo == null) {
            return null;
        }
        try {
            return repo.getName();
        } catch (Exception e) {
            return null;
        }
    }

    static Map<String, Object> fail(String error, String status) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", false);
        m.put("error", error);
        if (status != null && !status.isBlank()) {
            m.put("status", status);
        }
        return m;
    }

    static Map<String, Object> ok(String status) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", true);
        m.put("status", status);
        return m;
    }

    private static Map<String, Object> mutationGate() {
        String blocker = GhidraIdentity.mutationBlocker();
        if (blocker == null) {
            return null;
        }
        return fail(blocker, "identity_mismatch");
    }

    private static Map<String, Object> associationError(DomainFile file, String path) {
        if (!file.isVersioned()) {
            return fail("File is not under version control: " + path
                + ". A server-side (RMI) checkout would not associate this DomainFile; "
                + "checkin_program would then report the same error. Add the file with "
                + "/server/version_control/add, or /refresh_project if the repository "
                + "item was replaced.",
                "not_versioned");
        }
        if (file.isHijacked()) {
            return fail(hijackedMessage(path), "hijacked");
        }
        return null;
    }

    private static String hijackedMessage(String path) {
        return "DomainFile is hijacked (local copy is disconnected from the repository item): "
            + path + ". Check-in cannot use this file. /refresh_project after the repository "
            + "changes, or re-add the file from the repository.";
    }

    private static Map<String, Object> checkoutOwnerError(DomainFile file, String path) {
        try {
            ItemCheckoutStatus status = file.getCheckoutStatus();
            if (status == null) {
                return null;
            }
            String owner = status.getUser();
            String jvm = GhidraIdentity.jvmUser();
            if (owner != null && !owner.isBlank() && !owner.equals(jvm)) {
                return fail("Checkout user '" + owner + "' differs from JVM user '" + jvm
                    + "'. Undo that checkout (or terminate it) and check out again as '"
                    + jvm + "'.",
                    "identity_mismatch");
            }
        } catch (IOException ignored) {
            // status unavailable; Ghidra will still refuse at checkin if mismatched
        }
        return null;
    }

    private static void putCheckoutUser(Map<String, Object> out, DomainFile file) {
        try {
            ItemCheckoutStatus status = file.getCheckoutStatus();
            if (status != null) {
                out.put("checkout_user", status.getUser());
                out.put("checkout_id", status.getCheckoutId());
                out.put("checkout_version", status.getCheckoutVersion());
            }
        } catch (IOException ignored) {
            // optional
        }
    }

    private static void collectCheckouts(DomainFolder folder, RepositoryAdapter repo,
            List<Map<String, Object>> out) {
        for (DomainFile f : folder.getFiles()) {
            boolean local = f.isCheckedOut();
            ItemCheckoutStatus[] serverCheckouts = null;
            if (repo != null && f.isVersioned()) {
                try {
                    String path = f.getPathname();
                    int lastSlash = path.lastIndexOf('/');
                    String parentPath = lastSlash > 0 ? path.substring(0, lastSlash) : "/";
                    String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
                    serverCheckouts = repo.getCheckouts(parentPath, fileName);
                } catch (Exception ignored) {
                    // skip server view
                }
            }
            boolean server = serverCheckouts != null && serverCheckouts.length > 0;
            if (local || server) {
                Map<String, Object> row = fileRow(f);
                if (server) {
                    List<Map<String, Object>> sc = new ArrayList<>();
                    for (ItemCheckoutStatus cs : serverCheckouts) {
                        Map<String, Object> c = new LinkedHashMap<>();
                        c.put("checkout_id", cs.getCheckoutId());
                        c.put("user", cs.getUser());
                        c.put("checkout_version", cs.getCheckoutVersion());
                        sc.add(c);
                    }
                    row.put("server_checkouts", sc);
                }
                out.add(row);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectCheckouts(sub, repo, out);
        }
    }

    private static Map<String, Object> fileRow(DomainFile f) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", f.getName());
        row.put("path", f.getPathname());
        row.put("version", f.getVersion());
        row.put("latest_version", f.getLatestVersion());
        row.put("is_versioned", f.isVersioned());
        row.put("is_checked_out", f.isCheckedOut());
        row.put("is_checked_out_exclusive", f.isCheckedOutExclusive());
        row.put("is_read_only", f.isReadOnly());
        if (f.isCheckedOut()) {
            row.put("modified_since_checkout", f.modifiedSinceCheckout());
            row.put("is_hijacked", f.isHijacked());
            putCheckoutUser(row, f);
        }
        return row;
    }

    private static void collectIdentity(DomainFolder folder, String jvm,
            List<Map<String, Object>> warnings) {
        for (DomainFile f : folder.getFiles()) {
            if (!f.isCheckedOut()) {
                continue;
            }
            try {
                ItemCheckoutStatus status = f.getCheckoutStatus();
                if (status == null) {
                    continue;
                }
                String owner = status.getUser();
                if (owner != null && !owner.equals(jvm)) {
                    Map<String, Object> w = new LinkedHashMap<>();
                    w.put("path", f.getPathname());
                    w.put("checkout_user", owner);
                    w.put("jvm_user", jvm);
                    w.put("message", "Checkout user '" + owner + "' differs from JVM user '"
                        + jvm + "'");
                    warnings.add(w);
                }
            } catch (IOException ignored) {
                // skip
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectIdentity(sub, jvm, warnings);
        }
    }

    private static Resolved resolve(Project project, String filePath) {
        if (project == null) {
            return Resolved.error(fail("No project open", "no_project"));
        }
        if (filePath == null || filePath.isBlank()) {
            return Resolved.error(fail("'path' parameter required", "missing_path"));
        }
        DomainFile file;
        try {
            file = project.getProjectData().getFile(filePath);
        } catch (Exception e) {
            return Resolved.error(fail("Path lookup failed: " + e.getMessage(), null));
        }
        if (file == null) {
            return Resolved.error(fail("File not found: " + filePath, "not_found"));
        }
        return new Resolved(null, file, file.getPathname());
    }

    private static final class Resolved {
        final Map<String, Object> error;
        final DomainFile file;
        final String path;

        private Resolved(Map<String, Object> error, DomainFile file, String path) {
            this.error = error;
            this.file = file;
            this.path = path;
        }

        static Resolved error(Map<String, Object> error) {
            return new Resolved(error, null, null);
        }
    }
}
