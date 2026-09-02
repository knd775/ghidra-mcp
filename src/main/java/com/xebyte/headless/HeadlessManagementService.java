package com.xebyte.headless;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Program and project management endpoints for headless mode.
 * Only passed to AnnotationScanner in GhidraMCPHeadlessServer,
 * so this category is absent from the GUI plugin schema.
 */
@McpToolGroup(value = "headless", description = "Headless server program management (no GUI required)")
public class HeadlessManagementService {

    private final HeadlessProgramProvider programProvider;
    private final GhidraServerManager serverManager;

    public HeadlessManagementService(HeadlessProgramProvider programProvider,
                                     GhidraServerManager serverManager) {
        this.programProvider = programProvider;
        this.serverManager = serverManager;
    }

    // ========================================================================
    // Program management
    // ========================================================================

    @McpTool(path = "/load_program", method = "POST",
            description = "Load a binary file into the headless server for analysis. "
                + "format and language are independent (matching the GUI import dialog). "
                + "Omit both to auto-detect. Pass language alone to pin the processor while "
                + "keeping the file's container format (ELF/PE/Mach-O). Pass format=binary "
                + "to force a raw load of a headerless image. force_reimport replaces an "
                + "existing same-named project file instead of silently reopening it.",
            category = "headless")
    public Response loadProgram(
            @Param(value = "file", source = ParamSource.BODY, description = "Absolute path to the binary file") String filePath,
            @Param(value = "language", source = ParamSource.BODY, defaultValue = "",
                description = "Optional Ghidra language ID (e.g. 'ARM:LE:32:Cortex'). Pins the processor without forcing a raw load unless format=binary.") String languageId,
            @Param(value = "compiler_spec", source = ParamSource.BODY, defaultValue = "",
                description = "Optional compiler-spec ID (e.g. 'default', 'gcc', 'windows'). Only consulted when `language` is set; falls back to the language default when empty.") String compilerSpecId,
            @Param(value = "format", source = ParamSource.BODY, defaultValue = "",
                description = "Optional loader: omit for auto-detect / language-pinned container load; 'binary' for raw (headerless) firmware.") String format,
            @Param(value = "force_reimport", source = ParamSource.BODY, defaultValue = "false",
                description = "Replace an existing same-named program in the project instead of reopening it.") boolean forceReimport) {
        if (filePath == null || filePath.isEmpty()) {
            return Response.err("file path required");
        }
        // Enforce the GHIDRA_MCP_FILE_ROOT allow-list before touching the disk.
        // resolveWithinFileRoot canonicalizes the path (resolving symlinks and
        // `..`) and returns null when a root is configured and the path escapes
        // it; with no root configured it returns the canonical path unchanged.
        // filePath is non-null here, so a null result means "outside the root".
        SecurityConfig security = SecurityConfig.getInstance();
        Path resolved = security.resolveWithinFileRoot(filePath);
        if (resolved == null) {
            // Log the configured root server-side for the operator, but keep it
            // out of the client response so we don't disclose the filesystem
            // layout to the (untrusted) caller.
            Msg.warn(this, "Rejected /load_program for '" + filePath
                + "': outside configured GHIDRA_MCP_FILE_ROOT ("
                + security.getFileRoot() + ")");
            return Response.err("Access denied: path is outside the configured file root");
        }
        File file = resolved.toFile();
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }
        // Normalize once so the provider call and the error messages all use the
        // same trimmed values (a doc-copied " ARM:LE:32:Cortex " otherwise passes
        // the non-empty check but fails lookup with a confusing message).
        String normalizedLanguageId = (languageId == null) ? "" : languageId.trim();
        String normalizedCompilerSpecId = (compilerSpecId == null) ? "" : compilerSpecId.trim();
        String normalizedFormat = (format == null) ? "" : format.trim();
        ProgramImporter.Result loaded = programProvider.loadFromFilesystem(
            file, normalizedLanguageId, normalizedCompilerSpecId, normalizedFormat, forceReimport);
        if (loaded.success()) {
            Program program = loaded.program;
            String langOut = program.getLanguageID() != null
                ? program.getLanguageID().getIdAsString() : "";
            String formatOut = program.getExecutableFormat() != null
                ? program.getExecutableFormat() : "";
            String imageBase = program.getImageBase() != null
                ? "0x" + program.getImageBase() : "";
            java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("success", true);
            body.put("program", program.getName());
            body.put("language", langOut);
            body.put("compiler", ProgramImporter.compilerSpecId(program));
            body.put("executable_format", formatOut);
            body.put("image_base", imageBase);
            body.put("function_count", program.getFunctionManager().getFunctionCount());
            ProgramImporter.attachElfWindowsWarning(body, program);
            return Response.ok(body);
        }
        if (loaded.error != null && !loaded.error.isBlank()) {
            return Response.err(loaded.error);
        }
        if (!normalizedLanguageId.isEmpty()) {
            return Response.err("Failed to load program with language '" + normalizedLanguageId
                + "' from: " + filePath);
        }
        return Response.err("Failed to load program from: " + filePath
            + " (auto-detect failed; for raw firmware pass `language`, e.g. 'ARM:LE:32:Cortex')");
    }

    /**
     * Resolve a caller-supplied filesystem path against {@code GHIDRA_MCP_FILE_ROOT},
     * matching the containment {@link #loadProgram} already applies. Returns the
     * canonical {@link File} when allowed, or {@code null} (after a server-side
     * log that keeps the configured root out of the client response) when a root
     * is configured and the path escapes it. With no root set the path is
     * returned canonicalized — pre-v5.4.1 behavior, so general users are
     * unaffected.
     */
    private File resolveWithinRootOrLog(String userPath, String endpoint) {
        SecurityConfig security = SecurityConfig.getInstance();
        Path resolved = security.resolveWithinFileRoot(userPath);
        if (resolved == null) {
            Msg.warn(this, "Rejected " + endpoint + " for '" + userPath
                + "': outside configured GHIDRA_MCP_FILE_ROOT (" + security.getFileRoot() + ")");
            return null;
        }
        return resolved.toFile();
    }

    private static final String FILE_ROOT_DENY =
        "Access denied: path is outside the configured file root";

    // ========================================================================
    // Project management
    // ========================================================================

    @McpTool(path = "/create_project", method = "POST",
            description = "Create a new Ghidra project. Pass repo (and connect first) to create a "
                + "server-bound shared project instead of copying a .gpr from another account.",
            category = "headless")
    public Response createProject(
            @Param(value = "parentDir", source = ParamSource.BODY) String parentDir,
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "repo", source = ParamSource.BODY, defaultValue = "",
                description = "Optional repository name on the connected Ghidra Server. "
                    + "When set, the project is created shared (bound to that repo) rather than local-only.")
                String repo) {
        if (parentDir == null || parentDir.isEmpty()) return Response.err("parentDir required");
        if (name == null || name.isEmpty()) return Response.err("name required");
        File parent = resolveWithinRootOrLog(parentDir, "/create_project");
        if (parent == null) return Response.err(FILE_ROOT_DENY);
        parentDir = parent.getPath();
        try {
            ghidra.framework.client.RepositoryAdapter repository = null;
            if (repo != null && !repo.isBlank()) {
                if (!serverManager.isConnected()) {
                    return Response.err("Not connected to server. Call /server/connect before "
                        + "creating a shared project.");
                }
                try {
                    repository = serverManager.openRepository(repo.trim());
                } catch (Exception e) {
                    return Response.err("Cannot open repository '" + repo + "': " + e.getMessage());
                }
            }
            HeadlessProgramProvider.CreateProjectResult created =
                programProvider.createProject(parentDir, name, repository);
            if (!created.success) {
                return Response.err(created.error != null ? created.error : "Failed to create project");
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("success", true);
            body.put("name", created.name);
            body.put("path", created.path);
            body.put("project_server_bound", created.serverBound);
            if (created.repoName != null) {
                body.put("server_repo", created.repoName);
            }
            body.putAll(GhidraIdentity.describe());
            return Response.ok(body);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/open_project", method = "POST", description = "Open an existing Ghidra project (.gpr file or directory)", category = "headless")
    public Response openProject(
            @Param(value = "path", source = ParamSource.BODY) String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return Response.err("Project path required");
        }
        HeadlessProgramProvider.OpenProjectResult opened = programProvider.openProjectDetailed(projectPath);
        if (opened.success) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("success", true);
            body.put("project", opened.projectName);
            if (opened.identity != null) {
                body.putAll(opened.identity);
            }
            if (opened.checkoutIdentityWarnings != null && !opened.checkoutIdentityWarnings.isEmpty()) {
                body.put("checkout_identity_warnings", opened.checkoutIdentityWarnings);
            }
            HeadlessProgramProvider.ServerBindingInfo binding = programProvider.getProjectServerInfo();
            if (binding != null) {
                body.put("project_server_bound", binding.serverBound);
                if (binding.serverBound) {
                    body.put("server_repo", binding.repoName);
                }
            }
            return Response.ok(body);
        }
        String status = (opened.lockFiles != null && !opened.lockFiles.isEmpty())
            ? "stale_lock" : null;
        return Response.err(
            opened.error != null ? opened.error : "Failed to open project: " + projectPath,
            status);
    }

    @McpTool(path = "/close_project", method = "POST", description = "Close the currently open project", category = "headless")
    public Response closeProject() {
        if (!programProvider.hasProject()) {
            return Response.err("No project currently open");
        }
        String projectName = programProvider.getProjectName();
        HeadlessProgramProvider.CloseProjectResult closed = programProvider.closeProjectDetailed();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", closed.success);
        body.put("closed", projectName);
        body.put("openable", closed.openable);
        if (closed.remainingLocks != null && !closed.remainingLocks.isEmpty()) {
            body.put("remaining_lock_files", closed.remainingLocks);
            body.put("warning", "Close left lock files behind. The next open_project will fail until they are deleted: "
                + String.join(", ", closed.remainingLocks));
        }
        return Response.ok(body);
    }

    @McpTool(path = "/load_program_from_project", method = "POST", description = "Load a program from the open project. Returns structured diagnostics on failure (available paths, server-binding state) so the operator can tell server-side-checkout-but-not-shared from path-typo from server-unreachable. See discussion #119.", category = "headless")
    public Response loadProgramFromProject(
            @Param(value = "path", source = ParamSource.BODY, description = "Program path within the project") String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return Response.err("Program path required");
        }
        if (!programProvider.hasProject()) {
            return Response.err("No project open. Call /open_project first.");
        }

        HeadlessProgramProvider.ProgramLoadResult res =
            programProvider.loadProgramFromProjectDetailed(programPath);

        if (res.success) {
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("success", true);
            ok.put("program", res.program.getName());
            ok.put("path", programPath);
            return Response.ok(ok);
        }

        // Structured failure — exposed so a Docker-headless user can tell
        // "wrong path" from "project not bound to server" from "server
        // unreachable" without needing to read Ghidra logs in the container.
        Map<String, Object> diagnostics = new LinkedHashMap<>();
        diagnostics.put("project_open", true);
        diagnostics.put("project_name", programProvider.getProjectName());
        HeadlessProgramProvider.ServerBindingInfo binding = programProvider.getProjectServerInfo();
        if (binding != null) {
            diagnostics.put("project_server_bound", binding.serverBound);
            if (binding.serverBound) {
                diagnostics.put("server", binding.serverInfo);
                diagnostics.put("server_repo", binding.repoName);
            }
        }
        if (res.availablePaths != null) {
            diagnostics.put("available_program_paths", res.availablePaths);
        }
        if (res.serverHint != null && !res.serverHint.isEmpty()) {
            diagnostics.put("suggestion", res.serverHint);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("error", res.error);
        body.put("requested_path", programPath);
        body.put("diagnostics", diagnostics);
        return Response.ok(body);
    }

    @McpTool(path = "/checkin_program", method = "POST", description = "Check a program back in to the shared Ghidra Server as a new version (the write-back path GhidraServerManager.checkinFile can't provide — see #119). Requires a shared (server-bound) project opened via /open_project and the file checked out. Saves pending edits and releases the open program first so keep_checked_out=false can actually drop the server checkout. Returns version_before/version/version_bumped.", category = "headless")
    public Response checkinProgram(
            @Param(value = "path", source = ParamSource.BODY, description = "Project path of the file (e.g. '/scratch/writetest'); empty uses the current program") String path,
            @Param(value = "comment", source = ParamSource.BODY, description = "Checkin comment") String comment,
            @Param(value = "keep_checked_out", source = ParamSource.BODY, defaultValue = "false", description = "Keep the file checked out after the new version lands") boolean keepCheckedOut,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                description = "Preview the check-in without saving or creating a new version") boolean dryRun) {
        if (!programProvider.hasProject()) {
            return Response.err("No project open. Call /open_project first.");
        }
        Map<String, Object> res = programProvider.checkinProgram(path, comment, keepCheckedOut, dryRun);
        return fromVc(res);
    }

    @McpTool(path = "/get_project_info", description = "Get info about the currently open project, including server-binding state. A shared (server-bound) project is required for /server/version_control/checkout to deliver content the headless can open; if `project_server_bound` is false, the open project is local-only.", category = "headless")
    public Response getProjectInfo() {
        if (!programProvider.hasProject()) {
            return Response.ok(JsonHelper.mapOf("has_project", false));
        }
        List<HeadlessProgramProvider.ProjectFileInfo> files = programProvider.listProjectFiles();
        int programCount = (int) files.stream().filter(f -> "Program".equals(f.contentType)).count();

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("has_project", true);
        info.put("project_name", programProvider.getProjectName());
        info.put("file_count", files.size());
        info.put("program_count", programCount);

        // Server-binding visibility (#119) — lets the operator confirm at
        // a glance whether checkout flows will actually deliver content
        // their /load_program_from_project can pick up.
        HeadlessProgramProvider.ServerBindingInfo binding = programProvider.getProjectServerInfo();
        if (binding != null) {
            info.put("project_server_bound", binding.serverBound);
            if (binding.serverBound) {
                info.put("server", binding.serverInfo);
                info.put("server_repo", binding.repoName);
            }
        }
        info.putAll(GhidraIdentity.describe());
        List<Map<String, Object>> checkoutWarnings =
            ProjectVersionControl.checkoutIdentityWarnings(programProvider.getProject());
        if (!checkoutWarnings.isEmpty()) {
            info.put("checkout_identity_warnings", checkoutWarnings);
        }
        return Response.ok(info);
    }

    // ========================================================================
    // GZF export / import
    // ========================================================================

    @McpTool(path = "/export_program", method = "POST",
            description = "Export a program to a GZF (Ghidra packed-database) file on disk. The resulting .gzf "
                + "can be imported into any Ghidra GUI (File \u2192 Import) or back into a project via "
                + "/import_program. Resolution order: (1) the in-memory program with that name (captures live "
                + "analyst edits); (2) a DomainFile in the open project (on-disk state). Output is written to "
                + "`output_dir/output_name` (defaults: /data/exports and `<program>.gzf`). Refuses to overwrite "
                + "an existing file. self_contained=true disassociates FILE/PROJECT type archives on the "
                + "exported copy only so it opens in a project that lacks those archives; the program "
                + "in the project is unchanged.",
            category = "headless")
    public Response exportProgram(
            @Param(value = "program_name", source = ParamSource.BODY,
                description = "Program name or project path (e.g. 'myprog' or '/myprog').") String programName,
            @Param(value = "output_dir", source = ParamSource.BODY, defaultValue = "/data/exports",
                description = "Directory the .gzf will be written to. Must already exist.") String outputDir,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                description = "Output file name. Defaults to `<program>.gzf`. `.gzf` is appended if missing.") String outputName,
            @Param(value = "self_contained", source = ParamSource.BODY, defaultValue = "false",
                description = "Disassociate FILE/PROJECT type archives on the exported .gzf only. "
                        + "The source program's archive links are left in place.")
                    boolean selfContained) {
        if (programName == null || programName.isEmpty()) {
            return Response.err("program_name required");
        }
        String dirPath = (outputDir == null || outputDir.isEmpty()) ? "/data/exports" : outputDir;
        File dir = resolveWithinRootOrLog(dirPath, "/export_program");
        if (dir == null) return Response.err(FILE_ROOT_DENY);
        if (!dir.isDirectory()) {
            return Response.err("output_dir not a directory: " + dir.getAbsolutePath());
        }
        String name;
        if (outputName == null || outputName.isEmpty()) {
            name = HeadlessPaths.safeBasename(programName) + ".gzf";
        } else {
            String invalid = HeadlessPaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gzf")) {
            name = name + ".gzf";
        }
        File out = new File(dir, name);
        if (!HeadlessPaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        HeadlessProgramProvider.ExportResult res =
                programProvider.exportProgramToGzf(programName, out, selfContained);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("program", res.programName);
        body.put("path", res.outputPath);
        body.put("size_bytes", res.sizeBytes);
        body.put("content_type", "GZF");
        body.put("self_contained", selfContained);
        return Response.ok(body);
    }

    @McpTool(path = "/import_program", method = "POST",
            description = "Import a GZF (Ghidra packed-database) file into the open project. The GZF must already "
                + "exist on disk at `gzf_path` (typically staged on a shared volume by the orchestrator). Lands at "
                + "`target_folder/target_name` (defaults: `/` and the GZF basename sans `.gzf`). Set `overwrite=true` "
                + "to replace an existing program at the destination; otherwise the call fails on collision.",
            category = "headless")
    public Response importProgram(
            @Param(value = "gzf_path", source = ParamSource.BODY,
                description = "Absolute path to the .gzf file on disk.") String gzfPath,
            @Param(value = "target_folder", source = ParamSource.BODY, defaultValue = "/",
                description = "Destination folder in the project. Intermediate folders are created.") String targetFolder,
            @Param(value = "target_name", source = ParamSource.BODY, defaultValue = "",
                description = "Destination file name in the project. Defaults to the GZF basename sans `.gzf`.") String targetName,
            @Param(value = "overwrite", source = ParamSource.BODY, defaultValue = "false",
                description = "When true, delete any existing program at the destination before importing.") boolean overwrite) {
        if (gzfPath == null || gzfPath.isEmpty()) {
            return Response.err("gzf_path required");
        }
        File gzf = resolveWithinRootOrLog(gzfPath, "/import_program");
        if (gzf == null) return Response.err(FILE_ROOT_DENY);

        HeadlessProgramProvider.ImportResult res =
            programProvider.importProgramFromGzf(gzf, targetFolder, targetName, overwrite);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", programProvider.getProjectName());
        body.put("folder", res.folderPath);
        body.put("program", res.programName);
        body.put("content_type", res.contentType);
        return Response.ok(body);
    }

    // ========================================================================
    // GAR project archive / restore
    // ========================================================================

    @McpTool(path = "/archive_project", method = "POST",
            description = "Archive the currently open project to a Ghidra-native .gar file. The result can be "
                + "restored into any Ghidra GUI via File \u2192 Restore Project, or back into a headless instance "
                + "via /restore_project. Captures the entire project (all programs, folders, settings, "
                + "version-control metadata) \u2014 unlike /export_program which ships a single program as .gzf. "
                + "Output is written to `output_dir/output_name` (defaults: /data/exports and `<project>.gar`). "
                + "Refuses to overwrite an existing file. Callers should /save_all_programs first to flush "
                + "pending in-memory edits.",
            category = "headless")
    public Response archiveProject(
            @Param(value = "output_dir", source = ParamSource.BODY, defaultValue = "/data/exports",
                description = "Directory the .gar will be written to. Must already exist.") String outputDir,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                description = "Output file name. Defaults to `<project>.gar`. `.gar` is appended if missing.") String outputName) {
        String dirPath = (outputDir == null || outputDir.isEmpty()) ? "/data/exports" : outputDir;
        File dir = resolveWithinRootOrLog(dirPath, "/archive_project");
        if (dir == null) return Response.err(FILE_ROOT_DENY);
        if (!dir.isDirectory()) {
            return Response.err("output_dir not a directory: " + dir.getAbsolutePath());
        }
        String projectName = programProvider.getProjectName();
        String name;
        if (outputName == null || outputName.isEmpty()) {
            name = HeadlessPaths.safeBasename(projectName == null ? "project" : projectName) + ".gar";
        } else {
            String invalid = HeadlessPaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gar")) {
            name = name + ".gar";
        }
        File out = new File(dir, name);
        if (!HeadlessPaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        HeadlessProgramProvider.ArchiveResult res = programProvider.archiveCurrentProject(out);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", res.projectName);
        body.put("path", res.outputPath);
        body.put("size_bytes", res.sizeBytes);
        body.put("content_type", "GAR");
        return Response.ok(body);
    }

    @McpTool(path = "/restore_project", method = "POST",
            description = "Restore a Ghidra .gar archive into a fresh on-disk project at `parent_dir/project_name`. "
                + "Closes any currently-open project first. The restored project is NOT re-opened automatically; "
                + "follow up with /open_project so owner reset and project bookkeeping run via the same code path "
                + "as a user-driven open. Fails loudly if the destination project already exists.",
            category = "headless")
    public Response restoreProject(
            @Param(value = "gar_path", source = ParamSource.BODY,
                description = "Absolute path to the .gar file on disk.") String garPath,
            @Param(value = "parent_dir", source = ParamSource.BODY, defaultValue = "/data/ghidra_projects",
                description = "Directory under which the new project (project_name.gpr + project_name.rep/) will be created.") String parentDir,
            @Param(value = "project_name", source = ParamSource.BODY,
                description = "Name of the new project to create from the archive.") String projectName) {
        if (garPath == null || garPath.isEmpty()) {
            return Response.err("gar_path required");
        }
        File gar = new File(garPath);

        HeadlessProgramProvider.RestoreResult res =
            programProvider.restoreProject(gar, parentDir, projectName);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", res.projectName);
        body.put("project_dir", res.projectDir);
        return Response.ok(body);
    }

    // ========================================================================
    // Server status
    // ========================================================================

    @McpTool(path = "/server/status", description = "Check headless server connection status", category = "headless")
    public Response serverStatus() {
        return Response.text(serverManager.getStatus());
    }

    @McpTool(path = "/server/version_control/add", method = "POST",
            description = "Add a DomainFile in the open shared project to version control. "
                + "Requires an open server-bound project. Returns the new version number and "
                + "checkout state. Errors (does not no-op) if the file is already versioned, "
                + "the path is missing, no project is open, or the project is local-only.",
            category = "server")
    public Response addToVersionControl(
            @Param(value = "path", source = ParamSource.BODY,
                description = "Project DomainFile path, e.g. /nullcog.elf") String path,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "",
                description = "Initial version comment") String comment,
            @Param(value = "keep_checked_out", source = ParamSource.BODY, defaultValue = "false",
                aliases = {"keepCheckedOut"},
                description = "Keep the file checked out after adding it") boolean keepCheckedOut,
            @Param(value = "repo", source = ParamSource.BODY, defaultValue = "",
                description = "Ignored; the open project's repository is used. Accepted for compatibility.") String repo,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                description = "Preview the add without changing version-control state") boolean dryRun) {
        Map<String, Object> res = programProvider.addToVersionControl(path, comment, keepCheckedOut, dryRun);
        return fromVc(res);
    }

    @McpTool(path = "/refresh_project", method = "POST",
            description = "Close open programs and resync the open project's DomainFiles with the "
                + "bound Ghidra Server repository. Use after the repository changes structurally "
                + "(file deleted and re-added) or after copying a .gpr whose DomainFiles are stale.",
            category = "headless")
    public Response refreshProject() {
        return fromVc(programProvider.refreshProject());
    }

    private static Response fromVc(Map<String, Object> res) {
        if (res == null) {
            return Response.err("No result");
        }
        if (Boolean.FALSE.equals(res.get("success"))) {
            String error = String.valueOf(res.get("error"));
            Object status = res.get("status");
            if (status instanceof String s && !s.isBlank()) {
                return Response.err(error, s);
            }
            return Response.err(error);
        }
        return Response.ok(res);
    }

    @McpTool(path = "/upload_file", method = "POST",
            description = "Write a local file into GHIDRA_MCP_FILE_ROOT/uploads/ so a subsequent "
                + "import_file can load it with no host-filesystem access. filename is a name, "
                + "not a path: separators and '..' are rejected. Requires FILE_ROOT.",
            category = "headless")
    public Response uploadFile(
            @Param(value = "filename", source = ParamSource.BODY,
                description = "Destination filename (no path separators or '..')") String filename,
            @Param(value = "content_base64", source = ParamSource.BODY,
                description = "File bytes, base64-encoded") String contentBase64,
            @Param(value = "overwrite", source = ParamSource.BODY, defaultValue = "false",
                description = "Replace an existing file. Always refused if that file is open as a program.") boolean overwrite) {
        SecurityConfig security = SecurityConfig.getInstance();
        if (!security.hasFileRoot()) {
            return Response.err("upload_file requires GHIDRA_MCP_FILE_ROOT so uploads stay confined "
                + "to <root>/uploads/");
        }
        String nameError = HeadlessPaths.validateFilename(filename);
        if (nameError != null) {
            return Response.err("invalid filename: " + nameError);
        }
        if (contentBase64 == null || contentBase64.isEmpty()) {
            return Response.err("content_base64 is required");
        }

        byte[] bytes;
        try {
            String stripped = contentBase64.replaceAll("\\s+", "");
            bytes = Base64.getDecoder().decode(stripped);
        } catch (IllegalArgumentException e) {
            return Response.err("content_base64 is not valid base64");
        }
        if (bytes.length > security.getMaxUploadBytes()) {
            return Response.err("Upload exceeds maximum of " + security.getMaxUploadBytes()
                + " bytes (GHIDRA_MCP_MAX_UPLOAD_BYTES)");
        }

        Path dest = security.resolveWithinFileRoot(
            Path.of(security.getFileRoot(), "uploads", filename).toString());
        if (dest == null) {
            return Response.err("Access denied: path is outside the configured file root");
        }

        if (isOpenProgramFile(dest)) {
            return Response.err("Cannot overwrite a file currently open as a program: " + dest);
        }
        if (Files.exists(dest) && !overwrite) {
            return Response.err("File already exists: " + dest + " (pass overwrite=true to replace)");
        }

        try {
            Files.createDirectories(dest.getParent());
            if (overwrite) {
                Files.write(dest, bytes, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            } else {
                Files.write(dest, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            }
            String sha256 = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(bytes));
            return Response.ok(JsonHelper.mapOf(
                "path", dest.toString(),
                "bytes_written", bytes.length,
                "sha256", sha256));
        } catch (Exception e) {
            return Response.err("Upload failed: "
                + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
        }
    }

    private boolean isOpenProgramFile(Path dest) {
        Path canonical;
        try {
            canonical = dest.toAbsolutePath().normalize();
        } catch (Exception e) {
            return false;
        }
        for (Program program : programProvider.getAllOpenPrograms()) {
            String exec = program.getExecutablePath();
            if (exec == null || exec.isBlank()) {
                continue;
            }
            try {
                if (Path.of(exec).toAbsolutePath().normalize().equals(canonical)) {
                    return true;
                }
            } catch (Exception ignored) {
                // skip unparseable executable paths
            }
        }
        return false;
    }
}
