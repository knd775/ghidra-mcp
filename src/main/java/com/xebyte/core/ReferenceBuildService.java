package com.xebyte.core;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Compile pinned-source reference libraries into {@code GHIDRA_MCP_FILE_ROOT/uploads}
 * via the sibling builder container, then {@code import_file} can load the path.
 *
 * <p>The Ghidra container is the wrong place to build (uid 1000, no compiler).
 * Moving object bytes through an agent tool call has already silently corrupted
 * a 34 KB object (same length, different sha256). Source is fetched by ref;
 * objects never leave the shared volume.
 */
@McpToolGroup(value = "bsim",
        description = "Cross-build function matching via Ghidra BSim (CLI wrapper). "
                + "build_reference compiles pinned source into the shared volume for ingest. "
                + "builder_health lists what the container can compile.")
public class ReferenceBuildService {

    private static final String DEFAULT_MANIFEST_RESOURCE = "/reference/references.yaml";
    private static final String DEFAULT_MANIFEST_ON_VOLUME = "references.yaml";

    private final ReferenceBuild.BuilderConfig config;
    private final BuilderClient client;

    public ReferenceBuildService() {
        this(ReferenceBuild.fromEnv(), new BuilderClient.Http());
    }

    public ReferenceBuildService(ReferenceBuild.BuilderConfig config, BuilderClient client) {
        this.config = config;
        this.client = client;
    }

    @McpTool(path = "/build_reference", method = "POST",
            description = "Clone a git tag or commit in the builder container and compile "
                    + "it to GHIDRA_MCP_FILE_ROOT/uploads. Never pass object bytes through "
                    + "this tool; the shared volume is the handoff. ref must be a tag or SHA "
                    + "(bare branch names are refused). Compiled with -g; strip_debug=true runs "
                    + "strip --strip-debug (keeps .symtab) when corpus disk is tight. "
                    + "mode=sources accepts prepare (a shell command run in "
                    + "the cloned tree after checkout, before compile) so generated headers do not "
                    + "need a framework stub. prepare comes from this call or a manifest, never "
                    + "from repository content. Both modes return one envelope "
                    + "({status, mode, name, ref, artifacts, failed, command}); sources "
                    + "emits a one-element artifacts array. dry_run uses the same envelope "
                    + "with status would_execute and expected artifact paths; it does not "
                    + "clone or compile. "
                    + "Output name: <name>-<ref>-<toolchain>-<opt>.o, or in framework mode "
                    + "<name>-<library>-<ref>-<toolchain>-<opt>[-<board>].o. mode=framework "
                    + "configures a stub (docker/stubs/<framework>/), builds, and harvests "
                    + "build-tree objects, never the linked ELF. Each artifact is written with "
                    + "a <artifact>.json sidecar (resolved commit SHA, compiler --version, "
                    + "sha256, debug_path_prefix). A failed harvest removes objects it wrote. "
                    + "force=true deletes this spec's existing objects and sidecars before "
                    + "compile so a previous (including unreported) build is not reused. "
                    + "dry_run never deletes. Long builds return "
                    + "{status: started, job_id} when they outlive wait_seconds; poll "
                    + "build_reference_status.",
            category = "bsim")
    public Response buildReference(
            @Param(value = "name", source = ParamSource.BODY,
                    description = "Corpus entry name, e.g. littlefs") String name,
            @Param(value = "repo", source = ParamSource.BODY,
                    description = "Git URL") String repo,
            @Param(value = "ref", source = ParamSource.BODY,
                    description = "Tag or commit SHA. Required. Branch names are refused.") String ref,
            @Param(value = "sources", source = ParamSource.BODY,
                    description = "Source files to compile, JSON array e.g. [\"lfs.c\"]") Object sources,
            @Param(value = "toolchain", source = ParamSource.BODY, defaultValue = "gcc13-arm",
                    description = "Full identity <compiler><major>-<target> (gcc13-arm, "
                            + "gcc13-x86_64, clang17-arm). Selects which binary the builder "
                            + "invokes. Unknown names list identities from builder_health.")
                    String toolchain,
            @Param(value = "arch_flags", source = ParamSource.BODY,
                    defaultValue = "",
                    description = "Caller-supplied. Blank uses the identity default "
                            + "(gcc-arm: -mcpu=cortex-m0plus -mthumb; clang-arm: "
                            + "--target=thumbv6m-none-eabi)") String archFlags,
            @Param(value = "opt", source = ParamSource.BODY, defaultValue = "-Os",
                    description = "Optimisation level, e.g. -Os, -O2, -O3") String opt,
            @Param(value = "defines", source = ParamSource.BODY, defaultValue = "",
                    description = "Preprocessor defines, JSON array e.g. [\"LFS_NO_MALLOC\"]")
                    Object defines,
            @Param(value = "extra_flags", source = ParamSource.BODY, defaultValue = "",
                    description = "Extra compiler flags, JSON array") Object extraFlags,
            @Param(value = "prepare", source = ParamSource.BODY, defaultValue = "",
                    description = "mode=sources: shell command run in the cloned tree after "
                            + "checkout and before compile (e.g. make src/common/defs.h). "
                            + "Must come from this call or a manifest, never from repository "
                            + "content. Failed prepare returns the command's stdout and stderr.")
                    String prepare,
            @Param(value = "prepare_timeout", source = ParamSource.BODY, defaultValue = "300",
                    description = "Seconds allowed for prepare (default 300, max 3600).")
                    int prepareTimeout,
            @Param(value = "strip_debug", source = ParamSource.BODY, defaultValue = "false",
                    description = "strip --strip-debug (keeps .symtab). Default false so "
                            + "references keep DWARF for typed import and View Source.")
                    boolean stripDebug,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                    description = "Override filename. Default <name>-<ref>-<toolchain>-<opt>.o")
                    String outputName,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                    description = "Return the envelope with status would_execute and expected "
                            + "artifact paths; do not clone or compile")
                    boolean dryRun,
            @Param(value = "mode", source = ParamSource.BODY, defaultValue = "sources",
                    description = "sources (named .c files) or framework (stub project + harvest). Default sources.")
                    String mode,
            @Param(value = "framework", source = ParamSource.BODY, defaultValue = "",
                    description = "mode=framework: stub name, e.g. pico-sdk. Unknown names "
                            + "list stubs from builder_health.")
                    String framework,
            @Param(value = "libraries", source = ParamSource.BODY, defaultValue = "",
                    description = "mode=framework: CMake targets to link, JSON array. Empty is an error.")
                    Object libraries,
            @Param(value = "board", source = ParamSource.BODY, defaultValue = "",
                    description = "mode=framework: board id, e.g. pico or pico_w")
                    String board,
            @Param(value = "config", source = ParamSource.BODY, defaultValue = "",
                    description = "mode=framework: extra CMake -D defines, JSON object")
                    Object frameworkConfig,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = "Seconds to wait inline (max 55). Past that, poll "
                            + "build_reference_status with the returned job_id.")
                    int waitSeconds,
            @Param(value = "force", source = ParamSource.BODY, defaultValue = "false",
                    description = "Delete this spec's existing objects and sidecars, then "
                            + "rebuild. Use after an unreported build or to ignore a matching "
                            + "sidecar. dry_run reports would_replace and deletes nothing.")
                    boolean force) {
        try {
            ReferenceBuild.Inventory inv = requireInventory();
            ReferenceBuild.Spec spec = ReferenceBuild.parse(
                    name, repo, ref, sources, toolchain, archFlags, opt, defines, extraFlags,
                    stripDebug, outputName, inv.identities(),
                    mode, framework, libraries, board, frameworkConfig, inv.stubs(),
                    prepare, prepareTimeout);
            return runSpec(spec, dryRun, false, waitSeconds, force);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    /** Compat for callers that omit force. */
    public Response buildReference(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extraFlags,
            String prepare, int prepareTimeout,
            boolean stripDebug, String outputName, boolean dryRun,
            String mode, String framework, Object libraries, String board,
            Object frameworkConfig, int waitSeconds) {
        return buildReference(name, repo, ref, sources, toolchain, archFlags, opt,
                defines, extraFlags, prepare, prepareTimeout,
                stripDebug, outputName, dryRun,
                mode, framework, libraries, board, frameworkConfig,
                waitSeconds, false);
    }

    /** Sources-mode overload used by offline tests (new params default). */
    public Response buildReference(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extraFlags,
            boolean stripDebug, String outputName, boolean dryRun) {
        return buildReference(name, repo, ref, sources, toolchain, archFlags, opt,
                defines, extraFlags, "", ReferenceBuild.DEFAULT_PREPARE_TIMEOUT,
                stripDebug, outputName, dryRun,
                FrameworkBuild.MODE_SOURCES, "", null, "", null,
                ReferenceBuild.DEFAULT_WAIT_SECONDS, false);
    }

    /** Framework-mode overload used by offline tests (wait_seconds default). */
    public Response buildReference(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extraFlags,
            boolean stripDebug, String outputName, boolean dryRun,
            String mode, String framework, Object libraries, String board,
            Object frameworkConfig) {
        return buildReference(name, repo, ref, sources, toolchain, archFlags, opt,
                defines, extraFlags, "", ReferenceBuild.DEFAULT_PREPARE_TIMEOUT,
                stripDebug, outputName, dryRun,
                mode, framework, libraries, board, frameworkConfig,
                ReferenceBuild.DEFAULT_WAIT_SECONDS, false);
    }

    /** Framework/sources overload that still defaults prepare. */
    public Response buildReference(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extraFlags,
            boolean stripDebug, String outputName, boolean dryRun,
            String mode, String framework, Object libraries, String board,
            Object frameworkConfig, int waitSeconds) {
        return buildReference(name, repo, ref, sources, toolchain, archFlags, opt,
                defines, extraFlags, "", ReferenceBuild.DEFAULT_PREPARE_TIMEOUT,
                stripDebug, outputName, dryRun,
                mode, framework, libraries, board, frameworkConfig,
                waitSeconds, false);
    }

    /** Test overload that sets force without restating prepare. */
    public Response buildReference(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extraFlags,
            boolean stripDebug, String outputName, boolean dryRun,
            String mode, String framework, Object libraries, String board,
            Object frameworkConfig, int waitSeconds, boolean force) {
        return buildReference(name, repo, ref, sources, toolchain, archFlags, opt,
                defines, extraFlags, "", ReferenceBuild.DEFAULT_PREPARE_TIMEOUT,
                stripDebug, outputName, dryRun,
                mode, framework, libraries, board, frameworkConfig,
                waitSeconds, force);
    }

    @McpTool(path = "/build_manifest", method = "POST",
            description = "Expand docker/references.yaml (or a path under FILE_ROOT) into "
                    + "build_reference jobs and run them. A matrix of toolchain × opt (and "
                    + "board, for framework entries) is how the corpus covers compiler drift. "
                    + "Jobs whose artifact exists, whose sidecar sha256 still matches, and "
                    + "whose sidecar prepare matches the job are skipped; a missing or "
                    + "mismatched sidecar (or a changed prepare) rebuilds. force=true skips "
                    + "that check, deletes the expected objects and sidecars, and rebuilds. "
                    + "dry_run returns every command line without cloning or compiling "
                    + "(force still does not delete). One shared wait_seconds "
                    + "deadline covers the whole matrix; unfinished jobs return a job_id for "
                    + "build_reference_status. Userland corpus: path=references.userland.yaml.",
            category = "bsim")
    public Response buildManifest(
            @Param(value = "path", source = ParamSource.BODY, defaultValue = "",
                    description = "Manifest path under FILE_ROOT. Empty = /data/references.yaml "
                            + "then the baked-in docker/references.yaml.") String path,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                    description = "Resolve every job's command line; do not clone or compile")
                    boolean dryRun,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = "Shared inline wait for the whole matrix (max 55).")
                    int waitSeconds,
            @Param(value = "force", source = ParamSource.BODY, defaultValue = "false",
                    description = "Rebuild every job even when the sidecar hash matches. "
                            + "Deletes expected objects first. dry_run still compiles nothing.")
                    boolean force) {
        try {
            String yaml = readManifest(path);
            ReferenceBuild.Inventory inv;
            try {
                inv = requireInventory();
            } catch (IOException e) {
                return Response.err(e.getMessage(), "builder_unreachable");
            }
            List<ReferenceBuild.Spec> jobs = ReferenceManifest.parse(
                    yaml, inv.identities(), inv.stubs());
            List<Object> results = new ArrayList<>();
            List<Pending> pending = new ArrayList<>();
            int failed = 0;
            int skipped = 0;
            for (ReferenceBuild.Spec spec : jobs) {
                Response r = submitSpec(spec, dryRun, true, force);
                if (isStartedTicket(r)) {
                    pending.add(new Pending(spec, jobIdOf(r), results.size()));
                    results.add(null);
                    continue;
                }
                if (r instanceof Response.Err) failed++;
                Object parsed = JsonHelper.parseJson(r.toJson());
                if (parsed instanceof Map<?, ?> map && Boolean.TRUE.equals(map.get("skipped"))) {
                    skipped++;
                }
                results.add(parsed);
            }
            if (!pending.isEmpty() && !dryRun) {
                pollPending(pending, results, waitSeconds);
                for (int i = 0; i < results.size(); i++) {
                    if (results.get(i) == null) {
                        Pending left = findPending(pending, i);
                        Response ticket = left == null
                                ? Response.err("missing build job", "job_not_found")
                                : ticket(left.jobId);
                        results.set(i, JsonHelper.parseJson(ticket.toJson()));
                    }
                }
                failed = 0;
                for (Object row : results) {
                    if (row instanceof Map<?, ?> map && map.get("error") != null) {
                        failed++;
                    }
                }
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", failed == 0 ? "success" : "partial");
            body.put("dry_run", dryRun);
            if (force) body.put("force", true);
            body.put("count", jobs.size());
            body.put("failed", failed);
            body.put("skipped", skipped);
            String db = ReferenceManifest.databaseUrl(yaml);
            if (db != null && !db.isBlank()) body.put("database", db);
            body.put("results", results);
            return Response.ok(body);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    /** Overload used by offline tests. */
    public Response buildManifest(String path, boolean dryRun) {
        return buildManifest(path, dryRun, ReferenceBuild.DEFAULT_WAIT_SECONDS, false);
    }

    /** Overload used by offline tests (force default). */
    public Response buildManifest(String path, boolean dryRun, int waitSeconds) {
        return buildManifest(path, dryRun, waitSeconds, false);
    }

    @McpTool(path = "/builder_health", method = "GET",
            description = "What the ghidra-builder container can compile right now: packed "
                    + "toolchain identities, ARM GNU releases, and framework stubs. Proxies "
                    + "the builder's GET /health. build_reference and build_manifest refuse "
                    + "unknown names using this same list, not a Java constant.",
            category = "bsim")
    public Response builderHealth() {
        URI url = firstBuilderUrl();
        if (url == null) {
            return Response.err("no builder URL configured", "builder_unreachable");
        }
        try {
            Map<String, Object> body = client.health(url);
            Object http = body.get("_http_status");
            if (http instanceof Number n && n.intValue() >= 400) {
                return Response.err(String.valueOf(body.getOrDefault("error",
                        "builder /health HTTP " + n)), "builder_unreachable");
            }
            Map<String, Object> out = new LinkedHashMap<>(body);
            out.remove("_http_status");
            return Response.ok(out);
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        }
    }

    @McpTool(path = "/source_read", method = "POST",
            description = "Read a span of pinned reference source from the builder cache. "
                    + "artifact names the corpus object (sidecar supplies repo and commit). "
                    + "function= resolves file and line range from that object's DWARF; "
                    + "path= reads a repo-relative file. Confined to the source cache. "
                    + "Response is numbered lines, capped; a missing commit names the cache.",
            category = "bsim")
    public Response sourceRead(
            @Param(value = "artifact", source = ParamSource.BODY,
                    description = "Corpus artifact filename or path under FILE_ROOT, "
                            + "e.g. littlefs-v2.9.3-gcc13-arm-Os.o")
                    String artifact,
            @Param(value = "function", source = ParamSource.BODY, defaultValue = "",
                    description = "Resolve file/line from the artifact's DWARF, then return "
                            + "that span plus context lines either side")
                    String function,
            @Param(value = "path", source = ParamSource.BODY, defaultValue = "",
                    description = "Repo-relative path (or a /ref/<name>/... DWARF path)")
                    String path,
            @Param(value = "start_line", source = ParamSource.BODY, defaultValue = "0",
                    description = "First line (1-based). 0 means start of the resolved span.")
                    int startLine,
            @Param(value = "end_line", source = ParamSource.BODY, defaultValue = "0",
                    description = "Last line inclusive. 0 means end of the resolved span.")
                    int endLine,
            @Param(value = "context", source = ParamSource.BODY, defaultValue = "20",
                    description = "Extra lines either side when resolving by function")
                    int context) {
        try {
            if (artifact == null || artifact.isBlank()) {
                return Response.err("artifact is required");
            }
            String func = function == null ? "" : function.trim();
            String rel = path == null ? "" : path.trim();
            if (func.isEmpty() && rel.isEmpty()) {
                return Response.err("function or path is required");
            }
            String confined = confineArtifact(artifact.trim());
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("artifact", confined);
            if (!func.isEmpty()) req.put("function", func);
            if (!rel.isEmpty()) req.put("path", rel);
            if (startLine > 0) req.put("start_line", startLine);
            if (endLine > 0) req.put("end_line", endLine);
            req.put("context", context > 0 ? context : 20);
            URI url = firstBuilderUrl();
            if (url == null) {
                return Response.err("no builder URL configured", "builder_unreachable");
            }
            Map<String, Object> body = client.source(url, req);
            Object http = body.get("_http_status");
            if (http instanceof Number n && n.intValue() >= 400) {
                return Response.err(String.valueOf(body.getOrDefault("error",
                        "builder /source HTTP " + n)),
                        String.valueOf(body.getOrDefault("status", "source_failed")));
            }
            if (Boolean.FALSE.equals(body.get("ok")) && body.get("error") != null) {
                return Response.err(String.valueOf(body.get("error")),
                        String.valueOf(body.getOrDefault("status", "source_failed")));
            }
            Map<String, Object> out = new LinkedHashMap<>(body);
            out.remove("_http_status");
            return Response.ok(out);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        }
    }

    String confineArtifact(String artifact) {
        Path p = Path.of(artifact);
        for (Path part : p) {
            if ("..".equals(part.toString())) {
                throw new IllegalArgumentException("artifact path must not contain '..'");
            }
        }
        if (config.fileRoot() == null) {
            return artifact;
        }
        Path candidate;
        if (p.isAbsolute()) {
            candidate = p;
        } else if (p.getNameCount() == 1) {
            candidate = config.fileRoot().resolve(ReferenceBuild.UPLOADS).resolve(artifact);
        } else {
            candidate = config.fileRoot().resolve(artifact);
        }
        Path resolved = SecurityConfig.getInstance().resolveWithinFileRoot(candidate.toString());
        if (resolved == null) {
            throw new IllegalArgumentException("artifact path is outside GHIDRA_MCP_FILE_ROOT");
        }
        return resolved.toString();
    }

    @McpTool(path = "/build_reference_status", method = "GET",
            description = "Status and result of a builder job. build_reference and "
                    + "build_manifest return {status: started, job_id} when a compile "
                    + "outlives wait_seconds; poll this until status is done or failed. "
                    + "Blank job_id lists every retained job.",
            category = "bsim")
    public Response buildReferenceStatus(
            @Param(value = "job_id", defaultValue = "",
                    description = "Job id from build_reference. Blank lists retained jobs.")
                    String jobId) {
        URI url = firstBuilderUrl();
        if (url == null) {
            return Response.err("no builder URL configured", "builder_unreachable");
        }
        String toolchain = config.knownToolchains().isEmpty()
                ? "" : config.knownToolchains().get(0);
        try {
            Map<String, Object> body = client.jobStatus(toolchain, url, jobId == null ? "" : jobId);
            Object http = body.get("_http_status");
            if (http instanceof Number n && n.intValue() == 404) {
                return Response.err(String.valueOf(body.getOrDefault("error",
                        "No build job with id '" + jobId + "'")), "job_not_found");
            }
            body.remove("_http_status");
            if (jobId != null && !jobId.isBlank() && isPending(body)) {
                body.put("hint", "Poll build_reference_status(job_id=\"" + jobId
                        + "\") until status is done or failed.");
            }
            return Response.ok(body);
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        }
    }

    Response runSpec(ReferenceBuild.Spec spec, boolean dryRun) {
        return runSpec(spec, dryRun, false, ReferenceBuild.DEFAULT_WAIT_SECONDS, false);
    }

    Response runSpec(ReferenceBuild.Spec spec, boolean dryRun, boolean incremental) {
        return runSpec(spec, dryRun, incremental, ReferenceBuild.DEFAULT_WAIT_SECONDS, false);
    }

    Response runSpec(ReferenceBuild.Spec spec, boolean dryRun, boolean incremental, int waitSeconds) {
        return runSpec(spec, dryRun, incremental, waitSeconds, false);
    }

    Response runSpec(ReferenceBuild.Spec spec, boolean dryRun, boolean incremental, int waitSeconds,
                      boolean force) {
        Response submitted = submitSpec(spec, dryRun, incremental, force);
        if (dryRun || submitted instanceof Response.Err || isSkipped(submitted) || !isStartedTicket(submitted)) {
            return submitted;
        }
        String jobId = jobIdOf(submitted);
        URI url;
        try {
            url = config.urlFor(spec.toolchain());
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage(), "unknown_toolchain");
        }
        return awaitJob(spec, url, jobId, spec.commandLines(spec.isFramework()
                ? spec.uploadsDir(config.fileRoot())
                : spec.outputPath(config.fileRoot())), waitSeconds);
    }

    private Response submitSpec(ReferenceBuild.Spec spec, boolean dryRun, boolean incremental) {
        return submitSpec(spec, dryRun, incremental, false);
    }

    private Response submitSpec(ReferenceBuild.Spec spec, boolean dryRun, boolean incremental,
                                 boolean force) {
        if (config.fileRoot() == null) {
            return Response.err("build_reference requires GHIDRA_MCP_FILE_ROOT so the object "
                    + "lands on the shared volume import_file can see");
        }
        Path output = spec.isFramework()
                ? spec.uploadsDir(config.fileRoot())
                : spec.outputPath(config.fileRoot());
        List<List<String>> command = spec.commandLines(output);
        if (dryRun) {
            Map<String, Object> body = ReferenceBuild.resultEnvelope(
                    "would_execute", spec, spec.previewArtifacts(config.fileRoot()),
                    List.of(), command, "", "");
            body.put("dry_run", true);
            body.put("prepare_timeout", spec.prepareTimeout());
            if (force) {
                body.put("force", true);
                List<String> replace = new ArrayList<>();
                for (Path p : FrameworkBuild.existingExpected(spec, config.fileRoot())) {
                    replace.add(p.toString());
                }
                body.put("would_replace", replace);
            }
            return Response.ok(body);
        }

        if (force) {
            try {
                FrameworkBuild.deleteExpectedArtifacts(spec, config.fileRoot());
            } catch (IOException e) {
                return Response.err(
                        "force could not remove previous artifact: " + e.getMessage(),
                        "force_failed");
            }
        } else if (incremental) {
            if (spec.isFramework() && FrameworkBuild.allOutputsExist(spec, config.fileRoot())) {
                return skipped(spec, FrameworkBuild.expectedPaths(spec, config.fileRoot()));
            }
            if (!spec.isFramework() && FrameworkBuild.sourceOutputExists(spec, config.fileRoot())) {
                return skipped(spec, List.of(output.toString()));
            }
        }

        URI url;
        try {
            url = config.urlFor(spec.toolchain());
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage(), "unknown_toolchain");
        }

        Map<String, Object> request = spec.toBuilderRequest(output);
        Map<String, Object> built;
        try {
            built = client.submit(spec.toolchain(), url, request);
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        }

        if (isPending(built)) {
            return ticket(String.valueOf(built.get("job_id")));
        }
        return finishBuild(spec, unwrap(built), command, force);
    }

    private Response awaitJob(ReferenceBuild.Spec spec, URI url, String jobId,
                               List<List<String>> command, int waitSeconds) {
        int wait = Math.max(0, Math.min(ReferenceBuild.MAX_WAIT_SECONDS, waitSeconds));
        long deadline = System.currentTimeMillis() + wait * 1000L;
        while (System.currentTimeMillis() < deadline) {
            Map<String, Object> snap;
            try {
                snap = client.jobStatus(spec.toolchain(), url, jobId);
            } catch (IOException e) {
                return Response.err(e.getMessage(), "builder_unreachable");
            }
            if (!isPending(snap)) {
                return finishBuild(spec, unwrap(snap), command);
            }
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return ticket(jobId);
            }
        }
        return ticket(jobId);
    }

    private void pollPending(List<Pending> pending, List<Object> results, int waitSeconds) {
        int wait = Math.max(0, Math.min(ReferenceBuild.MAX_WAIT_SECONDS, waitSeconds));
        long deadline = System.currentTimeMillis() + wait * 1000L;
        while (!pending.isEmpty() && System.currentTimeMillis() < deadline) {
            Iterator<Pending> it = pending.iterator();
            while (it.hasNext()) {
                Pending p = it.next();
                URI url;
                try {
                    url = config.urlFor(p.spec.toolchain());
                } catch (IllegalArgumentException e) {
                    results.set(p.index, JsonHelper.parseJson(
                            Response.err(e.getMessage(), "unknown_toolchain").toJson()));
                    it.remove();
                    continue;
                }
                Map<String, Object> snap;
                try {
                    snap = client.jobStatus(p.spec.toolchain(), url, p.jobId);
                } catch (IOException e) {
                    results.set(p.index, JsonHelper.parseJson(
                            Response.err(e.getMessage(), "builder_unreachable").toJson()));
                    it.remove();
                    continue;
                }
                if (isPending(snap)) continue;
                Path output = p.spec.isFramework()
                        ? p.spec.uploadsDir(config.fileRoot())
                        : p.spec.outputPath(config.fileRoot());
                Response done = finishBuild(p.spec, unwrap(snap), p.spec.commandLines(output));
                results.set(p.index, JsonHelper.parseJson(done.toJson()));
                it.remove();
            }
            if (pending.isEmpty()) break;
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static Pending findPending(List<Pending> pending, int index) {
        for (Pending p : pending) {
            if (p.index == index) return p;
        }
        return null;
    }

    private Response finishBuild(ReferenceBuild.Spec spec, Map<String, Object> built,
                                List<List<String>> command) {
        return finishBuild(spec, built, command, false);
    }

    private Response finishBuild(ReferenceBuild.Spec spec, Map<String, Object> built,
                                List<List<String>> command, boolean force) {
        if (built.containsKey("ok") && Boolean.FALSE.equals(asBoolean(built.get("ok")))) {
            String message = String.valueOf(built.getOrDefault("error", "build failed"));
            String status = built.get("status") == null ? "build_failed" : String.valueOf(built.get("status"));
            if ("failed".equals(status) && built.get("result") instanceof Map<?, ?> nested) {
                Object inner = nested.get("status");
                if (inner != null) status = String.valueOf(inner);
                if (nested.get("error") != null) {
                    message = String.valueOf(nested.get("error"));
                }
                if (nested.get("stderr") != null || nested.get("stdout") != null) {
                    built = new LinkedHashMap<>(built);
                    if (nested.get("stderr") != null) {
                        built.put("stderr", nested.get("stderr"));
                    }
                    if (nested.get("stdout") != null) {
                        built.put("stdout", nested.get("stdout"));
                    }
                }
            }
            if (built.get("stderr") != null) {
                message = message + (message.contains(String.valueOf(built.get("stderr")))
                        ? "" : "\n" + built.get("stderr"));
            }
            if (built.get("stdout") != null) {
                String so = String.valueOf(built.get("stdout"));
                if (!so.isBlank() && !message.contains(so)) {
                    message = message + "\n" + so;
                }
            }
            return Response.err(message, status);
        }
        Object http = built.get("_http_status");
        if (http instanceof Number n && n.intValue() >= 400) {
            return Response.err(String.valueOf(built.getOrDefault("error", "builder HTTP " + n)),
                    "builder_http_" + n.intValue());
        }

        List<Object> artifacts;
        Object arts = built.get("artifacts");
        if (arts instanceof List<?> list && !list.isEmpty()) {
            Response bad = rejectBadArtifacts(list);
            if (bad != null) return bad;
            artifacts = new ArrayList<>(list);
        } else if (!spec.isFramework()) {
            Object countRaw = built.get("function_count");
            int count = JsonHelper.getInt(countRaw, -1);
            if (countRaw == null || count == 0) {
                return Response.err(
                        count == 0
                                ? "refusing to write: 0 defined functions (everything was "
                                + "optimised out or the wrong file was compiled)"
                                : "refusing to write: builder omitted function_count",
                        count == 0 ? "zero_functions" : "missing_function_count");
            }
            Path output = spec.outputPath(config.fileRoot());
            Map<String, Object> art = ReferenceBuild.artifactEntry(
                    String.valueOf(built.getOrDefault("path", output.toString())), "");
            art.put("bytes", built.get("bytes"));
            art.put("sha256", built.get("sha256"));
            art.put("function_count", built.get("function_count"));
            art.put("defined_functions", built.get("defined_functions"));
            artifacts = List.of(art);
        } else {
            return Response.err(
                    "refusing to write: 0 defined functions harvested "
                            + "(0 target objects in the build tree; the linked ELF was not used)",
                    "zero_functions");
        }

        Object failedRaw = built.get("failed");
        if (failedRaw == null) {
            failedRaw = built.get("failed_units");
        }
        List<?> failed = failedRaw instanceof List<?> list ? list : List.of();
        Map<String, Object> body = ReferenceBuild.resultEnvelope(
                "success", spec, artifacts, failed,
                built.getOrDefault("command", command),
                stringOrEmpty(built.get("commit_sha")),
                stringOrEmpty(built.get("cc_version")));
        if (force) body.put("force", true);
        return Response.ok(body);
    }

    private static Response rejectBadArtifacts(List<?> list) {
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> m)) {
                return Response.err(
                        "refusing to write: builder omitted function_count",
                        "missing_function_count");
            }
            Object countRaw = m.get("function_count");
            int fc = JsonHelper.getInt(countRaw, -1);
            if (countRaw == null) {
                return Response.err(
                        "refusing to write: builder omitted function_count",
                        "missing_function_count");
            }
            if (fc <= 0) {
                Object libObj = m.get("library");
                String lib = libObj == null ? "?" : String.valueOf(libObj);
                return Response.err(
                        "refusing to write: 0 defined functions in harvested " + lib
                                + " (the linked ELF was not used)",
                        "zero_functions");
            }
        }
        return null;
    }

    private static Response skipped(ReferenceBuild.Spec spec, List<?> paths) {
        List<Map<String, Object>> artifacts = new ArrayList<>();
        List<String> libs = spec.libraries();
        int i = 0;
        for (Object p : paths) {
            String lib = spec.isFramework() && i < libs.size() ? libs.get(i) : "";
            artifacts.add(ReferenceBuild.artifactEntry(String.valueOf(p), lib));
            i++;
        }
        Map<String, Object> body = ReferenceBuild.resultEnvelope(
                "skipped", spec, artifacts, List.of(), List.of(), "", "");
        body.put("skipped", true);
        body.put("reason", "sidecar hash matches");
        return Response.ok(body);
    }

    private static String stringOrEmpty(Object raw) {
        return raw == null ? "" : String.valueOf(raw);
    }

    private String readManifest(String path) throws IOException {
        if (path != null && !path.isBlank()) {
            if (config.fileRoot() == null) {
                throw new IllegalArgumentException(
                        "build_manifest path requires GHIDRA_MCP_FILE_ROOT");
            }
            Path resolved = SecurityConfig.getInstance().resolveWithinFileRoot(path);
            if (resolved == null) {
                throw new IllegalArgumentException(
                        "manifest path is outside GHIDRA_MCP_FILE_ROOT");
            }
            if (!Files.isRegularFile(resolved)) {
                throw new IllegalArgumentException("manifest not found: " + resolved);
            }
            return Files.readString(resolved, StandardCharsets.UTF_8);
        }
        if (config.fileRoot() != null) {
            Path onVolume = config.fileRoot().resolve(DEFAULT_MANIFEST_ON_VOLUME);
            if (Files.isRegularFile(onVolume)) {
                return Files.readString(onVolume, StandardCharsets.UTF_8);
            }
        }
        try (InputStream in = ReferenceBuildService.class.getResourceAsStream(DEFAULT_MANIFEST_RESOURCE)) {
            if (in == null) {
                throw new IllegalArgumentException(
                        "no manifest path given and " + DEFAULT_MANIFEST_RESOURCE
                                + " is not on the classpath");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Boolean asBoolean(Object raw) {
        if (raw instanceof Boolean b) return b;
        if (raw == null) return null;
        return Boolean.parseBoolean(String.valueOf(raw));
    }

    private static boolean isPending(Map<String, Object> body) {
        if (body == null) return false;
        String status = body.get("status") == null ? "" : String.valueOf(body.get("status"));
        return "queued".equals(status) || "running".equals(status) || "started".equals(status);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> unwrap(Map<String, Object> body) {
        Object nested = body.get("result");
        if (nested instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                copy.put(String.valueOf(e.getKey()), e.getValue());
            }
            if (body.get("_http_status") != null && !copy.containsKey("_http_status")) {
                copy.put("_http_status", body.get("_http_status"));
            }
            return copy;
        }
        return body;
    }

    private static Response ticket(String jobId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "started");
        body.put("job_id", jobId);
        body.put("hint", "The compile continues in the builder. Poll "
                + "build_reference_status(job_id=\"" + jobId + "\") for the result.");
        return Response.ok(body);
    }

    private static boolean isStartedTicket(Response r) {
        if (r instanceof Response.Err) return false;
        Object parsed = JsonHelper.parseJson(r.toJson());
        if (!(parsed instanceof Map<?, ?> map)) return false;
        return "started".equals(String.valueOf(map.get("status"))) && map.get("job_id") != null;
    }

    private static boolean isSkipped(Response r) {
        Object parsed = JsonHelper.parseJson(r.toJson());
        return parsed instanceof Map<?, ?> map && Boolean.TRUE.equals(map.get("skipped"));
    }

    private static String jobIdOf(Response r) {
        Object parsed = JsonHelper.parseJson(r.toJson());
        if (parsed instanceof Map<?, ?> map && map.get("job_id") != null) {
            return String.valueOf(map.get("job_id"));
        }
        return "";
    }

    private URI firstBuilderUrl() {
        if (config.toolchainUrls() == null || config.toolchainUrls().isEmpty()) return null;
        URI shared = config.sharedBuilderUrl();
        if (shared != null) return shared;
        return config.toolchainUrls().values().iterator().next();
    }

    private ReferenceBuild.Inventory requireInventory() throws IOException {
        URI url = firstBuilderUrl();
        if (url == null) {
            throw new IOException("no builder URL configured. Start the ghidra-builder service "
                    + "on the compose network.");
        }
        Map<String, Object> body = client.health(url);
        Object http = body.get("_http_status");
        if (http instanceof Number n && n.intValue() >= 400) {
            throw new IOException(String.valueOf(body.getOrDefault("error",
                    "builder /health HTTP " + n)));
        }
        ReferenceBuild.Inventory inv = ReferenceBuild.Inventory.fromHealth(body);
        if (inv.identities().isEmpty()) {
            throw new IOException("builder /health listed no identities");
        }
        return inv;
    }

    private record Pending(ReferenceBuild.Spec spec, String jobId, int index) {}
}
