package com.xebyte.core;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
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
                + "build_reference compiles pinned source into the shared volume for ingest.")
public class ReferenceBuildService {

    private static final String DEFAULT_MANIFEST_RESOURCE = "/reference/references.yaml";
    private static final String DEFAULT_MANIFEST_ON_VOLUME = "references.yaml";

    private final ReferenceBuild.BuilderConfig config;
    private final BuilderClient client;

    public ReferenceBuildService() {
        this(ReferenceBuild.fromEnv(), new BuilderClient.Http(
                System.getenv("GHIDRA_MCP_AUTH_TOKEN") == null
                        ? "" : System.getenv("GHIDRA_MCP_AUTH_TOKEN")));
    }

    public ReferenceBuildService(ReferenceBuild.BuilderConfig config, BuilderClient client) {
        this.config = config;
        this.client = client;
    }

    @McpTool(path = "/build_reference", method = "POST",
            description = "Clone a git tag or commit in the builder container and compile "
                    + "it to GHIDRA_MCP_FILE_ROOT/uploads. Never pass object bytes through "
                    + "this tool; the shared volume is the handoff. ref must be a tag or SHA "
                    + "(bare branch names are refused). strip_debug keeps .symtab. dry_run "
                    + "returns the gcc command line and output path without cloning or compiling. "
                    + "Output name: <name>-<ref>-<toolchain>-<opt>.o.",
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
            @Param(value = "toolchain", source = ParamSource.BODY, defaultValue = "gcc13",
                    description = "Selects the builder image/container (gcc10, gcc12, gcc13)")
                    String toolchain,
            @Param(value = "arch_flags", source = ParamSource.BODY,
                    defaultValue = "-mcpu=cortex-m0plus -mthumb",
                    description = "Architecture flags passed to gcc") String archFlags,
            @Param(value = "opt", source = ParamSource.BODY, defaultValue = "-Os",
                    description = "Optimisation level, e.g. -Os, -O2, -O3") String opt,
            @Param(value = "defines", source = ParamSource.BODY, defaultValue = "",
                    description = "Preprocessor defines, JSON array e.g. [\"LFS_NO_MALLOC\"]")
                    Object defines,
            @Param(value = "extra_flags", source = ParamSource.BODY, defaultValue = "",
                    description = "Extra gcc flags, JSON array") Object extraFlags,
            @Param(value = "strip_debug", source = ParamSource.BODY, defaultValue = "true",
                    description = "strip --strip-debug (keeps .symtab). Default true.")
                    boolean stripDebug,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                    description = "Override filename. Default <name>-<ref>-<toolchain>-<opt>.o")
                    String outputName,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                    description = "Return the command line and output path; do not clone or compile")
                    boolean dryRun) {
        try {
            ReferenceBuild.Spec spec = ReferenceBuild.parse(
                    name, repo, ref, sources, toolchain, archFlags, opt, defines, extraFlags,
                    stripDebug, outputName, config.knownToolchains());
            return runSpec(spec, dryRun);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    @McpTool(path = "/build_manifest", method = "POST",
            description = "Expand docker/references.yaml (or a path under FILE_ROOT) into "
                    + "build_reference jobs and run them. A matrix of toolchain × opt is how "
                    + "the corpus covers compiler drift. dry_run returns every command line "
                    + "without cloning or compiling.",
            category = "bsim")
    public Response buildManifest(
            @Param(value = "path", source = ParamSource.BODY, defaultValue = "",
                    description = "Manifest path under FILE_ROOT. Empty = /data/references.yaml "
                            + "then the baked-in docker/references.yaml.") String path,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                    description = "Resolve every job's command line; do not clone or compile")
                    boolean dryRun) {
        try {
            String yaml = readManifest(path);
            List<ReferenceBuild.Spec> jobs = ReferenceManifest.parse(yaml, config.knownToolchains());
            List<Object> results = new ArrayList<>();
            int failed = 0;
            for (ReferenceBuild.Spec spec : jobs) {
                Response r = runSpec(spec, dryRun);
                if (r instanceof Response.Err) failed++;
                results.add(JsonHelper.parseJson(r.toJson()));
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", failed == 0 ? "success" : "partial");
            body.put("dry_run", dryRun);
            body.put("count", jobs.size());
            body.put("failed", failed);
            body.put("results", results);
            return Response.ok(body);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    Response runSpec(ReferenceBuild.Spec spec, boolean dryRun) {
        if (config.fileRoot() == null) {
            return Response.err("build_reference requires GHIDRA_MCP_FILE_ROOT so the object "
                    + "lands on the shared volume import_file can see");
        }
        Path output = spec.outputPath(config.fileRoot());
        List<List<String>> command = spec.commandLines(output);
        if (dryRun) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "would_execute");
            body.put("dry_run", true);
            body.put("path", output.toString());
            body.put("command", command);
            body.put("toolchain", spec.toolchain());
            body.put("ref", spec.ref());
            body.put("name", spec.name());
            return Response.ok(body);
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
            built = client.build(spec.toolchain(), url, request, config.timeout());
        } catch (IOException e) {
            return Response.err(e.getMessage(), "builder_unreachable");
        }

        if (built.containsKey("ok") && Boolean.FALSE.equals(asBoolean(built.get("ok")))) {
            String message = String.valueOf(built.getOrDefault("error", "build failed"));
            String status = built.get("status") == null ? "build_failed" : String.valueOf(built.get("status"));
            if (built.get("stderr") != null) {
                message = message + (message.contains(String.valueOf(built.get("stderr")))
                        ? "" : "\n" + built.get("stderr"));
            }
            return Response.err(message, status);
        }
        Object http = built.get("_http_status");
        if (http instanceof Number n && n.intValue() >= 400) {
            return Response.err(String.valueOf(built.getOrDefault("error", "builder HTTP " + n)),
                    "builder_http_" + n.intValue());
        }

        Object countRaw = built.get("function_count");
        int count = JsonHelper.getInt(countRaw, -1);
        if (countRaw == null || count == 0) {
            return Response.err(
                    count == 0
                            ? "refusing to write: 0 defined functions (everything was optimised out "
                            + "or the wrong file was compiled)"
                            : "refusing to write: builder omitted function_count",
                    count == 0 ? "zero_functions" : "missing_function_count");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("path", built.getOrDefault("path", output.toString()));
        body.put("bytes", built.get("bytes"));
        body.put("sha256", built.get("sha256"));
        body.put("function_count", built.get("function_count"));
        body.put("defined_functions", built.get("defined_functions"));
        body.put("commit_sha", built.get("commit_sha"));
        body.put("command", built.getOrDefault("command", command));
        body.put("cc_version", built.get("cc_version"));
        body.put("toolchain", spec.toolchain());
        body.put("name", spec.name());
        body.put("ref", spec.ref());
        return Response.ok(body);
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
}
