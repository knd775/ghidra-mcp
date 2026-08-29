package com.xebyte.core;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * MCP wrappers around Ghidra's {@code bsim} CLI.
 *
 * <p>Create / ingest / list shell out to {@code support/bsim}. Query has no CLI
 * command, so it runs {@code BSim_McpQuery.java} in a helper {@code analyzeHeadless}
 * JVM (where the BSim module actually loads) and reads JSON back. Apply uses
 * those scores and renames in the currently-open program.
 *
 * <p>Every CLI run spawns a fresh JVM, so even "fast" operations take tens of
 * seconds and ingest/query take minutes — longer than the response budget of
 * the HTTP hops in front of this server (an MCP gateway or Cloudflare tunnel
 * gives up around 60-100s and fabricates a blank transport error). Each tool
 * therefore validates its input synchronously, submits the CLI-heavy body to
 * {@link BSimJobs}, and waits inline up to {@code wait_seconds}: fast calls
 * return their normal response, slow ones return a {@code job_id} for
 * {@code bsim_job_status}.
 *
 * <p>A corpus you cannot inspect is one you stop trusting, which is why
 * {@code bsim_list_corpus} exists. The tools do not invent a corpus: compile
 * the same library at several optimisation levels and compiler versions and
 * ingest <em>with symbols</em>.
 */
@McpToolGroup(value = "bsim",
        description = "Cross-build function matching via Ghidra BSim (CLI wrapper). "
                + "Returns similarity and confidence separately; never a bare ranked list. "
                + "CLI-heavy calls return a job_id when they outlive wait_seconds; poll "
                + "bsim_job_status for the result.")
public class BSimService {

    static final String QUERY_SCRIPT_RESOURCE = "/bsim/BSim_McpQuery.java";
    static final String QUERY_SCRIPT_NAME = "BSim_McpQuery.java";
    static final double DEFAULT_SIMILARITY = 0.7;
    static final String STRIPPED_WARNING =
            "This program has few or no user-defined function names. "
                    + "A stripped binary adds signature noise and yields no names to propagate. "
                    + "Ingest a build with symbols.";

    static final String WAIT_SECONDS_DESCRIPTION =
            "Seconds to wait inline before returning a job ticket (0-"
                    + BSimJobs.MAX_WAIT_SECONDS + "). BSim CLI runs spawn a separate JVM "
                    + "and routinely outlive HTTP gateway budgets; when the wait expires "
                    + "the operation continues server-side and bsim_job_status(job_id) "
                    + "returns its result.";

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final BSimCli cli;
    private final BSimJobs jobs;

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, new BSimCli());
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli) {
        this(programProvider, threadingStrategy, cli, new BSimJobs());
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli, BSimJobs jobs) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.cli = cli;
        this.jobs = jobs;
    }

    // ========================================================================
    // bsim_create_db
    // ========================================================================

    @McpTool(path = "/bsim_create_db", method = "POST",
            description = "Create a BSim database via `bsim createdatabase`. Default template "
                    + "medium_32 (32-bit ARM firmware). Call-graph data is recorded unless "
                    + "callgraph=false. H2 file: URLs need a writable parent directory; "
                    + "PostgreSQL when more than one writer is needed. The database is empty "
                    + "until bsim_ingest; a query against an empty corpus returns nothing useful. "
                    + "Returns a job_id instead of a result when the CLI outlives wait_seconds.",
            category = "bsim")
    public Response createDb(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim URL: file:/path/db, postgresql://..., elastic://..., https://...")
                    String dbUrl,
            @Param(value = "config_template", source = ParamSource.BODY, defaultValue = "medium_32",
                    description = "large_32 | medium_32 | medium_64 | medium_cpool | medium_nosize")
                    String configTemplate,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                    description = "Display name stored in the database metadata") String name,
            @Param(value = "description", source = ParamSource.BODY, defaultValue = "",
                    description = "Database description") String description,
            @Param(value = "callgraph", source = ParamSource.BODY, defaultValue = "true",
                    description = "Record call-graph data (do not pass --nocallgraph). "
                            + "Call-graph topology materially improves match quality.")
                    boolean callgraph,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            String template = BSimUrls.requireConfigTemplate(
                    (configTemplate == null || configTemplate.isBlank()) ? "medium_32" : configTemplate);
            List<String> args = new ArrayList<>();
            args.add("createdatabase");
            args.add(url);
            args.add(template);
            if (name != null && !name.isBlank()) {
                args.add("--name");
                args.add(BSimUrls.requireToken("name", name));
            }
            if (description != null && !description.isBlank()) {
                args.add("--description");
                args.add(BSimUrls.requireToken("description", description));
            }
            if (!callgraph) args.add("--nocallgraph");

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("config_template", template);
            BSimJobs.Job job = jobs.submit("bsim_create_db", request, () -> {
                ensureFileParent(url);
                BSimCli.Result r = runBsim(BSimCli.DEFAULT_TIMEOUT, args);
                if (!r.ok()) {
                    return cliError("createdatabase failed", r);
                }
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "success");
                body.put("db_url", url);
                body.put("config_template", template);
                body.put("callgraph", callgraph);
                body.put("executables", 0);
                return Response.ok(body);
            });
            return jobs.awaitOrTicket(job, waitSeconds);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    // ========================================================================
    // bsim_ingest
    // ========================================================================

    @McpTool(path = "/bsim_ingest", method = "POST",
            description = "Generate BSim signatures from a ghidraURL (or an open program) and "
                    + "commit them with `bsim generatesigs --bsim --commit`. Refuses a source with "
                    + "no functions, and a pointer-size mismatch against the existing corpus "
                    + "(ingesting 64-bit into a medium_32 database silently degrades results). "
                    + "Warns when the source has few user-defined names. Ingest with symbols. "
                    + "Ingest takes minutes: expect a job_id, then poll bsim_job_status.",
            category = "bsim")
    public Response ingest(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim database URL") String dbUrl,
            @Param(value = "source", source = ParamSource.BODY,
                    description = "ghidraURL, repository path, or open program name") String source,
            @Param(value = "xml_dir", source = ParamSource.BODY, defaultValue = "",
                    description = "Directory for signature XML. Default: a temp directory.")
                    String xmlDir,
            @Param(value = "commit", source = ParamSource.BODY, defaultValue = "true",
                    description = "Pass --commit so signatures land in the database") boolean commit,
            @Param(value = "overwrite", source = ParamSource.BODY, defaultValue = "false",
                    description = "Pass --overwrite if signature XML already exists") boolean overwrite,
            @Param(value = "program", defaultValue = "", selector = false,
                    description = "Optional open program used only for prechecks when source is "
                            + "not a ghidraURL. Not a program selector — source is the ingest target.")
                    String programName,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            if (source == null || source.isBlank()) {
                return Response.err("source is required (ghidraURL, repo path, or open program name)");
            }
            String credErr = BSimUrls.missingServerCredential(source);
            if (credErr != null) return Response.err(credErr);
            Program program = resolveProgramIfOpen(source, programName);
            // Fail unresolvable sources synchronously and specifically —
            // classify throws IllegalArgumentException with the remedy. The
            // ghidraURL it may resolve is rechecked for credentials here too
            // (repo paths become ghidra:// on this hop).
            String directUrl = classifySource(source, program);
            if (directUrl != null) {
                credErr = BSimUrls.missingServerCredential(directUrl);
                if (credErr != null) return Response.err(credErr);
            }

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("source", source);
            request.put("commit", commit);
            BSimJobs.Job job = jobs.submit("bsim_ingest", request,
                    () -> runIngest(url, source, program, xmlDir, commit, overwrite));
            return jobs.awaitOrTicket(job, waitSeconds);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    /** The CLI-heavy body of {@code bsim_ingest}; runs on the job worker. */
    private Response runIngest(String url, String source, Program program,
                               String xmlDir, boolean commit, boolean overwrite) throws Exception {
        try {
            List<String> warnings = new ArrayList<>();
            if (program != null) {
                Response reject = precheckProgram(program, url, warnings);
                if (reject != null) return reject;
            }

            // A caller-supplied xml_dir is theirs to keep; a temp one is ours
            // to remove — its contents are already in the database after
            // --commit, and its path is never returned to the caller.
            boolean tempXml = (xmlDir == null || xmlDir.isBlank());
            Path xmlPath = tempXml ? Files.createTempDirectory("bsim-xml-") : Path.of(xmlDir);
            Files.createDirectories(xmlPath);

            String ghidraUrl;
            Path tempProj = null;
            Path tempGzfDir = null;
            try {
                ResolvedSource resolved = resolveSource(source, program, xmlPath);
                ghidraUrl = resolved.ghidraUrl;
                tempProj = resolved.tempProject;
                tempGzfDir = resolved.tempGzfDir;
                // Repo paths become ghidra:// after resolve; check the resolved
                // URL too, not just the original source string.
                String credErr = BSimUrls.missingServerCredential(ghidraUrl);
                if (credErr != null) return Response.err(credErr);

                List<String> args = new ArrayList<>();
                args.add("generatesigs");
                args.add(ghidraUrl);
                args.add(xmlPath.toAbsolutePath().toString());
                args.add("--bsim");
                args.add(url);
                if (commit) args.add("--commit");
                if (overwrite) args.add("--overwrite");
                // A ghidra:// server URL is read by a STOCK Ghidra JVM that
                // never loads this extension's env-reading authenticator, so
                // pass the username as an argument and feed the password on
                // stdin, where HeadlessClientAuthenticator's no-console
                // fallback reads it.
                String stdinData = null;
                if (BSimUrls.isServerGhidraUrl(ghidraUrl)) {
                    String user = BSimCli.resolvedServerUser();
                    if (user != null) {
                        args.add("--user");
                        args.add(user);
                    }
                    String password = BSimCli.resolvedServerPassword();
                    if (password != null) {
                        stdinData = password + "\n";
                    }
                }
                BSimCli.Result r = runBsim(BSimCli.INGEST_TIMEOUT, args, stdinData);
                if (!r.ok()) {
                    return cliError("generatesigs failed", r);
                }

                BSimCli.Result countR = runBsim(BSimCli.DEFAULT_TIMEOUT, List.of("getexecount", url));
                Integer exeCount = BSimCliParser.parseExeCount(countR.output);

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "success");
                body.put("db_url", url);
                body.put("source", ghidraUrl);
                body.put("commit", commit);
                if (exeCount != null) body.put("executables", exeCount);
                if (!warnings.isEmpty()) body.put("warnings", warnings);
                return Response.ok(body);
            } finally {
                cleanupTemp(tempProj, tempGzfDir);
                if (tempXml) deleteRecursively(xmlPath);
            }
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // bsim_query
    // ========================================================================

    @McpTool(path = "/bsim_query", method = "POST",
            description = "Query one function or the whole open program against a BSim database. "
                    + "Each match has separate numeric similarity and confidence fields, plus the "
                    + "source executable name and architecture. The result is flagged ambiguous "
                    + "when the top two differently-named hits sit within 0.05 similarity. "
                    + "Never a bare ranked list. Short generic functions (accessors, thunks) "
                    + "often have high similarity and low confidence — that split is the point. "
                    + "Queries run a helper analyzeHeadless JVM and can take minutes: expect a "
                    + "job_id, then poll bsim_job_status.",
            category = "bsim")
    public Response query(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim database URL") String dbUrl,
            @Param(value = "function", source = ParamSource.BODY, defaultValue = "",
                    description = "Function name or address. Omit to query every function.")
                    String function,
            @Param(value = "similarity_threshold", source = ParamSource.BODY, defaultValue = "0.7",
                    description = "Minimum BSim similarity (0-1)") double similarityThreshold,
            @Param(value = "confidence_threshold", source = ParamSource.BODY, defaultValue = "0.0",
                    description = "Minimum BSim confidence/significance. 0.0 returns everything "
                            + "the index considers; raise it to hide generic hits.")
                    double confidenceThreshold,
            @Param(value = "max_matches", source = ParamSource.BODY, defaultValue = "10",
                    description = "Maximum matches per function") int maxMatches,
            @Param(value = "program", defaultValue = "") String programName,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("program", program.getName());
            if (function != null && !function.isBlank()) request.put("function", function);
            BSimJobs.Job job = jobs.submit("bsim_query", request,
                    () -> runQuery(url, program, function, similarityThreshold,
                            confidenceThreshold, maxMatches));
            return jobs.awaitOrTicket(job, waitSeconds);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    // ========================================================================
    // bsim_apply_matches
    // ========================================================================

    @McpTool(path = "/bsim_apply_matches", method = "POST",
            description = "Bulk-rename functions from BSim matches above a caller-chosen confidence "
                    + "floor. min_confidence has no default — there is no universally safe value. "
                    + "dry_run defaults to true and does not write. skip_named defaults to true "
                    + "(never overwrite an analyst name). Ambiguous matches are never applied, "
                    + "whatever the scores. Applied names are the BSim hit names as-is (C linkage, "
                    + "not PascalCase). Runs a full-program BSim query first, which takes minutes: "
                    + "expect a job_id, then poll bsim_job_status.",
            category = "bsim")
    public Response applyMatches(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim database URL") String dbUrl,
            @Param(value = "min_confidence", source = ParamSource.BODY,
                    description = "Required. Minimum BSim confidence. No default on purpose.")
                    Double minConfidence,
            @Param(value = "min_similarity", source = ParamSource.BODY, defaultValue = "0.8",
                    description = "Minimum similarity (default 0.8)") double minSimilarity,
            @Param(value = "skip_named", source = ParamSource.BODY, defaultValue = "true",
                    description = "Skip functions that already have a user-defined name")
                    boolean skipNamed,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "true",
                    description = "Preview without renaming. Default true. Honored in this method; "
                            + "a true dry_run does not call setName.")
                    boolean dryRun,
            @Param(value = "similarity_threshold", source = ParamSource.BODY, defaultValue = "0.7",
                    description = "Query-time similarity floor (before apply filters)")
                    double querySimilarity,
            @Param(value = "max_matches", source = ParamSource.BODY, defaultValue = "10",
                    description = "Matches fetched per function") int maxMatches,
            @Param(value = "program", defaultValue = "") String programName,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        if (minConfidence == null) {
            return Response.err(
                    "min_confidence is required. There is no universally safe default; "
                            + "choose a floor from the confidence values bsim_query returned on "
                            + "distinctive functions in this corpus.");
        }
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("program", program.getName());
            request.put("dry_run", dryRun);
            request.put("min_confidence", minConfidence);
            BSimJobs.Job job = jobs.submit("bsim_apply_matches", request,
                    () -> runApplyMatches(url, program, minConfidence, minSimilarity,
                            skipNamed, dryRun, querySimilarity, maxMatches));
            return jobs.awaitOrTicket(job, waitSeconds);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    /** The query + decide + rename body of {@code bsim_apply_matches}; runs on the job worker. */
    private Response runApplyMatches(String url, Program program, Double minConfidence,
                                     double minSimilarity, boolean skipNamed, boolean dryRun,
                                     double querySimilarity, int maxMatches) throws Exception {
        Response queried = runQuery(url, program, "", querySimilarity, 0.0, maxMatches);
        if (queried instanceof Response.Err) return queried;
        Map<String, Object> payload = JsonHelper.parseJson(queried.toJson());
        List<BSimMatches.FunctionResult> results =
                BSimMatches.parseQueryPayload(payload, program.getExecutableMD5());

        List<Map<String, Object>> renamed = new ArrayList<>();
        List<Map<String, Object>> wouldRename = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();

        for (BSimMatches.FunctionResult fr : results) {
            Function func = resolveApplyTarget(program, fr);
            String currentName = func != null ? func.getName() : fr.function;
            BSimMatches.ApplyAction action = BSimMatches.decide(
                    fr, currentName, skipNamed, minSimilarity, minConfidence);
            if (action != BSimMatches.ApplyAction.APPLY) {
                Map<String, Object> skip = new LinkedHashMap<>();
                skip.put("function", fr.function);
                if (fr.address != null) skip.put("address", fr.address);
                skip.put("reason", BSimMatches.reason(action));
                BSimMatches.Hit best = fr.best();
                if (best != null) {
                    skip.put("best_name", best.name);
                    skip.put("similarity", best.similarity);
                    skip.put("confidence", best.confidence);
                }
                skipped.add(skip);
                continue;
            }
            BSimMatches.Hit best = fr.best();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("function", fr.function);
            if (fr.address != null) row.put("address", fr.address);
            row.put("new_name", best.name);
            row.put("similarity", best.similarity);
            row.put("confidence", best.confidence);
            row.put("executable", best.executable);
            if (dryRun) {
                wouldRename.add(row);
                continue;
            }
            if (func == null) {
                row.put("reason", "function_not_found");
                skipped.add(row);
                continue;
            }
            try {
                final Function target = func;
                final String newName = best.name;
                threadingStrategy.executeWrite(program, "BSim apply " + newName, () -> {
                    target.setName(newName, SourceType.USER_DEFINED);
                    return null;
                });
                renamed.add(row);
            } catch (Exception e) {
                row.put("reason", "rename_failed");
                row.put("error", e.getMessage());
                skipped.add(row);
            }
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("dry_run", dryRun);
        body.put("min_confidence", minConfidence);
        body.put("min_similarity", minSimilarity);
        body.put("skip_named", skipNamed);
        body.put("renamed", renamed);
        body.put("would_rename", wouldRename);
        body.put("skipped", skipped);
        return Response.ok(body);
    }

    // ========================================================================
    // bsim_list_corpus
    // ========================================================================

    @McpTool(path = "/bsim_list_corpus", method = "POST",
            description = "List executables in a BSim database (`bsim listexes` / `getexecount`). "
                    + "Needed to answer what is actually in the corpus without shelling out. "
                    + "Returns a job_id instead of a result when the CLI outlives wait_seconds.",
            category = "bsim")
    public Response listCorpus(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim database URL") String dbUrl,
            @Param(value = "arch", source = ParamSource.BODY, defaultValue = "",
                    description = "Filter by architecture (passed as --arch)") String arch,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                    description = "Filter by executable name (passed as --name)") String name,
            @Param(value = "limit", source = ParamSource.BODY, defaultValue = "100",
                    description = "Maximum executables to list (bsim default is 20)") int limit,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            List<String> args = new ArrayList<>();
            args.add("listexes");
            args.add(url);
            if (arch != null && !arch.isBlank()) {
                args.add("--arch");
                args.add(BSimUrls.requireToken("arch", arch));
            }
            if (name != null && !name.isBlank()) {
                args.add("--name");
                args.add(BSimUrls.requireToken("name", name));
            }
            args.add("--limit");
            args.add(String.valueOf(Math.max(1, limit)));

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            BSimJobs.Job job = jobs.submit("bsim_list_corpus", request, () -> {
                BSimCli.Result r = runBsim(BSimCli.DEFAULT_TIMEOUT, args);
                if (!r.ok()) return cliError("listexes failed", r);

                List<BSimCliParser.ExeRecord> exes = BSimCliParser.parseExeList(r.output);
                Integer parsed = BSimCliParser.parseExeCount(r.output);
                int count = parsed != null ? parsed : exes.size();

                BSimCli.Result countR = runBsim(BSimCli.DEFAULT_TIMEOUT, List.of("getexecount", url));
                Integer total = BSimCliParser.parseExeCount(countR.output);

                List<Map<String, Object>> exeMaps = new ArrayList<>();
                for (BSimCliParser.ExeRecord e : exes) exeMaps.add(e.toMap());

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "success");
                body.put("db_url", url);
                body.put("count", total != null ? total : count);
                body.put("listed", exeMaps.size());
                body.put("executables", exeMaps);
                return Response.ok(body);
            });
            return jobs.awaitOrTicket(job, waitSeconds);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    // ========================================================================
    // bsim_job_status
    // ========================================================================

    @McpTool(path = "/bsim_job_status", method = "GET",
            description = "Status and result of a background BSim operation. BSim tools return "
                    + "{status: \"started\", job_id} when a CLI run outlives wait_seconds; poll "
                    + "this with that job_id until state is \"done\", then read the embedded "
                    + "result (identical to what the tool would have returned inline). Blank "
                    + "job_id lists every retained job.",
            category = "bsim")
    public Response jobStatus(
            @Param(value = "job_id", defaultValue = "",
                    description = "Job id from a BSim tool's started response. Blank lists all jobs.")
                    String jobId) {
        return jobs.status(jobId);
    }

    // ========================================================================
    // Internals
    // ========================================================================

    Response runQuery(String dbUrl, Program program, String function,
                      double similarity, double confidence, int maxMatches) throws Exception {
        // saveToPackedFile refuses to overwrite, so the gzf must be a path
        // nothing has created yet — File.createTempFile pre-creates a zero-byte
        // file and made every query fail with "<path> already exists". One
        // owned directory also gives every exit path a single recursive delete.
        Path workDir = Files.createTempDirectory("bsim-query-");
        try {
            File gzf = workDir.resolve("program.gzf").toFile();
            Path projDir = Files.createDirectory(workDir.resolve("proj"));
            Path scriptDir = workDir.resolve("script");
            Path outJson = workDir.resolve("query-out.json");
            program.saveToPackedFile(gzf, TaskMonitor.DUMMY);
            extractQueryScript(scriptDir);
            String funcArg = (function == null || function.isBlank()) ? "-" : function.trim();
            List<String> args = new ArrayList<>();
            args.add(projDir.toAbsolutePath().toString());
            args.add("BSimQuery");
            args.add("-import");
            args.add(gzf.getAbsolutePath());
            args.add("-overwrite");
            args.add("-noanalysis");
            args.add("-deleteProject");
            args.add("-scriptPath");
            args.add(scriptDir.toAbsolutePath().toString());
            args.add("-postScript");
            args.add(QUERY_SCRIPT_NAME);
            args.add(dbUrl);
            args.add(outJson.toAbsolutePath().toString());
            args.add(funcArg);
            args.add(Double.toString(similarity));
            args.add(Double.toString(confidence));
            args.add(Integer.toString(Math.max(1, maxMatches)));

            BSimCli.Result r;
            synchronized (BSimCli.LOCK) {
                r = cli.analyzeHeadless(BSimCli.QUERY_TIMEOUT, args);
            }
            if (!Files.isRegularFile(outJson) || Files.size(outJson) == 0) {
                return cliError("BSim query produced no JSON (analyzeHeadless exit "
                        + r.exitCode + ")", r);
            }
            String json = Files.readString(outJson, StandardCharsets.UTF_8);
            Map<String, Object> payload = JsonHelper.parseJson(json);
            if (payload.containsKey("error")) {
                return Response.err(String.valueOf(payload.get("error")));
            }
            String md5 = program.getExecutableMD5();
            List<BSimMatches.FunctionResult> results = BSimMatches.parseQueryPayload(payload, md5);
            if (function != null && !function.isBlank() && results.size() == 1) {
                return Response.ok(results.get(0).toMap());
            }
            List<Map<String, Object>> rows = new ArrayList<>();
            for (BSimMatches.FunctionResult fr : results) rows.add(fr.toMap());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("program", program.getName());
            body.put("results", rows);
            body.put("count", rows.size());
            return Response.ok(body);
        } finally {
            deleteRecursively(workDir);
        }
    }

    private Function resolveApplyTarget(Program program, BSimMatches.FunctionResult fr) {
        if (fr.address != null && !fr.address.isEmpty()) {
            Function byAddr = ServiceUtils.resolveFunction(program, fr.address);
            if (byAddr != null) return byAddr;
        }
        return ServiceUtils.resolveFunction(program, fr.function);
    }

    private Response precheckProgram(Program program, String dbUrl, List<String> warnings)
            throws Exception {
        FunctionManager fm = program.getFunctionManager();
        int total = fm.getFunctionCount();
        if (total == 0) {
            return Response.err("source has no functions; refusing to ingest. "
                    + "Analyze the program first.");
        }
        int named = 0;
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk() && !ServiceUtils.isAutoGeneratedName(f.getName())) named++;
        }
        if (named == 0 || named * 20 < total) {
            warnings.add(STRIPPED_WARNING);
        }
        int srcBits = program.getLanguage().getLanguageDescription().getSize();
        BSimCli.Result listR = runBsim(BSimCli.DEFAULT_TIMEOUT,
                List.of("listexes", dbUrl, "--limit", "50"));
        List<BSimCliParser.ExeRecord> existing = BSimCliParser.parseExeList(listR.output);
        List<String> archs = new ArrayList<>();
        for (BSimCliParser.ExeRecord e : existing) archs.add(e.arch);
        Set<Integer> sizes = BSimUrls.uniqueArchSizes(archs);
        if (sizes.size() == 1 && !sizes.contains(srcBits) && srcBits > 0) {
            int corpusBits = sizes.iterator().next();
            return Response.err(
                    "source language is " + srcBits + "-bit ("
                            + program.getLanguageID() + ") but the corpus is "
                            + corpusBits + "-bit. Ingesting across pointer sizes into a "
                            + "sized template (medium_32 / medium_64) silently degrades "
                            + "results. Use medium_nosize if you meant to mix sizes, or "
                            + "create a matching database.");
        }
        if (existing.isEmpty() && srcBits == 64) {
            warnings.add("Corpus is empty and the source is 64-bit. If this database was "
                    + "created with medium_32, ingest will silently degrade matches. "
                    + "Use medium_64 or medium_nosize.");
        }
        return null;
    }

    private Program resolveProgramIfOpen(String source, String programName) {
        if (programName != null && !programName.isBlank()) {
            Program p = programProvider.getProgram(programName);
            if (p != null) return p;
        }
        // A ghidraURL / repo path is never "the currently open program".
        // Falling back to current for any non-URL string ingested the open
        // program when the caller passed /repo/folder/name.
        if (BSimUrls.looksLikeGhidraUrl(source) || (source != null && source.startsWith("/"))) {
            return null;
        }
        Program byName = programProvider.getProgram(source);
        if (byName != null) return byName;
        Program current = programProvider.getCurrentProgram();
        if (current != null && source.equals(current.getName())) return current;
        return null;
    }

    /**
     * The synchronous, side-effect-free half of {@link #resolveSource}: return
     * the ghidraURL this source resolves to when that is knowable without
     * touching the filesystem or spawning anything, {@code null} when the
     * source is an open program that needs staging inside the job, and throw
     * {@link IllegalArgumentException} (with the remedy) when the source cannot
     * resolve at all — so an invalid source is a specific, immediate error
     * rather than a queued job that fails later.
     */
    private String classifySource(String source, Program program) {
        if (BSimUrls.looksLikeGhidraUrl(source)) {
            return BSimUrls.requireGhidraUrl(source);
        }
        if (program != null) {
            return null; // Staged (or shared-URL-resolved) inside the job.
        }
        if (source != null && source.startsWith("/")) {
            String host = System.getenv("GHIDRA_SERVER_HOST");
            String port = System.getenv("GHIDRA_SERVER_PORT");
            if (host != null && !host.isBlank()) {
                return "ghidra://" + host
                        + (port != null && !port.isBlank() ? ":" + port : "")
                        + source;
            }
            throw new IllegalArgumentException(
                    "Cannot resolve repository path '" + source + "' to a ghidraURL: "
                            + "GHIDRA_SERVER_HOST is not set. Pass a full "
                            + "ghidra://host/repo/path, or open the program.");
        }
        throw new IllegalArgumentException(
                "Cannot resolve source '" + source + "' to a ghidraURL. Pass "
                        + "ghidra://host/repo/path, a repository path starting with /, "
                        + "or the name of an open program.");
    }

    private ResolvedSource resolveSource(String source, Program program, Path workDir)
            throws Exception {
        if (program == null) {
            // classifySource already vetted these forms synchronously; it
            // throws the same specific errors for anything unresolvable.
            return new ResolvedSource(classifySource(source, program), null, null);
        }
        java.net.URL shared = program.getDomainFile().getSharedProjectURL(null);
        if (shared != null) {
            return new ResolvedSource(shared.toExternalForm(), null, null);
        }
        // Open local programs lock their project; export a GZF into a temp project
        // that `bsim generatesigs` can read. saveToPackedFile refuses to
        // overwrite, so the gzf is a fresh path inside a directory we own —
        // never pre-created via File.createTempFile.
        Path gzfDir = Files.createTempDirectory(workDir, "ingest-gzf-");
        Path proj = null;
        try {
            File gzf = gzfDir.resolve("program.gzf").toFile();
            program.saveToPackedFile(gzf, TaskMonitor.DUMMY);
            proj = Files.createTempDirectory(workDir, "ingest-proj-");
            List<String> args = new ArrayList<>();
            args.add(proj.toAbsolutePath().toString());
            args.add("BSimIngest");
            args.add("-import");
            args.add(gzf.getAbsolutePath());
            args.add("-overwrite");
            args.add("-noanalysis");
            BSimCli.Result r;
            synchronized (BSimCli.LOCK) {
                r = cli.analyzeHeadless(BSimCli.INGEST_TIMEOUT, args);
            }
            if (!r.ok()) {
                throw new IOException(
                        "Failed to stage source into a temp project: " + tail(r.output, 1500));
            }
            String ghidraUrl = "ghidra:" + proj.toAbsolutePath() + "/BSimIngest";
            return new ResolvedSource(ghidraUrl, proj, gzfDir);
        } catch (Exception e) {
            deleteRecursively(gzfDir);
            deleteRecursively(proj);
            throw e;
        }
    }

    private static final class ResolvedSource {
        final String ghidraUrl;
        final Path tempProject;
        final Path tempGzfDir;

        ResolvedSource(String ghidraUrl, Path tempProject, Path tempGzfDir) {
            this.ghidraUrl = ghidraUrl;
            this.tempProject = tempProject;
            this.tempGzfDir = tempGzfDir;
        }
    }

    private BSimCli.Result runBsim(Duration timeout, List<String> args) throws Exception {
        return runBsim(timeout, args, null);
    }

    private BSimCli.Result runBsim(Duration timeout, List<String> args, String stdinData)
            throws Exception {
        synchronized (BSimCli.LOCK) {
            return cli.bsim(timeout, args, stdinData);
        }
    }

    private Response cliError(String prefix, BSimCli.Result r) {
        String extracted = BSimCliParser.extractError(r.output);
        String detail = extracted != null ? extracted : tail(r.output, 1200);
        String msg = prefix + " (exit " + r.exitCode + ")";
        if (detail != null && !detail.isBlank()) msg = msg + ": " + detail;
        return Response.err(msg);
    }

    private static void ensureFileParent(String dbUrl) throws IOException {
        if (!dbUrl.toLowerCase().startsWith("file:")) return;
        File path = BSimUrls.fileUrlToPath(dbUrl);
        File parent = path.getParentFile();
        if (parent != null) Files.createDirectories(parent.toPath());
    }

    static void extractQueryScript(Path scriptDir) throws IOException {
        Files.createDirectories(scriptDir);
        Path dest = scriptDir.resolve(QUERY_SCRIPT_NAME);
        try (InputStream in = BSimService.class.getResourceAsStream(QUERY_SCRIPT_RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing classpath resource " + QUERY_SCRIPT_RESOURCE);
            }
            Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void cleanupTemp(Path proj, Path gzfDir) {
        deleteRecursively(gzfDir);
        deleteRecursively(proj);
    }

    static void deleteRecursively(Path root) {
        if (root == null || !Files.exists(root)) return;
        try {
            Files.walk(root)
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                    });
        } catch (IOException ignored) {
        }
    }

    static String tail(String s, int max) {
        if (s == null) return "";
        String t = s.strip();
        if (t.length() <= max) return t;
        return t.substring(t.length() - max);
    }
}
