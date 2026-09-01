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
import java.util.Locale;
import java.util.Map;

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
 * ingest <em>with symbols</em>. Constants and strings are extracted at ingest
 * into a companion {@code corroboration} schema so {@code corroborate_match}
 * never needs the reference program open.
 */
@McpToolGroup(value = "bsim",
        description = "Cross-build function matching via Ghidra BSim (CLI wrapper). "
                + "Returns similarity and confidence separately; never a bare ranked list. "
                + "corroborate_match adds constants/strings/callees as evidence, not a score. "
                + "CLI-heavy calls return a job_id when they outlive wait_seconds; poll "
                + "bsim_job_status for the result.")
public class BSimService {

    static final String QUERY_SCRIPT_RESOURCE = "/bsim/BSim_McpQuery.java";
    static final String QUERY_SCRIPT_NAME = "BSim_McpQuery.java";
    static final String EXTRACT_SCRIPT_RESOURCE = "/bsim/BSim_McpExtract.java";
    static final String EXTRACT_SCRIPT_NAME = "BSim_McpExtract.java";
    static final String DEFAULT_TEMPLATE = "medium_nosize";
    static final String WHOLE_PROGRAM_FUNCTION = "ALL";
    static final String STRIPPED_WARNING =
            "This program has few or no user-defined function names. "
                    + "A stripped binary adds signature noise and yields no names to propagate. "
                    + "Ingest a build with symbols.";
    static final String NO_DWARF_WARNING =
            "No function has a DWARF signature (has_dwarf=false for every row). The reference "
                    + "was probably built without -g; bsim_apply_matches(apply_signatures=true) "
                    + "will skip every function from it. Rebuild with -g to transfer types.";

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
    private final CorroborationStore.Factory stores;
    private final CorroborationExtractor extractor;
    private final BSimSignatures.Support signatures;

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, new BSimCli());
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli) {
        this(programProvider, threadingStrategy, cli, new BSimJobs());
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli, BSimJobs jobs) {
        this(programProvider, threadingStrategy, cli, jobs,
                CorroborationStore::open, CorroborationExtract.INSTANCE);
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli, BSimJobs jobs, CorroborationStore.Factory stores,
                       CorroborationExtractor extractor) {
        this(programProvider, threadingStrategy, cli, jobs, stores, extractor,
                BSimSignatures.GHIDRA);
    }

    public BSimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                       BSimCli cli, BSimJobs jobs, CorroborationStore.Factory stores,
                       CorroborationExtractor extractor, BSimSignatures.Support signatures) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.cli = cli;
        this.jobs = jobs;
        this.stores = stores != null ? stores : CorroborationStore::open;
        this.extractor = extractor != null ? extractor : CorroborationExtract.INSTANCE;
        this.signatures = signatures != null ? signatures : BSimSignatures.GHIDRA;
    }

    // ========================================================================
    // bsim_create_db
    // ========================================================================

    @McpTool(path = "/bsim_create_db", method = "POST",
            description = "Create a BSim database via `bsim createdatabase`. Default template "
                    + "medium_nosize (every database, unconditionally). medium_nosize beat "
                    + "medium_32 under compiler and optimisation drift and gave up nothing on "
                    + "identical builds. Call-graph data is recorded unless callgraph=false. "
                    + "Compose uses PostgreSQL (postgresql://ghidra-bsim:5432/bsim) so GUI "
                    + "clients on the VPN can search the same mixed-arch corpus. ARM firmware "
                    + "and x86-64 userland share one medium_nosize database; bsim_query(arch=...) "
                    + "constrains when you want same-arch only. file: H2 URLs remain "
                    + "for leftover local databases. Writes a <name>.ghidra-mcp.json sidecar "
                    + "with the template so bsim_list_databases can report it. Network db_url "
                    + "values must be on GHIDRA_MCP_BSIM_URLS. The database is empty until "
                    + "bsim_ingest. Returns a job_id instead of a result when the CLI outlives "
                    + "wait_seconds.",
            category = "bsim")
    public Response createDb(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim URL: postgresql://host/db (allowlisted) or file:/path/db")
                    String dbUrl,
            @Param(value = "config_template", source = ParamSource.BODY, defaultValue = "medium_nosize",
                    description = "medium_nosize (default) | medium_32 | medium_64 | large_32 | medium_cpool. "
                            + "medium_nosize accepts mixed pointer sizes; sized templates do not.")
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
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
            String template = BSimUrls.requireConfigTemplate(
                    (configTemplate == null || configTemplate.isBlank())
                            ? DEFAULT_TEMPLATE : configTemplate);
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
                BSimUrls.writeDatabaseSidecar(url, template);
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
    // bsim_list_databases
    // ========================================================================

    @McpTool(path = "/bsim_list_databases", method = "GET",
            description = "List BSim databases: allowlisted postgresql:// URLs "
                    + "(GHIDRA_MCP_BSIM_URLS) and any leftover H2 files under "
                    + "GHIDRA_MCP_BSIM_ROOT. Every row separates configuration from state. "
                    + "configured=true means only that the URL is allowlisted; present says "
                    + "whether the database is actually there, and probe explains it (ok, "
                    + "no_database, no_bsim_schema, auth_failed, unreachable, no_credential, "
                    + "not_probed). A live database also reports executables and "
                    + "corroboration_functions. config_template is CONFIGURATION, not a read "
                    + "of the database: config_template_source says whether it came from a "
                    + "bsim_create_db sidecar, GHIDRA_MCP_BSIM_TEMPLATES, or nowhere. Templates "
                    + "are fixed inside the database at createdatabase time. Never spawns the "
                    + "bsim CLI; probing is a short read-only JDBC connect (probe=false skips "
                    + "it and leaves present unreported). present is omitted whenever it is "
                    + "unknown, so read probe rather than treating a missing present as false.",
            category = "bsim")
    public Response listDatabases(
            @Param(value = "probe", defaultValue = "true",
                    description = "Contact each allowlisted network database to report whether "
                            + "it exists. false leaves present unreported and probe=not_probed.")
                    boolean probe,
            @Param(value = "probe_timeout_seconds", defaultValue = "3",
                    description = "Per-database connect/read budget in seconds (1-15). Several "
                            + "URLs are probed in one call, so keep it short.")
                    int probeTimeoutSeconds) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("config_templates", List.copyOf(BSimUrls.CONFIG_TEMPLATE_ORDER));
        String root = BSimUrls.bsimRootEnv();
        body.put("bsim_root", root);
        body.put("bsim_urls", BSimUrls.bsimAllowlistEnv());
        int timeout = Math.max(1, Math.min(15, probeTimeoutSeconds));
        List<Map<String, Object>> databases =
                new ArrayList<>(BSimUrls.listAllowlistedDatabases(probe, timeout));
        if (root != null && !root.isBlank()) {
            databases.addAll(BSimUrls.listFileDatabases(Path.of(root)));
        }
        body.put("databases", databases);
        body.put("count", databases.size());
        body.put("probed", probe);
        return Response.ok(body);
    }

    // ========================================================================
    // bsim_ingest
    // ========================================================================

    @McpTool(path = "/bsim_ingest", method = "POST",
            description = "Generate BSim signatures from a ghidraURL (or an open program) and "
                    + "commit them with `bsim generatesigs --bsim --commit`. Also extracts "
                    + "per-function constants, strings and direct callees into the companion "
                    + "corroboration schema (same PostgreSQL database, not BSim's tables) so "
                    + "corroborate_match does not need the reference program later. Also stores "
                    + "each function's typed prototype (DWARF only: has_dwarf) and exports the "
                    + "program's data types to <artifact>.gdt beside the artifact, so "
                    + "bsim_apply_matches(apply_signatures=true) never opens the reference. Refuses a "
                    + "source with no functions, and a pointer-size mismatch against a sized "
                    + "template (medium_32 / medium_64 / large_32). medium_nosize accepts mixed "
                    + "pointer sizes. Identical-MD5 re-ingest is skipped (BSim keys on MD5 but "
                    + "records the throwaway project URL, so a second pass is not a no-op) but "
                    + "corroboration and signatures are still written when the program is open — "
                    + "that is the backfill path. The ingest response carries executable_md5 for the "
                    + "artifact sidecar. Warns when the source has few user-defined names or no DWARF "
                    + "signatures. Ingest with symbols and -g. Ingest takes minutes: expect a job_id, "
                    + "then poll bsim_job_status.",
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
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
            if (source == null || source.isBlank()) {
                return Response.err("source is required (ghidraURL, repo path, or open program name)");
            }
            String credErr = BSimUrls.missingServerCredential(source);
            if (credErr != null) return Response.err(credErr);
            String userErr = BSimUrls.ambiguousIngestUser(url, source);
            if (userErr != null) return Response.err(userErr);
            Program program = resolveProgramIfOpen(source, programName);
            // Fail unresolvable sources synchronously and specifically —
            // classify throws IllegalArgumentException with the remedy. The
            // ghidraURL it may resolve is rechecked for credentials here too
            // (repo paths become ghidra:// on this hop).
            String directUrl = classifySource(source, program);
            if (directUrl != null) {
                credErr = BSimUrls.missingServerCredential(directUrl);
                if (credErr != null) return Response.err(credErr);
                // A repo path becomes ghidra:// on this hop, so the two
                // identities can only merge here — recheck after resolution.
                userErr = BSimUrls.ambiguousIngestUser(url, directUrl);
                if (userErr != null) return Response.err(userErr);
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
                Response skip = skipIfAlreadyIngested(program, url);
                if (skip != null) {
                    mergeSkipCorroboration(url, program, source, warnings, skip);
                    return skip;
                }
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
                if (BSimUrls.isServerGhidraUrl(ghidraUrl)) {
                    String user = BSimCli.resolvedServerUser();
                    if (user != null) {
                        args.add("--user");
                        args.add(user);
                    }
                }
                BSimCli.Result r = runBsim(BSimCli.INGEST_TIMEOUT, args);
                if (!r.ok()) {
                    return ingestCliError("generatesigs failed", r);
                }

                BSimCli.Result countR = runBsim(BSimCli.DEFAULT_TIMEOUT, List.of("getexecount", url));
                Integer exeCount = BSimCliParser.parseExeCount(countR.output);

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "success");
                body.put("db_url", url);
                body.put("source", ghidraUrl);
                body.put("commit", commit);
                if (exeCount != null) body.put("executables", exeCount);
                String md5 = programMd5(program);
                if (md5 != null && !md5.isBlank()) {
                    body.put("executable_md5", md5);
                    BSimUrls.recordIngestedMd5(url, md5);
                    recordArtifactExecutableMd5(program, md5);
                }
                if (program != null) body.put("executable_name", program.getName());
                storeCorroboration(url, program, ghidraUrl, commit, warnings, body);
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
                    + "Filter on confidence, not similarity. Cross-compiler matches legitimately "
                    + "score 0.2-0.4 similarity; confidence indicates whether that overlap is "
                    + "meaningful. Defaults: similarity_threshold=0.0, confidence_threshold=10.0 "
                    + "(a starting floor, not a calibration). Optional arch / executable / "
                    + "compiler / exclude_md5 are server-side BSimFilter atoms (not post-processed; "
                    + "max_matches applies after the filter). Functions whose feature vector is "
                    + "too small to identify are returned with identifiable=false, never dropped. "
                    + "Each match has separate numeric similarity and confidence, plus the source "
                    + "executable name and architecture. Flagged ambiguous when the top two "
                    + "differently-named hits sit within 0.05 similarity. A similarity_threshold "
                    + "above 0.5 silently drops cross-compiler matches and adds a warning. "
                    + "Opt-in corroborate=true attaches constants/strings/callee evidence to "
                    + "ambiguous, unidentifiable, or low-confidence hits without reordering "
                    + "them. Queries run a helper analyzeHeadless JVM and can take minutes: "
                    + "expect a job_id, then poll bsim_job_status.",
            category = "bsim")
    public Response query(
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim database URL") String dbUrl,
            @Param(value = "function", source = ParamSource.BODY, defaultValue = "",
                    description = "Function name or address. Omit to query every function.")
                    String function,
            @Param(value = "similarity_threshold", source = ParamSource.BODY, defaultValue = "0.0",
                    description = "Minimum BSim similarity (0-1). Default 0.0: cross-compiler "
                            + "matches sit at 0.2-0.4. Values above 0.5 typically return nothing "
                            + "against a real corpus.") double similarityThreshold,
            @Param(value = "confidence_threshold", source = ParamSource.BODY, defaultValue = "10.0",
                    description = "Minimum BSim confidence. Default 10.0. Confidence, not "
                            + "similarity, is the discriminating signal for cross-build matching.")
                    double confidenceThreshold,
            @Param(value = "max_matches", source = ParamSource.BODY, defaultValue = "10",
                    description = "Maximum matches per function") int maxMatches,
            @Param(value = "program", defaultValue = "") String programName,
            @Param(value = "arch", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: architecture equals (comma = OR). "
                            + "e.g. ARM:LE:32:Cortex")
                    String arch,
            @Param(value = "executable", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: executable name equals (comma = OR)")
                    String executable,
            @Param(value = "compiler", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: compiler equals (comma = OR)")
                    String compiler,
            @Param(value = "exclude_md5", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: exclude corpus executables by MD5 "
                            + "(comma = AND of not-equals)")
                    String excludeMd5,
            @Param(value = "min_feature_count", source = ParamSource.BODY, defaultValue = "8",
                    description = "Flag the queried function unidentifiable when its LSH vector "
                            + "has fewer than this many features. Default 8. 0 disables. "
                            + "Matches are still returned.")
                    int minFeatureCount,
            @Param(value = "min_function_size", source = ParamSource.BODY, defaultValue = "0",
                    description = "Byte-size proxy used only when min_feature_count is 0. Default 0 (off).")
                    int minFunctionSize,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds,
            @Param(value = "corroborate", source = ParamSource.BODY, defaultValue = "false",
                    description = "If true, attach corroboration evidence (constants, strings, "
                            + "direct callees) to ambiguous, unidentifiable, or low-confidence "
                            + "matches. Default false. Never reorders results.")
                    boolean corroborate,
            @Param(value = "corroborate_max_candidates", source = ParamSource.BODY, defaultValue = "3",
                    description = "When corroborate=true, evidence is attached to at most this "
                            + "many leading matches per function. Default 3.")
                    int corroborateMaxCandidates) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();
            QuerySpec spec = new QuerySpec(function, similarityThreshold, confidenceThreshold,
                    maxMatches, arch, executable, compiler, excludeMd5,
                    minFeatureCount, minFunctionSize, corroborate,
                    Math.max(1, corroborateMaxCandidates));

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("program", program.getName());
            if (function != null && !function.isBlank()) request.put("function", function);
            BSimJobs.Job job = jobs.submit("bsim_query", request,
                    () -> runQuery(url, program, spec));
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
                    + "(never overwrite an analyst name). Ambiguous matches are never applied. "
                    + "Duplicate proposed names are conflicts and none are applied by default. "
                    + "resolve_conflicts=best may select the highest-confidence candidate only "
                    + "when it clears conflict_min_confidence_margin. "
                    + "Functions flagged unidentifiable (too few LSH features) are skipped unless "
                    + "apply_unidentifiable=true. Optional arch / executable / compiler / "
                    + "exclude_md5 are the same server-side filters as bsim_query. Applied names "
                    + "are the BSim hit names as-is (C linkage, not PascalCase). "
                    + "apply_signatures=true (default false) additionally applies the reference's "
                    + "typed DWARF prototype to each function being renamed, importing struct/typedef "
                    + "types from the reference's .gdt archive with KEEP semantics (a type the target "
                    + "already defines by name is never replaced). A wrong signature propagates through "
                    + "the decompiler, so it has its own gates: min_signature_confidence (>= "
                    + "min_confidence, default 40), same architecture only, DWARF-sourced only, and the "
                    + "reference parameter count must equal what the target's decompiler infers; "
                    + "anything else gets the name only and is counted in the signatures block. "
                    + "Every applied signature carries a [bsim-sig] plate-comment marker naming the "
                    + "reference and confidence. dry_run previews signatures and imports no types. "
                    + "Runs a full-program BSim query first, which takes minutes: expect a job_id, "
                    + "then poll bsim_job_status.",
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
            @Param(value = "similarity_threshold", source = ParamSource.BODY, defaultValue = "0.0",
                    description = "Query-time similarity floor (before apply filters). Default 0.0, "
                            + "same as bsim_query: cross-compiler matches sit at 0.2-0.4.")
                    double querySimilarity,
            @Param(value = "max_matches", source = ParamSource.BODY, defaultValue = "10",
                    description = "Matches fetched per function") int maxMatches,
            @Param(value = "program", defaultValue = "") String programName,
            @Param(value = "arch", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: architecture equals (comma = OR)")
                    String arch,
            @Param(value = "executable", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: executable name equals (comma = OR)")
                    String executable,
            @Param(value = "compiler", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: compiler equals (comma = OR)")
                    String compiler,
            @Param(value = "exclude_md5", source = ParamSource.BODY, defaultValue = "",
                    description = "Server-side filter: exclude corpus executables by MD5")
                    String excludeMd5,
            @Param(value = "min_feature_count", source = ParamSource.BODY, defaultValue = "8",
                    description = "Skip functions whose LSH vector is below this feature count. "
                            + "Default 8. Same flag as bsim_query.")
                    int minFeatureCount,
            @Param(value = "apply_unidentifiable", source = ParamSource.BODY, defaultValue = "false",
                    description = "If true, apply matches even when the queried function is "
                            + "flagged unidentifiable. Default false — that is where a "
                            + "degenerate match bulk-renames into a shared repository.")
                    boolean applyUnidentifiable,
            @Param(value = "resolve_conflicts", source = ParamSource.BODY, defaultValue = "none",
                    description = "none | best. none skips every candidate in a duplicate-name "
                            + "group. best keeps only the confidence leader when its margin is met.")
                    String resolveConflicts,
            @Param(value = "conflict_min_confidence_margin", source = ParamSource.BODY,
                    defaultValue = "5.0",
                    description = "Minimum confidence lead required by resolve_conflicts=best. "
                            + "Exact ties are always skipped, even when this is 0.")
                    double conflictMinConfidenceMargin,
            @Param(value = "apply_signatures", source = ParamSource.BODY, defaultValue = "false",
                    description = "Also apply the reference's typed prototype (parameter names, "
                            + "struct pointer types, return type, calling convention) to each "
                            + "function being renamed. Default false: a wrong signature propagates "
                            + "to every caller, so opt in consciously. Only functions that pass "
                            + "min_signature_confidence, same-arch, DWARF and parameter-count "
                            + "checks get one; the rest keep the name only.")
                    boolean applySignatures,
            @Param(value = "min_signature_confidence", source = ParamSource.BODY,
                    defaultValue = "40.0",
                    description = "Confidence floor for signatures; must be >= min_confidence. "
                            + "Default 40 is a starting point, not a calibration.")
                    double minSignatureConfidence,
            @Param(value = "wait_seconds", source = ParamSource.BODY, defaultValue = "45",
                    description = WAIT_SECONDS_DESCRIPTION) int waitSeconds) {
        if (minConfidence == null) {
            return Response.err(
                    "min_confidence is required. There is no universally safe default; "
                            + "choose a floor from the confidence values bsim_query returned on "
                            + "distinctive functions in this corpus.");
        }
        try {
            String conflictMode = resolveConflicts == null
                    ? "none" : resolveConflicts.trim().toLowerCase(Locale.ROOT);
            if (!"none".equals(conflictMode) && !"best".equals(conflictMode)) {
                return Response.err("resolve_conflicts must be none or best; got: "
                        + resolveConflicts);
            }
            if (conflictMinConfidenceMargin < 0.0) {
                return Response.err("conflict_min_confidence_margin must be >= 0");
            }
            if (applySignatures && minSignatureConfidence < minConfidence) {
                return Response.err("min_signature_confidence (" + minSignatureConfidence
                        + ") must be >= min_confidence (" + minConfidence + "): a signature "
                        + "propagates through every caller, so it needs the stricter floor.");
            }
            String url = BSimUrls.requireBsimUrl(dbUrl);
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Map<String, Object> request = new LinkedHashMap<>();
            request.put("db_url", url);
            request.put("program", program.getName());
            request.put("dry_run", dryRun);
            request.put("min_confidence", minConfidence);
            request.put("resolve_conflicts", conflictMode);
            request.put("conflict_min_confidence_margin", conflictMinConfidenceMargin);
            request.put("apply_signatures", applySignatures);
            if (applySignatures) request.put("min_signature_confidence", minSignatureConfidence);
            BSimJobs.Job job = jobs.submit("bsim_apply_matches", request,
                    () -> runApplyMatches(url, program, minConfidence, minSimilarity,
                            skipNamed, dryRun, querySimilarity, maxMatches,
                            arch, executable, compiler, excludeMd5,
                            minFeatureCount, applyUnidentifiable, conflictMode,
                            conflictMinConfidenceMargin, applySignatures,
                            minSignatureConfidence));
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
                                     double querySimilarity, int maxMatches,
                                     String arch, String executable, String compiler,
                                     String excludeMd5, int minFeatureCount,
                                     boolean applyUnidentifiable, String resolveConflicts,
                                     double conflictMinConfidenceMargin,
                                     boolean applySignatures, double minSignatureConfidence)
            throws Exception {
        QuerySpec spec = new QuerySpec("", querySimilarity, 0.0, maxMatches,
                arch, executable, compiler, excludeMd5, minFeatureCount, 0);
        Response queried = runQuery(url, program, spec);
        if (queried instanceof Response.Err) return queried;
        Map<String, Object> payload = JsonHelper.parseJson(queried.toJson());
        List<BSimMatches.FunctionResult> results =
                BSimMatches.parseQueryPayload(payload, program.getExecutableMD5());
        try (SignatureRun sigRun = applySignatures
                ? new SignatureRun(url, program, dryRun, minSignatureConfidence) : null) {
            return applyResults(program, results, minConfidence, minSimilarity, skipNamed,
                    dryRun, applyUnidentifiable, resolveConflicts,
                    conflictMinConfidenceMargin, sigRun);
        }
    }

    private Response applyResults(Program program, List<BSimMatches.FunctionResult> results,
                                  Double minConfidence, double minSimilarity, boolean skipNamed,
                                  boolean dryRun, boolean applyUnidentifiable,
                                  String resolveConflicts, double conflictMinConfidenceMargin,
                                  SignatureRun sigRun) {

        List<Map<String, Object>> renamed = new ArrayList<>();
        List<Map<String, Object>> wouldRename = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("queried", results.size());
        counts.put("renamed", 0);
        counts.put("would_rename", 0);
        counts.put("already_named", 0);
        counts.put("unidentifiable", 0);
        counts.put("below_similarity", 0);
        counts.put("below_confidence", 0);
        counts.put("ambiguous", 0);
        counts.put("conflicting", 0);
        counts.put("no_matches", 0);
        counts.put("self_match", 0);
        counts.put("function_not_found", 0);
        counts.put("rename_failed", 0);

        List<ApplyCandidate> candidates = new ArrayList<>();

        for (BSimMatches.FunctionResult fr : results) {
            // Conflict grouping needs no Listing lookup. Resolve here only
            // when the current name is part of the decision, then defer any
            // remaining lookup until a candidate has survived grouping.
            Function func = skipNamed ? resolveApplyTarget(program, fr) : null;
            String currentName = func != null ? func.getName() : fr.function;
            BSimMatches.ApplyAction action = BSimMatches.decide(
                    fr, currentName, skipNamed, minSimilarity, minConfidence, applyUnidentifiable);
            if (action != BSimMatches.ApplyAction.APPLY) {
                String reason = BSimMatches.reason(action);
                counts.computeIfPresent(reason, (key, value) -> value + 1);
                Map<String, Object> skip = new LinkedHashMap<>();
                skip.put("function", fr.function);
                if (fr.address != null) skip.put("address", fr.address);
                skip.put("reason", reason);
                if (!fr.identifiable) skip.put("identifiable", false);
                BSimMatches.Hit best = fr.best();
                if (best != null) {
                    skip.put("best_name", best.name);
                    skip.put("similarity", best.similarity);
                    skip.put("confidence", best.confidence);
                }
                skipped.add(skip);
                continue;
            }
            candidates.add(new ApplyCandidate(fr, func, fr.best()));
        }

        Map<String, List<ApplyCandidate>> byName = new LinkedHashMap<>();
        for (ApplyCandidate candidate : candidates) {
            byName.computeIfAbsent(candidate.hit.name, ignored -> new ArrayList<>())
                    .add(candidate);
        }
        Map<String, List<Function>> existingByName = existingFunctionsByName(program, byName);

        List<Map<String, Object>> conflicts = new ArrayList<>();
        int resolvedConflictGroups = 0;
        int disabledConflictGroups = 0;
        int insufficientMarginGroups = 0;
        int existingNameGroups = 0;
        for (Map.Entry<String, List<ApplyCandidate>> entry : byName.entrySet()) {
            List<ApplyCandidate> group = entry.getValue();
            List<Function> existing = existingByName.getOrDefault(entry.getKey(), List.of());
            if (group.size() == 1 && existing.isEmpty()) {
                applyCandidate(program, group.get(0), dryRun, renamed, wouldRename,
                        skipped, counts, sigRun);
                continue;
            }

            group.sort((a, b) -> {
                int confidence = Double.compare(b.hit.confidence, a.hit.confidence);
                if (confidence != 0) return confidence;
                int similarity = Double.compare(b.hit.similarity, a.hit.similarity);
                if (similarity != 0) return similarity;
                return a.result.function.compareTo(b.result.function);
            });
            ApplyCandidate leader = group.get(0);
            double margin = group.size() > 1
                    ? leader.hit.confidence - group.get(1).hit.confidence : 0.0;
            boolean resolved = existing.isEmpty() && "best".equals(resolveConflicts)
                    && margin > 0.0 && margin >= conflictMinConfidenceMargin;

            Map<String, Object> conflict = new LinkedHashMap<>();
            conflict.put("name", entry.getKey());
            conflict.put("confidence_margin", margin);
            conflict.put("required_margin", conflictMinConfidenceMargin);
            List<Map<String, Object>> conflictCandidates = new ArrayList<>();
            for (ApplyCandidate candidate : group) {
                conflictCandidates.add(candidate.conflictMap());
            }
            conflict.put("candidates", conflictCandidates);
            if (!existing.isEmpty()) {
                List<Map<String, Object>> existingFunctions = new ArrayList<>();
                for (Function function : existing) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("function", function.getName());
                    if (function.getEntryPoint() != null) {
                        row.put("address", function.getEntryPoint().toString());
                    }
                    existingFunctions.add(row);
                }
                conflict.put("existing_functions", existingFunctions);
            }

            if (resolved) {
                resolvedConflictGroups++;
                conflict.put("resolution", "best");
                conflict.put("selected_function", leader.result.function);
                applyCandidate(program, leader, dryRun, renamed, wouldRename, skipped, counts,
                        sigRun);
                for (int i = 1; i < group.size(); i++) {
                    skipConflict(group.get(i), "best_not_selected", margin,
                            skipped, counts);
                }
            } else {
                String resolution;
                if (!existing.isEmpty()) {
                    existingNameGroups++;
                    resolution = "name_already_exists";
                } else if ("best".equals(resolveConflicts)) {
                    insufficientMarginGroups++;
                    resolution = "insufficient_margin";
                } else {
                    disabledConflictGroups++;
                    resolution = "disabled";
                }
                conflict.put("resolution", resolution);
                for (ApplyCandidate candidate : group) {
                    skipConflict(candidate, resolution, margin, skipped, counts);
                }
            }
            conflicts.add(conflict);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("dry_run", dryRun);
        body.put("min_confidence", minConfidence);
        body.put("min_similarity", minSimilarity);
        body.put("skip_named", skipNamed);
        body.put("resolve_conflicts", resolveConflicts);
        body.put("conflict_min_confidence_margin", conflictMinConfidenceMargin);
        body.put("counts", counts);
        Map<String, Object> conflictSummary = new LinkedHashMap<>();
        conflictSummary.put("groups", conflicts.size());
        conflictSummary.put("resolved_best", resolvedConflictGroups);
        conflictSummary.put("skipped_disabled", disabledConflictGroups);
        conflictSummary.put("skipped_insufficient_margin", insufficientMarginGroups);
        conflictSummary.put("skipped_existing_name", existingNameGroups);
        body.put("conflict_summary", conflictSummary);
        body.put("conflicts", conflicts);
        body.put("unidentifiable_skipped", counts.get("unidentifiable"));
        body.put("renamed", renamed);
        body.put("would_rename", wouldRename);
        body.put("skipped", skipped);
        if (sigRun != null) {
            body.put("apply_signatures", true);
            body.put("min_signature_confidence", sigRun.minConfidence);
            body.put("signatures", sigRun.summary());
            body.put("signature_details", sigRun.details);
            if (!sigRun.warnings.isEmpty()) body.put("warnings", sigRun.warnings);
        }
        return Response.ok(body);
    }

    private record ApplyCandidate(BSimMatches.FunctionResult result, Function function,
                                  BSimMatches.Hit hit) {
        Map<String, Object> row() {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("function", result.function);
            if (result.address != null && !result.address.isEmpty()) {
                row.put("address", result.address);
            }
            row.put("new_name", hit.name);
            row.put("similarity", hit.similarity);
            row.put("confidence", hit.confidence);
            row.put("executable", hit.executable);
            return row;
        }

        Map<String, Object> conflictMap() {
            Map<String, Object> row = row();
            row.remove("new_name");
            return row;
        }
    }

    private static Map<String, List<Function>> existingFunctionsByName(
            Program program, Map<String, List<ApplyCandidate>> proposed) {
        Map<String, List<Function>> existing = new LinkedHashMap<>();
        if (program == null || proposed.isEmpty()) return existing;
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            String name = function.getName();
            if (proposed.containsKey(name)) {
                existing.computeIfAbsent(name, ignored -> new ArrayList<>()).add(function);
            }
        }
        return existing;
    }

    private void applyCandidate(Program program, ApplyCandidate candidate, boolean dryRun,
                                List<Map<String, Object>> renamed,
                                List<Map<String, Object>> wouldRename,
                                List<Map<String, Object>> skipped,
                                Map<String, Integer> counts, SignatureRun sigRun) {
        Map<String, Object> row = candidate.row();
        if (dryRun) {
            wouldRename.add(row);
            counts.computeIfPresent("would_rename", (key, value) -> value + 1);
            if (sigRun != null) {
                // Read-only: resolving the target lets the preview run the
                // same guards (arch, DWARF, parameter count) the real pass will.
                Function target = candidate.function;
                if (target == null) {
                    try {
                        target = resolveApplyTarget(program, candidate.result);
                    } catch (Exception e) {
                        target = null;
                    }
                }
                sigRun.consider(candidate, target, row);
            }
            return;
        }
        Function target = candidate.function != null
                ? candidate.function : resolveApplyTarget(program, candidate.result);
        if (target == null) {
            row.put("reason", "function_not_found");
            skipped.add(row);
            counts.computeIfPresent("function_not_found", (key, value) -> value + 1);
            return;
        }
        try {
            final Function renameTarget = target;
            threadingStrategy.executeWrite(program, "BSim apply " + candidate.hit.name, () -> {
                renameTarget.setName(candidate.hit.name, SourceType.USER_DEFINED);
                return null;
            });
            renamed.add(row);
            counts.computeIfPresent("renamed", (key, value) -> value + 1);
            // Signatures only ride on a rename that just happened, so hand-named
            // functions (skip_named) are untouched by construction.
            if (sigRun != null) sigRun.consider(candidate, target, row);
        } catch (Exception e) {
            row.put("reason", "rename_failed");
            row.put("error", e.getMessage());
            skipped.add(row);
            counts.computeIfPresent("rename_failed", (key, value) -> value + 1);
        }
    }

    /**
     * Per-run state for {@code apply_signatures}. One store, one applier (and
     * so one decompiler) for the whole pass; {@link #consider} runs the guards
     * for a candidate whose name was (or would be) applied.
     */
    private final class SignatureRun implements AutoCloseable {
        final Program program;
        final boolean dryRun;
        final double minConfidence;
        final CorroborationStore store;
        final BSimSignatures.Applier applier;
        final String targetArch;
        final Map<String, Integer> counts = new LinkedHashMap<>();
        final List<Map<String, Object>> details = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        private int typesImported;
        private int typesKeptExisting;

        SignatureRun(String url, Program program, boolean dryRun, double minConfidence) {
            this.program = program;
            this.dryRun = dryRun;
            this.minConfidence = minConfidence;
            this.store = stores.open(url);
            this.applier = signatures.applier(program);
            this.targetArch = applier.targetArch(program);
            for (String key : List.of("applied", "would_apply",
                    "skipped_below_confidence", "skipped_cross_arch",
                    "skipped_param_mismatch", "skipped_no_dwarf",
                    "skipped_no_signature_data", "skipped_no_archive",
                    "skipped_already_applied", "skipped_target_unresolved", "failed")) {
                counts.put(key, 0);
            }
            if (!store.writable()) {
                warnings.add("apply_signatures: signature data lives in the companion "
                        + "PostgreSQL schema; this db_url is not postgresql://, so every "
                        + "signature is skipped_no_signature_data");
            }
        }

        void consider(ApplyCandidate candidate, Function target, Map<String, Object> row) {
            BSimMatches.Hit hit = candidate.hit;
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("function", hit.name);
            if (candidate.result.address != null && !candidate.result.address.isEmpty()) {
                detail.put("address", candidate.result.address);
            }
            detail.put("confidence", hit.confidence);
            detail.put("source", hit.executable);

            BSimSignatures.Signature sig = null;
            if (hit.confidence >= minConfidence && store.writable()) {
                String refExe = (hit.md5 != null && !hit.md5.isBlank()) ? hit.md5 : hit.executable;
                try {
                    CorroborationEvidence.FunctionRow ref = store.lookup(refExe, hit.name);
                    sig = ref == null ? null : ref.signature();
                } catch (Exception e) {
                    warnings.add("signature lookup failed for " + hit.name + ": "
                            + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                }
            }
            boolean archiveExists = sig != null && !sig.gdtPath().isEmpty()
                    && Files.isRegularFile(Path.of(sig.gdtPath()));
            boolean already = target != null && applier.alreadyApplied(target, hit.executable);
            BSimSignatures.Decision decision = BSimSignatures.decide(hit.confidence, minConfidence,
                    targetArch, hit.arch, sig, archiveExists, already, null);
            if (decision == BSimSignatures.Decision.APPLY && target == null) {
                record(row, detail, "skipped_target_unresolved");
                return;
            }
            Integer targetParams = null;
            if (decision == BSimSignatures.Decision.APPLY) {
                targetParams = applier.targetParamCount(program, target);
                decision = BSimSignatures.decide(hit.confidence, minConfidence,
                        targetArch, hit.arch, sig, archiveExists, already, targetParams);
            }
            if (decision != BSimSignatures.Decision.APPLY) {
                if (decision == BSimSignatures.Decision.SKIP_PARAM_MISMATCH) {
                    detail.put("reference_params", sig.paramCount());
                    detail.put("target_params", targetParams);
                } else if (decision == BSimSignatures.Decision.SKIP_CROSS_ARCH) {
                    detail.put("target_arch", targetArch);
                    detail.put("reference_arch", hit.arch);
                } else if (decision == BSimSignatures.Decision.SKIP_NO_ARCHIVE && sig != null) {
                    detail.put("gdt_path", sig.gdtPath());
                }
                if (sig != null && !sig.isEmpty()) detail.put("prototype", sig.prototype());
                record(row, detail, BSimSignatures.reason(decision));
                return;
            }
            detail.put("prototype", sig.prototype());
            if (!sig.callingConvention().isEmpty()) {
                detail.put("calling_convention", sig.callingConvention());
            }
            if (dryRun) {
                BSimSignatures.TypePlan plan = applier.plan(program, target, sig, hit.name);
                if (!plan.error().isEmpty()) {
                    detail.put("error", plan.error());
                    record(row, detail, "failed");
                    return;
                }
                addTypes(detail, plan.imported(), plan.keptExisting());
                record(row, detail, "would_apply");
                return;
            }
            String provenance = BSimSignatures.provenanceLine(hit.executable, hit.confidence);
            BSimSignatures.Outcome outcome;
            try {
                final Function fn = target;
                final BSimSignatures.Signature ref = sig;
                outcome = threadingStrategy.executeWrite(program,
                        "BSim apply signature " + hit.name,
                        () -> applier.apply(program, fn, ref, hit.name, provenance));
            } catch (Exception e) {
                outcome = BSimSignatures.Outcome.failed(
                        e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
            if (outcome == null || !outcome.ok()) {
                detail.put("error", outcome == null ? "no outcome" : outcome.error());
                record(row, detail, "failed");
                return;
            }
            if (!outcome.prototype().isEmpty()) detail.put("prototype", outcome.prototype());
            if (!outcome.callingConvention().isEmpty()) {
                detail.put("calling_convention", outcome.callingConvention());
            }
            detail.put("provenance", provenance);
            addTypes(detail, outcome.imported(), outcome.keptExisting());
            record(row, detail, "applied");
        }

        private void addTypes(Map<String, Object> detail, List<String> imported,
                              List<String> kept) {
            typesImported += imported.size();
            typesKeptExisting += kept.size();
            detail.put("types_imported", imported);
            detail.put("types_kept_existing", kept);
        }

        private void record(Map<String, Object> row, Map<String, Object> detail, String status) {
            detail.put("status", status);
            counts.merge(status, 1, Integer::sum);
            details.add(detail);
            if (row != null) row.put("signature", status);
        }

        Map<String, Object> summary() {
            Map<String, Object> m = new LinkedHashMap<>(counts);
            m.put("types_imported", typesImported);
            m.put("types_kept_existing", typesKeptExisting);
            return m;
        }

        @Override
        public void close() {
            try {
                applier.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void skipConflict(ApplyCandidate candidate, String resolution, double margin,
                                     List<Map<String, Object>> skipped,
                                     Map<String, Integer> counts) {
        Map<String, Object> row = candidate.row();
        row.put("reason", "conflicting");
        row.put("conflict_resolution", resolution);
        row.put("confidence_margin", margin);
        skipped.add(row);
        counts.computeIfPresent("conflicting", (key, value) -> value + 1);
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
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
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
    // corroborate_match
    // ========================================================================

    @McpTool(path = "/corroborate_match", method = "POST",
            description = "Compare listing-level constants, strings and direct callees of an "
                    + "open query function against a BSim corpus candidate. The reference side "
                    + "is read from the companion corroboration schema written at ingest — the "
                    + "reference program is not opened. Returns shared / query-only / ref-only "
                    + "evidence with distinctiveness marks and the string-match rule that fired; "
                    + "never a blended score. A miss (executable ingested before extraction "
                    + "existed, or a file: H2 URL) is status=no_evidence, not an error. "
                    + "string_normalisation: off | basename | auto (default auto: exact first, "
                    + "then basename for path-shaped __FILE__ strings).",
            category = "bsim")
    public Response corroborateMatch(
            @Param(value = "program", defaultValue = "",
                    description = "Program containing the query function") String programName,
            @Param(value = "function", source = ParamSource.BODY,
                    description = "Query function name or address") String function,
            @Param(value = "db_url", source = ParamSource.BODY,
                    description = "BSim / corroboration database URL") String dbUrl,
            @Param(value = "ref_executable", source = ParamSource.BODY,
                    description = "Corpus executable name or MD5") String refExecutable,
            @Param(value = "ref_function", source = ParamSource.BODY,
                    description = "Candidate function name in the corpus") String refFunction,
            @Param(value = "string_normalisation", source = ParamSource.BODY, defaultValue = "auto",
                    description = "off | basename | auto. auto tries exact then basename on paths.")
                    String stringNormalisation) {
        try {
            String url = BSimUrls.requireBsimUrl(dbUrl);
            String pgCred = BSimUrls.missingPostgresCredential(url);
            if (pgCred != null) return Response.err(pgCred);
            if (function == null || function.isBlank()) {
                return Response.err("function is required (name or address of the query function)");
            }
            if (refFunction == null || refFunction.isBlank()) {
                return Response.err("ref_function is required (corpus candidate name)");
            }
            if (refExecutable == null || refExecutable.isBlank()) {
                return Response.err("ref_executable is required (corpus executable name or MD5)");
            }
            CorroborationEvidence.StringNorm norm =
                    CorroborationEvidence.StringNorm.parse(stringNormalisation);
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            CorroborationEvidence.FunctionRow queryRow;
            try {
                queryRow = extractor.extractOne(program, function.trim());
            } catch (Exception e) {
                return Response.err("failed to extract query function: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
            if (queryRow == null) {
                return Response.err("function not found: " + function);
            }

            CorroborationStore store = stores.open(url);
            if (!store.writable()) {
                return Response.ok(CorroborationEvidence.noEvidence(
                        queryRow.functionName(), refFunction.trim(),
                        "unsupported_backend",
                        List.of("Corroboration data lives in a companion PostgreSQL schema; "
                                + "this db_url is not postgresql://")));
            }
            CorroborationEvidence.FunctionRow refRow;
            int extractedFunctionCount;
            try {
                refRow = store.lookup(refExecutable.trim(), refFunction.trim());
                extractedFunctionCount = refRow == null
                        ? store.executableFunctionCount(refExecutable.trim()) : -1;
            } catch (Exception e) {
                return Response.err("corroboration lookup failed: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
            if (refRow == null) {
                boolean executableWasExtracted = extractedFunctionCount > 0;
                Map<String, Object> miss = CorroborationEvidence.noEvidence(
                        queryRow.functionName(), refFunction.trim(),
                        executableWasExtracted ? "function_not_found" : "not_extracted",
                        executableWasExtracted
                                ? List.of("The executable has corroboration data, but function '"
                                        + refFunction.trim() + "' is not among its "
                                        + extractedFunctionCount + " extracted functions")
                                : List.of("No corroboration data for this executable; "
                                        + "it was ingested before extraction existed"));
                miss.put("extracted_function_count", extractedFunctionCount);
                return Response.ok(miss);
            }
            Map<String, Object> body = CorroborationEvidence.compare(queryRow, refRow, store, norm);
            return Response.ok(body);
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

    Response runQuery(String dbUrl, Program program, QuerySpec spec) throws Exception {
        // saveToPackedFile refuses to overwrite, so the gzf must be a path
        // nothing has created yet — File.createTempFile pre-creates a zero-byte
        // file and made every query fail with "<path> already exists". One
        // owned directory also gives every exit path a single recursive delete.
        Path workDir = Files.createTempDirectory("bsim-query-");
        try {
            File gzf = workDir.resolve(packedProgramFileName(program)).toFile();
            Path projDir = Files.createDirectory(workDir.resolve("proj"));
            Path scriptDir = workDir.resolve("script");
            Path outJson = workDir.resolve("query-out.json");
            program.saveToPackedFile(gzf, TaskMonitor.DUMMY);
            extractQueryScript(scriptDir);
            String funcArg = (spec.function == null || spec.function.isBlank())
                    ? WHOLE_PROGRAM_FUNCTION : spec.function.trim();
            // analyzeHeadless treats a bare "-" as a flag and drops later args.
            if ("-".equals(funcArg)) funcArg = WHOLE_PROGRAM_FUNCTION;
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
            args.add(Double.toString(spec.similarity));
            args.add(Double.toString(spec.confidence));
            args.add(Integer.toString(Math.max(1, spec.maxMatches)));
            if (nonBlank(spec.arch)) args.add("arch=" + spec.arch.trim());
            if (nonBlank(spec.executable)) args.add("executable=" + spec.executable.trim());
            if (nonBlank(spec.compiler)) args.add("compiler=" + spec.compiler.trim());
            if (nonBlank(spec.excludeMd5)) args.add("exclude_md5=" + spec.excludeMd5.trim());
            args.add("min_feature_count=" + spec.minFeatureCount);
            args.add("min_function_size=" + spec.minFunctionSize);

            BSimCli.Result r = analyzeHeadless(BSimCli.QUERY_TIMEOUT, args, dbUrl);
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
            List<String> warnings = new ArrayList<>();
            String simWarn = BSimMatches.similarityThresholdWarning(spec.similarity);
            if (simWarn != null) warnings.add(simWarn);
            try {
                int bits = program.getLanguage().getLanguageDescription().getSize();
                String sizeWarn = BSimUrls.pointerSizeQueryWarning(
                        bits, BSimUrls.readSidecarTemplate(dbUrl));
                if (sizeWarn != null) warnings.add(sizeWarn);
            } catch (Exception ignored) {
                // Language metadata missing on a stub program is not a query failure.
            }
            int unidentifiable = 0;
            for (BSimMatches.FunctionResult fr : results) {
                if (!fr.identifiable) unidentifiable++;
            }
            if (spec.function != null && !spec.function.isBlank() && results.size() == 1) {
                Map<String, Object> body = results.get(0).toMap();
                attachQueryCorroboration(dbUrl, program, spec, List.of(results.get(0)),
                        List.of(body), warnings);
                if (!warnings.isEmpty()) body.put("warnings", warnings);
                return Response.ok(body);
            }
            List<Map<String, Object>> rows = new ArrayList<>();
            for (BSimMatches.FunctionResult fr : results) rows.add(fr.toMap());
            attachQueryCorroboration(dbUrl, program, spec, results, rows, warnings);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("program", program.getName());
            body.put("results", rows);
            body.put("count", rows.size());
            body.put("identifiable_count", rows.size() - unidentifiable);
            body.put("unidentifiable_count", unidentifiable);
            if (!warnings.isEmpty()) body.put("warnings", warnings);
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
        String languageId;
        try {
            languageId = program.getLanguageID().getIdAsString();
        } catch (Exception e) {
            languageId = "";
        }
        String template = BSimUrls.readSidecarTemplate(dbUrl);
        String sizeErr = BSimUrls.pointerSizeIngestError(srcBits, languageId, template);
        if (sizeErr != null) return Response.err(sizeErr);
        int templateBits = BSimUrls.templatePointerBits(template);
        if ((template == null || templateBits < 0) && srcBits == 64) {
            warnings.add("Corpus template is unknown and the source is 64-bit. "
                    + "If this database was created with medium_32, Ghidra will accept "
                    + "the ingest and silently degrade matches. Use medium_nosize.");
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
            File gzf = gzfDir.resolve(packedProgramFileName(program)).toFile();
            program.saveToPackedFile(gzf, TaskMonitor.DUMMY);
            proj = Files.createTempDirectory(workDir, "ingest-proj-");
            List<String> args = new ArrayList<>();
            args.add(proj.toAbsolutePath().toString());
            args.add("BSimIngest");
            args.add("-import");
            args.add(gzf.getAbsolutePath());
            args.add("-overwrite");
            args.add("-noanalysis");
            BSimCli.Result r = analyzeHeadless(BSimCli.INGEST_TIMEOUT, args, null);
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
        String stdin = stdinData != null ? stdinData : BSimCli.stdinForBsimArgs(args);
        if (BSimUrls.argsContainFileUrl(args)) {
            synchronized (BSimCli.LOCK) {
                return cli.bsim(timeout, args, stdin);
            }
        }
        return cli.bsim(timeout, args, stdin);
    }

    private BSimCli.Result analyzeHeadless(Duration timeout, List<String> args, String dbUrl)
            throws Exception {
        if (dbUrl != null && BSimUrls.isFileUrl(dbUrl)) {
            synchronized (BSimCli.LOCK) {
                return cli.analyzeHeadless(timeout, args);
            }
        }
        return cli.analyzeHeadless(timeout, args);
    }

    private Response cliError(String prefix, BSimCli.Result r) {
        String extracted = BSimCliParser.databaseAuthError(r.output);
        if (extracted == null) extracted = BSimCliParser.extractError(r.output);
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
        extractClasspathScript(scriptDir, QUERY_SCRIPT_RESOURCE, QUERY_SCRIPT_NAME);
    }

    static void extractExtractScript(Path scriptDir) throws IOException {
        extractClasspathScript(scriptDir, EXTRACT_SCRIPT_RESOURCE, EXTRACT_SCRIPT_NAME);
    }

    private static void extractClasspathScript(Path scriptDir, String resource, String name)
            throws IOException {
        Files.createDirectories(scriptDir);
        Path dest = scriptDir.resolve(name);
        try (InputStream in = BSimService.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing classpath resource " + resource);
            }
            Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private Response skipIfAlreadyIngested(Program program, String dbUrl) throws Exception {
        String md5 = programMd5(program);
        if (md5 == null || md5.isBlank()) return null;
        BSimCli.Result listR = runBsim(BSimCli.DEFAULT_TIMEOUT,
                List.of("listexes", dbUrl, "--limit", "10000"));
        BSimCliParser.ExeRecord hit = null;
        for (BSimCliParser.ExeRecord e : BSimCliParser.parseExeList(listR.output)) {
            if (e.md5 != null && md5.equalsIgnoreCase(e.md5)) {
                hit = e;
                break;
            }
        }
        if (hit == null) return null;
        String currentCompiler = programCompiler(program);
        if (currentCompiler != null && hit.compiler != null
                && !hit.compiler.isBlank()
                && !"unknown".equalsIgnoreCase(hit.compiler)
                && !currentCompiler.equalsIgnoreCase(hit.compiler)) {
            return Response.err(
                    "MD5 " + md5 + " is already ingested as executable '" + hit.name
                            + "' compiler=" + hit.compiler + ". BSim keys on the executable "
                            + "MD5, not the compiler spec; overwrite=true does not replace it. "
                            + "Changing windows to gcc (or any compiler) on the same bytes "
                            + "requires a new database, not a re-ingest.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "skipped");
        body.put("reason", "already_ingested");
        body.put("db_url", dbUrl);
        body.put("executable_md5", md5);
        body.put("name", hit.name);
        if (hit.compiler != null) body.put("compiler", hit.compiler);
        return Response.ok(body);
    }

    private Response ingestCliError(String prefix, BSimCli.Result r) {
        String rewritten = BSimCliParser.rewriteIngestError(r.output);
        String detail = rewritten != null ? rewritten : tail(r.output, 1200);
        String msg = prefix + " (exit " + r.exitCode + ")";
        if (detail != null && !detail.isBlank()) msg = msg + ": " + detail;
        return Response.err(msg);
    }

    public static String packedProgramFileName(Program program) {
        String name = "";
        try {
            if (program != null) name = program.getName();
        } catch (Exception ignored) {
        }
        return packedProgramFileName(name);
    }

    public static String packedProgramFileName(String name) {
        if (name == null || name.isBlank()) name = "program";
        String sanitized = name.replaceAll("[^A-Za-z0-9._+-]+", "_");
        if (sanitized.isBlank()) sanitized = "program";
        if (sanitized.length() > 120) sanitized = sanitized.substring(0, 120);
        if (sanitized.toLowerCase(Locale.ROOT).endsWith(".gzf")) return sanitized;
        return sanitized + ".gzf";
    }

    private static String programMd5(Program program) {
        if (program == null) return null;
        try {
            String md5 = program.getExecutableMD5();
            return md5 == null || md5.isBlank() ? null : md5.trim();
        } catch (Exception e) {
            return null;
        }
    }

    private static String programCompiler(Program program) {
        if (program == null) return null;
        try {
            return program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        } catch (Exception e) {
            return null;
        }
    }

    static void recordArtifactExecutableMd5(Program program, String md5) {
        if (program == null || md5 == null || md5.isBlank()) return;
        String path;
        try {
            path = program.getExecutablePath();
        } catch (Exception e) {
            return;
        }
        if (path == null || path.isBlank()) return;
        Path sidecar = FrameworkBuild.sidecarPath(Path.of(path));
        if (!Files.isRegularFile(sidecar)) return;
        try {
            Map<String, Object> parsed = JsonHelper.parseJson(
                    Files.readString(sidecar, StandardCharsets.UTF_8));
            if (parsed == null) parsed = new LinkedHashMap<>();
            parsed.put("executable_md5", md5.trim().toLowerCase(Locale.ROOT));
            Files.writeString(sidecar, JsonHelper.toJson(parsed) + "\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

    private static boolean nonBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static final class QuerySpec {
        final String function;
        final double similarity;
        final double confidence;
        final int maxMatches;
        final String arch;
        final String executable;
        final String compiler;
        final String excludeMd5;
        final int minFeatureCount;
        final int minFunctionSize;
        final boolean corroborate;
        final int corroborateMax;

        QuerySpec(String function, double similarity, double confidence, int maxMatches,
                  String arch, String executable, String compiler, String excludeMd5,
                  int minFeatureCount, int minFunctionSize) {
            this(function, similarity, confidence, maxMatches, arch, executable, compiler,
                    excludeMd5, minFeatureCount, minFunctionSize, false, 3);
        }

        QuerySpec(String function, double similarity, double confidence, int maxMatches,
                  String arch, String executable, String compiler, String excludeMd5,
                  int minFeatureCount, int minFunctionSize,
                  boolean corroborate, int corroborateMax) {
            this.function = function;
            this.similarity = similarity;
            this.confidence = confidence;
            this.maxMatches = maxMatches;
            this.arch = arch == null ? "" : arch;
            this.executable = executable == null ? "" : executable;
            this.compiler = compiler == null ? "" : compiler;
            this.excludeMd5 = excludeMd5 == null ? "" : excludeMd5;
            this.minFeatureCount = minFeatureCount;
            this.minFunctionSize = minFunctionSize;
            this.corroborate = corroborate;
            this.corroborateMax = Math.max(1, corroborateMax);
        }
    }

    @SuppressWarnings("unchecked")
    private void mergeSkipCorroboration(String url, Program program, String source,
                                        List<String> warnings, Response skip) {
        if (!(skip instanceof Response.Ok ok) || !(ok.data() instanceof Map<?, ?> raw)) return;
        Map<String, Object> body = (Map<String, Object>) raw;
        storeCorroboration(url, program, source, true, warnings, body);
        if (!warnings.isEmpty()) body.put("warnings", warnings);
    }

    private void storeCorroboration(String url, Program program, String source,
                                    boolean commit, List<String> warnings,
                                    Map<String, Object> body) {
        if (!commit) return;
        CorroborationStore store = stores.open(url);
        if (!store.writable()) return;
        try {
            List<CorroborationEvidence.FunctionRow> rows;
            String md5 = programMd5(program);
            String exeName = program != null ? program.getName() : "";
            String gdtPath = "";
            if (program != null) {
                rows = extractor.extractAll(program);
                Path gdt = signatures.exportArchive(program, warnings);
                if (gdt != null) gdtPath = gdt.toString();
            } else {
                ScriptExtract extracted = extractCorroborationViaScript(source, warnings);
                rows = extracted.rows;
                gdtPath = extracted.gdtPath;
                if (!rows.isEmpty()) {
                    CorroborationEvidence.FunctionRow first = rows.get(0);
                    if (md5 == null || md5.isBlank()) md5 = first.executableMd5();
                    if (exeName == null || exeName.isBlank()) exeName = first.executableName();
                }
            }
            if (rows == null) rows = List.of();
            store.upsert(md5, exeName, rows, gdtPath);
            int dwarf = 0;
            int analysisOnly = 0;
            for (CorroborationEvidence.FunctionRow row : rows) {
                BSimSignatures.Signature sig = row == null ? null : row.signature();
                if (sig == null || sig.isEmpty()) continue;
                if (sig.hasDwarf()) dwarf++;
                else analysisOnly++;
            }
            if (!rows.isEmpty() && dwarf == 0) warnings.add(NO_DWARF_WARNING);
            if (body != null) {
                body.put("corroboration", rows.isEmpty() ? "empty" : "stored");
                body.put("corroboration_functions", rows.size());
                if (!gdtPath.isEmpty()) body.put("signature_archive", gdtPath);
                body.put("signatures_dwarf", dwarf);
                body.put("signatures_analysis_only", analysisOnly);
            }
        } catch (Exception e) {
            warnings.add("corroboration extract/store failed: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            if (body != null) body.put("corroboration", "failed");
        }
    }

    /** Rows plus the archive path the extract script wrote. */
    private record ScriptExtract(List<CorroborationEvidence.FunctionRow> rows, String gdtPath) {
        static final ScriptExtract NONE = new ScriptExtract(List.of(), "");
    }

    private ScriptExtract extractCorroborationViaScript(String ghidraUrl, List<String> warnings) {
        if (ghidraUrl == null || ghidraUrl.isBlank()) return ScriptExtract.NONE;
        HeadlessTarget target = HeadlessTarget.parse(ghidraUrl);
        if (target == null || target.fileName == null) {
            warnings.add("corroboration not stored: open the program and re-ingest "
                    + "(identical-MD5 skip still writes corroboration) so listing-level "
                    + "constants can be extracted");
            return ScriptExtract.NONE;
        }
        Path workDir = null;
        try {
            workDir = Files.createTempDirectory("bsim-extract-");
            Path scriptDir = workDir.resolve("script");
            Path outJson = workDir.resolve("extract.json");
            extractExtractScript(scriptDir);
            List<String> args = new ArrayList<>(target.headlessArgs());
            args.add("-noanalysis");
            if (BSimUrls.isServerGhidraUrl(ghidraUrl)) {
                String user = BSimCli.resolvedServerUser();
                if (user != null) {
                    args.add("-connect");
                    args.add(user);
                }
                // -p is what makes analyzeHeadless pass allowPasswordPrompt=true
                // to HeadlessClientAuthenticator. Without it the authenticator
                // logs "Headless client not configured to supply required
                // password" and hands back its BADPASSWORD sentinel, so the
                // password we do write to stdin is never read and this extract
                // can never authenticate against a repository. -connect alone
                // only names the user.
                args.add("-p");
            }
            args.add("-scriptPath");
            args.add(scriptDir.toAbsolutePath().toString());
            args.add("-postScript");
            args.add(EXTRACT_SCRIPT_NAME);
            args.add(outJson.toAbsolutePath().toString());
            // Where the .gdt goes when the artifact's directory is not writable.
            args.add(BSimSignatures.fallbackDirectory());
            BSimCli.Result r = analyzeHeadless(BSimCli.INGEST_TIMEOUT, args, null);
            if (!Files.isRegularFile(outJson) || Files.size(outJson) == 0) {
                warnings.add("corroboration extract script produced no JSON (exit "
                        + r.exitCode + ")");
                return ScriptExtract.NONE;
            }
            Map<String, Object> payload = JsonHelper.parseJson(
                    Files.readString(outJson, StandardCharsets.UTF_8));
            if (payload != null && payload.containsKey("error")) {
                warnings.add("corroboration extract: " + payload.get("error"));
                return ScriptExtract.NONE;
            }
            if (payload != null && payload.get("gdt_error") != null) {
                warnings.add("signature archive export failed: " + payload.get("gdt_error"));
            }
            return new ScriptExtract(
                    CorroborationStore.rowsFromExtractPayload(payload, "", ""),
                    CorroborationStore.gdtPathFromExtractPayload(payload));
        } catch (Exception e) {
            warnings.add("corroboration extract via script failed: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return ScriptExtract.NONE;
        } finally {
            deleteRecursively(workDir);
        }
    }

    @SuppressWarnings("unchecked")
    private void attachQueryCorroboration(String dbUrl, Program program, QuerySpec spec,
                                          List<BSimMatches.FunctionResult> results,
                                          List<Map<String, Object>> bodies,
                                          List<String> warnings) {
        if (!spec.corroborate || results == null || bodies == null) return;
        CorroborationStore store = stores.open(dbUrl);
        for (int i = 0; i < results.size() && i < bodies.size(); i++) {
            BSimMatches.FunctionResult fr = results.get(i);
            if (!BSimMatches.needsCorroboration(fr)) continue;
            Map<String, Object> body = bodies.get(i);
            Object matchesObj = body.get("matches");
            if (!(matchesObj instanceof List<?> matchList)) continue;
            CorroborationEvidence.FunctionRow queryRow;
            try {
                String sel = (fr.function != null && !fr.function.isEmpty())
                        ? fr.function : fr.address;
                queryRow = extractor.extractOne(program, sel);
            } catch (Exception e) {
                warnings.add("corroboration extract failed for " + fr.function + ": "
                        + e.getMessage());
                continue;
            }
            if (queryRow == null) {
                queryRow = CorroborationEvidence.FunctionRow.empty(fr.function);
            }
            int attached = 0;
            for (Object item : matchList) {
                if (attached >= spec.corroborateMax) break;
                if (!(item instanceof Map<?, ?> raw)) continue;
                Map<String, Object> match = (Map<String, Object>) raw;
                String refName = String.valueOf(match.getOrDefault("name", ""));
                String refExe = "";
                if (match.get("md5") != null && !String.valueOf(match.get("md5")).isBlank()) {
                    refExe = String.valueOf(match.get("md5"));
                } else if (match.get("executable") != null) {
                    refExe = String.valueOf(match.get("executable"));
                }
                Map<String, Object> evidence;
                try {
                    if (!store.writable()) {
                        evidence = CorroborationEvidence.noEvidence(
                                queryRow.functionName(), refName, "unsupported_backend",
                                List.of("Corroboration requires postgresql://"));
                    } else {
                        CorroborationEvidence.FunctionRow refRow = store.lookup(refExe, refName);
                        if (refRow == null) {
                            int extractedFunctionCount = store.executableFunctionCount(refExe);
                            boolean executableWasExtracted = extractedFunctionCount > 0;
                            evidence = CorroborationEvidence.noEvidence(
                                    queryRow.functionName(), refName,
                                    executableWasExtracted
                                            ? "function_not_found" : "not_extracted",
                                    executableWasExtracted
                                            ? List.of("The executable has corroboration data, but "
                                                    + "function '" + refName + "' is not among its "
                                                    + extractedFunctionCount
                                                    + " extracted functions")
                                            : List.of("No corroboration data for this executable; "
                                                    + "it was ingested before extraction existed"));
                            evidence.put("extracted_function_count", extractedFunctionCount);
                        } else {
                            evidence = CorroborationEvidence.compare(queryRow, refRow, store,
                                    CorroborationEvidence.StringNorm.AUTO);
                        }
                    }
                } catch (Exception e) {
                    evidence = CorroborationEvidence.noEvidence(
                            queryRow.functionName(), refName, "store_unavailable",
                            List.of("corroboration lookup failed: " + e.getMessage()));
                }
                match.put("corroboration", evidence);
                attached++;
            }
        }
    }

    /**
     * Split a ghidraURL into analyzeHeadless location / folder / process args.
     * {@code ghidra://host/repo/folder/file} and {@code ghidra:/dir/Project/file}.
     */
    static final class HeadlessTarget {
        final String location;
        final String folder;
        final String fileName;
        final boolean server;

        HeadlessTarget(String location, String folder, String fileName, boolean server) {
            this.location = location;
            this.folder = folder;
            this.fileName = fileName;
            this.server = server;
        }

        List<String> headlessArgs() {
            List<String> args = new ArrayList<>();
            args.add(location);
            if (folder != null && !folder.isEmpty()) args.add(folder);
            if (fileName != null) {
                args.add("-process");
                args.add(fileName);
            }
            return args;
        }

        static HeadlessTarget parse(String url) {
            if (url == null || url.isBlank()) return null;
            String trimmed = url.trim();
            if (!BSimUrls.isServerGhidraUrl(trimmed)) {
                // Local ghidra:/dir/Project URLs do not name the program
                // reliably; open it and re-ingest (MD5 skip still writes).
                return new HeadlessTarget("", "", null, false);
            }
            String rest = trimmed.substring("ghidra://".length());
            int slash = rest.indexOf('/');
            if (slash < 0) return null;
            String host = rest.substring(0, slash);
            String path = rest.substring(slash + 1);
            while (path.startsWith("/")) path = path.substring(1);
            String[] parts = path.split("/");
            if (parts.length < 2) return null;
            String repo = parts[0];
            String file = parts[parts.length - 1];
            StringBuilder folder = new StringBuilder();
            for (int i = 1; i < parts.length - 1; i++) {
                folder.append('/').append(parts[i]);
            }
            return new HeadlessTarget("ghidra://" + host + "/" + repo,
                    folder.toString(), file, true);
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
