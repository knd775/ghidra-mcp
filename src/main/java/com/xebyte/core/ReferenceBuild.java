package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Pure validation, naming, and compiler argv for {@code build_reference}.
 *
 * <p>{@code toolchain} is a full identity {@code <compiler><major>-<target>},
 * not a GCC version with ARM implied. Family drift (GCC vs LLVM) is larger than
 * version drift; a firmware littlefs matched a GCC 13 object at the right names
 * but 0.27–0.35 similarity because {@code lfs_dir_fetchmatch} was ~300 bytes
 * larger than any object that compiler could produce. The argv therefore records
 * the identity, opt, and defines in the output filename so
 * {@code bsim_list_corpus} still names the provenance.
 */
public final class ReferenceBuild {

    /** gcc-arm default when {@code arch_flags} is blank. Other identities differ. */
    public static final String DEFAULT_ARCH_FLAGS = "-mcpu=cortex-m0plus -mthumb";
    public static final String DEFAULT_OPT = "-Os";
    public static final String DEFAULT_TOOLCHAIN = "gcc13-arm";
    /** Binaries for {@code gcc*-arm}. Other identities resolve through {@link ToolchainIdentity}. */
    public static final String CC = "arm-none-eabi-gcc";
    public static final String LD = "arm-none-eabi-ld";
    public static final String STRIP = "arm-none-eabi-strip";
    public static final String NM = "arm-none-eabi-nm";
    public static final String UPLOADS = "uploads";
    public static final int DEFAULT_PORT = 8092;
    /** Inline wait budget. Past this the MCP hop fabricates a -32603. */
    public static final int MAX_WAIT_SECONDS = 55;
    public static final int DEFAULT_WAIT_SECONDS = 45;
    /** Builder substitutes the snapshot directory for this token at compile. */
    public static final String SNAPSHOT_PLACEHOLDER = "<snapshot>";
    /** DWARF paths recorded as {@code /ref/<name>/...} so one Ghidra transform covers the corpus. */
    public static final String DEBUG_PATH_ROOT = "/ref";

    /**
     * Identities the compose file ships, used as {@link BuilderConfig} map keys
     * when {@code GHIDRA_MCP_BUILDER_URL} is a single host. Validation and
     * {@code builder_health} read the container's {@code GET /health}, not this
     * list.
     */
    public static final List<String> DEFAULT_TOOLCHAINS =
            List.of("gcc10-arm", "gcc12-arm", "gcc13-arm");

    static final Pattern SHA = Pattern.compile("^[0-9a-f]{7,40}$", Pattern.CASE_INSENSITIVE);
    static final Pattern OPT = Pattern.compile("^-?O[0-9sgz]$");
    private static final List<String> BRANCH_NAMES = List.of(
            "HEAD", "head", "main", "master", "develop", "dev", "trunk", "next");

    private ReferenceBuild() {}

    /** One compile job. Inputs are the whole interface. */
    public record Spec(
            String name,
            String repo,
            String ref,
            List<String> sources,
            String toolchain,
            String archFlags,
            String opt,
            List<String> defines,
            List<String> extraFlags,
            boolean stripDebug,
            String outputName,
            String mode,
            String framework,
            List<String> libraries,
            String board,
            Map<String, String> config
    ) {
        public boolean isFramework() {
            return FrameworkBuild.MODE_FRAMEWORK.equals(mode);
        }

        public String optLabel() {
            return optToLabel(opt);
        }

        public String resolvedOutputName() {
            if (outputName != null && !outputName.isBlank()) {
                String n = outputName.trim();
                return n.endsWith(".o") ? n : n + ".o";
            }
            return name + "-" + filenameSafe(ref) + "-" + toolchain + "-" + optLabel() + ".o";
        }

        public String artifactName(String library) {
            return FrameworkBuild.artifactFileName(name, library, ref, toolchain, opt, board);
        }

        public Path outputPath(Path fileRoot) {
            return fileRoot.resolve(UPLOADS).resolve(resolvedOutputName());
        }

        public Path uploadsDir(Path fileRoot) {
            return fileRoot.resolve(UPLOADS);
        }

        public ToolchainIdentity identity() {
            return ToolchainIdentity.parse(toolchain);
        }

        public List<String> cflags() {
            List<String> flags = new ArrayList<>();
            flags.add("-fno-common");
            flags.add("-ffunction-sections");
            flags.add("-fno-ident");
            flags.add("-frandom-seed=" + resolvedOutputName());
            flags.add("-g");
            String debugPrefix = debugPathPrefix(name);
            flags.add("-fdebug-prefix-map=" + SNAPSHOT_PLACEHOLDER + "=" + debugPrefix);
            flags.add("-ffile-prefix-map=" + SNAPSHOT_PLACEHOLDER + "=" + debugPrefix);
            flags.add("-fmacro-prefix-map=" + SNAPSHOT_PLACEHOLDER + "=" + debugPrefix);
            flags.add(normalizeOpt(opt));
            flags.addAll(splitFlags(archFlags));
            for (String d : defines) {
                flags.add(d.startsWith("-D") ? d : "-D" + d);
            }
            flags.addAll(extraFlags);
            flags.add("-I.");
            return flags;
        }

        /** Full compile steps as they will run in the builder. */
        public List<List<String>> commandLines(Path output) {
            if (isFramework()) {
                return FrameworkBuild.commandLines(this);
            }
            ToolchainIdentity id = identity();
            List<List<String>> steps = new ArrayList<>();
            List<String> cf = cflags();
            if (sources.size() == 1) {
                List<String> cc = new ArrayList<>();
                cc.add(id.cc());
                cc.add("-c");
                cc.addAll(cf);
                cc.add(sources.get(0));
                cc.add("-o");
                cc.add(output.toString());
                steps.add(cc);
            } else {
                List<String> objects = new ArrayList<>();
                for (int i = 0; i < sources.size(); i++) {
                    String obj = output.getFileName().toString() + "." + i + ".o";
                    List<String> cc = new ArrayList<>();
                    cc.add(id.cc());
                    cc.add("-c");
                    cc.addAll(cf);
                    cc.add(sources.get(i));
                    cc.add("-o");
                    cc.add(obj);
                    steps.add(cc);
                    objects.add(obj);
                }
                List<String> ld = new ArrayList<>();
                ld.add(id.ld());
                ld.add("-r");
                ld.add("--build-id=none");
                ld.add("-o");
                ld.add(output.toString());
                ld.addAll(objects);
                steps.add(ld);
            }
            if (stripDebug) {
                steps.add(List.of(id.strip(), "--strip-debug", output.toString()));
            }
            return steps;
        }

        public Map<String, Object> toBuilderRequest(Path output) {
            ToolchainIdentity id = identity();
            if (isFramework()) {
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("mode", FrameworkBuild.MODE_FRAMEWORK);
                req.put("name", name);
                req.put("repo", repo);
                req.put("ref", ref);
                req.put("framework", framework);
                req.put("libraries", libraries);
                req.put("board", board);
                req.put("config", config);
                req.put("opt", opt);
                req.put("defines", defines);
                req.put("extra_flags", extraFlags);
                req.put("cc", id.cc());
                req.put("ld", id.ld());
                req.put("nm", id.nm());
                req.put("strip_debug", false);
                req.put("recurse_submodules", true);
                req.put("toolchain", toolchain);
                req.put("output_dir", output.toString());
                return req;
            }
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("mode", FrameworkBuild.MODE_SOURCES);
            req.put("name", name);
            req.put("repo", repo);
            req.put("ref", ref);
            req.put("sources", sources);
            req.put("cflags", cflags());
            req.put("opt", opt);
            req.put("defines", defines);
            req.put("extra_flags", extraFlags);
            req.put("cc", id.cc());
            req.put("ld", id.ld());
            req.put("strip", id.strip());
            req.put("nm", id.nm());
            req.put("strip_debug", stripDebug);
            req.put("toolchain", toolchain);
            req.put("output", output.toString());
            return req;
        }
    }

    public static Spec parse(
            String name,
            String repo,
            String ref,
            Object sourcesRaw,
            String toolchain,
            String archFlags,
            String opt,
            Object definesRaw,
            Object extraFlagsRaw,
            boolean stripDebug,
            String outputName,
            List<String> knownToolchains
    ) {
        String n = requireName(name);
        String r = requireRepo(repo);
        String pinned = requireRef(ref);
        List<String> sources = requireSources(sourcesRaw);
        String tc = (toolchain == null || toolchain.isBlank()) ? DEFAULT_TOOLCHAIN : toolchain.trim();
        ToolchainIdentity identity;
        try {
            identity = ToolchainIdentity.parse(tc);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + "; available: " + knownToolchains);
        }
        if (!knownToolchains.contains(identity.id())) {
            throw new IllegalArgumentException(
                    "unknown toolchain '" + identity.id() + "'; available: " + knownToolchains);
        }
        String flags = (archFlags == null || archFlags.isBlank())
                ? identity.defaultArchFlags()
                : archFlags.trim();
        String o = (opt == null || opt.isBlank()) ? DEFAULT_OPT : opt.trim();
        if (!OPT.matcher(normalizeOpt(o)).matches()) {
            throw new IllegalArgumentException(
                    "opt must be an -O level such as -Os, -O2, -O3; got: " + o);
        }
        List<String> defines = stringList(definesRaw);
        List<String> extra = stringList(extraFlagsRaw);
        for (String f : extra) {
            if (f.indexOf('\n') >= 0 || f.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("extra_flags contains illegal control characters");
            }
        }
        if (outputName != null && !outputName.isBlank()) {
            requireFilename("output_name", outputName.trim());
        }
        return new Spec(n, r, pinned, sources, tc, flags, normalizeOpt(o), defines, extra,
                stripDebug, outputName,
                FrameworkBuild.MODE_SOURCES, "", List.of(), "", Map.of());
    }

    public static Spec parse(
            String name,
            String repo,
            String ref,
            Object sourcesRaw,
            String toolchain,
            String archFlags,
            String opt,
            Object definesRaw,
            Object extraFlagsRaw,
            boolean stripDebug,
            String outputName,
            List<String> knownToolchains,
            String mode,
            String framework,
            Object librariesRaw,
            String board,
            Object configRaw
    ) {
        return parse(name, repo, ref, sourcesRaw, toolchain, archFlags, opt, definesRaw,
                extraFlagsRaw, stripDebug, outputName, knownToolchains,
                mode, framework, librariesRaw, board, configRaw, null);
    }

    public static Spec parse(
            String name,
            String repo,
            String ref,
            Object sourcesRaw,
            String toolchain,
            String archFlags,
            String opt,
            Object definesRaw,
            Object extraFlagsRaw,
            boolean stripDebug,
            String outputName,
            List<String> knownToolchains,
            String mode,
            String framework,
            Object librariesRaw,
            String board,
            Object configRaw,
            List<String> knownFrameworks
    ) {
        String resolvedMode = FrameworkBuild.requireMode(mode);
        if (FrameworkBuild.MODE_SOURCES.equals(resolvedMode)) {
            Spec base = parse(name, repo, ref, sourcesRaw, toolchain, archFlags, opt, definesRaw,
                    extraFlagsRaw, stripDebug, outputName, knownToolchains);
            return new Spec(base.name(), base.repo(), base.ref(), base.sources(), base.toolchain(),
                    base.archFlags(), base.opt(), base.defines(), base.extraFlags(),
                    base.stripDebug(), base.outputName(),
                    resolvedMode, "", List.of(), "", Map.of());
        }
        String n = requireName(name);
        String r = requireRepo(repo);
        String pinned = requireRef(ref);
        String fw = FrameworkBuild.requireFramework(framework, resolvedMode, knownFrameworks);
        List<String> libraries = FrameworkBuild.requireLibraries(librariesRaw, resolvedMode);
        String b = FrameworkBuild.requireBoard(board);
        Map<String, String> config = FrameworkBuild.stringMap(configRaw);
        String tc = (toolchain == null || toolchain.isBlank()) ? DEFAULT_TOOLCHAIN : toolchain.trim();
        ToolchainIdentity identity;
        try {
            identity = ToolchainIdentity.parse(tc);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + "; available: " + knownToolchains);
        }
        if (!knownToolchains.contains(identity.id())) {
            throw new IllegalArgumentException(
                    "unknown toolchain '" + identity.id() + "'; available: " + knownToolchains);
        }
        String flags = (archFlags == null || archFlags.isBlank())
                ? identity.defaultArchFlags()
                : archFlags.trim();
        String o = (opt == null || opt.isBlank()) ? DEFAULT_OPT : opt.trim();
        if (!OPT.matcher(normalizeOpt(o)).matches()) {
            throw new IllegalArgumentException(
                    "opt must be an -O level such as -Os, -O2, -O3; got: " + o);
        }
        List<String> defines = stringList(definesRaw);
        List<String> extra = stringList(extraFlagsRaw);
        for (String f : extra) {
            if (f.indexOf('\n') >= 0 || f.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("extra_flags contains illegal control characters");
            }
        }
        if (outputName != null && !outputName.isBlank()) {
            requireFilename("output_name", outputName.trim());
        }
        return new Spec(n, r, pinned, List.of(), tc, flags, normalizeOpt(o), defines, extra,
                false, outputName, resolvedMode, fw, libraries, b, config);
    }

    public static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name is required (corpus entry, e.g. littlefs)");
        }
        String n = name.trim();
        requireFilename("name", n);
        if (n.startsWith("-")) {
            throw new IllegalArgumentException("name must not start with '-' (looks like a flag)");
        }
        return n;
    }

    static void requireFilename(String label, String name) {
        if (name.isEmpty()) {
            throw new IllegalArgumentException(label + " must not be empty");
        }
        if (name.contains("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) {
            throw new IllegalArgumentException(label + " must be a filename, not a path: " + name);
        }
    }

    public static String requireRepo(String repo) {
        if (repo == null || repo.isBlank()) {
            throw new IllegalArgumentException("repo is required (https git URL)");
        }
        String r = repo.trim();
        if (r.indexOf('\n') >= 0 || r.indexOf('\r') >= 0 || r.indexOf('\0') >= 0 || r.indexOf(' ') >= 0) {
            throw new IllegalArgumentException("repo contains illegal characters");
        }
        String lower = r.toLowerCase(Locale.ROOT);
        if (lower.startsWith("file:")) {
            throw new IllegalArgumentException("repo must be a git URL, not a local file: path");
        }
        boolean ok = lower.startsWith("https://") || lower.startsWith("git://")
                || lower.startsWith("git@") || lower.startsWith("ssh://");
        if (!ok) {
            throw new IllegalArgumentException("repo must be an https://, git://, ssh://, or git@ URL");
        }
        return r;
    }

    public static String requireRef(String ref) {
        if (ref == null || ref.isBlank()) {
            throw new IllegalArgumentException(
                    "ref is required (a tag or commit SHA, not a branch)");
        }
        String value = ref.trim();
        if (value.startsWith("-")) {
            throw new IllegalArgumentException("ref must not start with '-' (looks like a flag)");
        }
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("ref contains illegal control characters");
        }
        if (value.startsWith("refs/heads/") || BRANCH_NAMES.contains(value)) {
            throw new IllegalArgumentException(
                    "ref '" + value + "' is a branch name; pin a tag or commit SHA so the "
                            + "corpus entry can be reproduced");
        }
        if (value.contains("/") && !SHA.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "ref '" + value + "' looks like a branch (contains '/'); pin a tag or commit SHA");
        }
        return value;
    }

    public static List<String> requireSources(Object raw) {
        List<String> sources = stringList(raw);
        if (sources.isEmpty()) {
            throw new IllegalArgumentException("sources is required (e.g. [\"lfs.c\"])");
        }
        for (String src : sources) {
            Path p = Path.of(src);
            if (src.startsWith("/") || src.startsWith("\\") || src.startsWith("-")) {
                throw new IllegalArgumentException(
                        "source '" + src + "' must be a relative path inside the repo");
            }
            for (Path part : p) {
                if (part.toString().equals("..")) {
                    throw new IllegalArgumentException(
                            "source '" + src + "' must not contain '..'");
                }
            }
        }
        return sources;
    }

    public static String normalizeOpt(String opt) {
        String o = opt.trim();
        if (o.startsWith("-")) return o;
        return "-" + o;
    }

    public static String optToLabel(String opt) {
        String n = normalizeOpt(opt);
        return n.startsWith("-") ? n.substring(1) : n;
    }

    public static String filenameSafe(String ref) {
        return ref.replaceAll("[^A-Za-z0-9._-]+", "_");
    }

    /** Recorded DWARF prefix for a corpus entry, e.g. {@code /ref/littlefs}. */
    public static String debugPathPrefix(String name) {
        String n = filenameSafe(name == null ? "" : name.trim());
        if (n.isEmpty()) n = "unnamed";
        return DEBUG_PATH_ROOT + "/" + n;
    }

    public static List<String> splitFlags(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) return out;
        StringBuilder cur = new StringBuilder();
        boolean inQuote = false;
        char q = 0;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (inQuote) {
                if (c == q) {
                    inQuote = false;
                } else {
                    cur.append(c);
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                inQuote = true;
                q = c;
                continue;
            }
            if (Character.isWhitespace(c)) {
                if (cur.length() > 0) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
                continue;
            }
            cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    public static List<String> stringList(Object raw) {
        if (raw == null) return List.of();
        if (raw instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) {
                if (o == null) continue;
                String s = String.valueOf(o).trim();
                if (!s.isEmpty()) out.add(s);
            }
            return out;
        }
        String s = String.valueOf(raw).trim();
        if (s.isEmpty() || "[]".equals(s)) return List.of();
        if (s.startsWith("[")) {
            try {
                JsonElement el = JsonParser.parseString(s);
                if (el.isJsonArray()) {
                    JsonArray arr = el.getAsJsonArray();
                    List<String> out = new ArrayList<>();
                    for (JsonElement item : arr) {
                        if (item == null || item.isJsonNull()) continue;
                        String v = item.isJsonPrimitive()
                                ? item.getAsString().trim()
                                : item.toString().trim();
                        if (!v.isEmpty()) out.add(v);
                    }
                    return out;
                }
            } catch (Exception ignored) {
                // fall through to comma-separated
            }
        }
        List<String> out = new ArrayList<>();
        for (String part : s.split(",")) {
            String t = part.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    public static Map<String, URI> urlsForSingleHost(URI url) {
        Map<String, URI> urls = new LinkedHashMap<>();
        for (String id : DEFAULT_TOOLCHAINS) {
            urls.put(id, url);
        }
        return urls;
    }

    public static Map<String, URI> defaultToolchainUrls() {
        return urlsForSingleHost(URI.create("http://ghidra-builder:" + DEFAULT_PORT));
    }

    /**
     * {@code gcc13-arm:http://ghidra-builder:8092,gcc12-arm:http://host:8092}.
     * Split on the first colon so the URL may itself contain colons; identity
     * keys contain hyphens, not colons.
     */
    public static Map<String, URI> parseToolchainUrls(String raw) {
        if (raw == null || raw.isBlank()) return defaultToolchainUrls();
        Map<String, URI> urls = new LinkedHashMap<>();
        for (String part : raw.split(",")) {
            String item = part.trim();
            if (item.isEmpty()) continue;
            int colon = item.indexOf(':');
            if (colon <= 0 || colon == item.length() - 1) {
                throw new IllegalArgumentException(
                        "GHIDRA_MCP_BUILDER_URLS entries must be toolchain:url, got: " + item);
            }
            String key = item.substring(0, colon).trim();
            String url = item.substring(colon + 1).trim();
            urls.put(key, URI.create(url));
        }
        return urls.isEmpty() ? defaultToolchainUrls() : urls;
    }

    public static BuilderConfig fromEnv() {
        String root = System.getenv("GHIDRA_MCP_FILE_ROOT");
        Path fileRoot = (root == null || root.isBlank()) ? null : Path.of(root);
        String token = System.getenv("GHIDRA_MCP_AUTH_TOKEN");
        String single = System.getenv("GHIDRA_MCP_BUILDER_URL");
        Map<String, URI> urls = (single != null && !single.isBlank())
                ? urlsForSingleHost(URI.create(single.trim()))
                : parseToolchainUrls(System.getenv("GHIDRA_MCP_BUILDER_URLS"));
        return new BuilderConfig(urls, fileRoot, token == null ? "" : token,
                Duration.ofSeconds(120));
    }

    public record BuilderConfig(
            Map<String, URI> toolchainUrls,
            Path fileRoot,
            String authToken,
            Duration timeout
    ) {
        public List<String> knownToolchains() {
            return List.copyOf(toolchainUrls.keySet());
        }

        /**
         * One builder holds every identity. Map keys are how compose used to
         * name per-GCC URLs, not a gate: an identity the container just grew
         * uses the shared URL. Distinct URLs (legacy {@code BUILDER_URLS})
         * still require an exact key.
         */
        public URI urlFor(String toolchain) {
            URI uri = toolchainUrls.get(toolchain);
            if (uri != null) return uri;
            URI shared = sharedBuilderUrl();
            if (shared != null) return shared;
            throw new IllegalArgumentException(
                    "unknown toolchain '" + toolchain + "'; available: " + knownToolchains());
        }

        URI sharedBuilderUrl() {
            URI first = null;
            for (URI u : toolchainUrls.values()) {
                if (u == null) continue;
                if (first == null) {
                    first = u;
                } else if (!first.equals(u)) {
                    return null;
                }
            }
            return first;
        }
    }

    /**
     * {@code GET /health} from the builder. {@code stubs} is null when the
     * field was omitted (older image); callers then scan local stub dirs.
     */
    public record Inventory(List<String> identities, List<String> stubs) {
        public static Inventory fromHealth(Map<String, Object> body) {
            List<String> identities = stringNames(body == null ? null : body.get("identities"));
            List<String> stubs = (body != null && body.containsKey("stubs"))
                    ? stringNames(body.get("stubs"))
                    : null;
            return new Inventory(List.copyOf(identities), stubs);
        }
    }

    static List<String> stringNames(Object raw) {
        if (!(raw instanceof List<?> list)) return List.of();
        List<String> out = new ArrayList<>();
        for (Object o : list) {
            if (o == null) continue;
            String s = String.valueOf(o).trim();
            if (!s.isEmpty()) out.add(s);
        }
        return out;
    }
}
