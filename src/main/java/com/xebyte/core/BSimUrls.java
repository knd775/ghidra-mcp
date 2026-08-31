package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validation and path helpers for BSim / Ghidra URLs passed into the CLI wrapper.
 *
 * <p>User-controlled strings become process arguments. Reject anything that
 * could be interpreted as an extra flag. {@code file:} URLs are confined to
 * {@code GHIDRA_MCP_BSIM_ROOT} when that env var is set. Network URLs
 * ({@code postgresql://}, {@code elastic://}, {@code https://}) must match
 * {@code GHIDRA_MCP_BSIM_URLS} — an allowlist of host plus database. That
 * check is fail-closed: an unset allowlist does not silently permit an
 * arbitrary outbound connection from a tool an agent can call.
 */
public final class BSimUrls {

    public static final Set<String> CONFIG_TEMPLATES = Set.of(
            "large_32", "medium_32", "medium_64", "medium_cpool", "medium_nosize");

    /** Display order for {@code bsim_list_databases}. */
    public static final List<String> CONFIG_TEMPLATE_ORDER = List.of(
            "large_32", "medium_32", "medium_64", "medium_cpool", "medium_nosize");

    private static final Pattern BSIM_URL = Pattern.compile(
            "^(file:|postgresql://|elastic://|https://).+", Pattern.CASE_INSENSITIVE);
    private static final Pattern GHIDRA_URL = Pattern.compile(
            "^ghidra:/.+", Pattern.CASE_INSENSITIVE);

    /** Test-only. {@code null} means read the real environment. Blank means unset. */
    static volatile String allowlistOverride;
    static volatile String rootOverride;
    static volatile String userOverride;
    static volatile String passwordOverride;
    static volatile String templatesOverride;

    private BSimUrls() {}

    public static String requireBsimUrl(String dbUrl) {
        String url = requireToken("db_url", dbUrl);
        if (!BSIM_URL.matcher(url).matches()) {
            throw new IllegalArgumentException(
                    "db_url must be file:/<path>/<db>, postgresql://..., elastic://..., or https://...");
        }
        rejectPasswordInUrl(url);
        confineFileUrl(url);
        confineNetworkUrl(url);
        return injectConfiguredUser(url);
    }

    public static String requireGhidraUrl(String source) {
        String url = requireToken("source", source);
        if (!GHIDRA_URL.matcher(url).matches()) {
            throw new IllegalArgumentException(
                    "source must be a ghidraURL: ghidra://host[:port]/repo[/folder] "
                            + "or ghidra:/<localdir>/<project>[?/<folder>]");
        }
        return url;
    }

    public static boolean looksLikeGhidraUrl(String s) {
        return s != null && GHIDRA_URL.matcher(s.trim()).matches();
    }

    public static boolean isServerGhidraUrl(String s) {
        return s != null && s.toLowerCase(Locale.ROOT).startsWith("ghidra://");
    }

    public static boolean isFileUrl(String s) {
        return s != null && s.toLowerCase(Locale.ROOT).startsWith("file:");
    }

    public static boolean isPostgresUrl(String s) {
        return s != null && s.toLowerCase(Locale.ROOT).startsWith("postgresql://");
    }

    public static boolean isNetworkUrl(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase(Locale.ROOT);
        return lower.startsWith("postgresql://")
                || lower.startsWith("elastic://")
                || lower.startsWith("https://");
    }

    /**
     * Server-bound {@code ghidra://} ingest needs a password the spawned
     * {@code bsim} JVM can actually use (it cannot pop the GUI prompt).
     * Returns an error naming {@code GHIDRA_SERVER_PASSWORD}, or {@code null}
     * when the source is not a server URL or a credential is already configured.
     */
    public static String missingServerCredential(String source) {
        if (!isServerGhidraUrl(source)) return null;
        if (GhidraMCPAuthInitializer.hasPassword()) return null;
        String password = System.getenv("GHIDRA_SERVER_PASSWORD");
        if (password == null || password.isBlank()) {
            password = System.getenv("GHIDRA_PASS");
        }
        if (password != null && !password.isBlank()) return null;
        return "source is a ghidra:// server URL, but GHIDRA_SERVER_PASSWORD is not set. "
                + "The spawned bsim process cannot prompt for a password; set "
                + "GHIDRA_SERVER_PASSWORD (and GHIDRA_SERVER_USER) so generatesigs "
                + "can read the repository.";
    }

    /**
     * PostgreSQL BSim needs a password the spawned JVM can use. Ghidra's
     * client has no authenticator in a stock helper JVM unless we feed the
     * password (stdin for {@code bsim}, env for {@code BSim_McpQuery}).
     */
    public static String missingPostgresCredential(String dbUrl) {
        if (!isPostgresUrl(dbUrl)) return null;
        if (resolvedBsimPassword() != null) return null;
        return "db_url is a postgresql:// URL, but GHIDRA_MCP_BSIM_PASSWORD is not set. "
                + "BSim PostgreSQL credentials are not the Ghidra Server login; set "
                + "GHIDRA_MCP_BSIM_PASSWORD (and GHIDRA_MCP_BSIM_USER) in the environment.";
    }

    public static String requireConfigTemplate(String template) {
        String t = requireToken("config_template", template);
        if (!CONFIG_TEMPLATES.contains(t)) {
            throw new IllegalArgumentException(
                    "config_template must be one of " + CONFIG_TEMPLATES + ", got: " + t);
        }
        return t;
    }

    /**
     * Pointer size implied by a config template. {@code 0} means the template
     * is size-agnostic ({@code medium_nosize}, {@code medium_cpool}).
     */
    public static int templatePointerBits(String template) {
        if (template == null) return -1;
        return switch (template) {
            case "large_32", "medium_32" -> 32;
            case "medium_64" -> 64;
            case "medium_nosize", "medium_cpool" -> 0;
            default -> -1;
        };
    }

    /**
     * Architecture string size in bits, or {@code -1} if unknown.
     * Ghidra language IDs look like {@code ARM:LE:32:Cortex}.
     */
    public static int archPointerBits(String arch) {
        if (arch == null || arch.isEmpty()) return -1;
        String[] parts = arch.split(":");
        if (parts.length >= 3) {
            try {
                return Integer.parseInt(parts[2]);
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    public static File fileUrlToPath(String fileUrl) {
        if (fileUrl == null || !fileUrl.toLowerCase(Locale.ROOT).startsWith("file:")) {
            throw new IllegalArgumentException("Not a file: URL: " + fileUrl);
        }
        URI uri;
        try {
            uri = URI.create(fileUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Not a file: URL: " + fileUrl);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            path = uri.getSchemeSpecificPart();
        }
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Not a file: URL: " + fileUrl);
        }
        // file:///C:/... → /C:/... → C:/...
        if (path.length() >= 3 && path.charAt(0) == '/' && Character.isLetter(path.charAt(1))
                && path.charAt(2) == ':') {
            path = path.substring(1);
        }
        return new File(path);
    }

    public static String bsimRootEnv() {
        return envOrOverride(rootOverride, "GHIDRA_MCP_BSIM_ROOT");
    }

    public static String bsimAllowlistEnv() {
        return envOrOverride(allowlistOverride, "GHIDRA_MCP_BSIM_URLS");
    }

    public static String resolvedBsimUser() {
        return envOrOverride(userOverride, "GHIDRA_MCP_BSIM_USER");
    }

    public static String resolvedBsimPassword() {
        return envOrOverride(passwordOverride, "GHIDRA_MCP_BSIM_PASSWORD");
    }

    public static String bsimTemplatesEnv() {
        return envOrOverride(templatesOverride, "GHIDRA_MCP_BSIM_TEMPLATES");
    }

    static String envOrOverride(String override, String name) {
        if (override != null) {
            return override.isBlank() ? null : override.trim();
        }
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) return null;
        return raw.trim();
    }

    static void confineFileUrl(String url) {
        if (!url.toLowerCase(Locale.ROOT).startsWith("file:")) return;
        String root = bsimRootEnv();
        if (root == null) return;
        File target = fileUrlToPath(url);
        File rootDir = new File(root);
        try {
            Path targetCanon = target.getCanonicalFile().toPath().toAbsolutePath().normalize();
            Path rootCanon = rootDir.getCanonicalFile().toPath().toAbsolutePath().normalize();
            if (!targetCanon.startsWith(rootCanon)) {
                throw new IllegalArgumentException(
                        "file: db_url must resolve under GHIDRA_MCP_BSIM_ROOT ("
                                + rootCanon + "), got: " + targetCanon);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot resolve file: URL: " + e.getMessage());
        }
    }

    static void confineNetworkUrl(String url) {
        if (!isNetworkUrl(url)) return;
        List<String> allowed = parseAllowlist(bsimAllowlistEnv());
        if (allowed.isEmpty()) {
            throw new IllegalArgumentException(
                    "network db_url is not allowed: GHIDRA_MCP_BSIM_URLS is not set. "
                            + "Configure an allowlist of BSim URLs (host plus database name). "
                            + "file: URLs still require GHIDRA_MCP_BSIM_ROOT when that is set. "
                            + "got: " + stripUserinfo(url));
        }
        String key = canonicalNetworkKey(url);
        for (String candidate : allowed) {
            if (key.equals(canonicalNetworkKey(candidate))) return;
        }
        throw new IllegalArgumentException(
                "db_url is not on GHIDRA_MCP_BSIM_URLS (configured: "
                        + String.join(", ", allowed) + "). got: " + stripUserinfo(url));
    }

    static void rejectPasswordInUrl(String url) {
        if (!isNetworkUrl(url)) return;
        URI uri = parseUri(url);
        String userInfo = uri.getUserInfo();
        if (userInfo != null && userInfo.contains(":")) {
            throw new IllegalArgumentException(
                    "db_url must not include a password. Set GHIDRA_MCP_BSIM_PASSWORD "
                            + "(it is not the Ghidra Server login) instead of putting credentials "
                            + "in a tool argument.");
        }
    }

    /** Insert {@code GHIDRA_MCP_BSIM_USER} into a postgres URL that has no userinfo. */
    public static String injectConfiguredUser(String url) {
        if (!isPostgresUrl(url)) return url;
        URI uri = parseUri(url);
        if (uri.getUserInfo() != null && !uri.getUserInfo().isBlank()) return url;
        String user = resolvedBsimUser();
        if (user == null) return url;
        requireToken("GHIDRA_MCP_BSIM_USER", user);
        String rest = url.substring("postgresql://".length());
        return "postgresql://" + user + "@" + rest;
    }

    static List<String> parseAllowlist(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) return out;
        for (String part : raw.split(",")) {
            String url = part.trim();
            if (url.isEmpty()) continue;
            out.add(url);
        }
        return out;
    }

    static String canonicalNetworkKey(String url) {
        URI uri = parseUri(url);
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("db_url is missing a scheme: " + url);
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException(
                    "db_url must include a host (postgresql://<host>/<database>): " + stripUserinfo(url));
        }
        int port = uri.getPort();
        if (port < 0) port = defaultPort(scheme);
        String db = databaseName(uri);
        if (db.isEmpty()) {
            throw new IllegalArgumentException(
                    "db_url must include a database name (postgresql://<host>/<database>): "
                            + stripUserinfo(url));
        }
        return scheme + "\0" + host.toLowerCase(Locale.ROOT) + "\0" + port + "\0" + db;
    }

    static int defaultPort(String scheme) {
        return switch (scheme) {
            case "postgresql" -> 5432;
            case "elastic" -> 9200;
            case "https" -> 443;
            default -> -1;
        };
    }

    public static String databaseName(String url) {
        if (isFileUrl(url)) {
            File path = fileUrlToPath(url);
            String name = path.getName();
            return name == null ? "" : name;
        }
        return databaseName(parseUri(url));
    }

    static String databaseName(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isBlank()) return "";
        while (path.startsWith("/")) path = path.substring(1);
        while (path.endsWith("/")) path = path.substring(0, path.length() - 1);
        int slash = path.indexOf('/');
        return slash < 0 ? path : path.substring(0, slash);
    }

    static URI parseUri(String url) {
        try {
            return URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("db_url is not a valid URL: " + url);
        }
    }

    static String stripUserinfo(String url) {
        if (url == null) return "";
        int scheme = url.indexOf("://");
        if (scheme < 0) return url;
        int at = url.indexOf('@', scheme + 3);
        if (at < 0) return url;
        return url.substring(0, scheme + 3) + url.substring(at + 1);
    }

    public static boolean argsContainFileUrl(List<String> args) {
        if (args == null) return false;
        for (String a : args) {
            if (isFileUrl(a)) return true;
        }
        return false;
    }

    public static boolean argsContainPostgresUrl(List<String> args) {
        if (args == null) return false;
        for (String a : args) {
            if (isPostgresUrl(a)) return true;
        }
        return false;
    }

    public static String requireToken(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.startsWith("-")) {
            throw new IllegalArgumentException(name + " must not start with '-' (looks like a flag)");
        }
        if (trimmed.indexOf('\n') >= 0 || trimmed.indexOf('\r') >= 0 || trimmed.indexOf('\0') >= 0) {
            throw new IllegalArgumentException(name + " contains illegal control characters");
        }
        return trimmed;
    }

    /** Unique, insertion-ordered pointer sizes from a set of architecture strings. */
    public static Set<Integer> uniqueArchSizes(Iterable<String> archs) {
        Set<Integer> sizes = new LinkedHashSet<>();
        if (archs == null) return sizes;
        for (String a : archs) {
            int bits = archPointerBits(a);
            if (bits > 0) sizes.add(bits);
        }
        return sizes;
    }

    /** Sidecar written next to an H2 {@code file:} database: {@code <name>.ghidra-mcp.json}. */
    public static Path databaseSidecar(String fileUrl) {
        File path = fileUrlToPath(fileUrl);
        return Path.of(path.getPath() + ".ghidra-mcp.json");
    }

    /** Sidecar path for file: or, when ROOT is set, {@code <root>/<dbname>.ghidra-mcp.json}. */
    public static Path sidecarPath(String dbUrl) {
        if (dbUrl == null) return null;
        if (isFileUrl(dbUrl)) return databaseSidecar(dbUrl);
        String root = bsimRootEnv();
        if (root == null) return null;
        String name = databaseName(dbUrl);
        if (name.isEmpty()) return null;
        return Path.of(root, name + ".ghidra-mcp.json");
    }

    public static void writeDatabaseSidecar(String dbUrl, String configTemplate) throws IOException {
        Path sidecar = sidecarPath(dbUrl);
        if (sidecar == null) return;
        Path parent = sidecar.getParent();
        if (parent != null) Files.createDirectories(parent);
        Map<String, Object> body = readSidecarMap(dbUrl);
        if (body == null) body = new LinkedHashMap<>();
        body.put("db_url", dbUrl);
        body.put("config_template", configTemplate);
        Files.writeString(sidecar, JsonHelper.toJson(body) + "\n", StandardCharsets.UTF_8);
    }

    /**
     * Record an ingested executable MD5 on the database sidecar so a manifest
     * runner can skip by MD5 without querying the database.
     */
    public static void recordIngestedMd5(String dbUrl, String md5) {
        if (md5 == null || md5.isBlank()) return;
        Path sidecar = sidecarPath(dbUrl);
        if (sidecar == null) return;
        try {
            Map<String, Object> body = readSidecarMap(dbUrl);
            if (body == null) body = new LinkedHashMap<>();
            body.put("db_url", dbUrl);
            if (!body.containsKey("config_template")) {
                String template = readSidecarTemplate(dbUrl);
                if (template != null) body.put("config_template", template);
            }
            List<String> md5s = new ArrayList<>();
            Object existing = body.get("ingested_md5s");
            if (existing instanceof List<?> list) {
                for (Object item : list) {
                    if (item != null) md5s.add(String.valueOf(item).toLowerCase(Locale.ROOT));
                }
            }
            String normalised = md5.trim().toLowerCase(Locale.ROOT);
            if (!md5s.contains(normalised)) md5s.add(normalised);
            body.put("ingested_md5s", md5s);
            Path parent = sidecar.getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.writeString(sidecar, JsonHelper.toJson(body) + "\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // Sidecar bookkeeping must not fail the ingest that already committed.
        }
    }

    static Map<String, Object> readSidecarMap(String dbUrl) {
        Path sidecar = sidecarPath(dbUrl);
        if (sidecar == null) return null;
        try {
            if (!Files.isRegularFile(sidecar)) return null;
            return JsonHelper.parseJson(Files.readString(sidecar, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    /** {@code config_template} from the sidecar, or {@code null} if missing/unreadable. */
    public static String readSidecarTemplate(String dbUrl) {
        Path sidecar = sidecarPath(dbUrl);
        if (sidecar == null) return templateForDatabaseName(databaseName(dbUrl));
        try {
            if (!Files.isRegularFile(sidecar)) {
                return templateForDatabaseName(databaseName(dbUrl));
            }
            Map<String, Object> parsed = JsonHelper.parseJson(
                    Files.readString(sidecar, StandardCharsets.UTF_8));
            if (parsed == null) return templateForDatabaseName(databaseName(dbUrl));
            Object t = parsed.get("config_template");
            return t == null ? templateForDatabaseName(databaseName(dbUrl)) : String.valueOf(t).trim();
        } catch (Exception e) {
            return templateForDatabaseName(databaseName(dbUrl));
        }
    }

    static String templateForDatabaseName(String name) {
        if (name == null || name.isBlank()) return null;
        String raw = bsimTemplatesEnv();
        if (raw == null) return null;
        for (String part : raw.split(",")) {
            String item = part.trim();
            int colon = item.indexOf(':');
            if (colon <= 0) continue;
            if (name.equals(item.substring(0, colon).trim())) {
                String t = item.substring(colon + 1).trim();
                return t.isEmpty() ? null : t;
            }
        }
        return null;
    }

    public static String pointerSizeQueryWarning(int programBits, String configTemplate) {
        int corpusBits = templatePointerBits(configTemplate);
        if (programBits <= 0 || corpusBits <= 0 || programBits == corpusBits) return null;
        return "This program is " + programBits + "-bit but the database template is "
                + configTemplate + " (" + corpusBits + "-bit). Ghidra will accept this "
                + "mismatch and silently degrade confidence. Query a matching sized "
                + "template, or a medium_nosize database (which accepts mixed pointer "
                + "sizes by design).";
    }

    /**
     * Refuse ingest into a sized template ({@code medium_32} / {@code medium_64}
     * / {@code large_32}) when the source pointer size disagrees. Gate on the
     * config template, not on whatever is already in the corpus:
     * {@code medium_nosize} accepts mixed sizes, and Ghidra's {@code generatesigs}
     * will otherwise accept a mismatch and quietly degrade results.
     *
     * @return an error message, or {@code null} if ingest may proceed
     */
    public static String pointerSizeIngestError(int srcBits, String languageId, String template) {
        int templateBits = templatePointerBits(template);
        if (templateBits <= 0 || srcBits <= 0 || templateBits == srcBits) return null;
        String lang = (languageId == null || languageId.isBlank()) ? "unknown" : languageId;
        return "source language is " + srcBits + "-bit (" + lang
                + ") but the database template is " + template + " (" + templateBits
                + "-bit). Ghidra's generatesigs will accept this mismatch and silently "
                + "degrade results. medium_nosize accepts mixed pointer sizes; "
                + "medium_32 / medium_64 / large_32 do not.";
    }

    /**
     * H2 databases under a BSim root: {@code name.mv.db} plus any sidecar-only
     * entries from {@code bsim_create_db}.
     */
    public static List<Map<String, Object>> listFileDatabases(Path root) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (root == null || !Files.isDirectory(root)) return out;
        LinkedHashSet<String> names = new LinkedHashSet<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(root)) {
            for (Path child : stream) {
                String fn = child.getFileName().toString();
                if (fn.endsWith(".mv.db")) {
                    names.add(fn.substring(0, fn.length() - ".mv.db".length()));
                } else if (fn.endsWith(".ghidra-mcp.json")) {
                    names.add(fn.substring(0, fn.length() - ".ghidra-mcp.json".length()));
                }
            }
        } catch (IOException ignored) {
            return out;
        }
        for (String name : names) {
            Map<String, Object> row = new LinkedHashMap<>();
            Path dbPath = root.resolve(name);
            String url = "file:" + dbPath.toAbsolutePath().normalize();
            row.put("name", name);
            row.put("db_url", url);
            row.put("backend", "h2");
            row.put("path", dbPath.toString());
            row.put("config_template", readSidecarTemplate(url));
            row.put("present", Files.isRegularFile(root.resolve(name + ".mv.db")));
            out.add(row);
        }
        return out;
    }

    /** Allowlisted network URLs, with template from sidecar or {@code GHIDRA_MCP_BSIM_TEMPLATES}. */
    public static List<Map<String, Object>> listAllowlistedDatabases() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String url : parseAllowlist(bsimAllowlistEnv())) {
            if (!isNetworkUrl(url)) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            String name = databaseName(url);
            row.put("name", name);
            row.put("db_url", url);
            row.put("backend", isPostgresUrl(url) ? "postgresql" : url.split(":", 2)[0]);
            row.put("config_template", readSidecarTemplate(url));
            out.add(row);
        }
        return out;
    }
}
