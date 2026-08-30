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
 * could be interpreted as an extra flag, and confine {@code file:} URLs to
 * {@code GHIDRA_MCP_BSIM_ROOT} when that env var is set.
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

    private BSimUrls() {}

    public static String requireBsimUrl(String dbUrl) {
        String url = requireToken("db_url", dbUrl);
        if (!BSIM_URL.matcher(url).matches()) {
            throw new IllegalArgumentException(
                    "db_url must be file:/<path>/<db>, postgresql://..., elastic://..., or https://...");
        }
        confineFileUrl(url);
        return url;
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
        String raw = System.getenv("GHIDRA_MCP_BSIM_ROOT");
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

    public static void writeDatabaseSidecar(String dbUrl, String configTemplate) throws IOException {
        if (dbUrl == null || !dbUrl.toLowerCase(Locale.ROOT).startsWith("file:")) return;
        Path sidecar = databaseSidecar(dbUrl);
        Path parent = sidecar.getParent();
        if (parent != null) Files.createDirectories(parent);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("db_url", dbUrl);
        body.put("config_template", configTemplate);
        Files.writeString(sidecar, JsonHelper.toJson(body) + "\n", StandardCharsets.UTF_8);
    }

    /** {@code config_template} from the sidecar, or {@code null} if missing/unreadable. */
    public static String readSidecarTemplate(String dbUrl) {
        if (dbUrl == null || !dbUrl.toLowerCase(Locale.ROOT).startsWith("file:")) return null;
        try {
            Path sidecar = databaseSidecar(dbUrl);
            if (!Files.isRegularFile(sidecar)) return null;
            Map<String, Object> parsed = JsonHelper.parseJson(
                    Files.readString(sidecar, StandardCharsets.UTF_8));
            if (parsed == null) return null;
            Object t = parsed.get("config_template");
            return t == null ? null : String.valueOf(t).trim();
        } catch (Exception e) {
            return null;
        }
    }

    public static String pointerSizeQueryWarning(int programBits, String configTemplate) {
        int corpusBits = templatePointerBits(configTemplate);
        if (programBits <= 0 || corpusBits <= 0 || programBits == corpusBits) return null;
        return "This program is " + programBits + "-bit but the database template is "
                + configTemplate + " (" + corpusBits + "-bit). 32-bit and 64-bit corpora "
                + "cannot share a database. Expect no useful matches. Query the matching "
                + "database (medium_32 / embedded for ARM firmware, medium_64 / userland "
                + "for x86-64).";
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
            row.put("path", dbPath.toString());
            row.put("config_template", readSidecarTemplate(url));
            row.put("present", Files.isRegularFile(root.resolve(name + ".mv.db")));
            out.add(row);
        }
        return out;
    }
}
