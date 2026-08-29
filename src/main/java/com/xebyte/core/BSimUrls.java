package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Locale;
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
}
