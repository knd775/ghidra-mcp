package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Restricted YAML (and JSON) reader for {@code docker/references.yaml}.
 *
 * <p>The manifest <em>is</em> the corpus definition. A matrix of toolchain × opt
 * expands to one {@link ReferenceBuild.Spec} per cell so nine littlefs objects
 * and twelve pico-sdk framework jobs are one reviewable document, not
 * twenty-one hand-written calls.
 */
public final class ReferenceManifest {

    private static final Gson GSON = new Gson();

    private ReferenceManifest() {}

    public static List<ReferenceBuild.Spec> load(Path path, List<String> knownToolchains)
            throws IOException {
        String text = Files.readString(path, StandardCharsets.UTF_8);
        return parse(text, knownToolchains);
    }

    public static List<ReferenceBuild.Spec> parse(String text, List<String> knownToolchains) {
        Object root = looksLikeJson(text) ? parseJson(text) : MiniYaml.parse(text);
        if (!(root instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("manifest root must be a mapping with 'references:'");
        }
        Object refs = map.get("references");
        if (!(refs instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException("manifest has no references:");
        }
        List<ReferenceBuild.Spec> jobs = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> entry)) {
                throw new IllegalArgumentException("each references: item must be a mapping");
            }
            jobs.addAll(expandEntry(asStringMap(entry), knownToolchains));
        }
        return jobs;
    }

    @SuppressWarnings("unchecked")
    static List<ReferenceBuild.Spec> expandEntry(Map<String, Object> entry, List<String> knownToolchains) {
        String name = string(entry, "name");
        String repo = string(entry, "repo");
        String ref = string(entry, "ref");
        Object sources = entry.get("sources");
        // Blank → identity default (gcc-arm vs clang-arm differ). Do not
        // inherit the gcc-arm flags onto a clang/xtensa/riscv cell.
        String archFlags = stringOr(entry, "arch_flags", "");
        boolean stripDebug = boolOr(entry, "strip_debug", true);
        String outputName = stringOr(entry, "output_name", "");
        Object defines = entry.get("defines");
        Object extra = entry.get("extra_flags");
        String mode = stringOr(entry, "mode", FrameworkBuild.MODE_SOURCES);
        String framework = stringOr(entry, "framework", "");
        Object libraries = entry.get("libraries");
        String board = stringOr(entry, "board", "");
        Object cmakeConfig = entry.get("config");

        Map<String, List<String>> matrix = matrixOf(entry.get("matrix"));
        if (matrix.isEmpty()) {
            String toolchain = stringOr(entry, "toolchain", ReferenceBuild.DEFAULT_TOOLCHAIN);
            String opt = stringOr(entry, "opt", ReferenceBuild.DEFAULT_OPT);
            return List.of(parseEntry(
                    name, repo, ref, sources, toolchain, archFlags, opt, defines, extra,
                    stripDebug, outputName, knownToolchains,
                    mode, framework, libraries, board, cmakeConfig));
        }

        // Fill missing axes from the entry-level defaults so a matrix of only
        // toolchain still compiles.
        matrix.putIfAbsent("toolchain", List.of(
                stringOr(entry, "toolchain", ReferenceBuild.DEFAULT_TOOLCHAIN)));
        matrix.putIfAbsent("opt", List.of(stringOr(entry, "opt", ReferenceBuild.DEFAULT_OPT)));
        if (FrameworkBuild.MODE_FRAMEWORK.equals(FrameworkBuild.requireMode(mode))
                && !board.isEmpty()) {
            matrix.putIfAbsent("board", List.of(board));
        }

        List<ReferenceBuild.Spec> jobs = new ArrayList<>();
        for (Map<String, String> cell : cartesian(matrix)) {
            String toolchain = cell.getOrDefault("toolchain",
                    stringOr(entry, "toolchain", ReferenceBuild.DEFAULT_TOOLCHAIN));
            String opt = cell.getOrDefault("opt", stringOr(entry, "opt", ReferenceBuild.DEFAULT_OPT));
            String arch = cell.getOrDefault("arch_flags", archFlags);
            String cellBoard = cell.getOrDefault("board", board);
            jobs.add(parseEntry(
                    name, repo, ref, sources, toolchain, arch, opt, defines, extra,
                    stripDebug, outputName, knownToolchains,
                    mode, framework, libraries, cellBoard, cmakeConfig));
        }
        return jobs;
    }

    private static ReferenceBuild.Spec parseEntry(
            String name, String repo, String ref, Object sources, String toolchain,
            String archFlags, String opt, Object defines, Object extra,
            boolean stripDebug, String outputName, List<String> knownToolchains,
            String mode, String framework, Object libraries, String board, Object cmakeConfig) {
        if (FrameworkBuild.MODE_FRAMEWORK.equals(FrameworkBuild.requireMode(mode))) {
            return ReferenceBuild.parse(
                    name, repo, ref, sources, toolchain, archFlags, opt, defines, extra,
                    stripDebug, outputName, knownToolchains,
                    mode, framework, libraries, board, cmakeConfig);
        }
        return ReferenceBuild.parse(
                name, repo, ref, sources, toolchain, archFlags, opt, defines, extra,
                stripDebug, outputName, knownToolchains);
    }

    static List<Map<String, String>> cartesian(Map<String, List<String>> matrix) {
        List<Map<String, String>> rows = new ArrayList<>();
        rows.add(new LinkedHashMap<>());
        for (Map.Entry<String, List<String>> e : matrix.entrySet()) {
            List<Map<String, String>> next = new ArrayList<>();
            for (Map<String, String> row : rows) {
                for (String val : e.getValue()) {
                    Map<String, String> copy = new LinkedHashMap<>(row);
                    copy.put(e.getKey(), val);
                    next.add(copy);
                }
            }
            rows = next;
        }
        return rows;
    }

    private static Map<String, List<String>> matrixOf(Object raw) {
        Map<String, List<String>> matrix = new LinkedHashMap<>();
        if (!(raw instanceof Map<?, ?> map)) return matrix;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            String key = String.valueOf(e.getKey());
            matrix.put(key, ReferenceBuild.stringList(e.getValue()));
        }
        return matrix;
    }

    private static Map<String, Object> asStringMap(Map<?, ?> entry) {
        Map<String, Object> out = new LinkedHashMap<>();
        entry.forEach((k, v) -> out.put(String.valueOf(k), v));
        return out;
    }

    private static String string(Map<String, Object> entry, String key) {
        Object v = entry.get(key);
        if (v == null || String.valueOf(v).isBlank()) {
            throw new IllegalArgumentException("references entry missing " + key);
        }
        return String.valueOf(v).trim();
    }

    private static String stringOr(Map<String, Object> entry, String key, String fallback) {
        Object v = entry.get(key);
        if (v == null || String.valueOf(v).isBlank()) return fallback;
        return String.valueOf(v).trim();
    }

    private static boolean boolOr(Map<String, Object> entry, String key, boolean fallback) {
        Object v = entry.get(key);
        if (v == null) return fallback;
        if (v instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(v));
    }

    private static boolean looksLikeJson(String text) {
        String t = text.stripLeading();
        return t.startsWith("{") || t.startsWith("[");
    }

    private static Object parseJson(String text) {
        return GSON.fromJson(text, new TypeToken<Map<String, Object>>() {}.getType());
    }

    /**
     * Indent-based subset: maps, list-of-maps, {@code [a, b]} flow sequences,
     * comments, unquoted scalars including {@code -Os}. Enough for the corpus
     * manifest; not a YAML implementation.
     */
    static final class MiniYaml {
        static Object parse(String text) {
            List<String> lines = new ArrayList<>();
            for (String raw : text.split("\n", -1)) {
                String stripped = stripComment(raw);
                if (stripped.isBlank()) continue;
                lines.add(rstrip(stripped));
            }
            return parseBlock(lines, 0, 0).value;
        }

        private static String stripComment(String raw) {
            boolean inQuote = false;
            char q = 0;
            for (int i = 0; i < raw.length(); i++) {
                char c = raw.charAt(i);
                if (inQuote) {
                    if (c == q) inQuote = false;
                    continue;
                }
                if (c == '"' || c == '\'') {
                    inQuote = true;
                    q = c;
                    continue;
                }
                if (c == '#' && (i == 0 || Character.isWhitespace(raw.charAt(i - 1)))) {
                    return raw.substring(0, i);
                }
            }
            return raw;
        }

        private static String rstrip(String s) {
            int i = s.length();
            while (i > 0 && Character.isWhitespace(s.charAt(i - 1))) i--;
            return s.substring(0, i);
        }

        private record Parsed(Object value, int nextIndex) {}

        private static Parsed parseBlock(List<String> lines, int index, int indent) {
            if (index >= lines.size()) return new Parsed(null, index);
            String first = lines.get(index);
            int ind = leadingSpaces(first);
            if (ind < indent) return new Parsed(null, index);
            if (ltrim(first).startsWith("- ")) {
                return parseList(lines, index, ind);
            }
            return parseMap(lines, index, ind);
        }

        private static Parsed parseMap(List<String> lines, int index, int indent) {
            Map<String, Object> map = new LinkedHashMap<>();
            int i = index;
            while (i < lines.size()) {
                String line = lines.get(i);
                int ind = leadingSpaces(line);
                if (ind < indent) break;
                if (ind > indent) {
                    throw new IllegalArgumentException("unexpected indent at: " + line.trim());
                }
                String body = ltrim(line);
                if (body.startsWith("- ")) {
                    throw new IllegalArgumentException("list item where a map key was expected: " + body);
                }
                int colon = splitKey(body);
                if (colon < 0) {
                    throw new IllegalArgumentException("expected key: value at: " + body);
                }
                String key = unquote(body.substring(0, colon).trim());
                String rest = body.substring(colon + 1).trim();
                i++;
                if (rest.isEmpty()) {
                    if (i < lines.size() && leadingSpaces(lines.get(i)) > indent) {
                        Parsed child = parseBlock(lines, i, indent + 2);
                        map.put(key, child.value);
                        i = child.nextIndex;
                    } else {
                        map.put(key, "");
                    }
                } else {
                    map.put(key, parseScalar(rest));
                }
            }
            return new Parsed(map, i);
        }

        private static Parsed parseList(List<String> lines, int index, int indent) {
            List<Object> list = new ArrayList<>();
            int i = index;
            while (i < lines.size()) {
                String line = lines.get(i);
                int ind = leadingSpaces(line);
                if (ind < indent) break;
                if (ind > indent) {
                    throw new IllegalArgumentException("unexpected indent at: " + line.trim());
                }
                String body = ltrim(line);
                if (!body.startsWith("- ")) {
                    break;
                }
                String rest = body.substring(2).trim();
                i++;
                if (rest.isEmpty()) {
                    Parsed child = parseBlock(lines, i, indent + 2);
                    list.add(child.value);
                    i = child.nextIndex;
                } else if (looksLikeKey(rest)) {
                    // `- name: littlefs` then possibly more keys at indent+2
                    Map<String, Object> item = new LinkedHashMap<>();
                    int colon = splitKey(rest);
                    String key = unquote(rest.substring(0, colon).trim());
                    String val = rest.substring(colon + 1).trim();
                    if (val.isEmpty()) {
                        Parsed child = parseBlock(lines, i, indent + 2);
                        item.put(key, child.value);
                        i = child.nextIndex;
                    } else {
                        item.put(key, parseScalar(val));
                    }
                    if (i < lines.size() && leadingSpaces(lines.get(i)) >= indent + 2
                            && !ltrim(lines.get(i)).startsWith("- ")) {
                        Parsed restMap = parseMap(lines, i, indent + 2);
                        if (restMap.value instanceof Map<?, ?> nested) {
                            nested.forEach((k, v) -> item.put(String.valueOf(k), v));
                        }
                        i = restMap.nextIndex;
                    }
                    list.add(item);
                } else {
                    list.add(parseScalar(rest));
                }
            }
            return new Parsed(list, i);
        }

        private static boolean looksLikeKey(String rest) {
            int colon = splitKey(rest);
            return colon > 0;
        }

        private static int splitKey(String body) {
            boolean inQuote = false;
            char q = 0;
            for (int i = 0; i < body.length(); i++) {
                char c = body.charAt(i);
                if (inQuote) {
                    if (c == q) inQuote = false;
                    continue;
                }
                if (c == '"' || c == '\'') {
                    inQuote = true;
                    q = c;
                    continue;
                }
                if (c == ':') {
                    if (i + 1 == body.length() || Character.isWhitespace(body.charAt(i + 1))) {
                        return i;
                    }
                }
            }
            return -1;
        }

        private static Object parseScalar(String raw) {
            if (raw.startsWith("[") && raw.endsWith("]")) {
                return parseFlowList(raw);
            }
            if ("true".equalsIgnoreCase(raw) || "false".equalsIgnoreCase(raw)) {
                return Boolean.parseBoolean(raw);
            }
            return unquote(raw);
        }

        private static List<String> parseFlowList(String raw) {
            String inner = raw.substring(1, raw.length() - 1).trim();
            if (inner.isEmpty()) return List.of();
            List<String> out = new ArrayList<>();
            StringBuilder cur = new StringBuilder();
            boolean inQuote = false;
            char q = 0;
            for (int i = 0; i < inner.length(); i++) {
                char c = inner.charAt(i);
                if (inQuote) {
                    if (c == q) inQuote = false;
                    else cur.append(c);
                    continue;
                }
                if (c == '"' || c == '\'') {
                    inQuote = true;
                    q = c;
                    continue;
                }
                if (c == ',') {
                    String t = cur.toString().trim();
                    if (!t.isEmpty()) out.add(unquote(t));
                    cur.setLength(0);
                    continue;
                }
                cur.append(c);
            }
            String t = cur.toString().trim();
            if (!t.isEmpty()) out.add(unquote(t));
            return out;
        }

        private static String unquote(String raw) {
            if (raw.length() >= 2) {
                char a = raw.charAt(0);
                char b = raw.charAt(raw.length() - 1);
                if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                    return raw.substring(1, raw.length() - 1);
                }
            }
            return raw;
        }

        private static int leadingSpaces(String s) {
            int n = 0;
            while (n < s.length() && s.charAt(n) == ' ') n++;
            return n;
        }

        private static String ltrim(String s) {
            int i = 0;
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
            return s.substring(i);
        }
    }
}
