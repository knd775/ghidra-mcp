package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Compare a live query extract against a corpus row. Returns evidence, never
 * a blended score: constants and strings are useful because they are
 * <em>legible</em>, and a second opaque number beside BSim confidence would
 * defeat that.
 *
 * <p>String comparison has three modes because {@code __FILE__} paths are the
 * most useful category and the one exact match loses: firmware carries the
 * developer's checkout, a {@code -fdebug-prefix-map} reference carries
 * {@code /ref/<name>/…}. Same file.
 */
public final class CorroborationEvidence {

    /**
     * A constant (or string) appearing in this fraction of corpus functions
     * or more is not distinctive. Marked, not dropped — sharing nothing
     * distinctive is itself informative.
     */
    public static final double DISTINCTIVE_FRACTION = 0.05;

    public enum StringNorm {
        OFF, BASENAME, AUTO;

        public static StringNorm parse(String raw) {
            if (raw == null || raw.isBlank() || "auto".equalsIgnoreCase(raw.trim())) {
                return AUTO;
            }
            String t = raw.trim().toLowerCase(Locale.ROOT);
            return switch (t) {
                case "off" -> OFF;
                case "basename" -> BASENAME;
                default -> throw new IllegalArgumentException(
                        "string_normalisation must be off, basename, or auto; got: " + raw);
            };
        }

        public String wire() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public record FunctionRow(
            String executableMd5,
            String executableName,
            String functionName,
            List<String> constants,
            List<String> strings,
            List<String> callees,
            boolean truncated) {

        public FunctionRow {
            executableMd5 = executableMd5 == null ? "" : executableMd5.toLowerCase(Locale.ROOT);
            executableName = executableName == null ? "" : executableName;
            functionName = functionName == null ? "" : functionName;
            constants = constants == null ? List.of() : List.copyOf(constants);
            strings = strings == null ? List.of() : List.copyOf(strings);
            callees = callees == null ? List.of() : List.copyOf(callees);
        }

        public static FunctionRow empty(String functionName) {
            return new FunctionRow("", "", functionName, List.of(), List.of(), List.of(), false);
        }
    }

    public interface Frequencies {
        int corpusFunctionCount();

        int constantFrequency(String constant);

        int stringFrequency(String string);
    }

    private CorroborationEvidence() {}

    public static boolean isDistinctive(int frequency, int corpusFunctions) {
        if (frequency <= 1) return true;
        if (corpusFunctions <= 0) return true;
        return ((double) frequency / (double) corpusFunctions) < DISTINCTIVE_FRACTION;
    }

    public static boolean looksLikePath(String s) {
        if (s == null || s.isEmpty()) return false;
        return s.indexOf('/') >= 0 || s.indexOf('\\') >= 0;
    }

    public static String basename(String s) {
        if (s == null || s.isEmpty()) return s;
        int slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
        return slash < 0 ? s : s.substring(slash + 1);
    }

    /**
     * Evidence map for one query/ref pair. Keys are fixed so callers can
     * depend on the shape; there is no score / rank / blend field.
     */
    public static Map<String, Object> compare(FunctionRow query, FunctionRow ref,
                                              Frequencies freq, StringNorm norm) {
        if (query == null) query = FunctionRow.empty("");
        if (ref == null) {
            return noEvidence(query.functionName(), "", "not_extracted",
                    List.of("No corroboration data for this executable; "
                            + "it was ingested before extraction existed"));
        }
        StringNorm mode = norm == null ? StringNorm.AUTO : norm;
        Frequencies frequencies = freq == null ? zeroFreq() : freq;
        int corpus = frequencies.corpusFunctionCount();

        Set<String> qConst = new LinkedHashSet<>(query.constants());
        Set<String> rConst = new LinkedHashSet<>(ref.constants());
        List<Map<String, Object>> sharedConstants = new ArrayList<>();
        List<String> queryOnlyConstants = new ArrayList<>();
        List<String> refOnlyConstants = new ArrayList<>();
        for (String c : qConst) {
            if (rConst.contains(c)) {
                sharedConstants.add(constantHit(c,
                        isDistinctive(frequencies.constantFrequency(c), corpus)));
            } else {
                queryOnlyConstants.add(c);
            }
        }
        for (String c : rConst) {
            if (!qConst.contains(c)) refOnlyConstants.add(c);
        }

        Set<String> usedRefStrings = new LinkedHashSet<>();
        List<Map<String, Object>> sharedStrings = new ArrayList<>();
        List<String> queryOnlyStrings = new ArrayList<>();
        int basenameMatches = 0;
        for (String qs : query.strings()) {
            StringHit hit = matchString(qs, ref.strings(), usedRefStrings, mode);
            if (hit == null) {
                queryOnlyStrings.add(qs);
            } else {
                if ("basename".equals(hit.match)) basenameMatches++;
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("value", hit.value);
                row.put("match", hit.match);
                row.put("query", hit.query);
                row.put("ref", hit.ref);
                row.put("distinctive",
                        isDistinctive(frequencies.stringFrequency(hit.ref), corpus)
                                || isDistinctive(frequencies.stringFrequency(hit.query), corpus));
                sharedStrings.add(row);
            }
        }
        List<String> refOnlyStrings = new ArrayList<>();
        for (String rs : ref.strings()) {
            if (!usedRefStrings.contains(rs)) refOnlyStrings.add(rs);
        }

        List<String> sharedCallees = new ArrayList<>();
        Set<String> rCallees = new LinkedHashSet<>(ref.callees());
        for (String c : query.callees()) {
            if (rCallees.contains(c)) sharedCallees.add(c);
        }

        List<String> notes = new ArrayList<>();
        notes.add(sharedConstants.size() + " of " + qConst.size() + " query constants shared");
        if (!sharedStrings.isEmpty()) {
            notes.add(sharedStrings.size() + " string"
                    + (sharedStrings.size() == 1 ? "" : "s")
                    + (basenameMatches > 0
                    ? " matched (" + basenameMatches + " on basename)"
                    : " matched"));
        }
        boolean anyDistinctive = false;
        for (Map<String, Object> c : sharedConstants) {
            if (Boolean.TRUE.equals(c.get("distinctive"))) anyDistinctive = true;
        }
        for (Map<String, Object> s : sharedStrings) {
            if (Boolean.TRUE.equals(s.get("distinctive"))) anyDistinctive = true;
        }
        if (!sharedConstants.isEmpty() && !anyDistinctive && sharedStrings.isEmpty()) {
            notes.add("nothing distinctive shared");
        }
        if (query.truncated() || ref.truncated()) {
            notes.add("one or both extracts were truncated");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("function", query.functionName());
        body.put("ref_function", ref.functionName());
        if (!ref.executableName().isEmpty()) body.put("ref_executable", ref.executableName());
        if (!ref.executableMd5().isEmpty()) body.put("ref_md5", ref.executableMd5());
        body.put("shared_constants", sharedConstants);
        body.put("query_only_constants", queryOnlyConstants);
        body.put("ref_only_constants", refOnlyConstants);
        body.put("shared_strings", sharedStrings);
        body.put("query_only_strings", queryOnlyStrings);
        body.put("ref_only_strings", refOnlyStrings);
        body.put("shared_callees", sharedCallees);
        body.put("notes", notes);
        return body;
    }

    public static Map<String, Object> noEvidence(String function, String refFunction,
                                                 String reason, List<String> notes) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "no_evidence");
        body.put("function", function == null ? "" : function);
        body.put("ref_function", refFunction == null ? "" : refFunction);
        body.put("reason", reason == null ? "not_extracted" : reason);
        body.put("notes", notes == null ? List.of() : List.copyOf(notes));
        return body;
    }

    public static boolean containsScoreKey(Map<String, Object> body) {
        if (body == null) return false;
        for (String key : body.keySet()) {
            if (isScoreKey(key)) return true;
            Object v = body.get(key);
            if (v instanceof Map<?, ?> nested) {
                @SuppressWarnings("unchecked")
                Map<String, Object> as = (Map<String, Object>) nested;
                if (containsScoreKey(as)) return true;
            }
            if (v instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> nested) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> as = (Map<String, Object>) nested;
                        if (containsScoreKey(as)) return true;
                    }
                }
            }
        }
        return false;
    }

    static boolean isScoreKey(String key) {
        if (key == null) return false;
        String k = key.toLowerCase(Locale.ROOT);
        return k.equals("score")
                || k.equals("corroboration_score")
                || k.equals("blended")
                || k.equals("blend")
                || k.equals("rank_boost")
                || k.endsWith("_score");
    }

    private static Map<String, Object> constantHit(String value, boolean distinctive) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", value);
        m.put("distinctive", distinctive);
        return m;
    }

    private record StringHit(String value, String match, String query, String ref) {}

    static StringHit matchString(String query, List<String> refs, Set<String> used, StringNorm mode) {
        if (query == null) return null;
        if (mode != StringNorm.BASENAME) {
            for (String ref : refs) {
                if (used.contains(ref)) continue;
                if (query.equals(ref)) {
                    used.add(ref);
                    return new StringHit(query, "exact", query, ref);
                }
            }
            if (mode == StringNorm.OFF) return null;
        }
        // basename / auto-fallback: both sides must look like paths. A format
        // string has no separators and stays exact-only, which is what we want.
        if (!looksLikePath(query)) return null;
        String qBase = basename(query);
        if (qBase == null || qBase.isEmpty()) return null;
        for (String ref : refs) {
            if (used.contains(ref) || !looksLikePath(ref)) continue;
            if (qBase.equals(basename(ref))) {
                used.add(ref);
                return new StringHit(qBase, "basename", query, ref);
            }
        }
        return null;
    }

    private static Frequencies zeroFreq() {
        return new Frequencies() {
            @Override public int corpusFunctionCount() { return 0; }
            @Override public int constantFrequency(String constant) { return 0; }
            @Override public int stringFrequency(String string) { return 0; }
        };
    }
}
