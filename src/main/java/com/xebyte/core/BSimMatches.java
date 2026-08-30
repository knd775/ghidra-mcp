package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Match scoring helpers for BSim query results.
 *
 * <p>The earlier fuzzy matcher returned a ranked list with one score. That
 * invited committing wrong names: {@code lfs_fs_traverse_} was the top hit
 * for three different firmware functions. BSim returns similarity
 * <em>and</em> confidence; this class keeps both, and flags a result
 * ambiguous when the top two named candidates sit within a small similarity
 * margin.
 */
public final class BSimMatches {

    /** Similarity gap below which two differently-named hits are ambiguous. */
    public static final double AMBIGUOUS_SIMILARITY_DELTA = 0.05;

    /**
     * Callers who still pass the old 0.7 similarity default silently get
     * nothing against a cross-compiler corpus. Warn above this, not at it:
     * 0.5 is already optimistic for GCC 10 vs 13.
     */
    public static final double CROSS_BUILD_SIMILARITY_WARN = 0.5;

    public enum ApplyAction {
        APPLY,
        SKIP_AMBIGUOUS,
        SKIP_NAMED,
        SKIP_SIMILARITY,
        SKIP_CONFIDENCE,
        SKIP_NO_MATCH,
        SKIP_SELF
    }

    public static final class Hit {
        public final String name;
        public final double similarity;
        public final double confidence;
        public final String executable;
        public final String arch;
        public final String md5;
        public final String address;

        public Hit(String name, double similarity, double confidence,
                   String executable, String arch, String md5, String address) {
            this.name = name;
            this.similarity = similarity;
            this.confidence = confidence;
            this.executable = executable;
            this.arch = arch;
            this.md5 = md5;
            this.address = address;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("similarity", similarity);
            m.put("confidence", confidence);
            m.put("executable", executable);
            m.put("arch", arch);
            if (md5 != null && !md5.isEmpty()) m.put("md5", md5);
            if (address != null && !address.isEmpty()) m.put("address", address);
            return m;
        }
    }

    public static final class FunctionResult {
        public final String function;
        public final String address;
        public final List<Hit> matches;
        public final boolean ambiguous;

        public FunctionResult(String function, String address, List<Hit> matches, boolean ambiguous) {
            this.function = function;
            this.address = address;
            this.matches = matches;
            this.ambiguous = ambiguous;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("function", function);
            if (address != null && !address.isEmpty()) m.put("address", address);
            List<Map<String, Object>> hits = new ArrayList<>();
            for (Hit h : matches) hits.add(h.toMap());
            m.put("matches", hits);
            m.put("ambiguous", ambiguous);
            return m;
        }

        public Hit best() {
            return matches.isEmpty() ? null : matches.get(0);
        }
    }

    private BSimMatches() {}

    public static String similarityThresholdWarning(double similarity) {
        if (similarity <= CROSS_BUILD_SIMILARITY_WARN) return null;
        return "similarity_threshold " + similarity
                + " will drop cross-compiler matches (typically 0.2-0.4); "
                + "filter on confidence_threshold";
    }

    public static void attachSimilarityWarning(Map<String, Object> body, double similarity) {
        if (body == null) return;
        String warning = similarityThresholdWarning(similarity);
        if (warning == null) return;
        body.put("warnings", List.of(warning));
    }

    /**
     * Drop hits from the same executable MD5 as the query program (self-matches
     * after ingesting the binary under analysis), then flag ambiguity.
     */
    public static FunctionResult finalizeResult(String function, String address,
                                                List<Hit> rawHits, String queryMd5) {
        List<Hit> hits = new ArrayList<>();
        if (rawHits != null) {
            for (Hit h : rawHits) {
                if (queryMd5 != null && !queryMd5.isEmpty()
                        && h.md5 != null && queryMd5.equalsIgnoreCase(h.md5)) {
                    continue;
                }
                hits.add(h);
            }
        }
        hits.sort((a, b) -> {
            int byConf = Double.compare(b.confidence, a.confidence);
            if (byConf != 0) return byConf;
            return Double.compare(b.similarity, a.similarity);
        });
        return new FunctionResult(function, address, hits, isAmbiguous(hits));
    }

    public static boolean isAmbiguous(List<Hit> hits) {
        if (hits == null || hits.size() < 2) return false;
        Hit a = hits.get(0);
        Hit b = hits.get(1);
        if (sameFunctionName(a.name, b.name)) return false;
        return (a.similarity - b.similarity) < AMBIGUOUS_SIMILARITY_DELTA;
    }

    public static ApplyAction decide(FunctionResult result, String currentName,
                                     boolean skipNamed, double minSimilarity, double minConfidence) {
        if (result == null || result.matches.isEmpty()) return ApplyAction.SKIP_NO_MATCH;
        if (result.ambiguous) return ApplyAction.SKIP_AMBIGUOUS;
        if (skipNamed && currentName != null && !currentName.isEmpty()
                && !ServiceUtils.isAutoGeneratedName(currentName)) {
            return ApplyAction.SKIP_NAMED;
        }
        Hit best = result.best();
        if (best.similarity < minSimilarity) return ApplyAction.SKIP_SIMILARITY;
        if (best.confidence < minConfidence) return ApplyAction.SKIP_CONFIDENCE;
        return ApplyAction.APPLY;
    }

    public static String reason(ApplyAction action) {
        return switch (action) {
            case APPLY -> "apply";
            case SKIP_AMBIGUOUS -> "ambiguous";
            case SKIP_NAMED -> "already_named";
            case SKIP_SIMILARITY -> "below_similarity";
            case SKIP_CONFIDENCE -> "below_confidence";
            case SKIP_NO_MATCH -> "no_matches";
            case SKIP_SELF -> "self_match";
        };
    }

    static boolean sameFunctionName(String a, String b) {
        if (a == null || b == null) return false;
        return Objects.equals(a.toLowerCase(Locale.ROOT), b.toLowerCase(Locale.ROOT));
    }

    @SuppressWarnings("unchecked")
    public static List<FunctionResult> parseQueryPayload(Map<String, Object> payload, String queryMd5) {
        List<FunctionResult> out = new ArrayList<>();
        if (payload == null) return out;
        Object results = payload.get("results");
        if (!(results instanceof List<?> list)) {
            // Single-function payload: {function, matches}
            if (payload.get("function") != null) {
                out.add(fromFunctionMap(payload, queryMd5));
            }
            return out;
        }
        for (Object item : list) {
            if (item instanceof Map<?, ?> m) {
                out.add(fromFunctionMap((Map<String, Object>) m, queryMd5));
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static FunctionResult fromFunctionMap(Map<String, Object> m, String queryMd5) {
        String function = str(m.get("function"));
        String address = str(m.get("address"));
        List<Hit> hits = new ArrayList<>();
        Object matches = m.get("matches");
        if (matches instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> hm)) continue;
                Map<String, Object> hit = (Map<String, Object>) hm;
                hits.add(new Hit(
                        str(hit.get("name")),
                        num(hit.get("similarity")),
                        num(hit.get("confidence")),
                        str(hit.get("executable")),
                        str(hit.get("arch")),
                        str(hit.get("md5")),
                        str(hit.get("address"))));
            }
        }
        return finalizeResult(function, address, hits, queryMd5);
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static double num(Object o) {
        if (o instanceof Number n) return n.doubleValue();
        if (o == null) return 0.0;
        try { return Double.parseDouble(String.valueOf(o)); }
        catch (NumberFormatException e) { return 0.0; }
    }
}
