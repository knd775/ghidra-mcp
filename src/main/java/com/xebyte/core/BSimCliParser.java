package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses stdout/stderr from Ghidra's {@code bsim} CLI.
 *
 * <p>{@code listexes} prints via {@code Msg.info}, so lines may carry a log
 * prefix. {@code getexecount} prints {@code Matching executable count: N} on
 * stdout. Keep this tolerant: a prefix change should not blank the corpus.
 */
public final class BSimCliParser {

    private static final Pattern EXE_LINE = Pattern.compile(
            "([0-9a-fA-F]{32})\\s+(.+?)\\s+(\\S+:\\S+:\\S+)\\s+(\\S+)\\s*$");
    private static final Pattern EXE_COUNT = Pattern.compile(
            "Matching executable count:\\s*(\\d+)");
    private static final Pattern EXE_FOUND = Pattern.compile(
            "(\\d+)\\s+executables found");
    private static final Pattern META_FIELD = Pattern.compile(
            "(?i)(?:^|\\s)(Database|Owner|Description):\\s*(.*)$");

    private BSimCliParser() {}

    public static final class ExeRecord {
        public final String md5;
        public final String name;
        public final String arch;
        public final String compiler;

        public ExeRecord(String md5, String name, String arch, String compiler) {
            this.md5 = md5;
            this.name = name;
            this.arch = arch;
            this.compiler = compiler;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("md5", md5);
            m.put("name", name);
            m.put("arch", arch);
            m.put("compiler", compiler);
            return m;
        }
    }

    public static List<ExeRecord> parseExeList(String output) {
        List<ExeRecord> out = new ArrayList<>();
        if (output == null || output.isEmpty()) return out;
        for (String line : output.split("\\R")) {
            String trimmed = stripLogPrefix(line);
            Matcher m = EXE_LINE.matcher(trimmed);
            if (m.find()) {
                out.add(new ExeRecord(m.group(1), m.group(2).trim(), m.group(3), m.group(4)));
            }
        }
        return out;
    }

    public static Integer parseExeCount(String output) {
        if (output == null) return null;
        Matcher count = EXE_COUNT.matcher(output);
        if (count.find()) {
            return Integer.parseInt(count.group(1));
        }
        Matcher found = EXE_FOUND.matcher(output);
        Integer last = null;
        while (found.find()) {
            last = Integer.parseInt(found.group(1));
        }
        return last;
    }

    public static Map<String, String> parseMetadata(String output) {
        Map<String, String> meta = new LinkedHashMap<>();
        if (output == null) return meta;
        for (String line : output.split("\\R")) {
            Matcher m = META_FIELD.matcher(stripLogPrefix(line));
            if (m.find()) {
                meta.put(m.group(1).toLowerCase(), m.group(2).trim());
            }
        }
        return meta;
    }

    /**
     * Best-effort error extraction. Ghidra mixes INFO with failures; prefer
     * explicit ERROR / Exception lines over a generic non-zero exit.
     */
    public static String extractError(String output) {
        if (output == null || output.isEmpty()) return null;
        String[] lines = output.split("\\R");
        String lastError = null;
        for (String line : lines) {
            String t = stripLogPrefix(line);
            if (t.matches("(?i).*\\b(ERROR|Exception:|FAILED|Invalid URL|Could not).*")) {
                lastError = t;
            }
        }
        return lastError;
    }

    static String stripLogPrefix(String line) {
        if (line == null) return "";
        String s = line.strip();
        // "2026-08-29 12:00:00 INFO  (BSimLaunchable) rest of line"
        int idx = s.indexOf(") ");
        if (idx > 0 && idx + 2 < s.length() && s.contains("(")) {
            String maybe = s.substring(idx + 2);
            if (maybe.length() >= 32 && Character.digit(maybe.charAt(0), 16) >= 0) {
                return maybe;
            }
            if (maybe.startsWith("Database:") || maybe.startsWith("Owner:")
                    || maybe.startsWith("Description:") || maybe.startsWith("BSim metadata")
                    || maybe.startsWith("Matching executable")
                    || maybe.contains("executables found")) {
                return maybe;
            }
        }
        return s;
    }
}
