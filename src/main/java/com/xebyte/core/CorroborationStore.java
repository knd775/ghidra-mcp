package com.xebyte.core;

import java.sql.Array;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Persist and look up corroboration rows. Production uses the companion
 * {@code corroboration} schema in the same PostgreSQL instance as BSim.
 * H2 {@code file:} URLs have nowhere natural to put that schema, so they
 * get a no-op store: lookups return miss, never an error.
 *
 * <p>No foreign keys into Ghidra's BSim tables. A lookup miss is "no
 * evidence available" — entries ingested before this feature existed, and
 * a {@code createdatabase} that Ghidra reruns, must degrade that way.
 */
public interface CorroborationStore extends CorroborationEvidence.Frequencies {

    @FunctionalInterface
    interface Factory {
        CorroborationStore open(String dbUrl);
    }

    void ensureSchema() throws Exception;

    void upsert(String executableMd5, String executableName,
                List<CorroborationEvidence.FunctionRow> rows) throws Exception;

    /**
     * Resolve {@code refExecutable} as an MD5 or an executable name and return
     * that function's row, or {@code null} on a miss.
     */
    CorroborationEvidence.FunctionRow lookup(String refExecutable, String refFunction)
            throws Exception;

    /** Number of extracted functions for one executable, selected by MD5 or name. */
    int executableFunctionCount(String refExecutable) throws Exception;

    /** True when this store can hold rows (PostgreSQL). */
    default boolean writable() {
        return true;
    }

    static CorroborationStore open(String dbUrl) {
        if (dbUrl != null && BSimUrls.isPostgresUrl(dbUrl)) {
            return new Jdbc(dbUrl);
        }
        return Noop.INSTANCE;
    }

    final class Noop implements CorroborationStore {
        static final Noop INSTANCE = new Noop();

        private Noop() {}

        @Override public void ensureSchema() {}
        @Override public void upsert(String executableMd5, String executableName,
                                     List<CorroborationEvidence.FunctionRow> rows) {}
        @Override public CorroborationEvidence.FunctionRow lookup(String refExecutable,
                                                                  String refFunction) {
            return null;
        }
        @Override public int executableFunctionCount(String refExecutable) { return 0; }
        @Override public boolean writable() { return false; }
        @Override public int corpusFunctionCount() { return 0; }
        @Override public int constantFrequency(String constant) { return 0; }
        @Override public int stringFrequency(String string) { return 0; }
    }

    final class Memory implements CorroborationStore {
        private final List<CorroborationEvidence.FunctionRow> rows = new ArrayList<>();

        @Override
        public synchronized void ensureSchema() {}

        @Override
        public synchronized void upsert(String executableMd5, String executableName,
                                        List<CorroborationEvidence.FunctionRow> incoming) {
            if (incoming == null) return;
            String md5 = normMd5(executableMd5);
            String exe = executableName == null ? "" : executableName;
            for (CorroborationEvidence.FunctionRow row : incoming) {
                if (row == null) continue;
                String rowMd5 = row.executableMd5().isEmpty() ? md5 : row.executableMd5();
                String rowExe = row.executableName().isEmpty() ? exe : row.executableName();
                CorroborationEvidence.FunctionRow stored = new CorroborationEvidence.FunctionRow(
                        rowMd5, rowExe, row.functionName(),
                        row.constants(), row.strings(), row.callees(), row.truncated());
                rows.removeIf(r -> r.executableMd5().equals(rowMd5)
                        && r.functionName().equals(row.functionName()));
                rows.add(stored);
            }
        }

        @Override
        public synchronized CorroborationEvidence.FunctionRow lookup(String refExecutable,
                                                                     String refFunction) {
            if (refFunction == null || refFunction.isBlank()) return null;
            String want = refFunction.trim();
            String exe = refExecutable == null ? "" : refExecutable.trim();
            String md5 = looksLikeMd5(exe) ? exe.toLowerCase(Locale.ROOT) : "";
            List<CorroborationEvidence.FunctionRow> hits = new ArrayList<>();
            for (CorroborationEvidence.FunctionRow row : rows) {
                if (!row.functionName().equals(want)) continue;
                if (exe.isEmpty()
                        || (!md5.isEmpty() && md5.equals(row.executableMd5()))
                        || exe.equalsIgnoreCase(row.executableName())) {
                    hits.add(row);
                }
            }
            if (hits.size() == 1) return hits.get(0);
            if (hits.size() > 1 && !md5.isEmpty()) {
                for (CorroborationEvidence.FunctionRow row : hits) {
                    if (md5.equals(row.executableMd5())) return row;
                }
            }
            return null;
        }

        @Override
        public synchronized int executableFunctionCount(String refExecutable) {
            String exe = refExecutable == null ? "" : refExecutable.trim();
            if (exe.isEmpty()) return 0;
            String md5 = looksLikeMd5(exe) ? exe.toLowerCase(Locale.ROOT) : "";
            int count = 0;
            for (CorroborationEvidence.FunctionRow row : rows) {
                if ((!md5.isEmpty() && md5.equals(row.executableMd5()))
                        || exe.equalsIgnoreCase(row.executableName())) {
                    count++;
                }
            }
            return count;
        }

        @Override
        public synchronized int corpusFunctionCount() {
            return rows.size();
        }

        @Override
        public synchronized int constantFrequency(String constant) {
            if (constant == null) return 0;
            int n = 0;
            for (CorroborationEvidence.FunctionRow row : rows) {
                if (row.constants().contains(constant)) n++;
            }
            return n;
        }

        @Override
        public synchronized int stringFrequency(String string) {
            if (string == null) return 0;
            int n = 0;
            for (CorroborationEvidence.FunctionRow row : rows) {
                if (row.strings().contains(string)) n++;
            }
            return n;
        }

        public synchronized List<CorroborationEvidence.FunctionRow> all() {
            return List.copyOf(rows);
        }
    }

    final class Jdbc implements CorroborationStore {
        private final String dbUrl;

        Jdbc(String dbUrl) {
            this.dbUrl = dbUrl;
        }

        @Override
        public void ensureSchema() throws SQLException {
            try (Connection c = connect(); Statement st = c.createStatement()) {
                for (String sql : DDL) {
                    st.execute(sql);
                }
            }
        }

        @Override
        public void upsert(String executableMd5, String executableName,
                           List<CorroborationEvidence.FunctionRow> incoming) throws SQLException {
            if (incoming == null || incoming.isEmpty()) return;
            ensureSchema();
            byte[] defaultMd5 = md5Bytes(executableMd5);
            String exe = executableName == null ? "" : executableName;
            try (Connection c = connect();
                 PreparedStatement ps = c.prepareStatement(UPSERT)) {
                c.setAutoCommit(false);
                try {
                    for (CorroborationEvidence.FunctionRow row : incoming) {
                        if (row == null || row.functionName().isEmpty()) continue;
                        byte[] md5 = md5Bytes(row.executableMd5());
                        if (md5 == null) md5 = defaultMd5;
                        if (md5 == null) continue;
                        String rowExe = row.executableName().isEmpty() ? exe : row.executableName();
                        ps.setBytes(1, md5);
                        ps.setString(2, row.functionName());
                        ps.setString(3, rowExe);
                        ps.setArray(4, c.createArrayOf("text", row.constants().toArray()));
                        ps.setArray(5, c.createArrayOf("text", row.strings().toArray()));
                        ps.setArray(6, c.createArrayOf("text", row.callees().toArray()));
                        ps.setBoolean(7, row.truncated());
                        ps.addBatch();
                    }
                    ps.executeBatch();
                    c.commit();
                } catch (SQLException e) {
                    c.rollback();
                    throw e;
                } finally {
                    c.setAutoCommit(true);
                }
            }
        }

        @Override
        public CorroborationEvidence.FunctionRow lookup(String refExecutable, String refFunction)
                throws SQLException {
            if (refFunction == null || refFunction.isBlank()) return null;
            ensureSchema();
            String exe = refExecutable == null ? "" : refExecutable.trim();
            byte[] md5 = looksLikeMd5(exe) ? md5Bytes(exe) : null;
            List<CorroborationEvidence.FunctionRow> hits = new ArrayList<>();
            try (Connection c = connect();
                 PreparedStatement ps = c.prepareStatement(LOOKUP)) {
                ps.setString(1, refFunction.trim());
                ps.setBytes(2, md5);
                ps.setString(3, exe);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        hits.add(readRow(rs));
                    }
                }
            }
            if (hits.size() == 1) return hits.get(0);
            if (hits.size() > 1 && md5 != null) {
                String hex = HexFormat.of().formatHex(md5);
                for (CorroborationEvidence.FunctionRow row : hits) {
                    if (hex.equals(row.executableMd5())) return row;
                }
            }
            return null;
        }

        @Override
        public int executableFunctionCount(String refExecutable) throws SQLException {
            ensureSchema();
            String exe = refExecutable == null ? "" : refExecutable.trim();
            if (exe.isEmpty()) return 0;
            byte[] md5 = looksLikeMd5(exe) ? md5Bytes(exe) : null;
            try (Connection c = connect();
                 PreparedStatement ps = c.prepareStatement(EXECUTABLE_FUNCTION_COUNT)) {
                ps.setBytes(1, md5);
                ps.setString(2, exe);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        }

        @Override
        public int corpusFunctionCount() {
            try {
                ensureSchema();
                try (Connection c = connect();
                     PreparedStatement ps = c.prepareStatement(
                             "SELECT COUNT(*) FROM corroboration.functions");
                     ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            } catch (SQLException e) {
                return 0;
            }
        }

        @Override
        public int constantFrequency(String constant) {
            return arrayFrequency("constants", constant);
        }

        @Override
        public int stringFrequency(String string) {
            return arrayFrequency("strings", string);
        }

        private int arrayFrequency(String column, String value) {
            if (value == null) return 0;
            try {
                ensureSchema();
                String sql = "SELECT COUNT(*) FROM corroboration.functions WHERE "
                        + column + " @> ARRAY[?]::text[]";
                try (Connection c = connect();
                     PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setString(1, value);
                    try (ResultSet rs = ps.executeQuery()) {
                        return rs.next() ? rs.getInt(1) : 0;
                    }
                }
            } catch (SQLException e) {
                return 0;
            }
        }

        private Connection connect() throws SQLException {
            try {
                Class.forName("org.postgresql.Driver");
            } catch (ClassNotFoundException e) {
                throw new SQLException(
                        "PostgreSQL JDBC driver is not on the classpath. "
                                + "Ship postgresql.jar in the GhidraMCP extension lib/.", e);
            }
            String jdbc = BSimUrls.toJdbcUrl(dbUrl);
            Properties props = new Properties();
            String user = BSimUrls.postgresUser(dbUrl);
            if (user != null && !user.isBlank()) props.setProperty("user", user);
            String password = BSimUrls.resolvedBsimPassword();
            if (password != null) props.setProperty("password", password);
            props.setProperty("sslmode", "require");
            return DriverManager.getConnection(jdbc, props);
        }
    }

    static final String[] DDL = {
            "CREATE SCHEMA IF NOT EXISTS corroboration",
            "CREATE TABLE IF NOT EXISTS corroboration.functions ("
                    + "exe_md5 bytea NOT NULL, "
                    + "function_name text NOT NULL, "
                    + "executable_name text NOT NULL DEFAULT '', "
                    + "constants text[] NOT NULL DEFAULT '{}', "
                    + "strings text[] NOT NULL DEFAULT '{}', "
                    + "callees text[] NOT NULL DEFAULT '{}', "
                    + "truncated boolean NOT NULL DEFAULT false, "
                    + "ingested_at timestamptz NOT NULL DEFAULT now(), "
                    + "PRIMARY KEY (exe_md5, function_name))",
            "CREATE INDEX IF NOT EXISTS corroboration_functions_constants_gin "
                    + "ON corroboration.functions USING gin (constants)",
            "CREATE INDEX IF NOT EXISTS corroboration_functions_strings_gin "
                    + "ON corroboration.functions USING gin (strings)",
            "CREATE INDEX IF NOT EXISTS corroboration_functions_exe_name "
                    + "ON corroboration.functions (executable_name)"
    };

    static final String UPSERT = "INSERT INTO corroboration.functions "
            + "(exe_md5, function_name, executable_name, constants, strings, callees, truncated, ingested_at) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, now()) "
            + "ON CONFLICT (exe_md5, function_name) DO UPDATE SET "
            + "executable_name = EXCLUDED.executable_name, "
            + "constants = EXCLUDED.constants, "
            + "strings = EXCLUDED.strings, "
            + "callees = EXCLUDED.callees, "
            + "truncated = EXCLUDED.truncated, "
            + "ingested_at = now()";

    static final String LOOKUP = "SELECT encode(exe_md5, 'hex') AS md5, function_name, "
            + "executable_name, constants, strings, callees, truncated "
            + "FROM corroboration.functions "
            + "WHERE function_name = ? AND (exe_md5 = ? OR lower(executable_name) = lower(?))";

    static final String EXECUTABLE_FUNCTION_COUNT = "SELECT COUNT(*) "
            + "FROM corroboration.functions "
            + "WHERE exe_md5 = ? OR lower(executable_name) = lower(?)";

    static CorroborationEvidence.FunctionRow readRow(ResultSet rs) throws SQLException {
        return new CorroborationEvidence.FunctionRow(
                rs.getString("md5"),
                rs.getString("executable_name"),
                rs.getString("function_name"),
                textArray(rs.getArray("constants")),
                textArray(rs.getArray("strings")),
                textArray(rs.getArray("callees")),
                rs.getBoolean("truncated"));
    }

    static List<String> textArray(Array array) throws SQLException {
        if (array == null) return List.of();
        Object raw = array.getArray();
        if (!(raw instanceof Object[] vals)) return List.of();
        List<String> out = new ArrayList<>();
        for (Object v : vals) {
            if (v != null) out.add(String.valueOf(v));
        }
        return out;
    }

    static boolean looksLikeMd5(String s) {
        if (s == null || s.length() != 32) return false;
        for (int i = 0; i < 32; i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    static String normMd5(String hex) {
        return hex == null ? "" : hex.trim().toLowerCase(Locale.ROOT);
    }

    static byte[] md5Bytes(String hex) {
        String n = normMd5(hex);
        if (!looksLikeMd5(n)) return null;
        return HexFormat.of().parseHex(n);
    }

    @SuppressWarnings("unchecked")
    static List<CorroborationEvidence.FunctionRow> rowsFromExtractPayload(
            Map<String, Object> payload, String fallbackMd5, String fallbackName) {
        if (payload == null) return List.of();
        String md5 = stringOr(payload.get("md5"), fallbackMd5);
        String exe = stringOr(payload.get("executable"), fallbackName);
        Object funcs = payload.get("functions");
        if (!(funcs instanceof List<?> list)) return List.of();
        List<CorroborationEvidence.FunctionRow> rows = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> raw)) continue;
            Map<String, Object> row = (Map<String, Object>) raw;
            rows.add(new CorroborationEvidence.FunctionRow(
                    md5, exe,
                    stringOr(row.get("function"), ""),
                    stringList(row.get("constants")),
                    stringList(row.get("strings")),
                    stringList(row.get("callees")),
                    bool(row.get("truncated"))));
        }
        return rows;
    }

    private static String stringOr(Object o, String fallback) {
        if (o == null) return fallback == null ? "" : fallback;
        String s = String.valueOf(o).trim();
        return s.isEmpty() && fallback != null ? fallback : s;
    }

    private static boolean bool(Object o) {
        if (o instanceof Boolean b) return b;
        return o != null && Boolean.parseBoolean(String.valueOf(o));
    }

    private static List<String> stringList(Object o) {
        if (!(o instanceof List<?> list)) return List.of();
        List<String> out = new ArrayList<>();
        for (Object v : list) {
            if (v != null) out.add(String.valueOf(v));
        }
        return out;
    }
}
