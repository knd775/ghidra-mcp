package com.xebyte.core;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Answers "does this BSim database actually exist?" for a network URL.
 *
 * <p>{@code bsim_list_databases} used to print every allowlisted URL as though
 * it were a database, with a {@code config_template} taken from a sidecar or
 * {@code GHIDRA_MCP_BSIM_TEMPLATES}. Both are configuration. An operator
 * reaches for that tool precisely when something is wrong, and it reported two
 * databases that had never been created, at a template neither of them had.
 * H2 rows were already honest ({@code present} is a file check), so the
 * asymmetry was worst exactly where it mattered.
 *
 * <p>This is a read-only probe over the shipped PostgreSQL JDBC driver — no
 * {@code bsim} CLI, no JVM spawn, no DDL. It creates nothing: a database that
 * does not exist stays not existing. Every failure is a reported state rather
 * than an exception, because "I could not reach it" and "it is not there" are
 * different answers and the caller needs to see which one it got.
 */
public final class BSimDbProbe {

    /** Per-URL connect/socket budget. Kept small: several URLs are probed in one call. */
    public static final int DEFAULT_TIMEOUT_SECONDS = 3;

    /** BSim's own metadata table, created by {@code bsim createdatabase}. */
    private static final String BSIM_TABLE = "keyvaluetable";

    /** BSim's executable table; its row count is the corpus size. */
    private static final String EXE_TABLE = "exetable";

    private BSimDbProbe() {}

    /**
     * Probe one network BSim URL.
     *
     * @return keys to merge into a {@code bsim_list_databases} row:
     *         {@code present} (Boolean, or {@code null} when unknowable),
     *         {@code probe} (state), {@code probe_detail} (why, when not ok),
     *         and on a live BSim database {@code executables} plus
     *         {@code corroboration_functions}.
     */
    public static Map<String, Object> probe(String dbUrl, int timeoutSeconds) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (dbUrl == null || dbUrl.isBlank()) {
            return state(out, null, "not_probed", "no db_url");
        }
        if (!BSimUrls.isPostgresUrl(dbUrl)) {
            // elastic:// and https:// backends have no driver here. Say so
            // rather than reporting a template as though it were a fact.
            return state(out, null, "unsupported",
                    "presence probe supports postgresql:// only");
        }
        if (BSimUrls.resolvedBsimPassword() == null) {
            return state(out, null, "no_credential",
                    "GHIDRA_MCP_BSIM_PASSWORD is not set, so this URL cannot be contacted");
        }
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            return state(out, null, "driver_missing",
                    "PostgreSQL JDBC driver is not on the classpath");
        }
        int timeout = timeoutSeconds > 0 ? timeoutSeconds : DEFAULT_TIMEOUT_SECONDS;
        try (Connection c = connect(dbUrl, timeout)) {
            boolean bsimTables = hasTable(c, BSIM_TABLE);
            if (!bsimTables) {
                // The database exists but bsim createdatabase never ran in it.
                // That is a real and distinct state: ingest would fail, and the
                // remedy is bsim_create_db, not a credential hunt.
                return state(out, false, "no_bsim_schema",
                        "database exists but has no BSim tables; run bsim_create_db");
            }
            state(out, true, "ok", null);
            Integer exes = count(c, "SELECT COUNT(*) FROM " + EXE_TABLE);
            if (exes != null) out.put("executables", exes);
            if (hasTable(c, "functions", "corroboration")) {
                Integer rows = count(c, "SELECT COUNT(*) FROM corroboration.functions");
                if (rows != null) out.put("corroboration_functions", rows);
            } else {
                out.put("corroboration_functions", 0);
            }
            return out;
        } catch (SQLException e) {
            return state(out, presenceFor(e), classify(e), sanitize(e));
        } catch (RuntimeException e) {
            return state(out, null, "error", e.getClass().getSimpleName());
        }
    }

    private static Connection connect(String dbUrl, int timeoutSeconds) throws SQLException {
        Properties props = new Properties();
        String user = BSimUrls.postgresUser(dbUrl);
        if (user != null && !user.isBlank()) props.setProperty("user", user);
        String password = BSimUrls.resolvedBsimPassword();
        if (password != null) props.setProperty("password", password);
        props.setProperty("sslmode", "require");
        props.setProperty("connectTimeout", Integer.toString(timeoutSeconds));
        props.setProperty("socketTimeout", Integer.toString(timeoutSeconds));
        props.setProperty("loginTimeout", Integer.toString(timeoutSeconds));
        return DriverManager.getConnection(BSimUrls.toJdbcUrl(dbUrl), props);
    }

    static boolean hasTable(Connection c, String table) throws SQLException {
        return hasTable(c, table, "public");
    }

    static boolean hasTable(Connection c, String table, String schema) throws SQLException {
        try (var ps = c.prepareStatement(
                "SELECT 1 FROM information_schema.tables "
                        + "WHERE table_schema = ? AND table_name = ?")) {
            ps.setString(1, schema);
            ps.setString(2, table);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static Integer count(Connection c, String sql) {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : null;
        } catch (SQLException e) {
            return null;
        }
    }

    /**
     * SQLSTATE, not message text: {@code 3D000} is a definite "no such
     * database", everything else leaves presence genuinely unknown.
     */
    public static String classify(SQLException e) {
        String sqlState = e.getSQLState() == null ? "" : e.getSQLState();
        return switch (sqlState) {
            case "3D000" -> "no_database";
            case "28P01", "28000" -> "auth_failed";
            case "08001", "08006", "08004", "08003" -> "unreachable";
            default -> sqlState.isEmpty() ? "unreachable" : "error";
        };
    }

    public static Boolean presenceFor(SQLException e) {
        return "no_database".equals(classify(e)) ? Boolean.FALSE : null;
    }

    /** Driver messages can echo the connection URL; never let a password through. */
    public static String sanitize(SQLException e) {
        String msg = e.getMessage();
        if (msg == null || msg.isBlank()) return e.getClass().getSimpleName();
        String password = BSimUrls.resolvedBsimPassword();
        if (password != null && !password.isBlank()) {
            msg = msg.replace(password, "***");
        }
        return msg.length() > 300 ? msg.substring(0, 300) : msg;
    }

    /**
     * {@code probe} is the field that always answers; {@code present} appears
     * only when the probe actually learned something. The response serializer
     * drops null values, so an unknown presence has to be an absent key rather
     * than a JSON null — which is why {@code probe} carries the real state and
     * no caller has to read a missing {@code present} as "false".
     */
    private static Map<String, Object> state(Map<String, Object> out, Boolean present,
                                             String probe, String detail) {
        if (present != null) out.put("present", present);
        out.put("probe", probe);
        if (detail != null && !detail.isBlank()) out.put("probe_detail", detail);
        return out;
    }
}
