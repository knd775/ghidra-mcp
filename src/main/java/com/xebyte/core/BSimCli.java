package com.xebyte.core;

import ghidra.framework.Application;
import generic.jar.ResourceFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Spawns Ghidra's {@code support/bsim} (and {@code analyzeHeadless} for query)
 * as a separate JVM. The headless MCP server does not load the BSim module, so
 * this is the only way to reach it without putting GUI-adjacent classes on
 * the server classpath.
 *
 * <p>H2 {@code file:} backends are single-writer. Callers should hold
 * {@link #LOCK} across a logical operation that uses a {@code file:} URL so
 * two requests cannot open the same database at once. PostgreSQL does not
 * need that lock; GUI clients and the MCP tools share the instance.
 */
public class BSimCli {

    private static final Logger LOG = Logger.getLogger(BSimCli.class.getName());

    /** Process-wide lock for H2 single-writer safety. */
    public static final Object LOCK = new Object();

    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(2);
    public static final Duration INGEST_TIMEOUT = Duration.ofMinutes(30);
    public static final Duration QUERY_TIMEOUT = Duration.ofMinutes(30);

    @FunctionalInterface
    public interface Runner {
        Result run(List<String> command, Duration timeout) throws IOException, InterruptedException;

        /**
         * Variant with data for the child's stdin (a Ghidra Server password —
         * see {@link BSimCli#runProcess}). Test fakes that don't care about
         * stdin inherit this delegation; the real runner overrides it.
         */
        default Result run(List<String> command, Duration timeout, String stdinData)
                throws IOException, InterruptedException {
            return run(command, timeout);
        }
    }

    public static final class Result {
        public final int exitCode;
        public final String output;
        public final List<String> command;

        public Result(int exitCode, String output, List<String> command) {
            this.exitCode = exitCode;
            this.output = output == null ? "" : output;
            this.command = command;
        }

        public boolean ok() {
            return exitCode == 0;
        }
    }

    private final Runner runner;
    private final File ghidraHome;

    public BSimCli() {
        this(new Runner() {
            @Override
            public Result run(List<String> command, Duration timeout)
                    throws IOException, InterruptedException {
                return runProcess(command, timeout, null);
            }

            @Override
            public Result run(List<String> command, Duration timeout, String stdinData)
                    throws IOException, InterruptedException {
                return runProcess(command, timeout, stdinData);
            }
        }, discoverGhidraHome());
    }

    public BSimCli(Runner runner, File ghidraHome) {
        this.runner = runner;
        this.ghidraHome = ghidraHome;
    }

    public File ghidraHome() {
        return ghidraHome;
    }

    public File bsimBinary() {
        return supportTool("bsim");
    }

    public File analyzeHeadlessBinary() {
        return supportTool("analyzeHeadless");
    }

    public Result bsim(Duration timeout, String... args) throws IOException, InterruptedException {
        return bsim(timeout, List.of(args), null);
    }

    /**
     * Run {@code support/bsim} with optional stdin data. Pass the resolved
     * Ghidra Server password (newline-terminated) as {@code stdinData} when the
     * command targets a {@code ghidra://} server URL: the spawned JVM does not
     * load this extension, so {@code GhidraMCPAuthInitializer} never registers
     * there and Ghidra's {@code HeadlessClientAuthenticator} falls back to
     * prompting on stdin.
     */
    public Result bsim(Duration timeout, List<String> args, String stdinData)
            throws IOException, InterruptedException {
        File bin = bsimBinary();
        if (bin == null || !bin.isFile()) {
            throw new IOException(missingToolMessage("bsim"));
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(bin.getAbsolutePath());
        cmd.addAll(args);
        return runner.run(cmd, timeout, stdinData);
    }

    public Result analyzeHeadless(Duration timeout, List<String> args)
            throws IOException, InterruptedException {
        File bin = analyzeHeadlessBinary();
        if (bin == null || !bin.isFile()) {
            throw new IOException(missingToolMessage("analyzeHeadless"));
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(bin.getAbsolutePath());
        cmd.addAll(args);
        return runner.run(cmd, timeout, null);
    }

    private File supportTool(String name) {
        if (ghidraHome == null) return null;
        File support = new File(ghidraHome, "support");
        if (isWindows()) {
            File bat = new File(support, name + ".bat");
            if (bat.isFile()) return bat;
        }
        File sh = new File(support, name);
        if (sh.isFile()) return sh;
        File bat = new File(support, name + ".bat");
        return bat.isFile() ? bat : sh;
    }

    private String missingToolMessage(String tool) {
        return "Ghidra " + tool + " not found. Set GHIDRA_HOME or GHIDRA_INSTALL_DIR to a Ghidra "
                + "install that contains support/" + tool
                + (ghidraHome == null ? "." : " (looked in " + ghidraHome.getAbsolutePath() + ").");
    }

    public static File discoverGhidraHome() {
        List<File> candidates = new ArrayList<>();
        addIfSet(candidates, System.getProperty("ghidra.home"));
        addIfSet(candidates, System.getenv("GHIDRA_HOME"));
        addIfSet(candidates, System.getenv("GHIDRA_INSTALL_DIR"));
        try {
            if (Application.isInitialized()) {
                ResourceFile root = Application.getApplicationRootDirectory();
                if (root != null) {
                    File f = root.getFile(false);
                    if (f != null) candidates.add(f);
                }
            }
        } catch (Throwable ignored) {
            // Application may be uninitialized in offline tests.
        }
        for (File c : candidates) {
            if (looksLikeGhidraHome(c)) return c;
        }
        return candidates.isEmpty() ? null : candidates.get(0);
    }

    static boolean looksLikeGhidraHome(File dir) {
        if (dir == null || !dir.isDirectory()) return false;
        File support = new File(dir, "support");
        return new File(support, "bsim").isFile()
                || new File(support, "bsim.bat").isFile();
    }

    private static void addIfSet(List<File> out, String raw) {
        if (raw != null && !raw.isBlank()) out.add(new File(raw.trim()));
    }

    private static boolean isWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase(Locale.ROOT).contains("win");
    }

    /**
     * Spawn the CLI process. Credentials never appear in {@code command} (they
     * travel via environment and stdin), so logging the argv is safe.
     *
     * <p>The child's stdin is written (when {@code stdinData} is set) and then
     * <b>always closed</b>. Ghidra's {@code HeadlessClientAuthenticator} reads
     * a password from stdin when there is no console; an open, never-written
     * pipe made that prompt block until the whole-process timeout killed the
     * JVM — a 30-minute zombie per {@code ghidra://} ingest attempt, holding
     * {@link #LOCK} the entire time. EOF instead fails the prompt immediately
     * with a real authentication error the caller can read.
     */
    static Result runProcess(List<String> command, Duration timeout, String stdinData)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        forwardChildCredentials(pb.environment());
        long startMs = System.currentTimeMillis();
        LOG.info(() -> "BSim CLI start (timeout " + timeout.toSeconds() + "s): "
                + String.join(" ", command));
        Process proc = pb.start();
        try (OutputStream stdin = proc.getOutputStream()) {
            if (stdinData != null && !stdinData.isEmpty()) {
                stdin.write(stdinData.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ignored) {
            // The child may have exited before reading stdin; its exit code
            // and output still tell the real story below.
        }
        StringBuilder out = new StringBuilder();
        Thread reader = new Thread(() -> {
            try (BufferedReader in = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                char[] buf = new char[4096];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    synchronized (out) {
                        out.append(buf, 0, n);
                    }
                }
            } catch (IOException ignored) {
            }
        }, "bsim-cli-stdout");
        reader.setDaemon(true);
        reader.start();
        boolean finished = proc.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        if (!finished) {
            proc.destroyForcibly();
            reader.join(2000);
            LOG.warning("BSim CLI timed out after " + timeout.toSeconds() + "s, killed: "
                    + String.join(" ", command));
            throw new IOException("Timed out after " + timeout.toSeconds()
                    + "s running: " + String.join(" ", command));
        }
        reader.join(5000);
        int code = proc.exitValue();
        String text;
        synchronized (out) {
            text = out.toString();
        }
        long tookMs = System.currentTimeMillis() - startMs;
        LOG.info(() -> "BSim CLI exit " + code + " in " + tookMs + "ms ("
                + text.length() + " output chars): " + command.get(0)
                + (command.size() > 1 ? " " + command.get(1) : ""));
        return new Result(code, text, command);
    }

    /**
     * Resolved Ghidra Server username for a spawned CLI, or {@code null}.
     * Same resolution order the server itself uses: registered authenticator,
     * then {@code GHIDRA_SERVER_USER}.
     */
    static String resolvedServerUser() {
        GhidraMCPAuthenticator auth = GhidraMCPAuthInitializer.getAuthenticator();
        if (auth != null && auth.getUsername() != null && !auth.getUsername().isBlank()) {
            return auth.getUsername();
        }
        String user = System.getenv("GHIDRA_SERVER_USER");
        return (user == null || user.isBlank()) ? null : user;
    }

    /**
     * Resolved Ghidra Server password for a spawned CLI's stdin, or
     * {@code null}. Authenticator first, then the same env vars
     * {@link #forwardServerCredentials} forwards.
     */
    static String resolvedServerPassword() {
        GhidraMCPAuthenticator auth = GhidraMCPAuthInitializer.getAuthenticator();
        if (auth != null) {
            String fromAuth = auth.passwordForChildEnv();
            if (fromAuth != null && !fromAuth.isBlank()) {
                return fromAuth;
            }
        }
        String password = System.getenv("GHIDRA_SERVER_PASSWORD");
        if (password == null || password.isBlank()) {
            password = System.getenv("GHIDRA_PASS");
        }
        return (password == null || password.isBlank()) ? null : password;
    }

    /**
     * Stdin payload for a {@code bsim} invocation: Ghidra Server password first
     * (when a {@code ghidra://} argument is present), then the PostgreSQL
     * password (when a {@code postgresql://} argument is present). Stock Ghidra
     * prompts in that order; an open pipe with nothing written blocks for the
     * whole process timeout.
     */
    public static String stdinForBsimArgs(List<String> args) {
        if (args == null) return null;
        boolean ghidraServer = false;
        boolean postgres = false;
        for (String a : args) {
            if (BSimUrls.isServerGhidraUrl(a)) ghidraServer = true;
            if (BSimUrls.isPostgresUrl(a)) postgres = true;
        }
        StringBuilder sb = new StringBuilder();
        if (ghidraServer) {
            String password = resolvedServerPassword();
            if (password != null) sb.append(password).append('\n');
        }
        if (postgres) {
            String password = BSimUrls.resolvedBsimPassword();
            if (password != null) sb.append(password).append('\n');
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    static void forwardChildCredentials(java.util.Map<String, String> env) {
        forwardServerCredentials(env);
        if (env == null) return;
        String user = BSimUrls.resolvedBsimUser();
        if (user != null && !user.isBlank()) {
            env.putIfAbsent("GHIDRA_MCP_BSIM_USER", user);
        }
        String password = BSimUrls.resolvedBsimPassword();
        if (password != null && !password.isBlank()) {
            env.putIfAbsent("GHIDRA_MCP_BSIM_PASSWORD", password);
        }
    }

    /**
     * Copy resolved Ghidra Server credentials into the child environment so a
     * spawned {@code bsim}/{@code analyzeHeadless} JVM can load
     * {@code GhidraMCPAuthInitializer} and authenticate a {@code ghidra://} URL.
     * No-op when nothing is configured; never logs the password.
     *
     * <p>Note this only helps when the child's Ghidra install actually contains
     * this extension. A stock install (the Docker image's {@code /opt/ghidra})
     * never reads these variables — there the password must be fed on stdin;
     * see {@link #bsim(Duration, List, String)}.
     */
    static void forwardServerCredentials(java.util.Map<String, String> env) {
        if (env == null) return;
        GhidraMCPAuthenticator auth = GhidraMCPAuthInitializer.getAuthenticator();
        if (auth != null) {
            String user = auth.getUsername();
            if (user != null && !user.isBlank()) {
                env.putIfAbsent("GHIDRA_SERVER_USER", user);
            }
            String fromAuth = auth.passwordForChildEnv();
            if (fromAuth != null && !fromAuth.isBlank()) {
                env.putIfAbsent("GHIDRA_SERVER_PASSWORD", fromAuth);
                return;
            }
        }
        if (env.getOrDefault("GHIDRA_SERVER_PASSWORD", "").isBlank()
                && env.getOrDefault("GHIDRA_PASS", "").isBlank()) {
            String password = System.getenv("GHIDRA_SERVER_PASSWORD");
            if (password == null || password.isBlank()) {
                password = System.getenv("GHIDRA_PASS");
            }
            if (password != null && !password.isBlank()) {
                env.putIfAbsent("GHIDRA_SERVER_PASSWORD", password);
            }
        }
    }
}
