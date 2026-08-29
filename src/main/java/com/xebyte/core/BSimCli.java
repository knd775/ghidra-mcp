package com.xebyte.core;

import ghidra.framework.Application;
import generic.jar.ResourceFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Spawns Ghidra's {@code support/bsim} (and {@code analyzeHeadless} for query)
 * as a separate JVM. The headless MCP server does not load the BSim module, so
 * this is the only way to reach it without putting GUI-adjacent classes on
 * the server classpath.
 *
 * <p>H2 backends are single-writer. Callers should hold {@link #LOCK} across
 * a logical operation (create, ingest, query) so two requests cannot open the
 * same {@code file:} database at once.
 */
public class BSimCli {

    /** Process-wide lock for H2 single-writer safety. */
    public static final Object LOCK = new Object();

    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(2);
    public static final Duration INGEST_TIMEOUT = Duration.ofMinutes(30);
    public static final Duration QUERY_TIMEOUT = Duration.ofMinutes(30);

    @FunctionalInterface
    public interface Runner {
        Result run(List<String> command, Duration timeout) throws IOException, InterruptedException;
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
        this(BSimCli::runProcess, discoverGhidraHome());
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
        File bin = bsimBinary();
        if (bin == null || !bin.isFile()) {
            throw new IOException(missingToolMessage("bsim"));
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(bin.getAbsolutePath());
        for (String a : args) cmd.add(a);
        return runner.run(cmd, timeout);
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
        return runner.run(cmd, timeout);
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

    static Result runProcess(List<String> command, Duration timeout)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        forwardServerCredentials(pb.environment());
        Process proc = pb.start();
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
            throw new IOException("Timed out after " + timeout.toSeconds()
                    + "s running: " + String.join(" ", command));
        }
        reader.join(5000);
        int code = proc.exitValue();
        String text;
        synchronized (out) {
            text = out.toString();
        }
        return new Result(code, text, command);
    }

    /**
     * Copy resolved Ghidra Server credentials into the child environment so a
     * spawned {@code bsim}/{@code analyzeHeadless} JVM can load
     * {@code GhidraMCPAuthInitializer} and authenticate a {@code ghidra://} URL.
     * No-op when nothing is configured; never logs the password.
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
