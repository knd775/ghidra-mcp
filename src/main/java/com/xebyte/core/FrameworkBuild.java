package com.xebyte.core;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Framework-mode argv, naming, and validation for {@code build_reference}.
 *
 * <p>A stub under {@code docker/stubs/<framework>/} is configured and built;
 * objects are harvested from the build tree, never from the linked ELF
 * ({@code --gc-sections} would drop anything {@code main.c} did not call).
 * Adding {@code stubs/zephyr/} is another directory, not a new MCP parameter.
 */
public final class FrameworkBuild {

    public static final String MODE_SOURCES = "sources";
    public static final String MODE_FRAMEWORK = "framework";
    /** Shipped stub; {@link #listFrameworks()} also scans {@code docker/stubs}. */
    public static final List<String> DEFAULT_FRAMEWORKS = List.of("pico-sdk");
    public static final Duration TIMEOUT = Duration.ofMinutes(20);

    private FrameworkBuild() {}

    public static String requireMode(String mode) {
        String m = (mode == null || mode.isBlank()) ? MODE_SOURCES : mode.trim();
        if (MODE_SOURCES.equals(m) || MODE_FRAMEWORK.equals(m)) return m;
        throw new IllegalArgumentException(
                "mode must be 'sources' or 'framework'; got '" + m + "'");
    }

    /**
     * Local stub names: {@code GHIDRA_MCP_STUBS}, {@code docker/stubs},
     * {@code /opt/ghidra-builder/stubs}, then {@link #DEFAULT_FRAMEWORKS}.
     * Used when {@code GET /health} omitted {@code stubs}. The builder is
     * the inventory; this scan is the fallback for unit tests and older images.
     */
    public static List<String> listFrameworks() {
        Set<String> names = new LinkedHashSet<>();
        String env = System.getenv("GHIDRA_MCP_STUBS");
        if (env != null && !env.isBlank()) {
            scanStubDir(Path.of(env), names);
        }
        scanStubDir(Path.of("docker", "stubs"), names);
        scanStubDir(Path.of("/opt/ghidra-builder/stubs"), names);
        names.addAll(DEFAULT_FRAMEWORKS);
        return List.copyOf(names);
    }

    static void scanStubDir(Path root, Set<String> names) {
        if (root == null || !Files.isDirectory(root)) return;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(root)) {
            for (Path child : stream) {
                if (Files.isDirectory(child)
                        && (Files.isRegularFile(child.resolve("CMakeLists.txt"))
                                || Files.isRegularFile(child.resolve("stub.json")))) {
                    names.add(child.getFileName().toString());
                }
            }
        } catch (IOException ignored) {
            // listing is advisory; the builder is authoritative at compile time
        }
    }

    public static String requireFramework(String framework, String mode) {
        return requireFramework(framework, mode, null);
    }

    /**
     * @param available {@code GET /health} stubs, or {@code null} to scan local
     *                  stub dirs. Non-null (including empty) is the container's
     *                  list and wins over {@link #listFrameworks()}.
     */
    public static String requireFramework(String framework, String mode, List<String> available) {
        if (!MODE_FRAMEWORK.equals(mode)) {
            return framework == null ? "" : framework.trim();
        }
        String f = framework == null ? "" : framework.trim();
        List<String> installed = available != null ? available : listFrameworks();
        if (f.isEmpty()) {
            throw new IllegalArgumentException(
                    "framework is required in mode=framework; available: " + installed);
        }
        if (f.contains("..") || f.indexOf('/') >= 0 || f.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("framework must be a directory name, not a path: " + f);
        }
        if (!installed.contains(f)) {
            throw new IllegalArgumentException(
                    "unknown framework '" + f + "'; available: " + installed);
        }
        return f;
    }

    public static List<String> requireLibraries(Object raw, String mode) {
        List<String> libraries = ReferenceBuild.stringList(raw);
        if (!MODE_FRAMEWORK.equals(mode)) return libraries;
        if (libraries.isEmpty()) {
            throw new IllegalArgumentException(
                    "libraries is required in mode=framework (linking nothing produces nothing)");
        }
        for (String lib : libraries) {
            ReferenceBuild.requireFilename("libraries", lib);
        }
        return libraries;
    }

    public static String requireBoard(String board) {
        if (board == null || board.isBlank()) return "";
        String b = board.trim();
        ReferenceBuild.requireFilename("board", b);
        return b;
    }

    public static Map<String, String> stringMap(Object raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null) return out;
        if (raw instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (k == null || v == null) return;
                String key = String.valueOf(k).trim();
                if (!key.isEmpty()) out.put(key, String.valueOf(v));
            });
        }
        return out;
    }

    public static String artifactFileName(
            String name, String library, String ref, String toolchain, String opt, String board) {
        String optLabel = ReferenceBuild.optToLabel(opt);
        String base = name + "-" + ReferenceBuild.filenameSafe(library) + "-"
                + ReferenceBuild.filenameSafe(ref) + "-" + toolchain + "-" + optLabel;
        if (board != null && !board.isBlank()) {
            base = base + "-" + ReferenceBuild.filenameSafe(board);
        }
        return base + ".o";
    }

    public static List<Path> expectedPaths(ReferenceBuild.Spec spec, Path fileRoot) {
        List<Path> paths = new ArrayList<>();
        Path uploads = fileRoot.resolve(ReferenceBuild.UPLOADS);
        for (String lib : spec.libraries()) {
            paths.add(uploads.resolve(artifactFileName(
                    spec.name(), lib, spec.ref(), spec.toolchain(), spec.opt(), spec.board())));
        }
        return paths;
    }

    public static boolean allOutputsExist(ReferenceBuild.Spec spec, Path fileRoot) {
        List<Path> paths = expectedPaths(spec, fileRoot);
        if (paths.isEmpty()) return false;
        for (Path p : paths) {
            if (!artifactIsCurrent(p)) return false;
        }
        return true;
    }

    public static boolean sourceOutputExists(ReferenceBuild.Spec spec, Path fileRoot) {
        return artifactIsCurrent(spec.outputPath(fileRoot));
    }

    /** Sidecar sits beside the object: {@code littlefs-v2.9.3-gcc13-arm-Os.o.json}. */
    public static Path sidecarPath(Path artifact) {
        return artifact.resolveSibling(artifact.getFileName().toString() + ".json");
    }

    /**
     * Artifact exists and its sidecar {@code sha256} matches the file.
     * Missing, unreadable, or mismatched sidecars are not current — rebuild,
     * do not crash.
     */
    public static boolean artifactIsCurrent(Path artifact) {
        try {
            if (artifact == null || !Files.isRegularFile(artifact) || Files.size(artifact) <= 0) {
                return false;
            }
            Path sidecar = sidecarPath(artifact);
            if (!Files.isRegularFile(sidecar)) return false;
            String json = Files.readString(sidecar, StandardCharsets.UTF_8);
            JsonElement el = JsonParser.parseString(json);
            if (!el.isJsonObject()) return false;
            JsonObject obj = el.getAsJsonObject();
            if (!obj.has("sha256") || obj.get("sha256").isJsonNull()) return false;
            String expected = obj.get("sha256").getAsString().trim().toLowerCase(Locale.ROOT);
            if (expected.isEmpty()) return false;
            return expected.equals(sha256Hex(artifact));
        } catch (Exception e) {
            return false;
        }
    }

    public static String sha256Hex(Path file) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) {
                md.update(buf, 0, n);
            }
        }
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static List<List<String>> commandLines(ReferenceBuild.Spec spec) {
        Path stub = findStubDir(spec.framework());
        String generator = stubGenerator(stub);
        if ("make".equals(generator)) {
            return makeCommandLines(spec, stub);
        }
        return cmakeCommandLines(spec);
    }

    static Path findStubDir(String framework) {
        if (framework == null || framework.isBlank()) return null;
        String env = System.getenv("GHIDRA_MCP_STUBS");
        List<Path> roots = new ArrayList<>();
        if (env != null && !env.isBlank()) roots.add(Path.of(env));
        roots.add(Path.of("docker", "stubs"));
        roots.add(Path.of("/opt/ghidra-builder/stubs"));
        for (Path root : roots) {
            Path child = root.resolve(framework);
            if (Files.isDirectory(child)
                    && (Files.isRegularFile(child.resolve("stub.json"))
                            || Files.isRegularFile(child.resolve("CMakeLists.txt")))) {
                return child;
            }
        }
        return null;
    }

    static String stubGenerator(Path stub) {
        if (stub == null) return "cmake";
        Path meta = stub.resolve("stub.json");
        if (!Files.isRegularFile(meta)) return "cmake";
        try {
            JsonElement el = JsonParser.parseString(Files.readString(meta, StandardCharsets.UTF_8));
            if (el.isJsonObject() && el.getAsJsonObject().has("generator")) {
                String g = el.getAsJsonObject().get("generator").getAsString().trim();
                if (!g.isEmpty()) return g;
            }
        } catch (Exception ignored) {
            return "cmake";
        }
        return "cmake";
    }

    static List<List<String>> makeCommandLines(ReferenceBuild.Spec spec, Path stub) {
        try {
            JsonObject meta = JsonParser.parseString(
                    Files.readString(stub.resolve("stub.json"), StandardCharsets.UTF_8)).getAsJsonObject();
            List<List<String>> steps = new ArrayList<>();
            addStringArrayStep(steps, meta, "prepare");
            addStringArrayStep(steps, meta, "configure");
            addStringArrayStep(steps, meta, "make");
            if (steps.isEmpty()) {
                steps.add(List.of("make", "-j"));
            }
            return steps;
        } catch (IOException e) {
            return List.of(List.of("make", "-j"));
        }
    }

    static void addStringArrayStep(List<List<String>> steps, JsonObject meta, String key) {
        if (!meta.has(key) || !meta.get(key).isJsonArray()) return;
        List<String> argv = new ArrayList<>();
        for (JsonElement el : meta.getAsJsonArray(key)) {
            if (el == null || el.isJsonNull()) continue;
            argv.add(el.getAsString());
        }
        if (!argv.isEmpty()) steps.add(argv);
    }

    static List<List<String>> cmakeCommandLines(ReferenceBuild.Spec spec) {
        ToolchainIdentity id = spec.identity();
        String cxx = cxxFromCc(id.cc());
        String sdk = ReferenceBuild.SNAPSHOT_PLACEHOLDER;
        List<String> extras = new ArrayList<>();
        extras.add("-g");
        extras.add("-fdebug-prefix-map=" + sdk + "=" + ReferenceBuild.debugPathPrefix(spec.name()));
        extras.add("-ffile-prefix-map=" + sdk + "=" + ReferenceBuild.debugPathPrefix(spec.name()));
        extras.add("-fmacro-prefix-map=" + sdk + "=" + ReferenceBuild.debugPathPrefix(spec.name()));
        extras.addAll(spec.extraFlags());
        for (String d : spec.defines()) {
            extras.add(d.startsWith("-D") ? d : "-D" + d);
        }
        String cflags = spec.opt();
        if (!extras.isEmpty()) {
            cflags = spec.opt() + " " + String.join(" ", extras);
        }
        List<String> configure = new ArrayList<>();
        configure.add("cmake");
        configure.add("-S");
        configure.add("<stub>/" + spec.framework());
        configure.add("-B");
        configure.add("<build>");
        configure.add("-G");
        configure.add("Ninja");
        configure.add("-DGHIDRA_SDK_PATH=" + sdk);
        configure.add("-DGHIDRA_LIBRARIES=" + String.join(";", spec.libraries()));
        configure.add("-DCMAKE_C_COMPILER=" + id.cc());
        configure.add("-DCMAKE_CXX_COMPILER=" + cxx);
        configure.add("-DCMAKE_C_FLAGS=" + cflags);
        configure.add("-DCMAKE_CXX_FLAGS=" + cflags);
        if (!spec.board().isBlank()) {
            configure.add("-DGHIDRA_BOARD=" + spec.board());
        }
        spec.config().forEach((k, v) -> configure.add("-D" + k + "=" + v));
        return List.of(configure, List.of("cmake", "--build", "<build>", "-j"));
    }

    static String cxxFromCc(String cc) {
        if (cc == null) return "g++";
        if (cc.matches(".*gcc-\\d+$")) return cc.replaceFirst("gcc-", "g++-");
        if (cc.endsWith("-gcc")) return cc.substring(0, cc.length() - 3) + "g++";
        if ("gcc".equals(cc)) return "g++";
        if ("clang".equals(cc)) return "clang++";
        return cc;
    }
}
