package com.xebyte.core;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Locate and optionally remove Ghidra project lock files under a
 * {@code .rep} directory / {@code .gpr} marker.
 *
 * <p>A successful {@code close()} that leaves these behind makes the next
 * {@code open_project} fail with a generic "Failed to open project" and
 * nothing to act on.
 */
public final class ProjectLocks {

    private ProjectLocks() {}

    public static List<String> find(File projectDir, File markerFile) {
        List<String> out = new ArrayList<>();
        addIfExists(out, markerFile != null
            ? new File(markerFile.getAbsolutePath() + ".lock") : null);
        addIfExists(out, markerFile != null
            ? new File(markerFile.getParentFile(), markerFile.getName() + ".lock") : null);
        if (projectDir != null && projectDir.isDirectory()) {
            File[] files = projectDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    String n = f.getName().toLowerCase(Locale.ROOT);
                    if (n.contains("lock")) {
                        addIfExists(out, f);
                    }
                }
            }
        }
        return out;
    }

    /**
     * Best-effort delete after we have closed the project we held. Returns
     * paths that still exist.
     */
    public static List<String> tryDelete(List<String> paths) {
        List<String> remaining = new ArrayList<>();
        if (paths == null) {
            return remaining;
        }
        for (String p : paths) {
            if (p == null || p.isBlank()) {
                continue;
            }
            try {
                Files.deleteIfExists(java.nio.file.Path.of(p));
            } catch (Exception ignored) {
                // fall through to existence check
            }
            if (Files.exists(java.nio.file.Path.of(p))) {
                remaining.add(p);
            }
        }
        return remaining;
    }

    public static String describeOpenFailure(String projectPath, Throwable error,
            File projectDir, File markerFile) {
        String base = "Failed to open project: " + projectPath;
        if (error != null && error.getMessage() != null && !error.getMessage().isBlank()) {
            base += " (" + error.getMessage() + ")";
        } else if (error != null) {
            base += " (" + error.getClass().getSimpleName() + ")";
        }
        List<String> locks = find(projectDir, markerFile);
        String errText = error != null && error.getMessage() != null
            ? error.getMessage().toLowerCase(Locale.ROOT) : "";
        boolean lockish = errText.contains("lock") || errText.contains("in use")
            || errText.contains("already open") || errText.contains("already in use");
        if (locks.isEmpty() && !lockish) {
            return base;
        }
        String lockList = locks.isEmpty()
            ? "none found under the .rep directory"
            : String.join(", ", locks);
        return base + ". Lock files: " + lockList
            + ". If no other Ghidra process has this project open, delete those files and retry.";
    }

    private static void addIfExists(List<String> out, File f) {
        if (f != null && f.exists()) {
            String path = f.getAbsolutePath();
            if (!out.contains(path)) {
                out.add(path);
            }
        }
    }
}
