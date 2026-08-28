package com.xebyte.core;

import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Shared loader-selection for {@code /load_program} and {@code /import_file}.
 *
 * <p>Passing {@code language} used to force {@link AutoImporter#importAsBinary},
 * which ignores container format (ELF/PE/Mach-O lose their image base, sections,
 * and symbols). Language and format are independent, matching the GUI import
 * dialog:
 *
 * <ul>
 *   <li>format omitted, language omitted → {@code importByUsingBestGuess}</li>
 *   <li>format omitted, language given → {@code importByLookingForLcs} (detect
 *       the container, pin the language). No silent fall-back to raw.</li>
 *   <li>{@code format=binary} → {@code importAsBinary} (headerless firmware)</li>
 * </ul>
 */
public final class ProgramImporter {

    public enum Mode {
        AUTO,
        LANGUAGE_PINNED,
        RAW_BINARY
    }

    public static final class Result {
        public final Program program;
        public final String error;

        private Result(Program program, String error) {
            this.program = program;
            this.error = error;
        }

        public static Result ok(Program program) {
            return new Result(program, null);
        }

        public static Result fail(String error) {
            return new Result(null, error);
        }

        public boolean success() {
            return program != null;
        }
    }

    private ProgramImporter() {}

    /**
     * Choose a loader from the caller's {@code format} and {@code language}.
     *
     * @throws IllegalArgumentException if {@code format} is present and not {@code binary}/{@code raw}
     */
    public static Mode selectMode(String format, String languageId) {
        String fmt = format == null ? "" : format.trim();
        if (!fmt.isEmpty()) {
            if (fmt.equalsIgnoreCase("binary") || fmt.equalsIgnoreCase("raw")) {
                return Mode.RAW_BINARY;
            }
            throw new IllegalArgumentException(
                "Unknown format '" + fmt + "'. Omit format for loader detection, "
                    + "or pass format=binary for a raw (headerless) image.");
        }
        String lang = languageId == null ? "" : languageId.trim();
        if (!lang.isEmpty()) {
            return Mode.LANGUAGE_PINNED;
        }
        return Mode.AUTO;
    }

    /**
     * Cheap container-format probe from magic bytes. Used to name the file's
     * detected format when {@code importByLookingForLcs} refuses a language —
     * we must not silently fall back to raw, so the error has to say what the
     * file actually is.
     */
    public static String detectContainerFormat(File file) {
        if (file == null || !file.isFile()) {
            return "unknown";
        }
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] mag = in.readNBytes(4);
            if (mag.length >= 4) {
                if (mag[0] == 0x7f && mag[1] == 'E' && mag[2] == 'L' && mag[3] == 'F') {
                    return "ELF";
                }
                if (mag[0] == 'M' && mag[1] == 'Z') {
                    return "PE";
                }
                int be = ((mag[0] & 0xff) << 24)
                    | ((mag[1] & 0xff) << 16)
                    | ((mag[2] & 0xff) << 8)
                    | (mag[3] & 0xff);
                if (be == 0xFEEDFACE || be == 0xFEEDFACF
                        || be == 0xCEFAEDFE || be == 0xCFFAEDFE) {
                    return "Mach-O";
                }
                if (be == 0xCAFEBABE || be == 0xBEBAFECA) {
                    return "Mach-O Fat";
                }
            }
        } catch (IOException ignored) {
            // probe is best-effort
        }
        return "unknown";
    }

    /**
     * Import {@code file} into {@code project} (nullable — in-memory when null)
     * under {@code folderPath} (defaults to {@code "/"}).
     */
    public static Result importFile(File file, Project project, String folderPath,
            String languageId, String compilerSpecId, String format,
            Object consumer, TaskMonitor monitor) {
        if (file == null || !file.exists()) {
            return Result.fail("File not found");
        }
        String folder = (folderPath == null || folderPath.isBlank()) ? "/" : folderPath;
        Mode mode;
        try {
            mode = selectMode(format, languageId);
        } catch (IllegalArgumentException e) {
            return Result.fail(e.getMessage());
        }

        String lang = languageId == null ? "" : languageId.trim();
        String spec = compilerSpecId == null ? "" : compilerSpecId.trim();

        if (mode == Mode.RAW_BINARY && lang.isEmpty()) {
            return Result.fail("format=binary requires language (e.g. 'ARM:LE:32:Cortex')");
        }
        if (mode == Mode.LANGUAGE_PINNED && lang.isEmpty()) {
            return Result.fail("language is required when pinning a processor");
        }

        try {
            return switch (mode) {
                case AUTO -> importBestGuess(file, project, folder, consumer, monitor);
                case LANGUAGE_PINNED -> importPinnedLanguage(
                    file, project, folder, lang, spec, consumer, monitor);
                case RAW_BINARY -> importRawBinary(
                    file, project, folder, lang, spec, consumer, monitor);
            };
        } catch (Exception e) {
            Msg.error(ProgramImporter.class, "Import failed for " + file.getAbsolutePath(), e);
            return Result.fail(describeImportFailure(file, lang, e));
        }
    }

    private static Result importBestGuess(File file, Project project, String folder,
            Object consumer, TaskMonitor monitor) throws Exception {
        MessageLog log = new MessageLog();
        LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
            file, project, folder, consumer, log, monitor);
        Program program = saveAndTakePrimary(loadResults, project, consumer, monitor);
        if (program == null) {
            return Result.fail("Failed to load program from: " + file.getAbsolutePath()
                + " (auto-detect failed; for raw firmware pass language, e.g. 'ARM:LE:32:Cortex')"
                + formatLog(log));
        }
        return Result.ok(program);
    }

    private static Result importPinnedLanguage(File file, Project project, String folder,
            String languageId, String compilerSpecId, Object consumer, TaskMonitor monitor)
            throws Exception {
        LanguageAndSpec las = resolveLanguage(languageId, compilerSpecId);
        if (las.error != null) {
            return Result.fail(las.error);
        }
        MessageLog log = new MessageLog();
        try {
            LoadResults<Program> loadResults = AutoImporter.importByLookingForLcs(
                file, project, folder, las.language, las.compilerSpec, consumer, log, monitor);
            Program program = saveAndTakePrimary(loadResults, project, consumer, monitor);
            if (program == null) {
                return Result.fail(incompatibleLanguageError(file, languageId, log, null));
            }
            return Result.ok(program);
        } catch (LoadException e) {
            return Result.fail(incompatibleLanguageError(file, languageId, log, e));
        }
    }

    private static Result importRawBinary(File file, Project project, String folder,
            String languageId, String compilerSpecId, Object consumer, TaskMonitor monitor)
            throws Exception {
        LanguageAndSpec las = resolveLanguage(languageId, compilerSpecId);
        if (las.error != null) {
            return Result.fail(las.error);
        }
        MessageLog log = new MessageLog();
        Loaded<Program> loaded = AutoImporter.importAsBinary(
            file, project, folder, las.language, las.compilerSpec, consumer, log, monitor);
        if (loaded != null && project != null) {
            loaded.save(monitor);
        }
        Program program = loaded != null ? loaded.getDomainObject(consumer) : null;
        if (program == null) {
            return Result.fail("Failed to load raw binary from: " + file.getAbsolutePath()
                + " (language=" + languageId + ")" + formatLog(log));
        }
        return Result.ok(program);
    }

    private static Program saveAndTakePrimary(LoadResults<Program> loadResults,
            Project project, Object consumer, TaskMonitor monitor) throws Exception {
        if (loadResults == null) {
            return null;
        }
        try {
            if (project != null) {
                loadResults.save(monitor);
            }
            // Add our consumer before close() so the Program stays open after
            // LoadResults drops its importer-side reference.
            return loadResults.getPrimaryDomainObject(consumer);
        } finally {
            loadResults.close();
        }
    }

    private static String incompatibleLanguageError(File file, String languageId,
            MessageLog log, Exception cause) {
        String detected = detectContainerFormat(file);
        StringBuilder sb = new StringBuilder();
        sb.append("No loader accepted ").append(file.getName())
            .append(" (detected format: ").append(detected)
            .append(") with language '").append(languageId)
            .append("'. Pass format=binary only for headerless images.");
        if (cause != null && cause.getMessage() != null && !cause.getMessage().isBlank()) {
            sb.append(" (").append(cause.getMessage()).append(")");
        }
        sb.append(formatLog(log));
        return sb.toString();
    }

    private static String describeImportFailure(File file, String languageId, Exception e) {
        if (e instanceof LoadException) {
            return incompatibleLanguageError(file, languageId, new MessageLog(), e);
        }
        String msg = e.getMessage();
        if (msg == null || msg.isBlank()) {
            msg = e.getClass().getSimpleName();
        }
        return "Import failed: " + msg;
    }

    private static String formatLog(MessageLog log) {
        if (log == null) {
            return "";
        }
        String text = log.toString();
        if (text == null || text.isBlank()) {
            return "";
        }
        return ". Import log: " + text;
    }

    private static LanguageAndSpec resolveLanguage(String languageId, String compilerSpecId) {
        try {
            LanguageService langService = DefaultLanguageService.getLanguageService();
            Language language = langService.getLanguage(new LanguageID(languageId));
            CompilerSpec compilerSpec;
            if (compilerSpecId != null && !compilerSpecId.isBlank()) {
                compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compilerSpecId.trim()));
                if (compilerSpec == null) {
                    return LanguageAndSpec.error(
                        "Unknown compiler spec '" + compilerSpecId.trim()
                            + "' for language '" + languageId + "'");
                }
            } else {
                compilerSpec = language.getDefaultCompilerSpec();
            }
            return new LanguageAndSpec(language, compilerSpec, null);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return LanguageAndSpec.error(
                "Unknown language '" + languageId + "': " + msg);
        }
    }

    private static final class LanguageAndSpec {
        final Language language;
        final CompilerSpec compilerSpec;
        final String error;

        LanguageAndSpec(Language language, CompilerSpec compilerSpec, String error) {
            this.language = language;
            this.compilerSpec = compilerSpec;
            this.error = error;
        }

        static LanguageAndSpec error(String error) {
            return new LanguageAndSpec(null, null, error);
        }
    }
}
