package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Where reference types live after ingest, and how {@code apply_signatures}
 * opens them.
 *
 * <p>A filesystem {@code .gdt} beside the artifact records the source
 * archive as a container path. Every GUI client without that filesystem
 * then warns {@code Archive file not found} on load. Project archives are
 * {@code DomainFile}s at {@link #PROJECT_FOLDER}; any client that can reach
 * the project can reach the types. File mode writes a configured stable
 * directory. Local mode disassociates after resolve so the program is
 * self-contained.
 *
 * <p>Archives are keyed by library and version, never by optimisation
 * flags: {@code littlefs-v2.9.3-gcc13-arm-O2.o} and the {@code -Os} twin
 * share {@code littlefs-v2.9.3}. A later {@code v2.10} is a new archive.
 */
public final class BSimTypeArchives {

    public static final String PROJECT_FOLDER = "/refs/types";
    public static final String ARCHIVE_SUFFIX = ".gdt";
    public static final String MODE_ENV = "GHIDRA_MCP_TYPE_ARCHIVE_MODE";
    public static final String DIR_ENV = "GHIDRA_MCP_TYPE_ARCHIVE_DIR";

    /** Test-only. {@code null} means read the real environment. Blank means unset. */
    static volatile String modeOverride;
    static volatile String dirOverride;

    private static final Object CONSUMER = new Object();

    private static final Pattern TOOLCHAIN = Pattern.compile(
            "-(gcc\\d+|clang\\d+)-(arm|x86_64|aarch64|riscv64)(?:-|$)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern OPT = Pattern.compile(
            "-(O[0123sg]|Os)(?:-|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern VERSION = Pattern.compile("v?\\d+(?:\\.\\d+)*");
    private static final Pattern FRAMEWORK_LIB = Pattern.compile(
            "^(hardware_[\\w]+|pico_[\\w]+|tinyusb_[\\w]+)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern ARTIFACT_EXT = Pattern.compile("\\.(o|elf|a|obj)$",
            Pattern.CASE_INSENSITIVE);

    public enum Mode {
        PROJECT,
        FILE,
        LOCAL
    }

    private BSimTypeArchives() {}

    public static String modeEnv() {
        return BSimUrls.envOrOverride(modeOverride, MODE_ENV);
    }

    public static String dirEnv() {
        return BSimUrls.envOrOverride(dirOverride, DIR_ENV);
    }

    public static Mode parseMode(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException(
                    "type_archive_mode must be project, file, or local");
        }
        String t = raw.trim().toLowerCase(Locale.ROOT);
        return switch (t) {
            case "project" -> Mode.PROJECT;
            case "file" -> Mode.FILE;
            case "local" -> Mode.LOCAL;
            default -> throw new IllegalArgumentException(
                    "type_archive_mode must be project, file, or local; got: " + raw);
        };
    }

    /**
     * Per-call override, then {@link #MODE_ENV}, then project-if-open,
     * then file-if-dir-configured, else local.
     */
    public static Mode resolveMode(String override, boolean projectOpen) {
        if (override != null && !override.isBlank()) return parseMode(override);
        String env = modeEnv();
        if (env != null && !env.isBlank()) return parseMode(env);
        if (projectOpen) return Mode.PROJECT;
        if (dirEnv() != null) return Mode.FILE;
        return Mode.LOCAL;
    }

    public static String projectPath(String archiveKey) {
        String key = archiveFileName(archiveKey);
        if (key.isEmpty()) return "";
        return PROJECT_FOLDER + "/" + key;
    }

    public static String archiveFileName(String archiveKey) {
        if (archiveKey == null || archiveKey.isBlank()) return "";
        String key = archiveKey.trim();
        if (!key.toLowerCase(Locale.ROOT).endsWith(ARCHIVE_SUFFIX)) {
            key = key + ARCHIVE_SUFFIX;
        }
        return key;
    }

    public static String archiveKey(String name, String ref) {
        String n = name == null ? "" : name.trim();
        String r = ref == null ? "" : ref.trim();
        if (n.isEmpty()) return r;
        if (r.isEmpty()) return n;
        return n + "-" + r;
    }

    public static String archiveKeyFromSidecar(Map<String, Object> sidecar) {
        if (sidecar == null) return "";
        return archiveKey(string(sidecar.get("name")), string(sidecar.get("ref")));
    }

    /**
     * Strip toolchain, opt, board, and a framework library token so
     * {@code pico-sdk-hardware_i2c-2.1.0-gcc13-arm-O2-pico.o} becomes
     * {@code pico-sdk-2.1.0} and {@code littlefs-v2.9.3-gcc13-arm-Os.o}
     * becomes {@code littlefs-v2.9.3}.
     */
    public static String archiveKeyFromExecutable(String executable) {
        if (executable == null || executable.isBlank()) return "";
        String name;
        try {
            name = Path.of(executable.trim()).getFileName().toString();
        } catch (Exception e) {
            name = executable.trim();
        }
        name = ARTIFACT_EXT.matcher(name).replaceFirst("");
        Matcher toolchain = TOOLCHAIN.matcher(name);
        if (toolchain.find()) {
            name = name.substring(0, toolchain.start());
        } else {
            Matcher opt = OPT.matcher(name);
            if (opt.find()) name = name.substring(0, opt.start());
        }
        return dropFrameworkLibrary(name);
    }

    static String dropFrameworkLibrary(String stem) {
        if (stem == null || stem.isBlank()) return "";
        String[] parts = stem.split("-");
        if (parts.length < 3) return stem;
        int verIdx = -1;
        for (int i = parts.length - 1; i >= 0; i--) {
            if (VERSION.matcher(parts[i]).matches()) {
                verIdx = i;
                break;
            }
        }
        if (verIdx < 2) return stem;
        if (!FRAMEWORK_LIB.matcher(parts[verIdx - 1]).matches()) return stem;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < verIdx - 1; i++) {
            if (sb.length() > 0) sb.append('-');
            sb.append(parts[i]);
        }
        sb.append('-').append(parts[verIdx]);
        return sb.toString();
    }

    /**
     * Prefer the builder sidecar ({@code name}+{@code ref}); fall back to
     * parsing the executable / gdt filename.
     */
    public static String archiveKeyForHit(String executable, String gdtPath) {
        String fromSidecar = sidecarKeyBesideGdt(gdtPath);
        if (!fromSidecar.isEmpty()) return fromSidecar;
        if (executable != null && !executable.isBlank()) {
            return archiveKeyFromExecutable(executable);
        }
        if (gdtPath != null && !gdtPath.isBlank()) {
            String file;
            try {
                file = Path.of(gdtPath.trim()).getFileName().toString();
            } catch (Exception e) {
                file = gdtPath.trim();
            }
            if (file.toLowerCase(Locale.ROOT).endsWith(ARCHIVE_SUFFIX)) {
                file = file.substring(0, file.length() - ARCHIVE_SUFFIX.length());
            }
            return archiveKeyFromExecutable(file);
        }
        return "";
    }

    public static String archiveKeyForProgram(Program program) {
        if (program == null) return "";
        try {
            String path = program.getExecutablePath();
            if (path != null && !path.isBlank()) {
                Path sidecar = FrameworkBuild.sidecarPath(Path.of(path));
                if (Files.isRegularFile(sidecar)) {
                    Map<String, Object> parsed = JsonHelper.parseJson(
                            Files.readString(sidecar));
                    String key = archiveKeyFromSidecar(parsed);
                    if (!key.isEmpty()) return key;
                }
            }
        } catch (Exception ignored) {
        }
        try {
            return archiveKeyFromExecutable(program.getName());
        } catch (Exception e) {
            return "";
        }
    }

    static String sidecarKeyBesideGdt(String gdtPath) {
        if (gdtPath == null || gdtPath.isBlank()) return "";
        try {
            Path gdt = Path.of(gdtPath.trim());
            String file = gdt.getFileName().toString();
            if (!file.toLowerCase(Locale.ROOT).endsWith(ARCHIVE_SUFFIX)) return "";
            Path sidecar = gdt.resolveSibling(
                    file.substring(0, file.length() - ARCHIVE_SUFFIX.length()) + ".json");
            if (!Files.isRegularFile(sidecar)) return "";
            return archiveKeyFromSidecar(JsonHelper.parseJson(Files.readString(sidecar)));
        } catch (Exception e) {
            return "";
        }
    }

    public static boolean isExternalArchive(SourceArchive source) {
        if (source == null) return false;
        ArchiveType type = source.getArchiveType();
        return type == ArchiveType.FILE || type == ArchiveType.PROJECT;
    }

    public static boolean isFileArchive(SourceArchive source) {
        return source != null && source.getArchiveType() == ArchiveType.FILE;
    }

    /**
     * Make types local to {@code dtm} by disassociating every FILE/PROJECT
     * source archive. Built-in and program archives stay. Returns how many
     * types were disassociated.
     */
    public static int disassociateExternal(DataTypeManager dtm) {
        return disassociate(dtm, true);
    }

    /** Disassociate only FILE-type source archives (fallback-local imports). */
    public static int disassociateFileArchives(DataTypeManager dtm) {
        return disassociate(dtm, false);
    }

    private static int disassociate(DataTypeManager dtm, boolean includeProject) {
        if (dtm == null) return 0;
        int n = 0;
        List<SourceArchive> archives = new ArrayList<>();
        try {
            List<SourceArchive> listed = dtm.getSourceArchives();
            if (listed != null) archives.addAll(listed);
        } catch (Exception e) {
            return 0;
        }
        for (SourceArchive source : archives) {
            if (source == null) continue;
            if (includeProject ? !isExternalArchive(source) : !isFileArchive(source)) continue;
            try {
                List<DataType> types = dtm.getDataTypes(source);
                if (types != null) {
                    for (DataType dt : types) {
                        if (dt == null) continue;
                        try {
                            dtm.disassociate(dt);
                            n++;
                        } catch (Exception ignored) {
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            try {
                dtm.removeSourceArchive(source);
            } catch (Exception ignored) {
            }
        }
        return n;
    }

    public static boolean archiveAvailable(Program program, ProgramProvider provider,
                                           BSimSignatures.Signature sig, String archiveKey,
                                           Mode mode) {
        if (mode == Mode.PROJECT && findProjectArchive(program, provider, archiveKey) != null) {
            return true;
        }
        if (mode == Mode.FILE) {
            Path stable = stableFilePath(archiveKey);
            if (stable != null && Files.isRegularFile(stable)) return true;
        }
        return sig != null && !sig.gdtPath().isEmpty()
                && Files.isRegularFile(Path.of(sig.gdtPath()));
    }

    /**
     * Open the archive {@code apply_signatures} will resolve from.
     * Project-mode with a missing DomainFile, and FILE-mode with no published
     * stable path, fall back to the filesystem {@code .gdt} and mark
     * {@link OpenedArchive#fallbackLocal()}.
     */
    public static OpenedArchive openForApply(Program program, ProgramProvider provider,
                                             BSimSignatures.Signature sig, String archiveKey,
                                             Mode mode) throws IOException {
        if (mode == Mode.PROJECT) {
            DomainFile df = findProjectArchive(program, provider, archiveKey);
            if (df != null) {
                try {
                    Object opened = df.getDomainObject(CONSUMER, false, false, TaskMonitor.DUMMY);
                    if (opened instanceof DataTypeArchive archive) {
                        return OpenedArchive.project(archive, df.getPathname());
                    }
                    if (opened != null) {
                        try {
                            ((ghidra.framework.model.DomainObject) opened).release(CONSUMER);
                        } catch (Exception ignored) {
                        }
                    }
                } catch (Exception e) {
                    // Fall through to local.
                }
            }
            FileDataTypeManager file = openFileArchive(sig);
            return OpenedArchive.fallbackLocal(file, sig == null ? "" : sig.gdtPath());
        }
        if (mode == Mode.FILE) {
            Path stable = stableFilePath(archiveKey);
            if (stable != null && Files.isRegularFile(stable)) {
                return OpenedArchive.file(
                        FileDataTypeManager.openFileArchive(stable.toFile(), false),
                        stable.toString());
            }
            FileDataTypeManager file = openFileArchive(sig);
            return OpenedArchive.fallbackLocal(file, sig == null ? "" : sig.gdtPath());
        }
        FileDataTypeManager file = openFileArchive(sig);
        return OpenedArchive.local(file, sig == null ? "" : sig.gdtPath());
    }

    static FileDataTypeManager openFileArchive(BSimSignatures.Signature sig) throws IOException {
        if (sig == null || sig.gdtPath().isEmpty()) {
            throw new IOException("no archive path");
        }
        return BSimSignatures.openArchive(sig.gdtPath());
    }

    /**
     * Publish the file {@code .gdt} into the configured destination.
     * {@code project} writes/updates {@link #PROJECT_FOLDER}; {@code file}
     * copies into {@link #DIR_ENV}; {@code local} writes nothing.
     *
     * @return repository or filesystem path recorded for the sidecar, or
     *         {@code null} when nothing was published
     */
    public static String publish(Program program, ProgramProvider provider, String archiveKey,
                                 Path fileGdt, Mode mode, List<String> warnings) {
        if (archiveKey == null || archiveKey.isBlank()) {
            if (warnings != null) {
                warnings.add("type archive: empty archive key; not publishing");
            }
            return null;
        }
        if (fileGdt == null || !Files.isRegularFile(fileGdt)) {
            if (warnings != null) {
                warnings.add("type archive: file .gdt missing; not publishing " + archiveKey);
            }
            return null;
        }
        try {
            return switch (mode) {
                case PROJECT -> publishProject(program, provider, archiveKey, fileGdt, warnings);
                case FILE -> publishFile(archiveKey, fileGdt, warnings);
                case LOCAL -> null;
            };
        } catch (Exception e) {
            if (warnings != null) {
                warnings.add("type archive publish failed for " + archiveKey + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
            return null;
        }
    }

    static String publishFile(String archiveKey, Path fileGdt, List<String> warnings)
            throws IOException {
        String dir = dirEnv();
        if (dir == null || dir.isBlank()) {
            if (warnings != null) {
                warnings.add("type archive: GHIDRA_MCP_TYPE_ARCHIVE_DIR is unset; "
                        + "file mode has nowhere client-resolvable to write");
            }
            return null;
        }
        Path destDir = Path.of(dir.trim());
        Files.createDirectories(destDir);
        Path dest = destDir.resolve(archiveFileName(archiveKey));
        Files.copy(fileGdt, dest, StandardCopyOption.REPLACE_EXISTING);
        return dest.toString();
    }

    static String publishProject(Program program, ProgramProvider provider, String archiveKey,
                                 Path fileGdt, List<String> warnings) throws Exception {
        DomainFolder folder = projectTypesFolder(program, provider);
        if (folder == null) {
            if (warnings != null) {
                warnings.add("type archive: no project open; not publishing "
                        + archiveKey + " as a project archive");
            }
            if (dirEnv() != null) return publishFile(archiveKey, fileGdt, warnings);
            return null;
        }
        String fileName = archiveFileName(archiveKey);
        DomainFile existing = folder.getFile(fileName);
        if (existing == null && fileName.endsWith(ARCHIVE_SUFFIX)) {
            existing = folder.getFile(fileName.substring(0, fileName.length() - ARCHIVE_SUFFIX.length()));
        }
        DataTypeArchive archive;
        if (existing != null) {
            Object opened = existing.getDomainObject(CONSUMER, true, false, TaskMonitor.DUMMY);
            if (!(opened instanceof DataTypeArchive dtArchive)) {
                if (opened instanceof ghidra.framework.model.DomainObject obj) {
                    obj.release(CONSUMER);
                }
                throw new IOException("existing " + existing.getPathname()
                        + " is not a data type archive");
            }
            archive = dtArchive;
        } else {
            archive = new DataTypeArchiveDB(folder, fileName, CONSUMER);
        }
        try {
            copyFileArchiveInto(fileGdt, archive.getDataTypeManager());
            archive.save("BSim type archive " + archiveKey, TaskMonitor.DUMMY);
            DomainFile saved = archive.getDomainFile();
            return saved != null ? saved.getPathname() : projectPath(archiveKey);
        } finally {
            archive.release(CONSUMER);
        }
    }

    static void copyFileArchiveInto(Path fileGdt, DataTypeManager dest) throws IOException {
        FileDataTypeManager src = FileDataTypeManager.openFileArchive(fileGdt.toFile(), false);
        try {
            int tx = dest.startTransaction("BSim type archive");
            boolean ok = false;
            try {
                List<DataType> all = new ArrayList<>();
                src.getAllDataTypes(all);
                for (DataType dt : all) {
                    if (dt == null || BSimSignatures.isBuiltIn(dt)) continue;
                    try {
                        dest.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    } catch (Exception ignored) {
                    }
                }
                disassociateFileArchives(dest);
                ok = true;
            } finally {
                dest.endTransaction(tx, ok);
            }
        } finally {
            src.close();
        }
    }

    static DomainFolder projectTypesFolder(Program program, ProgramProvider provider)
            throws Exception {
        if (provider != null) {
            DomainFolder folder = provider.ensureProjectFolder(PROJECT_FOLDER);
            if (folder != null) return folder;
        }
        ProjectData data = projectDataOf(program, provider);
        if (data == null) return null;
        DomainFolder current = data.getRootFolder();
        for (String part : new String[] {"refs", "types"}) {
            DomainFolder next = current.getFolder(part);
            if (next == null) next = current.createFolder(part);
            current = next;
        }
        return current;
    }

    static DomainFile findProjectArchive(Program program, ProgramProvider provider,
                                         String archiveKey) {
        if (archiveKey == null || archiveKey.isBlank()) return null;
        String fileName = archiveFileName(archiveKey);
        String path = PROJECT_FOLDER + "/" + fileName;
        String alt = fileName.endsWith(ARCHIVE_SUFFIX)
                ? PROJECT_FOLDER + "/" + fileName.substring(0, fileName.length() - ARCHIVE_SUFFIX.length())
                : path;
        ProjectData data = projectDataOf(program, provider);
        if (data != null) {
            DomainFile df = data.getFile(path);
            if (df == null) df = data.getFile(alt);
            if (df != null) return df;
        }
        if (provider != null) {
            try {
                DomainFolder folder = provider.ensureProjectFolder(PROJECT_FOLDER);
                if (folder != null) {
                    DomainFile df = folder.getFile(fileName);
                    if (df == null && fileName.endsWith(ARCHIVE_SUFFIX)) {
                        df = folder.getFile(fileName.substring(0,
                                fileName.length() - ARCHIVE_SUFFIX.length()));
                    }
                    return df;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    static ProjectData projectDataOf(Program program, ProgramProvider provider) {
        if (provider != null) {
            try {
                Project project = provider.getProject();
                if (project != null) return project.getProjectData();
            } catch (Exception ignored) {
            }
        }
        if (program == null) return null;
        try {
            DomainFile df = program.getDomainFile();
            if (df == null || df.getParent() == null) return null;
            return df.getParent().getProjectData();
        } catch (Exception e) {
            return null;
        }
    }

    static Path stableFilePath(String archiveKey) {
        String dir = dirEnv();
        if (dir == null || dir.isBlank() || archiveKey == null || archiveKey.isBlank()) {
            return null;
        }
        return Path.of(dir.trim()).resolve(archiveFileName(archiveKey));
    }

    static String string(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    /** An opened archive plus how it should be treated after resolve. */
    public static final class OpenedArchive implements AutoCloseable {
        private final DataTypeManager manager;
        private final DataTypeArchive projectArchive;
        private final Mode mode;
        private final boolean fallbackLocal;
        private final String path;

        private OpenedArchive(DataTypeManager manager, DataTypeArchive projectArchive,
                              Mode mode, boolean fallbackLocal, String path) {
            this.manager = manager;
            this.projectArchive = projectArchive;
            this.mode = mode;
            this.fallbackLocal = fallbackLocal;
            this.path = path == null ? "" : path;
        }

        public static OpenedArchive project(DataTypeArchive archive, String path) {
            return new OpenedArchive(archive.getDataTypeManager(), archive,
                    Mode.PROJECT, false, path);
        }

        public static OpenedArchive file(FileDataTypeManager manager, String path) {
            return new OpenedArchive(manager, null, Mode.FILE, false, path);
        }

        public static OpenedArchive local(FileDataTypeManager manager, String path) {
            return new OpenedArchive(manager, null, Mode.LOCAL, false, path);
        }

        public static OpenedArchive fallbackLocal(FileDataTypeManager manager, String path) {
            return new OpenedArchive(manager, null, Mode.LOCAL, true, path);
        }

        /** Test double: no live DataTypeManager. */
        public static OpenedArchive stub(Mode mode, boolean fallbackLocal, String path) {
            return new OpenedArchive(null, null, mode, fallbackLocal, path);
        }

        public DataTypeManager manager() {
            return manager;
        }

        public Mode mode() {
            return mode;
        }

        public boolean fallbackLocal() {
            return fallbackLocal;
        }

        /** True when imported types should be disassociated (local or fallback). */
        public boolean disassociateAfter() {
            return mode == Mode.LOCAL || fallbackLocal;
        }

        public String path() {
            return path;
        }

        @Override
        public void close() {
            if (projectArchive != null) {
                try {
                    projectArchive.release(CONSUMER);
                } catch (Exception ignored) {
                }
                return;
            }
            if (manager instanceof FileDataTypeManager file) {
                try {
                    file.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
