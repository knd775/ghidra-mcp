package com.xebyte.core;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Set;

/**
 * Typed-signature transfer for {@code bsim_apply_matches}.
 *
 * <p>Every corpus reference is built with {@code -g}, so a matched function
 * has a fully typed prototype in the reference program's DWARF. References
 * are disposable inputs, never opened again after ingest, so the data lives
 * in two places written at ingest time: a Ghidra Data Type Archive
 * ({@code <artifact>.gdt}, every type the DWARF produced plus one
 * {@link FunctionDefinition} per DWARF-signed function under
 * {@link #ARCHIVE_CATEGORY}) and the prototype text, parameter count and
 * signature source in the companion {@code corroboration} schema.
 *
 * <p>A wrong name costs one rename. A wrong signature <em>propagates</em>: the
 * decompiler trusts it, and a bad struct pointer turns every caller into
 * confidently wrong field accesses. So signatures sit behind stricter gates
 * than names ({@link #decide}), and every type resolution into the target
 * uses {@link DataTypeConflictHandler#KEEP_HANDLER}: a type the analyst
 * already defined is never replaced, which also makes repeated runs
 * idempotent.
 */
public final class BSimSignatures {

    /** Category inside the archive holding one FunctionDefinition per function. */
    public static final String ARCHIVE_CATEGORY = "/bsim-sig";
    public static final String ARCHIVE_SUFFIX = ".gdt";
    /** Plate-comment marker that distinguishes a BSim-applied signature from hand work. */
    public static final String PROVENANCE_TAG = "[bsim-sig]";
    /**
     * Plate-comment marker stamped when the tool applies a name. Distinct from
     * {@link #PROVENANCE_TAG} so a names-only run is still reclaimable, and
     * from a hand rename, which never gets either line.
     */
    public static final String NAME_PROVENANCE_TAG = "[bsim]";
    /** Function tag attached to every name the tool applies. */
    public static final String FUNCTION_TAG = "bsim";
    /**
     * Separate, higher floor for signatures. 40 is a starting point, not a
     * calibration: in one real run every match above 40 was a large distinctive
     * function and the band between 15 and 40 was mixed.
     */
    public static final double DEFAULT_MIN_SIGNATURE_CONFIDENCE = 40.0;
    public static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    private BSimSignatures() {}

    // ------------------------------------------------------------------
    // Data
    // ------------------------------------------------------------------

    /**
     * What ingest stores for one function. {@code prototype} is Ghidra's
     * {@code getPrototypeString(true, true)}; {@code hasDwarf} is true only when
     * the signature source is {@link SourceType#IMPORTED} (DWARF), never
     * analysis, because an analysis-inferred signature is no better than the
     * target's own.
     */
    public record Signature(String prototype, String callingConvention, int paramCount,
                            boolean hasDwarf, String gdtPath) {
        public Signature {
            prototype = prototype == null ? "" : prototype;
            callingConvention = callingConvention == null ? "" : callingConvention;
            gdtPath = gdtPath == null ? "" : gdtPath;
        }

        public Signature withGdtPath(String path) {
            return new Signature(prototype, callingConvention, paramCount, hasDwarf, path);
        }

        public boolean isEmpty() {
            return prototype.isEmpty();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("prototype", prototype);
            if (!callingConvention.isEmpty()) m.put("calling_convention", callingConvention);
            m.put("param_count", paramCount);
            m.put("has_dwarf", hasDwarf);
            if (!gdtPath.isEmpty()) m.put("gdt_path", gdtPath);
            return m;
        }
    }

    /** Outcome of the guards in {@link #decide}. */
    public enum Decision {
        APPLY,
        SKIP_BELOW_CONFIDENCE,
        SKIP_CROSS_ARCH,
        SKIP_NO_SIGNATURE_DATA,
        SKIP_NO_DWARF,
        SKIP_NO_ARCHIVE,
        SKIP_ALREADY_APPLIED,
        SKIP_PARAM_MISMATCH
    }

    /**
     * Re-associate a local type with the current archive without changing
     * its definition. Structural identity is required: an analyst edit is
     * reported, not overwritten.
     */
    public enum RelinkDecision {
        RELINK,
        SKIP_NOT_IN_ARCHIVE,
        SKIP_DIFFERS,
        SKIP_FAILED
    }

    public static String reason(Decision d) {
        return switch (d) {
            case APPLY -> "applied";
            case SKIP_BELOW_CONFIDENCE -> "skipped_below_confidence";
            case SKIP_CROSS_ARCH -> "skipped_cross_arch";
            case SKIP_NO_SIGNATURE_DATA -> "skipped_no_signature_data";
            case SKIP_NO_DWARF -> "skipped_no_dwarf";
            case SKIP_NO_ARCHIVE -> "skipped_no_archive";
            case SKIP_ALREADY_APPLIED -> "skipped_already_applied";
            case SKIP_PARAM_MISMATCH -> "skipped_param_mismatch";
        };
    }

    public static String relinkReason(RelinkDecision d) {
        return switch (d) {
            case RELINK -> "relinked";
            case SKIP_NOT_IN_ARCHIVE -> "not_in_archive";
            case SKIP_DIFFERS -> "differs";
            case SKIP_FAILED -> "failed";
        };
    }

    /**
     * {@code inArchive} is a type of the same name in the target archive;
     * {@code equivalent} is {@link DataType#isEquivalent}. A missing type
     * or a later edit must not be replaced.
     */
    public static RelinkDecision decideRelink(boolean inArchive, boolean equivalent) {
        if (!inArchive) return RelinkDecision.SKIP_NOT_IN_ARCHIVE;
        if (!equivalent) return RelinkDecision.SKIP_DIFFERS;
        return RelinkDecision.RELINK;
    }

    /** Type work a signature application would do, computed without writing. */
    public record TypePlan(List<String> imported, List<String> keptExisting, String error) {
        public TypePlan {
            imported = imported == null ? List.of() : List.copyOf(imported);
            keptExisting = keptExisting == null ? List.of() : List.copyOf(keptExisting);
            error = error == null ? "" : error;
        }

        public static TypePlan failed(String error) {
            return new TypePlan(List.of(), List.of(), error);
        }
    }

    /** Result of one signature application. */
    public record Outcome(boolean ok, String error, String prototype, String callingConvention,
                          List<String> imported, List<String> keptExisting) {
        public Outcome {
            error = error == null ? "" : error;
            prototype = prototype == null ? "" : prototype;
            callingConvention = callingConvention == null ? "" : callingConvention;
            imported = imported == null ? List.of() : List.copyOf(imported);
            keptExisting = keptExisting == null ? List.of() : List.copyOf(keptExisting);
        }

        public static Outcome failed(String error) {
            return new Outcome(false, error, "", "", List.of(), List.of());
        }
    }

    // ------------------------------------------------------------------
    // Guards (pure)
    // ------------------------------------------------------------------

    /**
     * The load-bearing gates, in order of cost. {@code targetParamCount} may be
     * {@code null} to defer the (decompiler-priced) parameter check: a caller
     * runs the cheap guards first and only counts parameters for a candidate
     * that survived them. A negative count means "could not determine" and is
     * treated as a mismatch: an unverifiable signature is not applied.
     */
    public static Decision decide(double confidence, double minSignatureConfidence,
                                  String targetArch, String refArch,
                                  Signature sig, boolean archiveExists,
                                  boolean alreadyApplied, Integer targetParamCount) {
        if (confidence < minSignatureConfidence) return Decision.SKIP_BELOW_CONFIDENCE;
        if (!sameArch(targetArch, refArch)) return Decision.SKIP_CROSS_ARCH;
        if (sig == null || sig.isEmpty()) return Decision.SKIP_NO_SIGNATURE_DATA;
        if (!sig.hasDwarf()) return Decision.SKIP_NO_DWARF;
        if (!archiveExists) return Decision.SKIP_NO_ARCHIVE;
        if (alreadyApplied) return Decision.SKIP_ALREADY_APPLIED;
        if (targetParamCount != null
                && (targetParamCount < 0 || targetParamCount != sig.paramCount())) {
            return Decision.SKIP_PARAM_MISMATCH;
        }
        return Decision.APPLY;
    }

    /**
     * BSim's own tutorial warns that applying data types across architectures
     * is unsafe. Unknown on either side counts as different.
     */
    public static boolean sameArch(String targetArch, String refArch) {
        if (targetArch == null || refArch == null) return false;
        String a = targetArch.trim();
        String b = refArch.trim();
        if (a.isEmpty() || b.isEmpty()) return false;
        return a.equalsIgnoreCase(b);
    }

    // ------------------------------------------------------------------
    // Provenance (pure)
    // ------------------------------------------------------------------

    public static String provenanceLine(String executable, double confidence) {
        return PROVENANCE_TAG + " from " + (executable == null ? "" : executable)
                + " conf=" + String.format(Locale.ROOT, "%.1f", confidence);
    }

    public static String nameProvenanceLine(String executable, double confidence) {
        return NAME_PROVENANCE_TAG + " from " + (executable == null ? "" : executable)
                + " conf=" + String.format(Locale.ROOT, "%.1f", confidence);
    }

    /** A {@code [bsim]} or {@code [bsim-sig]} plate line. */
    public static boolean isBsimProvenanceLine(String line) {
        if (line == null) return false;
        String t = line.trim();
        return t.startsWith(PROVENANCE_TAG)
                || t.startsWith(NAME_PROVENANCE_TAG + " ")
                || t.equals(NAME_PROVENANCE_TAG);
    }

    public static boolean hasBsimProvenanceComment(String comment) {
        if (comment == null || comment.isBlank()) return false;
        for (String line : comment.split("\\R")) {
            if (isBsimProvenanceLine(line)) return true;
        }
        return false;
    }

    /** Plate marker or the {@link #FUNCTION_TAG} function tag. */
    public static boolean hasBsimProvenance(Function function) {
        if (function == null) return false;
        try {
            if (hasBsimProvenanceComment(function.getComment())) return true;
        } catch (Exception ignored) {
        }
        try {
            Set<FunctionTag> tags = function.getTags();
            if (tags == null) return false;
            for (FunctionTag tag : tags) {
                if (tag != null && FUNCTION_TAG.equals(tag.getName())) return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** Confidence from the last BSim plate marker; empty when unparseable. */
    public static OptionalDouble provenanceConfidence(String comment) {
        if (comment == null || comment.isBlank()) return OptionalDouble.empty();
        OptionalDouble found = OptionalDouble.empty();
        for (String line : comment.split("\\R")) {
            if (!isBsimProvenanceLine(line)) continue;
            String t = line.trim();
            int i = t.lastIndexOf("conf=");
            if (i < 0) continue;
            try {
                found = OptionalDouble.of(Double.parseDouble(t.substring(i + 5).trim()));
            } catch (NumberFormatException ignored) {
            }
        }
        return found;
    }

    /**
     * Append a {@link #NAME_PROVENANCE_TAG} line, replacing an earlier name
     * marker. {@link #PROVENANCE_TAG} signature lines and hand text stay.
     */
    public static String mergeNameProvenance(String existing, String line) {
        List<String> kept = new ArrayList<>();
        if (existing != null && !existing.isBlank()) {
            for (String l : existing.split("\\R")) {
                String t = l.trim();
                if (t.startsWith(NAME_PROVENANCE_TAG + " ") || t.equals(NAME_PROVENANCE_TAG)) {
                    continue;
                }
                kept.add(l);
            }
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).isBlank()) {
            kept.remove(kept.size() - 1);
        }
        kept.add(line);
        return String.join("\n", kept);
    }

    /** Drop every {@code [bsim]} / {@code [bsim-sig]} line; keep hand text. */
    public static String stripBsimProvenance(String existing) {
        if (existing == null || existing.isBlank()) return "";
        List<String> kept = new ArrayList<>();
        for (String l : existing.split("\\R")) {
            if (isBsimProvenanceLine(l)) continue;
            kept.add(l);
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).isBlank()) {
            kept.remove(kept.size() - 1);
        }
        while (!kept.isEmpty() && kept.get(0).isBlank()) {
            kept.remove(0);
        }
        return String.join("\n", kept);
    }

    /** Ghidra's {@code FUN_<addr>} form, so a demoted name is auto-generated again. */
    public static String defaultFunctionName(Address addr) {
        if (addr == null) return "FUN_unknown";
        try {
            return SymbolUtilities.getDefaultFunctionName(addr);
        } catch (Exception | LinkageError e) {
            String hex = addr.toString();
            int colon = hex.lastIndexOf(':');
            if (colon >= 0) hex = hex.substring(colon + 1);
            if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
            return "FUN_" + hex;
        }
    }

    /**
     * Executable named on the last {@code [bsim-sig]} plate line, used to
     * pick the archive when relinking types that were applied before
     * project archives existed.
     */
    public static String provenanceExecutable(String comment) {
        if (comment == null || comment.isBlank()) return "";
        String found = "";
        for (String line : comment.split("\\R")) {
            String t = line.trim();
            if (!t.startsWith(PROVENANCE_TAG)) continue;
            String rest = t.substring(PROVENANCE_TAG.length()).trim();
            if (rest.startsWith("from ")) rest = rest.substring(5);
            int conf = rest.lastIndexOf(" conf=");
            if (conf >= 0) rest = rest.substring(0, conf);
            found = rest.trim();
        }
        return found;
    }

    /** True when the plate comment already carries a marker from this reference. */
    public static boolean hasProvenance(String comment, String executable) {
        if (comment == null || comment.isBlank()) return false;
        for (String line : comment.split("\\R")) {
            String t = line.trim();
            if (!t.startsWith(PROVENANCE_TAG)) continue;
            if (executable == null || executable.isBlank()) return true;
            String from = " from " + executable.trim();
            if (t.contains(from + " ") || t.endsWith(from)) return true;
        }
        return false;
    }

    /**
     * Append the marker to an existing plate comment, replacing any earlier
     * marker so a re-application never stacks lines. Hand-written text stays.
     */
    public static String mergeProvenance(String existing, String line) {
        List<String> kept = new ArrayList<>();
        if (existing != null && !existing.isBlank()) {
            for (String l : existing.split("\\R")) {
                if (l.trim().startsWith(PROVENANCE_TAG)) continue;
                kept.add(l);
            }
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).isBlank()) {
            kept.remove(kept.size() - 1);
        }
        kept.add(line);
        return String.join("\n", kept);
    }

    // ------------------------------------------------------------------
    // Archive location
    // ------------------------------------------------------------------

    /**
     * {@code <artifact>.gdt} beside the artifact and its sidecar when that
     * directory can be written; otherwise {@code <fallbackDir>/<md5>.gdt}.
     * Never a temp directory that gets deleted: the archive must outlive the
     * ingest, because the reference program will not.
     */
    public static Path archivePathFor(String executablePath, String md5, String fallbackDir) {
        if (executablePath != null && !executablePath.isBlank()) {
            try {
                Path artifact = Path.of(executablePath.trim());
                Path parent = artifact.getParent();
                if (parent != null && Files.isDirectory(parent) && Files.isWritable(parent)) {
                    return parent.resolve(artifact.getFileName().toString() + ARCHIVE_SUFFIX);
                }
            } catch (Exception ignored) {
                // An unparseable executable path falls through to the fallback.
            }
        }
        String name = (md5 == null || md5.isBlank()) ? "reference" : md5.trim().toLowerCase(Locale.ROOT);
        Path dir = (fallbackDir == null || fallbackDir.isBlank())
                ? Path.of(System.getProperty("java.io.tmpdir"), "ghidra-mcp-gdt")
                : Path.of(fallbackDir.trim());
        return dir.resolve(name + ARCHIVE_SUFFIX);
    }

    /** {@code GHIDRA_MCP_BSIM_ROOT/gdt} when the root is configured, else blank. */
    public static String fallbackDirectory() {
        String root = BSimUrls.bsimRootEnv();
        if (root == null || root.isBlank()) return "";
        return Path.of(root.trim(), "gdt").toString();
    }

    // ------------------------------------------------------------------
    // Ingest side (Ghidra)
    // ------------------------------------------------------------------

    /** Prototype text, convention, formal parameter count and signature source. */
    public static Signature describe(Function f) {
        if (f == null) return null;
        try {
            FunctionSignature sig = f.getSignature(true);
            String proto = f.getPrototypeString(true, true);
            String cc = f.getCallingConventionName();
            int params = sig != null && sig.getArguments() != null
                    ? sig.getArguments().length : f.getParameterCount();
            // IMPORTED on an external or thunk is Ghidra's own library
            // archive (memcpy, printf...), not the reference's DWARF, and the
            // archive export skips those functions for the same reason.
            boolean dwarf = !f.isExternal() && !f.isThunk()
                    && f.getSignatureSource() == SourceType.IMPORTED;
            return new Signature(proto, cc, params, dwarf, "");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Write the program's data types and one FunctionDefinition per
     * DWARF-signed function to a Ghidra Data Type Archive. Returns the number
     * of function definitions written. Overwrites an existing archive so a
     * re-ingest refreshes it.
     */
    public static int exportArchive(Program program, Path gdt) throws IOException {
        if (program == null || gdt == null) return 0;
        if (gdt.getParent() != null) Files.createDirectories(gdt.getParent());
        Files.deleteIfExists(gdt);
        FileDataTypeManager archive = FileDataTypeManager.createFileArchive(gdt.toFile());
        try {
            int count = 0;
            int tx = archive.startTransaction("BSim signature export");
            boolean ok = false;
            try {
                List<DataType> all = new ArrayList<>();
                program.getDataTypeManager().getAllDataTypes(all);
                for (DataType dt : all) {
                    if (dt == null || isBuiltIn(dt)) continue;
                    try {
                        archive.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    } catch (Exception ignored) {
                        // One unexportable type must not lose the archive.
                    }
                }
                CategoryPath category = new CategoryPath(ARCHIVE_CATEGORY);
                archive.createCategory(category);
                for (Function f : program.getFunctionManager().getFunctions(true)) {
                    if (f == null) continue;
                    try {
                        if (f.isThunk() || f.isExternal()) continue;
                        if (f.getSignatureSource() != SourceType.IMPORTED) continue;
                        FunctionDefinitionDataType def = new FunctionDefinitionDataType(
                                category, f.getName(), f.getSignature(true));
                        archive.resolve(def, DataTypeConflictHandler.KEEP_HANDLER);
                        count++;
                    } catch (Exception ignored) {
                        // Same: skip the one function, keep the archive.
                    }
                }
                ok = true;
            } finally {
                archive.endTransaction(tx, ok);
            }
            archive.save();
            return count;
        } finally {
            archive.close();
        }
    }

    static boolean isBuiltIn(DataType dt) {
        try {
            SourceArchive src = dt.getSourceArchive();
            return src != null && src.getArchiveType() == ArchiveType.BUILT_IN;
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Apply side
    // ------------------------------------------------------------------

    /**
     * Everything apply-time needs from Ghidra, behind one seam so the guard
     * logic in {@code BSimService} is testable without a Listing. One
     * instance per apply run; {@link #close()} releases the decompiler.
     */
    public interface Applier extends AutoCloseable {
        /** Language ID string of the target, e.g. {@code ARM:LE:32:Cortex}. */
        String targetArch(Program program);

        /**
         * Parameter count the target's decompiler currently infers for this
         * function (falls back to the listing count); negative when unknown.
         */
        int targetParamCount(Program program, Function function);

        /** True when this function already carries a marker from this reference. */
        boolean alreadyApplied(Function function, String executable);

        /** Preview the type work without writing. Safe under {@code dry_run}. */
        TypePlan plan(Program program, Function function, Signature sig, String refFunction,
                      DataTypeManager archive);

        /** Apply the signature. The caller holds the program transaction. */
        Outcome apply(Program program, Function function, Signature sig, String refFunction,
                      String provenance, DataTypeManager archive);

        @Override
        default void close() {}
    }

    /** Ingest-side and apply-side Ghidra access, injected into {@code BSimService}. */
    public interface Support {
        /**
         * Export the archive for an open program; {@code null} (with a warning)
         * when it could not be written.
         */
        Path exportArchive(Program program, List<String> warnings);

        Applier applier(Program program);

        /**
         * Publish the file {@code .gdt} as a project / file / local archive.
         * Default is a no-op so tests that only care about the file path stay
         * focused.
         */
        default BSimTypeArchives.PublishResult publishTypeArchive(Program program,
                                                                  ProgramProvider provider,
                                                                  String archiveKey, Path fileGdt,
                                                                  BSimTypeArchives.Mode mode,
                                                                  List<String> warnings) {
            return BSimTypeArchives.PublishResult.NONE;
        }

        /** Named user types reachable from this function's current signature. */
        default List<String> namedSignatureTypes(Function function) {
            return BSimSignatures.namedSignatureTypes(function);
        }

        /**
         * Re-associate one local type with {@code archive} when the
         * definitions match. Writes only when {@code dryRun} is false.
         */
        default RelinkDecision relinkNamedType(Program program, String typeName,
                                               DataTypeManager archive, boolean dryRun) {
            return BSimSignatures.relinkNamedType(program, typeName, archive, dryRun);
        }

        default boolean archiveAvailable(Program program, ProgramProvider provider,
                                         Signature sig, String archiveKey,
                                         BSimTypeArchives.Mode mode) {
            return sig != null && !sig.gdtPath().isEmpty()
                    && Files.isRegularFile(Path.of(sig.gdtPath()));
        }

        default BSimTypeArchives.OpenedArchive openForApply(Program program,
                                                            ProgramProvider provider,
                                                            Signature sig, String archiveKey,
                                                            BSimTypeArchives.Mode mode)
                throws IOException {
            return BSimTypeArchives.openForApply(program, provider, sig, archiveKey, mode);
        }
    }

    public static final Support GHIDRA = new Support() {
        @Override
        public Path exportArchive(Program program, List<String> warnings) {
            try {
                Path gdt = archivePathFor(program.getExecutablePath(),
                        program.getExecutableMD5(), fallbackDirectory());
                BSimSignatures.exportArchive(program, gdt);
                return gdt;
            } catch (Exception e) {
                if (warnings != null) {
                    warnings.add("signature archive export failed: "
                            + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                }
                return null;
            }
        }

        @Override
        public BSimTypeArchives.PublishResult publishTypeArchive(Program program,
                                                                 ProgramProvider provider,
                                                                 String archiveKey, Path fileGdt,
                                                                 BSimTypeArchives.Mode mode,
                                                                 List<String> warnings) {
            return BSimTypeArchives.publish(program, provider, archiveKey, fileGdt, mode, warnings);
        }

        @Override
        public boolean archiveAvailable(Program program, ProgramProvider provider,
                                        Signature sig, String archiveKey,
                                        BSimTypeArchives.Mode mode) {
            return BSimTypeArchives.archiveAvailable(program, provider, sig, archiveKey, mode);
        }

        @Override
        public Applier applier(Program program) {
            return new GhidraApplier();
        }
    };

    static final class GhidraApplier implements Applier {
        private DecompInterface decompiler;
        private boolean decompilerFailed;

        @Override
        public String targetArch(Program program) {
            try {
                return program.getLanguageID().getIdAsString();
            } catch (Exception e) {
                return "";
            }
        }

        @Override
        public int targetParamCount(Program program, Function function) {
            try {
                DecompInterface di = decompiler(program);
                if (di != null) {
                    DecompileResults res = di.decompileFunction(function,
                            DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
                    if (res != null && res.decompileCompleted()
                            && res.getHighFunction() != null
                            && res.getHighFunction().getFunctionPrototype() != null) {
                        return res.getHighFunction().getFunctionPrototype().getNumParams();
                    }
                }
            } catch (Exception ignored) {
                // Fall through to the listing count.
            }
            try {
                return function.getParameterCount();
            } catch (Exception e) {
                return -1;
            }
        }

        private DecompInterface decompiler(Program program) {
            if (decompiler != null) return decompiler;
            if (decompilerFailed) return null;
            DecompInterface di = new DecompInterface();
            try {
                if (!di.openProgram(program)) {
                    di.dispose();
                    decompilerFailed = true;
                    return null;
                }
            } catch (Exception e) {
                di.dispose();
                decompilerFailed = true;
                return null;
            }
            decompiler = di;
            return decompiler;
        }

        @Override
        public boolean alreadyApplied(Function function, String executable) {
            try {
                return function.getSignatureSource() == SourceType.USER_DEFINED
                        && hasProvenance(function.getComment(), executable);
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public TypePlan plan(Program program, Function function, Signature sig, String refFunction,
                             DataTypeManager archive) {
            if (archive == null) {
                return TypePlan.failed("cannot open " + (sig == null ? "" : sig.gdtPath()));
            }
            FunctionDefinition def = findDefinition(archive, refFunction);
            if (def == null) {
                return TypePlan.failed("archive has no signature for " + refFunction);
            }
            List<String> imported = new ArrayList<>();
            List<String> kept = new ArrayList<>();
            planTypes(def, program.getDataTypeManager(), imported, kept);
            return new TypePlan(imported, kept, "");
        }

        @Override
        public Outcome apply(Program program, Function function, Signature sig,
                             String refFunction, String provenance, DataTypeManager archive) {
            if (archive == null) {
                return Outcome.failed("cannot open " + (sig == null ? "" : sig.gdtPath()));
            }
            try {
                FunctionDefinition def = findDefinition(archive, refFunction);
                if (def == null) {
                    return Outcome.failed("archive has no signature for " + refFunction);
                }
                DataTypeManager target = program.getDataTypeManager();
                List<String> imported = new ArrayList<>();
                List<String> kept = new ArrayList<>();
                planTypes(def, target, imported, kept);

                Map<String, DataType> cache = new LinkedHashMap<>();
                FunctionDefinitionDataType applied = new FunctionDefinitionDataType(function.getName());
                DataType ret = def.getReturnType();
                applied.setReturnType(ret == null ? VoidDataType.dataType
                        : materialize(ret, true, target, cache));
                ParameterDefinition[] args = def.getArguments();
                List<ParameterDefinition> params = new ArrayList<>();
                if (args != null) {
                    for (ParameterDefinition arg : args) {
                        params.add(new ParameterDefinitionImpl(arg.getName(),
                                materialize(arg.getDataType(), true, target, cache),
                                arg.getComment()));
                    }
                }
                applied.setArguments(params.toArray(new ParameterDefinition[0]));
                applied.setVarArgs(def.hasVarArgs());
                applied.setNoReturn(def.hasNoReturn());

                String cc = sig.callingConvention();
                boolean ccKnown = conventionKnown(program, cc);
                if (ccKnown) {
                    try {
                        applied.setCallingConvention(cc);
                    } catch (Exception ignored) {
                        ccKnown = false;
                    }
                }

                String savedComment = function.getComment();
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                        function.getEntryPoint(), applied, SourceType.USER_DEFINED,
                        false, false, DataTypeConflictHandler.KEEP_HANDLER,
                        FunctionRenameOption.NO_CHANGE);
                if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                    return Outcome.failed("ApplyFunctionSignatureCmd: " + cmd.getStatusMsg());
                }
                if (ccKnown) {
                    try {
                        function.setCallingConvention(cc);
                    } catch (Exception ignored) {
                        // The signature applied; the convention stays whatever the cmd set.
                    }
                }
                function.setComment(mergeProvenance(savedComment, provenance));
                return new Outcome(true, "", function.getPrototypeString(true, true),
                        function.getCallingConventionName(), imported, kept);
            } catch (Exception e) {
                return Outcome.failed(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
        }

        @Override
        public void close() {
            if (decompiler != null) {
                try {
                    decompiler.dispose();
                } catch (Exception ignored) {
                }
                decompiler = null;
            }
        }
    }

    static boolean conventionKnown(Program program, String cc) {
        if (cc == null || cc.isBlank()) return false;
        String t = cc.trim();
        if ("unknown".equalsIgnoreCase(t) || "default".equalsIgnoreCase(t)) return false;
        try {
            return program.getCompilerSpec().getCallingConvention(t) != null;
        } catch (Exception e) {
            return false;
        }
    }

    static FileDataTypeManager openArchive(String gdtPath) throws IOException {
        if (gdtPath == null || gdtPath.isBlank()) throw new IOException("no archive path");
        File f = new File(gdtPath);
        if (!f.isFile()) throw new IOException("archive missing");
        return FileDataTypeManager.openFileArchive(f, false);
    }

    static FunctionDefinition findDefinition(DataTypeManager archive, String name) {
        if (name == null || name.isBlank()) return null;
        DataType dt = archive.getDataType(new DataTypePath(new CategoryPath(ARCHIVE_CATEGORY), name));
        return dt instanceof FunctionDefinition fd ? fd : null;
    }

    // ------------------------------------------------------------------
    // Type mapping
    // ------------------------------------------------------------------

    /**
     * Classify every named type the definition reaches. Types the prototype
     * names directly are matched against the target <em>by name</em>, in any
     * category, so a hand-defined {@code lfs_t} at the root wins over the
     * archive's {@code /DWARF/lfs.h/lfs_t}. Types nested inside an imported
     * struct are matched by Ghidra's category path, which is what
     * {@link DataTypeManager#resolve} does with {@code KEEP_HANDLER}.
     */
    static void planTypes(FunctionDefinition def, DataTypeManager target,
                          List<String> imported, List<String> kept) {
        Set<String> seen = new LinkedHashSet<>();
        walk(def.getReturnType(), true, target, seen, imported, kept);
        ParameterDefinition[] args = def.getArguments();
        if (args != null) {
            for (ParameterDefinition arg : args) {
                walk(arg.getDataType(), true, target, seen, imported, kept);
            }
        }
    }

    private static void walk(DataType dt, boolean topLevel, DataTypeManager target,
                             Set<String> seen, List<String> imported, List<String> kept) {
        if (dt == null) return;
        if (dt instanceof Pointer p) {
            walk(p.getDataType(), topLevel, target, seen, imported, kept);
            return;
        }
        if (dt instanceof Array a) {
            walk(a.getDataType(), topLevel, target, seen, imported, kept);
            return;
        }
        if (dt instanceof BitFieldDataType b) {
            walk(b.getBaseDataType(), false, target, seen, imported, kept);
            return;
        }
        if (!isNamedUserType(dt)) return;
        String key = dt.getDataTypePath().getPath();
        if (!seen.add(key)) return;
        DataType existing = topLevel ? findByName(target, dt) : target.getDataType(dt.getDataTypePath());
        if (existing != null) {
            kept.add(dt.getName());
            return;
        }
        imported.add(dt.getName());
        if (dt instanceof TypeDef td) {
            walk(td.getDataType(), false, target, seen, imported, kept);
        } else if (dt instanceof Composite c) {
            DataTypeComponent[] comps = c.getDefinedComponents();
            if (comps != null) {
                for (DataTypeComponent comp : comps) {
                    walk(comp.getDataType(), false, target, seen, imported, kept);
                }
            }
        } else if (dt instanceof FunctionDefinition fd) {
            walk(fd.getReturnType(), false, target, seen, imported, kept);
            ParameterDefinition[] args = fd.getArguments();
            if (args != null) {
                for (ParameterDefinition arg : args) {
                    walk(arg.getDataType(), false, target, seen, imported, kept);
                }
            }
        }
    }

    /** Build the target-side type for an archive type, importing with KEEP. */
    private static DataType materialize(DataType dt, boolean topLevel, DataTypeManager target,
                                        Map<String, DataType> cache) {
        if (dt == null) return DataType.DEFAULT;
        if (dt instanceof Pointer p) {
            DataType base = p.getDataType() == null ? null
                    : materialize(p.getDataType(), topLevel, target, cache);
            return new PointerDataType(base, -1, target);
        }
        if (dt instanceof Array a) {
            DataType base = materialize(a.getDataType(), topLevel, target, cache);
            return new ArrayDataType(base, a.getNumElements(), a.getElementLength(), target);
        }
        if (!isNamedUserType(dt)) return dt;
        String key = dt.getDataTypePath().getPath();
        DataType cached = cache.get(key);
        if (cached != null) return cached;
        DataType existing = topLevel ? findByName(target, dt) : target.getDataType(dt.getDataTypePath());
        DataType result = existing != null
                ? existing : target.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
        cache.put(key, result);
        return result;
    }

    static boolean isNamedUserType(DataType dt) {
        return dt instanceof Composite
                || dt instanceof TypeDef
                || dt instanceof ghidra.program.model.data.Enum
                || dt instanceof FunctionDefinition;
    }

    /** A same-named type anywhere in the target; a same-path one is preferred. */
    static DataType findByName(DataTypeManager target, DataType dt) {
        List<DataType> found = new ArrayList<>();
        try {
            target.findDataTypes(dt.getName(), found);
        } catch (Exception e) {
            return null;
        }
        DataType samePath = null;
        DataType any = null;
        for (DataType f : found) {
            if (f == null || f instanceof Pointer || f instanceof Array) continue;
            if (!isNamedUserType(f)) continue;
            if (f.getDataTypePath().equals(dt.getDataTypePath())) {
                samePath = f;
            } else if (any == null) {
                any = f;
            }
        }
        return samePath != null ? samePath : any;
    }

    // ------------------------------------------------------------------
    // Relink already-applied signatures onto the current archive
    // ------------------------------------------------------------------

    /**
     * Counts and skipped rows for {@code relink_types}. Unique type names
     * across the program; an already-linked equivalent type counts as
     * relinked so a second run reports the same numbers.
     */
    public static final class RelinkReport {
        private int relinked;
        private int skippedNotInArchive;
        private int skippedDiffers;
        private int failed;
        private final Set<String> archives = new LinkedHashSet<>();
        private final List<Map<String, Object>> skipped = new ArrayList<>();

        public void addArchive(String archiveKey) {
            if (archiveKey != null && !archiveKey.isBlank()) archives.add(archiveKey.trim());
        }

        public void add(RelinkDecision decision, String typeName, String archiveKey) {
            if (decision == RelinkDecision.RELINK) {
                relinked++;
                return;
            }
            if (decision == RelinkDecision.SKIP_NOT_IN_ARCHIVE) skippedNotInArchive++;
            else if (decision == RelinkDecision.SKIP_DIFFERS) skippedDiffers++;
            else failed++;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("type", typeName == null ? "" : typeName);
            row.put("reason", relinkReason(decision));
            if (archiveKey != null && !archiveKey.isBlank()) row.put("archive", archiveKey);
            skipped.add(row);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("relinked", relinked);
            m.put("skipped_not_in_archive", skippedNotInArchive);
            m.put("skipped_differs", skippedDiffers);
            m.put("failed", failed);
            m.put("archives", new ArrayList<>(archives));
            return m;
        }

        public List<Map<String, Object>> skippedRows() {
            return List.copyOf(skipped);
        }
    }

    /** Named user types reachable from the function's current prototype. */
    public static List<String> namedSignatureTypes(Function function) {
        List<String> names = new ArrayList<>();
        if (function == null) return names;
        Set<String> seen = new LinkedHashSet<>();
        try {
            collectNamed(function.getReturnType(), seen, names);
            Parameter[] params = function.getParameters();
            if (params != null) {
                for (Parameter p : params) {
                    if (p != null) collectNamed(p.getDataType(), seen, names);
                }
            }
            if (!names.isEmpty()) return names;
        } catch (Exception ignored) {
        }
        try {
            FunctionSignature sig = function.getSignature(true);
            if (sig == null) return names;
            collectNamed(sig.getReturnType(), seen, names);
            ParameterDefinition[] args = sig.getArguments();
            if (args != null) {
                for (ParameterDefinition arg : args) {
                    if (arg != null) collectNamed(arg.getDataType(), seen, names);
                }
            }
        } catch (Exception ignored) {
        }
        return names;
    }

    private static void collectNamed(DataType dt, Set<String> seen, List<String> names) {
        if (dt == null) return;
        if (dt instanceof Pointer p) {
            collectNamed(p.getDataType(), seen, names);
            return;
        }
        if (dt instanceof Array a) {
            collectNamed(a.getDataType(), seen, names);
            return;
        }
        if (dt instanceof BitFieldDataType b) {
            collectNamed(b.getBaseDataType(), seen, names);
            return;
        }
        if (!isNamedUserType(dt)) return;
        if (!seen.add(dt.getName())) return;
        names.add(dt.getName());
        if (dt instanceof TypeDef td) {
            collectNamed(td.getDataType(), seen, names);
        } else if (dt instanceof Composite c) {
            DataTypeComponent[] comps = c.getDefinedComponents();
            if (comps != null) {
                for (DataTypeComponent comp : comps) {
                    collectNamed(comp.getDataType(), seen, names);
                }
            }
        } else if (dt instanceof FunctionDefinition fd) {
            collectNamed(fd.getReturnType(), seen, names);
            ParameterDefinition[] args = fd.getArguments();
            if (args != null) {
                for (ParameterDefinition arg : args) {
                    collectNamed(arg.getDataType(), seen, names);
                }
            }
        }
    }

    /**
     * If {@code typeName} exists in both the program and the archive and
     * the definitions match, point the local type at the archive. Does
     * not change the type's fields, name, or any function signature.
     */
    public static RelinkDecision relinkNamedType(Program program, String typeName,
                                                 DataTypeManager archive, boolean dryRun) {
        if (typeName == null || typeName.isBlank()) return RelinkDecision.SKIP_NOT_IN_ARCHIVE;
        DataType archived = archive == null ? null : findNamed(archive, typeName);
        DataType local = null;
        if (program != null) {
            try {
                local = findNamed(program.getDataTypeManager(), typeName);
            } catch (Exception ignored) {
            }
        }
        RelinkDecision decision = decideRelink(archived != null && local != null,
                local != null && archived != null && structurallyIdentical(local, archived));
        if (decision != RelinkDecision.RELINK || dryRun) return decision;
        try {
            if (applyRelink(local, program.getDataTypeManager(), archive)) {
                return RelinkDecision.RELINK;
            }
        } catch (Exception ignored) {
            // Association is best-effort; the type stays as it was.
        }
        return RelinkDecision.SKIP_FAILED;
    }

    static boolean structurallyIdentical(DataType local, DataType archived) {
        if (local == null || archived == null) return false;
        try {
            return local.isEquivalent(archived);
        } catch (Exception e) {
            return false;
        }
    }

    static DataType findNamed(DataTypeManager dtm, String name) {
        if (dtm == null || name == null || name.isBlank()) return null;
        List<DataType> found = new ArrayList<>();
        try {
            dtm.findDataTypes(name, found);
        } catch (Exception e) {
            return null;
        }
        DataType any = null;
        for (DataType f : found) {
            if (f == null || f instanceof Pointer || f instanceof Array) continue;
            if (!isNamedUserType(f) || !name.equals(f.getName())) continue;
            try {
                if (BSimTypeArchives.isExternalArchive(f.getSourceArchive())) return f;
            } catch (Exception ignored) {
            }
            if (any == null) any = f;
        }
        return any;
    }

    static boolean applyRelink(DataType local, DataTypeManager target, DataTypeManager archive) {
        if (local == null || target == null || archive == null) return false;
        SourceArchive archiveSource;
        try {
            archiveSource = archive.getLocalSourceArchive();
        } catch (Exception e) {
            return false;
        }
        if (archiveSource == null) return false;
        SourceArchive resolved;
        try {
            resolved = target.resolveSourceArchive(archiveSource);
        } catch (Exception e) {
            resolved = archiveSource;
        }
        if (resolved == null) resolved = archiveSource;
        if (alreadyLinked(local, resolved)) return true;
        try {
            SourceArchive current = local.getSourceArchive();
            if (current != null && BSimTypeArchives.isExternalArchive(current)
                    && !sameSource(current, resolved)) {
                target.disassociate(local);
            }
        } catch (Exception ignored) {
        }
        try {
            local.setSourceArchive(resolved);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean alreadyLinked(DataType local, SourceArchive archiveSource) {
        if (local == null || archiveSource == null) return false;
        try {
            return sameSource(local.getSourceArchive(), archiveSource);
        } catch (Exception e) {
            return false;
        }
    }

    static boolean sameSource(SourceArchive a, SourceArchive b) {
        if (a == null || b == null) return false;
        try {
            if (!BSimTypeArchives.isExternalArchive(a) || !BSimTypeArchives.isExternalArchive(b)) {
                return false;
            }
            return a.getSourceArchiveID() != null
                    && a.getSourceArchiveID().equals(b.getSourceArchiveID());
        } catch (Exception e) {
            return false;
        }
    }
}
