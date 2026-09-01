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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
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
            boolean dwarf = f.getSignatureSource() == SourceType.IMPORTED;
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
        TypePlan plan(Program program, Function function, Signature sig, String refFunction);

        /** Apply the signature. The caller holds the program transaction. */
        Outcome apply(Program program, Function function, Signature sig, String refFunction,
                      String provenance);

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
        public TypePlan plan(Program program, Function function, Signature sig, String refFunction) {
            FileDataTypeManager archive;
            try {
                archive = openArchive(sig.gdtPath());
            } catch (Exception e) {
                return TypePlan.failed("cannot open " + sig.gdtPath() + ": " + e.getMessage());
            }
            try {
                FunctionDefinition def = findDefinition(archive, refFunction);
                if (def == null) {
                    return TypePlan.failed("archive has no signature for " + refFunction);
                }
                List<String> imported = new ArrayList<>();
                List<String> kept = new ArrayList<>();
                planTypes(def, program.getDataTypeManager(), imported, kept);
                return new TypePlan(imported, kept, "");
            } finally {
                archive.close();
            }
        }

        @Override
        public Outcome apply(Program program, Function function, Signature sig,
                             String refFunction, String provenance) {
            FileDataTypeManager archive;
            try {
                archive = openArchive(sig.gdtPath());
            } catch (Exception e) {
                return Outcome.failed("cannot open " + sig.gdtPath() + ": " + e.getMessage());
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
            } finally {
                archive.close();
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
}
