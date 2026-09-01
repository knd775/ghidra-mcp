// BSim MCP corroboration extract
//
// Listing-level constants, strings and direct callees for every function in
// the open program, plus each function's typed prototype and a Ghidra Data
// Type Archive (.gdt) of the program's types for bsim_apply_matches
// (apply_signatures=true). Keep this file byte-identical to
// ghidra_scripts/BSim_McpExtract.java. The algorithm must stay aligned with
// CorroborationExtract.java (cap 64, lowercase 0x hex, no callee recursion)
// and BSimSignatures.java (category /bsim-sig, DWARF = IMPORTED source,
// <artifact>.gdt beside the artifact else <fallback>/<md5>.gdt).
//
// Args: [0]=output JSON path
//       [1]=optional fallback directory for the .gdt when the artifact's
//           directory is not writable (blank = java.io.tmpdir/ghidra-mcp-gdt)
//
// @author Ben Ethington
// @category Analysis.BSim
// @description MCP helper: extract corroboration evidence and signatures to JSON

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class BSim_McpExtract extends GhidraScript {

    private static final int CAP = 64;
    private static final int STRING_CHARS = 256;
    private static final String ARCHIVE_CATEGORY = "/bsim-sig";
    private static final String ARCHIVE_SUFFIX = ".gdt";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            println("{\"error\":\"Args: outputPath [gdtFallbackDir]\"}");
            return;
        }
        String outPath = args[0].trim();
        String gdtFallback = args.length > 1 ? args[1].trim() : "";
        if (currentProgram == null) {
            writeJson("{\"error\":\"No program is open\"}", outPath);
            return;
        }
        StringBuilder json = new StringBuilder();
        json.append("{\"md5\":\"");
        json.append(escape(nullToEmpty(currentProgram.getExecutableMD5())));
        json.append("\",\"executable\":\"");
        json.append(escape(nullToEmpty(currentProgram.getName())));
        json.append("\",\"functions\":[");
        boolean first = true;
        Listing listing = currentProgram.getListing();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func == null) continue;
            if (!first) json.append(',');
            first = false;
            appendFunction(json, listing, func);
        }
        json.append("]");
        String gdtError = null;
        String gdtPath = "";
        int signatureCount = 0;
        try {
            File gdt = archivePathFor(currentProgram.getExecutablePath(),
                    currentProgram.getExecutableMD5(), gdtFallback);
            signatureCount = exportArchive(gdt);
            gdtPath = gdt.getAbsolutePath();
        } catch (Exception e) {
            gdtError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        }
        json.append(",\"gdt_path\":\"").append(escape(gdtPath)).append('"');
        json.append(",\"signature_count\":").append(signatureCount);
        if (gdtError != null) {
            json.append(",\"gdt_error\":\"").append(escape(gdtError)).append('"');
        }
        json.append('}');
        writeJson(json.toString(), outPath);
    }

    private void appendFunction(StringBuilder json, Listing listing, Function func) {
        Set<String> constants = new LinkedHashSet<>();
        Set<String> strings = new LinkedHashSet<>();
        Set<String> callees = new LinkedHashSet<>();
        boolean truncated = false;
        if (func.getBody() != null) {
            for (Instruction instr : listing.getInstructions(func.getBody(), true)) {
                truncated |= collectInstruction(listing, instr, constants, strings);
            }
            truncated |= collectCallees(func, callees);
        }
        truncated = truncated || constants.size() > CAP || strings.size() > CAP
                || callees.size() > CAP;
        json.append("{\"function\":\"").append(escape(func.getName())).append("\",");
        json.append("\"constants\":");
        appendArray(json, cap(constants));
        json.append(",\"strings\":");
        appendArray(json, cap(strings));
        json.append(",\"callees\":");
        appendArray(json, cap(callees));
        json.append(",\"truncated\":").append(truncated);
        appendSignature(json, func);
        json.append('}');
    }

    private static void appendSignature(StringBuilder json, Function func) {
        try {
            FunctionSignature sig = func.getSignature(true);
            String prototype = func.getPrototypeString(true, true);
            String cc = func.getCallingConventionName();
            int params = sig != null && sig.getArguments() != null
                    ? sig.getArguments().length : func.getParameterCount();
            // Externals and thunks carry Ghidra's library-archive signature,
            // not the reference's DWARF (mirrors BSimSignatures.describe).
            boolean dwarf = !func.isExternal() && !func.isThunk()
                    && func.getSignatureSource() == SourceType.IMPORTED;
            json.append(",\"prototype\":\"").append(escape(nullToEmpty(prototype))).append('"');
            json.append(",\"calling_convention\":\"").append(escape(nullToEmpty(cc))).append('"');
            json.append(",\"param_count\":").append(params);
            json.append(",\"has_dwarf\":").append(dwarf);
        } catch (Exception ignored) {
            // A function without a readable signature simply has no signature row.
        }
    }

    private static File archivePathFor(String executablePath, String md5, String fallbackDir) {
        if (executablePath != null && !executablePath.isBlank()) {
            try {
                File artifact = new File(executablePath.trim());
                File parent = artifact.getParentFile();
                if (parent != null && parent.isDirectory() && parent.canWrite()) {
                    return new File(parent, artifact.getName() + ARCHIVE_SUFFIX);
                }
            } catch (Exception ignored) {
            }
        }
        String name = (md5 == null || md5.isBlank()) ? "reference" : md5.trim().toLowerCase(Locale.ROOT);
        File dir = (fallbackDir == null || fallbackDir.isBlank())
                ? new File(System.getProperty("java.io.tmpdir"), "ghidra-mcp-gdt")
                : new File(fallbackDir.trim());
        return new File(dir, name + ARCHIVE_SUFFIX);
    }

    private int exportArchive(File gdt) throws Exception {
        File parent = gdt.getParentFile();
        if (parent != null) parent.mkdirs();
        if (gdt.exists() && !gdt.delete()) {
            throw new java.io.IOException("cannot replace " + gdt);
        }
        FileDataTypeManager archive = FileDataTypeManager.createFileArchive(gdt);
        try {
            int count = 0;
            int tx = archive.startTransaction("BSim signature export");
            boolean ok = false;
            try {
                List<DataType> all = new ArrayList<>();
                currentProgram.getDataTypeManager().getAllDataTypes(all);
                for (DataType dt : all) {
                    if (dt == null || isBuiltIn(dt)) continue;
                    try {
                        archive.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    } catch (Exception ignored) {
                    }
                }
                CategoryPath category = new CategoryPath(ARCHIVE_CATEGORY);
                archive.createCategory(category);
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    if (f == null) continue;
                    try {
                        if (f.isThunk() || f.isExternal()) continue;
                        if (f.getSignatureSource() != SourceType.IMPORTED) continue;
                        FunctionDefinitionDataType def = new FunctionDefinitionDataType(
                                category, f.getName(), f.getSignature(true));
                        archive.resolve(def, DataTypeConflictHandler.KEEP_HANDLER);
                        count++;
                    } catch (Exception ignored) {
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

    private static boolean isBuiltIn(DataType dt) {
        try {
            SourceArchive src = dt.getSourceArchive();
            return src != null && src.getArchiveType() == ArchiveType.BUILT_IN;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean collectInstruction(Listing listing, Instruction instr,
            Set<String> constants, Set<String> strings) {
        boolean truncated = false;
        int n = instr.getNumOperands();
        for (int i = 0; i < n; i++) {
            boolean memory = false;
            Reference[] opRefs = instr.getOperandReferences(i);
            if (opRefs != null) {
                for (Reference ref : opRefs) {
                    if (ref != null && ref.isMemoryReference()) {
                        memory = true;
                        truncated |= addString(listing, ref.getToAddress(), strings);
                    }
                }
            }
            if (!memory) {
                Scalar scalar = instr.getScalar(i);
                if (scalar != null) {
                    truncated |= !addCapped(constants, "0x" + Long.toHexString(scalar.getUnsignedValue()));
                }
            }
        }
        Reference[] from = instr.getReferencesFrom();
        if (from != null) {
            for (Reference ref : from) {
                if (ref != null && ref.isMemoryReference() && ref.getReferenceType().isData()) {
                    truncated |= addString(listing, ref.getToAddress(), strings);
                }
            }
        }
        return truncated;
    }

    private static boolean collectCallees(Function func, Set<String> callees) {
        boolean truncated = false;
        Set<Function> called;
        try {
            called = func.getCalledFunctions(null);
        } catch (Exception e) {
            return false;
        }
        if (called == null) return false;
        for (Function callee : called) {
            if (callee == null) continue;
            Function named = callee;
            try {
                if (callee.isThunk()) {
                    Function thunked = callee.getThunkedFunction(true);
                    if (thunked != null) named = thunked;
                }
            } catch (Exception ignored) {
            }
            String name = named.getName();
            if (name == null || name.isEmpty()) continue;
            if (name.equals(func.getName())) continue;
            truncated |= !addCapped(callees, name);
        }
        return truncated;
    }

    private static boolean addString(Listing listing, Address addr, Set<String> strings) {
        if (listing == null || addr == null) return false;
        Data data = listing.getDataAt(addr);
        if (data == null) {
            try {
                data = listing.getDefinedDataContaining(addr);
            } catch (Exception ignored) {
                data = null;
            }
        }
        if (data == null || !data.hasStringValue()) return false;
        String value = stringValue(data);
        if (value == null || value.isEmpty()) return false;
        boolean cut = value.length() > STRING_CHARS;
        if (cut) value = value.substring(0, STRING_CHARS);
        return cut || !addCapped(strings, value);
    }

    private static String stringValue(Data data) {
        Object raw = data.getValue();
        if (raw instanceof String && !((String) raw).isEmpty()) return (String) raw;
        if (raw != null && !(raw instanceof Address)) {
            String as = raw.toString();
            if (as != null && !as.isEmpty()) return as;
        }
        String repr = data.getDefaultValueRepresentation();
        if (repr == null || repr.isEmpty()) return null;
        if (repr.length() >= 2 && repr.charAt(0) == '"' && repr.charAt(repr.length() - 1) == '"') {
            return repr.substring(1, repr.length() - 1);
        }
        return repr;
    }

    private static boolean addCapped(Set<String> dest, String value) {
        if (value == null || value.isEmpty()) return true;
        if (dest.size() >= CAP && !dest.contains(value)) return false;
        dest.add(value);
        return true;
    }

    private static List<String> cap(Set<String> values) {
        List<String> out = new ArrayList<>();
        int i = 0;
        for (String v : values) {
            if (i++ >= CAP) break;
            out.add(v);
        }
        return out;
    }

    private static void appendArray(StringBuilder json, List<String> values) {
        json.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) json.append(',');
            json.append('"').append(escape(values.get(i))).append('"');
        }
        json.append(']');
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t");
    }

    private void writeJson(String json, String path) throws Exception {
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null) parent.mkdirs();
        try (PrintWriter pw = new PrintWriter(f, "UTF-8")) {
            pw.print(json);
        }
        println(json.length() > 200 ? json.substring(0, 200) + "..." : json);
    }
}
