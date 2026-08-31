// BSim MCP corroboration extract
//
// Listing-level constants, strings and direct callees for every function in
// the open program. Keep this file byte-identical to
// ghidra_scripts/BSim_McpExtract.java. The algorithm must stay aligned with
// CorroborationExtract.java (cap 64, lowercase 0x hex, no callee recursion).
//
// Args: [0]=output JSON path
//
// @author Ben Ethington
// @category Analysis.BSim
// @description MCP helper: extract corroboration evidence to JSON

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class BSim_McpExtract extends GhidraScript {

    private static final int CAP = 64;
    private static final int STRING_CHARS = 256;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            println("{\"error\":\"Args: outputPath\"}");
            return;
        }
        String outPath = args[0].trim();
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
        json.append("]}");
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
        json.append(",\"truncated\":").append(truncated).append('}');
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
