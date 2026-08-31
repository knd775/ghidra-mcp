package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Listing-level constants, strings and <em>direct</em> callees for one function.
 *
 * <p>BSim features deliberately omit constant values, register names and data
 * types so the same function still matches after a recompile. That trade makes
 * BSim blind to the evidence a human uses (CRC polynomials, hash IVs, format
 * strings). This extractor reads the disjoint set: scalar immediates that are
 * not memory addresses, string data the reference manager points at, and the
 * names {@link Function#getCalledFunctions} already resolved. It does not walk
 * into callees — that would inflate agreement and re-introduce inlining as a
 * variable.
 *
 * <p>Nothing is filtered here. {@code 0}, {@code 1} and {@code 0xffffffff} are
 * stored; distinctiveness is judged at query time against the live corpus.
 */
public final class CorroborationExtract implements CorroborationExtractor {

    public static final CorroborationExtract INSTANCE = new CorroborationExtract();

    /** Per-list cap. A few dozen is ample; mark truncation rather than grow. */
    public static final int CAP = 64;

    /** Individual string length cap; longer values are cut and mark truncation. */
    public static final int STRING_CHARS = 256;

    private CorroborationExtract() {}

    @Override
    public List<CorroborationEvidence.FunctionRow> extractAll(Program program) {
        List<CorroborationEvidence.FunctionRow> rows = new ArrayList<>();
        if (program == null) return rows;
        String md5 = programMd5(program);
        String exe = programName(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func == null) continue;
            rows.add(extract(program, func, md5, exe));
        }
        return rows;
    }

    @Override
    public CorroborationEvidence.FunctionRow extractOne(Program program, String functionOrAddress) {
        if (program == null || functionOrAddress == null || functionOrAddress.isBlank()) {
            return null;
        }
        Function func = ServiceUtils.resolveFunction(program, functionOrAddress.trim());
        if (func == null) return null;
        return extract(program, func, programMd5(program), programName(program));
    }

    public static CorroborationEvidence.FunctionRow extract(Program program, Function func,
                                                           String md5, String exeName) {
        Set<String> constants = new LinkedHashSet<>();
        Set<String> strings = new LinkedHashSet<>();
        Set<String> callees = new LinkedHashSet<>();
        boolean truncated = false;

        if (program != null && func != null && func.getBody() != null) {
            Listing listing = program.getListing();
            for (Instruction instr : listing.getInstructions(func.getBody(), true)) {
                truncated |= collectInstruction(listing, instr, constants, strings);
            }
            truncated |= collectCallees(func, callees);
        }

        List<String> constList = cap(constants);
        List<String> strList = cap(strings);
        List<String> calleeList = cap(callees);
        truncated = truncated
                || constants.size() > CAP
                || strings.size() > CAP
                || callees.size() > CAP;
        return new CorroborationEvidence.FunctionRow(
                md5 == null ? "" : md5,
                exeName == null ? "" : exeName,
                func == null ? "" : func.getName(),
                constList, strList, calleeList, truncated);
    }

    static boolean collectInstruction(Listing listing, Instruction instr,
                                      Set<String> constants, Set<String> strings) {
        boolean truncated = false;
        if (instr == null) return false;
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
                    truncated |= !addCapped(constants, canonicalizeConstant(scalar.getUnsignedValue()));
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

    static boolean collectCallees(Function func, Set<String> callees) {
        if (func == null) return false;
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
            if (name == null || name.isBlank()) continue;
            if (name.equals(func.getName())) continue;
            truncated |= !addCapped(callees, name);
        }
        return truncated;
    }

    static boolean addString(Listing listing, Address addr, Set<String> strings) {
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
        boolean overflow = !addCapped(strings, value);
        return cut || overflow;
    }

    static String stringValue(Data data) {
        Object raw = data.getValue();
        if (raw instanceof String s && !s.isEmpty()) return s;
        if (raw != null) {
            String as = raw.toString();
            if (as != null && !as.isEmpty() && !(raw instanceof Address)) return as;
        }
        String repr = data.getDefaultValueRepresentation();
        if (repr == null || repr.isEmpty()) return null;
        if (repr.length() >= 2 && repr.charAt(0) == '"' && repr.charAt(repr.length() - 1) == '"') {
            return repr.substring(1, repr.length() - 1);
        }
        return repr;
    }

    /** Canonical form used at ingest and at live query extract: lowercase {@code 0x…}. */
    public static String canonicalizeConstant(long unsigned) {
        return "0x" + Long.toHexString(unsigned);
    }

    public static boolean addCapped(Set<String> dest, String value) {
        if (value == null || value.isEmpty()) return true;
        if (dest.size() >= CAP && !dest.contains(value)) return false;
        dest.add(value);
        return true;
    }

    public static List<String> cap(Set<String> values) {
        List<String> out = new ArrayList<>();
        int i = 0;
        for (String v : values) {
            if (i++ >= CAP) break;
            out.add(v);
        }
        return List.copyOf(out);
    }

    static String programMd5(Program program) {
        if (program == null) return "";
        try {
            String md5 = program.getExecutableMD5();
            return md5 == null ? "" : md5.trim().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    static String programName(Program program) {
        if (program == null) return "";
        try {
            String name = program.getName();
            return name == null ? "" : name;
        } catch (Exception e) {
            return "";
        }
    }
}
