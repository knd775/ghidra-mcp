// BSim MCP Query
//
// Query the current program (or one function) against a BSim database and write
// JSON with separate similarity and confidence fields per match. Run from
// analyzeHeadless as a helper JVM — the headless MCP server does not load BSim.
//
// Args: [0]=bsimURL  [1]=output JSON path  [2]=function name/address or ALL
//       [3]=similarity threshold  [4]=confidence threshold  [5]=max matches
//       then optional key=value: arch= executable= compiler= exclude_md5=
//       min_feature_count= min_function_size=
//
// Whole-program MUST pass ALL, never "-". analyzeHeadless treats a bare "-" as
// a flag and drops the remaining args, so QueryNearest kept its 0.7 default
// and the whole-program path ignored similarity_threshold.
//
// Filters are QueryNearest.bsimFilter (server-side). Do not post-filter: max
// is applied after the filter, so a client-side cut would silently return
// fewer hits than requested.
//
// @author Ben Ethington
// @category Analysis.BSim
// @description MCP helper: BSim query to JSON (similarity + confidence)

import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import generic.lsh.vector.LSHVector;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.gui.filters.ArchitectureBSimFilterType;
import ghidra.features.bsim.gui.filters.CompilerBSimFilterType;
import ghidra.features.bsim.gui.filters.ExecutableNameBSimFilterType;
import ghidra.features.bsim.gui.filters.NotMd5BSimFilterType;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager.BSimPostgresDataSource;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.description.SignatureRecord;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class BSim_McpQuery extends GhidraScript {

    private static final int CHUNK = 500;
    private static final int DEFAULT_MIN_FEATURE_COUNT = 8;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            println("{\"error\":\"Args: bsimUrl outputPath [function|ALL] [sim] [conf] [max] [key=value...]\"}");
            return;
        }
        if (currentProgram == null) {
            writeJson("{\"error\":\"No program is open\"}", args[1]);
            return;
        }
        String bsimUrl = args[0].trim();
        String outPath = args[1].trim();
        String funcSel = args.length > 2 ? args[2].trim() : "ALL";
        // Default 0.0, not QueryNearest's 0.7: a missing arg must not silently
        // drop the cross-build matches this tool exists to find.
        double simThresh = args.length > 3 && !args[3].isEmpty() ? Double.parseDouble(args[3]) : 0.0;
        double confThresh = args.length > 4 && !args[4].isEmpty() ? Double.parseDouble(args[4]) : 0.0;
        int maxMatches = args.length > 5 && !args[5].isEmpty() ? Integer.parseInt(args[5]) : 10;
        String arch = "";
        String executable = "";
        String compiler = "";
        String excludeMd5 = "";
        int minFeatureCount = DEFAULT_MIN_FEATURE_COUNT;
        int minFunctionSize = 0;
        for (int i = 6; i < args.length; i++) {
            String a = args[i];
            int eq = a.indexOf('=');
            if (eq <= 0) continue;
            String key = a.substring(0, eq).trim();
            String val = a.substring(eq + 1);
            switch (key) {
                case "arch" -> arch = val;
                case "executable" -> executable = val;
                case "compiler" -> compiler = val;
                case "exclude_md5" -> excludeMd5 = val;
                case "min_feature_count" -> {
                    if (!val.isEmpty()) minFeatureCount = Integer.parseInt(val);
                }
                case "min_function_size" -> {
                    if (!val.isEmpty()) minFunctionSize = Integer.parseInt(val);
                }
                default -> {
                }
            }
        }

        List<Function> targets = new ArrayList<>();
        FunctionManager fman = currentProgram.getFunctionManager();
        if (funcSel.isEmpty() || "-".equals(funcSel) || "ALL".equalsIgnoreCase(funcSel)) {
            FunctionIterator it = fman.getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (!f.isThunk() && !f.isExternal()) targets.add(f);
            }
        } else {
            Function f = lookupFunction(funcSel);
            if (f == null) {
                writeJson("{\"error\":\"No function matching " + escape(funcSel) + "\"}", outPath);
                return;
            }
            targets.add(f);
        }

        BSimFilter filter = buildFilter(arch, executable, compiler, excludeMd5);

        FunctionDatabase database = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
            applyPostgresCredentials(bsimUrl, url);
            database = BSimClientFactory.buildClient(url, false);
            if (!database.initialize()) {
                String err = database.getLastError() != null
                        ? database.getLastError().message : "BSim initialize failed";
                writeJson("{\"error\":\"" + escape(err) + "\"}", outPath);
                return;
            }

            StringBuilder json = new StringBuilder();
            json.append("{\"program\":\"").append(escape(currentProgram.getName())).append("\",");
            json.append("\"program_md5\":\"").append(escape(nullToEmpty(currentProgram.getExecutableMD5())))
                    .append("\",");
            json.append("\"results\":[");
            boolean firstResult = true;
            int identifiableCount = 0;
            int unidentifiableCount = 0;
            int from = 0;
            while (from < targets.size()) {
                int to = Math.min(from + CHUNK, targets.size());
                List<Function> chunk = targets.subList(from, to);
                from = to;
                Map<Long, Long> sizes = new HashMap<>();
                for (Function f : chunk) {
                    sizes.put(Long.valueOf(f.getEntryPoint().getOffset()), Long.valueOf(functionSize(f)));
                }
                GenSignatures gensig = null;
                Set<Long> emitted = new HashSet<>();
                try {
                    gensig = new GenSignatures(false);
                    gensig.setVectorFactory(database.getLSHVectorFactory());
                    gensig.openProgram(currentProgram, null, null, null, null, null);
                    gensig.scanFunctions(chunk.iterator(), chunk.size(), monitor);
                    DescriptionManager manager = gensig.getDescriptionManager();
                    if (manager.numFunctions() > 0) {
                        QueryNearest query = new QueryNearest();
                        query.manage = manager;
                        query.max = maxMatches;
                        query.thresh = simThresh;
                        query.signifthresh = confThresh;
                        if (filter != null && !filter.isEmpty()) {
                            query.bsimFilter = filter;
                        }
                        ResponseNearest response = query.execute(database);
                        if (response != null && response.result != null) {
                            Iterator<SimilarityResult> resultIter = response.result.iterator();
                            while (resultIter.hasNext()) {
                                SimilarityResult sim = resultIter.next();
                                FunctionDescription base = sim.getBase();
                                emitted.add(Long.valueOf(base.getAddress()));
                                int features = featureCount(base);
                                long size = sizes.containsKey(Long.valueOf(base.getAddress()))
                                        ? sizes.get(Long.valueOf(base.getAddress())).longValue() : 0L;
                                boolean identifiable = isIdentifiable(features, size, minFeatureCount,
                                        minFunctionSize);
                                String reason = identifiableReason(features, size, minFeatureCount,
                                        minFunctionSize);
                                if (identifiable) identifiableCount++;
                                else unidentifiableCount++;
                                if (!firstResult) json.append(",");
                                firstResult = false;
                                appendFunctionStart(json, base.getFunctionName(), base.getAddress(),
                                        identifiable, reason, features, size);
                                json.append("\"matches\":[");
                                boolean firstHit = true;
                                Iterator<SimilarityNote> notes = sim.iterator();
                                while (notes.hasNext()) {
                                    SimilarityNote note = notes.next();
                                    FunctionDescription match = note.getFunctionDescription();
                                    ExecutableRecord exe = match.getExecutableRecord();
                                    if (!firstHit) json.append(",");
                                    firstHit = false;
                                    json.append("{");
                                    json.append("\"name\":\"").append(escape(match.getFunctionName())).append("\",");
                                    json.append("\"similarity\":").append(note.getSimilarity()).append(",");
                                    json.append("\"confidence\":").append(note.getSignificance()).append(",");
                                    json.append("\"executable\":\"").append(escape(exe.getNameExec())).append("\",");
                                    json.append("\"arch\":\"").append(escape(exe.getArchitecture())).append("\",");
                                    json.append("\"md5\":\"").append(escape(exe.getMd5())).append("\",");
                                    json.append("\"address\":\"0x").append(Long.toHexString(match.getAddress())).append("\"");
                                    json.append("}");
                                }
                                json.append("]}");
                            }
                        }
                    }
                } finally {
                    if (gensig != null) gensig.dispose();
                }
                // Functions BSim produced no vector for still belong in the
                // skip list on apply. Emit empty matches so they are not silent.
                for (Function f : chunk) {
                    long addr = f.getEntryPoint().getOffset();
                    if (emitted.contains(Long.valueOf(addr))) continue;
                    long size = sizes.containsKey(Long.valueOf(addr))
                            ? sizes.get(Long.valueOf(addr)).longValue() : functionSize(f);
                    int features = 0;
                    boolean identifiable = isIdentifiable(features, size, minFeatureCount, minFunctionSize);
                    String reason = identifiableReason(features, size, minFeatureCount, minFunctionSize);
                    if (identifiable) identifiableCount++;
                    else unidentifiableCount++;
                    if (!firstResult) json.append(",");
                    firstResult = false;
                    appendFunctionStart(json, f.getName(), addr, identifiable, reason, features, size);
                    json.append("\"matches\":[]}");
                }
            }
            json.append("],");
            json.append("\"identifiable_count\":").append(identifiableCount).append(",");
            json.append("\"unidentifiable_count\":").append(unidentifiableCount);
            json.append("}");
            writeJson(json.toString(), outPath);
        } catch (Exception e) {
            writeJson("{\"error\":\"" + escape(e.getClass().getSimpleName() + ": " + e.getMessage()) + "\"}",
                    outPath);
        } finally {
            if (database != null) {
                try { database.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void appendFunctionStart(StringBuilder json, String name, long addr,
            boolean identifiable, String reason, int features, long size) {
        json.append("{\"function\":\"").append(escape(name)).append("\",");
        json.append("\"address\":\"0x").append(Long.toHexString(addr)).append("\",");
        json.append("\"identifiable\":").append(identifiable).append(",");
        if (!identifiable && reason != null && !reason.isEmpty()) {
            json.append("\"reason\":\"").append(escape(reason)).append("\",");
        }
        json.append("\"feature_count\":").append(features).append(",");
        json.append("\"function_size\":").append(size).append(",");
    }

    private static BSimFilter buildFilter(String arch, String executable, String compiler,
            String excludeMd5) {
        BSimFilter filter = new BSimFilter();
        addEqualsAtoms(filter, new ArchitectureBSimFilterType(), arch);
        addEqualsAtoms(filter, new ExecutableNameBSimFilterType(), executable);
        addEqualsAtoms(filter, new CompilerBSimFilterType(), compiler);
        addEqualsAtoms(filter, new NotMd5BSimFilterType(), excludeMd5);
        return filter;
    }

    private static void addEqualsAtoms(BSimFilter filter,
            ghidra.features.bsim.gui.filters.BSimFilterType type, String raw) {
        if (raw == null || raw.isBlank()) return;
        for (String part : raw.split(",")) {
            String val = part.trim();
            if (!val.isEmpty()) {
                filter.addAtom(type, val);
            }
        }
    }

    private static int featureCount(FunctionDescription base) {
        if (base == null) return 0;
        SignatureRecord sig = base.getSignatureRecord();
        if (sig == null) return 0;
        LSHVector vec = sig.getLSHVector();
        if (vec == null) return 0;
        return vec.numEntries();
    }

    private static long functionSize(Function f) {
        if (f == null || f.getBody() == null) return 0L;
        return f.getBody().getNumAddresses();
    }

    private static boolean isIdentifiable(int features, long size, int minFeatureCount,
            int minFunctionSize) {
        if (minFeatureCount > 0 && features < minFeatureCount) return false;
        if (minFeatureCount <= 0 && minFunctionSize > 0 && size < minFunctionSize) return false;
        return true;
    }

    private static String identifiableReason(int features, long size, int minFeatureCount,
            int minFunctionSize) {
        if (minFeatureCount > 0 && features < minFeatureCount) {
            return "feature_count=" + features + " below threshold " + minFeatureCount
                    + "; similarity is not meaningful at this size";
        }
        if (minFeatureCount <= 0 && minFunctionSize > 0 && size < minFunctionSize) {
            return "function_size=" + size + " below threshold " + minFunctionSize
                    + "; similarity is not meaningful at this size";
        }
        return "";
    }

    private static void applyPostgresCredentials(String bsimUrl, URL url) {
        if (bsimUrl == null || !bsimUrl.toLowerCase().startsWith("postgresql:")) return;
        String user = envOr("GHIDRA_MCP_BSIM_USER", null);
        String password = envOr("GHIDRA_MCP_BSIM_PASSWORD", null);
        if (password == null || password.isEmpty()) return;
        BSimServerInfo info = new BSimServerInfo(url);
        BSimPostgresDataSource ds = BSimPostgresDBConnectionManager.getDataSource(info);
        String username = (user != null && !user.isEmpty()) ? user : ds.getUserName();
        if (user != null && !user.isEmpty()) {
            ds.setPreferredUserName(user);
        }
        if (username != null && !username.isEmpty()) {
            ds.setPassword(username, password.toCharArray());
        }
    }

    private static String envOr(String name, String fallback) {
        String v = System.getenv(name);
        if (v == null || v.isEmpty()) return fallback;
        return v;
    }

    private Function lookupFunction(String sel) {
        Function named = getFunction(sel);
        if (named != null) return named;
        try {
            Address addr = toAddr(sel);
            if (addr != null) {
                Function at = getFunctionAt(addr);
                if (at != null) return at;
                return getFunctionContaining(addr);
            }
        } catch (Exception ignored) {
        }
        return null;
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
