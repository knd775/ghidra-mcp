// BSim MCP Query
//
// Query the current program (or one function) against a BSim database and write
// JSON with separate similarity and confidence fields per match. Run from
// analyzeHeadless as a helper JVM — the headless MCP server does not load BSim.
//
// Args: [0]=bsimURL  [1]=output JSON path  [2]=function name/address or "-"
//       [3]=similarity threshold  [4]=confidence threshold  [5]=max matches
//
// @author Ben Ethington
// @category Analysis.BSim
// @description MCP helper: BSim query to JSON (similarity + confidence)

import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
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

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            println("{\"error\":\"Args: bsimUrl outputPath [function|-] [sim] [conf] [max]\"}");
            return;
        }
        if (currentProgram == null) {
            writeJson("{\"error\":\"No program is open\"}", args[1]);
            return;
        }
        String bsimUrl = args[0].trim();
        String outPath = args[1].trim();
        String funcSel = args.length > 2 ? args[2].trim() : "-";
        double simThresh = args.length > 3 && !args[3].isEmpty() ? Double.parseDouble(args[3]) : 0.7;
        double confThresh = args.length > 4 && !args[4].isEmpty() ? Double.parseDouble(args[4]) : 0.0;
        int maxMatches = args.length > 5 && !args[5].isEmpty() ? Integer.parseInt(args[5]) : 10;

        List<Function> targets = new ArrayList<>();
        FunctionManager fman = currentProgram.getFunctionManager();
        if (funcSel.isEmpty() || "-".equals(funcSel)) {
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

        FunctionDatabase database = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
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
            int from = 0;
            while (from < targets.size()) {
                int to = Math.min(from + CHUNK, targets.size());
                List<Function> chunk = targets.subList(from, to);
                from = to;
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
                        ResponseNearest response = query.execute(database);
                        if (response != null && response.result != null) {
                            Iterator<SimilarityResult> resultIter = response.result.iterator();
                            while (resultIter.hasNext()) {
                                SimilarityResult sim = resultIter.next();
                                FunctionDescription base = sim.getBase();
                                emitted.add(Long.valueOf(base.getAddress()));
                                if (!firstResult) json.append(",");
                                firstResult = false;
                                json.append("{\"function\":\"").append(escape(base.getFunctionName())).append("\",");
                                json.append("\"address\":\"0x").append(Long.toHexString(base.getAddress())).append("\",");
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
                    if (!firstResult) json.append(",");
                    firstResult = false;
                    json.append("{\"function\":\"").append(escape(f.getName())).append("\",");
                    json.append("\"address\":\"0x").append(Long.toHexString(addr)).append("\",");
                    json.append("\"matches\":[]}");
                }
            }
            json.append("]}");
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
