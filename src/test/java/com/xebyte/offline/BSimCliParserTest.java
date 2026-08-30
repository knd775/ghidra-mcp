package com.xebyte.offline;

import com.xebyte.core.BSimCliParser;
import com.xebyte.core.BSimMatches;
import com.xebyte.core.BSimService;
import com.xebyte.core.BSimUrls;
import junit.framework.TestCase;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parser / scoring / URL tests for the BSim CLI wrapper. No Ghidra process.
 */
public class BSimCliParserTest extends TestCase {

    public void testParseListexesPlain() {
        String out = "aabbccddeeff00112233445566778899 littlefs-2.9.3-gcc13-Os ARM:LE:32:Cortex gcc\n"
                + "1 executables found\n";
        List<BSimCliParser.ExeRecord> exes = BSimCliParser.parseExeList(out);
        assertEquals(1, exes.size());
        assertEquals("littlefs-2.9.3-gcc13-Os", exes.get(0).name);
        assertEquals("ARM:LE:32:Cortex", exes.get(0).arch);
        assertEquals("gcc", exes.get(0).compiler);
        assertEquals(Integer.valueOf(1), BSimCliParser.parseExeCount(out));
    }

    public void testParseListexesLogPrefix() {
        String out = "2026-08-29 00:00:00 INFO  (BSimLaunchable) "
                + "deadbeefdeadbeefdeadbeefdeadbeef firmware.elf ARM:LE:32:Cortex unknown\n"
                + "2026-08-29 00:00:00 INFO  (BSimLaunchable) 1 executables found\n";
        List<BSimCliParser.ExeRecord> exes = BSimCliParser.parseExeList(out);
        assertEquals(1, exes.size());
        assertEquals("firmware.elf", exes.get(0).name);
        assertEquals(Integer.valueOf(1), BSimCliParser.parseExeCount(out));
    }

    public void testParseEmptyCorpus() {
        String out = "Matching executable count: 0\n";
        assertEquals(Integer.valueOf(0), BSimCliParser.parseExeCount(out));
        assertTrue(BSimCliParser.parseExeList(out).isEmpty());
    }

    public void testParseMetadata() {
        String out = "BSim metadata: \n Database: littlefs\n Owner: ben\n Description: RP2040 refs\n";
        Map<String, String> meta = BSimCliParser.parseMetadata(out);
        assertEquals("littlefs", meta.get("database"));
        assertEquals("ben", meta.get("owner"));
        assertEquals("RP2040 refs", meta.get("description"));
    }

    public void testAmbiguousNeverAppliedAtAnyConfidence() {
        List<BSimMatches.Hit> hits = List.of(
                hit("lfs_fs_traverse_", 0.99, 80.0),
                hit("lfs_dir_getread", 0.96, 75.0));
        BSimMatches.FunctionResult fr = BSimMatches.finalizeResult("FUN_1", "0x1", hits, null);
        assertTrue(fr.ambiguous);
        assertEquals(BSimMatches.ApplyAction.SKIP_AMBIGUOUS,
                BSimMatches.decide(fr, "FUN_1", true, 0.8, 0.0));
        assertEquals(BSimMatches.ApplyAction.SKIP_AMBIGUOUS,
                BSimMatches.decide(fr, "FUN_1", true, 0.5, 100.0));
    }

    public void testNotAmbiguousWhenSameNameFromTwoBuilds() {
        List<BSimMatches.Hit> hits = List.of(
                hit("lfs_bd_read", 0.94, 38.2, "littlefs-gcc13-Os"),
                hit("lfs_bd_read", 0.93, 36.0, "littlefs-gcc11-O2"));
        assertFalse(BSimMatches.isAmbiguous(hits));
        BSimMatches.FunctionResult fr = BSimMatches.finalizeResult("FUN_1", "0x1", hits, null);
        assertEquals(BSimMatches.ApplyAction.APPLY,
                BSimMatches.decide(fr, "FUN_1", true, 0.8, 20.0));
    }

    public void testSkipAlreadyNamed() {
        List<BSimMatches.Hit> hits = List.of(hit("lfs_bd_read", 0.94, 38.2));
        BSimMatches.FunctionResult fr = BSimMatches.finalizeResult("ProcessBuffer", "0x1", hits, null);
        assertEquals(BSimMatches.ApplyAction.SKIP_NAMED,
                BSimMatches.decide(fr, "ProcessBuffer", true, 0.8, 20.0));
        assertEquals(BSimMatches.ApplyAction.APPLY,
                BSimMatches.decide(fr, "FUN_1000", true, 0.8, 20.0));
    }

    public void testSkipBelowConfidenceEvenAtHighSimilarity() {
        List<BSimMatches.Hit> hits = List.of(hit("lfs_bd_sync", 0.99, 4.2));
        BSimMatches.FunctionResult fr = BSimMatches.finalizeResult("FUN_1", "0x1", hits, null);
        assertEquals(BSimMatches.ApplyAction.SKIP_CONFIDENCE,
                BSimMatches.decide(fr, "FUN_1", true, 0.8, 20.0));
    }

    public void testDropSelfMatchesByMd5() {
        BSimMatches.Hit self = new BSimMatches.Hit(
                "FUN_1", 1.0, 99.0, "firmware.elf", "ARM:LE:32:Cortex", "abc", "0x1");
        BSimMatches.Hit other = new BSimMatches.Hit(
                "lfs_bd_read", 0.94, 38.2, "littlefs.o", "ARM:LE:32:Cortex", "def", "0x2");
        BSimMatches.FunctionResult fr = BSimMatches.finalizeResult(
                "FUN_1", "0x1", List.of(self, other), "abc");
        assertEquals(1, fr.matches.size());
        assertEquals("lfs_bd_read", fr.best().name);
        assertFalse(fr.ambiguous);
    }

    public void testParseQueryPayloadAddsAmbiguous() {
        Map<String, Object> payload = new LinkedHashMap<>();
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, Object> fn = new LinkedHashMap<>();
        fn.put("function", "FUN_10006cd8");
        fn.put("address", "0x10006cd8");
        fn.put("matches", List.of(
                hitMap("lfs_bd_read", 0.94, 38.2, "littlefs-2.9.3-gcc13-Os.o", "ARM:LE:32:Cortex"),
                hitMap("lfs_bd_prog", 0.71, 9.4, "littlefs-2.9.3-gcc13-Os.o", "ARM:LE:32:Cortex")));
        results.add(fn);
        payload.put("results", results);
        List<BSimMatches.FunctionResult> parsed = BSimMatches.parseQueryPayload(payload, null);
        assertEquals(1, parsed.size());
        assertEquals("FUN_10006cd8", parsed.get(0).function);
        assertEquals(0.94, parsed.get(0).best().similarity, 0.0001);
        assertEquals(38.2, parsed.get(0).best().confidence, 0.0001);
        assertFalse(parsed.get(0).ambiguous);
        Map<String, Object> asMap = parsed.get(0).toMap();
        assertFalse(asMap.containsKey("similarity"));
        assertTrue(((List<?>) asMap.get("matches")).size() == 2);
        assertEquals(Boolean.FALSE, asMap.get("ambiguous"));
    }

    public void testMissingServerCredentialOnlyForServerUrls() {
        assertNull(BSimUrls.missingServerCredential("ghidra:/tmp/proj/Name"));
        assertNull(BSimUrls.missingServerCredential("/5n4ck3y/nullcog-v2"));
        if (System.getenv("GHIDRA_SERVER_PASSWORD") != null
                && !System.getenv("GHIDRA_SERVER_PASSWORD").isBlank()) {
            return;
        }
        if (System.getenv("GHIDRA_PASS") != null && !System.getenv("GHIDRA_PASS").isBlank()) {
            return;
        }
        String err = BSimUrls.missingServerCredential(
                "ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2");
        assertNotNull(err);
        assertTrue(err.contains("GHIDRA_SERVER_PASSWORD"));
    }

    public void testRejectBadDbUrl() {
        try {
            BSimUrls.requireBsimUrl("--help");
            fail("expected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("flag") || e.getMessage().contains("file:"));
        }
        try {
            BSimUrls.requireBsimUrl("javascript:alert(1)");
            fail("expected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("db_url"));
        }
        assertEquals("file:/srv/ghidra/bsim/lfs", BSimUrls.requireBsimUrl("file:/srv/ghidra/bsim/lfs"));
    }

    public void testConfigTemplateAllowlist() {
        assertEquals("medium_32", BSimUrls.requireConfigTemplate("medium_32"));
        assertEquals(32, BSimUrls.templatePointerBits("medium_32"));
        assertEquals(64, BSimUrls.templatePointerBits("medium_64"));
        assertEquals(0, BSimUrls.templatePointerBits("medium_nosize"));
        try {
            BSimUrls.requireConfigTemplate("huge_128");
            fail("expected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("config_template"));
        }
    }

    public void testArchPointerBits() {
        assertEquals(32, BSimUrls.archPointerBits("ARM:LE:32:Cortex"));
        assertEquals(64, BSimUrls.archPointerBits("x86:LE:64:default"));
        assertEquals(-1, BSimUrls.archPointerBits(""));
        assertEquals(Set.of(32), BSimUrls.uniqueArchSizes(
                List.of("ARM:LE:32:Cortex", "ARM:LE:32:v8")));
        assertEquals(Set.of(32, 64), BSimUrls.uniqueArchSizes(
                List.of("ARM:LE:32:Cortex", "x86:LE:64:default")));
    }

    public void testFileUrlToPathIsAbsolute() {
        File oneSlash = BSimUrls.fileUrlToPath("file:/tmp/bsim/lfs");
        File threeSlash = BSimUrls.fileUrlToPath("file:///tmp/bsim/lfs");
        assertTrue("file:/tmp/... must not become CWD-relative", oneSlash.isAbsolute());
        assertTrue(threeSlash.isAbsolute());
        assertEquals(oneSlash.getAbsolutePath(), threeSlash.getAbsolutePath());
    }

    public void testQueryScriptResourceMatchesGhidraScriptsCopy() throws Exception {
        byte[] resource = BSimService.class.getResourceAsStream("/bsim/BSim_McpQuery.java").readAllBytes();
        Path copy = Path.of("ghidra_scripts", "BSim_McpQuery.java");
        assertTrue("ghidra_scripts/BSim_McpQuery.java missing", Files.isRegularFile(copy));
        byte[] disk = Files.readAllBytes(copy);
        assertEquals(new String(resource, StandardCharsets.UTF_8),
                new String(disk, StandardCharsets.UTF_8));
        String src = new String(resource, StandardCharsets.UTF_8);
        // The helper is Java source that appends JSON keys; the file contains
        // \"confidence\": rather than the raw JSON token "confidence":
        assertTrue(src.contains("confidence"));
        assertTrue(src.contains("similarity"));
        assertFalse("script must not emit a combined score field",
                src.contains("\\\"score\\\":") || src.contains("\"score\":"));
    }

    public void testSimilarityThresholdWarningFiresAboveHalf() {
        assertNull(BSimMatches.similarityThresholdWarning(0.0));
        assertNull(BSimMatches.similarityThresholdWarning(0.5));
        String warn = BSimMatches.similarityThresholdWarning(0.7);
        assertNotNull(warn);
        assertTrue(warn, warn.contains("0.7"));
        assertTrue(warn, warn.contains("confidence"));
        Map<String, Object> body = new LinkedHashMap<>();
        BSimMatches.attachSimilarityWarning(body, 0.0);
        assertFalse(body.containsKey("warnings"));
        BSimMatches.attachSimilarityWarning(body, 0.7);
        assertTrue(body.containsKey("warnings"));
        @SuppressWarnings("unchecked")
        List<String> warnings = (List<String>) body.get("warnings");
        assertEquals(1, warnings.size());
        assertEquals(warn, warnings.get(0));
    }

    private static BSimMatches.Hit hit(String name, double sim, double conf) {
        return hit(name, sim, conf, "ref.o");
    }

    private static BSimMatches.Hit hit(String name, double sim, double conf, String exe) {
        return new BSimMatches.Hit(name, sim, conf, exe, "ARM:LE:32:Cortex", "md5", "0x10");
    }

    private static Map<String, Object> hitMap(String name, double sim, double conf, String exe, String arch) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("similarity", sim);
        m.put("confidence", conf);
        m.put("executable", exe);
        m.put("arch", arch);
        return m;
    }
}
