package com.xebyte.offline;

import com.xebyte.core.BSimCli;
import com.xebyte.core.BSimJobs;
import com.xebyte.core.BSimMatches;
import com.xebyte.core.BSimService;
import com.xebyte.core.BSimTestCredentials;
import com.xebyte.core.BSimTestEnv;
import com.xebyte.core.CorroborationEvidence;
import com.xebyte.core.CorroborationEvidence.FunctionRow;
import com.xebyte.core.CorroborationEvidence.StringNorm;
import com.xebyte.core.CorroborationExtract;
import com.xebyte.core.CorroborationExtractor;
import com.xebyte.core.CorroborationStore;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Offline coverage for corroboration extract/compare/store and the
 * {@code corroborate_match} / ingest / query wiring. No PostgreSQL, no Ghidra
 * Listing — the listing walk is exercised by the extract script staying
 * aligned with {@link CorroborationExtract}, and compare is the contract the
 * acceptance cases actually name.
 */
public class CorroborationTest extends TestCase {

    private Path tmp;
    private CorroborationStore.Memory store;

    @Override
    protected void setUp() throws Exception {
        tmp = Files.createTempDirectory("corr-test-");
        Files.createDirectories(tmp.resolve("ghidra/support"));
        Files.createFile(tmp.resolve("ghidra/support/bsim"));
        Files.createFile(tmp.resolve("ghidra/support/analyzeHeadless"));
        store = new CorroborationStore.Memory();
        BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        BSimTestEnv.setPassword("secret");
        BSimTestEnv.setUser("bsim");
    }

    @Override
    protected void tearDown() {
        BSimTestCredentials.clear();
        BSimTestEnv.clear();
    }

    // ------------------------------------------------------------------
    // Compare: the cases BSim cannot settle
    // ------------------------------------------------------------------

    public void testPrintfStubsShareNoStrings() {
        FunctionRow query = row("FUN_printf_a",
                List.of("0x1"),
                List.of("hello from firmware"),
                List.of("printf"));
        FunctionRow ref = row("printf_wrapper",
                List.of("0x1"),
                List.of("unrelated banner"),
                List.of("printf"));
        Map<String, Object> ev = CorroborationEvidence.compare(query, ref, store, StringNorm.AUTO);
        assertFalse(CorroborationEvidence.containsScoreKey(ev));
        assertTrue(((List<?>) ev.get("shared_strings")).isEmpty());
        assertEquals(List.of("hello from firmware"), ev.get("query_only_strings"));
        assertEquals(List.of("unrelated banner"), ev.get("ref_only_strings"));
        assertEquals(List.of("printf"), ev.get("shared_callees"));
    }

    public void testDistinctiveMagicConstantIsMarked() {
        seedCorpusUbiquitous();
        store.upsert("aa".repeat(16), "crc.o", List.of(
                row("aa".repeat(16), "crc.o", "crc16_modbus",
                        List.of("0xa001", "0x1"), List.of(), List.of(), false)));
        FunctionRow query = row("FUN_crc", List.of("0xa001", "0x1"), List.of(), List.of());
        FunctionRow ref = store.lookup("crc.o", "crc16_modbus");
        Map<String, Object> ev = CorroborationEvidence.compare(query, ref, store, StringNorm.AUTO);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> shared = (List<Map<String, Object>>) ev.get("shared_constants");
        Map<String, Object> magic = null;
        Map<String, Object> one = null;
        for (Map<String, Object> c : shared) {
            if ("0xa001".equals(c.get("value"))) magic = c;
            if ("0x1".equals(c.get("value"))) one = c;
        }
        assertNotNull(magic);
        assertEquals(Boolean.TRUE, magic.get("distinctive"));
        assertNotNull(one);
        assertEquals("0x1 is in most of the corpus", Boolean.FALSE, one.get("distinctive"));
        assertFalse(CorroborationEvidence.containsScoreKey(ev));
    }

    public void testFilePathBasenameMatchShowsBothOriginals() {
        FunctionRow query = row("lfs_bd_read", List.of(),
                List.of("/home/ch1pqu1k/dev/dc34/firmware/src/pico-vfs2/vendor/littlefs/lfs.c",
                        "FS OK [%06X](%2506X) %uKB"),
                List.of());
        FunctionRow ref = row("lfs_bd_read", List.of(),
                List.of("/ref/littlefs/lfs.c", "FS OK [%06X](%2506X) %uKB"),
                List.of());
        Map<String, Object> ev = CorroborationEvidence.compare(query, ref, store, StringNorm.AUTO);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> shared = (List<Map<String, Object>>) ev.get("shared_strings");
        assertEquals(2, shared.size());
        Map<String, Object> path = shared.get(0);
        assertEquals("basename", path.get("match"));
        assertEquals("lfs.c", path.get("value"));
        assertTrue(String.valueOf(path.get("query")).endsWith("lfs.c"));
        assertEquals("/ref/littlefs/lfs.c", path.get("ref"));
        Map<String, Object> fmt = shared.get(1);
        assertEquals("exact", fmt.get("match"));
        assertEquals("FS OK [%06X](%2506X) %uKB", fmt.get("value"));
    }

    public void testBasenameOffDoesNotMatchDifferentPaths() {
        FunctionRow query = row("f", List.of(),
                List.of("/home/dev/lfs.c"), List.of());
        FunctionRow ref = row("f", List.of(),
                List.of("/ref/littlefs/lfs.c"), List.of());
        Map<String, Object> ev = CorroborationEvidence.compare(query, ref, store, StringNorm.OFF);
        assertTrue(((List<?>) ev.get("shared_strings")).isEmpty());
    }

    public void testCalleeRecursionDoesNotOccur() {
        // Query only sees what extract stored for THIS function. A constant
        // that lives only in a callee is absent from the query row — that is
        // the no-recursion contract, not a compare-time walk.
        FunctionRow query = row("wrapper", List.of("0x54"), List.of(), List.of("inner"));
        FunctionRow ref = row("wrapper", List.of("0x54", "0xa001"), List.of(), List.of("inner"));
        Map<String, Object> ev = CorroborationEvidence.compare(query, ref, store, StringNorm.AUTO);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> shared = (List<Map<String, Object>>) ev.get("shared_constants");
        assertEquals(1, shared.size());
        assertEquals("0x54", shared.get(0).get("value"));
        assertEquals(List.of("0xa001"), ev.get("ref_only_constants"));
        assertFalse(String.valueOf(ev.get("notes")).contains("0xa001")
                && String.valueOf(ev.get("shared_constants")).contains("0xa001")
                && shared.size() > 1);
    }

    public void testCrossArchitectureConstantsStillMatch() {
        FunctionRow arm = new FunctionRow("aa".repeat(16), "fw.elf", "FUN_fnv",
                List.of("0x811c9dc5", "0x1000193"), List.of(), List.of(), false);
        FunctionRow x64 = new FunctionRow("bb".repeat(16), "fnv.o", "fnv1a",
                List.of("0x811c9dc5", "0x1000193"), List.of(), List.of(), false);
        Map<String, Object> ev = CorroborationEvidence.compare(arm, x64, store, StringNorm.AUTO);
        assertEquals(2, ((List<?>) ev.get("shared_constants")).size());
        assertTrue(((List<?>) ev.get("query_only_constants")).isEmpty());
        assertFalse(CorroborationEvidence.containsScoreKey(ev));
    }

    public void testNoAggregateScoreInAnyResponseShape() {
        Map<String, Object> miss = CorroborationEvidence.noEvidence(
                "FUN_1", "lfs_bd_read", "not_extracted",
                List.of("No corroboration data for this executable; "
                        + "it was ingested before extraction existed"));
        assertEquals("no_evidence", miss.get("status"));
        assertEquals("not_extracted", miss.get("reason"));
        assertFalse(CorroborationEvidence.containsScoreKey(miss));
        assertFalse(miss.containsKey("score"));
        assertFalse(miss.containsKey("corroboration_score"));
    }

    public void testLookupMissIsNoEvidenceNotAnError() {
        FunctionRow query = row("FUN_1", List.of("0x1"), List.of(), List.of());
        Map<String, Object> ev = CorroborationEvidence.compare(query, null, store, StringNorm.AUTO);
        assertEquals("no_evidence", ev.get("status"));
        assertEquals("not_extracted", ev.get("reason"));
        assertTrue(String.valueOf(ev.get("notes")).contains("ingested before extraction"));
    }

    public void testCanonicalizeConstantIsLowercaseHex() {
        assertEquals("0xa001", CorroborationExtract.canonicalizeConstant(0xA001L));
        assertEquals("0xffffffff", CorroborationExtract.canonicalizeConstant(0xFFFFFFFFL));
        assertEquals("0x0", CorroborationExtract.canonicalizeConstant(0));
    }

    public void testCapMarksTruncationWithoutGrowingUnbounded() {
        List<String> many = new ArrayList<>();
        for (int i = 0; i < CorroborationExtract.CAP + 10; i++) {
            many.add("0x" + Integer.toHexString(i + 2));
        }
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>(many);
        List<String> capped = CorroborationExtract.cap(set);
        assertEquals(CorroborationExtract.CAP, capped.size());
        assertFalse(CorroborationExtract.addCapped(set, "0xdead"));
    }

    public void testStringNormParseRejectsUnknown() {
        assertEquals(StringNorm.AUTO, StringNorm.parse(""));
        assertEquals(StringNorm.OFF, StringNorm.parse("off"));
        assertEquals(StringNorm.BASENAME, StringNorm.parse("basename"));
        try {
            StringNorm.parse("fuzzy");
            fail("expected rejection");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("string_normalisation"));
        }
    }

    // ------------------------------------------------------------------
    // Schema isolation
    // ------------------------------------------------------------------

    public void testDdlLivesInCompanionSchemaNotBsimTables() {
        for (String sql : CorroborationStore.DDL) {
            assertTrue(sql, sql.contains("corroboration"));
            assertFalse(sql, sql.toLowerCase().contains("descriptable"));
            assertFalse(sql, sql.toLowerCase().contains("exetable"));
            assertFalse(sql, sql.contains(" createdatabase"));
        }
        assertTrue(CorroborationStore.DDL[0].contains("CREATE SCHEMA IF NOT EXISTS corroboration"));
        assertTrue(CorroborationStore.DDL[1].contains("CREATE TABLE IF NOT EXISTS corroboration.functions"));
    }

    public void testFileUrlStoreIsNoop() throws Exception {
        CorroborationStore noop = CorroborationStore.open("file:/tmp/bsim/re");
        assertFalse(noop.writable());
        assertNull(noop.lookup("any", "fn"));
        assertEquals(0, noop.corpusFunctionCount());
    }

    public void testJdbcUrlRequiresSsl() {
        BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/embedded");
        String jdbc = com.xebyte.core.BSimUrls.toJdbcUrl("postgresql://ghidra-bsim:5432/embedded");
        assertTrue(jdbc, jdbc.startsWith("jdbc:postgresql://"));
        assertTrue(jdbc, jdbc.contains("sslmode=require"));
        assertFalse(jdbc, jdbc.contains("secret"));
        assertFalse(jdbc, jdbc.contains("password"));
    }

    // ------------------------------------------------------------------
    // Service wiring: ingest stores, query does not reorder, miss degrades
    // ------------------------------------------------------------------

    public void testIngestStoresRowsOnPostgres() throws Exception {
        FunctionRow row = row("aa".repeat(16), "nullcog.elf", "lfs_bd_read",
                List.of("0x7fffffff", "0x3ff"),
                List.of("/ref/littlefs/lfs.c"),
                List.of("memcpy_impl"), false);
        BSimService svc = serviceWith(programNamed("nullcog.elf"), (p, n) -> row, p -> List.of(row));
        Response r = svc.ingest("postgresql://ghidra-bsim:5432/embedded",
                "nullcog.elf", "", true, false, "", 45);
        assertFalse("ingest failed: " + r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("\"corroboration\":\"stored\""));
        FunctionRow got = store.lookup("nullcog.elf", "lfs_bd_read");
        assertNotNull(got);
        assertEquals(List.of("0x7fffffff", "0x3ff"), got.constants());
        assertEquals(List.of("/ref/littlefs/lfs.c"), got.strings());
        assertEquals(List.of("memcpy_impl"), got.callees());
    }

    public void testAlreadyIngestedStillWritesCorroboration() throws Exception {
        FunctionRow row = row("00112233445566778899aabbccddeeff", "nullcog.elf",
                "crc16", List.of("0xa001"), List.of(), List.of(), false);
        BSimCli skipCli = new BSimCli((cmd, timeout) -> {
            if (cmd.contains("listexes")) {
                return new BSimCli.Result(0,
                        "00112233445566778899aabbccddeeff nullcog.elf ARM:LE:32:Cortex gcc\n"
                                + "1 executables found\n", cmd);
            }
            return new BSimCli.Result(0, "ok\n", cmd);
        }, tmp.resolve("ghidra").toFile());
        BSimService svc = new BSimService(providerOf(programNamed("nullcog.elf")),
                new NoopThreadingStrategy(), skipCli, new BSimJobs(),
                this::storeFor, extractor(row));
        Response r = svc.ingest("postgresql://ghidra-bsim:5432/embedded",
                "nullcog.elf", "", true, false, "", 45);
        assertFalse(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("already_ingested"));
        assertNotNull(store.lookup("nullcog.elf", "crc16"));
    }

    public void testCorroborateMatchNoEvidenceForUnknownExecutable() {
        FunctionRow query = row("FUN_1", List.of("0x1"), List.of(), List.of());
        BSimService svc = serviceWith(programNamed("fw.elf"), (p, n) -> query, p -> List.of(query));
        Response r = svc.corroborateMatch("fw.elf", "FUN_1",
                "postgresql://ghidra-bsim:5432/embedded",
                "never-ingested.o", "lfs_bd_read", "auto");
        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("no_evidence"));
        assertTrue(json, json.contains("not_extracted"));
        assertTrue(json, json.contains("ingested before extraction"));
        assertFalse(json, json.contains("\"score\""));
    }

    public void testCorroborateMatchDistinguishesMissingFunction() throws Exception {
        FunctionRow query = row("FUN_1", List.of("0x1"), List.of(), List.of());
        List<FunctionRow> extracted = List.of(
                row("aa".repeat(16), "littlefs.o", "lfs_bd_read",
                        List.of(), List.of(), List.of(), false),
                row("aa".repeat(16), "littlefs.o", "lfs_dir_get",
                        List.of(), List.of(), List.of(), false));
        store.upsert("aa".repeat(16), "littlefs.o", extracted);
        BSimService svc = serviceWith(programNamed("fw.elf"), (p, n) -> query, p -> List.of(query));

        Response r = svc.corroborateMatch("fw.elf", "FUN_1",
                "postgresql://ghidra-bsim:5432/embedded",
                "littlefs.o", "lfs_bd_cmp", "auto");

        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("function_not_found"));
        assertFalse(json, json.contains("not_extracted"));
        assertTrue(json, json.contains("\"extracted_function_count\":2"));
    }

    public void testApplyMatchesReportsAndSkipsDuplicateNamesByDefault() throws Exception {
        String resultJson = duplicateApplyPayload(40.63, 36.88);
        BSimService svc = queryService(row("FUN_1", List.of(), List.of(), List.of()), resultJson);

        Response r = svc.applyMatches("postgresql://ghidra-bsim:5432/embedded",
                15.0, 0.15, false, false, 0.0, 10, "",
                "", "", "", "", 8, false, "none", 5.0, 45);

        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"conflicting\":2"));
        assertTrue(json, json.contains("\"groups\":1"));
        assertTrue(json, json.contains("\"name\":\"lfs_bd_read\""));
        assertTrue(json, json.contains("FUN_100068b0"));
        assertTrue(json, json.contains("FUN_10006cd8"));
        assertTrue(json, json.contains("\"renamed\":[]"));
    }

    public void testApplyMatchesBestRequiresMarginAndNeverResolvesTie() throws Exception {
        BSimService marginSvc = queryService(
                row("FUN_1", List.of(), List.of(), List.of()),
                duplicateApplyPayload(60.48, 55.58));
        Response resolved = marginSvc.applyMatches(
                "postgresql://ghidra-bsim:5432/embedded",
                15.0, 0.15, false, true, 0.0, 10, "",
                "", "", "", "", 8, false, "best", 4.0, 45);
        String resolvedJson = resolved.toJson();
        assertTrue(resolvedJson, resolvedJson.contains("\"resolved_best\":1"));
        assertTrue(resolvedJson, resolvedJson.contains("\"would_rename\":[{"));
        assertTrue(resolvedJson, resolvedJson.contains("FUN_100068b0"));
        assertTrue(resolvedJson, resolvedJson.contains("\"conflicting\":1"));

        BSimService tiedSvc = queryService(
                row("FUN_1", List.of(), List.of(), List.of()),
                duplicateApplyPayload(41.11, 41.11));
        Response tied = tiedSvc.applyMatches(
                "postgresql://ghidra-bsim:5432/embedded",
                15.0, 0.15, false, true, 0.0, 10, "",
                "", "", "", "", 8, false, "best", 0.0, 45);
        String tiedJson = tied.toJson();
        assertTrue(tiedJson, tiedJson.contains("\"skipped_insufficient_margin\":1"));
        assertTrue(tiedJson, tiedJson.contains("\"would_rename\":[]"));
        assertTrue(tiedJson, tiedJson.contains("\"conflicting\":2"));
    }

    public void testCorroborateMatchFileUrlIsNoEvidence() {
        FunctionRow query = row("FUN_1", List.of("0x1"), List.of(), List.of());
        BSimService svc = serviceWith(programNamed("fw.elf"), (p, n) -> query, p -> List.of(query));
        Response r = svc.corroborateMatch("fw.elf", "FUN_1",
                "file:" + tmp.resolve("re"), "ref.o", "lfs_bd_read", "auto");
        assertFalse(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("no_evidence"));
        assertTrue(r.toJson(), r.toJson().contains("unsupported_backend"));
    }

    public void testCorroborateMatchReturnsEvidenceWithoutScore() {
        FunctionRow query = row("FUN_10006cd8",
                List.of("0x7fffffff", "0x3ff", "0xffffffff"),
                List.of("/home/dev/vendor/littlefs/lfs.c"),
                List.of("memcpy_impl"));
        FunctionRow ref = row("bb".repeat(16), "littlefs.o", "lfs_bd_read",
                List.of("0x7fffffff", "0x3ff", "0xffffffff"),
                List.of("/ref/littlefs/lfs.c"),
                List.of("memcpy_impl"), false);
        store.upsert(ref.executableMd5(), ref.executableName(), List.of(ref));
        BSimService svc = serviceWith(programNamed("fw.elf"), (p, n) -> query, p -> List.of(query));
        Response r = svc.corroborateMatch("fw.elf", "FUN_10006cd8",
                "postgresql://ghidra-bsim:5432/embedded",
                "littlefs.o", "lfs_bd_read", "auto");
        assertFalse("unexpected error: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("0x7fffffff"));
        assertTrue(json, json.contains("basename"));
        assertTrue(json, json.contains("memcpy_impl"));
        assertFalse(json, json.contains("\"score\""));
        assertFalse(json, json.contains("corroboration_score"));
    }

    public void testQueryCorroborateDoesNotReorderMatches() throws Exception {
        FunctionRow query = row("FUN_stub", List.of("0x1"), List.of("aaa"), List.of("printf"));
        FunctionRow refA = row("cc".repeat(16), "a.o", "printf_a",
                List.of("0x1"), List.of("aaa"), List.of("printf"), false);
        FunctionRow refB = row("dd".repeat(16), "b.o", "printf_b",
                List.of("0x1"), List.of("zzz"), List.of("printf"), false);
        store.upsert(refA.executableMd5(), refA.executableName(), List.of(refA));
        store.upsert(refB.executableMd5(), refB.executableName(), List.of(refB));

        String resultJson = "{\"function\":\"FUN_stub\",\"address\":\"0x1000\","
                + "\"identifiable\":false,\"feature_count\":2,\"matches\":["
                + "{\"name\":\"printf_a\",\"similarity\":1.0,\"confidence\":9.2,"
                + "\"executable\":\"a.o\",\"arch\":\"ARM:LE:32:Cortex\",\"md5\":\""
                + "c".repeat(32) + "\"},"
                + "{\"name\":\"printf_b\",\"similarity\":1.0,\"confidence\":9.1,"
                + "\"executable\":\"b.o\",\"arch\":\"ARM:LE:32:Cortex\",\"md5\":\""
                + "d".repeat(32) + "\"}],\"ambiguous\":true}";

        BSimService svc = queryService(query, resultJson);
        Response r = svc.query("postgresql://ghidra-bsim:5432/embedded", "FUN_stub",
                0.0, 0.0, 10, "", "", "", "", "", 8, 0, 45, true, 3);
        assertFalse("query failed: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        int a = json.indexOf("\"name\":\"printf_a\"");
        int b = json.indexOf("\"name\":\"printf_b\"");
        assertTrue(json, a >= 0 && b > a);
        assertTrue(json, json.contains("\"corroboration\""));
        assertTrue(json, json.contains("aaa"));
        assertFalse(json.contains("\"score\""));
        // High-confidence unique hits are not the subject; this result is
        // unidentifiable so evidence is attached to the first 3 (both) hits.
        assertTrue(BSimMatches.needsCorroboration(
                BSimMatches.parseQueryPayload(
                        com.xebyte.core.JsonHelper.parseJson(resultJson), "").get(0)));
    }

    public void testQueryCorroborateDefaultDoesNotAttach() throws Exception {
        BSimService svc = queryService(row("blake2b_compress", List.of(), List.of(), List.of()),
                "{\"function\":\"blake2b_compress\",\"address\":\"0x1000\",\"matches\":["
                        + "{\"name\":\"blake2b_compress\",\"similarity\":1.0,\"confidence\":95.0,"
                        + "\"executable\":\"nullcog-v2\",\"arch\":\"x86:LE:32:default\","
                        + "\"md5\":\"ffff\",\"address\":\"0x1000\"}]}");
        Response r = svc.query("file:" + tmp.resolve("qdb"), "blake2b_compress",
                0.7, 0.0, 10, "", "", "", "", "", 8, 0, 45, false, 3);
        assertFalse(r instanceof Response.Err);
        assertFalse(r.toJson(), r.toJson().contains("\"corroboration\""));
    }

    public void testNeedsCorroborationGatesHighConfidence() {
        BSimMatches.Hit strong = new BSimMatches.Hit(
                "lfs_bd_read", 0.9, 41.83, "lfs.o", "ARM:LE:32:Cortex", "ab", "0x1");
        BSimMatches.FunctionResult ok = new BSimMatches.FunctionResult(
                "FUN_1", "0x1", List.of(strong), false, true, "", 40);
        assertFalse(BSimMatches.needsCorroboration(ok));
        BSimMatches.FunctionResult unident = new BSimMatches.FunctionResult(
                "FUN_1", "0x1", List.of(strong), false, false, "too small", 2);
        assertTrue(BSimMatches.needsCorroboration(unident));
        BSimMatches.Hit weak = new BSimMatches.Hit(
                "printf_a", 1.0, 9.2, "a.o", "ARM:LE:32:Cortex", "cd", "0x2");
        BSimMatches.FunctionResult low = new BSimMatches.FunctionResult(
                "FUN_2", "0x2", List.of(weak), false, true, "", 4);
        assertTrue(BSimMatches.needsCorroboration(low));
    }

    public void testDistinctiveFraction() {
        assertTrue(CorroborationEvidence.isDistinctive(1, 200));
        assertTrue(CorroborationEvidence.isDistinctive(2, 200));
        assertFalse(CorroborationEvidence.isDistinctive(20, 200));
        assertTrue(CorroborationEvidence.isDistinctive(1, 0));
    }

    public void testRowsFromExtractPayload() {
        Map<String, Object> payload = com.xebyte.core.JsonHelper.parseJson(
                "{\"md5\":\"aa\",\"executable\":\"lfs.o\",\"functions\":["
                        + "{\"function\":\"lfs_bd_read\",\"constants\":[\"0x3ff\"],"
                        + "\"strings\":[\"/ref/littlefs/lfs.c\"],\"callees\":[\"memcpy\"],"
                        + "\"truncated\":false}]}");
        List<FunctionRow> rows = CorroborationStore.rowsFromExtractPayload(payload, "", "");
        assertEquals(1, rows.size());
        assertEquals("lfs_bd_read", rows.get(0).functionName());
        assertEquals(List.of("0x3ff"), rows.get(0).constants());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private void seedCorpusUbiquitous() {
        for (int i = 0; i < 40; i++) {
            String md5 = String.format("%032x", i + 1);
            store.upsert(md5, "obj" + i, List.of(
                    row(md5, "obj" + i, "fn" + i,
                            List.of("0x1", "0x0", "0xffffffff"), List.of(), List.of(), false)));
        }
    }

    private static FunctionRow row(String function, List<String> constants,
                                   List<String> strings, List<String> callees) {
        return new FunctionRow("", "", function, constants, strings, callees, false);
    }

    private static String duplicateApplyPayload(double firstConfidence, double secondConfidence) {
        return "{\"program\":\"fw.elf\",\"results\":["
                + "{\"function\":\"FUN_100068b0\","
                + "\"matches\":[{\"name\":\"lfs_bd_read\",\"similarity\":0.4,"
                + "\"confidence\":" + firstConfidence + ",\"executable\":\"littlefs.o\"}]},"
                + "{\"function\":\"FUN_10006cd8\","
                + "\"matches\":[{\"name\":\"lfs_bd_read\",\"similarity\":0.4,"
                + "\"confidence\":" + secondConfidence + ",\"executable\":\"littlefs.o\"}]}]}";
    }

    private static FunctionRow row(String md5, String exe, String function,
                                   List<String> constants, List<String> strings,
                                   List<String> callees, boolean truncated) {
        return new FunctionRow(md5, exe, function, constants, strings, callees, truncated);
    }

    private CorroborationStore storeFor(String url) {
        return com.xebyte.core.BSimUrls.isPostgresUrl(url) ? store : CorroborationStore.open(url);
    }

    private BSimService serviceWith(Program program, ExtractOne one, ExtractAll all) {
        return new BSimService(providerOf(program), new NoopThreadingStrategy(),
                recordingCli(null), new BSimJobs(), this::storeFor, extractor(one, all));
    }

    private BSimService queryService(FunctionRow query, String resultJson) {
        return new BSimService(providerOf(programNamed("nullcog.elf")),
                new NoopThreadingStrategy(), recordingCli(resultJson), new BSimJobs(),
                this::storeFor, extractor(query));
    }

    private static CorroborationExtractor extractor(FunctionRow row) {
        return extractor((p, n) -> row, p -> List.of(row));
    }

    private static CorroborationExtractor extractor(ExtractOne one, ExtractAll all) {
        return new CorroborationExtractor() {
            @Override public List<FunctionRow> extractAll(Program program) { return all.get(program); }
            @Override public FunctionRow extractOne(Program program, String functionOrAddress) {
                return one.get(program, functionOrAddress);
            }
        };
    }

    private BSimCli recordingCli(String queryJson) {
        return new BSimCli((cmd, timeout) -> {
            int ps = cmd.indexOf("-postScript");
            if (queryJson != null && ps >= 0) {
                Path out = Path.of(cmd.get(ps + 3));
                try {
                    Files.writeString(out, queryJson);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            if (cmd.contains("getexecount") || cmd.contains("listexes")) {
                return new BSimCli.Result(0, "0 executables found\n", cmd);
            }
            return new BSimCli.Result(0, "ok\n", cmd);
        }, tmp.resolve("ghidra").toFile());
    }

    private static Program programNamed(String name) {
        return (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(), new Class<?>[] {Program.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "getExecutableMD5" -> "00112233445566778899aabbccddeeff";
                    case "getExecutablePath" -> "";
                    case "getCompilerSpec" -> compilerSpec();
                    case "getLanguageID" -> new LanguageID("ARM:LE:32:Cortex");
                    case "getLanguage" -> language();
                    case "getFunctionManager" -> functionManager();
                    case "getDomainFile" -> domainFile();
                    case "saveToPackedFile" -> {
                        java.io.File f = (java.io.File) args[0];
                        if (f.exists()) throw new java.io.IOException("already exists");
                        Files.write(f.toPath(), new byte[] {0x1f, (byte) 0x8b});
                        yield null;
                    }
                    case "toString" -> name;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static FunctionManager functionManager() {
        FunctionIterator none = (FunctionIterator) Proxy.newProxyInstance(
                FunctionIterator.class.getClassLoader(),
                new Class<?>[] {FunctionIterator.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "iterator" -> prox;
                    case "hasNext" -> false;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return (FunctionManager) Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getFunctionCount" -> 3;
                    case "getFunctions" -> none;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static Language language() {
        LanguageDescription desc = (LanguageDescription) Proxy.newProxyInstance(
                LanguageDescription.class.getClassLoader(),
                new Class<?>[] {LanguageDescription.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSize" -> 32;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return (Language) Proxy.newProxyInstance(
                Language.class.getClassLoader(), new Class<?>[] {Language.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getLanguageDescription" -> desc;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static CompilerSpec compilerSpec() {
        CompilerSpecID specId = new CompilerSpecID("gcc");
        return (CompilerSpec) Proxy.newProxyInstance(
                CompilerSpec.class.getClassLoader(), new Class<?>[] {CompilerSpec.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getCompilerSpecID" -> specId;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static DomainFile domainFile() {
        return (DomainFile) Proxy.newProxyInstance(
                DomainFile.class.getClassLoader(), new Class<?>[] {DomainFile.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSharedProjectURL" -> null;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static ProgramProvider providerOf(Program p) {
        return new ProgramProvider() {
            @Override public Program getCurrentProgram() { return p; }
            @Override public Program getProgram(String name) {
                return p.getName().equals(name) ? p : null;
            }
            @Override public Program[] getAllOpenPrograms() { return new Program[] {p}; }
            @Override public void setCurrentProgram(Program program) {}
        };
    }

    @FunctionalInterface
    private interface ExtractOne {
        FunctionRow get(Program program, String name);
    }

    @FunctionalInterface
    private interface ExtractAll {
        List<FunctionRow> get(Program program);
    }

}
