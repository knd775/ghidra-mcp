package com.xebyte.offline;

import com.xebyte.core.BSimCli;
import com.xebyte.core.BSimJobs;
import com.xebyte.core.BSimService;
import com.xebyte.core.BSimSignatures;
import com.xebyte.core.BSimSignatures.Decision;
import com.xebyte.core.BSimSignatures.Outcome;
import com.xebyte.core.BSimSignatures.Signature;
import com.xebyte.core.BSimSignatures.TypePlan;
import com.xebyte.core.BSimTestCredentials;
import com.xebyte.core.BSimTestEnv;
import com.xebyte.core.CorroborationEvidence.FunctionRow;
import com.xebyte.core.CorroborationExtractor;
import com.xebyte.core.CorroborationStore;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import junit.framework.TestCase;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Typed-signature transfer for {@code bsim_apply_matches}: the guards, the
 * ingest-side storage, and the apply-side wiring, all without a Listing.
 * Ghidra access is behind {@link BSimSignatures.Support}, so these tests
 * pin what the service decides and reports; the archive/decompiler path is
 * exercised live.
 */
public class BSimSignaturesTest extends TestCase {

    private static final String REF_MD5 = "aa".repeat(16);
    private static final String ARM = "ARM:LE:32:Cortex";
    private static final String PROTOTYPE = "int lfs_mount(lfs_t * lfs, struct lfs_config * cfg)";

    private Path tmp;
    private CorroborationStore.Memory store;
    private Path gdt;

    @Override
    protected void setUp() throws Exception {
        tmp = Files.createTempDirectory("bsim-sig-test-");
        Files.createDirectories(tmp.resolve("ghidra/support"));
        Files.createFile(tmp.resolve("ghidra/support/bsim"));
        Files.createFile(tmp.resolve("ghidra/support/analyzeHeadless"));
        store = new CorroborationStore.Memory();
        gdt = tmp.resolve("littlefs.o.gdt");
        Files.writeString(gdt, "not a real archive; existence is what the guard checks");
        BSimTestEnv.setAllowlist("postgresql://ghidra-bsim:5432/bsim");
        BSimTestEnv.setPassword("secret");
        BSimTestEnv.setUser("bsim");
    }

    @Override
    protected void tearDown() {
        BSimTestCredentials.clear();
        BSimTestEnv.clear();
    }

    // ------------------------------------------------------------------
    // Guards: pure decisions, in the order the service pays for them
    // ------------------------------------------------------------------

    public void testDecideRunsEveryGuardInOrder() {
        Signature dwarf = new Signature(PROTOTYPE, "__stdcall", 2, true, gdt.toString());
        Signature analysis = new Signature(PROTOTYPE, "__stdcall", 2, false, gdt.toString());

        assertEquals(Decision.SKIP_BELOW_CONFIDENCE,
                BSimSignatures.decide(39.9, 40.0, ARM, ARM, dwarf, true, false, 2));
        assertEquals(Decision.SKIP_CROSS_ARCH,
                BSimSignatures.decide(64.0, 40.0, ARM, "x86:LE:64:default", dwarf, true, false, 2));
        assertEquals(Decision.SKIP_NO_SIGNATURE_DATA,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, null, true, false, 2));
        assertEquals(Decision.SKIP_NO_DWARF,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, analysis, true, false, 2));
        assertEquals(Decision.SKIP_NO_ARCHIVE,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, dwarf, false, false, 2));
        assertEquals(Decision.SKIP_ALREADY_APPLIED,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, dwarf, true, true, 2));
        assertEquals(Decision.SKIP_PARAM_MISMATCH,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, dwarf, true, false, 3));
        assertEquals("an unknown target count is a mismatch, not a pass",
                Decision.SKIP_PARAM_MISMATCH,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, dwarf, true, false, -1));
        assertEquals("null defers the parameter check", Decision.APPLY,
                BSimSignatures.decide(64.0, 40.0, ARM, ARM, dwarf, true, false, null));
        assertEquals(Decision.APPLY,
                BSimSignatures.decide(40.0, 40.0, ARM, ARM, dwarf, true, false, 2));
    }

    public void testSameArchIsCaseInsensitiveAndUnknownIsDifferent() {
        assertTrue(BSimSignatures.sameArch("ARM:LE:32:Cortex", "arm:le:32:cortex"));
        assertFalse(BSimSignatures.sameArch("ARM:LE:32:Cortex", "ARM:LE:32:v7"));
        assertFalse(BSimSignatures.sameArch("ARM:LE:32:Cortex", ""));
        assertFalse(BSimSignatures.sameArch(null, "ARM:LE:32:Cortex"));
    }

    public void testProvenanceMarkerIsDetectedAndReplacedNotStacked() {
        String line = BSimSignatures.provenanceLine("littlefs-v2.9.3-gcc13-arm-O2.o", 101.0);
        assertEquals("[bsim-sig] from littlefs-v2.9.3-gcc13-arm-O2.o conf=101.0", line);
        assertFalse(BSimSignatures.hasProvenance(null, "littlefs-v2.9.3-gcc13-arm-O2.o"));
        assertFalse(BSimSignatures.hasProvenance("Mounts the filesystem.", "littlefs-v2.9.3-gcc13-arm-O2.o"));

        String merged = BSimSignatures.mergeProvenance("Mounts the filesystem.\n", line);
        assertEquals("Mounts the filesystem.\n" + line, merged);
        assertTrue(BSimSignatures.hasProvenance(merged, "littlefs-v2.9.3-gcc13-arm-O2.o"));
        assertFalse("a different reference is not the same provenance",
                BSimSignatures.hasProvenance(merged, "littlefs-v2.9.3-gcc13-arm-Os.o"));

        String again = BSimSignatures.mergeProvenance(merged,
                BSimSignatures.provenanceLine("littlefs-v2.9.3-gcc13-arm-O2.o", 98.0));
        assertEquals("re-application replaces the marker instead of stacking",
                1, again.split("\\[bsim-sig\\]", -1).length - 1);
        assertTrue(again.startsWith("Mounts the filesystem."));
        assertTrue(again.endsWith("conf=98.0"));
    }

    public void testNameProvenanceIsDistinctFromSignatureAndIsReclaimable() {
        String name = BSimSignatures.nameProvenanceLine("littlefs-Os.o", 60.48);
        assertEquals("[bsim] from littlefs-Os.o conf=60.5", name);
        assertTrue(BSimSignatures.isBsimProvenanceLine(name));
        String sigLine = BSimSignatures.provenanceLine("littlefs-O2.o", 159.34);
        assertTrue(sigLine.startsWith("[bsim-sig]"));
        assertTrue(BSimSignatures.isBsimProvenanceLine(sigLine));
        assertTrue(BSimSignatures.hasBsimProvenanceComment(
                "Hand plate.\n" + name));
        assertEquals(60.5, BSimSignatures.provenanceConfidence(name).orElse(-1), 0.01);
        assertTrue(BSimSignatures.provenanceConfidence("[bsim] tag only").isEmpty());

        String mixed = BSimSignatures.mergeNameProvenance(
                "Hand plate.\n[bsim-sig] from old.o conf=40.0\n[bsim] from old.o conf=10.0",
                name);
        assertTrue(mixed.contains("Hand plate."));
        assertTrue(mixed.contains("[bsim-sig] from old.o conf=40.0"));
        assertTrue(mixed.contains(name));
        assertEquals("name marker is replaced, not stacked",
                1, mixed.split("\\[bsim\\] ", -1).length - 1);

        String stripped = BSimSignatures.stripBsimProvenance(mixed);
        assertEquals("Hand plate.", stripped);
        assertEquals("FUN_1000ade8", BSimSignatures.defaultFunctionName(address("0x1000ade8")));
    }

    public void testArchivePathPrefersArtifactDirectoryThenFallback() throws Exception {
        Path uploads = Files.createDirectories(tmp.resolve("uploads"));
        Path beside = BSimSignatures.archivePathFor(
                uploads.resolve("littlefs-v2.9.3-gcc13-arm-O2.o").toString(), REF_MD5,
                tmp.resolve("fallback").toString());
        assertEquals(uploads.resolve("littlefs-v2.9.3-gcc13-arm-O2.o.gdt"), beside);

        Path fallback = BSimSignatures.archivePathFor(
                "/nonexistent/dir/ref.o", REF_MD5, tmp.resolve("fallback").toString());
        assertEquals(tmp.resolve("fallback").resolve(REF_MD5 + ".gdt"), fallback);

        Path blank = BSimSignatures.archivePathFor("", "", "");
        assertTrue(blank.toString(), blank.getFileName().toString().endsWith(".gdt"));
        assertTrue(blank.toString(), blank.toString().contains("ghidra-mcp-gdt"));
    }

    // ------------------------------------------------------------------
    // Ingest side
    // ------------------------------------------------------------------

    public void testIngestStoresPrototypeAndArchivePath() throws Exception {
        FunctionRow row = new FunctionRow(REF_MD5, "littlefs.o", "lfs_mount",
                List.of("0x3ff"), List.of(), List.of(), false,
                new Signature(PROTOTYPE, "__stdcall", 2, true, ""));
        FakeSupport support = new FakeSupport(tmp.resolve("exported.gdt"));
        BSimService svc = ingestService(row, support);

        Response r = svc.ingest("postgresql://ghidra-bsim:5432/bsim", "littlefs.o",
                "", true, false, "", 45);
        assertFalse("ingest failed: " + r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"signature_archive\":\""));
        assertTrue(json, json.contains("\"signatures_dwarf\":1"));
        assertTrue(json, json.contains("\"signatures_analysis_only\":0"));
        assertFalse(json, json.contains("without -g"));
        assertEquals(1, support.exported.size());

        FunctionRow stored = store.lookup("littlefs.o", "lfs_mount");
        assertNotNull(stored);
        assertNotNull(stored.signature());
        assertEquals(PROTOTYPE, stored.signature().prototype());
        assertEquals(2, stored.signature().paramCount());
        assertTrue(stored.signature().hasDwarf());
        assertEquals("the archive path is stamped on every row",
                tmp.resolve("exported.gdt").toString(), stored.signature().gdtPath());
        assertEquals(List.of("littlefs"), support.published);
        assertTrue(json, json.contains("\"type_archive\":\"littlefs\""));
    }

    public void testIngestPublishesLibraryVersionArchiveKey() throws Exception {
        FunctionRow row = new FunctionRow(REF_MD5, "littlefs-v2.9.3-gcc13-arm-O2.o", "lfs_mount",
                List.of("0x3ff"), List.of(), List.of(), false,
                new Signature(PROTOTYPE, "__stdcall", 2, true, ""));
        FakeSupport support = new FakeSupport(tmp.resolve("exported-keyed.gdt"));
        BSimService svc = ingestService(row, support);
        Response r = svc.ingest("postgresql://ghidra-bsim:5432/bsim",
                "littlefs-v2.9.3-gcc13-arm-O2.o", "", true, false, "", 45);
        assertFalse("ingest failed: " + r.toJson(), r instanceof Response.Err);
        assertEquals(List.of("littlefs-v2.9.3"), support.published);
        assertTrue(r.toJson(), r.toJson().contains("\"type_archive\":\"littlefs-v2.9.3\""));
    }

    public void testIngestWithoutDwarfWarnsAndMarksRows() throws Exception {
        FunctionRow row = new FunctionRow(REF_MD5, "stripped.o", "lfs_mount",
                List.of(), List.of(), List.of(), false,
                new Signature("undefined4 lfs_mount(undefined4 param_1)", "unknown", 1, false, ""));
        BSimService svc = ingestService(row, new FakeSupport(tmp.resolve("stripped.gdt")));
        Response r = svc.ingest("postgresql://ghidra-bsim:5432/bsim", "stripped.o",
                "", true, false, "", 45);
        assertFalse(r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"signatures_dwarf\":0"));
        assertTrue(json, json.contains("\"signatures_analysis_only\":1"));
        assertTrue("must say the reference lacks -g", json.contains("without -g"));
        assertFalse(store.lookup("stripped.o", "lfs_mount").signature().hasDwarf());
    }

    public void testExtractPayloadCarriesSignatureAndArchivePath() {
        Map<String, Object> payload = JsonHelper.parseJson(
                "{\"md5\":\"" + REF_MD5 + "\",\"executable\":\"littlefs.o\","
                        + "\"gdt_path\":\"/data/uploads/littlefs.o.gdt\",\"signature_count\":1,"
                        + "\"functions\":[{\"function\":\"lfs_mount\",\"constants\":[],"
                        + "\"strings\":[],\"callees\":[],\"truncated\":false,"
                        + "\"prototype\":\"" + PROTOTYPE + "\",\"calling_convention\":\"__stdcall\","
                        + "\"param_count\":2,\"has_dwarf\":true},"
                        + "{\"function\":\"no_sig\",\"constants\":[],\"strings\":[],"
                        + "\"callees\":[],\"truncated\":false}]}");
        List<FunctionRow> rows = CorroborationStore.rowsFromExtractPayload(payload, "", "");
        assertEquals(2, rows.size());
        Signature sig = rows.get(0).signature();
        assertNotNull(sig);
        assertEquals(PROTOTYPE, sig.prototype());
        assertEquals("__stdcall", sig.callingConvention());
        assertEquals(2, sig.paramCount());
        assertTrue(sig.hasDwarf());
        assertEquals("/data/uploads/littlefs.o.gdt", sig.gdtPath());
        assertNull("a function the script gave no prototype has no signature",
                rows.get(1).signature());
        assertEquals("/data/uploads/littlefs.o.gdt",
                CorroborationStore.gdtPathFromExtractPayload(payload));
    }

    public void testSchemaCarriesSignatureColumnsWithIdempotentAlters() {
        String ddl = String.join("\n", CorroborationStore.DDL);
        for (String column : List.of("prototype", "calling_convention", "param_count",
                "has_dwarf", "gdt_path")) {
            assertTrue(column, ddl.contains("ADD COLUMN IF NOT EXISTS " + column));
        }
        assertTrue(CorroborationStore.UPSERT.contains("prototype = EXCLUDED.prototype"));
        assertTrue(CorroborationStore.UPSERT.contains("has_dwarf = EXCLUDED.has_dwarf"));
        assertTrue(CorroborationStore.LOOKUP.contains("gdt_path"));
        for (String sql : CorroborationStore.DDL) {
            assertTrue("companion schema only: " + sql, sql.contains("corroboration"));
        }
    }

    // ------------------------------------------------------------------
    // Apply side
    // ------------------------------------------------------------------

    public void testApplySignaturesIsOffByDefaultAndLeavesTheResponseAlone() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = apply(svc, false, false, 15.0, 40.0);
        assertFalse(r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertFalse("no signatures block when not requested", json.contains("\"signatures\""));
        assertFalse(json.contains("signature_details"));
        assertTrue("no applier is even opened", applier.applied.isEmpty() && applier.opened == 0);
    }

    public void testHighConfidenceSameArchDwarfMatchGetsTheSignature() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = apply(svc, true, false, 15.0, 40.0);
        assertFalse(r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"signature\":\"applied\""));
        assertTrue(json, json.contains("\"applied\":1"));
        assertTrue(json, json.contains("\"types_imported\":1"));
        assertTrue(json, json.contains("\"types_kept_existing\":1"));
        assertTrue(json, json.contains("\"prototype\":\"" + PROTOTYPE + "\""));
        assertTrue(json, json.contains("\"source\":\"littlefs.o\""));
        assertTrue("provenance names reference and confidence",
                json.contains("[bsim-sig] from littlefs.o conf=101.0"));
        assertEquals(1, applier.applied.size());
        assertEquals("lfs_mount", applier.applied.get(0));
        assertEquals("[bsim-sig] from littlefs.o conf=101.0", applier.provenance.get(0));
        assertEquals("the decompiler is released at the end of the run", 1, applier.closed);
    }

    public void testParameterCountMismatchAppliesTheNameOnly() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        applier.paramCount = 3;
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = apply(svc, true, false, 15.0, 40.0);
        String json = r.toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_param_mismatch\":1"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertTrue("both counts are named", json.contains("\"reference_params\":2"));
        assertTrue(json, json.contains("\"target_params\":3"));
        assertTrue(applier.applied.isEmpty());
    }

    public void testCrossArchitectureAppliesTheNameOnly() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, "x86:LE:64:default"));
        Response r = apply(svc, true, false, 15.0, 40.0);
        String json = r.toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_cross_arch\":1"));
        assertTrue(json, json.contains("\"reference_arch\":\"x86:LE:64:default\""));
        assertTrue(json, json.contains("\"target_arch\":\"" + ARM + "\""));
        assertTrue(applier.applied.isEmpty());
        assertEquals("no decompile for a candidate the cheap guards rejected",
                0, applier.paramCountCalls);
    }

    public void testAnalysisOnlyReferenceAppliesTheNameOnly() throws Exception {
        seedReference(false, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_no_dwarf\":1"));
        assertTrue(applier.applied.isEmpty());
    }

    public void testBetweenTheTwoFloorsAppliesTheNameOnly() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(30.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_below_confidence\":1"));
        assertTrue(applier.applied.isEmpty());
    }

    public void testMissingArchiveIsSkippedNotCrashed() throws Exception {
        Files.delete(gdt);
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_no_archive\":1"));
        assertTrue(json, json.contains(gdt.getFileName().toString()));
        assertTrue(applier.applied.isEmpty());
    }

    public void testReferenceIngestedBeforeSignaturesIsSkipped() throws Exception {
        store.upsert(REF_MD5, "littlefs.o", List.of(new FunctionRow(REF_MD5, "littlefs.o",
                "lfs_mount", List.of(), List.of(), List.of(), false)));
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"skipped_no_signature_data\":1"));
        assertTrue(applier.applied.isEmpty());
    }

    public void testDryRunPreviewsSignaturesAndImportsNothing() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = apply(svc, true, true, 15.0, 40.0);
        String json = r.toJson();
        assertTrue(json, json.contains("\"dry_run\":true"));
        assertTrue(json, json.contains("\"would_rename\":[{"));
        assertTrue(json, json.contains("\"signature\":\"would_apply\""));
        assertTrue(json, json.contains("\"would_apply\":1"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertTrue("the preview still reports the planned type work",
                json.contains("\"types_imported\":2"));
        assertTrue(json, json.contains("\"types_kept_existing\":0"));
        assertTrue("dry run must import no types and change no signatures",
                applier.applied.isEmpty());
        assertEquals(1, applier.planned.size());
    }

    public void testSecondRunIsIdempotent() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        applier.alreadyApplied = true; // the marker from run one is on the function
        // After run one the function is named lfs_mount, so the second run
        // must use skip_named=false to reach it at all.
        BSimService svc = applyService(applier, matchJson(101.0, ARM), "lfs_mount");
        String json = apply(svc, true, false, 15.0, 40.0, false).toJson();
        assertTrue(json, json.contains("\"name_unchanged\":1"));
        assertTrue(json, json.contains("\"conflicting\":0"));
        assertTrue(json, json.contains("\"renamed\":[]"));
        assertTrue(json, json.contains("\"skipped_already_applied\":1"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertTrue(json, json.contains("\"types_imported\":0"));
        assertTrue(json, json.contains("\"types_kept_existing\":0"));
        assertFalse(json, json.contains("\"error\""));
        assertTrue(applier.applied.isEmpty());
    }

    /**
     * Live 2026-09-01: with skip_named=false every function named by an
     * earlier run was reported "conflicting" with itself, so a names-only
     * pass could never be followed by apply_signatures=true.
     */
    public void testAlreadyNamedFunctionIsNotAConflictWithItself() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM), "lfs_mount");
        String json = apply(svc, true, false, 15.0, 40.0, false).toJson();
        assertTrue(json, json.contains("\"conflicting\":0"));
        assertTrue(json, json.contains("\"name_unchanged\":1"));
        assertTrue(json, json.contains("\"renamed\":[]"));
        assertTrue(json, json.contains("\"unchanged\":[{"));
        assertTrue(json, json.contains("\"rename\":\"unchanged\""));
        assertTrue(json, json.contains("\"applied\":1"));
        assertEquals(List.of("lfs_mount"), applier.applied);
    }

    public void testAlreadyNamedFunctionStaysAlreadyNamedUnderSkipNamed() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM), "lfs_mount");
        String json = apply(svc, true, false, 15.0, 40.0, true).toJson();
        assertTrue(json, json.contains("\"already_named\":1"));
        assertTrue(json, json.contains("\"name_unchanged\":0"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertTrue(applier.applied.isEmpty());
    }

    /**
     * Live 2026-09-01: with a debug-stripped copy of the reference in the
     * corpus, BSim's order between the two identical copies is a coin toss
     * and 24 of 40 signatures were skipped_no_dwarf while the DWARF copy of
     * the same function sat one row down.
     */
    public void testNoDwarfBestHitFallsBackToADwarfCopyOfTheSameName() throws Exception {
        seedReference(true, 2);
        seedStrippedCopy();
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, twoCopiesJson(101.0, 100.0));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"applied\":1"));
        assertTrue(json, json.contains("\"skipped_no_dwarf\":0"));
        assertTrue(json, json.contains("\"source\":\"littlefs.o\""));
        assertTrue(json, json.contains("\"best_hit_source\":\"littlefs-stripped.o\""));
        assertTrue(json, json.contains("\"best_hit_reason\":\"skipped_no_dwarf\""));
        assertEquals(List.of("[bsim-sig] from littlefs.o conf=100.0"), applier.provenance);
    }

    public void testNoSameNameAlternativeKeepsTheBestHitsReason() throws Exception {
        seedReference(false, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"skipped_no_dwarf\":1"));
        assertFalse(json, json.contains("best_hit_source"));
        assertTrue(applier.applied.isEmpty());
    }

    /** A tie that flips order between runs must not re-apply from the other copy. */
    public void testAlreadyAppliedCopyWinsOverAPassingBestHit() throws Exception {
        seedReference(true, 2);
        seedStrippedCopy();
        // This time both copies carry DWARF, and the function already has
        // the marker from the second one.
        store.upsert(STRIPPED_MD5, "littlefs-stripped.o", List.of(new FunctionRow(STRIPPED_MD5,
                "littlefs-stripped.o", "lfs_mount", List.of("0x3ff"), List.of(), List.of(), false,
                new Signature(PROTOTYPE, "__stdcall", 2, true, ""))), gdt.toString());
        FakeApplier applier = new FakeApplier();
        applier.appliedFrom = java.util.Set.of("littlefs.o");
        BSimService svc = applyService(applier, twoCopiesJson(101.0, 100.0), "lfs_mount");
        String json = apply(svc, true, false, 15.0, 40.0, false).toJson();
        assertTrue(json, json.contains("\"skipped_already_applied\":1"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertTrue(json, json.contains("\"source\":\"littlefs.o\""));
        assertTrue(applier.applied.isEmpty());
    }

    /**
     * A debug-stripped littlefs.o still reported signatures_dwarf=8 live:
     * memcpy, printf and friends are externals whose IMPORTED signature is
     * Ghidra's library archive, not the reference's DWARF.
     */
    public void testDescribeDoesNotCountLibraryArchiveSignaturesAsDwarf() {
        assertTrue(BSimSignatures.describe(signedFunction(false, false)).hasDwarf());
        assertFalse(BSimSignatures.describe(signedFunction(true, false)).hasDwarf());
        assertFalse(BSimSignatures.describe(signedFunction(false, true)).hasDwarf());
    }

    private static Function signedFunction(boolean external, boolean thunk) {
        return (Function) Proxy.newProxyInstance(
                Function.class.getClassLoader(), new Class<?>[] {Function.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSignature" -> null;
                    case "getPrototypeString" -> "void * memcpy(void * d, void * s, size_t n)";
                    case "getCallingConventionName" -> "__stdcall";
                    case "getParameterCount" -> 3;
                    case "getSignatureSource" -> SourceType.IMPORTED;
                    case "isExternal" -> external;
                    case "isThunk" -> thunk;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    public void testExistingNameElsewhereIsNotApplied() throws Exception {
        seedReferenceNamed("lfs_dir_relocatingcommit", true, 2);
        StubFunction holder = bsimHolder("lfs_dir_relocatingcommit", "0x1000ade8", 60.48);
        StubFunction candidate = new StubFunction("FUN_1000b404", "0x1000b404");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("FUN_1000b404", "0x1000b404", "lfs_dir_relocatingcommit", 159.34),
                holder, candidate);
        String json = apply(svc, false, false, 15.0, 40.0, false).toJson();
        assertTrue(json, json.contains("\"name_exists_elsewhere\":1"));
        assertTrue(json, json.contains("\"existing_address\":\"0x1000ade8\""));
        assertTrue(json, json.contains("\"existing_confidence\":60.5"));
        assertTrue(json, json.contains("\"renamed\":[]"));
        assertEquals("lfs_dir_relocatingcommit", holder.name);
        assertEquals("FUN_1000b404", candidate.name);
        assertTrue("post-run names stay unique", uniqueNames(holder, candidate));
    }

    public void testBestPlusMarginReassignsBsimHolder() throws Exception {
        seedReferenceNamed("lfs_dir_relocatingcommit", true, 2);
        StubFunction holder = bsimHolder("lfs_dir_relocatingcommit", "0x1000ade8", 60.48);
        StubFunction candidate = new StubFunction("FUN_1000b404", "0x1000b404");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("FUN_1000b404", "0x1000b404", "lfs_dir_relocatingcommit", 159.34),
                holder, candidate);
        String json = applyNamed(svc, false, false, false, true, "best", 5.0, "").toJson();
        assertTrue(json, json.contains("\"reassigned\":1"));
        assertTrue(json, json.contains("\"resolution\":\"reassigned\""));
        assertTrue(json, json.contains("\"demoted_to\":\"FUN_1000ade8\""));
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertEquals("FUN_1000ade8", holder.name);
        assertEquals("lfs_dir_relocatingcommit", candidate.name);
        assertFalse(holder.comment.contains("[bsim]"));
        assertTrue(holder.tags.isEmpty());
        assertTrue(candidate.comment.contains("[bsim] from"));
        assertTrue(candidate.tags.contains("bsim"));
        assertTrue(uniqueNames(holder, candidate));
    }

    public void testHandNamedHolderIsNeverDemoted() throws Exception {
        seedReferenceNamed("lfs_dir_relocatingcommit", true, 2);
        StubFunction holder = new StubFunction("lfs_dir_relocatingcommit", "0x1000ade8");
        holder.comment = "Hand analysis of the relocating commit path.";
        StubFunction candidate = new StubFunction("FUN_1000b404", "0x1000b404");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("FUN_1000b404", "0x1000b404", "lfs_dir_relocatingcommit", 159.34),
                holder, candidate);
        String json = applyNamed(svc, false, false, false, true, "best", 5.0, "").toJson();
        assertTrue(json, json.contains("\"name_exists_elsewhere\":1"));
        assertTrue(json, json.contains("\"existing_bsim_provenance\":false"));
        assertFalse(json, json.contains("\"reassigned\":1"));
        assertEquals("lfs_dir_relocatingcommit", holder.name);
        assertEquals("FUN_1000b404", candidate.name);
        assertTrue(holder.comment.contains("Hand analysis"));
        assertTrue(uniqueNames(holder, candidate));
    }

    public void testTagOnlyHolderIsNotDemotedWithoutParseableConfidence() throws Exception {
        seedReferenceNamed("lfs_dir_relocatingcommit", true, 2);
        StubFunction holder = new StubFunction("lfs_dir_relocatingcommit", "0x1000ade8");
        holder.tags.add("bsim");
        StubFunction candidate = new StubFunction("FUN_1000b404", "0x1000b404");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("FUN_1000b404", "0x1000b404", "lfs_dir_relocatingcommit", 159.34),
                holder, candidate);
        String json = applyNamed(svc, false, false, false, true, "best", 5.0, "").toJson();
        assertTrue(json, json.contains("\"name_exists_elsewhere\":1"));
        assertTrue(json, json.contains("\"existing_bsim_provenance\":true"));
        assertEquals("lfs_dir_relocatingcommit", holder.name);
        assertEquals("FUN_1000b404", candidate.name);
    }

    public void testRenameNamedFalseKeepsHandNameAndStillAppliesSignature() throws Exception {
        seedReferenceNamed("interpret", true, 2);
        StubFunction named = new StubFunction("z_interpret", "0x1000");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("z_interpret", "0x1000", "interpret", 88.0), named);
        String json = applyNamed(svc, true, false, false, false, "none", 5.0, "").toJson();
        assertTrue(json, json.contains("\"rename_suppressed\":1"));
        assertTrue(json, json.contains("\"current_name\":\"z_interpret\""));
        assertTrue(json, json.contains("\"proposed_name\":\"interpret\""));
        assertTrue(json, json.contains("\"applied\":1"));
        assertEquals("z_interpret", named.name);
        assertEquals(List.of("interpret"), applier.applied);
    }

    public void testRenameNamedTrueOverwritesTheHandName() throws Exception {
        seedReferenceNamed("interpret", true, 2);
        StubFunction named = new StubFunction("z_interpret", "0x1000");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("z_interpret", "0x1000", "interpret", 88.0), named);
        String json = applyNamed(svc, false, false, false, true, "none", 5.0, "").toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"rename_suppressed\":0"));
        assertEquals("interpret", named.name);
    }

    public void testRenameNamedIsIgnoredWhenSkipNamed() throws Exception {
        seedReferenceNamed("interpret", true, 2);
        StubFunction named = new StubFunction("z_interpret", "0x1000");
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier,
                namedMatchJson("z_interpret", "0x1000", "interpret", 88.0), named);
        String json = applyNamed(svc, true, false, true, true, "none", 5.0, "").toJson();
        assertTrue(json, json.contains("\"already_named\":1"));
        assertTrue(json, json.contains("\"rename_suppressed\":0"));
        assertTrue(json, json.contains("\"applied\":0"));
        assertEquals("z_interpret", named.name);
        assertTrue(applier.applied.isEmpty());
    }

    public void testSignatureRunCachesOpenedArchiveByKey() throws Exception {
        store.upsert(REF_MD5, "littlefs.o", List.of(
                new FunctionRow(REF_MD5, "littlefs.o", "lfs_mount",
                        List.of("0x3ff"), List.of(), List.of(), false,
                        new Signature(PROTOTYPE, "__stdcall", 2, true, "")),
                new FunctionRow(REF_MD5, "littlefs.o", "lfs_stat",
                        List.of("0x4ff"), List.of(), List.of(), false,
                        new Signature(PROTOTYPE, "__stdcall", 2, true, ""))),
                gdt.toString());
        FakeApplier applier = new FakeApplier();
        FakeSupport support = new FakeSupport(applier);
        String query = "{\"program\":\"fw.elf\",\"results\":["
                + "{\"function\":\"FUN_1000\",\"address\":\"0x1000\",\"matches\":["
                + "{\"name\":\"lfs_mount\",\"similarity\":0.6,\"confidence\":101.0,"
                + "\"executable\":\"littlefs.o\",\"arch\":\"" + ARM + "\","
                + "\"md5\":\"" + REF_MD5 + "\",\"address\":\"0x2000\"}]},"
                + "{\"function\":\"FUN_2000\",\"address\":\"0x2000\",\"matches\":["
                + "{\"name\":\"lfs_stat\",\"similarity\":0.6,\"confidence\":99.0,"
                + "\"executable\":\"littlefs.o\",\"arch\":\"" + ARM + "\","
                + "\"md5\":\"" + REF_MD5 + "\",\"address\":\"0x3000\"}]}]}";
        BSimService svc = applyService(support, query,
                new StubFunction("FUN_1000", "0x1000"),
                new StubFunction("FUN_2000", "0x2000"));
        String json = applyNamed(svc, true, false, true, false, "none", 5.0, "").toJson();
        assertTrue(json, json.contains("\"applied\":2"));
        assertEquals(List.of("littlefs"), support.openedKeys);
    }

    public void testMissingProjectArchiveFallsBackLocal() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        FakeSupport support = new FakeSupport(applier);
        support.projectArchiveMissing = true;
        BSimService svc = applyService(support, matchJson(101.0, ARM),
                new StubFunction("FUN_1000"));
        String json = applyNamed(svc, true, false, true, false, "none", 5.0, "project").toJson();
        assertTrue(json, json.contains("\"types_fallback_local\":1"));
        assertTrue(json, json.contains("\"applied\":1"));
        assertEquals(List.of("lfs_mount"), applier.applied);
    }

    public void testFailedApplicationIsReportedNotHidden() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        applier.outcome = Outcome.failed("ApplyFunctionSignatureCmd: boom");
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        String json = apply(svc, true, false, 15.0, 40.0).toJson();
        assertTrue(json, json.contains("\"renamed\":[{"));
        assertTrue(json, json.contains("\"failed\":1"));
        assertTrue(json, json.contains("boom"));
    }

    public void testSignatureFloorMustNotSitBelowTheNameFloor() throws Exception {
        seedReference(true, 2);
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = apply(svc, true, true, 50.0, 40.0);
        assertTrue(r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("min_signature_confidence"));
        assertEquals("no query may run on invalid input", 0, applier.opened);
    }

    public void testFileBackendSkipsEverySignatureWithAWarning() throws Exception {
        FakeApplier applier = new FakeApplier();
        BSimService svc = applyService(applier, matchJson(101.0, ARM));
        Response r = svc.applyMatches("file:" + tmp.resolve("h2db"), 15.0, 0.15, true, false, false,
                0.0, 10, "", "", "", "", "", 8, false, "none", 5.0, true, 40.0, "", 45);
        assertFalse(r.toJson(), r instanceof Response.Err);
        String json = r.toJson();
        assertTrue(json, json.contains("\"skipped_no_signature_data\":1"));
        assertTrue(json, json.contains("not postgresql://"));
        assertTrue(applier.applied.isEmpty());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private void seedReference(boolean dwarf, int params) throws Exception {
        seedReferenceNamed("lfs_mount", dwarf, params);
    }

    private void seedReferenceNamed(String name, boolean dwarf, int params) throws Exception {
        store.upsert(REF_MD5, "littlefs.o", List.of(new FunctionRow(REF_MD5, "littlefs.o",
                name, List.of("0x3ff"), List.of(), List.of(), false,
                new Signature(PROTOTYPE, "__stdcall", params, dwarf, ""))), gdt.toString());
    }

    private static final String STRIPPED_MD5 = "ffeeddccbbaa99887766554433221100";

    /** Two hits for the same name: a debug-stripped copy first, the DWARF one second. */
    private static String twoCopiesJson(double strippedConfidence, double dwarfConfidence) {
        return "{\"program\":\"fw.elf\",\"results\":[{\"function\":\"FUN_1000\","
                + "\"address\":\"0x1000\",\"matches\":[{\"name\":\"lfs_mount\","
                + "\"similarity\":1.0,\"confidence\":" + strippedConfidence + ","
                + "\"executable\":\"littlefs-stripped.o\",\"arch\":\"" + ARM + "\","
                + "\"md5\":\"" + STRIPPED_MD5 + "\",\"address\":\"0x2000\"},"
                + "{\"name\":\"lfs_mount\","
                + "\"similarity\":1.0,\"confidence\":" + dwarfConfidence + ","
                + "\"executable\":\"littlefs.o\",\"arch\":\"" + ARM + "\","
                + "\"md5\":\"" + REF_MD5 + "\",\"address\":\"0x2000\"}]}]}";
    }

    private void seedStrippedCopy() throws Exception {
        store.upsert(STRIPPED_MD5, "littlefs-stripped.o", List.of(new FunctionRow(STRIPPED_MD5,
                "littlefs-stripped.o", "lfs_mount", List.of("0x3ff"), List.of(), List.of(), false,
                new Signature(PROTOTYPE, "__stdcall", 2, false, ""))), "");
    }

    private static String matchJson(double confidence, String arch) {
        return namedMatchJson("FUN_1000", "0x1000", "lfs_mount", confidence, arch);
    }

    private static String namedMatchJson(String function, String address, String name,
                                         double confidence) {
        return namedMatchJson(function, address, name, confidence, ARM);
    }

    private static String namedMatchJson(String function, String address, String name,
                                         double confidence, String arch) {
        return "{\"program\":\"fw.elf\",\"results\":[{\"function\":\"" + function + "\","
                + "\"address\":\"" + address + "\",\"matches\":[{\"name\":\"" + name + "\","
                + "\"similarity\":0.6,\"confidence\":" + confidence + ","
                + "\"executable\":\"littlefs.o\",\"arch\":\"" + arch + "\","
                + "\"md5\":\"" + REF_MD5 + "\",\"address\":\"0x2000\"}]}]}";
    }

    private static Response apply(BSimService svc, boolean signatures, boolean dryRun,
                                  double minConfidence, double minSignatureConfidence) {
        return apply(svc, signatures, dryRun, minConfidence, minSignatureConfidence, true);
    }

    private static Response apply(BSimService svc, boolean signatures, boolean dryRun,
                                  double minConfidence, double minSignatureConfidence,
                                  boolean skipNamed) {
        return svc.applyMatches("postgresql://ghidra-bsim:5432/bsim", minConfidence, 0.15,
                skipNamed, false, dryRun, 0.0, 10, "", "", "", "", "", 8, false, "none", 5.0,
                signatures, minSignatureConfidence, "", 45);
    }

    private static Response applyNamed(BSimService svc, boolean signatures, boolean dryRun,
                                       boolean skipNamed, boolean renameNamed,
                                       String resolveConflicts, double margin,
                                       String typeArchiveMode) {
        return svc.applyMatches("postgresql://ghidra-bsim:5432/bsim", 15.0, 0.15,
                skipNamed, renameNamed, dryRun, 0.0, 10, "", "", "", "", "", 8, false,
                resolveConflicts, margin, signatures, 40.0, typeArchiveMode, 45);
    }

    private BSimService ingestService(FunctionRow row, FakeSupport support) {
        Program program = program("littlefs.o".equals(row.executableName())
                ? "littlefs.o" : row.executableName(), new StubFunction("FUN_1000"));
        CorroborationExtractor extractor = new CorroborationExtractor() {
            @Override public List<FunctionRow> extractAll(Program p) { return List.of(row); }
            @Override public FunctionRow extractOne(Program p, String f) { return row; }
        };
        return new BSimService(providerOf(program), direct(), recordingCli(null),
                new BSimJobs(), this::storeFor, extractor, support);
    }

    private BSimService applyService(FakeApplier applier, String queryJson) {
        return applyService(applier, queryJson, "FUN_1000");
    }

    private BSimService applyService(FakeApplier applier, String queryJson, String currentName) {
        return applyService(new FakeSupport(applier), queryJson, new StubFunction(currentName));
    }

    private BSimService applyService(FakeApplier applier, String queryJson,
                                     StubFunction... functions) {
        return applyService(new FakeSupport(applier), queryJson, functions);
    }

    private BSimService applyService(FakeSupport support, String queryJson,
                                     StubFunction... functions) {
        Program program = program("fw.elf", functions);
        FunctionRow query = FunctionRow.empty(functions.length == 0
                ? "FUN_1000" : functions[functions.length - 1].name);
        CorroborationExtractor extractor = new CorroborationExtractor() {
            @Override public List<FunctionRow> extractAll(Program p) { return List.of(query); }
            @Override public FunctionRow extractOne(Program p, String f) { return query; }
        };
        return new BSimService(providerOf(program), direct(), recordingCli(queryJson),
                new BSimJobs(), this::storeFor, extractor, support);
    }

    private CorroborationStore storeFor(String url) {
        return com.xebyte.core.BSimUrls.isPostgresUrl(url) ? store : CorroborationStore.open(url);
    }

    private BSimCli recordingCli(String queryJson) {
        return new BSimCli((cmd, timeout) -> {
            int ps = cmd.indexOf("-postScript");
            if (queryJson != null && ps >= 0) {
                Files.writeString(Path.of(cmd.get(ps + 3)), queryJson);
            }
            if (cmd.contains("getexecount") || cmd.contains("listexes")) {
                return new BSimCli.Result(0, "0 executables found\n", cmd);
            }
            return new BSimCli.Result(0, "ok\n", cmd);
        }, tmp.resolve("ghidra").toFile());
    }

    /** Runs actions inline: the rename and the signature write must actually happen here. */
    private static ThreadingStrategy direct() {
        return new ThreadingStrategy() {
            @Override public <T> T executeRead(Callable<T> action) throws Exception {
                return action.call();
            }
            @Override public <T> T executeWrite(Program program, String txName, Callable<T> action)
                    throws Exception {
                return action.call();
            }
            @Override public boolean isHeadless() { return true; }
        };
    }

    /** Ingest-side export and apply-side applier, recorded instead of touching Ghidra. */
    private static final class FakeSupport implements BSimSignatures.Support {
        final Path exportTo;
        final FakeApplier applier;
        final List<String> exported = new ArrayList<>();

        FakeSupport(Path exportTo) {
            this.exportTo = exportTo;
            this.applier = new FakeApplier();
        }

        FakeSupport(FakeApplier applier) {
            this.exportTo = null;
            this.applier = applier;
        }

        @Override
        public Path exportArchive(Program program, List<String> warnings) {
            exported.add(program.getName());
            try {
                Files.writeString(exportTo, "gdt");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return exportTo;
        }

        boolean projectArchiveMissing;
        final List<String> published = new ArrayList<>();
        final List<String> openedKeys = new ArrayList<>();

        @Override
        public String publishTypeArchive(Program program, ProgramProvider provider,
                                         String archiveKey, Path fileGdt,
                                         com.xebyte.core.BSimTypeArchives.Mode mode,
                                         List<String> warnings) {
            published.add(archiveKey);
            return "/refs/types/" + archiveKey + ".gdt";
        }

        @Override
        public boolean archiveAvailable(Program program, ProgramProvider provider,
                                        Signature sig, String archiveKey,
                                        com.xebyte.core.BSimTypeArchives.Mode mode) {
            return sig != null && !sig.gdtPath().isEmpty()
                    && java.nio.file.Files.isRegularFile(java.nio.file.Path.of(sig.gdtPath()));
        }

        @Override
        public com.xebyte.core.BSimTypeArchives.OpenedArchive openForApply(
                Program program, ProgramProvider provider, Signature sig, String archiveKey,
                com.xebyte.core.BSimTypeArchives.Mode mode) {
            openedKeys.add(archiveKey);
            boolean fallback = mode == com.xebyte.core.BSimTypeArchives.Mode.PROJECT
                    && projectArchiveMissing;
            return com.xebyte.core.BSimTypeArchives.OpenedArchive.stub(
                    fallback ? com.xebyte.core.BSimTypeArchives.Mode.LOCAL : mode,
                    fallback, sig == null ? "" : sig.gdtPath());
        }

        @Override
        public BSimSignatures.Applier applier(Program program) {
            applier.opened++;
            return applier;
        }
    }

    private static final class FakeApplier implements BSimSignatures.Applier {
        String arch = ARM;
        int paramCount = 2;
        int paramCountCalls;
        boolean alreadyApplied;
        int opened;
        int closed;
        final List<String> applied = new ArrayList<>();
        final List<String> provenance = new ArrayList<>();
        final List<String> planned = new ArrayList<>();
        TypePlan plan = new TypePlan(List.of("lfs_t", "lfs_config"), List.of(), "");
        Outcome outcome = new Outcome(true, "", PROTOTYPE, "__stdcall",
                List.of("lfs_config"), List.of("lfs_t"));

        @Override public String targetArch(Program program) { return arch; }

        @Override public int targetParamCount(Program program, Function function) {
            paramCountCalls++;
            return paramCount;
        }

        /** When set, only these references count as already applied. */
        java.util.Set<String> appliedFrom;

        @Override public boolean alreadyApplied(Function function, String executable) {
            if (appliedFrom != null) return appliedFrom.contains(executable);
            return alreadyApplied;
        }

        @Override public TypePlan plan(Program program, Function function, Signature sig,
                                       String refFunction,
                                       ghidra.program.model.data.DataTypeManager archive) {
            planned.add(refFunction);
            return plan;
        }

        @Override public Outcome apply(Program program, Function function, Signature sig,
                                       String refFunction, String provenanceLine,
                                       ghidra.program.model.data.DataTypeManager archive) {
            applied.add(refFunction);
            provenance.add(provenanceLine);
            return outcome;
        }

        @Override public void close() { closed++; }
    }

    /** Rename + provenance + listing identity. */
    private static final class StubFunction {
        String name;
        String comment = "";
        final String address;
        final Set<String> tags = new LinkedHashSet<>();
        StubFunction(String name) { this(name, "0x1000"); }
        StubFunction(String name, String address) {
            this.name = name;
            this.address = address;
        }
    }

    private static StubFunction bsimHolder(String name, String address, double confidence) {
        StubFunction fn = new StubFunction(name, address);
        fn.comment = BSimSignatures.nameProvenanceLine("littlefs-Os.o", confidence);
        fn.tags.add(BSimSignatures.FUNCTION_TAG);
        return fn;
    }

    private static boolean uniqueNames(StubFunction... functions) {
        Set<String> names = new LinkedHashSet<>();
        for (StubFunction fn : functions) {
            if (!names.add(fn.name)) return false;
        }
        return names.size() == functions.length;
    }

    private static Address address(String hex) {
        String shown = hex.startsWith("0x") || hex.startsWith("0X") ? hex : "0x" + hex;
        int hash = shown.toLowerCase().hashCode();
        return (Address) Proxy.newProxyInstance(
                Address.class.getClassLoader(), new Class<?>[] {Address.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "toString" -> shown;
                    case "hashCode" -> hash;
                    case "equals" -> a[0] != null && shown.equals(a[0].toString());
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static Function functionProxy(StubFunction fn, Address entry) {
        return (Function) Proxy.newProxyInstance(
                Function.class.getClassLoader(), new Class<?>[] {Function.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getName" -> fn.name;
                    case "setName" -> { fn.name = (String) a[0]; yield null; }
                    case "getEntryPoint" -> entry;
                    case "getComment" -> fn.comment;
                    case "setComment" -> { fn.comment = a[0] == null ? "" : (String) a[0]; yield null; }
                    case "addTag" -> { fn.tags.add((String) a[0]); yield true; }
                    case "removeTag" -> { fn.tags.remove((String) a[0]); yield true; }
                    case "getTags" -> tagSet(fn.tags);
                    case "isThunk" -> false;
                    case "isExternal" -> false;
                    case "toString" -> fn.name;
                    case "hashCode" -> System.identityHashCode(prox);
                    case "equals" -> prox == a[0];
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    private static Set<FunctionTag> tagSet(Set<String> names) {
        Set<FunctionTag> tags = new LinkedHashSet<>();
        for (String name : names) {
            tags.add((FunctionTag) Proxy.newProxyInstance(
                    FunctionTag.class.getClassLoader(), new Class<?>[] {FunctionTag.class},
                    (prox, m, a) -> switch (m.getName()) {
                        case "getName" -> name;
                        case "toString" -> name;
                        case "hashCode" -> name.hashCode();
                        case "equals" -> a[0] instanceof FunctionTag t && name.equals(t.getName());
                        default -> throw new UnsupportedOperationException(m.getName());
                    }));
        }
        return tags;
    }

    private static Program program(String name, StubFunction... fns) {
        if (fns == null || fns.length == 0) {
            fns = new StubFunction[] { new StubFunction("FUN_1000") };
        }
        List<Address> entries = new ArrayList<>();
        List<Function> functions = new ArrayList<>();
        Map<String, Address> bySpell = new java.util.LinkedHashMap<>();
        Map<Address, Function> byEntry = new java.util.IdentityHashMap<>();
        for (StubFunction fn : fns) {
            Address entry = address(fn.address);
            Function function = functionProxy(fn, entry);
            entries.add(entry);
            functions.add(function);
            byEntry.put(entry, function);
            bySpell.put(fn.address, entry);
            String bare = fn.address.startsWith("0x") || fn.address.startsWith("0X")
                    ? fn.address.substring(2) : fn.address;
            bySpell.put(bare, entry);
            bySpell.put(bare.toLowerCase(), entry);
            bySpell.put("0x" + bare, entry);
            bySpell.put("0X" + bare, entry);
        }
        FunctionManager fm = (FunctionManager) Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(), new Class<?>[] {FunctionManager.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getFunctionCount" -> functions.size();
                    case "getFunctions" -> functionsOver(functions);
                    case "getFunctionAt", "getFunctionContaining" -> {
                        Address want = (Address) a[0];
                        Function hit = byEntry.get(want);
                        if (hit != null) yield hit;
                        for (int i = 0; i < entries.size(); i++) {
                            if (entries.get(i).equals(want)) yield functions.get(i);
                        }
                        yield null;
                    }
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        AddressFactory af = (AddressFactory) Proxy.newProxyInstance(
                AddressFactory.class.getClassLoader(), new Class<?>[] {AddressFactory.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getAddress" -> bySpell.get(String.valueOf(a[0]));
                    case "getAddressSpaces" -> new ghidra.program.model.address.AddressSpace[0];
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        LanguageDescription desc = (LanguageDescription) Proxy.newProxyInstance(
                LanguageDescription.class.getClassLoader(),
                new Class<?>[] {LanguageDescription.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSize" -> 32;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        Language language = (Language) Proxy.newProxyInstance(
                Language.class.getClassLoader(), new Class<?>[] {Language.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getLanguageDescription" -> desc;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        CompilerSpecID specId = new CompilerSpecID("gcc");
        CompilerSpec spec = (CompilerSpec) Proxy.newProxyInstance(
                CompilerSpec.class.getClassLoader(), new Class<?>[] {CompilerSpec.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getCompilerSpecID" -> specId;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        DomainFile domainFile = (DomainFile) Proxy.newProxyInstance(
                DomainFile.class.getClassLoader(), new Class<?>[] {DomainFile.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "getSharedProjectURL" -> null;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(), new Class<?>[] {Program.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "getExecutableMD5" -> "00112233445566778899aabbccddeeff";
                    case "getExecutablePath" -> "";
                    case "getCompilerSpec" -> spec;
                    case "getLanguageID" -> new LanguageID(ARM);
                    case "getLanguage" -> language;
                    case "getFunctionManager" -> fm;
                    case "getAddressFactory" -> af;
                    case "getDataTypeManager" -> null;
                    case "getDomainFile" -> domainFile;
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

    private static FunctionIterator functionsOver(List<Function> functions) {
        Iterator<Function> it = functions.iterator();
        return (FunctionIterator) Proxy.newProxyInstance(
                FunctionIterator.class.getClassLoader(), new Class<?>[] {FunctionIterator.class},
                (prox, m, a) -> switch (m.getName()) {
                    case "iterator" -> prox;
                    case "hasNext" -> it.hasNext();
                    case "next" -> it.next();
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
}
