package com.xebyte.core;

import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.HeadlessProgramProvider.ExportResult;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * Real {@link ProgramDB} coverage for {@code self_contained} export. The
 * mock path in {@link com.xebyte.GzfExportImportTest} never reaches
 * {@code PackedDatabase.packDatabase}.
 */
public class SelfContainedExportGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
                installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                    configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("export-open-tx", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void selfContainedExportSucceedsWithOpenProgramTransaction() throws Exception {
        int tx = program.startTransaction("analyst documentation");
        boolean closed = false;
        Path dir = null;
        File out = null;
        try {
            program.getListing().setComment(builder.addr("0x1000"), CodeUnit.PLATE_COMMENT,
                    "keep me");
            assertEquals("live listing must see the uncommitted plate before export",
                    "keep me", plateComment(program, "0x1000"));

            HeadlessProgramProvider provider = new HeadlessProgramProvider();
            provider.setCurrentProgram(program);
            dir = Files.createTempDirectory("gzf-self-contained-ghidra");
            out = dir.resolve("out.gzf").toFile();
            ExportResult res = provider.exportProgramToGzf(program.getName(), out, true);

            assertTrue("self-contained export must succeed with an open ProgramDB transaction: "
                    + res.error, res.success);
            assertTrue("packed output must be a real GZF", out.length() > 2);
            assertTrue("live database transaction must still be open",
                    program.getDBHandle().isTransactionActive());
            assertEquals("keep me", plateInPacked(out, "0x1000"));
            assertTrue(program.endTransaction(tx, true));
            closed = true;
            assertEquals("keep me", plateComment(program, "0x1000"));
        } finally {
            if (!closed) {
                program.endTransaction(tx, false);
            }
            if (out != null && out.exists() && !out.delete()) {
                out.deleteOnExit();
            }
            if (dir != null) {
                try {
                    Files.deleteIfExists(dir);
                } catch (IOException e) {
                    dir.toFile().deleteOnExit();
                }
            }
        }
    }

    private static String plateComment(Program p, String addr) {
        return p.getListing().getComment(CodeUnit.PLATE_COMMENT,
                p.getAddressFactory().getAddress(addr));
    }

    /**
     * Re-open the packed snapshot the same way {@code writeFlattenedPacked}
     * does. Avoids {@code saveToPackedFile}'s ContentHandler lookup, which
     * {@link ApplicationConfiguration} does not register.
     */
    private static String plateInPacked(File packed, String addr) throws Exception {
        PackedDatabase pdb = PackedDatabase.getPackedDatabase(packed, false, TaskMonitor.DUMMY);
        Object consumer = new Object();
        Program copy = null;
        try {
            DBHandle handle = pdb.open(TaskMonitor.DUMMY);
            copy = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, consumer);
            return plateComment(copy, addr);
        } finally {
            if (copy != null) {
                copy.release(consumer);
            }
            pdb.dispose();
        }
    }
}
