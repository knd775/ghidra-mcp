package com.xebyte.offline;

import com.xebyte.core.ProgramImporter;
import ghidra.util.task.TaskMonitor;
import junit.framework.TestCase;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;

/**
 * Offline tests for {@link ProgramImporter} loader-selection and magic-byte
 * format detection. The AutoImporter call itself needs a live Ghidra runtime;
 * these pin the decision that used to silently force {@code importAsBinary}
 * whenever {@code language} was set.
 */
public class ProgramImporterTest extends TestCase {

    public void testSelectModeAutoWhenNothingPassed() {
        assertEquals(ProgramImporter.Mode.AUTO, ProgramImporter.selectMode(null, null));
        assertEquals(ProgramImporter.Mode.AUTO, ProgramImporter.selectMode("", ""));
        assertEquals(ProgramImporter.Mode.AUTO, ProgramImporter.selectMode("  ", "  "));
    }

    public void testSelectModeLanguagePinsWithoutForcingRaw() {
        assertEquals(ProgramImporter.Mode.LANGUAGE_PINNED,
            ProgramImporter.selectMode("", "ARM:LE:32:Cortex"));
        assertEquals(ProgramImporter.Mode.LANGUAGE_PINNED,
            ProgramImporter.selectMode(null, "ARM:LE:32:Cortex"));
    }

    public void testSelectModeFormatBinaryIsRaw() {
        assertEquals(ProgramImporter.Mode.RAW_BINARY,
            ProgramImporter.selectMode("binary", "ARM:LE:32:Cortex"));
        assertEquals(ProgramImporter.Mode.RAW_BINARY,
            ProgramImporter.selectMode("BINARY", ""));
        assertEquals(ProgramImporter.Mode.RAW_BINARY,
            ProgramImporter.selectMode("raw", "x86:LE:32:default"));
    }

    public void testSelectModeUnknownFormatThrows() {
        try {
            ProgramImporter.selectMode("elf", "ARM:LE:32:Cortex");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Unknown format"));
            assertTrue(e.getMessage().contains("binary"));
        }
    }

    public void testDetectElfMagic() throws Exception {
        File f = File.createTempFile("probe", ".elf");
        f.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(new byte[] { 0x7f, 'E', 'L', 'F', 0x01, 0x01 });
        }
        assertEquals("ELF", ProgramImporter.detectContainerFormat(f));
    }

    public void testDetectPeMagic() throws Exception {
        File f = File.createTempFile("probe", ".exe");
        f.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(new byte[] { 'M', 'Z', 0x00, 0x00 });
        }
        assertEquals("PE", ProgramImporter.detectContainerFormat(f));
    }

    public void testDetectMachOMagic() throws Exception {
        File f = File.createTempFile("probe", ".macho");
        f.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(new byte[] { (byte) 0xCF, (byte) 0xFA, (byte) 0xED, (byte) 0xFE });
        }
        assertEquals("Mach-O", ProgramImporter.detectContainerFormat(f));
    }

    public void testDetectUnknownForEmptyFile() throws Exception {
        File f = Files.createTempFile("probe", ".bin").toFile();
        f.deleteOnExit();
        assertEquals("unknown", ProgramImporter.detectContainerFormat(f));
    }

    public void testImportFileRawWithoutLanguageFailsBeforeLoader() throws Exception {
        File f = Files.createTempFile("probe", ".bin").toFile();
        f.deleteOnExit();
        ProgramImporter.Result r = ProgramImporter.importFile(
            f, null, "/", "", "", "binary", this, TaskMonitor.DUMMY);
        assertFalse(r.success());
        assertTrue(r.error.contains("format=binary requires language"));
    }

    public void testImportFileUnknownFormatFailsBeforeLoader() throws Exception {
        File f = Files.createTempFile("probe", ".elf").toFile();
        f.deleteOnExit();
        ProgramImporter.Result r = ProgramImporter.importFile(
            f, null, "/", "ARM:LE:32:Cortex", "", "elf", this, TaskMonitor.DUMMY);
        assertFalse(r.success());
        assertTrue(r.error.contains("Unknown format"));
    }
}
