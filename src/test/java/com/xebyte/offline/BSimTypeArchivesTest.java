package com.xebyte.offline;

import com.xebyte.core.BSimTestEnv;
import com.xebyte.core.BSimTypeArchives;
import com.xebyte.core.BSimTypeArchives.Mode;
import com.xebyte.core.BSimTypeArchives.OpenedArchive;
import junit.framework.TestCase;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure archive-keying and mode resolution. No Listing, no file archive.
 */
public class BSimTypeArchivesTest extends TestCase {

    @Override
    protected void tearDown() {
        BSimTestEnv.clear();
    }

    public void testArchiveKeyFromSidecarIsNamePlusRef() {
        Map<String, Object> sidecar = new LinkedHashMap<>();
        sidecar.put("name", "littlefs");
        sidecar.put("ref", "v2.9.3");
        assertEquals("littlefs-v2.9.3", BSimTypeArchives.archiveKeyFromSidecar(sidecar));
        sidecar.put("name", "pico-sdk");
        sidecar.put("ref", "2.1.0");
        assertEquals("pico-sdk-2.1.0", BSimTypeArchives.archiveKeyFromSidecar(sidecar));
    }

    public void testArchiveKeyFromExecutableDropsToolchainOptAndFrameworkLibrary() {
        assertEquals("littlefs-v2.9.3", BSimTypeArchives.archiveKeyFromExecutable(
                "littlefs-v2.9.3-gcc13-arm-O2.o"));
        assertEquals("littlefs-v2.9.3", BSimTypeArchives.archiveKeyFromExecutable(
                "/data/uploads/littlefs-v2.9.3-gcc13-arm-Os.o"));
        assertEquals("frotz-2.54", BSimTypeArchives.archiveKeyFromExecutable(
                "frotz-2.54-gcc13-arm-O2.o"));
        assertEquals("pico-sdk-2.1.0", BSimTypeArchives.archiveKeyFromExecutable(
                "pico-sdk-hardware_i2c-2.1.0-gcc13-arm-O2-pico.o"));
        assertEquals("littlefs-logging-v2.9.3", BSimTypeArchives.archiveKeyFromExecutable(
                "littlefs-logging-v2.9.3-gcc13-arm-O2.o"));
    }

    public void testProjectPathIsVersionedNotFloating() {
        assertEquals("/refs/types/littlefs-v2.9.3.gdt",
                BSimTypeArchives.projectPath("littlefs-v2.9.3"));
        assertEquals("/refs/types/frotz-2.54.gdt",
                BSimTypeArchives.projectPath("frotz-2.54"));
        assertFalse(BSimTypeArchives.projectPath("littlefs-v2.9.3")
                .equals(BSimTypeArchives.projectPath("littlefs-v2.10.0")));
    }

    public void testResolveModePrefersOverrideThenProjectThenFileThenLocal() {
        BSimTestEnv.setTypeArchiveMode("");
        BSimTestEnv.setTypeArchiveDir("");
        assertEquals(Mode.PROJECT, BSimTypeArchives.resolveMode("project", false));
        assertEquals(Mode.FILE, BSimTypeArchives.resolveMode("file", true));
        assertEquals(Mode.LOCAL, BSimTypeArchives.resolveMode("local", true));
        assertEquals(Mode.PROJECT, BSimTypeArchives.resolveMode("", true));
        assertEquals(Mode.LOCAL, BSimTypeArchives.resolveMode("", false));
        BSimTestEnv.setTypeArchiveDir("/shared/types");
        assertEquals(Mode.FILE, BSimTypeArchives.resolveMode("", false));
        BSimTestEnv.setTypeArchiveMode("local");
        assertEquals(Mode.LOCAL, BSimTypeArchives.resolveMode("", true));
    }

    public void testFileModeWithoutStablePathIsFallbackLocal() {
        OpenedArchive fallback = OpenedArchive.fallbackLocal(null, "/ref/littlefs.o.gdt");
        OpenedArchive asFile = OpenedArchive.file(null, "/ref/littlefs.o.gdt");
        assertTrue(fallback.fallbackLocal());
        assertTrue(fallback.disassociateAfter());
        assertFalse(asFile.fallbackLocal());
        assertFalse(asFile.disassociateAfter());
    }

    public void testParseModeRejectsUnknown() {
        try {
            BSimTypeArchives.parseMode("disassociate");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("project, file, or local"));
        }
    }
}
