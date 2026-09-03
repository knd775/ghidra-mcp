package com.xebyte.core;

/**
 * Test-only overrides for {@link BSimUrls} environment reads. Production code
 * must go through the real env vars; these fields are package-visible so this
 * helper can set them without a public API.
 */
public final class BSimTestEnv {

    private BSimTestEnv() {}

    public static void setAllowlist(String urls) {
        BSimUrls.allowlistOverride = urls;
    }

    public static void setRoot(String root) {
        BSimUrls.rootOverride = root;
    }

    public static void setUser(String user) {
        BSimUrls.userOverride = user;
    }

    public static void setPassword(String password) {
        BSimUrls.passwordOverride = password;
    }

    public static void setTemplates(String templates) {
        BSimUrls.templatesOverride = templates;
    }

    public static void setTypeArchiveMode(String mode) {
        BSimTypeArchives.modeOverride = mode;
    }

    public static void setTypeArchiveDir(String dir) {
        BSimTypeArchives.dirOverride = dir;
    }

    public static void clear() {
        BSimUrls.allowlistOverride = null;
        BSimUrls.rootOverride = null;
        BSimUrls.userOverride = null;
        BSimUrls.passwordOverride = null;
        BSimUrls.templatesOverride = null;
        BSimTypeArchives.modeOverride = null;
        BSimTypeArchives.dirOverride = null;
    }
}
