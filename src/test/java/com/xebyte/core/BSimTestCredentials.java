package com.xebyte.core;

/**
 * Test-only bridge to {@link GhidraMCPAuthInitializer}'s package-private
 * install hook, so offline tests (in {@code com.xebyte.offline}) can exercise
 * the credential paths — e.g. that a {@code ghidra://} ingest passes
 * {@code --user} and feeds the password on stdin — without touching real
 * environment variables.
 */
public final class BSimTestCredentials {

    private BSimTestCredentials() {}

    public static void install(String user, String password) {
        GhidraMCPAuthInitializer.installAuthenticatorForTest(
                new GhidraMCPAuthenticator(user, password.toCharArray()));
    }

    public static void clear() {
        GhidraMCPAuthInitializer.installAuthenticatorForTest(null);
    }
}
