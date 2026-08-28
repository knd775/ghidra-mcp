package com.xebyte.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Local JVM identity versus Ghidra Server auth identity.
 *
 * <p>{@code user.name} (set via {@code -Duser.name} / {@code GHIDRA_USER}) is
 * the name Ghidra records on checkouts and compares at check-in.
 * {@code GHIDRA_SERVER_USER} is the RMI login. They are not interchangeable.
 * A copied {@code .gpr}/{@code .rep} keeps checkout ownership from the
 * original account; {@code resetOwner=true} on open rewrites {@code project.prp}
 * but does not transfer those checkouts.
 */
public final class GhidraIdentity {

    private GhidraIdentity() {}

    public static String jvmUser() {
        String n = System.getProperty("user.name");
        return n != null ? n : "";
    }

    public static String serverUser() {
        String n = System.getenv("GHIDRA_SERVER_USER");
        return n != null ? n : "";
    }

    public static boolean usersDiffer() {
        String server = serverUser();
        if (server.isBlank()) {
            return false;
        }
        return !server.equals(jvmUser());
    }

    public static String mismatchWarning() {
        if (!usersDiffer()) {
            return null;
        }
        return "JVM user.name ('" + jvmUser() + "') differs from GHIDRA_SERVER_USER ('"
            + serverUser() + "'). Ghidra records checkouts under user.name. Set GHIDRA_USER to "
            + "the same value as GHIDRA_SERVER_USER before taking a checkout. A copied project "
            + "can still hold checkouts owned by the original account; those will fail at "
            + "check-in until undone and re-taken.";
    }

    /** Fields for connect / open / status payloads. */
    public static Map<String, Object> describe() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jvm_user", jvmUser());
        String server = serverUser();
        if (!server.isBlank()) {
            out.put("ghidra_server_user", server);
        }
        boolean mismatch = usersDiffer();
        out.put("identity_mismatch", mismatch);
        if (mismatch) {
            out.put("identity_warning", mismatchWarning());
        }
        return out;
    }

    /**
     * Error text when a mutating version-control call should not proceed
     * because the JVM user and the server login disagree. Null when the call
     * may continue.
     */
    public static String mutationBlocker() {
        return mismatchWarning();
    }
}
