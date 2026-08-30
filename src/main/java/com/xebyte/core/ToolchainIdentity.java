package com.xebyte.core;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Full toolchain identity: {@code <compiler><major>-<target>}.
 *
 * <p>Family drift (GCC vs LLVM) is larger than version drift. A corpus of only
 * GCC-built objects will not match Clang/Rust firmware. The identity therefore
 * names compiler <em>and</em> target, not a GCC version with ARM implied.
 * {@code gcc13-arm} is what this repo ships; {@code clang17-arm} /
 * {@code gcc12-xtensa} / {@code gcc13-riscv} parse to the right binaries and
 * default {@code arch_flags} so adding a prefix later is a layer in the same
 * image, not a new MCP parameter.
 *
 * <p>The major number selects which packed prefix the builder invokes:
 * {@code gcc10-arm} and {@code gcc13-arm} are different binaries in one
 * container. The installed set is what {@code GET /health} lists; this class
 * only answers "what would this identity run".
 */
public record ToolchainIdentity(
        String id,
        String family,
        int major,
        String target,
        String cc,
        String ld,
        String strip,
        String nm,
        String defaultArchFlags
) {
    /** {@code gcc13-arm}, {@code clang17-arm}, {@code gcc12-xtensa}. */
    public static final Pattern ID = Pattern.compile(
            "^([a-z]+)([0-9]+)-([a-z][a-z0-9]*)$");

    public static final String FORMAT_HINT =
            "<compiler><major>-<target> (e.g. gcc13-arm, clang17-arm)";

    /** Pairs this class can turn into a compiler command line. */
    public static final List<String> KNOWN_PAIRS = List.of(
            "gcc-arm", "clang-arm", "gcc-xtensa", "gcc-riscv");

    public static ToolchainIdentity parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException(
                    "toolchain is required; format is " + FORMAT_HINT);
        }
        String id = raw.trim();
        Matcher m = ID.matcher(id);
        if (!m.matches()) {
            throw new IllegalArgumentException(
                    "toolchain must be " + FORMAT_HINT + "; got '" + id + "'");
        }
        String family = m.group(1);
        int major = Integer.parseInt(m.group(2));
        String target = m.group(3);
        Tools tools = toolsFor(family, target);
        return new ToolchainIdentity(
                id, family, major, target, tools.cc, tools.ld, tools.strip, tools.nm,
                tools.archFlags);
    }

    static Tools toolsFor(String family, String target) {
        String pair = family + "-" + target;
        return switch (pair) {
            case "gcc-arm" -> new Tools(
                    "arm-none-eabi-gcc",
                    "arm-none-eabi-ld",
                    "arm-none-eabi-strip",
                    "arm-none-eabi-nm",
                    "-mcpu=cortex-m0plus -mthumb");
            case "clang-arm" -> new Tools(
                    "clang",
                    "ld.lld",
                    "llvm-strip",
                    "llvm-nm",
                    "--target=thumbv6m-none-eabi");
            case "gcc-xtensa" -> new Tools(
                    "xtensa-esp32-elf-gcc",
                    "xtensa-esp32-elf-ld",
                    "xtensa-esp32-elf-strip",
                    "xtensa-esp32-elf-nm",
                    "-mlongcalls");
            case "gcc-riscv" -> new Tools(
                    "riscv32-unknown-elf-gcc",
                    "riscv32-unknown-elf-ld",
                    "riscv32-unknown-elf-strip",
                    "riscv32-unknown-elf-nm",
                    "-march=rv32imac -mabi=ilp32");
            default -> throw new IllegalArgumentException(
                    "unknown compiler/target '" + family + "-" + target
                            + "'; known pairs: " + KNOWN_PAIRS);
        };
    }

    record Tools(String cc, String ld, String strip, String nm, String archFlags) {}
}
