package jnic.compile;

import jnic.ObfuscationException;
import jnic.Target;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Drives the zig toolchain: builds the portable runtime static archive once, then links
 * each generated master translation unit into the target's shared library.
 */
public final class ZigDriver {

    private final Path executable;
    private final String version;

    private ZigDriver(Path executable, String version) {
        this.executable = executable;
        this.version = version;
    }

    public Path executable() { return executable; }

    public String version() { return version; }

    /** Finds zig via ZIG_HOME, then PATH, then the vendored tools/ layout. */
    public static ZigDriver locate() {
        String exe = System.getProperty("os.name").toLowerCase().contains("win") ? "zig.exe" : "zig";
        for (Path candidate : candidates(exe)) {
            if (!Files.isRegularFile(candidate)) continue;
            try {
                String v = execCapture(candidate.getParent(), candidate.toString(), "version");
                return new ZigDriver(candidate.toAbsolutePath(), v.trim());
            } catch (IOException | InterruptedException e) {
                throw new ObfuscationException("failed to run zig at " + candidate + ": " + e.getMessage(), e);
            }
        }
        throw new ObfuscationException("zig not found; set ZIG_HOME or add zig to PATH");
    }

    private static List<Path> candidates(String exe) {
        List<Path> out = new ArrayList<>();
        String zh = System.getenv("ZIG_HOME");
        if (zh != null) out.add(Path.of(zh, exe));
        for (String dir : System.getProperty("PATH", "").split(File.pathSeparator)) {
            if (!dir.isBlank()) out.add(Path.of(dir, exe));
        }
        Path cwd = Path.of("").toAbsolutePath();
        out.add(cwd.resolve("tools/zig-windows-x86_64-0.13.0").resolve(exe));
        return out;
    }

    /**
     * Compiles the runtime sources into a static archive for {@code target}.
     * Sources are extracted from the obfuscator's own resources.
     *
     * @param workDir scratch dir holding extracted zig sources
     * @param outA    destination archive path
     */
    public void buildRuntime(Path workDir, Target target, boolean fastCompile, Path outA) {
        try {
            Path src = workDir.resolve("jnicrt.zig");
            Files.createDirectories(workDir);
            Files.write(src, runtimeResource());
            exec(workDir,
                executable.toString(),
                "build-lib",
                fastCompile ? "-OReleaseSmall" : "-OReleaseFast",
                "-target", target.zigTriple(),
                "--name", "jnicrt",
                "-femit-bin=" + outA.toAbsolutePath(),
                src.toAbsolutePath().toString());
        } catch (IOException e) {
            throw new ObfuscationException("runtime static-lib build failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ObfuscationException("interrupted during zig build", e);
        }
    }

    /**
     * Compiles one generated master TU against JNI headers and links it with the
     * runtime archive into the final shared library.
     */
    public void linkMaster(Path workDir, Target target, boolean fastCompile, Path masterC, Path runtimeA, Path outLib) {
        String javaHome = System.getProperty("java.home");
        try {
            exec(workDir,
                executable.toString(),
                "cc",
                "-shared",
                "-target", target.zigTriple(),
                "-I" + Path.of(javaHome, "include"),
                "-I" + Path.of(javaHome, "include", target.jniMdSubdir()),
                fastCompile ? "-Oz" : "-O2",
                "-g",
                "-o", outLib.toAbsolutePath().toString(),
                masterC.toAbsolutePath().toString(),
                runtimeA.toAbsolutePath().toString());
        } catch (IOException e) {
            throw new ObfuscationException("shared-library build failed for " + target + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ObfuscationException("interrupted during zig cc", e);
        }
    }

    private byte[] runtimeResource() {
        try (java.io.InputStream in = ZigDriver.class.getResourceAsStream("/jnic/zig/jnicrt.zig")) {
            if (in == null)
                throw new ObfuscationException("bundled resource missing: /jnic/zig/jnicrt.zig");
            return in.readAllBytes();
        } catch (IOException e) {
            throw new ObfuscationException("failed reading bundled zig runtime", e);
        }
    }

    private static void exec(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).inheritIO().start();
        if (!p.waitFor(15, TimeUnit.MINUTES))
            throw new IOException("timed out: " + String.join(" ", cmd));
        if (p.exitValue() != 0)
            throw new IOException("command failed (" + p.exitValue() + "): " + String.join(" ", cmd));
    }

    private static String execCapture(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).start();
        byte[] out = p.getInputStream().readAllBytes();
        if (!p.waitFor(1, TimeUnit.MINUTES)) throw new IOException("timed out: zig version");
        if (p.exitValue() != 0) throw new IOException("zig version failed");
        return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    }
}

