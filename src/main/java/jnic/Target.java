package jnic;

/**
 * Supported compilation targets. Each target maps to a zig cross-compilation triple,
 * a JNI header subdirectory, an embedded-library resource directory and the platform's
 * shared library naming convention.
 */
public enum Target {
    WINDOWS_X86_64("x86_64-windows-gnu", "win32", "jnic.dll"),
    WINDOWS_AARCH64("aarch64-windows-gnu", "win32", "jnic.dll"),
    LINUX_X86_64("x86_64-linux-gnu", "linux", "libjnic.so"),
    LINUX_AARCH64("aarch64-linux-gnu", "linux", "libjnic.so"),
    MACOS_X86_64("x86_64-macos", "darwin", "libjnic.dylib"),
    MACOS_AARCH64("aarch64-macos", "darwin", "libjnic.dylib");

    /** Directory (inside the output jar) holding this target's native library. */
    public final String resourceDir;

    private final String zigTriple;
    private final String jniMdSubdir;
    private final String libName;

    Target(String zigTriple, String jniMdSubdir, String libName) {
        this.zigTriple = zigTriple;
        this.jniMdSubdir = jniMdSubdir;
        this.libName = libName;
        String n = name().toLowerCase(java.util.Locale.ROOT);   // e.g. windows_x86_64
        int u = n.indexOf('_');
        this.resourceDir = "META-INF/jnic/" + n.substring(0, u) + "-" + n.substring(u + 1);
    }

    public String zigTriple() { return zigTriple; }
    public String jniMdSubdir() { return jniMdSubdir; }
    public String libName() { return libName; }

    /** Full jar entry path of the native library for this target. */
    public String libResourcePath() { return resourceDir + "/" + libName; }

    /**
     * Detects the target matching the machine we are currently running on,
     * used by tests and by users who want a single-target quick build.
     */
    public static Target current() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        boolean aarch64 = arch.contains("aarch64") || arch.contains("arm64");
        if (os.contains("win")) return aarch64 ? WINDOWS_AARCH64 : WINDOWS_X86_64;
        if (os.contains("mac") || os.contains("darwin")) return aarch64 ? MACOS_AARCH64 : MACOS_X86_64;
        if (os.contains("nux") || os.contains("nix") || os.contains("aix")) return aarch64 ? LINUX_AARCH64 : LINUX_X86_64;
        throw new ObfuscationException("unsupported host OS: " + os);
    }
}
