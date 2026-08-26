# Obfuscating a JAR — Portable Folder Setup

## Folder layout

Before starting, set up a working folder like this:

```
obfuscate/
├── jnic-1.0.0.jar                          the obfuscator (from build/libs/)
├── tools/
│   └── zig-windows-x86_64-0.13.0/          full zig toolchain folder
├── myapp.jar                               your input jar
└── config.xml                              obfuscation config (see below)
```

**Why `tools/zig-...`:** the obfuscator looks for zig in this order:

1. `ZIG_HOME` environment variable
2. `zig.exe` on `PATH`
3. `tools\zig-windows-x86_64-0.13.0\zig.exe` relative to the **folder you run from**

If zig is already installed globally (1 or 2), you can skip copying the `tools/` folder entirely.

## Requirements on the machine doing the obfuscating

- **JDK 25+** (a full JDK, not a bare JRE — the JNI headers inside `java.home/include` are used during compilation)
- Run all commands from inside this folder (`cd obfuscate` first) so the zig fallback path resolves

## Config file

```xml
<jnic>
    <targets>
        <target>WINDOWS_X86_64</target>
    </targets>
    <options>
        <stringObf>true</stringObf>
        <flowObf>true</flowObf>
        <fastCompile>false</fastCompile>
    </options>
</jnic>
```

### Targets (any combination)

| Name | Platform |
|---|---|
| `WINDOWS_X86_64` | Windows x64 |
| `WINDOWS_AARCH64` | Windows ARM64 |
| `LINUX_X86_64` | Linux x64 |
| `LINUX_AARCH64` | Linux ARM64 |
| `MACOS_X86_64` | macOS x64 |
| `MACOS_AARCH64` | macOS Apple Silicon |

Each target cross-compiles its own native library and embeds it in the output jar — build once, ship everywhere.

### Options

| Option | Effect |
|---|---|
| `stringObf` | Encrypts every string literal (ChaCha20); decrypted lazily at runtime |
| `flowObf` | Relabels all program counters with per-method XOR keys |
| `fastCompile` | Smaller/faster obfuscator builds (`ReleaseSmall` + `-Oz`) at some runtime perf cost |

## Running the obfuscator

```bat
cd obfuscate
java -jar jnic-1.0.0.jar myapp.jar myapp-protected.jar config.xml
```

Progress prints `[jnic] ...` lines; the result is `myapp-protected.jar`.

### What goes into the output jar

- Your original classes — selected method bodies removed, methods marked `native`, an injected `<clinit>` that binds them at load time
- `jnic/loader/JNICLoader.class` (+ helpers) — runtime support, extracted and loaded automatically
- `META-INF/jnic/<target>/<lib>` — one native library per configured target

### Selection rules

By default every method **with a body** is nativized except constructors and interface-declared defaults. To narrow scope:

```xml
<jnic>
    ...
    <include>
        <match className="com/mycompany/secret/.*"/>
    </include>
    <exclude>
        <match className=".*" methodName="toString"/>
    </exclude>
</jnic>
```

All attributes are regexes against internal names (`com/foo/Bar`). Omitted attribute = matches everything. `<include>` empty means "everything"; `<exclude>` always wins. `includeAnnotation` / `excludeAnnotation` elements (binary or source class name) gate by runtime-visible annotations.

### Input constraints

- Java 8+ bytecode (class version 52+); no `JSR`/`RET`; no `ConstantDynamic`
- Constructors and interface default methods are never nativized (stay as bytecode)
- Reflection over method bodies of nativized code won't see original bytecode

## Running the protected jar

Copy `myapp-protected.jar` to any machine matching one of the compiled targets:

```bat
java --enable-native-access=ALL-UNNAMED -jar myapp-protected.jar
```

On first launch the loader extracts the correct native library to a temp file, loads it, and binds your methods — no installation steps. On JDK 21+ the `--enable-native-access=ALL-UNNAMED` flag silences restricted-method warnings.
