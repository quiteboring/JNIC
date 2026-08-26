# Contributing to JNIC

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| JDK | 25+ | Must be a full **JDK** (not a JRE) — JNI headers from `java.home/include` are used during native compilation |
| Git | any | |

You do **not** need to install Gradle (the wrapper handles it) or Zig separately for Java-only changes. The vendored Zig toolchain in `tools/` is required only when building protected jars with the obfuscator.

## Setup

```bat
git clone https://github.com/YOUR_USERNAME/JNIC.git
cd JNIC

:: point JAVA_HOME at your JDK 25 install
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%

:: build and verify
.\gradlew.bat clean fatJar
```

Output lands in `build/libs/jnic-1.0.0.jar`.

## Project structure

```
├── src/main/java/jnic/
│   ├── Main.java                  CLI entry point
│   ├── Config.java                XML config parser
│   ├── Pipeline.java              end-to-end orchestration
│   ├── Target.java                supported platforms enum
│   ├── ObfuscationException.java
│   ├── classfile/ClassFile.java   minimal classfile parser (CP, Code, annotations)
│   ├── compile/ZigDriver.java     zig toolchain wrapper (build-lib + zig cc)
│   ├── crypto/ChaCha.java         build-side ChaCha20 encryptor
│   ├── gen/
│   │   ├── Bytecodes.java         JVMS opcode table + lengths/successors
│   │   ├── Analyzer.java          slot-depth dataflow over method bodies
│   │   ├── Desc.java              method/type descriptor parsing
│   │   ├── CEmitter.java          bytecode → C switch-interpreter emitter (~1100 lines)
│   │   └── GroupEmitter.java      per-class TU assembler + bind dispatcher
│   ├── io/JarIO.java              jar read/write preserving entry order
│   ├── match/MatchRule.java       <match> regex rules
│   ├── match/Matcher.java         include/exclude + annotation gate logic
│   ├── select/Selector.java       picks nativizable methods per class
│   └── transform/Nativizer.java   ASM surgery: strip code, mark native, inject clinit
├── src/main/resources/jnic/
│   ├── preamble.c                 support runtime compiled into every TU
│   └── zig/jnicrt.zig             portable crypto primitives (embedded at build)
├── loader-src/jnic/loader/
│   └── JNICLoader.java            injected runtime (compiled at release 11)
├── tools/zig-windows-x86_64-0.13.0/   vendored zig compiler (gitignored)
└── OBFUSCATING.md                 user-facing usage guide
```

### Key concepts

- **Two-pass compilation**: each target gets a runtime static library (`jnicrt.a` from `jnicrt.zig`) plus one master translation unit linking all transpiled methods against JNI headers via `zig cc -shared`.
- **Cell operand stack**: all transpiled methods use a flat `Cell` union stack mirroring JVM slot semantics exactly — category-2 values occupy two slots.
- **Handler edges**: exception handlers are seeded at depth 1 (throwable only) into the dataflow; propagation leaves the pending exception intact.
- **Interface exclusion**: interfaces are never nativized because HotSpot cannot dispatch registered natives through inherited default-method vtables.
- **Loader injection**: `Nativizer` renames original `<clinit>` → `jn$clinit`, emits a fresh clinit calling `JNICLoader.bind(group, Class)` which invokes `RegisterNatives`.

## Making changes

1. Create a branch: `git checkout -b my-feature`
2. Make your changes — keep the existing code style (no Lombok, no external deps beyond ASM)
3. Rebuild: `.\gradlew.bat clean fatJar`
4. Test with your own jar:
   ```bat
   cd test-or-wherever
   java -jar path\to\jnic-1.0.0.jar input.jar output.jar config.xml
   java --enable-native-access=ALL-UNNAMED -jar output.jar
   ```
5. Submit a PR with a clear description of what changed and why.

### Adding opcode support or fixing emitter bugs

The emitter (`CEmitter.java`) maps every JVM instruction to its C equivalent inside a `switch(pc)` interpreter. When adding an op:

1. Add it to `Bytecodes.java`: length, successors, terminates (if applicable), localVarIndex/isCategory2Store/isLoad/isStore (if applicable)
2. Add it to `Analyzer.delta()`: net slot-count change per invocation
3. Add it to `CEmitter.emitInstruction()`: the C emission

All three must agree on slot counts. A mismatch causes either false overflow/underflow errors or silent stack corruption.

### Adding a new compilation target

Add an entry to the `Target` enum in `Target.java`:

```java
FREEBSD_X86_64("x86_64-freebsd-gnu", "freebsd", "libjnic.so"),
```

The zig triple determines cross-compilation; `jniMdSubdir` picks the JNI header directory; `libName` is the shared library filename convention.

### Debugging protected jar crashes

Set `JNIC_TRACE=1` environment variable before launching the protected jar to get per-instruction `[function pc sp s0 s1 s2]` traces on stderr (requires the trace macro to be re-enabled in `preamble.c`). Use `-Xcheck:jni` to catch bad JNI argument passing.

## Reporting issues

Include:
1. The exact config.xml used
2. The full obfuscator console output
3. For runtime crashes: the hs_err log or stack trace, plus the expected-vs-actual output diff
