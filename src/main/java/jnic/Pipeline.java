package jnic;

import jnic.classfile.ClassFile;
import jnic.compile.ZigDriver;
import jnic.gen.CEmitter;
import jnic.gen.GroupEmitter;
import jnic.io.JarIO;
import jnic.match.Matcher;
import jnic.select.Selector;
import jnic.transform.Nativizer;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** End-to-end obfuscation run: select, transpile, rewrite, compile, embed, emit. */
public final class Pipeline {

    public static void run(Path in, Path out, Config config, ZigDriver zig) throws Exception {
        Map<String, byte[]> entries = JarIO.read(in);
        Matcher matcher = new Matcher(config);
        CEmitter.FLOW_OBF = config.options.flowObf;

        List<GroupEmitter.EmittedClass> emitted = new ArrayList<>();
        Map<String, byte[]> result = new LinkedHashMap<>();
        int groupCounter = 0;

        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            String name = e.getKey();
            if (!name.endsWith(".class") || name.startsWith("META-INF/") || name.equals("module-info.class")) {
                result.put(name, e.getValue());
                continue;
            }
            String internalName = name.substring(0, name.length() - ".class".length());
            ClassFile cf = ClassFile.parse(e.getValue(), internalName);

            List<ClassFile.MethodInfo> selected =
                Selector.select(cf, matcher, List.copyOf(cf.visibleAnnotations));
            if (selected.isEmpty()) {
                result.put(name, e.getValue());
                continue;
            }

            GroupEmitter.EmittedClass ec =
                new GroupEmitter.EmittedClass(internalName, groupCounter++, selected);
            for (int k = 0; k < selected.size(); k++) {
                ClassFile.MethodInfo m = selected.get(k);
                String fn = "F" + ec.group + "_" + k;
                ec.bodies.add(CEmitter.emit(cf, m, ec.symbols, fn));
            }
            if (config.options.stringObf) {
                byte[] key = new byte[32];
                new java.security.SecureRandom().nextBytes(key);
                ec.symbols.strKey = key;
                java.util.Random rnd = new java.security.SecureRandom();
                for (String lit : ec.symbols.strConsts) {
                    byte[] data = CEmitter.modifiedUtf8(lit);
                    byte[] nonce = new byte[12];
                    rnd.nextBytes(nonce);
                    jnic.crypto.ChaCha.xor(key, 1, nonce, data, 0, data.length);
                    byte[] blob = new byte[12 + data.length];
                    System.arraycopy(nonce, 0, blob, 0, 12);
                    System.arraycopy(data, 0, blob, 12, data.length);
                    ec.symbols.strBlobs.add(blob);
                }
            }
            emitted.add(ec);

            Set<String> keys = new java.util.HashSet<>();
            for (ClassFile.MethodInfo m : selected) keys.add(m.name + " " + m.desc);
            result.put(name, Nativizer.rewrite(e.getValue(), keys, ec.group,
                config.options.stringObf, entries));
        }

        if (emitted.isEmpty())
            System.out.println("[jnic] no methods matched; output is a copy of the input");

        GroupEmitter master = new GroupEmitter(emitted, config.options.stringObf);
        String masterC = master.emit();

        Path work = Files.createTempDirectory("jnic-build");
        try {
            // Loader classes are bundled resources of this jar (compiled from loader-src).
            copyLoaderClasses(result);

            for (Target target : config.targets) {
                System.out.println("[jnic] building " + target);
                Path runtimeA = work.resolve("jnicrt-" + target.name().toLowerCase(Locale.ROOT) + ".a");
                zig.buildRuntime(work, target, config.options.fastCompile, runtimeA);
                Path lib = work.resolve(target.libName());
                Files.writeString(work.resolve("master-" + target + ".c"), masterC);
                zig.linkMaster(work, target, config.options.fastCompile,
                    work.resolve("master-" + target + ".c"), runtimeA, lib);
                result.put(target.libResourcePath(), Files.readAllBytes(lib));
            }
        } finally {
            if (!Boolean.getBoolean("jnic.keepwork")) deleteTree(work);
        }

        JarIO.write(out, result);
    }

    private static void copyLoaderClasses(Map<String, byte[]> out) throws Exception {
        ClassLoader cl = Pipeline.class.getClassLoader();
        java.util.jar.JarFile jar = null;
        try {
            Object src = Pipeline.class.getProtectionDomain().getCodeSource().getLocation();
            Path self = Path.of(((java.net.URL) src).toURI());
            if (Files.isRegularFile(self)) {
                jar = new java.util.jar.JarFile(self.toFile());
                var it = jar.entries();
                while (it.hasMoreElements()) {
                    String n = it.nextElement().getName();
                    if (!n.startsWith("jnic/loader/") || !n.endsWith(".class")) continue;
                    if (out.containsKey(n)) continue;
                    try (InputStream in = cl.getResourceAsStream(n)) {
                        if (in != null) out.put(n, in.readAllBytes());
                    }
                }
                return;
            }
        } catch (Exception ignored) {
            // fall through to classpath scan
        } finally {
            if (jar != null) jar.close();
        }
        // Exploded-classpath fallback (dev runs): scan known names.
        List<String> names = new ArrayList<>();
        names.add("jnic/loader/JNICLoader.class");
        for (String nested : new String[]{"BsmEntry", "Buf", "ClsIdx", "StrIdx", "MtIdx",
                                          "MhIdx", "Ref", "NtIdx"})
            names.add("jnic/loader/BsmParser$" + nested + ".class");
        for (String n : names) {
            try (InputStream in = cl.getResourceAsStream(n)) {
                if (in != null) out.putIfAbsent(n, in.readAllBytes());
            }
        }
    }

    private static void deleteTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.delete(path); } catch (Exception ignored) { }
            });
        }
    }

    private Pipeline() {}
}
