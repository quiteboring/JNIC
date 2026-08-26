package jnic.gen;

import jnic.classfile.ClassFile;
import jnic.classfile.ClassFile.MethodInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * Assembles the master C translation unit for one target. Each nativized class becomes
 * a self-contained scope (tables + macros + functions + bind routine); a JNIEXPORT
 * dispatcher routes JNICLoader.bind0(group, host) to the right class.
 *
 * Per-class macro contract consumed by {@link CEmitter}:
 * CLS_AT(i), STRC(i), IFID(i), SFID(i), VMID(i), SMID(i) plus statics SELF/BOOLARR/OBJCLS,
 * and arrays FREF[n][4], MREF[m][3].
 */
public final class GroupEmitter {

    public static final class EmittedClass {
        public final String className;
        public final int group;
        public final List<MethodInfo> methods;   // selected methods in class order
        public final List<String> functionNames = new ArrayList<>();
        public final List<String> signatures = new ArrayList<>();
        public final List<String> bodies = new ArrayList<>();
        public final CEmitter.Symbols symbols = new CEmitter.Symbols();

        public EmittedClass(String className, int group, List<MethodInfo> methods) {
            this.className = className;
            this.group = group;
            this.methods = methods;
        }
    }

    private final StringBuilder o = new StringBuilder();
    private final List<EmittedClass> classes;
    private final boolean stringObf;

    public GroupEmitter(List<EmittedClass> classes, boolean stringObf) {
        this.classes = classes;
        this.stringObf = stringObf;
    }

    /** Produces the complete master TU text. */
    public String emit() {
        o.append("#include <jni.h>\n");
        o.append(preambleResource());
        for (EmittedClass c : classes) emitClassScope(c);
        emitDispatcher();
        return o.toString();
    }

    private static String preambleResource() {
        try (java.io.InputStream in = GroupEmitter.class.getResourceAsStream("/jnic/preamble.c")) {
            if (in == null) throw new IllegalStateException("missing resource /jnic/preamble.c");
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8) + "\n";
        } catch (java.io.IOException e) {
            throw new IllegalStateException("failed reading preamble", e);
        }
    }

    private void emitClassScope(EmittedClass c) {
        CEmitter.Symbols sy = c.symbols;
        // Force-intern the names/signatures of every native method so bind() can reference them.
        for (MethodInfo m : c.methods) {
            sy.utf8(m.name.equals("<clinit>") ? "jn$clinit" : m.name);
            sy.utf8(m.desc);
        }
        int idx = c.group;

        line("/* ===== class " + c.className + " (group " + idx + ") ===== */");
        line("static jclass SELF_" + idx + " = NULL;");
        line("static jclass BOOLARR_" + idx + " = NULL;");
        line("static jclass OBJCLS_" + idx + " = NULL;");

        line("static const char *UT_" + idx + "[" + Math.max(sy.utf8.size(), 1) + "] = {");
        for (String s : sy.utf8) line("  \"" + CEmitter.cstr(s) + "\",");
        line("};");

        line("static const jint CLSIDX_" + idx + "[" + Math.max(sy.classNames.size(), 1) + "] = {");
        for (String s : sy.classNames) line("  " + sy.utf8.indexOf(s) + ",");
        line("};");

        if (stringObf && !sy.strBlobs.isEmpty()) {
            int total = 0;
            for (byte[] b : sy.strBlobs) total += b.length;
            line("static const unsigned char SKEY_" + idx + "[32] = {");
            StringBuilder kh = new StringBuilder();
            for (byte b : sy.strKey) kh.append(String.format("0x%02X,", b));
            line(kh.toString());
            line("};");
            line("static const unsigned char SBLOB_" + idx + "[" + total + "] = {");
            StringBuilder bh = new StringBuilder();
            for (byte[] b : sy.strBlobs) for (byte v : b) bh.append(String.format("0x%02X,", v));
            int pos = 0;
            for (byte[] b : sy.strBlobs) { for (int q = 0; q < b.length; q++) { if (bh.length() >= 2400) { line(bh.toString()); bh = new StringBuilder(); } } }
            line(bh.toString());
            line("};");
            line("static const jint SOFF_" + idx + "[" + sy.strBlobs.size() + "] = {");
            StringBuilder oh = new StringBuilder(); int o2 = 0;
            for (byte[] b : sy.strBlobs) { oh.append(o2).append(","); o2 += b.length; }
            line(oh.toString());
            line("};");
            line("static const jint SLEN_" + idx + "[" + sy.strBlobs.size() + "] = {");
            StringBuilder lh = new StringBuilder();
            for (byte[] b : sy.strBlobs) lh.append(b.length).append(",");
            line(lh.toString());
            line("};");
            line("#define STRC(k) jn_strdec(env, &STR_" + idx + "[k], SKEY_" + idx + ", SBLOB_" + idx + " + SOFF_" + idx + "[k], SLEN_" + idx + "[k])");
        } else {
            line("static const jint STRIDX_" + idx + "[" + Math.max(sy.strConsts.size(), 1) + "] = {");
            for (String s : sy.strConsts) line("  " + sy.utf8.indexOf(s) + ",");
            line("};");
            line("#define STRC(k) jn_string_const(env, &STR_" + idx + "[k], UT[STRIDX[k]])");
        }

        line("static jclass CLS_" + idx + "[" + Math.max(sy.classNames.size(), 1) + "];");
        line("static jobject STR_" + idx + "[" + Math.max(sy.strConsts.size(), 1) + "];");

        if (!sy.fieldRefs.isEmpty()) {
            line("static const jint FREF_" + idx + "[" + sy.fieldRefs.size() + "][4] = {");
            for (int[] r : sy.fieldRefs)
                line("  {" + r[0] + ", " + r[1] + ", " + r[2] + ", " + r[3] + "},");
            line("};");
            line("static jfieldID FID_" + idx + "[" + sy.fieldRefs.size() + "];");
        }
        if (!sy.methodRefs.isEmpty()) {
            line("static const jint MREF_" + idx + "[" + sy.methodRefs.size() + "][3] = {");
            for (int[] r : sy.methodRefs)
                line("  {" + r[0] + ", " + r[1] + ", " + r[2] + "},");
            line("};");
            line("static jmethodID MID_" + idx + "[" + sy.methodRefs.size() + "];");
        }

        String i = "_" + idx;
        line("#define SELF SELF" + i);
        line("#define BOOLARR BOOLARR" + i);
        line("#define OBJCLS OBJCLS" + i);
        line("#define UT UT" + i);
        line("#define CLSIDX CLSIDX" + i);
        line("#define STRIDX STRIDX" + i);
        line("#define FREF FREF" + i);
        line("#define MREF MREF" + i);
        line("#define CLS_AT(k) jn_cls(env, &CLS" + i + "[k], UT[CLSIDX[k]])");
        if (!sy.fieldRefs.isEmpty()) {
            line("#define FID FID" + i);
            line("#define IFID(k) (FID[k] ? FID[k] : (FID[k] = (*env)->GetFieldID(env, CLS_AT(FREF[k][0]), UT[FREF[k][1]], UT[FREF[k][2]])))");
            line("#define SFID(k) (FID[k] ? FID[k] : (FID[k] = (*env)->GetStaticFieldID(env, CLS_AT(FREF[k][0]), UT[FREF[k][1]], UT[FREF[k][2]])))");
        }
        if (!sy.methodRefs.isEmpty()) {
            line("#define MID MID" + i);
            line("#define VMID(k) (MID[k] ? MID[k] : (MID[k] = (*env)->GetMethodID(env, CLS_AT(MREF[k][0]), UT[MREF[k][1]], UT[MREF[k][2]])))");
            line("#define SMID(k) (MID[k] ? MID[k] : (MID[k] = (*env)->GetStaticMethodID(env, CLS_AT(MREF[k][0]), UT[MREF[k][1]], UT[MREF[k][2]])))");
        }

        for (int k = 0; k < c.methods.size(); k++) {
            MethodInfo m = c.methods.get(k);
            String fn = "F" + idx + "_" + k;
            c.functionNames.add(fn);
            c.signatures.add(m.desc);
            o.append(c.bodies.get(k)).append('\n');
        }

        line("static jint bind" + i + "(JNIEnv *env, jclass host) {");
        line("  if (!SELF" + i + ") {");
        line("    SELF" + i + " = (*env)->NewGlobalRef(env, host);");
        line("    if (!SELF" + i + ") return 1;");
        line("  }");
        line("  JnNativeMethod _nm[" + Math.max(c.methods.size(), 1) + "] = {");
        for (int k = 0; k < c.methods.size(); k++) {
            MethodInfo m = c.methods.get(k);
            String regName = m.name.equals("<clinit>") ? "jn$clinit" : m.name;
            line("    {(char*)UT[" + utf8IndexOf(sy, regName) + "], (char*)UT["
                + utf8IndexOf(sy, m.desc) + "], (void*)" + c.functionNames.get(k) + "},");
        }
        line("  };");
        line("  return (*env)->RegisterNatives(env, host, (const JNINativeMethod*)_nm, "
            + c.methods.size() + ") == 0 ? 0 : 2;");
        line("}");

        line("#undef SELF");
        line("#undef BOOLARR");
        line("#undef OBJCLS");
        line("#undef UT");
        line("#undef CLSIDX");
        line("#undef STRIDX");
        line("#undef FREF");
        line("#undef MREF");
        line("#undef CLS_AT");
        line("#undef STRC");
        if (!sy.fieldRefs.isEmpty()) {
            line("#undef FID");
            line("#undef IFID");
            line("#undef SFID");
        }
        if (!sy.methodRefs.isEmpty()) {
            line("#undef MID");
            line("#undef VMID");
            line("#undef SMID");
        }
    }

    private static int utf8IndexOf(CEmitter.Symbols sy, String s) {
        int i = sy.utf8.indexOf(s);
        if (i < 0) throw new IllegalStateException("bind symbol not interned: " + s);
        return i;
    }

    private void emitDispatcher() {
        line("JNIEXPORT jint JNICALL Java_jnic_loader_JNICLoader_bind0(JNIEnv *env, jclass loader, jint group, jclass host) {");
        line("  switch (group) {");
        for (EmittedClass c : classes)
            line("    case " + c.group + ": return bind_" + c.group + "(env, host);");
        line("    default: return -1;");
        line("  }");
        line("}");
    }

    private void line(String s) { o.append(s).append('\n'); }
}
