package jnic.classfile;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal classfile reader extracting exactly what the transpiler needs:
 * constant pool (with raw modified-UTF-8 bytes) and Code attribute contents.
 * Rejects constructs documented as incompatible (pre-Java 8 versions,
 * ConstantDynamic entries).
 */
public final class ClassFile {

    public static final class ConstPool {
        public final int tag;
        /** Raw bytes for CONSTANT_Utf8. */
        public final byte[] utf8;
        public final int a, b;
        /** Decoded integer/float/long/double payload (boxed); raw bits kept too. */
        public final Object boxed;

        ConstPool(int tag, byte[] utf8, int a, int b, Object boxed) {
            this.tag = tag;
            this.utf8 = utf8;
            this.a = a;
            this.b = b;
            this.boxed = boxed;
        }

        public String utf8Value() {
            StringBuilder sb = new StringBuilder(utf8.length);
            int i = 0;
            while (i < utf8.length) {
                int c = utf8[i++] & 0xFF;
                if (c < 0x80) sb.append((char) c);
                else if ((c & 0xE0) == 0xC0)
                    sb.append((char) (((c & 0x1F) << 6) | (utf8[i++] & 0x3F)));
                else if ((c & 0xF0) == 0xE0)
                    sb.append((char) (((c & 0x0F) << 12) | ((utf8[i++] & 0x3F) << 6)
                        | (utf8[i++] & 0x3F)));
                else throw new IllegalStateException("invalid modified UTF-8 byte");
            }
            return sb.toString();
        }
    }

    public static final class ExceptionEntry {
        public final int startPc, endPc, handlerPc, catchType; // catchType 0 = catch-all

        ExceptionEntry(int s, int e, int h, int c) {
            this.startPc = s;
            this.endPc = e;
            this.handlerPc = h;
            this.catchType = c;
        }
    }

    public static final class MethodInfo {
        public final int access;
        public final String name, desc;
        public final int maxStack, maxLocals;
        public final byte[] code;          // null for abstract/native methods
        public final List<ExceptionEntry> handlers;
        public final List<String> visibleAnnotations;

        MethodInfo(int access, String name, String desc, int maxStack, int maxLocals,
                   byte[] code, List<ExceptionEntry> handlers, List<String> visibleAnnotations) {
            this.access = access;
            this.name = name;
            this.desc = desc;
            this.maxStack = maxStack;
            this.maxLocals = maxLocals;
            this.code = code;
            this.handlers = handlers;
            this.visibleAnnotations = visibleAnnotations;
        }

        public boolean hasCode() { return code != null; }
    }

    public static final int TAG_UTF8 = 1, TAG_INT = 3, TAG_FLOAT = 4, TAG_LONG = 5, TAG_DOUBLE = 6,
        TAG_CLASS = 7, TAG_STRING = 8, TAG_FIELD = 9, TAG_METHOD = 10, TAG_IFACE_METHOD = 11,
        TAG_NAME_AND_TYPE = 12, TAG_METHOD_HANDLE = 15, TAG_METHOD_TYPE = 16, TAG_DYNAMIC = 17,
        TAG_INVOKE_DYNAMIC = 18, TAG_MODULE = 19, TAG_PACKAGE = 20;

    public static final class BootstrapEntry {
        public final int bsmRef;          // CONSTANT_MethodHandle index
        public final int[] args;          // static argument CP indices

        BootstrapEntry(int bsmRef, int[] args) {
            this.bsmRef = bsmRef;
            this.args = args;
        }
    }

    public final int access;
    public final int minor, major;
    public final String className;
    public final ConstPool[] cp; // index 0 unused
    public final List<MethodInfo> methods;
    public final List<BootstrapEntry> bootstrapMethods;
    public final List<String> visibleAnnotations;

    private ClassFile(int access, int minor, int major, String className, ConstPool[] cp, List<MethodInfo> methods,
                      List<BootstrapEntry> bootstrapMethods, List<String> visibleAnnotations) {
        this.access = access;
        this.minor = minor;
        this.major = major;
        this.className = className;
        this.cp = cp;
        this.methods = methods;
        this.bootstrapMethods = bootstrapMethods;
        this.visibleAnnotations = visibleAnnotations;
    }

    public static ClassFile parse(byte[] data, String expectedName) {
        Reader r = new Reader(data);
        boolean trace = Boolean.getBoolean("jnic.debug.cp");
        try {
            int magic = r.u4();
            if (trace) {
                StringBuilder hb = new StringBuilder();
                for (int x = 0; x < Math.min(24, data.length); x++)
                    hb.append(String.format("%02X ", data[x]));
                System.out.println("parse len=" + data.length + " head=" + hb);
            }
            if (magic != 0xCAFEBABE) throw bad(expectedName, "not a class file");
            int minor = r.u2(), major = r.u2();
            if (major < 52) throw bad(expectedName,
                "unsupported class file version " + major + " (Java 8 / major 52+ required)");
            int count = r.u2();
            ConstPool[] cp = new ConstPool[count];
            for (int i = 1; i < count; i++) {
                int tag = r.u1();
                if (trace) System.out.println("cp[" + i + "] tag=" + tag);
                switch (tag) {
                    case TAG_UTF8 -> cp[i] = new ConstPool(tag, r.bytes(r.u2()), 0, 0, null);
                    case TAG_INT -> cp[i] = new ConstPool(tag, null, 0, 0, r.s4());
                    case TAG_FLOAT -> cp[i] = new ConstPool(tag, null, 0, 0, Float.intBitsToFloat(r.u4()));
                    case TAG_LONG -> cp[i] = new ConstPool(tag, null, 0, 0, r.s8());
                    case TAG_DOUBLE -> cp[i] = new ConstPool(tag, null, 0, 0, Double.longBitsToDouble(r.u8()));
                    case TAG_CLASS, TAG_STRING, TAG_METHOD_TYPE, TAG_MODULE, TAG_PACKAGE ->
                        cp[i] = new ConstPool(tag, null, r.u2(), 0, null);
                    case TAG_FIELD, TAG_METHOD, TAG_IFACE_METHOD, TAG_NAME_AND_TYPE, TAG_INVOKE_DYNAMIC ->
                        cp[i] = new ConstPool(tag, null, r.u2(), r.u2(), null);
                    case TAG_METHOD_HANDLE -> cp[i] = new ConstPool(tag, null, r.u1(), r.u2(), null);
                    case TAG_DYNAMIC -> throw bad(expectedName,
                        "ConstantDynamic entries are not supported");
                    default -> throw bad(expectedName, "unknown constant pool tag " + tag);
                }
                if (tag == TAG_LONG || tag == TAG_DOUBLE) i++; // 8-byte constants take two slots
            }

            int access = r.u2(), thisClass = r.u2(), superClass = r.u2(); // super may be 0 (Object)
            String cn = className(cp, thisClass);
            if (expectedName != null && !expectedName.equals(cn))
                throw bad(expectedName, "internal name mismatch: " + cn);
            int icount = r.u2();
            r.skip(icount * 2L);

                List<MethodInfo> methods = new ArrayList<>();
                skipMembers(r);
            int mcount = r.u2();
            for (int i = 0; i < mcount; i++) {
                int maccess = r.u2();
                String mname = utf8(cp, r.u2());
                String mdesc = utf8(cp, r.u2());
                int acount = r.u2();
                int maxStack = 0, maxLocals = 0;
                byte[] code = null;
                List<ExceptionEntry> handlers = List.of();
                List<String> mAnns = List.of();
                for (int j = 0; j < acount; j++) {
                    String aname = utf8(cp, r.u2());
                    int alen = r.u4();
                    if (aname.equals("Code")) {
                        maxStack = r.u2();
                        maxLocals = r.u2();
                        int clen = r.u4();
                        code = r.bytes(clen);
                        int ecount = r.u2();
                        List<ExceptionEntry> hs = new ArrayList<>(ecount);
                        for (int k = 0; k < ecount; k++)
                            hs.add(new ExceptionEntry(r.u2(), r.u2(), r.u2(), r.u2()));
                        handlers = List.copyOf(hs);
                        // Remaining Code sub-attributes (LineNumberTable etc.) are irrelevant.
                        r.skip(alen - (2L + 2 + 4 + clen + 2 + ecount * 8L));
                    } else if (aname.equals("RuntimeVisibleAnnotations")) {
                        mAnns = readAnnotationNames(cp, r);
                    } else {
                        r.skip(alen);
                    }
                }
                methods.add(new MethodInfo(maccess, mname, mdesc, maxStack, maxLocals, code, handlers, mAnns));
            }

            List<BootstrapEntry> bsm = List.of();
            List<String> cAnns = List.of();
            int attrCount = r.u2();
            for (int i = 0; i < attrCount; i++) {
                String aname = utf8(cp, r.u2());
                int alen = r.u4();
                if (aname.equals("BootstrapMethods")) {
                    int bc = r.u2();
                    List<BootstrapEntry> es = new ArrayList<>(bc);
                    for (int j = 0; j < bc; j++) {
                        int ref = r.u2();
                        int argc = r.u2();
                        int[] argv = new int[argc];
                        for (int k = 0; k < argc; k++) argv[k] = r.u2();
                        es.add(new BootstrapEntry(ref, argv));
                    }
                    bsm = List.copyOf(es);
                } else if (aname.equals("RuntimeVisibleAnnotations")) {
                    cAnns = readAnnotationNames(cp, r);
                } else {
                    r.skip(alen);
                }
            }
            return new ClassFile(access, minor, major, cn, cp, methods, bsm, cAnns);
        } catch (EOFException e) {
            throw bad(expectedName, "truncated class file");
        } catch (IOException e) {
            throw bad(expectedName, "malformed class file: " + e.getMessage());
        }
    }

    /** Skips one member table (fields or methods): access/name/desc plus attributes. */
    private static void skipMembers(Reader r) throws java.io.IOException {
        for (int n = r.u2(); n > 0; n--) {
            r.u2(); r.u2(); r.u2();
            for (int k = r.u2(); k > 0; k--) { r.u2(); r.skip(r.u4()); }
        }
    }

    private static List<String> readAnnotationNames(ConstPool[] cp, Reader r) {
        int count = r.u2();
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String desc = utf8(cp, r.u2());
            out.add(desc.startsWith("L") && desc.endsWith(";")
                ? desc.substring(1, desc.length() - 1) : desc);
            skipElementValuePairs(r);
        }
        return out;
    }

    private static void skipElementValuePairs(Reader r) {
        int n = r.u2();
        for (int i = 0; i < n; i++) {
            r.u2();
            skipElementValue(r);
        }
    }

    private static void skipElementValue(Reader r) {
        int tag = r.u1();
        switch (tag) {
            case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's', 'c' -> r.u2();
            case 'e' -> { r.u2(); r.u2(); }
            case '@' -> { r.u2(); skipElementValuePairs(r); }
            case '[' -> {
                int n = r.u2();
                for (int i = 0; i < n; i++) skipElementValue(r);
            }
            default -> throw new IllegalStateException("bad annotation element tag " + (char) tag);
        }
    }

    public static IllegalArgumentException bad(String name, String msg) {
        return new IllegalArgumentException(name + ": " + msg);
    }

    public String utf8(int idx) { return cp[idx].utf8Value(); }
    public String classNameAt(int idx) { return utf8(cp[idx].a); }
    /** Owner class internal name of a CONSTANT_Fieldref/Methodref/InterfaceMethodref. */
    public String refClassAt(int refIdx) { return classNameAt(cp[refIdx].a); }
    public String nameOfRef(int idx) { return utf8(cp[cp[idx].b].a); }
    public String descOfRef(int idx) { return utf8(cp[cp[idx].b].b); }

    private static String utf8(ConstPool[] cp, int idx) {
        ConstPool c = cp[idx];
        if (c == null || c.tag != TAG_UTF8) throw new IllegalStateException("cp#" + idx + " is not Utf8");
        return c.utf8Value();
    }

    private static String className(ConstPool[] cp, int idx) {
        return utf8(cp, cp[idx].a);
    }

    private static final class Reader {
        private final byte[] d;
        private int p;

        Reader(byte[] d) { this.d = d; }

        int u1() { return d[p++] & 0xFF; }
        int u2() { int v = ((d[p] & 0xFF) << 8) | (d[p + 1] & 0xFF); p += 2; return v; }
        int u4() {
            int v = ((d[p] & 0xFF) << 24) | ((d[p + 1] & 0xFF) << 16) | ((d[p + 2] & 0xFF) << 8) | (d[p + 3] & 0xFF);
            p += 4;
            return v;
        }

        int s4() { return u4(); }

        long u8() {
            long v = ((long) u4() << 32) | (u4() & 0xFFFFFFFFL);
            return v;
        }

        long s8() {
            long v = ((long) s4() << 32) | (u4() & 0xFFFFFFFFL);
            return v;
        }
        byte[] bytes(int n) { byte[] b = new byte[n]; System.arraycopy(d, p, b, 0, n); p += n; return b; }
        void skip(long n) throws IOException {
            if (p + n > d.length) throw new EOFException();
            p += (int) n;
        }
    }
}
