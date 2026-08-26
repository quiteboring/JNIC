package jnic.loader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime support injected into every JNIC-protected jar. Extracts and loads the
 * native runtime for the current platform, registers native method tables during
 * class initialization, and bridges constructs the transpiler lowered to Java:
 * general invokedynamic bootstrap resolution, signature-polymorphic MethodHandle /
 * VarHandle calls, and encrypted string literals (pure-Java ChaCha20).
 */
public final class JNICLoader {

    /** 32-byte ChaCha20 keys used by {@link #d}; generated per build. */
    public static byte[][] keys;

    private static final ConcurrentHashMap<String, MethodHandle> SITE_CACHE = new ConcurrentHashMap<>();
    private static final Object[] EMPTY = new Object[0];

    static {
        String osProp = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        String archProp = System.getProperty("os.arch", "").toLowerCase(java.util.Locale.ROOT);
        String osKey;
        if (osProp.contains("win")) osKey = "windows";
        else if (osProp.contains("linux")) osKey = "linux";
        else if (osProp.contains("mac") || osProp.contains("darwin")) osKey = "macos";
        else throw new ExceptionInInitializerError(
            "jnic: unsupported OS '" + System.getProperty("os.name") + "'");

        String archKey;
        if (archProp.equals("amd64") || archProp.equals("x86_64")) archKey = "x86_64";
        else if (archProp.equals("aarch64") || archProp.equals("arm64")) archKey = "aarch64";
        else throw new ExceptionInInitializerError("jnic: unsupported arch '" + archProp + "'");

        String libFile;
        if (osKey.equals("windows")) libFile = "jnic.dll";
        else if (osKey.equals("linux")) libFile = "libjnic.so";
        else libFile = "libjnic.dylib";
        String resPath = "/META-INF/jnic/" + osKey + "-" + archKey + "/" + libFile;

        try {
            byte[] lib;
            InputStream in = JNICLoader.class.getResourceAsStream(resPath);
            if (in == null)
                throw new IOException("native library resource not found: " + resPath);
            try {
                lib = in.readAllBytes();
            } finally {
                in.close();
            }
            Path tmp = Files.createTempFile("jnic-", libFile.substring(libFile.lastIndexOf('.')));
            Files.write(tmp, lib);
            try {
                Files.setPosixFilePermissions(tmp,
                    Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                           java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                           java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
            } catch (UnsupportedOperationException | IOException e) {
                File f = tmp.toFile();
                f.setReadable(true, false);
                f.setExecutable(true);
            }
            System.load(tmp.toAbsolutePath().toString());
            tmp.toFile().deleteOnExit();
        } catch (Throwable t) {
            throw new ExceptionInInitializerError(t);
        }
    }

    private JNICLoader() {}

    /**
     * Registers the native implementations of one nativized class. Called from the
     * injected clinit prologue; must run before any nativized body executes.
     */
    public static void bind(int groupIndex, Class<?> owner) {
        int r = bind0(groupIndex, owner);
        if (r != 0)
            throw new UnsatisfiedLinkError("jnic: RegisterNatives failed group=" + groupIndex
                + " owner=" + owner.getName() + " status=" + r);
    }

    private static native int bind0(int groupIndex, Class<?> owner);

    /**
     * Executes a retained BootstrapMethods entry of {@code host} and invokes the
     * resulting call-site target on {@code dynArgs}. The transpiler emits calls here
     * for every invokedynamic it does not bake into C (everything beyond string concat).
     */
    public static Object bootstrap(Class<?> host, int bsmIndex, String name, String mtypeDesc,
                                   Object[] dynArgs) throws Throwable {
        ClassLoader cl = host.getClassLoader();
        ClassLoader eff = cl == null ? ClassLoader.getSystemClassLoader() : cl;
        MethodType mt;
        try {
            mt = MethodType.fromMethodDescriptorString(mtypeDesc, eff);
        } catch (RuntimeException e) {
            throw new IllegalStateException("jnic bootstrap: bad method type " + mtypeDesc, e);
        }
        String key = host.getName() + "#" + bsmIndex + "#" + name + "#" + mtypeDesc;
        MethodHandle target = SITE_CACHE.computeIfAbsent(key,
            k -> resolveSite(host, bsmIndex, name, mt));
        Object[] args = dynArgs == null ? EMPTY : dynArgs;
        try {
            if (mt.returnType() == void.class) {
                target.invokeWithArguments(args);
                return null;
            }
            return target.invokeWithArguments(args);
        } catch (RuntimeException | Error t) {
            throw t;
        } catch (Throwable t) {
            throw new IllegalStateException("jnic bootstrap: invocation failed for " + key, t);
        }
    }

    private static MethodHandle resolveSite(Class<?> host, int bsmIndex, String name, MethodType mt) {
        MethodHandles.Lookup lk = lookupFor(host);
        BsmParser.BsmEntry[] bsms;
        String resPath = "/" + host.getName().replace('.', '/') + ".class";
        InputStream in = host.getResourceAsStream(resPath);
        if (in == null)
            throw new IllegalStateException("jnic bootstrap: class bytes unavailable: " + resPath);
        try {
            bsms = BsmParser.parse(in.readAllBytes(), host, lk);
        } catch (IOException e) {
            throw new IllegalStateException("jnic bootstrap: failed reading " + resPath, e);
        } finally {
            try { in.close(); } catch (IOException ignored) { }
        }
        if (bsmIndex < 0 || bsmIndex >= bsms.length)
            throw new IllegalStateException("jnic bootstrap: index " + bsmIndex + " out of range for "
                + host.getName() + " (" + bsms.length + " entries)");
        MethodHandle bsm = bsms[bsmIndex].bsm;
        List<Object> argv = new ArrayList<>();
        Class<?>[] pt = bsm.type().parameterArray();
        int i = 0;
        if (i < pt.length && pt[i] == MethodHandles.Lookup.class) { argv.add(lk); i++; }
        if (i < pt.length && pt[i] == String.class) { argv.add(name); i++; }
        if (i < pt.length && pt[i] == MethodType.class) { argv.add(mt); i++; }
        for (Object sa : bsms[bsmIndex].staticArgs) argv.add(sa);
        Object res;
        try {
            res = bsm.invokeWithArguments(argv);
        } catch (Throwable t) {
            throw new IllegalStateException("jnic bootstrap: bsm invocation failed for "
                + host.getName() + "#bsm" + bsmIndex, t);
        }
        if (res instanceof CallSite) return ((CallSite) res).getTarget();
        if (res instanceof MethodHandle) return (MethodHandle) res;
        throw new IllegalStateException("jnic bootstrap: unexpected result "
            + (res == null ? "null" : res.getClass().getName()));
    }

    static MethodHandles.Lookup lookupFor(Class<?> host) {
        try {
            return MethodHandles.privateLookupIn(host, MethodHandles.lookup());
        } catch (IllegalAccessException e) {
            return MethodHandles.lookup().in(host);
        }
    }

    /** Signature-polymorphic MethodHandle.invoke / invokeExact landing pad. */
    public static Object mhInvoke(Object mh, Object[] args) throws Throwable {
        return ((MethodHandle) mh).invokeWithArguments(args == null ? EMPTY : args);
    }

    /**
     * invokespecial on an INTERFACE method (Iface.super.m()): nonvirtual JNI calls do
     * not support interfaces, so dispatch via findSpecial(owner, ..., recv.getClass()).
     */
    public static Object invokeSpecial(Class<?> owner, Class<?> unused, String name,
                                       String desc, Object recv, Object[] args) throws Throwable {
        ClassLoader cl = owner.getClassLoader() != null ? owner.getClassLoader()
            : ClassLoader.getSystemClassLoader();
        MethodType mt = MethodType.fromMethodDescriptorString(desc, cl);
        MethodHandle mh = lookupFor(owner).findSpecial(owner, name, mt, owner);
        List<Object> argv = new ArrayList<>(args == null ? 1 : args.length + 1);
        argv.add(recv);
        if (args != null) for (Object o : args) argv.add(o);
        return mh.invokeWithArguments(argv);
    }

    /**
     * Signature-polymorphic VarHandle access-mode landing pad.
     * Op codes: get=0 getOpaque=1 getAcquire=2 getVolatile=3 set=4 setOpaque=5
     * setRelease=6 setVolatile=7 compareAndSet=8 compareAndExchange=9..11(+Acq/Rel)
     * getAndSet=12..14 getAndAdd=15..17 getAndBitwiseOr=18..20 And=21..23 Xor=24..26.
     * Operands: coordinates followed by value(s); returns old/witness value or null.
     */
    public static Object varHandleOp(Object vh, int op, Object[] operands) throws Throwable {
        VarHandle v = (VarHandle) vh;
        Object[] o = operands == null ? EMPTY : operands;
        switch (op) {
            case 0:  return v.get(o);
            case 1:  return v.getOpaque(o);
            case 2:  return v.getAcquire(o);
            case 3:  return v.getVolatile(o);
            case 4:  v.set(o); return null;
            case 5:  v.setOpaque(o); return null;
            case 6:  v.setRelease(o); return null;
            case 7:  v.setVolatile(o); return null;
            case 8:  return v.compareAndSet(o);
            case 9:  return v.compareAndExchange(o);
            case 10: return v.compareAndExchangeAcquire(o);
            case 11: return v.compareAndExchangeRelease(o);
            case 12: return v.getAndSet(o);
            case 13: return v.getAndSetAcquire(o);
            case 14: return v.getAndSetRelease(o);
            case 15: return v.getAndAdd(o);
            case 16: return v.getAndAddAcquire(o);
            case 17: return v.getAndAddRelease(o);
            case 18: return v.getAndBitwiseOr(o);
            case 19: return v.getAndBitwiseOrAcquire(o);
            case 20: return v.getAndBitwiseOrRelease(o);
            case 21: return v.getAndBitwiseAnd(o);
            case 22: return v.getAndBitwiseAndAcquire(o);
            case 23: return v.getAndBitwiseAndRelease(o);
            case 24: return v.getAndBitwiseXor(o);
            case 25: return v.getAndBitwiseXorAcquire(o);
            case 26: return v.getAndBitwiseXorRelease(o);
            default:
                throw new UnsupportedOperationException("jnic: unsupported VarHandle op " + op);
        }
    }

    /** Decrypts [12B nonce][ciphertext] with key {@code keys[keyIndex]}, counter start 1. */
    public static String d(int keyIndex, byte[] blob) {
        byte[][] ks = keys;
        if (ks == null || keyIndex < 0 || keyIndex >= ks.length || ks[keyIndex] == null
                || ks[keyIndex].length != 32)
            throw new IllegalStateException("jnic: invalid string key index " + keyIndex);
        if (blob == null || blob.length < 13)
            throw new IllegalStateException("jnic: encrypted blob too short");
        byte[] buf = blob.clone();
        chachaCrypt(ks[keyIndex], buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    // ---- pure-Java ChaCha20 (RFC 8439), keystream XOR only ----

    private static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    static void chachaCrypt(byte[] key32, byte[] nonceAndData) {
        int[] st = initState(key32, nonceAndData);
        int off = 12;
        while (off < nonceAndData.length) {
            byte[] ksBlock = keystream(st);
            int n = Math.min(64, nonceAndData.length - off);
            for (int i = 0; i < n; i++)
                nonceAndData[off + i] ^= ksBlock[i];
            off += n;
            st[12]++;
        }
    }

    private static int[] initState(byte[] key32, byte[] nonce12) {
        int[] s = new int[16];
        System.arraycopy(SIGMA, 0, s, 0, 4);
        for (int i = 0; i < 8; i++) s[4 + i] = leInt(key32, i * 4);
        s[12] = 1;
        for (int i = 0; i < 3; i++) s[13 + i] = leInt(nonce12, i * 4);
        return s;
    }

    private static byte[] keystream(int[] st) {
        int[] x = st.clone();
        for (int r = 0; r < 10; r++) {
            qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
        }
        byte[] out = new byte[64];
        for (int i = 0; i < 16; i++) putLeInt(out, i * 4, x[i] + st[i]);
        return out;
    }

    private static void qr(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Integer.rotateLeft(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Integer.rotateLeft(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Integer.rotateLeft(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Integer.rotateLeft(x[b], 7);
    }

    private static int leInt(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
            | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static void putLeInt(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}

/**
 * Minimal classfile reader resolving a class's BootstrapMethods attribute into live
 * MethodHandles and constant arguments.
 */
final class BsmParser {

    static final class BsmEntry {
        final MethodHandle bsm;
        final Object[] staticArgs;
        BsmEntry(MethodHandle bsm, Object[] staticArgs) {
            this.bsm = bsm;
            this.staticArgs = staticArgs;
        }
    }

    private final byte[] raw;
    private final Object[] cp;
    private final Class<?> host;
    private final MethodHandles.Lookup lk;
    private final ClassLoader loader;

    private BsmParser(byte[] raw, Object[] cp, Class<?> host, MethodHandles.Lookup lk) {
        this.raw = raw;
        this.cp = cp;
        this.host = host;
        this.lk = lk;
        this.loader = host.getClassLoader() != null ? host.getClassLoader()
            : ClassLoader.getSystemClassLoader();
    }

    static BsmEntry[] parse(byte[] cf, Class<?> host, MethodHandles.Lookup lk) throws IOException {
        Buf b = new Buf(cf);
        if (b.u4() != 0xCAFEBABE) throw new IOException("bad magic");
        b.u2(); // minor
        int major = b.u2();
        if (major < 45 || major > 70) throw new IOException("implausible major version " + major);

        BsmParser p = new BsmParser(cf, new Object[b.u2()], host, lk);
        Object[] cp = p.cp;
        for (int i = 1; i < cp.length; i++) {
            switch (b.u1()) {
                case 1: {
                    int len = b.u2();
                    cp[i] = p.utf8At(b.pos, len);
                    b.skip(len);
                    break;
                }
                case 3: cp[i] = b.i4(); break;
                case 4: cp[i] = Float.intBitsToFloat(b.i4()); break;
                case 5: cp[i] = b.i8(); i++; break;
                case 6: cp[i] = Double.longBitsToDouble(b.i8()); i++; break;
                case 7: case 19: case 20: cp[i] = new ClsIdx(b.u2()); break;
                case 8: cp[i] = new StrIdx(b.u2()); break;
                case 9: case 10: case 11: cp[i] = new Ref(b.u2(), b.u2()); break;
                case 12: cp[i] = new NtIdx(b.u2(), b.u2()); break;
                case 15: cp[i] = new MhIdx(b.u1(), b.u2()); break;
                case 16: cp[i] = new MtIdx(b.u2()); break;
                case 17: case 18: b.u2(); b.u2(); break;
                default: throw new IOException("unknown cp tag at #" + i);
            }
        }

        b.u2(); b.u2(); b.u2();                       // access, this, super
        for (int n = b.u2(); n > 0; n--) b.u2();      // interfaces
        p.skipMembers(b);                              // fields
        p.skipMembers(b);                              // methods

        for (int n = b.u2(); n > 0; n--) {
            int nameIdx = b.u2();
            int len = b.u4();
            boolean target = "BootstrapMethods".contentEquals((String) cp[nameIdx]);
            if (!target) {
                b.skip(len);
            } else {
                return p.readEntries(b);
            }
        }
        return new BsmEntry[0];
    }

    private BsmEntry[] readEntries(Buf b) {
        BsmEntry[] out = new BsmEntry[b.u2()];
        for (int j = 0; j < out.length; j++) {
            MethodHandle mh = resolveMh((MhIdx) cp[b.u2()]);
            Object[] argv = new Object[b.u2()];
            for (int k = 0; k < argv.length; k++) argv[k] = resolveConst(b.u2());
            out[j] = new BsmEntry(mh, argv);
        }
        return out;
    }

    private void skipMembers(Buf b) {
        for (int n = b.u2(); n > 0; n--) {
            b.u2(); b.u2(); b.u2();
            for (int k = b.u2(); k > 0; k--) { b.u2(); b.skip(b.u4()); }
        }
    }

    private Object resolveConst(int idx) {
        Object c = cp[idx];
        if (c instanceof String || c instanceof Integer || c instanceof Long
                || c instanceof Float || c instanceof Double) return c;
        if (c instanceof StrIdx) return utf8Of(((StrIdx) c).idx);
        if (c instanceof ClsIdx) return cls(((ClsIdx) c).idx);
        if (c instanceof MtIdx) return mtype(utf8Of(((MtIdx) c).idx));
        if (c instanceof MhIdx) return resolveMh((MhIdx) c);
        throw new IllegalStateException("unsupported bootstrap argument kind: " + c);
    }

    private MethodHandle resolveMh(MhIdx m) {
        Ref ref = (Ref) cp[m.ref];
        NtIdx nt = (NtIdx) cp[ref.nat];
        String name = utf8Of(nt.name);
        String desc = utf8Of(nt.desc);
        Class<?> owner = cls(ref.cls);
        try {
            switch (m.kind) {
                case 1: return lk.findGetter(owner, name, fieldType(desc));
                case 2: return lk.findStaticGetter(owner, name, fieldType(desc));
                case 3: return lk.findSetter(owner, name, fieldType(desc));
                case 4: return lk.findStaticSetter(owner, name, fieldType(desc));
                case 5: case 9: return lk.findVirtual(owner, name, mtype(desc));
                case 6: return lk.findStatic(owner, name, mtype(desc));
                case 7:
                    try {
                        return lk.findSpecial(owner, name, mtype(desc), host);
                    } catch (NoSuchMethodException | IllegalAccessException e) {
                        return lk.findVirtual(owner, name, mtype(desc));
                    }
                case 8: return lk.findConstructor(owner, mtype(desc));
                default:
                    throw new IllegalStateException("bad method handle kind " + m.kind);
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot resolve " + owner.getName()
                + "." + name + desc + " (kind " + m.kind + ")", e);
        }
    }

    private MethodType mtype(String desc) {
        try {
            return MethodType.fromMethodDescriptorString(desc, loader);
        } catch (RuntimeException e) {
            throw new IllegalStateException("bad descriptor " + desc, e);
        }
    }

    private Class<?> fieldType(String fieldDesc) {
        return mtype("(" + fieldDesc + ")V").returnType();
    }

    private Class<?> cls(int idx) {
        String internal = utf8Of(((ClsIdx) cp[idx]).idx).replace('/', '.');
        try {
            return Class.forName(internal, false, loader);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("class not loadable: " + internal, e);
        }
    }

    private String utf8Of(int utf8Idx) { return (String) cp[utf8Idx]; }

    private String utf8At(int off, int len) {
        StringBuilder sb = new StringBuilder(len);
        int i = off;
        int end = off + len;
        while (i < end) {
            int c = raw[i++] & 0xFF;
            if (c < 0x80) sb.append((char) c);
            else if ((c & 0xE0) == 0xC0)
                sb.append((char) (((c & 0x1F) << 6) | (raw[i++] & 0x3F)));
            else if ((c & 0xF0) == 0xE0)
                sb.append((char) (((c & 0x0F) << 12) | ((raw[i++] & 0x3F) << 6) | (raw[i++] & 0x3F)));
            else throw new IllegalStateException("invalid modified UTF-8");
        }
        return sb.toString();
    }

    private static final class ClsIdx { final int idx; ClsIdx(int idx) { this.idx = idx; } }
    private static final class StrIdx { final int idx; StrIdx(int idx) { this.idx = idx; } }
    private static final class MtIdx { final int idx; MtIdx(int idx) { this.idx = idx; } }
    private static final class MhIdx {
        final int kind, ref;
        MhIdx(int kind, int ref) { this.kind = kind; this.ref = ref; }
    }
    private static final class Ref {
        final int cls, nat;
        Ref(int cls, int nat) { this.cls = cls; this.nat = nat; }
    }
    private static final class NtIdx {
        final int name, desc;
        NtIdx(int name, int desc) { this.name = name; this.desc = desc; }
    }

    private static final class Buf {
        final byte[] bytes;
        int pos;

        Buf(byte[] bytes) { this.bytes = bytes; }

        int u1() { return bytes[pos++] & 0xFF; }

        int u2() { int v = ((bytes[pos] & 0xFF) << 8) | (bytes[pos + 1] & 0xFF); pos += 2; return v; }

        int u4() {
            int v = ((bytes[pos] & 0xFF) << 24) | ((bytes[pos + 1] & 0xFF) << 16)
                | ((bytes[pos + 2] & 0xFF) << 8) | (bytes[pos + 3] & 0xFF);
            pos += 4;
            return v;
        }

        int i4() { return u4(); }

        long i8() { return ((long) i4() << 32) | (u4() & 0xFFFFFFFFL); }

        void skip(long n) {
            if (pos + n > bytes.length) throw new IllegalStateException("truncated class file");
            pos += (int) n;
        }
    }
}
