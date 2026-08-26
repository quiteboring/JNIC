package jnic.transform;

import jnic.ObfuscationException;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.Map;
import java.util.Set;

/**
 * Rewrites one class for nativization:
 * selected methods lose their Code and become ACC_NATIVE (annotations kept); any existing
 * clinit is renamed to private synthetic {@code jn$clinit}; a fresh clinit binds this
 * class's native table via JNICLoader.bind(group, X.class) and then calls jn$clinit.
 */
public final class Nativizer {

    private static final String LOADER = "jnic/loader/JNICLoader";

    /**
     * @param allClasses every ".class" entry of the input jar (internal-name key),
     *                   used to resolve common supertypes without touching disk
     */
    public static byte[] rewrite(byte[] original, Set<String> selectedDescs,
                                 int group, boolean stringObf, Map<String, byte[]> allClasses) {
        JarLoader loader = allClasses.isEmpty() ? null : new JarLoader(allClasses);
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
            @Override
            protected String getCommonSuperClass(String type1, String type2) {
                return commonSuper(loader, type1, type2);
            }
        };
        boolean hasClinit = hasClinit(original);
        try {
            cr.accept(new Rewriter(cw, selectedDescs, group, stringObf, hasClinit), 0);
            return cw.toByteArray();
        } catch (Exception e) {
            throw new ObfuscationException("rewrite failed: " + e.getMessage(), e);
        }
    }

    private static boolean hasClinit(byte[] bytes) {
        boolean[] found = new boolean[1];
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
                if (name.equals("<clinit>")) found[0] = true;
                return null;
            }
        }, 0);
        return found[0];
    }

    /** Resolution against jar bytes first, then the obfuscator's own classpath. */
    private static final class JarLoader extends ClassLoader {
        private final Map<String, byte[]> map;

        JarLoader(Map<String, byte[]> map) {
            super(JarLoader.class.getClassLoader());
            this.map = map;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    byte[] b = map.get(name.replace('.', '/') + ".class");
                    if (b != null) c = defineClass(name, b, 0, b.length);
                    else c = super.loadClass(name, false);
                }
                if (resolve) resolveClass(c);
                return c;
            }
        }
    }

    private static String commonSuper(JarLoader loader, String t1, String t2) {
        if (t1.equals(t2)) return t1;
        if (t1.startsWith("[") || t2.startsWith("[")) return "java/lang/Object";
        if (loader == null) return "java/lang/Object";
        try {
            Class<?> a = loader.loadClass(t1.replace('/', '.'), false);
            Class<?> b = loader.loadClass(t2.replace('/', '.'), false);
            if (a.isAssignableFrom(b)) return t1;
            if (b.isAssignableFrom(a)) return t2;
            if (a.isInterface() || b.isInterface()) return "java/lang/Object";
            for (Class<?> s = a.getSuperclass(); s != null; s = s.getSuperclass())
                if (s.isAssignableFrom(b)) return s.getName().replace('.', '/');
            return "java/lang/Object";
        } catch (ClassNotFoundException e) {
            return "java/lang/Object";
        }
    }

    private static final class Rewriter extends ClassVisitor implements Opcodes {
        private final Set<String> selected;
        private final int group;
        private final boolean stringObf;
        private final boolean hasClinit;
        private String className;

        Rewriter(ClassVisitor cv, Set<String> selected, int group, boolean stringObf, boolean hasClinit) {
            super(ASM9, cv);
            this.selected = selected;
            this.group = group;
            this.stringObf = stringObf;
            this.hasClinit = hasClinit;
        }

        @Override
        public void visit(int version, int access, String name, String sig, String superName, String[] ifs) {
            this.className = name;
            super.visit(version, access, name, sig, superName, ifs);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
            if (name.equals("<clinit>")) {
                if (selected.contains(name + " " + desc)) {
                    int na = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC
                        | Opcodes.ACC_NATIVE;
                    MethodVisitor mv = super.visitMethod(na, "jn$clinit", desc, sig, exceptions);
                    return mv == null ? null : new AnnotationsOnly(mv);
                }
                return super.visitMethod(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC
                        | (access & ~(Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED | Opcodes.ACC_FINAL)),
                    "jn$clinit", desc, sig, exceptions);
            }
            if (selected.contains(name + " " + desc)) {
                int na = (access | Opcodes.ACC_NATIVE) & ~Opcodes.ACC_SYNCHRONIZED;
                MethodVisitor mv = super.visitMethod(na, name, desc, sig, exceptions);
                return mv == null ? null : new AnnotationsOnly(mv);
            }
            return super.visitMethod(access, name, desc, sig, exceptions);
        }

        @Override
        public void visitEnd() {
            emitFreshClinit();
            super.visitEnd();
        }

        private void emitFreshClinit() {
            MethodVisitor mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            mv.visitCode();
            pushInt(mv, group);
            mv.visitLdcInsn(Type.getObjectType(className));
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, LOADER, "bind",
                "(ILjava/lang/Class;)V", false);
            if (hasClinit)
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, className, "jn$clinit", "()V", false);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(2, 0);
            mv.visitEnd();
        }

        private void pushInt(MethodVisitor mv, int v) {
            if (v >= 0 && v <= 5) mv.visitInsn(Opcodes.ICONST_0 + v);
            else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) mv.visitIntInsn(Opcodes.BIPUSH, v);
            else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) mv.visitIntInsn(Opcodes.SIPUSH, v);
            else mv.visitLdcInsn(v);
        }
    }

    /** Passes annotations through; swallows all code events so no Code attribute is written. */
    private static final class AnnotationsOnly extends MethodVisitor {
        AnnotationsOnly(MethodVisitor mv) { super(Opcodes.ASM9, mv); }

        @Override public void visitCode() { }
        @Override public void visitInsn(int opcode) { }
        @Override public void visitIntInsn(int opcode, int operand) { }
        @Override public void visitVarInsn(int opcode, int varIndex) { }
        @Override public void visitTypeInsn(int opcode, String type) { }
        @Override public void visitFieldInsn(int opcode, String owner, String name, String descriptor) { }
        @Override public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) { }
        @Override public void visitInvokeDynamicInsn(String name, String descriptor, org.objectweb.asm.Handle bsm, Object... args) { }
        @Override public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) { }
        @Override public void visitLabel(org.objectweb.asm.Label label) { }
        @Override public void visitLdcInsn(Object value) { }
        @Override public void visitIincInsn(int varIndex, int increment) { }
        @Override public void visitTableSwitchInsn(int min, int max, org.objectweb.asm.Label dflt, org.objectweb.asm.Label... labels) { }
        @Override public void visitLookupSwitchInsn(org.objectweb.asm.Label dflt, int[] keys, org.objectweb.asm.Label[] labels) { }
        @Override public void visitMultiANewArrayInsn(String descriptor, int numDimensions) { }
        @Override public void visitTryCatchBlock(org.objectweb.asm.Label start, org.objectweb.asm.Label end, org.objectweb.asm.Label handler, String type) { }
        @Override public void visitMaxs(int maxStack, int maxLocals) { }
        @Override public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) { }
        @Override public void visitLocalVariable(String name, String descriptor, String signature, org.objectweb.asm.Label start, org.objectweb.asm.Label end, int index) { }
        @Override public void visitLineNumber(int line, org.objectweb.asm.Label start) { }
    }

    private Nativizer() {}
}
