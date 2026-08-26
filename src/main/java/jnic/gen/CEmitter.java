package jnic.gen;

import static jnic.gen.Bytecodes.*;

import jnic.classfile.ClassFile;
import jnic.classfile.ClassFile.ConstPool;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

/**
 * Emits one C function per method body: a switch(pc) interpreter over raw slots with a
 * uniform Cell operand stack. Operands are baked at emission time; no bytecode array is
 * embedded in the output. Requires GroupEmitter-provided scope macros CLS_AT(i), STRC(i),
 * IFID(i), SFID(i), VMID(i), SMID(i) and per-class statics SELF, BOOLARR, OBJCLS.
 */
public final class CEmitter {

    /** Interning tables shared by every method of one class group; consumed by GroupEmitter. */
    public static final class Symbols {
        public final java.util.List<String> utf8 = new java.util.ArrayList<>();
        private final java.util.Map<String, Integer> utf8Map = new java.util.HashMap<>();
        public final java.util.List<String> classNames = new java.util.ArrayList<>();
        private final java.util.Map<String, Integer> clsMap = new java.util.HashMap<>();
        public final java.util.List<String> strConsts = new java.util.ArrayList<>();
        /** Per-literal [12B nonce][ciphertext] blobs; populated by Pipeline when stringObf. */
        public final java.util.List<byte[]> strBlobs = new java.util.ArrayList<>();
        public byte[] strKey;
        private final java.util.Map<String, Integer> strMap = new java.util.HashMap<>();
        public final java.util.List<int[]> fieldRefs = new java.util.ArrayList<>();
        private final java.util.Map<String, Integer> fldMap = new java.util.HashMap<>();
        public final java.util.List<int[]> methodRefs = new java.util.ArrayList<>();
        private final java.util.Map<String, Integer> mthMap = new java.util.HashMap<>();

        public int utf8(String s) {
            Integer i = utf8Map.get(s);
            if (i == null) { i = utf8.size(); utf8.add(s); utf8Map.put(s, i); }
            return i;
        }

        public int cls(String internalName) {
            Integer i = clsMap.get(internalName);
            if (i == null) {
                i = classNames.size();
                classNames.add(internalName);
                clsMap.put(internalName, i);
                utf8(internalName);
            }
            return i;
        }

        public int strConst(String literal) {
            Integer i = strMap.get(literal);
            if (i == null) {
                i = strConsts.size();
                strConsts.add(literal);
                strMap.put(literal, i);
                utf8(literal);
            }
            return i;
        }

        /** Row: {classIdx, nameUtf8Idx, descUtf8Idx, isStatic}. */
        public int fld(String owner, String name, String desc, boolean stat) {
            String key = owner + '.' + name + ':' + desc + (stat ? 'S' : 'I');
            Integer i = fldMap.get(key);
            if (i == null) {
                i = fieldRefs.size();
                fieldRefs.add(new int[]{cls(owner), utf8(name), utf8(desc), stat ? 1 : 0});
                fldMap.put(key, i);
            }
            return i;
        }

        /** Row: {classIdx, nameUtf8Idx, descUtf8Idx}. */
        public int mth(String owner, String name, String desc) {
            String key = owner + '.' + name + ':' + desc;
            Integer i = mthMap.get(key);
            if (i == null) {
                i = methodRefs.size();
                methodRefs.add(new int[]{cls(owner), utf8(name), utf8(desc)});
                mthMap.put(key, i);
            }
            return i;
        }
    }

    /** VarHandle access-mode op codes; must mirror JNICLoader.varHandleOp exactly. */
    private static final Map<String, Integer> VH_OPS = Map.ofEntries(
        Map.entry("get", 0), Map.entry("getOpaque", 1), Map.entry("getAcquire", 2), Map.entry("getVolatile", 3),
        Map.entry("set", 4), Map.entry("setOpaque", 5), Map.entry("setRelease", 6), Map.entry("setVolatile", 7),
        Map.entry("compareAndSet", 8),
        Map.entry("compareAndExchange", 9), Map.entry("compareAndExchangeAcquire", 10),
        Map.entry("compareAndExchangeRelease", 11),
        Map.entry("getAndSet", 12), Map.entry("getAndSetAcquire", 13), Map.entry("getAndSetRelease", 14),
        Map.entry("getAndAdd", 15), Map.entry("getAndAddAcquire", 16), Map.entry("getAndAddRelease", 17),
        Map.entry("getAndBitwiseOr", 18), Map.entry("getAndBitwiseOrAcquire", 19),
        Map.entry("getAndBitwiseOrRelease", 20),
        Map.entry("getAndBitwiseAnd", 21), Map.entry("getAndBitwiseAndAcquire", 22),
        Map.entry("getAndBitwiseAndRelease", 23),
        Map.entry("getAndBitwiseXor", 24), Map.entry("getAndBitwiseXorAcquire", 25),
        Map.entry("getAndBitwiseXorRelease", 26));

    private final ClassFile cf;
    private final ClassFile.MethodInfo m;
    private final Symbols sy;
    private final StringBuilder o = new StringBuilder();
    private byte[] code;
    private Analyzer.Result flow;
    private int maxS, maxL;
    private boolean sync;
    private int pc;
    private int fk;
    /** Set once by Pipeline before emission; enables pc relabeling. */
    public static volatile boolean FLOW_OBF;

    private CEmitter(ClassFile cf, ClassFile.MethodInfo m, Symbols sy) {
        this.cf = cf;
        this.m = m;
        this.sy = sy;
    }

    public static String emit(ClassFile cf, ClassFile.MethodInfo m, Symbols sy, String fnName) {
        return new CEmitter(cf, m, sy).run(fnName);
    }

    // ------------------------------------------------------------------ driver

    private String run(String fnName) {
        code = m.code;
        fk = FLOW_OBF ? java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 1 << 30) : 0;
        boolean isStatic = (m.access & Opcodes.ACC_STATIC) != 0;
        sync = (m.access & Opcodes.ACC_SYNCHRONIZED) != 0;
        flow = Analyzer.analyze(code, m.maxLocals, m.maxStack, m.handlers, where(), deltas());
        maxS = Math.max(m.maxStack, 1);
        maxL = Math.max(m.maxLocals, 1);

        List<String> params = Desc.params(m.desc);
        StringBuilder sig = new StringBuilder("static ").append(Desc.jniType(Desc.returnType(m.desc)))
            .append(' ').append(fnName).append("(JNIEnv *env");
        if (isStatic) sig.append(", jclass cz");
        else sig.append(", jobject self");
        for (int i = 0; i < params.size(); i++)
            sig.append(", ").append(Desc.jniType(params.get(i))).append(" p").append(i);
        line(sig.append(") {").toString());

        line("  Cell S[" + (maxS + 2) + "], L[" + maxL + "];");
        line("  const jint FK = " + fk + ";");
        line("  jint sp = 0, pc = " + L(0) + ", ipc = 0;");
        line("  memset(L, 0, sizeof L);");
        line("  memset(S, 0, sizeof S);");

        int slot = 0;
        if (!isStatic) { line("  L[0].r = self;"); slot = 1; }
        for (int i = 0; i < params.size(); i++) {
            String p = params.get(i);
            if (Desc.slotSize(p) == 2) line("  L[" + slot + "].l = p" + i + "; L[" + (slot + 1) + "].l = 0;");
            else if (isRef(p)) line("  L[" + slot + "].r = p" + i + ";");
            else if (p.equals("F")) line("  L[" + slot + "].f = p" + i + ";");
            else if (p.equals("D")) line("  L[" + slot + "].d = p" + i + ";");
            else line("  L[" + slot + "].i = p" + i + ";");
            slot += Desc.slotSize(p);
        }

        String zero = zeroLiteral(m.desc);
        String retZero = m.desc.endsWith(")V") ? "return;" : "return " + zero + ";";
        line("  if ((*env)->PushLocalFrame(env, 64) < 0) " + retZero);
        if (sync)
            line("  if ((*env)->MonitorEnter(env, " + monExpr(isStatic) + ") != JNI_OK) "
                + "{ (*env)->PopLocalFrame(env, NULL); " + retZero + " }");

        line("  for (;;) {");
        emitExceptionBlock(isStatic, retZero);
        line("    ipc = pc;");
        
        line("    switch (pc) {");
        line("      default: (*env)->FatalError(env, \"jnic: bad pc\");");

        int n = code.length;
        while (pc < n) {
            if (!flow.reachable[pc]) { pc += Bytecodes.length(code, pc); continue; }
            o.append("      case ").append(L(pc)).append(": ");
            emitInstruction();
        }

        line("    }");
        line("  }");
        line("}");
        return o.toString();
    }

    private void emitExceptionBlock(boolean isStatic, String retZero) {
        line("    if ((*env)->ExceptionCheck(env)) {");
        line("      jobject exc = (*env)->ExceptionOccurred(env);");
        List<ClassFile.ExceptionEntry> hs = m.handlers;
        if (!hs.isEmpty()) {
            line("      jint mh = -1, mtgt = 0;");
            line("      jclass tcls = (*env)->GetObjectClass(env, exc);");
            int k = 0;
            for (ClassFile.ExceptionEntry h : hs) {
                if (h.catchType == 0) {
                    line("      if (mh < 0 && (ipc ^ FK) >= " + h.startPc + " && (ipc ^ FK) < " + h.endPc
                        + ") { mh = " + k + "; mtgt = " + L(h.handlerPc) + "; }");
                } else {
                    int ci = sy.cls(cf.classNameAt(h.catchType));
                    line("      if (mh < 0 && (ipc ^ FK) >= " + h.startPc + " && (ipc ^ FK) < " + h.endPc + ") {");
                    line("        jclass cc = CLS_AT(" + ci + ");");
                    line("        if (cc != NULL && (*env)->IsAssignableFrom(env, tcls, cc)) "
                        + "{ mh = " + k + "; mtgt = " + L(h.handlerPc) + "; }");
                    line("      }");
                }
                k++;
            }
            line("      (*env)->DeleteLocalRef(env, tcls);");
            line("      if (mh >= 0) {");
            line("        (*env)->ExceptionClear(env);");
            line("        S[0].r = exc;");
            line("        sp = 1;");
            line("        pc = mtgt;");
            line("        continue;");
            line("      }");
        }
        line("      " + syncExit(isStatic));
        line("      (*env)->PopLocalFrame(env, NULL);");
        line("      " + retZero);
        line("    }");
    }

    private String monExpr(boolean isStatic) { return isStatic ? "(jobject)cz" : "self"; }

    private String syncExit(boolean isStatic) {
        return sync ? "(*env)->MonitorExit(env, " + monExpr(isStatic) + ");" : "";
    }

    private void emitReturnPop() {
        if (sync) line(syncExit((m.access & Opcodes.ACC_STATIC) != 0));
        String r = Desc.returnType(m.desc);
        boolean two = r.equals("J") || r.equals("D");
        line("  sp -= " + (two ? 2 : 1) + ";");
        line("  (*env)->PopLocalFrame(env, NULL);");
        line("  return S[sp]." + cellField(r) + ";");
    }

    // ------------------------------------------------------------- instruction dispatch

    private void emitInstruction() {
        int op = code[pc] & 0xFF;
        int next = pc + Bytecodes.length(code, pc);
        boolean wide = op == WIDE;
        int realOp = wide ? (code[pc + 1] & 0xFF) : op;

        if (wide) {
            switch (realOp) {
                case IINC -> emitIinc(true);
                case LLOAD, DLOAD -> emitLoad2(realOp);
                case ILOAD, FLOAD, ALOAD -> emitLoad(realOp);
                case LSTORE, DSTORE -> emitStore2(realOp);
                case ISTORE, FSTORE, ASTORE -> emitStore(realOp);
                default -> throw new IllegalArgumentException(
                    where() + ": unsupported wide opcode " + realOp);
            }
            pc = next;
            return;
        }
        if (realOp == IINC) { emitIinc(false); pc = next; return; }

        switch (op) {
            case NOP -> line("pc = " + L(next) + "; break;");
            case ACONST_NULL -> line("{ Cell _c; _c.r = NULL; SPUSH(_c); } pc = " + L(next) + "; break;");
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2,
                 ICONST_3, ICONST_4, ICONST_5 ->
                line("{ Cell _c; _c.i = " + (op - ICONST_M1 - 1) + "; SPUSH(_c); } pc = " + L(next) + "; break;");
            case LCONST_0, LCONST_1 ->
                line("{ Cell _c; _c.l = " + (op - LCONST_0) + "LL; SPUSH2(_c); } pc = " + L(next) + "; break;");
            case FCONST_0, FCONST_1, FCONST_2 ->
                line("{ Cell _c; _c.f = " + (op - FCONST_0) + ".0f; SPUSH(_c); } pc = " + L(next) + "; break;");
            case DCONST_0, DCONST_1 ->
                line("{ Cell _c; _c.d = " + (op - DCONST_0) + ".0; SPUSH2(_c); } pc = " + L(next) + "; break;");
            case BIPUSH -> line("{ Cell _c; _c.i = " + (byte) code[pc + 1] + "; SPUSH(_c); } pc = " + L(next) + "; break;");
            case SIPUSH -> line("{ Cell _c; _c.i = " + (short) u16(pc + 1) + "; SPUSH(_c); } pc = " + L(next) + "; break;");
            case LDC, LDC_W -> emitLdc(next);
            case LDC2_W -> emitLdc2(next);

            case ILOAD, ILOAD_0, ILOAD_1, ILOAD_2, ILOAD_3,
                 FLOAD, FLOAD_0, FLOAD_1, FLOAD_2, FLOAD_3,
                 ALOAD, ALOAD_0, ALOAD_1, ALOAD_2, ALOAD_3 ->
                emitLoad(realOp);
            case LLOAD, LLOAD_0, LLOAD_1, LLOAD_2, LLOAD_3,
                 DLOAD, DLOAD_0, DLOAD_1, DLOAD_2, DLOAD_3 ->
                emitLoad2(realOp);

            case ISTORE, ISTORE_0, ISTORE_1, ISTORE_2, ISTORE_3,
                 FSTORE, FSTORE_0, FSTORE_1, FSTORE_2, FSTORE_3,
                 ASTORE, ASTORE_0, ASTORE_1, ASTORE_2, ASTORE_3 ->
                emitStore(realOp);
            case LSTORE, LSTORE_0, LSTORE_1, LSTORE_2, LSTORE_3,
                 DSTORE, DSTORE_0, DSTORE_1, DSTORE_2, DSTORE_3 ->
                emitStore2(realOp);

            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD,
                 BALOAD, CALOAD, SALOAD -> emitArrayLoad(op, next);
            case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE,
                 BASTORE, CASTORE, SASTORE -> emitArrayStore(op);

            case POP -> line("sp -= 1; pc = " + L(next) + "; break;");
            case POP2 -> line("sp -= 2; pc = " + L(next) + "; break;");
            case DUP -> line("S[sp] = S[sp-1]; sp += 1; pc = " + L(next) + "; break;");
            case DUP_X1 -> line(
                "{ Cell _a = S[sp-1], _b = S[sp-2]; S[sp-2] = _a; S[sp-1] = _b; S[sp] = _a; sp += 1; } pc = " + L(next) + "; break;");
            case DUP_X2 -> line(
                "{ Cell _a = S[sp-1], _b = S[sp-2], _c2 = S[sp-3]; S[sp-3] = _a; S[sp-2] = _c2; S[sp-1] = _b; S[sp] = _a; sp += 1; } pc = " + L(next) + "; break;");
            case DUP2 -> line("S[sp] = S[sp-2]; S[sp+1] = S[sp-1]; sp += 2; pc = " + L(next) + "; break;");
            case DUP2_X1 -> line(
                "{ Cell _a = S[sp-1], _b = S[sp-2], _c2 = S[sp-3]; S[sp-3] = _b; S[sp-2] = _a; S[sp-1] = _c2; S[sp] = _b; S[sp+1] = _a; sp += 2; } pc = " + L(next) + "; break;");
            case DUP2_X2 -> line(
                "{ Cell _a = S[sp-1], _b = S[sp-2], _c2 = S[sp-3], _d = S[sp-4];"
                    + " S[sp-4] = _b; S[sp-3] = _a; S[sp-2] = _d; S[sp-1] = _c2; S[sp] = _b; S[sp+1] = _a; sp += 2; } pc = " + L(next) + "; break;");
            case SWAP -> line(
                "{ Cell _t = S[sp-1]; S[sp-1] = S[sp-2]; S[sp-2] = _t; } pc = " + L(next) + "; break;");

            case IADD -> { binI("(jint)((juint)_a + (juint)_b)"); fall(next); }
            case LADD -> { binL("(jlong)((julong)_a + (julong)_b)"); fall(next); }
            case FADD -> { binF("_a + _b"); fall(next); }
            case DADD -> { binD("_a + _b"); fall(next); }
            case ISUB -> { binI("(jint)((juint)_a - (juint)_b)"); fall(next); }
            case LSUB -> { binL("(jlong)((julong)_a - (julong)_b)"); fall(next); }
            case FSUB -> { binF("_a - _b"); fall(next); }
            case DSUB -> { binD("_a - _b"); fall(next); }
            case IMUL -> { binI("(jint)((juint)_a * (juint)_b)"); fall(next); }
            case LMUL -> { binL("(jlong)((julong)_a * (julong)_b)"); fall(next); }
            case FMUL -> { binF("_a * _b"); fall(next); }
            case DMUL -> { binD("_a * _b"); fall(next); }
            case IDIV -> { binI("jn_idiv(env, _a, _b)"); fall(next); }
            case LDIV -> { binL("jn_ldiv(env, _a, _b)"); fall(next); }
            case FDIV -> { binF("_a / _b"); fall(next); }
            case DDIV -> { binD("_a / _b"); fall(next); }
            case IREM -> { binI("jn_irem(env, _a, _b)"); fall(next); }
            case LREM -> { binL("jn_lrem(env, _a, _b)"); fall(next); }
            case FREM -> { binF("fmodf(_a, _b)"); fall(next); }
            case DREM -> { binD("fmod(_a, _b)"); fall(next); }

            case INEG -> line("S[sp-1].i = (jint)(0u - (juint)S[sp-1].i); pc = " + L(next) + "; break;");
            case LNEG -> line("S[sp-2].l = (jlong)(0ull - (julong)S[sp-2].l); pc = " + L(next) + "; break;");
            case FNEG -> line("S[sp-1].f = -S[sp-1].f; pc = " + L(next) + "; break;");
            case DNEG -> line("S[sp-2].d = -S[sp-2].d; pc = " + L(next) + "; break;");

            case ISHL -> { binI("(jint)((juint)_a << (_b & 31))"); fall(next); }
            case LSHL -> line(
                "{ jint _b = S[sp-1].i; jlong _a = S[sp-3].l; sp -= 3;"
                    + " S[sp].l = (jlong)((julong)_a << (_b & 63)); S[sp+1].l = 0; sp += 2; } pc = " + L(next) + "; break;");
            case ISHR -> { binI("(_a >> (_b & 31))"); fall(next); }
            case LSHR -> line(
                "{ jint _b = S[sp-1].i; jlong _a = S[sp-3].l; sp -= 3;"
                    + " S[sp].l = (_a >> (_b & 63)); S[sp+1].l = 0; sp += 2; } pc = " + L(next) + "; break;");
            case IUSHR -> { binI("(jint)((juint)_a >> (_b & 31))"); fall(next); }
            case LUSHR -> line(
                "{ jint _b = S[sp-1].i; jlong _a = S[sp-3].l; sp -= 3;"
                    + " S[sp].l = (jlong)((julong)_a >> (_b & 63)); S[sp+1].l = 0; sp += 2; } pc = " + L(next) + "; break;");
            case IAND -> { binI("(_a & _b)"); fall(next); }
            case LAND -> { binL("(_a & _b)"); fall(next); }
            case IOR -> { binI("(_a | _b)"); fall(next); }
            case LOR -> { binL("(_a | _b)"); fall(next); }
            case IXOR -> { binI("(_a ^ _b)"); fall(next); }
            case LXOR -> { binL("(_a ^ _b)"); fall(next); }

            case I2L -> line("S[sp].l = 0; S[sp-1].l = (jlong)S[sp-1].i; sp += 1; pc = " + L(next) + "; break;");
            case I2F -> line("S[sp-1].f = (jfloat)S[sp-1].i; pc = " + L(next) + "; break;");
            case I2D -> line("S[sp].l = 0; S[sp-1].d = (jdouble)S[sp-1].i; sp += 1; pc = " + L(next) + "; break;");
            case L2I -> line("S[sp-2].i = (jint)S[sp-2].l; sp -= 1; pc = " + L(next) + "; break;");
            case L2F -> line("S[sp-2].f = (jfloat)S[sp-2].l; sp -= 1; pc = " + L(next) + "; break;");
            case L2D -> line("S[sp-2].d = (jdouble)S[sp-2].l; sp -= 1; pc = " + L(next) + "; break;");
            case F2I -> line("S[sp-1].i = jn_f2i(S[sp-1].f); pc = " + L(next) + "; break;");
            case F2L -> line("S[sp].l = 0; S[sp-1].l = jn_f2l(S[sp-1].f); sp += 1; pc = " + L(next) + "; break;");
            case F2D -> line("S[sp].l = 0; S[sp-1].d = (jdouble)S[sp-1].f; sp += 1; pc = " + L(next) + "; break;");
            case D2I -> line("S[sp-2].i = jn_d2i(S[sp-2].d); sp -= 1; pc = " + L(next) + "; break;");
            case D2L -> line("S[sp-2].l = jn_d2l(S[sp-2].d); sp -= 1; pc = " + L(next) + "; break;");
            case D2F -> line("S[sp-2].f = (jfloat)S[sp-2].d; sp -= 1; pc = " + L(next) + "; break;");
            case I2B -> line("S[sp-1].i = (jint)(jbyte)S[sp-1].i; pc = " + L(next) + "; break;");
            case I2C -> line("S[sp-1].i = (jint)(jchar)S[sp-1].i; pc = " + L(next) + "; break;");
            case I2S -> line("S[sp-1].i = (jint)(jshort)S[sp-1].i; pc = " + L(next) + "; break;");

            case LCMP -> line(
                "{ jlong _b = S[sp-2].l; jlong _a = S[sp-4].l; sp -= 4;"
                    + " S[sp].i = (_a > _b) - (_a < _b); sp += 1; } pc = " + L(next) + "; break;");
            case FCMPL, FCMPG -> line(
                "{ jfloat _a = S[sp-2].f, _b = S[sp-1].f; sp -= 1;"
                    + " S[sp-1].i = (_a != _a || _b != _b) ? " + (op == FCMPL ? "-1" : "1")
                    + " : (_a > _b) - (_a < _b); } pc = " + L(next) + "; break;");
            case DCMPL, DCMPG -> line(
                "{ jdouble _b = S[sp-2].d; jdouble _a = S[sp-4].d; sp -= 4;"
                    + " S[sp].i = (_a != _a || _b != _b) ? " + (op == DCMPL ? "-1" : "1")
                    + " : (_a > _b) - (_a < _b); sp += 1; } pc = " + L(next) + "; break;");

            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE -> {
                String cmp = switch (op) {
                    case IFEQ -> "=="; case IFNE -> "!="; case IFLT -> "<";
                    case IFGE -> ">="; case IFGT -> ">"; default -> "<=";
                };
int target = pc + s16(pc + 1);
line("{ jint _v = S[--sp].i; if (_v " + cmp + " 0) pc = " + L(target)
+ "; else pc = " + L(next) + "; } break;");
            }
            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE,
                 IF_ICMPGT, IF_ICMPLE -> {
                String cmp = switch (op) {
                    case IF_ICMPEQ -> "=="; case IF_ICMPNE -> "!=";
                    case IF_ICMPLT -> "<"; case IF_ICMPGE -> ">=";
                    case IF_ICMPGT -> ">"; default -> "<=";
                };
                int target = pc + s16(pc + 1);
line("{ jint _b = S[--sp].i, _a = S[--sp].i; if (_a " + cmp + " _b) pc = "
+ L(target) + "; else pc = " + L(next) + "; } break;");
            }
            case IF_ACMPEQ, IF_ACMPNE -> {
                int target = pc + s16(pc + 1);
                line("{ jobject _b = S[--sp].r, _a = S[--sp].r; jboolean _s = (*env)->IsSameObject(env, _a, _b);"
+ " if (_s " + (op == IF_ACMPEQ ? "!= 0" : "== 0") + ") pc = " + L(target)
+ "; else pc = " + L(next) + "; } break;");
            }
            case IFNULL, IFNONNULL -> {
                int target = pc + s16(pc + 1);
                line("{ jobject _o = S[--sp].r; if (_o " + (op == IFNULL ? "== NULL" : "!= NULL")
                    + ") pc = " + L(target) + "; else pc = " + L(next) + "; } break;");
            }

            case GOTO -> line("pc = " + L(pc + s16(pc + 1)) + "; break;");
            case GOTO_W -> line("pc = " + L(pc + s32(pc + 1)) + "; break;");

            case TABLESWITCH -> emitTableSwitch();
            case LOOKUPSWITCH -> emitLookupSwitch();

            case IRETURN, LRETURN, DRETURN, FRETURN -> { line("{"); emitReturnPop(); line("}"); }
            case ARETURN -> {
                line("{");
                if (sync) line(syncExit(false));
                line("  jobject _pr = (*env)->PopLocalFrame(env, S[--sp].r);");
                line("  return _pr;");
                line("}");
            }
            case RETURN -> {
                line("{");
                if (sync) line(syncExit((m.access & Opcodes.ACC_STATIC) != 0));
                line("  (*env)->PopLocalFrame(env, NULL);");
                line("  return;");
                line("}");
            }

            case GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD ->
                emitFieldOp(op, next);

            case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC,
                 INVOKEINTERFACE -> emitInvoke(op, next);
            case INVOKEDYNAMIC -> emitInvokedynamic(next);

            case NEW -> {
                int ci = sy.cls(cf.classNameAt(u16(pc + 1)));
                line("{ jobject _o = (*env)->AllocObject(env, CLS_AT(" + ci + "));"
                    + " if (!_o) break; Cell _c; _c.r = _o; SPUSH(_c); } pc = " + L(next) + "; break;");
            }
            case NEWARRAY -> emitNewArray(next);
            case ANEWARRAY -> {
                int ci = sy.cls(cf.classNameAt(u16(pc + 1)));
                line("{ jint _n = S[--sp].i;"
                    + " if (_n < 0) { jn_throw_named(env, \"java/lang/NegativeArraySizeException\", NULL); break; }"
                    + " jobject _o = (*env)->NewObjectArray(env, _n, CLS_AT(" + ci + "), NULL);"
                    + " if (!_o) break; Cell _c; _c.r = _o; SPUSH(_c); } pc = " + L(next) + "; break;");
            }
            case MULTIANEWARRAY -> emitMultiNewArray(next);
            case ARRAYLENGTH -> line(
                "{ jobject _o = S[--sp].r; if (!_o) { JN_NPE(env); break; }"
                    + " Cell _c; _c.i = (*env)->GetArrayLength(env, _o); SPUSH(_c); } pc = " + L(next) + "; break;");

            case ATHROW -> line(
                "{ jobject _o = S[--sp].r; if (!_o) JN_NPE(env); else (*env)->Throw(env, _o); } break;");

            case CHECKCAST -> {
                int ci = sy.cls(cf.classNameAt(u16(pc + 1)));
                line("{ jobject _o = S[sp-1].r;"
                    + " if (_o != NULL) { jclass _tc = CLS_AT(" + ci + ");"
                    + "   if (_tc != NULL) { jclass _oc = (*env)->GetObjectClass(env, _o);"
                    + "     jboolean _ok = (*env)->IsAssignableFrom(env, _oc, _tc);"
                    + "     (*env)->DeleteLocalRef(env, _oc);"
                    + "     if (!_ok) jn_throw_named(env, \"java/lang/ClassCastException\", NULL); } }"
                    + "} pc = " + L(next) + "; break;");
            }
            case INSTANCEOF -> {
                int ci = sy.cls(cf.classNameAt(u16(pc + 1)));
                line("{ jobject _o = S[--sp].r; jint _r = 0;"
                    + " if (_o != NULL) { jclass _tc = CLS_AT(" + ci + ");"
                    + "   if (_tc == NULL) break;"
                    + "   jclass _oc = (*env)->GetObjectClass(env, _o);"
                    + "   _r = (*env)->IsAssignableFrom(env, _oc, _tc);"
                    + "   (*env)->DeleteLocalRef(env, _oc); }"
                    + " Cell _c; _c.i = _r; SPUSH(_c); } pc = " + L(next) + "; break;");
            }

            case MONITORENTER -> line(
                "{ jobject _o = S[--sp].r; if (!_o) JN_NPE(env); else (*env)->MonitorEnter(env, _o); }"
                    + " pc = " + L(next) + "; break;");
            case MONITOREXIT -> line(
                "{ jobject _o = S[--sp].r; if (!_o) JN_NPE(env); else (*env)->MonitorExit(env, _o); }"
                    + " pc = " + L(next) + "; break;");

            case WIDE -> throw new IllegalStateException("unreachable: wide handled above");
            case JSR, JSR_W, RET ->
                throw new IllegalArgumentException(where() + ": JSR/RET rejected earlier");

            default -> throw new IllegalArgumentException(where() + ": unsupported opcode " + op);
        }
        pc = next;
    }

    private void fall(int next) { o.append("pc = ").append(L(next)).append("; break;\n"); }

    // ------------------------------------------------------------------ helpers

    private void line(String s) { o.append("      ").append(s).append('\n'); }

    private int u16(int off) { return ((code[off] & 0xFF) << 8) | (code[off + 1] & 0xFF); }
    private int s16(int off) { return (short) u16(off); }
    private int s32(int off) {
        return ((code[off] & 0xFF) << 24) | ((code[off + 1] & 0xFF) << 16)
            | ((code[off + 2] & 0xFF) << 8) | (code[off + 3] & 0xFF);
    }

    private static boolean isRef(String type) { return type.charAt(0) == 'L' || type.charAt(0) == '['; }

    private static String cellField(String type) {
        return switch (type.charAt(0)) {
            case 'J' -> "l";
            case 'D' -> "d";
            case 'F' -> "f";
            default -> isRef(type) ? "r" : "i";
        };
    }

    private static String jvalueField(String type) {
        char c = type.charAt(0);
        return c == 'J' ? "j" : c == 'D' ? "d" : c == 'F' ? "f" : isRef(type) ? "l" : "i";
    }

    private String zeroLiteral(String methodDesc) {
        String r = Desc.returnType(methodDesc);
        return switch (cellField(r)) {
            case "l" -> "0";
            case "d" -> "0.0";
            case "f" -> "0.0f";
            case "r" -> "NULL";
            default -> "0";
        };
    }

    private int L(int off) { return fk == 0 ? off : (off ^ fk); }

    private String where() { return cf.className + "." + m.name + m.desc; }

    private void binI(String expr) {
        line("{ jint _a = S[sp-2].i, _b = S[sp-1].i; sp -= 1; S[sp-1].i = " + expr + "; }");
    }

    private void binL(String expr) {
        line("{ jlong _b = S[sp-2].l; jlong _a = S[sp-4].l; sp -= 4;"
            + " S[sp].l = " + expr + "; S[sp+1].l = 0; sp += 2; }");
    }

    private void binF(String expr) {
        line("{ jfloat _a = S[sp-2].f, _b = S[sp-1].f; sp -= 1; S[sp-1].f = " + expr + "; }");
    }

    private void binD(String expr) {
        line("{ jdouble _b = S[sp-2].d; jdouble _a = S[sp-4].d; sp -= 4;"
            + " S[sp].d = " + expr + "; S[sp+1].l = 0; sp += 2; }");
    }

    private Analyzer.RefDeltas deltas() {
        return new Analyzer.RefDeltas() {
            @Override public int invokeDelta(int op, int cpIndex) {
                String desc = cf.descOfRef(cpIndex);
                boolean stat = op == INVOKESTATIC || op == INVOKEDYNAMIC;
                int consumed = Desc.paramSlots(desc) + (stat ? 0 : 1);
                String ret = Desc.returnType(desc);
                int produced = ret.equals("V") ? 0 : Desc.slotSize(ret);
                return produced - consumed;
            }

            @Override public int fieldDelta(int op, int cpIndex) {
                int fs = Desc.slotSize(cf.descOfRef(cpIndex));
                return switch (op) {
                    case GETSTATIC -> fs;
                    case PUTSTATIC -> -fs;
                    case GETFIELD -> fs - 1;
                    default -> -(fs + 1); // PUTFIELD
                };
            }
        };
    }

    // ------------------------------------------------------------ loads / stores

    private void emitLoad(int realOp) {
        int idx = Bytecodes.localVarIndex(code, pc);
        boolean f = realOp == FLOAD || (realOp >= FLOAD_0 && realOp <= FLOAD_3);
        String fld = f ? "f" : isLoadRef(realOp) ? "r" : "i";
        line("{ Cell _c; _c." + fld + " = L[" + idx + "]." + fld + "; SPUSH(_c); } pc = "
            + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    private static boolean isLoadRef(int realOp) {
        return realOp == ALOAD || (realOp >= ALOAD_0 && realOp <= ALOAD_3);
    }

    private void emitLoad2(int realOp) {
        int idx = Bytecodes.localVarIndex(code, pc);
        boolean d = realOp == DLOAD || (realOp >= DLOAD_0 && realOp <= DLOAD_3);
        String fld = d ? "d" : "l";
        line("{ Cell _c; _c." + fld + " = L[" + idx + "]." + fld + "; SPUSH2(_c); } pc = "
            + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    private void emitStore(int realOp) {
        int idx = Bytecodes.localVarIndex(code, pc);
        boolean f = realOp == FSTORE || (realOp >= FSTORE_0 && realOp <= FSTORE_3);
        boolean r = realOp == ASTORE || (realOp >= ASTORE_0 && realOp <= ASTORE_3);
        String fld = f ? "f" : r ? "r" : "i";
        line("L[" + idx + "]." + fld + " = S[--sp]." + fld + "; pc = "
            + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    private void emitStore2(int realOp) {
        int idx = Bytecodes.localVarIndex(code, pc);
        boolean d = realOp == DSTORE || (realOp >= DSTORE_0 && realOp <= DSTORE_3);
        String fld = d ? "d" : "l";
        line("sp -= 2; L[" + idx + "]." + fld + " = S[sp]." + fld + "; pc = "
            + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    private void emitIinc(boolean wide) {
        int idx = wide ? u16(pc + 2) : code[pc + 1] & 0xFF;
        int cst = wide ? s16(pc + 4) : (byte) code[pc + 2];
        line("L[" + idx + "].i = (jint)((juint)L[" + idx + "].i + (juint)" + cst + "); pc = "
            + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    // ------------------------------------------------------------- arrays

    private static final String[] NEWARRAY_TYPES = {"Boolean", "Char", "Float", "Double",
        "Byte", "Short", "Int", "Long"};

    private void emitNewArray(int next) {
        String t = NEWARRAY_TYPES[(code[pc + 1] & 0xFF) - 4];
        line("{ jint _n = S[--sp].i;"
            + " if (_n < 0) { jn_throw_named(env, \"java/lang/NegativeArraySizeException\", NULL); break; }"
            + " jobject _o = (*env)->New" + t + "Array(env, _n);"
            + " if (!_o) break; Cell _c; _c.r = _o; SPUSH(_c); } pc = " + L(next) + "; break;");
    }

    private void emitMultiNewArray(int next) {
        String cls = cf.classNameAt(u16(pc + 1));
        int dims = code[pc + 3] & 0xFF;
        line("{ enum { _D = " + dims + " }; jint _ln[_D];"
            + " for (int _q = _D - 1; _q >= 0; --_q) _ln[_q] = S[--sp].i;"
            + " jobject _ar = jn_multi_build(env, \"" + cstr(cls) + "\", _D, _ln);"
            + " if (!_ar) break; Cell _c; _c.r = _ar; SPUSH(_c); } pc = " + L(next) + "; break;");
    }

    private void emitArrayLoad(int op, int next) {
        String arrFn = switch (op) {
            case IALOAD -> "Int"; case LALOAD -> "Long";
            case FALOAD -> "Float"; case DALOAD -> "Double";
            case CALOAD -> "Char"; case SALOAD -> "Short";
            default -> "Byte";
        };
        if (op == AALOAD) {
            line("{ jobject _ar = S[sp-2].r; jint _ix = S[sp-1].i; sp -= 2;"
                + " if (!_ar) { JN_NPE(env); break; }"
                + " jint _len = (*env)->GetArrayLength(env, _ar);"
                + " if (_ix < 0 || _ix >= _len) { jn_aioobe(env, _ix); break; }"
                + " Cell _c; _c.r = (*env)->GetObjectArrayElement(env, _ar, _ix); SPUSH(_c); }"
                + " pc = " + L(next) + "; break;");
            return;
        }
        String elemT = switch (op) {
            case IALOAD -> "jint"; case LALOAD -> "jlong";
            case FALOAD -> "jfloat"; case DALOAD -> "jdouble";
            case CALOAD -> "jchar"; case SALOAD -> "jshort";
            default -> "jbyte";
        };
        String store = switch (op) {
            case LALOAD -> "_c.l = _v; SPUSH2(_c)";
            case FALOAD -> "_c.f = _v; SPUSH(_c)";
            case DALOAD -> "_c.d = _v; SPUSH2(_c)";
            default -> "_c.i = _v; SPUSH(_c)";
        };
        String boolMask = op == BALOAD
            ? " if (jn_is_bool_array(env, _ar, jn_cls(env, &BOOLARR, \"[Z\"))) _v &= 1;\n"
            + "                " : " ";
        line("{ jobject _ar = S[sp-2].r; jint _ix = S[sp-1].i; sp -= 2;"
            + " if (!_ar) { JN_NPE(env); break; }"
            + " jint _len = (*env)->GetArrayLength(env, _ar);"
            + " if (_ix < 0 || _ix >= _len) { jn_aioobe(env, _ix); break; }"
            + " " + elemT + " _v;"
            + " (*env)->Get" + arrFn + "ArrayRegion(env, _ar, _ix, 1, &_v);" + boolMask
            + " Cell _c; " + store + "; } pc = " + L(next) + "; break;");
    }

    private void emitArrayStore(int op) {
        if (op == AASTORE) {
            line("{ Cell _v = S[sp-1]; jint _ix = S[sp-2].i; jobject _ar = S[sp-3].r; sp -= 3;"
                + " if (!_ar) { JN_NPE(env); break; }"
                + " jint _len = (*env)->GetArrayLength(env, _ar);"
                + " if (_ix < 0 || _ix >= _len) { jn_aioobe(env, _ix); break; }"
                + " (*env)->SetObjectArrayElement(env, _ar, _ix, _v.r); }"
                + " pc = " + L(pc + Bytecodes.length(code, pc)) + "; break;");
            return;
        }
        String arrFn = switch (op) {
            case IASTORE -> "Int"; case LASTORE -> "Long";
            case FASTORE -> "Float"; case DASTORE -> "Double";
            case CASTORE -> "Char"; case SASTORE -> "Short";
            default -> "Byte";
        };
        String elemT = switch (op) {
            case IASTORE -> "jint"; case LASTORE -> "jlong";
            case FASTORE -> "jfloat"; case DASTORE -> "jdouble";
            case CASTORE -> "jchar"; case SASTORE -> "jshort";
            default -> "jbyte";
        };
        String valRead = op == LASTORE || op == DASTORE
            ? "Cell _val = S[sp-1];"
            : op == FASTORE
            ? "jfloat _val = S[sp-1].f;"
            : "jint _ival = S[sp-1].i;";
        String valExpr = switch (op) {
            case Opcodes.LASTORE -> "_val.l"; case Opcodes.DASTORE -> "_val.d";
            case Opcodes.FASTORE -> "_val";
            case Opcodes.IASTORE -> "_ival";
            case Opcodes.CASTORE -> "(jchar)_ival"; case Opcodes.SASTORE -> "(jshort)_ival";
            default -> "(jbyte)_ival";
        };
        String boolMask = op == BASTORE
            ? " if (jn_is_bool_array(env, _ar, jn_cls(env, &BOOLARR, \"[Z\"))) _bv &= 1;\n"
            + "                " : " ";
        line("{ " + valRead + " jint _ix = S[sp-" + (op == LASTORE || op == DASTORE ? 3 : 2)
            + "].i; jobject _ar = S[sp-" + (op == LASTORE || op == DASTORE ? 4 : 3)
            + "].r; sp -= " + (op == LASTORE || op == DASTORE ? 4 : 3) + ";"
            + " if (!_ar) { JN_NPE(env); break; }"
            + " jint _len = (*env)->GetArrayLength(env, _ar);"
            + " if (_ix < 0 || _ix >= _len) { jn_aioobe(env, _ix); break; }"
            + " " + elemT + " _bv = (" + elemT + ")(" + valExpr + ");" + boolMask
            + " (*env)->Set" + arrFn + "ArrayRegion(env, _ar, _ix, 1, &_bv); }"
            + " pc = " + L(pc + Bytecodes.length(code, pc)) + "; break;");
    }

    // ------------------------------------------------------------- switches

    private void emitTableSwitch() {
        int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
        int def = pc + s32(base);
        int lo = s32(base + 4), hi = s32(base + 8);
        line("{ jint _v = S[--sp].i;");
        line("  if (_v < " + lo + " || _v > " + hi + ") { pc = " + L(def) + "; break; }");
        line("  switch (_v) {");
        for (int v = lo; v <= hi; v++) {
            int t = pc + s32(base + 12 + (v - lo) * 4);
            line("    case " + v + ": pc = " + L(t) + "; break;");
        }
        line("    default: pc = " + L(def) + "; break;");
        line("  } }");
        line("  break;");
    }

    private void emitLookupSwitch() {
        int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
        int def = pc + s32(base);
        int pairs = s32(base + 4);
        line("{ jint _v = S[--sp].i; switch (_v) {");
        for (int i = 0; i < pairs; i++) {
            int match = s32(base + 8 + i * 8);
            int t = pc + s32(base + 8 + i * 8 + 4);
            line("    case " + match + ": pc = " + L(t) + "; break;");
        }
        line("    default: pc = " + L(def) + "; break;");
        line("  } }");
        line("  break;");
    }

    // ------------------------------------------------------------- ldc

    private void emitLdc(int next) {
        int op = code[pc] & 0xFF;
        int cpIdx = op == LDC ? (code[pc + 1] & 0xFF) : u16(pc + 1);
        ConstPool c = cf.cp[cpIdx];
        switch (c.tag) {
            case ClassFile.TAG_INT -> line("{ Cell _c; _c.i = " + (Integer) c.boxed + "; SPUSH(_c); } pc = "
                + L(next) + "; break;");
            case ClassFile.TAG_FLOAT -> line("{ Cell _c; _c.f = " + floatLiteral((Float) c.boxed)
                + "; SPUSH(_c); } pc = " + L(next) + "; break;");
            case ClassFile.TAG_STRING -> {
                int si = sy.strConst(cf.utf8(c.a));
                line("{ Cell _c; _c.r = STRC(" + si + "); SPUSH(_c); } pc = " + L(next) + "; break;");
            }
            case ClassFile.TAG_CLASS -> {
                int ci = sy.cls(cf.utf8(c.a));
                line("{ Cell _c; _c.r = CLS_AT(" + ci + "); SPUSH(_c); } pc = " + L(next) + "; break;");
            }
            default -> throw new IllegalArgumentException(where()
                + ": unsupported ldc constant tag " + c.tag);
        }
    }

    private void emitLdc2(int next) {
        ConstPool c = cf.cp[u16(pc + 1)];
        if (c.tag == ClassFile.TAG_LONG)
            line("{ Cell _c; _c.l = " + (Long) c.boxed + "LL; SPUSH2(_c); } pc = " + L(next) + "; break;");
        else if (c.tag == ClassFile.TAG_DOUBLE)
            line("{ Cell _c; _c.d = " + doubleLiteral((Double) c.boxed) + "; SPUSH2(_c); } pc = "
                + L(next) + "; break;");
        else throw new IllegalArgumentException(where() + ": ldc2_w with tag " + c.tag);
    }

    private static String floatLiteral(float f) {
        if (Float.isNaN(f)) return "(0.0f / 0.0f)";
        if (f == Float.POSITIVE_INFINITY) return "(1.0f / 0.0f)";
        if (f == Float.NEGATIVE_INFINITY) return "(-1.0f / 0.0f)";
        return Float.toHexString(f) + "f";
    }

    private static String doubleLiteral(double d) {
        if (Double.isNaN(d)) return "(0.0 / 0.0)";
        if (d == Double.POSITIVE_INFINITY) return "(1.0 / 0.0)";
        if (d == Double.NEGATIVE_INFINITY) return "(-1.0 / 0.0)";
        return Double.toHexString(d);
    }

    /** Encodes as modified UTF-8 then escapes every non-printable byte octally. */
    /** Encodes a string as modified UTF-8 (the classfile/JNI NewStringUTF form). */
    public static byte[] modifiedUtf8(String s) {
        java.io.ByteArrayOutputStream enc = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= 1 && ch <= 0x7F) enc.write(ch);
            else if (ch <= 0x7FF) {
                enc.write(0xC0 | (ch >> 6));
                enc.write(0x80 | (ch & 0x3F));
            } else {
                enc.write(0xE0 | (ch >> 12));
                enc.write(0x80 | ((ch >> 6) & 0x3F));
                enc.write(0x80 | (ch & 0x3F));
            }
        }
        return enc.toByteArray();
    }

    /** Escapes bytes as a C string literal body (octal for non-printables). */
    static String cstr(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int v = b & 0xFF;
            if (v >= 0x20 && v <= 0x7E && v != '"' && v != '\\') sb.append((char) v);
            else if (v == '"') sb.append("\\\"");
            else if (v == '\\') sb.append("\\\\");
            else sb.append('\\').append(Character.forDigit((v >> 6) & 7, 8))
                    .append(Character.forDigit((v >> 3) & 7, 8))
                    .append(Character.forDigit(v & 7, 8));
        }
        return sb.toString();
    }

    static String cstr(String s) { return cstr(modifiedUtf8(s)); }

    // ------------------------------------------------------------- fields

    private void emitFieldOp(int op, int next) {
        int cpIdx = u16(pc + 1);
        String owner = cf.refClassAt(cpIdx);
        String name = cf.nameOfRef(cpIdx);
        String desc = cf.descOfRef(cpIdx);
        boolean stat = op == GETSTATIC || op == PUTSTATIC;
        int fi = sy.fld(owner, name, desc, stat);
        String fld = cellField(desc);

        switch (op) {
            case GETSTATIC -> {
                boolean two = desc.equals("J") || desc.equals("D");
                line("{ jfieldID _f = SFID(" + fi + "); if (!_f) break;"
                    + " Cell _c; _c." + fld + " = (*env)->GetStatic" + jniAccessor(desc)
                    + "Field(env, CLS_AT(FREF[" + fi + "][0]), _f);"
                    + (two ? " S[sp] = _c; S[sp+1].l = 0; sp += 2;" : " SPUSH(_c);") + " }"
                    + " pc = " + L(next) + "; break;");
            }
            case PUTSTATIC -> {
                boolean two = desc.equals("J") || desc.equals("D");
                line("{ Cell _v = S[sp-1]; sp -= " + (two ? 2 : 1) + ";"
                    + " jfieldID _f = SFID(" + fi + "); if (!_f) break;"
                    + " (*env)->SetStatic" + jniAccessor(desc) + "Field(env, CLS_AT(FREF["
                    + fi + "][0]), _f, _v." + fld + "); }"
                    + " pc = " + L(next) + "; break;");
            }
            case GETFIELD -> line(
                "{ jobject _o = S[--sp].r; if (!_o) { JN_NPE(env); break; }"
                    + " jfieldID _f = IFID(" + fi + "); if (!_f) break;"
                    + " Cell _c; _c." + fld + " = (*env)->Get" + jniAccessor(desc) + "Field(env, _o, _f);"
                    + (fld.equals("l") || fld.equals("d")
                        ? " S[sp] = _c; S[sp+1].l = 0; sp += 2; }" : " SPUSH(_c); }")
                    + " pc = " + L(next) + "; break;");
            default -> { // PUTFIELD
                boolean two = desc.equals("J") || desc.equals("D");
                line("{ Cell _v = S[sp-1]; jobject _o = S[sp-" + (two ? 3 : 2) + "].r; sp -= "
                    + (two ? 3 : 2) + ";"
                    + " if (!_o) { JN_NPE(env); break; }"
                    + " jfieldID _f = IFID(" + fi + "); if (!_f) break;"
                    + " (*env)->Set" + jniAccessor(desc) + "Field(env, _o, _f, _v." + fld + "); }"
                    + " pc = " + L(next) + "; break;");
            }
        }
    }

    private static String jniAccessor(String desc) {
        return switch (desc.charAt(0)) {
            case 'B' -> "Byte"; case 'C' -> "Char"; case 'S' -> "Short"; case 'Z' -> "Boolean";
            case 'I' -> "Int";
            case 'J' -> "Long"; case 'F' -> "Float"; case 'D' -> "Double";
            default -> "Object";
        };
    }

    // ------------------------------------------------------------- invokes

    private void emitInvoke(int op, int next) {
        int cpIdx = u16(pc + 1);
        String owner = cf.refClassAt(cpIdx);
        String name = cf.nameOfRef(cpIdx);
        String desc = cf.descOfRef(cpIdx);

        if (op == INVOKEVIRTUAL) {
            Integer vhOp = null;
            if (owner.equals("java/lang/invoke/MethodHandle")
                && (name.equals("invoke") || name.equals("invokeExact"))) {
                emitPolyCall(desc, -1, next);
                return;
            }
            if (owner.equals("java/lang/invoke/VarHandle")) {
                Integer code0 = VH_OPS.get(name);
                if (code0 == null)
                    throw new IllegalArgumentException(where() + ": unknown VarHandle mode " + name);
                emitPolyCall(desc, code0, next);
                return;
            }
        }

        List<String> ps = Desc.params(desc);
        String ret = Desc.returnType(desc);
        boolean stat = op == INVOKESTATIC;
        boolean special = op == INVOKESPECIAL;
        boolean ifaceSpecial = special && cf.cp[cpIdx].tag == ClassFile.TAG_IFACE_METHOD;
        int argSlots = Desc.paramSlots(desc);
        int base = flow.inDepth[pc] - argSlots - (stat ? 0 : 1);
        int mi = sy.mth(owner, name, desc);

        if (ifaceSpecial) {
            // HotSpot cannot do nonvirtual dispatch on interfaces; use the loader bridge.
            String btags = tagsFromTypes(ps);
            line("{");
            line("  jobject _rv = S[" + base + "].r;");
            line("  jobjectArray _da = (*env)->NewObjectArray(env, " + ps.size() + ", jn_objcls(env), NULL);");
            line("  if (!_da) break;");
            int boff = 0;
            for (int i = 0; i < ps.size(); i++) {
                line("  { jobject _bx = jn_box(env, '" + btags.charAt(i) + "', S["
                    + (base + 1 + boff) + "]);"
                    + " (*env)->SetObjectArrayElement(env, _da, " + i + ", _bx);"
                    + " }");
                boff += Desc.slotSize(ps.get(i));
            }
            line("  if (_rv == NULL) { JN_NPE(env); break; }");
            line("  static jobject NM" + mi + " = NULL, DS" + mi + " = NULL;");
            line("  jobject _out = jn_call_special(env, CLS_AT(MREF[" + mi + "][0]), SELF,"
                + " jn_string_const(env, &NM" + mi + ", UT[MREF[" + mi + "][1]]),"
                + " jn_string_const(env, &DS" + mi + ", UT[MREF[" + mi + "][2]]), _rv, _da);");
            line("  sp = " + base + ";");
            if (!ret.equals("V")) {
                boolean two = ret.equals("J") || ret.equals("D");
                line("  if ((*env)->ExceptionCheck(env)) break;");
                line("  { Cell _c; jn_unbox(env, _out, '" + retTag(ret) + "', &_c); S[sp] = _c;"
                    + (two ? " S[sp+1].l = 0;" : "")
                    + " sp += " + (two ? 2 : 1) + "; }");
            } else {
                line("  if ((*env)->ExceptionCheck(env)) break;");
            }
            line("} pc = " + L(next) + "; break;");
            return;
        }

        line("{");
        if (!stat) line("  jobject _rv = S[" + base + "].r;");
        line("  jvalue _a[" + Math.max(ps.size(), 1) + "];");
        int off = 0;
        for (int i = 0; i < ps.size(); i++) {
            String p = ps.get(i);
            line("  _a[" + i + "]." + jvalueField(p) + " = S[" + (base + (stat ? 0 : 1) + off) + "]."
                + cellField(p) + ";");
            off += Desc.slotSize(p);
        }
        if (!stat) line("  if (_rv == NULL) { JN_NPE(env); break; }");
        line("  jmethodID _m = " + (stat ? "SMID" : "VMID") + "(" + mi + ");");
        line("  if (!_m) break;");
        line("  sp = " + base + ";");

        String call = switch (ret.charAt(0)) {
            case 'V' -> "(*env)->CallVoidMethodA";
            case 'B', 'Z', 'S', 'I', 'C' -> "(*env)->CallIntMethodA";
            case 'J' -> "(*env)->CallLongMethodA";
            case 'F' -> "(*env)->CallFloatMethodA";
            case 'D' -> "(*env)->CallDoubleMethodA";
            default -> "(*env)->CallObjectMethodA";
        };
        if (stat) call = call.replace("Call", "CallStatic");
        else if (special) call = call.replace("Call", "CallNonvirtual");

        String argsTail = stat
            ? "(env, CLS_AT(MREF[" + mi + "][0]), _m, _a)"
            : special
            ? "(env, _rv, CLS_AT(MREF[" + mi + "][0]), _m, _a)"
            : "(env, _rv, _m, _a)";

        if (ret.equals("V")) {
            line("  " + call + argsTail + ";");
        } else {
            String ctype = Desc.jniType(ret);
            line("  " + ctype + " _rr = " + call + argsTail + ";");
            if (ret.equals("J") || ret.equals("D"))
                line("  { Cell _c; _c." + cellField(ret) + " = _rr; SPUSH2(_c); }");
            else
                line("  { Cell _c; _c." + cellField(ret) + " = _rr; SPUSH(_c); }");
        }
        line("} pc = " + L(next) + "; break;");
    }

    /**
     * Signature-polymorphic calls. kind -1 = MethodHandle.invoke/invokeExact; otherwise
     * a VarHandle op code from VH_OPS.
     */
    private void emitPolyCall(String desc, int kind, int next) {
        List<String> ps = Desc.params(desc);
        String ret = Desc.returnType(desc);
        int base = flow.inDepth[pc] - ps.size() - 1;
        String tags = tagsFromTypes(ps);
        String retTag = retTag(ret);

        line("{");
        line("  jobject _h = S[" + base + "].r;");
        line("  if (!_h) { JN_NPE(env); break; }");
        line("  jobjectArray _da = (*env)->NewObjectArray(env, " + ps.size() + ", jn_objcls(env), NULL);");
        line("  if (!_da) break;");
        int boff = 0;
        for (int i = 0; i < ps.size(); i++) {
            line("  { Cell _c; _c." + cellField(ps.get(i)) + " = S[" + (base + 1 + boff) + "]."
                + cellField(ps.get(i)) + "; jobject _bx = jn_box(env, '" + tags.charAt(i) + "', _c);"
                + " (*env)->SetObjectArrayElement(env, _da, " + i + ", _bx);"
                + " }");
            boff += Desc.slotSize(ps.get(i));
        }
        line("  jobject _out = " + (kind < 0 ? "jn_mh_invoke(env, _h, _da)"
            : "jn_vh_op(env, _h, " + kind + ", _da)") + ";");
        line("  if ((*env)->ExceptionCheck(env)) break;");
        line("  sp = " + base + ";");
        if (!ret.equals("V")) {
            line("  { Cell _c; jn_unbox(env, _out, '" + retTag + "', &_c); S[sp] = _c;"
                + (ret.equals("J") || ret.equals("D") ? " S[sp+1].l = 0; " : "")
                + " sp += " + (ret.equals("J") || ret.equals("D") ? 2 : 1) + "; }");
        }
        line("} pc = " + L(next) + "; break;");
    }

    private static String tagsFromTypes(List<String> types) {
        StringBuilder sb = new StringBuilder();
        for (String t : types) sb.append(retTag(t));
        return sb.toString();
    }

    private static String retTag(String t) {
        return switch (t.charAt(0)) {
            case 'Z' -> "Z"; case 'C' -> "C"; case 'B' -> "B"; case 'S' -> "S";
            case 'I' -> "I"; case 'J' -> "J"; case 'F' -> "F"; case 'D' -> "D";
            default -> "L";
        };
    }

    // ------------------------------------------------------------- invokedynamic

    private void emitInvokedynamic(int next) {
        int cpIdx = u16(pc + 1);
        ConstPool idy = cf.cp[cpIdx];
        int bsmAttr = idy.a;
        ClassFile.BootstrapEntry bs = cf.bootstrapMethods.get(bsmAttr);
        ConstPool mh = cf.cp[bs.bsmRef];
        ConstPool mr = cf.cp[mh.b];
        String bsmOwner = cf.classNameAt(mr.a);
        String bsmName = cf.utf8(cf.cp[mr.b].a);

        boolean concat = bsmOwner.equals("java/lang/invoke/StringConcatFactory")
            && (bsmName.equals("makeConcatWithConstants") || bsmName.equals("makeConcat"));
        if (concat) { emitConcat(bs, idy, next); return; }
        emitGenericBsm(bs, idy, next);
    }

    private void emitConcat(ClassFile.BootstrapEntry bs, ConstPool idy, int next) {
        String indyDesc = cf.descOfRef(u16(pc + 1));
        List<String> dynTypes = Desc.params(indyDesc);
        String dynTags = tagsFromTypes(dynTypes);

        String recipe;
        List<Integer> constIdxs;
        if (bs.args.length > 0 && cf.cp[bs.args[0]].tag == ClassFile.TAG_STRING) {
            recipe = cf.utf8(cf.cp[bs.args[0]].a);
            constIdxs = new java.util.ArrayList<>();
            for (int i = 1; i < bs.args.length; i++) constIdxs.add(bs.args[i]);
        } else {
            StringBuilder rb = new StringBuilder();
            for (int i = 0; i < dynTypes.size(); i++) rb.append('\u0001');
            recipe = rb.toString();
            constIdxs = List.of();
        }

        int base = flow.inDepth[pc] - Desc.paramSlots(indyDesc);
        int k = (int) SITE_SEQ.getAndIncrement();

        line("{");
        line("  static const char RC" + k + "[] = \"" + cstr(recipe) + "\";");
        line("  static const char DT" + k + "[] = \"" + cstr(dynTags) + "\";");
        if (!constIdxs.isEmpty()) {
            StringBuilder st = new StringBuilder();
            for (int ci : constIdxs) st.append(concatConstTag(ci));
            line("  static const char RT" + k + "[] = \"" + cstr(st.toString()) + "\";");
            line("  Cell SV" + k + "[" + constIdxs.size() + "];");
            for (int j = 0; j < constIdxs.size(); j++)
                line("  " + concatConstInit(constIdxs.get(j), "SV" + k + "[" + j + "]") + ";");
        }
        line("  Cell DY" + k + "[" + dynTypes.size() + "];");
        int doff = 0;
        for (int i = 0; i < dynTypes.size(); i++) {
            line("  DY" + k + "[" + i + "] = S[" + (base + doff) + "];");
            doff += Desc.slotSize(dynTypes.get(i));
        }
        line("  sp = " + base + ";");
        line("  jstring _rs = jn_concat(env, RC" + k + ", "
            + (constIdxs.isEmpty() ? "NULL, NULL" : "RT" + k + ", SV" + k) + ", DT" + k + ", DY" + k + ");");
        line("  if (!_rs) break;");
        line("  { Cell _c; _c.r = _rs; SPUSH(_c); }");
        line("} pc = " + L(next) + "; break;");
    }

    private char concatConstTag(int cpIdx) {
        ConstPool c = cf.cp[cpIdx];
        return switch (c.tag) {
            case ClassFile.TAG_INT -> 'I';
            case ClassFile.TAG_LONG -> 'J';
            case ClassFile.TAG_FLOAT -> 'F';
            case ClassFile.TAG_DOUBLE -> 'D';
            case ClassFile.TAG_STRING, ClassFile.TAG_CLASS -> 'L';
            default -> throw new IllegalArgumentException(where()
                + ": unsupported concat constant tag " + c.tag);
        };
    }

    private String concatConstInit(int cpIdx, String cell) {
        ConstPool c = cf.cp[cpIdx];
        return switch (c.tag) {
            case ClassFile.TAG_INT -> cell + ".i = " + (Integer) c.boxed;
            case ClassFile.TAG_LONG -> cell + ".l = " + (Long) c.boxed + "LL";
            case ClassFile.TAG_FLOAT -> cell + ".f = " + floatLiteral((Float) c.boxed);
            case ClassFile.TAG_DOUBLE -> cell + ".d = " + doubleLiteral((Double) c.boxed);
            case ClassFile.TAG_STRING -> cell + ".r = STRC(" + sy.strConst(cf.utf8(c.a)) + ")";
            default -> cell + ".r = CLS_AT(" + sy.cls(cf.classNameAt(cpIdx)) + ")";
        };
    }

    private void emitGenericBsm(ClassFile.BootstrapEntry bs, ConstPool idy, int next) {
        String indyDesc = cf.descOfRef(u16(pc + 1));
        List<String> dynTypes = Desc.params(indyDesc);
        String dynTags = tagsFromTypes(dynTypes);
        String ret = Desc.returnType(indyDesc);
        int base = flow.inDepth[pc] - Desc.paramSlots(indyDesc);
        int nameU = sy.utf8(cf.nameOfRef(u16(pc + 1)));
        int descU = sy.utf8(indyDesc);
        int k = (int) SITE_SEQ.getAndIncrement();

        line("{");
        line("  static const char DT" + k + "[] = \"" + cstr(dynTags) + "\";");
        line("  static jobject NM" + k + " = NULL, DS" + k + " = NULL;");
        line("  Cell DY" + k + "[" + dynTypes.size() + "];");
        int doff = 0;
        for (int i = 0; i < dynTypes.size(); i++) {
            line("  DY" + k + "[" + i + "] = S[" + (base + doff) + "];");
            doff += Desc.slotSize(dynTypes.get(i));
        }
        line("  jobjectArray _da = (*env)->NewObjectArray(env, " + dynTypes.size() + ", jn_objcls(env), NULL);");
        line("  if (!_da) break;");
        line("  for (int _q = " + (dynTypes.size() - 1) + "; _q >= 0; --_q) {");
        line("    jobject _bx = jn_box(env, DT" + k + "[_q], DY" + k + "[_q]);");
        line("    (*env)->SetObjectArrayElement(env, _da, _q, _bx);");
        line("  }");
        line("  jobject _out = jn_call_bsm(env, SELF, " + idy.a
            + ", jn_string_const(env, &NM" + k + ", UT[" + nameU + "]),"
            + " jn_string_const(env, &DS" + k + ", UT[" + descU + "]), _da);");
        line("  if ((*env)->ExceptionCheck(env)) break;");
        line("  sp = " + base + ";");
        if (!ret.equals("V")) {
            boolean two = ret.equals("J") || ret.equals("D");
            line("  { Cell _c; jn_unbox(env, _out, '" + retTag(ret) + "', &_c); S[sp] = _c;"
                + (two ? " S[sp+1].l = 0;" : "")
                + " sp += " + (two ? 2 : 1) + "; }");
        }
        line("} pc = " + L(next) + "; break;");
    }

    private static final java.util.concurrent.atomic.AtomicLong SITE_SEQ = new java.util.concurrent.atomic.AtomicLong();
}




