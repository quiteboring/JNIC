package jnic.gen;

import java.util.ArrayList;
import java.util.List;

/** Complete JVMS opcode table plus instruction lengths, successors and operand accessors. */
public final class Bytecodes {

    public static final int NOP = 0, ACONST_NULL = 1, ICONST_M1 = 2, ICONST_0 = 3, ICONST_1 = 4,
        ICONST_2 = 5, ICONST_3 = 6, ICONST_4 = 7, ICONST_5 = 8, LCONST_0 = 9, LCONST_1 = 10,
        FCONST_0 = 11, FCONST_1 = 12, FCONST_2 = 13, DCONST_0 = 14, DCONST_1 = 15,
        BIPUSH = 16, SIPUSH = 17, LDC = 18, LDC_W = 19, LDC2_W = 20,
        ILOAD = 21, LLOAD = 22, FLOAD = 23, DLOAD = 24, ALOAD = 25,
        ILOAD_0 = 26, ILOAD_1 = 27, ILOAD_2 = 28, ILOAD_3 = 29,
        LLOAD_0 = 30, LLOAD_1 = 31, LLOAD_2 = 32, LLOAD_3 = 33, FLOAD_0 = 34, FLOAD_1 = 35,
        FLOAD_2 = 36, FLOAD_3 = 37, DLOAD_0 = 38, DLOAD_1 = 39, DLOAD_2 = 40, DLOAD_3 = 41,
        ALOAD_0 = 42, ALOAD_1 = 43, ALOAD_2 = 44, ALOAD_3 = 45,
        IALOAD = 46, LALOAD = 47, FALOAD = 48, DALOAD = 49, AALOAD = 50, BALOAD = 51,
        CALOAD = 52, SALOAD = 53,
        ISTORE = 54, LSTORE = 55, FSTORE = 56, DSTORE = 57, ASTORE = 58,
        ISTORE_0 = 59, ISTORE_1 = 60, ISTORE_2 = 61, ISTORE_3 = 62,
        LSTORE_0 = 63, LSTORE_1 = 64, LSTORE_2 = 65, LSTORE_3 = 66,
        FSTORE_0 = 67, FSTORE_1 = 68, FSTORE_2 = 69, FSTORE_3 = 70,
        DSTORE_0 = 71, DSTORE_1 = 72, DSTORE_2 = 73, DSTORE_3 = 74,
        ASTORE_0 = 75, ASTORE_1 = 76, ASTORE_2 = 77, ASTORE_3 = 78,
        IASTORE = 79, LASTORE = 80, FASTORE = 81, DASTORE = 82, AASTORE = 83, BASTORE = 84,
        CASTORE = 85, SASTORE = 86,
        POP = 87, POP2 = 88, DUP = 89, DUP_X1 = 90, DUP_X2 = 91, DUP2 = 92, DUP2_X1 = 93,
        DUP2_X2 = 94, SWAP = 95,
        IADD = 96, LADD = 97, FADD = 98, DADD = 99, ISUB = 100, LSUB = 101, FSUB = 102,
        DSUB = 103, IMUL = 104, LMUL = 105, FMUL = 106, DMUL = 107, IDIV = 108, LDIV = 109,
        FDIV = 110, DDIV = 111, IREM = 112, LREM = 113, FREM = 114, DREM = 115,
        INEG = 116, LNEG = 117, FNEG = 118, DNEG = 119,
        ISHL = 120, LSHL = 121, ISHR = 122, LSHR = 123, IUSHR = 124, LUSHR = 125,
        IAND = 126, LAND = 127, IOR = 128, LOR = 129, IXOR = 130, LXOR = 131, IINC = 132,
        I2L = 133, I2F = 134, I2D = 135, L2I = 136, L2F = 137, L2D = 138, F2I = 139,
        F2L = 140, F2D = 141, D2I = 142, D2L = 143, D2F = 144, I2B = 145, I2C = 146,
        I2S = 147, LCMP = 148, FCMPL = 149, FCMPG = 150, DCMPL = 151, DCMPG = 152,
        IFEQ = 153, IFNE = 154, IFLT = 155, IFGE = 156, IFGT = 157, IFLE = 158,
        IF_ICMPEQ = 159, IF_ICMPNE = 160, IF_ICMPLT = 161, IF_ICMPGE = 162, IF_ICMPGT = 163,
        IF_ICMPLE = 164, IF_ACMPEQ = 165, IF_ACMPNE = 166, GOTO = 167, JSR = 168, RET = 169,
        TABLESWITCH = 170, LOOKUPSWITCH = 171,
        IRETURN = 172, LRETURN = 173, FRETURN = 174, DRETURN = 175, ARETURN = 176, RETURN = 177,
        GETSTATIC = 178, PUTSTATIC = 179, GETFIELD = 180, PUTFIELD = 181,
        INVOKEVIRTUAL = 182, INVOKESPECIAL = 183, INVOKESTATIC = 184, INVOKEINTERFACE = 185,
        INVOKEDYNAMIC = 186,
        NEW = 187, NEWARRAY = 188, ANEWARRAY = 189, ARRAYLENGTH = 190, ATHROW = 191,
        CHECKCAST = 192, INSTANCEOF = 193, MONITORENTER = 194, MONITOREXIT = 195,
        WIDE = 196, MULTIANEWARRAY = 197, IFNULL = 198, IFNONNULL = 199, GOTO_W = 200,
        JSR_W = 201;

    private Bytecodes() {}

    /** Length in bytes of the instruction starting at {@code pc}. */
    public static int length(byte[] code, int pc) {
        int op = code[pc] & 0xFF;
        switch (op) {
            case BIPUSH, NEWARRAY, LDC, ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
                 ISTORE, LSTORE, FSTORE, DSTORE, ASTORE, RET -> { return 2; }
            case SIPUSH, LDC_W, LDC2_W, IINC, GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD,
                 INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, NEW, ANEWARRAY, CHECKCAST,
                 INSTANCEOF, GOTO,
                 IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
                 IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                 IF_ACMPEQ, IF_ACMPNE, IFNULL, IFNONNULL -> { return 3; }
            case GOTO_W -> { return 5; }
            case INVOKEINTERFACE, INVOKEDYNAMIC -> { return 5; }
            case MULTIANEWARRAY -> { return 4; }
            case TABLESWITCH -> {
                int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
                int low = read32(code, base + 4);
                int high = read32(code, base + 8);
                return base + 12 + (high - low + 1) * 4 - pc;
            }
            case LOOKUPSWITCH -> {
                int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
                int pairs = read32(code, base + 4);
                return base + 8 + pairs * 8 - pc;
            }
            case WIDE -> {
                int next = code[pc + 1] & 0xFF;
                return next == IINC ? 6 : 4;
            }
            default -> {
                if (isInvalid(op)) throw new IllegalArgumentException("invalid opcode " + op);
                return 1;
            }
        }
    }

    /** Absolute branch target offsets (empty for straight-line instructions). */
    public static List<Integer> successors(byte[] code, int pc) {
        List<Integer> out = new ArrayList<>(4);
        int op = code[pc] & 0xFF;
        switch (op) {
            case GOTO -> out.add(pc + read16s(code, pc + 1));
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
                 IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                 IF_ACMPEQ, IF_ACMPNE, IFNULL, IFNONNULL -> {
                out.add(pc + read16s(code, pc + 1));
                out.add(pc + length(code, pc));
            }
            case GOTO_W -> out.add(pc + read32(code, pc + 1));
            case TABLESWITCH -> {
                int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
                out.add(pc + read32(code, base));
                int low = read32(code, base + 4), high = read32(code, base + 8);
                for (int i = 0; i <= high - low; i++) out.add(pc + read32(code, base + 12 + i * 4));
            }
            case LOOKUPSWITCH -> {
                int base = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
                out.add(pc + read32(code, base));
                int n = read32(code, base + 4);
                for (int i = 0; i < n; i++) out.add(pc + read32(code, base + 8 + i * 8 + 4));
            }
            default -> {
                if (!terminates(op)) out.add(pc + length(code, pc));
            }
        }
        return out;
    }

    /** True if control cannot continue to the following instruction. */
    public static boolean terminates(int op) {
        return switch (op) {
            case GOTO, GOTO_W, ARETURN, IRETURN, LRETURN, FRETURN, DRETURN, RETURN,
                 ATHROW, RET, TABLESWITCH, LOOKUPSWITCH -> true;
            default -> false;
        };
    }

    /**
     * For xLOAD/xSTORE/IINC forms: the local-variable index operand, or -1 when the
     * instruction takes no local index. Handles _n shortcuts and WIDE prefixes.
     */
    public static int localVarIndex(byte[] code, int pc) {
        int op = code[pc] & 0xFF;
        if (op == WIDE) {
            int next = code[pc + 1] & 0xFF;
            return read16(code, pc + 2);
        }
        return switch (op) {
            case ILOAD_0, FLOAD_0, ALOAD_0, ISTORE_0, FSTORE_0, ASTORE_0, LSTORE_0,
                 DSTORE_0, LLOAD_0, DLOAD_0 -> 0;
            case ILOAD_1, FLOAD_1, ALOAD_1, ISTORE_1, FSTORE_1, ASTORE_1, LSTORE_1,
                 DSTORE_1, LLOAD_1, DLOAD_1 -> 1;
            case ILOAD_2, FLOAD_2, ALOAD_2, ISTORE_2, FSTORE_2, ASTORE_2, LSTORE_2,
                 DSTORE_2, LLOAD_2, DLOAD_2 -> 2;
            case ILOAD_3, FLOAD_3, ALOAD_3, ISTORE_3, FSTORE_3, ASTORE_3, LSTORE_3,
                 DSTORE_3, LLOAD_3, DLOAD_3 -> 3;
            case ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
                 ISTORE, LSTORE, FSTORE, DSTORE, ASTORE -> code[pc + 1] & 0xFF;
            case IINC -> code[pc + 1] & 0xFF;
            default -> -1;
        };
    }

    public static boolean isCategory2Store(int op) {
        return switch (op) {
            case LSTORE, DSTORE, LSTORE_0, LSTORE_1, LSTORE_2, LSTORE_3,
                 DSTORE_0, DSTORE_1, DSTORE_2, DSTORE_3 -> true;
            default -> false;
        };
    }

    public static boolean isLoad(int op) {
        return switch (op) {
            case ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
                 ILOAD_0, ILOAD_1, ILOAD_2, ILOAD_3,
                 LLOAD_0, LLOAD_1, LLOAD_2, LLOAD_3,
                 FLOAD_0, FLOAD_1, FLOAD_2, FLOAD_3,
                 DLOAD_0, DLOAD_1, DLOAD_2, DLOAD_3,
                 ALOAD_0, ALOAD_1, ALOAD_2, ALOAD_3 -> true;
            default -> false;
        };
    }

    public static boolean isStore(int op) {
        return switch (op) {
            case ISTORE, LSTORE, FSTORE, DSTORE, ASTORE,
                 ISTORE_0, ISTORE_1, ISTORE_2, ISTORE_3,
                 LSTORE_0, LSTORE_1, LSTORE_2, LSTORE_3,
                 FSTORE_0, FSTORE_1, FSTORE_2, FSTORE_3,
                 DSTORE_0, DSTORE_1, DSTORE_2, DSTORE_3,
                 ASTORE_0, ASTORE_1, ASTORE_2, ASTORE_3 -> true;
            default -> false;
        };
    }

    /** Opcodes above 201 are reserved or undefined; everything 0..201 is a real instruction. */
    static boolean isInvalid(int op) {
        return op > 201;
    }

    static int read16(byte[] c, int p) { return ((c[p] & 0xFF) << 8) | (c[p + 1] & 0xFF); }
    static int read16s(byte[] c, int p) { return (short) read16(c, p); }
    static int read32(byte[] c, int p) {
        return ((c[p] & 0xFF) << 24) | ((c[p + 1] & 0xFF) << 16)
            | ((c[p + 2] & 0xFF) << 8) | (c[p + 3] & 0xFF);
    }
}
