package jnic.gen;

import jnic.classfile.ClassFile;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Slot-depth dataflow over one method body. The generated interpreter manipulates its
 * operand stack at raw slot granularity exactly like the JVM, so only slot counts,
 * reachability and consistency are tracked here. Handler entry frames hold exactly one
 * slot (the throwable), so exception edges contribute nothing to the dataflow.
 */
public final class Analyzer {

    /** Descriptor-aware net deltas for invokes and field accesses, resolved by the caller. */
    public interface RefDeltas {
        int invokeDelta(int op, int cpIndex);

        int fieldDelta(int op, int cpIndex);
    }

    public static final class Result {
        public final boolean[] reachable;
        public final int[] inDepth;

        Result(boolean[] reachable, int[] inDepth) {
            this.reachable = reachable;
            this.inDepth = inDepth;
        }
    }

    public static Result analyze(byte[] code, int maxLocals, int maxStack,
                                 List<ClassFile.ExceptionEntry> handlers, String where,
                                 RefDeltas deltas) {
        int n = code.length;
        boolean[] reachable = new boolean[n];
        int[] depth = new int[n];
        java.util.Arrays.fill(depth, -1);
        Deque<int[]> work = new ArrayDeque<>();
        work.push(new int[]{0, 0});
        // Exception handlers are entered with exactly one stack slot (the throwable);
        // they are usually reachable ONLY through the exception edge.
        for (ClassFile.ExceptionEntry h : handlers)
            if (h.handlerPc >= 0 && h.handlerPc < n) work.push(new int[]{h.handlerPc, 1});
        while (!work.isEmpty()) {
            int[] cur = work.pop();
            int pc = cur[0], d = cur[1];
            if (pc < 0 || pc >= n)
                throw invalid(where, "branch target " + pc + " outside method body");
            if (depth[pc] >= 0) {
                if (depth[pc] != d)
                    throw invalid(where, "inconsistent stack depth (" + depth[pc] + " vs "
                        + d + ") at offset " + pc);
                continue;
            }
            reachable[pc] = true;
            depth[pc] = d;

            int op = code[pc] & 0xFF;
            if (op == Bytecodes.JSR || op == Bytecodes.JSR_W || op == Bytecodes.RET)
                throw invalid(where, "JSR/RET subroutines are not supported");
            if (op == Bytecodes.WIDE && (code[pc + 1] & 0xFF) == Bytecodes.RET)
                throw invalid(where, "wide RET is not supported");

            int idx = Bytecodes.localVarIndex(code, pc);
            if (idx >= 0) {
                int realOp = op == Bytecodes.WIDE ? (code[pc + 1] & 0xFF) : op;
                int span = Bytecodes.isCategory2Store(realOp) ? 2 : 1;
                if (idx + span > maxLocals)
                    throw invalid(where, "local variable index " + idx + " exceeds max_locals at offset " + pc
                        + " (op=" + op + ")");
            }

            int len = Bytecodes.length(code, pc);
            if (len <= 0 || pc + len > n)
                throw invalid(where, "instruction at offset " + pc + " overruns code");

            int delta = delta(code, pc, deltas);
            int out = d + delta;
            if (out < 0)
                throw invalid(where, "operand stack underflow at offset " + pc);
            if (out > maxStack)
                throw invalid(where, "operand stack overflow (" + out + " > max_stack " + maxStack
                    + ") at offset " + pc);

            for (int succ : Bytecodes.successors(code, pc))
                work.push(new int[]{succ, out});
        }
        return new Result(reachable, depth);
    }

    private static int delta(byte[] code, int pc, RefDeltas rd) {
        int op = code[pc] & 0xFF;
        switch (op) {
            case Bytecodes.NOP, Bytecodes.IINC, Bytecodes.GOTO, Bytecodes.GOTO_W, Bytecodes.RETURN,
                 Bytecodes.SWAP, Bytecodes.CHECKCAST, Bytecodes.INSTANCEOF, Bytecodes.ARRAYLENGTH,
                 Bytecodes.MONITORENTER, Bytecodes.MONITOREXIT,
                 Bytecodes.NEWARRAY, Bytecodes.ANEWARRAY,
                 Bytecodes.INEG, Bytecodes.FNEG, Bytecodes.LNEG, Bytecodes.DNEG,
                 Bytecodes.I2B, Bytecodes.I2C, Bytecodes.I2S, Bytecodes.I2F, Bytecodes.L2D,
                 Bytecodes.F2I, Bytecodes.D2L:
                return 0;

            case Bytecodes.ACONST_NULL, Bytecodes.ICONST_M1, Bytecodes.ICONST_0, Bytecodes.ICONST_1,
                 Bytecodes.ICONST_2, Bytecodes.ICONST_3, Bytecodes.ICONST_4, Bytecodes.ICONST_5,
                 Bytecodes.FCONST_0, Bytecodes.FCONST_1, Bytecodes.FCONST_2, Bytecodes.BIPUSH,
                 Bytecodes.SIPUSH, Bytecodes.LDC, Bytecodes.LDC_W,
                 Bytecodes.ILOAD, Bytecodes.FLOAD, Bytecodes.ALOAD,
                 Bytecodes.ILOAD_0, Bytecodes.ILOAD_1, Bytecodes.ILOAD_2, Bytecodes.ILOAD_3,
                 Bytecodes.FLOAD_0, Bytecodes.FLOAD_1, Bytecodes.FLOAD_2, Bytecodes.FLOAD_3,
                 Bytecodes.ALOAD_0, Bytecodes.ALOAD_1, Bytecodes.ALOAD_2, Bytecodes.ALOAD_3,
                 Bytecodes.NEW, Bytecodes.DUP, Bytecodes.DUP_X1, Bytecodes.DUP_X2:
                return 1;

            case Bytecodes.LCONST_0, Bytecodes.LCONST_1, Bytecodes.DCONST_0, Bytecodes.DCONST_1,
                 Bytecodes.LDC2_W,
                 Bytecodes.LLOAD, Bytecodes.DLOAD,
                 Bytecodes.LLOAD_0, Bytecodes.LLOAD_1, Bytecodes.LLOAD_2, Bytecodes.LLOAD_3,
                 Bytecodes.DLOAD_0, Bytecodes.DLOAD_1, Bytecodes.DLOAD_2, Bytecodes.DLOAD_3,
                 Bytecodes.DUP2, Bytecodes.DUP2_X1, Bytecodes.DUP2_X2:
                return 2;

            case Bytecodes.POP: return -1;
            case Bytecodes.POP2: return -2;

            case Bytecodes.ISTORE, Bytecodes.FSTORE, Bytecodes.ASTORE,
                 Bytecodes.ISTORE_0, Bytecodes.ISTORE_1, Bytecodes.ISTORE_2, Bytecodes.ISTORE_3,
                 Bytecodes.FSTORE_0, Bytecodes.FSTORE_1, Bytecodes.FSTORE_2, Bytecodes.FSTORE_3,
                 Bytecodes.ASTORE_0, Bytecodes.ASTORE_1, Bytecodes.ASTORE_2, Bytecodes.ASTORE_3:
                return -1;
            case Bytecodes.LSTORE, Bytecodes.DSTORE,
                 Bytecodes.LSTORE_0, Bytecodes.LSTORE_1, Bytecodes.LSTORE_2, Bytecodes.LSTORE_3,
                 Bytecodes.DSTORE_0, Bytecodes.DSTORE_1, Bytecodes.DSTORE_2, Bytecodes.DSTORE_3:
                return -2;

            case Bytecodes.IALOAD, Bytecodes.FALOAD, Bytecodes.AALOAD, Bytecodes.BALOAD,
                 Bytecodes.CALOAD, Bytecodes.SALOAD:
                return -1;
            case Bytecodes.LALOAD, Bytecodes.DALOAD:
                return 0;

            case Bytecodes.IASTORE, Bytecodes.FASTORE, Bytecodes.AASTORE, Bytecodes.BASTORE,
                 Bytecodes.CASTORE, Bytecodes.SASTORE:
                return -3;
            case Bytecodes.LASTORE, Bytecodes.DASTORE:
                return -4;

            case Bytecodes.IADD, Bytecodes.ISUB, Bytecodes.IMUL, Bytecodes.IDIV, Bytecodes.IREM,
                 Bytecodes.ISHL, Bytecodes.ISHR, Bytecodes.IUSHR, Bytecodes.IAND, Bytecodes.IOR,
                 Bytecodes.IXOR, Bytecodes.FADD, Bytecodes.FSUB, Bytecodes.FMUL, Bytecodes.FDIV,
                 Bytecodes.FREM, Bytecodes.FCMPL, Bytecodes.FCMPG:
                return -1;

            case Bytecodes.LADD, Bytecodes.LSUB, Bytecodes.LMUL, Bytecodes.LDIV, Bytecodes.LREM,
                 Bytecodes.LAND, Bytecodes.LOR, Bytecodes.LXOR, Bytecodes.DADD, Bytecodes.DSUB,
                 Bytecodes.DMUL, Bytecodes.DDIV, Bytecodes.DREM:
                return -2;

            case Bytecodes.LCMP, Bytecodes.DCMPL, Bytecodes.DCMPG:
                return -3;

            case Bytecodes.I2L, Bytecodes.I2D, Bytecodes.F2L, Bytecodes.F2D:
                return 1;
            case Bytecodes.L2I, Bytecodes.L2F, Bytecodes.D2I, Bytecodes.D2F:
                return -1;

            case Bytecodes.LSHL, Bytecodes.LSHR, Bytecodes.LUSHR:
                return -1;

            case Bytecodes.IFEQ, Bytecodes.IFNE, Bytecodes.IFLT, Bytecodes.IFGE, Bytecodes.IFGT,
                 Bytecodes.IFLE, Bytecodes.IFNULL, Bytecodes.IFNONNULL,
                 Bytecodes.TABLESWITCH, Bytecodes.LOOKUPSWITCH:
                return -1;

            case Bytecodes.IF_ICMPEQ, Bytecodes.IF_ICMPNE, Bytecodes.IF_ICMPLT, Bytecodes.IF_ICMPGE,
                 Bytecodes.IF_ICMPGT, Bytecodes.IF_ICMPLE, Bytecodes.IF_ACMPEQ, Bytecodes.IF_ACMPNE:
                return -2;

            case Bytecodes.IRETURN, Bytecodes.FRETURN, Bytecodes.ARETURN: return -1;
            case Bytecodes.LRETURN, Bytecodes.DRETURN: return -2;
            case Bytecodes.ATHROW: return -1;

            case Bytecodes.GETFIELD, Bytecodes.PUTFIELD, Bytecodes.GETSTATIC, Bytecodes.PUTSTATIC:
                return rd.fieldDelta(op, u16(code, pc + 1));

            case Bytecodes.INVOKEVIRTUAL, Bytecodes.INVOKESPECIAL, Bytecodes.INVOKESTATIC,
                 Bytecodes.INVOKEINTERFACE, Bytecodes.INVOKEDYNAMIC:
                return rd.invokeDelta(op, op == Bytecodes.INVOKEDYNAMIC ? u16(code, pc + 1) : u16(code, pc + 1));

            default:
                throw new IllegalStateException("unhandled opcode " + op + " in analyzer");
        }
    }

    static int u16(byte[] c, int p) {
        return ((c[p] & 0xFF) << 8) | (c[p + 1] & 0xFF);
    }

    private static IllegalArgumentException invalid(String where, String msg) {
        return new IllegalArgumentException(where + ": " + msg);
    }
}
