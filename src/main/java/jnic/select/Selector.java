package jnic.select;

import static jnic.gen.Bytecodes.*;

import jnic.classfile.ClassFile;
import jnic.gen.Analyzer;
import jnic.gen.Bytecodes;
import jnic.gen.Desc;
import jnic.match.Matcher;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;

/** Picks the methods of a class whose bodies will be transpiled to C. */
public final class Selector {

    /** Methods safe to nativize: has code, not a constructor, not already native. */
    public static List<ClassFile.MethodInfo> select(ClassFile cf, Matcher matcher,
                                                    List<String> classAnnotations) {
        List<ClassFile.MethodInfo> out = new ArrayList<>();
        // Interface-declared methods stay Java: registered natives on interfaces do not
        // reliably dispatch through implementing classes (inherited default vtables).
        if ((cf.access & 0x0200) != 0) return out;
        for (ClassFile.MethodInfo m : cf.methods) {
            if (!m.hasCode()) continue;
            if ((m.access & Opcodes.ACC_NATIVE) != 0) continue;
            if (m.name.equals("<init>")) continue; // constructors stay Java (object init protocols)
            if (!matcher.selects(cf.className, m.name, m.desc, classAnnotations, List.of())) continue;

            // Validate the body is transpilable before committing to it.
            try {
                Analyzer.analyze(m.code, m.maxLocals, m.maxStack, m.handlers,
                    cf.className + "." + m.name + m.desc, new Analyzer.RefDeltas() {
                        @Override public int invokeDelta(int op, int cpIndex) {
                            String desc = cf.descOfRef(cpIndex);
                            boolean stat = op == INVOKESTATIC || op == Bytecodes.INVOKEDYNAMIC;
                            int consumed = Desc.paramSlots(desc) + (stat ? 0 : 1);
                            String ret = Desc.returnType(desc);
                            return (ret.equals("V") ? 0 : Desc.slotSize(ret)) - consumed;
                        }

                        @Override public int fieldDelta(int op, int cpIndex) {
                            int fs = Desc.slotSize(cf.descOfRef(cpIndex));
                            return switch (op) {
                                case GETSTATIC -> fs;
                                case PUTSTATIC -> -fs;
                                case GETFIELD -> fs - 1;
                                default -> -(fs + 1);
                            };
                        }
                    });
            } catch (RuntimeException e) {
                System.out.println("[jnic] skipping " + e.getMessage());
                continue;
            }
            out.add(m);
        }
        return out;
    }
}

