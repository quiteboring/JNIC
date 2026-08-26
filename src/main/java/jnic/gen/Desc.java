package jnic.gen;

import java.util.ArrayList;
import java.util.List;

/** Method/type descriptor parsing shared by the analyzer caller and the C emitter. */
public final class Desc {

    /** Parameter types of a method descriptor, each in internal form: I, J, Z, Lfoo/Bar;, [I ... */
    public static List<String> params(String methodDesc) {
        List<String> out = new ArrayList<>();
        int i = 1;
        if (methodDesc.charAt(0) != '(') throw new IllegalArgumentException(methodDesc);
        while (methodDesc.charAt(i) != ')') {
            int start = i;
            while (methodDesc.charAt(i) == '[') i++;
            if (methodDesc.charAt(i) == 'L') {
                i = methodDesc.indexOf(';', i) + 1;
            } else {
                i++;
            }
            out.add(methodDesc.substring(start, i));
        }
        return out;
    }

    public static int slotSize(String type) {
        return type.equals("J") || type.equals("D") ? 2 : 1;
    }

    public static int paramSlots(String methodDesc) {
        int s = 0;
        for (String p : params(methodDesc)) s += slotSize(p);
        return s;
    }

    /** Return type in internal form, e.g. V, I, Ljava/lang/Object;, [[D */
    public static String returnType(String methodDesc) {
        return methodDesc.substring(methodDesc.indexOf(')') + 1);
    }

    /** JNI spelling of a value type for declarations: jint/jlong/.../jobject/void. */
    public static String jniType(String type) {
        return switch (type) {
            case "B" -> "jbyte";
            case "Z" -> "jboolean";
            case "S" -> "jshort";
            case "C" -> "jchar";
            case "I" -> "jint";
            case "J" -> "jlong";
            case "F" -> "jfloat";
            case "D" -> "jdouble";
            case "V" -> "void";
            default -> "jobject";
        };
    }

    private Desc() {}
}
