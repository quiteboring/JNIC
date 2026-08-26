/*
 * jnic-preamble: support runtime compiled into every generated translation unit.
 * Per-class tables/caches are emitted by GroupEmitter and referenced through macros
 * expanded inside per-class scopes. Stateful caches below initialize lazily with a
 * benign first-use race: racing threads compute identical JNI IDs.
 */
#ifndef JNIC_PREAMBLE_H
#define JNIC_PREAMBLE_H

#include <jni.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t juint;
typedef uint64_t julong;

typedef union {
    jlong   l;
    jdouble d;
    jobject r;
    jint    i;
    jfloat  f;
} Cell;

/* Entry layout required by JNINativeMethod; kept local so generated TUs need no jni_md extras. */
typedef struct { const char *name; const char *sig; void *fn; } JnNativeMethod;

/* Operand-stack primitives. Category-2 values occupy two slots: value then padding. */
#define SPUSH(c)  (S[sp++] = (c))
#define SPOP      (S[--sp])
#define SPUSH2(v) do { S[sp] = (v); S[sp+1].l = 0; sp += 2; } while (0)
#define SPOP2     (sp -= 2, S[sp])

/* ---- saturated narrowing casts (JVMS semantics; plain C casts would be UB) ---- */
static jint jn_f2i(jfloat v) {
    if (v != v) return 0;
    if (v >= 2147483647.0f) return INT32_MAX;
    if (v <= -2147483648.0f) return INT32_MIN;
    return (jint) v;
}
static jlong jn_f2l(jfloat v) {
    if (v != v) return 0;
    if (v >= 9223372036854775807.0f) return INT64_MAX;
    if (v <= -9223372036854775808.0f) return INT64_MIN;
    return (jlong) v;
}
static jint jn_d2i(jdouble v) {
    if (v != v) return 0;
    if (v >= 2147483647.0) return INT32_MAX;
    if (v <= -2147483648.0) return INT32_MIN;
    return (jint) v;
}
static jlong jn_d2l(jdouble v) {
    if (v != v) return 0;
    if (v >= 9223372036854775807.0) return INT64_MAX;
    if (v <= -9223372036854775808.0) return INT64_MIN;
    return (jlong) v;
}

/* Java division semantics: /0 throws ArithmeticException, MIN/-1 wraps. */
static void jn_throw_named(JNIEnv *env, const char *cls, const char *msg);

static jint jn_idiv(JNIEnv *env, jint a, jint b) {
    if (b == 0) { jn_throw_named(env, "java/lang/ArithmeticException", "/ by zero"); return 0; }
    return (a == INT32_MIN && b == -1) ? a : a / b;
}
static jint jn_irem(JNIEnv *env, jint a, jint b) {
    if (b == 0) { jn_throw_named(env, "java/lang/ArithmeticException", "/ by zero"); return 0; }
    return (a == INT32_MIN && b == -1) ? 0 : a % b;
}
static jlong jn_ldiv(JNIEnv *env, jlong a, jlong b) {
    if (b == 0) { jn_throw_named(env, "java/lang/ArithmeticException", "/ by zero"); return 0; }
    return (a == INT64_MIN && b == -1) ? a : a / b;
}
static jlong jn_lrem(JNIEnv *env, jlong a, jlong b) {
    if (b == 0) { jn_throw_named(env, "java/lang/ArithmeticException", "/ by zero"); return 0; }
    return (a == INT64_MIN && b == -1) ? 0 : a % b;
}

/* ---- exception raising ---- */
static void jn_throw_named(JNIEnv *env, const char *cls, const char *msg) {
    jclass c = (*env)->FindClass(env, cls);
    if (c == NULL) return;
    (*env)->ThrowNew(env, c, msg ? msg : "");
}

#define JN_NPE(env) jn_throw_named(env, "java/lang/NullPointerException", NULL)

static void jn_aioobe(JNIEnv *env, jint ix) {
    char msg[24];
    snprintf(msg, sizeof msg, "%d", (int) ix);
    jn_throw_named(env, "java/lang/ArrayIndexOutOfBoundsException", msg);
}

extern void jn_chacha20(unsigned char *, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *);

static jobject jn_strdec(JNIEnv *env, jobject *cache, const unsigned char *key,
                         const unsigned char *blob, jint blen) {
    if (*cache == NULL) {
        if (blen < 12) return NULL;
        int ctlen = blen - 12;
        unsigned char *tmp = (unsigned char *) malloc(ctlen + 1);
        if (!tmp) return NULL;
        if (ctlen > 0)
            jn_chacha20(tmp, blob + 12, (unsigned long long) ctlen, key, blob);
        tmp[ctlen] = 0;
        jstring s = (*env)->NewStringUTF(env, (const char *) tmp);
        free(tmp);
        if (s == NULL) return NULL;
        *cache = (*env)->NewGlobalRef(env, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return *cache;
}

/* ---- lazy class / string resolution with external cache cells ---- */
static jclass jn_cls(JNIEnv *env, jclass *cache, const char *name) {
    if (*cache == NULL) {
        jclass l = (*env)->FindClass(env, name);
        if (l == NULL) return NULL;
        *cache = (*env)->NewGlobalRef(env, l);
        (*env)->DeleteLocalRef(env, l);
    }
    return *cache;
}

static jobject jn_string_const(JNIEnv *env, jobject *cache, const char *utf8) {
    if (*cache == NULL) {
        jstring s = (*env)->NewStringUTF(env, utf8);
        if (s == NULL) return NULL;
        *cache = (*env)->NewGlobalRef(env, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return *cache;
}

/* ---- multi-dimensional array creation ----
 * cls is the full array class name of the current level ("[[I"); left counts the
 * dimensions this call fills. Primitive leaves allocate via New*Array; object/array
 * levels via NewObjectArray(FindClass(cls)). cls+1 strips exactly one '['.
 */
static jclass jn_objcls(JNIEnv *env) {
    static jclass obj = NULL;
    return jn_cls(env, &obj, "java/lang/Object");
}
static jobject jn_multi_build(JNIEnv *env, const char *cls, int left, const jint *lens) {
    jint n = lens[0];
    if (n < 0) { jn_throw_named(env, "java/lang/NegativeArraySizeException", NULL); return NULL; }
    if (left == 1) {
        switch (cls[1]) {
            case 'I': return (*env)->NewIntArray(env, n);
            case 'J': return (*env)->NewLongArray(env, n);
            case 'Z': return (*env)->NewBooleanArray(env, n);
            case 'B': return (*env)->NewByteArray(env, n);
            case 'C': return (*env)->NewCharArray(env, n);
            case 'S': return (*env)->NewShortArray(env, n);
            case 'F': return (*env)->NewFloatArray(env, n);
            case 'D': return (*env)->NewDoubleArray(env, n);
            default: {
                jclass cc = (*env)->FindClass(env, cls);
                return cc ? (jobject)(*env)->NewObjectArray(env, n, cc, NULL) : NULL;
            }
        }
    }
    jclass cc = (*env)->FindClass(env, cls);
    if (!cc) return NULL;
    jobjectArray arr = (*env)->NewObjectArray(env, n, cc, NULL);
    if (!arr) return NULL;
    for (jint i = 0; i < n; i++) {
        jobject sub = jn_multi_build(env, cls + 1, left - 1, lens + 1);
        if (!sub && (*env)->ExceptionCheck(env)) return NULL;
        (*env)->SetObjectArrayElement(env, arr, i, sub);
        (*env)->DeleteLocalRef(env, sub);
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    return (jobject) arr;
}

/* ---- boolean[] vs byte[] discrimination for baload/bastore ---- */
static jboolean jn_is_bool_array(JNIEnv *env, jobject arr, jclass boolArrCls) {
    if (boolArrCls == NULL) return JNI_FALSE;
    jclass ac = (*env)->GetObjectClass(env, arr);
    jboolean same = (*env)->IsSameObject(env, ac, boolArrCls);
    (*env)->DeleteLocalRef(env, ac);
    return same;
}

/* ================= invokedynamic support ================= */

/* Ingredient tags shared by concat recipes and boxing bridges. */
enum { JN_T_REF = 'L', JN_T_Z = 'Z', JN_T_C = 'C', JN_T_B = 'B', JN_T_S = 'S',
       JN_T_I = 'I', JN_T_J = 'J', JN_T_F = 'F', JN_T_D = 'D' };

typedef struct {
    jclass    StringBuilder;
    jmethodID sbInit, sbToString;
    jmethodID apL, apZ, apC, apI, apJ, apF, apD;
    jclass    Integer, Long, Float, Double, Boolean, Character, Short, Byte;
    jmethodID intVof, longVof, floatVof, doubleVof, boolVof, charVof, shortVof, byteVof;
    jmethodID intVal, longVal, floatVal, doubleVal, boolVal, charVal, shortVal, byteVal;
    jclass    Loader;
    jmethodID boot, mhInvoke, vhOp, special;
} JnBridge;

static JnBridge g_bridge;
static volatile int g_bridge_ready;

/* FindClass yields local refs; every cached class here must outlive this call. */
static jclass jn_global_cls(JNIEnv *env, const char *name) {
    jclass l = (*env)->FindClass(env, name);
    if (l == NULL) return NULL;
    jclass g = (*env)->NewGlobalRef(env, l);
    (*env)->DeleteLocalRef(env, l);
    return g;
}

static jboolean jn_bridge_init(JNIEnv *env) {
    if (__atomic_load_n(&g_bridge_ready, __ATOMIC_ACQUIRE)) return JNI_TRUE;
    JnBridge *b = &g_bridge;
    b->StringBuilder = jn_global_cls(env, "java/lang/StringBuilder");
    if (!b->StringBuilder) return JNI_FALSE;
    b->sbInit     = (*env)->GetMethodID(env, b->StringBuilder, "<init>", "()V");
    b->sbToString = (*env)->GetMethodID(env, b->StringBuilder, "toString", "()Ljava/lang/String;");
    b->apL = (*env)->GetMethodID(env, b->StringBuilder, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
    b->apZ = (*env)->GetMethodID(env, b->StringBuilder, "append", "(Z)Ljava/lang/StringBuilder;");
    b->apC = (*env)->GetMethodID(env, b->StringBuilder, "append", "(C)Ljava/lang/StringBuilder;");
    b->apI = (*env)->GetMethodID(env, b->StringBuilder, "append", "(I)Ljava/lang/StringBuilder;");
    b->apJ = (*env)->GetMethodID(env, b->StringBuilder, "append", "(J)Ljava/lang/StringBuilder;");
    b->apF = (*env)->GetMethodID(env, b->StringBuilder, "append", "(F)Ljava/lang/StringBuilder;");
    b->apD = (*env)->GetMethodID(env, b->StringBuilder, "append", "(D)Ljava/lang/StringBuilder;");
    if (!b->sbInit || !b->sbToString || !b->apL || !b->apZ || !b->apC || !b->apI || !b->apJ || !b->apF || !b->apD)
        return JNI_FALSE;
    b->Integer   = jn_global_cls(env, "java/lang/Integer");
    b->Long      = jn_global_cls(env, "java/lang/Long");
    b->Float     = jn_global_cls(env, "java/lang/Float");
    b->Double    = jn_global_cls(env, "java/lang/Double");
    b->Boolean   = jn_global_cls(env, "java/lang/Boolean");
    b->Character = jn_global_cls(env, "java/lang/Character");
    b->Short     = jn_global_cls(env, "java/lang/Short");
    b->Byte      = jn_global_cls(env, "java/lang/Byte");
    if (!b->Integer || !b->Long || !b->Float || !b->Double || !b->Boolean || !b->Character || !b->Short || !b->Byte)
        return JNI_FALSE;
    b->intVof    = (*env)->GetStaticMethodID(env, b->Integer, "valueOf", "(I)Ljava/lang/Integer;");
    b->longVof   = (*env)->GetStaticMethodID(env, b->Long, "valueOf", "(J)Ljava/lang/Long;");
    b->floatVof  = (*env)->GetStaticMethodID(env, b->Float, "valueOf", "(F)Ljava/lang/Float;");
    b->doubleVof = (*env)->GetStaticMethodID(env, b->Double, "valueOf", "(D)Ljava/lang/Double;");
    b->boolVof   = (*env)->GetStaticMethodID(env, b->Boolean, "valueOf", "(Z)Ljava/lang/Boolean;");
    b->charVof   = (*env)->GetStaticMethodID(env, b->Character, "valueOf", "(C)Ljava/lang/Character;");
    b->shortVof  = (*env)->GetStaticMethodID(env, b->Short, "valueOf", "(S)Ljava/lang/Short;");
    b->byteVof   = (*env)->GetStaticMethodID(env, b->Byte, "valueOf", "(B)Ljava/lang/Byte;");
    if (!b->intVof || !b->longVof || !b->floatVof || !b->doubleVof || !b->boolVof || !b->charVof || !b->shortVof || !b->byteVof)
        return JNI_FALSE;
    b->intVal    = (*env)->GetMethodID(env, b->Integer, "intValue", "()I");
    b->longVal   = (*env)->GetMethodID(env, b->Long, "longValue", "()J");
    b->floatVal  = (*env)->GetMethodID(env, b->Float, "floatValue", "()F");
    b->doubleVal = (*env)->GetMethodID(env, b->Double, "doubleValue", "()D");
    b->boolVal   = (*env)->GetMethodID(env, b->Boolean, "booleanValue", "()Z");
    b->charVal   = (*env)->GetMethodID(env, b->Character, "charValue", "()C");
    b->shortVal  = (*env)->GetMethodID(env, b->Short, "shortValue", "()S");
    b->byteVal   = (*env)->GetMethodID(env, b->Byte, "byteValue", "()B");
    if (!b->intVal || !b->longVal || !b->floatVal || !b->doubleVal || !b->boolVal || !b->charVal || !b->shortVal || !b->byteVal)
        return JNI_FALSE;
    b->Loader = jn_global_cls(env, "jnic/loader/JNICLoader");
    if (!b->Loader) return JNI_FALSE;
    b->boot = (*env)->GetStaticMethodID(env, b->Loader, "bootstrap",
        "(Ljava/lang/Class;ILjava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;");
    b->mhInvoke = (*env)->GetStaticMethodID(env, b->Loader, "mhInvoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    b->vhOp = (*env)->GetStaticMethodID(env, b->Loader, "varHandleOp",
        "(Ljava/lang/Object;I[Ljava/lang/Object;)Ljava/lang/Object;");
    b->special = (*env)->GetStaticMethodID(env, b->Loader, "invokeSpecial",
        "(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (!b->boot || !b->mhInvoke || !b->vhOp || !b->special) return JNI_FALSE;
    __atomic_store_n(&g_bridge_ready, 1, __ATOMIC_RELEASE);
    return JNI_TRUE;
}

/* invokespecial targeting an interface method (Iface.super.m()): HotSpot cannot do
 * nonvirtual dispatch on interfaces, so delegate to a MethodHandles findSpecial. */
static jobject jn_call_special(JNIEnv *env, jclass owner, jclass specialCaller,
                               jstring name, jstring desc, jobject recv, jobjectArray args) {
    if (!jn_bridge_init(env)) return NULL;
    jvalue a[6];
    a[0].l = owner;
    a[1].l = specialCaller;
    a[2].l = name;
    a[3].l = desc;
    a[4].l = recv;
    a[5].l = args;
    return (*env)->CallStaticObjectMethodA(env, g_bridge.Loader, g_bridge.special, a);
}

static jobject jn_box(JNIEnv *env, char tag, Cell v) {
    JnBridge *b = &g_bridge;
    jvalue a;
    switch (tag) {
        case JN_T_Z: a.z = (jboolean)(v.i & 1); return (*env)->CallStaticObjectMethodA(env, b->Boolean, b->boolVof, &a);
        case JN_T_C: a.c = (jchar)v.i;          return (*env)->CallStaticObjectMethodA(env, b->Character, b->charVof, &a);
        case JN_T_B: a.b = (jbyte)v.i;          return (*env)->CallStaticObjectMethodA(env, b->Byte, b->byteVof, &a);
        case JN_T_S: a.s = (jshort)v.i;         return (*env)->CallStaticObjectMethodA(env, b->Short, b->shortVof, &a);
        case JN_T_I: a.i = v.i;                 return (*env)->CallStaticObjectMethodA(env, b->Integer, b->intVof, &a);
        case JN_T_J: a.j = v.l;                 return (*env)->CallStaticObjectMethodA(env, b->Long, b->longVof, &a);
        case JN_T_F: a.f = v.f;                 return (*env)->CallStaticObjectMethodA(env, b->Float, b->floatVof, &a);
        case JN_T_D: a.d = v.d;                 return (*env)->CallStaticObjectMethodA(env, b->Double, b->doubleVof, &a);
        default:     return v.r;
    }
}

/* On failure leaves the pending exception set in env. */
static int jn_unbox(JNIEnv *env, jobject o, char tag, Cell *out) {
    JnBridge *b = &g_bridge;
    switch (tag) {
        case JN_T_Z: out->i = (*env)->CallBooleanMethod(env, o, b->boolVal); return 1;
        case JN_T_C: out->i = (*env)->CallCharMethod(env, o, b->charVal);    return 1;
        case JN_T_B: out->i = (*env)->CallByteMethod(env, o, b->byteVal);    return 1;
        case JN_T_S: out->i = (*env)->CallShortMethod(env, o, b->shortVal);  return 1;
        case JN_T_I: out->i = (*env)->CallIntMethod(env, o, b->intVal);      return 1;
        case JN_T_J: out->l = (*env)->CallLongMethod(env, o, b->longVal);    return 1;
        case JN_T_F: out->f = (*env)->CallFloatMethod(env, o, b->floatVal);  return 1;
        case JN_T_D: out->d = (*env)->CallDoubleMethod(env, o, b->doubleVal); return 1;
        default:     out->r = o;                                             return 1;
    }
}

static void jn_sb_append(JNIEnv *env, jobject sb, char tag, Cell v) {
    JnBridge *b = &g_bridge;
    jvalue a;
    switch (tag) {
        /* Byte and Short have no StringBuilder overloads; widening to int matches
         * String.valueOf(byte)/valueOf(short) output exactly. */
        case JN_T_B:
        case JN_T_S:
        case JN_T_I: a.i = v.i; (*env)->CallObjectMethodA(env, sb, b->apI, &a); break;
        case JN_T_Z: a.z = (jboolean)(v.i & 1); (*env)->CallObjectMethodA(env, sb, b->apZ, &a); break;
        case JN_T_C: a.c = (jchar)v.i;          (*env)->CallObjectMethodA(env, sb, b->apC, &a); break;
        case JN_T_J: a.j = v.l;                 (*env)->CallObjectMethodA(env, sb, b->apJ, &a); break;
        case JN_T_F: a.f = v.f;                 (*env)->CallObjectMethodA(env, sb, b->apF, &a); break;
        case JN_T_D: a.d = v.d;                 (*env)->CallObjectMethodA(env, sb, b->apD, &a); break;
        default:     a.l = v.r;                 (*env)->CallObjectMethodA(env, sb, b->apL, &a); break;
    }
}

static jstring jn_sb_tostr(JNIEnv *env, jobject sb) {
    return (jstring)(*env)->CallObjectMethod(env, sb, g_bridge.sbToString);
}

/* StringConcatFactory emulation: recipe '\x01' dynamic args, '\x02' constants,
 * anything else is literal text. Formatting delegates to StringBuilder.append
 * overloads so String.valueOf semantics match the JVM exactly. */
static jstring jn_concat(JNIEnv *env,
                         const char *recipe,
                         const char *statTags, const Cell *statVals,
                         const char *dynTags, Cell *dyn) {
    if (!jn_bridge_init(env)) return NULL;
    jobject sb = (*env)->NewObject(env, g_bridge.StringBuilder, g_bridge.sbInit);
    if (!sb) return NULL;
    int si = 0, di = 0;
    const unsigned char *p = (const unsigned char *) recipe;
    while (*p) {
        if (*p == 0x01) {
            p++;
            Cell v = dyn[di++];
            jn_sb_append(env, sb, dynTags[di - 1], v);
        } else if (*p == 0x02) {
            p++;
            jn_sb_append(env, sb, statTags[si], statVals[si]);
            si++;
        } else if (*p < 0x80) {
            jchar ch = (jchar) *p++;
            jstring lit = (*env)->NewString(env, &ch, 1);
            if (!lit) return NULL;
            jvalue a; a.l = lit;
            (*env)->CallObjectMethodA(env, sb, g_bridge.apL, &a);
            (*env)->DeleteLocalRef(env, lit);
        } else {
            /* Multi-byte modified-UTF-8 sequence -> single jchar. */
            jchar ch;
            unsigned char b0 = p[0];
            if ((b0 & 0xE0) == 0xC0) { ch = (jchar)(((b0 & 0x1F) << 6) | (p[1] & 0x3F)); p += 2; }
            else { ch = (jchar)(((b0 & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F)); p += 3; }
            jstring lit = (*env)->NewString(env, &ch, 1);
            if (!lit) return NULL;
            jvalue a; a.l = lit;
            (*env)->CallObjectMethodA(env, sb, g_bridge.apL, &a);
            (*env)->DeleteLocalRef(env, lit);
        }
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    return jn_sb_tostr(env, sb);
}

/* General invokedynamic fallback: delegate to the injected loader, which parses the
 * host class's retained BootstrapMethods attribute and executes the real BSM. */
static jobject jn_call_bsm(JNIEnv *env, jclass host, jint bsmIndex,
                           jstring name, jstring mtypeDesc, jobjectArray dynArgs) {
    if (!jn_bridge_init(env)) return NULL;
    jvalue args[5];
    args[0].l = host;
    args[1].i = bsmIndex;
    args[2].l = name;
    args[3].l = mtypeDesc;
    args[4].l = dynArgs;
    return (*env)->CallStaticObjectMethodA(env, g_bridge.Loader, g_bridge.boot, args);
}

static jobject jn_mh_invoke(JNIEnv *env, jobject mh, jobjectArray args) {
    if (!jn_bridge_init(env)) return NULL;
    jvalue a[2];
    a[0].l = mh;
    a[1].l = args;
    return (*env)->CallStaticObjectMethodA(env, g_bridge.Loader, g_bridge.mhInvoke, a);
}

static jobject jn_vh_op(JNIEnv *env, jobject vh, jint op, jobjectArray args) {
    if (!jn_bridge_init(env)) return NULL;
    jvalue a[3];
    a[0].l = vh;
    a[1].i = op;
    a[2].l = args;
    return (*env)->CallStaticObjectMethodA(env, g_bridge.Loader, g_bridge.vhOp, a);
}

#endif /* JNIC_PREAMBLE_H */

