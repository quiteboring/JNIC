package jnic.match;

import jnic.Config;

import java.util.List;

/**
 * Applies include/exclude match rules plus annotation gates to decide whether a method
 * is nativized. Annotation rules override plain match tags, mirroring documented JNIC
 * behavior: a class or method carrying the excludeAnnotation is never nativized; when
 * includeAnnotation is set, only carriers are considered at all.
 */
public final class Matcher {

    private final Config config;

    public Matcher(Config config) {
        this.config = config;
    }

    /**
     * @param className        internal name
     * @param methodName       method name
     * @param methodDesc       method descriptor
     * @param classAnnotations internal names of runtime-visible class annotations
     * @param methodAnnotations internal names of runtime-visible method annotations
     */
    public boolean selects(String className, String methodName, String methodDesc,
                           List<String> classAnnotations, List<String> methodAnnotations) {
        String incAnn = config.includeAnnotation;
        if (incAnn != null
            && !classAnnotations.contains(incAnn)
            && !methodAnnotations.contains(incAnn)) return false;
        String excAnn = config.excludeAnnotation;
        if (excAnn != null
            && (classAnnotations.contains(excAnn) || methodAnnotations.contains(excAnn))) return false;
        for (MatchRule r : config.exclude)
            if (r.matches(className, methodName, methodDesc)) return false;
        if (config.include.isEmpty()) return true;
        for (MatchRule r : config.include)
            if (r.matches(className, methodName, methodDesc)) return true;
        return false;
    }
}
