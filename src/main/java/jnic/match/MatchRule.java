package jnic.match;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A single {@code <match>} rule. All attributes are regular expressions;
 * an omitted attribute matches everything.
 */
public final class MatchRule {
    private final Pattern className;
    private final Pattern methodName;
    private final Pattern methodDesc;

    public MatchRule(String className, String methodName, String methodDesc) {
        try {
            this.className = className == null ? null : Pattern.compile(className);
            this.methodName = methodName == null ? null : Pattern.compile(methodName);
            this.methodDesc = methodDesc == null ? null : Pattern.compile(methodDesc);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("invalid regex in <match>: " + e.getMessage(), e);
        }
    }

    public boolean matches(String className, String methodName, String methodDesc) {
        return (this.className == null || this.className.matcher(className).matches())
            && (this.methodName == null || this.methodName.matcher(methodName).matches())
            && (this.methodDesc == null || this.methodDesc.matcher(methodDesc).matches());
    }

    @Override
    public String toString() {
        return "<match class=" + className + " method=" + methodName + " desc=" + methodDesc + ">";
    }
}
