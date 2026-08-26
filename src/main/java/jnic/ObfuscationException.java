package jnic;

/** Fatal, user-facing obfuscation failure with a clear message. */
public class ObfuscationException extends RuntimeException {
    public ObfuscationException(String message) { super(message); }
    public ObfuscationException(String message, Throwable cause) { super(message, cause); }
}
