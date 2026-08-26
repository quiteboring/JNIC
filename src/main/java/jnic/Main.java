package jnic;

import jnic.compile.ZigDriver;
import jnic.io.JarIO;
import jnic.match.Matcher;
import jnic.select.Selector;
import jnic.transform.Nativizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * CLI entry point.
 *
 * Usage: java -jar jnic.jar &lt;input.jar&gt; &lt;output.jar&gt; &lt;config.xml&gt;
 */
public final class Main {
    public static void main(String[] args) {
        try {
            run(args);
        } catch (UsageException e) {
            System.err.println("Usage: java -jar jnic.jar <input.jar> <output.jar> <config.xml>");
            System.err.println(e.getMessage());
            System.exit(2);
        } catch (ObfuscationException e) {
            System.err.println("error: " + e.getMessage());
            if (e.getCause() != null) e.getCause().printStackTrace(System.err);
            System.exit(1);
        } catch (Exception e) {
            System.err.println("internal error: " + e);
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length != 3) throw new UsageException("expected exactly 3 arguments, got " + args.length);
        Path in = Path.of(args[0]);
        Path out = Path.of(args[1]);
        Path cfgPath = Path.of(args[2]);
        if (!Files.isRegularFile(in)) throw new UsageException("input jar not found: " + in);
        if (!Files.isRegularFile(cfgPath)) throw new UsageException("config not found: " + cfgPath);

        Config config = Config.parse(cfgPath);
        ZigDriver zig = ZigDriver.locate();
        System.out.println("[jnic] using zig " + zig.version() + " at " + zig.executable());

        long t0 = System.currentTimeMillis();
        Pipeline.run(in, out, config, zig);
        System.out.println("[jnic] done in " + ((System.currentTimeMillis() - t0) / 1000.0) + "s -> " + out);
    }

    private Main() {}

    private static final class UsageException extends ObfuscationException {
        UsageException(String m) { super(m); }
    }
}
