package jnic.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Reads and writes JAR files, preserving entry order and the manifest. */
public final class JarIO {

    public static final class Entry {
        public final String name;
        public final byte[] data;

        public Entry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    /** Reads all entries in order. Duplicate entry names are rejected. */
    public static Map<String, byte[]> read(Path jar) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipInputStream zin = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                if (entries.putIfAbsent(e.getName(), readAll(zin)) != null)
                    throw new IOException("duplicate jar entry: " + e.getName());
            }
        }
        if (!entries.containsKey("META-INF/MANIFEST.MF"))
            throw new IOException("not a jar (missing META-INF/MANIFEST.MF): " + jar);
        return entries;
    }

    /** Writes entries in iteration order; a missing manifest is synthesized. */
    public static void write(Path out, Map<String, byte[]> entries) throws IOException {
        Path parent = out.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (ZipOutputStream zout = new ZipOutputStream(Files.newOutputStream(out))) {
            byte[] manifest = entries.get("META-INF/MANIFEST.MF");
            if (manifest == null) manifest = "Manifest-Version: 1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8);
            put(zout, "META-INF/MANIFEST.MF", manifest);
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                if (e.getKey().equals("META-INF/MANIFEST.MF")) continue;
                put(zout, e.getKey(), e.getValue());
            }
        }
    }

    private static void put(ZipOutputStream zout, String name, byte[] data) throws IOException {
        ZipEntry e = new ZipEntry(name);
        e.setTime(0L); // reproducible output
        zout.putNextEntry(e);
        zout.write(data);
        zout.closeEntry();
    }

    private static byte[] readAll(ZipInputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[16384];
        int n;
        while ((n = in.read(tmp)) > 0) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }

    private JarIO() {}
}
