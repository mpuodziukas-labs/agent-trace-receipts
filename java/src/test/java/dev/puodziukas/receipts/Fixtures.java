package dev.puodziukas.receipts;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Test helpers: the committed fixture was written by the Python recorder with the demo key. */
final class Fixtures {
    static final String NAME = "run-INV-1001.jsonl";
    static final byte[] KEY = "demo-key-not-secret-0".getBytes(StandardCharsets.UTF_8);

    private Fixtures() {}

    /** Copies the fixture and its head file into dir and returns the receipts path. */
    static Path copyTo(Path dir) throws IOException {
        for (String n : new String[] {NAME, NAME + ".head"}) {
            try (InputStream in = Fixtures.class.getResourceAsStream("/fixtures/" + n)) {
                if (in == null) {
                    throw new IOException("missing test resource " + n);
                }
                Files.write(dir.resolve(n), in.readAllBytes());
            }
        }
        return dir.resolve(NAME);
    }

    static List<String> lines(Path p) throws IOException {
        List<String> out = new ArrayList<>(Files.readAllLines(p, StandardCharsets.UTF_8));
        return out;
    }

    static void writeLines(Path p, List<String> lines) throws IOException {
        Files.writeString(p, String.join("\n", lines) + "\n", StandardCharsets.UTF_8);
    }
}
