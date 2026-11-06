package dev.puodziukas.receipts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {

    /** Root of the fixture lines; printed by `python3 java/tools/merkle_ref.py root <fixture>`. */
    private static final String FIXTURE_ROOT = "0da19886f3d881192475c4a6640230b1858061a0c62e87d34e440edf5cebf19a";
    private static final Map<String, String> ENV = Map.of("TRACE_KEY", "demo-key-not-secret-0");

    @TempDir Path dir;

    private record Run(int code, String out, String err) {}

    private static Run run(Map<String, String> env, String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = Main.run(args, env, new PrintStream(o, true, StandardCharsets.UTF_8),
                new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Run(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    @Test
    void verifyCleanFixtureExitsZero() throws IOException {
        Path p = Fixtures.copyTo(dir);
        Run r = run(ENV, "verify", p.toString());
        assertEquals(0, r.code(), r.err());
        assertTrue(r.out().startsWith("OK"), r.out());
    }

    @Test
    void verifyTamperedFixtureExitsOneAndNamesTheIndex() throws IOException {
        Path p = Fixtures.copyTo(dir);
        List<String> lines = Fixtures.lines(p);
        lines.remove(1);
        Fixtures.writeLines(p, lines);
        Run r = run(ENV, "verify", p.toString());
        assertEquals(1, r.code());
        assertTrue(r.out().contains("BROKEN at record 1"), r.out());
    }

    @Test
    void rootPrintsTheMerkleRootOfTheLines() throws IOException {
        Path p = Fixtures.copyTo(dir);
        Run r = run(ENV, "root", p.toString());
        assertEquals(0, r.code(), r.err());
        assertEquals(FIXTURE_ROOT, r.out().trim());
    }

    @Test
    void usageErrorsExitTwo() throws IOException {
        Path p = Fixtures.copyTo(dir);
        assertEquals(2, run(ENV).code());
        assertEquals(2, run(ENV, "verify").code());
        assertEquals(2, run(ENV, "frobnicate", p.toString()).code());
        assertEquals(2, run(ENV, "verify", p.toString(), "extra").code());
        assertEquals(2, run(Map.of(), "verify", p.toString()).code());
        assertEquals(2, run(Map.of("TRACE_KEY", "short"), "verify", p.toString()).code());
        assertEquals(2, run(ENV, "verify", dir.resolve("absent.jsonl").toString()).code());
    }

    @Test
    void rootOfEmptyFileIsAnErrorNotTheEmptyTreeRoot() throws IOException {
        Path p = dir.resolve("empty.jsonl");
        Files.write(p, new byte[0]);
        Run r = run(ENV, "root", p.toString());
        assertEquals(1, r.code());
    }
}
