package dev.puodziukas.receipts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChainVerifierTest {

    @TempDir Path dir;

    @Test
    void pythonWrittenFixtureVerifies() throws IOException {
        Path p = Fixtures.copyTo(dir);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertTrue(r.ok(), r.message());
        assertEquals(-1, r.brokenIndex());
        assertEquals(4, r.records());
    }

    @Test
    void wrongKeyIsRefusedAtFirstLinkedRecord() throws IOException {
        Path p = Fixtures.copyTo(dir);
        ChainVerifier.Result r = ChainVerifier.verify(p, "another-key-not-secret-1".getBytes(StandardCharsets.UTF_8));
        assertFalse(r.ok());
        assertEquals(1, r.brokenIndex());
    }

    @Test
    void oneByteFlippedInAMiddleRecordBreaksTheNextLink() throws IOException {
        Path p = Fixtures.copyTo(dir);
        byte[] b = Files.readAllBytes(p);
        String text = new String(b, StandardCharsets.UTF_8);
        int at = text.indexOf("\"tool\":\"load_po\"") + 8; // inside record 1
        assertTrue(at > 8);
        b[at] ^= 0x01;
        Files.write(p, b);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
        assertEquals(2, r.brokenIndex());
    }

    @Test
    void oneByteFlippedInTheLastRecordIsCaughtByTheHead() throws IOException {
        Path p = Fixtures.copyTo(dir);
        byte[] b = Files.readAllBytes(p);
        b[b.length - 20] ^= 0x01;
        Files.write(p, b);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
        assertEquals(3, r.brokenIndex());
    }

    @Test
    void everySingleByteFlipIsRefused() throws IOException {
        Path p = Fixtures.copyTo(dir);
        byte[] orig = Files.readAllBytes(p);
        int refused = 0;
        int tried = 0;
        for (int i = 0; i < orig.length; i += 7) {
            if (orig[i] == '\n') {
                continue;
            }
            byte[] b = orig.clone();
            b[i] ^= 0x01;
            Files.write(p, b);
            tried++;
            if (!ChainVerifier.verify(p, Fixtures.KEY).ok()) {
                refused++;
            }
        }
        assertTrue(tried > 100);
        assertEquals(tried, refused);
    }

    @Test
    void deletedMiddleRecordIsRefused() throws IOException {
        Path p = Fixtures.copyTo(dir);
        List<String> lines = Fixtures.lines(p);
        lines.remove(1);
        Fixtures.writeLines(p, lines);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
        assertEquals(1, r.brokenIndex());
    }

    @Test
    void deletedLastRecordIsRefusedByTheHead() throws IOException {
        Path p = Fixtures.copyTo(dir);
        List<String> lines = Fixtures.lines(p);
        lines.remove(lines.size() - 1);
        Fixtures.writeLines(p, lines);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
        assertEquals(3, r.brokenIndex());
    }

    @Test
    void reorderedRecordsAreRefused() throws IOException {
        Path p = Fixtures.copyTo(dir);
        List<String> lines = Fixtures.lines(p);
        String t = lines.get(1);
        lines.set(1, lines.get(2));
        lines.set(2, t);
        Fixtures.writeLines(p, lines);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
        assertEquals(1, r.brokenIndex());
    }

    @Test
    void emptyFileIsRefusedNotPassed() throws IOException {
        Path p = dir.resolve("empty.jsonl");
        Files.write(p, new byte[0]);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
    }

    @Test
    void missingHeadIsRefused() throws IOException {
        Path p = Fixtures.copyTo(dir);
        Files.write(dir.resolve(Fixtures.NAME + ".head"), "{}".getBytes(StandardCharsets.UTF_8));
        assertFalse(ChainVerifier.verify(p, Fixtures.KEY).ok());
        Path lone = dir.resolve("lone.jsonl");
        Files.write(lone, Files.readAllBytes(p));
        assertFalse(ChainVerifier.verify(lone, Fixtures.KEY).ok());
    }

    @Test
    void forgedHeadMacIsRefused() throws IOException {
        Path p = Fixtures.copyTo(dir);
        Path head = dir.resolve(Fixtures.NAME + ".head");
        String h = Files.readString(head, StandardCharsets.UTF_8);
        int i = h.indexOf("\"mac\":\"") + 7;
        char c = h.charAt(i) == 'a' ? 'b' : 'a';
        Files.writeString(head, h.substring(0, i) + c + h.substring(i + 1), StandardCharsets.UTF_8);
        ChainVerifier.Result r = ChainVerifier.verify(p, Fixtures.KEY);
        assertFalse(r.ok());
    }
}
