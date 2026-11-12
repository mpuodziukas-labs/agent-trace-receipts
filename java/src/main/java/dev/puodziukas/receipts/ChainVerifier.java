package dev.puodziukas.receipts;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Recomputes the keyed hash chain that trace.py writes. Record i carries in prev_hash the
 * HMAC-SHA256 (hex) of the raw bytes of line i-1 under TRACE_KEY; record 0 carries 64 zeros.
 * The sidecar "&lt;file&gt;.head" anchors the record count and the last line with its own
 * domain-separated MAC, so dropping the final record is caught too.
 *
 * <p>This checks the chain and the head anchor. It does not replay tools against data.
 */
public final class ChainVerifier {
    static final String GENESIS = "0".repeat(64);

    /** brokenIndex is the first bad record (0-based), or -1 when ok. */
    public record Result(boolean ok, int brokenIndex, int records, String message) {}

    private ChainVerifier() {}

    public static Result verify(Path receipts, byte[] key) throws IOException {
        List<byte[]> raw = splitLines(Files.readAllBytes(receipts));
        if (raw.isEmpty()) {
            return new Result(false, 0, 0, "no records in file");
        }
        List<Map<String, Object>> recs = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            Map<String, Object> rec = parseRecord(raw.get(i));
            if (rec == null) {
                return new Result(false, i, raw.size(), "record is not a valid JSON object");
            }
            recs.add(rec);
        }
        String expected = GENESIS;
        for (int i = 0; i < raw.size(); i++) {
            Object got = recs.get(i).get("prev_hash");
            if (!(got instanceof String g) || !MessageDigest.isEqual(ascii(g), ascii(expected))) {
                return new Result(false, i, raw.size(),
                        "hash chain broken (edited, deleted, reordered, or wrong TRACE_KEY)");
            }
            expected = HexFormat.of().formatHex(hmac(key, raw.get(i)));
        }
        return checkHead(receipts, key, raw, recs);
    }

    private static Result checkHead(Path receipts, byte[] key, List<byte[]> raw, List<Map<String, Object>> recs)
            throws IOException {
        int len = raw.size();
        Path hp = receipts.resolveSibling(receipts.getFileName() + ".head");
        if (!Files.isRegularFile(hp)) {
            return new Result(false, len - 1, len, "head anchor missing");
        }
        Map<String, Object> head;
        try {
            Object o = Json.parse(new String(Files.readAllBytes(hp), StandardCharsets.UTF_8));
            head = o instanceof Map<?, ?> ? castMap(o) : null;
        } catch (IllegalArgumentException e) {
            head = null;
        }
        Object runId = recs.get(0).get("run_id");
        if (head == null || !head.keySet().equals(java.util.Set.of("run_id", "steps", "last_hash", "mac"))
                || !(head.get("steps") instanceof Long n) || !(head.get("mac") instanceof String mac)
                || !(head.get("last_hash") instanceof String last) || !(runId instanceof String rid)) {
            return new Result(false, len - 1, len, "head anchor unreadable");
        }
        byte[] lastLine = raw.get(len - 1);
        if (n == len - 1L && eq(mac, headMac(key, rid, n, n == 0 ? new byte[0] : raw.get((int) (n - 1))))) {
            return new Result(false, len - 1, len, "head anchor is one line behind: incomplete run or an appended record");
        }
        if (n != len) {
            return new Result(false, (int) Math.max(0, Math.min(n, len)), len,
                    "head anchor step count " + n + " != " + len + " records");
        }
        if (!eq(last, HexFormat.of().formatHex(hmac(key, lastLine)))) {
            return new Result(false, len - 1, len, "head anchor last hash mismatch");
        }
        if (!head.get("run_id").equals(rid)) {
            return new Result(false, 0, len, "head anchor run_id differs from the trace");
        }
        if (!eq(mac, headMac(key, rid, len, lastLine))) {
            return new Result(false, len - 1, len, "head anchor signature mismatch");
        }
        return new Result(true, -1, len, "ok");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    private static Map<String, Object> parseRecord(byte[] line) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(line)).toString();
            Object o = Json.parse(text);
            return o instanceof Map<?, ?> ? castMap(o) : null;
        } catch (CharacterCodingException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Lines split on LF, without the terminator; one final terminator does not add an empty line. */
    static List<byte[]> splitLines(byte[] all) {
        List<byte[]> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < all.length; i++) {
            if (all[i] == '\n') {
                out.add(java.util.Arrays.copyOfRange(all, start, i));
                start = i + 1;
            }
        }
        if (start < all.length) {
            out.add(java.util.Arrays.copyOfRange(all, start, all.length));
        }
        return out;
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    /** HMAC(key, "head\0" + run_id + "\0" + steps + "\0" + last_line), hex, as trace.head_mac. */
    private static String headMac(byte[] key, String runId, long steps, byte[] lastLine) {
        byte[] pre = ("head\0" + runId + "\0" + steps + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[pre.length + lastLine.length];
        System.arraycopy(pre, 0, msg, 0, pre.length);
        System.arraycopy(lastLine, 0, msg, pre.length, lastLine.length);
        return HexFormat.of().formatHex(hmac(key, msg));
    }

    private static boolean eq(String a, String b) {
        return MessageDigest.isEqual(ascii(a), ascii(b));
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
