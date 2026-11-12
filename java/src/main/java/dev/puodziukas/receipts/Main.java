package dev.puodziukas.receipts;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * CLI. {@code verify <receipts>} exits 0 when the chain is intact and 1 when it is broken;
 * {@code root <receipts>} prints the Merkle root over the lines of the file. Exit 2 is a usage
 * or input error (bad arguments, unreadable file, TRACE_KEY missing or shorter than 16 bytes).
 */
public final class Main {
    static final int MIN_KEY_LEN = 16;

    private Main() {}

    public static void main(String[] args) {
        System.exit(run(args, System.getenv(), System.out, System.err));
    }

    static int run(String[] args, Map<String, String> env, PrintStream out, PrintStream err) {
        if (args.length != 2 || !(args[0].equals("verify") || args[0].equals("root"))) {
            err.println("usage: verify <receipts> | root <receipts>   (verify needs TRACE_KEY in the environment)");
            return 2;
        }
        Path file = Path.of(args[1]);
        try {
            if (args[0].equals("verify")) {
                String raw = env.get("TRACE_KEY");
                if (raw == null || raw.getBytes(StandardCharsets.UTF_8).length < MIN_KEY_LEN) {
                    err.println("TRACE_KEY must be set to a secret of at least " + MIN_KEY_LEN + " characters");
                    return 2;
                }
                ChainVerifier.Result r = ChainVerifier.verify(file, raw.getBytes(StandardCharsets.UTF_8));
                if (r.ok()) {
                    out.println("OK " + r.records() + " records");
                    return 0;
                }
                out.println("BROKEN at record " + r.brokenIndex() + ": " + r.message());
                return 1;
            }
            List<byte[]> leaves = ChainVerifier.splitLines(Files.readAllBytes(file));
            if (leaves.isEmpty()) {
                err.println("no records in file");
                return 1;
            }
            out.println(HexFormat.of().formatHex(MerkleLog.root(leaves)));
            return 0;
        } catch (IOException e) {
            err.println("cannot read " + file + ": " + e.getMessage());
            return 2;
        }
    }
}
