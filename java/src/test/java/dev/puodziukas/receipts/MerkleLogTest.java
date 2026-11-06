package dev.puodziukas.receipts;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class MerkleLogTest {

    private static final HexFormat HEX = HexFormat.of();

    /** Same inputs and roots as java/tools/merkle_ref.py vectors (computed by that script). */
    private static final String[] VECTOR_LEAVES = {
        "", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"
    };
    private static final String[] VECTOR_ROOTS = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    };

    private static byte[] sha(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] leaf(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static List<byte[]> leaves(int n) {
        List<byte[]> l = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            l.add(leaf("leaf-" + i));
        }
        return l;
    }

    /** Test-local bottom-up root: independent of the recursive split in MerkleLog. */
    private static byte[] bottomUpRoot(List<byte[]> data) {
        if (data.isEmpty()) {
            return sha();
        }
        List<byte[]> level = new ArrayList<>();
        for (byte[] d : data) {
            level.add(sha(new byte[] {0}, d));
        }
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>();
            for (int i = 0; i + 1 < level.size(); i += 2) {
                next.add(sha(new byte[] {1}, level.get(i), level.get(i + 1)));
            }
            if (level.size() % 2 == 1) {
                next.add(level.get(level.size() - 1));
            }
            level = next;
        }
        return level.get(0);
    }

    private static byte[] flip(byte[] b, int bit) {
        byte[] c = b.clone();
        c[(bit / 8) % c.length] ^= (byte) (1 << (bit % 8));
        return c;
    }

    // ---- hashes and roots ----

    @Test
    void emptyTreeRootIsSha256OfEmptyString() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HEX.formatHex(MerkleLog.root(List.of())));
    }

    @Test
    void leafAndNodeHashesUseDomainPrefixes() {
        byte[] a = leaf("a");
        byte[] b = leaf("b");
        assertArrayEquals(sha(new byte[] {0}, a), MerkleLog.hashLeaf(a));
        assertArrayEquals(sha(new byte[] {1}, a, b), MerkleLog.hashChildren(a, b));
        assertFalse(java.util.Arrays.equals(MerkleLog.hashLeaf(a), sha(a)));
    }

    @Test
    void knownSmallTreeRoots() {
        for (int n = 0; n <= 8; n++) {
            List<byte[]> l = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                l.add(HEX.parseHex(VECTOR_LEAVES[i]));
            }
            assertEquals(VECTOR_ROOTS[n], HEX.formatHex(MerkleLog.root(l)), "n=" + n);
        }
    }

    @Test
    void rootMatchesBottomUpReferenceUpTo130Leaves() {
        for (int n = 0; n <= 130; n++) {
            assertArrayEquals(bottomUpRoot(leaves(n)), MerkleLog.root(leaves(n)), "n=" + n);
        }
    }

    // ---- structural examples from RFC 6962 section 2.1.3 and 2.1.4 (seven leaves) ----

    @Test
    void rfcShapedProofsForSevenLeaves() {
        List<byte[]> d = leaves(7);
        byte[][] h = new byte[7][];
        for (int i = 0; i < 7; i++) {
            h[i] = MerkleLog.hashLeaf(d.get(i));
        }
        byte[] ab = MerkleLog.hashChildren(h[0], h[1]);
        byte[] cd = MerkleLog.hashChildren(h[2], h[3]);
        byte[] ef = MerkleLog.hashChildren(h[4], h[5]);
        byte[] efg = MerkleLog.hashChildren(ef, h[6]);
        // PATH(0, D[7]) = [h(d1), h(d2,d3), h(h(d4,d5),d6)]
        List<byte[]> p0 = MerkleLog.inclusionProof(0, d);
        assertEquals(3, p0.size());
        assertArrayEquals(h[1], p0.get(0));
        assertArrayEquals(cd, p0.get(1));
        assertArrayEquals(efg, p0.get(2));
        // PATH(6, D[7]) = [h(h(d4,d5)), h(h(d0,d1),h(d2,d3))]
        List<byte[]> p6 = MerkleLog.inclusionProof(6, d);
        assertEquals(2, p6.size());
        assertArrayEquals(ef, p6.get(0));
        assertArrayEquals(MerkleLog.hashChildren(ab, cd), p6.get(1));
        // PROOF(3, D[7]) = [h(d2), h(d3), h(d0,d1), h(h(d4,d5),d6)]
        List<byte[]> c3 = MerkleLog.consistencyProof(3, d);
        assertEquals(4, c3.size());
        assertArrayEquals(h[2], c3.get(0));
        assertArrayEquals(h[3], c3.get(1));
        assertArrayEquals(ab, c3.get(2));
        assertArrayEquals(efg, c3.get(3));
        // PROOF(4, D[7]) = [h(h(h(d4,d5),d6))] : the node over d4..d6 only
        List<byte[]> c4 = MerkleLog.consistencyProof(4, d);
        assertEquals(1, c4.size());
        assertArrayEquals(efg, c4.get(0));
    }

    // ---- inclusion ----

    @Test
    void everyInclusionProofForSizes1To64Verifies() {
        int checked = 0;
        for (int n = 1; n <= 64; n++) {
            List<byte[]> d = leaves(n);
            byte[] root = MerkleLog.root(d);
            for (int i = 0; i < n; i++) {
                List<byte[]> proof = MerkleLog.inclusionProof(i, d);
                assertTrue(MerkleLog.verifyInclusion(d.get(i), i, n, proof, root), "n=" + n + " i=" + i);
                checked++;
            }
        }
        assertEquals(64 * 65 / 2, checked);
    }

    @Test
    void everyInclusionProofWithOneBitFlippedFails() {
        int flips = 0;
        for (int n = 1; n <= 64; n++) {
            List<byte[]> d = leaves(n);
            byte[] root = MerkleLog.root(d);
            for (int i = 0; i < n; i++) {
                List<byte[]> proof = MerkleLog.inclusionProof(i, d);
                for (int e = 0; e < proof.size(); e++) {
                    int bits = n <= 8 ? 256 : 8;
                    for (int k = 0; k < bits; k++) {
                        int bit = n <= 8 ? k : (k * 32 + e * 5 + i) % 256;
                        List<byte[]> bad = new ArrayList<>(proof);
                        bad.set(e, flip(proof.get(e), bit));
                        assertFalse(MerkleLog.verifyInclusion(d.get(i), i, n, bad, root),
                                "n=" + n + " i=" + i + " e=" + e + " bit=" + bit);
                        flips++;
                    }
                }
                // a flipped bit in the leaf or in the root fails too
                assertFalse(MerkleLog.verifyInclusion(flip(d.get(i), 3), i, n, proof, root));
                assertFalse(MerkleLog.verifyInclusion(d.get(i), i, n, proof, flip(root, (i * 11) % 256)));
            }
        }
        assertTrue(flips > 10000);
    }

    @Test
    void inclusionProofWithWrongShapeFails() {
        List<byte[]> d = leaves(13);
        byte[] root = MerkleLog.root(d);
        List<byte[]> proof = MerkleLog.inclusionProof(5, d);
        assertTrue(MerkleLog.verifyInclusion(d.get(5), 5, 13, proof, root));
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 6, 13, proof, root));
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 5, 100, proof, root)); // size is bound by the proof shape and the root
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 13, 13, proof, root));
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 5, 13, proof.subList(0, proof.size() - 1), root));
        List<byte[]> longer = new ArrayList<>(proof);
        longer.add(new byte[32]);
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 5, 13, longer, root));
        assertFalse(MerkleLog.verifyInclusion(d.get(5), 5, 13, List.of(), root));
    }

    @Test
    void singleLeafTreeHasEmptyProof() {
        List<byte[]> d = leaves(1);
        assertTrue(MerkleLog.inclusionProof(0, d).isEmpty());
        assertTrue(MerkleLog.verifyInclusion(d.get(0), 0, 1, List.of(), MerkleLog.root(d)));
    }

    @Test
    void proofRequestsOutOfRangeAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> MerkleLog.inclusionProof(3, leaves(3)));
        assertThrows(IllegalArgumentException.class, () -> MerkleLog.inclusionProof(-1, leaves(3)));
        assertThrows(IllegalArgumentException.class, () -> MerkleLog.consistencyProof(0, leaves(3)));
        assertThrows(IllegalArgumentException.class, () -> MerkleLog.consistencyProof(4, leaves(3)));
    }

    // ---- consistency ----

    @Test
    void everyConsistencyProofForSizes1To64Verifies() {
        int checked = 0;
        for (int n = 1; n <= 64; n++) {
            List<byte[]> d = leaves(n);
            byte[] second = MerkleLog.root(d);
            for (int m = 1; m <= n; m++) {
                byte[] first = MerkleLog.root(d.subList(0, m));
                List<byte[]> proof = MerkleLog.consistencyProof(m, d);
                assertTrue(MerkleLog.verifyConsistency(m, n, first, second, proof), "m=" + m + " n=" + n);
                if (m == n) {
                    assertTrue(proof.isEmpty());
                }
                checked++;
            }
        }
        assertEquals(64 * 65 / 2, checked);
    }

    @Test
    void everyConsistencyProofWithOneBitFlippedFails() {
        int flips = 0;
        for (int n = 1; n <= 64; n++) {
            List<byte[]> d = leaves(n);
            byte[] second = MerkleLog.root(d);
            for (int m = 1; m <= n; m++) {
                byte[] first = MerkleLog.root(d.subList(0, m));
                List<byte[]> proof = MerkleLog.consistencyProof(m, d);
                for (int e = 0; e < proof.size(); e++) {
                    int bits = n <= 8 ? 256 : 8;
                    for (int k = 0; k < bits; k++) {
                        int bit = n <= 8 ? k : (k * 32 + e * 7 + m) % 256;
                        List<byte[]> bad = new ArrayList<>(proof);
                        bad.set(e, flip(proof.get(e), bit));
                        assertFalse(MerkleLog.verifyConsistency(m, n, first, second, bad),
                                "m=" + m + " n=" + n + " e=" + e + " bit=" + bit);
                        flips++;
                    }
                }
                assertFalse(MerkleLog.verifyConsistency(m, n, flip(first, m), second, proof));
                assertFalse(MerkleLog.verifyConsistency(m, n, first, flip(second, n), proof));
            }
        }
        assertTrue(flips > 10000);
    }

    @Test
    void consistencyProofWithWrongShapeFails() {
        List<byte[]> d = leaves(21);
        byte[] second = MerkleLog.root(d);
        byte[] first = MerkleLog.root(d.subList(0, 6));
        List<byte[]> proof = MerkleLog.consistencyProof(6, d);
        assertTrue(MerkleLog.verifyConsistency(6, 21, first, second, proof));
        assertFalse(MerkleLog.verifyConsistency(7, 21, first, second, proof));
        assertFalse(MerkleLog.verifyConsistency(6, 100, first, second, proof));
        assertFalse(MerkleLog.verifyConsistency(0, 21, first, second, proof));
        assertFalse(MerkleLog.verifyConsistency(22, 21, first, second, proof));
        assertFalse(MerkleLog.verifyConsistency(6, 21, first, second, proof.subList(0, proof.size() - 1)));
        List<byte[]> longer = new ArrayList<>(proof);
        longer.add(new byte[32]);
        assertFalse(MerkleLog.verifyConsistency(6, 21, first, second, longer));
        assertFalse(MerkleLog.verifyConsistency(6, 21, first, second, List.of()));
        // equal sizes need an empty proof and equal roots
        assertFalse(MerkleLog.verifyConsistency(21, 21, second, second, proof));
        assertFalse(MerkleLog.verifyConsistency(21, 21, first, second, List.of()));
    }

    @Test
    void consistencyRejectsAHistoryThatWasRewritten() {
        List<byte[]> d = leaves(30);
        List<byte[]> rewritten = new ArrayList<>(d);
        rewritten.set(2, leaf("rewritten"));
        byte[] oldRoot = MerkleLog.root(d.subList(0, 10));
        byte[] newRoot = MerkleLog.root(rewritten);
        assertFalse(MerkleLog.verifyConsistency(10, 30, oldRoot, newRoot, MerkleLog.consistencyProof(10, rewritten)));
    }

    // ---- property-style loop, fixed seed ----

    @Test
    void randomTreesWithFixedSeed() {
        Random rnd = new Random(0x6962L);
        for (int iter = 0; iter < 300; iter++) {
            int n = 1 + rnd.nextInt(400);
            List<byte[]> d = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                byte[] x = new byte[rnd.nextInt(40)];
                rnd.nextBytes(x);
                d.add(x);
            }
            byte[] root = MerkleLog.root(d);
            assertArrayEquals(bottomUpRoot(d), root, "iter " + iter);

            int i = rnd.nextInt(n);
            List<byte[]> ip = MerkleLog.inclusionProof(i, d);
            assertTrue(MerkleLog.verifyInclusion(d.get(i), i, n, ip, root), "incl iter " + iter);
            if (!ip.isEmpty()) {
                List<byte[]> bad = new ArrayList<>(ip);
                int e = rnd.nextInt(bad.size());
                bad.set(e, flip(bad.get(e), rnd.nextInt(256)));
                assertFalse(MerkleLog.verifyInclusion(d.get(i), i, n, bad, root), "incl flip iter " + iter);
            }

            int m = 1 + rnd.nextInt(n);
            byte[] first = bottomUpRoot(d.subList(0, m));
            List<byte[]> cp = MerkleLog.consistencyProof(m, d);
            assertTrue(MerkleLog.verifyConsistency(m, n, first, root, cp), "cons iter " + iter);
            if (!cp.isEmpty()) {
                List<byte[]> bad = new ArrayList<>(cp);
                int e = rnd.nextInt(bad.size());
                bad.set(e, flip(bad.get(e), rnd.nextInt(256)));
                assertFalse(MerkleLog.verifyConsistency(m, n, first, root, bad), "cons flip iter " + iter);
            }
        }
    }
}
