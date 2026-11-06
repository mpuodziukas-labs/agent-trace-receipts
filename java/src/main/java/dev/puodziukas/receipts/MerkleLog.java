package dev.puodziukas.receipts;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Merkle tree hash, inclusion proofs and consistency proofs as defined in RFC 6962 section 2.1
 * and verified with the algorithms of RFC 9162 section 2.1.
 */
public final class MerkleLog {
    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

    private MerkleLog() {}

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-256(0x00 || leaf). */
    public static byte[] hashLeaf(byte[] leaf) {
        MessageDigest md = sha256();
        md.update(LEAF_PREFIX);
        return md.digest(leaf);
    }

    /** SHA-256(0x01 || left || right). */
    public static byte[] hashChildren(byte[] left, byte[] right) {
        MessageDigest md = sha256();
        md.update(NODE_PREFIX);
        md.update(left);
        return md.digest(right);
    }

    /** Merkle tree hash of the leaves; the empty tree hashes to SHA-256 of the empty string. */
    public static byte[] root(List<byte[]> leaves) {
        if (leaves.isEmpty()) {
            return sha256().digest();
        }
        return mth(leaves, 0, leaves.size());
    }

    /** Largest power of two strictly less than n, for n >= 2. */
    private static int split(int n) {
        return Integer.highestOneBit(n - 1);
    }

    private static byte[] mth(List<byte[]> d, int lo, int hi) {
        if (hi - lo == 1) {
            return hashLeaf(d.get(lo));
        }
        int k = split(hi - lo);
        return hashChildren(mth(d, lo, lo + k), mth(d, lo + k, hi));
    }

    /** Audit path for the leaf at index (RFC 6962 PATH). */
    public static List<byte[]> inclusionProof(int index, List<byte[]> leaves) {
        if (index < 0 || index >= leaves.size()) {
            throw new IllegalArgumentException("leaf index " + index + " outside tree of " + leaves.size());
        }
        List<byte[]> out = new ArrayList<>();
        path(index, leaves, 0, leaves.size(), out);
        return out;
    }

    private static void path(int m, List<byte[]> d, int lo, int hi, List<byte[]> out) {
        if (hi - lo == 1) {
            return;
        }
        int k = split(hi - lo);
        if (m < k) {
            path(m, d, lo, lo + k, out);
            out.add(mth(d, lo + k, hi));
        } else {
            path(m - k, d, lo + k, hi, out);
            out.add(mth(d, lo, lo + k));
        }
    }

    /** Proof that the tree of the first {@code first} leaves is a prefix of the whole tree (RFC 6962 PROOF). */
    public static List<byte[]> consistencyProof(int first, List<byte[]> leaves) {
        if (first < 1 || first > leaves.size()) {
            throw new IllegalArgumentException("first size " + first + " outside 1.." + leaves.size());
        }
        List<byte[]> out = new ArrayList<>();
        subproof(first, leaves, 0, leaves.size(), true, out);
        return out;
    }

    private static void subproof(int m, List<byte[]> d, int lo, int hi, boolean complete, List<byte[]> out) {
        int n = hi - lo;
        if (m == n) {
            if (!complete) {
                out.add(mth(d, lo, hi));
            }
            return;
        }
        int k = split(n);
        if (m <= k) {
            subproof(m, d, lo, lo + k, complete, out);
            out.add(mth(d, lo + k, hi));
        } else {
            subproof(m - k, d, lo + k, hi, false, out);
            out.add(mth(d, lo, lo + k));
        }
    }

    /** RFC 9162 section 2.1.3.2: does the proof place this leaf at index in the tree with this root? */
    public static boolean verifyInclusion(byte[] leaf, long index, long size, List<byte[]> proof, byte[] root) {
        if (index < 0 || index >= size) {
            return false;
        }
        long fn = index;
        long sn = size - 1;
        byte[] r = hashLeaf(leaf);
        for (byte[] p : proof) {
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                r = hashChildren(p, r);
                if ((fn & 1) == 0) {
                    while ((fn & 1) == 0 && fn != 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                r = hashChildren(r, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && MessageDigest.isEqual(r, root);
    }

    /** RFC 9162 section 2.1.4.2: is the tree of size first (root firstRoot) a prefix of the tree of size second? */
    public static boolean verifyConsistency(long first, long second, byte[] firstRoot, byte[] secondRoot,
                                            List<byte[]> proof) {
        if (first < 1 || first > second) {
            return false;
        }
        if (first == second) {
            return proof.isEmpty() && MessageDigest.isEqual(firstRoot, secondRoot);
        }
        List<byte[]> path = new ArrayList<>();
        if ((first & (first - 1)) == 0) {
            path.add(firstRoot);
        }
        path.addAll(proof);
        if (path.isEmpty()) {
            return false;
        }
        long fn = first - 1;
        long sn = second - 1;
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }
        byte[] fr = path.get(0);
        byte[] sr = path.get(0);
        for (int i = 1; i < path.size(); i++) {
            byte[] c = path.get(i);
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                fr = hashChildren(c, fr);
                sr = hashChildren(c, sr);
                if ((fn & 1) == 0) {
                    while ((fn & 1) == 0 && fn != 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                sr = hashChildren(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return MessageDigest.isEqual(fr, firstRoot) && MessageDigest.isEqual(sr, secondRoot) && sn == 0;
    }
}
