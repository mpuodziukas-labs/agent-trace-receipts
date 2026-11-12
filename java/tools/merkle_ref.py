"""merkle_ref.py - tiny independent RFC 6962 reference, used to cross-check the Java MerkleLog.

It builds the tree bottom up, level by level (an odd node is carried up unchanged),
which is a different algorithm from the recursive split in the Java code. Both give the
RFC 6962 tree hash.

Usage:
    python3 merkle_ref.py root <file>     # leaves are the lines of the file, without the newline
    python3 merkle_ref.py vectors         # roots of the first 1..8 leaves of the fixed test inputs
    python3 merkle_ref.py --selftest
"""

import hashlib
import sys

# Fixed leaf inputs (hex) shared with the Java tests.
VECTOR_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                 "606162636465666768696a6b6c6d6e6f"]


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def selftest() -> int:
    empty = root([]).hex()
    one = root([b""]).hex()
    ok = (empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          and one == hashlib.sha256(b"\x00").hexdigest()
          and root([b"a", b"b"]) == node_hash(leaf_hash(b"a"), leaf_hash(b"b")))
    print("selftest", "1/1" if ok else "0/1")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    if argv[:1] == ["vectors"]:
        leaves = [bytes.fromhex(h) for h in VECTOR_LEAVES]
        for n in range(0, len(leaves) + 1):
            print(n, root(leaves[:n]).hex())
        return 0
    if len(argv) == 2 and argv[0] == "root":
        with open(argv[1], "rb") as f:
            lines = f.read().split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        if not lines:
            print("error: no leaves in file", file=sys.stderr)
            return 1
        print(root(lines).hex())
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
