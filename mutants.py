"""Mutation check: remove each defense in a scratch copy, the matching tests must go RED.
A control copy must pass first. A mutant that hangs past TIMEOUT counts as killed.
Usage: python3 mutants.py [repo_dir]   (default: the directory holding this file)"""
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent
TIMEOUT = 60                                            # test_hostile alone takes about 16 s
V = "tests/test_verify.py"
TR = "tests/test_trace.py"
H = "tests/test_hostile.py"
R = "tests/test_redteam.py"
T = "trace.py"
F = "verify.py"
# (name, file, text to remove, text to put in, test file that must fail)
MUTANTS = [
    ("key: a key of one repeated byte is strong enough", T, "MIN_DISTINCT_BYTES = 8", "MIN_DISTINCT_BYTES = 1", H),
    ("recorder: an earlier trace is overwritten", T, '"w" if force else "x"', '"w"', H),
    ("recorder: a failed step records rc 0", T, "            s.rc = 1\n", "            s.rc = 0\n", TR),
    ("recorder: the chain value is never advanced", T, "        self._prev = chain_hash(self.key, line)", "        self._prev = GENESIS", TR),
    ("shape: a non-canonical line is accepted", F, "elif canonical(rec) != line:", "elif False:", R),
    ("shape: extra or missing fields are accepted", F, "        if set(rec) != FIELDS:", "        if False:", R),
    ("shape: a bool counts as an integer", F, "    return type(x) is int", "    return isinstance(x, int)", R),
    ("chain: the previous hash is not compared", F, "if not isinstance(got, str) or not hmac.compare_digest(got, prev):", "if not isinstance(got, str):", V),
    ("head: the signature is not checked", F, "    if not hmac.compare_digest(mac, head_mac(key, run_id, len(raw), raw[-1])):", "    if False:", R),
    ("head: another run_id in the anchor is accepted", F, '    if head["run_id"] != run_id:', "    if False:", R),
    ("sequence: out of order step numbers are accepted", F, '        if not (_int(rec.get("step")) and rec["step"] == i):', "        if False:", R),
    ("times: a step that starts early is accepted", F, "        elif s < prev_start:", "        elif False:", R),
    ("replay: the output is not replayed against the data", F, '        elif sha256_json(out) != rec.get("output_sha256") or rc != rec.get("rc"):', "        elif False:", V),
    ("expected: a run with a different step count is accepted", F, "    if len(steps) != len(exp):", "    if False:", R),
    ("policy: approve after a failed step is accepted", F, '        failed = failed or rec.get("rc") != 0', "        failed = False", V),
    ("policy: approve with an open flag is accepted", F, '        if rec.get("tool") == "approve" and open_flag:', "        if False:", V),
    ("names: a duplicate run_id is accepted", F, "        if len(group) > 1:", "        if False:", H),
    ("cli: a refused trace exits 0", F, "    return 0 if len(good) == len(results) and not notes else 1", "    return 0", V),
]


def pytest_rc(tree, test):
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                           cwd=tree, capture_output=True, timeout=TIMEOUT,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124                                      # a mutant that hangs the tests is caught
    return r.returncode


def fresh(tmp, name):
    dst = pathlib.Path(tmp) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dst


def main():
    killed = 0
    tests = sorted({m[4] for m in MUTANTS})
    with tempfile.TemporaryDirectory() as tmp:
        for t in tests:
            if pytest_rc(fresh(tmp, "control-" + pathlib.Path(t).stem), t) != 0:
                print(f"control FAIL {t}"); return 1
        print(f"control {len(tests)}/{len(tests)} test files pass unmodified")
        for i, (name, f, old, new, test) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1"); return 1
            (tree / f).write_text(src.replace(old, new))
            red = pytest_rc(tree, test) != 0
            killed += red
            print(f"{'RED ' if red else 'LIVE'} {name}")
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
