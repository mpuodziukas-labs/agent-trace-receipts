#!/usr/bin/env bash
# verify-java.sh - build and test the Java verifier, then run its CLI on the committed fixture.
#
#   scripts/verify-java.sh             run the unit tests and the CLI checks; exit 0 only if all pass
#   scripts/verify-java.sh --selftest  plant defects in a temp copy of the Java source and prove
#                                      the tests go RED on each, and GREEN on the clean copy
#
# Needs: bash, a Java 17 JDK (set JAVA_HOME if the default java is not 17), Maven, python3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_DIR="$ROOT/java"
FIXTURE_DIR="$JAVA_DIR/src/test/resources/fixtures"
FIXTURE="$FIXTURE_DIR/run-INV-1001.jsonl"
DEMO_KEY="demo-key-not-secret-0"
MAIN="dev.puodziukas.receipts.Main"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP:?}"' EXIT

fail() {
    echo "verify-java: FAIL: $*" >&2
    exit 1
}

# run_tests <java dir>: sets MVN_RC, TESTS_RUN, TESTS_FAILED (failures plus errors), MVN_LOG.
run_tests() {
    local dir="$1"
    MVN_RC=0
    MVN_LOG="$(mvn -B -f "$dir/pom.xml" test 2>&1)" || MVN_RC=$?
    local summary
    summary="$(printf '%s\n' "$MVN_LOG" | grep 'Tests run:' | grep -v ' -- in ' | tail -n 1 || true)"
    TESTS_RUN="$(printf '%s\n' "$summary" | sed -n 's/.*Tests run: \([0-9]*\),.*/\1/p')"
    local failures errors
    failures="$(printf '%s\n' "$summary" | sed -n 's/.*Failures: \([0-9]*\),.*/\1/p')"
    errors="$(printf '%s\n' "$summary" | sed -n 's/.*Errors: \([0-9]*\),.*/\1/p')"
    TESTS_RUN="${TESTS_RUN:-0}"
    TESTS_FAILED=$(( ${failures:-0} + ${errors:-0} ))
}

# cli <java dir> <expected exit code> <args...>: runs the compiled CLI, fails on a different exit code.
cli() {
    local dir="$1" want="$2"
    shift 2
    local got=0
    TRACE_KEY="$DEMO_KEY" java -cp "$dir/target/classes" "$MAIN" "$@" >"$TMP/cli.out" 2>"$TMP/cli.err" || got=$?
    if [ "$got" -ne "$want" ]; then
        cat "$TMP/cli.out" "$TMP/cli.err" >&2
        fail "'$*' exited $got, expected $want"
    fi
    echo "verify-java: cli $* -> exit $got (expected)"
}

main_run() {
    run_tests "$JAVA_DIR"
    printf '%s\n' "$MVN_LOG" | tail -n 25
    [ "$MVN_RC" -eq 0 ] || fail "mvn test exited $MVN_RC"
    [ "$TESTS_RUN" -gt 0 ] || fail "no tests ran"
    [ "$TESTS_FAILED" -eq 0 ] || fail "$TESTS_FAILED tests failed"
    echo "verify-java: tests run=$TESTS_RUN failed=$TESTS_FAILED"

    [ -s "$FIXTURE" ] || fail "fixture missing: $FIXTURE"
    cli "$JAVA_DIR" 0 verify "$FIXTURE"

    # tampered copies must exit 1: one record deleted, one byte changed
    mkdir "$TMP/tamper"
    cp "$FIXTURE" "$FIXTURE.head" "$TMP/tamper/"
    local name
    name="$(basename "$FIXTURE")"
    sed '2d' "$FIXTURE" >"$TMP/tamper/$name"
    cli "$JAVA_DIR" 1 verify "$TMP/tamper/$name"
    sed '2s/load_po/load_pp/' "$FIXTURE" >"$TMP/tamper/$name"
    cmp -s "$FIXTURE" "$TMP/tamper/$name" && fail "byte-change tamper did not change the file"
    cli "$JAVA_DIR" 1 verify "$TMP/tamper/$name"

    # fresh trace from the Python recorder, verified by Java
    TRACE_KEY="$DEMO_KEY" python3 "$ROOT/agent.py" --invoice INV-1015 --out "$TMP/live" >/dev/null
    cli "$JAVA_DIR" 0 verify "$TMP/live/run-INV-1015.jsonl"

    # Merkle root parity with the independent Python reference
    local jroot proot
    jroot="$(TRACE_KEY="$DEMO_KEY" java -cp "$JAVA_DIR/target/classes" "$MAIN" root "$FIXTURE")"
    proot="$(python3 "$JAVA_DIR/tools/merkle_ref.py" root "$FIXTURE")"
    [ -n "$jroot" ] || fail "java root is empty"
    [ "$jroot" = "$proot" ] || fail "root mismatch: java=$jroot python=$proot"
    echo "verify-java: root $jroot matches merkle_ref.py"
    echo "verify-java: PASS"
}

# selftest: one clean copy must be GREEN; each planted defect in its own copy must go RED.
selftest() {
    local pass=0 total=0
    mkdir "$TMP/clean"
    (cd "$JAVA_DIR" && tar cf - --exclude=target .) | (cd "$TMP/clean" && tar xf -)

    total=$((total + 1))
    run_tests "$TMP/clean"
    if [ "$MVN_RC" -eq 0 ] && [ "$TESTS_RUN" -gt 0 ] && [ "$TESTS_FAILED" -eq 0 ]; then
        pass=$((pass + 1))
        echo "selftest: clean copy GREEN ($TESTS_RUN tests)"
    else
        echo "selftest: clean copy was not GREEN (rc=$MVN_RC run=$TESTS_RUN failed=$TESTS_FAILED)" >&2
    fi

    local names=("node prefix 0x01 -> 0x00" "leaf prefix 0x00 -> 0x02" "genesis 64 zeros -> 63" "inclusion verify always true")
    local files=("MerkleLog.java" "MerkleLog.java" "ChainVerifier.java" "MerkleLog.java")
    local exprs=(
        's/NODE_PREFIX = 0x01/NODE_PREFIX = 0x00/'
        's/LEAF_PREFIX = 0x00/LEAF_PREFIX = 0x02/'
        's/"0".repeat(64)/"0".repeat(63)/'
        's/return sn == 0 \&\& MessageDigest.isEqual(r, root);/return true;/'
    )
    local i
    for i in "${!names[@]}"; do
        total=$((total + 1))
        local plant="$TMP/plant$i"
        mkdir "$plant"
        cp -R "$TMP/clean/." "$plant/"
        local src="$plant/src/main/java/dev/puodziukas/receipts/${files[$i]}"
        sed "${exprs[$i]}" "$src" >"$src.new"
        if cmp -s "$src" "$src.new"; then
            echo "selftest: plant '${names[$i]}' changed nothing, selftest is broken" >&2
            continue
        fi
        mv "$src.new" "$src"
        run_tests "$plant"
        # RED for the right reason: the tests ran and some failed (not a compile error)
        if [ "$MVN_RC" -ne 0 ] && [ "$TESTS_RUN" -gt 0 ] && [ "$TESTS_FAILED" -gt 0 ]; then
            pass=$((pass + 1))
            echo "selftest: plant '${names[$i]}' RED ($TESTS_FAILED of $TESTS_RUN tests failed)"
        else
            echo "selftest: plant '${names[$i]}' was not caught (rc=$MVN_RC run=$TESTS_RUN failed=$TESTS_FAILED)" >&2
        fi
    done

    echo "selftest $pass/$total"
    [ "$pass" -eq "$total" ]
}

case "${1:-}" in
    "") main_run ;;
    --selftest) selftest ;;
    *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
