# agent-trace-receipts

Proves: agent observability and audit trail (OpenTelemetry-style receipts). Verify in 60s: `python3 evaluate.py`.

Where this fits: NIST AI RMF function MEASURE. Sources in SOURCES.md.

![CI](https://github.com/mpuodziukas-labs/agent-trace-receipts/actions/workflows/ci.yml/badge.svg)

An agent that reconciles invoices against purchase orders saves analyst hours,
but only if every step can be shown later: what it read, what it called, what
came back, how long it took, and whether it failed. Silent failures cost money:
a mismatched invoice gets paid and nobody can show why.

This repo makes every agent run produce a tamper-evident trace (an
HMAC-SHA256 chain keyed by a secret you hold) and ships a verifier that refuses
a bad one. Zero marginal cost: Python standard library only, no network, no
API key, no model.

The title line this README carried before the standard layout, kept as written:

```text
# Agent Trace Receipts
```

## Ticket

| Field | Value |
|---|---|
| Ticket | agent-trace-receipts 2026-10-25 |
| Status | LIVE |
| Severity of a false pass | A tampered, truncated or doctored agent trace is accepted because the evaluator printed all-N/N, and a wrong invoice approval can no longer be shown to be wrong from the record. |
| Scope (in) | Recording a keyed hash-chained trace per agent run, verifying it (shape, chain, signed head, sequence, times, replay, business rules), the tamper suite, the synthetic metrics report and the multi-agent handoff demo. |
| Out of scope | Truth of tool outputs, key management, non-repudiation toward a third party, older-valid-trace replacement and concurrent tool calls (see Limitations). |
| Owner | Michael Puodziukas, michael@puodziukas.dev |
| Opened | 2026-10-02 |
| Last verified | 2026-10-25, `\| Tampered traces refused: reversed_times \| 19/19 \|` |
| Oracle | `python3 evaluate.py`, last line `\| Tampered traces refused: reversed_times \| 19/19 \|`; `python3 mutants.py`, last line `mutants killed 18/18` |
| Dependencies | Runtime: Python 3 standard library only. Test: pytest. |
| Supported platforms | macOS (both oracles measured here, rc=0); Linux through the ubuntu-latest runner in .github/workflows/ci.yml (not measured here). |

## Quick start

```bash
python3 evaluate.py
python3 mutants.py
```

## Quickstart

```bash
export TRACE_KEY=demo-key-not-secret-0   # demo value; use your own secret, 16+ characters
python3 agent.py --out traces      # run the scripted agent, write one trace per invoice
python3 verify.py traces --expect  # verify every trace against the run list, print the run report
python3 evaluate.py                # run the tamper suite, print N/N results
```

`verify.py` needs the same `TRACE_KEY` the recorder used. A missing, short or
wrong key is refused (exit 2 for missing or short, 1 for a wrong key).
`evaluate.py` makes its own random key per run.

Tests: `pip install pytest && python3 -m pytest -v`. Run in place; this is not an installable package.

## Normal procedure

1. From the repo root run `python3 evaluate.py`. It needs no key from you, runs the scripted agent over every invoice, applies every tamper class to the clean traces and prints one table.
2. Read the table. A row counts as refused only when the check that owns that tamper class fires. PASS means every row reads N/N. The first rows of the output read exactly:

```text
| Check | Result |
|---|---|
| Planted mismatches caught | 11/11 |
```

3. Run `python3 mutants.py` to prove the tests can fail. It copies the repo to a temporary directory, removes one defense at a time and requires the matching tests to go red. PASS ends with `mutants killed 18/18`.
4. To verify real traces, export `TRACE_KEY` as in the Quickstart section, then run `python3 verify.py traces --expect`. Exit 0 means every trace verified, 1 means a trace was refused, 2 means a usage error.

## Abnormal procedure

| Symptom | Cause | Action | Oracle |
|---|---|---|---|
| `evaluate.py` exits 1 and a row is short of N/N | A check no longer fires for the tamper class that row names, or the agent output changed | Find the row name in the table, then read the verifier check that owns that class in `verify.py` | `python3 evaluate.py` |
| `verify.py` exits 2 | `TRACE_KEY` is missing or short, there are no traces, or the data directory is bad | Export a key of 16 or more characters and pass an existing trace directory | `python3 verify.py traces --expect` |
| `verify.py` exits 1 and names a reason | The trace was edited, truncated, renamed or recorded with a different key | Read the named reason for the refused file and compare it with the key used by the recorder | `python3 verify.py traces --expect` |
| `agent.py` refuses to write a trace | The trace file already exists and the recorder will not overwrite it | Pass `--force` only when the old trace is not needed | `python3 agent.py --out traces --force` |
| `mutants.py` prints a LIVE line | A removed defense that the tests do not detect, which is a gap in the tests | Add or tighten a test until that line prints RED | `python3 mutants.py` |
| `mutants.py` prints `control FAIL` or `pattern matched` | The unmodified tests fail in the copy (for example pytest is missing), or the source line a mutant targets has moved | Run `pip install pytest`, or update the pattern in `mutants.py` | `python3 mutants.py` |

## Emergency procedure

A trace verified but the recorded run is wrong in production: a doctored trace was accepted.

1. Freeze: stop treating traces from the affected recorder as evidence, treat `TRACE_KEY` as exposed and record the repo commit and the trace file that misled you.
2. Replay: run `python3 verify.py` over the offending trace directory with the real key. If it exits 0, add the tamper as a new class in `evaluate.py` and a matching mutant in `mutants.py`, fix the owning check in `verify.py`, then run `python3 evaluate.py` and `python3 mutants.py` and expect every count N/N.
3. Tell: the owner (michael@puodziukas.dev) and everyone who relied on the trace. Name the missing check and the Limitations item that covers it.

## Honesty Statement

> **All data here is synthetic, authored for this repository (19 invoices,
> 14 purchase orders, vendors and amounts invented). It is NOT production data
> and NOT client data. The agent is a deterministic script, not an LLM.**
>
> The results below show that the verifier catches the tamper classes this
> repo defines, on traces this repo generates. They are not a security audit
> and do not generalize beyond those classes. See [Limitations](#limitations).

## Results

Measured by `python3 evaluate.py` on the bundled synthetic data. A test fails
if this block ever differs from the program output.

<!-- results:start -->
```
| Check | Result |
|---|---|
| Planted mismatches caught | 11/11 |
| Clean traces accepted | 19/19 |
| Tampered traces refused: edit_line | 19/19 |
| Tampered traces refused: delete_step | 17/17 |
| Tampered traces refused: reorder_steps | 19/19 |
| Tampered traces refused: approve_after_failure | 3/3 |
| Tampered traces refused: approve_open_flag | 8/8 |
| Tampered traces refused: missing_end_time | 19/19 |
| Tampered traces refused: rechain_unkeyed | 19/19 |
| Tampered traces refused: truncate_unkeyed | 19/19 |
| Tampered traces refused: noncanonical_with_key | 19/19 |
| Tampered traces refused: bad_sequence_with_key | 19/19 |
| Tampered traces refused: forge_output_with_key | 19/19 |
| Tampered traces refused: truncate_with_key | 19/19 |
| Tampered traces refused: drop_flag_with_key | 11/11 |
| Tampered traces refused: approve_without_compare | 2/2 |
| Tampered traces refused: forge_compare_input | 6/6 |
| Tampered traces refused: splice_runs | 19/19 |
| Tampered traces refused: reversed_times | 19/19 |
```
<!-- results:end -->

Planted mismatches: 3 price, 3 quantity, 2 duplicate invoices, 3 missing
purchase orders (11 total), plus 8 clean invoices that must be approved.

## Sample trace excerpt

The first two lines of `traces/run-INV-1015.jsonl`, the duplicate invoice,
after `TRACE_KEY=demo-key-not-secret-0 python3 agent.py --invoice INV-1015`
(the command prints only `INV-1015 flagged (duplicate)`; the trace goes to the
file). Only timestamps and every `prev_hash` after the first vary by run.
Each line carries the HMAC-SHA256 of the previous raw line in `prev_hash`.

<!-- sample:start -->
```json
{"end_ms":1790971028472.109,"input":{"invoice_id":"INV-1015"},"input_sha256":"93c24b7b74fa318e1e5c10e5c4f59e6754f13cca03d8934c07a0022e3d10ef1f","output":{"duplicate_of":"INV-1001","invoice_id":"INV-1015","invoice_number":"A-1001","lines":[{"qty":7,"sku":"SKU-103","unit_price_cents":1125},{"qty":9,"sku":"SKU-104","unit_price_cents":1165}],"po_id":"PO-5001","vendor":"Birch Packaging"},"output_sha256":"2f6c0e75632624c8a2708dce113d9bd1c21d7db1bd5dce342e4079012583275e","parent":null,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","rc":0,"run_id":"run-INV-1015","start_ms":1790971028472.102,"step":0,"tool":"load_invoice"}
{"end_ms":1790971028472.378,"input":{"invoice_id":"INV-1015","reason":"duplicate"},"input_sha256":"94593722818e76541d429233246e5b7dd17b14f70b4b65fb5034976d814d6bc9","output":{"invoice_id":"INV-1015","open":true,"reason":"duplicate"},"output_sha256":"b5e6792ac5ed9eab253ab4266840ff4140f074c92044fe242c32b1e4b681b3a9","parent":0,"prev_hash":"ae593805835b55e801dc0918674d1ac9a47f37b350b803fce7537cfc91156fa6","rc":0,"run_id":"run-INV-1015","start_ms":1790971028472.376,"step":1,"tool":"flag_mismatch"}
```
<!-- sample:end -->

Running `python3 verify.py traces --expect` over a directory prints a run report like:

```
traces: 19  steps: 69
  approve        n=8   p50=0.001 ms  max=0.003 ms
  compare_lines  n=14  p50=0.002 ms  max=0.004 ms
  flag_mismatch  n=11  p50=0.001 ms  max=0.002 ms
  load_invoice   n=19  p50=0.004 ms  max=0.007 ms
  load_po        n=17  p50=0.001 ms  max=0.005 ms
failures (rc!=0 steps): 3
mismatches caught: 11/11
```

Latencies are measured at run time and differ per machine, so they are not part of the results table.

## Cost, latency and token metrics

`metrics.py` reads a seeded synthetic traffic file (`data/traffic.jsonl`, 200 records) and prints
p50/p95/p99 latency, total tokens, total cost and cost per request, per route and tool. Each record
carries `route, tool, model, token_in, token_out, latency_ms`. `cost_usd` is computed from
`data/pricing.json`, which is labelled "illustrative prices, not a vendor quote". No model call, no
network. Percentiles use the nearest-rank method. A record with negative or non-integer tokens, a
missing or non-finite latency, or an unknown model is refused (exit 1, the line number is named); an
empty file is exit 2. These usage records are a separate file from the HMAC-chained step traces and
are not covered by the chain.

```bash
python3 metrics.py              # report over data/traffic.jsonl
python3 metrics.py --generate   # rewrite the traffic file (seed 7)
```

Output of `python3 metrics.py`, checked by a test against the real command:

<!-- metrics:start -->
```
route/tool                         n  p50_ms  p95_ms  p99_ms  tok_in  tok_out  cost_usd   usd/req
invoice_reconcile/approve         19     212    3997    3997   10154     1880  0.011868  0.000625
invoice_reconcile/compare_lines   19     289    3929    3929   12573     2624  0.039577  0.002083
invoice_reconcile/load_invoice    28     300    3312    3519   19994     5117  0.095192  0.003400
mismatch_triage/compare_lines     40     140     808    4121   24499     5643  0.084554  0.002114
mismatch_triage/flag_mismatch     34     168    1141    3409   22676     5373  0.089241  0.002625
po_lookup/load_po                 60     211    3065    3833   36468     7697  0.105102  0.001752
ALL                              200     277    3065    3929  126364    28334  0.425536  0.002128
```
<!-- metrics:end -->

## Multi-agent handoff, escalation and audit

`multiagent.py` runs two scripted agents (intake and resolver) over three synthetic refund cases and
writes both agents' steps to one existing HMAC-chained trace; the record shape is unchanged. A
handoff record carries `from, to, reason, context_hash`, and the receiving agent writes a matching
`receive` record. Escalation rule: confidence below 0.80, or a refund over 500, writes an `escalate`
record to the human queue instead of acting. No action, handoff or receive may follow until a
`human_approval` record for that escalation is on the chain.

The verifier adds two checks on top of chain, head, sequence and times: every handoff has exactly one
matching receive (same id, same receiving agent, same context hash), and nothing happens after an
escalation without a human approval. Three planted tampers are made by a key holder who re-signs the
chain, so only the new checks can catch them: a dropped handoff, an action after an escalation
(the approval removed), and reordered records. Each is refused with a named reason. No model call, no network.

```bash
python3 multiagent.py
```

Output of `python3 multiagent.py`, checked by a test against the real command:

<!-- multiagent:start -->
```
scenario: intake and resolver, 3 cases, one chained trace
   0 act             intake   classify CASE-1
   1 handoff         intake -> resolver H-1 (classified:refund) ctx=554ed1b2
   2 receive         resolver got H-1 ctx=554ed1b2
   3 act             resolver evaluate_refund CASE-1
   4 act             resolver issue_refund CASE-1
   5 act             intake   classify CASE-2
   6 escalate        intake CASE-2 -> human queue (low_confidence)
   7 human_approval  human:ops-queue approved escalation at step 6
   8 handoff         intake -> resolver H-2 (classified:refund) ctx=68885586
   9 receive         resolver got H-2 ctx=68885586
  10 act             resolver evaluate_refund CASE-2
  11 act             resolver issue_refund CASE-2
  12 act             intake   classify CASE-3
  13 handoff         intake -> resolver H-3 (classified:refund) ctx=c22af5a0
  14 receive         resolver got H-3 ctx=c22af5a0
  15 act             resolver evaluate_refund CASE-3
  16 escalate        resolver CASE-3 -> human queue (policy:refund_over_limit)
human queue: 1 escalation pending approval
verification: 6/6 checks passed (chain, head, sequence, times, handoff_receive, escalation_gate)
  planted dropped_handoff: refused (receive without handoff)
  planted action_after_escalation: refused (action after escalation without human approval)
  planted reordered_records: refused (receive before handoff)
tamper suite: 3/3 refused with the expected reason
```
<!-- multiagent:end -->

## How it works

- `trace.py`: a recorder (context manager). Each step is one JSONL line with
  `run_id, step, parent, tool, input, input_sha256, output, output_sha256, rc,
  start_ms, end_ms, prev_hash`, where the two hashes cover the `input` and
  `output` payloads. `prev_hash` is HMAC-SHA256 of the previous raw line, keyed
  with the `TRACE_KEY` environment variable (16+ characters; the first line
  chains to an all-zero value). Changing, removing or reordering any line
  breaks the chain, and without the key nobody can recompute a valid one: an
  unkeyed hash chain can be rewritten end to end by anyone who can write the
  file, so this repo does not offer a plain-SHA-256 mode. A `.head` file next
  to the trace stores the run id, step count, the keyed MAC of the last line
  and its own domain-separated MAC (`HMAC(key, "head" + run_id + steps +
  last line)`), which never equals any line's `prev_hash`, so an outsider who
  drops the final step cannot forge the head. The head is written atomically
  (temp file, fsync, rename) after the line is fsynced; a head that lags by
  one line is reported as a recorder crash, not as tampering. The recorder
  refuses to overwrite an existing trace unless you pass `--force`.
- `agent.py`: a scripted reconciler with five tools (`load_invoice`,
  `load_po`, `compare_lines`, `flag_mismatch`, `approve`). Every call is
  recorded. A failed lookup is recorded with `rc=1`, then the invoice is flagged.
- `verify.py`: checks the record shape and canonical encoding, the keyed
  chain, the signed head anchor, step numbering, parents and times (finite,
  non-negative, in order), then replays each recorded tool call against the
  data and compares hashes. Because the agent is deterministic, it also re-runs
  the agent for the invoice and requires every step (tool, parent, input,
  output, rc) to match, which rejects dropped, added, spliced or doctored
  steps and runs that never reached approve or flag. Two business rules give
  named errors: no `approve` after a failed step, and no `approve` while a
  mismatch flag is open. It prints a run report (steps, per-tool p50 and max
  latency, failures, mismatches caught). A `run-*` file name must equal its
  `run_id`, and no `run_id` may appear twice. With `--expect` the run list in
  `data/expected.json` is the truth: a missing, extra or renamed trace is
  refused and the mismatch denominator comes from that list. Any unexpected
  error refuses the trace instead of crashing. Exit 0 verified, 1 refused, 2 usage (no traces, bad data
  directory, `TRACE_KEY` missing or short).
- `evaluate.py`: runs the agent over every invoice, then applies seventeen
  tamper classes to the clean traces. Three are raw edits (edit a line, delete
  a middle step, reorder steps). Two are outsiders without the key: one edits
  a step and recomputes the whole chain and head (`rechain_unkeyed`), one
  drops the last step and rewrites the head (`truncate_unkeyed`). Twelve are
  forgeries by an insider who holds the key and re-chains validly (approve
  after a failed step, approve with an open flag, blank end time, truncate,
  drop the flag, approve with no compare step, hide a mismatch in the compare
  input, splice another run, reversed times, non-canonical encoding, a bad
  step number, a doctored tool output), so only the shape, sequence, replay,
  workflow and time checks can catch them. Each row counts as refused only
  when the check that owns that class fires, so switching a check off lowers
  its own row below N/N.

Tests include planted-RED mutation tests: the chain keying, the expected-run
check and the approve-after-failure check are each replaced with an
always-pass stub (or plain SHA-256), and the suite asserts that the evaluation
notices the drop. `tests/test_redteam.py` holds the attack tests, malformed
input and CLI contract tests, and checks of the README's own claims.

## Limitations

- The chain proves integrity, not truth of tool outputs. A tool that returns a
  wrong answer produces a perfectly valid trace. Replay only helps where tools
  are deterministic and the data is available at verify time; the expected-run
  check works only because this agent is a deterministic script, and a real
  model-driven agent cannot be re-run that way.
- Key management is on you. HMAC is symmetric: anyone holding `TRACE_KEY`
  (the recorder, and every verifier) can forge a trace, and there is no
  non-repudiation toward a third party. A key holder is still constrained by
  the replay and workflow checks, but can alter timestamps freely within the
  ordering rules. The key must be at least 16 characters with at least 8 distinct
  bytes and not only whitespace; beyond that, strength is on you. For an
  external auditor, use asymmetric signatures and keep the signing key off the
  host that runs the agent; that is not implemented here.
- Putting back an older valid trace is not detected. Deleting or renaming a
  trace file is detected only with `--expect`; without it `verify.py` can only
  report on the files it is given (`verified N/M`).
- Steps are written when they finish and the trace is a single linear run.
  Concurrent or nested tool calls are not modeled.
- The data directory is trusted. Replay checks a trace against the invoices
  and purchase orders it is given; those files are not hashed or signed, so
  someone who changes them and re-records with the key produces a trace that
  verifies against the changed data.
- Business rules are two examples for this invoice workflow. Other workflows
  need their own rules.
- Metrics: synthetic traffic, seeded, with illustrative prices, not a vendor quote.
  The numbers show the arithmetic works, not what any real system costs or how fast it runs.
- Multi-agent scenario: both agents are scripted functions, not LLMs, writing one linear trace. The
  checks prove the handoff and escalation records are complete and ordered, not that a real model's
  confidence is calibrated or that the human approval came from a real person (the approver is a
  recorded label, and a key holder can write one).
- Synthetic data, one scripted agent, seventeen tamper classes. Real agents add
  failure modes this suite does not cover.
- The pytest suite was not run for the README restructuring; only the two oracles named in the Ticket were run.

## Java verifier

`java/` holds a second, independent implementation in Java 17 (JUnit 5 is the
only dependency, and only for tests). It reads the trace files the Python
recorder writes and checks them without importing any Python code. The Merkle
part is our own design; the design follows RFC 6962/9162 as used by
transparency logs such as Trillian and Rekor. No code was copied from them.

What it proves:

- `ChainVerifier` recomputes the keyed chain the way `trace.py` does: record
  i must carry the HMAC-SHA256 of the raw bytes of line i-1 in `prev_hash`,
  record 0 carries 64 zeros, and the `.head` file must match the record count,
  the last line and its own domain-separated MAC. It reports OK or the first
  broken record index. The committed fixture
  `java/src/test/resources/fixtures/run-INV-1001.jsonl` was written by
  `agent.py` with the demo key; Java accepts it and refuses a flipped byte, a
  deleted record and two reordered records.
- `MerkleLog` implements the RFC 6962 leaf hash `SHA-256(0x00 || leaf)`, node
  hash `SHA-256(0x01 || left || right)`, the tree root, inclusion proofs and
  consistency proofs, with the verification algorithms of RFC 9162 section 2.1.
  The empty tree root is the SHA-256 of the empty string. Small-tree roots are
  checked against `java/tools/merkle_ref.py`, a short Python reference that
  builds the tree bottom up. Every inclusion and consistency proof for tree
  sizes 1 to 64 verifies, and the same proofs fail with one bit flipped. A
  seeded random loop covers larger trees.
- `Main` is the command line: `verify <receipts>` exits 0 for an intact chain
  and 1 for a broken one (2 for bad usage or a missing `TRACE_KEY`), and
  `root <receipts>` prints the Merkle root over the lines of the file.

Commands (Java 17 and Maven; `python3` for the live parity step):

```bash
bash scripts/verify-java.sh              # tests, CLI on the fixture, tampered copies, Python parity
bash scripts/verify-java.sh --selftest   # plants four defects in a temp copy, expects RED each time
cd java && mvn -q test
TRACE_KEY=demo-key-not-secret-0 java -cp java/target/classes dev.puodziukas.receipts.Main verify \
  java/src/test/resources/fixtures/run-INV-1001.jsonl
```

Measured on the current tree: 31 tests passed, 0 failed (11 chain, 15 Merkle,
5 command line), and `--selftest` prints `selftest 5/5` (one clean copy green,
four planted defects red).

Limits: the Java side checks the chain and the head, not the tool replay or the
business rules, which stay in `verify.py`. The Merkle root is a separate
construct over the raw lines; the Python recorder does not publish a log, so
inclusion and consistency proofs are verified locally and there is no log
server. The chain still uses a shared HMAC key, so the key holder can forge it.

## Hostile review 2026-10-04

An independent adversarial review (`RED-RUN-REVIEW.txt`) found 7 issues: 2 high,
3 medium, 2 low. All 7 are fixed, each with a test in
`tests/test_hostile.py` that failed before the fix.

- T1 high: the head copied a chain value, so a keyless truncation passed the head check. Fixed: the head has its own domain-separated MAC.
- T2 high: a copied trace under another name hid a flagged invoice. Fixed: file name bound to `run_id`, duplicate `run_id` refused, denominator from `expected.json`.
- T3 medium: a renamed trace dropped out silently. Fixed: `--expect` refuses missing and extra traces.
- T4 medium: six checks could be switched off and the table stayed N/N. Fixed: each row needs its owning check to fire; four new classes.
- T5 medium: a crash between line and head wrote an unexplained refusal. Fixed: atomic head, fsync order, labelled crash state.
- T6 low: an all-whitespace key was accepted. Fixed: at least 8 distinct bytes and not only whitespace.
- T7 low: re-running the agent destroyed the old trace. Fixed: exclusive create, `--force` to overwrite.

## Files

```text
agent.py     scripted reconciliation agent and tools
trace.py     hash-chained JSONL recorder
verify.py    verifier and run report
evaluate.py  agent run plus tamper suite
metrics.py   token, latency and cost report over synthetic traffic
multiagent.py  two scripted agents, handoff and escalation records, and their verifier
data/        synthetic invoices, purchase orders, expected outcomes, traffic, illustrative pricing
tests/       pytest suite (unit, red-team attacks, hostile-review findings, README parity, mutation tests)
RED-RUN-REVIEW.txt  the hostile review findings table
java/        Java 17 verifier: chain check, Merkle log proofs, CLI, tests, fixture
scripts/     verify-java.sh runs the Java tests, CLI checks and its own selftest
```

## Architecture

| Path | Role | Lines |
|---|---|---|
| `agent.py` | Scripted reconciliation agent and its five tools | 159 |
| `trace.py` | Keyed hash-chained JSONL recorder | 163 |
| `verify.py` | Verifier: shape, chain, head, sequence, times, replay, business rules | 405 |
| `evaluate.py` | The oracle: agent run plus tamper suite, prints the table | 376 |
| `metrics.py` | Token, latency and cost report over synthetic traffic | 170 |
| `multiagent.py` | Two scripted agents with handoff and escalation records | 258 |
| `mutants.py` | Mutation check: removes one defense per copy and requires red tests | 74 |
| `.github/workflows/ci.yml` | CI workflow | 35 |
| `data/` | Synthetic invoices, purchase orders, expected outcomes, traffic, pricing | none: directory |
| `tests/` | Pytest suite | none: directory |

Data flow:

1. `agent.py` runs the scripted agent and `trace.py` writes one keyed JSONL trace and head file per invoice.
2. `verify.py` checks each trace and, with `--expect`, the run list in `data/expected.json`.
3. `evaluate.py` applies every tamper class to the clean traces and counts the refusals.
4. `evaluate.py` prints the table and exits with code zero only when every count is N/N.
5. `mutants.py` removes one defense at a time from a copy and requires `tests/` to go red.

## Test and mutation evidence

Measured on 2026-10-25 on macOS by running both oracles from the repo root. Each exited with code zero (rc=0). Last line of `python3 evaluate.py`:

```text
| Tampered traces refused: reversed_times | 19/19 |
```

Last line of `python3 mutants.py`:

```text
mutants killed 18/18
```

## Change log

| Date | Change | Oracle after |
|---|---|---|
| 2026-10-25 | Additive restructuring to the README standard: sections added, no old line altered | `python3 evaluate.py` last line `\| Tampered traces refused: reversed_times \| 19/19 \|`; `python3 mutants.py` last line `mutants killed 18/18` |
| 2026-10-04 | Hostile review fixes (date from the Hostile review section) | none: no oracle output was recorded for that review in this README |

## License

MIT, see [LICENSE](LICENSE).

Agent verification contract: [AGENTS.md](AGENTS.md)
