# Agent Trace Receipts

Proves: agent observability and audit trail (OpenTelemetry-style receipts). Verify in 60s: `python3 evaluate.py`.

![CI](https://github.com/mpuodziukas-labs/agent-trace-receipts/actions/workflows/ci.yml/badge.svg)

An agent that reconciles invoices against purchase orders saves analyst hours,
but only if every step can be shown later: what it read, what it called, what
came back, how long it took, and whether it failed. Silent failures cost money:
a mismatched invoice gets paid and nobody can show why.

This repo makes every agent run produce a tamper-evident trace (an
HMAC-SHA256 chain keyed by a secret you hold) and ships a verifier that refuses
a bad one. Zero marginal cost: Python standard library only, no network, no
API key, no model.

## Quickstart

```bash
export TRACE_KEY=demo-key-not-secret-0   # demo value; use your own secret, 16+ characters
python3 agent.py --out traces      # run the scripted agent, write one trace per invoice
python3 verify.py traces           # verify every trace, print the run report
python3 evaluate.py                # run the tamper suite, print N/N results
```

`verify.py` needs the same `TRACE_KEY` the recorder used. A missing, short or
wrong key is refused (exit 2 for missing or short, 1 for a wrong key).
`evaluate.py` makes its own random key per run.

Tests: `pip install pytest && python3 -m pytest -v`. Run in place; this is not an installable package.

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
| Tampered traces refused: delete_step | 19/19 |
| Tampered traces refused: reorder_steps | 19/19 |
| Tampered traces refused: approve_after_failure | 3/3 |
| Tampered traces refused: approve_open_flag | 8/8 |
| Tampered traces refused: missing_end_time | 19/19 |
| Tampered traces refused: rechain_unkeyed | 19/19 |
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

Running `python3 verify.py traces` over a directory prints a run report like:

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
  to the trace stores the run id, step count and the keyed MAC of the last
  line, so dropping the final step and rewriting the head is caught too.
- `agent.py`: a scripted reconciler with five tools (`load_invoice`,
  `load_po`, `compare_lines`, `flag_mismatch`, `approve`). Every call is
  recorded. A failed lookup is recorded with `rc=1`, then the invoice is flagged.
- `verify.py`: checks the record shape and canonical encoding, the keyed
  chain, the head anchor, step numbering, parents and times (finite,
  non-negative, in order), then replays each recorded tool call against the
  data and compares hashes. Because the agent is deterministic, it also re-runs
  the agent for the invoice and requires every step (tool, parent, input,
  output, rc) to match, which rejects dropped, added, spliced or doctored
  steps and runs that never reached approve or flag. Two business rules give
  named errors: no `approve` after a failed step, and no `approve` while a
  mismatch flag is open. It prints a run report (steps, per-tool p50 and max
  latency, failures, mismatches caught). Any unexpected error refuses the trace
  instead of crashing. Exit 0 verified, 1 refused, 2 usage (no traces, bad data
  directory, `TRACE_KEY` missing or short).
- `evaluate.py`: runs the agent over every invoice, then applies thirteen
  tamper classes to the clean traces. Three are raw edits (edit a line, delete
  a step, reorder steps). One is an outsider who edits a step and recomputes
  the whole chain and head without the key (`rechain_unkeyed`). Nine are
  forgeries by an insider who holds the key and re-chains validly (approve
  after a failed step, approve with an open flag, blank end time, truncate,
  drop the flag, approve with no compare step, hide a mismatch in the compare
  input, splice another run, reversed times), so only the replay, workflow and
  time checks can catch them.

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
  ordering rules. Only length is enforced on the key, not strength. For an
  external auditor, use asymmetric signatures and keep the signing key off the
  host that runs the agent; that is not implemented here.
- Deleting a whole trace file, or putting back an older valid trace, is not
  detected: `verify.py` can only report on the files it is given
  (`verified N/M`). Compare against the list of runs you expect.
- Steps are written when they finish and the trace is a single linear run.
  Concurrent or nested tool calls are not modeled.
- The data directory is trusted. Replay checks a trace against the invoices
  and purchase orders it is given; those files are not hashed or signed, so
  someone who changes them and re-records with the key produces a trace that
  verifies against the changed data.
- Business rules are two examples for this invoice workflow. Other workflows
  need their own rules.
- Synthetic data, one scripted agent, thirteen tamper classes. Real agents add
  failure modes this suite does not cover.

## Files

```
agent.py     scripted reconciliation agent and tools
trace.py     hash-chained JSONL recorder
verify.py    verifier and run report
evaluate.py  agent run plus tamper suite
data/        synthetic invoices, purchase orders, expected outcomes
tests/       pytest suite (unit, red-team attacks, README parity, mutation tests)
```

## License

MIT, see [LICENSE](LICENSE).
