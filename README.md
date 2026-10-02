# Agent Trace Receipts

An agent that reconciles invoices against purchase orders saves analyst hours,
but only if every step can be shown later: what it read, what it called, what
came back, how long it took, and whether it failed. Silent failures cost money:
a mismatched invoice gets paid and nobody can show why.

This repo makes every agent run produce a tamper-evident trace and ships a
verifier that refuses a bad one. Zero marginal cost: Python standard library
only, no network, no API key, no model.

## Quickstart

```bash
python3 agent.py --out traces      # run the scripted agent, write one trace per invoice
python3 verify.py traces           # verify every trace, print the run report
python3 evaluate.py                # run the tamper suite, print N/N results
```

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
```
<!-- results:end -->

Planted mismatches: 3 price, 3 quantity, 2 duplicate invoices, 3 missing
purchase orders (11 total), plus 8 clean invoices that must be approved.

## Sample trace excerpt

Two lines from the duplicate invoice `INV-1015` (real output of
`python3 agent.py --invoice INV-1015`; timestamps and nothing else vary by run).
Each line carries the SHA-256 of the previous raw line in `prev_hash`.

<!-- sample:start -->
```json
{"end_ms":1790970654354.575,"input":{"invoice_id":"INV-1015"},"input_sha256":"93c24b7b74fa318e1e5c10e5c4f59e6754f13cca03d8934c07a0022e3d10ef1f","output":{"duplicate_of":"INV-1001","invoice_id":"INV-1015","invoice_number":"A-1001","lines":[{"qty":7,"sku":"SKU-103","unit_price_cents":1125},{"qty":9,"sku":"SKU-104","unit_price_cents":1165}],"po_id":"PO-5001","vendor":"Birch Packaging"},"output_sha256":"2f6c0e75632624c8a2708dce113d9bd1c21d7db1bd5dce342e4079012583275e","parent":null,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","rc":0,"run_id":"run-INV-1015","start_ms":1790970654354.568,"step":0,"tool":"load_invoice"}
{"end_ms":1790970654354.834,"input":{"invoice_id":"INV-1015","reason":"duplicate"},"input_sha256":"94593722818e76541d429233246e5b7dd17b14f70b4b65fb5034976d814d6bc9","output":{"invoice_id":"INV-1015","open":true,"reason":"duplicate"},"output_sha256":"b5e6792ac5ed9eab253ab4266840ff4140f074c92044fe242c32b1e4b681b3a9","parent":0,"prev_hash":"8d8b439d1cc87dfc146b6dd468c6c7b03650ede3f92542d9393ee7beaa043508","rc":0,"run_id":"run-INV-1015","start_ms":1790970654354.832,"step":1,"tool":"flag_mismatch"}
```
<!-- sample:end -->

Running `python3 verify.py` over a directory prints a run report like:

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
  `run_id, step, parent, tool, input_sha256, output_sha256, rc, start_ms,
  end_ms, prev_hash`, plus the `input` and `output` payloads that the two
  hashes cover. `prev_hash` is the SHA-256 of the previous raw line, so
  changing, removing or reordering any line breaks the chain. A `.head` file
  next to the trace stores the step count and last line hash, so dropping the
  final step is caught too.
- `agent.py`: a scripted reconciler with five tools (`load_invoice`,
  `load_po`, `compare_lines`, `flag_mismatch`, `approve`). Every call is
  recorded. A failed lookup is recorded with `rc=1`, then the invoice is flagged.
- `verify.py`: recomputes the chain, the head anchor, step numbering and
  times, then replays each recorded tool call against the data and compares
  hashes. It then applies two business rules: no `approve` after a failed
  step, and no `approve` while a mismatch flag is open. It prints a run report
  (steps, per-tool p50 and max latency, failures, mismatches caught).
  Exit 0 verified, 1 refused, 2 usage.
- `evaluate.py`: runs the agent over every invoice, then applies six tamper
  classes to the clean traces. Three are raw edits (edit a line, delete a
  step, reorder steps). Three are forgeries by an attacker who recomputes the
  chain correctly (approve after a failed step, approve with an open flag,
  blank end time), so only the replay and business rules can catch them.

Tests include planted-RED mutation tests: the chain check and the
approve-after-failure check are each replaced with an always-pass stub, and
the suite asserts that the evaluation notices the drop.

## Limitations

- The hash chain proves integrity, not truth of tool outputs. A tool that
  returns a wrong answer produces a perfectly valid trace. Replay only helps
  where tools are deterministic and the data is available at verify time.
- The chain and head file are not signed. Someone who can rewrite the trace,
  the head file and every hash together can forge a consistent history; the
  anchor needs to live somewhere the writer cannot reach (signed, or stored
  off the host) to stop that.
- Steps are written when they finish and the trace is a single linear run.
  Concurrent or nested tool calls are not modeled.
- Business rules are two examples for this invoice workflow. Other workflows
  need their own rules.
- Synthetic data, one scripted agent, six tamper classes. Real agents add
  failure modes this suite does not cover.

## Files

```
agent.py     scripted reconciliation agent and tools
trace.py     hash-chained JSONL recorder
verify.py    verifier and run report
evaluate.py  agent run plus tamper suite
data/        synthetic invoices, purchase orders, expected outcomes
tests/       pytest suite (unit, README parity, mutation tests)
```

## License

MIT, see [LICENSE](LICENSE).
