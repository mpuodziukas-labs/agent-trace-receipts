# Verifying this repository

Purpose: demonstrates a tamper-evident audit trail for agent runs, where edited, deleted, reordered or forged steps are refused for teams subject to model-risk, audit or change-control review.

Verify: `python3 evaluate.py`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `| Planted mismatches caught | 11/11 |`

Scope: synthetic data, fixed seed, offline, under 60 seconds.

Limitations: The chain proves integrity, not the truth of tool outputs. The HMAC key is symmetric, so any key holder can forge a trace and there is no non-repudiation. Replaying an older valid trace is not detected. The trace is a single linear run and concurrent calls are not modeled. Scripted synthetic agents only.

Anything else = not verified.
