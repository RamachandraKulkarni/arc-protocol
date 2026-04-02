# Live Proof of Concept

This document records the live proof run of the ARC Protocol. It is a reproducible record that
the protocol works end-to-end with a real AI agent.

---

## Setup

The proof ran on Windows 11 with the following configuration.

**Terminal 1: Log server**
```bash
python -m uvicorn arc_log.server:app --host 127.0.0.1 --port 8080
```
Output: log server public key printed to stdout.

**Terminal 2: Claude Code session**
Claude Code (desktop application) was given a task: create four files (`data.csv`,
`process.py`, `results.txt`, `summary.json`) using ARC-wrapped shell commands. The ARC
environment was configured with the log server URL set to `http://localhost:8080`.

**Terminal 3: Isolated verifier**
A completely isolated PowerShell window with:

- No environment variables from the agent session
- No imports from the `arc-protocol` directory
- No knowledge of what Claude Code was instructed to do

The verifier was provided only with:

- Five receipt IDs
- The log server URL: `http://localhost:8080`

---

## What the Verifier Knew

The verifier script received only these inputs:

```python
LOG_URL = "http://localhost:8080"
RECEIPT_IDS = [
    "arc_01KN6RGD75FMHNC1TBZ5MBZE7F",
    "arc_01KN6SYG39A1FMXTQTAWDM97H3",
    "arc_01KN6T08ZM9VXSAHVP1Y7QR5EB",
    "arc_01KN6T2HBHRW4PBDYHXWSYVD6Z",
    "arc_01KN6T3RFS3N41YDFMG6QJRDQ1",
]
```

The verifier called `GET /v1/log/verify/{receipt_id}` for each ID and evaluated the four checks
returned.

---

## Full Verification Output

| Receipt ID | Action | Intent Seq | Receipt Seq | found_in_log | log_chain_consistent | intent_committed | receipt_committed | Valid |
|------------|--------|------------|-------------|-------------|---------------------|-----------------|------------------|-------|
| arc_01KN6RGD75FMHNC1TBZ5MBZE7F | data.csv creation | 2 | 3 | Yes | Yes | Yes | Yes | Yes |
| arc_01KN6SYG39A1FMXTQTAWDM97H3 | type data.csv | 4 | 5 | Yes | Yes | Yes | Yes | Yes |
| arc_01KN6T08ZM9VXSAHVP1Y7QR5EB | type process.py | 6 | 7 | Yes | Yes | Yes | Yes | Yes |
| arc_01KN6T2HBHRW4PBDYHXWSYVD6Z | type results.txt | 8 | 9 | Yes | Yes | Yes | Yes | Yes |
| arc_01KN6T3RFS3N41YDFMG6QJRDQ1 | type summary.json | 10 | 11 | Yes | Yes | Yes | Yes | Yes |

Summary output:
```
Total: 5  Valid: 5  Invalid: 0
OVERALL: ALL VALID - PROOF COMPLETE
```

---

## Sequence Number Analysis

Intent sequence numbers: 2, 4, 6, 8, 10
Receipt sequence numbers: 3, 5, 7, 9, 11

For every action, the intent sequence number is exactly one less than the receipt sequence
number. This confirms:

1. Phase 1 was committed before Phase 2 for every action.
2. The log server enforced the ordering requirement in all five cases.
3. No entries were committed out of order.

Sequence numbers start at two (not zero) because sequence numbers zero and one were used by log
server initialization entries committed at startup.

---

## What Was Proved

A process with zero knowledge of the agent session independently verified five receipts using
only public log data. This demonstrates:

1. The protocol works end-to-end on real hardware with a production AI agent.
2. The log preserved receipt integrity: the verifier ran after the agent session ended,
   confirming persistence across server state.
3. The Merkle chain remained consistent through all 11 log entries. No tampering occurred
   between generation and verification.
4. Third-party verification requires no shared secrets, no session context, and no agent
   runtime access.

---

## Reproduction Instructions

To reproduce this proof:

**Step 1: Start the log server**
```bash
cd arc-protocol
pip install -e ".[dev]"
python -m uvicorn arc_log.server:app --host 127.0.0.1 --port 8080
```
Note the public key printed at startup.

**Step 2: Run a Claude Code session with ARC enabled**

Configure the ARC environment:
```python
import os
os.environ["ARC_LOG_URL"] = "http://localhost:8080"
```
Or use the `arc_shell.py` integration that wraps Claude Code tool calls with ARC receipts.

**Step 3: Collect receipt IDs**

Receipt IDs are printed to the agent session output as each tool call completes. Format:
`arc_[26 uppercase characters]`.

**Step 4: Verify from an isolated environment**

In a new terminal with no access to the agent session:
```python
import httpx

LOG_URL = "http://localhost:8080"
receipt_ids = ["arc_...", "arc_...", ...]  # from step 3

for rid in receipt_ids:
    resp = httpx.get(f"{LOG_URL}/v1/log/verify/{rid}")
    data = resp.json()
    valid = (
        data["is_consistent"]
        and data["intent_committed"]
        and data["receipt_committed"]
    )
    print(f"{rid}: valid={valid}")
```
