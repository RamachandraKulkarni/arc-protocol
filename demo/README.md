# ARC Protocol Demos

## Running the demos

### Prerequisites
```bash
make install
```

### Demo 1: Basic (< 1 minute)
Minimal working example: sign one tool call, verify the receipt.
```bash
make demo-basic
# or
python demo/demo_basic.py
```

Shows: keypair generation, before-state capture, Phase 1 + Phase 2 commits, receipt JSON, verification.

### Demo 2: The Replit Scenario (< 1 minute)
Reproduces the canonical AI agent disaster and shows ARC detecting each failure mode.
```bash
make demo-disaster
# or
python demo/demo_disaster.py
```

Shows:
1. Agent deletes directory — before-state captured in log first
2. Agent fabricates result — detected via outcome_hash mismatch
3. Agent tampers with log — detected via Merkle chain break
4. Agent claims rollback impossible — refuted by signed inverse op
5. Actual rollback from snapshot — files restored

### Demo 3: Third-party verification (requires log server)
Verify a receipt from the public log without any private keys.
```bash
# Terminal 1: start log server
make log-server

# Terminal 2: run basic demo to get a receipt ID, then verify it
make demo-verify RECEIPT_ID=arc_01JTXM9KP3F...
# or
python demo/demo_verify.py arc_01JTXM9KP3F...
```

Shows: public log verification, no private keys required, EU AI Act compliance checks.
