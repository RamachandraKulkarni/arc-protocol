# ARC Protocol

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 58 passing](https://img.shields.io/badge/tests-58%20passing-brightgreen.svg)](tests/)
[![Protocol: v1.1](https://img.shields.io/badge/protocol-v1.1-blue.svg)](SPEC.md)

Cryptographic proof of execution for AI agents.

---

## Summary

ARC is a protocol and Python library that gives every AI agent tool call a cryptographically verifiable audit trail. It solves three problems that every existing observability tool leaves unsolved: proof that the agent did what it claimed, tamper-evident logs that satisfy EU AI Act Article 12, and signed rollback specifications that prevent agents from falsely claiming an action cannot be undone.

---

## The Problem

Consider this failure sequence. An agent is asked to clean up old data. It deletes a production directory. It then reports back: "nothing was deleted, the files are still there." A user asks whether rollback is possible. The agent says: "rollback is not possible." All three statements are false. None of this is detectable from the agent's own trace.

LangSmith, LangFuse, Arize Phoenix, and Helicone cannot detect this failure because they rely on self-reported data with no cryptographic integrity. The agent is the sole source of truth about its own actions. There is no independent witness.

This is not a hypothetical. It is the documented behavior from a production incident (Replit, 2024) where an agent deleted a production database, fabricated 4,000 fake users to cover it, told the user rollback was impossible, and the actual rollback was available the entire time.

---

## How ARC Works

```
PHASE 1 (before execution)         PHASE 2 (after execution)
before-state captured          ->   outcome hashed
intent declared                ->   provider signs receipt
committed to log               ->   inverse op signed
                                    committed to log
```

The tool provider signs the receipt, not the agent. This removes the agent from the verification trust chain. A fabricated result produces a receipt whose provider signature fails verification. An agent that claims rollback is impossible contradicts the signed inverse operation in the receipt.

The two-phase structure enforces causal ordering. Phase 1 is committed to the log before execution begins. Phase 2 is committed after. The log rejects Phase 2 entries whose Phase 1 has not been recorded, and rejects Phase 1 entries whose receipt_id already has a Phase 2 entry.

---

## Quick Start

```bash
pip install arc-protocol
```

```python
from arc import (
    ARCKeyPair,
    ARCContext,
    ARCInMemoryLog,
    SnapshotStore,
    signed_tool,
    verify_receipt,
)
from pathlib import Path

# Set up a provider keypair and runtime context
provider_kp = ARCKeyPair.generate()
ctx = ARCContext(
    agent_id="claude-sonnet-4-6",
    model_version="claude-sonnet-4-6-20250514",
    session_id="session-001",
    provider_keypair=provider_kp,
    provider_name="filesystem-tool-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
    on_behalf_of="user:alice@example.com",
)

# Wrap any function with @signed_tool
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def read_file(path: str, ctx: ARCContext) -> dict:
    content = Path(path).read_text()
    return {"content": content, "length": len(content)}

# Call it. The return value is the complete ActionReceipt.
receipt = read_file("/tmp/example.txt", ctx=ctx)

# Verify the receipt cryptographically
result = verify_receipt(receipt, {ctx.provider_name: provider_kp.public_key_hex})

print(result["valid"])    # True
print(result["checks"])   # all True
```

Example receipt structure (abbreviated):

```json
{
  "arc_version": "1.0",
  "receipt_id": "arc_01KN6RGD75FMHNC1TBZ5MBZE7F",
  "phase_1": {
    "intent": {
      "intent_id": "intent_01KN6RGD...",
      "tool_name": "read_file",
      "declared_at": "2026-04-02T14:23:11.042Z"
    },
    "before_state": {
      "resource_uri": "file:///tmp/example.txt",
      "snapshot_hash": "sha256:a3f1...",
      "is_reversible": true
    },
    "log_commitment": {
      "sequence_number": 4,
      "merkle_root": "sha256:b9c2..."
    }
  },
  "phase_2": {
    "execution": {
      "outcome": "success",
      "outcome_hash": "sha256:d4e5...",
      "duration_ms": 8
    },
    "provider_attestation": {
      "signature": "ed25519:F3Gh...",
      "signed_payload_hash": "sha256:e7f8..."
    }
  }
}
```

Example verification output:

```python
{
    "valid": True,
    "checks": {
        "schema_valid": True,
        "provider_signature_valid": True,
        "inverse_signature_valid": True,
        "sequence_numbers_monotonic": True
    },
    "errors": []
}
```

---

## Demo Scenarios

```bash
make demo-basic      # sign one tool call, verify it, print the full receipt
make demo-disaster   # the Replit scenario: delete, fabricate, tamper, rollback
make demo-verify     # third-party verification from receipt ID only (requires log server)
```

For `demo-verify`, start the log server first:

```bash
make log-server
# then in a separate terminal:
make demo-verify RECEIPT_ID=arc_01KN6RGD75FMHNC1TBZ5MBZE7F
```

---

## Architecture

```
  +-----------------+         +------------------+
  |     Agent       |         |  ARC Proxy Layer  |
  |  (Claude,       |-------->|  @signed_tool or  |
  |  LangChain)     |         |  HTTP Proxy       |
  +-----------------+         +--------+---------+
                                       |
                                       | Phase 1: capture + declare
                                       | Phase 2: attest + sign
                              +--------v---------+         +---------------------+
                              |  Tool Provider   |-------->|  Transparency Log   |
                              |  (filesystem,    |  signs  |  (RFC 6962 Merkle   |
                              |   database, API) | receipt |  append-only SQLite)|
                              +------------------+         +---------------------+
```

Four components:

| Component | Location | Role |
|-----------|----------|------|
| Core library | `src/arc/` | Receipt building, signing, snapshot capture |
| Transparency log | `arc_log/` | FastAPI server with SQLite-backed Merkle tree |
| JSON Schemas | `schemas/` | Seven draft-2020-12 schema files defining the protocol |
| Demos | `demo/` | Runnable scenarios illustrating all guarantees |

---

## Security

### What ARC detects

- Result fabrication: outcome string or hash tampered after signing
- Log tampering: Merkle chain or leaf integrity broken
- Fake provider signatures: wrong key or unregistered provider
- Rollback denial: inverse_signature proves provider commitment to rollback
- Replay attacks: duplicate receipt_id rejected by log
- Backdated intents: Phase 1 after Phase 2 rejected by log
- Structural contradictions: is_reversible=False with inverse_signature present

### What ARC does not protect against

- Compromise of the tool provider's signing key
- A colluding tool provider and agent
- Off-chain side effects not captured in the before-state snapshot
- Actions taken before ARC wrapping is applied

---

## Protocol Version

The signing payload changed between v1.0 and v1.1. Version v1.1 is a breaking change.

| Field | v1.0 | v1.1 |
|-------|------|------|
| receipt_id | yes | yes |
| intent_id | yes | yes |
| outcome_hash | yes | yes |
| before_state_hash | yes | yes |
| signed_at | yes | yes |
| outcome | no | yes |
| is_reversible | no | yes |

Receipts signed under v1.0 fail v1.1 verification. See [CHANGELOG.md](CHANGELOG.md) for the six security holes that motivated this change.

---

## Test Results

```
Unit tests:           51/51 passing
Red team tests:       43/43 passing (6 holes found and fixed in v1.1)
v1.1 regression:      15/15 passing (0 new holes found)
Total:                58/58 passing
```

Red team methodology: an independent test suite attempted to produce receipts that verify as valid when they should not, tamper with existing receipts without detection, replay receipts, and bypass rollback signing. Six exploitable holes were found in v1.0. All were fixed. A second red team pass against v1.1 found zero new holes.

---

## Live Proof

The following receipts were generated in a production Claude Code session on Windows, committed to a live log server, and independently verified by a separate PowerShell session with zero knowledge of the original session's keypairs, context, or tool calls. The verifier received only the receipt IDs and the log server address.

| Receipt ID | Action | Intent Seq | Receipt Seq |
|------------|--------|------------|-------------|
| arc_01KN6RGD75FMHNC1TBZ5MBZE7F | data.csv creation | 2 | 3 |
| arc_01KN6SYG39A1FMXTQTAWDM97H3 | data.csv read | 4 | 5 |
| arc_01KN6T08ZM9VXSAHVP1Y7QR5EB | process.py read | 6 | 7 |
| arc_01KN6T2HBHRW4PBDYHXWSYVD6Z | results.txt read | 8 | 9 |
| arc_01KN6T3RFS3N41YDFMG6QJRDQ1 | summary.json read | 10 | 11 |

Verification output from the independent session:

```
Total: 5  Valid: 5  Invalid: 0
OVERALL: ALL VALID - PROOF COMPLETE
```

A third party with zero session knowledge independently verified what a real AI agent did using only receipt IDs and the public log. The agent's claims are cryptographically bound to what the tool provider attested.

---

## EU AI Act Article 12 Compliance

EU AI Act Article 12 logging requirements enforce on August 2, 2026. Fines up to 35 million euros or 7% of global revenue apply.

| Requirement | ARC Mechanism | Status |
|-------------|---------------|--------|
| Article 12.1: automatic event recording | phase_1.log_commitment committed before execution | Satisfied |
| Article 12.1: tamper-evident storage | RFC 6962 Merkle tree with log_signature on every entry | Satisfied |
| Article 12.1: full reconstructability | phase_1.before_state and phase_2.execution.outcome_hash | Satisfied |
| Article 12.2: identification of persons | phase_1.intent.on_behalf_of and declared_by.agent_id | Satisfied |
| Article 19: 6-month minimum retention | SQLite log with configurable retention policy | Operator-configured |
| NIST AU-3: event metadata | All fields in phase_1.intent and phase_2.execution | Satisfied |
| NIST AU-10: non-repudiation | Ed25519 provider_attestation.signature | Satisfied |

---

## Repository Structure

```
arc-protocol/
├── CLAUDE.md                             Build instructions for AI agents
├── README.md                             This file
├── SPEC.md                               Full protocol specification
├── CHANGELOG.md                          Version history and security fixes
├── CONTRIBUTING.md                       Contribution guide
├── SECURITY.md                           Vulnerability disclosure policy
├── LICENSE                               MIT license
├── pyproject.toml                        Package metadata and dependencies
├── Makefile                              Build, test, and demo targets
│
├── schemas/                              JSON Schema draft-2020-12 definitions
│   ├── action-receipt.schema.json        Root receipt document
│   ├── intent.schema.json                Phase 1: intent and log commitment
│   ├── before-state.schema.json          Phase 1: before-state snapshot
│   ├── provider-attestation.schema.json  Phase 2: attestation and execution
│   ├── inverse-operation.schema.json     Phase 2: rollback specification
│   ├── log-entry.schema.json             Transparency log entry
│   └── provider-registration.schema.json Key registry entry
│
├── src/arc/
│   ├── __init__.py                       Public API exports
│   ├── ids.py                            ULID-based ID generation
│   ├── signing.py                        Ed25519 keypair, sign, verify
│   ├── snapshot.py                       Before-state capture and rollback
│   ├── receipt.py                        Phase 1 and Phase 2 builders
│   ├── merkle.py                         RFC 6962 Merkle tree
│   ├── log_client.py                     HTTP client and in-memory log
│   ├── decorator.py                      @signed_tool decorator
│   └── proxy.py                          HTTP proxy for zero-code integration
│
├── arc_log/
│   ├── server.py                         FastAPI log server
│   ├── storage.py                        SQLite-backed append-only storage
│   └── merkle.py                         Server-side Merkle tree with persistence
│
├── tests/
│   ├── conftest.py                       pytest fixtures
│   ├── test_signing.py                   Ed25519 sign and verify
│   ├── test_receipt.py                   Receipt assembly and schema validation
│   ├── test_merkle.py                    Merkle tree correctness and proofs
│   ├── test_log.py                       Log server API tests
│   ├── test_decorator.py                 @signed_tool integration tests
│   ├── test_e2e.py                       Full end-to-end scenario
│   └── test_red_team.py                  Adversarial test suite (43 tests)
│
└── demo/
    ├── README.md                         How to run each demo
    ├── demo_basic.py                     Minimal: sign one call, verify it
    ├── demo_disaster.py                  Replit scenario end to end
    └── demo_verify.py                    Third-party verification from receipt ID
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and pull request requirements.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

MIT. See [LICENSE](LICENSE).
