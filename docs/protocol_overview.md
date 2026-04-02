# Protocol Overview

ARC (Agent Receipt and Certification) gives every AI agent tool call a cryptographically verifiable audit trail. This document explains how the protocol works conceptually. For the exact signing specification, see [signing_specification.md](signing_specification.md).

## The Three Problems

**Problem 1: No proof of execution.**
When an agent says "I deleted the file," there is no cryptographic proof it happened. The agent is the sole source of truth about its own actions. No existing protocol verifies the agent's claim against an independent record.

**Problem 2: No tamper-evident observability.**
Existing observability tools (LangSmith, LangFuse, Arize Phoenix) capture execution traces. These traces are mutable and self-reported. An agent that modifies its own trace produces one that is structurally identical to an unmodified trace. None of these tools satisfies EU AI Act Article 12 tamper-evidence requirements.

**Problem 3: No reversibility.**
No standard protocol exists for undoing agent actions. An agent that claims rollback is impossible cannot be contradicted. An agent that deleted data and wants to cover the deletion has no signed commitment to contradict.

## The Action Receipt

ARC solves all three problems with one primitive: the Action Receipt.

An Action Receipt is a two-phase cryptographic structure:

```
PHASE 1 (before execution)         PHASE 2 (after execution)
before-state captured          ->   outcome hashed
intent declared                ->   provider signs receipt
committed to log               ->   inverse op signed
                                    committed to log
```

Phase 1 commits before the action executes. Phase 2 commits after. The gap between them is the actual tool execution.

## The Critical Architectural Decision

The tool provider signs the receipt, not the agent.

This removes the agent from the verification trust chain. An agent that fabricates a result produces a receipt whose provider signature fails verification because the provider signed the actual outcome_hash. An agent that lies about rollback availability contradicts the signed inverse operation in the receipt because the provider committed to rollback availability with its private key.

No matter what the agent reports, the signed receipt is an independent record.

## Phase 1: Pre-Action Declaration

Before a tool executes, ARC takes the following steps:

1. Captures the before-state of the resource being acted upon. For a filesystem path, this means reading the file contents and recording the hash. For an in-memory dict, this means making a deep copy. The snapshot is stored by reference (snap_... ID) so large snapshots do not bloat the receipt.

2. Declares the intent: tool name, exact arguments, agent identity (agent_id, model_version, session_id), the user on whose behalf the action is taken (on_behalf_of), and a reasoning commitment (SHA-256 of the agent's reasoning text).

3. Commits the intent and before-state hash to the transparency log. The log returns a sequence number and a Merkle inclusion proof. These are embedded in the receipt as the Phase 1 log commitment.

## Phase 2: Post-Execution Attestation

After the tool executes, the tool provider takes the following steps:

1. Computes outcome_hash: SHA-256 of the canonical JSON of the actual tool result.

2. Constructs the signing payload as a canonical JSON object with these fields (sorted alphabetically, no whitespace, UTF-8 encoding): before_state_hash, intent_id, is_reversible, outcome, outcome_hash, receipt_id, signed_at.

3. Signs the payload with Ed25519. Stores the signature in provider_attestation.signature.

4. Optionally signs a rollback specification containing: receipt_id, inverse_tool, inverse_arguments, valid_until. This produces the inverse_signature.

5. Commits the complete receipt to the transparency log. The log returns a second sequence number and Merkle proof.

## The Transparency Log

The log is an RFC 6962-compatible append-only Merkle tree. Every log entry contains:
- A sequence number (monotonically increasing; gaps indicate tampering)
- content_hash (SHA-256 of the committed content)
- previous_root (Merkle root before this entry)
- merkle_root (Merkle root after this entry)
- log_signature (log operator's Ed25519 signature over the entry)

Two consistency checks detect tampering:

1. Chain check: previous_root of entry N+1 must equal merkle_root of entry N.
2. Leaf integrity check: rebuild the Merkle tree from all content_hashes and verify the rebuilt root matches the stored root.

## Verification

Anyone with a receipt_id and the log server URL can verify the receipt:

```
GET /v1/log/verify/{receipt_id}
```

Returns:
- found: whether the receipt exists in the log
- is_consistent: whether the Merkle chain is intact
- intent_committed: whether Phase 1 was committed (at a lower sequence number than Phase 2)
- receipt_committed: whether Phase 2 was committed

No shared secrets are required. No access to the agent session is needed. No authentication is required for reads.

## Rollback

If is_reversible=True in the receipt, the inverse operation specifies how to undo the action. The before-state snapshot (retrieved by snapshot_ref) contains the full resource state before the action. rollback_filesystem() recreates deleted files, restores modified files, and removes created files.

The inverse_signature proves the provider committed to rollback availability. An agent cannot alter it.

## Relationship to Existing Protocols

| Protocol | Timestamps | Caller Identity | Before-State | Crypto Signing | Rollback |
|----------|-----------|----------------|--------------|----------------|---------|
| MCP (tools/call) | No | No | No | No | No |
| OpenAI function calling | No | No | No | No | No |
| Anthropic tool_use | No | No | No | No | No |
| LangSmith traces | Post-hoc | Partial | No | No | No |
| ARC Action Receipt | Yes (two phases) | Yes | Yes | Yes (provider) | Yes (signed) |

ARC is designed to compose with these protocols, not replace them. The @signed_tool decorator wraps any function. The HTTP proxy wraps any tool endpoint. ARC adds the receipt layer without requiring changes to the underlying protocol.

## EU AI Act Article 12 Compliance

Article 12 requires logging systems for high-risk AI that are tamper-evident, time-stamped, and sufficient to reconstruct the AI system's reasoning.

| Article 12 Requirement | ARC Field |
|------------------------|-----------|
| Tamper-evident logs | Merkle tree with RFC 6962 chain; log_signature per entry |
| Timestamps | declared_at (Phase 1), completed_at (Phase 2) |
| Input/output recording | arguments (input), outcome_hash (output) |
| Duration recording | execution.duration_ms |
| Reasoning traceability | reasoning_commitment (hash of reasoning text) |
| Actor identification | declared_by.agent_id, declared_by.model_version |
| Authorization chain | authorization.delegation_chain |

The transparency log's append-only structure and cryptographic chain mean entries cannot be altered retroactively without detection. This satisfies the tamper-evidence requirement.
