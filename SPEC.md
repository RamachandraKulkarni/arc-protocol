# ARC Protocol Specification v1.0

## 1. Overview

ARC (Agent Receipt & Certification) is a cryptographic protocol for AI agent tool calls. It solves three interconnected problems:

1. **Proof of execution** — AI agents self-report their actions with no independent verification. ARC introduces a *tool-provider-signed* receipt that proves execution occurred and what the outcome actually was.

2. **Observability** — No standard schema exists for tamper-evident agent reasoning traces. ARC defines a two-phase structured receipt committed to an append-only Merkle transparency log.

3. **Reversibility** — No protocol exists for undoing agent actions. ARC captures before-state in a cryptographic snapshot and has the provider sign an inverse operation specification.

The core insight: these three problems are the same problem at three phases of execution. The solution is a single primitive — the **Action Receipt** — a two-phase, cryptographically signed record.

---

## 2. Threat Model

### What ARC protects against

- **Agent fabrication**: An agent reports a result that differs from what the tool actually produced. The `outcome_hash` in the receipt is computed and signed by the tool provider, not the agent. A fabricated report produces a hash mismatch.

- **Log tampering**: An agent (or compromised system) modifies log entries to hide what happened. The Merkle tree chains every entry to the next; modifying any entry breaks the chain.

- **Rollback denial**: An agent falsely claims that an action cannot be undone. The inverse operation specification is signed by the provider and embedded in the receipt. The agent has no authority to override it.

- **Unauthorized actions**: By recording `declared_by`, `on_behalf_of`, and `authorization.scope`, ARC creates an auditable delegation chain.

- **Replay attacks**: `sequence_number` in log commitments is monotonically increasing. A replayed entry would have a non-sequential sequence number.

### What ARC does NOT protect against

- **Compromised tool provider**: If the provider itself is malicious, it can sign false receipts. ARC assumes the provider is trusted. This is the same assumption made by all current tool protocols (MCP, function calling).

- **Off-chain verification of execution**: ARC proves what the provider *attested*, not that the computation itself was correct. TEE (Trusted Execution Environment) integration is out of scope for v1.

- **Content of reasoning**: The `reasoning_commitment` is a hash commitment; the pre-image is stored by the agent runtime. ARC cannot verify the reasoning was genuine.

- **Side channels**: ARC does not protect against network-level interception between agent and provider.

---

## 3. Protocol Description

### Phase 1 (Pre-Action Declaration)

Before a tool executes, the system:

1. **Generates IDs**: A `receipt_id` (arc_...) and `intent_id` (intent_...) are generated using ULID.

2. **Captures before-state**: A cryptographic snapshot of the target resource is captured. For filesystems, this includes file contents (base64-encoded) to enable rollback. The snapshot is stored in a `SnapshotStore` indexed by `snapshot_ref` (snap_...).

3. **Builds the Intent block**: Contains `tool_name`, `arguments`, `declared_by` (agent identity), `reasoning_commitment` (SHA-256 of the agent's reasoning text), and `declared_at` (timestamp).

4. **Commits to log**: The intent is committed to the transparency log. The log returns a `LogCommitment` containing `sequence_number`, `merkle_root` (after this entry was appended), and `committed_at`.

5. **Returns Phase 1 dict**: Contains `intent`, `before_state`, and `log_commitment`. This is immutable once committed.

### Phase 2 (Post-Execution Attestation)

After the tool executes, the provider:

1. **Records execution**: `started_at`, `completed_at`, `duration_ms`, and `outcome` (success/failure/partial).

2. **Computes outcome hash**: SHA-256 of the canonical JSON of the actual tool return value. This is what gets signed.

3. **Builds signing payload**: `sha256_hex(canonical_json({receipt_id, intent_id, outcome_hash, before_state_hash, signed_at}))`. This exact set of five fields is what the provider signs.

4. **Signs with Ed25519**: The provider's private key signs the signing payload. The signature is stored as `ed25519:` + base64(64-byte signature).

5. **Signs the inverse operation**: If the action is reversible, the provider signs `sha256_hex(canonical_json({receipt_id, inverse_tool, inverse_arguments, valid_until}))`. This proves the provider committed to supporting rollback.

6. **Commits receipt to log**: The complete receipt is committed. The log returns a second `LogCommitment` (`log_proof`).

7. **Returns complete ActionReceipt**.

---

## 4. Schema Reference

All schemas use JSON Schema draft-2020-12. See `schemas/` directory.

### `action-receipt.schema.json`
Root document. Fields: `arc_version` ("1.0"), `receipt_id` (arc_ + ULID), `phase_1`, `phase_2`.

### `intent.schema.json`
Phase 1 structures. Key `$defs`: `Phase1`, `Intent`, `LogCommitment`.

- `Intent.intent_id`: intent_ + ULID
- `Intent.reasoning_commitment`: SHA-256 of agent reasoning text (pre-image stored separately)
- `LogCommitment.sequence_number`: monotonically increasing; gaps indicate tampering
- `LogCommitment.merkle_root`: Merkle root AFTER this entry; enables consistency checks

### `before-state.schema.json`
Pre-action resource snapshot.

- `resource_uri`: URI identifying the resource (e.g., `file:///data/users/`, `db://mydb/table`)
- `resource_type`: enum of 12 resource categories
- `snapshot_ref`: snap_ + ULID; references stored snapshot content
- `snapshot_hash`: SHA-256 of canonical JSON of the snapshot content
- `is_reversible`: whether rollback is possible for this resource type

### `provider-attestation.schema.json`
Phase 2 structures. Key `$defs`: `Phase2`, `Execution`, `Attestation`.

- `Execution.outcome_hash`: SHA-256 of canonical JSON of the actual tool return value
- `Attestation.signature`: ed25519: + base64(64-byte Ed25519 signature)
- `Attestation.signed_payload_hash`: SHA-256 of the canonical signing payload

### `inverse-operation.schema.json`
Rollback specification. If `is_reversible=true`, requires `inverse_tool`, `inverse_arguments`, `valid_until`, `inverse_signature`.

### `log-entry.schema.json`
Transparency log entry. Chains via `previous_root` → `merkle_root`. Signed by the log operator.

### `provider-registration.schema.json`
Key registry. Maps `provider_id` to `public_key_hex` (64-char lowercase hex Ed25519 public key).

---

## 5. Signing Specification

### Algorithm
Ed25519 (RFC 8032). 32-byte private key, 32-byte public key, 64-byte signature.

### Provider Signing Payload
The exact payload the provider signs is constructed as follows:

```python
payload_obj = {
    "before_state_hash": before_state_hash,  # sha256:... of snapshot
    "intent_id": intent_id,                   # intent_... ULID
    "outcome_hash": outcome_hash,             # sha256:... of result
    "receipt_id": receipt_id,                 # arc_... ULID
    "signed_at": signed_at,                   # ISO 8601 UTC timestamp
}
canonical = canonical_json(payload_obj)       # see below
payload_hash = sha256_hex(canonical)          # sha256:... prefixed
signing_input = payload_hash.encode("utf-8") # bytes to sign
```

### Canonical JSON
Rules (must be followed exactly; both signers and verifiers use this):
- Keys sorted alphabetically at every nesting level
- No extra whitespace (compact: no spaces after `:` or `,`)
- UTF-8 encoding
- `None`/`null` → JSON `null`

Example: `{"z": 1, "a": 2}` → `b'{"a":2,"z":1}'`

### Signature Format
`ed25519:` + base64-standard (with padding) encoding of the 64-byte signature.
Pattern: `^ed25519:[A-Za-z0-9+/]{86}==$`

### Inverse Operation Signing Payload
```python
inv_payload_obj = {
    "inverse_arguments": inverse_arguments,
    "inverse_tool": inverse_tool,
    "receipt_id": receipt_id,
    "valid_until": valid_until,
}
inv_payload = sha256_hex(canonical_json(inv_payload_obj)).encode("utf-8")
```

---

## 6. Merkle Tree Specification

ARC uses RFC 6962-compatible binary Merkle trees.

### Hash Functions

**Leaf hash** (domain prefix `0x00`):
```
leaf_hash(data) = SHA-256(0x00 || data)
```

**Node hash** (domain prefix `0x01`):
```
node_hash(left, right) = SHA-256(0x01 || raw(left) || raw(right))
```

where `raw(h)` strips the `sha256:` prefix and returns the 32 raw bytes.

**Empty tree root**: `SHA-256(b"")` (SHA-256 of empty bytes)

### Domain Separation
The `0x00`/`0x01` prefixes are required. Without them, an attacker can construct a node hash that equals a leaf hash, enabling second-preimage attacks.

### Inclusion Proof
A list of sibling hashes from the leaf level to the root. Verify by reconstructing the path from leaf to root, trying left/right orderings at each level until the expected root is matched.

### Append-Only Guarantee
The `previous_root` field in each log entry is the Merkle root *before* the entry was appended. The `merkle_root` field is the root *after*. Any modification to an earlier entry changes its contribution to the root, breaking the chain at the next entry.

---

## 7. Log API Specification

### `POST /v1/log/intent`
Commit a Phase 1 intent to the log.

Request:
```json
{"receipt_id": "arc_...", "intent": {...intent object...}}
```

Response:
```json
{
  "log_entry": {...LogEntry...},
  "commitment": {
    "log_id": "arc-log-v1",
    "sequence_number": 0,
    "merkle_root": "sha256:...",
    "inclusion_proof": [...],
    "committed_at": "2026-04-02T00:00:00Z"
  }
}
```

### `POST /v1/log/receipt`
Commit a complete receipt to the log. Requires a matching intent entry to already exist.

Request:
```json
{"receipt": {...complete ActionReceipt...}}
```

Response: same structure as intent.

### `GET /v1/log/verify/{receipt_id}`
Verify a receipt is in the log. Public, no authentication.

Response:
```json
{
  "receipt_id": "arc_...",
  "found": true,
  "entries": [...],
  "intent_committed": true,
  "receipt_committed": true,
  "is_consistent": true,
  "verification_time": "2026-04-02T00:00:00Z"
}
```

### `GET /v1/log/entries?from_seq=0&limit=10`
Return log entries from sequence `from_seq`, up to `limit` entries (max 100).

### `GET /v1/log/root`
Return the current signed tree head.

Response:
```json
{
  "sequence_number": 42,
  "merkle_root": "sha256:...",
  "timestamp": "2026-04-02T00:00:00Z",
  "log_signature": "ed25519:..."
}
```

---

## 8. Verification Algorithm

Given a receipt `R` and a `provider_registry = {provider_id: public_key_hex}`:

1. **Schema check**: Validate `R` against `action-receipt.schema.json`. If invalid, `valid=False`.

2. **Lookup provider**: Find `public_key_hex` by `R.phase_2.provider_attestation.provider_id`. If not found, `valid=False`.

3. **Reconstruct signing payload**:
   ```python
   payload = build_signing_payload(
       receipt_id = R.receipt_id,
       intent_id = R.phase_1.intent.intent_id,
       outcome_hash = R.phase_2.execution.outcome_hash,
       before_state_hash = R.phase_1.before_state.snapshot_hash,
       signed_at = R.phase_2.provider_attestation.signed_at,
   )
   ```

4. **Verify Ed25519 signature**: `verify(payload, R.phase_2.provider_attestation.signature, public_key_hex)`. If fails, `valid=False`.

5. **Verify inverse signature** (if `is_reversible=True`):
   ```python
   inv_payload = sha256_hex(canonical_json({
       "inverse_arguments": R.phase_2.inverse.inverse_arguments,
       "inverse_tool": R.phase_2.inverse.inverse_tool,
       "receipt_id": R.receipt_id,
       "valid_until": R.phase_2.inverse.valid_until,
   })).encode("utf-8")
   verify(inv_payload, R.phase_2.inverse.inverse_signature, public_key_hex)
   ```

6. **Monotonicity check**: `R.phase_2.log_proof.sequence_number > R.phase_1.log_commitment.sequence_number`. If not, `valid=False`.

7. Return `{"valid": all_checks_pass, "checks": {...}, "errors": [...]}`

---

## 9. Rollback Algorithm

Given a receipt `R` and a `SnapshotStore`:

1. Check `R.phase_2.inverse.is_reversible == True`.
2. Check `R.phase_2.inverse.valid_until > now()`.
3. Verify the inverse signature (step 5 of Verification Algorithm).
4. Retrieve snapshot: `snap = store.retrieve(R.phase_1.before_state.snapshot_ref)`.
5. Verify: `sha256_hex(canonical_json(snap.content)) == R.phase_1.before_state.snapshot_hash`.
6. Execute rollback:
   - For `filesystem:file`: restore file bytes from `snap.content.content_b64`
   - For `filesystem:directory`: recreate all files from `snap.content.files[*].content_b64`
   - For `memory:key`: restore dict from `snap.content`
   - For `api:response`: not reversible by default
7. Return success/failure.

---

## 10. Integration Guide

### LangChain

```python
from langchain.tools import tool
from arc import signed_tool, ARCContext

@tool
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def delete_file(path: str, ctx: ARCContext) -> dict:
    """Delete a file from the filesystem."""
    os.remove(path)
    return {"deleted": path}

# Pass ctx via tool metadata or as a bound parameter
```

### OpenAI Agents SDK

```python
from agents import function_tool
from arc import signed_tool, ARCContext

@function_tool
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def read_file(path: str, ctx: ARCContext) -> dict:
    return {"content": open(path).read()}
```

### Raw MCP

ARC can wrap MCP tool handlers:

```python
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    # Before: capture state, declare intent to log
    snap = capture_filesystem(arguments["path"], store)
    receipt_id, phase1 = builder.declare_intent(name, arguments, snap, reasoning)

    # Execute the actual MCP tool
    result = await actual_tool_handler(name, arguments)

    # After: sign and commit
    receipt = builder.attest_execution(receipt_id, kp, "mcp-server-v1", "success", result, phase1)

    # Return result with receipt ID in metadata
    return [TextContent(type="text", text=json.dumps(result))]
```

---

## 11. EU AI Act Compliance Map

Article 12 (Transparency through logging) requires:

| Requirement | ARC Implementation |
|---|---|
| Logging shall be automatic | `@signed_tool` decorator; zero agent cooperation required |
| Tamper-evident records | RFC 6962 Merkle tree; `previous_root` chains all entries |
| Log what system did | `phase_2.execution.outcome_hash` — SHA-256 of actual tool output |
| Log state before action | `phase_1.before_state.snapshot_hash` — before-state hash |
| Timestamps | `declared_at`, `started_at`, `completed_at`, log `timestamp` |
| System identification | `declared_by.agent_id`, `declared_by.model_version` |
| Operator identification | `on_behalf_of`, `authorization.granted_by` |
| 6-month retention capable | SQLite log server with configurable retention |
| Accessible to authorities | `GET /v1/log/verify/{receipt_id}` — public read endpoint |
| Enable supervisory access | Merkle root published at `GET /v1/log/root` |

Fines for non-compliance: up to €35M or 7% of global annual revenue. Enforcement begins **August 2, 2026**.

---

## 12. Known Limitations

1. **Compromised provider**: ARC cannot detect a malicious tool provider signing false receipts. The provider trust model is the same as all current protocols. TEE integration (e.g., AWS Nitro, Azure Confidential Computing) would address this.

2. **Off-chain verification**: ARC proves what was *attested*, not that the computation was *correct*. Formal verification of tool behavior is out of scope.

3. **Snapshot size**: For large resources (multi-GB databases), storing full before-state is impractical. Production deployments should use `snapshot_ref` to point to external storage (S3, etc.) rather than embedding content.

4. **Time synchronization**: Receipt timestamps rely on system clocks. Clock skew can cause minor timestamp ordering anomalies. NTP synchronization is assumed.

5. **Key rotation**: The provider-registration schema supports `revoked_at` but v1 has no key rotation ceremony. Production deployments should implement key rotation with overlap periods.

6. **Multi-party receipts**: ARC v1 handles single provider signatures. Multi-party signing (e.g., two-of-three provider attestation) is a future extension.

7. **Network partitions**: If the log server is unavailable, `ARCLogClient` will raise `ARCLogError`. The decorator will not execute the tool (fail-open vs fail-closed is configurable in future versions). `ARCInMemoryLog` provides a local fallback.
