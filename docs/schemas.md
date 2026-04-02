# Schema Reference

ARC uses seven JSON Schema draft-2020-12 files to define the protocol. All schemas are in the schemas/ directory.

## Schema 1: action-receipt.schema.json

Root document. Every Action Receipt must validate against this schema.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| arc_version | string | yes | Protocol version. Value: "1.0". |
| receipt_id | string | yes | Globally unique receipt ID. Pattern: arc_[0-9A-Z]{26} |
| phase_1 | object | yes | Pre-action declaration. See intent.schema.json. |
| phase_2 | object | yes | Post-execution attestation. See provider-attestation.schema.json. |

## Schema 2: intent.schema.json

Phase 1 pre-action declaration. Contains three required blocks.

### Phase1 Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| intent | object | yes | The intent declaration. |
| before_state | object | yes | Pre-action resource snapshot. |
| log_commitment | object | yes | Proof of Phase 1 log commit. |

### Intent Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| intent_id | string | yes | Pattern: intent_[0-9A-Z]{26} |
| tool_name | string | yes | Name of the tool as registered by the provider. |
| arguments | object | yes | Exact arguments passed to the tool. |
| declared_by | object | yes | Agent identity: agent_id, model_version, session_id. |
| reasoning_commitment | string | yes | SHA-256 of reasoning text. Pattern: sha256:[a-f0-9]{64} |
| declared_at | string | yes | ISO 8601 UTC timestamp. Must be before execution. |
| tool_provider_id | string | no | Provider DID or URI. |
| on_behalf_of | string | no | User who authorized this action. |
| authorization | object | no | Scope, delegation chain, parent receipt. |

### LogCommitment Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| log_id | string | yes | Transparency log identifier. |
| sequence_number | integer | yes | Monotonically increasing. Minimum 0. |
| merkle_root | string | yes | Merkle root after this entry. Pattern: sha256:[a-f0-9]{64} |
| committed_at | string | yes | ISO 8601 UTC timestamp. |
| inclusion_proof | array | no | Sibling hashes from leaf to root. |

## Schema 3: before-state.schema.json

Pre-action resource snapshot.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| resource_uri | string | yes | URI of the resource. Examples: file:///data/file.txt, db://mydb/table, memory:key. |
| resource_type | string | yes | Enumeration. See resource type table below. |
| snapshot_hash | string | yes | SHA-256 of canonical JSON of snapshot content. Pattern: sha256:[a-f0-9]{64} |
| captured_at | string | yes | ISO 8601 UTC timestamp. |
| snapshot_ref | string | no | Reference ID for stored snapshot. Pattern: snap_[0-9A-Z]{26} |
| snapshot_size_bytes | integer | no | Size of snapshot in bytes. |
| is_reversible | boolean | no | Whether this resource type supports rollback. |

Resource type enumeration (12 values):

| Value | Description |
|-------|-------------|
| filesystem:file | A single file on disk |
| filesystem:directory | A directory and its contents recursively |
| database:row | A single database row |
| database:table | An entire database table |
| database:collection | A document store collection |
| email:message | A single email message |
| email:inbox | An email inbox |
| api:response | An API response (read before write) |
| memory:key | A single key in an in-memory store |
| memory:namespace | A named set of keys |
| process:state | A running process state |
| custom | Caller-defined resource type |

## Schema 4: provider-attestation.schema.json

Phase 2 post-execution attestation. Contains three required blocks.

### Phase2 Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| execution | object | yes | Execution record. |
| provider_attestation | object | yes | Provider signature block. |
| log_proof | object | yes | Phase 2 log commitment (same structure as LogCommitment). |
| inverse | object | no | Rollback specification. See inverse-operation.schema.json. |

### Execution Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| started_at | string | yes | ISO 8601 UTC timestamp. |
| completed_at | string | yes | ISO 8601 UTC timestamp. |
| duration_ms | integer | yes | Wall-clock duration in milliseconds. Minimum 0. |
| outcome | string | yes | One of: success, failure, partial. |
| outcome_hash | string | yes | SHA-256 of canonical JSON of actual tool result. |
| error_code | string | no | Provider error code. Present only on failure or partial. |
| error_message | string | no | Human-readable error. Present only on failure. |

Outcome values:
- success: tool completed without error
- failure: tool errored
- partial: tool partially completed (example: three of five files deleted)

### Attestation Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| provider_id | string | yes | Provider DID or URI. Must match a key in the registry. |
| provider_name | string | yes | Human-readable name and version. |
| signed_at | string | yes | ISO 8601 UTC timestamp. Must be >= completed_at. |
| signature | string | yes | Ed25519 signature. Pattern: ed25519:[A-Za-z0-9+/]{86}== |
| signed_payload_hash | string | yes | SHA-256 of the canonical signing payload. Pattern: sha256:[a-f0-9]{64} |

## Schema 5: inverse-operation.schema.json

Rollback specification. Fields other than is_reversible are conditionally required when is_reversible=true.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| is_reversible | boolean | yes | If false, all other fields are absent. Rollback is not possible. |
| inverse_tool | string | conditional | Required when is_reversible=true. Tool name for rollback. |
| inverse_arguments | object | conditional | Required when is_reversible=true. Arguments to inverse_tool. |
| valid_until | string | conditional | Required when is_reversible=true. Expiry timestamp for rollback availability. |
| inverse_signature | string | conditional | Required when is_reversible=true. Provider's Ed25519 signature over the rollback spec. |
| estimated_duration_ms | integer | no | Estimated rollback time in milliseconds. |

The inverse_signature covers the payload: SHA-256 of the canonical JSON of {receipt_id, inverse_tool, inverse_arguments, valid_until}. This signature proves the provider committed to supporting the rollback. An agent cannot forge or alter it.

## Schema 6: log-entry.schema.json

Transparency log entry. Every commit to the log produces one of these.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| entry_id | string | yes | Pattern: log_[0-9A-Z]{26} |
| entry_type | string | yes | One of: intent (Phase 1), receipt (Phase 2). |
| sequence_number | integer | yes | Monotonically increasing. Gaps indicate tampering. |
| receipt_id | string | yes | The receipt this entry belongs to. Pattern: arc_[0-9A-Z]{26} |
| content_hash | string | yes | SHA-256 of committed content. |
| previous_root | string | yes | Merkle root before this entry. |
| merkle_root | string | yes | Merkle root after this entry. |
| timestamp | string | yes | ISO 8601 UTC timestamp. |
| log_signature | string | yes | Log operator Ed25519 signature. Pattern: ed25519:[A-Za-z0-9+/]{86}== |

The chain property: for any two consecutive entries N and N+1, the previous_root of entry N+1 must equal the merkle_root of entry N. Any break in this chain indicates tampering.

## Schema 7: provider-registration.schema.json

Key registry entry. Maps a provider to its Ed25519 public key.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| provider_id | string | yes | Stable identifier. Format: tool:{name}:{version} or a DID. |
| provider_name | string | yes | Human-readable name. |
| public_key_hex | string | yes | Ed25519 public key as 64-character lowercase hex. Pattern: [a-f0-9]{64} |
| capabilities | array | yes | List of resource types this provider can attest. |
| registered_at | string | yes | ISO 8601 UTC registration timestamp. |
| revoked_at | string or null | no | Revocation timestamp. Null if active. |

## ID Format Reference

All ARC identifiers use a common format: a prefix followed by a 26-character ULID (uppercase, base32).

| Prefix | Example | Schema field |
|--------|---------|-------------|
| arc_ | arc_01JTXM9KP3FABCDEFGHIJK | receipt_id |
| intent_ | intent_01JTXM9KP3FABCDEFGHIJK | intent_id |
| snap_ | snap_01JTXM9KP3FABCDEFGHIJK | snapshot_ref |
| log_ | log_01JTXM9KP3FABCDEFGHIJK | entry_id |

ULIDs are lexicographically sortable and encode a timestamp in the first ten characters. Two IDs generated in the same millisecond differ only in the random component.

## Hash Format Reference

All hashes in ARC use a prefixed hex string format: sha256: followed by 64 lowercase hex characters (32 bytes).

```
sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
```

All signatures use the prefix ed25519: followed by 88 characters of base64url encoding (64 bytes, base64-padded).

```
ed25519:MEUCIQD3jKPiEk3F7zVnvKi5ozUFhLlVs7Hk6M8kVsGAFg+KNwIgR...==
```

Strip the prefix before performing cryptographic operations.
