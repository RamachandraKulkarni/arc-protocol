# ARC Protocol Signing Specification

This specification is complete enough to implement a verifier from scratch in any language.

---

## Signing Algorithm

ARC uses Ed25519 as defined in RFC 8032. Ed25519 produces 64-byte signatures from 32-byte
private keys and 32-byte public keys. Signatures are encoded as base64 with the prefix
"ed25519:".

Python reference implementation uses:
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
```

---

## Canonical JSON

Canonical JSON is the deterministic serialization used for all signing and hashing operations.
Both the signer and the verifier must produce identical bytes from the same input.

Rules:

1. Keys sorted alphabetically at every nesting level.
2. No extra whitespace (no spaces after colons or commas).
3. UTF-8 encoding.
4. JSON null for Python `None` values.
5. No trailing newline.

Reference implementation:
```python
import json

def canonical_json(obj: dict) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        allow_nan=False,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
```

Test vector:

- Input: `{"z": 1, "a": 2, "m": {"b": 3, "a": 4}}`
- Output bytes: `{"a":2,"m":{"a":4,"b":3},"z":1}` (UTF-8)

---

## v1.1 Signing Payload Fields

The signing payload contains exactly seven fields. All are required. The field names are sorted
alphabetically (canonical JSON).

| Field | Type | Description |
|-------|------|-------------|
| `before_state_hash` | string | SHA-256 hash of the before-state snapshot, prefixed "sha256:" |
| `intent_id` | string | The intent ID from Phase 1, prefixed "intent_" |
| `is_reversible` | boolean | Whether the action supports rollback |
| `outcome` | string | One of: "success", "failure", "partial" |
| `outcome_hash` | string | SHA-256 hash of the canonical JSON of the tool result, prefixed "sha256:" |
| `receipt_id` | string | The receipt ID, prefixed "arc_" |
| `signed_at` | string | ISO 8601 UTC timestamp of signing, e.g. "2026-04-02T12:00:00Z" |

---

## Step-by-Step Payload Construction

1. Collect the seven field values.
2. Construct a dict with exactly these seven keys.
3. Serialize with `canonical_json()` to produce UTF-8 bytes.
4. Compute SHA-256 of the canonical JSON bytes:
   `sha256_bytes = hashlib.sha256(canonical_bytes).digest()`
5. Encode as hex with "sha256:" prefix:
   `signed_payload_hash = "sha256:" + sha256_bytes.hex()`

The `signed_payload_hash` is stored in the receipt at
`phase_2.provider_attestation.signed_payload_hash`.

---

## Step-by-Step Signature Construction

1. Construct the signing payload (seven fields, canonical JSON, SHA-256 hash as above).
2. The bytes to sign are the UTF-8 encoding of the `signed_payload_hash` string.
   Example: `b"sha256:abcdef1234..."`
3. Sign with Ed25519: `sig_bytes = private_key.sign(payload_hash_bytes)`
4. Encode as base64: `sig_b64 = base64.b64encode(sig_bytes).decode("ascii")`
5. Prepend prefix: `signature = "ed25519:" + sig_b64`

The signature is stored at `phase_2.provider_attestation.signature`.

---

## Step-by-Step Verification

1. Extract `signed_payload_hash` from `phase_2.provider_attestation.signed_payload_hash`.
2. Extract `signature` from `phase_2.provider_attestation.signature`.
3. Reconstruct the signing payload from the seven fields in the receipt.
4. Recompute `canonical_json()` of the reconstructed payload.
5. Recompute SHA-256 of the canonical JSON bytes.
6. Compare with `signed_payload_hash`. If they differ, the payload was tampered.
7. Decode the signature: strip "ed25519:" prefix, base64-decode to 64 bytes.
8. Get the provider's public key from the registry using `provider_id`.
9. Call `Ed25519PublicKey.verify(signature_bytes, payload_hash_bytes)`.
10. If `verify()` raises, the signature is invalid.

---

## Inverse Operation Signing Payload

The inverse operation uses a separate four-field signing payload.

| Field | Type | Description |
|-------|------|-------------|
| `inverse_arguments` | object | Arguments to pass to `inverse_tool` |
| `inverse_tool` | string | Tool name for rollback |
| `receipt_id` | string | The receipt ID this inverse operation belongs to |
| `valid_until` | string | ISO 8601 UTC timestamp after which rollback may not be available |

Construction follows the same canonical JSON + SHA-256 + Ed25519 process as the main payload.

The `inverse_signature` is stored at `phase_2.inverse.inverse_signature`.

---

## Test Vector

Payload fields:
```json
{
  "before_state_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "intent_id": "intent_01EXAMPLE00000000000000001",
  "is_reversible": true,
  "outcome": "success",
  "outcome_hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "receipt_id": "arc_01EXAMPLE00000000000000001",
  "signed_at": "2026-04-02T12:00:00Z"
}
```

Canonical JSON bytes (UTF-8):
```
{"before_state_hash":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","intent_id":"intent_01EXAMPLE00000000000000001","is_reversible":true,"outcome":"success","outcome_hash":"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","receipt_id":"arc_01EXAMPLE00000000000000001","signed_at":"2026-04-02T12:00:00Z"}
```

A valid signature has the form:
```
ed25519:AAAA...AAAA==
```
where `AAAA...AAAA==` is 88 base64 characters encoding 64 bytes.

---

## Version Comparison

| Field | v1.0 | v1.1 |
|-------|------|------|
| `receipt_id` | yes | yes |
| `intent_id` | yes | yes |
| `outcome_hash` | yes | yes |
| `before_state_hash` | yes | yes |
| `signed_at` | yes | yes |
| `outcome` | no | yes |
| `is_reversible` | no | yes |

v1.1 is a breaking change. Receipts signed under v1.0 use a five-field payload. Recomputing the
signing payload from a v1.0 receipt using the v1.1 seven-field construction will produce a
different hash, and the signature will fail verification. Both versions must be identified by a
version field to enable correct verification.
