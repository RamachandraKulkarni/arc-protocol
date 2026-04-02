# Log Server API Reference

The ARC transparency log server exposes five HTTP endpoints. All endpoints accept and return JSON. No authentication is required for read endpoints. The reference implementation uses no authentication for write endpoints (production deployments should add API key auth for writes).

Base URL: http://localhost:8080 (default)

---

## POST /v1/log/intent

Commit a Phase 1 intent to the log. Call this before executing the tool.

**Request body:**

```json
{
  "receipt_id": "arc_01JTXM9KP3F...",
  "intent": {
    "intent_id": "intent_01JTXM9KP3F...",
    "tool_name": "delete_file",
    "arguments": {"path": "/tmp/data.txt"},
    "declared_by": {
      "agent_id": "my-agent",
      "model_version": "my-model-v1",
      "session_id": "session-001"
    },
    "reasoning_commitment": "sha256:abc123...",
    "declared_at": "2026-04-02T12:00:00Z"
  }
}
```

**Response (200 OK):**

```json
{
  "log_entry": {
    "entry_id": "log_01JTXM9KP3F...",
    "entry_type": "intent",
    "sequence_number": 4,
    "receipt_id": "arc_01JTXM9KP3F...",
    "content_hash": "sha256:def456...",
    "previous_root": "sha256:aaa111...",
    "merkle_root": "sha256:bbb222...",
    "timestamp": "2026-04-02T12:00:01Z",
    "log_signature": "ed25519:AAAA...=="
  },
  "commitment": {
    "log_id": "arc-log-local",
    "sequence_number": 4,
    "merkle_root": "sha256:bbb222...",
    "committed_at": "2026-04-02T12:00:01Z"
  }
}
```

Embed the returned commitment object in phase_1.log_commitment of your receipt.

**Error responses:**

| Status | Error code | Condition |
|--------|-----------|-----------|
| 400 | invalid_receipt_id | receipt_id does not match pattern arc_[0-9A-Z]{26} |
| 400 | missing_fields | Required fields absent from intent object |
| 409 | duplicate_receipt_id | This receipt_id already has an intent entry |
| 409 | receipt_exists | A receipt entry already exists for this receipt_id (Phase 2 committed before Phase 1) |

---

## POST /v1/log/receipt

Commit a Phase 2 receipt to the log. Call this after the tool executes and the provider has signed.

**Request body:** The complete ActionReceipt JSON object.

```json
{
  "arc_version": "1.0",
  "receipt_id": "arc_01JTXM9KP3F...",
  "phase_1": { ... },
  "phase_2": { ... }
}
```

**Response (200 OK):**

```json
{
  "log_entry": {
    "entry_id": "log_01JTXM9KP3G...",
    "entry_type": "receipt",
    "sequence_number": 5,
    "receipt_id": "arc_01JTXM9KP3F...",
    "content_hash": "sha256:ghi789...",
    "previous_root": "sha256:bbb222...",
    "merkle_root": "sha256:ccc333...",
    "timestamp": "2026-04-02T12:00:05Z",
    "log_signature": "ed25519:BBBB...=="
  },
  "commitment": {
    "log_id": "arc-log-local",
    "sequence_number": 5,
    "merkle_root": "sha256:ccc333...",
    "committed_at": "2026-04-02T12:00:05Z"
  }
}
```

Embed the returned commitment object in phase_2.log_proof of your receipt.

**Error responses:**

| Status | Error code | Condition |
|--------|-----------|-----------|
| 400 | schema_invalid | Receipt does not validate against action-receipt.schema.json. Body contains list of validation errors. |
| 404 | intent_not_found | No intent entry exists for this receipt_id. Phase 1 must be committed first. |
| 409 | duplicate_receipt_id | A receipt entry already exists for this receipt_id |

---

## GET /v1/log/verify/{receipt_id}

Public verification endpoint. Call this from any third-party process to verify a receipt. No authentication required.

**Path parameter:** receipt_id (string, format: arc_[0-9A-Z]{26})

**Response (200 OK, receipt found):**

```json
{
  "receipt_id": "arc_01JTXM9KP3F...",
  "found": true,
  "entries": [
    {
      "entry_type": "intent",
      "sequence_number": 4,
      "content_hash": "sha256:def456...",
      "previous_root": "sha256:aaa111...",
      "merkle_root": "sha256:bbb222...",
      "timestamp": "2026-04-02T12:00:01Z",
      "log_signature": "ed25519:AAAA...=="
    },
    {
      "entry_type": "receipt",
      "sequence_number": 5,
      "content_hash": "sha256:ghi789...",
      "previous_root": "sha256:bbb222...",
      "merkle_root": "sha256:ccc333...",
      "timestamp": "2026-04-02T12:00:05Z",
      "log_signature": "ed25519:BBBB...=="
    }
  ],
  "intent_committed": true,
  "receipt_committed": true,
  "is_consistent": true,
  "verification_time": "2026-04-02T12:05:00Z"
}
```

**Checks performed:**

| Field | Check |
|-------|-------|
| found | At least one log entry exists for this receipt_id |
| intent_committed | An entry with entry_type="intent" exists |
| receipt_committed | An entry with entry_type="receipt" exists |
| is_consistent | For all entries: previous_root of entry N+1 equals merkle_root of entry N |

**Response (200 OK, receipt not found):**

```json
{
  "receipt_id": "arc_01JTXM9KP3F...",
  "found": false,
  "entries": [],
  "intent_committed": false,
  "receipt_committed": false,
  "is_consistent": false,
  "verification_time": "2026-04-02T12:05:00Z"
}
```

Note: the endpoint returns 200 even when the receipt is not found. Check the found field. A 404 response indicates a malformed receipt_id, not a missing receipt.

---

## GET /v1/log/entries

Enumerate log entries in sequence number order. Use this for auditing and for building external log monitors.

**Query parameters:**

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| from_seq | integer | 0 | - | Start from this sequence number (inclusive) |
| limit | integer | 20 | 100 | Number of entries to return |

**Response (200 OK):**

```json
{
  "entries": [
    {
      "entry_id": "log_01JTXM9KP3F...",
      "entry_type": "intent",
      "sequence_number": 0,
      "receipt_id": "arc_01JTXM9KP3F...",
      "content_hash": "sha256:abc123...",
      "previous_root": "sha256:000000...",
      "merkle_root": "sha256:def456...",
      "timestamp": "2026-04-02T11:00:00Z",
      "log_signature": "ed25519:CCCC...=="
    }
  ],
  "total": 11,
  "from_seq": 0,
  "limit": 20
}
```

The total field gives the total number of entries in the log, not the number returned in this response. Use from_seq pagination to retrieve entries beyond the limit.

**Pagination example:**

```python
import httpx

def get_all_entries(base_url: str) -> list[dict]:
    entries = []
    from_seq = 0
    limit = 100
    while True:
        resp = httpx.get(
            f"{base_url}/v1/log/entries",
            params={"from_seq": from_seq, "limit": limit},
        )
        resp.raise_for_status()
        data = resp.json()
        entries.extend(data["entries"])
        if len(entries) >= data["total"]:
            break
        from_seq += limit
    return entries
```

---

## GET /v1/log/root

Current signed tree head. Used by log monitors to track log state over time.

**Response (200 OK):**

```json
{
  "sequence_number": 10,
  "merkle_root": "sha256:zzz999...",
  "timestamp": "2026-04-02T12:05:00Z",
  "log_signature": "ed25519:DDDD...=="
}
```

The log_signature covers the payload: canonical JSON of {sequence_number, merkle_root, timestamp}.

The log operator's Ed25519 public key is printed to stdout when the server starts:

```
ARC Log Server started.
Log operator public key: a1b2c3d4...
Listening on 0.0.0.0:8080
```

Log monitors should record this public key at registration time and verify log_signature on each call to /v1/log/root. A change in the public key or a signature failure indicates a compromised log operator.

---

## Starting the Log Server

```bash
# From the arc-protocol directory:
uvicorn arc_log.server:app --host 0.0.0.0 --port 8080

# Or using the installed script:
arc-log

# With auto-reload (development only):
uvicorn arc_log.server:app --host 0.0.0.0 --port 8080 --reload
```

The server stores entries in SQLite at ./arc_log.db. Point the ARC_LOG_DB environment variable to a different path if needed:

```bash
ARC_LOG_DB=/var/data/arc_log.db arc-log
```

---

## Error Response Format

All error responses use the following structure:

```json
{
  "error": "error_code",
  "detail": "Human-readable description of the error.",
  "validation_errors": [...]
}
```

The validation_errors array is present only on schema validation failures (400 schema_invalid). Each entry is a jsonschema ValidationError message.

---

## Rate Limits

The reference implementation does not enforce rate limits. Production deployments should add rate limiting at the reverse proxy layer (nginx, caddy, or a cloud load balancer).

Recommended starting limits for write endpoints: 100 requests per second per IP. Reads are append-only and idempotent; they can be served from a read replica without rate limits.
