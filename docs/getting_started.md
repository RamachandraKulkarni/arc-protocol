# Getting Started

This guide takes you from installation to a verified signed receipt in under five minutes.

## Requirements

- Python 3.11 or later
- pip

## Installation

```bash
pip install arc-protocol
```

For development (tests and linting):

```bash
pip install arc-protocol[dev]
```

Or install from source:

```bash
git clone https://github.com/arc-protocol/arc-protocol
cd arc-protocol
pip install -e ".[dev]"
```

## Your First Signed Receipt

The following example creates an ARCContext, wraps a function with @signed_tool, executes the function, and verifies the receipt.

```python
from arc import (
    ARCContext,
    ARCKeyPair,
    ARCInMemoryLog,
    SnapshotStore,
    signed_tool,
    verify_receipt,
)

# 1. Set up the context
keypair = ARCKeyPair.generate()
ctx = ARCContext(
    agent_id="my-agent-v1",
    model_version="my-model-v1",
    session_id="session-001",
    provider_keypair=keypair,
    provider_name="my-tools-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
    on_behalf_of="user:alice@example.com",
)

# 2. Wrap a function
@signed_tool(resource="dict", resource_uri_from_args="key")
def update_config(key: str, value: str, ctx: ARCContext) -> dict:
    return {"key": key, "value": value, "updated": True}

# 3. Execute it
receipt = update_config("timeout", "30s", ctx=ctx)

# 4. Verify the receipt
registry = {ctx.provider_name: keypair.public_key_hex}
result = verify_receipt(receipt, registry)

print(result["valid"])          # True
print(result["checks"])         # dict of individual check results
print(receipt["receipt_id"])    # arc_01...
```

Expected output:

```
True
{'schema_valid': True, 'provider_signature_valid': True, 'inverse_signature_valid': True, 'sequence_numbers_monotonic': True}
arc_01JTXM9KP3F...
```

## Using the Persistent Log Server

For persistent receipts visible to third parties:

**Terminal 1: Start the log server**

```bash
python -m uvicorn arc_log.server:app --host 127.0.0.1 --port 8080
```

The server prints its public key at startup. Note this key.

**Terminal 2: Use ARCLogClient instead of ARCInMemoryLog**

```python
from arc import ARCLogClient

ctx = ARCContext(
    ...
    log=ARCLogClient(base_url="http://localhost:8080"),
    ...
)
```

**Terminal 3: Verify from anywhere**

```bash
curl http://localhost:8080/v1/log/verify/arc_01JTXM9KP3F...
```

Response:

```json
{
  "receipt_id": "arc_01JTXM9KP3F...",
  "found": true,
  "intent_committed": true,
  "receipt_committed": true,
  "is_consistent": true
}
```

## Running the Demos

Three pre-built demos are included:

```bash
# Minimal: sign one tool call, verify it
make demo-basic

# Replit scenario: delete, fabricate, tamper, rollback
make demo-disaster

# Third-party verification (requires log server running)
make demo-verify RECEIPT_ID=arc_01JTXM9KP3F...
```

## Next Steps

- [Protocol Overview](protocol_overview.md): understand the two-phase receipt
- [Integration Guide](integration_guide.md): integrate with LangChain, MCP, or your existing tools
- [Schema Reference](schemas.md): field-by-field documentation for all seven schemas
- [Log Server API](log_api.md): HTTP endpoint reference for the transparency log
