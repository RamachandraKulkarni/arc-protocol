# ARC Protocol Documentation

ARC (Agent Receipt and Certification) is a protocol and Python library for cryptographic proof
of execution in AI agent systems.

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [Getting Started](getting_started.md) | Install ARC and produce your first signed receipt in five minutes |
| [Protocol Overview](protocol_overview.md) | Conceptual explanation of the two-phase Action Receipt |
| [Schemas](schemas.md) | All seven JSON Schema definitions documented field by field |
| [Signing Specification](signing_specification.md) | Exact signing algorithm for verifier implementers |
| [Log API](log_api.md) | All five transparency log endpoints documented |
| [Integration Guide](integration_guide.md) | LangChain, MCP, and raw Python integration patterns |
| [EU AI Act Compliance](compliance_map.md) | Article 12 requirement mapping |
| [Red Team Report](red_team_report.md) | Six documented holes, all fixed, full attack catalog |
| [Live Proof](proof_of_concept.md) | 5/5 valid receipts verified by isolated third party |
| [FAQ](faq.md) | Common questions |

---

## Quick Reference

Install:
```bash
pip install arc-protocol
```

Wrap a tool call:
```python
from arc import signed_tool, ARCContext, ARCKeyPair, ARCInMemoryLog, SnapshotStore

ctx = ARCContext(
    agent_id="my-agent",
    model_version="my-model-v1",
    session_id="session-001",
    provider_keypair=ARCKeyPair.generate(),
    provider_name="my-tools-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
)

@signed_tool(resource="filesystem", resource_uri_from_args="path")
def read_file(path: str, ctx: ARCContext) -> dict:
    with open(path) as f:
        return {"content": f.read()}

receipt = read_file("/tmp/data.txt", ctx=ctx)
```

Verify a receipt:
```python
from arc import verify_receipt

result = verify_receipt(receipt, {ctx.provider_name: ctx.provider_keypair.public_key_hex})
print(result["valid"])   # True
```

---

## Protocol Version

Current version: 1.1

See [CHANGELOG](../CHANGELOG.md) for version history.
