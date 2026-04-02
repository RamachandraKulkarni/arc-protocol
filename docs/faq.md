# Frequently Asked Questions

---

## What is an Action Receipt?

An Action Receipt is a two-phase cryptographic record of an AI agent tool call. Phase 1 captures
the resource state before the action and commits an intent declaration to the transparency log.
Phase 2 records the execution outcome, signed by the tool provider, and commits the complete
receipt to the log. The receipt proves that a specific agent declared a specific intent, that the
tool executed with a specific outcome, and that the entire record was committed to a
tamper-evident log.

---

## Why does the tool provider sign, not the agent?

If the agent signed its own receipts, fabrication would be undetectable. An agent could sign a
false result with its own key and the signature would verify. The tool provider's signature
removes the agent from the trust chain. The provider signs `outcome_hash` (SHA-256 of the actual
tool result). If the agent reports a different result, the hash comparison fails. If the agent
modifies the receipt and re-signs with its own key, the provider signature fails because the key
is different.

---

## What is the difference between v1.0 and v1.1?

v1.1 expands the signing payload from five fields to seven fields. The two added fields are
`outcome` (the "success"/"failure" string) and `is_reversible` (the rollback availability
boolean). In v1.0, both could be modified without breaking the provider signature. The expansion
is a breaking change: receipts signed under v1.0 fail v1.1 verification.

---

## Does ARC require modifying my existing tools?

No. The `@signed_tool` decorator wraps any existing Python function without changes to the
function itself. The proxy pattern (URL swap) requires no code changes at all: replace the tool
endpoint URL with the ARC proxy URL and all tool calls are automatically wrapped.

---

## What happens if a tool call fails?

A failed tool call produces a receipt with `outcome="failure"`. The `@signed_tool` decorator
catches exceptions, records the error code and message in the receipt, and commits the receipt to
the log. Failed actions must be logged because an unrecorded failure is indistinguishable from a
fabricated success.

---

## Can I use ARC without the log server?

Yes. `ARCInMemoryLog` provides the same interface as `ARCLogClient` but runs entirely in memory
without HTTP. It is suitable for development, testing, and scenarios where persistence is not
required.

---

## Does ARC satisfy EU AI Act Article 12?

ARC satisfies the tamper-evidence, automatic recording, full reconstructability, and identity
identification requirements of Article 12. Log retention duration (Article 19 minimum six months)
is operator-configured: ARC provides the storage mechanism but does not enforce a retention
policy. See [docs/compliance_map.md](compliance_map.md) for the full mapping.

---

## What is the orphan receipt gap?

An orphan receipt is a Phase 2 receipt committed to the log without a prior Phase 1 intent. This
can occur if Phase 1 was never submitted. The log server checks for a matching intent by
`receipt_id` before accepting a Phase 2, but if Phase 1 was never submitted, the check passes.
Risk is low: any verifier checking `intent_committed` will flag an orphan receipt as incomplete.
This is tracked for fix in v1.2.

---

## Can ARC detect a colluding agent and tool provider?

No. If the agent and tool provider collude, the provider can sign a false result with a
legitimate key. The receipt will verify as cryptographically valid. ARC operates under the
assumption that the tool provider is honest but the agent may not be. If provider trust cannot
be assumed, TEE attestation or multi-party signing is required.

---

## What log storage is supported?

The reference implementation uses SQLite via `arc_log/storage.py`. The database path is
configurable via the `ARC_LOG_DB` environment variable. For production deployments, the storage
backend can be replaced by implementing the same interface against PostgreSQL, object storage, or
any append-friendly store.

---

## How do I rotate provider keys?

Key rotation is tracked for v1.2. The current reference implementation does not include a key
rotation ceremony. Provider keys are generated at initialization and persist for the lifetime of
the deployment. If a key is compromised, the affected provider must be deregistered and a new
provider registered with a new key. Receipts signed with the compromised key remain in the log
but verification will fail once the key is revoked from the registry.
