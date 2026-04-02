# EU AI Act and NIST Compliance Mapping

This document maps ARC Protocol fields and mechanisms to regulatory requirements. Each
requirement is assessed as satisfied, partially satisfied, or operator-configured (meaning ARC
provides the mechanism but the operator must configure it).

---

## EU AI Act Article 12

Article 12 requires high-risk AI systems to log events in a way that enables verification of the
system's operation. The requirements become enforceable on August 2, 2026.

| Requirement | ARC Field or Mechanism | Status |
|-------------|----------------------|--------|
| Article 12.1: automatic recording of events | `phase_1.log_commitment`: every action is committed to the log before execution begins. The `@signed_tool` decorator handles this automatically. | Satisfied |
| Article 12.1: tamper-evident storage | RFC 6962 Merkle tree: every log entry is signed by the log operator (`log_signature` field). The chain check and leaf integrity check detect any modification. | Satisfied |
| Article 12.1: full reconstructability of AI system behavior | `phase_1.before_state` captures resource state before the action. `phase_2.execution.outcome_hash` records the exact result. The combination enables before/after reconstruction. | Satisfied |
| Article 12.1: logging for the duration of the AI system lifecycle | SQLite persistence via `arc_log/storage.py` with configurable database path (`ARC_LOG_DB` environment variable). | Operator-configured |
| Article 12.2: identification of persons in the verification chain | `phase_1.intent.declared_by.agent_id` identifies the AI model. `phase_1.intent.on_behalf_of` identifies the human user who authorized the action. | Satisfied |
| Article 12.2: logging of operations that could affect system outputs | The `@signed_tool` decorator captures every tool call. Partial coverage depends on whether all tool calls are wrapped. | Operator-configured |
| Article 19: minimum 6-month log retention | SQLite log with configurable retention. No automatic purging. Operator must configure a retention policy or connect external storage. | Operator-configured |

---

## NIST SP 800-53 Audit Controls

| Control | Requirement | ARC Coverage | Status |
|---------|-------------|--------------|--------|
| AU-2: Event Logging | Define auditable events | All tool calls wrapped with `@signed_tool` are auditable. Scope defined by operator. | Operator-configured |
| AU-3: Content of Audit Records | Event type, time, location, source, outcome, identity | `tool_name` (type), `declared_at`/`started_at` (time), `resource_uri` (location), `declared_by` (source), `outcome` (outcome), `agent_id` + `on_behalf_of` (identity) | Satisfied |
| AU-4: Audit Log Storage Capacity | Sufficient storage for audit logs | SQLite with configurable path. Storage capacity is operator responsibility. | Operator-configured |
| AU-9: Protection of Audit Information | Protect audit logs from unauthorized modification | RFC 6962 Merkle tree with log operator signature. Modification is detectable but not prevented at the storage layer. | Satisfied (detection) |
| AU-10: Non-Repudiation | Provide irrefutable evidence of action | Ed25519 `provider_attestation.signature` over seven-field canonical JSON payload. Non-repudiation is cryptographically binding. | Satisfied |
| AU-12: Audit Record Generation | Generate audit records for events | `@signed_tool` generates a complete two-phase receipt for every wrapped tool call, including failed calls. | Satisfied |

---

## What "Operator-Configured" Means

Three requirements are marked "operator-configured" because ARC provides the mechanism but does
not enforce the policy.

**Log retention:** ARC does not automatically purge or archive logs. The operator must configure
a retention policy (minimum six months for EU AI Act compliance).

**Tool call coverage:** ARC requires explicit wrapping with `@signed_tool` or the proxy pattern.
If an agent uses unwrapped tool calls, those calls are not logged.

**Storage capacity:** ARC uses SQLite by default. High-volume deployments should configure
external storage via the `ARC_LOG_DB` environment variable or a custom storage backend.
