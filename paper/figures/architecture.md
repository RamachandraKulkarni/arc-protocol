# ARC Protocol Architecture

```
                    ARC PROTOCOL ARCHITECTURE
                    ==========================

  ┌─────────────────────────────────────────────────────────────────┐
  │                         AI AGENT                                │
  │  (Claude Code, LangChain, CrewAI, AutoGen, OpenAI Agents SDK)   │
  └────────────────────────────┬────────────────────────────────────┘
                               │ tool call request
                               ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                    ARC PROXY LAYER                              │
  │                                                                  │
  │  ┌───────────────────────┐    ┌──────────────────────────────┐  │
  │  │   @signed_tool        │    │   HTTP Proxy (URL swap)      │  │
  │  │   decorator           │    │   Zero-code integration      │  │
  │  └──────────┬────────────┘    └───────────────┬──────────────┘  │
  │             │                                 │                  │
  │     PHASE 1 (before execution)                │                  │
  │     1. Capture before-state snapshot          │                  │
  │     2. Declare intent (tool, args, reasoning) │                  │
  │     3. Commit to transparency log             │                  │
  └─────────────┬───────────────────────────────────────────────────┘
                │
                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                     TOOL PROVIDER                               │
  │           (filesystem, database, API, email)                    │
  │                                                                  │
  │  Tool executes. Actual result produced.                          │
  │                                                                  │
  │     PHASE 2 (after execution)                                    │
  │     1. Hash execution outcome (outcome_hash)                     │
  │     2. Sign 7-field payload with Ed25519 private key             │
  │     3. Sign inverse operation (rollback specification)           │
  │     4. Commit complete receipt to transparency log               │
  └─────────────────────────────────────────────────────────────────┘
                │
                │ log commitment
                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                   TRANSPARENCY LOG                              │
  │           (FastAPI + SQLite + RFC 6962 Merkle Tree)             │
  │                                                                  │
  │  Append-only. Every entry signed by log operator.               │
  │  Public verification endpoint: GET /v1/log/verify/{receipt_id}  │
  │  No authentication required for reads.                          │
  └─────────────────────────────────────────────────────────────────┘
                │
                │ GET /v1/log/verify/{receipt_id}
                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │              INDEPENDENT VERIFIER                               │
  │  (any party, any language, any location)                        │
  │                                                                  │
  │  Needs only: receipt_id + log server URL                        │
  │  Returns: found_in_log, log_chain_consistent,                   │
  │           intent_committed, receipt_committed                   │
  └─────────────────────────────────────────────────────────────────┘
```

## Data Flow Summary

| Phase | Actor | Action | Commitment |
|-------|-------|--------|------------|
| Phase 1 | ARC Proxy | Capture before-state | before_state_hash |
| Phase 1 | ARC Proxy | Declare intent | intent committed at seq N |
| Execution | Tool Provider | Execute action | actual result produced |
| Phase 2 | Tool Provider | Hash outcome | outcome_hash |
| Phase 2 | Tool Provider | Sign receipt | Ed25519 signature |
| Phase 2 | Tool Provider | Sign rollback | inverse_signature |
| Phase 2 | ARC Proxy | Commit to log | receipt committed at seq N+1 |
| Verification | Any Party | Query log | four checks, public endpoint |
