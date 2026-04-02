# ARC Protocol Threat Model

```
                       ARC THREAT MODEL
                       ================

  TRUSTED                          UNTRUSTED
  --------                         ---------

  ┌─────────────────┐              ┌─────────────────┐
  │  Tool Provider  │              │      Agent      │
  │                 │              │                 │
  │  Signs receipts │              │  Self-reports   │
  │  with Ed25519   │              │  its own actions│
  │  private key    │              │                 │
  │                 │              │  MAY fabricate  │
  │  Assumed honest │              │  MAY tamper     │
  │  (not colluding)│              │  MAY backdate   │
  └────────┬────────┘              └────────┬────────┘
           │                                │
           │ PROTECTED                      │ UNPROTECTED
           ▼                                ▼

  ┌─────────────────────────────────────────────────────┐
  │                    RECEIPT                          │
  │                                                     │
  │  SIGNED fields (provider cannot be repudiated):     │
  │  - before_state_hash (pre-action snapshot)          │
  │  - intent_id (links to Phase 1 declaration)         │
  │  - is_reversible (rollback availability)            │
  │  - outcome (success/failure/partial label)          │
  │  - outcome_hash (SHA-256 of actual result)          │
  │  - receipt_id (unique receipt identifier)           │
  │  - signed_at (timestamp of signing)                 │
  │                                                     │
  │  SIGNED inverse operation:                          │
  │  - receipt_id, inverse_tool,                        │
  │    inverse_arguments, valid_until                   │
  └─────────────────────────────────────────────────────┘

  ATTACKS ARC DETECTS:
  --------------------
  [X] Outcome string flip    "failure" -> "success"     caught: outcome in payload
  [X] Outcome hash tamper    recompute hash of lie       caught: sig covers outcome_hash
  [X] Rollback denial        is_reversible True->False   caught: is_reversible in payload
  [X] Log leaf tamper        content_hash modified       caught: leaf integrity check
  [X] Log chain tamper       merkle_root modified        caught: chain check
  [X] Fake provider sig      wrong keypair               caught: registry check
  [X] Replay attack          duplicate receipt_id        caught: duplicate guard
  [X] Backdated intent       declared_at after started   caught: timestamp ordering
  [X] Backdated Phase 1      Phase 1 after Phase 2       caught: ordering in commit

  ATTACKS ARC DOES NOT DETECT:
  ----------------------------
  [ ] Provider key compromise       provider honest but key stolen
  [ ] Provider-agent collusion      both parties fabricate together
  [ ] Off-chain side effects        action affects resources not in snapshot
  [ ] Pre-ARC actions               actions before wrapping is applied
  [ ] TEE integrity                 computational correctness (semantic only)
```
