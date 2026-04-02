# Test Results

## Test Suite Summary

| Category | Tests | Passing | Failing |
|----------|-------|---------|---------|
| Unit tests | 51 | 51 | 0 |
| First red team | 43 | 37 | 6 |
| After remediation | 43 | 43 | 0 |
| Second red team (v1.1 surfaces) | 15 | 15 | 0 |
| **Total (v1.1)** | **58** | **58** | **0** |

Note: "First red team" and "After remediation" run the same 43 tests. The failing count reflects holes in v1.0 before the fixes. After remediation, all 43 pass. The 15 second red team tests are new and only exist in v1.1.

## Red Team Hole Summary

| Hole | Attack | v1.0 Result | v1.1 Result | Root Cause |
|------|--------|-------------|-------------|------------|
| 1 | Outcome string flip | Undetected | Caught | Payload too narrow |
| 2 | Rollback denial (is_reversible) | Undetected | Caught | Payload too narrow |
| 3 | Log content_hash tamper | Undetected | Caught | Missing leaf integrity check |
| 4 | Replay attack | Undetected | Caught | No duplicate guard |
| 5 | Backdated intent timestamp | Undetected | Caught | No temporal ordering |
| 6 | Backdated Phase 1 in log | Undetected | Caught | No Phase ordering check |

## v1.1 Second Red Team Coverage

| Test | Target | Result |
|------|--------|--------|
| Expanded payload check (outcome) | outcome in signing payload | Pass |
| Expanded payload check (is_reversible) | is_reversible in signing payload | Pass |
| Duplicate intent guard | commit_intent rejects duplicate | Pass |
| Duplicate receipt guard | commit_receipt rejects duplicate | Pass |
| Phase ordering: receipt before intent | commit_intent rejects if receipt exists | Pass |
| Content_hash leaf integrity | verify_consistency detects tampered leaf | Pass |
| Structural contradiction detection | is_reversible=False with inverse_signature | Pass |
| Timestamp ordering: Phase 1 after Phase 2 | verify_receipt detects inversion | Pass |
| Payload reconstruction consistency | canonical_json determinism across calls | Pass |
| Cross-version detection | v1.0 receipt fails v1.1 verification | Pass |
| Partial fabrication: outcome only | only outcome changed, hash intact | Pass |
| Partial fabrication: is_reversible only | only is_reversible changed | Pass |
| Orphan receipt detection | Phase 2 without Phase 1 flagged | Pass |
| Log signature verification | log operator signature checked | Pass |
| Multi-receipt consistency | 10 receipts, all consistent | Pass |

## Live Proof Results

| Receipt ID | Action | Intent Seq | Receipt Seq | Valid |
|------------|--------|------------|-------------|-------|
| arc_01KN6RGD75FMHNC1TBZ5MBZE7F | data.csv creation | 2 | 3 | Yes |
| arc_01KN6SYG39A1FMXTQTAWDM97H3 | type data.csv | 4 | 5 | Yes |
| arc_01KN6T08ZM9VXSAHVP1Y7QR5EB | type process.py | 6 | 7 | Yes |
| arc_01KN6T2HBHRW4PBDYHXWSYVD6Z | type results.txt | 8 | 9 | Yes |
| arc_01KN6T3RFS3N41YDFMG6QJRDQ1 | type summary.json | 10 | 11 | Yes |

Final result: 5/5 valid. PROOF COMPLETE.
