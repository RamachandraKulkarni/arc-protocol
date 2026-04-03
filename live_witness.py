import sys, json
sys.stdout.reconfigure(encoding='utf-8')

try:
    import httpx
    def get(url):
        return httpx.get(url, timeout=10).json()
except ImportError:
    import urllib.request
    def get(url):
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())

LOG = 'http://localhost:8080'
W   = 62

def banner(t):
    pad = W - len(t) - 4
    print(f'\n{chr(35)*W}')
    print(f'##  {t.center(pad)}  ##')
    print(f'{chr(35)*W}')

def section(t):
    print(f'\n{chr(45)*W}')
    print(f'  {t}')
    print(f'{chr(45)*W}')

def field(label, value, indent=4):
    print(f'{" "*indent}{label:<28} {value}')

banner('ARC LIVE LOG  WITNESS')

# ── Log root ───────────────────────────────────────────────
section('Log server state')
root = get(f'{LOG}/v1/log/root')
field('sequence_number',  root['sequence_number'])
field('total entries',    root['sequence_number'] + 1)
field('merkle_root',      root['merkle_root'])
field('timestamp',        root['timestamp'])
field('log_signature',    root['log_signature'][:45] + '...')

# ── All entries ────────────────────────────────────────────
entries = get(f'{LOG}/v1/log/entries?from_seq=0&limit=100')

banner('ALL LOG ENTRIES')

receipt_ids = []
for e in entries:
    print(f'\n  Seq {e["sequence_number"]}  [{e["entry_type"].upper()}]')
    field('entry_id',       e['entry_id'])
    field('receipt_id',     e['receipt_id'])
    field('content_hash',   e['content_hash'][:52] + '...')
    field('previous_root',  e['previous_root'][:52] + '...')
    field('merkle_root',    e['merkle_root'][:52] + '...')
    field('timestamp',      e['timestamp'])
    field('log_signature',  e['log_signature'][:42] + '...')

    if e['receipt_id'] not in receipt_ids:
        receipt_ids.append(e['receipt_id'])

# ── Merkle chain verification ──────────────────────────────
banner('MERKLE CHAIN VERIFICATION')

print()
ok = True
for i in range(len(entries) - 1):
    curr = entries[i]
    nxt  = entries[i + 1]
    match = curr['merkle_root'] == nxt['previous_root']
    status = 'OK' if match else 'BROKEN'
    print(f'  seq {curr["sequence_number"]} -> seq {nxt["sequence_number"]}  [{status}]')
    if not match:
        ok = False
        print(f'    expected: {curr["merkle_root"][:40]}')
        print(f'    got:      {nxt["previous_root"][:40]}')

print(f'\n  Chain integrity: {"INTACT" if ok else "BROKEN"}')

# ── Per-receipt verification ───────────────────────────────
banner('PER-RECEIPT VERIFICATION')

all_valid = True
for rid in receipt_ids:
    print(f'\n  {rid}')
    v = get(f'{LOG}/v1/log/verify/{rid}')
    checks = {
        'found':             v.get('found', False),
        'intent_committed':  v.get('intent_committed', False),
        'receipt_committed': v.get('receipt_committed', False),
        'is_consistent':     v.get('is_consistent', False),
    }
    for k, val in checks.items():
        mark = 'OK  ' if val else 'FAIL'
        print(f'    [{mark}] {k}')
        if not val:
            all_valid = False

    entries_for = v.get('entries', [])
    if len(entries_for) >= 2:
        p1 = next((e for e in entries_for if e['entry_type'] == 'intent'), None)
        p2 = next((e for e in entries_for if e['entry_type'] == 'receipt'), None)
        if p1 and p2:
            print(f'    Phase 1 seq:  {p1["sequence_number"]}  at {p1["timestamp"]}')
            print(f'    Phase 2 seq:  {p2["sequence_number"]}  at {p2["timestamp"]}')
            gap = p2["sequence_number"] - p1["sequence_number"]
            print(f'    Seq gap:      {gap}  ({"OK" if gap == 1 else "UNEXPECTED"})')

# ── Summary ────────────────────────────────────────────────
banner('SUMMARY')

print(f'''
  Log server:      {LOG}
  Total entries:   {len(entries)}
  Unique receipts: {len(receipt_ids)}
  Merkle chain:    {"INTACT" if ok else "BROKEN"}
  All receipts:    {"VALID" if all_valid else "ISSUES FOUND"}

  Receipt IDs:''')

for rid in receipt_ids:
    print(f'    {rid}')

print(f'''
  This witness has zero knowledge of the agent sessions.
  All data read directly from the public transparency log.
  Verification requires only the log server URL.

{"="*W}
  ARC LIVE WITNESS: COMPLETE
{"="*W}
''')
