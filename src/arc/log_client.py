"""
Log client for the ARC transparency log.
ARCLogClient: HTTP client for the log server.
ARCInMemoryLog: In-process log for testing and demos.
"""

import threading
from datetime import datetime, timezone

from arc.ids import new_log_entry_id
from arc.merkle import MerkleTree
from arc.signing import ARCKeyPair, canonical_json, sha256_hex


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ARCLogError(Exception):
    """Raised on HTTP errors from the log server."""


def _require_httpx():
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for ARCLogClient. Install it with: pip install arc-protocol[client]"
        ) from None


class ARCLogClient:
    """
    HTTP client for the ARC transparency log server.
    base_url: URL of the log server (e.g. 'http://localhost:8080')
    """

    def __init__(self, base_url: str) -> None:
        _require_httpx()  # fail fast at construction time
        self.base_url = base_url.rstrip("/")

    def commit_intent(self, intent_dict: dict, receipt_id: str) -> dict:
        """Commit a Phase 1 intent to the log. Returns LogCommitment dict."""
        httpx = _require_httpx()
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/log/intent",
                json={"receipt_id": receipt_id, "intent": intent_dict},
            )
            if resp.status_code != 200:
                raise ARCLogError(f"Log server error {resp.status_code}: {resp.text}")
            return resp.json()["commitment"]

    def commit_receipt(self, receipt_dict: dict) -> dict:
        """Commit a complete receipt to the log. Returns LogCommitment dict."""
        httpx = _require_httpx()
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{self.base_url}/v1/log/receipt",
                json={"receipt": receipt_dict},
            )
            if resp.status_code != 200:
                raise ARCLogError(f"Log server error {resp.status_code}: {resp.text}")
            return resp.json()["commitment"]

    def verify(self, receipt_id: str) -> dict:
        """Query log entries for a receipt_id."""
        httpx = _require_httpx()
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}/v1/log/verify/{receipt_id}")
            if resp.status_code != 200:
                raise ARCLogError(f"Log server error {resp.status_code}: {resp.text}")
            return resp.json()

    def get_entry(self, sequence_number: int) -> dict:
        """Get a log entry by sequence number."""
        httpx = _require_httpx()
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}/v1/log/entries?from_seq={sequence_number}&limit=1")
            if resp.status_code != 200:
                raise ARCLogError(f"Log server error {resp.status_code}: {resp.text}")
            entries = resp.json()
            if not entries:
                raise ARCLogError(f"No entry at sequence {sequence_number}")
            return entries[0]

    def get_root(self) -> dict:
        """Get current signed tree head."""
        httpx = _require_httpx()
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}/v1/log/root")
            if resp.status_code != 200:
                raise ARCLogError(f"Log server error {resp.status_code}: {resp.text}")
            return resp.json()


class ARCInMemoryLog:
    """
    In-process transparency log for testing and demos.
    Same interface as ARCLogClient but runs entirely in memory.
    Thread-safe. Uses MerkleTree internally.
    """

    def __init__(self, log_id: str = "arc-inmemory-log-v1") -> None:
        self.log_id = log_id
        self._tree = MerkleTree()
        self._entries: list[dict] = []
        self._receipt_entries: dict[str, list[int]] = {}  # receipt_id → [seq, ...]
        self._keypair = ARCKeyPair.generate()
        self._lock = threading.Lock()

    def _append(self, entry_type: str, receipt_id: str, content: dict) -> tuple[dict, dict]:
        """Internal: append content to the log, return (log_entry, log_commitment)."""
        content_bytes = canonical_json(content)
        content_hash = sha256_hex(content_bytes)
        timestamp = _now_iso()
        entry_id = new_log_entry_id()

        with self._lock:
            prev_root = self._tree.root()
            seq, proof = self._tree.append(content_hash)
            new_root = self._tree.root()

            sign_payload_obj = {
                "content_hash": content_hash,
                "merkle_root": new_root,
                "previous_root": prev_root,
                "sequence_number": seq,
                "timestamp": timestamp,
            }
            log_signature = self._keypair.sign(canonical_json(sign_payload_obj))

            log_entry = {
                "entry_id": entry_id,
                "entry_type": entry_type,
                "sequence_number": seq,
                "receipt_id": receipt_id,
                "content_hash": content_hash,
                "previous_root": prev_root,
                "merkle_root": new_root,
                "timestamp": timestamp,
                "log_signature": log_signature,
            }
            self._entries.append(log_entry)
            if receipt_id not in self._receipt_entries:
                self._receipt_entries[receipt_id] = []
            self._receipt_entries[receipt_id].append(seq)

            log_commitment = {
                "log_id": self.log_id,
                "sequence_number": seq,
                "merkle_root": new_root,
                "inclusion_proof": proof,
                "committed_at": timestamp,
            }

            return log_entry, log_commitment

    def commit_intent(self, intent_dict: dict, receipt_id: str) -> dict:
        """Commit Phase 1 intent. Returns LogCommitment."""
        with self._lock:
            existing = self._receipt_entries.get(receipt_id, [])
            existing_entries = [self._entries[s] for s in existing if s < len(self._entries)]

            if any(e["entry_type"] == "intent" for e in existing_entries):
                raise ARCLogError(
                    f"intent already committed for receipt_id={receipt_id}. "
                    "Duplicate intent submissions are not allowed."
                )
            if any(e["entry_type"] == "receipt" for e in existing_entries):
                raise ARCLogError(
                    f"receipt already committed for receipt_id={receipt_id}. "
                    "Intent must be committed BEFORE receipt. "
                    "Backdated intent submission rejected."
                )
        _, commitment = self._append("intent", receipt_id, intent_dict)
        return commitment

    def commit_receipt(self, receipt_dict: dict) -> dict:
        """Commit complete receipt. Returns LogCommitment."""
        receipt_id = receipt_dict["receipt_id"]
        with self._lock:
            existing = self._receipt_entries.get(receipt_id, [])
            existing_entries = [self._entries[s] for s in existing if s < len(self._entries)]
            if any(e["entry_type"] == "receipt" for e in existing_entries):
                raise ARCLogError(
                    f"receipt already committed for receipt_id={receipt_id}. "
                    "Replay: this receipt_id is already in the log."
                )
        _, commitment = self._append("receipt", receipt_id, receipt_dict)
        return commitment

    def verify(self, receipt_id: str) -> dict:
        """Return verification info for a receipt_id."""
        with self._lock:
            seqs = self._receipt_entries.get(receipt_id, [])
            entries = [self._entries[s] for s in seqs if s < len(self._entries)]

        intent_committed = any(e["entry_type"] == "intent" for e in entries)
        receipt_committed = any(e["entry_type"] == "receipt" for e in entries)
        is_consistent = self._check_consistency(entries)

        return {
            "receipt_id": receipt_id,
            "found": len(entries) > 0,
            "entries": entries,
            "intent_committed": intent_committed,
            "receipt_committed": receipt_committed,
            "is_consistent": is_consistent,
            "verification_time": _now_iso(),
        }

    def _check_consistency(self, entries: list[dict]) -> bool:
        """Check that entries are monotonically sequenced."""
        seqs = [e["sequence_number"] for e in entries]
        return seqs == sorted(seqs)

    def get_entry(self, sequence_number: int) -> dict:
        with self._lock:
            if sequence_number >= len(self._entries):
                raise ARCLogError(f"No entry at sequence {sequence_number}")
            return self._entries[sequence_number]

    def get_root(self) -> dict:
        return {
            "sequence_number": len(self._entries) - 1,
            "merkle_root": self._tree.root(),
            "timestamp": _now_iso(),
            "log_signature": self._keypair.sign(self._tree.root().encode()),
        }

    def verify_consistency(self) -> dict:
        """
        Check that the entire log is internally consistent.

        Pass 1: Merkle root chain  -  entry[n].merkle_root == entry[n+1].previous_root
        Pass 2: Content integrity  -  rebuild Merkle tree from content_hashes and verify
                the rebuilt root matches the stored final merkle_root.
        """
        with self._lock:
            entries = list(self._entries)

        is_consistent = True
        errors = []
        prev_root = None

        # Pass 1: chain check
        for entry in entries:
            seq = entry["sequence_number"]
            prev = entry["previous_root"]
            curr = entry["merkle_root"]
            if prev_root is not None and prev != prev_root:
                is_consistent = False
                errors.append(
                    f"Chain break at sequence {seq}: expected previous_root={prev_root}, got {prev}"
                )
            prev_root = curr

        # Pass 2: rebuild tree from content_hashes and verify final root
        if entries:
            rebuilt = MerkleTree()
            for entry in entries:
                rebuilt.append(entry["content_hash"])
            rebuilt_root = rebuilt.root()
            stored_root = entries[-1]["merkle_root"]
            if rebuilt_root != stored_root:
                is_consistent = False
                # Binary search for first tampered entry
                for i, entry in enumerate(entries):
                    check = MerkleTree()
                    for e in entries[: i + 1]:
                        check.append(e["content_hash"])
                    if check.root() != entry["merkle_root"]:
                        errors.append(
                            f"content_hash tampered at sequence {entry['sequence_number']}: "
                            f"rebuilt Merkle root does not match stored merkle_root"
                        )
                        break
                else:
                    errors.append("Rebuilt Merkle root does not match stored final root")

        return {
            "is_consistent": is_consistent,
            "entry_count": len(entries),
            "errors": errors,
        }

    def tamper_entry(self, sequence_number: int, field: str, value: str) -> None:
        """FOR TESTING ONLY: Tamper with a log entry to simulate an attack."""
        with self._lock:
            if sequence_number < len(self._entries):
                self._entries[sequence_number][field] = value
