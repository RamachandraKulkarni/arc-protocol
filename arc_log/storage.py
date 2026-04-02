"""
SQLite-backed append-only log storage for the ARC transparency log server.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone

from arc.ids import new_log_entry_id
from arc.signing import ARCKeyPair, canonical_json, sha256_hex
from arc_log.merkle import PersistentMerkleTree


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class LogStorage:
    """
    SQLite-backed log storage with Merkle tree tracking.
    Each entry is signed by the log operator keypair.
    """

    def __init__(self, db_path: str, log_keypair: ARCKeyPair) -> None:
        self._db_path = db_path
        self._keypair = log_keypair
        self._lock = threading.Lock()
        self._merkle = PersistentMerkleTree(db_path)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                seq INTEGER PRIMARY KEY,
                entry_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                previous_root TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                log_signature TEXT NOT NULL,
                content TEXT NOT NULL
            )"""
        )
        conn.commit()
        conn.close()

    def append_intent(self, receipt_id: str, intent_dict: dict) -> tuple[dict, dict]:
        """
        Append a Phase 1 intent to the log.
        Returns (log_entry, log_commitment).
        """
        return self._append("intent", receipt_id, intent_dict)

    def append_receipt(self, receipt_dict: dict) -> tuple[dict, dict]:
        """
        Append a complete receipt (Phase 2) to the log.
        Returns (log_entry, log_commitment).
        """
        receipt_id = receipt_dict["receipt_id"]
        return self._append("receipt", receipt_id, receipt_dict)

    def _append(self, entry_type: str, receipt_id: str, content: dict) -> tuple[dict, dict]:
        with self._lock:
            content_bytes = canonical_json(content)
            content_hash = sha256_hex(content_bytes)
            timestamp = _now_iso()
            entry_id = new_log_entry_id()

            seq, proof, prev_root, new_root = self._merkle.append(content_hash)

            # Build the payload the log operator signs
            sign_payload_obj = {
                "content_hash": content_hash,
                "merkle_root": new_root,
                "previous_root": prev_root,
                "sequence_number": seq,
                "timestamp": timestamp,
            }
            sign_payload = canonical_json(sign_payload_obj)
            log_signature = self._keypair.sign(sign_payload)

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

            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    seq,
                    entry_id,
                    receipt_id,
                    entry_type,
                    content_hash,
                    prev_root,
                    new_root,
                    timestamp,
                    log_signature,
                    json.dumps(content),
                ),
            )
            conn.commit()
            conn.close()

            log_commitment = {
                "log_id": "arc-log-v1",
                "sequence_number": seq,
                "merkle_root": new_root,
                "inclusion_proof": proof,
                "committed_at": timestamp,
            }

            return log_entry, log_commitment

    def get_entries_for_receipt(self, receipt_id: str) -> list[dict]:
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT seq,entry_id,receipt_id,entry_type,content_hash,previous_root,merkle_root,timestamp,log_signature "
            "FROM entries WHERE receipt_id=? ORDER BY seq",
            (receipt_id,),
        ).fetchall()
        conn.close()
        return [
            {
                "entry_id": r[1],
                "entry_type": r[3],
                "sequence_number": r[0],
                "receipt_id": r[2],
                "content_hash": r[4],
                "previous_root": r[5],
                "merkle_root": r[6],
                "timestamp": r[7],
                "log_signature": r[8],
            }
            for r in rows
        ]

    def get_entry_by_seq(self, seq: int) -> dict | None:
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT seq,entry_id,receipt_id,entry_type,content_hash,previous_root,merkle_root,timestamp,log_signature "
            "FROM entries WHERE seq=?",
            (seq,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "entry_id": row[1],
            "entry_type": row[3],
            "sequence_number": row[0],
            "receipt_id": row[2],
            "content_hash": row[4],
            "previous_root": row[5],
            "merkle_root": row[6],
            "timestamp": row[7],
            "log_signature": row[8],
        }

    def get_entries_range(self, from_seq: int, limit: int) -> list[dict]:
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT seq,entry_id,receipt_id,entry_type,content_hash,previous_root,merkle_root,timestamp,log_signature "
            "FROM entries WHERE seq >= ? ORDER BY seq LIMIT ?",
            (from_seq, min(limit, 100)),
        ).fetchall()
        conn.close()
        return [
            {
                "entry_id": r[1],
                "entry_type": r[3],
                "sequence_number": r[0],
                "receipt_id": r[2],
                "content_hash": r[4],
                "previous_root": r[5],
                "merkle_root": r[6],
                "timestamp": r[7],
                "log_signature": r[8],
            }
            for r in rows
        ]

    def current_root(self) -> str:
        return self._merkle.root()

    def count(self) -> int:
        return self._merkle.count()

    def verify_consistency(self) -> dict:
        """Check that all log entries chain correctly."""
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT seq,previous_root,merkle_root FROM entries ORDER BY seq"
        ).fetchall()
        conn.close()

        is_consistent = True
        errors = []
        prev_root = None

        for row in rows:
            seq, prev, curr = row
            if prev_root is not None and prev != prev_root:
                is_consistent = False
                errors.append(f"Chain break at sequence {seq}: expected previous_root={prev_root}, got {prev}")
            prev_root = curr

        return {
            "is_consistent": is_consistent,
            "entry_count": len(rows),
            "errors": errors,
        }
