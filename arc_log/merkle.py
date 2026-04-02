"""
Server-side Merkle tree with SQLite persistence for the ARC transparency log.
"""

import hashlib
import sqlite3
import threading
from arc.merkle import leaf_hash, node_hash, _EMPTY_ROOT


class PersistentMerkleTree:
    """
    Append-only Merkle tree backed by SQLite.
    Stores leaf hashes; recomputes tree on demand.
    Thread-safe.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS merkle_leaves (
                seq INTEGER PRIMARY KEY,
                leaf_hash TEXT NOT NULL
            )"""
        )
        conn.commit()
        conn.close()

    def _get_leaves(self) -> list[str]:
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute("SELECT leaf_hash FROM merkle_leaves ORDER BY seq").fetchall()
        conn.close()
        return [r[0] for r in rows]

    def append(self, content_hash: str) -> tuple[int, list[str], str, str]:
        """
        Append content_hash to the tree.
        Returns (sequence_number, inclusion_proof, previous_root, new_root).
        """
        with self._lock:
            leaves = self._get_leaves()
            prev_root = self._compute_root(leaves)
            seq = len(leaves)
            new_leaf = leaf_hash(bytes.fromhex(content_hash[7:]))
            leaves.append(new_leaf)

            conn = sqlite3.connect(self._db_path)
            conn.execute("INSERT INTO merkle_leaves (seq, leaf_hash) VALUES (?,?)", (seq, new_leaf))
            conn.commit()
            conn.close()

            new_root = self._compute_root(leaves)
            proof = self._compute_proof(leaves, seq)
            return seq, proof, prev_root, new_root

    def root(self) -> str:
        with self._lock:
            leaves = self._get_leaves()
            return self._compute_root(leaves)

    def count(self) -> int:
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            count = conn.execute("SELECT COUNT(*) FROM merkle_leaves").fetchone()[0]
            conn.close()
            return count

    @staticmethod
    def _compute_root(leaves: list[str]) -> str:
        if not leaves:
            return _EMPTY_ROOT
        current = list(leaves)
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(node_hash(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])
            current = next_level
        return current[0]

    @staticmethod
    def _compute_proof(leaves: list[str], index: int) -> list[str]:
        proof = []
        current_level = list(leaves)
        i = index
        while len(current_level) > 1:
            if i % 2 == 0:
                if i + 1 < len(current_level):
                    proof.append(current_level[i + 1])
            else:
                proof.append(current_level[i - 1])
            next_level = []
            for j in range(0, len(current_level), 2):
                if j + 1 < len(current_level):
                    next_level.append(node_hash(current_level[j], current_level[j + 1]))
                else:
                    next_level.append(current_level[j])
            current_level = next_level
            i = i // 2
        return proof
