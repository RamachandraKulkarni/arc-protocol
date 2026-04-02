"""
ARC Protocol  -  Agent Receipt & Certification
Cryptographic proof of execution for AI agents.
"""

from arc.decorator import ARCContext, signed_tool
from arc.ids import new_intent_id, new_receipt_id, new_snapshot_id
from arc.log_client import ARCInMemoryLog  # no external deps
from arc.merkle import MerkleTree, leaf_hash, node_hash
from arc.receipt import ReceiptBuilder, verify_receipt
from arc.signing import ARCKeyPair, canonical_json, sha256_hex
from arc.snapshot import (
    Snapshot,
    SnapshotStore,
    capture_dict,
    capture_filesystem,
    rollback_filesystem,
)

__version__ = "1.1.2"


def __getattr__(name: str):
    if name == "ARCLogClient":
        from arc.log_client import ARCLogClient
        return ARCLogClient
    raise AttributeError(f"module 'arc' has no attribute {name!r}")


__all__ = [
    "ARCKeyPair",
    "ARCContext",
    "ARCInMemoryLog",
    "ARCLogClient",  # available via lazy import
    "signed_tool",
    "ReceiptBuilder",
    "verify_receipt",
    "SnapshotStore",
    "Snapshot",
    "capture_filesystem",
    "capture_dict",
    "rollback_filesystem",
    "new_receipt_id",
    "new_intent_id",
    "new_snapshot_id",
    "MerkleTree",
    "leaf_hash",
    "node_hash",
    "canonical_json",
    "sha256_hex",
]
