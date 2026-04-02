"""
ARC Protocol  -  Agent Receipt & Certification
Cryptographic proof of execution for AI agents.
"""

from arc.decorator import ARCContext, signed_tool
from arc.ids import new_receipt_id
from arc.log_client import ARCInMemoryLog, ARCLogClient
from arc.receipt import ReceiptBuilder, verify_receipt
from arc.signing import ARCKeyPair, sha256_hex
from arc.snapshot import SnapshotStore, capture_dict, capture_filesystem, rollback_filesystem

__version__ = "1.0.1"

__all__ = [
    "ARCKeyPair",
    "ARCContext",
    "ARCLogClient",
    "ARCInMemoryLog",
    "signed_tool",
    "ReceiptBuilder",
    "verify_receipt",
    "SnapshotStore",
    "capture_filesystem",
    "capture_dict",
    "rollback_filesystem",
    "new_receipt_id",
    "sha256_hex",
]
