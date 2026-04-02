"""
ULID-based ID generation for ARC protocol.
All IDs are prefixed ULIDs: 26-char uppercase base32 encoding.
"""

import secrets
import time

# Base32 Crockford alphabet (uppercase)
_ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """Generate a 26-character ULID (Universally Unique Lexicographically Sortable Identifier)."""
    # 48-bit millisecond timestamp
    ts_ms = time.time_ns() // 1_000_000
    ts_bits = ts_ms & 0xFFFFFFFFFFFF  # 48 bits

    # 80 bits of randomness
    rand = int.from_bytes(secrets.token_bytes(10), "big")

    # Encode timestamp (10 chars, 5 bits each)
    chars = []
    t = ts_bits
    for _ in range(10):
        chars.append(_ENCODING[t & 0x1F])
        t >>= 5
    chars.reverse()

    # Encode randomness (16 chars, 5 bits each)
    r = rand
    rand_chars = []
    for _ in range(16):
        rand_chars.append(_ENCODING[r & 0x1F])
        r >>= 5
    rand_chars.reverse()

    return "".join(chars) + "".join(rand_chars)


def new_receipt_id() -> str:
    """Generate a receipt ID: arc_ + 26-char ULID uppercase."""
    return f"arc_{_ulid()}"


def new_intent_id() -> str:
    """Generate an intent ID: intent_ + 26-char ULID uppercase."""
    return f"intent_{_ulid()}"


def new_snapshot_id() -> str:
    """Generate a snapshot ID: snap_ + 26-char ULID uppercase."""
    return f"snap_{_ulid()}"


def new_log_entry_id() -> str:
    """Generate a log entry ID: log_ + 26-char ULID uppercase."""
    return f"log_{_ulid()}"
