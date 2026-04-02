"""
Ed25519 signing and verification for ARC protocol.
Uses the `cryptography` library exclusively.
"""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class ARCKeyPair:
    """An Ed25519 keypair for an ARC participant (tool provider, log operator, or proxy)."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

    @classmethod
    def generate(cls) -> "ARCKeyPair":
        """Generate a fresh Ed25519 keypair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_key_hex(cls, hex_str: str) -> "ARCKeyPair":
        """Reconstruct keypair from 64-char lowercase hex private key."""
        raw = bytes.fromhex(hex_str)
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private_key)

    @property
    def public_key_hex(self) -> str:
        """32-byte Ed25519 public key as 64-char lowercase hex."""
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    @property
    def private_key_hex(self) -> str:
        """32-byte Ed25519 private key as 64-char lowercase hex. Never put in receipts."""
        raw = self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return raw.hex()

    def sign(self, payload: bytes) -> str:
        """Sign payload bytes. Returns 'ed25519:' + base64(64-byte signature)."""
        sig_bytes = self._private_key.sign(payload)
        return "ed25519:" + base64.b64encode(sig_bytes).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a signature string against payload. Returns False (not raises) on failure."""
        try:
            if not signature.startswith("ed25519:"):
                return False
            sig_bytes = base64.b64decode(signature[len("ed25519:") :])
            self._public_key.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    @classmethod
    def from_public_key_hex(cls, hex_str: str) -> "ARCKeyPair":
        """Create a verify-only wrapper from a public key hex string."""
        raise NotImplementedError("Use verify_with_public_key_hex for public-key-only verification")


def verify_with_public_key_hex(payload: bytes, signature: str, public_key_hex: str) -> bool:
    """Verify a signature using just a public key hex string (no private key needed)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        raw = bytes.fromhex(public_key_hex)
        pub_key = Ed25519PublicKey.from_public_bytes(raw)
        if not signature.startswith("ed25519:"):
            return False
        sig_bytes = base64.b64decode(signature[len("ed25519:") :])
        pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, Exception):
        return False


def canonical_json(obj: dict) -> bytes:
    """
    Produce canonical (deterministic) JSON bytes for signing.
    Rules:
    - Keys sorted alphabetically at every level
    - No extra whitespace
    - UTF-8 encoding
    - None → JSON null
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    """Returns 'sha256:' + lowercase hex of SHA-256(data)."""
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def build_signing_payload(
    receipt_id: str,
    intent_id: str,
    outcome_hash: str,
    before_state_hash: str,
    signed_at: str,
    outcome: str | None = None,
    is_reversible: bool | None = None,
) -> bytes:
    """
    Construct the canonical payload that providers sign.

    When outcome and is_reversible are provided (v1.1+), the payload covers 7 fields:
      {before_state_hash, intent_id, is_reversible, outcome, outcome_hash, receipt_id, signed_at}
    This prevents silent mutation of the outcome string and inverse-op flag.

    When omitted (legacy/test callers), the 5-field payload is used for backward compat.

    CRITICAL: Both signers and verifiers must pass the same set of arguments.
    """
    payload_obj: dict = {
        "before_state_hash": before_state_hash,
        "intent_id": intent_id,
        "outcome_hash": outcome_hash,
        "receipt_id": receipt_id,
        "signed_at": signed_at,
    }
    if outcome is not None:
        payload_obj["outcome"] = outcome
    if is_reversible is not None:
        payload_obj["is_reversible"] = is_reversible
    canonical = canonical_json(payload_obj)
    payload_hash = sha256_hex(canonical)
    return payload_hash.encode("utf-8")


def build_inverse_signing_payload(
    receipt_id: str,
    inverse_tool: str,
    inverse_arguments: dict,
    valid_until: str,
) -> bytes:
    payload_obj = {
        "inverse_arguments": inverse_arguments,
        "inverse_tool": inverse_tool,
        "receipt_id": receipt_id,
        "valid_until": valid_until,
    }
    return sha256_hex(canonical_json(payload_obj)).encode("utf-8")
