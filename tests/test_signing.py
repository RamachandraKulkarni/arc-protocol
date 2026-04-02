"""Tests for Ed25519 signing, verification, and canonical JSON."""

from arc.signing import ARCKeyPair, build_signing_payload, canonical_json, sha256_hex


def test_keypair_generation_produces_valid_keys(provider_keypair):
    assert len(provider_keypair.public_key_hex) == 64
    assert len(provider_keypair.private_key_hex) == 64


def test_sign_and_verify_roundtrip(provider_keypair):
    payload = b"test payload for signing"
    sig = provider_keypair.sign(payload)
    assert sig.startswith("ed25519:")
    assert provider_keypair.verify(payload, sig) is True


def test_tampered_payload_fails_verification(provider_keypair):
    payload = b"original payload"
    sig = provider_keypair.sign(payload)
    tampered = b"tampered payload"
    assert provider_keypair.verify(tampered, sig) is False


def test_wrong_key_fails_verification():
    kp1 = ARCKeyPair.generate()
    kp2 = ARCKeyPair.generate()
    payload = b"test"
    sig = kp1.sign(payload)
    assert kp2.verify(payload, sig) is False


def test_canonical_json_is_deterministic():
    obj = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    b1 = canonical_json(obj)
    b2 = canonical_json(obj)
    assert b1 == b2
    assert b'{"a":2,"m":{"a":4,"b":3},"z":1}' == b1


def test_canonical_json_nested_sort():
    obj = {"z": {"y": 1, "x": 2}, "a": 3}
    result = canonical_json(obj)
    assert result == b'{"a":3,"z":{"x":2,"y":1}}'


def test_sha256_hex_format():
    result = sha256_hex(b"hello")
    assert result.startswith("sha256:")
    assert len(result) == 71  # "sha256:" (7) + 64 hex chars


def test_sha256_hex_known_value():
    # Known SHA-256 of empty bytes
    result = sha256_hex(b"")
    assert result == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_from_private_key_hex_roundtrip(provider_keypair):
    hex_str = provider_keypair.private_key_hex
    restored = ARCKeyPair.from_private_key_hex(hex_str)
    assert restored.public_key_hex == provider_keypair.public_key_hex

    payload = b"roundtrip test"
    sig = provider_keypair.sign(payload)
    assert restored.verify(payload, sig) is True


def test_build_signing_payload_is_deterministic():
    p1 = build_signing_payload(
        receipt_id="arc_01JTXM9KP3FABCDE12345678AB",
        intent_id="intent_01JTXM9KP3FABCDE12345678AB",
        outcome_hash="sha256:" + "a" * 64,
        before_state_hash="sha256:" + "b" * 64,
        signed_at="2026-04-02T00:00:00Z",
    )
    p2 = build_signing_payload(
        receipt_id="arc_01JTXM9KP3FABCDE12345678AB",
        intent_id="intent_01JTXM9KP3FABCDE12345678AB",
        outcome_hash="sha256:" + "a" * 64,
        before_state_hash="sha256:" + "b" * 64,
        signed_at="2026-04-02T00:00:00Z",
    )
    assert p1 == p2


def test_signature_format():
    kp = ARCKeyPair.generate()
    sig = kp.sign(b"test")
    # Format: ed25519: + base64(64 bytes) = ed25519: + 88 chars (with padding)
    assert sig.startswith("ed25519:")
    b64_part = sig[len("ed25519:"):]
    import base64
    decoded = base64.b64decode(b64_part)
    assert len(decoded) == 64  # Ed25519 signature is always 64 bytes


def test_verify_invalid_signature_format(provider_keypair):
    assert provider_keypair.verify(b"test", "not-a-valid-sig") is False
    assert provider_keypair.verify(b"test", "ed25519:!!!invalid!!!") is False
