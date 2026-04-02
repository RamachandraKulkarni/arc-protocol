"""Tests for RFC 6962-compatible Merkle tree."""

from arc.merkle import MerkleTree, leaf_hash, node_hash
from arc.signing import sha256_hex


def test_empty_tree_has_deterministic_root():
    tree1 = MerkleTree()
    tree2 = MerkleTree()
    assert tree1.root().startswith("sha256:")
    assert tree1.root() == tree2.root()


def test_single_entry_inclusion_proof():
    tree = MerkleTree()
    h = sha256_hex(b"entry0")
    seq, proof = tree.append(h)
    assert seq == 0
    assert MerkleTree.verify_inclusion(h, proof, tree.root()) is True


def test_multi_entry_inclusion_proofs():
    tree = MerkleTree()
    hashes = [sha256_hex(f"entry{i}".encode()) for i in range(8)]
    seqs = []
    for h in hashes:
        seq, _ = tree.append(h)
        seqs.append(seq)
    root = tree.root()
    # Use prove() to get proofs valid for the current (final) root
    for h, seq in zip(hashes, seqs):
        proof = tree.prove(seq)
        assert MerkleTree.verify_inclusion(h, proof, root) is True


def test_tampered_entry_fails_proof():
    tree = MerkleTree()
    h = sha256_hex(b"original")
    _, proof = tree.append(h)
    tampered = sha256_hex(b"tampered")
    assert MerkleTree.verify_inclusion(tampered, proof, tree.root()) is False


def test_sequential_numbering():
    tree = MerkleTree()
    for i in range(5):
        seq, _ = tree.append(sha256_hex(f"entry{i}".encode()))
        assert seq == i


def test_root_changes_on_append():
    tree = MerkleTree()
    root0 = tree.root()
    tree.append(sha256_hex(b"entry0"))
    root1 = tree.root()
    tree.append(sha256_hex(b"entry1"))
    root2 = tree.root()
    assert root0 != root1
    assert root1 != root2


def test_odd_number_of_leaves():
    tree = MerkleTree()
    hashes = [sha256_hex(f"entry{i}".encode()) for i in range(5)]
    seqs = []
    for h in hashes:
        seq, _ = tree.append(h)
        seqs.append(seq)
    root = tree.root()
    for h, seq in zip(hashes, seqs):
        proof = tree.prove(seq)
        assert MerkleTree.verify_inclusion(h, proof, root) is True


def test_leaf_hash_uses_domain_separation():
    data = b"test"
    lh = leaf_hash(data)
    assert lh.startswith("sha256:")
    # Leaf hash uses 0x00 prefix  -  different from plain SHA-256
    import hashlib
    plain = "sha256:" + hashlib.sha256(data).hexdigest()
    assert lh != plain


def test_node_hash_uses_domain_separation():
    left = sha256_hex(b"left")
    right = sha256_hex(b"right")
    nh = node_hash(left, right)
    assert nh.startswith("sha256:")


def test_two_entries_tree():
    tree = MerkleTree()
    h0 = sha256_hex(b"a")
    h1 = sha256_hex(b"b")
    seq0, _ = tree.append(h0)
    seq1, _ = tree.append(h1)
    root = tree.root()
    proof0 = tree.prove(seq0)
    proof1 = tree.prove(seq1)
    assert MerkleTree.verify_inclusion(h0, proof0, root) is True
    assert MerkleTree.verify_inclusion(h1, proof1, root) is True


def test_verify_consistency():
    tree = MerkleTree()
    for i in range(4):
        tree.append(sha256_hex(f"entry{i}".encode()))
    result = tree.verify_consistency()
    assert result["is_consistent"] is True
    assert result["leaf_count"] == 4
