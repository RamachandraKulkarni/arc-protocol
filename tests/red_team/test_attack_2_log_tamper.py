"""
ATTACK 2: Log Tampering
An agent modifies the transparency log after entries have been committed.

WHAT ARC MUST DETECT:
- Each log entry contains previous_root = Merkle root before it was added
- Each entry contains merkle_root = root after it was added
- These chain: entry[n].merkle_root == entry[n+1].previous_root
- Any modification that breaks this chain is detected by verify_consistency()
- verify_consistency() returns is_consistent=False with errors naming the sequence number

HOLE FOUND (see RED_TEAM_FINDINGS.md):
- verify_consistency() checks the previous_root→merkle_root chain but does NOT
  recompute the Merkle tree from content_hash values. An attacker can change a
  stored content_hash (what was committed) without breaking the chain check.
"""

from arc import ARCContext, signed_tool


class TestLogTampering:
    def test_breaking_merkle_chain_at_middle_entry_detected(self, populated_log):
        """
        Attacker modifies merkle_root of entry 3, which breaks the chain at entry 4
        (entry 4's previous_root no longer matches entry 3's merkle_root).

        verify_consistency() must detect this and name sequence 4 in the error.
        """
        # Tamper: change merkle_root of entry 3 to a fake value
        populated_log.tamper_entry(3, "merkle_root", "sha256:" + "b" * 64)

        consistency = populated_log.verify_consistency()
        assert consistency["is_consistent"] is False
        # Error should name the sequence number where the chain breaks.
        # Error format: "Chain break at sequence N: ..."
        assert len(consistency["errors"]) > 0
        import re

        broken_seqs = [
            int(m.group(1))
            for e in consistency["errors"]
            for m in [re.search(r"sequence\s+(\d+)", e)]
            if m
        ]
        assert any(s == 4 for s in broken_seqs), (
            f"Expected chain break reported at sequence 4, got errors: {consistency['errors']}"
        )

    def test_first_entry_tamper_cascades_entire_log(self, populated_log):
        """
        If entry 0's merkle_root is tampered, every subsequent entry's
        previous_root chain is wrong.
        verify_consistency() must report a break starting at sequence 1.
        """
        populated_log.tamper_entry(0, "merkle_root", "sha256:" + "c" * 64)

        consistency = populated_log.verify_consistency()
        assert consistency["is_consistent"] is False
        import re

        broken_seqs = [
            int(m.group(1))
            for e in consistency["errors"]
            for m in [re.search(r"sequence\s+(\d+)", e)]
            if m
        ]
        assert any(s == 1 for s in broken_seqs), (
            f"Expected chain break at sequence 1, got errors: {consistency['errors']}"
        )

    def test_tampered_previous_root_detected(self, populated_log):
        """
        Attacker changes previous_root of entry 5 to a fake value.
        This breaks the chain check at entry 5 itself.
        """
        populated_log.tamper_entry(5, "previous_root", "sha256:" + "d" * 64)

        consistency = populated_log.verify_consistency()
        assert consistency["is_consistent"] is False
        assert any("5" in e for e in consistency["errors"]), (
            f"Expected error mentioning sequence 5, got: {consistency['errors']}"
        )

    def test_content_hash_modification_not_detected_by_chain_check(self, populated_log):
        """
        Attacker modifies content_hash of entry 3  -  changing what was ostensibly logged  -
        WITHOUT updating the merkle_root.

        EXPECTED: verify_consistency() detects this.
        ACTUAL: verify_consistency() does NOT detect it. The chain check only compares
                previous_root → merkle_root pairs; it does not recompute the Merkle
                tree from content_hash values.

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 3.
        """
        populated_log.tamper_entry(3, "content_hash", "sha256:" + "a" * 64)

        consistency = populated_log.verify_consistency()

        # This assertion WILL FAIL  -  exposing the hole:
        assert consistency["is_consistent"] is False, (
            "HOLE 3: verify_consistency() does not recompute Merkle trees from content_hash "
            "values. An attacker can change what was committed (content_hash) without breaking "
            "the previous_root→merkle_root chain check. Content tampering goes undetected. "
            "See RED_TEAM_FINDINGS.md."
        )

    def test_log_chain_intact_for_legitimate_entries(self, populated_log):
        """
        Baseline: an untampered log passes the consistency check.
        Verifies the fixture and check work correctly before adversarial cases.
        """
        consistency = populated_log.verify_consistency()
        assert consistency["is_consistent"] is True
        assert len(consistency["errors"]) == 0
        assert consistency["entry_count"] == 10

    def test_receipt_log_entries_consistent_after_tool_call(self, ctx, temp_dir):
        """
        After a complete Phase 1 + Phase 2 tool call, the log entries for that receipt
        are sequenced correctly (intent before receipt).
        """

        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def read_file(path: str, ctx: ARCContext) -> dict:
            import pathlib

            return {"content": pathlib.Path(path).read_text()}

        import os

        file_path = os.path.join(temp_dir, "file1.txt")
        receipt = read_file(file_path, ctx=ctx)

        log_verify = ctx.log.verify(receipt["receipt_id"])
        assert log_verify["intent_committed"] is True
        assert log_verify["receipt_committed"] is True
        assert log_verify["is_consistent"] is True

        [e["sequence_number"] for e in log_verify["entries"]]
        intent_seq = next(
            e["sequence_number"] for e in log_verify["entries"] if e["entry_type"] == "intent"
        )
        receipt_seq = next(
            e["sequence_number"] for e in log_verify["entries"] if e["entry_type"] == "receipt"
        )
        assert intent_seq < receipt_seq, "Intent must precede receipt in the log"
