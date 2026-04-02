"""
ARC Transparency Log Server  -  FastAPI application.
Three endpoints for writing and reading log entries.
"""

import json
import os
import re
from datetime import datetime, timezone

try:
    from fastapi import FastAPI, HTTPException, Query
    from pydantic import BaseModel
except ImportError:
    raise ImportError(
        "FastAPI and pydantic are required for the ARC log server. "
        "Install them with: pip install arc-protocol[server]"
    ) from None

from arc.signing import ARCKeyPair, canonical_json, sha256_hex
from arc_log.storage import LogStorage


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ARC Transparency Log",
    description="Append-only transparency log for ARC Agent Receipt & Certification",
    version="1.0.0",
)

# Module-level singletons (initialized on startup)
_storage: LogStorage | None = None
_log_keypair: ARCKeyPair | None = None
_DB_PATH = os.environ.get("ARC_LOG_DB", "./arc_log.db")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_receipt_id(receipt_id: str) -> bool:
    return bool(re.match(r"^arc_[0-9A-Z]{26}$", receipt_id))


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    global _storage, _log_keypair
    _log_keypair = ARCKeyPair.generate()
    _storage = LogStorage(_DB_PATH, _log_keypair)
    print(f"[ARC Log Server] Log operator public key: {_log_keypair.public_key_hex}")
    print(f"[ARC Log Server] Database: {_DB_PATH}")
    print(f"[ARC Log Server] Ready.")


def get_storage() -> LogStorage:
    if _storage is None:
        raise RuntimeError("Storage not initialized")
    return _storage


# ─── Request/Response Models ──────────────────────────────────────────────────

class CommitIntentRequest(BaseModel):
    receipt_id: str
    intent: dict


class CommitReceiptRequest(BaseModel):
    receipt: dict


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.post("/v1/log/intent")
def commit_intent(req: CommitIntentRequest):
    """
    Commit a Phase 1 intent to the log.
    Returns the log entry and commitment to embed in phase_1.
    """
    if not _valid_receipt_id(req.receipt_id):
        raise HTTPException(status_code=400, detail=f"Invalid receipt_id format: {req.receipt_id}")

    # Basic intent validation
    required_fields = ["intent_id", "tool_name", "arguments", "declared_by", "reasoning_commitment", "declared_at"]
    for field in required_fields:
        if field not in req.intent:
            raise HTTPException(status_code=400, detail=f"Missing intent field: {field}")

    storage = get_storage()
    log_entry, commitment = storage.append_intent(req.receipt_id, req.intent)

    return {"log_entry": log_entry, "commitment": commitment}


@app.post("/v1/log/receipt")
def commit_receipt(req: CommitReceiptRequest):
    """
    Commit a complete receipt (Phase 2) to the log.
    Validates that a matching intent entry exists.
    """
    receipt = req.receipt
    receipt_id = receipt.get("receipt_id", "")

    if not _valid_receipt_id(receipt_id):
        raise HTTPException(status_code=400, detail=f"Invalid receipt_id format: {receipt_id}")

    if receipt.get("arc_version") != "1.0":
        raise HTTPException(status_code=400, detail="Invalid arc_version (expected '1.0')")

    storage = get_storage()

    # Verify that intent was already committed
    verify_result = storage.get_entries_for_receipt(receipt_id)
    intent_entries = [e for e in verify_result if e["entry_type"] == "intent"]
    if not intent_entries:
        raise HTTPException(
            status_code=409,
            detail=f"No intent entry found for receipt_id {receipt_id}. Commit intent first."
        )

    log_entry, commitment = storage.append_receipt(receipt)
    return {"log_entry": log_entry, "commitment": commitment}


@app.get("/v1/log/verify/{receipt_id}")
def verify_receipt_log(receipt_id: str):
    """
    Verify that a receipt is in the log. Public endpoint, no auth required.
    """
    if not _valid_receipt_id(receipt_id):
        raise HTTPException(status_code=400, detail=f"Invalid receipt_id format: {receipt_id}")

    storage = get_storage()
    entries = _storage.get_entries_for_receipt(receipt_id)

    intent_committed = any(e["entry_type"] == "intent" for e in entries)
    receipt_committed = any(e["entry_type"] == "receipt" for e in entries)

    # Check consistency of these entries
    is_consistent = True
    if len(entries) >= 2:
        seqs = [e["sequence_number"] for e in entries]
        is_consistent = seqs == sorted(seqs) and seqs[1] > seqs[0]

    return {
        "receipt_id": receipt_id,
        "found": len(entries) > 0,
        "entries": entries,
        "intent_committed": intent_committed,
        "receipt_committed": receipt_committed,
        "is_consistent": is_consistent,
        "verification_time": _now_iso(),
    }


@app.get("/v1/log/entries")
def get_entries(
    from_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=10, ge=1, le=100),
):
    """Return log entries from sequence number from_seq, up to limit entries."""
    storage = get_storage()
    entries = storage.get_entries_range(from_seq, limit)
    return entries



@app.get("/v1/log/receipt/{receipt_id}")
async def get_receipt(receipt_id: str):
    """Return the full receipt content stored for a given receipt_id."""
    entries = _storage.get_entries_for_receipt(receipt_id)
    for entry in entries:
        if entry.get("entry_type") == "receipt" and entry.get("content"):
            try:
                return json.loads(entry["content"])
            except Exception:
                return entry
    raise HTTPException(status_code=404, detail=f"Receipt {receipt_id} not found")

@app.get("/v1/log/root")
def get_root():
    """Return the current signed tree head."""
    storage = get_storage()
    kp = _log_keypair
    current_root = storage.current_root()
    count = storage.count()
    timestamp = _now_iso()

    sign_payload_obj = {
        "merkle_root": current_root,
        "sequence_number": count - 1,
        "timestamp": timestamp,
    }
    log_signature = kp.sign(canonical_json(sign_payload_obj))

    return {
        "sequence_number": count - 1,
        "merkle_root": current_root,
        "timestamp": timestamp,
        "log_signature": log_signature,
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "arc-log-server", "version": "1.0.0"}


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    import uvicorn
    uvicorn.run(
        "arc_log.server:app",
        host="0.0.0.0",
        port=int(os.environ.get("ARC_LOG_PORT", "8080")),
        reload=False,
    )


if __name__ == "__main__":
    main()

