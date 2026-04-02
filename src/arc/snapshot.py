"""
Before-state capture and rollback for ARC protocol.
Supports filesystem paths, in-memory dicts, and API responses.
"""

import base64
import copy
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from arc.ids import new_snapshot_id
from arc.signing import canonical_json, sha256_hex


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Snapshot:
    snapshot_ref: str
    resource_uri: str
    resource_type: str
    content: dict
    snapshot_hash: str
    snapshot_size_bytes: int
    captured_at: str
    is_reversible: bool


class SnapshotStore:
    """
    In-memory (or SQLite-backed) store for snapshot content.
    Indexed by snapshot_ref.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path
        self._memory: dict[str, Snapshot] = {}
        if db_path:
            self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_ref TEXT PRIMARY KEY,
                resource_uri TEXT,
                resource_type TEXT,
                content TEXT,
                snapshot_hash TEXT,
                snapshot_size_bytes INTEGER,
                captured_at TEXT,
                is_reversible INTEGER
            )"""
        )
        conn.commit()
        conn.close()

    def store(self, snap: Snapshot) -> None:
        self._memory[snap.snapshot_ref] = snap
        if self._db_path:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?,?,?,?)",
                (
                    snap.snapshot_ref,
                    snap.resource_uri,
                    snap.resource_type,
                    json.dumps(snap.content),
                    snap.snapshot_hash,
                    snap.snapshot_size_bytes,
                    snap.captured_at,
                    int(snap.is_reversible),
                ),
            )
            conn.commit()
            conn.close()

    def retrieve(self, snapshot_ref: str) -> Snapshot | None:
        if snapshot_ref in self._memory:
            return self._memory[snapshot_ref]
        if self._db_path:
            conn = sqlite3.connect(self._db_path)
            row = conn.execute(
                "SELECT * FROM snapshots WHERE snapshot_ref=?", (snapshot_ref,)
            ).fetchone()
            conn.close()
            if row:
                snap = Snapshot(
                    snapshot_ref=row[0],
                    resource_uri=row[1],
                    resource_type=row[2],
                    content=json.loads(row[3]),
                    snapshot_hash=row[4],
                    snapshot_size_bytes=row[5],
                    captured_at=row[6],
                    is_reversible=bool(row[7]),
                )
                self._memory[snapshot_ref] = snap
                return snap
        return None


def capture_filesystem(path: str | Path, store: SnapshotStore) -> Snapshot:
    """
    Capture before-state of a filesystem path.
    For a file: records path, size, mtime, sha256 of content + actual base64 content.
    For a directory: records file tree with content for rollback.
    """
    p = Path(path)
    ref = new_snapshot_id()
    captured_at = _now_iso()

    if p.is_file():
        raw = p.read_bytes()
        file_hash = hashlib.sha256(raw).hexdigest()
        content = {
            "type": "file",
            "path": str(p),
            "size": len(raw),
            "mtime": p.stat().st_mtime,
            "sha256": file_hash,
            "content_b64": base64.b64encode(raw).decode("ascii"),
        }
        resource_type = "filesystem:file"
        resource_uri = f"file://{p}"
    elif p.is_dir():
        files = []
        for fpath in sorted(p.rglob("*")):
            if fpath.is_file():
                raw = fpath.read_bytes()
                files.append(
                    {
                        "path": str(fpath),
                        "relative_path": str(fpath.relative_to(p)),
                        "size": len(raw),
                        "mtime": fpath.stat().st_mtime,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "content_b64": base64.b64encode(raw).decode("ascii"),
                    }
                )
        content = {
            "type": "directory",
            "path": str(p),
            "file_count": len(files),
            "files": files,
        }
        resource_type = "filesystem:directory"
        resource_uri = f"file://{p}"
    else:
        # Path doesn't exist yet  -  record absence
        content = {"type": "absent", "path": str(p)}
        resource_type = "filesystem:file"
        resource_uri = f"file://{p}"

    content_bytes = canonical_json(content)
    snap_hash = sha256_hex(content_bytes)

    snap = Snapshot(
        snapshot_ref=ref,
        resource_uri=resource_uri,
        resource_type=resource_type,
        content=content,
        snapshot_hash=snap_hash,
        snapshot_size_bytes=len(content_bytes),
        captured_at=captured_at,
        is_reversible=True,
    )
    store.store(snap)
    return snap


def capture_dict(key: str, data: dict, store: SnapshotStore) -> Snapshot:
    """
    Capture before-state of an in-memory dict.
    resource_uri = f"memory:{key}"
    """
    ref = new_snapshot_id()
    captured_at = _now_iso()
    content = copy.deepcopy(data)
    content_bytes = canonical_json(content)
    snap_hash = sha256_hex(content_bytes)

    snap = Snapshot(
        snapshot_ref=ref,
        resource_uri=f"memory:{key}",
        resource_type="memory:key",
        content=content,
        snapshot_hash=snap_hash,
        snapshot_size_bytes=len(content_bytes),
        captured_at=captured_at,
        is_reversible=True,
    )
    store.store(snap)
    return snap


def capture_api_response(url: str, response_data: dict, store: SnapshotStore) -> Snapshot:
    """
    Capture the state of an API response (read before write).
    is_reversible = False (cannot undo API side effects in general).
    """
    ref = new_snapshot_id()
    captured_at = _now_iso()
    content = copy.deepcopy(response_data)
    content_bytes = canonical_json(content)
    snap_hash = sha256_hex(content_bytes)

    snap = Snapshot(
        snapshot_ref=ref,
        resource_uri=f"api:{url}",
        resource_type="api:response",
        content=content,
        snapshot_hash=snap_hash,
        snapshot_size_bytes=len(content_bytes),
        captured_at=captured_at,
        is_reversible=False,
    )
    store.store(snap)
    return snap


def rollback_filesystem(snap: Snapshot) -> bool:
    """
    Restore filesystem to before-state.
    For files: recreate or restore from stored content.
    For directories: recreate all files from stored content.
    Returns True if rollback succeeded.
    """
    try:
        content = snap.content
        snap_type = content.get("type")

        if snap_type == "file":
            path = Path(content["path"])
            raw = base64.b64decode(content["content_b64"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            return True

        elif snap_type == "directory":
            base_path = Path(content["path"])
            base_path.mkdir(parents=True, exist_ok=True)
            for file_entry in content["files"]:
                fpath = Path(file_entry["path"])
                raw = base64.b64decode(file_entry["content_b64"])
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_bytes(raw)
            return True

        elif snap_type == "absent":
            # Resource didn't exist before  -  nothing to restore
            path = Path(content["path"])
            if path.exists():
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    import shutil
                    shutil.rmtree(path)
            return True

        return False
    except Exception:
        return False


def rollback_dict(snap: Snapshot, target: dict) -> bool:
    """Restore dict to before-state content. Returns True."""
    try:
        target.clear()
        target.update(copy.deepcopy(snap.content))
        return True
    except Exception:
        return False
