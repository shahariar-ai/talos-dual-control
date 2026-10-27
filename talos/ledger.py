"""Append-only, hash-chained ledger.

Every entry stores the hash of the previous entry, so editing, deleting or
re-ordering any past line breaks the chain and ``verify`` points at the first
broken sequence number. Large payloads (file snapshots used for rollback) live
in a content-addressed blob store: the file name *is* the SHA-256 of its
content, and the hash is also recorded inside the chained entry.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class Ledger:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.blob_dir = self.path.parent / "blobs"
        self.blob_dir.mkdir(exist_ok=True)
        self._lock = threading.Lock()

    # -- reading ---------------------------------------------------------
    def entries(self) -> list[dict]:
        out: list[dict] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    # -- writing ---------------------------------------------------------
    def append(self, kind: str, session: str, **fields: Any) -> dict:
        with self._lock:
            existing = self.entries()
            prev = existing[-1]["hash"] if existing else GENESIS
            body: dict[str, Any] = {
                "seq": len(existing) + 1,
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "kind": kind,
                "session": session,
                **fields,
                "prev": prev,
            }
            body["hash"] = sha256_hex(prev + canonical(body))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return body

    # -- integrity -------------------------------------------------------
    def head(self) -> dict:
        """The chain's current tip. Keep a copy somewhere Talos cannot write (a git commit, an email,
        a printed page): a hash chain alone cannot reveal that the *last* entries were cut off."""
        es = self.entries()
        return {"seq": len(es), "hash": es[-1]["hash"] if es else GENESIS}

    def verify(self, anchor: dict | None = None) -> tuple[bool, int | None, str]:
        """Return (ok, first_broken_seq, message). With an externally stored ``anchor`` (from ``head()``)
        it also detects truncation and rewriting of everything up to the anchor."""
        ok, bad, msg = self._verify_chain()
        if not ok or anchor is None:
            return ok, bad, msg
        es = self.entries()
        n = anchor["seq"]
        if len(es) < n:
            return False, len(es) + 1, f"ledger was truncated: it has {len(es)} entries but the anchor says {n}"
        if n and es[n - 1]["hash"] != anchor["hash"]:
            return False, n, f"entry #{n} no longer matches the anchor: history was rewritten"
        return True, None, f"chain intact and consistent with anchor at #{n}"

    def _verify_chain(self) -> tuple[bool, int | None, str]:
        prev = GENESIS
        for i, e in enumerate(self.entries(), start=1):
            claimed = e.get("hash")
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != i:
                return False, i, f"entry #{i}: sequence number is {e.get('seq')} (an entry was removed or reordered)"
            if e.get("prev") != prev:
                return False, i, f"entry #{i}: link to the previous entry is broken"
            if sha256_hex(prev + canonical(body)) != claimed:
                return False, i, f"entry #{i}: content was modified after it was written"
            prev = claimed
        return True, None, "chain intact"

    # -- blob store ------------------------------------------------------
    def store_blob(self, data: bytes) -> str:
        h = sha256_hex(data)
        p = self.blob_dir / h
        if not p.exists():
            p.write_bytes(data)
        return h

    def load_blob(self, h: str) -> bytes:
        data = (self.blob_dir / h).read_bytes()
        if sha256_hex(data) != h:
            raise ValueError(f"snapshot {h[:8]} failed its integrity check")
        return data
