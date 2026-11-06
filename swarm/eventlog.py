"""Append-only, hash-chained event log — ground truth for the report (SPEC §4).

Every action appends one JSON line; each line's hash chains the previous one, so any later
EDIT, REORDER, or MIDDLE DELETION breaks verify() (a prev-hash mismatch). Written independently
of agent narration, so the report can be reconciled against it.

Scope of the guarantee, stated honestly: verify() re-walks prev-linkage only, so it does NOT by
itself detect (a) truncation of the TAIL (dropping the last k entries leaves a still-consistent
chain) or (b) a full forward re-hash (the chain carries no secret/signature). Those are covered
by anchoring the entry COUNT and final hash EXTERNALLY — the preregistration/manifest anchor
(scripts/preregister.py, data/corpus/MANIFEST) records them, so a truncated or re-hashed log
fails against that anchor even though verify() alone would not catch it.
"""
import json
import hashlib
import time
import threading
from pathlib import Path

GENESIS = "0" * 64


def _hash(prev, payload):
    """sha256 over the previous hash + the entry (canonical, minus its hash)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


class EventLog:
    def __init__(self, path, on_append=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries = self._load()
        self._last = self._entries[-1]["hash"] if self._entries else GENESIS
        self._on_append = on_append
        self._lock = threading.Lock()

    def _load(self):
        if not self.path.exists():
            return []
        with self.path.open() as f:
            return [json.loads(line) for line in f if line.strip()]

    def append(self, actor, action, data=None):
        with self._lock:
            payload = {
                "seq": len(self._entries),
                "ts": time.time(),
                "actor": actor,
                "action": action,
                "data": data or {},
                "prev": self._last,
            }
            payload["hash"] = _hash(self._last, payload)
            with self.path.open("a") as f:
                f.write(json.dumps(payload, sort_keys=True) + "\n")
            self._entries.append(payload)
            self._last = payload["hash"]
        if self._on_append:
            try:
                self._on_append(payload)
            except Exception:
                pass
        return payload

    def entries(self):
        with self._lock:
            return list(self._entries)

    def verify(self):
        """Re-walk the chain. Returns (ok, first_bad_seq_or_None)."""
        prev = GENESIS
        for e in self._entries:
            recomputed = _hash(prev, {k: e[k] for k in e if k != "hash"})
            if e.get("prev") != prev or recomputed != e.get("hash"):
                return False, e.get("seq")
            prev = e["hash"]
        return True, None


if __name__ == "__main__":  # self-check: chain holds, reopens, tamper is caught
    import tempfile

    p = Path(tempfile.mkdtemp()) / "events.jsonl"
    log = EventLog(p)
    log.append("red", "recon", {"target": "struts"})
    log.append("red", "exploit", {"cve": "CVE-2017-5638"})
    assert log.verify() == (True, None)

    # reopening appends onto the existing chain, not a fresh one
    reopened = EventLog(p)
    reopened.append("blue", "detect", {})
    assert reopened.verify()[0]

    # tampering with a committed entry breaks verification
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["data"] = {"target": "decoy"}            # rewrite, keep stale hash
    lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, bad = EventLog(p).verify()
    assert ok is False and bad == 0, (ok, bad)
    print("eventlog ok")
