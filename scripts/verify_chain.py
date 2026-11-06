#!/usr/bin/env python3
"""Standalone hash chain verifier — the stdlib hash WALKER half of the auditor's tool.

Given only the event log, verify that every entry chains correctly from genesis to head. Pure
stdlib, and — by construction (brief v3 A4) — it imports NOTHING from `swarm/` (nor from
`redteam/`), so a judge can run it independently and `t2_imports` can assert its isolation. The
scope / floor re-derivation is a SEPARATE tool, `scripts/verify_scope.py` (a thin CLI over
`redteam/reverify_floor`), so this half stays a pure chain walk and neither half imports `swarm`.

Hash algorithm: sha256(prev_hash + canonical_json(entry_without_hash))
Canonical JSON: sorted keys, compact separators (",", ":")

Usage:
  python scripts/verify_chain.py                     # verify data/events.jsonl
  python scripts/verify_chain.py path/to/events.jsonl
"""
import hashlib
import json
import sys
from pathlib import Path

GENESIS = "0" * 64


def verify(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    if not entries:
        print("EMPTY: no entries in the log")
        return False

    print(f"Log: {path}")
    print(f"Entries: {len(entries)}")
    print(f"Genesis: {GENESIS}")
    print()

    prev_hash = GENESIS
    ok = True

    for e in entries:
        seq = e["seq"]
        stored_hash = e["hash"]
        stored_prev = e.get("prev", "")

        # Verify prev pointer
        if stored_prev != prev_hash:
            print(f"  BROKEN prev pointer at seq {seq}")
            print(f"    stored prev:   {stored_prev}")
            print(f"    expected prev: {prev_hash}")
            ok = False
            break

        # Recompute: sha256(prev_hash + compact_json(entry without hash))
        entry_no_hash = {k: v for k, v in e.items() if k != "hash"}
        body = json.dumps(entry_no_hash, sort_keys=True, separators=(",", ":"))
        computed = hashlib.sha256((prev_hash + body).encode()).hexdigest()

        if computed != stored_hash:
            print(f"  BROKEN hash at seq {seq}")
            print(f"    stored:   {stored_hash}")
            print(f"    computed: {computed}")
            ok = False
            break

        prev_hash = stored_hash

    if ok:
        print(f"Head hash: {entries[-1]['hash']}")
        print(f"Chain length: {len(entries)}")
        print(f"Status: VERIFIED")
        print()

        # Summary stats
        actors = {}
        actions = {}
        for e in entries:
            actors[e["actor"]] = actors.get(e["actor"], 0) + 1
            actions[e["action"]] = actions.get(e["action"], 0) + 1

        print("Actor breakdown:")
        for actor, count in sorted(actors.items()):
            print(f"  {actor}: {count} events")

        print("\nAction breakdown:")
        for action, count in sorted(actions.items()):
            print(f"  {action}: {count}")

        blocks = sum(1 for e in entries if e["action"] == "gate.block")
        allows = sum(1 for e in entries if e["action"] == "gate.allow")
        # Chain-level tallies only (pure stdlib). The SCOPE / floor verdict is NOT computed here —
        # run `scripts/verify_scope.py <log>` for the out-of-scope re-derivation (it wraps
        # redteam/reverify_floor). Keeping that out of this file is what lets the walker import no
        # swarm/ code at all (brief v3 A4; enforced by t2_imports).
        print(f"\nGate events: {allows} allow, {blocks} block "
              f"(scope/floor verdict: run scripts/verify_scope.py)")

    return ok


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/events.jsonl"
    path = Path(path)
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    ok = verify(path)
    sys.exit(0 if ok else 1)
