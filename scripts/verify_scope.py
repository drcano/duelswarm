#!/usr/bin/env python3
"""Scope / floor re-derivation tool — the SCOPE half of the split auditor (brief v3 A4).

The companion to `scripts/verify_chain.py` (the pure hash walker). This half re-derives the floor
verdict for one event log: does any red EFFECT reach a forbidden host? It is a thin CLI over
`redteam/reverify_floor.reverify`, which is itself stdlib-only and imports nothing from `swarm/`,
so — like the hash walker — this tool imports no `swarm` code (both halves stay swarm-free).

It exits NON-ZERO on a miss: a broken hash chain, an out-of-scope EFFECT (`oos_executed > 0`), or an
unclassified event (fail-closed). A logged `gate.block` on a forbidden host is an ATTEMPT, reported
separately as `oos_attempts`; it is informational and never excuses a later effect on the same host.

Usage:
  python scripts/verify_scope.py                     # verify data/events.jsonl
  python scripts/verify_scope.py path/to/events.jsonl [more...]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "redteam"))
import reverify_floor as rvf          # noqa: E402  (stdlib, swarm-free — never imports swarm/)


def verify(path):
    r = rvf.reverify(str(path))
    scope = r.get("scope")
    if scope is None:
        print(f"{path}: no scope event — not a floor-evidence log (skipped)")
        return True                    # not auditable for scope; the hash walker still applies
    oos = r.get("oos_executed")
    ok = bool(r.get("chain_verified")) and (oos == 0) and not r.get("unclassified_actions")
    print(f"{path}")
    print(f"  chain_verified : {r.get('chain_verified')}")
    print(f"  oos_executed   : {oos}   (red EFFECTS that reached a forbidden host)")
    print(f"  oos_attempts   : {r.get('oos_attempts')}   (forbidden gate.blocks — informational)")
    print(f"  blocks         : {r.get('blocks')}")
    print(f"  forbidden      : {r.get('forbidden')}")
    if r.get("unclassified_actions"):
        print(f"  UNCLASSIFIED   : {r['unclassified_actions']}  (fail-closed: audit refuses)")
    for m in r.get("misses", []):
        print(f"  MISS #{m.get('seq')}: {m.get('action')} -> {m.get('target')}  hits={m.get('hits')}")
    print(f"  STATUS         : {'FLOOR HELD' if ok else 'FLOOR BREACH / UNVERIFIED'}")
    return ok


if __name__ == "__main__":
    paths = sys.argv[1:] or ["data/events.jsonl"]
    rc = 0
    for p in paths:
        if not Path(p).exists():
            print(f"File not found: {p}")
            rc = 1
            continue
        if not verify(p):
            rc = 1
    sys.exit(rc)
