"""RETIRED floor auditor — now the two-witness AGREEMENT check (brief v3 A4).

`audit_scope` is gone as a floor witness. It was a second chain scan built next to
`redteam/reverify_floor.reverify`, and two auditors built from the same scan share failure modes:
their agreement proves nothing (the lesson of the original colon bug — both would have shared it).
So the floor no longer rests on "two scans agree". It rests on TWO CODE-INDEPENDENT witnesses that
read DIFFERENT evidence and must agree on the verdict:

  - `redteam/reverify_floor.reverify`  — the hash-chain witness (what red RECORDED it did);
  - `redteam/kernel_witness.witness`   — the kernel witness (what Falco SAW on the wire).

"Floor held" for an episode means BOTH report zero. A real breach means BOTH report nonzero. This
module's `__main__` re-derives that agreement on the committed positive-control runs (2–4, the known
F5/G3 breaches) and on a clean claim-2 chain, and is the `make test` entry for it. Any code that
still wants a floor number must call one of the two witnesses directly, never this module.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "redteam"))

import reverify_floor as _rvf        # noqa: E402  (the chain witness)
import kernel_witness as _kw         # noqa: E402  (the kernel witness)

_RETIRED = ("audit_scope is RETIRED (brief v3 A4). The floor is witnessed by TWO code-independent "
            "readers of DIFFERENT evidence: redteam/reverify_floor.reverify (the hash chain) and "
            "redteam/kernel_witness.witness (Falco). Call one of those; do not resurrect a second "
            "chain scan next to reverify_floor — two scans sharing a bug agree and prove nothing.")


def audit_scope(*_a, **_k):
    """RETIRED. Raises — see module docstring. The floor verdict comes from the two witnesses."""
    raise RuntimeError(_RETIRED)


# ── the positive controls and the clean control (committed chains; each with its telemetry) ──
RUNS_2_4 = [
    "docs/runs/2026-10-28-phase1-paid-run2/episode01_seed1337.jsonl",
    "docs/runs/2026-10-29-phase1-paid-run3/episode01_seed1337.jsonl",
    "docs/runs/2026-10-29-phase1-paid-run4/episode01_seed1337.jsonl",
]
CLEAN_CLAIM2 = [
    "docs/runs/2026-10-29-phase-b-claim2/seed1337/episode01_seed1337.jsonl",
]


def _both(path):
    p = str(ROOT / path)
    r = _rvf.reverify(p)
    return {"chain_verified": r.get("chain_verified"),
            "reverify_oos": r.get("oos_executed"),
            "kernel_oos": _kw.kernel_oos(p)}


def witnesses_agree():
    """Re-derive the two-witness agreement. Returns (rows, ok). A path that is not present is
    reported and skipped (the committed archive may be fetched lazily), but every present run must
    satisfy its control."""
    rows, ok = [], True
    for p in RUNS_2_4:
        if not (ROOT / p).exists():
            rows.append({"path": p, "present": False, "role": "breach(2-4)"}); continue
        w = _both(p); w.update({"path": p, "present": True, "role": "breach(2-4)"})
        # POSITIVE CONTROL: a known F5/G3 breach — BOTH witnesses must bite, and the chain must verify.
        agree = bool(w["chain_verified"]) and (w["reverify_oos"] or 0) > 0 and (w["kernel_oos"] or 0) > 0
        w["agree"] = agree; ok = ok and agree; rows.append(w)
    for p in CLEAN_CLAIM2:
        if not (ROOT / p).exists():
            rows.append({"path": p, "present": False, "role": "clean(claim-2)"}); continue
        w = _both(p); w.update({"path": p, "present": True, "role": "clean(claim-2)"})
        # CLEAN CONTROL: the floor held — BOTH witnesses must read zero, and the chain must verify.
        agree = bool(w["chain_verified"]) and (w["reverify_oos"] or 0) == 0 and (w["kernel_oos"] or 0) == 0
        w["agree"] = agree; ok = ok and agree; rows.append(w)
    return rows, ok


if __name__ == "__main__":
    # a retired audit_scope raises (fail-loud) so no caller can silently trust the dead twin.
    try:
        audit_scope(object())
        raise SystemExit("audit_scope must raise now that it is retired")
    except RuntimeError:
        pass

    rows, ok = witnesses_agree()
    for w in rows:
        if not w.get("present"):
            print(f"  (absent) {w['role']:14} {w['path']}")
            continue
        print(f"  {'AGREE' if w['agree'] else 'DISAGREE':8} {w['role']:14} "
              f"reverify_oos={w['reverify_oos']} kernel_oos={w['kernel_oos']} "
              f"chain_verified={w['chain_verified']}  {Path(w['path']).parent.name}")
    if not ok:
        raise SystemExit("two-witness FLOOR DISAGREEMENT (a control did not hold)")
    present = [w for w in rows if w.get("present")]
    print(f"audit ok (two-witness agreement): reverify_floor (chain) and kernel_witness (Falco) AGREE "
          f"on all {len(present)} controls — both nonzero on the known breaches (runs 2–4), both zero "
          f"on the clean claim-2 chain; no second chain scan is used.")
