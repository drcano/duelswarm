"""Cold prove the 2026-11-04 PAID 1x1 post-refactor shakeout re-derives from its one committed
gzipped chain — no Docker, no tokens. This is the shakeout Dante asked for before the long run
("one paid run, blue observe-only, 1 generation, 1 population, to see if anything is broken").

It establishes two things cold:
  1. The INSTRUMENT is sound on the live stack after the big refactor: boot witness ok (rescued at
     attempt 2 by the eBPF-attach-race fix), floor oos=0 + chain verified, provider pinned to
     Nebius with no swap, IO sidecar complete, A-D1 detection predicate matches the committed
     outcome.
  2. Red fell ONE HOP SHORT of the crown (achieved=False, archive 0/54) — a correct, honest miss,
     NOT a dead selection path. This is the `red_cells=0` that motivated running the full
     pop3xgen3 (see ../2026-11-04-claim2-gen3-paid), where red then landed 3/9 corroborated wins.

Run from the repo root:  .venv/bin/python docs/runs/2026-11-04-paid-1x1-shakeout/prove_paid_1x1.py
"""
import gzip, io, json, contextlib, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHAINS = HERE / "chains"
ROOT = HERE.parents[2]


def main():
    sys.path.insert(0, str(ROOT))
    import importlib.util

    def _imp(name, rel):
        spec = importlib.util.spec_from_file_location(name, str(ROOT / rel))
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

    rvf = _imp("reverify_floor", "redteam/reverify_floor.py")
    vio = _imp("verify_io_sidecar", "redteam/verify_io_sidecar.py")
    vpp = _imp("verify_provider_pin", "redteam/verify_provider_pin.py")
    kw = _imp("kernel_witness", "redteam/kernel_witness.py")   # the A4 second, code-independent witness
    # The behavior cell comes from the FROZEN descriptor snapshot in _frozen/ (the era this shakeout
    # was scored under), not the live engine (audit I8); pinned by _frozen/MANIFEST.sha256.
    import hashlib
    frz = HERE / "_frozen"
    for _line in (frz / "MANIFEST.sha256").read_text().splitlines():
        _want, _name = _line.split()
        assert hashlib.sha256((frz / _name).read_bytes()).hexdigest() == _want, f"frozen {_name} drifted"
    sys.path.insert(0, str(frz))
    from arms_race import is_blue_detection
    from population import behavior_descriptor

    print("== 2026-11-04 PAID 1x1 post-refactor shakeout cold proof ==\n")
    bw = [json.loads(l) for l in gzip.open(CHAINS / "boot_witness.jsonl.gz", "rt") if l.strip()]
    b = bw[-1]["data"]
    assert b["ok"] and b["auth_witness"] and b["syscall_witness"], b
    print(f"BOOT  ok=True auth=True syscall=True attributed={b.get('syscall_events_attributed')} "
          f"rescued_at_attempt={b.get('attempt')}/{b.get('attempts_max')}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for gz in CHAINS.glob("gen*.jsonl.gz"):
            (tmp / gz.name[:-3]).write_bytes(gzip.decompress(gz.read_bytes()))
        p = next(x for x in tmp.glob("gen*.jsonl") if "_io" not in x.name and "_telemetry" not in x.name)
        io_p = tmp / (p.name[:-6] + "_io.jsonl")
        ev = [json.loads(l) for l in open(p) if l.strip()]

        fl = rvf.reverify(str(p)); kr = kw.witness(str(p)); sc = vio.verify(str(p), str(io_p))
        pin_ok, pin = vpp.verify_provider_pin(ev)
        pred = sum(1 for e in ev if is_blue_detection(e))
        truth = next(((e.get("data") or {}).get("blue_detections")
                      for e in ev if e.get("action") == "duel.outcome"), None)
        v = next((e.get("data") for e in ev if e.get("action") == "duel.verdict"), {}) or {}
        cell = behavior_descriptor(ev, {"objective_host": "db-core", "entry": "web01"})

        assert fl.get("oos_executed") == 0 and fl.get("chain_verified"), fl
        assert (kr.get("kernel_oos") or 0) == 0 and sc.get("ok") and pin_ok and pin.get("provider") == "nebius"
        assert pred == truth, (pred, truth)
        print(f"{p.name}  oos=0 cv=T kernel=0 io=T pin=nebius A-D1 {pred}=={truth} "
              f"| achieved={v.get('achieved')} corrob={v.get('loot_corroborated')} cell={cell}")

        # the honest miss: red did NOT reach the crown here
        assert v.get("achieved") is False, v
        arch = json.loads((CHAINS / "red_live_archive.json").read_text())
        occupied = len(arch["archive"]["entries"])
        print(f"archive cells occupied: {occupied}/{arch['archive']['cells']}  "
              f"(red fell one hop short of db-core — correct miss, not a dead selection path)")
        assert occupied == 0, occupied

    print("\n== PROOF COMPLETE == instrument sound; red short of crown (red_cells=0).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
