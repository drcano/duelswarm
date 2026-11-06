"""Cold prove the 2026-11-04 PAID claim-2 co-evolution run (pop 3 x gen 3, blue observe-only)
re-derives from its committed gzipped chains — no Docker, no tokens, no range needed.

Nothing here reads the run's own live_generations_summary.json for a verdict; every number is
re-derived from the raw chains with the SAME verifier tools the floor ships. The summary is only
spot-checked against the cold result at the end.

What it re-derives, per the 2026-10-30 discipline:

  1. Boot witness: ok=True, auth+syscall witnesses genuinely attributed (the eBPF-attach-race fix
     rescued it at attempt 2 — recorded, not hidden).
  2. INSTRUMENT, every one of the 9 episodes (must hold by construction):
       - reverify_floor: the hash chain re-walks clean (chain_verified) and oos_executed == 0
       - kernel_witness: the SECOND, code-independent witness (Falco net.flow) reports kernel_oos == 0
         — the A4 two-witness floor (the retired auditor_parity chain-scan twin is gone)
       - verify_io_sidecar: the IO sidecar is complete (every turn pinned, no dangling)
       - verify_provider_pin: exactly one provider pinned (Nebius) and every llm.call is on the
         pinned lineage — no silent mid-run swap
       - A-D1 unified predicate: sum(is_blue_detection) == duel.outcome.blue_detections
       - provenance: real paid LLM moves (>= floor), zero silent router fallbacks, floor HELD
  3. OFFENSE (a RESULT, not a build gate): count the telemetry-corroborated crown thefts — a win
     counts ONLY when duel.verdict.achieved AND loot_corroborated (the crown host's own telemetry
     witnessed the loot, independent reconciler). 3/9 here, one per generation.
  4. DIVERSITY NULL (the honest negative this run exists to surface): re-derive the MAP-Elites
     behavior descriptor for all 9 episodes. They collapse to a SINGLE cell (0,2,1,2) of 54
     (diversity 1/54 = 0.0185) — every axis saturates on the live range, so the co-evolution
     archive has no diversity gradient to climb. This is asserted, not papered over.

Run from the repo root:  .venv/bin/python docs/runs/2026-11-04-claim2-gen3-paid/prove_claim2_gen3.py
"""
import gzip, io, json, contextlib, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHAINS = HERE / "chains"
ROOT = HERE.parents[2]   # repo root


def _mains_unzipped(tmp: Path):
    """Unzip every gen*.jsonl (main, io, telemetry) into tmp; return the 9 main-chain paths."""
    for gz in sorted(CHAINS.glob("gen*.jsonl.gz")):
        (tmp / gz.name[:-3]).write_bytes(gzip.decompress(gz.read_bytes()))
    return sorted(p for p in tmp.glob("gen*.jsonl")
                  if "_io" not in p.name and "_telemetry" not in p.name)


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
    # Scoring comes from the FROZEN descriptor snapshot vendored in _frozen/ (the OLD pre-seq-52
    # (entry, breadth, stealth, depth) descriptor this run was SCORED under), NOT the live engine — the
    # seq-52 redesign deliberately re-binned this very archive, so importing the live descriptor would
    # silently rewrite this run's diversity-null finding (I8). Pinned by _frozen/MANIFEST.sha256.
    import hashlib
    frz = HERE / "_frozen"
    for _line in (frz / "MANIFEST.sha256").read_text().splitlines():
        _want, _name = _line.split()
        assert hashlib.sha256((frz / _name).read_bytes()).hexdigest() == _want, f"frozen {_name} drifted"
    sys.path.insert(0, str(frz))
    from arms_race import is_blue_detection
    from population import behavior_descriptor, live_red_score_fitness, gated_objective

    gt = {"objective_host": "db-core", "entry": "web01"}
    print("== 2026-11-04 claim-2 pop3xgen3 PAID cold proof ==\n")

    # 1. boot witness
    bw = [json.loads(l) for l in gzip.open(CHAINS / "boot_witness.jsonl.gz", "rt") if l.strip()]
    b = bw[-1]["data"]
    assert b["ok"] and b["auth_witness"] and b["syscall_witness"], b
    assert b.get("syscall_events_attributed", 0) >= 1, b
    print(f"BOOT  ok=True auth=True syscall=True attributed={b.get('syscall_events_attributed')} "
          f"rescued_at_attempt={b.get('attempt')}/{b.get('attempts_max')}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        mains = _mains_unzipped(tmp)
        assert len(mains) == 9, [p.name for p in mains]

        wins = corrob = 0
        per_gen = {0: 0, 1: 0, 2: 0}
        cells = {}
        tiers = set()
        for p in mains:
            ev = [json.loads(l) for l in open(p) if l.strip()]
            io_p = tmp / (p.name[:-6] + "_io.jsonl")

            fl = rvf.reverify(str(p))
            pv = rvf.provenance(str(p))
            kr = kw.witness(str(p))            # second, code-independent witness (Falco), A4 two-witness floor
            sc = vio.verify(str(p), str(io_p))
            pin_ok, pin = vpp.verify_provider_pin(ev)
            pred = sum(1 for e in ev if is_blue_detection(e))
            truth = next(((e.get("data") or {}).get("blue_detections")
                          for e in ev if e.get("action") == "duel.outcome"), None)
            v = next((e.get("data") for e in ev if e.get("action") == "duel.verdict"), {}) or {}

            assert fl.get("oos_executed") == 0 and fl.get("chain_verified"), (p.name, fl)
            assert (kr.get("kernel_oos") or 0) == 0, (p.name, kr)
            assert sc.get("ok"), (p.name, sc)
            assert pin_ok and pin.get("provider") == "nebius", (p.name, pin)
            assert pred == truth, (p.name, pred, truth)
            assert pv.get("silent_fallback_events") == 0 and pv.get("llm_duel"), (p.name, pv)
            assert pv.get("floor_status") == "HELD", (p.name, pv.get("floor_status"))

            for e in ev:
                if e.get("action") == "llm.call":
                    tiers.add((e.get("data") or {}).get("tier"))
            won = bool(v.get("achieved")) and bool(v.get("loot_corroborated"))
            wins += bool(v.get("achieved"))
            corrob += won
            if won:
                per_gen[int(p.name[3])] += 1
            cell = behavior_descriptor(ev, gt)
            cells[cell] = cells.get(cell, 0) + 1
            print(f"{p.name:26s} OK  oos=0 cv=T kernel=0 io=T pin=nebius A-D1={pred} "
                  f"llm={pv.get('llm_driven_moves')} silent=0 floor=HELD | "
                  f"achieved={v.get('achieved')} corrob={v.get('loot_corroborated')} "
                  f"cell={cell} fit={round(live_red_score_fitness(ev, gt), 3)} "
                  f"gated_obj={gated_objective(ev)}")

        print("\n-- cross-episode (RESULTS, not gates) --")
        print(f"crown thefts (verdict.achieved):        {wins}/9")
        print(f"  reconciler-corroborated of those:     {corrob}/9  (gen0={per_gen[0]} "
              f"gen1={per_gen[1]} gen2={per_gen[2]})")
        print(f"red model tiers used:                   {sorted(t for t in tiers if t)}")
        print(f"distinct behavior cells occupied:       {len(cells)}/54  "
              f"(diversity={len(cells)/54:.4f})")
        print(f"cell histogram:                         {cells}")

        # the instrument holds by construction (asserts above); offense is strong AND real
        assert corrob == 3, corrob
        assert per_gen == {0: 1, 1: 1, 2: 1}, per_gen
        # the honest negative, asserted so a future descriptor fix must move this number
        assert len(cells) == 1 and (0, 2, 1, 2) in cells, cells

    print("\n== PROOF COMPLETE ==")
    print("Instrument SOUND on all 9 episodes. Offense: 3/9 telemetry-corroborated crown thefts, "
          "one per generation. DIVERSITY NULL: the archive collapsed to 1/54 cells — co-evolution "
          "has no behavioral gradient on this range under the current 4-D descriptor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
