"""Cold re-derivation of the two first-arsenal live runs from the COMMITTED artifacts alone.

No Docker, no API, no live range. For each run it:
  1. verifies the engagement log AND the telemetry chain as tamper-evident hash chains;
  2. re-derives the hard floor COLD (reverify_floor): chain_verified, oos_executed == 0;
  3. re-runs the (amended 2026-10-28) reconciler with the IP->name resolver and the crown-file
     marker REGENERATED DETERMINISTICALLY from the committed seed (topo_to_compose.generate_unified)
     — so the corroboration is re-derivable by an external checker, not only live;
  4. computes the telemetry-gated objective verdict (duel.verdict): achieved iff red's loot claim
     is witnessed on the crown host's own telemetry.

Run:  .venv/bin/python docs/runs/2026-10-27-arsenal-first-live/rederive.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))

from swarm import topo_to_compose as T, live_truth          # noqa: E402
import reverify_floor as rvf                                 # noqa: E402
import importlib.util                                        # noqa: E402

_spec = importlib.util.spec_from_file_location("lar", ROOT / "scripts" / "live_arms_race_run.py")
_lar = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_lar)
_vspec = importlib.util.spec_from_file_location("vc", ROOT / "scripts" / "verify_chain.py")
_vc = importlib.util.module_from_spec(_vspec); _vspec.loader.exec_module(_vc)

HERE = Path(__file__).resolve().parent
RUNS = [("A (blue-active)", HERE / "A-blue-active"),
        ("B (observe-only)", HERE / "B-observe-only")]


def _seed(run_dir):
    s = json.loads((run_dir / "series.json").read_text()).get("seeds") or [1337]
    return (s[0] if isinstance(s, list) else s)


def _resolver_and_markers(seed):
    topo, gt = T.generate_unified(seed)
    facts = T.unified_facts(topo, gt)
    _, ip_by_host = T.plan_ips(topo, facts)
    ip2name = {ip: n for n, nets in ip_by_host.items() for ip in nets.values()}
    crown = (gt.get("crown") or {}).get("data")
    cf = next((f for f in facts["flags"] if f["host"] == crown), None)
    markers = [".crown", "crown jewel"] + ([Path(cf["dst_path"]).name.lower()] if cf else [])
    return (lambda d: ip2name.get(d, d)), markers, crown


def main():
    ok_all = True
    for label, d in RUNS:
        red = d / "episode01_seed1337.jsonl"
        tele = d / "episode01_seed1337_telemetry.jsonl"
        seed = _seed(d)
        print(f"\n=== Run {label}  seed={seed}  {d.name} ===")
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):          # verify_chain prints its own report
            chains_ok = _vc.verify(str(red)) and _vc.verify(str(tele))
        fl = rvf.reverify(str(red))
        resolve, markers, crown = _resolver_and_markers(seed)
        rec = live_truth.reconcile(str(red), str(tele), resolve=resolve, crown_markers=markers)
        R = [json.loads(x) for x in red.read_text().splitlines() if x.strip()]
        claimed = next((e["data"]["achieved"] for e in R if e.get("action") == "duel.outcome"), None)
        verdict = _lar._corroborated_objective(claimed, rec)
        print(f"  hash chains verified : {chains_ok}")
        print(f"  floor (cold)         : chain_verified={fl['chain_verified']} oos_executed={fl['oos_executed']}")
        print(f"  reconcile (amended)  : checkable={rec['checkable']} corroborated={rec['corroborated']} "
              f"flagged={rec['flagged']}")
        for rp in rec["reports"]:
            print(f"      {rp['claim']:9s} {str(rp['dst']):14s} corroborated={rp['corroborated']}")
        print(f"  duel.outcome.achieved (red self-report) = {claimed}")
        print(f"  duel.verdict.achieved (telemetry-gated) = {verdict['achieved']}  "
              f"(loot_corroborated={verdict['loot_corroborated']})")
        ok_all = ok_all and chains_ok and fl["chain_verified"] and fl["oos_executed"] == 0
    print(f"\nre-derivation {'OK' if ok_all else 'FAILED'} (chains verified; floor cold on both runs)")
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
