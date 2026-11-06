"""Cold re-derivation of the MSF-session + harvested-cred clean run (paid seed, 2026-10-28).

No Docker, no API. Verifies both hash chains, re-derives the floor cold (oos_executed==0), re-runs
the amended reconciler (resolver + crown filename regenerated from the committed seed), and prints
the telemetry-gated verdict and the foothold modality (a real MSF session, not the out-of-band
channel). Run:  .venv/bin/python docs/runs/2026-10-28-msf-session-and-harvest-clean/rederive.py
"""
import io
import contextlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "redteam"))
from swarm import topo_to_compose as T, live_truth          # noqa: E402
import reverify_floor as rvf                                 # noqa: E402
import importlib.util                                        # noqa: E402

_spec = importlib.util.spec_from_file_location("lar", ROOT / "scripts" / "live_arms_race_run.py")
_lar = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_lar)
_vspec = importlib.util.spec_from_file_location("vc", ROOT / "scripts" / "verify_chain.py")
_vc = importlib.util.module_from_spec(_vspec); _vspec.loader.exec_module(_vc)

HERE = Path(__file__).resolve().parent
red = HERE / "episode01_seed1337.jsonl"
tele = HERE / "episode01_seed1337_telemetry.jsonl"
seed = (json.loads((HERE / "series.json").read_text()).get("series") or [{}])[0].get("seed", 1337)

topo, gt = T.generate_unified(seed); facts = T.unified_facts(topo, gt)
_, ip_by_host = T.plan_ips(topo, facts)
ip2name = {ip: n for n, nets in ip_by_host.items() for ip in nets.values()}
cf = next((f for f in facts["flags"] if f["host"] == (gt.get("crown") or {}).get("data")), None)
markers = [".crown", "crown jewel"] + ([Path(cf["dst_path"]).name.lower()] if cf else [])

with contextlib.redirect_stdout(io.StringIO()):
    chains_ok = _vc.verify(str(red)) and _vc.verify(str(tele))
fl = rvf.reverify(str(red))
rec = live_truth.reconcile(str(red), str(tele), resolve=lambda d: ip2name.get(d, d), crown_markers=markers)
R = [json.loads(x) for x in red.read_text().splitlines() if x.strip()]
claimed = next((e["data"]["achieved"] for e in R if e.get("action") == "duel.outcome"), None)
verdict = _lar._corroborated_objective(claimed, rec)
foot = next((e["data"] for e in R if e.get("action") == "confirm"
             and (e.get("data") or {}).get("confirms") == "foothold"), {})

print(f"seed={seed}  chains_verified={chains_ok}")
print(f"floor (cold): chain_verified={fl['chain_verified']} oos_executed={fl['oos_executed']}")
print(f"foothold modality: {foot.get('method')}  (session_id={foot.get('session_id')})")
print(f"reconcile (amended): checkable={rec['checkable']} corroborated={rec['corroborated']} flagged={rec['flagged']}")
for rp in rec["reports"]:
    print(f"   {rp['claim']:9s} {str(rp['dst']):14s} corroborated={rp['corroborated']}")
print(f"duel.verdict.achieved (telemetry-gated) = {verdict['achieved']}  (loot_corroborated={verdict['loot_corroborated']})")
ok = chains_ok and fl["chain_verified"] and fl["oos_executed"] == 0
print(f"\nre-derivation {'OK' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
