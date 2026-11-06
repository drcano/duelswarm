"""Stealth vs detection — the contest is REAL, not rigged (dry, FREE; 2026-10-27).

Rationale: docs/design-log/2026-10-27-stealth-vs-detection-benign-baseline.md and
CC-brief-stealth-detection.md. The loud-entry contest is a foregone conclusion (blue alerts on the
only traffic on an empty network). The real contest needs three pieces TOGETHER:
  1. a BENIGN BASELINE to hide inside (swarm.benign_baseline),
  2. a QUIET RED (assumed-breach valid-cred entry, lateral by valid logins, still map-blind),
  3. a DISCRIMINATING BLUE (no alert on a login's presence; it discriminates by the login graph,
     carries a false-positive cost).

This proves — on re-derivable hash chains, with ONE engine (run_interleaved_duel) and the
instrument untouched — that BOTH outcomes are reachable, the difference being detector EFFICACY
(does red's path ride a legitimate edge?), NOT a tuned threshold:
  - STEALTH WINS: red's lateral rides a BASELINE edge (living-off-the-land); blue's graph detector
    is blind to it; red reaches db-core and exfils the crown.
  - DETECTION WINS: red's lateral is a NOVEL edge; blue flags the anomaly and contains before exfil.
  - FALSE-POSITIVE SANITY: on a benign-only run blue does NOT contain benign hosts (and the FP
    mechanism is real — a too-short baseline turns a rare benign edge novel, recorded as damage).

Blue and its threshold are IDENTICAL across the stealth/detection configs — only red's path differs.

    .venv/bin/python scripts/prove_stealth_detection.py --selftest   # offline, dry (free)
"""
import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))

from swarm.eventlog import EventLog
from swarm.gate import Gate
from swarm.live_blue_agent import run_interleaved_duel, LoginGraphDiscriminator
from swarm import benign_baseline
from swarm.llm import UsageCounter


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── a QUIET, map-blind red over a fake world (assumed-breach foothold; valid-login lateral) ──────
def _quiet_red(world):
    """Assumed breach: red already holds a valid credential for its foothold (initial access
    achieved off-camera by phishing/prior compromise — NO loud Struts fault). It is still MAP-BLIND:
    it holds a cred, not the crown location/graph/scope. Its plan: authenticate the held foothold
    (valid login), scan for reachable hosts, pivot to the data host by VALID LOGIN (T1021), exfil.
    The LLM-free scripted stub stands in for the paid seat; the tradecraft (which path) is the only
    thing that differs between the stealth and detection configs."""
    class _R:
        usage = UsageCounter()
        def model_for(self, r): return "nano", "test/quiet-red"
        def chat(self, role, messages, **kw):
            w = world   # assumed breach: red already OWNS its foothold (initial access off-camera)
            if not w["scanned"]:
                w["scanned"] = True
                return json.dumps({"thought": "look around from the foothold", "tool": "scan",
                                   "args": {"from": w["foothold"]}})
            if "db-core" not in w["owned"] and "db-core" not in w["pivot_tried"]:
                w["pivot_tried"].add("db-core")
                return json.dumps({"thought": "move to the data host with a valid login",
                                   "tool": "pivot", "args": {"frm": w["foothold"], "to": "db-core"}})
            if "db-core" in w["owned"] and not w["located"]:
                return json.dumps({"thought": "fingerprint the host to locate the customer records",
                                   "tool": "fingerprint", "args": {"host": "db-core"}})
            if "db-core" in w["owned"] and not w["looted"] and "db-core" not in w["loot_tried"]:
                w["loot_tried"].add("db-core")
                return json.dumps({"thought": "read and exfiltrate the customer records",
                                   "tool": "loot", "args": {"host": "db-core"}})
            return json.dumps({"thought": "nothing more to do", "tool": "done", "args": {}})
    return _R()


def _idle_red(world):
    """The benign-only control's 'red': it never moves on the target — it only looks around for a
    while (no pivot to db-core, no anomalous edge), so the benign baseline flows across many ticks
    with NO attacker edge. Lets us measure whether blue false-positives on benign logins."""
    class _R:
        usage = UsageCounter()
        def model_for(self, r): return "nano", "test/idle-red"
        def chat(self, role, messages, **kw):
            w = world
            w["looks"] = w.get("looks", 0) + 1
            if w["looks"] <= w["idle_turns"]:
                return json.dumps({"thought": "scan quietly", "tool": "scan", "args": {"from": "self"}})
            return json.dumps({"thought": "done", "tool": "done", "args": {}})
    return _R()


def _red_tools(world):
    def t_scan(**k):
        return {"hosts": [{"ip": "db-core"}, {"ip": "cache"}]}
    def t_pivot(frm=None, to=None, **k):
        if (frm or world["foothold"]) in world["contained"] or world["foothold"] in world["contained"]:
            return {"owned": False, "host": None, "blocked": True}
        world["owned"].add(to); return {"owned": True, "host": to, "from": frm}
    def t_fingerprint(host=None, **k):
        # the map-blind locate-before-exfil DWELL on an owned host (red's own action); if the host was
        # cut off since the pivot, it fails — blue's containment landed.
        if host in world["contained"] or host not in world["owned"]:
            return {"located": False, "host": host, "blocked": True}
        world["located"] = True
        return {"located": True, "host": host, "records": "customer PII table"}
    def t_loot(host=None, **k):
        if (world["foothold"] in world["contained"] or host in world["contained"]
                or host not in world["owned"] or not world["located"]):
            return {"looted": False, "host": host}
        world["looted"].append(host); return {"looted": True, "host": host}
    return {"scan": t_scan, "pivot": t_pivot, "fingerprint": t_fingerprint, "loot": t_loot}


def _telemetry_window(world):
    """Red's REAL telemetry, one window at a time. Quiet entry emits NOTHING (initial access already
    achieved). The ONLY red telemetry is the LATERAL login onto db-core — a T1021 'Accepted password'
    line carrying the login-graph edge (foothold -> db-core). Exfil over the established session
    leaves no new auth line, so it is NOT detectable — blue must catch the anomalous edge or miss."""
    sent = set()
    def _w():
        out = []
        if "db-core" in world["owned"] and "lateral" not in sent:
            sent.add("lateral")
            out.append({"stage": "lateral_movement", "technique": "T1021", "target": "db-core",
                        "source": world["foothold"], "p_fire": 0.80, "confirmed": True,
                        "basis": "real-telemetry[host]: SSH lateral movement (accepted auth)",
                        "source_line": f"Accepted password for dbadmin from 10.9.0.5 port 22 ssh2"})
        return out
    return _w


def _trained_discriminator(seed):
    """Blue's login-graph model, LEARNED from the benign WARMUP (label-free — the warmup period
    simply has no red), then FROZEN for the contest."""
    disc = LoginGraphDiscriminator()
    wu = benign_baseline.warmup_schedule(seed)
    for e in [x for x in wu if x["kind"] == "login"]:
        disc.observe({"source": e["src"], "target": e["dst"], "technique": "T1021"})
    return disc.freeze()


def _run(foothold, *, seed, red=_quiet_red, discriminator=True, idle_turns=0):
    """One dry interleaved duel with the benign baseline on. `foothold` sets red's starting host
    (which fixes whether its lateral onto db-core is a baseline or a novel edge). Returns
    (result, world, chain_events, path)."""
    world = {"foothold": foothold, "owned": {foothold}, "contained": set(), "looted": [],
             "foothold_up": False, "scanned": False, "pivot_tried": set(), "loot_tried": set(), "located": False,
             "idle_turns": idle_turns}
    pth = Path(tempfile.mktemp(suffix=".jsonl"))
    lg = EventLog(pth)
    # scope: red's own two hosts + every benign host (so blue CAN act on a benign host — which is how
    # a false positive is even possible; the gate still records any out-of-scope attempt).
    hosts = sorted({foothold, "db-core", "cache"} | benign_baseline.benign_hosts())
    red_scope = [foothold, "db-core", "cache"]
    gate = Gate([], lg, scope_by_actor={"red": red_scope, "blue": hosts})
    # Declare the rules of engagement into the chain so the floor can RE-DERIVE oos per actor cold
    # (red's authorized universe is its own hosts; blue is granted reach across the benign hosts it
    # may have to contain). Mirrors the live runner's `roe` event.
    lg.append("system", "roe", {"in_scope": red_scope, "scope_by_actor": {"red": red_scope, "blue": hosts}})

    def _contain(c):
        host = c.replace("range-", "")
        world["contained"].add(host)
        return {"fidelity": "real", "contained": True, "method": "test isolate (route severed)"}

    sched = benign_baseline.benign_schedule(seed, n_ticks=40)
    disc = _trained_discriminator(seed) if discriminator else None
    res = run_interleaved_duel(
        lg, gate, red_router=red(world), red_tools=_red_tools(world),
        start_subnet="10.9.0.0/24", telemetry_window=_telemetry_window(world),
        objective="data_theft", max_turns=12, contain_fn=_contain,
        benign_window=benign_baseline.benign_window(sched), discriminator=disc,
        benign_hosts=benign_baseline.benign_hosts())
    chain = [json.loads(x) for x in pth.read_text().splitlines() if x.strip()]
    return res, world, chain, pth


def _floor_cold(path):
    rf = _load("_reverify_floor", "redteam/reverify_floor.py")
    return rf.reverify(str(path))


def _selftest():
    from swarm import live_agent
    SEED = 1337

    # RED MAP-BLIND: the quiet-red seat is intent-aware (data_theft) but is handed NO ground truth —
    # not the crown host (db-core), not the login graph, not the legitimate path it must find to
    # blend. assert_red_map_blind re-derives red's exact seeded context and proves it leaks none of
    # it (the exact mirror of blue being LABEL-FREE, asserted on the chains below).
    gt = {"host_tier": {"db-core": "data", "backup": "mgmt", "db-bastion": "mgmt", "ws01": "fleet"},
          "crown_loot": {"host": "db-core", "user": "dbadmin", "path": "/var/lib/db/customers"},
          "credential_graph": [{"src": "backup", "dst": "db-core", "user": "svc_backup"}]}
    live_agent.assert_red_map_blind(objective="data_theft", ground_truth=gt,
                                    start_subnet="10.9.0.0/24")

    # sanity: the benign warmup covers every legitimate edge for this seed, so a benign contest login
    # is never (for this seed) a novel edge — isolating the HONEST FP source to baseline length.
    disc = _trained_discriminator(SEED)
    assert benign_baseline.benign_edges() <= disc.baseline, \
        ("warmup must cover the benign edges for the FP-sanity seed", benign_baseline.benign_edges() - disc.baseline)

    # ── STEALTH WINS: red's foothold is `backup`, whose edge to db-core is LEGITIMATE (baseline).
    #    Red rides it (living-off-the-land); blue's graph detector is blind; red exfils the crown.
    s_res, s_world, s_chain, s_path = _run("backup", seed=SEED)
    assert s_res["achieved"] and not s_res["prevented"], ("stealth: red should exfil", s_res["duel_outcome"])
    assert s_world["looted"] == ["db-core"], ("the crown must have egressed", s_world)
    assert not s_res["contained"], ("blue must not have contained — the edge was legitimate", s_res)
    # blue SAW the login (it is in the detection stream) but did NOT treat it as evidence (known edge)
    assert any(e["action"] == "blue.detect.bernoulli" and (e["data"] or {}).get("source") == "backup"
               for e in s_chain), "blue must have observed the backup->db-core login"
    assert s_res["belief"]["confidence"] < 0.70, ("a known-edge login is not evidence", s_res["belief"])

    # ── DETECTION WINS: SAME blue, SAME threshold — only red's foothold differs to `ws01`, whose
    #    edge to db-core is NOVEL. Blue flags the anomaly and contains before the exfil.
    d_res, d_world, d_chain, d_path = _run("ws01", seed=SEED)
    assert d_res["prevented"] and not d_res["achieved"], ("detection: blue should prevent", d_res["duel_outcome"])
    assert not d_world["looted"], ("the crown must NOT have egressed", d_world)
    assert "db-core" in d_res["contained"], ("blue must have contained the anomalous target", d_res)
    anom = [e for e in d_chain if e["action"] == "blue.detector"
            and (e["data"] or {}).get("anomalous_edges")]
    assert any(["ws01", "db-core"] in (e["data"]["anomalous_edges"]) for e in anom), \
        "blue must have logged the ws01->db-core novel edge as the anomaly"
    assert d_res["duel_outcome"]["tick_of_prevention"] is not None, d_res["duel_outcome"]

    # the difference is DETECTOR EFFICACY (red's path), not a tuned threshold: identical blue config
    assert not s_res["duel_outcome"]["false_positive"] and not d_res["duel_outcome"]["false_positive"], \
        "neither real-red config may contain a benign host"

    # ── FALSE-POSITIVE SANITY: benign-only (idle red, no anomalous edge) over many ticks. Blue must
    #    NOT contain a benign host, and belief must stay below the bar — it does not alert on logins.
    f_res, f_world, f_chain, f_path = _run("ws01", seed=SEED, red=_idle_red, idle_turns=10)
    assert not f_res["achieved"] and not f_res["contained"], ("benign-only: blue must stay its hand", f_res)
    assert f_res["duel_outcome"]["benign_contained"] == [], ("no benign host may be contained", f_res["duel_outcome"])
    assert f_res["belief"]["confidence"] < 0.70, ("benign logins must not cross the bar", f_res["belief"])
    n_benign_logins = sum(1 for e in f_chain if e["action"] == "blue.detect.bernoulli"
                          and (e["data"] or {}).get("technique") == "T1021")
    assert n_benign_logins >= 5, ("blue must actually have seen a volume of benign logins", n_benign_logins)

    # ── THE FP MECHANISM IS REAL (honest): with NO warmup, a benign edge is novel -> blue contains a
    #    BENIGN host -> recorded as damage. We do not tune this away; it is the measured FP cost.
    bare = LoginGraphDiscriminator().freeze()          # learned nothing -> every edge looks novel
    fp_world = {"foothold": "backup", "owned": {"backup"}, "contained": set(), "looted": [],
                "foothold_up": False, "scanned": False, "pivot_tried": set(), "loot_tried": set(), "located": False,
                "idle_turns": 10}
    fp_path = Path(tempfile.mktemp(suffix=".jsonl"))
    lg = EventLog(fp_path)
    hosts = sorted({"backup", "db-core", "cache"} | benign_baseline.benign_hosts())
    red_scope = ["backup", "db-core", "cache"]
    gate = Gate([], lg, scope_by_actor={"red": red_scope, "blue": hosts})
    lg.append("system", "roe", {"in_scope": red_scope, "scope_by_actor": {"red": red_scope, "blue": hosts}})
    def _c(c):
        h = c.replace("range-", ""); fp_world["contained"].add(h)
        return {"fidelity": "real", "contained": True, "method": "test isolate"}
    sched = benign_baseline.benign_schedule(SEED, n_ticks=40)
    fp_res = run_interleaved_duel(
        lg, gate, red_router=_idle_red(fp_world), red_tools=_red_tools(fp_world),
        start_subnet="10.9.0.0/24", telemetry_window=_telemetry_window(fp_world),
        objective="data_theft", max_turns=12, contain_fn=_c,
        benign_window=benign_baseline.benign_window(sched),
        discriminator=bare, benign_hosts=benign_baseline.benign_hosts())
    assert fp_res["duel_outcome"]["false_positive"], \
        ("with no baseline, blue SHOULD false-positive — the FP cost is real", fp_res["duel_outcome"])
    assert fp_res["duel_outcome"]["benign_contained"], fp_res["duel_outcome"]

    # ── INVARIANTS on every chain: floor re-derives cold (oos=0, chain verified); three streams
    #    present (red moves, blue belief, duel.outcome); the benign labels never entered blue's view.
    for label, path, chain in (("stealth", s_path, s_chain), ("detection", d_path, d_chain),
                               ("benign-only", f_path, f_chain), ("fp-demo", fp_path, None)):
        fl = _floor_cold(path)
        assert fl["chain_verified"] and fl["oos_executed"] == 0, (label, "floor breached", fl)
        ch = chain if chain is not None else [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
        assert any(e["action"] == "move.source" and e.get("actor") == "red" for e in ch), (label, "no red stream")
        assert any(e["action"] == "blue.belief" for e in ch), (label, "no blue belief stream")
        assert any(e["action"] == "duel.outcome" for e in ch), (label, "no duel.outcome")
        # label-free: no benign/malicious label ever appears in a blue detection beat
        for e in ch:
            if e["action"] in ("blue.detect.bernoulli", "blue.belief", "blue.detector"):
                d = e["data"] or {}
                assert not any(k in d for k in ("benign", "malicious", "is_red")), (label, "benign label leaked", e)
        path.unlink(missing_ok=True)

    print("prove_stealth_detection selftest ok (the stealth contest is REAL, not rigged: ONE engine, "
          "instrument untouched. STEALTH WINS — red's lateral rides a LEGITIMATE edge (backup->db-core, "
          "living-off-the-land), blue's login-graph detector is blind, the crown egresses. DETECTION "
          "WINS — SAME blue + SAME threshold, red's foothold is `ws01` so its lateral is a NOVEL edge; "
          "blue flags the anomaly and contains before exfil. The difference is DETECTOR EFFICACY "
          "(red's path), not a tuned threshold. FP SANITY — on a benign-only run blue contains NO "
          "benign host and belief stays below the bar (it does not alert on a login's presence), yet "
          "the FP cost is REAL: with no baseline a benign edge is novel and blue contains a benign "
          "host (recorded as damage, not tuned away). Red MAP-BLIND, blue LABEL-FREE; three streams "
          "on each chain; floor re-derives oos=0 + chain verified COLD on all four)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.parse_args()
    sys.exit(_selftest())
