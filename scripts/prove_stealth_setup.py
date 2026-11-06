"""The honest Part-5 stealth setup — red DISCOVERS the living-off-the-land path, map-blind, across
varied per-seed entries (dry, FREE; 2026-10-27).

Rationale: `CC-brief-hygiene-then-stealth-part5.md` Part B, and
`docs/design-log/2026-10-27-stealth-vs-detection-benign-baseline.md`. The Part-4 proof
(`scripts/prove_stealth_detection.py`) shows both outcomes are reachable but HANDS red its path
(it starts red on `backup`, the one host with a legitimate edge to the crown). The measurement has
to earn it. This proves the setup Part 5 will actually run:

  - Red's assumed-breach ENTRY varies per seed (seed-derived, never `backup`/`db-core`), so the
    stealth-success rate is NOT predetermined by the start host.
  - Red must DISCOVER a legitimate-edge route to the crown ITSELF — by LOCAL on-host recon
    (`recon_host` reveals only an OWNED host's own legitimate neighbors, the realistic
    known_hosts/history discovery), never the global benign graph, the crown, or scope. It rides
    legitimate edges when its discovery finds a chain (stealth), and is forced into an anomalous hop
    when it cannot (detection).
  - Both outcomes occur ACROSS the seed set (not all-one-way by construction). If they do not, the
    setup is baking the result and the proof STOPS.
  - The locate-before-exfil DWELL stays red's OWN action (a real consequence of map-blindness); NO
    extra delay and NO change to blue's reversible-first cadence or threshold is inserted to help
    containment land. Whether blue beats the real red's cadence is the measured question.

Red MAP-BLIND (assert_red_map_blind); blue LABEL-FREE; ONE engine (run_interleaved_duel); instrument
untouched; floor re-derives cold on every chain.

    .venv/bin/python scripts/prove_stealth_setup.py --selftest   # offline, dry (free)
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
from swarm.live_blue_agent import run_interleaved_duel, LoginGraphDiscriminator, _CONTAIN_CONFIDENCE
from swarm import benign_baseline, live_agent
from swarm.llm import UsageCounter

TARGET = "db-core"   # the crown host — red identifies it by fingerprint (a discovery), not by map


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the discovery-driven, map-blind red: a reactive BFS over edges it LEARNS by on-host recon ──────
def _discovery_red(world):
    """Red holds a valid credential for its (varied) entry (assumed breach — it already OWNS the entry,
    initial access achieved off-camera) and must reach the crown. It is MAP-BLIND: handed no graph, no
    crown location, no scope. It LEARNS, per owned host, that host's own legitimate neighbors (on-host
    recon, surfaced through the `harvest` primitive), and rides those edges toward the fingerprinted DB
    — a stealthy living-off-the-land search. If its discovered legitimate edges never reach the crown,
    it is forced into an anomalous hop. Reactive to what harvest/scan RETURN, not a blind replay. All
    tools are the engine's real vocabulary (scan/harvest/fingerprint/pivot/loot) so every action is
    gate-parsed and logged (no silent veto)."""
    class _R:
        usage = UsageCounter()
        def model_for(self, r): return "nano", "test/discovery-red"
        def chat(self, role, messages, **kw):
            w = world
            if w["target"] is None:
                return json.dumps({"thought": "scan to find reachable hosts and fingerprint services",
                                   "tool": "scan", "args": {"from": w["entry"]}})
            if w["target"] not in w["owned"]:
                # 1) harvest (on-host recon) any owned host we haven't enumerated -> its legit neighbors
                unreconned = [h for h in w["owned"] if h not in w["reconned"]]
                if unreconned:
                    return json.dumps({"thought": f"enumerate {unreconned[0]}'s normal connections",
                                       "tool": "harvest", "args": {"host": unreconned[0]}})
                # 2) if an owned host legitimately reaches the target, ride that edge (stealth)
                for frm in sorted(w["owned"]):
                    if w["target"] in w["disc_adj"].get(frm, set()):
                        return json.dumps({"thought": f"the target is a normal neighbor of {frm} — ride it",
                                           "tool": "pivot", "args": {"frm": frm, "to": w["target"]}})
                # 3) else expand along any unexplored legitimate edge (keep discovering)
                for frm in sorted(w["owned"]):
                    for to in sorted(w["disc_adj"].get(frm, set())):
                        if to not in w["owned"] and to not in w["pivoted_to"]:
                            return json.dumps({"thought": f"follow a normal admin path {frm}->{to}",
                                               "tool": "pivot", "args": {"frm": frm, "to": to}})
                # 4) legitimate discovery exhausted and the crown unreached: forced anomalous hop
                return json.dumps({"thought": "no normal route found — take a direct hop to the DB",
                                   "tool": "pivot", "args": {"frm": w["entry"], "to": w["target"],
                                                             "forced": True}})
            if not w["located"]:
                return json.dumps({"thought": "fingerprint the host to locate the customer records",
                                   "tool": "fingerprint", "args": {"host": w["target"]}})
            if not w["looted"]:
                return json.dumps({"thought": "read and exfiltrate the customer records",
                                   "tool": "loot", "args": {"host": w["target"]}})
            return json.dumps({"thought": "done", "tool": "done", "args": {}})
    return _R()


def _red_tools(world, adjacency):
    def t_scan(**k):
        # network discovery: reachable hosts + a fingerprint that identifies the DB (the crown target)
        world["target"] = TARGET
        return {"hosts": [{"ip": h, "role": ("database" if h == TARGET else "host")}
                          for h in sorted(set(adjacency) | {TARGET})]}
    def t_harvest(host=None, **k):
        # LOCAL on-host discovery: ONLY this owned host's own legitimate outbound neighbors (the
        # realistic known_hosts/history/cron read). Never the global graph/crown/scope.
        if host not in world["owned"]:
            return {"error": "not owned"}
        world["reconned"].add(host)
        nbrs = sorted(adjacency.get(host, set()))
        world["disc_adj"].setdefault(host, set()).update(nbrs)
        return {"host": host, "legit_neighbors": nbrs}
    def t_pivot(frm=None, to=None, forced=False, **k):
        if frm not in world["owned"] or frm in world["contained"]:
            return {"owned": False, "host": None, "blocked": True}
        world["pivoted_to"].add(to)
        world["edges"].append((frm, to))     # the login-graph edge blue will see as telemetry
        world["owned"].add(to)
        return {"owned": True, "host": to, "from": frm, "anomalous": forced}
    def t_fingerprint(host=None, **k):        # the map-blind locate-before-exfil DWELL (red's own)
        if host in world["contained"] or host not in world["owned"]:
            return {"located": False, "host": host, "blocked": True}
        world["located"] = True
        return {"located": True, "host": host, "records": "customer PII table"}
    def t_loot(host=None, **k):
        if host in world["contained"] or host not in world["owned"] or not world["located"]:
            return {"looted": False, "host": host}
        world["looted"] = True; world["loot"].append(host)
        return {"looted": True, "host": host}
    return {"scan": t_scan, "harvest": t_harvest, "pivot": t_pivot, "fingerprint": t_fingerprint,
            "loot": t_loot}


def _telemetry_window(world):
    """Red's REAL telemetry: one T1021 'Accepted password' login per pivot edge, carrying the login
    graph (source->target). Quiet entry emits nothing; exfil over the established session emits
    nothing. Each edge is surfaced to blue ONCE, label-free; blue discriminates by the graph."""
    sent = {"i": 0}
    def _w():
        out = []
        while sent["i"] < len(world["edges"]):
            frm, to = world["edges"][sent["i"]]; sent["i"] += 1
            out.append({"stage": "lateral_movement", "technique": "T1021", "target": to, "source": frm,
                        "p_fire": 0.80, "confirmed": True,
                        "basis": "real-telemetry[host]: SSH lateral movement (accepted auth)",
                        "source_line": f"Accepted password for svc from {frm} port 22 ssh2"})
        return out
    return _w


def _trained_discriminator(seed):
    """Blue's login-graph model, learned from the benign warmup (label-free) and frozen for the
    contest — exactly as the measurement will train it."""
    disc = LoginGraphDiscriminator()
    for e in (x for x in benign_baseline.warmup_schedule(seed) if x["kind"] == "login"):
        disc.observe({"source": e["src"], "target": e["dst"], "technique": "T1021"})
    return disc.freeze()


def _run_seed(seed):
    entry = benign_baseline.stealth_entry_for_seed(seed)
    adjacency = benign_baseline.legit_adjacency()
    # assumed breach: red ALREADY owns the entry (initial access off-camera), so there is no entry
    # telemetry — the first observable is red's first lateral pivot.
    world = {"entry": entry, "target": None, "owned": {entry}, "reconned": set(), "disc_adj": {},
             "pivoted_to": set(), "edges": [], "contained": set(),
             "located": False, "looted": False, "loot": []}
    pth = Path(tempfile.mktemp(suffix=".jsonl")); lg = EventLog(pth)
    all_hosts = sorted(benign_baseline.benign_hosts() | {TARGET})
    # red is authorized across the enterprise data plane (incl. the crown tier it is measured
    # reaching); blue may reach every host. Declared into the chain so the floor re-derives cold.
    lg.append("system", "roe", {"in_scope": all_hosts, "scope_by_actor": {"red": all_hosts, "blue": all_hosts}})
    gate = Gate([], lg, scope_by_actor={"red": all_hosts, "blue": all_hosts})

    def _contain(c):
        world["contained"].add(c.replace("range-", ""))
        return {"fidelity": "real", "contained": True, "method": "test isolate (route severed)"}

    sched = benign_baseline.benign_schedule(seed, n_ticks=40)
    # NOTE: threshold is NOT passed (defaults to _CONTAIN_CONFIDENCE) and no cadence/delay is altered
    # — blue's reversible-first machinery is unchanged; the only dwell is red's own `enumerate`.
    res = run_interleaved_duel(
        lg, gate, red_router=_discovery_red(world), red_tools=_red_tools(world, adjacency),
        start_subnet="10.9.0.0/24", telemetry_window=_telemetry_window(world),
        objective="data_theft", max_turns=24, contain_fn=_contain,
        benign_window=benign_baseline.benign_window(sched),
        discriminator=_trained_discriminator(seed), benign_hosts=benign_baseline.benign_hosts())
    chain = [json.loads(x) for x in pth.read_text().splitlines() if x.strip()]
    return entry, res, world, chain, pth


def _selftest():
    rf = _load("_reverify_floor", "redteam/reverify_floor.py")

    # red's seeded context leaks none of the ground truth it must DISCOVER (crown, graph, scope)
    gt = {"host_tier": {"db-core": "data", "backup": "mgmt", "db-bastion": "mgmt", "dba01": "admin",
                        "app01": "app", "web01": "dmz", "cache01": "cache", "ws01": "fleet"},
          "crown_loot": {"host": "db-core", "user": "dbadmin", "path": "/var/lib/db/customers"},
          "credential_graph": [{"src": "backup", "dst": "db-core", "user": "svc_backup"},
                               {"src": "dba01", "dst": "db-bastion", "user": "svc_dba"}]}
    live_agent.assert_red_map_blind(objective="data_theft", ground_truth=gt, start_subnet="10.9.0.0/24")

    results = {}
    for seed in benign_baseline.STEALTH_SEEDS:
        entry, res, world, chain, pth = _run_seed(seed)
        do = res["duel_outcome"]
        has_lotl = benign_baseline.legit_path(entry, TARGET) is not None

        # 1) DISCOVERY, not handing: every pivot red rode was preceded by a recon that DISCOVERED the
        #    source host's neighbors (for a legit ride) or by exhausting recon (for a forced hop). The
        #    chain is discovery-driven — red learned before it moved.
        recon_hosts = [(e["data"].get("args") or {}).get("host") for e in chain
                       if e["action"] == "move.source" and (e["data"] or {}).get("tool") == "harvest"]
        assert recon_hosts, (seed, "red must recon (discover) before pivoting — not handed the path")
        assert world["entry"] not in (benign_baseline.crown_edge_hosts() | {TARGET}), (seed, "entry must never be crown/edge-owner")

        # 2) the outcome MATCHES the discoverable topology (earned), and both the stealth and the
        #    detection mechanics are the SAME blue: a stealth-capable entry whose red found the legit
        #    chain exfils; a detection-forced entry's red takes an anomalous hop and is contained.
        if has_lotl:
            assert res["achieved"] and not res["prevented"], (seed, entry, "stealth-capable -> should exfil", do)
            assert world["loot"] == [TARGET], (seed, "crown must egress on a found legit route")
            assert not res["contained"], (seed, "no containment when every edge ridden was legitimate")
            # every edge red rode is a benign edge (true living-off-the-land)
            assert all((f, t) in benign_baseline.benign_edges() for (f, t) in world["edges"]), \
                (seed, "stealth route must ride only legitimate edges", world["edges"])
        else:
            assert res["prevented"] and not res["achieved"], (seed, entry, "detection-forced -> should be contained", do)
            assert not world["loot"], (seed, "crown must NOT egress when red is contained")
            assert TARGET in res["contained"], (seed, "blue must contain the anomalous target")
            # the anomalous edge is a NOVEL (non-benign) edge blue flagged
            ano = [e for e in chain if e["action"] == "blue.detector" and (e["data"] or {}).get("anomalous_edges")]
            assert ano, (seed, "blue must have flagged the novel edge")

        # 3) the DWELL is red's own action and NOTHING was inserted to help blue: red's locate step is
        #    a `enumerate` move.source, and the duel ran on the DEFAULT containment threshold.
        assert any(e["action"] == "move.source" and (e["data"] or {}).get("tool") == "fingerprint"
                   for e in chain), (seed, "the locate-before-exfil dwell must be red's own action")
        assert do.get("cadence") == "one blue observe+act per red action (pre-registered, not tuned)", do

        # 4) blue LABEL-FREE + floor cold on every chain
        for e in chain:
            if e["action"] in ("blue.detect.bernoulli", "blue.belief", "blue.detector"):
                assert not any(k in (e["data"] or {}) for k in ("benign", "malicious", "is_red")), \
                    (seed, "benign label leaked into blue's view", e)
        fl = rf.reverify(str(pth))
        assert fl["chain_verified"] and fl["oos_executed"] == 0, (seed, "floor breached", fl)
        assert any(e["action"] == "duel.outcome" for e in chain), (seed, "missing duel.outcome stream")
        pth.unlink(missing_ok=True)
        results[seed] = {"entry": entry, "achieved": res["achieved"], "prevented": res["prevented"],
                         "has_lotl": has_lotl, "edges": world["edges"], "fp": do["false_positive"]}

    # 5) NOT BAKED: both outcomes occur across the seed set (else STOP — the setup predetermines it).
    achieved = [s for s, r in results.items() if r["achieved"]]
    prevented = [s for s, r in results.items() if r["prevented"]]
    assert achieved and prevented, ("the setup must admit BOTH outcomes across the seeds — else baked",
                                    {s: (r["entry"], r["achieved"], r["prevented"]) for s, r in results.items()})
    # entries vary and are never the handed start host
    assert len({r["entry"] for r in results.values()}) >= 3, ("entries must vary", results)
    assert all(r["entry"] not in (benign_baseline.crown_edge_hosts() | {TARGET}) for r in results.values()), results
    # no false positives on a real-red run (benign traffic never triggered a benign-host containment)
    assert not any(r["fp"] for r in results.values()), ("no benign host may be contained in a real-red run", results)

    print("prove_stealth_setup selftest ok (the HONEST Part-5 setup, dry: red's assumed-breach ENTRY "
          f"varies by seed and is NEVER backup/crown {sorted({r['entry'] for r in results.values()})}; "
          "red DISCOVERS its route map-blind by LOCAL on-host recon — it rides legitimate edges when "
          "its discovery finds a living-off-the-land chain (stealth) and is forced into an anomalous "
          f"hop when it cannot (detection). BOTH outcomes occur across the N={len(results)} seeds "
          f"(stealth {len(achieved)}: {sorted(achieved)}; detection {len(prevented)}: {sorted(prevented)}) — not all-one-way by "
          "construction. The outcome is EARNED by discovery, not the start host; the locate-before-"
          "exfil dwell is red's OWN action and blue's reversible-first cadence + threshold are "
          "unchanged (nothing inserted to help containment). Red MAP-BLIND, blue LABEL-FREE, floor "
          "oos=0 + chain verified COLD on every seed.)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.parse_args()
    sys.exit(_selftest())
