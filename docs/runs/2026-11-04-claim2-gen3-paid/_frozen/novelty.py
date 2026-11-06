"""Emergent TTP scoring — measured against the generator's own ground truth (frontier F1).

The range generator (swarm/range_gen.py) emits, per seed, the *intended* playbook:
the pivot topology (`topology_edges`) and the objective technique
(`objective_attack_id`) plus each host's known `attack_id`. That is the baseline —
what a scripted attacker following the seeded plan would do.

`score_novelty` reads what red ACTUALLY did from the hash-chained log and reports
where it diverged: pivot edges not in the intended graph (`novel_edges`) and
objective-reach routes / orderings not in the intended plan (`novel_combos`). It is
a measurement, never an assertion: some seeds yield zero novelty, and we report the
zero. The result is emitted as a `("system","novelty",…)` event so every number on
the dashboard is replayable from the log.

ponytail: edges are reconstructed from the gate.allow spine (the authoritative
"red acted on host X" record) + the range's ground truth — no second source of truth.
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))  # runnable as script or -m

# Red actions that constitute "reaching" the crown-jewel objective.
_OBJECTIVE_ACTIONS = {"db_exploit", "enumerate_db"}
# Red actions that constitute lateral movement to a new host.
_LATERAL_ACTIONS = {"pivot", "lateral_movement"}


def _red_gate_allows(entries):
    """(seq, target) for each authorized red action, in order — the edge spine."""
    out = []
    for e in entries:
        if e.get("action") == "gate.allow" and e.get("actor") == "red":
            d = e.get("data", {})
            tgt = d.get("resolved") or d.get("target")
            if tgt:
                out.append((e.get("seq"), tgt))
    return out


def score_novelty(entries, ground_truth, pool=None):
    """Compare red's realized attack to the seed's intended playbook.

    Returns {novel_edges, novel_combos, emergence_score, baseline, realized_edges,
    headline, events}. `events` is a list of ("system","novelty",data) to append.
    """
    gt = ground_truth or {}
    in_scope = list(gt.get("in_scope") or [])
    out_scope = list(gt.get("out_of_scope") or [])
    hosts_known = set(in_scope) | set(out_scope)
    entry = in_scope[0] if in_scope else (gt.get("entry") or "struts")
    crown = gt.get("crown_jewel_host") or gt.get("objective_host")
    obj_attack = gt.get("objective_attack_id")

    intended_edges = {tuple(e) for e in (gt.get("topology_edges") or [])}
    intended_dsts = {b for _, b in intended_edges}

    # Realized pivot edges: red operates from the entry foothold, so each authorized
    # action on another known host is an (entry -> host) traversal. First touch only.
    allows = _red_gate_allows(entries)
    realized_edges, seen = [], set()
    for _seq, tgt in allows:
        if tgt == entry or tgt not in hosts_known:
            continue
        edge = (entry, tgt)
        if edge not in seen:
            seen.add(edge)
            realized_edges.append(edge)

    # A novel edge: a traversal the generator's intended topology did not plan.
    novel_edges = [list(edge) for edge in realized_edges if edge not in intended_edges]

    # Technique set/order red actually used (from the red action events).
    realized_techs = [e.get("data", {}).get("attack") for e in entries
                      if e.get("actor") == "red" and e.get("data", {}).get("attack")]

    # Baseline playbook techniques: the seeded objective + every pool host's known id.
    baseline_techs = {obj_attack} if obj_attack else set()
    baseline_techs.add("T1190")  # the entry exploit is always the seeded anchor
    if pool:
        for section in ("entry", "in_scope_pool", "out_scope_pool"):
            sec = pool.get(section)
            for h in ([sec] if isinstance(sec, dict) else (sec or [])):
                if h.get("attack_id"):
                    baseline_techs.add(h["attack_id"])
    baseline_techs.discard(None)

    novel_combos = []

    # (1) Unplanned objective route: the crown was reached via an edge the intended
    #     topology did not contain (e.g. a direct entry->crown when the plan routed
    #     through a pivot host first).
    if crown and (entry, crown) in set(realized_edges) and (entry, crown) not in intended_edges:
        novel_combos.append({"type": "unplanned_objective_route",
                             "detail": f"reached {crown} via an edge not in the seeded topology"})

    # (2) Objective before lateral movement: red hit the crown technique before any
    #     traversal to another host — an ordering the seeded plan (recon->pivot->crown)
    #     does not prescribe. Both are read from the gate.allow spine (the authoritative
    #     "red acted on host X" record) so this holds for real logs, where lateral
    #     movement appears as gate.allow(tool=pivot), not a bare "pivot" action event.
    def _first_obj(e):
        if e.get("actor") != "red":
            return False
        if e.get("action") in _OBJECTIVE_ACTIONS:
            return True
        d = e.get("data", {})
        return (e.get("action") == "gate.allow"
                and (d.get("tool") == "enumerate_db"
                     or ((d.get("resolved") or d.get("target")) == crown and crown)))

    def _first_lat(e):
        if e.get("actor") != "red":
            return False
        if e.get("action") in _LATERAL_ACTIONS:
            return True
        d = e.get("data", {})
        tgt = d.get("resolved") or d.get("target")
        return e.get("action") == "gate.allow" and tgt and tgt != entry and tgt in hosts_known

    first_obj = next((e.get("seq") for e in entries if _first_obj(e)), None)
    first_lat = next((e.get("seq") for e in entries if _first_lat(e)), None)
    if first_obj is not None and (first_lat is None or first_obj < first_lat):
        novel_combos.append({"type": "objective_before_lateral",
                             "detail": "crown-jewel technique executed before any lateral movement"})

    emergence_score = len(novel_edges) + len(novel_combos)

    if emergence_score == 0:
        headline = "Red followed the seeded playbook — no emergent TTPs this run."
    elif novel_edges:
        e0 = novel_edges[0]
        headline = (f"Red reached the objective via a route not in the seeded plan "
                    f"({e0[0]} -> {e0[1]}).")
    else:
        headline = f"Red deviated from the seeded plan: {novel_combos[0]['type']}."

    data = {"novel_edges": novel_edges, "novel_combos": novel_combos,
            "emergence_score": emergence_score, "baseline": "ground_truth",
            "realized_edges": [list(x) for x in realized_edges],
            "intended_edges": [list(x) for x in intended_edges],
            "headline": headline}
    return {**data, "events": [("system", "novelty", data)]}


def emit_novelty(log, ground_truth, pool=None):
    """Score the log in place and append the novelty event. Returns the result."""
    res = score_novelty(log.entries(), ground_truth, pool)
    for actor, action, data in res["events"]:
        log.append(actor, action, data)
    return res


if __name__ == "__main__":  # self-check: null (intended path) vs. emergent (unplanned pivot)
    gt = {"in_scope": ["struts", "db"], "out_of_scope": ["ldap"],
          "crown_jewel_host": "db", "objective_attack_id": "T1213",
          "topology_edges": [["struts", "db"]]}

    def ev(seq, actor, action, **data):
        return {"seq": seq, "actor": actor, "action": action, "data": data}

    # A: red follows the intended path struts -> db, pivots then hits the crown.
    entries_A = [
        ev(1, "red", "gate.allow", tool="recon", target="struts", attack="T1595"),
        ev(2, "red", "gate.allow", tool="exploit", target="struts", attack="T1190"),
        ev(3, "red", "pivot", target="db", attack="T1021"),
        ev(4, "red", "gate.allow", tool="pivot", target="db", attack="T1021"),
        ev(5, "red", "db_exploit", host="db", attack="T1213"),
        ev(6, "red", "gate.allow", tool="enumerate_db", target="db", attack="T1213"),
    ]
    rA = score_novelty(entries_A, gt)
    assert rA["emergence_score"] == 0, rA
    assert rA["novel_edges"] == [] and rA["novel_combos"] == [], rA
    assert "no emergent" in rA["headline"].lower(), rA["headline"]

    # B: red pivots via an UNPLANNED host (jenkins not in the intended topology).
    gtB = dict(gt, in_scope=["struts", "db", "jenkins"])
    entries_B = [
        ev(1, "red", "gate.allow", tool="exploit", target="struts", attack="T1190"),
        ev(2, "red", "pivot", target="jenkins", attack="T1021"),
        ev(3, "red", "gate.allow", tool="pivot", target="jenkins", attack="T1021"),
        ev(4, "red", "pivot", target="db", attack="T1021"),
        ev(5, "red", "gate.allow", tool="pivot", target="db", attack="T1021"),
        ev(6, "red", "gate.allow", tool="enumerate_db", target="db", attack="T1213"),
        ev(7, "red", "db_exploit", host="db", attack="T1213"),
    ]
    rB = score_novelty(entries_B, gtB)
    assert rB["emergence_score"] >= 1, rB
    assert ["struts", "jenkins"] in rB["novel_edges"], rB["novel_edges"]
    assert "not in the seeded plan" in rB["headline"], rB["headline"]

    # Honest-null is the default: an empty log yields score 0, not an error.
    rE = score_novelty([], gt)
    assert rE["emergence_score"] == 0 and rE["events"][0][1] == "novelty"

    # emit_novelty appends exactly one verifiable event and keeps the chain intact.
    import tempfile
    from eventlog import EventLog
    lg = EventLog(_Path(tempfile.mkdtemp()) / "e.jsonl")
    for e in entries_B:
        lg.append(e["actor"], e["action"], e["data"])
    before = len(lg.entries())
    res = emit_novelty(lg, gtB)
    assert len(lg.entries()) == before + 1
    assert lg.entries()[-1]["action"] == "novelty"
    ok, bad = lg.verify(); assert ok, bad
    print(f"novelty ok: null run score 0; unplanned pivot -> {rB['novel_edges']}, "
          f"score {rB['emergence_score']}; event emitted + chained")
