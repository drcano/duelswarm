"""Environment co-evolution — UED coupled to the real populations (Brick 5,
DUELSWARM_LIQUID_SPEC §5.4/§9).

`swarm.range_adversary` proposes ranges at the PAIRED-regret frontier, but scores them
with a MODELLED solver (its own docstring: "in a live driver, replace with K real
duels"). Brick 5 is that replacement: the Minimal-Criterion-Coevolution gate runs the
REAL Brick-1 red and Brick-2 blue against each generated world, and the curriculum tracks
the populations' accumulating skill (blue's memory) so difficulty ratchets over time.

The MCC gate is grounded, not vacuous: red "progresses" only when the crown is genuinely
reachable in the substrate (netmodel.reachable, attacker→crown via a pivot) AND the real
objective-blind red reaches it; blue "defends" only when the real fast tier detects AND
contains. A world whose real segmented substrate/reachability does not hold ("can't be
booted") does not count. The floor holds every generation.

Populations here are the deterministic Brick 1–4 agents; the LLM populations and the
pyribs Quality-Diversity archive are Brick 6 / live.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/env_coevo.py`

from swarm import netmodel, coevolve, spine
from swarm.topo_to_compose import to_compose, emit_range_topology, load_pool
from swarm.live_red import run_sim_red
from swarm.gate import Gate
from swarm.eventlog import EventLog
from swarm.range_adversary import propose_candidates


def is_real_substrate(r):
    """A world counts only if it is real substrate (§4): its segmented compose builds and
    the crown is reachable from the attacker via a pivot (a front-door crown is trivially
    reachable). An unbootable / unreachable world does not count."""
    try:
        to_compose(r)
        net, ip = netmodel.plan_network(r)
        crown, entry = r["objective"]["host"], r["entry"]
        if crown == entry:
            return True
        return net.reachable(ip["attacker"][0], ip[crown][0])
    except Exception:
        return False


def mcc_evaluate(r, blue_known, tmpdir=None):
    """Run ONE real duel on range `r`; return the MCC verdict + the frontier challenge."""
    if not is_real_substrate(r):
        return {"mcc": False, "real_substrate": False, "red_progress": False,
                "blue_defends": False, "novel_cves": [], "reason": "not-real-substrate",
                "path": None, "events": []}
    tmpdir = tmpdir or Path(tempfile.mkdtemp())
    path = tmpdir / f"mcc-{r['seed']}.jsonl"
    log = EventLog(path)
    log.append("system", "scope", {"in_scope": r["scope"]["in_scope"]})
    log.append("system", "roe", {"scope_by_actor": r["scope_by_actor"]})
    emit_range_topology(log, r)
    gate = Gate([], log, scope_by_actor=r["scope_by_actor"])
    red = run_sim_red(gate, log, r)                      # the ONE engine (dry/SIM fidelity)
    from swarm.live_blue_agent import run_blue_fight     # the ONE blue engine (dry router)
    out = run_blue_fight(log, gate)
    red_progress = bool(red["crown_reached"])
    blue_defends = bool(out["contained"])
    novel = [a["cve"] for a in coevolve.arsenal(r) if a["cve"] not in blue_known]
    return {"mcc": red_progress and blue_defends, "real_substrate": True,
            "red_progress": red_progress, "blue_defends": blue_defends,
            "novel_cves": novel, "reason": None, "path": str(path),
            "events": log.entries()}


def env_curriculum(pool=None, n_generations=4, n_candidates=6, start_seed=2_000_000):
    """UED/POET loop coupled to the real populations. Each generation proposes fresh
    worlds, gates them by real-agent MCC, keeps the one at the regret frontier (most
    techniques novel to the current blue), and lets the duel teach blue — so difficulty
    tracks skill. Emits range.* beats. Returns the generations + the curriculum chain."""
    pool = pool or load_pool()
    tmpdir = Path(tempfile.mkdtemp())
    clog = EventLog(tmpdir / "curriculum.jsonl")      # the curriculum's own hash chain
    blue_known, mastered, generations = set(), [], []

    for g in range(n_generations):
        cands = propose_candidates(n_candidates, pool, start_seed=start_seed + g * 1000)
        # UED over-produces: the generator also proposes an aggressive world with the
        # pivot graph severed (an unsolvable candidate). MCC's job is to filter it — a
        # real gate, not a rubber stamp. (A world that can't be booted does not count.)
        cands = cands + [_break_world(cands[0])]
        scored = []
        for r in cands:
            m = mcc_evaluate(r, blue_known, tmpdir=tmpdir)
            clog.append("range", "range.proposal", {"seed": r["seed"], "mcc": m["mcc"],
                        "novel": len(m["novel_cves"]), "real_substrate": m["real_substrate"]})
            if not m["mcc"]:
                clog.append("range", "range.reject", {"seed": r["seed"],
                            "reason": m["reason"] or "mcc-fail"})
                continue
            scored.append((r, m))
        if not scored:
            generations.append({"gen": g + 1, "picked": None, "mastered": len(mastered)})
            continue
        # regret frontier: the hardest-but-solvable world for the current skill = the
        # MCC-passing world introducing the most techniques novel to blue.
        r, m = max(scored, key=lambda t: (len(t[1]["novel_cves"]), -t[0]["seed"]))
        clog.append("range", "range.accept", {"seed": r["seed"], "novel": len(m["novel_cves"])})
        picked_cves = [a["cve"] for a in coevolve.arsenal(r)]
        newly = [c for c in picked_cves if c not in blue_known]
        blue_known |= set(picked_cves)                 # the duel taught blue -> skill rises
        for c in newly:
            if c not in mastered:
                mastered.append(c)
        clog.append("range", "range.curriculum", {"gen": g + 1, "picked": r["seed"],
                    "novel_introduced": len(newly), "mastered": len(mastered),
                    "difficulty": len(m["novel_cves"])})
        generations.append({"gen": g + 1, "picked": r["seed"],
                            "novel_introduced": len(newly), "difficulty": len(m["novel_cves"]),
                            "mastered": len(mastered), "mcc": True, "path": m["path"],
                            "events": m["events"]})
    return {"generations": generations, "mastered": mastered,
            "curriculum_events": clog.entries()}


def open_endedness(generations):
    """POET ANNECS-style: distinct challenges (CVEs/techniques) the populations have
    mastered, accumulating over generations. Monotone growth = the arms race keeps
    opening new ground (bounded by the finite pool registry)."""
    series = [g["mastered"] for g in generations if g.get("picked") is not None]
    monotone = all(series[i] <= series[i + 1] for i in range(len(series) - 1))
    return {"annecs": series[-1] if series else 0, "monotone_skill_growth": monotone,
            "mastered_series": series,
            "difficulty_series": [g["difficulty"] for g in generations if g.get("picked") is not None]}


def _break_world(r):
    """A deliberately UNBOOTABLE world: sever the pivot graph so the (internal) crown is
    unreachable from the attacker. Must FAIL MCC."""
    import copy
    b = copy.deepcopy(r)
    b["topology"]["edges"] = []      # no host bridges the attacker side to the internal crown
    return b


if __name__ == "__main__":  # self-check: MCC real (gate rejects), skill ratchets, floor=0
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "redteam"))
    import reverify_floor as rvf
    from swarm.topo_to_compose import generate_range

    pool = load_pool()

    # MCC is REAL: a well-formed world passes; a severed-pivot world FAILS and is rejected.
    # The broken-world assertion needs the ENTRY on a different subnet from the crown,
    # so removing the pivot edges actually disconnects reachability (netmodel._segment_cidr
    # maps `perimeter` → DMZ, everything deeper → INTERNAL; a same-subnet entry/crown pair
    # stays reachable via the entry's attacker-NIC bridge even with no edges). Pick the
    # first seed where the entry sits on `perimeter` (struts / webrce) — the vetted-T1
    # arsenal has internal-subnet entries now (weblogic / gitlab), so a fixed seed is brittle.
    def _perimeter_seed():
        for s in range(1337, 1337 + 100):
            r = generate_range(s, pool)
            if any(h["name"] == r["entry"] and (h.get("segment") or "").lower() == "perimeter"
                   for h in r["hosts"]):
                return s
        raise AssertionError("no perimeter-entry seed found in 100 tries")
    good = generate_range(_perimeter_seed(), pool)
    assert good["objective"]["host"] != good["entry"], "pick a seed with an internal crown"
    assert mcc_evaluate(good, set())["mcc"], "a well-formed world must pass real-agent MCC"
    broken = _break_world(good)
    mb = mcc_evaluate(broken, set())
    assert not mb["mcc"] and not mb["real_substrate"], ("broken world must fail MCC", mb)

    # the curriculum ratchets: skill grows monotonically, open-endedness accumulates.
    res = env_curriculum(pool, n_generations=4, n_candidates=6)
    picked = [g for g in res["generations"] if g.get("picked") is not None]
    assert picked, "the curriculum accepted no world"
    oe = open_endedness(res["generations"])
    assert oe["monotone_skill_growth"], ("skill must not regress", oe)
    assert oe["annecs"] >= 2, ("open-endedness should accumulate >=2 challenges", oe)

    # the floor holds every accepted generation (per-actor auditor).
    for g in picked:
        vr = rvf.reverify(g["path"])
        assert vr["chain_verified"] and vr["oos_executed"] == 0, (g["gen"], vr)

    # the MCC gate actually rejected worlds in the run (not a rubber stamp).
    rejects = [e for e in res["curriculum_events"] if e["action"] == "range.reject"]
    print(f"env_coevo ok: real-agent MCC (a severed-pivot world is rejected; "
          f"{len(rejects)} rejections logged); curriculum ratchets "
          f"mastered={oe['mastered_series']} (ANNECS={oe['annecs']}); floor 0 every generation")
