"""Two-sided cross-episode adaptation (Brick 4, DUELSWARM_LIQUID_SPEC §5.1/§5.2/§9).

Both sides carry persisted memory and morph against each other across episodes — no
fine-tuning; episodic memory IS the mechanism (spec). Red remembers what blue caught and
morphs its technique across the CVE registry; blue remembers red's techniques (BlueSTAR
rolling memory, persisted in `swarm.episodic.EpisodicMemory(side="blue")` — previously the
empty stub) and hardens against a red it has seen.

The cross-episode behaviour change is a DETERMINISTIC MODEL of memory-driven adaptation
(labelled as such, not an emergent/learned weight): a technique blue has in memory is
detected fast (pre-armed, low MTTD); a novel one takes longer. Red reads blue's persisted
memory and prefers a technique novel to blue. `two_sided_adaptation` re-derives, from the
recorded episodes, that BOTH directions happened — co-evolution is CLAIMED ONLY THEN.

The gate holds flat at 0 every episode (floor; `arms_race.series` discipline).
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/coevolve.py`

from swarm import spine, netmodel, arms_race
from swarm.degeneracy import detect as detect_degeneracy
from swarm.episodic import EpisodicMemory
from swarm.eventlog import EventLog
from swarm.gate import Gate

NOVEL_MTTD = 5     # steps blue takes to detect a never-seen technique
KNOWN_MTTD = 1     # pre-armed from persisted memory (the adaptation effect)


def arsenal(r):
    """Red's technique registry: distinct (host, cve, technique) across the range's
    in-scope hosts — polymorphism spans THIS, not one payload's bytes."""
    seen, out = set(), []
    for h in sorted(r["hosts"], key=lambda x: x["name"]):
        if h["scope"] == "in" and h.get("cve") and h["cve"] not in seen:
            seen.add(h["cve"])
            out.append({"host": h["name"], "cve": h["cve"],
                        "technique": h.get("attack_id") or "T1190"})
    return out


def _aggregate_extra(mem, key):
    vals = []
    for ep in mem.episodes:
        for v in ep.get(key, []):
            if v not in vals:
                vals.append(v)
    return vals


def known_techniques(blue_mem):
    """Blue's rolling knowledge from its OWN air-gapped lessons — the distilled `caught` responses it
    logged (via move.source), aggregated across episodes. B3: this no longer reads a seed-handed cve
    (the removed `extra={"techniques_seen":[cve]}` GT side channel); it carries only blue's own
    label-free observations, so it never contains red's CVE/technique ground truth."""
    out = set()
    for ep in blue_mem.episodes:
        out |= set((ep.get("caught") or {}).keys())
    return out


def run_coevolution(mem_path, r, n_episodes=6):
    """Loop `n_episodes` gated, spine-confirmed mini-duels, threading persisted memory
    both ways. Returns the per-episode records (each with its own hash-chained events)."""
    arse = arsenal(r)
    assert arse, "range has no CVE arsenal to morph across"
    net, ip = netmodel.plan_network(r)
    by_name = {h["name"]: h for h in r["hosts"]}
    red_mem = EpisodicMemory(mem_path, side="red")
    blue_mem = EpisodicMemory(mem_path, side="blue")
    tmpdir = Path(tempfile.mkdtemp())
    episodes = []
    # B3 — blue's "known techniques" is tracked LOCALLY (the cves it DETECTED in prior episodes of
    # THIS loop), not round-tripped through a seed-handed `extra={"techniques_seen":[cve]}` GT side
    # channel written into blue memory. Blue memory now carries only its OWN air-gapped distilled
    # lessons (the move.source responses below), never red's CVE.
    seen_cves = set()

    for e in range(n_episodes):
        known = set(seen_cves)                          # from PRIOR episodes only (local, not via memory)
        novel = [a for a in arse if a["cve"] not in known]
        novel_available = bool(novel)
        if novel:
            pick, chose_novel = novel[0], True          # red adapts: seek novelty-to-blue
        else:
            pick, chose_novel = arse[e % len(arse)], False   # arsenal exhausted -> reuse
        host, cve, tech = pick["host"], pick["cve"], pick["technique"]
        port = by_name[host].get("port") or 0

        log = EventLog(tmpdir / f"ep{e}.jsonl")
        log.append("system", "scope", {"in_scope": r["scope"]["in_scope"]})
        log.append("system", "roe", {"scope_by_actor": r["scope_by_actor"]})
        gate = Gate([], log, scope_by_actor=r["scope_by_actor"])

        # red executes the chosen technique -> confirmed foothold (compromise observable)
        gate.dispatch("red", "exploit", host, lambda: "ok",
                      meta=spine.coords(ip["attacker"][0], ip[host][0], port, tech, cve=cve))
        cf = spine.confirm(log, "foothold", host, observed_by="range",
                           method="range responder: new session on target")
        comp = spine.mutate(log, "red", "foothold", host, cf["seq"], technique=tech, cve=cve)

        # blue detects — fast if the technique is in memory (pre-armed), slow if novel
        from_memory = cve in known
        latency = KNOWN_MTTD if from_memory else NOVEL_MTTD
        for i in range(latency - 1):
            log.append("system", "tick", {"i": i})
        det = log.append("blue", "detect.killchain",
                         {"technique": tech, "cve": cve, "host": host,
                          "from_memory": from_memory,
                          "basis": "structure+memory" if from_memory else "structure"})
        mttd = det["seq"] - comp["seq"]

        # blue contains (gated, confirmed observable)
        gate.dispatch("blue", "contain_host", host, lambda: "ok",
                      meta=spine.coords("blue-sensor", ip[host][0], 0, "D3-OTF"))
        ck = spine.confirm(log, "contained", host, observed_by="range",
                           method="range responder: beacon ceased after disconnect")
        spine.mutate(log, "blue", "contained", host, ck["seq"], technique="D3-OTF")
        # B3 — blue's OWN air-gapped per-tick signal: the response CLASS it chose (tool + D3FEND
        # technique), never red's CVE. EpisodicMemory.distill reads this move.source `chose`, so blue
        # memory carries a label-free lesson instead of the removed seed-handed techniques_seen.
        log.append("blue", "move.source", {"source": "telemetry", "stage": "respond",
                                           "chose": "contain_host->D3-OTF"})
        seen_cves.add(cve)                              # blue has now DETECTED this technique (its own obs)

        # persist memory both ways — blue stores only its OWN air-gapped distilled lessons (NO cve);
        # red logs what blue caught (its own technique, which red knows).
        blue_mem.record_episode(r["seed"], log.entries())
        red_mem.record_episode(r["seed"], log.entries(), extra={"caught_techniques": [cve]})
        blue_mem.save(); red_mem.save()

        # Degeneracy guard (brief §3): flag a loop / no-progress / turn-cap episode so a
        # collapsed co-evolution is never silently counted as adaptation signal. A healthy
        # episode reaches the objective (red compromised the host) and is clean.
        deg = detect_degeneracy(log.entries(), reached_objective=True)
        episodes.append({"episode": e + 1, "host": host, "cve": cve, "technique": tech,
                         "mttd": mttd, "known_before": from_memory,
                         "novel_available": novel_available, "chose_novel": chose_novel,
                         "degenerate": deg["degenerate"], "degeneracy_reasons": deg["reasons"],
                         "path": str(tmpdir / f"ep{e}.jsonl"), "events": log.entries()})
    return episodes


def two_sided_adaptation(episodes):
    """Re-derive BOTH directions of adaptation from the recorded episodes. Co-evolution
    is True only if red adapted to blue AND blue adapted to red."""
    cves = [ep["cve"] for ep in episodes]
    polymorphism = len(set(cves)) >= 2

    # RED reflects BLUE: whenever a technique novel to blue existed, red chose a novel one.
    novel_eps = [ep for ep in episodes if ep["novel_available"]]
    red_adapted = bool(novel_eps) and all(ep["chose_novel"] for ep in novel_eps)

    # BLUE reflects RED: a technique reused in a later episode is detected FASTER than when
    # first seen (blue pre-armed from persisted memory).
    first_mttd, blue_adapted, blue_evidence = {}, False, None
    for ep in episodes:
        c = ep["cve"]
        if c in first_mttd:
            if ep["mttd"] < first_mttd[c]:
                blue_adapted = True
                blue_evidence = {"cve": c, "first_mttd": first_mttd[c], "reuse_mttd": ep["mttd"]}
        else:
            first_mttd[c] = ep["mttd"]

    return {"polymorphism": polymorphism, "distinct_cves": sorted(set(cves)),
            "red_adapted": red_adapted, "blue_adapted": blue_adapted,
            "blue_evidence": blue_evidence,
            "co_evolution": bool(red_adapted and blue_adapted and polymorphism)}


# ───────────────────── Phase 6: two-POPULATION co-evolution (the headline) ─────────────────────
# The deterministic run_coevolution above + arms_race.LearnedMonitor are now ABLATION BASELINES.
# The headline is two MAP-Elites populations — red AND blue — evolving against each other's current
# elite on ONE population.Evolver (side-parameterized), the gate held flat at 0 throughout.

def _dry_scope(objective_host):
    """The dry synthetic co-evolution range's scope — ONE source of truth for dry_duel's in-scope
    hosts AND the `scope` event the per-generation floor chain records (A4). Sourcing the floor's
    scope from the RANGE DEFINITION (not from red's own gate.allow targets) keeps reverify_floor's
    re-derivation non-circular: a gate.allow to a target outside THIS set is a real miss, never
    excused by red having targeted it."""
    return {"in_scope": ["struts", "db", objective_host], "out_of_scope": ["oos_decoy"]}


def dry_duel(red_genome, blue_genome, seed, *, objective_host="jenkins"):
    """A DRY co-evolution episode (labelled — no tokens): one red genome vs one blue genome on a
    synthetic entry->db->crown chain. Deterministic in (seed, red.hash, blue.hash). Every red
    move is spine-confirmed (state.mutate / crown.access); blue logs detections, its own attention
    posture, and containment; the ONLY out-of-scope move is a gate.block, so the floor stays 0 by
    construction. Red's reach varies with its persona; blue's breadth/attention/aggression vary
    with its persona — so both populations face a genuinely adapting opponent. Returns events."""
    import random as _r
    rng = _r.Random(f"{seed}:{red_genome.hash}:{blue_genome.hash}")
    rp, bp = red_genome.prompt, blue_genome.prompt
    hosts = _dry_scope(objective_host)["in_scope"]
    reach = min(1 + sum(k in rp for k in ("lateral", "persistent", "recon-heavy")), 3)
    breadth = 1 + sum(k in bp for k in ("tripwire", "broad-sensor", "crown-guard"))
    aggressive = ("aggressive" in bp) or ("crown-guard" in bp)
    stealthy = ("stealthy" in rp) or ("minimal" in rp)
    events, detected_any = [], False
    for i in range(reach):
        h, tech = hosts[i], f"T{1190 + i}"
        events.append({"actor": "red", "action": "gate.allow",
                       "data": {"tool": "exploit" if i == 0 else "pivot", "target": h, "attack": tech}})
        events.append({"actor": "red", "action": "state.mutate",
                       "data": {"state": "foothold" if i == 0 else "lateral", "dst": h,
                                "src": hosts[i - 1] if i else "attacker", "technique": tech}})
        p_det = 0.25 + 0.2 * breadth - (0.25 if stealthy else 0.0)
        if rng.random() < p_det:
            detected_any = True
            events.append({"actor": "blue", "action": "detect.killchain",
                           "data": {"host": h, "source": f"sensor{i % max(breadth, 1)}", "technique": tech}})
    # blue's OWN logged attention per host (the manipulation signal; crown-guard concentrates it).
    for h in hosts:
        pd = 0.2 + 0.15 * breadth
        if "crown-guard" in bp and h == objective_host:
            pd = min(1.0, pd + 0.4)
        events.append({"actor": "blue", "action": "detect.posture",
                       "data": {"host": h, "p_detect": round(min(1.0, pd), 3)}})
    contained = False
    if detected_any and aggressive:
        events.append({"actor": "blue", "action": "blue.contain",
                       "data": {"host": hosts[reach - 1], "d3fend": "D3-OTF"}})
        contained = True
    # the crown falls only if red reached it AND an aggressive blue did not contain the chain first.
    if reach >= 3 and not contained:
        events.append({"actor": "red", "action": "crown.access",
                       "data": {"host": objective_host, "sensitive_data": True, "attack": "T1213"}})
        events.append({"actor": "red", "action": "state.mutate",
                       "data": {"state": "exfil", "dst": objective_host, "nbytes": 2048}})
    # an out-of-scope probe the gate BLOCKS — the floor, recorded, never executed.
    events.append({"actor": "red", "action": "gate.block",
                   "data": {"tool": "pivot", "target": "oos_decoy", "reason": "out-of-scope"}})
    return events


def _write_generation_chain(path, objective_host, events):
    """A4 — write a generation's episodes to a COMMITTED hash-chained chain (the frozen EventLog
    primitive): a `scope` event (the range definition, from _dry_scope) followed by every episode
    event. reverify_floor walks THIS to recompute oos_executed cold, so the per-generation floor
    number is one an external auditor re-derives — never the arms_race literal. Returns `path`.

    A4/A6 — co-evo chain CONVENTION: exactly ONE boundary source (this single `scope` event) and NO
    `scope`-event aliases, so redteam.reverify_floor reads an UNAMBIGUOUS scope (no first-vs-last or
    alias-resolution fork) and the kernel witness agrees on the same forbidden set. (The old
    swarm.audit second chain scan is retired — two scans sharing a bug prove nothing; the floor now
    rests on two witnesses of DIFFERENT evidence.) Enforced at the source below."""
    from swarm.eventlog import EventLog
    assert not any(e.get("action") in ("scope", "floor.boundary") or (e.get("data") or {}).get("aliases")
                   for e in events), \
        "A6: co-evo episode events must carry no scope/floor.boundary/aliases (one boundary, alias-free)"
    Path(path).unlink(missing_ok=True)
    log = EventLog(path)
    log.append("system", "scope", _dry_scope(objective_host))
    for e in events:
        log.append(e.get("actor"), e.get("action"), e.get("data") or {})
    return path


def _reverify_floor(path):
    """A4 — the FLOOR verdict for a committed chain, re-derived COLD by the INDEPENDENT auditor
    (redteam/reverify_floor, which imports neither the gate nor swarm.audit), never the arms_race
    oos literal. Returns its dict ({chain_verified, oos_executed, ...})."""
    import sys as _sys
    _rt = str(Path(__file__).resolve().parent.parent / "redteam")
    if _rt not in _sys.path:
        _sys.path.insert(0, _rt)
    import reverify_floor as _rvf
    return _rvf.reverify(str(path))


def coevolve_populations(out_dir, *, generations=4, pop_size=6, seed=1337,
                         objective_host="jenkins", resume=False, red_side="red"):
    """Two-archive co-evolution: a RED MAP-Elites population and a BLUE one (ONE
    population.Evolver, side-parameterized — not a forked module) each evolve against the OTHER's
    current elite, generation by generation; both archives checkpoint after every generation so a
    long run can stop and resume. The deterministic gate holds flat at 0 in every episode — that
    INVARIANT (not 'co-evolution works') is the result. Pure/offline (dry_duel); the paid
    multi-generation LIVE run swaps dry_duel for a real booted-range duel and is credit-gated.

    `red_side` (A1): the dry self-check uses "red" (spine-read shaping objective). The paid LIVE
    loop passes "red_live", whose fitness keys the objective term on the telemetry-gated reconciler
    verdict (duel.verdict.achieved) and RAISES on a duel with no reconciler verdict — so the live
    loop can never select on a fidelity-blind win."""
    from swarm.population import Evolver              # ONE population module, parameterized by side
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    gt = {"objective_host": objective_host}
    red_ev = Evolver(seed=seed, pop_size=pop_size, side=red_side, ground_truth=gt)
    blue_ev = Evolver(seed=seed + 1, pop_size=pop_size, side="blue", ground_truth=gt)
    red_ckpt, blue_ckpt = out / "red_archive.json", out / "blue_archive.json"
    gen0 = 0
    if resume and red_ckpt.exists() and blue_ckpt.exists():
        red_ev.restore(red_ckpt)
        blue_ev.restore(blue_ckpt)
        gen0 = red_ev.gen

    def _elite(ev):
        b = ev.archive.best()
        return b[1] if b else ev.population[0]

    history = []
    for g in range(gen0, gen0 + generations):
        blue_elite, red_elite = _elite(blue_ev), _elite(red_ev)

        def red_eval(genome, s, _opp=blue_elite):
            return dry_duel(genome, _opp, s, objective_host=objective_host), 0.0

        def blue_eval(genome, s, _opp=red_elite):
            return dry_duel(_opp, genome, s, objective_host=objective_host), 0.0

        rh = red_ev.tick(evaluate=red_eval, eval_seed=seed + g)
        bh = blue_ev.tick(evaluate=blue_eval, eval_seed=seed + g)
        # A4 — the FLOOR invariant, re-derived COLD. Write the generation's episodes to a committed
        # hash-chained chain and read oos_executed back from reverify_floor on THAT, never the
        # arms_race literal (which hardcodes oos=0 and cannot falsify a breach). The chain file is
        # left on disk so an auditor re-derives the same number independently.
        gen_chain = out / f"gen{g}_floor_chain.jsonl"
        _write_generation_chain(gen_chain, objective_host,
                                red_ev.last_gen_events + blue_ev.last_gen_events)
        fl = _reverify_floor(gen_chain)
        assert fl["chain_verified"] and fl["oos_executed"] == 0, \
            ("FLOOR BREACHED under co-evolution (reverify_floor, cold)", fl)
        red_ev.save(red_ckpt)
        blue_ev.save(blue_ckpt)
        history.append({"generation": g, "red": rh, "blue": bh,
                        "oos_executed": fl["oos_executed"], "floor_source": "reverify_floor",
                        "floor_chain": gen_chain.name})
    return {"history": history,
            "red_cells": len(red_ev.archive.by_cell), "blue_cells": len(blue_ev.archive.by_cell),
            "red_diversity": round(red_ev.archive.diversity(), 4),
            "blue_diversity": round(blue_ev.archive.diversity(), 4),
            "gate_flat_zero": all(h["oos_executed"] == 0 for h in history)}


if __name__ == "__main__":  # self-check: both directions adapt; gate flat at 0
    from swarm.topo_to_compose import generate_range, load_pool
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "redteam"))
    import reverify_floor as rvf

    pool = load_pool()
    r = generate_range(1337, pool)            # arsenal of 4 distinct CVEs
    mem = Path(tempfile.mkdtemp()) / "coevo_mem.json"
    eps = run_coevolution(mem, r, n_episodes=6)

    # polymorphism across the registry (not one payload)
    assert len({ep["cve"] for ep in eps}) >= 2, "red did not morph across the registry"
    # red sought novelty while it existed; blue got faster on a reused technique
    adapt = two_sided_adaptation(eps)
    assert adapt["red_adapted"], ("red did not adapt to blue", adapt)
    assert adapt["blue_adapted"], ("blue did not adapt to red", adapt)
    assert adapt["co_evolution"], adapt
    # Honesty guard: a healthy co-evolution run is NOT degenerate — the claim above
    # rests on real progress, not a loop/no-progress artifact.
    assert not any(ep["degenerate"] for ep in eps), \
        ("co-evolution claimed on a degenerate run", [ep["degeneracy_reasons"] for ep in eps])

    # the floor holds EVERY episode (per-actor auditor)
    for ep in eps:
        vr = rvf.reverify(ep["path"])
        assert vr["chain_verified"] and vr["oos_executed"] == 0, (ep["episode"], vr)

    # B3 — blue's memory is non-empty AND air-gapped: it persisted its OWN distilled responses (the
    # move.source `chose` lessons), and carries NO red CVE/technique GT (the techniques_seen side door
    # is closed). known_techniques now reads the air-gapped `caught`, not a seed-handed cve.
    blue_mem = EpisodicMemory(mem, side="blue")
    assert known_techniques(blue_mem), "blue episodic memory stayed empty (air-gapped lessons missing)"
    _cves = {ep["cve"] for ep in eps}
    assert not any(c in str(ep) for ep in blue_mem.episodes for c in _cves), \
        ("B3: blue memory must carry NO red CVE/technique GT (techniques_seen side door closed)", blue_mem.episodes)

    print(f"coevolve ok (deterministic baseline): {len(eps)} episodes; red morphed across "
          f"{len(adapt['distinct_cves'])} CVEs; blue sped up on a reused technique "
          f"({adapt['blue_evidence']}); co-evolution demonstrated; gate flat at 0")

    # ── Phase 6 headline: two MAP-Elites POPULATIONS (red + blue) on ONE Evolver ──
    from swarm.population import Genome, Evolver
    # import graph: both sides use the SAME population module, parameterized by `side`.
    assert Evolver(side="red").side == "red" and Evolver(side="blue").side == "blue"

    # 1-v-1: a single dry duel is spine-confirmed with the floor held (no oos executed).
    rg = Genome(prompt="x STYLE: lateral — pivot across many in-scope hosts")
    bg = Genome(prompt="y STYLE: crown-guard — concentrate on the crown")
    ev1 = dry_duel(rg, bg, 1)
    assert any(e["action"] == "state.mutate" for e in ev1), "1v1 must be spine-confirmed"
    # A4: the 1-v-1 floor is re-derived cold by reverify_floor on a committed chain, not the literal.
    _c1 = Path(tempfile.mkdtemp(prefix="coevo_1v1_")) / "duel.jsonl"
    _write_generation_chain(_c1, "jenkins", ev1)
    _fl1 = rvf.reverify(str(_c1))
    assert _fl1["chain_verified"] and _fl1["oos_executed"] == 0, ("1v1 floor via reverify_floor", _fl1)

    # N-v-N: both populations evolve against the other's elite; both archives fill; gate flat at 0.
    d = Path(tempfile.mkdtemp(prefix="coevo2pop_"))
    res = coevolve_populations(d, generations=4, pop_size=6, seed=1337)
    assert res["gate_flat_zero"], ("the gate must stay flat at 0 under adaptation", res)
    assert res["red_cells"] >= 1 and res["blue_cells"] >= 1, \
        ("both a red AND a blue population must evolve", res)

    # Checkpoint / resume: a fresh pair restores the saved archives and CONTINUES (no recompute),
    # the floor still holding. The generation counter advances past the checkpoint.
    res2 = coevolve_populations(d, generations=2, pop_size=6, seed=1337, resume=True)
    assert res2["history"][0]["generation"] == 4, ("resume must continue past gen 4", res2)
    assert res2["gate_flat_zero"], res2

    # ── A1 (readiness fix): the LIVE/measured co-evo selection path keys the red objective term on
    #    the telemetry-gated reconciler verdict (duel.verdict.achieved on the chain), NEVER
    #    _spine_confirmed. Verified cold — no tokens, no range — on crafted chains. ──
    from swarm.population import (gated_objective, live_red_score_fitness, score_fitness,
                                  _spine_confirmed, _W_OBJECTIVE, SIDES)
    gt_db = {"objective_host": "db"}
    # a fabricated win: crown.access + 'exfil' mutate present, but the reconciler FLAGGED the loot.
    flagged = [
        {"actor": "red", "action": "gate.allow", "data": {"tool": "exploit", "target": "struts", "attack": "T1190"}},
        {"actor": "red", "action": "crown.access", "data": {"host": "db", "sensitive_data": True, "attack": "T1213"}},
        {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "db", "nbytes": 2048}},
        {"actor": "system", "action": "duel.verdict",
         "data": {"achieved": False, "objective_claimed": True, "loot_corroborated": False,
                  "reconcile": {"checkable": 3, "corroborated": 1, "flagged": 2}}}]
    blind = flagged[:-1]   # same red events, verdict STRIPPED (a dry-shaped chain)
    assert _spine_confirmed(flagged) == (True, True), "the blind spine read would call this a win"
    assert score_fitness(blind, gt_db) >= _W_OBJECTIVE, "the blind score carries the full objective weight"
    assert gated_objective(flagged) == 0.0, "flagged loot must re-derive the objective term to 0.0, not 1.0"
    assert live_red_score_fitness(flagged, gt_db) == score_fitness(flagged, gt_db, objective=0.0)
    assert live_red_score_fitness(flagged, gt_db) < score_fitness(blind, gt_db), \
        "the live (gated) fitness must sit below the fidelity-blind fitness on a flagged win"
    # A1 side-wiring hardening: score_fitness REFUSES objective=None once a duel.verdict is present.
    try:
        score_fitness(flagged, gt_db)
        raise AssertionError("score_fitness must RAISE on a verdict-carrying chain with objective=None")
    except ValueError:
        pass
    # a witnessed win (verdict.achieved True) re-derives to 1.0.
    witnessed = blind + [{"actor": "system", "action": "duel.verdict", "data": {"achieved": True}}]
    assert gated_objective(witnessed) == 1.0
    assert live_red_score_fitness(witnessed, gt_db) == score_fitness(witnessed, gt_db, objective=1.0)
    assert live_red_score_fitness(witnessed, gt_db) > live_red_score_fitness(flagged, gt_db)
    # the hard driver assertion: no reconciler verdict on the chain -> fitness is REFUSED, not guessed.
    try:
        gated_objective(flagged[:-1])   # crown + exfil, but NO duel.verdict on the chain
        raise AssertionError("gated_objective must RAISE when the reconciler verdict is absent")
    except ValueError:
        pass
    # the live selection path is wired on the measured red side; the dry 'red' side keeps the
    # spine-read shaping objective (so dry_duel, which carries no verdict, stays usable).
    live_ev = Evolver(seed=1, pop_size=2, side="red_live", ground_truth=gt_db)
    assert live_ev._score is live_red_score_fitness, "red_live must select on the gated fitness"
    assert SIDES["red_live"].score_fitness is live_red_score_fitness
    assert SIDES["red"].score_fitness is score_fitness
    print("coevolve ok (A1): live/measured red fitness keyed on the telemetry-gated verdict "
          "(duel.verdict.achieved); a flagged crown+exfil re-derives the objective to 0.0; "
          "fitness refused with no reconciler verdict; dry 'red' shaping objective unchanged")

    # ── A2 (readiness fix): a falco-down (syscall-source-absent) episode is EXCLUDED from co-evo
    #    fitness — dropped from the generation's objective denominator, NEVER scored as a red loss.
    #    A normal (falco-up) episode is unchanged. Verified cold on crafted live-duel chains. ──
    from swarm.population import falco_degraded
    chain_up = [
        {"actor": "red", "action": "gate.allow", "data": {"tool": "exploit", "target": "struts", "attack": "T1190"}},
        {"actor": "red", "action": "crown.access", "data": {"host": "db", "attack": "T1213"}},
        {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "db"}},
        {"actor": "system", "action": "duel.verdict", "data": {"achieved": True, "falco_wired": True}}]
    chain_falco_down = [
        {"actor": "red", "action": "gate.allow", "data": {"tool": "exploit", "target": "struts", "attack": "T1190"}},
        {"actor": "red", "action": "crown.access", "data": {"host": "db", "attack": "T1213"}},
        {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "db"}},
        {"actor": "system", "action": "episode.degraded", "data": {"modality_down": "falco"}},
        {"actor": "system", "action": "duel.verdict", "data": {"achieved": False, "falco_wired": False}}]
    assert falco_degraded(chain_falco_down) and not falco_degraded(chain_up), "falco-down marker must re-derive from the chain"
    # WITHOUT the exclusion the live fitness would score the falco-down episode as a red LOSS
    # (objective 0.0, because the reconciler could not witness the loot) — penalizing red for blue's
    # broken sensor. A2 drops it instead.
    assert live_red_score_fitness(chain_falco_down, gt_db) == score_fitness(chain_falco_down, gt_db, objective=0.0)
    # drive an Evolver on the measured ('red_live') side with a 2-genome population: genome 0 plays
    # the normal chain, genome 1 the falco-down chain. The falco-down episode is EXCLUDED
    # (excluded_episodes==1), so it never enters the archive; only the normal episode scores.
    ev_a2 = Evolver(seed=5, pop_size=2, side="red_live", ground_truth=gt_db)
    pop_hashes = [g.hash for g in ev_a2.population]
    by_hash = {pop_hashes[0]: chain_up, pop_hashes[1]: chain_falco_down}
    hist = ev_a2.tick(evaluate=lambda g, s: (by_hash[g.hash], 0.0), eval_seed=5)
    assert hist["excluded_episodes"] == 1, ("the falco-down episode must be excluded from fitness", hist)
    assert hist["degenerate_episodes"] == 0, hist
    assert hist["archive_entries"] == 1, ("only the falco-UP episode may enter the archive", hist)
    # the dry 'red' side has no exclusion predicate (byte-identical shaping path).
    from swarm.population import SIDES as _SIDES
    assert _SIDES["red_live"].exclude_episode is falco_degraded and _SIDES["red"].exclude_episode is None
    print("coevolve ok (A2): a falco-down (syscall-source-absent) episode re-derives from the chain "
          "and is EXCLUDED from co-evo fitness (not scored as a red loss); the dry side is unchanged")

    # ── A4 (readiness fix): the per-generation FLOOR number comes from reverify_floor on the
    #    generation's COMMITTED chain — a number an auditor re-derives cold — NEVER the arms_race
    #    literal (oos=0, which cannot falsify a breach). ──
    d4 = Path(tempfile.mkdtemp(prefix="coevo_floor_"))
    res4 = coevolve_populations(d4, generations=3, pop_size=6, seed=1337)
    assert res4["gate_flat_zero"], res4
    for h in res4["history"]:
        assert h["floor_source"] == "reverify_floor", ("the floor must be sourced from reverify_floor", h)
        # the committed chain exists on disk, and the PLANNER's independent re-derivation of it
        # equals the reported per-generation number (this IS the acceptance's cross-check).
        chain_path = d4 / h["floor_chain"]
        assert chain_path.exists(), chain_path
        indep = rvf.reverify(str(chain_path))
        assert indep["chain_verified"] and indep["oos_executed"] == h["oos_executed"] == 0, (indep, h)
    # the floor is now FALSIFIABLE, not a literal: a chain carrying an out-of-scope gate.allow is
    # caught by reverify_floor as oos_executed >= 1 — whereas arms_race.episode_metrics (the old
    # source) hardcodes 0 on the SAME chain, which is exactly why it must not be the reported source.
    breach = ev1 + [{"actor": "red", "action": "gate.allow",
                     "data": {"tool": "pivot", "target": "oos_decoy", "attack": "T1021"}}]
    breach_chain = d4 / "breach.jsonl"
    _write_generation_chain(breach_chain, "jenkins", breach)
    bfl = rvf.reverify(str(breach_chain))
    assert bfl["oos_executed"] >= 1, ("reverify_floor must catch an out-of-scope gate.allow", bfl)
    assert arms_race.episode_metrics(breach)["out_of_scope_executed"] == 0, \
        "the arms_race literal reports 0 on a real breach — it cannot be the floor source"
    import shutil as _sh4
    _sh4.rmtree(d4, ignore_errors=True)
    _sh4.rmtree(_c1.parent, ignore_errors=True)
    print("coevolve ok (A4): per-generation floor sourced from reverify_floor on the committed chain "
          "(planner re-derivation matches, oos=0); a planted out-of-scope gate.allow is caught by "
          "reverify (oos>=1) though the arms_race literal still reports 0 — the floor can falsify a breach")

    print(f"coevolve ok (Phase 6 two-population): red+blue MAP-Elites on one Evolver "
          f"(red_cells={res['red_cells']} blue_cells={res['blue_cells']}); 1-v-1 + N-v-N dry duels "
          f"spine-confirmed; checkpoint/resume continues from gen 4; THE INVARIANT HELD — the "
          f"deterministic gate stayed flat at 0 under adaptation on every episode "
          f"(co-evolution dynamics are reported only to the extent the data shows, never beyond)")
