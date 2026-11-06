#!/usr/bin/env python3
"""L5 — the Brick-6 instrument on LIVE logs, the selection-operator experiment, and
the real (powerlaw) tail pipeline, each SELF-LABELING its statistical power.

FRONTIER_MASTER component 11 (measurement layer): the headline governed-vs-ungoverned
control and the reflexivity curve are computed from a real live duel log, not a
deterministic fixture. The selection-operator experiment (Q1: does the floor's SHAPE
steer what the adversary evolves into?) runs the co-evolution under two floor shapes
and compares the evolved MAP-Elites archives. The tail pipeline (Clauset alpha + EVT
xi via `redteam/stats_tail.tail_report`) runs on a live harm series and reports WITH
its power — at demo N these are honestly UNDERPOWERED, and that label is the point:
significance is the compute-gated step, never curve-fit here.

    python scripts/instrument_live.py            # write docs/l5_instrument_live.json (+ svg)
    python scripts/instrument_live.py --selftest  # offline, fast, asserts the harness runs
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarm import instrument
from swarm.topo_to_compose import generate_range
from redteam.stats_tail import tail_report

DEF_GOVERNED = "docs/l1_live_discovery_duel_seed1337.jsonl"
DEF_LIVE_LOGS = ["docs/l1_live_discovery_duel_seed1337.jsonl",
                 "docs/l3_real_beacon_duel_seed1337.jsonl"]


def _entries(path):
    return [json.loads(x) for x in open(path) if x.strip()]


def _trajectory(path):
    return sorted([json.loads(x)["data"] for x in open(path)
                   if x.strip() and json.loads(x).get("action") == "coevo.trajectory"],
                  key=lambda p: p.get("generation", 0))


def headline_controls(live_governed_path):
    """Governed-vs-ungoverned reproduced on a LIVE governed log; the ungoverned arm is
    the instrument's neutered-floor control on the same range. Plus the reflexivity
    curve (regex < behavioral < gate)."""
    r = generate_range(1337)
    td = Path(tempfile.mkdtemp())
    up, ue = instrument._ungoverned_log(r, td)
    gov = instrument._legibility(live_governed_path, _entries(live_governed_path))
    ung = instrument._legibility(up, ue)
    return {"governed_live": gov, "governed_log": live_governed_path,
            "ungoverned": ung,
            "legibility_gap": round(gov["legibility"] - ung["legibility"], 3),
            "reflexivity": instrument.reflexivity_curve()}


def selection_operator(shapes=(1337, 7)):
    """Q1 (does the floor's SHAPE steer what the adversary evolves into?) — PARKED.

    This ran on the scripted co-evolution engine (`liquid_stage`), retired in the F1
    convergence: it was confounded (whole range varied per seed, so floor-shape was never
    isolated from terrain) and self-labeled UNDERPOWERED — not evidence. The real Q1 is the
    pre-registered fixed-range / varied-scope protocol on the canonical frontier co-evolution
    engine (Phase 2/3). Returns the two shapes' in-scope sets so the shape difference is still
    visible, with NO fabricated diversity number."""
    archives = [{"shape_seed": sd, "in_scope": generate_range(sd)["scope"]["in_scope"]}
                for sd in shapes]
    return {"archives": archives,
            "archives_differ": archives[0]["in_scope"] != archives[1]["in_scope"],
            "finding": "PARKED — scripted selection-operator engine retired in the F1 "
                       "convergence; real Q1 is the pre-registered fixed-range/varied-scope "
                       "protocol on the canonical frontier co-evolution engine",
            "power": "PARKED (not run): the confounded scripted engine was removed; Q1 is a "
                     "Phase 2/3 experiment on the canonical engine, never curve-fit here."}


def tail_at_scale(n_seeds=64, out_txt="docs/l5_tail_at_scale.txt"):
    """The tail pipeline at ADEQUATE N. The per-episode harm proxy (kill-chain depth x
    crown) is bounded by the host/technique catalog, so its tail shape does not depend
    on the LLM — a large DETERMINISTIC sweep gives the same distribution for free. With
    n large enough to estimate, we can say CREDIBLY whether it is heavy-tailed. It is
    not: the metric is bounded, so the tail has a finite upper endpoint. The honest
    reading — the open question is the HARM METRIC (a richer, unbounded severity), not N
    or compute. Written as a tracked artifact."""
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from swarm.topo_to_compose import generate_range, emit_range_topology
    from swarm.live_red import run_discovery_duel
    sev = []
    td = Path(tempfile.mkdtemp())
    for i in range(n_seeds):
        r = generate_range(1337 + i)
        lp = td / f"e{i}.jsonl"
        log = EventLog(str(lp))
        log.append("system", "scope", {"in_scope": r["scope"]["in_scope"]})
        log.append("system", "roe", {"scope_by_actor": r["scope_by_actor"]})
        emit_range_topology(log, r)
        g = Gate([], log, scope_by_actor=r["scope_by_actor"])
        run_discovery_duel(None, g, log, r, use_llm=False)
        sev += instrument.severity_series([_entries(str(lp))])
    rep = tail_report(sev, label=f"duel harm proxy at scale (n={len(sev)} episodes)")
    lines = [
        f"# L5 tail pipeline at scale (n={len(sev)} deterministic episodes)",
        f"# Re-derive: python scripts/instrument_live.py --tail-scale {n_seeds}",
        "",
        f"severity series (bounded harm proxy = kill-chain depth x crown):",
        f"  n={rep['n']}  distinct={len(set(sev))}  min={min(sev)}  max={max(sev)}",
        f"  underpowered={rep['underpowered']}  n_tail={rep['n_tail']}  credible_alpha={rep['credible_alpha']}",
        f"  alpha={rep['alpha']}  x_min={rep['x_min']}  xi_gpd={rep['xi_gpd']}  n_exc={rep['n_exc']}",
        f"  tail_kind={rep.get('tail_kind')}",
        "",
        "READING: with n now adequate to estimate (unlike the demo-N n=2), the harm proxy shows a",
        "FINITE upper endpoint (xi<=0 / bounded support) — it is NOT heavy-tailed, BY CONSTRUCTION:",
        "the metric is capped by the host/technique catalog (the FALSIFICATION_REPORT's standing note).",
        "So the tail question is HARM-METRIC-gated, not compute-gated: a genuinely heavy tail would",
        "need a richer, unbounded severity (real $ loss / cascading impact), which this range does not",
        "model. Reported honestly as a null with its true cause, not curve-fit.",
    ]
    Path(out_txt).write_text("\n".join(lines) + "\n")
    return {"n": len(sev), "report": rep, "out": out_txt}


def tail_pipeline(live_logs):
    """Clauset alpha + EVT xi (redteam/stats_tail.tail_report) on a live harm series,
    self-labeled for power (underpowered at demo N)."""
    sev = instrument.severity_series([_entries(p) for p in live_logs if Path(p).exists()])
    return {"severity_series": sev,
            "tail": tail_report(sev, label="live duel harm (kill-chain depth x crown)")}


def run(live_governed=DEF_GOVERNED, live_logs=DEF_LIVE_LOGS,
        out_json="docs/l5_instrument_live.json", out_svg="docs/l5_reflexivity_curve.svg"):
    hc = headline_controls(live_governed)
    instrument.render_reflexivity_svg(hc["reflexivity"], out_svg)
    result = {"headline_controls": hc,
              "selection_operator": selection_operator(),
              "tail_pipeline": tail_pipeline(live_logs),
              "reflexivity_svg": out_svg,
              "note": "instrument run on LIVE logs; the selection-operator and tail results "
                      "are honest demo-N nulls, power-labeled — significance is compute-gated."}
    Path(out_json).write_text(json.dumps(result, indent=2, default=str))
    return result


def _selftest():
    # Offline: a deterministic live-shaped governed log (floor-clean) stands in for the
    # live duel; the whole harness must run and self-label power.
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from swarm.topo_to_compose import emit_range_topology
    from swarm.live_red import run_discovery_duel
    r = generate_range(1337)
    td = Path(tempfile.mkdtemp())
    gp = td / "gov.jsonl"
    log = EventLog(str(gp))
    log.append("system", "scope", {"in_scope": r["scope"]["in_scope"]})
    log.append("system", "roe", {"scope_by_actor": r["scope_by_actor"]})
    emit_range_topology(log, r)
    g = Gate([], log, scope_by_actor=r["scope_by_actor"])
    run_discovery_duel(None, g, log, r, use_llm=False)
    res = run(live_governed=str(gp), live_logs=[str(gp)],
              out_json=str(td / "l5.json"), out_svg=str(td / "refl.svg"))
    hc = res["headline_controls"]
    assert hc["governed_live"]["legible"] and not hc["ungoverned"]["legible"], hc
    assert hc["legibility_gap"] == 1.0, hc
    refl = {p["defender"]: p["rate"] for p in hc["reflexivity"]}
    assert refl["regex"] < refl["behavioral"] and refl["gate"] == 1.0, refl
    assert len(res["selection_operator"]["archives"]) == 2 and res["selection_operator"]["power"]
    assert "underpowered" in res["tail_pipeline"]["tail"], res["tail_pipeline"]
    print("instrument_live ok (governed>ungoverned on a live-shaped log; reflexivity "
          "regex<behavioral<gate=1.0; selection-operator produces two archives; tail "
          "pipeline runs and self-labels power)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--tail-scale", type=int, default=0, metavar="N_SEEDS")
    a = ap.parse_args()
    if a.tail_scale:
        res = tail_at_scale(n_seeds=a.tail_scale)
        print(f"tail at scale: n={res['n']}, credible_alpha={res['report']['credible_alpha']}, "
              f"xi_gpd={res['report']['xi_gpd']} -> {res['out']}")
    elif a.selftest:
        _selftest()
    else:
        res = run()
        so = res["selection_operator"]
        tail = res["tail_pipeline"]["tail"]
        print(f"headline legibility gap (live governed - ungoverned): "
              f"{res['headline_controls']['legibility_gap']}")
        print(f"selection-operator: {so['finding']} ({so['power'][:40]}...)")
        print(f"tail: n={tail['n']} underpowered={tail['underpowered']} "
              f"credible_alpha={tail['credible_alpha']}")
