"""ONE measurement engine — the only reachable paid-measurement path is the interleaved duel on the
unified range (2026-10-27 consolidation; free, no Docker/API).

Rationale: `CC-brief` Part 0. Before this, three duel paths were reachable and a `--mode live` on the
default generated range measured a SEPARATE range (the 2026-10-26 pre-spend blocker). This proves the
footgun is closed: the generated-range LIVE measurement is REFUSED, the retired sequential path is
gone, and the ONLY live measurement path runs `run_interleaved_duel` on the unified range.

    .venv/bin/python scripts/prove_one_engine.py --selftest
"""
import argparse
import inspect
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))


def _selftest():
    import live_arms_race_run as m

    # 1) BEHAVIOURAL: a paid measurement cannot be fired on the wrong engine — generated + live is
    #    refused with a message pointing at the one engine (the 2026-10-26 pre-spend footgun, closed).
    raised = None
    try:
        m._episode(1, "live", None, tempfile.mkdtemp(), range_kind="generated")
    except RuntimeError as e:
        raised = str(e)
    assert raised and "RETIRED" in raised and "unified" in raised, \
        f"generated-range LIVE measurement must be REFUSED, got: {raised!r}"

    # 2) the retired sequential measurement path (generated+live post-hoc run_blue_fight) is GONE.
    assert not hasattr(m, "_run_live_episode"), "_run_live_episode (sequential footgun) must be retired"

    # 3) the ONE measurement engine: the live/unified episode runs the interleaved duel; the only
    #    other (generated) episode path is the dry shakeout and never runs the interleaved duel.
    assert "run_interleaved_duel" in inspect.getsource(m._run_unified_live_episode), \
        "the unified (measurement) episode must run the interleaved duel"
    dry_src = inspect.getsource(m._run_dry_episode)
    assert "run_interleaved_duel" not in dry_src, "the dry shakeout must not be a measurement engine"

    # 4) and a `--mode live` CANNOT default into the generated path silently: the generated branch of
    #    _episode raises on live (the same guard proven behaviourally above), so the only way to run
    #    live is `--range unified`.
    ep_src = inspect.getsource(m._episode)
    assert "generated-range LIVE measurement is RETIRED" in ep_src and "raise RuntimeError" in ep_src, \
        "the generated branch must hard-refuse live"

    # 5) ONE-OF-EACH + the parallel engines / dead-module lineage are GONE (by the file + import
    #    graph). The 2026-10-27 consolidation collapsed the reachable duel drivers + the dead-module
    #    lineage into one engine; assert they are absent so any re-introduction fails loudly here.
    import importlib
    GONE_FILES = [
        # parallel attackers / duel drivers / legacy experiment runners
        "scripts/arms_race_enterprise_frontier.py", "scripts/arms_race_enterprise.py",
        "scripts/arms_race_check.py", "scripts/measured_duel.py", "scripts/scrutiny_duel.py",
        "scripts/run_decision_experiment.py", "scripts/run_experiments.py",
        "scripts/prove_n2n3_tiered.py", "scripts/prove_n3_live_blue.py",
        # dead swarm modules (0 live importers)
        "swarm/blue_llm.py", "swarm/blue_counter_recon.py", "swarm/report.py",
        "swarm/live_blue.py", "swarm/orienteering.py", "swarm/judge.py", "swarm/deception.py",
    ]
    back = [rel for rel in GONE_FILES if (ROOT / rel).exists()]
    assert not back, f"a retired engine/driver/dead module is back on disk: {back}"
    GONE_MODULES = ["swarm.live_blue", "swarm.orienteering", "swarm.judge", "swarm.blue_llm",
                    "swarm.report", "swarm.blue_counter_recon", "swarm.deception"]
    for mod in GONE_MODULES:
        try:
            importlib.import_module(mod)
            raise AssertionError(f"retired module still importable: {mod}")
        except ModuleNotFoundError:
            pass

    # 5b) NO PARALLEL LIVE DRIVER — structural, not a hardcoded filename list (audit MEDIUM-3). The
    #     load-bearing "live" act is building a paid LLM router; the ONLY sanctioned builders are the
    #     one engine, the uncounted reasoning-vs-recall control, the one-call smoke, and the factory
    #     itself. ANY OTHER module that calls make_router is a parallel live driver -> FAIL by name
    #     (replaces run_live's removed inspect-check: run_live was deleted, so it must not reappear).
    import re as _re
    from swarm import live_red as _lr
    assert not hasattr(_lr, "run_live"), "run_live (the parallel-live driver) must stay deleted"
    SANCTIONED_ROUTER = {
        "swarm/llm.py",                        # the router factory itself
        "scripts/live_arms_race_run.py",       # the ONE engine (the only Nebius-COUNTED path)
        "scripts/prove_control_reasoning.py",  # reasoning-vs-recall control — uncounted, stamped
        "scripts/smoke_test.py",               # the sanctioned one-call Nebius smoke
    }
    offenders = []
    for py in sorted((ROOT / "swarm").rglob("*.py")) + sorted((ROOT / "scripts").rglob("*.py")):
        rel = str(py.relative_to(ROOT))
        if "__pycache__" in rel or rel in SANCTIONED_ROUTER:
            continue
        if _re.search(r"\bmake_router\s*\(", py.read_text()):
            offenders.append(rel)
    assert not offenders, ("a module builds a live LLM router outside the one engine (parallel-live "
                           f"driver?): {offenders}")

    # 5c) the uncounted frontier control is STAMPED non-Nebius/uncounted on its output + log (MEDIUM-3),
    #     so the sole Nebius-COUNTED measurement path is unambiguously the one engine.
    ctl_src = (ROOT / "scripts" / "prove_control_reasoning.py").read_text()
    assert '"counted": False' in ctl_src and "non_nebius" in ctl_src and "UNCOUNTED CONTROL" in ctl_src, \
        "the reasoning-vs-recall control must stamp its output/log uncounted + non-Nebius-aware"

    # ONE of each, present and canonical: one red loop, one blue, one range, one measurement duel
    # (+ its dry/verify helper). Importing these is the positive half of one-of-each.
    from swarm.live_agent import run_red_agent                    # the ONE red loop
    from swarm.live_blue_agent import run_blue_fight, run_interleaved_duel   # ONE blue + the ONE duel
    from swarm.live_red import run_discovery_duel, run_sim_red    # the dry/verify helper (kept, #4)
    from swarm import topo_to_compose                             # the ONE range
    assert all(callable(f) for f in (run_red_agent, run_blue_fight, run_interleaved_duel,
                                     run_discovery_duel, run_sim_red)), "one-of-each must be callable"

    print("prove_one_engine ok (ONE measurement engine: the generated-range LIVE measurement is "
          "REFUSED [the 2026-10-26 pre-spend footgun, closed], the retired sequential _run_live_episode "
          "is gone, and the ONLY reachable live-measurement path is _run_unified_live_episode -> "
          "run_interleaved_duel on the unified range. The generated range is free DRY shakeout only. "
          "ONE-OF-EACH: one red loop (run_red_agent), one blue (run_blue_fight), one range "
          "(topo_to_compose), one measurement duel (run_interleaved_duel) + its dry/verify helper "
          "(run_discovery_duel); the parallel engines + dead-module lineage are GONE by the file+import graph.)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.parse_args()
    sys.exit(_selftest())
