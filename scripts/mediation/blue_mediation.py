"""B2 — blue-effect MEDIATION test (no TCB edit).

Blue's eviction ladder (`swarm.blue_contain`: remove_foothold / rollback_host / close_vector, plus
contain_host) performs REAL effects through `swarm.gate.run_effect` (the one effect path). B2 requires
that every blue host-affecting effect reaches `run_effect` ONLY via `gate.dispatch("blue", ...)` — so a
blue action is scope-mediated and chain-recorded on the SAME deterministic floor as a red action, and
`reverify_floor` sees it. A duel must NEVER call a `blue_contain` primitive directly.

This test spies on `blue_contain.run_effect` and, for each effect, checks whether a `Gate.dispatch`
frame is on the call stack (mediated) or not (unmediated). It asserts every WIRED eviction (the
`blue_contain.blue_eviction_executors()` routed through `gate.dispatch`) is mediated and emits a
`gate.allow` chain record, and that a DIRECT `blue_contain.rollback_host(...)` call is FLAGGED as
unmediated. Cold: the spy returns a benign "docker not available" result, so no container is touched.
"""
import inspect
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))

from swarm import blue_contain, spine          # noqa: E402
from swarm.gate import Gate                     # noqa: E402
from swarm.eventlog import EventLog             # noqa: E402


def _dispatch_on_stack():
    """True iff a Gate.dispatch frame (swarm/gate.py) is on the current call stack — i.e. the effect
    about to run is gate-mediated."""
    for fr in inspect.stack():
        if fr.function == "dispatch" and fr.filename.replace("\\", "/").endswith("swarm/gate.py"):
            return True
    return False


def _selftest():
    import tempfile
    records = []                                 # mediated? per run_effect call
    orig = blue_contain.run_effect

    def _spy(*a, **k):
        records.append(_dispatch_on_stack())
        return types.SimpleNamespace(returncode=127, stdout="", stderr="docker not available")

    blue_contain.run_effect = _spy
    p = Path(tempfile.mktemp(suffix=".jsonl"))
    try:
        log = EventLog(p)
        log.append("system", "scope", {"in_scope": ["h1"]})
        gate = Gate([], log, scope_by_actor={"blue": ["h1"]})
        execs = blue_contain.blue_eviction_executors()
        assert set(execs) == {"kill_session", "rollback_host", "close_vector"}, execs

        # WIRED: each eviction routed through gate.dispatch("blue", ...) — EVERY effect must be mediated.
        records.clear()
        for tool, fx in execs.items():
            gate.dispatch("blue", tool, "h1", (lambda fx=fx: fx("range-h1")),
                          meta=spine.coords("blue-sensor", "h1", 0, tool))
        wired = list(records)
        assert wired and all(wired), ("every WIRED blue eviction effect must be gate-mediated", wired)
        # each wired eviction left a gate.allow chain record, so reverify_floor sees blue's effects.
        E = log.entries()
        allows = [e for e in E if e.get("actor") == "blue" and e.get("action") == "gate.allow"]
        assert len(allows) == len(execs), ("each wired eviction must emit a gate.allow record", len(allows))

        # DIRECT: a blue_contain primitive called straight (bypassing the gate) is UNMEDIATED -> FLAGGED.
        records.clear()
        blue_contain.rollback_host("range-ghost")
        direct = list(records)
        assert direct and not any(direct), \
            ("a DIRECT blue_contain.rollback_host(...) call must be UNMEDIATED (the test bites)", direct)
        # contain_host too (the already-wired primitive) is unmediated when called directly.
        records.clear()
        blue_contain.remove_foothold("range-ghost", patterns=("implant",))
        assert records and not any(records), ("a direct remove_foothold call must be flagged", records)
    finally:
        blue_contain.run_effect = orig
        p.unlink(missing_ok=True)

    print("blue_mediation ok (B2): every WIRED blue eviction (kill_session/rollback_host/close_vector) "
          "reaches run_effect ONLY via gate.dispatch — mediated, each with a gate.allow chain record so "
          "reverify_floor sees blue on the floor; a DIRECT blue_contain primitive call is UNMEDIATED and "
          "FLAGGED (the test bites). No frozen file edited.")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("usage: blue_mediation.py --selftest")
    sys.exit(2)
