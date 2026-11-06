"""C1 — egress mediation on a free-form red command (no gate.py edit).

Red's live tools take a fixed verb+target, so `gate.check_egress` (the free-form-command egress
check) never runs on the live path. Before red gets a shell / `run_command` tool, C1 requires that
ANY such tool pass `command=` to `gate.dispatch`, so every outbound host the command references is
canonicalized and default-denied against the actor's scope — the SAME deterministic floor as a
verb+target action, recorded as `gate.block` on the chain (so `reverify_floor` sees it).

This test proves the mediation on the gate as it is (gate.py FROZEN, no edit): a free-form red
command to an out-of-scope target is BLOCKED by `check_egress` via `gate.dispatch(command=...)` and
logged, the tool body never runs, and an in-scope command runs. It ALSO surfaces — does not paper
over — that `check_egress`'s host parser does not canonicalize three IP encodings (decimal / hex /
ipv6-mapped), so it does NOT block those: they are the KNOWN bypass set `parser_fuzz` reports and the
COMPENSATING terrain for the kernel-segmentation backstop (C2), asserted here so a parser change is
flagged. `swarm.live_red.build_agent_tools(enable_shell=True)` exposes a reference `run_command` tool
that passes `command=` for exactly this mediation.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from swarm.gate import Gate, OutOfScope     # noqa: E402
from swarm.eventlog import EventLog         # noqa: E402

# The IP encodings parser_fuzz reports as TRUE BYPASSES: check_egress does not resolve them to their
# dotted OOS IP (172.22.0.4), so it does not block them. NOT a claim that check_egress blocks them —
# the kernel segmentation backstop (C2) is the compensating control.
_KNOWN_BYPASS_ENCODINGS = {
    "decimal":     "curl http://2887122948/",            # == 172.22.0.4
    "hex":         "curl http://0xac160004/",            # == 172.22.0.4
    "ipv6_mapped": "curl http://[::ffff:172.22.0.4]/",   # == 172.22.0.4
}


def _selftest():
    import tempfile
    p = Path(tempfile.mktemp(suffix=".jsonl"))
    log = EventLog(p)
    gate = Gate([], log, scope_by_actor={"red": ["10.9.0.5"]})
    ran = {"n": 0}

    # (1) a free-form red command whose egress target is an OUT-OF-SCOPE dotted IP is BLOCKED by
    #     check_egress — via gate.dispatch(command=...) — and logged as gate.block; the body never runs.
    blocked = False
    try:
        gate.dispatch("red", "run_command", "10.9.0.5",
                      (lambda: ran.__setitem__("n", ran["n"] + 1)),
                      command="curl http://172.22.0.4/steal")
    except OutOfScope:
        blocked = True
    assert blocked and ran["n"] == 0, "a free-form red command egressing OOS must be blocked AND not run"
    E = log.entries()
    blk = [e for e in E if e.get("actor") == "red" and e.get("action") == "gate.block"
           and (e.get("data") or {}).get("reason") == "egress-out-of-scope"]
    assert blk and "172.22.0.4" in (blk[-1]["data"].get("egress_blocked") or []), \
        ("the egress block must be recorded on the chain", E)

    # (2) an IN-SCOPE command passes egress mediation and the body runs.
    gate.dispatch("red", "run_command", "10.9.0.5",
                  (lambda: ran.__setitem__("n", ran["n"] + 1)),
                  command="curl http://10.9.0.5/health")
    assert ran["n"] == 1, "an in-scope command must run"

    # (3) the three IP-encoding bypasses: check_egress does NOT block them (surfaced, not papered over)
    #     — the kernel segmentation backstop (C2) is the compensating control. Assert the KNOWN set so
    #     a change to the gate's host parser (which would narrow this gap) is flagged here.
    missed = []
    for name, cmd in _KNOWN_BYPASS_ENCODINGS.items():
        ok, blk2 = gate.check_egress(cmd, actor="red")
        if ok and not blk2:
            missed.append(name)
    assert set(missed) == set(_KNOWN_BYPASS_ENCODINGS), \
        ("the known IP-encoding bypass set changed — reconcile with parser_fuzz + the kernel backstop", missed)

    # (4) the reference run_command tool (build_agent_tools(enable_shell=True)) passes command= so the
    #     SAME mediation runs through the live engine's tool surface.
    from swarm import live_red
    p2 = Path(tempfile.mktemp(suffix=".jsonl"))
    log2 = EventLog(p2)
    g2 = Gate([], log2, scope_by_actor={"red": ["10.9.0.5"]})
    tools, _st = live_red.build_agent_tools(
        log2, g2, attacker_container="a", foothold_container="w", entry_net="10.9.0.0/24",
        inner_net="10.20.0.0/24", enable_shell=True)
    assert "run_command" in tools, "enable_shell must expose a run_command tool"
    res = tools["run_command"](command="curl http://172.22.0.4/steal", target="10.9.0.5")
    assert res.get("blocked") and not res.get("ran"), ("the run_command tool must block an OOS egress", res)
    assert any(e.get("action") == "gate.block" and (e.get("data") or {}).get("reason") == "egress-out-of-scope"
               for e in log2.entries()), "the tool's OOS command must be a gate.block on the chain"
    p.unlink(missing_ok=True)
    p2.unlink(missing_ok=True)

    print("egress_mediation ok (C1): a free-form red command to an OOS target is BLOCKED by "
          "check_egress via gate.dispatch(command=) + recorded as gate.block (body never runs); an "
          "in-scope command runs; the run_command tool (enable_shell) routes command= for the same "
          "mediation; the 3 IP-encoding bypasses (decimal/hex/ipv6-mapped) are SURFACED as check_egress "
          "gaps (parser_fuzz's set), compensated by the kernel segmentation backstop (C2) — no gate.py edit")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("usage: egress_mediation.py --selftest")
    sys.exit(2)
