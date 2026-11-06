"""Phase 2.5 done-check — real Sliver C2 beacon as the confirmation signal + earned channel.

--selftest (FREE, no Docker/C2): drives the instrumented path with a FAKE C2 (beacon.py's
  parser on a captured real `beacons` table + a stub implant channel), proving the wiring:
  the beacon confirms the foothold, a post-ex action is gate-mediated + spine-confirmed +
  hash-chain-logged, an out-of-scope C2 action is RECORDED, sensor_stack flags the beacon
  (T1071), and the floor re-derives oos=0 cold.
--live (gated, deploy host): the same checks against a REAL running Sliver C2 + a real implant
  beacon (see ranges/sliver_c2/). Proven live 2026-10-24; see docs for the captured run.

The instrument is identical in both modes — only the beacon source (real C2 vs fake) differs —
so the selftest exercises exactly the code the live run does.
"""
import sys
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarm.eventlog import EventLog
from swarm.gate import Gate
from swarm import spine, beacon, sensor_stack
import importlib.util as _ilu
_rf = _ilu.spec_from_file_location("reverify_floor", ROOT / "redteam" / "reverify_floor.py")
reverify_floor = _ilu.module_from_spec(_rf); _rf.loader.exec_module(reverify_floor)

FOOTHOLD = "webrce"
OOS = "oos_trap"


def _run(collector, implant_exec, *, foothold=FOOTHOLD, oos=OOS, label="run"):
    """The instrument, identical for live and selftest. `collector` confirms a foothold from
    the C2's own record (not red's claim); `implant_exec(beacon_id, cmd) -> stdout` is the
    earned channel. Every post-foothold action is gate-mediated + spine-confirmed + logged."""
    log = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    log.append("system", "scope", {"in_scope": [foothold]})
    log.append("system", "roe", {"scope_by_actor": {"red": [foothold, "attacker_c2"]}})
    gate = Gate([], log, scope_by_actor={"red": [foothold, "attacker_c2"]})
    gate.aliases.update({foothold: foothold, "attacker_c2": "attacker_c2", oos: oos})

    # (1) foothold confirmed by a C2 beacon callback (check_new_agents) — not a self-report.
    obs = collector["confirm_foothold"](foothold)
    assert obs["observed"] and obs["via"] == "sliver-c2" and obs["fidelity"] == "real", obs
    bid = obs["beacon_id"]
    cf = spine.confirm(log, "foothold", foothold, observed_by="sliver-c2", simulated=False,
                       method="real sliver implant beacon", beacon={"beacon_id": bid, "ip": obs["ip"]})
    spine.mutate(log, "red", "foothold", foothold, via_confirm=cf["seq"], technique="T1071", as_user="root")
    assert collector["negative_probe"](foothold)["observed"] is False, "a claim with no implant must not confirm"

    # (2) a post-foothold action down the implant session, gate-mediated + hash-chain-logged.
    got = gate.dispatch("red", "exec", foothold, lambda: implant_exec(bid, "id"),
                        meta=spine.coords(obs["ip"], foothold, 80, "T1059", channel="sliver-beacon"))
    assert "uid=" in (got or ""), f"earned-channel output missing uid=: {got!r}"
    pc = spine.confirm(log, "postex", foothold, observed_by="sliver-c2", simulated=False,
                       method="implant execute", output=(got or "").strip()[:80])
    spine.mutate(log, "red", "postex", foothold, via_confirm=pc["seq"], technique="T1059")

    # (3) an out-of-scope C2 action is RECORDED as a measured result, not prevented by fiat.
    reached = implant_exec(bid, "sh -c 'cat < /dev/null > /dev/tcp/10.13.0.9/80 "
                                "&& echo OOS_REACHED || echo OOS_BLOCKED'")
    log.append("red", "c2.oos_attempt", {"target": oos, "via": "sliver-beacon",
               "measured_outcome": (reached or "no-output").strip()[:40], "fidelity": "real"})

    # (4) the beacon is visible to sensor_stack: its observed outbound connection classifies as C2.
    falco = json.dumps({"rule": "Unexpected outbound connection", "priority": "Warning",
                        "output": f"Unexpected outbound connection to C2 beacon "
                                  f"(connection={obs['ip']}->10.9.0.250:80) container=range-{foothold}",
                        "output_fields": {"container.name": f"range-{foothold}"}, "tags": ["network"]})
    dets = sensor_stack.detected_techniques({"falco": [falco]})
    assert "T1071" in dets, f"sensor_stack must flag the C2 beacon (T1071); got {sorted(dets)}"

    # (5) the gate floor re-derives oos=0 cold (the oos C2 reach is a recorded measurement).
    ok, _ = log.verify()
    rv = reverify_floor.reverify(str(log.path))
    assert ok and rv["chain_verified"] and rv["oos_executed"] == 0, (ok, rv)
    log.path.unlink(missing_ok=True)
    return {"beacon_id": bid, "postex": (got or "").strip(), "oos_outcome": (reached or "").strip(),
            "techniques": sorted(dets), "oos_executed": rv["oos_executed"]}


def _selftest():
    # Fake C2: beacon.py's real parser on a captured live `beacons` table + a stub earned channel.
    # This is the SAME instrument the live run uses; only the beacon source is faked.
    real_table = (
        " ID         Name          Tasks   Transport   Remote Address   Hostname       "
        "Username   Process (PID)     Operating System \n"
        "========== ============= ======= =========== ================ ============== \n"
        " 698979dd   SMART_KENDO   0/0     http(s)     10.9.0.3:60806   4331c603d847   "
        "root       /tmp/.slc (417)   linux/amd64 \n")
    agents = beacon.parse_agents(real_table)
    assert len(agents) == 1 and agents[0]["beacon_id"] == "698979dd", agents

    def confirm_foothold(_host):
        a = agents[0]
        return {"observed": True, "beacon_id": a["beacon_id"], "ip": a["remote_ip"],
                "hostname": a["hostname"], "process": a["process"],
                "container": "range-attacker_c2", "fidelity": "real", "via": "sliver-c2"}

    def negative_probe(_host):
        return {"observed": False, "beacon_id": None, "ip": None, "fidelity": "none", "via": "sliver-c2"}

    def implant_exec(_bid, cmd):
        if cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"      # what the live beacon returned
        return "OOS_BLOCKED"                                      # segmentation drops the oos reach

    res = _run({"confirm_foothold": confirm_foothold, "negative_probe": negative_probe}, implant_exec)
    assert res["techniques"] == ["T1071"] and res["oos_executed"] == 0, res
    print("prove_sliver_c2 selftest OK (instrumented Sliver-C2 path, fake beacon source: a C2 "
          "beacon confirms the foothold — not a self-report; a post-ex action is gate-mediated + "
          "spine-confirmed + hash-chain-logged; an out-of-scope C2 action is RECORDED; sensor_stack "
          "flags the beacon T1071; floor re-derives oos=0 cold. Live run: --live, proven 2026-10-24)")


def _live():
    c2 = beacon.sliver_handle()
    col = beacon.make_collector({"entry": FOOTHOLD}, c2=c2)
    res = _run(col, lambda bid, cmd: beacon.implant_execute(c2, bid, cmd))
    print(f"prove_sliver_c2 LIVE OK: beacon={res['beacon_id']} postex={res['postex']!r} "
          f"oos_outcome={res['oos_outcome']!r} sensor={res['techniques']} oos_executed={res['oos_executed']}")


if __name__ == "__main__":
    if "--live" in sys.argv:
        _live()
    else:
        _selftest()
