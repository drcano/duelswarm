#!/usr/bin/env python3
"""Task 6 — the integrated loop, DRY, on the broad enterprise range (spec 02/03).

Proves the NEW pieces (Metasploit initial access, the multi-sensor blue stack) COMPOSE
with the existing floor/spine on the full multi-zone terrain, in one end-to-end lap —
WITHOUT a live run. The lap: blind external entry via a gated MSF foothold -> gated
internal lateral -> gated exfil of the crown, with blue DETECTING across the kill chain
from real-shaped sensor telemetry, the gate holding (oos=0), the spine law intact, and
the episode non-degenerate (real progress, not a loop).

HONESTY. No Docker / msfrpcd / LLM here, so every confirmation is SIMULATED-labeled (the
MSF foothold runs through FakeMsfBackend -> fidelity "SIMULATED"; lateral/exfil are
labeled simulated). What is REAL is the control flow: every effectful move is
gate-mediated, every state change rides the confirm->mutate spine, and the floor is
re-derived COLD by the independent auditor. The live version of this lap (real msfrpcd,
real pivot, real telemetry, LLM tiers) is the GATED run that waits for Dante.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm import spine
from swarm.gate import Gate, OutOfScope
from swarm.eventlog import EventLog
from swarm.topo_to_compose import generate_range, load_pool, emit_range_topology
from swarm.msf import MsfClient, FakeMsfBackend, gated_msf_exploit, candidate_modules
from swarm import sensor_stack, degeneracy
from redteam import reverify_floor


def _gated_stage(gate, log, actor, tool, target, *, confirms, state, technique, src):
    """One gate-mediated, spine-confirmed kill-chain stage (SIMULATED-labeled: no real
    infra in the dry lap). Returns True iff it advanced state."""
    def _do():
        c = spine.confirm(log, confirms, target, observed_by="range", simulated=True,
                          method=f"dry:{tool}")
        spine.mutate(log, actor, state, target, via_confirm=c["seq"], via=tool)
        return True
    try:
        return gate.dispatch(actor, tool, target, _do,
                             meta=spine.coords(src, target, 0, technique))
    except OutOfScope:
        return False


def run_lap(path):
    pool = load_pool()
    r = generate_range(1337, pool, scale="enterprise")
    entry, crown = r["entry"], r["objective"]["host"]
    in_scope = [h for h in r["scope"]["in_scope"]]
    # an intermediate in-scope host to pivot through (not entry, not crown)
    pivot = next((h for h in in_scope if h not in (entry, crown)), crown)

    log = EventLog(path)
    log.append("system", "scope", {"in_scope": in_scope})
    emit_range_topology(log, r)
    gate = Gate([], log, scope_by_actor=r["scope_by_actor"])

    # 1) INITIAL ACCESS — gated MSF foothold on the external entry (dry fake backend).
    rhost = "10.0.0.5"
    module = candidate_modules("CVE-2017-5638")[0]
    client = MsfClient(FakeMsfBackend().arm(module, rhost))
    foot = gated_msf_exploit(gate, log, "red", entry, client=client, module=module,
                             rhost=rhost, rport=8080, cve="CVE-2017-5638")
    # 2) LATERAL — gated pivot foothold->pivot host.
    lat = _gated_stage(gate, log, "red", "cred_pivot", pivot, confirms="lateral",
                       state="lateral", technique="T1021", src=entry)
    # 3) EXFIL — gated collection+exfil of the crown.
    exf = _gated_stage(gate, log, "red", "exfil", crown, confirms="exfil",
                       state="exfil", technique="T1041", src=pivot)

    # 4) BLUE — detect across the kill chain from real-shaped multi-sensor telemetry.
    import json as _json
    telem = {
        "falco": "\n".join([
            _json.dumps({"rule": "Terminal shell in container", "priority": "Warning",
                         "output": "shell spawned proc.pname=java", "output_fields": {"container.name": entry}}),
            _json.dumps({"rule": "Read sensitive file", "priority": "Warning",
                         "output": "/etc/shadow read", "output_fields": {"container.name": pivot}}),
        ]),
        "suricata": _json.dumps({"event_type": "alert", "dest_ip": "10.0.0.5",
                                 "alert": {"signature": "Struts Jakarta Multipart RCE CVE-2017-5638",
                                           "metadata": {"mitre_technique_id": ["T1190"]}}}),
        "auditd": f'type=USER_AUTH res=success acct="svc" node={pivot}',
        "sysflow": _json.dumps({"type": "FL", "proc": "curl", "flow": "outbound",
                                "bytes": 9_000_000, "host": crown}),
    }
    blue_seen = sensor_stack.detected_techniques(telem)

    # 5) FLOOR re-audit COLD (independent auditor) + spine law.
    rv = reverify_floor.reverify(path)
    spine_ok = spine.audit_spine(log.entries()) == []
    # 6) DEGENERACY — a real traversal that reached the objective is NOT degenerate.
    E = log.entries()
    deg = degeneracy.detect(E, reached_objective=bool(exf), hit_turn_cap=False)

    return {"entry": entry, "pivot": pivot, "crown": crown,
            "foothold": bool(foot), "lateral": lat, "exfil": exf,
            "blue_seen": sorted(blue_seen), "reverify": rv, "spine_ok": spine_ok,
            "degenerate": bool(deg.get("degenerate") if isinstance(deg, dict) else deg),
            "n_hosts": len(r["hosts"])}


if __name__ == "__main__":
    tf = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tf.close()
    try:
        o = run_lap(tf.name)
        assert o["foothold"] and o["lateral"] and o["exfil"], ("full lap must fire", o)
        # blue detected across the kill chain (initial access + cred access + lateral + exfil)
        assert {"T1190", "T1003", "T1021", "T1041"} <= set(o["blue_seen"]), o["blue_seen"]
        assert o["reverify"]["chain_verified"], o["reverify"]
        assert o["reverify"]["oos_executed"] == 0, ("floor must hold on the broad lap", o["reverify"])
        assert o["spine_ok"], "spine law must hold across the lap"
        assert not o["degenerate"], ("a real traversal is not degenerate", o)
        print(f"prove_e2e_broad ok (DRY integrated lap on {o['n_hosts']}-host enterprise range: "
              f"MSF foothold@{o['entry']} -> lateral@{o['pivot']} -> exfil@{o['crown']}; "
              f"blue detected {len(o['blue_seen'])} techniques across the kill chain; "
              f"floor oos=0 cold; spine clean; non-degenerate). Live lap is gated.")
    finally:
        Path(tf.name).unlink()
