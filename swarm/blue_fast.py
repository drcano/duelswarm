"""Tiered blue — the deterministic FAST TIER that fights (Brick 2, DUELSWARM_LIQUID_SPEC §5.2).

Architectural law: liquid agents propose; the deterministic floor disposes; **nothing
in the fast path is an LLM**. This module imports no router/llm by design
(`swarm/live_blue_agent.py`'s selftest asserts it). The LLM *slow* tier (`swarm/blue_llm.py`)
correlates over time on a background thread; it is not in this path.

Blue UTILITIES — the deterministic detector + metrics the ONE blue engine runs on. The FIGHT
itself is the one engine (`live_blue_agent.run_blue_fight`); this module holds no fight loop
(the old fast-tier fight loop was retired and every caller is on `run_blue_fight`). Jobs:
  * `detect_kill_chain` — detect on the kill-chain STRUCTURE of the spine stream
    (gated actions + observer-CONFIRMED state transitions), independent of payload
    bytes. The confirmed transitions (foothold/lateral/exfil from `state.mutate`) are
    observer-produced, so they cannot be evaded by obfuscating the payload — which is
    exactly where the regex byte detector (`blue_detect._detect_blind`, now HEURISTIC
    defense-in-depth) fails.
  * `compare_detectors` — structure-vs-bytes: how many obfuscated variants each tier catches.
  * `_sim_contain` — the default SIM containment effect `run_blue_fight` injects offline.
  * `mttc_mttd` / `survive_the_fix` — the IR metrics (MTTD/MTTC; RvB TDSR/SDR: reward only when
    the fix works AND the service survives; penalize self-inflicted availability loss).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/blue_fast.py`

from swarm import spine

# Kill-chain stage by ATT&CK technique (structure, not bytes) and by confirmed state.
_STAGE_BY_TECH = {
    "T1595": "recon", "T1046": "recon", "T1083": "discovery",
    "T1190": "initial_access", "T1210": "initial_access",
    "T1078": "lateral_movement", "T1021": "lateral_movement", "T1550.002": "lateral_movement",
    "T1003": "credential_access", "T1558": "credential_access", "T1558.003": "credential_access",
    "T1213": "collection", "T1005": "collection",
    "T1560": "collection", "T1053": "persistence", "T1505.003": "persistence",
    "T1071": "command_and_control",
    "T1070": "defense_evasion", "T1562": "defense_evasion",   # log-clearing / impair-defenses (tamper)
    "T1611": "privilege_escalation",
}
_STAGE_BY_STATE = {"foothold": "initial_access", "lateral": "lateral_movement",
                   "exfil": "exfiltration"}


def detect_kill_chain(entries):
    """Behavioral detections from the spine STRUCTURE — payload-byte-independent.

    Two structural signals, neither a byte signature:
      - a gated red action whose technique maps to a kill-chain stage;
      - an observer-CONFIRMED state transition (`state.mutate`) — the un-fakeable one.
    """
    dets = []
    for e in entries:
        action, d, actor = e.get("action"), e.get("data") or {}, e.get("actor")
        if actor == "red" and action == "gate.allow":
            tech = d.get("technique") or d.get("attack")
            stage = _STAGE_BY_TECH.get(tech)
            if stage:
                dets.append({"seq": e.get("seq"), "stage": stage, "technique": tech,
                             "target": d.get("target"), "confirmed": False,
                             "basis": "gated-action-structure", "d3fend": "D3-DA"})
        elif action == "state.mutate" and d.get("state") in _STAGE_BY_STATE:
            dets.append({"seq": e.get("seq"), "stage": _STAGE_BY_STATE[d["state"]],
                         "technique": d.get("technique"), "target": d.get("dst"),
                         "confirmed": True, "basis": "confirmed-state-transition",
                         "d3fend": "D3-DA"})
    return dets


def compare_detectors(logs):
    """For a list of event-lists (byte-variants of one technique): how many the
    behavioral detector catches vs the regex byte detector. Reproduces the prototype
    result (structure catches all variants; regex catches ~one)."""
    from swarm.blue_detect import _detect_blind

    class _L:   # _detect_blind wants a .entries() shim
        def __init__(self, e): self._e = e
        def entries(self): return self._e

    behavioral = sum(1 for e in logs
                     if any(d["stage"] == "initial_access" for d in detect_kill_chain(e)))
    regex = sum(1 for e in logs if _detect_blind(_L(e)))
    return {"behavioral": behavioral, "regex": regex, "n": len(logs)}


def _sim_contain(container):
    """SIMULATED containment for the offline loop/proof (no Docker): the call
    'succeeds' and the range will confirm the beacon stopped. Real runs pass
    blue_contain.contain_host instead."""
    return {"contained": True, "host": container, "action": "network-disconnect",
            "fidelity": "SIMULATED"}


def _first(entries, pred):
    return min((e.get("seq") for e in entries if pred(e)), default=None)


def mttc_mttd(entries):
    """MTTD (confirmed-compromise -> detection) and MTTC (detection -> CONFIRMED
    containment), in event-step units. The confirmed containment is the observable
    (beacon stops), so MTTC reflects a real action, not narration — and detection
    precedes containment, so the MTTC<MTTD inversion (the narration tell) is gone."""
    def _st(e, s):
        return e.get("action") == "state.mutate" and (e.get("data") or {}).get("state") == s

    first_comp = _first(entries, lambda e: _st(e, "foothold") or _st(e, "lateral"))
    first_det = _first(entries, lambda e: e.get("action") == "detect.killchain")
    first_contain = _first(entries, lambda e: _st(e, "contained"))
    mttd = (first_det - first_comp) if (first_comp is not None and first_det is not None
                                        and first_det >= first_comp) else None
    mttc = (first_contain - first_det) if (first_det is not None and first_contain is not None
                                           and first_contain >= first_det) else None
    inversion = (first_det is not None and first_contain is not None
                 and first_contain < first_det)
    return {"mttd_steps": mttd, "mttc_steps": mttc, "first_compromise": first_comp,
            "first_detection": first_det, "first_confirmed_containment": first_contain,
            "containment_confirmed": first_contain is not None,
            "mttc_lt_mttd_inversion": inversion}


def survive_the_fix(entries, in_scope):
    """RvB TDSR/SDR (spec §5.2): reward only when the fix WORKS and the service SURVIVES.

    TDSR = confirmed-contained compromised hosts / compromised hosts.
    SDR  = clean in-scope hosts blue disrupted / in-scope hosts (self-inflicted loss).
    A defender that DoSes a clean host to 'win' scores strictly lower than a targeted fix.
    """
    def _dst(e):
        return (e.get("data") or {}).get("dst")

    def _state(e, s):
        return e.get("action") == "state.mutate" and (e.get("data") or {}).get("state") == s

    compromised = {_dst(e) for e in entries if _state(e, "foothold") or _state(e, "lateral")}
    contained = {_dst(e) for e in entries if _state(e, "contained")}
    in_scope = set(in_scope)
    hit = compromised & contained
    collateral = (contained - compromised) & in_scope      # clean hosts blue knocked out
    tdsr = len(hit) / len(compromised) if compromised else 0.0
    sdr = len(collateral) / len(in_scope) if in_scope else 0.0
    return {"tdsr": round(tdsr, 3), "sdr": round(sdr, 3),
            "score": round(tdsr - sdr, 3),
            "collateral": sorted(collateral),
            "survived": tdsr == 1.0 and not collateral}


if __name__ == "__main__":  # self-check: structure beats bytes; fight is confirmed; survive
    from swarm.eventlog import EventLog
    import tempfile

    # ── A: kill-chain structure catches byte-variants the regex misses ──
    def _variant(payload, confirmed_foothold=True):
        ev = [
            {"seq": 0, "actor": "system", "action": "scope", "data": {"in_scope": ["struts"]}},
            {"seq": 1, "actor": "red", "action": "gate.allow",
             "data": {"tool": "exploit", "target": "struts", "technique": "T1190",
                      "command": payload, "output": payload}},
        ]
        if confirmed_foothold:
            ev += [
                {"seq": 2, "actor": "range", "action": "confirm",
                 "data": {"confirms": "foothold", "dst": "struts"}},
                {"seq": 3, "actor": "red", "action": "state.mutate",
                 "data": {"state": "foothold", "dst": "struts", "via_confirm": 2}},
            ]
        return ev

    # 8 variants of the SAME T1190 RCE: only one carries a plaintext regex signature,
    # the other seven are obfuscated bytes — but all share the kill-chain structure.
    variants = [
        _variant("ProcessBuilder('/bin/sh')"),                  # regex hits this one
        _variant("%50rocess%42uilder base64:cadd"),             # obfuscated
        _variant("\\u0050rocessBuilder unicode-escaped"),
        _variant("eval(atob('cHJvY2Vzcw=='))"),
        _variant("python -c 'import os;os.system(chr(105))'"),
        _variant("gzip|base64 staged blob"),
        _variant("${jndi:ldap} generic marshaller"),
        _variant("hex:2f62696e2f7368 spawn"),
    ]
    cmp = compare_detectors(variants)
    assert cmp["behavioral"] == 8, cmp
    assert cmp["regex"] <= 2 and cmp["regex"] < cmp["behavioral"], cmp

    # ── B/C: the IR METRICS over a confirmed-containment chain. The FIGHT itself is the one engine
    # (live_blue_agent.run_blue_fight, proven there); here we test the metric utilities on a
    # hand-built chain — a confirmed red foothold + a confirmed blue containment observable (the same
    # spine confirm/mutate the one engine emits), so the metrics have real, un-narrated input.
    tf = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tf.close()
    log = EventLog(tf.name)
    log.append("system", "scope", {"in_scope": ["struts", "db"]})
    log.append("red", "gate.allow", {"tool": "exploit", "target": "struts", "technique": "T1190"})
    _cf = log.append("range", "confirm", {"confirms": "foothold", "dst": "struts"})
    log.append("red", "state.mutate", {"state": "foothold", "dst": "struts", "via_confirm": _cf["seq"]})
    log.append("blue", "detect.killchain", {"detections": 1, "stages": ["initial_access"]})
    log.append("blue", "blue.contain", {"host": "struts", "action": "network-disconnect", "d3fend": "D3-NI"})
    _ccf = spine.confirm(log, "contained", "struts", observed_by="range", simulated=True,
                         method="range responder: beacon from host ceased after disconnect")
    spine.mutate(log, "blue", "contained", "struts", _ccf["seq"], technique="D3-NI")
    E = log.entries()
    # containment is a confirmed observable, not a bare narration
    assert any(e["action"] == "state.mutate" and e["data"]["state"] == "contained"
               and e["data"]["dst"] == "struts" for e in E)
    m = mttc_mttd(E)
    assert m["containment_confirmed"] and not m["mttc_lt_mttd_inversion"], m
    assert m["first_detection"] <= m["first_confirmed_containment"], m

    # survive-the-fix: the targeted fix survives; a self-DoS on a clean host scores lower
    s_targeted = survive_the_fix(E, in_scope=["struts", "db"])
    assert s_targeted["survived"] and s_targeted["sdr"] == 0.0, s_targeted
    selfdos = list(E) + [
        {"seq": 99, "actor": "range", "action": "confirm", "data": {"confirms": "contained", "dst": "db"}},
        {"seq": 100, "actor": "blue", "action": "state.mutate",
         "data": {"state": "contained", "dst": "db", "via_confirm": 99}},  # db was never compromised
    ]
    s_dos = survive_the_fix(selfdos, in_scope=["struts", "db"])
    assert not s_dos["survived"] and s_dos["score"] < s_targeted["score"], (s_dos, s_targeted)

    Path(tf.name).unlink()
    print("blue_fast ok (kill-chain structure 8/8 vs regex; containment is a confirmed "
          "observable; MTTC real, no inversion; self-DoS scored below the targeted fix)")
