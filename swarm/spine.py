"""The confirmed-observable spine (Brick 0, DUELSWARM_LIQUID_SPEC §3).

The single most important law in the system, promoted from Incalmo's confirmation
design to a universal rule:

    No population's state ever moves on an agent's word. State mutates ONLY on a
    confirmed, independently-observed, logged event.

Two primitives:
  * `coords(...)`  — real action coordinates (src_ip -> dst_ip:dst_port + technique)
    attached to every mediated action's `meta`, so no event in the log is a bare
    label like "red attacks db".
  * `confirm(...)` / `mutate(...)` — a state-changing outcome (foothold, lateral
    move, exfil, containment) is recorded by `mutate()` ONLY with a reference to a
    prior `confirm()` event. The confirmation is emitted by an OBSERVER actor (the
    target/range responder), never by the acting agent. For the current simulated
    range it is tagged `SIMULATED`; the target to converge on (a later brick) is a
    real implant beacon/callback, as in Incalmo's `check_new_agents`.

`audit_spine(entries)` re-derives, from the raw log, that every state mutation has
a matching prior confirmation from an observer (never a red/blue self-report).
"""

# (no baked port table: coords() takes dst_port as an argument, sourced from the range/log.)


def coords(src_ip, dst_ip, dst_port, technique, **extra):
    """Real coordinates for a mediated action's `meta` (SPEC §3): every action is a
    real invocation with a source, a destination, a port and a method."""
    return {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
            "technique": technique, **extra}


def confirm(log, confirms, dst, *, observed_by="range", simulated=True,
            method="", beacon=None, **data):
    """Emit a confirmation event — the ONLY thing that may advance state.

    `confirms`: what was confirmed ("foothold", "exfil", "contained", ...).
    `dst`: the host/target it concerns. `observed_by`: the observer (the target/
    range responder, NOT the acting agent). `simulated`: True tags it SIMULATED.

    `beacon` (L3): a real out-of-band observation dict from `swarm.beacon`
    (`{observed, ip, beacon_id, container}`). When it is present and `observed`, the
    confirmation is grounded in a brand-new implant callback on the booted target
    (Incalmo `check_new_agents`) — fidelity becomes "real", the observer is the
    collector, and the real beacon source is recorded. Absent/unobserved, the caller
    keeps the labeled SIMULATED range responder (dry / no-Docker).
    """
    if beacon and beacon.get("observed"):
        simulated = False
        observed_by = "collector"
        data["beacon"] = {k: beacon.get(k) for k in ("beacon_id", "ip", "container")}
    rec = {"confirms": confirms, "dst": dst, "observed_by": observed_by,
           "fidelity": "SIMULATED" if simulated else "real", "method": method, **data}
    return log.append(observed_by, "confirm", rec)


def mutate(log, actor, state, dst, via_confirm, **data):
    """Record a state-changing outcome — only ever with `via_confirm` pointing at a
    prior confirmation event's seq for the same dst. Never call this off an agent's
    self-report; call `confirm()` first and pass its seq here."""
    rec = {"state": state, "dst": dst, "via_confirm": via_confirm, **data}
    return log.append(actor, "state.mutate", rec)


def audit_spine(entries):
    """Re-derive the spine law from the raw log. Returns a list of violations
    (empty == clean): a mutation with no / mismatched / non-prior confirmation, or
    a confirmation an agent issued about itself (a self-report masquerading as an
    observation)."""
    confirms = {}      # seq -> (dst, observed_by)
    violations = []
    for e in entries:
        action, data, seq = e.get("action"), e.get("data") or {}, e.get("seq")
        if action == "confirm":
            confirms[seq] = (data.get("dst"), e.get("actor"))
            if e.get("actor") in ("red", "blue"):
                violations.append({"kind": "self-confirmed", "seq": seq})
        elif action == "state.mutate":
            vc = data.get("via_confirm")
            if vc is None or vc not in confirms:
                violations.append({"kind": "unconfirmed-mutation", "seq": seq,
                                   "state": data.get("state"), "dst": data.get("dst")})
                continue
            cdst, _ = confirms[vc]
            if cdst != data.get("dst"):
                violations.append({"kind": "confirmation-dst-mismatch", "seq": seq})
            if vc >= seq:
                violations.append({"kind": "confirmation-not-prior", "seq": seq})
    return violations


def actions_missing_coords(entries, actors=("red", "judge")):
    """gate.allow events (the mediated actions) for `actors` that lack real
    coordinates. Returns offenders (empty == every action is coordinate-bearing)."""
    need = ("src_ip", "dst_ip", "dst_port", "technique")
    bad = []
    for e in entries:
        if e.get("action") == "gate.allow" and e.get("actor") in actors:
            d = e.get("data") or {}
            if any(d.get(k) in (None, "", []) for k in need):
                bad.append({"seq": e.get("seq"), "tool": d.get("tool"),
                            "missing": [k for k in need if d.get(k) in (None, "", [])]})
    return bad


if __name__ == "__main__":  # self-check: the law holds and catches self-reports
    class _Log:
        def __init__(self): self.e = []
        def append(self, actor, action, data=None):
            rec = {"seq": len(self.e), "actor": actor, "action": action, "data": data or {}}
            self.e.append(rec); return rec

    log = _Log()
    # coordinates are real, not labels
    c = coords("10.9.0.2", "10.10.0.2", 8080, "T1190", cve="CVE-2017-5638")
    assert c["src_ip"] and c["dst_ip"] and c["dst_port"] and c["technique"]

    # a confirmed mutation is clean
    cf = confirm(log, "foothold", "struts", observed_by="range",
                 method="range responder: new shell session observed")
    assert cf["actor"] == "range" and cf["data"]["fidelity"] == "SIMULATED"
    mutate(log, "red", "foothold", "struts", via_confirm=cf["seq"])
    assert audit_spine(log.e) == [], audit_spine(log.e)

    # an UNCONFIRMED mutation is caught
    bad = _Log()
    mutate(bad, "red", "foothold", "db", via_confirm=None)
    v = audit_spine(bad.e)
    assert any(x["kind"] == "unconfirmed-mutation" for x in v), v

    # a mutation pointing at a confirmation RED issued about itself is caught
    bad2 = _Log()
    selfc = bad2.append("red", "confirm", {"confirms": "foothold", "dst": "db"})
    mutate(bad2, "red", "foothold", "db", via_confirm=selfc["seq"])
    v2 = audit_spine(bad2.e)
    assert any(x["kind"] == "self-confirmed" for x in v2), v2

    # a mutation whose confirmation concerns a DIFFERENT dst is caught
    bad3 = _Log()
    cf3 = confirm(bad3, "foothold", "struts")
    mutate(bad3, "red", "foothold", "db", via_confirm=cf3["seq"])
    assert any(x["kind"] == "confirmation-dst-mismatch" for x in audit_spine(bad3.e))

    # coordinate checker flags a bare-label gate.allow
    nolog = _Log()
    nolog.append("red", "gate.allow", {"tool": "exploit", "target": "db"})
    assert actions_missing_coords(nolog.e), "should flag a coordinate-less action"
    assert not actions_missing_coords(log.e)   # the confirmed path logged no gate.allow

    print("spine ok (coordinates real; state moves only on an observer's confirmation)")
