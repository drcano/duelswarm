"""Blue response-frontier service (step 3) — the defensive mirror of
`attack_graph_service.FrontierService`.

Incalmo gives the attacker a frontier of high-level moves over its belief; blue had
every defensive EXECUTOR (contain/terrain-shift/counter-recon/decoy/restore) but no
frontier to choose them over — it ran a fixed detect->triage->contain. This enumerates
the defensive moves available from blue's LOSSY sensor belief (the suspected-compromised
hosts it actually observed, never red's gate.allow), so the blue loop can CHOOSE a
response each turn, mis-attribute, and lose — symmetric to red.

Belief here is deliberately thin (the counted path's blue sees only the lossy sensor
view, not a topology): a set of observed suspected-compromised hosts, plus what blue has
already investigated / contained. Every verb it emits is backed by a real gate-mediated
executor (blue's offense — counter-recon — is under the SAME floor as red).
"""


class BlueResponseFrontier:
    def __init__(self):
        self._actioned = set()     # {(action, target)} — dedup, no response retaken

    def record_action(self, action, target):
        self._actioned.add((action, target))

    def taken(self, action, target):
        return (action, target) in self._actioned

    def frontier(self, observed, *, contained=(), investigated=()):
        """Ordered defensive moves from blue's lossy belief. `observed` = suspected-
        compromised hosts the sensor surfaced; `contained`/`investigated` = blue's own
        prior responses (read from its action log). Correlation comes first (understand
        before acting), then containment of a suspected host, then hardening the terrain
        once something is held, then gated counter-recon."""
        observed, contained, investigated = set(observed), set(contained), set(investigated)
        moves = []
        # 1) investigate/correlate a suspected host blue has not yet triaged.
        for h in sorted(observed - investigated):
            if not self.taken("investigate", h):
                moves.append({"action": "investigate", "target": h,
                              "reason": "correlate telemetry before responding"})
        # 2) contain (revoke the compromised credential) a suspected, not-contained host.
        for h in sorted(observed - contained):
            if not self.taken("contain", h):
                moves.append({"action": "contain", "target": h,
                              "reason": "suspected lateral movement — revoke credential"})
        # 3) terrain-shift (rotate creds / MTD) to harden what remains, once blue holds
        #    at least one containment (a response that only makes sense mid-incident).
        if contained:
            for h in sorted(observed - contained):
                if not self.taken("terrain_shift", h):
                    moves.append({"action": "terrain_shift", "target": h,
                                  "reason": "rotate credentials to sever a re-pivot"})
        # 4) counter-recon (gated blue OFFENSE — under the same floor as red) once there
        #    is an incident to attribute.
        if observed:
            for h in sorted(observed):
                if not self.taken("counter_recon", h):
                    moves.append({"action": "counter_recon", "target": h,
                                  "reason": "fingerprint/attribute the attacker infrastructure"})
        return moves


if __name__ == "__main__":  # self-check: frontier grows/shrinks with blue's belief
    fr = BlueResponseFrontier()
    # empty belief -> no response (nothing observed to act on).
    assert fr.frontier(set()) == []
    # one observed host -> investigate + contain + counter_recon (no terrain yet: nothing
    # contained). Order: investigate first, then contain, then counter_recon.
    f = fr.frontier({"db1"})
    kinds = [m["action"] for m in f]
    assert kinds[0] == "investigate" and "contain" in kinds and "counter_recon" in kinds
    assert "terrain_shift" not in kinds, "no terrain-shift before any containment"
    # after containing db1, terrain-shift appears for the remaining suspected host db2.
    f2 = fr.frontier({"db1", "db2"}, contained={"db1"})
    assert any(m["action"] == "terrain_shift" and m["target"] == "db2" for m in f2), f2
    assert all(m["target"] != "db1" for m in f2 if m["action"] == "contain"), "contained host retires"
    # dedup: a taken response is not re-offered.
    fr.record_action("contain", "db2")
    assert not any(m["action"] == "contain" and m["target"] == "db2"
                   for m in fr.frontier({"db1", "db2"}, contained={"db1"}))
    print("blue_response ok (defensive frontier from lossy belief: investigate->contain->"
          "terrain_shift->counter_recon; contained host retires; terrain only mid-incident; dedup)")
