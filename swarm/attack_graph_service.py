"""Attack-graph frontier service (Brick 1, DUELSWARM_LIQUID_SPEC §5.1).

Computes red's next moves from its DISCOVERED belief state (swarm.env_state),
never from the range ground truth — the Incalmo `attack_graph_service` pattern
(`get_possible_targets_from_host`, `get_possible_attack_paths`,
`find_exfiltration_path`, `record_action` dedup).

The anti-beeline property lives here: `find_exfiltration_path` returns `None` while
no crown-data host has been discovered, so there is literally nothing to beeline to
until red discovers it. The frontier of an empty belief is "enumerate from the edge".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/attack_graph_service.py`


class FrontierService:
    def __init__(self):
        self._actioned = set()     # {(action, target)} — dedup, no move is retaken

    def record_action(self, action, target):
        self._actioned.add((action, target))

    def taken(self, action, target):
        return (action, target) in self._actioned

    def possible_targets_from_host(self, env, host):
        """Discovered hosts reachable to act on from `host` that red has not yet
        actioned. (Reachability red has observed = the hosts in belief; the gate +
        substrate enforce the real routing when red actually dispatches.)"""
        return [n for n in env.known_hosts()
                if n != host and not self.taken("exploit", n)]

    def get_possible_attack_paths(self, env):
        return self.frontier(env)

    def frontier(self, env):
        """Ordered candidate next actions from the current belief. Enumeration of a
        not-yet-enumerated known host comes first (discovery grows belief; the SIM seat
        live_red.SimFrontierRouter and the mh generators take moves[0], so recon-first is the
        anti-beeline invariant);
        then exploitation of a discovered service; credential-pivot and privesc moves off
        the discovered IR (M2 — Incalmo-shaped works_on + SudoBaron/WriteablePasswd);
        then exfil — ONLY once a crown-data host has been discovered.

        Each move's `reason` is a neutral phase label naming what the move is; it
        instructs nothing (recon stays moves[0], the list order and generation are
        unchanged, so every moves[0] caller is unaffected). Exfil is offered on
        discovery, with the gate and the one engine's turn loop enforcing the foothold.
        Anti-grazing rests on the structural foothold guard in
        prove_n2n3_tiered.observe plus the existing stall cap, not on prompt steering."""
        moves = []
        # 1) enumerate every known host we have not yet reconned — this is what red
        #    does first and keeps doing while belief is thin (no beeline).
        for name in sorted(env.known_hosts()):
            if not self.taken("recon", name):
                moves.append({"action": "recon", "target": name,
                              "reason": "recon: enumerate for neighbors, services, data"})
        # 1b) inner enumeration FROM a held foothold (Incalmo's vantage-parameterized
        #    Scan): a foothold opens the subnet reachable from it. Vantage-keyed, so it is
        #    a DISTINCT action from the external ("recon", host) — scanning a new subnet
        #    from a new foothold is never collapsed into a prior external scan (the
        #    seed-20 dead-end, where (recon, entry) was spent pre-foothold so inner enum
        #    could never fire). Offered only for an infected host, so it appears only
        #    after a foothold (recon-first for unknown hosts is unchanged: section 1 runs
        #    first, so external recon is still moves[0] whenever an unknown host exists).
        for name in sorted(n for n, r in env.hosts.items() if r["infected"]):
            if not self.taken("recon_from", name):
                moves.append({"action": "recon_from", "target": name,
                              "reason": f"recon_from: enumerate the subnet reachable from foothold {name}"})
        # 2) exploit a discovered service on a known, not-yet-exploited host.
        for name in sorted(env.known_hosts()):
            rec = env.hosts[name]
            if rec["services"] and not rec["infected"] and not self.taken("exploit", name):
                # show the discovered service BANNERS (port:label), not just port numbers, so the
                # planner can prioritize a vulnerable product/version over a hardened decoy.
                svc = sorted(f"{p}:{v}" for p, v in rec["services"].items())
                moves.append({"action": "exploit", "target": name,
                              "reason": f"exploit: discovered service(s) {svc}"})
        # 3) M2 — credential pivot: one path per usable (host,user) key edge from a
        #    FOOTHOLD red actually holds (Incalmo's SSHCredential.works_on). This is
        #    the gap the audit flagged: lateral movement driven by discovered creds,
        #    not just by open ports. The pivot is a lateral move, so it is deduped
        #    under ("lateral", dst_host) — one credential-driven lateral per dst.
        for src in sorted(n for n, r in env.hosts.items() if r["infected"]):
            for (sh, su, dh, du) in env.hosts[src]["ssh_keys_from"]:
                if dh == src or env.hosts.get(dh, {}).get("infected"):
                    continue
                if self.taken("lateral", dh):
                    continue
                moves.append({"action": "cred_pivot", "target": dh,
                              "from": src, "as_user": du,
                              "src_host": sh, "src_user": su,
                              "reason": f"cred_pivot: ssh key from {sh}:{su} works on {dh}:{du}"})
        # 4) M2 — privesc on a held foothold where red is not yet root (SudoBaron /
        #    WriteablePasswd). Each distinct discovered privesc vuln is one move.
        for name in sorted(n for n, r in env.hosts.items() if r["infected"]):
            rec = env.hosts[name]
            if any(info.get("root") for info in rec["users"].values()):
                continue    # already root on this foothold
            for pe in rec["privesc"]:
                key = (pe["user"], pe["to_user"], pe["vuln"])
                if self.taken("privesc", (name,) + key):
                    continue
                moves.append({"action": "privesc", "target": name,
                              "from_user": pe["user"], "to_user": pe["to_user"],
                              "vuln": pe["vuln"], "privesc_key": key,
                              "reason": f"privesc: local {pe['vuln']}: {pe['user']} -> {pe['to_user']}"})
        # 5) exfil — one move per discovered crown-data host that red has ALREADY COMPROMISED
        #    (infected). You cannot exfiltrate from a host you do not hold: gating the offer on
        #    infection means red must land a real, grounded exploit on the crown BEFORE exfil is
        #    even a candidate — no "reach the crown for free at exfil time" shortcut. (Anti-beeline
        #    unchanged: still no exfil before crown-data discovery.)
        for crown in sorted(env.crown_candidates()):
            if self.taken("exfiltrate", crown) or not env.hosts.get(crown, {}).get("infected"):
                continue
            moves.append({"action": "exfiltrate", "target": crown,
                          "reason": "exfiltrate: crown data discovered on a held host"})
        return moves

    def find_exfiltration_path(self, env):
        """A path to a discovered crown-data host, or None while the objective is
        still unknown. The None case is the whole point: red cannot target the crown
        before discovering it."""
        crowns = env.crown_candidates()
        if not crowns:
            return None
        crown = sorted(crowns)[0]
        # minimal path: the infected hosts red holds, ending at the crown.
        footholds = [n for n, r in env.hosts.items() if r["infected"]]
        return footholds + [crown] if crown not in footholds else [crown]


if __name__ == "__main__":  # self-check: empty belief => enumerate, no exfil path
    from swarm.env_state import EnvState

    fs = FrontierService()
    env = EnvState()
    # with nothing discovered there is no crown and no exfil path (no beeline).
    assert fs.find_exfiltration_path(env) is None
    assert fs.frontier(env) == [], "empty belief has no known host to act on yet"

    # discover the edge host: the frontier is to enumerate it.
    env.apply({"seq": 1, "actor": "range", "action": "discovery",
               "data": {"kind": "hosts", "from": "attacker",
                        "hosts": [{"name": "struts", "ips": ["10.10.0.2"], "services": {"8080": "http"}}]}})
    f = fs.frontier(env)
    assert any(m["action"] == "recon" and m["target"] == "struts" for m in f)
    assert fs.find_exfiltration_path(env) is None, "no crown discovered yet"

    # exploit struts, discover db + its crown data: NOW an exfil path appears.
    fs.record_action("recon", "struts")
    fs.record_action("exploit", "struts")
    env.mark_infected("struts")
    env.apply({"seq": 2, "actor": "range", "action": "discovery",
               "data": {"kind": "hosts", "from": "struts",
                        "hosts": [{"name": "db", "ips": ["10.11.0.3"], "services": {"5432": "postgres"}}]}})
    assert fs.find_exfiltration_path(env) is None, "db known but crown not yet revealed"
    env.apply({"seq": 3, "actor": "range", "action": "discovery",
               "data": {"kind": "crown_data", "host": "db"}})
    path = fs.find_exfiltration_path(env)
    assert path and path[-1] == "db", path
    # crown data discovered but db NOT yet compromised -> exfil is NOT offered (you cannot
    # exfiltrate from a host you do not hold; red must land the crown exploit first).
    assert not any(m["action"] == "exfiltrate" and m["target"] == "db" for m in fs.frontier(env))

    # dedup: a taken action is not re-proposed.
    fs.record_action("recon", "db")
    assert not any(m["action"] == "recon" and m["target"] == "db" for m in fs.frontier(env))

    # recon_from (Incalmo vantage scan): a held foothold (struts, infected above) opens
    # inner enumeration — a DISTINCT move from the already-spent external ("recon","struts"),
    # so a foothold is never a dead-end. It is deduped on its own vantage key.
    assert fs.taken("recon", "struts")  # external recon on struts was spent earlier
    assert any(m["action"] == "recon_from" and m["target"] == "struts" for m in fs.frontier(env)), \
        "a foothold must open a vantage-keyed recon_from even when external recon is spent"
    fs.record_action("recon_from", "struts")
    assert not any(m["action"] == "recon_from" and m["target"] == "struts" for m in fs.frontier(env))
    # recon_from is never offered for a host red does not hold (db not yet compromised).
    assert not any(m["action"] == "recon_from" and m["target"] == "db" for m in fs.frontier(env))
    # NOW red lands the crown exploit on db -> both exfil AND recon_from from it become available
    # (the exfil-needs-a-held-host invariant: no exfil was offered while db was merely discovered).
    env.mark_infected("db")
    f3 = fs.frontier(env)
    assert any(m["action"] == "exfiltrate" and m["target"] == "db" for m in f3), \
        "exfil must be offered once the crown is compromised"

    # ── M2: credential-pivot + privesc frontier moves. ──
    fs2 = FrontierService()
    env2 = EnvState()
    # discover + hold a webserver with an ssh key to db1 and db2, a privesc on it.
    env2.apply({"seq": 1, "actor": "range", "action": "discovery",
                "data": {"kind": "hosts", "from": "attacker",
                         "hosts": [{"name": "web", "ips": ["10.10.0.2"], "services": {"8080": "http"}}]}})
    env2.apply({"seq": 2, "actor": "red", "action": "state.mutate",
                "data": {"state": "foothold", "dst": "web", "as_user": "www-data"}})
    env2.apply({"seq": 3, "actor": "range", "action": "discovery",
                "data": {"kind": "ssh_keys", "host": "web", "username": "deploy",
                         "works_on": [{"host": "db1", "username": "dbadmin"},
                                      {"host": "db2", "username": "dbadmin"}]}})
    env2.apply({"seq": 4, "actor": "range", "action": "discovery",
                "data": {"kind": "privesc_vuln", "host": "web", "username": "www-data",
                         "to_user": "root", "vuln": "SudoBaron"}})
    f = fs2.frontier(env2)
    pivots = [m for m in f if m["action"] == "cred_pivot"]
    privs = [m for m in f if m["action"] == "privesc"]
    assert len(pivots) == 2 and {m["target"] for m in pivots} == {"db1", "db2"}, pivots
    assert len(privs) == 1 and privs[0]["vuln"] == "SudoBaron", privs
    # A cred_pivot is NOT emitted for an already-held destination.
    env2.apply({"seq": 5, "actor": "red", "action": "state.mutate",
                "data": {"state": "lateral", "dst": "db1", "as_user": "dbadmin"}})
    assert all(m["target"] != "db1" for m in fs2.frontier(env2) if m["action"] == "cred_pivot")
    # After a confirmed privesc on web, the privesc move retires (user is root).
    env2.apply({"seq": 6, "actor": "red", "action": "state.mutate",
                "data": {"state": "privesc", "dst": "web", "to_user": "root"}})
    assert not any(m["action"] == "privesc" and m["target"] == "web" for m in fs2.frontier(env2))

    # Frontier homogeneity: with ssh_keys + privesc in belief, the frontier offers
    # strictly more KINDS of moves than the baseline exploit-only menu.
    kinds = {m["action"] for m in f}
    assert {"cred_pivot", "privesc"} <= kinds, kinds

    # recon-first invariant unchanged (moves[0] callers depend on it); every move's reason
    # names its own phase and injects no preference into the menu.
    assert f[0]["action"] == "recon", f[0]           # recon still enumerated first
    for m in f:
        assert m["reason"].startswith(m["action"] + ":"), m   # every move names its phase; no preference injected

    print("attack_graph_service ok (frontier from belief; no exfil path before discovery; "
          "M2: cred_pivot + privesc moves emitted off the IR; pivots dedup by lateral dst; "
          "privesc retires when user is root; recon-first invariant held; every move names "
          "its kill-chain phase; no preference injected into the menu)")
