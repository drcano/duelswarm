"""prove_oracle — the oracle expert reference drives the ONE engine end-to-end (FREE, no paid range).

oracle_red is a PURE module (no swarm import, so leak_test's ORACLE rail covers it). This proof lives
OUTSIDE scripts/validation — it is not a validator — so it MAY import both the engine
(swarm.live_agent.run_red_agent) and the oracle router, and drive one against the other over a simulated
seam world whose tool contract is identical to the engine's own selftest (swarm/live_agent.py __main__):
exploit -> {grounded,host}, pivot -> {owned,host}, harvest -> {ssh_key_paths}, loot -> {looted}.

It proves, for free, that the GT-derived oracle script run_red_agent actually consumes drives a complete
entry -> credential-seam -> crown kill chain to `crown_looted`, owning every seam host. It does NOT score
gap-to-ceiling (that needs the full interleaved duel's state.mutate + duel.verdict, which is the PAID
run); here the claim is only that the expert reference is a working engine driver, end to end.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _simulated_seam_world(chain_ips, entry_cve, crown_ip, key_path, start_subnet):
    """A zoned fake range matching the engine's tool contract: a linear seam the oracle must walk.
    Returns (tools, owned_live) — owned_live is the live truth the proof asserts against."""
    entry_ip = chain_ips[0]
    # each owned host 'reveals' the next hop when scanned from it (discovery state, as on a live range)
    scan_from = {"self": [{"ip": entry_ip, "ports": [8080]}]}
    for a, b in zip(chain_ips, chain_ips[1:]):
        scan_from[a] = [{"ip": b, "ports": [22]}]
    exploitable = {(entry_ip, entry_cve): True}
    pivot_ok = set(zip(chain_ips, chain_ips[1:]))          # (entry,h1),(h1,h2),...,(h_{n-1},crown)
    owned_live = set()

    def t_scan(**a):
        src = a.get("from") or "self"
        if src != "self" and src not in owned_live:
            return {"error": "not owned", "hosts": []}
        return {"hosts": scan_from.get(src, [])}

    def t_fingerprint(**a):
        return {"fingerprint": "tcp/22 OpenSSH" if a.get("ip") != entry_ip
                else "Server: Apache-Coyote/1.1; /index.action [200]"}

    def t_exploit(**a):
        ok = exploitable.get((a.get("ip"), a.get("cve")), False)
        if ok:
            owned_live.add(a["ip"])
        return {"grounded": ok, "host": a.get("ip") if ok else None, "method": "msf" if ok else None}

    def t_harvest(**a):
        return {"ssh_key_paths": [key_path] if a.get("host") in owned_live else []}

    def t_pivot(**a):
        ok = (a.get("from"), a.get("to")) in pivot_ok and a.get("from") in owned_live
        if ok:
            owned_live.add(a["to"])
        return {"owned": ok, "host": a.get("to") if ok else None}

    def t_loot(**a):
        return {"looted": a.get("host") == crown_ip and a.get("host") in owned_live}

    tools = {"scan": t_scan, "fingerprint": t_fingerprint, "exploit": t_exploit,
             "harvest": t_harvest, "pivot": t_pivot, "loot": t_loot}
    return tools, owned_live


def _selftest():
    from swarm.live_agent import run_red_agent
    from swarm.eventlog import EventLog
    import scripts.validation.oracle_red as oracle_red

    # the Phase-1 seam shape (4 hops to the crown), as DATA the oracle derives its script from.
    gt = {
        "crown": {"data": "db-core"},
        "crown_login": {"user": "svc_dba", "path": "/home/svc_dba/pii.json"},
        "cred_seam": {"chain": ["web01", "dba01", "db-bastion", "db-core"]},
    }
    n2i = {"web01": "10.10.0.11", "dba01": "10.35.0.10",
           "db-bastion": "10.60.0.10", "db-core": "10.40.0.11"}
    chain_ips = [n2i[h] for h in gt["cred_seam"]["chain"]]
    crown_ip = n2i["db-core"]
    key_path = "/home/svc_dba/.ssh/id_ed25519"
    start_subnet = "10.90.0.0/24"

    tools, owned_live = _simulated_seam_world(chain_ips, "CVE-2017-5638", crown_ip, key_path, start_subnet)
    router = oracle_red.OracleRouter(gt, n2i, entry_cve="CVE-2017-5638", start_subnet=start_subnet,
                                     inner_subnets=["10.35.0.0/24"])

    d = Path(tempfile.mkdtemp())
    log = EventLog(d / "oracle_proof.jsonl")
    res = run_red_agent(log, router, tools=tools, start_subnet=start_subnet,
                        max_turns=44, strict=True, no_progress_stop=44)

    # the expert reference reached the crown through the ONE engine, owning every seam host.
    assert res["outcome"] == "crown_looted", ("oracle must loot the crown via the engine", res["outcome"])
    assert crown_ip in res["looted"], ("the looted host must be the crown", res["looted"])
    assert set(chain_ips) <= set(res["owned"]), ("the oracle must own every seam host", res["owned"])
    assert owned_live >= set(chain_ips), ("live truth must agree the seam is owned", sorted(owned_live))
    assert res["turns"] <= 44, ("the expert chain must close within the matched budget", res["turns"])

    # and the chain the run produced verifies (re-derivable cold) — the engine's own hash chain.
    vok, bad = log.verify()
    assert vok, ("the engine's hash chain must verify", bad)

    print(f"prove_oracle ok (oracle drove the ONE engine to crown_looted in {res['turns']} turns; "
          f"owned the full seam {gt['cred_seam']['chain']}; chain verifies)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print("usage: prove_oracle.py --selftest")
        sys.exit(2)
