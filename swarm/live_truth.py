"""Independent reconciler — red's claims vs the hash-chained TELEMETRY chain.

The telemetry chain (swarm.live_telemetry) is the PRIMARY record: a tamper-evident log of the
actual system/network events that physically happened on the targets and the wire, written by
neither agent. This module cross-checks red's own account (its grounded spine claims in the
engagement log) against that primary record. A claim is CORROBORATED only when the telemetry
chain independently witnesses the matching real event; a claim the telemetry does not witness
is FLAGGED. That is what makes a result airtight: "red compromised X" counts only if the
system's own record shows it, not because the harness confirmed red to itself.

Corroboration mapping (claim -> what the TARGETS' own telemetry must show):
  foothold -> the exploit's trace on the entry: a T1190 service event (the Struts Jakarta
              fault) OR a Falco exec of a shell/`id` in the entry container OR a net.flow to
              the entry's service port.
  lateral  -> the pivot's EARNED trace on the destination: a COMPLETED ssh auth (the sshd
              "Accepted password/publickey" service line — SUCCESS only) OR a web-exploit fault
              (T1190/T1210) OR the entailed crown read. A bare :22 connect, and an sshd-session/
              sshd-auth fork, are both tagged T1021 but occur for a FAILED login too, so neither
              corroborates (2026-10-28c §11 amendment, seq 38).
  loot     -> the ACTUAL read of the crown secret: a Falco sensitive-file-open on the crown
              (the one claim only syscall telemetry can witness).
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def load_chain(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out                                          # no telemetry at all -> nothing witnessed
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:                               # noqa: BLE001
                pass
    return out


def _norm(h):
    """Normalize a host key: sensors name a container 'range-crown_db', the scope/claim names
    it 'crown_db'. Strip the range- prefix so the primary record and the claim line up."""
    h = h or ""
    return h[6:] if h.startswith("range-") else h


# A net.flow record comes from one of two real sensors with DIFFERENT field names: host
# conntrack (parse_conntrack -> src/dst) OR Falco's connect() probe (parse_falco_netflows ->
# src_host/dst_ip). On a Docker range the intra-bridge pivots are L2-switched and NEVER enter
# conntrack, so the ssh pivot is witnessed ONLY by the Falco-connect record (dst_ip). Reading
# just `dst` therefore blinds the reconciler to every real inner pivot — these accessors read
# whichever field the sensor used, so a flow corroborates regardless of its source.
def _flow_dst(f):
    return f.get("dst") or f.get("dst_ip")


def _flow_src(f):
    return f.get("src") or f.get("src_host")


# The crown-read witness: a syscall whose signal names the crown file. The DEFAULT markers are the
# legacy ".crown"-dotfile naming; the live caller passes the ACTUAL crown filename (harness ground
# truth — the primary-record checker is told WHAT to look for, which is never red's claim), so the
# witness matches the real range (e.g. /home/dbadmin/pii.json) rather than a hardcoded path.
_DEFAULT_CROWN_MARKERS = (".crown", "crown jewel")

# A COMPLETED ssh auth is the ONLY sound T1021 lateral witness. A bare `:22` connect AND an
# `sshd-session`/`sshd-auth` fork are both tagged T1021 by Falco, but both occur for a FAILED
# login too — observed live on wks-01 (sshd-session fork + `Failed password`, where red never
# held a valid cred). sshd logs "Accepted password/publickey" ONLY on success, so that
# service-log line is the witness: index_telemetry marks the destination with this sentinel when
# it sees that line, and the lateral branch requires the sentinel, NEVER the bare T1021 tag.
_AUTH_OK_SENTINEL = "T1021.accepted"
_AUTH_OK_TOKENS = ("accepted password", "accepted publickey",
                   "accepted keyboard-interactive", "accepted auth")


def index_telemetry(chain_events, crown_markers=_DEFAULT_CROWN_MARKERS):
    """Index the primary record for corroboration lookups."""
    tech_by_host, reads_by_host, flows = {}, {}, []
    markers = tuple(m.lower() for m in (crown_markers or _DEFAULT_CROWN_MARKERS))
    for e in chain_events:
        a, d = e.get("action"), (e.get("data") or {})
        if a in ("svc.event", "sys.syscall"):
            h = _norm(d.get("host"))
            tech_by_host.setdefault(h, set()).add(d.get("technique"))
            sig = " ".join(str(d.get(k, "")) for k in ("signal", "label", "raw")).lower()
            # loot evidence must be the ACTUAL read of the crown file, not any syscall on the host —
            # precise corroboration, no loose matching (rigor: the read itself, nothing else). The
            # marker is the real crown filename, so a `cat <crown>` exec or open() both witness it.
            if a == "sys.syscall" and any(mk in sig for mk in markers):
                reads_by_host.setdefault(h, []).append(sig[:160])
            # a COMPLETED ssh auth on this host's OWN service log — success only, not a connect/fork.
            if a == "svc.event" and any(tok in sig for tok in _AUTH_OK_TOKENS):
                tech_by_host[h].add(_AUTH_OK_SENTINEL)
        elif a == "net.flow":
            flows.append(d)
    return tech_by_host, reads_by_host, flows


def _grounded_claims(log_path):
    claims = []
    for e in load_chain(log_path):
        if e.get("action") == "state.mutate" and e.get("actor") == "red":
            d = e.get("data") or {}
            st = d.get("state")
            if st in ("foothold", "lateral", "loot", "exfil"):
                claims.append({"state": "loot" if st in ("loot", "exfil") else st,
                               "dst": d.get("dst"), "seq": e.get("seq"),
                               "method": d.get("via") or d.get("module") or d.get("cve") or ""})
    return claims


def _corroborated(claim, host_key, tech_by_host, reads_by_host, flows):
    st = claim["state"]
    techs = tech_by_host.get(host_key, set())
    if st == "foothold":
        if "T1190" in techs:
            return True, "service: exploit fault (T1190) on the entry's own log"
        if any((_flow_dst(f) in (host_key, claim["dst"])) for f in flows):
            return True, "network: inbound flow to the entry's service port"
        return False, "no exploit trace in the entry's telemetry"
    if st == "lateral":
        # A lateral is corroborated ONLY by evidence a COMPLETED pivot produces, never by incidental
        # traffic. The witnesses, in order:
        #   - a web-exploit fault on the destination's OWN service log (T1190/T1210): the OGNL/
        #     traversal request that an exploit-per-hop lands;
        #   - a COMPLETED ssh auth on the destination's own log: the sshd "Accepted password/
        #     publickey" service line (success ONLY), marked _AUTH_OK_SENTINEL by index_telemetry —
        #     NOT the bare T1021 tag, which a mere connect or an sshd-session/sshd-auth fork also
        #     carries (both happen for a FAILED login — live on wks-01, where red never authed);
        #   - the ENTAILED crown read: a crown-file read on the destination (reads_by_host) can only
        #     happen through a real session ON it, so it entails the pivot — recon cannot produce it.
        # The bare `dport=22` flow fallback was DROPPED (2026-10-28b §11 amendment); the bare T1021
        # tag is DROPPED here too (2026-10-28c, seq 38): conntrack/Falco log every :22 connect and
        # every per-connection sshd fork including red's OWN failed recon/pivot attempts, so neither
        # is a completed pivot — it would rubber-stamp a pivot red never landed. A neutral check
        # requires the pivot's own earned signature (a completed auth / exploit fault / the read it
        # enabled), not incidental traffic.
        if "T1190" in techs or "T1210" in techs:
            return True, "service: web-exploit fault (T1190/T1210) on the destination's own log"
        if _AUTH_OK_SENTINEL in techs:
            return True, "service: sshd 'Accepted' — a COMPLETED auth (success) on the destination's own log"
        if reads_by_host.get(host_key):
            return True, "entailed: a crown-file read on the destination (a real session ON it, not recon)"
        return False, "no completed auth / web-exploit / entailed crown read to the destination in telemetry"
    if st == "loot":
        if reads_by_host.get(host_key):
            return True, f"syscall: sensitive-file read on the crown ({reads_by_host[host_key][0]})"
        return False, "no crown-file read in syscall telemetry"
    return None, "claim type not observable from telemetry"


def reconcile(red_log_path, telemetry_chain_path, *, resolve=None, crown_markers=None):
    """Cross-check each grounded red claim against the telemetry CHAIN. `resolve(dst)` maps a
    claim's dst (name/ip) to the telemetry host key (identity by default; the live caller passes
    the gate's IP->name canonicalizer so an IP claim lines up with the name-keyed syscall record).
    `crown_markers` is the crown-file witness string(s) (the live caller passes the real crown
    filename; default = the legacy ".crown" naming). Returns a report; `flagged` = claimed but the
    primary record does not witness it."""
    resolve = resolve or (lambda dst: dst)
    chain = load_chain(telemetry_chain_path)
    tech_by_host, reads_by_host, flows = index_telemetry(chain, crown_markers or _DEFAULT_CROWN_MARKERS)
    reports = []
    for cl in _grounded_claims(red_log_path):
        hk = _norm(resolve(cl["dst"]))
        corrob, why = _corroborated(cl, hk, tech_by_host, reads_by_host, flows)
        reports.append({"claim": cl["state"], "dst": cl["dst"], "method": cl["method"],
                        "corroborated": corrob, "evidence": why, "flagged": corrob is False})
    checkable = [r for r in reports if r["corroborated"] is not None]
    return {"reports": reports, "claims": len(reports), "checkable": len(checkable),
            "corroborated": sum(1 for r in checkable if r["corroborated"]),
            "flagged": sum(1 for r in reports if r["flagged"]),
            "telemetry_events": len(chain),
            "all_corroborated": all(r["corroborated"] for r in checkable) if checkable else None}


if __name__ == "__main__":  # self-check: reconcile claims against a real telemetry chain
    import tempfile
    from swarm.eventlog import EventLog
    from swarm import live_telemetry

    # build the PRIMARY telemetry chain from (fixture) real captures, exactly as the live path
    chain_p = Path(tempfile.mktemp(suffix=".jsonl")); chain = EventLog(chain_p)
    live_telemetry.ingest(
        chain,
        service_logs={
            "struts_edge": "JakartaMultiPartRequest processUpload failed java.lang.RuntimeException",
            "app_0": "sshd[55]: Accepted publickey for svc from 10.11.0.5 port 44512 ssh2",
            "crown_db": "sshd[9]: Server listening on 0.0.0.0 port 22.",   # NO accepted-key: pivot unwitnessed
        },
        conntrack_text="[NEW] tcp 6 120 src=10.11.0.5 dst=10.11.0.11 sport=5 dport=22 [UNREPLIED]\n",
        falco_lines=['{"output":"Sensitive file opened for reading (file=/root/.crown_crown_db '
                     'container=range-crown_db)","priority":"Warning"}'])

    # red's engagement log: a foothold, two witnessed pivots, a loot, and an UNWITNESSED pivot claim.
    red_p = Path(tempfile.mktemp(suffix=".jsonl")); red = EventLog(red_p)
    red.append("range", "confirm", {"confirms": "foothold", "dst": "struts_edge"})
    red.append("red", "state.mutate", {"state": "foothold", "dst": "struts_edge", "via": "msf", "via_confirm": 1})
    red.append("range", "confirm", {"confirms": "lateral", "dst": "app_0"})
    red.append("red", "state.mutate", {"state": "lateral", "dst": "app_0", "via": "ssh", "via_confirm": 3})
    red.append("range", "confirm", {"confirms": "lateral", "dst": "crown_db"})
    red.append("red", "state.mutate", {"state": "lateral", "dst": "crown_db", "via": "ssh", "via_confirm": 5})
    red.append("range", "confirm", {"confirms": "loot", "dst": "crown_db"})
    red.append("red", "state.mutate", {"state": "loot", "dst": "crown_db", "via": "cat", "via_confirm": 7})
    # a pivot red CLAIMS to a host with NO witness at all — must stay FLAGGED.
    red.append("red", "state.mutate", {"state": "lateral", "dst": "ghost_host", "via": "ssh", "via_confirm": 9})

    r = reconcile(str(red_p), str(chain_p))
    by = {(x["claim"], x["dst"]): x for x in r["reports"]}
    assert by[("foothold", "struts_edge")]["corroborated"] is True, by[("foothold", "struts_edge")]
    assert by[("lateral", "app_0")]["corroborated"] is True, by[("lateral", "app_0")]
    # the crown pivot is now corroborated by the ENTAILED crown read: a crown-file read ON crown_db
    # can only happen through a real session on it, so it entails the pivot (2026-10-28b amendment —
    # before it, this lateral was spuriously FLAGGED even though the loot it enabled was witnessed).
    assert by[("lateral", "crown_db")]["corroborated"] is True, by[("lateral", "crown_db")]
    assert "entailed" in by[("lateral", "crown_db")]["evidence"], by[("lateral", "crown_db")]
    # the LOOT is corroborated by the ACTUAL crown-file read (syscall) — only telemetry shows this.
    assert by[("loot", "crown_db")]["corroborated"] is True, by[("loot", "crown_db")]
    # the UNWITNESSED pivot (no auth / exploit / crown read) stays FLAGGED — exactly one.
    assert by[("lateral", "ghost_host")]["corroborated"] is False, by[("lateral", "ghost_host")]
    assert r["flagged"] == 1 and r["all_corroborated"] is False, r

    # exploit-per-hop (HTTP RCE) lateral: corroborated by the destination's OWN web-exploit fault
    # (T1190), never an ssh login; a lateral with no web evidence at all stays FLAGGED.
    ok_x, why_x = _corroborated({"state": "lateral", "dst": "webapp_rce", "method": "exploit-per-hop"},
                                "webapp_rce", {"webapp_rce": {"T1190"}}, {}, [])
    assert ok_x is True and "web-exploit" in why_x, (ok_x, why_x)
    no_ev, _ = _corroborated({"state": "lateral", "dst": "x", "method": "exploit-per-hop"},
                             "x", {}, {}, [])
    assert no_ev is False, "an unwitnessed exploit-per-hop lateral must stay flagged"

    # REGRESSION (2026-10-28b) — a bare `dport=22` flow must NOT corroborate a LATERAL. red's own
    # recon scans the host's :22 (the observe1 chain holds 607 such connects), so a connect alone is
    # a false-POSITIVE vector; the fallback was DROPPED. A ssh pivot now needs a COMPLETED auth
    # (T1021) or the entailed crown read — not incidental traffic.
    scan_flow = {"src_host": "attacker", "dst_ip": "10.40.0.10", "dport": 22,
                 "event": "connect", "source": "falco-connect"}
    bare22, _ = _corroborated({"state": "lateral", "dst": "10.40.0.10"}, "db-core", {}, {}, [scan_flow])
    assert bare22 is False, ("a bare :22 connect must NOT corroborate a pivot (recon scans :22)", bare22)
    # a COMPLETED ssh auth corroborates the pivot — but ONLY the sshd "Accepted" success line
    # (marked from the destination's OWN service log), never the bare T1021 tag.
    acc_chain = [{"action": "svc.event", "data": {"host": "range-db-core", "technique": "T1021",
                  "label": "SSH lateral movement (accepted auth)",
                  "raw": "Accepted password for dbadmin from 10.40.0.11 port 41486 ssh2"}}]
    tbh_acc, _, _ = index_telemetry(acc_chain)
    assert _AUTH_OK_SENTINEL in tbh_acc["db-core"], tbh_acc
    ok_auth, why_auth = _corroborated({"state": "lateral", "dst": "db-core"}, "db-core", tbh_acc, {}, [])
    assert ok_auth is True and "COMPLETED auth" in why_auth, (ok_auth, why_auth)
    # BITING (seq 38): a bare T1021 tag — a :22 connect OR an sshd-session/sshd-auth fork, BOTH of
    # which a FAILED login also produces — must NOT corroborate. Live on wks-01: sshd-session fork
    # + `Failed password`, where red never held a valid cred; a lateral there stays FLAGGED.
    fail_chain = [{"action": "sys.syscall", "data": {"host": "range-wks-01", "technique": "T1021",
                   "signal": "Informational Outbound connect (dst=127.0.0.1 dport=65535 "
                             "proc=sshd-session container=range-wks-01)"}},
                  {"action": "svc.event", "data": {"host": "range-wks-01", "technique": "T1110",
                   "raw": "Failed password for invalid user alice from 10.40.0.11 port 5 ssh2"}}]
    tbh_fail, _, _ = index_telemetry(fail_chain)
    assert "T1021" in tbh_fail["wks-01"] and _AUTH_OK_SENTINEL not in tbh_fail["wks-01"], tbh_fail
    flag_fork, _ = _corroborated({"state": "lateral", "dst": "wks-01"}, "wks-01", tbh_fail, {}, [])
    assert flag_fork is False, ("an sshd-session fork / bare T1021 (no Accepted) must NOT corroborate", flag_fork)
    # the ENTAILED crown read corroborates the pivot it required (a session ON the destination).
    ok_ent, why_ent = _corroborated({"state": "lateral", "dst": "db-core"}, "db-core",
                                     {}, {"db-core": ["...cat /home/dbadmin/pii.json..."]}, [])
    assert ok_ent is True and "entailed" in why_ent, (ok_ent, why_ent)

    # REGRESSION — the FOOTHOLD witness still accepts an inbound flow, and reads whichever field the
    # sensor used (conntrack `dst` OR Falco-connect `dst_ip`); reading only `dst` (the old bug)
    # missed the Falco-connect record of the real ingress.
    foot_flow = {"src_host": "attacker", "dst_ip": "10.90.0.11", "dport": 8080,
                 "event": "connect", "source": "falco-connect"}
    ok_fe, why_fe = _corroborated({"state": "foothold", "dst": "10.90.0.11"},
                                  "dmz-web", {}, {}, [foot_flow])
    assert ok_fe is True and "inbound flow" in why_fe, ("falco-connect dst_ip must corroborate the entry", ok_fe, why_fe)

    # REGRESSION — the crown-read witness. The real crown file is /home/dbadmin/pii.json, not a
    # ".crown" dotfile; the read is captured as a `cat <crown>` exec on the crown host. With the
    # real filename passed as the marker it corroborates; the legacy default would miss it (the
    # reason observe1's genuine crown read was flagged). The marker is harness ground truth, not red's.
    crown_chain = [{"action": "sys.syscall", "data": {"host": "range-db-core",
                    "signal": "Notice Shell/tool exec (proc=cat cmdline=cat /home/dbadmin/pii.json "
                              "parent=sshd-session container=range-db-core)"}}]
    _, reads_real, _ = index_telemetry(crown_chain, crown_markers=[".crown", "crown jewel", "pii.json"])
    assert reads_real.get("db-core"), ("the real crown filename must be witnessed", reads_real)
    _, reads_legacy, _ = index_telemetry(crown_chain)   # default markers miss pii.json (the old blind spot)
    assert not reads_legacy.get("db-core"), reads_legacy

    chain_p.unlink(missing_ok=True); red_p.unlink(missing_ok=True)
    print("live_truth ok (reconciles red's claims against the hash-chained TELEMETRY chain: a "
          "foothold by the entry's exploit fault / inbound flow, a pivot by the destination's own "
          "COMPLETED auth or the entailed crown read (a bare :22 connect does NOT corroborate — "
          "recon scans :22), the crown LOOT by the actual file-read syscall; an unwitnessed pivot is "
          "FLAGGED — the system's own data decides, not the harness)")
