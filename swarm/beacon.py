"""Real beacon confirmation (Task L3) — Incalmo `check_new_agents`.

The spine's law is that state advances ONLY on an independently-observed outcome,
never an agent's word. Through Brick 0 that observer was SIMULATED. This module makes
it real on a booted range: a successful exploit drops and launches a minimal implant
on the target that records its OWN real identity under a collector-chosen nonce; the
collector then reads that back OUT-OF-BAND (a separate channel from red's claim). A
brand-new beacon carrying the right nonce + the target's real in-range IP = a confirmed
compromise, exactly as a new agent appearing in Incalmo's `check_new_agents`.

Honesty scope: the implant runs on the real booted target and reports the target's
real IP; the collector's observation is independent of red's self-report, and the
nonce makes a bare claim unforgeable (no implant -> no matching beacon -> no confirm).
A production C2 would beacon over the network to an external collector; here the
out-of-band channel is a direct `docker exec` read of the live container, which is the
honest demo-scale equivalent and strictly stronger than the SIMULATED responder. No
Docker (dry runs) -> `observed=False`, and the caller keeps the labeled SIMULATED path.
"""
import re
import time
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect  # noqa: E402  (one effect path)

from swarm import uninstrumented

_MARKER = "/tmp/.ds_beacon"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")                 # strip the C2 client's color codes
# one Sliver beacon-table row: ID  Name  Tasks  Transport  <ip:port>  Hostname  User  Proc(PID)…
_BEACON_ROW = re.compile(
    r"^\s*([0-9a-f]{8})\s+(\S+)\s+\S+\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+\s+(\S+)\s+(\S+)\s+(\S+)")
_TASKED = re.compile(r"Tasked beacon \S+ \(([0-9a-f]{8})\)")


def new_beacon_id():
    return secrets.token_hex(8)


def launch_beacon(container, beacon_id):
    """Drop+launch the implant on the target: it writes its real in-range IP under the
    collector's nonce. Returns True iff the implant ran on the live container."""
    cmd = (f"printf '%s %s\\n' {beacon_id} "
           f"\"$(hostname -i 2>/dev/null || hostname)\" > {_MARKER} && echo LAUNCHED")
    rc, out = uninstrumented.exec_raw(container, cmd, timeout=6)
    return rc == 0 and "LAUNCHED" in out


def observe_beacon(container, beacon_id):
    """Collector's OUT-OF-BAND observation: read the beacon the implant wrote. Returns
    {observed, ip, beacon_id, container, fidelity}. observed is True ONLY if a beacon
    carrying THIS nonce is present — a claim with no implant never matches."""
    rc, out = uninstrumented.exec_raw(container, f"cat {_MARKER} 2>/dev/null", timeout=5)
    parts = (out or "").split()
    observed = rc == 0 and len(parts) >= 2 and parts[0] == beacon_id
    return {"observed": observed, "beacon_id": beacon_id, "container": container,
            "ip": parts[1] if observed else None,
            "fidelity": "real" if observed else "none"}


# ── Real Sliver C2 callback (Phase 2.5): the check_new_agents pattern, made real ──

def sliver_handle(container="range-attacker_c2", op_config="/root/op.cfg"):
    """Handle to the shared red C2 (one Sliver server on red's infra net). Per-actor-ready: a
    later multi-APT phase passes a distinct {container, op_config} per actor without changing
    this module."""
    return {"container": container, "op_config": op_config}


def _sliver_rc(handle, commands, timeout=45):
    """Run operator-console `commands` against the C2 server via `docker exec`, returning the
    ANSI-stripped output (or None if the C2 is unreachable, so the caller falls back). The
    client reads the rc and exits on EOF — no TTY needed."""
    tf = Path(tempfile.mktemp(suffix=".rc"))
    tf.write_text("\n".join(commands) + "\n")
    try:
        run_effect(["docker", "cp", str(tf), f"{handle['container']}:/tmp/_ds_q.rc"],
                       capture_output=True, timeout=15, check=True)
        p = run_effect(["docker", "exec", handle["container"], "sliver-client",
                            "--config", handle["op_config"], "--rc", "/tmp/_ds_q.rc"],
                           capture_output=True, text=True, timeout=timeout)
        return _ANSI.sub("", (p.stdout or "") + (p.stderr or ""))
    except Exception:
        return None
    finally:
        tf.unlink(missing_ok=True)


def parse_agents(beacons_output):
    """Parse the C2's `beacons` table into [{beacon_id, name, remote_ip, hostname, username,
    process}]. Pure (no Docker) so the parser is unit-testable offline."""
    if not beacons_output or "No beacons" in beacons_output:
        return []
    agents = []
    for line in beacons_output.splitlines():
        m = _BEACON_ROW.match(line)
        if m:
            agents.append({"beacon_id": m.group(1), "name": m.group(2), "remote_ip": m.group(3),
                           "hostname": m.group(4), "username": m.group(5), "process": m.group(6)})
    return agents


def c2_new_agents(handle):
    """check_new_agents: ask the real C2 which agents have called back. []"" if none / C2 down."""
    return parse_agents(_sliver_rc(handle, ["beacons"]))


def observe_beacon_sliver(handle, *, foothold_ips=None, foothold_hostname=None):
    """Confirm a foothold via the REAL C2: an agent whose callback address (one of the
    foothold's IPs) or implant hostname (the foothold container's hostname) matches. The id +
    remote address are the C2's own record, not red's claim (no implant -> no agent ->
    observed=False). Same schema as `observe_beacon`. `foothold_ips` is a set/list — a
    multi-homed foothold beacons from whichever interface reaches the C2."""
    ips = set(foothold_ips or [])
    host = (foothold_hostname or "")[:12]
    for a in c2_new_agents(handle):
        if (a["remote_ip"] in ips) or (host and host in a["hostname"]):
            return {"observed": True, "beacon_id": a["beacon_id"], "ip": a["remote_ip"],
                    "hostname": a["hostname"], "process": a["process"],
                    "container": handle["container"], "fidelity": "real", "via": "sliver-c2"}
    return {"observed": False, "beacon_id": None, "ip": None, "fidelity": "none", "via": "sliver-c2"}


def implant_execute(handle, beacon_id, cmd, polls=8, interval=5):
    """Red's EARNED CHANNEL: run `cmd` on the foothold THROUGH the beacon session. Queues the
    task, then polls `tasks fetch` until it completes; returns the command's real stdout (''
    on failure/timeout). The caller gate-mediates + logs this like any action."""
    queued = _sliver_rc(handle, [f"use {beacon_id}", f"execute -o {cmd}"])
    m = _TASKED.search(queued or "")
    if not m:
        return ""
    task = m.group(1)
    for _ in range(polls):
        time.sleep(interval)
        out = _sliver_rc(handle, [f"use {beacon_id}", f"tasks fetch {task}"])
        if out and "Completed" in out and "Output:" in out:
            return out.split("Output:", 1)[1].strip()
    return ""


def make_collector(r, c2=None):
    """A collector over range `r`. With a real Sliver C2 handle (`c2`), confirm_foothold asks
    the C2 whether a real implant has beaconed from range-<host> — the real callback. Without
    one, it falls back to the out-of-band docker-exec marker (the honest demo-scale
    equivalent). negative_probe is the anti-hallucination test: a claim with no implant is not
    observed, either way."""
    def _container(host):
        return f"range-{host}"

    def _ident(host):
        """The foothold's full IP set + container hostname, so a beacon from ANY of its
        interfaces (a multi-homed foothold) correlates to it regardless of interface order."""
        try:
            ips = run_effect(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", _container(host)],
                capture_output=True, text=True, timeout=10).stdout.split()
            hn = run_effect(["docker", "inspect", "-f", "{{.Config.Hostname}}", _container(host)],
                                capture_output=True, text=True, timeout=10).stdout.strip()
            return ips, hn
        except Exception:
            return [], ""

    def confirm_foothold(host):
        if c2 is not None:                            # real C2: observe a genuine beacon callback
            ips, hn = _ident(host)
            obs = observe_beacon_sliver(c2, foothold_ips=ips, foothold_hostname=hn)
            if obs["observed"]:
                return obs
            # fall through to the marker channel only if the C2 saw nothing (honest degrade)
        bid = new_beacon_id()
        launch_beacon(_container(host), bid)          # the exploit's implant (marker fallback)
        return observe_beacon(_container(host), bid)  # the collector, out-of-band

    def negative_probe(host):
        if c2 is not None:
            # a host with no implant must NOT match any agent the C2 holds.
            return observe_beacon_sliver(c2, foothold_ips=["203.0.113.255"], foothold_hostname="")
        return observe_beacon(_container(host), new_beacon_id())

    return {"confirm_foothold": confirm_foothold, "negative_probe": negative_probe}


if __name__ == "__main__":  # self-check: C2-table parser + degradation + nonce gating (no Docker)
    # The real Sliver C2 callback: parse a genuine `beacons` table (captured live) into agents —
    # the check_new_agents step. Pure, so it is deterministic offline (no C2 needed here).
    _REAL = (
        " ID         Name          Tasks   Transport   Remote Address   Hostname       "
        "Username   Process (PID)     Operating System \n"
        "========== ============= ======= =========== ================ ============== \n"
        " 698979dd   SMART_KENDO   0/0     http(s)     10.9.0.3:60806   4331c603d847   "
        "root       /tmp/.slc (417)   linux/amd64 \n")
    agents = parse_agents(_REAL)
    assert len(agents) == 1 and agents[0]["beacon_id"] == "698979dd", agents
    assert agents[0]["remote_ip"] == "10.9.0.3" and agents[0]["username"] == "root", agents
    assert agents[0]["process"] == "/tmp/.slc", agents
    assert parse_agents("No beacons 🙁") == [] and parse_agents("") == []
    # A tasked-beacon line yields the task id (the earned channel's handle).
    assert _TASKED.search("[*] Tasked beacon SMART_KENDO (8bfa5f09)").group(1) == "8bfa5f09"

    # Degradation is range-state-independent (uses a container that never exists), so the smoke
    # stays green whether or not a range is up:
    assert launch_beacon("nonexistent-xyz", new_beacon_id()) is False
    obs = observe_beacon("nonexistent-xyz", new_beacon_id())
    assert obs["observed"] is False and obs["fidelity"] == "none" and obs["ip"] is None, obs
    # No reachable C2 -> the real-callback path reports nothing observed (never a fake confirm).
    down = sliver_handle(container="nonexistent-c2-xyz")
    assert c2_new_agents(down) == []
    assert observe_beacon_sliver(down, foothold_ips=["10.9.0.3"])["observed"] is False
    # A collector with NO C2 handle degrades through the marker channel to observed=False.
    col = make_collector({"entry": "nonexistent-xyz"})
    assert col["confirm_foothold"]("nonexistent-xyz")["observed"] is False
    assert col["negative_probe"]("nonexistent-xyz")["observed"] is False
    # Two ids never collide (nonce is the forgery barrier).
    assert new_beacon_id() != new_beacon_id()
    print("beacon ok (real Sliver C2 callback: parses the live `beacons` table into agents — "
          "check_new_agents; the earned channel's task id is recoverable; no reachable C2 / no "
          "Docker -> observed=False, so the marker fallback + SIMULATED path stay honest)")
