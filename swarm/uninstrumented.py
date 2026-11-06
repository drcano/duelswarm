"""Uninstrumented red channel — the honesty substrate for env-boundary proofs.

A real adversary does not call `gate.dispatch`; they open a shell on the earned
foothold and type. For the boundaries-hold claim to mean anything, red must be
able to issue arbitrary commands against the compromised entry WITHOUT routing
through the Python authorization gate. This module is that channel.

Live duels still prefer the agent's gate-dispatched shell/exec channel (the
earned command channel a weapon returns, routed through the gate), because the
gate stays as *one* layer. This module exists so
`scripts/prove_env_boundaries.py` can neuter the gate and prove the floor still
holds — i.e. the segmentation at the Docker/Linux bridge layer, not red's
cooperation, is what keeps `oos_missed == 0`.

Nothing here is ever called from live duel code paths. Keep it that way.
"""

# CLASS-2 (deliberately UNGOVERNED) channel: this module is the one place that does NOT route
# through the gate's single effect primitive, by design — it exists to prove the segmentation
# floor holds even when the gate is bypassed. It therefore keeps its OWN subprocess and must
# stay import-isolated from swarm.gate (enforced by scripts/mediation/static_coverage.py's
# class-2 isolation check). This is the documented exception to the one-effect-path (invariant #1).
import subprocess


def exec_raw(container, cmd, timeout=10):
    """Direct `docker exec` on `container`, no gate, no logging.

    This is the attacker's point of view: a free-form shell on the compromised
    host. Returns (returncode, stdout+stderr) — the OS tells the truth about
    whether the packet reached its destination.
    """
    try:
        r = subprocess.run(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "docker not available"
    except Exception as e:
        return 1, f"exec error: {e}"


def tcp_reaches(container, host, port, timeout=3):
    """From inside `container`, does a TCP connect to host:port succeed?

    Uses bash /dev/tcp (zero dependencies in the vulnerable images). Returns
    True iff the kernel delivers a connection — the honest env-boundary signal.
    `timeout` is kept short because the segmented network drops on route, not
    on refusal, so these calls hang otherwise.
    """
    # Sentinels are distinct substrings — "REACHABLE" in "UNREACHABLE" was the
    # bug that masked a working boundary.
    cmd = (
        f"timeout {timeout} bash -c "
        f"'(echo > /dev/tcp/{host}/{port}) 2>/dev/null && echo OPEN "
        f"|| echo SHUT'"
    )
    _, out = exec_raw(container, cmd, timeout=timeout + 2)
    return "OPEN" in out and "SHUT" not in out


def host_gateway_reachable(container, gw, ports=(80, 443, 2375), timeout=2):
    """Does the compromised entry still have ANY L3 reach to the Docker-HOST gateway?

    This is the §E gap Phase 0a closes. After the host-side firewall installs its
    `raw/PREROUTING -i <bridge> -d <gw> -j DROP`, a packet to the gateway is silently
    dropped, so a connect just times out. BEFORE it, the gateway host answers: an open
    port completes the connect, a closed one sends a RST ("Connection refused") — and
    BOTH prove the packet reached the host. So:
        reachable      = any probe OPENs or is actively REFUSED (the host responded);
        unreachable    = every probe times out (the packet was dropped on the way).
    ICMP is deliberately NOT used: Phase 0a drops CAP_NET_RAW, so `ping` can't open a
    raw socket and would read as a false 'unreachable' whether or not the firewall is up.
    """
    for p in ports:
        cmd = f"(timeout {timeout} bash -c 'echo > /dev/tcp/{gw}/{p}') 2>&1; echo RC=$?"
        _, out = exec_raw(container, cmd, timeout=timeout + 3)
        low = out.lower()
        if "rc=0" in low:            # connect completed: reached + open
            return True
        if "refused" in low:         # RST came back: reached + closed
            return True
    return False                     # every probe timed out → dropped on the way to the host


def _discover_ingress_gateway(net="duelswarm-range_ingress"):
    """The Docker-host gateway IP of the ingress bridge — the address the entry could
    reach at L3 before Phase 0a. Returns None if Docker or the net is absent, so the
    probe degrades to 'unmeasured' rather than raising (and never claims a false pass)."""
    try:
        out = subprocess.check_output(
            ["docker", "network", "inspect", net],
            text=True, timeout=6, stderr=subprocess.DEVNULL)
        import json as _json
        return _json.loads(out)[0]["IPAM"]["Config"][0]["Gateway"]
    except Exception:
        return None


def probe_boundary(entry_container, out_hosts, in_hosts,
                   internet_hosts=("1.1.1.1", "example.com"), ports=(22, 80, 443, 8080, 5432),
                   host_gateway=None):
    """From the compromised entry (UNINSTRUMENTED — direct docker exec, no gate),
    measure what the ENVIRONMENT BOUNDARY actually permits. Returns the honest signal:

      oos_tcp_reaches : (host, port) tuples that connected — MUST be []  (a)
      internet_blocked: no route from the foothold to the open internet  (b)
      host_gateway    : note — the Docker-host gateway gap (F2 section E), scoped not failed (c)
      in_scope_reaches: count of in-scope pivots reachable — MUST be > 0 (floor leaves the duel playable)

    `available` is False (and the floor claim unproven, not failed) when Docker/the
    container is absent, so the live duel degrades to the structural record cleanly.
    """
    probe = exec_raw(entry_container, "true", timeout=4)[0] == 0
    if not probe:
        return {"available": False, "note": "entry container not reachable (no Docker / not booted)"}

    oos = []
    for h in out_hosts:
        for p in ports:
            if tcp_reaches(entry_container, h, p, timeout=2):
                oos.append((h, p))
    in_reaches = sum(1 for h in in_hosts
                     if any(tcp_reaches(entry_container, h, p, timeout=2) for p in (22, 80, 8080, 5432)))
    # Internet: a reach shows html/200/connected; timeout/no-route is the floor holding.
    inet_reached = []
    for h in internet_hosts:
        rc, out = exec_raw(entry_container, f"curl -s -m 4 http://{h}/ -o /dev/null -w '%{{http_code}}' 2>&1", timeout=8)
        if any(code in out for code in ("200", "301", "302")):
            inet_reached.append(h)
    # (c) Phase 0a §E: actually MEASURE L3 reach to the Docker-host gateway (was a
    # hardcoded "OPEN" note). Discover the ingress gateway if the caller didn't pass it.
    gw = host_gateway or _discover_ingress_gateway()
    if gw:
        gw_reach = host_gateway_reachable(entry_container, gw)
        gw_fields = {
            "host_gateway_ip": gw,
            "host_gateway_reachable": gw_reach,
            "host_gateway_unreachable": not gw_reach,   # (c) Phase 0a done-check: MUST be True
        }
    else:
        # No Docker / no ingress net: the §E check is UNMEASURED — never a silent pass.
        gw_fields = {
            "host_gateway_ip": None,
            "host_gateway_reachable": None,
            "host_gateway_unreachable": None,
            "host_gateway_note": "ingress gateway not discoverable (Docker/net absent) — "
                                 "§E gateway check UNMEASURED, not passed",
        }
    return {
        "available": True, "entry_container": entry_container,
        "oos_tcp_reaches": oos,                 # (a) must be []
        "internet_blocked": not inet_reached,   # (b) must be True
        "internet_reached": inet_reached,
        "in_scope_reaches": in_reaches,         # floor playable: must be > 0
        **gw_fields,
        # ok now REQUIRES the gateway measured-and-unreachable: on a booted range whose
        # host firewall is not up yet, the gateway answers and ok is honestly False.
        "ok": (not oos) and (not inet_reached) and in_reaches > 0
              and gw_fields["host_gateway_unreachable"] is True,
    }


if __name__ == "__main__":  # self-check: schema + no-Docker degradation
    # Without a container, exec_raw returns a clear error, never raises.
    rc, out = exec_raw("nonexistent-container-xyz", "true", timeout=2)
    assert rc != 0, (rc, out)
    assert isinstance(out, str), out
    # tcp_reaches degrades the same way (returns False when exec fails).
    assert tcp_reaches("nonexistent-container-xyz", "any", 80, timeout=1) is False
    # probe_boundary degrades cleanly to unproven (not failed) with no container.
    pb = probe_boundary("nonexistent-container-xyz", ["decoy"], ["db"])
    assert pb["available"] is False, pb
    # host_gateway_reachable degrades to False (every /dev/tcp probe fails) with no container,
    # and gateway discovery returns None (not raise) when Docker/the net is absent.
    assert host_gateway_reachable("nonexistent-container-xyz", "172.22.0.1", timeout=1) is False
    assert _discover_ingress_gateway("duelswarm-no-such-net-xyz") is None
    print("uninstrumented ok (direct docker exec, no gate; probe_boundary + gateway probe "
          "degrade cleanly without Docker)")
