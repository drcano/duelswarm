"""N1 — REAL recon against the booted range (retires the mh_recon SIMULATED oracle
for the `recon` move class).

mh_recon.reveal() emits discovery events read from the MHBench IR, tagged
`fidelity:"SIMULATED" source:"mhbench_ir"` — it fires facts the model author put in
the IR, not facts observed on a running host. This module replaces that for recon with
a REAL observation: an actual TCP connect-scan from a source container to a target's
real in-range IP (busybox `nc -z`), through the gate. An open port is open because a
real socket connected; a closed/filtered port is closed because the segmented network
dropped the route — the same physical truth the N0 L3 ping probe showed, now at L4.

Honesty scope (brief N1, one move class at a time):
  - REAL: the open/closed observation. `fidelity:"real" source:"tcp-connect"`.
  - STILL STUB: the service BANNER/version fingerprint behind the port — the listener
    is `nc -lk -e /bin/true`, not a real sshd/http daemon, so there is nothing to
    fingerprint yet. We emit `services:{port:"open"}`, never a faked version string.
  - The scan is routed through `gate.dispatch` exactly like every other move: a target
    outside the actor's scope is blocked and never scanned (floor preserved).

No Docker (dry/offline) -> `scan_host` returns all-False with observed=False, and the
caller keeps the labeled SIMULATED path (mh_recon). Nothing is faked to look real.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect, EffectTimeout  # noqa: E402  (one effect path)
from swarm import shellsafe  # noqa: E402  (A2: keep agent ip/port shell-inert)


def _exec(container, cmd, timeout):
    """Direct `docker exec` with busybox `sh` (alpine has no bash). (rc, out)."""
    try:
        r = run_effect(
            ["docker", "exec", container, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except EffectTimeout:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "docker not available"


def _connect_cmd(ip, port, timeout):
    """A portable, REAL TCP-connect probe: exit 0 iff a real connection to ip:port opens.
    Tries, in order, whatever the container actually has — busybox/openbsd `nc -z`, then
    bash's `/dev/tcp` (bounded by `timeout`), then perl's IO::Socket::INET (self-bounded by
    alarm). No simulation and no hardcoded host/port — every branch makes a live connect.
    Minimal images (e.g. the struts foothold) have no `nc` but do have bash+perl, so inner
    recon from such a foothold still works. Exit 125 if the container has none of them."""
    t = int(timeout) or 1
    return (
        f"if command -v nc >/dev/null 2>&1; then nc -z -w{t} {ip} {port}; "
        f"elif command -v timeout >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then "
        f"timeout {t} bash -c 'exec 3<>/dev/tcp/{ip}/{port}'; "
        f"elif command -v perl >/dev/null 2>&1; then "
        f"perl -e 'use IO::Socket::INET; alarm({t}); "
        f"exit(IO::Socket::INET->new(PeerAddr=>\"{ip}:{port}\",Timeout=>{t})?0:1)'; "
        f"else exit 125; fi"
    )


def scan_port(src_container, ip, port, timeout=1):
    """True iff `src_container` can open a real TCP connection to ip:port. Uses the first
    real connect primitive the container has (nc -z, else bash /dev/tcp, else perl): exit
    0 == connected (open), nonzero == closed/no-route/no-tool. A REAL connect every time,
    never a simulated result."""
    try:                                   # A2: ip/port go into a shell probe — drop an unclean one
        ip = shellsafe.host(ip)
        port = shellsafe.port(port)
    except shellsafe.UnsafeValue:
        return False
    rc, _ = _exec(src_container, _connect_cmd(ip, port, timeout), timeout=timeout + 3)
    return rc == 0


def _batch_script(pairs, timeout):
    """A busybox-sh script that connect-probes every (ip, port) in `pairs` CONCURRENTLY from
    inside the container and prints `ip port` for each that opens. Same real-connect primitive
    as _connect_cmd (nc -z, else bash /dev/tcp, else perl), just run in parallel and bounded by
    `timeout` each — so a subnet sweep costs ~one timeout of wall-clock instead of N serial
    docker-exec round-trips. No simulation, no hardcoded host/port."""
    t = int(timeout) or 1
    probe = (
        "p(){ "
        "if command -v nc >/dev/null 2>&1; then nc -z -w%d \"$1\" \"$2\" >/dev/null 2>&1; "
        "elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then "
        "timeout %d bash -c \"exec 3<>/dev/tcp/$1/$2\" >/dev/null 2>&1; "
        "elif command -v perl >/dev/null 2>&1; then "
        "perl -e 'use IO::Socket::INET; alarm($ARGV[2]); "
        "exit(IO::Socket::INET->new(PeerAddr=>\"$ARGV[0]:$ARGV[1]\",Timeout=>$ARGV[2])?0:1)' "
        "\"$1\" \"$2\" %d; "
        "else return 125; fi; }\n"
    ) % (t, t, t)
    lines = [probe]
    for ip, port in pairs:
        try:                               # A2: skip any pair that is not a clean host/IP + int port
            ip = shellsafe.host(ip)
            port = shellsafe.port(port)
        except shellsafe.UnsafeValue:
            continue
        lines.append('( p %s %s && echo "%s %s" ) &' % (ip, port, ip, port))
    lines.append("wait")
    return "\n".join(lines)


def scan_many(src_container, pairs, timeout=1):
    """Real parallel connect-scan of many (ip, port) pairs from `src_container` in ONE docker
    exec. Returns a set of (ip, port) that opened, or None if the scan could not run (no Docker)
    — distinct from 'ran and found nothing' (empty set). Identical observation to scan_port, just
    batched + concurrent."""
    pairs = list(pairs)
    if not pairs:
        return set()
    t = int(timeout) or 1
    # wall-clock is ~one timeout (probes run concurrently) + docker/startup slack, not N*timeout.
    rc, out = _exec(src_container, _batch_script(pairs, t), timeout=t + 20)
    if rc == 127:                                   # docker unavailable
        return None
    open_set = set()
    for ln in out.splitlines():
        parts = ln.strip().split()
        if len(parts) == 2 and parts[1].isdigit():
            open_set.add((parts[0], int(parts[1])))
    return open_set


def scan_host(src_container, ip, ports, timeout=1):
    """Real connect-scan of `ports` on `ip` from `src_container`.
    Returns (observed, {port: open_bool}). observed=False means the scan could not
    run at all (no Docker) — distinct from 'ran and found everything closed'."""
    probe_rc, _ = _exec(src_container, "true", timeout=timeout + 2)
    if probe_rc in (127,):                      # docker unavailable
        return False, {p: False for p in ports}
    return True, {p: scan_port(src_container, ip, p, timeout) for p in ports}


def reveal_real(log, gate, actor, src_host, src_container, targets, *, timeout=1, banners=None):
    """Gate-mediated REAL recon. `targets` = [(target_host, target_ip, ports), ...].

    Each target is dispatched through the gate as a `recon` tool call; an out-of-scope
    target raises OutOfScope (logged gate.block, never scanned). For an allowed target,
    run the real connect-scan and append a `discovery` event tagged fidelity:"real".
    Returns {target_host: {port: open_bool}} for the targets that were scanned.

    `banners` (optional) maps target_ip -> an observed service banner (e.g. the HTTP Server
    header grabbed during the sweep); when present it becomes the service LABEL in belief
    instead of a bare "open", so red can tell a vulnerable Apache/2.4.49 from an nginx decoy.
    """
    from swarm.gate import OutOfScope
    banners = banners or {}

    results = {}
    for host, ip, ports in targets:
        def _do(h=host, i=ip, ps=ports):
            observed, open_map = scan_host(src_container, i, ps, timeout)
            open_ports = sorted(p for p, up in open_map.items() if up)
            label = banners.get(i) or "open"
            log.append(actor, "discovery", {
                "fidelity": "real", "source": "tcp-connect",
                "from": src_host, "kind": "services", "host": h,
                "scanned_ip": i, "observed": observed,
                "open_ports": open_ports,
                "services": {str(p): label for p in open_ports},
            })
            results[h] = open_map
            return open_map
        try:
            gate.dispatch(actor, "recon", host, _do,
                          meta={"mv_kind": "recon", "technique": "T1046", "dst_ip": ip})
        except OutOfScope:
            results[host] = "blocked"
    return results


def drop_oos(log, gate, actor, candidate_ips):
    """Gate the BLIND sweep's target set FIRST, FAIL-CLOSED (brief v3 A3; was 2026-10-29 HIGH-1).

    The old rule kept any ip NOT present as a known-out-of-scope alias — so an ip the gate could
    not vouch for (unknown, or an obfuscated spelling the alias map misses) passed through and was
    physically probed. This now dispatches EVERY candidate through the gate and keeps it ONLY on a
    gate.allow (it resolves to an in-scope host); every other candidate is a gate.block and dropped,
    never probed. One verdict per candidate, recorded in the recon phase. No network here — pure
    scope decisions — so the physical sweep that follows can reach no out-of-scope host."""
    from swarm.gate import OutOfScope
    keep = []
    for ip in candidate_ips:
        # FAIL-CLOSED (brief v3 A3): dispatch EVERY candidate. Keep it only if the gate ALLOWS it
        # (it resolves to an in-scope host); a known out-of-scope host OR one the gate cannot vouch
        # for (unknown / unparseable / an obfuscated IP spelling) raises OutOfScope -> a gate.block
        # is recorded and the ip is dropped, never physically probed. One verdict per candidate.
        try:
            gate.dispatch(actor, "recon", ip, lambda: None,
                          meta={"mv_kind": "recon", "technique": "T1046", "dst_ip": ip})
            keep.append(ip)
        except OutOfScope:
            pass
    return keep


if __name__ == "__main__":  # self-check: gate mediation + event shape, no Docker needed
    from swarm.gate import Gate

    class _Rec:
        def __init__(self): self.events = []
        def append(self, actor, action, data=None):
            self.events.append((actor, action, data)); return {}

    # Fake the real scan so the self-test needs no containers: pretend the pivot's
    # 8080 is open and everything else closed. Rebind the module global reveal_real
    # resolves at call time.
    scan_host = lambda c, ip, ports, timeout=1: (True, {p: (ip == "10.0.0.5" and p == 8080) for p in ports})

    log = _Rec()
    gate = Gate(["webserver", "db"], log)
    res = reveal_real(log, gate, "red", "attacker", "range-attacker", [
        ("webserver", "10.0.0.5", [8080]),   # in scope, open
        ("db",        "10.0.0.6", [22]),      # in scope, closed (no-route modeled)
        ("decoy",     "10.0.0.9", [22]),      # OUT of scope -> blocked, never scanned
    ])
    acts = [a for _, a, _ in log.events]
    assert acts == ["gate.allow", "discovery", "gate.allow", "discovery", "gate.block"], acts
    assert res["webserver"][8080] is True and res["db"][22] is False
    assert res["decoy"] == "blocked"
    # the blocked target produced NO discovery event (never scanned)
    disc_hosts = [d["host"] for _, a, d in log.events if a == "discovery"]
    assert "decoy" not in disc_hosts, disc_hosts
    # every discovery is tagged real, never a faked banner
    for _, a, d in log.events:
        if a == "discovery":
            assert d["fidelity"] == "real" and d["source"] == "tcp-connect"
            assert all(v == "open" for v in d["services"].values())
    # drop_oos (HIGH-1): the BLIND sweep gates its target set FIRST. A KNOWN out-of-scope host in the
    # swept range yields a recorded gate.block and is DROPPED (never reaches the physical sweep); an
    # in-scope host and an empty ip (no host in the alias map) pass through to the caller's sweep.
    log2 = _Rec()
    g2 = Gate([], log2, scope_by_actor={"red": ["web01"]})
    g2.aliases.update({"10.0.0.11": "web01", "10.0.0.13": "dc-01"})   # both KNOWN hosts; dc-01 is oos
    cand = ["10.0.0.1", "10.0.0.11", "10.0.0.12", "10.0.0.13"]        # empty, web01(in), empty, dc-01(oos)
    keep = drop_oos(log2, g2, "red", cand)
    acts2 = [(a, (d or {}).get("resolved") or (d or {}).get("target")) for _, a, d in log2.events]
    assert keep == ["10.0.0.1", "10.0.0.11", "10.0.0.12"], keep       # oos (.13) dropped; rest kept
    assert acts2 == [("gate.block", "dc-01")], acts2                  # exactly one block, for the oos host
    # in-scope host was NOT dispatched here (reveal_real gates it downstream — no double gate.allow)
    assert not any(a == "gate.allow" for a, _ in acts2), acts2
    print("live_recon ok (gated real connect-scan; oos target blocked+unscanned; "
          "discovery fidelity=real, no faked fingerprint; drop_oos gates the target set FIRST — "
          "a KNOWN oos host is blocked + dropped before any probe, in-scope + empty pass through)")
