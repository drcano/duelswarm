#!/usr/bin/env python3
"""Stage 3 — kernel-truth reachability (needs a real Linux host + root).

Establishes, from the KERNEL rather than the gate's log, which guarantee the
network carries and which the parser carries.

Oracle = the kernel + conntrack, NOT the gate. This checker shares no code with
`swarm/gate.py` or the duel engine: it reads only (a) the compose topology
(claimed scope) and (b) a capture of real `connect(2)` attempts + conntrack
state (measured truth). A stranger re-runs it against the same capture and gets
the same matrix.

Three pure, self-tested pieces + one live measurer:
  claimed_matrix(compose)  — the per-host reachability the topology PROMISES
                             (offline; derivable now).
  diff(claimed, measured)  — measured must be a SUBSET of claimed; any extra
                             reach is a VIOLATION (kernel reaches past the claim).
  correlate(capture, log)  — every real outbound connect either rode a
                             gate.allow in the hash-chained log or is tagged as
                             the labeled class-2 raw (uninstrumented) path.
  measure(entry, ...)      — LIVE: from each container, connect-probe every host
                             + the docker-host gateway + the internet, and read
                             conntrack. Degrades cleanly (available:False) with
                             no Docker/root, so the floor claim stays UNRUN, not
                             falsely PASSED.

STATUS ON THIS HOST: the live measurer is UNRUN — this macOS box is a LinuxKit
VM (CLAUDE.md F2 §E: §E is moot here). `--measure` must run on the Linux deploy
host with root. `--selftest` exercises the pure logic on the real compose + a
synthetic capture fixture, no Docker needed, and is wired into `make test`.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
IN_SCOPE = {"struts", "db", "jenkins"}          # SPEC §4 authorized set
INTERNET_PROBES = ("1.1.1.1", "example.com")


def _short(name):
    return name.replace("range-", "")


def claimed_matrix(compose_path=COMPOSE):
    """Per-host reachability the TOPOLOGY promises (offline).

    Rule: two containers can reach each other iff they share a docker network.
    `internal: true` networks carry no egress; the `ingress` bridge (masquerade
    off) gives its members L3 reach to the docker-HOST gateway (F2 §E) but no
    internet SNAT. Returns dict: host -> {"hosts": set, "host_gateway": bool,
    "internet": bool}."""
    spec = yaml.safe_load(Path(compose_path).read_text())
    nets = spec.get("networks", {})
    ingress_nets = {n for n, cfg in nets.items()
                    if not (cfg or {}).get("internal", False)}
    members = {}            # network -> set(host)
    host_nets = {}          # host -> set(network)
    for svc, cfg in spec.get("services", {}).items():
        host = _short(cfg.get("container_name", svc))
        hn = cfg.get("networks", [])
        hn = list(hn.keys()) if isinstance(hn, dict) else list(hn)
        host_nets[host] = set(hn)
        for n in hn:
            members.setdefault(n, set()).add(host)
    claimed = {}
    for host, hn in host_nets.items():
        reach = set()
        for n in hn:
            if n in ingress_nets:
                continue                         # ingress != inter-container mesh
            reach |= members.get(n, set())
        reach.discard(host)
        claimed[host] = {
            "hosts": reach,
            "host_gateway": bool(hn & ingress_nets),   # F2 §E gap
            "internet": False,                          # all internal / no SNAT
        }
    return claimed


def diff(claimed, measured):
    """measured must be a SUBSET of claimed. Returns list of VIOLATIONS: a real
    reach the topology did not promise. `measured`: host -> {"hosts": set,
    "host_gateway": bool, "internet": bool}."""
    violations = []
    for host, m in measured.items():
        c = claimed.get(host, {"hosts": set(), "host_gateway": False, "internet": False})
        extra = set(m.get("hosts", set())) - set(c["hosts"])
        for dst in sorted(extra):
            violations.append({"src": host, "dst": dst, "kind": "host-reach-not-claimed"})
        if m.get("internet") and not c["internet"]:
            violations.append({"src": host, "dst": "internet", "kind": "internet-egress"})
        # host_gateway reach beyond claim is the §E residual, reported separately
        if m.get("host_gateway") and not c["host_gateway"]:
            violations.append({"src": host, "dst": "docker-host-gateway",
                               "kind": "host-gateway-not-claimed"})
    return violations


def floor_invariants(claimed, measured):
    """The two floor facts, read off the MEASURED matrix: no in-scope->oos reach,
    no internet egress from any host."""
    oos = set(claimed) - IN_SCOPE
    oos_reaches, inet_reaches = [], []
    for host, m in measured.items():
        if host in IN_SCOPE:
            for dst in m.get("hosts", set()):
                if dst in oos:
                    oos_reaches.append((host, dst))
        if m.get("internet"):
            inet_reaches.append(host)
    return {"oos_tcp_reaches": oos_reaches, "internet_reaches": inet_reaches,
            "floor_holds": not oos_reaches and not inet_reaches}


def correlate(capture, log_entries):
    """Every real outbound connect in `capture['connects']` must ride a
    gate.allow in the hash-chained log OR carry raw_path=True (the labeled
    class-2 uninstrumented channel). Returns the unexplained connects."""
    allowed = set()
    for e in log_entries:
        if e.get("action") == "gate.allow":
            d = e.get("data", {})
            for k in ("target", "resolved"):
                if d.get(k):
                    allowed.add(d[k])
    unexplained = []
    for c in capture.get("connects", []):
        if c.get("raw_path"):
            continue                              # labeled class-2 path, by design
        dst = c.get("dst")
        if dst not in allowed:
            unexplained.append(c)
    return unexplained


# ── LIVE measurement (needs Docker + root; degrades cleanly otherwise) ──────
def _exec(container, cmd, timeout=6, shell="sh"):
    try:
        r = subprocess.run(["docker", "exec", container, shell, "-c", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "docker not available"
    except Exception as e:
        return 1, str(e)


def _has_bash(container):
    return _exec(container, "command -v bash")[0] == 0


def _tcp_reaches(container, ip, port, timeout=2):
    """Real connect(2) from inside `container` to ip:port via bash /dev/tcp.
    The kernel decides OPEN (SYN/ACK) vs SHUT (refused/dropped-on-route).
    Needs bash (alpine ash lacks /dev/tcp) — callers guard with _has_bash."""
    rc, out = _exec(container,
                    f"timeout {timeout} bash -c '(echo >/dev/tcp/{ip}/{port}) "
                    f"2>/dev/null && echo OPEN || echo SHUT'",
                    timeout=timeout + 2, shell="bash")
    return "OPEN" in out and "SHUT" not in out


def _l3_pingable(container, ip, timeout=2):
    rc, out = _exec(container, f"ping -c1 -W{timeout} {ip}", timeout=timeout + 2)
    return "bytes from" in out and "0 packets received" not in out


def _discover_ips():
    """Real per-host IPs from docker inspect (the ground truth, not the gate's
    guess). Returns {short_name: [ip, ...]} — ALL addresses, because a
    multi-homed host (struts/jenkins on range+ingress) is only reachable from a
    peer on the IP of the network they actually share."""
    ips = {}
    try:
        names = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                               capture_output=True, text=True, timeout=6).stdout.split()
    except Exception:
        return ips
    for name in names:
        if not name.startswith("range-"):
            continue
        r = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
            capture_output=True, text=True, timeout=6)
        addrs = r.stdout.split()
        if addrs:
            ips[_short(name)] = addrs
    return ips


def measure(hosts, host_gateway_ip=None, ports=(22, 80, 389, 25, 8080, 5432)):
    """From every container, connect-probe every host BY REAL IP (the Stage-2
    bypasses resolve to an IP, so probing by name would conflate DNS-isolation
    with L3/L4-isolation). Also L3-ping the gateway (§E) and probe the internet.
    Returns (available, measured_matrix, capture_connects). available=False with
    no Docker / unbooted range (UNRUN, never a false PASS)."""
    ips = _discover_ips()
    if not ips or any(h not in ips for h in hosts):
        return False, {}, []
    measured, connects = {}, []
    for src in hosts:
        sc = f"range-{src}"
        if _exec(sc, "true")[0] != 0:          # liveness via sh (universal)
            return False, {}, []
        has_bash = _has_bash(sc)               # L4 /dev/tcp needs bash
        reach = set()
        for dst in hosts:
            if dst == src:
                continue
            # Probe ALL of dst's IPs; reachable on ANY shared-network IP counts.
            hit_ip = open_port = None
            l3 = False
            for dip in ips[dst]:
                p = (next((p for p in ports if _tcp_reaches(sc, dip, p)), None)
                     if has_bash else None)
                ping = _l3_pingable(sc, dip)
                if p is not None or ping:
                    hit_ip, open_port, l3 = dip, p, ping
                    break
                hit_ip = dip
            ok = open_port is not None
            connects.append({"src": src, "dst": dst, "dst_ips": ips[dst],
                             "reached_on_ip": (hit_ip if (ok or l3) else None),
                             "l4_open_port": open_port,
                             "l4_measured": has_bash, "l3_ping": l3,
                             "reached": ok or l3, "raw_path": True})
            if ok or l3:
                reach.add(dst)
        inet = False
        for h in INTERNET_PROBES:
            rc, out = _exec(sc, f"curl -s -m 4 http://{h}/ -o /dev/null -w '%{{http_code}}'")
            hit = any(c in out for c in ("200", "301", "302"))
            inet = inet or hit
            connects.append({"src": src, "dst": f"internet:{h}", "l4_open_port": None,
                             "l3_ping": _l3_pingable(sc, h), "reached": hit,
                             "raw_path": True})
        gw = False
        if host_gateway_ip:
            gw_l4 = _tcp_reaches(sc, host_gateway_ip, 22) if has_bash else False
            gw_l3 = _l3_pingable(sc, host_gateway_ip)
            gw = gw_l4 or gw_l3
            connects.append({"src": src, "dst": "docker-host-gateway",
                             "dst_ip": host_gateway_ip, "l4_open_port": 22 if gw_l4 else None,
                             "l3_ping": gw_l3, "reached": gw, "raw_path": True})
        measured[src] = {"hosts": reach, "internet": inet, "host_gateway": gw}
    return True, measured, connects


def _selftest():
    claimed = claimed_matrix()
    # Topology sanity: in-scope mesh reachable, oos NOT in in-scope reach.
    assert "db" in claimed["struts"]["hosts"], claimed["struts"]
    assert "jenkins" in claimed["struts"]["hosts"]
    assert "decoy" not in claimed["struts"]["hosts"], "in-scope must NOT claim oos"
    assert "struts" not in claimed["decoy"]["hosts"], "oos must NOT claim in-scope"
    assert claimed["struts"]["host_gateway"] is True, "struts on ingress (F2 §E)"
    assert claimed["db"]["host_gateway"] is False, "db has no ingress"
    assert all(not c["internet"] for c in claimed.values()), "no internet claimed"

    # diff: a measured matrix that matches the claim has no violations.
    good = {h: {"hosts": set(c["hosts"]), "internet": False,
                "host_gateway": c["host_gateway"]} for h, c in claimed.items()}
    assert diff(claimed, good) == [], "clean measurement must not violate"
    # a measured in-scope->oos reach is a violation AND breaks the floor.
    bad = {h: {"hosts": set(c["hosts"]), "internet": False,
               "host_gateway": c["host_gateway"]} for h, c in claimed.items()}
    bad["struts"]["hosts"].add("decoy")
    bad["struts"]["internet"] = True
    v = diff(claimed, bad)
    assert any(x["dst"] == "decoy" for x in v) and any(x["dst"] == "internet" for x in v), v
    fi = floor_invariants(claimed, bad)
    assert fi["floor_holds"] is False and ("struts", "decoy") in fi["oos_tcp_reaches"]
    assert floor_invariants(claimed, good)["floor_holds"] is True

    # correlate: a connect with no gate.allow and no raw_path is unexplained;
    # one that rode an allow, or is tagged raw, is explained.
    log = [{"action": "gate.allow", "data": {"tool": "recon", "target": "db"}}]
    cap = {"connects": [
        {"src": "struts", "dst": "db"},                 # explained (allow)
        {"src": "struts", "dst": "decoy"},              # UNEXPLAINED
        {"src": "struts", "dst": "ldap", "raw_path": True},  # labeled class-2
    ]}
    un = correlate(cap, log)
    assert [c["dst"] for c in un] == ["decoy"], un
    print("reachability_probe selftest ok (claimed matrix from compose; "
          "diff/floor/correlate logic verified on fixtures; live measurer UNRUN "
          "on this LinuxKit VM — run --measure on the Linux deploy host)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--claimed", action="store_true", help="print claimed matrix")
    ap.add_argument("--measure", action="store_true",
                    help="LIVE kernel probe (needs Docker+root on Linux)")
    ap.add_argument("--gateway", help="docker-host gateway IP for the §E probe")
    ap.add_argument("--log", help="hash-chained event log for correlation")
    ap.add_argument("--capture", help="connect-capture JSON to correlate/diff")
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return 0

    claimed = claimed_matrix()
    if args.claimed:
        print(json.dumps({h: {"hosts": sorted(c["hosts"]),
                              "host_gateway": c["host_gateway"],
                              "internet": c["internet"]}
                          for h, c in claimed.items()}, indent=2))
        return 0

    if args.measure:
        avail, measured, connects = measure(set(claimed), host_gateway_ip=args.gateway)
        if not avail:
            print("UNRUN: no booted range / no Docker (expected on a non-Linux host). "
                  "Run on the Linux deploy host with root.")
            return 0
        v = diff(claimed, measured)
        fi = floor_invariants(claimed, measured)
        cap_obj = {"connects": connects}
        if args.capture:
            Path(args.capture).write_text(json.dumps(cap_obj, indent=2))
        out = {"measured": {h: {"hosts": sorted(m["hosts"]),
                                "internet": m["internet"],
                                "host_gateway": m["host_gateway"]}
                            for h, m in measured.items()},
               "violations": v, "floor": fi}
        if args.log:
            log = [json.loads(l) for l in Path(args.log).read_text().splitlines() if l.strip()]
            out["unexplained_connects"] = correlate(cap_obj, log)
        print(json.dumps(out, indent=2))
        return 0 if fi["floor_holds"] and not v else 1

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
