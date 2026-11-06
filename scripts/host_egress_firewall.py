#!/usr/bin/env python3
"""Host-side egress firewall — closes the §E gap the compose file cannot.

The topology guarantee (F2) is airtight for the INTERNET: both data-plane nets are
`internal: true`, and the `ingress` bridge runs with IP-masquerade OFF, so no range
container has an SNAT route out. The one hole left (proof section E) is that the entry
still has L3 reach to the Docker HOST via the ingress bridge gateway: it can ping the
gateway IP and hit host-published ports / any service the host binds on 0.0.0.0.
That is a native-Linux *deployment* concern — a packet destined to the host IP lands
in iptables INPUT / nat-PREROUTING, not the FORWARD path a compose file can shape —
so it is closed here, on the host, not in docker-compose.yml.

What it installs (see `_install_rules`) — conntrack-aware, in filter/INPUT:
  1. accept ESTABLISHED,RELATED from the bridge, so replies to connections the HOST
     initiated survive — including the docker-proxy localhost hairpin that the live
     Struts foothold (http://127.0.0.1:<port>) and measured_duel / prove_n2n3 / vet_pool
     rely on. These are host-initiated flows the container only answers; it cannot turn
     them into a new connection to the host.
  2. drop everything else from the bridge to ANY host IP — this blocks a container from
     INITIATING a connection to the host gateway (the §E escape) or any host interface
     (multi-homed defense for the deploy box's eth0). NEW container->gateway is dropped;
     the pivot path (dest = another container IP, FORWARD not INPUT) is untouched.

Why not a raw/PREROUTING blanket drop to the gateway? The earlier design used one, but
being pre-conntrack it also killed the docker-proxy localhost hairpin (the proxy sources
from the gateway IP, so the container's reply is dst=gateway) — which broke the live
Struts foothold. filter/INPUT with the ESTABLISHED accept closes §E identically for
container-INITIATED traffic while preserving that legitimate inbound. `--down` still
removes the legacy raw rule (`_legacy_rules`) to clean hosts that had the old version.

Platform note: the deploy host is now a NATIVE-Linux machine,
so the ingress bridge is a real host interface and §E is a live concern this closes —
exactly why Phase 0a hardens it (we are about to run real offensive tooling + a real AD
tier inside the range). `make range-up`/`range-down` install/remove it with the range;
run the `--*` forms directly for ops. On a non-Linux host (e.g. Docker Desktop's LinuxKit
VM, which already isolates via its own VM) `--verify` SKIPs and `--up`/`--down` are no-ops
through the Makefile's best-effort hook. `--selftest` is deterministic (no root, no docker)
and checks the rule logic; it is wired into `make test`.

  sudo python scripts/host_egress_firewall.py --up       # install (Linux, range up)
  sudo python scripts/host_egress_firewall.py --down      # remove
  sudo python scripts/host_egress_firewall.py --verify    # probe §E closed, §B intact
  python scripts/host_egress_firewall.py --selftest        # rule-logic check (any OS)

Privilege model (Phase 0a): the live standup (swarm/range_runtime) installs/removes this
automatically, but the DUEL PROCESS NEVER RUNS AS ROOT. It calls --up/--down via `sudo -n`,
with root confined to this one script by a narrow NOPASSWD sudoers line. --up/--down are
stdlib-only, so they run under a FIXED /usr/bin/python3 to keep that rule stable:
  <user> ALL=(root) NOPASSWD: /usr/bin/python3 <repo>/scripts/host_egress_firewall.py --up, \
                              /usr/bin/python3 <repo>/scripts/host_egress_firewall.py --down
--verify stays non-root and is authoritative: range_runtime HALTS the standup if §E is open.
"""
import argparse
import json
import platform
import shutil
import subprocess
import sys

COMMENT = "duelswarm-hostguard"            # tags our rules for idempotent teardown
INGRESS_NET = "duelswarm-range_ingress"    # docker network name (range_gen uses the same)


def _install_rules(bridge, gateway):
    """The rules §E INSTALLS, as table/chain/spec dicts. Conntrack-aware filter/INPUT:
    accept ESTABLISHED,RELATED replies (so legit inbound, incl. the docker-proxy localhost
    hairpin the live Struts foothold uses, survives), then drop everything else the bridge
    sends to a host IP (blocks container-INITIATED reach to the gateway/host — the §E
    closure). `gateway` is unused here (INPUT covers all host IPs incl. the gateway) but
    kept in the signature so callers pass (bridge, gateway) uniformly.

    List order is the final top-to-bottom order within the chain (see `up`, which inserts
    in reverse so element 0 ends up on top). The ESTABLISHED,RELATED ACCEPT MUST stay above
    the DROP, or inbound-DNAT return traffic dies."""
    c = ["-m", "comment", "--comment", COMMENT]
    return [
        {"table": "filter", "chain": "INPUT",
         "rule": ["-i", bridge, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                  "-j", "ACCEPT", *c]},
        {"table": "filter", "chain": "INPUT",
         "rule": ["-i", bridge, "-j", "DROP", *c]},
    ]


def _legacy_rules(bridge, gateway):
    """Deprecated rule the earlier design installed: a pre-conntrack raw/PREROUTING blanket
    drop to the gateway. It also killed the docker-proxy localhost hairpin (dst=gateway on
    the reply), breaking the live Struts foothold, so it is no longer installed — but
    `down` still removes it to clean hosts that ran the old version."""
    c = ["-m", "comment", "--comment", COMMENT]
    return [
        {"table": "raw", "chain": "PREROUTING",
         "rule": ["-i", bridge, "-d", gateway, "-j", "DROP", *c]},
    ]


def rules_for(bridge, gateway):
    """Back-compat alias = the INSTALL set (`_install_rules`)."""
    return _install_rules(bridge, gateway)


def _cmd(r, op, at_top=False):
    base = ["iptables", "-t", r["table"], op, r["chain"]]
    if op == "-I" and at_top:
        base += ["1"]
    return base + r["rule"]


def _run(cmd, check=True, timeout=20):
    """Run a command, never hanging: a stuck curl/iptables times out and returns a
    non-zero result instead of blocking --verify forever (the ^C bug on first run)."""
    try:
        return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, 124, stdout=(e.stdout or ""),
                                           stderr=f"timeout after {timeout}s")


def _present(r):
    # iptables -C returns 0 iff the exact rule exists.
    return _run(_cmd(r, "-C"), check=False).returncode == 0


def discover(net=INGRESS_NET):
    """(bridge-iface, gateway-ip) for the ingress network, from docker inspect.
    The ingress subnet is Docker-assigned (not pinned in compose), so read it live.
    The net NAME varies by compose project (duelswarm-range_ingress for the root range,
    duelswarm-range-<seed>_ingress for a generated one), so if the pinned name is absent,
    fall back to the one DNAT ingress bridge — a range net whose name ends in `ingress`."""
    candidates = [net]
    try:
        allnets = subprocess.check_output(
            ["docker", "network", "ls", "--format", "{{.Name}}"], text=True).split()
        candidates += [n for n in allnets if n != net and n.endswith("ingress")]
    except Exception:
        pass
    for n in candidates:
        try:
            info = json.loads(subprocess.check_output(["docker", "network", "inspect", n]))[0]
        except Exception:
            continue
        bridge = info.get("Options", {}).get("com.docker.network.bridge.name") \
            or "br-" + info["Id"][:12]
        gw = info["IPAM"]["Config"][0]["Gateway"]
        return bridge, gw
    raise RuntimeError("no ingress network found — is the range up? "
                       f"(looked for {net!r} then any *_ingress net)")


def _discover_entry_and_pivot():
    """(entry_container, pivot_service): the published entry (a member of the ingress
    net) and one OTHER in-scope host to pivot to. Container names are `range-<host>`;
    the in-container DNS target is the bare service name, so the pivot is returned
    de-prefixed. Returns (None, None) if nothing is booted — never a hardcoded host."""
    entry = pivot = None
    try:
        for net in subprocess.check_output(
                ["docker", "network", "ls", "--format", "{{.Name}}"], text=True).split():
            if not net.endswith("ingress"):
                continue
            info = json.loads(subprocess.check_output(["docker", "network", "inspect", net]))[0]
            members = [c["Name"] for c in info.get("Containers", {}).values()]
            if members:
                entry = members[0]
                break
    except Exception:
        return None, None
    # Pivot = an in-scope host the entry can ACTUALLY reach: one that shares a non-ingress
    # (data-plane) network with the entry. Picking any in-scope host in `docker ps` order can land
    # on a non-adjacent tier (e.g. a Tier-0 mgmt/identity host), which is correctly UNREACHABLE by
    # segmentation and would turn the "duel stays playable" (in_scope_reaches>0) check into a false
    # FAIL. Adjacency = a shared data segment, so the probe tests a real in-scope edge.
    def _data_nets(container):
        try:
            info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            return {n for n in info["NetworkSettings"]["Networks"] if not n.endswith("ingress")}
        except Exception:
            return set()
    try:
        entry_nets = _data_nets(entry)
        in_scope = []
        out = subprocess.check_output(
            ["docker", "ps", "--format", '{{.Names}}\t{{.Label "duelswarm.scope"}}'], text=True)
        for line in out.splitlines():
            name, _, scope = line.partition("\t")
            if name and name != entry and name != "range-attacker" and scope == "in":
                in_scope.append(name)
        # prefer an in-scope host adjacent to the entry (shares a data segment); else fall back.
        adjacent = [n for n in in_scope if _data_nets(n) & entry_nets]
        chosen = adjacent or in_scope
        if chosen:
            pivot = chosen[0][len("range-"):] if chosen[0].startswith("range-") else chosen[0]
    except Exception:
        pass
    return entry, pivot


def _published_hostport(container):
    """The host-side published port of `container` (varies by seed), from `docker port`."""
    try:
        for line in subprocess.check_output(["docker", "port", container], text=True).splitlines():
            if "->" in line:
                return line.rsplit(":", 1)[-1].strip()
    except Exception:
        pass
    return None


def up():
    bridge, gw = discover()
    rules = rules_for(bridge, gw)
    # Insert in reverse so rules[0] lands on top and the chain order matches the list.
    for r in reversed(rules):
        if _present(r):
            print(f"  present  {r['table']}/{r['chain']}: {' '.join(r['rule'])}")
        else:
            _run(_cmd(r, "-I", at_top=True))
            print(f"  added    {r['table']}/{r['chain']}: {' '.join(r['rule'])}")
    print(f"host-guard UP on bridge {bridge} (gateway {gw})")


def down():
    bridge, gw = discover()
    # Remove the current install set AND the deprecated raw rule, so a host that ran the
    # old version (which installed the raw/PREROUTING drop) is cleaned too.
    for r in _install_rules(bridge, gw) + _legacy_rules(bridge, gw):
        n = 0
        while _present(r):
            _run(_cmd(r, "-D"))
            n += 1
        print(f"  removed {n}x  {r['table']}/{r['chain']}: {' '.join(r['rule'])}")
    print("host-guard DOWN")


def _exec(container, *args):
    return _run(["docker", "exec", container, *args], check=False)


def verify():
    """Probe that §E is closed and §B/§C still work. Linux + docker + range up.

    Entry/pivot/published-port are DISCOVERED from the booted range (no hardcoded host
    names), and the gateway reach uses the TCP-response probe in swarm.uninstrumented —
    NOT ICMP, because Phase 0a drops CAP_NET_RAW so `ping` can no longer open a raw socket
    and would read as a false 'blocked' whether or not this firewall is installed."""
    # Exit-code contract (MEDIUM-6): 0 = PASS, 1 = FAIL, 2 = SKIP/INCONCLUSIVE. A caller that trusts
    # the exit code can now tell a real PASS from a skipped/uncertifiable run — before, SKIP and PASS
    # both returned 0 and a vacuous SKIP read as a pass.
    if platform.system() != "Linux":
        print(f"SKIP: --verify needs the native-Linux deploy host (this is "
              f"{platform.system()}; Docker Desktop isolates via its VM). Rule logic "
              f"is covered by --selftest.")
        return 2
    # the canonical reach measurement lives in one place (the class-2 uninstrumented
    # channel); reuse it here rather than re-implement with hardcoded names.
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from swarm import uninstrumented as u

    try:
        bridge, gw = discover()
    except RuntimeError as e:
        print(f"SKIP: no booted range ({e}) — bring the range up first.")
        return 2
    entry, pivot = _discover_entry_and_pivot()
    if not entry:
        print("SKIP: no booted range (ingress net has no containers) — bring the range up first.")
        return 2
    print(f"ingress bridge {bridge}, host gateway {gw}; entry={entry} pivot={pivot or '(none)'}\n")

    # (C) LIVENESS CONTROL, FIRST (MEDIUM-6): the §E 'unreachable' verdicts below are only meaningful
    # if the probe mechanism itself works from this entry. An in-scope pivot MUST be reachable; if it
    # is not, we cannot distinguish 'blocked by §E' from 'the probe/container is broken' — that is
    # INCONCLUSIVE, never PASS. Without a discovered pivot there is no liveness control, so §E reads
    # cannot be certified as a clean PASS either.
    if pivot:
        live = any(u.tcp_reaches(entry, pivot, p, timeout=2) for p in (22, 80, 8080, 5432))
        print(f"  (C) {entry} -> {pivot} (pivot liveness)   {'PIVOT-OK' if live else 'UNREACHABLE'}")
        if not live:
            print("\nRESULT: INCONCLUSIVE — the liveness control failed (entry cannot reach an "
                  "in-scope pivot), so an 'unreachable' §E read below cannot be trusted as blocking.")
            return 2
    else:
        print("  (C) no in-scope pivot discovered — liveness control unavailable.")
        live = None

    ok = True

    # (E) entry -> host gateway: MUST be unreachable now (TCP-response, not ICMP).
    gw_reach = u.host_gateway_reachable(entry, gw)
    ok &= not gw_reach
    print(f"  (E) {entry} -> gateway {gw}   "
          f"{'UNREACHABLE-OK' if not gw_reach else 'REACHABLE-FAIL'}")

    # (D) entry -> open INTERNET: MUST be unreachable (MEDIUM-6 — §E's whole point is no egress to the
    # world; --verify used to test only the gateway + ingress + pivot and never the internet, so it
    # could pass while egress leaked. The run-time floor.boundary witness already tested this; now
    # --verify does too).
    inet = [f"{h}:{p}" for h, p in (("1.1.1.1", 443), ("example.com", 80))
            if u.tcp_reaches(entry, h, p, timeout=3)]
    ok &= not inet
    print(f"  (D) {entry} -> internet   {'BLOCKED-OK' if not inet else f'REACHED-FAIL {inet}'}")

    # (B) host -> entry published port (discovered): MUST still work (inbound DNAT survives).
    hostport = _published_hostport(entry)
    if hostport and shutil.which("curl"):
        code = _run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "4", f"http://localhost:{hostport}"], check=False).stdout
        works = code not in ("", "000")
        ok &= works
        print(f"  (B) host -> localhost:{hostport}        "
              f"{'REACHABLE-OK' if works else 'BLOCKED-FAIL'} [http_code={code}]")

    if live is None:                        # no liveness control -> cannot certify a clean PASS
        print("\nRESULT: INCONCLUSIVE — no in-scope pivot to serve as a liveness control, so the §E "
              "'unreachable' reads cannot be certified as blocking (not a PASS).")
        return 2
    print("\nRESULT:", "PASS — §E closed (gateway + internet unreachable), ingress + pivots intact"
          if ok else "FAIL")
    return 0 if ok else 1


def selftest():
    """Deterministic check of the rule logic — no root, no docker, any OS."""
    rules = _install_rules("br-deadbeef", "172.22.0.1")

    # §E is now enforced entirely in filter/INPUT (conntrack-aware) — NO raw/PREROUTING
    # rule in the install set (that one broke the docker-proxy localhost hairpin).
    assert all(r["table"] == "filter" and r["chain"] == "INPUT" for r in rules), \
        "install set must be filter/INPUT only (no pre-conntrack blanket drop)"
    assert len(rules) == 2, rules

    # INPUT: ESTABLISHED,RELATED ACCEPT must precede the DROP (else inbound/hairpin dies).
    inp = rules
    assert "ACCEPT" in inp[0]["rule"] and "ESTABLISHED,RELATED" in inp[0]["rule"], inp[0]
    assert inp[1]["rule"] == ["-i", "br-deadbeef", "-j", "DROP",
                              "-m", "comment", "--comment", COMMENT], inp[1]
    # `up` inserts reversed with -I 1, so list-order == final top-to-bottom order:
    # the ACCEPT (inp[0]) ends up above the DROP (inp[1]). Guard it.
    assert rules.index(inp[0]) < rules.index(inp[1]), "ACCEPT must sit above DROP"

    # The DROP matches the bridge only (no -d): it blocks container-INITIATED traffic to
    # ANY host IP incl. the gateway, while the ESTABLISHED accept lets replies through.
    assert "-d" not in inp[1]["rule"], "INPUT drop is bridge-scoped, not a single dest"

    # The legacy raw rule is still produced for TEARDOWN only (clean old hosts), and it is
    # the only place -d <gateway> appears.
    legacy = _legacy_rules("br-deadbeef", "172.22.0.1")
    assert len(legacy) == 1 and legacy[0]["table"] == "raw", legacy
    assert legacy[0]["rule"][:4] == ["-i", "br-deadbeef", "-d", "172.22.0.1"], legacy

    # Every rule (install + legacy) is tagged so --down removes exactly what was added.
    assert all(r["rule"][-4:] == ["-m", "comment", "--comment", COMMENT]
               for r in rules + legacy)

    # Command construction: -I goes to the top, -C/-D omit the position.
    assert _cmd(inp[0], "-I", at_top=True)[:6] == ["iptables", "-t", "filter", "-I", "INPUT", "1"]
    assert _cmd(inp[1], "-C")[:5] == ["iptables", "-t", "filter", "-C", "INPUT"]
    assert _cmd(legacy[0], "-D")[:5] == ["iptables", "-t", "raw", "-D", "PREROUTING"]

    # _run bounds every command (the ^C-on-verify bug): timeout yields rc 124, never a hang.
    r = _run(["sleep", "5"], check=False, timeout=1)
    assert r.returncode == 124, r
    print("host_egress_firewall selftest: OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--up", action="store_true", help="install the host guard (Linux, root)")
    g.add_argument("--down", action="store_true", help="remove the host guard")
    g.add_argument("--verify", action="store_true", help="probe §E closed, §B/§C intact")
    g.add_argument("--selftest", action="store_true", help="rule-logic check (any OS)")
    a = ap.parse_args()
    if a.selftest:
        selftest()
    elif a.verify:
        sys.exit(verify())
    elif a.up:
        up()
    else:
        down()
