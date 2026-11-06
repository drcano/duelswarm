# Egress floor — the one documented residual (FULL_BUILD_BRIEF Phase 3, F4)

**Precise floor claim: network-isolation-primary, parser-secondary, one documented residual.**

## What is CLOSED (structural, not cooperative)

Internet egress from any range container is **structurally absent**, not merely denied:

- Every data-plane network (`range_attacker`, `range_dmz`/segment nets, `range_db_net`,
  `range_oos`) is `internal: true` — Docker installs no SNAT/MASQUERADE for them, so there is
  no route off the bridge at all.
- The entry stays reachable only through a single `ingress` bridge with
  `com.docker.network.bridge.enable_ip_masquerade: false` — DNAT **in** (published port →
  struts:8080) works, but with masquerade **off** there is no SNAT **out**, so it is not an
  egress route to the internet.

`scripts/prove_env_boundaries.py` asserts this as a structural theorem (runs in `make test`),
and the `--live` mode drives red through the uninstrumented channel and shows every out-of-scope
reach fails at the kernel even with the gate removed.

## The RESIDUAL (measured, not closed)

A masquerade-off bridge still hands its containers a **default route via the bridge gateway**,
which *is* the Docker host. So the entry retains **L3 reach to the Docker host** (and thus to
host-published ports) — it does **not** reach the internet.

Measured directly on a masquerade-off bridge (2026-10-19, this machine):

```
bridge gateway (Docker host): 172.20.0.1
default via 172.20.0.1 dev eth0
ping Docker-host gateway  -> HOST GATEWAY REACHABLE   (residual present)
ping 1.1.1.1 (internet)   -> internet unreachable     (floor holds: no SNAT)
```

Reproduce:

```bash
docker network create --driver bridge -o com.docker.network.bridge.enable_ip_masquerade=false ds_probe
GW=$(docker network inspect ds_probe -f '{{(index .IPAM.Config 0).Gateway}}')
docker run --rm --network ds_probe alpine sh -c \
  "ping -c1 -W2 $GW; ping -c1 -W2 1.1.1.1"   # gateway up, internet down
docker network rm ds_probe
```

## Why it is not closed in compose

The same gateway that leaks host L3 reach is the DNAT path that makes the Struts entry
reachable for the real CVE-2017-5638 exploit. Dropping the container's default route / the
bridge gateway to sever host reach also severs inbound DNAT, so the measured path (which needs
to reach `struts:8080`) breaks. Docker compose cannot express "DNAT in, no gateway route out"
on one bridge.

## The fix (host-side, out of compose scope)

A **host-side egress firewall** closes it without touching ingress: a bridge-level `iptables`
rule (or a cloud security group) that drops entry→host and entry→host-published traffic while
leaving established inbound DNAT flows. This is deployment configuration, not range topology, so
it lives with the host, not in `docker-compose.yml`.

## Scope statement for the falsification report

The floor defended by this testbed is **no internet egress** (structural: `internal:true` +
masquerade-off), with the dispatch parser as an additive second layer. The **one residual** is
entry↔Docker-host L3 via the ingress gateway, which needs a host-side firewall. This residual is
an L3 reach to the *local host*, not an escape to any real external target, and it is stated
here rather than silently absorbed into the floor claim.
