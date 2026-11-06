"""Real network substrate model (Brick 0, DUELSWARM_LIQUID_SPEC §4).

Ported minimal from Incalmo's network model (incalmo/core/models/network/*):
`Subnet / Host / OpenPort / SSHCredential / Network`. Real CIDR via stdlib
`ipaddress` — NO hand-rolled IP math. Reachability is COMPUTED from the topology
(which hosts are multi-homed on which subnets), never asserted — so when the gate
blocks a cross-segment action it is enforcing something physically real: the
attacker subnet literally cannot route to the crown except through a pivot that
bridges the two subnets.

This module is the single source of truth for the range's IP/subnet layout.
`plan_network(range_dict)` turns a swarm.range_gen range into a real segmented
`Network` (attacker / dmz / internal subnets, multi-homed pivots, crown on the
internal subnet only); swarm.range_gen.to_compose consumes it to assign real IPAM
CIDRs + static container IPs, and emits it into the `range.topology` log event.
"""
import sys
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/netmodel.py`

# Three real private segments (DUELSWARM_LIQUID_SPEC §4: attacker .9 / web .10 / db .11).
ATTACKER_CIDR = "10.9.0.0/24"
DMZ_CIDR = "10.10.0.0/24"
INTERNAL_CIDR = "10.11.0.0/24"
DATA_CIDR = "10.12.0.0/24"  # crown/data tier: reachable ONLY via its spine parent (depth >=2)
OOS_CIDR = "10.99.0.0/24"   # out-of-scope hosts (isolated network, F2)


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str = ""
    cve: tuple = ()          # tuple (not list) so Host stays hashable/copyable


@dataclass
class SSHCredential:
    host_ip: str
    username: str
    port: int = 22
    agent_discovered: str = None    # the red agent that found it (None = seeded)
    utilized: bool = False


@dataclass
class Subnet:
    ip_mask: str                     # real CIDR, e.g. "10.11.0.0/24"
    attacker_subnet: bool = False

    def network(self):
        return ipaddress.ip_network(self.ip_mask, strict=False)

    def contains(self, ip):
        return ipaddress.ip_address(ip) in self.network()


@dataclass
class Host:
    ip_addresses: list               # multi-homed when len > 1 (a pivot bridges subnets)
    hostname: str = ""
    open_ports: dict = field(default_factory=dict)     # {port: OpenPort}
    ssh_config: list = field(default_factory=list)      # [SSHCredential]
    infected: bool = False
    infection_source: str = None     # hostname of the host red pivoted from


@dataclass
class Network:
    subnets: list = field(default_factory=list)         # [Subnet]
    hosts: list = field(default_factory=list)           # [Host]

    # Incalmo-named primitive: real CIDR membership, no hand-rolled math.
    def is_ip_in_ipmask(self, ip, ip_mask):
        return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_mask, strict=False)

    def is_ip_in_subnet(self, ip, subnet):
        return subnet.contains(ip)

    def subnet_of(self, ip):
        for s in self.subnets:
            if s.contains(ip):
                return s
        return None

    def find_host_by_ip(self, ip):
        for h in self.hosts:
            if ip in h.ip_addresses:
                return h
        return None

    def _bridges(self, without=None):
        """Subnet-adjacency from topology: two subnet CIDRs are adjacent iff some
        host (other than `without`) is multi-homed on both. This is where
        reachability comes FROM the topology instead of being assumed."""
        adj = {}
        for h in self.hosts:
            if without is not None and h.hostname == without:
                continue      # drop the pivot: proves "reachable ONLY via it"
            cidrs = {self.subnet_of(ip).ip_mask for ip in h.ip_addresses
                     if self.subnet_of(ip)}
            for a in cidrs:
                for b in cidrs:
                    if a != b:
                        adj.setdefault(a, set()).add(b)
        return adj

    def reachable(self, src_ip, dst_ip, without=None):
        """True iff dst is reachable from src over the real segment graph. Same
        subnet = reachable; otherwise only if a chain of multi-homed bridge hosts
        connects the two subnets. `without=<hostname>` removes that host's
        interfaces first, so `reachable(attacker, crown) and not
        reachable(attacker, crown, without=pivot)` proves pivot-only access."""
        src, dst = self.subnet_of(src_ip), self.subnet_of(dst_ip)
        if src is None or dst is None:
            return False
        if src.ip_mask == dst.ip_mask:
            return True
        adj = self._bridges(without=without)
        seen, frontier = {src.ip_mask}, [src.ip_mask]
        while frontier:
            cur = frontier.pop()
            if cur == dst.ip_mask:
                return True
            for nxt in adj.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)
        return dst.ip_mask in seen


def _segment_cidr(segment, is_entry):
    """Map a range segment label to one of the three real subnets. Perimeter/dmz
    stays attacker-facing; everything deeper is internal (where the crown lives)."""
    if (segment or "").lower() in ("perimeter", "dmz", "corporate_it"):
        return DMZ_CIDR
    return INTERNAL_CIDR


def plan_network(r):
    """Build a real segmented `Network` from a range dict (swarm.range_gen).

    Layout (DUELSWARM_LIQUID_SPEC §4): an `attacker` subnet carrying a red-origin
    host and the entry's attacker-facing NIC; a `dmz` subnet for perimeter hosts;
    an `internal` subnet for the deeper hosts incl. the crown. The ENTRY is
    multi-homed (attacker-facing + its own segment) — the pivot. Any in-scope host
    that is the parent of a host in a different subnet in the pivot graph is also
    multi-homed on the child's subnet, so lateral paths are physical facts.

    Returns (Network, ip_by_host) where ip_by_host maps hostname -> [ip, ...] in a
    stable order (primary IP first) for the compose + coordinate layer.
    """
    hosts = r["hosts"]
    entry = r["entry"]
    edges = r["topology"]["edges"]
    by_name = {h["name"]: h for h in hosts}
    in_scope = {h["name"] for h in hosts if h["scope"] == "in"}

    # 1) assign each host a home subnet from its segment (out-of-scope -> isolated).
    home = {}
    for h in hosts:
        if h["scope"] != "in":
            # a reachable-but-out-of-scope TRAP (amendment C / crit-4a) is homed on the
            # INTERNAL segment so a foothold can route to it and discover it; the gate — not
            # topology — blocks it. Every other out-of-scope host stays isolated on range_oos.
            home[h["name"]] = INTERNAL_CIDR if h.get("trap") else OOS_CIDR
        else:
            home[h["name"]] = _segment_cidr(h.get("segment"), h["name"] == entry)

    # 1b) the crown lives on a DEDICATED data-tier subnet. Only the host that has a pivot
    #     edge INTO the crown bridges to it (step 2), so when the crown is >= 2 hops deep the
    #     entry has NO data-tier NIC and must traverse the mid to reach it — depth-2 becomes a
    #     physical L3 fact, not a label. (Single-hop ranges keep the direct entry->crown edge,
    #     which bridges the entry to the data tier, so they are unaffected.)
    crown = (r.get("ground_truth") or {}).get("crown_jewel_host")
    if crown in home and home[crown] not in (OOS_CIDR,):
        home[crown] = DATA_CIDR

    # 2) multi-homing from the pivot graph: a parent on a different subnet than its
    #    child bridges the two (it must sit on the child's subnet to route there).
    extra = {name: set() for name in by_name}
    for a, b in edges:
        if a in home and b in home and home[a] != home[b] and a in in_scope and b in in_scope:
            extra[a].add(home[b])

    # 3) the entry is the pivot off the attacker subnet: it carries an
    #    attacker-facing NIC in addition to its segment home.
    extra[entry].add(ATTACKER_CIDR)

    # 4) materialize subnets + per-host IPs (stable, deterministic by name order).
    used_cidrs = {ATTACKER_CIDR} | {home[n] for n in home} | {
        c for s in extra.values() for c in s}
    subnets = [Subnet(c, attacker_subnet=(c == ATTACKER_CIDR))
               for c in (ATTACKER_CIDR, DMZ_CIDR, INTERNAL_CIDR, DATA_CIDR, OOS_CIDR)
               if c in used_cidrs]
    counters = {s.ip_mask: 2 for s in subnets}      # .1 reserved (gateway convention)

    def _next(cidr):
        n = counters[cidr]
        counters[cidr] += 1
        return str(list(ipaddress.ip_network(cidr).hosts())[n - 1])

    # the red-origin attacker host (the box red operates from) sits on .9 alone.
    ip_by_host = {}
    netmodel_hosts = []
    attacker_ip = _next(ATTACKER_CIDR)
    netmodel_hosts.append(Host([attacker_ip], hostname="attacker"))
    ip_by_host["attacker"] = [attacker_ip]

    for h in sorted(by_name.values(), key=lambda x: x["name"]):
        name = h["name"]
        cidrs = [home[name]] + sorted(c for c in extra[name] if c != home[name])
        ips = [_next(c) for c in cidrs]
        ports = {}
        if h.get("port"):
            ports[h["port"]] = OpenPort(h["port"], h.get("software") or "",
                                        tuple([h["cve"]] if h.get("cve") else []))
        netmodel_hosts.append(Host(ips, hostname=name, open_ports=ports))
        ip_by_host[name] = ips

    return Network(subnets=subnets, hosts=netmodel_hosts), ip_by_host


if __name__ == "__main__":  # self-check: real CIDR, multi-homed reachability, pivot-only
    # A hand-built pivot: attacker(.9) -> web(.10 & .11 pivot) -> db(.11, crown).
    net = Network(
        subnets=[Subnet(ATTACKER_CIDR, attacker_subnet=True),
                 Subnet(DMZ_CIDR), Subnet(INTERNAL_CIDR)],
        hosts=[
            Host(["10.9.0.2"], "attacker"),
            Host(["10.9.0.3", "10.11.0.2"], "web"),   # multi-homed pivot
            Host(["10.11.0.3"], "db"),                 # crown, internal only
        ])
    # real CIDR membership
    assert net.is_ip_in_ipmask("10.11.0.3", INTERNAL_CIDR)
    assert not net.is_ip_in_ipmask("10.9.0.2", INTERNAL_CIDR)
    assert net.subnet_of("10.11.0.3").ip_mask == INTERNAL_CIDR
    assert net.find_host_by_ip("10.11.0.3").hostname == "db"
    # same-subnet reachability
    assert net.reachable("10.9.0.2", "10.9.0.3")
    # multi-homed pivot bridges attacker -> internal
    assert net.reachable("10.9.0.2", "10.11.0.3"), "attacker should reach crown via web pivot"
    # pivot-only: drop the pivot and the crown is unreachable from the attacker
    assert not net.reachable("10.9.0.2", "10.11.0.3", without="web"), \
        "crown must be reachable ONLY via the pivot"
    # a host with no bridge to internal cannot reach the crown
    net.hosts.append(Host(["10.10.0.9"], "lonely-dmz"))
    assert not net.reachable("10.10.0.9", "10.11.0.3")

    # plan_network over a real generated range: entry is the multi-homed pivot,
    # the crown is on the internal subnet only, attacker can reach it ONLY via entry.
    from swarm.topo_to_compose import generate_range, load_pool
    pool = load_pool()
    for seed in range(12):
        r = generate_range(seed, pool)
        nm, ip_by_host = plan_network(r)
        entry, crown = r["entry"], r["objective"]["host"]
        a_ip = ip_by_host["attacker"][0]
        crown_ips = ip_by_host[crown]
        # the entry is the sole host on the attacker subnet: no deeper host carries
        # an attacker-facing NIC.
        assert nm.subnet_of(a_ip).ip_mask == ATTACKER_CIDR
        for name, ips in ip_by_host.items():
            if name in ("attacker", entry):
                continue
            assert all(nm.subnet_of(ip).ip_mask != ATTACKER_CIDR for ip in ips), \
                (seed, name, "only the entry may sit on the attacker subnet")
        # the crown is reachable from the attacker...
        assert nm.reachable(a_ip, crown_ips[0]), (seed, "attacker cannot reach crown at all")
        # ...and, unless the crown IS the front-door entry, ONLY via the entry pivot.
        if crown != entry:
            assert not nm.reachable(a_ip, crown_ips[0], without=entry), \
                (seed, crown, "a behind-the-entry crown must be reachable only via the pivot")
        # the entry is genuinely multi-homed (attacker-facing + its segment / internal)
        assert len(ip_by_host[entry]) >= 2, (seed, entry, ip_by_host[entry])
        # every assigned IP is unique
        allips = [ip for ips in ip_by_host.values() for ip in ips]
        assert len(allips) == len(set(allips)), (seed, "duplicate IP assigned")
    print("netmodel ok (real CIDR, multi-homed reachability, pivot-only crown access)")
