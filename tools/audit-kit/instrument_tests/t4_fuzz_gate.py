"""Property-based fuzz of swarm/gate.py target canonicalization (hypothesis). Pure scope decisions:
no network, no subprocess. Gate is built the way the live harness builds it (scope_by_actor of host
NAMES, aliases = the ip->name / range-<name>->name map _resolve_container_ips would produce)."""
import ipaddress, socket, sys, json
from pathlib import Path
from hypothesis import given, settings, strategies as st, HealthCheck, Phase

REPO = Path(sys.argv[1]); sys.path.insert(0, str(REPO))
from swarm.gate import Gate, OutOfScope  # noqa: E402

FORBID_IP, ALLOW_IP = "10.50.0.11", "10.50.0.10"
FB = int(ipaddress.ip_address(FORBID_IP))


class Log:
    def __init__(s): s.ev = []
    def append(s, a, act, d=None): s.ev.append((a, act, d)); return {}


def mk(scope_kind="names"):
    lg = Log()
    red = ["web01"] if scope_kind == "names" else [ALLOW_IP]
    g = Gate([], lg, scope_by_actor={"red": red}, known_hosts=["web01", "dc-01"])
    g.aliases.update({ALLOW_IP: "web01", FORBID_IP: "dc-01", "range-web01": "web01", "range-dc-01": "dc-01"})
    if scope_kind == "ips":   # harness at scripts/live_arms_race_run.py:229-230 style: ip -> ip
        g.aliases = {ALLOW_IP: ALLOW_IP, FORBID_IP: FORBID_IP}
    return g, lg


def decide(target, kind="names"):
    g, lg = mk(kind); ran = []
    try:
        g.dispatch("red", "probe", target, lambda: ran.append(1))
    except OutOfScope:
        pass
    return "ALLOWED" if ran else "BLOCKED"


def egress(cmd, kind="names"):
    g, _ = mk(kind)
    ok, blk = g.check_egress(cmd, actor="red")
    return "ALLOWED" if ok else f"BLOCKED{blk}"


def libc_resolves_to_forbidden(s):
    try:
        return socket.inet_aton(s.strip()) == socket.inet_aton(FORBID_IP)
    except OSError:
        return False


# ---- IPv4 spelling generators (every produced string is checked against inet_aton ground truth) ----
parts = [10, 50, 0, 11]


def fmt(n, base, pad):
    if base == 10:
        return ("0" * pad + str(n)) if pad and False else str(n)
    if base == 16:
        return "0x" + "0" * pad + format(n, "x")
    if base == 8:
        return "0" + "0" * pad + format(n, "o") if n else "0"
    return str(n)


@st.composite
def ipv4_spelling(draw):
    form = draw(st.sampled_from(["4part", "3part", "2part", "1part"]))
    if form == "4part":
        nums = parts
    elif form == "3part":
        nums = [10, 50, 11]           # a.b.c : c fills the low 16 bits
    elif form == "2part":
        nums = [10, (50 << 16) | 11]  # a.b   : b fills the low 24 bits
    else:
        nums = [FB]
    out = []
    for n in nums:
        base = draw(st.sampled_from([10, 16, 8]))
        pad = draw(st.integers(0, 2))
        if base == 16:
            s = "0x" + "0" * pad + format(n, draw(st.sampled_from(["x", "X"])))
        elif base == 8:
            s = "0" + "0" * pad + format(n, "o") if n else "0" * (pad + 1)
        else:
            s = str(n)
        out.append(s)
    s = ".".join(out)
    if draw(st.booleans()):
        s += "."
    return s


@st.composite
def wrapped(draw):
    ip = draw(st.one_of(ipv4_spelling(), st.just(FORBID_IP)))
    w = draw(st.sampled_from(["{}", " {}", "{} ", "{}\n", "\t{}", "http://{}:22", "http://{}/", "ssh://root@{}",
                              "root@{}", "{}/32", "{}:22", "::ffff:{}", "[::ffff:{}]", "HTTP://{}"]))
    return w.format(ip), ip


FAILS = {"target": [], "egress": []}


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck), phases=[Phase.generate])
@given(wrapped())
def test_target(pair):
    s, ip = pair
    # ground truth: a string that names the forbidden address by any spelling libc accepts
    if not (libc_resolves_to_forbidden(ip) or ip == FORBID_IP):
        return
    for kind in ("names", "ips"):
        d = decide(s, kind)
        if d == "ALLOWED":
            FAILS["target"].append((kind, s))


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck), phases=[Phase.generate])
@given(ipv4_spelling(), st.sampled_from(["curl {}", "curl http://{}/", "wget {}/x", "nc {} 22", "ssh root@{}",
                                          "bash -c 'cat </dev/tcp/{}/22'", "python3 -c \"import socket;socket.create_connection(('{}',22))\"",
                                          "curl {}:80", "ping -c1 {}"]))
def test_egress(ip, tmpl):
    if not libc_resolves_to_forbidden(ip):
        return
    cmd = tmpl.format(ip)
    for kind in ("names", "ips"):
        if egress(cmd, kind) == "ALLOWED":
            FAILS["egress"].append((kind, cmd))


test_target(); test_egress()

# ---- deterministic hand list (the brief's explicit forms + userinfo/separator confusion) ----
fixed = ["10.50.0.11", "171048971", "0x0a32000b", "0xa32000b", "012.062.0.013", "10.50.11", "10.3276811",
         "010.050.000.011", "10.50.0.11.", " 10.50.0.11", "10.50.0.11\n", "DC-01", "dc-01.", "Range-dc-01",
         "::ffff:10.50.0.11", "::ffff:a32:b", "[::ffff:10.50.0.11]", "http://10.50.0.11:22", "http://[::ffff:a32:b]/",
         "root@10.50.0.11", "10.50.0.11/32", "10.50.0.0/24", "10.50.0.11:22",
         # userinfo / separator confusion: declared string's first ':'-field is in scope, real host is not
         "web01:22@10.50.0.11", "web01:x@dc-01", "10.50.0.10:80@10.50.0.11", "range-web01:1@10.50.0.11",
         "web01:22 10.50.0.11", "web01:@dc-01", "http://web01@10.50.0.11/", "web01@10.50.0.11",
         "range-web01/../dc-01", "web01#@10.50.0.11"]
table = []
for s in fixed:
    row = {"target": s, "libc_forbidden": libc_resolves_to_forbidden(s),
           "names_scope": decide(s, "names"), "ips_scope": decide(s, "ips")}
    g, _ = mk("names"); row["canon_names"] = g._canonicalize(s)
    table.append(row)
egress_fixed = ["curl 171048971", "curl http://171048971/", "curl 0x0a32000b", "nc 0xa32000b 22", "curl 10.50.11",
                "curl 012.062.0.013", "curl http://[::ffff:10.50.0.11]/", "curl http://[::ffff:a32:b]/",
                "nc 10.50.0.11 22", "ping -c1 10.50.0.11", "python3 -c \"import socket;socket.create_connection(('10.50.0.11',22))\"",
                "H=10.50.0.11; curl http://$H/", "curl http://web01@10.50.0.11/", "curl -u web01:x 10.50.0.11",
                "curl $(printf 10.50.0.11)", "nc dc-01 22", "curl DC-01"]
etable = [{"command": c, "names_scope": egress(c, "names"), "ips_scope": egress(c, "ips")} for c in egress_fixed]

res = {"hypothesis_target_bypasses": sorted(set(map(tuple, FAILS["target"]))),
       "hypothesis_egress_bypasses": sorted(set(map(tuple, FAILS["egress"]))),
       "fixed_targets": table, "fixed_egress": etable}
Path(sys.argv[2]).write_text(json.dumps(res, indent=1))
print("hypothesis target-string bypasses (declared target allowed though libc maps it to dc-01):",
      len(res["hypothesis_target_bypasses"]))
for x in res["hypothesis_target_bypasses"][:15]:
    print("   ", x)
print("hypothesis egress bypasses (command reaching dc-01 by a libc-valid spelling, not blocked):",
      len(res["hypothesis_egress_bypasses"]))
for x in res["hypothesis_egress_bypasses"][:25]:
    print("   ", x)
print("\nFIXED TARGET TABLE (target | libc->dc-01 | names-scope | ips-scope | canonical)")
for r in table:
    print(f"   {r['target']!r:34} {str(r['libc_forbidden']):5} {r['names_scope']:8} {r['ips_scope']:8} {r['canon_names']!r}")
print("\nFIXED EGRESS TABLE (command | names-scope | ips-scope)")
for r in etable:
    print(f"   {r['command']!r:75} {r['names_scope']:30} {r['ips_scope']}")
