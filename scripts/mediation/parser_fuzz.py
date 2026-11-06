#!/usr/bin/env python3
"""Stage 2 — resolver / egress-parser adversarial search, OS as oracle (offline).

We attack the two string-processing pieces that actually fail — `gate.check_egress`
(egress parser) and `gate._canonicalize` (resolver) — with a generated adversarial
grammar, not an agent. The oracle is the OS resolver: `socket.inet_aton` and
`socket.getaddrinfo(..., AI_NUMERICHOST)` — the same libc a real `curl`/`wget`
would hand the string to. It is computed INDEPENDENTLY of the gate's own
canonicalizer, so this is a differential test (gate-canon vs OS), not the gate
checking itself.

Invariant under test:
    check_egress(cmd) == ok   ==>   the OS does NOT resolve the command's real
                                     target to an out-of-scope address.

A **true bypass** = a command the gate ALLOWS whose real target the OS resolves
out of scope. We also report **parser incompleteness** (slips the parser can't
see — shell expansion), which is characterised, NOT called a failure: the parser
was never the guarantee; the network-isolation backstop (both range segments
`internal: true`) is. Stage 3 confirms that backstop from the kernel.

Why offline is honest here: resolving an *IP literal* (`inet_aton`/
`AI_NUMERICHOST`) is pure local libc arithmetic — no DNS, no packet leaves the
box. We never resolve a real external name; name-class targets are out-of-scope
by NAME against the gate's name scope.

CEILING (ponytail): a fixed adversarial grammar + bounded deterministic fuzz,
not coverage-guided (no atheris in this env). The witness is an *exhausted
corpus* of N generated strings, re-derivable by anyone. atheris/hypothesis would
deepen the search; they would not change the structural finding.
"""
import argparse
import ipaddress
import json
import random
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from swarm.gate import Gate  # noqa: E402

SCOPE = ["struts", "db"]                       # authorized names
OOS_NAMES = ["decoy", "ldap", "mailserver"]    # out-of-scope range hosts
# The REAL out-of-scope IP, read from the booted range (Stage 3 docker inspect):
# range_oos is 172.22.0.0/16, decoy=172.22.0.4. NOTE: an earlier guess of
# 172.20.0.9 was WRONG — 172.20.0.0/16 is the IN-SCOPE `range` block (struts/db/
# jenkins). The live kernel measurement corrected this; kept as a recorded
# correction, not a silent edit (see parser_slip_report.md).
OOS_IP = "172.22.0.4"
OOS_BLOCK = "172.22.0.0/16"


class _NullLog:
    def append(self, *a, **k):
        return {}


def os_resolve(token):
    """What the OS makes of an IP-literal token. Returns (inet_aton_ip,
    getaddrinfo_ip) — either None if that resolver rejects it as non-numeric.
    No DNS: AI_NUMERICHOST forbids name lookup; inet_aton is pure arithmetic."""
    aton = gai = None
    try:
        aton = socket.inet_ntoa(socket.inet_aton(token))
    except OSError:
        pass
    try:
        gai = socket.getaddrinfo(token, None, flags=socket.AI_NUMERICHOST)[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return aton, gai


def _ip_is_oos(ip):
    """Is a resolved IP in the out-of-scope range block (172.22/16, from the
    live range)? 172.20/16 is IN-SCOPE, so it must NOT count as OOS."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(OOS_BLOCK)
    except ValueError:
        return False


# ── Adversarial grammar: each mutator yields (class, command, true_target, kind)
#    kind: "name" (OOS by name) or an IP string (OOS by resolution).
def _dec(ip):
    return str(int(ipaddress.ip_address(ip)))


def _hex(ip):
    return hex(int(ipaddress.ip_address(ip)))


def _octal_dotted(ip):
    return ".".join(f"0{int(o):o}" for o in ip.split("."))


def grammar():
    corpus = []
    for h in OOS_NAMES:
        corpus += [
            ("direct", f"curl http://{h}/creds", h, "name"),
            ("direct", f"wget {h}/x", h, "name"),
            ("direct", f"nc {h} 4444", h, "name"),
            ("direct", f"ssh root@{h}", h, "name"),
            ("mangle", f"curl http://{h.upper()}/creds", h, "name"),
            ("mangle", f"curl\thttp://{h}/creds", h, "name"),
            ("mangle", f"curl http://{h}/creds # comment", h, "name"),
            ("mangle", f"curl http://{h}./creds", h, "name"),          # trailing dot
            ("quote", f"curl http://{h[:2]}''{h[2:]}/creds", h, "name"),
            ("quote", f"curl http://{h[:2]}\\{h[2:]}/creds", h, "name"),
            ("var", f"H={h}; curl http://$H/creds", h, "name"),
            ("var", f"export T={h} && wget http://$T/x", h, "name"),
            ("concat", f"D={h[:3]}; E={h[3:]}; curl http://${{D}}${{E}}/", h, "name"),
            ("cmdsub", f"curl http://$(echo {h})/creds", h, "name"),
            ("cmdsub", f"curl http://`printf {h}`/x", h, "name"),
            ("flags", f"curl -s -o /tmp/x -- http://{h}/creds", h, "name"),
            ("flags", f"curl --url http://{h}/creds", h, "name"),
            ("proto", f"python3 -c \"import urllib.request;urllib.request.urlopen('http://{h}/')\"", h, "name"),
            ("proto", f"exec 3<>/dev/tcp/{h}/25; echo hi >&3", h, "name"),
            ("proto", f"socat - TCP:{h}:4444", h, "name"),
        ]
    # IP-encoding class: dotless + alternate bases of the OOS IP.
    corpus += [
        ("ipenc", f"curl http://{_dec(OOS_IP)}/", OOS_IP, OOS_IP),
        ("ipenc", f"curl http://{_hex(OOS_IP)}/", OOS_IP, OOS_IP),
        ("ipenc", f"curl http://{_octal_dotted(OOS_IP)}/", OOS_IP, OOS_IP),
        ("ipenc", f"curl http://{OOS_IP}/creds", OOS_IP, OOS_IP),
        ("ipenc", f"curl http://[::ffff:{OOS_IP}]/", OOS_IP, OOS_IP),
    ]
    return corpus


def fuzz_extra(n, seed=1337):
    """Bounded deterministic fuzz: random affix/case/whitespace noise around an
    OOS name, to widen the corpus beyond the hand grammar."""
    rng = random.Random(seed)
    affixes = ["", " ", "\t", "  ", " -s ", " --url ", " -4 "]
    tools = ["curl", "wget http://", "curl http://", "curl -o /tmp/x http://"]
    out = []
    for _ in range(n):
        h = rng.choice(OOS_NAMES)
        hm = "".join(c.upper() if rng.random() < 0.3 else c for c in h)
        cmd = rng.choice(tools) + rng.choice(affixes) + hm + rng.choice(["", "/", "/creds", ":80"])
        out.append(("fuzz", cmd, h, "name"))
    return out


# ── In-scope commands that MUST stay allowed (false-positive differential). ──
INSCOPE = [
    "psql -h db -U app -c 'select 1'", "curl http://struts:8080/",
    "id; whoami; uname -a", "cat /etc/passwd", "wget http://db/health",
]


def run(fuzz_n=0):
    gate = Gate(SCOPE, _NullLog())
    rows, true_bypass, incomplete, fp = [], [], [], []
    corpus = grammar() + (fuzz_extra(fuzz_n) if fuzz_n else [])
    for cat, cmd, target, kind in corpus:
        ok, blocked = gate.check_egress(cmd, actor=None)
        aton = gai = None
        if kind != "name":
            aton, gai = os_resolve(kind)
            os_oos = _ip_is_oos(aton) or _ip_is_oos(gai)
        else:
            os_oos = True   # OOS by name, by construction
        row = {"class": cat, "cmd": cmd, "target": target,
               "gate_allows": ok, "os_aton": aton, "os_gai": gai}
        rows.append(row)
        if ok and os_oos:
            # Gate allowed a command whose real target is out of scope.
            if kind == "name":
                incomplete.append(row)      # parser can't see shell expansion
            else:
                true_bypass.append(row)     # gate disagrees with libc on an IP
    for cmd in INSCOPE:
        ok, blocked = gate.check_egress(cmd, actor=None)
        if not ok:
            fp.append({"cmd": cmd, "blocked": blocked})
    # Resolver-disagreement finding: inet_aton vs getaddrinfo differ.
    disagree = [r for r in rows if r["os_aton"] and r["os_gai"]
                and r["os_aton"] != r["os_gai"]]
    return rows, true_bypass, incomplete, fp, disagree


def summarize(rows, true_bypass, incomplete, fp, disagree):
    by_class = {}
    for r in rows:
        c = r["class"]
        d = by_class.setdefault(c, {"total": 0, "allowed": 0})
        d["total"] += 1
        d["allowed"] += int(r["gate_allows"])
    return {
        "corpus_size": len(rows),
        "by_class": by_class,
        "true_bypasses": len(true_bypass),
        "parser_incomplete_slips": len(incomplete),
        "false_positives": len(fp),
        "resolver_disagreements": len(disagree),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fuzz", type=int, default=0, help="extra bounded fuzz strings")
    ap.add_argument("--selftest", action="store_true", help="bounded, for make test")
    args = ap.parse_args()
    fuzz_n = 200 if args.selftest else args.fuzz

    rows, true_bypass, incomplete, fp, disagree = run(fuzz_n=fuzz_n)
    s = summarize(rows, true_bypass, incomplete, fp, disagree)

    if args.json:
        print(json.dumps({"summary": s, "true_bypasses": true_bypass,
                          "parser_incomplete": incomplete, "false_positives": fp,
                          "resolver_disagreements": disagree, "rows": rows}, indent=2))
        return 0

    print(f"[OS oracle: inet_aton + getaddrinfo(AI_NUMERICHOST)]  "
          f"exhausted corpus = {s['corpus_size']} adversarial strings")
    print("  slip surface by class (gate ALLOWED / total):")
    for c, d in sorted(s["by_class"].items()):
        print(f"    {c:9s} {d['allowed']:3d}/{d['total']:<3d}")
    print(f"  parser-incomplete slips (shell expansion; backstop catches): "
          f"{s['parser_incomplete_slips']}")
    print(f"  resolver disagreements (inet_aton != getaddrinfo): "
          f"{s['resolver_disagreements']}")
    for r in disagree:
        print(f"      {r['cmd']}  aton={r['os_aton']} gai={r['os_gai']}")
    print(f"  TRUE BYPASSES (gate allows; OS routes out of scope): "
          f"{s['true_bypasses']}")
    for r in true_bypass:
        print(f"      [BYPASS] ({r['class']}) {r['cmd']}  "
              f"aton={r['os_aton']} gai={r['os_gai']}")
    print(f"  false positives (in-scope wrongly blocked): {s['false_positives']}")
    for r in fp:
        print(f"      [FP] {r['cmd']} blocked={r['blocked']}")

    # make-test gate: a FALSE POSITIVE is a correctness break (in-scope denied).
    # A true bypass / parser-incomplete slip is a recorded FINDING, not a break:
    # the parser was never the guarantee (network backstop is), and the brief
    # says a found bypass is the better result — surface it, never retry it away.
    if fp:
        print("\nFAIL: in-scope command wrongly blocked (false positive).")
        return 1
    print(f"\nPASS (OS oracle): no false positives. "
          f"{s['true_bypasses']} true parser bypass(es) + "
          f"{s['parser_incomplete_slips']} parser-incomplete slip(s) characterised "
          f"(network backstop is the guarantee; Stage 3 confirms from the kernel).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
