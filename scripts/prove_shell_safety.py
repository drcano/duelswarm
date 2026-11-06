#!/usr/bin/env python3
"""A2 planted test (brief v3): no agent-supplied value reaches a shell unquoted.

Drives every red tool that must build a shell command string with an injection payload
(`x;touch /tmp/PWNED;#` and per-argument equivalents) through a FAKE executor that records the
exact command string, then asserts each injected value is either DROPPED (an unclean scan/probe
target is never run) or present only inside a `shlex.quote()`d token. Base64-wrapped payloads
(`echo <b64> | base64 -d | bash`) are decoded first, so the check sees the real inner script.
Reproduces audit section 7 G2 and shows the injection is gone.

Lives in scripts/ (not redteam/) on purpose: it imports swarm.*, and the redteam/ package keeps
its swarm-independent import contract (G6).

Run:  python3 scripts/prove_shell_safety.py        # exits non-zero on any unquoted injection
"""
import base64
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# This test exercises the SHELL-string builders only, not the LLM. live_red imports the LLM stack
# at module load (swarm.llm -> openai); stub the absent SDK so the sink functions import offline.
import types as _types  # noqa: E402


class _Stub(_types.ModuleType):
    def __getattr__(self, n):
        return type(n, (), {})


for _m in ("openai",):
    sys.modules.setdefault(_m, _Stub(_m))

from swarm import live_fingerprint, live_recon, live_lateral, live_pivot, live_red  # noqa: E402

PAYLOAD = "touch /tmp/PWNED"
MARKERS = (PAYLOAD, "rm -rf", "INJECTED")
INJ = "x;" + PAYLOAD + ";#"        # a target/value carrying a shell-injection payload

_recorded = []


def _rec_exec(*a, **k):
    """Patched over run_effect: capture the shell string (the sh/bash -c tail of the argv)."""
    argv = a[0] if a else k.get("args")
    if isinstance(argv, (list, tuple)) and argv:
        _recorded.append(str(argv[-1]))

    class R:
        returncode, stdout, stderr = 1, "", ""
    return R()


def _rec_cmd(cmd):                 # fingerprint run_cmd / AD exec_fn
    _recorded.append(str(cmd))
    return ""


def _expand(cmd):
    """Reveal any base64 payload so the check sees the inner script, not the opaque blob."""
    m = re.search(r"echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+-d", cmd)
    if m:
        try:
            return cmd + "\n" + base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except Exception:
            return cmd
    return cmd


def _inert(cmd, injected):
    """True iff every injected value in `cmd` (base64 expanded) appears only as its
    shlex.quote()d form or not at all: removing those leaves no live payload."""
    s = _expand(cmd)
    for v in injected:
        s = s.replace(shlex.quote(v), "")
    return not any(m in s for m in MARKERS)


fails = []


def check(label, injected):
    bad = [c for c in _recorded if not _inert(c, injected)]
    print(f"  [{'FAIL' if bad else 'ok  '}] {label}: {len(_recorded)} cmd(s) recorded, "
          f"{len(bad)} with an unquoted injection")
    for c in bad:
        print("      UNQUOTED:", c[:160])
    if bad:
        fails.append(label)
    _recorded.clear()


class _Log:
    def __init__(s):
        s.ev = []

    def append(s, *a, **k):
        s.ev.append((a, k))

    def entries(s):
        return []


class _Gate:
    def dispatch(s, actor, tool, target, fn, **kw):
        return fn()


# patch the one effect primitive in each agent module
live_recon.run_effect = _rec_exec
live_red.run_effect = _rec_exec
live_pivot.run_effect = _rec_exec

print("A2 planted shell-injection test (fake executor records every command string):")

# 1. fingerprint: an unclean ip is never probed; a clean one probes with no payload
live_fingerprint.fingerprint_service(_rec_cmd, INJ, 8080)
check("fingerprint_service(ip=INJ) -> dropped", [INJ])
live_fingerprint.fingerprint_service(_rec_cmd, "web01", 8080)
check("fingerprint_service(ip=web01) -> clean", ["web01"])

# 2. recon connect-scan: unclean target dropped; a mixed batch keeps only the clean pair
live_recon.scan_port("c", INJ, 80)
check("scan_port(ip=INJ) -> dropped", [INJ])
live_recon.scan_many("c", [(INJ, 80), ("10.0.0.5", 80)])
check("scan_many([INJ, 10.0.0.5]) -> only clean", [INJ])

# 3. lateral /dev/tcp delivery: a clean dst_ip builds, an unclean one builds nothing
cve = sorted(live_lateral.http_rce_cves())[0]
assert live_lateral._bash_deliver("10.0.0.5", 80, cve, "id") is not None, \
    "a supported cve + clean dst_ip must build a delivery"
assert live_lateral._bash_deliver(INJ, 80, cve, "id") is None, \
    "an unclean dst_ip must NOT build a /dev/tcp delivery"
print("  [ok  ] _bash_deliver(dst_ip=INJ) -> None (dropped); clean dst_ip builds")

# 4. pivot ssh: key_path / user / dst_ip / remote_cmd all quoted
live_pivot._ssh("c", "k" + INJ, "u" + INJ, INJ, "cat /x;" + PAYLOAD)
check("_ssh(key/user/dst_ip/remote_cmd=INJ)", ["k" + INJ, "u" + INJ, INJ, "cat /x;" + PAYLOAD])

# 5. AD moves: domain / user / password / nthash / dc_ip / dst_ip quoted through exec_fn
g, lg = _Gate(), _Log()
live_pivot.kerberoast(lg, g, "red", _rec_cmd, INJ, "CORP" + INJ, "svc" + INJ, "pw" + INJ)
check("kerberoast(dc_ip/domain/user/password=INJ)", [INJ, "CORP" + INJ, "svc" + INJ, "pw" + INJ])
live_pivot.pass_the_hash(lg, g, "red", _rec_cmd, "dst", INJ, "CORP" + INJ, "svc" + INJ, "aa" + INJ)
check("pass_the_hash(dst_ip/domain/user/nthash=INJ)", [INJ, "CORP" + INJ, "svc" + INJ, "aa" + INJ])
live_pivot.dc_auth(lg, g, "red", _rec_cmd, "dc", INJ, "CORP" + INJ, "svc" + INJ,
                   nthash="aa" + INJ, password="pw" + INJ)
check("dc_auth(dc_ip/domain/user/nthash/password=INJ)",
      [INJ, "CORP" + INJ, "svc" + INJ, "aa" + INJ, "pw" + INJ])

# 6. fast_web_sweep: an unclean host is filtered out of the (base64) sweep script
live_red.fast_web_sweep("c", "10.0.0.0/29", ips=[INJ, "10.0.0.5"])
check("fast_web_sweep(ips=[INJ, 10.0.0.5]) -> only clean", [INJ])

if fails:
    print(f"\nA2 VIOLATED: {len(fails)} sink(s) leaked an unquoted agent metacharacter: {fails}")
    sys.exit(1)
print("\nA2 PROVEN: every red tool keeps agent-supplied values shell-inert (quoted or dropped); "
      "the G2 /dev/tcp target injection is gone.")
