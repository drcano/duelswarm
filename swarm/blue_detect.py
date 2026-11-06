"""Blue team detection — air-gapped from red (SPEC §4).

Blue receives ONLY the range's telemetry/event-log stream — no access to red's
plan or memory. Detection fires from real container logs + the event log.

Detection signatures cover the full APT kill chain:
  - OGNL injection / RCE indicators
  - Post-exploitation enumeration
  - Network scanning
  - Credential harvesting
  - Data staging / exfiltration
  - Persistence mechanisms (cron, webshell, SSH backdoor, LD_PRELOAD)
  - Anti-forensics / defense evasion
  - Lateral movement
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect  # one effect path (invariant #1)
import re
from datetime import datetime


_SUSPICIOUS_PATTERNS = [
    (r"multipart/form-data.*ognl", "OGNL injection in Content-Type header", "critical"),
    (r"ProcessBuilder", "ProcessBuilder invocation (command execution)", "critical"),
    (r"getRuntime\(\)\.exec", "Runtime.exec() call (RCE)", "critical"),
    (r"OgnlContext", "OgnlContext reference (exploit framework)", "high"),
    (r"memberAccess", "OGNL memberAccess manipulation (security bypass)", "high"),
    (r"\.health\.jsp", "Suspicious JSP file access (potential webshell)", "critical"),
    (r"curl.*attacker\.local", "C2 callback attempt detected", "high"),
    (r"crontab", "Crontab modification attempt (persistence)", "high"),
    (r"/etc/shadow", "Shadow file access attempt (credential theft)", "high"),
    (r"authorized_keys", "SSH authorized_keys modification (backdoor)", "critical"),
    (r"ld\.so\.preload", "LD_PRELOAD hijack attempt (rootkit)", "critical"),
    (r"/dev/tcp/", "Bash /dev/tcp network probe (scanning)", "medium"),
    (r"tar.*czf.*\.tar\.gz", "Data staging for exfiltration", "high"),
    (r"docker\.sock", "Docker socket access (container escape vector)", "critical"),
    (r"169\.254\.169\.254", "Cloud metadata service probe (SSRF/escape)", "critical"),
    (r"openssl.*enc.*aes", "Data encryption for covert exfiltration", "high"),
    (r"psql.*-h.*-U", "Database access via harvested credentials", "critical"),
    (r"pg_roles|information_schema", "Database schema enumeration", "high"),
    (r"nslookup.*exfil|dns.*tunnel", "DNS tunneling exfiltration attempt", "critical"),
    (r"beacon|callback|c2", "C2 beacon establishment detected", "critical"),
]


def tail_container_logs(container="range-struts", lines=200):
    """Pull recent logs from the Struts container."""
    try:
        result = run_effect(
            ["docker", "logs", "--tail", str(lines), container],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"error reading logs: {e}"


def detect_from_logs(container="range-struts", lines=200):
    """Scan container logs for indicators of exploitation and post-exploitation."""
    logs = tail_container_logs(container, lines)
    seen = {}
    for line in logs.splitlines():
        for pattern, description, severity in _SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if pattern in seen:
                    seen[pattern]["count"] += 1
                else:
                    seen[pattern] = {
                        "ts": datetime.now().isoformat(timespec="seconds"),
                        "description": description,
                        "severity": severity,
                        "pattern": pattern,
                        "log_line": line[:300],
                        "source": f"container:{container}",
                        "count": 1,
                    }
                break
    return list(seen.values())


# Map ATT&CK technique IDs to detection descriptions and D3FEND countermeasures
_TECHNIQUE_DETECTIONS = {
    "T1595": ("Active scanning / reconnaissance", "D3-NTA"),
    "T1190": ("Exploit of public-facing application", "D3-NTA"),
    "T1059": ("Command & scripting interpreter execution", "D3-DA"),
    "T1552": ("Unsecured credential access", "D3-DA"),
    "T1083": ("File & directory discovery", "D3-DA"),
    "T1087": ("Account discovery", "D3-DA"),
    "T1016": ("System network configuration discovery", "D3-DA"),
    "T1021": ("Lateral movement via remote services", "D3-NTA"),
    "T1005": ("Data collection from local system", "D3-NTA"),
    "T1053": ("Persistence via scheduled task/cron", "D3-DA"),
    "T1046": ("Internal network service scanning", "D3-NTA"),
    "T1003": ("Credential dumping / harvesting", "D3-DA"),
    "T1070": ("Defense evasion / anti-forensics", "D3-DA"),
    "T1505.003": ("Webshell persistence", "D3-DA"),
    "T1213": ("Data from information repositories (DB)", "D3-DA"),
    "T1611": ("Container escape attempt", "D3-DA"),
    "T1071": ("Application layer protocol (C2)", "D3-NTA"),
    "T1560": ("Archive collected data (encrypted exfil)", "D3-NTA"),
    "T1078": ("Valid accounts — credential reuse for lateral movement", "D3-DA"),
}

# Actions that indicate specific post-exploitation behavior
_ACTION_DETECTIONS = {
    "shell": ("Remote code execution achieved", "D3-NTA", "critical"),
    "discovery": ("Host enumeration and discovery", "D3-DA", "high"),
    "network_scan": ("Internal network scanning from compromised host", "D3-NTA", "high"),
    "credential_harvest": ("Credential harvesting across host", "D3-DA", "critical"),
    "exfiltrate": ("Data collection and staging for exfiltration", "D3-NTA", "critical"),
    "persistence": ("Persistence mechanism established", "D3-DA", "critical"),
    "defense_evasion": ("Anti-forensics and log clearing detected", "D3-DA", "high"),
    "db_exploit": ("Database exploitation via harvested credentials", "D3-DA", "critical"),
    "container_escape": ("Container escape vector assessment", "D3-DA", "critical"),
    "c2_beacon": ("C2 beacon deployment and channel testing", "D3-NTA", "critical"),
    "encrypt_staged": ("Encrypted data staging for covert exfiltration", "D3-NTA", "high"),
}


# Observable telemetry byproducts a defender can see on the host/wire, as
# opposed to red's self-applied labels (ATT&CK IDs, action names, descriptions).
_OBSERVABLE_FIELDS = ("output", "command", "cmd", "log_line", "payload",
                      "request", "url", "path", "target", "tool")


def detect_from_eventlog(log, mode="blind"):
    """Reconstruct blue detections from the event log.

    mode="blind" (default, brief §2.2): detect ONLY from observable telemetry
        byproducts (command/output/log strings) via the same signatures used on
        container logs — never from red's semantic action/technique labels. This
        is the honest air-gap: blue misses techniques that leave no matching
        signature (that's a real detection gap, not a bug).
    mode="oracle": the old behavior — reads red's labeled actions and ATT&CK
        technique IDs. Kept ONLY for the blind-vs-oracle ablation (brief §4);
        blue is not air-gapped in this mode.
    """
    return _detect_oracle(log) if mode == "oracle" else _detect_blind(log)


def _detect_blind(log):
    """HEURISTIC (Brick 2): regex signature-match on observable payload byproducts;
    label-free (no red ATT&CK IDs). Demoted to defense-in-depth — it catches only the
    byte-variants whose payload matches a signature (the prototype result: ~1/8 Struts
    variants). The real detector is the payload-independent kill-chain-structure detector
    `swarm/blue_fast.detect_kill_chain` (the deterministic fast tier); this stays as a
    cheap second layer, never the primary."""
    detections, seen = [], set()
    for entry in log.entries():
        data = entry.get("data", {})
        blob = " ".join(str(data.get(f, "")) for f in _OBSERVABLE_FIELDS)
        if not blob.strip():
            continue
        for pattern, description, severity in _SUSPICIOUS_PATTERNS:
            if pattern in seen:
                continue
            if re.search(pattern, blob, re.IGNORECASE):
                seen.add(pattern)
                detections.append({
                    "ts": entry.get("ts"),
                    "seq": entry.get("seq"),
                    "hash": entry.get("hash", "")[:12],
                    "description": description,
                    "d3fend": "D3-NTA",
                    "technique": "inferred",  # inferred from telemetry, NOT red's label
                    "severity": severity,
                })
                break
    return detections


def _detect_oracle(log):
    """Comprehensive event log analysis for adversary kill chain reconstruction."""
    detections = []
    for entry in log.entries():
        if entry["actor"] != "red":
            continue
        action = entry["action"]
        data = entry.get("data", {})
        attack = data.get("attack", "")

        # Technique-based detection from gate events
        if action == "gate.allow" and attack in _TECHNIQUE_DETECTIONS:
            desc, d3fend = _TECHNIQUE_DETECTIONS[attack]
            det = {
                "ts": entry["ts"],
                "seq": entry["seq"],
                "hash": entry["hash"][:12],
                "description": f"{desc}: {attack} via {data.get('tool', 'unknown')} → {data.get('target', '?')}",
                "d3fend": d3fend,
                "technique": attack,
                "severity": "critical" if attack in ("T1190", "T1003", "T1078") else "high",
            }
            if data.get("cve"):
                det["cve"] = data["cve"]
            detections.append(det)

        # Action-based detection from logged red team events
        if action in _ACTION_DETECTIONS:
            desc, d3fend, severity = _ACTION_DETECTIONS[action]
            iocs = []
            if action == "credential_harvest":
                iocs = data.get("sources", [])
            elif action == "network_scan":
                iocs = data.get("services", [])
            elif action == "persistence":
                iocs = data.get("methods", [])
            elif action == "defense_evasion":
                iocs = data.get("actions", [])

            detections.append({
                "ts": entry["ts"],
                "seq": entry["seq"],
                "hash": entry["hash"][:12],
                "description": desc,
                "d3fend": d3fend,
                "technique": attack or action,
                "severity": severity,
                "iocs": iocs,
            })

    return detections


if __name__ == "__main__":  # self-check: blind air-gap detects less, leaks no red labels
    class _Log:
        def __init__(self, e): self._e = e
        def entries(self): return self._e

    # Red actions: one leaves an observable signature (ProcessBuilder in output),
    # one is silent (credential_harvest labeled only by red's ATT&CK ID T1003).
    evs = [
        {"actor": "red", "action": "gate.allow", "seq": 1, "ts": "t", "hash": "h1",
         "data": {"attack": "T1190", "tool": "exploit", "target": "struts",
                  "output": "ProcessBuilder spawned /bin/sh"}},
        {"actor": "red", "action": "credential_harvest", "seq": 2, "ts": "t", "hash": "h2",
         "data": {"attack": "T1003", "sources": ["/etc/shadow-cache"]}},  # silent: no observable
    ]
    log = _Log(evs)

    oracle = detect_from_eventlog(log, mode="oracle")
    blind = detect_from_eventlog(log, mode="blind")

    # Oracle reads red's labels -> catches both (incl. the silent harvest via T1003).
    assert any(d["technique"] == "T1003" for d in oracle), "oracle should read red's label"
    # Blind catches only the one with an observable signature, and never a red ATT&CK ID.
    assert len(blind) == 1, blind
    assert blind[0]["technique"] == "inferred", blind
    assert all(not str(d["technique"]).startswith("T1") for d in blind), "blind leaked a red label"
    assert len(blind) < len(oracle), "air-gap should lower detection, not raise it"
    print(f"blue_detect ok (oracle={len(oracle)} blind={len(blind)})")
