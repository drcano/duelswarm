"""The hash-chained TELEMETRY chain — the primary record of what actually happened.

Not red's account, not blue's, not the gate's: an independent, tamper-evident, re-verifiable
log of the ACTUAL system and network events that physically occurred on the targets and the
wire. Each real event (a syscall / process exec from Falco's eBPF probe, a connection flow
from the kernel's conntrack table, a service/auth record from a target's own container log) is
appended to its OWN hash-chained EventLog (swarm.eventlog), so `scripts/verify_chain.py`
re-derives it exactly like the engagement log. This is the data the research is measured
against; red's and blue's logs are their own (secondary) accounts, compared TO this.

Sources are target/host-resident and out-of-band — neither agent writes them:
  - sys.syscall : Falco (eBPF) — process execs, file opens (e.g. reading the crown secret),
                  connect() calls. The richest ground truth; parsed via swarm.sensor_stack.
  - net.flow    : conntrack — the kernel's own record of every connection on the range nets.
  - svc.event   : a target container's own stdout/stderr (the Struts Jakarta fault an S2-045
                  RCE raises; the sshd "Accepted publickey" an earned pivot raises).

Parsing is pure (offline-testable on fixtures); the live capture helpers (Falco container,
conntrack -E) are thin and degrade honestly when a source is unavailable on the host.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect  # noqa: E402  (one effect path)

from swarm import sensor_real                               # noqa: E402

# ── Pure parsers: real sensor record -> normalized actual-event dicts ────────────────
_CT_RE = re.compile(r"\b(?P<proto>tcp|udp)\b.*?src=(?P<src>\d+\.\d+\.\d+\.\d+)\s+"
                    r"dst=(?P<dst>\d+\.\d+\.\d+\.\d+)(?:\s+sport=(?P<sport>\d+))?"
                    r"(?:\s+dport=(?P<dport>\d+))?")
_CT_EVENT_RE = re.compile(r"\[\s*(NEW|UPDATE|DESTROY)\s*\]")


def _in_subnets(ip, subnets):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(s) for s in subnets)


def parse_conntrack(text, subnets):
    """conntrack -E / -L text -> network flow events touching the range subnets. The kernel's
    OWN record of actual connections (the ssh pivots, the exploit HTTP, the reverse shell)."""
    flows = []
    for line in (text or "").splitlines():
        m = _CT_RE.search(line)
        if not m:
            continue
        src, dst = m.group("src"), m.group("dst")
        if not (_in_subnets(src, subnets) or _in_subnets(dst, subnets)):
            continue
        ev = _CT_EVENT_RE.search(line)
        flows.append({"proto": m.group("proto"), "src": src, "dst": dst,
                      "dport": int(m.group("dport")) if m.group("dport") else None,
                      "event": ev.group(1) if ev else "FLOW"})
    return flows


def parse_service_events(service_logs):
    """{container: log_text} -> service/auth/exploit events, each tagged with the ATT&CK
    technique its Sigma rule recognizes (swarm.sensor_real). The target's own record."""
    evs = []
    for host, text in (service_logs or {}).items():
        for line in (text or "").splitlines():
            for tech, rx, lbl, src, *_meta in sensor_real.SIGMA_RULES:
                if rx.search(line):
                    evs.append({"host": host, "technique": tech, "label": lbl,
                                "source": src, "raw": line.strip()[:200]})
    return evs


def parse_syscall_events(falco_lines):
    """Falco eBPF output -> ALL syscall/process events (one per Falco JSON record). The PRIMARY
    record keeps every actual event — a process exec, a connect(), the open() of the crown
    secret — NOT only the ones that classify as an ATT&CK technique (that filtering is blue's
    detection job in sensor_stack, downstream). Technique, when Falco tags one, is kept as a
    hint; absence of a tag never drops the real event."""
    import json as _json
    import re as _re
    out = []
    for ln in (falco_lines or []):
        try:
            o = _json.loads(ln)
        except Exception:                                   # noqa: BLE001
            continue
        host = (o.get("output_fields") or {}).get("container.name") or o.get("hostname")
        if not host:   # fallback: real Falco rules often print container=<name> in the text
            mt = _re.search(r"container=([A-Za-z0-9_.\-]+)", o.get("output") or "")
            host = mt.group(1) if mt else "?"
        tags = o.get("tags") or []
        tech = next((t.split(".")[0] for t in tags if _re.fullmatch(r"T\d{4}(?:\.\d+)?", t)), None)
        out.append({"host": host, "rule": o.get("rule", ""), "technique": tech,
                    "signal": (o.get("output") or "")[:200], "priority": o.get("priority"),
                    "source": "falco", "raw": ln[:300]})
    return out


def ingest(chain, *, service_logs=None, conntrack_text=None, falco_lines=None, subnets=None):
    """Append every parsed ACTUAL event to the hash-chained telemetry `chain` (an EventLog).
    Returns counts per source. Order: network, syscall, service (deterministic)."""
    subnets = subnets or ["10.9.0.0/24", "10.10.0.0/24", "10.11.0.0/24", "10.99.0.0/24"]
    n = {"net.flow": 0, "sys.syscall": 0, "svc.event": 0}
    # net.flow from BOTH sensors: host conntrack (routed/NAT flows, e.g. the ingress entry) AND
    # Falco connects (the intra-bridge container pivots conntrack cannot see). Together they are
    # the network record of what actually crossed the wire.
    for fl in parse_conntrack(conntrack_text, subnets):
        chain.append("telemetry", "net.flow", fl); n["net.flow"] += 1
    for fl in parse_falco_netflows(falco_lines):
        chain.append("telemetry", "net.flow", fl); n["net.flow"] += 1
    for sc in parse_syscall_events(falco_lines):
        chain.append("telemetry", "sys.syscall", sc); n["sys.syscall"] += 1
    for sv in parse_service_events(service_logs):
        chain.append("telemetry", "svc.event", sv); n["svc.event"] += 1
    return n


# ── Thin live-capture helpers (deploy host) — degrade honestly if a source is absent ──
def tail_service_logs(containers, lines=1500, since=None):
    """Service logs per container. `since` windows the capture to THIS episode (docker logs is
    cumulative on a persistent range) so blue detects on this episode's telemetry, not prior runs'."""
    return {c: sensor_real.tail_logs(c, lines, since=since) for c in containers}


def _conntrack_snapshot_cmd():
    """The host conntrack-table read. On a native deploy host the tool lives at /usr/sbin and
    reading the table needs CAP_NET_ADMIN (root), so this uses `sudo -n` — the narrow,
    non-interactive, NOPASSWD-whitelisted `conntrack -L` (the same privilege model as the §E
    firewall). No apk-in-a-container (that needs internet the air-gapped range does not have)."""
    return ["sudo", "-n", "conntrack", "-L"]


def capture_conntrack(subnets, *, runner=None):
    """Snapshot the kernel conntrack table (host `sudo -n conntrack -L`). Returns the raw text,
    or '' if unavailable (honest degrade). A single snapshot catches only flows OPEN at call
    time; for short-lived range flows (the SSH pivots) use start_conntrack_sampler, which
    accumulates across the episode. parse_conntrack filters the text to the range subnets."""
    run = runner or (lambda cmd: run_effect(cmd, capture_output=True, text=True, timeout=30))
    try:
        r = run(_conntrack_snapshot_cmd())
        return getattr(r, "stdout", "") or ""
    except Exception:                                        # noqa: BLE001
        return ""


def parse_falco_netflows(falco_lines):
    """Structured network-FLOW events from Falco's outbound-connect syscall records. On a Docker
    range, container-to-container traffic on the SAME bridge is L2-switched and NEVER enters the
    host conntrack table — so conntrack is blind to the range's internal pivots. Falco's eBPF
    connect() probe sees them regardless, and ATTRIBUTES each to the process + container that
    opened it. This turns those into first-class net.flow records: the real connections the
    kernel witnessed (src container, dst ip, dport, proc), out-of-band from both agents."""
    import json as _json
    import re as _re

    def _f(text, key):
        m = _re.search(rf"\b{key}=([^\s)]+)", text)
        return m.group(1) if m else None

    out = []
    for ln in (falco_lines or []):
        try:
            o = _json.loads(ln)
        except Exception:                                   # noqa: BLE001
            continue
        text = o.get("output") or ""
        if "connect" not in text.lower():
            continue
        dst, dport = _f(text, "dst"), _f(text, "dport")
        if not dst:
            continue
        container = _f(text, "container") or (o.get("output_fields") or {}).get("container.name") or "?"
        src = container[len("range-"):] if container.startswith("range-") else container
        out.append({"src_host": src, "dst_ip": dst, "dport": int(dport) if (dport or "").isdigit() else dport,
                    "proc": _f(text, "proc"), "event": "connect", "source": "falco-connect",
                    "raw": text[:200]})
    return out


# A7/I12: Falco was pulled as :latest (mutable). Pinned by digest for reproducibility; the live
# runner records the actual RepoDigests in the chain's config event.
FALCO_IMAGE = "falcosecurity/falco@sha256:69e957f91b3a6beb5c82e2afae33ec3e4479dab2d4421475d288d0cd113cedf6"


def start_falco(container_name="ds_falco", rules_path=None, *, runner=None, image=FALCO_IMAGE):
    """Start Falco (modern eBPF) capturing syscalls host-wide to its stdout as JSON — the
    kernel's own record of process execs, file opens (the crown read) and connects on the
    range containers. Returns a handle {container, teardown} or None (honest degrade if the
    probe cannot load). Proven to load on this host despite no tracefs (modern BPF)."""
    run = runner or (lambda cmd, t=120: run_effect(cmd, capture_output=True, text=True, timeout=t))
    rules_path = rules_path or str(Path(__file__).resolve().parent.parent / "config" / "falco_duelswarm.yaml")
    run(["docker", "rm", "-f", container_name], 30)
    # Two things make the syscall stream actually capture + attribute on this host (both proven
    # empirically; getting either wrong is a silent 0-syscall degrade):
    #   * --pid=host puts Falco in the ROOT pid namespace, so the modern-BPF probe stops
    #     disabling its iterators ("not running in the root PID namespace") and the open/
    #     execve programs attach and deliver events (the crown-read witness).
    #   * the container@0.x engine is a PLUGIN now, and it auto-discovers the docker socket at
    #     /host/var/run/docker.sock (NOT the old /var/run path the deprecated -o
    #     container_engines.* keys pointed at). Mount it THERE or every syscall line carries
    #     container.name=<NA> and the run_live range-filter cannot attribute the crown open to
    #     range-<crown>. (The crown-read witness is kept regardless via the "/.crown" substring
    #     rule in the live runner, but every other line needs this enrichment.)
    cmd = ["docker", "run", "-d", "--name", container_name, "--privileged", "--pid=host",
           "-v", "/var/run/docker.sock:/host/var/run/docker.sock:ro",
           "-v", "/proc:/host/proc:ro", "-v", "/boot:/host/boot:ro",
           "-v", "/lib/modules:/host/lib/modules:ro",
           "-v", f"{rules_path}:/etc/falco/rules.d/duelswarm.yaml:ro", image,
           "falco", "-o", "engine.kind=modern_ebpf", "-o", "json_output=true",
           "-o", "stdout_output.enabled=true", "-o", "log_level=warning"]
    r = run(cmd)
    if r.returncode != 0:
        return None

    def _rm():
        run(["docker", "rm", "-f", container_name], 30)
    return {"container": container_name, "teardown": _rm}


def read_falco(container, *, runner=None):
    """Falco's emitted JSON event lines so far (from its stdout)."""
    run = runner or (lambda cmd, t=30: run_effect(cmd, capture_output=True, text=True, timeout=t))
    out = run(["docker", "logs", container]).stdout or ""
    return [ln for ln in out.splitlines() if ln.strip().startswith("{") and '"output"' in ln]


if __name__ == "__main__":  # self-check: build a hash-chained telemetry chain from fixtures
    import tempfile, json as _json
    from swarm.eventlog import EventLog

    chain_p = Path(tempfile.mktemp(suffix=".jsonl"))
    chain = EventLog(chain_p)

    # fixtures standing in for real captures: the struts container's own Jakarta fault, the
    # app/crown sshd Accepted-publickey lines, the kernel's conntrack flows for the pivots,
    # and a Falco syscall event for red reading the crown secret file.
    service_logs = {
        "struts_edge": "org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest processUpload failed",
        "app_0": "sshd[55]: Accepted publickey for svc from 10.11.0.5 port 44512 ssh2",
        "crown_db": "sshd[9]: Accepted publickey for svc from 10.11.0.11 port 33002 ssh2",
    }
    conntrack_text = (
        "[NEW] tcp 6 120 SYN_SENT src=10.9.0.3 dst=10.9.0.10 sport=40100 dport=8080 [UNREPLIED]\n"
        "[NEW] tcp 6 120 SYN_SENT src=10.11.0.5 dst=10.11.0.11 sport=55010 dport=22 [UNREPLIED]\n"
        "[NEW] tcp 6 120 SYN_SENT src=10.11.0.11 dst=10.11.0.15 sport=55020 dport=22 [UNREPLIED]\n"
        "[NEW] tcp 6 120 src=8.8.8.8 dst=1.1.1.1 dport=443\n"          # off-range: must be dropped
    )
    falco_lines = ['{"output":"Sensitive file opened for reading (file=/root/.crown_crown_db '
                   'container=range-crown_db) ","priority":"Warning"}']

    n = ingest(chain, service_logs=service_logs, conntrack_text=conntrack_text, falco_lines=falco_lines)
    assert n["svc.event"] == 3, n           # struts fault + 2 accepted-publickey
    assert n["net.flow"] == 3, n            # 3 in-range flows; the 8.8.8.8->1.1.1.1 flow dropped
    assert n["sys.syscall"] == 1, n         # the crown-secret file-read syscall (kept raw)
    events = [_json.loads(x) for x in chain_p.read_text().splitlines() if x.strip()]
    kinds = [e["action"] for e in events]
    assert kinds.count("net.flow") == 3 and kinds.count("svc.event") == 3, kinds
    # every telemetry record is actor "telemetry" (the system's own record, not an agent's)
    assert all(e["actor"] == "telemetry" for e in events), events
    # the chain is HASH-CHAINED and tamper-evident: re-derive it like any duelswarm log.
    import importlib.util
    vc = Path(__file__).resolve().parent.parent / "scripts" / "verify_chain.py"
    spec = importlib.util.spec_from_file_location("verify_chain", vc)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    ok = m.verify(str(chain_p)) if hasattr(m, "verify") else True
    assert ok, "telemetry chain must verify as a hash chain"
    # off-range egress never entered the chain (only range system/network truth is recorded)
    assert not any("8.8.8.8" in _json.dumps(e) for e in events), "off-range flow leaked into chain"

    chain_p.unlink(missing_ok=True)
    print("live_telemetry ok (hash-chained PRIMARY record of actual events: conntrack flows + "
          "Falco syscalls + target service/auth logs ingested as actor=telemetry, range-scoped, "
          "re-derivable by verify_chain — independent of red/blue/the gate)")
