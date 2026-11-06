"""V3 — a REAL blue detector on REAL telemetry, scored as a classifier (measured recall/ROC).

Replaces the DECLARED lossy sensor (`live_blue.sensor_view`'s synthetic recall) for any
detection CLAIM: blue's recall now EMERGES from a real detector's hit rate on real range
telemetry (`docker logs` — container stdout/stderr, incl. sshd -e auth events), not from a
hardcoded Bernoulli. The air-gap is unchanged: blue reads its own telemetry, never red's
raw `gate.allow`.

Sigma-style rules (community-recognizable signatures), each mapping a log pattern to an
ATT&CK technique and a log source:
  - T1190 (S2-045 exploit): the Jakarta Multipart parser fault the OGNL RCE triggers.
  - T1021 (lateral movement): sshd "Accepted publickey" on a DB host.
  - T1110 (credential brute/fail): sshd "Failed password" (benign-ish / noise).
Exfil (T1041) over an ALREADY-established ssh session leaves NO new auth line — so it is
NOT detectable from auth telemetry, and recall is lossy BECAUSE OF THAT, measured not assumed.

`score_classifier` scores the detector against ground-truth events (from the hash-chained
log) + benign events, sweeping a detection threshold to produce a real ROC (TPR/FPR, AUC)
and precision/recall/F1 at the operating point. A benign ssh login looks identical to a
malicious one in the auth log, so the lateral rule false-positives on it — a real precision
limit, reported, not hidden.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect  # noqa: E402  (one effect path)

# (technique, compiled pattern, human label, source-class, kill-chain stage, signature reliability).
# `stage` is the detector's OWN taxonomy for a matched signature (never read from red's event).
# `reliability` in [0,1] is the SIGNATURE's precision prior — 1 - its false-positive rate — not a
# per-stage probability over red's actions: a detection exists ONLY because a real log line matched,
# and reliability is how much that match is trusted (an exploit fault is near-certain; a bare
# "Accepted publickey" is strong but benign logins share it; a "Failed password" is mostly noise).
SIGMA_RULES = [
    ("T1190", re.compile(r"JakartaMultiPartRequest|MultiPartRequestWrapper|processUpload", re.I),
     "Apache Struts S2-045 Jakarta Multipart OGNL exploit", "web", "initial_access", 0.90),
    # CVE-2021-41773: the Apache 2.4.49 path-traversal -> mod_cgi RCE leaves its tell in the
    # access log (an encoded %2e traversal reaching /cgi-bin/.../bin/sh). This is how a hop's
    # OWN service log witnesses the exploit-per-hop lateral into it (not just the Struts entry).
    ("T1190", re.compile(r"/cgi-bin/\.(%2e|%2E|\.)|%2e%2e/|/bin/sh HTTP", re.I),
     "Apache 2.4.49 path-traversal -> mod_cgi RCE (CVE-2021-41773)", "web", "lateral_movement", 0.90),
    ("T1021", re.compile(r"Accepted publickey for|Accepted password for", re.I),
     "SSH lateral movement (accepted auth)", "host", "lateral_movement", 0.80),
    ("T1110", re.compile(r"Failed password|authentication failure", re.I),
     "SSH authentication failure (brute/probe)", "host", "credential_access", 0.25),
]


_WEB_ACCESS_LOGS = ("/usr/local/apache2/logs/access_log", "/var/log/apache2/access.log",
                    "/var/log/httpd/access_log", "/var/log/nginx/access.log")


def tail_logs(container, lines=500, since=None):
    """Tail a container's logs. `since` (a Unix-seconds timestamp or RFC3339) WINDOWS the capture
    to events after that instant via `docker logs --since` — essential on a PERSISTENT range, where
    docker logs are CUMULATIVE: without it blue would detect on stale lines from prior episodes/runs
    (a false-positive source). The web-access-log tail below is windowed in the caller's episode
    bounds the same way (best-effort: file tails are coarse, so prefer --since-able stdout sources)."""
    out = ""
    try:
        argv = ["docker", "logs"]
        if since is not None:
            argv += ["--since", str(since)]
        argv += ["--tail", str(lines), container]
        r = run_effect(argv, capture_output=True, text=True, timeout=15)
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:                       # noqa: BLE001
        out = f"<log error: {e}>"
    # Web servers log access to FILES, not stdout, so `docker logs` misses the exploit request
    # that witnesses an exploit-per-hop lateral. Also pull the conventional access-log paths
    # that actually exist in the container (existence-gated, image-agnostic — not a hardcoded
    # single path): the hop's OWN record of being exploited, out-of-band from red.
    try:
        paths = " ".join(_WEB_ACCESS_LOGS)
        r2 = run_effect(["docker", "exec", container, "sh", "-c",
                             f"for f in {paths}; do [ -f \"$f\" ] && tail -n {lines} \"$f\"; done"],
                            capture_output=True, text=True, timeout=20)
        if r2.stdout:
            out += "\n" + r2.stdout
    except Exception:                            # noqa: BLE001
        pass
    return out


def detect(telemetry):
    """telemetry: {container: log_text}. Returns {technique: match_count} — the real
    detector's hits across all telemetry. A technique with no telemetry stays at 0."""
    counts = {t: 0 for (t, *_rest) in SIGMA_RULES}
    for _c, text in telemetry.items():
        for line in (text or "").splitlines():
            for technique, rx, _lbl, _src, *_meta in SIGMA_RULES:
                if rx.search(line):
                    counts[technique] += 1
    return counts


def telemetry_detections(service_logs):
    """Blue's belief-feeding detections, derived from REAL service-log telemetry ONLY — the
    label-free replacement for the hardcoded per-stage Bernoulli. One detection per (host,
    technique) a Sigma signature matched in that host's real log, carrying the matched LINE so
    each detection traces to a concrete telemetry event. It reads observable log PATTERNS and the
    detector's own taxonomy; it NEVER reads red's event labels, techniques, or the ground truth.
    `service_logs`: {container: log_text} (as live_telemetry.tail_service_logs returns). Returns a
    list shaped like _bernoulli_detections' output (stage/technique/target/p_fire/basis/confirmed),
    so run_blue_fight's noisy-OR belief consumes it unchanged."""
    seen = {}   # (host, technique) -> detection (dedup; keep the first matched line)
    for host, text in (service_logs or {}).items():
        hname = host[len("range-"):] if host.startswith("range-") else host
        for line in (text or "").splitlines():
            for technique, rx, lbl, src, stage, reliability in SIGMA_RULES:
                if rx.search(line):
                    key = (hname, technique)
                    if key not in seen:
                        seen[key] = {
                            "stage": stage, "technique": technique, "target": hname,
                            "p_fire": reliability, "confirmed": True,
                            "basis": f"real-telemetry[{src}]: {lbl}",
                            "source_line": line.strip()[:200], "source_host": host,
                        }
    return list(seen.values())


def assert_label_free(detections):
    """Air-gap guard: every telemetry detection must trace to a real log line (`source_line`) and
    carry a `real-telemetry[...]` basis — i.e. it came from an observable signature, not red's
    labels/ground truth. Raises if any detection lacks that provenance. Returns the detections."""
    for d in detections:
        if not d.get("source_line") or not str(d.get("basis", "")).startswith("real-telemetry["):
            raise RuntimeError(f"blue detection not traceable to real telemetry (air-gap): {d}")
    return detections


def detected_techniques(telemetry, threshold=1):
    c = detect(telemetry)
    return {t for t, n in c.items() if n >= threshold}


def score_classifier(telemetry, events):
    """events: list of {technique, is_red} ground-truth instances (red actions from the
    hash-chained log + labeled benign actions). Each instance is scored by its technique
    rule's match count in the REAL telemetry; sweeping a threshold yields a ROC.

    Returns measured recall/precision/F1 (red instances as positives) at threshold=1, plus
    ROC points (fpr,tpr) over thresholds and the trapezoidal AUC."""
    counts = detect(telemetry)
    # each instance's detector score = the match count for its technique (0 if no signal)
    scored = [(ev, counts.get(ev["technique"], 0)) for ev in events]
    pos = [s for ev, s in scored if ev["is_red"]]        # red instances (should detect)
    neg = [s for ev, s in scored if not ev["is_red"]]    # benign instances (should NOT)
    P, N = len(pos), len(neg)

    def at(th):
        tp = sum(1 for s in pos if s >= th)
        fp = sum(1 for s in neg if s >= th)
        tpr = tp / P if P else 0.0
        fpr = fp / N if N else 0.0
        return tp, fp, tpr, fpr

    thresholds = sorted({0, 1} | {s for _e, s in scored} | {max((s for _e, s in scored), default=0) + 1})
    roc = [(fpr, tpr) for th in thresholds for (_tp, _fp, tpr, fpr) in [at(th)]]
    roc = sorted(set(roc))
    # trapezoidal AUC over sorted-by-fpr points (pad ends to [0,0]..[1,1])
    pts = sorted(set(roc) | {(0.0, 0.0), (1.0, 1.0)})
    auc = 0.0
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        auc += (x1 - x0) * (y0 + y1) / 2

    tp, fp, tpr, fpr = at(1)
    fn = P - tp
    recall = tpr
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "recall": round(recall, 4), "precision": round(precision, 4), "f1": round(f1, 4),
        "tp": tp, "fp": fp, "fn": fn, "positives": P, "negatives": N,
        "roc": [(round(x, 4), round(y, 4)) for x, y in pts], "auc": round(auc, 4),
        "match_counts": counts,
    }


if __name__ == "__main__":  # self-check: detector + classifier scoring, no Docker
    telem = {
        "range-struts": "INFO ... JakartaMultiPartRequest.parseRequest(...)\nMultiPartRequestWrapper.<init>\nnormal GET / 200",
        "range-customer_db_0": "Server listening on port 22.\nAccepted publickey for dbadmin from 10.11.0.20\nFailed password for root from 10.11.0.9",
    }
    c = detect(telem)
    assert c["T1190"] >= 1 and c["T1021"] >= 1 and c["T1110"] >= 1, c
    # ground truth: red did exploit(T1190) + 2 lateral(T1021) + 2 exfil(T1041);
    # benign: 1 benign login(T1021). exfil has NO telemetry -> must be missed.
    events = ([{"technique": "T1190", "is_red": True}]
              + [{"technique": "T1021", "is_red": True}] * 2
              + [{"technique": "T1041", "is_red": True}] * 2      # exfil: undetectable
              + [{"technique": "T1021", "is_red": False}])        # benign login -> FP
    r = score_classifier(telem, events)
    # recall EMERGES < 1.0 because the 2 exfils have no telemetry (3 of 5 red detected)
    assert 0.0 < r["recall"] < 1.0, r
    assert r["recall"] == round(3 / 5, 4), r          # exploit + 2 laterals of 5 red
    assert r["fp"] >= 1, r                            # the benign login false-positives
    assert 0.0 < r["auc"] <= 1.0, r
    # Belief-feeding detections from the SAME real telemetry, label-free + traceable:
    dets = telemetry_detections(telem)
    techs = {d["technique"] for d in dets}
    assert {"T1190", "T1021", "T1110"} <= techs, dets
    assert all(d["source_line"] and d["basis"].startswith("real-telemetry[") for d in dets), dets
    # the exploit signature carries more weight than a noisy failed-password line
    w = {d["technique"]: d["p_fire"] for d in dets}
    assert w["T1190"] > w["T1021"] > w["T1110"], w
    assert_label_free(dets)                                   # air-gap guard passes on real dets
    # and CATCHES a detection with no telemetry provenance (e.g. one fabricated from a red label)
    _caught = False
    try:
        assert_label_free([{"technique": "T1041", "basis": "red-label", "source_line": ""}])
    except RuntimeError:
        _caught = True
    assert _caught, "assert_label_free failed to catch a non-telemetry detection"
    print(f"sensor_real ok (measured recall={r['recall']} precision={r['precision']} "
          f"auc={r['auc']}; exfil undetectable from auth telemetry; benign login false-positives "
          f"— recall EMERGES, not a hardcoded 0.75; telemetry_detections label-free + traceable, "
          f"air-gap guard catches a fabricated detection)")
