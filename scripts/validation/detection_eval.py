"""detection_eval — replay a detection ruleset over a run's telemetry and report which
techniques fired (true positives) and which went silent (false negatives).

The telemetry is realistic iff real detectors trip on it at a realistic rate. This is the
EXTERNAL detection judge, the defender-side analogue of the offensive probes. It reads the
hash-chained event log (and, when present, the Falco capture) — it never touches a live effect
site, and its output is never fed to red.

Rule form (a pragmatic Sigma subset so the rig is dependency-light and testable; a full SigmaHQ
ruleset is run on the host as the deeper audit):
    {"id": "...", "technique": "T1558.003", "match": {"<field>": <spec>, ...}}
where <field> is a flattened event field ("action", "actor", "data.attack_id", "data.target", ...)
and <spec> is an exact value or {"contains": "<substr>"} / {"in": [...]}.

Verdict: ok iff at least one true positive AND the detection rate over red's ground-truth
techniques clears `min_rate` — a real ruleset must trip on real telemetry, and silence is a
realism finding, not a pass.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.validation._common import verdict, unmeasured  # noqa: E402


def _flatten(event):
    """Event -> flat {field: value} with data.* promoted, for rule matching."""
    flat = {"actor": event.get("actor"), "action": event.get("action")}
    for k, v in (event.get("data") or {}).items():
        flat[f"data.{k}"] = v
    return flat


def _spec_matches(spec, value):
    if isinstance(spec, dict):
        if "contains" in spec:
            return value is not None and str(spec["contains"]).lower() in str(value).lower()
        if "in" in spec:
            return value in spec["in"]
        return False
    return spec == value


def _rule_matches(rule, flat):
    return all(_spec_matches(spec, flat.get(field)) for field, spec in rule["match"].items())


def _load_events(telemetry_path):
    out = []
    for line in Path(telemetry_path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _red_ground_truth_techniques(events, red_actors=("red", "attacker")):
    """Techniques red actually exercised — the ground truth detection is scored against. A red
    action is one whose actor is red/attacker (or an attacker container), carrying an attack id."""
    techs = set()
    for e in events:
        actor = str(e.get("actor") or "")
        is_red = any(actor == r or actor.startswith(r) or "attacker" in actor for r in red_actors)
        if not is_red:
            continue
        d = e.get("data") or {}
        t = d.get("attack_id") or d.get("technique") or (d.get("objective") or {}).get("attack_id")
        if t:
            techs.add(t)
    return techs


def evaluate(telemetry_path, rules, min_rate=0.5, red_actors=("red", "attacker")):
    """Replay `rules` over the telemetry at `telemetry_path`. Returns a verdict whose evidence
    carries fired/TP/FN/FP technique sets and the detection rate."""
    p = Path(telemetry_path)
    if not p.exists():
        return unmeasured("detection_eval", f"telemetry not found: {telemetry_path}")
    if not rules:
        return unmeasured("detection_eval", "no rules supplied")
    events = _load_events(p)
    if not events:
        return unmeasured("detection_eval", "telemetry empty / unparseable")

    fired = {}  # technique -> [rule ids that fired]
    for e in events:
        flat = _flatten(e)
        for rule in rules:
            if _rule_matches(rule, flat):
                fired.setdefault(rule["technique"], []).append(rule["id"])

    ground_truth = _red_ground_truth_techniques(events, red_actors)
    fired_techs = set(fired)
    tp = sorted(ground_truth & fired_techs)
    fn = sorted(ground_truth - fired_techs)       # red did it; no rule tripped — realism finding
    fp = sorted(fired_techs - ground_truth)       # fired with no corresponding red action
    rate = (len(tp) / len(ground_truth)) if ground_truth else 0.0
    ok = bool(tp) and rate >= min_rate
    detail = (f"{len(tp)}/{len(ground_truth)} red techniques detected (rate {rate:.2f} "
              f">= {min_rate}); {len(fn)} silent, {len(fp)} rules fired without a red action")
    return verdict("detection_eval", available=True, ok=ok, detail=detail,
                   evidence={"true_positives": tp, "false_negatives": fn, "false_positives": fp,
                             "detection_rate": round(rate, 3), "ground_truth": sorted(ground_truth),
                             "fired": {k: sorted(set(v)) for k, v in fired.items()}})


# A small default ruleset over duelswarm's own telemetry idioms (extended on the host with a
# real SigmaHQ ruleset). These match the event shapes the engine already emits.
DEFAULT_RULES = [
    {"id": "ds-kerberoast", "technique": "T1558.003",
     "match": {"action": {"contains": "roast"}}},
    {"id": "ds-pth", "technique": "T1550.002",
     "match": {"action": {"contains": "pass_the_hash"}}},
    {"id": "ds-cred-dump", "technique": "T1003",
     "match": {"action": {"contains": "secretsdump"}}},
    {"id": "ds-oos-block", "technique": "T1021",
     "match": {"action": "gate.block"}},
    {"id": "ds-exfil", "technique": "T1213",
     "match": {"data.attack_id": "T1213"}},
    # tamper is first-class (D3FEND-aware blue, Phase 4): log-clearing (T1070) and impair-defenses
    # (T1562) are themselves loud, tamper-evident signals — a silent chain here is a realism finding.
    {"id": "ds-log-clear", "technique": "T1070",
     "match": {"data.technique": "T1070"}},
    {"id": "ds-impair-defenses", "technique": "T1562",
     "match": {"data.technique": "T1562"}},
    # a honey-SPN TGS request is a tripwire (near-zero false positive): any touch is malicious.
    {"id": "ds-honey-spn", "technique": "T1558.003",
     "match": {"data.honey_spn": True}},
]


def _selftest():
    import tempfile
    # A fixture run: red kerberoasts (T1558.003) and exfiltrates (T1213); a rule covers each,
    # but there is NO rule for T1021 ground truth below -> it must show as a false negative.
    events = [
        {"seq": 0, "actor": "system", "action": "scope", "data": {}},
        {"seq": 1, "actor": "red", "action": "tool.kerberoast", "data": {"attack_id": "T1558.003"}},
        {"seq": 2, "actor": "red", "action": "tool.exfiltrate", "data": {"attack_id": "T1213"}},
        {"seq": 3, "actor": "red", "action": "tool.smb_login", "data": {"attack_id": "T1021"}},
        {"seq": 4, "actor": "blue", "action": "contain", "data": {}},
    ]
    rules = [
        {"id": "r-roast", "technique": "T1558.003", "match": {"action": {"contains": "kerberoast"}}},
        {"id": "r-exfil", "technique": "T1213", "match": {"data.attack_id": "T1213"}},
        {"id": "r-noise", "technique": "T9999", "match": {"action": "nonexistent"}},  # never fires
    ]
    tmp = Path(tempfile.mktemp(suffix=".jsonl"))
    tmp.write_text("\n".join(json.dumps(e) for e in events))
    v = evaluate(tmp, rules, min_rate=0.5)
    tmp.unlink()
    ev = v["evidence"]
    assert v["available"] and ev["true_positives"] == ["T1213", "T1558.003"], ev
    assert ev["false_negatives"] == ["T1021"], ev           # red did it; no rule -> silent
    assert ev["false_positives"] == [], ev                  # r-noise never fired
    assert ev["detection_rate"] == round(2 / 3, 3), ev   # stored rate is rounded to 3 dp
    assert v["ok"] is True, v                                # 0.67 >= 0.5 and TP present

    # all-silent ruleset -> ok False (a real finding: the telemetry didn't trip anything)
    tmp2 = Path(tempfile.mktemp(suffix=".jsonl"))
    tmp2.write_text("\n".join(json.dumps(e) for e in events))
    vb = evaluate(tmp2, [{"id": "r-x", "technique": "T1", "match": {"action": "never"}}], min_rate=0.5)
    assert vb["ok"] is False and vb["evidence"]["true_positives"] == [], vb

    # missing telemetry / no rules -> UNMEASURED, never a silent pass
    assert evaluate("/no/such/file.jsonl", rules)["available"] is False
    assert evaluate(tmp2, [])["available"] is False, "empty ruleset must be UNMEASURED"
    tmp2.unlink()
    print("detection_eval selftest: OK")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="replay detection rules over a run's telemetry")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("telemetry", nargs="?", help="path to a run's event-log JSONL")
    ap.add_argument("--min-rate", type=float, default=0.5)
    a = ap.parse_args()
    if a.selftest or not a.telemetry:
        _selftest()
    else:
        from scripts.validation._common import print_verdict
        import sys as _s
        v = evaluate(a.telemetry, DEFAULT_RULES, min_rate=a.min_rate)
        print_verdict(v)
        _s.exit(0 if v["available"] and v["ok"] else (2 if not v["available"] else 1))
