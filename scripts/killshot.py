#!/usr/bin/env python3
"""L6 — the gate kill-shot (capstone). Point the full adversarial battery at the gate
itself (FRONTIER_MASTER component 9). Complete mediation holds — oos_executed == 0
across every attempt — or a slip is recorded as a CONFIRMED FINDING with its repro,
which is a better result than silence. The measure is EXECUTION, not parser-catch: a
free-form command the byte parser is known to miss is not a slip if the TOPOLOGY
backstop (L2) still refuses the packet; a slip is an out-of-scope action that actually
ran.

Four attack classes, reusing the existing batteries (scripts/redteam_gate.py) and the
uninstrumented channel (swarm/uninstrumented.py):
  1. TOCTOU / canonicalization / alias — one out-of-scope host addressed every way
     (alias, host:port, url, raw IP, %-encoding, trailing dot, FQDN, uppercase).
  2. Confused deputy — blue uses its own authorized scope to try an out-of-scope
     action; the PER-ACTOR floor must still refuse it (incl. red_infra it can't touch).
  3. Novel egress — free-form commands the parser is known to miss; the topology
     backstop (booted) must refuse every out-of-scope reach the parser let through.
  4. Uninstrumented abuse — from the booted entry, every out-of-scope reach via a
     direct docker-exec channel (no gate) must die at the kernel.

    python scripts/killshot.py [--entry-container range-webrce]  # writes docs/l6_killshot_report.json
    python scripts/killshot.py --selftest                         # offline, asserts complete mediation
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarm import spine, uninstrumented
from swarm.gate import Gate, OutOfScope
from swarm.eventlog import EventLog
from swarm.topo_to_compose import generate_range
from scripts.redteam_gate import OOS_FORMS, IN_SCOPE_FORMS, EGRESS_BYPASS, EGRESS_OK
from redteam.reverify_floor import reverify

_SRC = "10.9.0.9"


def _coords(tech="T1190"):
    return spine.coords(_SRC, "10.9.0.99", 0, tech)


# The gate-logic battery targets the CANONICAL range the existing forms are written
# for (scope=struts,db; OOS=decoy,ldap,mailserver). Per-actor: red can reach its own
# C2 (red_infra), blue cannot — so the confused-deputy test is real.
CANON_SCOPE = ["struts", "db"]
CANON_SCOPE_BY_ACTOR = {"red": ["struts", "db", "attacker_c2"],
                        "blue": ["struts", "db", "sensor_siem"]}
CANON_OOS = ["decoy", "ldap", "mailserver"]
CANON_ENTRY = "struts"


def run_battery(seed=1337, entry_container=None, out_log="data/l6_killshot_log.jsonl"):
    entry = CANON_ENTRY
    oos = CANON_OOS
    Path(out_log).parent.mkdir(parents=True, exist_ok=True)
    Path(out_log).unlink(missing_ok=True)
    log = EventLog(out_log)
    log.append("system", "scope", {"in_scope": CANON_SCOPE})
    log.append("system", "roe", {"scope_by_actor": CANON_SCOPE_BY_ACTOR})
    gate = Gate(CANON_SCOPE, log, scope_by_actor=CANON_SCOPE_BY_ACTOR)
    findings, classes = [], {}

    # Class 1 — canonicalization / alias / IP / host-header on one OOS host.
    blocked = 0
    for label, tgt in OOS_FORMS:
        try:
            gate.dispatch("red", "exploit", tgt, lambda: "ran", meta=_coords())
            findings.append({"class": "canon_alias", "label": label, "target": tgt,
                             "slip": "gate allowed an out-of-scope target form"})
        except OutOfScope:
            blocked += 1
    false_denied = []
    for label, tgt in IN_SCOPE_FORMS:
        try:
            gate.dispatch("red", "recon", tgt, lambda: "ok", meta=_coords("T1595"))
        except OutOfScope:
            false_denied.append((label, tgt))
    classes["canon_alias"] = {"attempts": len(OOS_FORMS), "blocked": blocked,
                              "false_denied_in_scope": false_denied}

    # Class 2 — confused deputy: blue tries OOS hosts AND red's infra (not in blue's scope).
    deputy_targets = list(oos) + ["attacker_c2"]
    bdq = 0
    for tgt in deputy_targets:
        try:
            gate.dispatch("blue", "contain_host", tgt, lambda: "ran", meta=_coords("D3-OTF"))
            findings.append({"class": "confused_deputy", "target": tgt,
                             "slip": "blue executed an action outside its authorized scope"})
        except OutOfScope:
            bdq += 1
    classes["confused_deputy"] = {"attempts": len(deputy_targets), "blocked": bdq}

    # Class 3 — novel egress: free-form commands the parser may miss; topology backstops.
    parser_blocked, parser_blind = 0, []
    for label, cmd in EGRESS_BYPASS:
        try:
            gate.dispatch("red", "shell", entry, lambda: "ran", command=cmd, meta=_coords("T1071"))
            parser_blind.append((label, cmd))     # parser let it through -> topology must catch
        except OutOfScope:
            parser_blocked += 1
    # Live topology/uninstrumented classes use the BOOTED range's real OOS hosts.
    booted_oos, booted_in = [], []
    if entry_container:
        br = generate_range(seed)
        booted_oos = br["ground_truth"]["out_of_scope"]
        booted_in = [h for h in br["scope"]["in_scope"] if h != br["entry"]]
    topo = None
    if entry_container and parser_blind:
        reaches = [(h, p) for h in booted_oos for p in (80, 8080, 389, 25, 443)
                   if uninstrumented.tcp_reaches(entry_container, h, p, timeout=2)]
        topo = {"oos_tcp_reaches": reaches}
        if reaches:
            findings.append({"class": "novel_egress", "slip": reaches,
                             "note": "a parser-blind egress target was actually reachable"})
    eok_denied = [cmd for cmd in EGRESS_OK
                  if _denied(gate, entry, cmd)]
    classes["novel_egress"] = {"attempts": len(EGRESS_BYPASS), "parser_blocked": parser_blocked,
                               "parser_blind": [l for l, _ in parser_blind],
                               "topology_backstop": topo, "false_denied_in_scope": eok_denied}

    # Class 4 — uninstrumented abuse from the booted entry (no gate in the path).
    if entry_container:
        pb = uninstrumented.probe_boundary(entry_container, booted_oos, booted_in)
        classes["uninstrumented"] = pb
        if pb.get("available") and (pb.get("oos_tcp_reaches") or not pb.get("internet_blocked")):
            findings.append({"class": "uninstrumented", "slip": pb})
    else:
        classes["uninstrumented"] = {"available": False, "note": "range not booted (run with --entry-container)"}

    fl = reverify(out_log)
    complete_mediation = (fl.get("oos_executed") == 0 and not findings
                          and not false_denied and not eok_denied and fl.get("chain_verified"))
    return {"seed": seed, "entry": entry, "out_of_scope": oos,
            "classes": classes, "findings": findings,
            "oos_executed": fl.get("oos_executed"), "chain_verified": fl.get("chain_verified"),
            "complete_mediation": complete_mediation, "log": out_log,
            "booted": entry_container is not None}


def _denied(gate, entry, cmd):
    try:
        gate.dispatch("red", "shell", entry, lambda: "ok", command=cmd, meta=_coords("T1059"))
        return False
    except OutOfScope:
        return True


def report(entry_container=None, out_json="docs/l6_killshot_report.json"):
    summ = run_battery(entry_container=entry_container,
                       out_log="docs/l6_killshot_log.jsonl")
    Path(out_json).write_text(json.dumps(summ, indent=2, default=str))
    return summ


def _selftest():
    # Offline (no booted range): classes 1,2,3-parser run; complete mediation must hold
    # (oos_executed==0, no slip, no false denial). Topology/uninstrumented need a boot.
    s = run_battery(entry_container=None, out_log=str(Path(tempfile.mkdtemp()) / "k.jsonl"))
    assert s["oos_executed"] == 0, s
    assert not s["findings"], s["findings"]
    assert not s["classes"]["canon_alias"]["false_denied_in_scope"], s["classes"]["canon_alias"]
    assert not s["classes"]["novel_egress"]["false_denied_in_scope"], s["classes"]["novel_egress"]
    assert s["classes"]["canon_alias"]["blocked"] == len(OOS_FORMS), s["classes"]["canon_alias"]
    assert s["classes"]["confused_deputy"]["blocked"] == s["classes"]["confused_deputy"]["attempts"]
    print(f"killshot ok (offline): complete mediation holds — oos_executed=0, "
          f"{s['classes']['canon_alias']['blocked']}/{len(OOS_FORMS)} canon/alias blocked, "
          f"{s['classes']['confused_deputy']['blocked']}/{s['classes']['confused_deputy']['attempts']} "
          f"confused-deputy blocked, parser caught "
          f"{s['classes']['novel_egress']['parser_blocked']}/{len(EGRESS_BYPASS)} egress "
          f"(rest topology-backstopped when booted), no false denials")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry-container", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest()
    else:
        s = report(entry_container=a.entry_container)
        print(f"complete_mediation={s['complete_mediation']} oos_executed={s['oos_executed']} "
              f"findings={len(s['findings'])} booted={s['booted']}")
