"""Falsification battery — attack our OWN instruments; prove they catch us being wrong.

A green PASS that only confirms the thesis is confirmation bias baked into the instrument.
This does the opposite: it actively tries to slip lies past the airtight checks and verifies
each lie is CAUGHT. If any attack SLIPS through, the instrument is vacuous and the battery
fails. Every check here is adversarial — its success is the detector surviving an attack.

Attacks:
  A. fabricated foothold — red logs a foothold the primary telemetry never witnessed
     -> the reconciler MUST flag it (else corroboration is meaningless).
  B. fabricated loot — red claims it read the crown with no file-read syscall in telemetry
     -> MUST flag.
  C. chain tamper — a byte flipped in a hash-chained log -> verify_chain MUST detect the break.
  D. honest control — a fully-corroborated log -> the reconciler MUST NOT false-flag it
     (a detector that flags everything is as useless as one that flags nothing).
  E. reasoning-vs-recall control is its own harness (scripts/prove_control_reasoning.py).

Offline: no Docker, no key, no network — pure adversarial logic over fixtures.
"""
import sys
import json
import argparse
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))

from swarm.eventlog import EventLog               # noqa: E402
from swarm import live_telemetry, live_truth       # noqa: E402
import verify_chain as vc                          # noqa: E402


def _red_log(claims):
    """Build an engagement log asserting each (state, dst) claim as a grounded spine mutation."""
    log = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    seq = 0
    for st, dst in claims:
        log.append("range", "confirm", {"confirms": st, "dst": dst}); seq += 1
        log.append("red", "state.mutate", {"state": st, "dst": dst, "via": "x", "via_confirm": seq}); seq += 1
    return log.path


def _telemetry(service_logs=None, conntrack_text=None, falco_lines=None):
    chain = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    live_telemetry.ingest(chain, service_logs=service_logs or {}, conntrack_text=conntrack_text or "",
                          falco_lines=falco_lines or [])
    return chain.path


def run():
    results = []   # (attack, expectation, caught)

    # A. FABRICATED FOOTHOLD: red claims a foothold on 'edge' the telemetry never witnessed.
    red = _red_log([("foothold", "edge")])
    tele = _telemetry(service_logs={"edge": "nginx: GET / 200"})   # no Jakarta fault, no exploit trace
    rec = live_truth.reconcile(str(red), str(tele))
    caught = any(r["claim"] == "foothold" and r["flagged"] for r in rec["reports"])
    results.append(("fabricated foothold (no exploit trace)", "FLAG", caught))

    # B. FABRICATED LOOT: red claims it read the crown; no file-read syscall anywhere.
    red = _red_log([("loot", "crown")])
    tele = _telemetry(service_logs={"crown": "sshd: Server listening on 0.0.0.0 port 22."})
    rec = live_truth.reconcile(str(red), str(tele))
    caught = any(r["claim"] == "loot" and r["flagged"] for r in rec["reports"])
    results.append(("fabricated loot (no crown-file read)", "FLAG", caught))

    # C. CHAIN TAMPER: flip a field in a hash-chained telemetry log -> verify_chain must break.
    tele = _telemetry(service_logs={"edge": "JakartaMultiPartRequest processUpload failed"},
                      falco_lines=['{"output":"Sensitive file opened for reading (file=/root/.crown_x '
                                   'container=range-crown)","priority":"Warning"}'])
    assert vc.verify(str(tele)) is True, "a freshly written chain must verify"
    lines = tele.read_text().splitlines()
    mid = len(lines) // 2
    e = json.loads(lines[mid]); e["data"]["host"] = "tampered-host"       # forge an event, keep its hash
    lines[mid] = json.dumps(e)
    tele.write_text("\n".join(lines) + "\n")
    caught = vc.verify(str(tele)) is False
    results.append(("hash-chain tamper (forged telemetry event)", "DETECT", caught))

    # D. HONEST CONTROL: a fully-corroborated log must NOT be false-flagged.
    red = _red_log([("foothold", "edge"), ("lateral", "app"), ("loot", "crown")])
    tele = _telemetry(
        service_logs={"edge": "JakartaMultiPartRequest processUpload failed",
                      "app": "sshd[1]: Accepted publickey for svc from 10.11.0.5 port 5 ssh2"},
        conntrack_text="[NEW] tcp 6 120 src=10.11.0.5 dst=10.11.0.9 sport=5 dport=22 [UNREPLIED]\n",
        falco_lines=['{"output":"Sensitive file opened for reading (file=/root/.crown_crown '
                     'container=range-crown)","priority":"Warning"}'])
    # app pivot witnessed by sshd; loot by the crown file-read; foothold by the Jakarta fault.
    rec = live_truth.reconcile(str(red), str(tele))
    clean = rec["flagged"] == 0 and rec["corroborated"] >= 2
    results.append(("honest run NOT false-flagged", "NO-FLAG", clean))

    return results


def main():
    argparse.ArgumentParser().parse_args()
    results = run()
    print("=== falsification battery (attacking our own instruments) ===")
    allok = True
    for attack, expect, caught in results:
        allok = allok and caught
        print(f"  [{'CAUGHT' if caught else 'SLIPPED'}] expect={expect:7} :: {attack}")
    verdict = ("every lie was caught and the honest run was not false-flagged — the airtight "
               "checks BITE" if allok else
               "an attack slipped past an instrument — the check is vacuous")
    print(f"\n{'PASS' if allok else 'FAIL'}: {verdict}")
    return 0 if allok else 1


def _selftest():
    results = run()
    for attack, _expect, caught in results:
        assert caught, f"adversarial check did not bite: {attack}"
    print("prove_falsification selftest ok (the reconciler FLAGS a fabricated foothold and a "
          "fabricated loot; verify_chain DETECTS a forged telemetry event; an honest run is NOT "
          "false-flagged — our own airtight checks catch us being wrong, so they are not vacuous)")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    raise SystemExit(main())
