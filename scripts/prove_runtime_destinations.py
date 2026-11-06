#!/usr/bin/env python3
"""A3 acceptance (4): the RUNTIME destination check — the part the static oracle t1b cannot see.

t1b proves no red-reachable effect escapes gate.dispatch. It CANNOT prove that an effect inside a
dispatched tool_fn touches only the destination the gate checked (a batched sweep could reach more
hosts than the one target). This harness closes that gap at runtime: it wraps run_effect to record,
for every argv, the destination IPs it touches AND the canonical target set of the ENCLOSING
gate.dispatch, drives the REAL gated recon path (drop_oos -> reveal_real -> scan_host -> _exec ->
run_effect) with forbidden-IP spellings planted in the candidate list, and asserts:

  1. every destination a red effect touches is in its enclosing dispatch's checked targets;
  2. the forbidden IP appears ONLY as gate.block, never as a touched destination (dotted, decimal,
     hex and IPv6-mapped spellings are all planted);
  3. POSITIVE CONTROL: a deliberately UNGATED sweep (a scan run outside any dispatch) IS caught by
     check 1 — proving the check has teeth and is not vacuous.

Lives in scripts/ (imports swarm.*), keeping redteam/ swarm-independent (G6).
Run:  python3 scripts/prove_runtime_destinations.py        # exits non-zero on any violation
"""
import ipaddress
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# dry harness, no LLM: stub the absent openai SDK so importing live_red/live_weapon works offline
import types as _types  # noqa: E402


class _Stub(_types.ModuleType):
    def __getattr__(self, n):
        return type(n, (), {})


sys.modules.setdefault("openai", _Stub("openai"))

from swarm import gate as gatemod, live_recon  # noqa: E402
from swarm.gate import Gate, OutOfScope         # noqa: E402

FORBID = "10.50.0.11"       # dc-01 (out of scope)
INSCOPE = "10.50.0.10"      # web01 (in scope)
_fb_int = int(ipaddress.ip_address(FORBID))
FORBID_SPELLINGS = [FORBID, str(_fb_int), hex(_fb_int), "::ffff:" + FORBID]   # dotted/decimal/hex/ipv6

# ── instrument: a stack of the canonical targets the current dispatch(es) checked, and a recorder
#    of every run_effect's destination IPs + that stack ──
_STACK = []
_TOUCHED = []          # (dest_ips:set, checked_targets:set, argv:list)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_orig_dispatch = Gate.dispatch


def _traced_dispatch(self, actor, tool, target, tool_fn, *a, **k):
    try:
        canon = self._parse_target(target).host
    except OutOfScope:
        canon = None

    def _traced_fn(*aa, **kk):
        _STACK.append(canon)
        try:
            return tool_fn(*aa, **kk)
        finally:
            _STACK.pop()
    return _orig_dispatch(self, actor, tool, target, _traced_fn, *a, **k)


Gate.dispatch = _traced_dispatch


def _traced_run_effect(argv, **k):
    dests = set(_IP_RE.findall(" ".join(str(x) for x in argv)))
    _TOUCHED.append((dests, set(t for t in _STACK if t), list(argv)))

    class R:
        returncode, stdout, stderr = 1, "", ""     # record only; never a real docker exec
    return R()


gatemod.run_effect = _traced_run_effect
live_recon.run_effect = _traced_run_effect
import swarm.live_red as _lr  # noqa: E402
_lr.run_effect = _traced_run_effect


class _Log:
    def __init__(s):
        s.ev = []

    def append(s, actor, action, data=None):
        s.ev.append((actor, action, data or {}))
        return {}

    def entries(s):
        return []


def _blocks_for(log, target):
    return [d for a, act, d in log.ev if act == "gate.block" and d.get("target") == target]


def _allows_for(log, target):
    return [d for a, act, d in log.ev if act == "gate.allow" and d.get("target") == target]


fails = []


def main():
    log = _Log()
    gate = Gate([], log, scope_by_actor={"red": [INSCOPE]})
    gate.aliases.update({INSCOPE: INSCOPE, FORBID: FORBID})   # resolve_ips-style; FORBID known, OOS

    # candidate list with the forbidden IP in EVERY spelling + an unknown host, plus the in-scope one
    cand = [INSCOPE] + FORBID_SPELLINGS + ["10.50.0.99"]
    kept = live_recon.drop_oos(log, gate, "red", cand)
    print(f"drop_oos kept {kept} of {len(cand)} candidates (fail-closed)")
    if kept != [INSCOPE]:
        fails.append(f"drop_oos must keep ONLY the in-scope host, kept={kept}")

    # the real gated discovery over the kept set (per-host gate.dispatch -> scan_host -> run_effect)
    live_recon.reveal_real(log, gate, "red", "attacker", "range-attacker",
                           [(ip, ip, [22, 8080]) for ip in kept])

    # 1. every touched destination is in its enclosing dispatch's checked target set
    for dests, checked, argv in _TOUCHED:
        stray = dests - checked
        if stray:
            fails.append(f"destination(s) {stray} touched outside the dispatch's checked targets "
                         f"{checked} (argv={argv[:6]})")
    print(f"gated recon: {len(_TOUCHED)} run_effect call(s), all destinations within checked targets"
          if not fails else f"gated recon: {len(_TOUCHED)} run_effect call(s)")

    # 2. the forbidden IP appears only as gate.block, never as a touched destination
    touched_all = set().union(*[d for d, _c, _a in _TOUCHED]) if _TOUCHED else set()
    if FORBID in touched_all:
        fails.append(f"forbidden {FORBID} was TOUCHED by a run_effect")
    for sp in FORBID_SPELLINGS:
        if not _blocks_for(log, sp):
            fails.append(f"forbidden spelling {sp!r} was not recorded as a gate.block")
        if _allows_for(log, sp):
            fails.append(f"forbidden spelling {sp!r} was ALLOWED")
    print(f"forbidden IP: blocked in {len(FORBID_SPELLINGS)} spellings, touched by 0 effects"
          if not any('forbidden' in f for f in fails) else "forbidden IP: VIOLATION")

    # 3. POSITIVE CONTROL: a deliberately UNGATED sweep of the forbidden IP must trip check 1
    _TOUCHED.clear()
    live_recon.scan_many("range-attacker", [(FORBID, 22)])      # NOT through drop_oos / dispatch
    caught = any(FORBID in dests and FORBID not in checked for dests, checked, _ in _TOUCHED)
    if not caught:
        fails.append("positive control FAILED: an ungated sweep of the forbidden IP was not caught")
    else:
        print("positive control: an ungated sweep of the forbidden IP IS caught (check has teeth)")

    # 4. EARNED-CHANNEL EGRESS (fix 1): a post-ex command through an earned shell on an ALLOWED host
    #    that reaches a FORBIDDEN host is a gate.block with NO effect — check_egress sees command=.
    from swarm import live_weapon
    from swarm.eventlog import EventLog
    import json as _json
    import tempfile
    ep = Path(tempfile.mktemp(suffix=".jsonl"))
    elog = EventLog(ep)
    egate = Gate([], elog, scope_by_actor={"red": [INSCOPE]})
    egate.aliases.update({INSCOPE: INSCOPE, FORBID: FORBID})
    eran = []
    res = live_weapon._response_weapon("CVE-2021-41773", gate=egate, log=elog, actor="red",
                                       target=INSCOPE, rport=80, pub_host=INSCOPE, pub_port=80,
                                       fire_fn=lambda c: (eran.append(c) or "uid=0(root)"))
    if not (res.get("grounded") and res.get("exec")):
        fails.append("earned-channel setup: the response weapon did not ground on the in-scope host")
    else:
        blocked = False
        try:
            res["exec"]("curl " + FORBID)       # the earned shell curls a forbidden host
        except OutOfScope:
            blocked = True
        if not blocked:
            fails.append("earned-channel egress: a forbidden curl was NOT gate-blocked")
        if ("curl " + FORBID) in eran:
            fails.append("earned-channel egress: the forbidden curl REACHED the effect")
        evs = [_json.loads(x) for x in ep.read_text().splitlines() if x.strip()]
        if not any(e.get("action") == "gate.block"
                   and (e.get("data") or {}).get("reason") == "egress-out-of-scope" for e in evs):
            fails.append("earned-channel egress: no gate.block(egress-out-of-scope) recorded")
        if not any(f.startswith("earned-channel") for f in fails):
            print("earned-channel egress: a forbidden curl through the earned shell -> gate.block, no effect")
    ep.unlink(missing_ok=True)

    # 5. FAIL-CLOSED local reads (fix 2): own_ips/own_subnets with NO gate must RAISE, not read;
    #    with the explicit TCB read-gate they read (returning, possibly empty, no raise).
    for fn in (_lr.own_ips, _lr.own_subnets):
        raised = False
        try:
            fn("range-attacker")                         # no gate= -> must fail closed
        except TypeError:
            raised = True
        if not raised:
            fails.append(f"{fn.__name__} must require a gate (fail-closed); it ran with none")
    try:
        _lr.own_ips("range-attacker", gate=_lr.TCB_READ_GATE)   # explicit TCB read: no raise
    except Exception as e:                               # noqa: BLE001
        fails.append(f"own_ips with TCB_READ_GATE should not raise: {e!r}")
    if not any(f.endswith("with none") or "TCB_READ_GATE" in f for f in fails):
        print("fail-closed reads: own_ips/own_subnets RAISE with no gate, read with TCB_READ_GATE")

    print("=" * 70)
    if fails:
        print(f"A3 RUNTIME CHECK FAILED ({len(fails)}):")
        for f in fails:
            print("  -", f)
        sys.exit(1)
    print("A3 RUNTIME CHECK PASSED: every red effect touches only its dispatch's checked targets; "
          "the forbidden IP is only ever a gate.block; the ungated-sweep positive control is caught.")


if __name__ == "__main__":
    main()
