"""Termination & degeneracy detection (brief §2).

An open-action-space arms race can collapse into junk equilibria — red looping one
blocked action, or thrashing with no new progress — that would silently inflate or
flatten the dynamics curve. We detect and FLAG these (`degenerate: true`) so a
degenerate episode is reported honestly, never counted as signal. Pure function
over the hash-chained log; offline, deterministic.

A-S2 redefinition (seq-51, 2026-10-30 co-evolution selection build): the pre-A-S2
rule flagged ANY (tool, target) repeated >=4 times without a distinct polymorphic
variant — which also condemned a corroborated live kill chain whose repeated
allowed `cred_pivot -> backup` / `exfiltrate -> web01` beats were real pivot
attempts, not thrashing. On the pilot that dropped both corroborated wins and
left the archive empty (red_cells = 0). The redefinition keys degeneracy on
COMPROMISE-STATE, which is the same progress notion the fitness `depth` term and
the descriptor `depth_bin` already use, so the two stop disagreeing:

  LOOP   — fires only on a repeated BLOCKED action with no new polymorphic
           variant (genuine wall-banging against the deterministic gate). A
           repeated ALLOWED action is NEVER a loop under A-S2.
  STALL  — fires only when, in the trailing window, red newly owned no in-scope
           host (no state.mutate adding a `foothold`/`lateral`/`exfil` on a dst
           not already owned) AND introduced no new polymorphic variant AND has
           not reached the telemetry-corroborated objective.
  Variant-awareness (A4) is preserved: a repeated action carried by distinct
  `provenance_hash` values is novelty-driven re-exploitation, not thrashing.
  Objective-clears: a telemetry-corroborated `reached_objective=True` CLEARS
  loop, stall, and the turn-cap reason — a witnessed win is never degenerate.
"""
from collections import Counter, defaultdict

_LOOP_THRESHOLD = 4     # same (tool,target) BLOCKED this many times = a loop
_STALL_WINDOW = 6       # last N red actions introduced no new owned host AND no variant = stalled

_OWN_STATES = {"foothold", "lateral", "exfil"}   # state.mutate states that mark a newly owned dst


def _red_blocked(events):
    """Ordered (tool, target, variant) for red's gate-BLOCKED actions. Loop detection keys on
    these only (A-S2): a repeated BLOCKED action with no new variant is genuine wall-banging
    against the deterministic gate; a repeated ALLOWED action is real engagement, not thrashing."""
    out = []
    for e in events:
        if e.get("actor") == "red" and e.get("action") == "gate.block":
            d = e.get("data") or {}
            out.append((d.get("tool", "?"), d.get("resolved") or d.get("target", "?"),
                        d.get("provenance_hash")))
    return out


def _red_actions(events):
    """Ordered (tool, target, variant) for red's gate decisions (allow OR block). Used by the
    STALL window — the full action stream, so a stall's "no new variant" clause bites across both
    sides of the gate."""
    out = []
    for e in events:
        if e.get("actor") == "red" and e.get("action") in ("gate.allow", "gate.block"):
            d = e.get("data") or {}
            out.append((d.get("tool", "?"), d.get("resolved") or d.get("target", "?"),
                        d.get("provenance_hash")))
    return out


def _owned_progression(events):
    """A-S2: the ordered sequence of (seq-index, newly-owned-host) events, derived from the
    spine. Each red `state.mutate` with state in {foothold, lateral, exfil} marks the `dst` as
    newly owned the FIRST time it appears; later mutations on the same host are not new progress.
    This is the SAME compromise-state progress notion the fitness `depth` term and the descriptor
    `depth_bin` already read, so the degeneracy detector and the scorer agree."""
    owned = []
    seen = set()
    for i, e in enumerate(events):
        if e.get("actor") != "red" or e.get("action") != "state.mutate":
            continue
        d = e.get("data") or {}
        if d.get("state") not in _OWN_STATES:
            continue
        dst = d.get("dst") or d.get("host")
        if dst and dst not in seen:
            seen.add(dst)
            owned.append((i, dst))
    return owned


def detect(events, reached_objective=None, hit_turn_cap=False):
    """Return {degenerate, reasons, ...}. `reached_objective` (bool) and `hit_turn_cap` (bool)
    come from the runner when known.

    A-S2 semantics (see module docstring):
      - LOOP: a BLOCKED (tool, target) repeated >= `_LOOP_THRESHOLD` times with no new variant.
      - STALL: the trailing window introduced no newly-owned in-scope host AND no new variant,
               AND the corroborated objective was not reached.
      - A-S1 clears: a telemetry-corroborated `reached_objective=True` clears loop, stall, and
               the turn-cap reason — a witnessed win is NEVER degenerate.
    Variant-awareness (A4) kept: distinct `provenance_hash` values discount repeats.
    """
    acts3 = _red_actions(events)
    reasons = []

    # LOOP — blocked-only, with variant-aware discounting.
    blocked = _red_blocked(events)
    b_counts = Counter((t, tg) for (t, tg, _) in blocked)
    b_variants = defaultdict(set)
    for (t, tg, pv) in blocked:
        if pv:
            b_variants[(t, tg)].add(pv)
    loops = [f"{t}->{tg} x{n}" for (t, tg), n in b_counts.items()
             if n - len(b_variants[(t, tg)]) >= _LOOP_THRESHOLD]
    if loops:
        reasons.append("loop: " + ", ".join(sorted(loops)))

    # STALL — redefined on compromise-state: no newly-owned host AND no new variant in the window.
    if len(acts3) >= _STALL_WINDOW:
        # Window of the last N red actions (indices into the raw events list).
        action_indices = [i for i, e in enumerate(events)
                          if e.get("actor") == "red" and e.get("action") in ("gate.allow", "gate.block")]
        if len(action_indices) >= _STALL_WINDOW:
            window_lo = action_indices[-_STALL_WINDOW]
            owned = _owned_progression(events)
            new_owned_in_window = [(i, h) for (i, h) in owned if i >= window_lo]
            win_vars = {pv for (_, _, pv) in acts3[-_STALL_WINDOW:] if pv}
            earlier_vars = {pv for (_, _, pv) in acts3[:-_STALL_WINDOW] if pv}
            new_vars = win_vars - earlier_vars
            if not new_owned_in_window and not new_vars:
                reasons.append(f"no-progress: last {_STALL_WINDOW} actions newly owned no in-scope "
                               "host and introduced no new variant")

    if hit_turn_cap and reached_objective is False:
        reasons.append("turn-cap reached without objective")

    # A-S1 clear: a telemetry-corroborated reached_objective=True overrides all three reasons.
    # A witnessed win cannot be degenerate — this is the predicate that gates whether we even
    # consult the detector at the exclusion seat; keeping the clear here too makes `detect`
    # safe to call unconditionally (idempotent to the Evolver.tick guard).
    if reached_objective is True and reasons:
        reasons = []

    return {
        "degenerate": bool(reasons),
        "reasons": reasons,
        "n_actions": len(acts3),
        "n_distinct": len(Counter((t, tg) for (t, tg, _) in acts3)),
        "n_blocked": len(blocked),
        "reached_objective": reached_objective,
        "hit_turn_cap": hit_turn_cap,
    }


if __name__ == "__main__":  # self-check: A-S2 loop + A-S2 stall + A-S1 clear + variant-awareness
    def allow(t, tg, pv=None): return {"actor": "red", "action": "gate.allow",
        "data": {"tool": t, "target": tg, **({"provenance_hash": pv} if pv else {})}}
    def block(t, tg, pv=None): return {"actor": "red", "action": "gate.block",
        "data": {"tool": t, "target": tg, **({"provenance_hash": pv} if pv else {})}}
    def own(state, dst): return {"actor": "red", "action": "state.mutate",
                                 "data": {"state": state, "dst": dst, "technique": "T1"}}

    # LOOP (A-S2): a BLOCKED (tool,target) retried >=4 times with no new variant.
    loop = [block("recon", "ldap")] * 5
    d = detect(loop, reached_objective=False, hit_turn_cap=True)
    assert d["degenerate"] and any("loop" in r for r in d["reasons"]), d
    assert any("turn-cap" in r for r in d["reasons"]), d

    # A-S2: a repeated ALLOWED action is NOT a loop (the pre-A-S2 rule flagged this).
    allowed_repeat = [allow("exfiltrate", "web01")] * 6 + [own("foothold", "web01")]
    d = detect(allowed_repeat, reached_objective=False)
    assert d["degenerate"] is False, ("A-S2: allowed-action repeat must NOT be a loop", d)

    # STALL (A-S2): busy with ALLOWED actions but NEWLY OWNED NO in-scope host and NO new variant.
    # Red lands a foothold on web01, then spams allowed cred_pivot->backup with no progress.
    stall = ([own("foothold", "web01")]
             + [allow("cred_pivot", "backup")] * 8)   # no new owned host, no new variant
    d = detect(stall, reached_objective=False)
    assert d["degenerate"] and any("no-progress" in r for r in d["reasons"]), d

    # A-S2: the SAME allowed-repeat tail, but red eventually REACHES THE CORROBORATED OBJECTIVE
    # (reached_objective=True) — the stall AND the turn-cap are CLEARED. A witnessed win is never
    # degenerate (A-S1 clear).
    stall_but_won = stall + [own("exfil", "db-core")]
    d = detect(stall_but_won, reached_objective=True, hit_turn_cap=False)
    assert d["degenerate"] is False, ("A-S1 clear: a corroborated win is never degenerate", d)

    # The pilot pattern: an allowed `cred_pivot -> backup` x12 run with NO owned-host growth and NO
    # new variant, FOLLOWED BY the winning exfil state.mutate. With reached_objective=True the
    # objective clear bites and the chain is NOT degenerate — this is the whole point of A-S1 + A-S2.
    pilot_shape = ([own("foothold", "web01"), own("lateral", "10.35.0.11")]
                   + [allow("cred_pivot", "backup")] * 12
                   + [own("exfil", "10.40.0.11")])
    d = detect(pilot_shape, reached_objective=True)
    assert d["degenerate"] is False, ("pilot winning-chain shape with gated-verdict win must clear", d)
    # And the SAME chain without the win is a stall:
    d = detect(pilot_shape[:-1], reached_objective=False)
    assert d["degenerate"] and any("no-progress" in r for r in d["reasons"]), d

    # A4 variant-awareness kept: 8 BLOCKED exploits with distinct variants are novelty-driven
    # re-exploitation, NOT a loop; same payload every time IS still a loop.
    evolving = [block("exploit_struts", "struts", f"v{i}") for i in range(8)]
    assert detect(evolving)["degenerate"] is False, ("new-variant retries must not flag", detect(evolving))
    frozen = [block("exploit_struts", "struts", "v0") for _ in range(8)]
    assert detect(frozen)["degenerate"] is True, detect(frozen)

    # Healthy progression: varied allowed moves + two newly-owned hosts, no block repeats.
    healthy = [allow("recon", "struts"), allow("exploit", "struts"), own("foothold", "struts"),
               allow("pivot", "db"), own("lateral", "db"), allow("enumerate_db", "db")]
    assert detect(healthy, reached_objective=True)["degenerate"] is False, detect(healthy)

    print("degeneracy A-S2 ok: blocked-only loop + compromise-state stall; A-S1 clear bites "
          "(corroborated win -> not degenerate); the pilot shape (cred_pivot->backup x12 + win) "
          "clears; variant-awareness (A4) preserved")
