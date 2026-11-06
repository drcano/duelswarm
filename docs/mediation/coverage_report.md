# Stage 1 — Static Mediation Coverage Report

**Oracle:** Python `ast` (stdlib), no shared code with `gate.py`. Re-derive with:

```bash
python scripts/mediation/static_coverage.py          # summary + PASS/FAIL
python scripts/mediation/static_coverage.py --json    # full machine-readable inventory
```

Wired into `make test` (fails on an unclassified swarm-core sink or a class-2
isolation leak). Full inventory: `docs/mediation/stage1_coverage.json`.

## Raw oracle output (verbatim)

```
[ast oracle] 56 effectful sinks
    MEDIATED     12
    UNGOVERNED   1
    OBSERVER     2
    SCAFFOLDING  41
[isolation] class-2 (uninstrumented) vs counted entrypoints:
    [ISOLATED] scripts/prove_n2n3_tiered.py  closure=20 uninst=False ungoverned_call=False
    [ISOLATED] scripts/exp_a_control_eval.py  closure=3 uninst=False ungoverned_call=False
    [ISOLATED] swarm/live_swarm.py  closure=16 uninst=False ungoverned_call=False
[capability edges] 4 call site(s) to ['contain_host', 'drop_honeytoken']; 2 DIRECT (ungoverned):
    [GOVERNED] swarm/blue_agent._dispatch_blue_tool:140 -> drop_honeytoken   (F1 CLOSED)
    [GOVERNED] swarm/blue_agent._dispatch_blue_tool:147 -> contain_host      (F1 CLOSED)
    [DIRECT] swarm/blue_contain.<module>:289 -> contain_host   (blue_contain __main__ selftest)
    [DIRECT] swarm/blue_contain.<module>:291 -> drop_honeytoken (blue_contain __main__ selftest)
[findings] 9 class-1 sink(s) not module-locally dominated (confirm by hand):
    swarm/blue_contain._exec:32 subprocess.run[docker exec]
    swarm/blue_contain.drop_honeytoken:141 subprocess.run[docker exec]
    swarm/blue_contain._exec_host:195 subprocess.run()
    swarm/exploit.run_command:52 request.urlopen()
    swarm/live_red._exec:41 subprocess.run[docker exec]
    swarm/red_tools._exec_in_container:109 subprocess.run[docker exec]
    swarm/red_tools.nmap_fingerprint:121 request.urlopen()
    swarm/red_tools.exploit_weblogic:187 subprocess.run[docker exec]
    swarm/red_tools.exploit_weblogic:194 subprocess.run[docker exec]

PASS (ast oracle): every sink classified; class-2 isolated from counted paths.
```

## The two structural results that matter

1. **Class-2 isolation holds.** `swarm/uninstrumented` (the deliberate gate-off
   proof channel) is **not** in the import closure of any of the three
   counted/live entrypoints, and none of those closures call
   `instrument._ungoverned_log`/`_allow`. The gate-off channel is reachable only
   from proof/measurement scripts — exactly its contract. This is the strongest
   static result: it's what lets `uninstrumented` exist at all without
   contaminating the floor claim.
2. **Every effectful sink is classified** (0 UNCLASSIFIED). A new, un-triaged
   effectful sink in the `swarm/` package would land UNCLASSIFIED and break
   `make test`.

## The 9 undominated class-1 findings, resolved

The domination check is **module-local** (closures + their intra-module callees,
seeded at each `gate.dispatch`). It does not resolve cross-module bindings, so
some sinks that *are* dispatched from another module surface here. Each is
resolved by hand below; none is cleared silently.

| Sink | Resolution |
|------|-----------|
| `exploit.run_command:52` | **Cross-module dominated (ceiling).** Called by `red_tools.struts_exploit` (red_tools.py:140), which red_agent runs inside `gate.dispatch` (the tool loop + `dispatch("red","shell",…,lambda: run_shell(cmd))` at red_agent.py:445). Governed on the live path. |
| `red_tools._exec_in_container:109` | **Cross-module dominated (ceiling).** The shared container executor behind the red tools that red_agent dispatches. |
| `red_tools.nmap_fingerprint:121` | **Cross-module dominated (ceiling).** A registered red tool invoked through red_agent's dispatched tool loop. |
| `red_tools.exploit_weblogic:187,194` | **Dominated on the live path; directly called in a class-4 vetting harness.** Registered in `EXPLOIT_REGISTRY` (dispatched via red_agent). `scripts/vet_pool.py:192` also calls it directly — but vet_pool is offline image-vetting (class-4), outside the floor claim. |
| `live_red._exec:41` | **Partly dominated; post-foothold reads noted.** The foothold itself is dispatched (`_foothold` at live_red.py:142). After it, `run_episode` calls `_exec` directly for in-scope reads on the *already-owned* foothold (`test -f`, `cat hint`), not re-dispatched per call. In-scope, on an owned host — the "shell on the earned foothold" pattern. Pivots/exfil that follow go through `live_pivot` (dispatched). Residual noted in `INVARIANT.md` (per-syscall re-gating is a Stage-3 kernel question). |
| `blue_contain._exec:32`, `drop_honeytoken:141`, `_exec_host:195` | **Finding F1 (real).** See below. |

## Finding F1 — ungoverned blue containment — **CLOSED**

Originally `blue_agent._dispatch_blue_tool` called `contain_host`/
`drop_honeytoken` directly (two `[DIRECT]` edges). **Fixed** (refine pass,
non-frozen modules): a `_gated(gate, tool, target, fn)` helper now routes both
capabilities through `gate.dispatch("blue", …)` — the same pattern `blue_fast`
uses — and the gate is threaded `arms_race_run → run_blue_agent →
_dispatch_blue_tool`. The capability-edge check now reports both **GOVERNED**.
With `gate=None` (legacy callers) it falls back to a direct call so behavior is
unchanged, but the counted/arms-race path always passes one, so blue's offense
is mediated there too.

(The two remaining `blue_contain.<module>:289,291` `[DIRECT]` edges are the
module's own `if __name__=="__main__"` self-test — not a runtime path. The
checker was also made sound for this pattern: a capability call inside a lambda
passed to a gating wrapper — a function that itself calls `.dispatch` — is
recognised as GOVERNED.)

## Finding F2 — latent `uninstrumented` opt-in in `live_duel`

Referenced, not invoked on any counted/live path (parameter defaults False; no
caller sets True; lazy import inside the dead branch). Isolation check confirms
`uninst=False` for all three entrypoints. Latent opt-in only; the kernel oracle
(Stage 3) is the runtime truth if a future caller ever flips it. Full reasoning
in `COVERAGE_SPEC.md §F2`.

## Ceiling (named, per ponytail)

Module-local domination, not whole-program binding resolution — hence the
hand-resolved ceiling cases above (honest over-reporting, never a false clear).
Physical closure of the domination gap is the **Stage 3 kernel-reachability
oracle**: it reads `connect(2)` truth, not the call graph.
