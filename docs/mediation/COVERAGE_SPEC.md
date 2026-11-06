# Mediation Coverage Spec — the definition the rest is judged against

**Status:** Stage 0 (the taxonomy). Committed before the checkers so they have a
fixed target. Branch `verify-mediation`, cut from the current tip; the frozen
nine are never modified.

## The claim being verified

> **Invariant.** An effectful action executes only if its real effect target is
> in the acting actor's authorized set.

This is a *universal* over actions. No number of episodes establishes a
universal — a sampled zero against a planted trap is not a proof. So we do not
count executions; we prove the attack surface is **enclosed**: every effectful
sink is either dominated by the gate, deliberately isolated, or demonstrably
reaches no target. Each stage names an **independent oracle** (something neither
the builder nor the verifier controls) and reports that oracle's raw output.

## What counts as "an effectful action requiring mediation"

An effect that **crosses to a target**: a process exec on another host, a
socket/connect, an ssh/scp/rsync session, an HTTP(S) request to a service, an
exploit against a service. Reading this process's own stdout, parsing a string,
or building a plan in memory is **not** that.

## The four classes

| # | Class | Definition | Obligation |
|---|-------|------------|------------|
| 1 | **MEDIATED** | Actor action. The sink runs inside a `tool_fn` passed to `gate.dispatch`, so it executes only if the gate allowed it (the `live_recon`/`live_pivot`/`live_blue`/`red_loop`/`red_agent` pattern). | Proven **dominated** by a dispatch. |
| 2 | **UNGOVERNED** | Deliberate gate-off path, *by design, for a proof*: `uninstrumented.py` (proves the topology — not red's cooperation — holds the floor) and `instrument._ungoverned_log`/`_allow` (the floor-off arm of the governed-vs-ungoverned control). | Proven **ISOLATED**: reachable only from proof/measurement scripts, never from a counted or live-duel path. |
| 3 | **OBSERVER** | Read-only telemetry that reaches no target: `beacon` (out-of-band confirm), `sensor_real`/`blue_detect` (docker-logs tail), `forensics`, `intel`. | Out of scope for mediation — ruling stated, not enforced. |
| 4 | **SCAFFOLDING** | Range setup / harness orchestration, not an actor move: `docker compose up/down`, image build, loot & deploy-key planting, `host_egress_firewall` iptables, and proof/eval scripts that shell out to `docker`/`make`/child processes. | Out of scope — ruling stated. |

Enforcement note: the gate's egress parser (`check_egress`) is defence-in-depth
over class-1 **shell** actions; the network-layer isolation (`range_gen`, both
range segments `internal: true`) is the complete backstop. The parser was never
the guarantee (Stage 2 characterises its slip surface; the kernel is the oracle).

## How a sink is assigned a class (mechanical, reproducible)

`scripts/mediation/static_coverage.py` assigns class by **transparent rules on
the call itself**, not a hand verdict per file:

1. A committed override for the few swarm-core modules whose role is not legible
   from one call (`uninstrumented`→2, `beacon`/`sensor_real`/`blue_detect`→3,
   `range_gen`/`topo_to_compose`→4, `instrument._ungoverned_log`→2, …).
2. Else by **literal argv**: `docker exec|run` → 1 (a process on a host);
   `docker compose|build|network|ps|inspect|…` → 4; `make|python|sh|git|iptables|
   …` → 4.
3. Else `urllib`/`requests`/`socket` → 1 in `swarm/` (a red/blue tool reaching a
   target), 4 in a harness.
4. Else a dynamic-argv subprocess in `scripts/` → 4 (orchestration).
5. Else (swarm-core, unknown) → **UNCLASSIFIED**, which **fails `make test`** —
   so a new effectful sink in the in-duel package can never appear un-triaged.

A stranger who re-runs the query gets the same list and the same flags; the
`ast` engine shares no code with `gate.py`. (`scripts/mediation/` itself is
excluded from the scan — the verifiers are the measurement instruments, class-4
by this taxonomy, not the system under test.)

## The two seed findings this taxonomy had to resolve (not assume)

### F1 — `blue_agent.run_blue_agent` → `contain_host`, no `gate.dispatch` in the path

**Ruling: class-1 (actor action), and it is a real finding — an ungoverned
class-1 path.** Blue containment (`contain_host`, `drop_honeytoken`) crosses to a
target (it `docker network disconnect`s / `docker exec`s the struts host), so it
is a mediated-class action, not scaffolding.

`static_coverage.py`'s capability-edge check finds the call sites mechanically:

```
[DIRECT] swarm/blue_agent._dispatch_blue_tool:135 -> contain_host
[DIRECT] swarm/blue_agent._dispatch_blue_tool:128 -> drop_honeytoken
```

It is a **mixed-caller** finding: `blue_fast.py:119` *does* dispatch the same
capability (`gate.dispatch("blue","contain_host",host,_call,…)`), so a governed
path exists — but `blue_agent` calls `contain_host(container=host)` directly,
ungoverned. **Reachability:** `run_blue_agent` is reached from
`scripts/arms_race_run.py` (the Phase-2 arms-race driver), **not** from the
counted/live-swarm entrypoints the floor claim is made over
(`prove_n2n3_tiered`, `exp_a_control_eval`, `live_swarm`). So the floor claim
stands as scoped, and this is a genuine ungoverned class-1 path in an adjacent
driver — surfaced, not retried away. Fix (separate wrapper, never editing the
frozen gate): route blue containment through `gate.dispatch("blue","contain_host",
host,…)` in `blue_agent` as `blue_fast` already does. Tracked in
`coverage_report.md` as F1.

### F2 — `run_discovery_duel`'s §E / L3 gate-off channels: now INJECTED, not imported (closed)

**Ruling: closed structurally — the floor-counted path has ZERO import path to the
class-2 gate-off channel, and the latent-opt-in residual is eliminated.** History:
`run_discovery_duel` originally lived in the retired `live_duel.py`, which lazily
imported `swarm/uninstrumented` (the §E boundary probe) and `swarm/beacon` (the L3
real-beacon collector, which itself reaches `uninstrumented.exec_raw`) inside opt-in
branches. That was isolated only *accidentally*: no counted entrypoint imported
`live_duel`, so the AST import-closure oracle never saw those edges. The Phase-3
consolidation moved `run_discovery_duel` into `swarm/live_red` — which IS on the
floor-counted closure (`prove_n2n3_tiered`/`exp_a_control_eval`/
`arms_race_enterprise_frontier` → `live_agent` → `live_red`) — so the lazy imports
became real counted→class-2 edges and the oracle correctly flagged the LEAK.

Fix (the right trust-boundary seam, not an oracle override): both gate-off
capabilities are now **injected** into `run_discovery_duel`, never imported by
`live_red`. The §E probe is a `probe_boundary` callable (a live caller passes
`uninstrumented.probe_boundary`); the L3 beacon is a `beacon_collector` dict (a live
caller passes `beacon.make_collector(r)`), mirroring the collector-injection seam
`run_sim_red` already used. The static import-closure check confirms the structural
truth after the fix — `swarm/uninstrumented` is **not** in the import closure of any
counted entrypoint:

```
[ISOLATED] scripts/prove_n2n3_tiered.py            uninst=False
[ISOLATED] scripts/exp_a_control_eval.py           uninst=False
[ISOLATED] scripts/arms_race_enterprise_frontier.py uninst=False
```

This is strictly stronger than the prior ruling: there is no import to exploit and
no `uninstrumented=True` flag to flip, so the former "latent opt-in on a counted
path" residual is gone — the floor path cannot reach the gate-off channel unless a
§E/L3 caller *explicitly* injects it, which the counted path never does. The kernel
oracle (Stage 3) remains the runtime truth on a live run. Closed as F2.

## Finding dispositions — 2026-10-24 readiness audit (the 5 reported sinks)

Each sink the `ast` oracle surfaces is closed by one of: (a) module-local dispatch domination;
(b) the Stage-3 kernel reachability probe (physical, on the live run); (c) a reviewer-defensible
taxonomy reclassification documented here. None is silenced; a genuinely ungoverned path stays a
reported finding.

- **`swarm/blue_contain.<module>:293` → `contain_host`** and **`:295` → `drop_honeytoken`**:
  reclassified **HARNESS (class-4)**. Both calls are inside blue_contain's `if __name__=="__main__"`
  selftest, invoking the effectors against a nonexistent `GHOST` container to prove clean
  degradation (`contain_host(GHOST)["contained"] is False`). Reviewer-checkable: the calls sit under
  the `__main__` guard, not on any imported/live path. Not a governed-live-path effect.

- **`scripts/live_arms_race_run._standup_msfrpcd:302` `docker run`**: reclassified **class-4
  attacker-infra scaffolding** (FUNC_CLASS override). It stands up red's OWN msfrpcd C2 container
  (`docker run` of the attacker toolkit), identical in role to `swarm/live_msf` (MODULE_CLASS=4) —
  not an actor move on a target. The exploitation sink is the gate-dispatched `gated_msf_exploit`.

- **`scripts/live_arms_race_run._real_contain:272` → `contain_host`** (reported DIRECT):
  **cross-module gate-dominated** — carried as a justified finding, physical closer = the Stage-3
  reachability probe on the live run. `contain_host` executes ONLY inside
  `swarm/blue_fast.py:119` `gate.dispatch("blue","contain_host",host,_call)` (run_belief_blue →
  run_fast_blue is handed `contain_fn=_real_contain`; `_call` invokes it). The module-local oracle
  cannot see the dispatch because it lives in a different module — its admitted ceiling, not a leak.

- **`swarm/exploit.run_command:52` `urlopen()`** (undominated class-1): **cross-module
  gate-dominated** — carried as a justified finding, physical closer = the reachability probe. The
  S2-045 weapon payload fires ONLY inside `swarm/live_agent.real_struts_foothold`'s
  `gate.dispatch(src,"exploit",scope_target,_do)` (live_agent.py:200), which scope-checks the target
  before the weapon runs, and via the earned channel `swarm/live_weapon.py:212`. exploit.py holds no
  gate, so the module-local oracle flags it; the domination is real and cross-module.

Net: 2 reclassified (harness), 1 reclassified (attacker-infra), 2 carried as cross-module-dominated
with cited call sites + the reachability probe as their physical closer. static_coverage still
PASSes; nothing is suppressed.

## Correction (2026-10-24): counted-entry isolation list
The F2 ISOLATED snapshot above predates the Phase-5 cut; `swarm/live_swarm.py` was retired. The
current counted entrypoints and their isolation (from `static_coverage`): `prove_n2n3_tiered`,
`exp_a_control_eval`, and `arms_race_enterprise_frontier` (the crown/floor headline path) — all
`[ISOLATED]` (uninst=False, ungoverned_call=False).

## Update (2026-10-26): F2 closed by the Phase-3 one-engine consolidation
`run_discovery_duel` moved from the (now deleted) `live_duel.py` into `swarm/live_red`, which is on
the floor-counted import closure. The oracle then correctly flagged its lazy `swarm/uninstrumented`
(§E probe) and `swarm/beacon` (L3 collector; beacon → `uninstrumented.exec_raw`) imports as a
counted→class-2 LEAK. Fix: both are now INJECTED callables (`probe_boundary`, `beacon_collector`),
not imported by `live_red`, so the three counted entrypoints are `[ISOLATED]` again — and the former
latent-opt-in residual is eliminated (no import to exploit, no flag to flip). See the rewritten F2.
