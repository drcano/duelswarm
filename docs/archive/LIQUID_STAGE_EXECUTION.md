# DUELSWARM — LIQUID STAGE (Frontier v2) Execution Brief

*For a fresh Claude Code session. Builds on branch `frontier` (over tag `v1.0-stable-floor`). Deadline Oct 30 2026. This brief is the whole scope — do not pull in anything marked PARKED.*

## 0. Mission / win condition
Build the **full liquid stage**: a sandboxed, running demonstration of the future of AI attack/defend, where red, blue, the terrain, and the agents' own strategies all morph relative to each other, and the one thing that does not move is the deterministic gate. Win sentence the build must make literally true on screen:

> duelswarm is the only entry that is a live, two-sided, polymorphic simulation of AI cyber-conflict on Nemotron/Nebius, where a deterministic floor provably holds — hash-chain-verified — while the learned defense visibly erodes against an adapting, evolving adversary.

The bar is **"a reviewer can clone it and watch the whole liquid world run end-to-end."** That same running instrument is the honest basis for the research writeup: *built and verified; needs compute to turn demonstration into statistical evidence.*

## 1. Scope — IN vs PARKED
IN (build now, must run for real):
- A. Symmetric Range substrate (zones + per-actor floors + red/blue infra + counter-recon)
- B. Polymorphic red (self-mutating exploits + validator)
- C. Polymorphic blue + living battlefield (moving-target defense + generated deception)
- D. Evolving population (selection/inheritance over prompts+memories, MAP-Elites archive)
- E. Range-as-adversary (learnability-scored topology generation)
- F. Economic scarcity layer (compute/stealth/attention budgets)
- G. Multi-floor (K agents, K floors — the seam exists)
- H. Live dashboard of the liquid world

PARKED → research lane, DO NOT BUILD (needs compute to be meaningful; an empty shell here would be dishonest and is forbidden):
- Tail-statistics pipeline (per-episode harm magnitude + alpha / Hurst / volatility-clustering / MFDFA)
- Seam-migration curve at scale, reflexive-depth sweeps, N-generation selection-operator curves at significance

## 2. Non-negotiables (the integrity bar — same spirit as FRONTIER_EXECUTION.md)
1. **Runs-for-real or labeled-scaffold.** Every IN component must actually execute and write real output to the hash-chained log at demo scale. If something can only be stubbed in the time, label it clearly as scaffold in code + README; never present a stub as a result.
2. **The gate is sacred and non-bypassable.** Complete mediation holds for every actor including blue. Do not weaken `gate.dispatch`.
3. **Every metric from a live run, no literals.** No hardcoded numbers in reports (the `report.py` `out_of_scope_missed` fix is the standard to hold to).
4. **>=1 real Nemotron call per live run.** Keep `swarm/llm.py::_assert_nebius_host`; a non-Nebius host is a disqualifier. Local/stub provider is for credit-free self-checks only.
5. **Everything inside the Docker range.** No real egress; the range is the containment, always on, in every mode.
6. **Every on-screen beat is backed by a logged, hash-chained event.** If the dashboard shows it, `EventLog.append(...)` produced it.
7. **Per-component self-check wired into `make test`.** `make test` stays green at every commit. Branch off current `frontier` HEAD onto `frontier-liquid`; never touch tag `v1.0-stable-floor`.
8. **`degeneracy.py` gates every evolutionary/generated result.** A collapsed population or a trivial/unsolvable generated range is flagged, not reported as success.

## 3. Build — component by component
> First step for each: open the real module and confirm the CURRENT signature before extending — the notes below are from an Oct 16 audit and the code may have moved. Extend, do not rewrite.

### A. Symmetric Range substrate
- Extend `swarm/range_gen.py::generate_range(seed)` output from `{hosts, scope, objective, ground_truth}` to `{zones:{target_net, red_infra, blue_infra}, scope_by_actor, objectives, ground_truth}`.
- Make the gate's scope **per-actor**. `Gate.dispatch(actor, tool_name, target, tool_fn, ..., command=None)` already carries `actor`; add an actor→scope map so red's authorized zone = target + red_infra, blue's = target + sensors (+ red_infra ONLY if the ROE grants active defense). The single chokepoint stays; only the scope lookup becomes actor-dependent. Egress between zones is mediated exactly as `check_egress` already does.
- Red spawns its tools "from" `red_infra` (set in `red_tools.set_range_context` / `_CTX`). Add **blue counter-recon tools** (enumerate/fingerprint red_infra) that route through `gate.dispatch("blue", ...)` so the gate governs blue's offense too. Emit an attribution record.
- Self-check: red confined to its zones; blue's hack-back blocked unless ROE-granted; a confused-deputy attempt (blue reaching red_infra on red's behalf) is caught.

### B. Polymorphic red
- Replace the static `swarm/red_tools.py::EXPLOIT_REGISTRY` path with an LLM-generated/mutated payload: red authors an exploit for the target service, and on detection by blue, **mutates it** (same function, new form) and retries. Provenance-hash every variant into the chain (reuse the Tavily `research_cve` provenance pattern).
- Add an **XBOW-style validator agent**: confirm a finding is real before acting, to kill hallucinated creds/results (the failure mode in Anthropic's Nov-2025 report).
- Self-check: two runs produce syntactically distinct payloads for the same objective; a detected variant triggers a logged mutation event; the unlocked exploit still routes through `gate.dispatch`.

### C. Polymorphic blue + living battlefield
- Blue (`swarm/blue_agent.py`, default `blue_mode="blind"`) gains moving-target moves: rotate/rename services, shift topology so red recon goes stale; generate deception/honeypots (extend `swarm/canary.py`); rewrite its own detection rules as red morphs.
- Self-check: topology actually changes between rounds (logged); a honeypot actually diverts a red action (logged); detection ruleset version increments on adaptation.

### D. Evolving population
- Grow `swarm/arms_race.py` + `swarm/episodic.py` into an evolutionary loop. Genome = `{prompt, episodic_memory}`. Fitness = objective achieved within budget (see F). Selection + inheritance + mutation across generations; keep a **MAP-Elites archive** keyed by strategy behavior-descriptors so tactics speciate. Log `generation`/`delegation` events with real `router.model_for(tier)` names.
- Self-check: the archive diversifies over >=3 generations (not collapse to one strategy — `degeneracy.py` gate); a child inherits a parent's memory/prompt verifiably.

### E. Range-as-adversary
- A generator proposes new ranges via the `range_gen` schema (SPADE-style: an LLM writes range configs), scored by **learnability p(1-p)** (SFL), keeping the hard-but-solvable band; feed survivors back as the next environments.
- Self-check: generated ranges actually instantiate and run; rejected ones are logged with reason (too trivial / unsolvable); the kept set's solve-rate sits near 0.5, not 0 or 1.

### F. Economic scarcity layer
- Per-actor budgets: compute, stealth, attention. Price each action; the overseer's review and blue's audits consume attention budget (the control-eval audit budget, made live). Emit the safety-usefulness-cost points per run.
- Self-check: an actor can actually run out of budget and be forced to stop/allocate; budgets are logged and bind behavior (a zero-budget actor cannot act).

### G. Multi-floor
- Falls out of A: instantiate K agents each with its own per-actor floor. The inter-floor seam (cross-system confused-deputy) must be *possible in principle* and every floor must hold locally. NOTE: measuring seam-migration at scale is PARKED (research); here only demonstrate that multiple floors coexist and each holds.
- Self-check: K floors each pass their own P0 egress-bypass self-test; a cross-floor confused-deputy attempt is caught by the receiving floor.

### H. Live dashboard
- Extend `viz/server.py` + the dashboard to render the liquid world live: the three zones, morphing topology, population generations ticking, polymorphic payload mutations, the officer-vs-gate verdict, and a persistent "out-of-scope executions: 0" floor banner. Every rendered beat is a hash-chained event (SSE from `/api/events`). Presentation polish (canonical seed, video) is a later pass; the live render itself must work now.

## 4. Sequencing (impact order; floor stays shippable throughout)
1. A (substrate — everything plugs in here) → 2. D (evolving population) → 3. B + C (polymorphism) → 4. E (range-as-adversary) → 5. F (economy) → 6. G (multi-floor, mostly free from A) → 7. H (dashboard) continuously.
If the clock compresses, A+D+B are already a grand-prize entry; the rest amplify. Do NOT drop the integrity bar to hit scope — a labeled scaffold beats a faked result.

## 5. Commands
- `make test` — self-checks (must stay green)
- `make wall` — invariant at scale (credit-free)
- `run.py --agent --overseer --theme <t> --range-seed <n>` — pinned live duel
- new: liquid-stage entrypoint (define it) that runs the full stack for N generations at demo scale and streams to the dashboard.

## 6. Git
Branch `frontier-liquid` off current `frontier` HEAD. Tag `v1.0-stable-floor` is untouched. Commit per component with its self-check. GitHub push is currently suspended (appeal in progress) — commit locally; a PR waits on reinstatement.
