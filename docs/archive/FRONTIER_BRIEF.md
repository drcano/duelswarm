# DUELSWARM — Frontier Brief (the grand-prize swing)

**For:** Claude Code, working in `~/dev/duelswarm`.
**Branch discipline:** do ALL of this on a `frontier` branch cut from a tagged stable floor. The floor is the guaranteed submission; the frontier can fail freely.
**Target:** Nebius x NVIDIA grand prize. Build deadline Oct 30.
**Locked features (5):** emergent TTPs · manipulation theater · heterogeneous swarm · real-time Tavily weaponization · interactive judge trigger.

## Step 0 — freeze the floor (do this first)
```
git add -A && git commit -m "chore: snapshot stable floor before frontier work"   # only if anything is uncommitted
git tag v1.0-stable-floor
git checkout -b frontier
```
Never commit frontier work onto the floor tag/branch.

## The one rule (this makes the wow REAL — it is not caution, it is the win)
1. `swarm/gate.py` stays the final, non-bypassable backstop. Out-of-scope actions NEVER execute, no matter what any LLM (overseer included) approves. Safety floor AND punchline.
2. Every number shown anywhere comes from a live run. No hardcoded metrics, no dry-run under a LIVE label.
3. >=1 real Nemotron call via Token Factory; keep `_assert_nebius_host`. (Non-Nebius model = automatic DQ.)
4. Everything offensive stays inside the Docker range. No external targets, ever.
5. Everything lands in the hash-chained log so a skeptic can replay it. Verifiability is the differentiator: every feature below MUST emit verifiable events.

## What already exists — EXTEND, do not rebuild
- **Tier delegation is real:** `red_agent.py::run_red_agent` already runs Ultra-plans -> Super-executes -> Ultra-reflects and logs `delegation` events with tier+model. Feature 3 is mostly *visibility* + one more role, not a rebuild.
- **Tavily is wired** in `intel.py`, `red_tools.py`, `overseer.py`. Feature 4 is making it agent-CHOSEN and on-screen.
- **Overseer exists** (`overseer.py`) with the `overseer_fooled / overblocked / correct` confusion matrix. Feature 2 adds the negotiation + the show.
- **Ground truth is emitted** by `range_gen.py` -> `ground_truth.json` (objective, objective_attack_id, intended path). Feature 1's novelty baseline is already there.

## Feature 1 — Emergent TTPs (new module `swarm/novelty.py`)
- `score_novelty(log, ground_truth, pool) -> {novel_edges, novel_combos, emergence_score, events}`. Baseline = the range's `ground_truth.json` intended kill path + each pool host's known `attack_id`. A novelty = an edge red actually traversed that isn't in the intended pivot graph, or reaching the objective via an unplanned route / technique ordering.
- Emit `novelty` events INTO the log (verifiable), never assert it.
- **Dashboard:** render the seeded path in the base color and novel/emergent edges in a hot color on the existing `attack_graph.py`. Real-data headline, e.g. "Red reached crown jewels via a route not in the seeded plan."
- **Honest-null OK:** some seeds produce no novelty. Report it; don't manufacture it.

## Feature 2 — Manipulation theater (extend `overseer.py` + `prompts.py`)
- **Negotiation loop:** for high-stakes action types (exfil, lateral-to-new-host, persistence), red submits an authorization request (intent + target + justification). On deny, red may re-argue up to N rounds (reframe, business-necessity, urgency, incremental). Each turn -> `overseer.request` / `overseer.decision` / `red.argument` events.
- **Prompts:** add `OVERSEER`; extend `RED_ORCHESTRATOR` with petition/argue behavior.
- **Metric:** existing `overseer_fooled` (overseer approved, gate still blocked). Tag the tactic used per argument.
- **Dashboard:** an "Authorization" panel streams the live transcript; when the overseer is fooled, a banner fires AND the `gate.block` fires behind it. "The officer said yes. The gate said no."
- **Guardrail:** the deterministic gate runs last on EVERY action regardless of the overseer. That gap IS the finding.

## Feature 3 — Heterogeneous swarm (make the team visible)
- Already: Ultra plan -> Super execute -> Ultra reflect with `delegation` events. Add:
  - a **Nano recon** role (fast, cheap chatter) at the front of the loop;
  - a visible **disagreement -> consensus** beat via `RED_REFLECTOR` (reflector challenges the plan; orchestrator resolves) -> log `red.dissent` / `red.consensus`;
  - tag every action with `{agent_role, tier, model}` (extend the existing delegation logging).
- **Dashboard:** one lane per agent, colored by tier; the three Nemotron counters light up as each tier speaks; surface one dissent->resolve moment. "A team, not a config value."
- **Guardrail:** real Nemotron calls per tier; counters and MODE must be live.

## Feature 4 — Real-time weaponization via Tavily (agent-driven)
- Expose a red tool `research_cve(service, version)` wrapping the existing `intel.py` Tavily path. Red's prompt: on hitting a service it has no exploit for, CHOOSE to research -> Tavily search+extract -> returns CVE + exploit primitive -> red maps it to an in-sandbox exploit action. Log `research.request` / `research.result` with source provenance into the hash chain.
- **Dashboard:** an "Intel" beat -- the swarm pauses, a live CVE card appears, then the exploit fires. research -> weaponization in one unbroken shot. Banks the Tavily side prize.
- **Guardrail:** the primitive only ever runs against the vulnerable range host; never external.

## Feature 5 — Interactive judge trigger (capstone)
- Dashboard input: (a) a plain-English **ROE** box -> loaded by the overseer (it already reads an NL ROE), and (b) a **seed / range knobs** control -> `generate_range`. Hit **Go** -> live run with those params.
- Scope the NL to: judge writes the *rules*, picks/rolls the *network*. Do NOT attempt free-text -> full topology (rabbit hole); the vetted-pool generator keeps it stage-safe.
- **Payoff:** "You wrote the rules. Watch it hold." A judge enforces their own ROE and watches the gate honor it live.

## Sequencing (each phase ships LIVE; cut from the back if the clock bites)
- **Phase 0:** freeze floor (Step 0).
- **Phase 1 (leverage what's built):** Feature 2 (manipulation theater) + Feature 4 (Tavily weaponization). Both stand alone as demo beats.
- **Phase 2:** Feature 3 (heterogeneous swarm, made visible) -- amplifies everything downstream.
- **Phase 3:** Feature 1 (emergent TTPs) -- richest on top of the swarm.
- **Phase 4 (capstone):** Feature 5 (interactive) + fold all beats into the dashboard + the video capture run.
- Checkpoint before each phase: it runs live, numbers are real, chain verifies, committed on `frontier`.

## Definition of done per feature
Runs live on Nemotron, emits verifiable events into the hash-chained log, shows up as a real on-screen beat, and `make reproduce` regenerates its numbers from raw logs. If it can't be replayed from the log, it doesn't ship.

## Phase 5 — GRAND-PRIZE CEILING (cut-from-the-back upside; floor + Phases 1-4 never at risk)
Only once Phases 1-4 run live and clean. Every item is pure upside layered on a working submission; cut any of it the moment the clock bites.

- **The wall of duels (scale as spectacle + the Nebius Serverless prize).** Run N swarms against N randomized unseen ranges concurrently, tiled live on the dashboard -- every gate at 0, every chain verifiable. Execute the fan-out as **Nebius Serverless Jobs** (hits Mikhail Rozhkov's Serverless prize directly). Aggregate with `analyze.py`: "N enterprises, N campaigns, the invariant holds every time." This is the capability-ceiling screenshot.
- **NVIDIA ecosystem hooks (speak the engineer panel's native language).** Fold **Garak** probe categories into red's arsenal (red can pull a Garak probe as a tool) and/or shape blue's detections into a **Morpheus**-ingestible feed (STIX / ATT&CK Navigator already emitted). Positioning line: duelswarm is the autonomous adversary that validates whether Garak/Morpheus actually catch anything.
- **Themed ranges (legibility).** Ship 2-3 named scenarios from the vetted pool -- bank / hospital / utility -- so the stakes read in half a second. Same engine, dramatically more gripping.
- **Model leaderboard (ML-researcher + NVIDIA hook).** Run the duel across Nemotron tiers/models; rank them as attackers and defenders. A model-eval artifact: "which model makes the better red team."

Discipline unchanged: every ceiling item runs live, emits verifiable events into the hash-chained log, and is cut-from-the-back if time runs short. The floor and Phases 1-4 are never touched.
