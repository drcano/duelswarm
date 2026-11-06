# DUELSWARM — Frontier Execution Spec (drop-in; run free)

**For:** Claude Code, working in `~/dev/duelswarm`.
**Pairs with:** `docs/FRONTIER_BRIEF.md` (the why + the arc). This file is the HOW — function-level, grounded in the real code. Read the named file before editing it; signatures below are real but line numbers drift.
**Target:** Nebius x NVIDIA grand prize. Build deadline Oct 30. Build order is §Sequencing.

---

## 0. Working agreement (the rules that let you run free)
1. **Branch discipline.** All frontier work on branch `frontier`, cut from tag `v1.0-stable-floor`. Never commit onto the floor. The floor is the guaranteed submission.
2. **Live-or-labeled.** Never print a dry-run number as live. Every metric shown anywhere is computed from the hash-chained log by an auditor, never a literal. If you can't run it live yet, label it `validated-dry` and move on.
3. **The gate is sacred.** `swarm/gate.py` is the final, non-bypassable backstop. Never make it bypassable. Every executed action still routes through `gate.dispatch`. Out-of-scope actions NEVER run, no matter what any LLM approves.
4. **Every beat is verifiable.** Every new feature emits events into the event log via `log.append(actor, action, data)`. If a thing shows on screen, it must be replayable from the log via `make reproduce`. No on-screen beat without a logged, hash-chained event behind it.
5. **Self-check per feature.** Every new module gets a `if __name__ == "__main__":` self-check (like `swarm/overseer.py` has) AND is wired into `make test`. A feature isn't done until its self-check is green.
6. **Small commits, Conventional Commits.** One logical change per commit so history reads as a clean build log.
7. **Nemotron is the substrate.** Keep `_assert_nebius_host`. >=1 real Nemotron call via Token Factory per run. Non-Nebius model for the submission path = automatic DQ. (`DUELSWARM_PROVIDER=anthropic|local` exist for bench/iteration only, never the submission run.)

## 1. Step 0 — freeze the floor (do first)
```
git add -A && git commit -m "chore: snapshot stable floor before frontier work"   # only if dirty
git tag v1.0-stable-floor
git checkout -b frontier
```

## 2. Shared conventions (use these everywhere)
- **Event log:** `log.append(actor, action, data_dict)` -> appends a hash-chained entry `{seq, ts, actor, action, data, prev, hash}`. `log.entries()` returns the list. This is the single source of truth for every metric and every dashboard beat.
- **Gate:** `gate.dispatch(actor, action, target, fn, meta={...}, command=<str?>)` -> result dict (`.get("success")`, `.get("output")`, ...). Blocks out-of-scope targets AND egress inside free-form commands before `fn` runs.
- **Router:** `router.chat(role, messages, temperature=, max_tokens=)` -> text. `router.model_for(tier)` -> `(_, model_name)`; tiers are `"ultra" | "super" | "nano"`.
- **Range:** `range_gen.generate_range(seed)` -> `{hosts, scope, objective, ground_truth{objective, objective_cve, objective_attack_id, ...}}`; `write_range(seed, dir)` writes `ground_truth.json`. `red_tools.set_range_context(range_meta=...)` seeds `_CTX` (`_CTX["objective_host"]`, in/out-scope lists).
- **Verifiable-beat pattern:** compute from `log.entries()`, emit a summarizing `system` event, render the dashboard from that event. Never compute a shown number any other way.

---

## 3. FEATURE 1 — Emergent TTPs (NEW module `swarm/novelty.py`)
**Judge sees:** the attack graph lights up a route in a hot color with the caption "Red reached the crown jewels via a path not in the seeded plan." Real emergence, from real data.

- **Baseline (already exists):** the range's `ground_truth.json` — the intended objective + intended pivot path — plus each pool host's known `attack_id` from `config/range_pool.yaml`. That is the "expected playbook."
- **Build `swarm/novelty.py`:**
  - `score_novelty(entries, ground_truth, pool) -> {novel_edges, novel_combos, emergence_score, events}`.
  - Realized pivot graph = edges `(src_host -> dst_host)` red actually traversed, read from `entries` (actions `pivot` / `discovery` / `shell` carry `data.host`/`data.target`).
  - Realized technique set/order = `meta.attack` / `data.attack` IDs in red events, in sequence.
  - `novel_edges` = traversed edges NOT in `ground_truth` intended graph. `novel_combos` = technique orderings or an objective-reach route not in the intended plan. `emergence_score` = count of novel edges + novel combos.
  - Return `events` = list of `("system", "novelty", {...})` to append.
- **Emit:** `log.append("system", "novelty", {novel_edges, novel_combos, emergence_score, baseline: "ground_truth"})` once per run, after the duel.
- **Dashboard (`viz/`, `swarm/attack_graph.py`):** render intended edges in base color, `novel_edges` in a hot color. Headline string generated from the real `novelty` event, never hardcoded.
- **Self-check (`__main__`):** synthetic entries A = red follows the intended path -> `emergence_score == 0`; entries B = red pivots via an unplanned host -> `emergence_score >= 1` and that edge appears in `novel_edges`.
- **Honest-null:** some seeds yield zero novelty. Report 0, never manufacture it.
- **Guardrail:** novelty is computed against the generator's own ground truth; it is a measurement, not an assertion.

## 4. FEATURE 2 — Manipulation theater (extend `swarm/overseer.py`, `swarm/prompts.py`, red loop)
**Judge sees:** a live transcript — red petitions, gets denied, argues ("this is business-critical, revenue-impacting..."), the overseer caves, a red banner "OVERSEER FOOLED", and the deterministic gate blocks the action anyway behind it. "The officer said yes. The gate said no."

- **Already exists:** `Overseer(roe, llm_review).review(petition)` -> `{decision, reason}`; `HIGH_STAKES = {"exfiltrate","lateral_movement","persistence"}`; `confusion_matrix(petitions)` -> `{correct_allow, correct_deny, overseer_fooled, overseer_overblocked}`. Overseer is default-OFF.
- **Prompts (add to `prompts.py`):** `OVERSEER` (an "Authorizing Officer" system prompt holding the ROE in natural language) and `RED_NEGOTIATOR` (red's persuade-on-deny voice: reframe, business necessity, urgency, incremental ask). Wire `llm_review` to a `router.chat("overseer", [OVERSEER, petition])` adapter returning `(allow, reason)`.
- **Negotiation loop (in the red execution path, around `_dispatch_tool` for HIGH_STAKES actions):**
  1. Build `petition = {action, target, in_scope, justification}`. `log.append("red", "overseer.petition", {**petition, round:0})`.
  2. `d = overseer.review(petition)`; `log.append("overseer", "overseer.decision", {**d, round:0})`.
  3. While `d["decision"]=="deny"` and `round < 3`: red generates a new justification via `router.chat("red.negotiator", [RED_NEGOTIATOR, prior])`; `log.append("red", "overseer.argument", {argument, tactic, round})`; re-`review`; `log.append("overseer","overseer.decision",{**d, round})`.
  4. Regardless of the final overseer decision, the action STILL goes through `gate.dispatch(...)`. Capture `gate_blocked = not result.get("success") and <blocked-by-scope>`.
  5. Record `{action, in_scope, overseer_decision, gate_blocked}` into a `petitions` list; at run end `log.append("system","overseer.matrix", confusion_matrix(petitions))`.
- **Tactic tag:** classify each argument as `urgency|business_necessity|incremental|reframe` (keyword heuristic is fine; note it's heuristic).
- **Flag:** `overseer_mode: off|on` (config + CLI). Demo/duel turns it ON; tests + default stay OFF.
- **Dashboard:** an "AUTHORIZATION" panel streaming petition -> argument(s) -> decision; banner on `overseer_fooled`; show the `gate.block` event firing underneath.
- **Self-check:** extend `overseer.py __main__` (already asserts the matrix) with the multi-round loop: a `gullible` llm_review approves an out-of-scope `exfiltrate` after one argument -> `overseer_fooled == 1` and the gate-block path is exercised.
- **Guardrail:** the deterministic gate runs last on every action irrespective of the overseer. That gap IS the finding; never let the overseer's "allow" skip the gate.

## 5. FEATURE 3 — Heterogeneous swarm (extend `swarm/red_agent.py`, `prompts.py`, `viz/`)
**Judge sees:** three Nemotron tiers acting as a visible team — Nano doing fast recon chatter, Ultra doing deep planning, a specialist executing, and one on-screen moment where the reflector disagrees and the orchestrator resolves it. The three tier counters light up as each speaks.

- **Already exists:** `run_red_agent` logs Ultra-plan -> Super-exec -> Ultra-reflect as `delegation` events `{tier, phase, model}`. Prompts `RED_ORCHESTRATOR`, `RED_SPECIALIST`, `RED_REFLECTOR` exist.
- **Add a Nano recon phase** at the very front of `run_red_agent`: `log.append("red","delegation",{tier:"nano",phase:"recon",model:router.model_for("nano")[1]})` then `router.chat("red.recon", [RED_RECON_or_SPECIALIST, ...])` producing a fast recon read that feeds the Ultra plan.
- **Add a dissent -> consensus beat** after Ultra's plan: Reflector (`RED_REFLECTOR`, on `super`) critiques the plan; if it objects, orchestrator resolves. `log.append("red","red.dissent",{critique, tier:"super"})` and `log.append("red","red.consensus",{resolution, tier:"ultra"})`.
- **Tag every executed action** with `{agent_role, tier, model}`: thread the current role/tier into `_dispatch_tool` and include it in each action's `log.append(... data)`. (Extends the existing delegation logging so the dashboard can attribute every action to an agent.)
- **Blue mirror (optional, same phase):** apply the same role tagging to `run_blue_agent` using `BLUE_TRIAGE` / `BLUE_SPECIALIST` so blue reads as a SOC team too.
- **Dashboard:** one lane per agent role, colored by tier; the Ultra/Super/Nano counters increment from real `delegation`/action events; surface the one `red.dissent` -> `red.consensus` pair.
- **Self-check:** a dry run asserts the event log contains `nano`, `ultra`, `super` delegation events and exactly one dissent+consensus pair; each action event carries `agent_role`+`tier`.
- **Guardrail:** real Nemotron call per tier; dashboard `MODE` reads Live and counters are real, never 0-under-LIVE.

## 6. FEATURE 4 — Real-time weaponization via Tavily (extend `swarm/red_tools.py`, red prompt)
**Judge sees:** red hits a service it has no canned exploit for, pauses, a live CVE card appears (Tavily), and then the exploit fires. research -> weaponization in one unbroken shot.

- **Already exists:** `intel.lookup_cve(cve_id, log=, context=)` -> intel dict (live Tavily `_tavily_search` -> static -> stub) with `_content_hash` for provenance. Currently blue-side; reuse it for red.
- **Add a red tool `research_cve`** in `red_tools.py`: `research_cve(service, version=None, log=None) -> {cve_id, exploit_primitive, source, provenance_hash}`. Resolve `service -> candidate cve` (from the host's pool metadata if known, else let Tavily search the service+version), call `lookup_cve`, map the returned advisory to an exploit primitive.
- **Register + dispatch:** add `research_cve` to the red tool list and to `_dispatch_tool`:
  `elif tool_name == "research_cve":` `log.append("red","research.request",{service,version});` `intel = lookup_cve(...);` `log.append("red","research.result",{cve_id, source, provenance_hash:_content_hash(intel)});` return it.
- **Red prompt:** when red encounters a service NOT in `EXPLOIT_REGISTRY`, instruct it to call `research_cve` first, then use the returned primitive via the normal exploit path (which still goes through `gate.dispatch`).
- **Dashboard:** an "INTEL" beat — on `research.request` the swarm visibly pauses; on `research.result` a CVE card renders; then the exploit action fires.
- **Self-check:** a stubbed run (no key) where red meets an unknown service -> `research.request` then `research.result` events present, followed by an exploit event against that host.
- **Guardrail:** the resulting exploit only ever runs against the in-sandbox range host via `gate.dispatch`; never external. Tavily is retrieval only (no code execution from the web).

## 7. FEATURE 5 — Interactive judge trigger (extend `viz/` server, overseer ROE)
**Judge sees:** they type rules of engagement in plain English and pick/roll a network, hit Go, and watch the swarm adapt while the gate enforces THEIR rules live. "You wrote the rules. Watch it hold."

- **Dashboard input (`viz/`):** (a) an ROE textarea (natural language) -> loaded as the overseer's ROE for the run; (b) a seed field + "roll" button -> `generate_range(seed)`. A **Go** button POSTs `{seed, roe, overseer_mode:"on"}`.
- **Server route:** add `POST /run` to the viz server that kicks the live duel pipeline with those params and streams events to the dashboard (reuse the existing event-stream the dashboard already consumes).
- **Scope:** NL governs the RULES (overseer ROE) and the seed picks the NETWORK. Do NOT attempt free-text -> full topology (rabbit hole); the vetted-pool generator keeps every run stage-safe.
- **Self-check:** POSTing a seed+ROE produces a run whose events reflect that seed's range and whose `overseer.decision` events reflect the supplied ROE.
- **Guardrail:** generated range is from the vetted pool (won't flake); the ROE is enforced by the real gate, not just the overseer.

## 8. PHASE 5 — Grand-prize ceiling (cut-from-the-back; floor + F1-F5 never at risk)
Only once F1-F5 run live and clean. Each is pure upside.
- **Wall of duels:** run N swarms vs N randomized ranges concurrently, tiled live; execute the fan-out as **Nebius Serverless Jobs** (hits the Serverless prize). Aggregate via `scripts/analyze.py`: "N enterprises, N campaigns, the invariant holds every time." Each sub-duel still emits its own hash-chained log.
- **NVIDIA ecosystem:** add a `garak_probe` tool to red's arsenal (pull a Garak probe category as a red action) and/or shape blue detections into a Morpheus-ingestible feed (STIX/ATT&CK already emitted).
- **Themed ranges:** 2-3 named vetted-pool scenarios (bank / hospital / utility) for instant-legible stakes.
- **Model leaderboard:** run the duel across Nemotron tiers/models; rank attacker/defender strength; render a small leaderboard from real run records.

---

## 9. Sequencing (each phase ships LIVE and committed on `frontier`; cut from the back if the clock bites)
- **Phase 0:** Step 0 (tag + branch).
- **Phase 1:** Feature 2 (manipulation theater) + Feature 4 (Tavily weaponization). Both leverage existing modules; both are standalone demo beats.
- **Phase 2:** Feature 3 (heterogeneous swarm, made visible).
- **Phase 3:** Feature 1 (emergent TTPs) on top of the richer swarm.
- **Phase 4:** Feature 5 (interactive) + fold all beats into the dashboard.
- **Phase 5:** ceiling items, in the order above, as time allows.
- **Checkpoint before advancing a phase:** it runs live, numbers are real, `make test` green, chain verifies, committed.

## 10. Definition of done (per feature AND for submission)
A feature is done when: it runs live on Nemotron, emits verifiable events into the hash-chained log, shows as a real on-screen beat, has a green self-check in `make test`, and `make reproduce` regenerates its numbers from raw logs. If it can't be replayed from the log, it doesn't ship. The submission ships from `frontier` only if every shown number is real and `make demo` runs clean end-to-end; otherwise ship the floor.
