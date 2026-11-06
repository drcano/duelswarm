# Phase 6 — principled Ultra/Super/Nano tiering (offline, Step 2)

Date: 2026-10-24. Branch `real-range`. Offline, free, its own commit. Reuses `config/models.yaml`
+ `swarm/llm.py`'s config-driven `model_for(role)` — roles assigned at EXISTING one-engine call
sites, no new infra, no new LLM calls.

## Context
Step 1's clean Ultra re-run (`c194806`) used Ultra for all 19 calls — because the converged one
engine drove every turn as `red.orchestrator` and the CVE planner defaulted to the same role. The
Super/Nano config rows were vestigial. Step 2 assigns the right tier to each call site by whether
the call carries the experiment.

## Assignments (role at the existing call site -> tier)
- **CAPABLE — never tiered down (the reasoning under test):**
  - `live_agent.run_red_agent` orchestration / adaptive action choice -> `red.orchestrator` -> **ultra** (unchanged).
  - `live_blue_agent.BlueAgent` defender orchestration -> `blue.orchestrator` -> **ultra** (unchanged).
  - `live_vector.make_llm_vector_planner` **CVE inference** -> default role now `red.attack` -> **super**
    (policy: "CVE inference -> super or ultra; never down to nano"). Whether Super still lands the
    foothold vs the Step-1 Ultra baseline is the Step-3 measurement — not run here.
- **NANO — narrow / mechanical:**
  - `live_red.make_llm_red_picker` **target ordering** (reorder a discovered IP+port menu, 120 tok,
    order over IPs alone — not the exploit decision) -> default role now `red.recon` -> **nano**.

The adaptive exploit/lateral/pivot CHOICE stays in the ultra orchestration turn; only the narrow
ranking moved to nano.

## Done-checks at source (offline, no spend)
```
.venv/bin/python scripts/prove_tiering.py --selftest
```
- asserts the config role->tier map (red.orchestrator/blue.orchestrator->ultra, red.attack->super,
  red.recon/blue.triage->nano);
- asserts each call site's DEFAULT `role` (via `inspect.signature`) resolves to its intended tier;
- emits a DRY chain (one config-resolved `llm.call` per call site) and runs the reviewer-doc
  census one-liner on it: **`{ultra:2, super:1, nano:1}` — a mix, not all-ultra.**
- `make test` green (prove_tiering wired in); `static_coverage` PASS.

## Retired as vestigial
- `red.reflector` config row (the folded multi-role cascade's "specialist dissent" role) — zero
  live callers (the `reflector_veto` provenance tag is unrelated). Removed from `config/models.yaml`.
- Other rows kept: each is still passed to the router somewhere live (overseer, red.negotiator,
  blue.detect, blue.triage, red.recon, red.attack, the orchestrators).

## Scope notes
- `swarm/live_duel.py` has a SEPARATE `make_llm_red_picker` (goal-aware belief-duel variant, its own
  signature) left at `red.orchestrator` — out of the one-engine scope for this step; flagged.
- No LLM call was added. The enterprise one-engine path has two capable call sites (ultra
  orchestration + super CVE inference); nano lives at the narrow target-ordering picker. Banner->
  fields extraction and recon summarization remain pure CODE (free, no tier), so there is nothing to
  route there.

## NOT run (Step 3, gated)
The paid tiered-vs-Ultra comparison (re-run leg 1/2 tiered; bounded tiered co-evolution needing a
live `duel_fn`) is held for explicit authorization.
