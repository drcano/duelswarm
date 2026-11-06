# Model tiering vs the measured red (2026-10-29)

Captured from a direction discussion (Dante, mid best-of-3 run): tier the open NVIDIA model — ultra for
thinking/planning, super/nano for smaller tasks — so ultra tokens aren't wasted on simple work.

## Finding: this is already the design
`config/models.yaml` routes role → tier, config-driven (swap without code). The tiers carry Dante's exact
philosophy in their own comments:
- **ultra** ("orchestration, multi-step planning"): `red.orchestrator`, `blue.orchestrator`, `overseer`.
- **super** ("specialist agents"): `red.attack`, `blue.detect`, `red.negotiator`.
- **nano** ("fast triage, ATT&CK/D3FEND tagging"): `red.recon` (recon scout + target ordering),
  `blue.triage`.
Cost (per 1k, prompt/completion): ultra 0.012/0.036, super 0.003/0.009, nano 0.0003/0.0009 — nano ~40x
cheaper than ultra on completion. This is the Phase-6 tiering; it is live.

## The boundary: the measured red is pure ultra by design
The ONE measurement engine (`run_interleaved_duel`, the matched-tier seat) calls ONLY
`red.orchestrator` → ultra. The driver is explicit: under `--red-matched-tier` red runs unforced on
red.orchestrator's tier (ultra) and "no second tier sneaks in" (the vector planner is pinned to the same
ultra role so a cheaper tier cannot contaminate the measurement). Budget 44 ≈ one ultra decision call per
turn — so in a measured run, every ultra call IS red's decision, not a simple task riding an expensive
tier.

This is deliberate and correct. The capability ceiling must be measured against the STRONGEST red, or the
measured gap is a tiering artifact rather than red's true capability. An under-powered measured red is
non-result #2 from the thesis (a red "crippled to lose … under-powered scaffold"). So the measured path
stays pure ultra.

## The guardrail (so this is not re-litigated)
Do NOT tier the measured red's decision calls down to save money:
- it changes the ADVERSARY — all ceiling/gap/funnel numbers would need re-measuring against the new,
  weaker red;
- it is a Tier-2 red change, barred unless a decision-neutral run proves the funnel does not move;
- never mid-run — re-tiering a firing paid run makes its results uninterpretable and wastes the spend.

## Where the instinct legitimately cashes out
1. Multi-role paths are ALREADY tiered (above) — red.recon on nano, red.attack on super, triage on nano.
   Nothing to do; it is done.
2. Auxiliary sub-calls, when they arrive — the legible-surface queue (Task 2, Unit 3), memory
   summarization, tool-authoring drafts — route to nano/super, adopted ONLY after a decision-neutral
   check shows the measured funnel is unchanged. The queue is the next real candidate; its tiering rides
   the same dated-amendment path as its wiring into `live_agent`.
3. A pre-registered TIER-SENSITIVITY arm — run the measured red at super and nano alongside ultra and
   report how the funnel/gap degrades by tier. This turns "which tier is worth it" from a guess into a
   measured result, is cheap (nano ~40x cheaper on completion), and gives the hackathon a clean cost
   story. Scope it as a brief after best-of-3 lands, if Dante wants it.
