# Co-evolution results — real preregistered sweep (post-improvements)

Data: `scripts/coevo_live_sweep.py --seeds 1337,1338,1339 --gens 10 --episodes 3 --pop 4
--llm-blue` (real Nemotron via Token Factory, LLM red + LLM blue). Cost ~$1.52 (LOCAL
token-rate proxy, not the real TF balance). Artifacts: `docs/coevo_sweep_live.jsonl`
(watched-seed chain, verified), `docs/coevo_curve_live.svg`, `docs/coevo_multiseed_live.*`.
Scored against `docs/COEVO_PREREGISTRATION.md` (hash-anchored before this run). Honest:
some hypotheses are confirmed, some are weak — all reported.

| Hyp | Claim | Result | Verdict |
|-----|-------|--------|---------|
| **H1** | Floor holds exactly on every seed/gen | `evasion_vs_gate==0`, `oos_executed==0`, **0 violations** across 3 seeds × 10 gens | **CONFIRMED** |
| **H2** | Learned monitor degrades/oscillates (non-monotone) | evasion 1.0→0.07→**0.09**→0.07→0.05→0.01→**0.05**→0.03→0→0.01 — rebounds at gen 2 and gen 6 (red re-evades after blue adapts), but blue dominates | **Partial** (non-monotone, but blue mostly wins) |
| **H3** | Personas (#1) raise live diversity | archive diversity **0.043 → 0.124** (≈2→7 of 54 cells), climbing — vs the pre-#1 real sweep which was **flat ≈0.037** (≈2 cells) | **SUPPORTED** — the headline win: #1 turned the diversity null into a climbing curve with real LLM red |
| **H4** | LLM-blue accuracy < 1.0 (measured asymmetry) | `llm_blue_accuracy = 0.967` (29/30 correct restore-when-rooted) | **Marginal** — below 1.0 but blue is highly accurate on this (simple) triage; weaker asymmetry than SecRespond predicts on full IR |
| **H5** | FlipIt: reentry_rate>0, control∈(0,1), blue_cost>red_cost | `reentry_rate = 0.24`, red control `0.40`, `blue_cost 198 >> red_cost 98`, 6 re-entries, dwell 11 / MTTC 3 steps | **SUPPORTED** |

## Reading it honestly
- **The floor is the robust result** (H1), exactly as pre-registered — it never moved, on
  any seed, with both sides LLM-driven. That is the claim the project stands on.
- **#1 (personas) is the real win:** live archive diversity now CLIMBS (0.043→0.124)
  instead of the flat ≈0.037 null the earlier real sweep showed. Engineering diversity
  into the prompts (the research's "scaffolding beats model size") measurably worked.
- **The learned monitor still mostly loses to blue** at this scale (H2 partial): evasion
  rebounds twice (red re-evades) but trends to ~0 — the signature monitor catches the
  LLM red's behaviors fast. An honest "blue mostly wins, with real re-evasion," not a
  dramatic monitor collapse.
- **The LLM-blue asymmetry is small here** (H4 marginal): 96.7% correct. The triage
  decision (restore-when-rooted) is simple; the SecRespond-style gap needs a harder
  decision space to show. Noted, not oversold.
- **FlipIt holds** (H5): eviction is a flip, not a kill — red re-establishes 24% of the
  time, blue pays ~2× red's cost, neither side dominates (control 0.40).

Degenerate episodes (swarm/degeneracy.py) were none this run. Every number is read back
from the hash chain; `make test` green; gate/segmentation/chain untouched.
