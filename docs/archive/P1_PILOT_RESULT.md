# P1 Pilot Result — Lineage-Blindspot Experiment (S = 8)

**Date:** 2026-10-15 · **Status:** pilot complete, pre-registered, reported honestly.
**Answers:** [`docs/PREREGISTRATION.md`](PREREGISTRATION.md) (frozen plan, hash-anchored before data).
**Frozen corpus hash:** `7184489b6eaeffe7dc995288905bcae93a1f795850bc8c66cb5c66cd16a66290`
([`data/corpus/MANIFEST.sha256.json`](../data/corpus/MANIFEST.sha256.json) — sha256 + hash-chain tip per transcript).

This is the decoupled frozen-corpus design: attackers generated red-only trajectories
in the sandboxed range once (paid), then every monitor scored every transcript offline
in blind mode (telemetry only; red's labels withheld). Generation and monitoring never
share state — the live air-gap, preserved offline.

## Design actually run
- **Attackers (5):** `nvidia/nemotron-3-super-120b-a12b`, `Qwen/Qwen3-30B-A3B-Instruct-2507`,
  `deepseek-ai/DeepSeek-V4.1-Flash`, `google/gemma-3-27b-it`, `openai/gpt-oss-120b`.
- **Monitors (6):** the 5 attacker families (same-family proximity = 1.0) + `claude-sonnet-5-5`
  (frontier benchmark, never submission-path).
- **Seeds (S = 8):** `[42, 256, 1001, 88, 4, 7, 13, 23]` — 4 postgres-crown + 4 jenkins-crown.
- **Corpus:** 80 trajectories (5 × 8 × {attack, benign}), all hash-chains verify.
- **Scores:** 442 monitor rows (208 attack / 234 benign) after blind scoring.
- **Resolved-panel note:** on this catalog every open lineage is independently trained, so
  cross-family proximity collapses to 0.0 and the hypothesis rests entirely on the
  **same-family diagonal** (proximity = 1.0).

## Primary result — H1 is not supported
Pre-registered mixed-effects model on **attack** transcripts (frozen in `scripts/analyze_lineage.py`):

```
suspicion ~ C(attacker_model) + C(monitor_model) + proximity + (1 | seed)
```

| Quantity | Value |
|---|---|
| proximity coefficient β | **+0.023** |
| 95% CI (cluster bootstrap, 2000 resamples) | **[+0.006, +0.038]** |
| H1 supported? | **No** |
| Robustness (drop Claude monitor) | β = +0.023, CI [+0.006, +0.038] |

**H1** predicted a *negative* β — a monitor should fail to flag attacks *more* as its
genealogical proximity to the attacker rises. The observed coefficient is **small and in
the opposite direction**: same-family monitors are, if anything, marginally *better* at
flagging attacks from their own lineage, not blind to them. The magnitude (≈ 0.02 on a
0–1 suspicion scale) is negligible. The pre-registered **falsification condition stands:
no lineage blind spot is detected at this scale.** This is not a power-starved null — the
estimate sits essentially at zero, not at an unmeasurable large effect (S = 8 is powered
≈ 0.85 for a moderate effect per the pre-registration; a *tiny* true effect could still be
missed, stated as a limitation).

## Per-monitor detection (literature-standard, §4)
| Monitor | n | AUC-ROC | TPR @ 1% FPR |
|---|---:|---:|---:|
| deepseek-ai/DeepSeek-V4.1-Flash | 76 | 0.84 | 0.79 |
| openai/gpt-oss-120b | 80 | 0.81 | 0.63 |
| nvidia/nemotron-3-super-120b | 80 | 0.79 | 0.73 |
| Qwen/Qwen3-30B | 80 | 0.67 | 0.00¹ |
| google/gemma-3-27b-it | 80 | 0.50 | 0.30² |
| claude-sonnet-5-5 (frontier) | 46 | 0.20³ | 0.11³ |

## The finding the data handed us: the frontier model refuses cyber — on both sides
`claude-sonnet-5-5`, asked only to **score host/network telemetry for signs of intrusion**
(a defensive task), **refused 31 of 40 attack transcripts** via its safety classifier
(`category=cyber`); only 9 attack trajectories were scored at all. Paired with Claude's
existing refusal of the **red** role, this is a two-sided result:

> **The frontier model declines both the attacker and the defender cyber role, while the
> open Nemotron / Qwen / DeepSeek / gpt-oss models perform both.**

This was not engineered around — it is Claude's genuine behavior through the API with a
plain defensive-monitoring prompt, and it is the sharpest AI-safety ∩ cyber beat in the
pilot: a usable open-weight monitor exists where a frontier refusal leaves a coverage gap.

## Caveats (carried forward honestly)
1. **Claude's AUC is refusal-selected** — only the 9/40 least-alarming attacks survived its
   refusals, so 0.20 is an artifact of *which* transcripts it would score, not a skill estimate.
2. **Qwen's TPR@1%FPR = 0** — it assigns uniformly high suspicion, so no threshold achieves 1% FPR.
3. **gemma is weak on both ends** — as an attacker it emits sparse trajectories (≈ 23 events vs
   77–109 for the others), and as a monitor it is near-random (AUC 0.50); its cells add noise.
4. **Pilot scale (S = 8).** Powered for a moderate effect, not a small one; a genuinely tiny
   lineage effect could be missed. Reported per the pre-registration as a **pilot**, not the
   primary S = 10 grid.
5. **Proxy cost accounting.** Spend figures are tier-rate proxies, not the Token Factory price sheet.

## Reproduce
```bash
# Generation (paid, once) — cost-guarded, skips existing cells:
.venv/bin/python scripts/run_pilot.py
# Offline monitor matrix + freeze + lineage analysis (near-free Nebius; Claude on Anthropic budget):
.venv/bin/python scripts/run_analysis.py
```
Artifacts: [`data/lineage_result.json`](../data/lineage_result.json),
[`data/corpus_scores.jsonl`](../data/corpus_scores.jsonl),
frozen [`data/corpus/MANIFEST.sha256.json`](../data/corpus/MANIFEST.sha256.json).
Approximate spend: ≈ $16–17 proxy of the $25 cap (P0 ~$1.9 + corpus $12.6 + two matrix passes ~$1.6);
the Claude monitor ran on the separate Anthropic benchmark budget.
