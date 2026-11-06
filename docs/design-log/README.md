# Design log — reading order

The design log is the dated, append-only record of how duelswarm was built and verified. Nothing
here is rewritten after the fact; corrections are new dated entries. Read the current authoritative
documents in this order; the rest are the historical record, newest-informative-first.

## Authoritative, current (read these first)

1. [`2026-10-23-thesis.md`](2026-10-23-thesis.md) — what the range is **for**; the epistemics.
2. [`2026-10-29-falsifiable-claims-experiment-brief.md`](2026-10-29-falsifiable-claims-experiment-brief.md)
   — the four claims, each stated with its falsifier (the current experiment spine).
3. [`2026-10-29-planner-verifier-handoff.md`](2026-10-29-planner-verifier-handoff.md) — the
   planner/verifier role, repo layout, the cold-re-derivation toolchain, decision-neutrality.
4. [`2026-11-06-full-audit.md`](2026-11-06-full-audit.md) — the independent audit of the tree
   (findings G*, F*, I*, R* referenced throughout the recent work).
5. [`2026-11-06-cc-brief-v3.md`](2026-11-06-cc-brief-v3.md) — the current build brief (Phase A
   instrument-soundness, D1 cleanup, Phase B capability gate, Phase C experiment redesign).
6. [`2026-11-06-a4-verification.md`](2026-11-06-a4-verification.md),
   [`2026-11-06-a4-mutation-survivors.md`](2026-11-06-a4-mutation-survivors.md),
   [`2026-11-06-a3-verification.md`](2026-11-06-a3-verification.md),
   [`2026-11-06-a10-snapshot-verification.md`](2026-11-06-a10-snapshot-verification.md) — the
   independent verifications of the Phase-A floor/instrument work.
7. [`2026-11-06-phaseA-A4-A9-completion.md`](2026-11-06-phaseA-A4-A9-completion.md) — the Phase-A
   (A4-follow-up → A9) completion record, per item, with the honest gaps.

## Pre-registration

The hash-chained pre-registration lives outside the design log, in `docs/prereg.jsonl`, with the
amendment rationales in [`../prereg/RATIONALES.md`](../prereg/RATIONALES.md). Re-derive it with
`make verify` (which runs `scripts/preregister.py --verify`).

## Everything else

The remaining dated entries are the build's working record — session handoffs, per-phase briefs and
verification verdicts, and diagnoses of specific defects. They are kept for the auditable history,
not as current instructions; where an older entry is superseded, a newer entry says so.
