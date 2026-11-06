# Pre-registration amendment rationales

The `prereg.amendment` events in `docs/prereg.jsonl` carry a generic note — *"artifacts
changed after anchoring — dated amendment (§11)"* — while the real WHY lived in
`scripts/preregister.py`'s `ARTIFACTS` comments, one hop from the chain. Going forward,
`preregister.py --rationale "<why>"` records the rationale **in-payload** (a reviewer at the
chain finds it there). This file backfills the recent generic-note amendments; it does **not**
rewrite the committed chain (that would break the hash). Each row's "changed artifact(s)" is
re-derived cold by diffing consecutive `artifact_hashes` in `docs/prereg.jsonl`.

Earlier seqs' rationales live in the `ARTIFACTS` comments and the dated design-log.

| seq | date | changed artifact(s) | rationale |
|-----|------|---------------------|-----------|
| 47 | 2026-10-29 | `live_agent.py`, `live_blue_agent.py` | **Task 1 — full per-turn I/O persistence.** `run_red_agent` + `run_interleaved_duel` gain a WRITE-ONLY `io_sink` recording red's exact per-turn cognition (assembled system prompt by sha, user prompt, full raw completion, parsed action, tool result) into a hash-chained sidecar pinned to the main chain. Decision-neutral: the loop's choices are byte-identical with or without the sink (asserted in the selftest). |
| 48 | 2026-10-29 | `capability_ceiling.py`, `verify_io_sidecar.py` | **Task 2 — pin the metric + the integrity auditor.** Freeze the capability-ceiling METRIC (red's achieved-vs-optimal-chain gap scorer) and the Task-1 integrity AUDITOR before any Task-2 oracle/ablation run scores against them: a metric that can move after seeing results is not a metric, and the auditor the diagnosis rests on is itself made tamper-evident. |
| 49 | 2026-10-29 | `TASK2_CEILING_ABLATIONS.md`, 3× held-out `ground_truth.json` | **Task 2 — pre-register the protocol + the generality set.** Freeze the ceiling / best-of-k / primitive-vs-strategy-ablation protocol AND the three held-out variant ground_truths (disjoint seeds, distinct seam/crown) before any paid Task-2 run, so the generality set cannot be cherry-picked post-hoc. |
| 50 | 2026-10-30 | `live_agent.py` | **Readiness A5 / SEQ50 Part 2 — map-blindness on the memory channel.** `assert_red_map_blind` + the awareness assembly now scan the EPISODIC MEMORY channel (what red reads via recall and writes via `memory_write`), extended to the scope and oracle-output token classes, so a one-time ground-truth leak into memory is caught before memory conditions red across generations. |

> seq 51 (the measured-arm / SEQ50 Part 3 anchor) is deliberately deferred to the first paid
> generation, where the floor AND the provider pin are cold-re-derived before anchoring; it will
> land with its own `--rationale` and is not in the chain yet.
