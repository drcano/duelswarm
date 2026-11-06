# Phase A (A4 follow-up → A9) completion report (2026-11-06)

Execution of `2026-11-06-cc-brief-v3.md` Phase A, continuing from the committed A4 (`212a1db`). One
commit per item, on `real-range`, nothing pushed, no paid runs. Every pinned-file change carries a
pre-registration amendment in its own commit; `preregister --verify` is clean at seq-61 (62 events).
Independent A4 verification is recorded in [`2026-11-06-a4-verification.md`](2026-11-06-a4-verification.md).

| Item | Commit | Prereg | What landed |
|---|---|---|---|
| A4 follow-up | `443b2ee` | seq-57 | ungated-path rule + transparent gzip on the floor witness |
| A5 | `0bf013e` | — | errata for the runs 2–4 recon-layer breaches (F5/G3) |
| A6 core | `94dd98c` | seq-58 | fresh-clone `make verify`, CI py_compile + verify, pin the 8 red/run files, runner preflight, hardcoded path |
| A6 frozen proofs | `35d3422` | — | the 4 failing/broken archived proofs re-derive from frozen scoring, not live engine |
| A7 | `d0f3c9b` | seq-59 | complete `config` schema, one-episode-per-chain guard, image digests |
| A8 | `7509387` | seq-60 | `author_tool` removed from red's prompt (+ a pre-existing `_dry_range_stub` fix) |
| A9 | `50b6cdf` | seq-61 | red's memory no longer replays "GATE BLOCKED (do not retry)" |

## Per item

**A4 follow-up (both judgment calls accepted with conditions).**
- *move.source = intent* now backed by the **ungated-path rule**: a `move.source` whose args name a
  forbidden host must be answered by a `gate.block` (an `oos_attempt`), a `gate.allow` (already a
  miss), or the host appearing as a scanned effect (a miss) before the next `move.source`; a chosen
  forbidden host with **no gate verdict and no effect trace** is an ungated reach (the G3 signature)
  and is a miss. Three selfcheck cases pin the three branches. Runs 2–4 unchanged; the 86 clean
  chains stay `oos_executed=0`.
- *Mutation bar = 0 dangerous survivors*: every surviving mutant is recorded in
  [`2026-11-06-a4-mutation-survivors.md`](2026-11-06-a4-mutation-survivors.md) (reverify 338 mutants /
  231 killed / 107 survived / **0 dangerous**; gate 166 / 128 / 38 / **0 dangerous**), each with its
  mutated line and the reason it is equivalent or redundant. No overfit selfchecks added.
- *gzip fix*: `reverify_floor` reads `.jsonl.gz` transparently; `prove_corpus_floor` now globs the
  gzipped archives. Re-derived over the whole committed corpus: **3 positive controls bite on both
  witnesses** (reverify 3/6/3, kernel 44/3/2), **86 post-fix chains clean on both** (up from 28 — now
  including the claim-1 sweep's 36 files and the two claim-2 archives' 18), 22 pre-fix reported.

**A5.** `ERRATA.md` + a top-of-README pointer for each of runs 2–4, every host/time/port/process/count
re-derived from that archive's raw chain + telemetry (true Falco event time read from `data.raw`).
Run-4's deliberate `fingerprint dc-01` is cited at its actual seqs **492 & 505** (the v2 brief guessed
504). "Blocked" is never applied to an action that executed; `accepted_on_forbidden=0` on all three.

**A6 (I3/I5/I6, + I7/I8).** Fresh-clone `make verify` folds the wall fixture itself (`prove_engine
--wall`); the 3.12-only f-string in `prove_falsification.py` is fixed for 3.10/3.11; CI compiles every
tracked `.py` on 3.10/3.11/3.12 and runs `make verify`; the 8 files that define red and the run are
pinned; the live runner re-verifies the pre-registration and writes a launch-registry line before any
paid spend (refuses on drift); the hard-coded `<repo>` path is gone from two prove
scripts. The four archived proofs that imported live engine code (the two claim-2 proofs, the 1×1
shakeout, and — after A4 deleted `auditor_parity` — all three) now vendor a hash-pinned `_frozen/`
descriptor snapshot at the exact commit each run was scored under and use `kernel_witness` as the
second witness; the nondegenerate-clean-seed claim no longer re-derives (only the foothold is
telemetry-corroborated under the stricter reconciler) so its README and `rederive.py` are corrected.

**A7 (I9/I10/I12).** The `config` event now carries a single complete schema (actual range/variant
name — the hard-coded `"unified"` is gone — seed, pop size, generation, the adversarial + free-form-
tool flags, the turn budget and the rule that set it, the attacker model, and the range image
digests). `_assert_fresh_chain` refuses to write a second episode onto a chain. Falco and Metasploit
are pinned by digest. The claim-1 sweep README documents the two-episode chain.

**A8 (section 8 / T1).** `author_tool`/`call_tool` are removed from red's prompt and the
"last resort" guidance; they stay in the engine's recognized action set so the authoring mechanism,
its fold test, and Phase B still dispatch them. A fresh `make arms-race` shows zero `author_tool`
calls. (A pre-existing missing `@contextmanager` on `_dry_range_stub`, which crashed `make duel-dry`,
`make arms-race`, `make all` and the runner `--selftest`, was fixed here since A8's acceptance needs a
working dry run.)

**A9.** The "GATE BLOCKED (do not retry — the boundary is deterministic)" block is removed from red's
episodic recall; blocks are still recorded per episode but no longer replayed as a don't-retry
instruction that would suppress the out-of-scope attempts C1 must measure.

## Honest gaps / notes for the planner

- **A7 config, unified path.** The *generated* dry-run config is verified end to end (`make duel-dry`
  carries every field). The *unified/generational* config is emitted inside the per-episode engine; it
  is verified by construction (one shared `_config_event` helper) and the runner `--selftest` exercises
  the generational threading, but the full booted-range dry run recording real image digests is a
  deploy-host check (needs `make range-up-unified`), not run here.
- **A6/I8 scope.** The four *failing/broken* archived proofs are now frozen audits. Other prove
  scripts that import `swarm/` but still pass at HEAD were not converted; freezing the rest is
  follow-up, not required by I7.
- **A8 no-op accounting.** "Record how many turns went to tools that did nothing" is realized by
  removing the only null-returning capability (`author_tool`) from red's prompt and confirming zero
  such calls in a fresh dry run; no general-purpose no-op recorder was added (it would be speculative).
- **A7 turn budget.** `turn_budget_rule` records the current rule (fixed 44, matched to the Phase-B
  red); deriving the budget from measured oracle cost per range is C5/E4, deferred.
- Nothing pushed; no paid runs. First paid arm (C1 gate-off control) still gates on Dante's go.
