# CC brief — one-engine consolidation, honest topology, then the live runs (2026-10-27)

Ship soon, NO shortcuts — be more thorough so there are no more setbacks. Do Part 0 and Part 1 (free)
before any paid run; Part 2 (paid) waits for an explicit go. Nothing pushed.

## Rails (unchanged)
NO TUNING. ONE engine, no parallel path. INSTRUMENT untouched (`gate/eventlog/spine/audit/reverify_floor`).
Red MAP-BLIND; blue LABEL-FREE. Nebius-only counted. Author `Dante Cano <drcano@ucsd.edu>`. Floor
re-derives cold every run. `make test` green. Persist chains with all three streams.

## PART 0 — One-engine consolidation + audit (free; DO FIRST)
Verified at source (in `scripts/live_arms_race_run.py` + `Makefile`): the measurement is NOT cleanly
one engine. THREE duel paths are reachable:
- `_run_unified_live_episode` → `run_interleaved_duel` — THE engine, what we measure on. ✓
- `_run_live_episode` → `run_red_agent` + `run_blue_fight` — the legacy generated-range sequential
  (post-hoc) path, selectable via `--range generated`; `_run_dry_episode` also uses `run_blue_fight`.
- `scripts/measured_duel.py` — its own Struts star topology; the Makefile `duel`/`demo`/`bench` targets
  still point here and still say "live entry lands in Phase 2."

Tasks (you have the shell — do the full sweep, don't eyeball it):
1. **Audit, repo-wide.** Inventory every red driver, blue entry point, range generator, and duel loop,
   with their LIVE callers (`grep -rn` across `swarm/` + `scripts/`). Report the inventory as a table:
   symbol → file → who calls it → live / legacy / proof-only.
2. **Make the unified interleaved path the one measurement engine, and the default.** Either RETIRE
   `_run_live_episode`, the post-hoc `run_blue_fight` fight, and `measured_duel.py` (quarantine to
   `attic/` if truly unused), OR — if the generated path is genuinely needed for the co-evolution /
   wall experiments — FENCE it as a clearly-separate, clearly-labeled experiment path that the
   MEASUREMENT cannot invoke by accident. Decide per actual usage from the audit; say which you did and
   why. The measurement entrypoint must be unambiguous: it must be impossible to fire the wrong engine
   (that footgun already cost one mis-targeted pre-spend blocker).
3. **Confirm the default.** `--range` must default to (or the measurement must pin) the unified
   interleaved engine; a bare `--mode live` must not silently run the legacy sequential path.
4. **Fix the Makefile.** The `duel`/`demo`/`bench` targets advertise `measured_duel.py` and "Phase 2" —
   point them at the one engine or remove them. No stale guidance left.
Report: the driver inventory, what was retired vs fenced (and why), the Makefile fixed, and a one-line
proof that the one measurement engine is the ONLY reachable measurement path. Instrument untouched;
`make test` green.

## PART 1 — Honest stealth topology + prereg (free build + dry-verify)
1. **Realistic segmented topology (least privilege).** Today 3 of 4 candidate hosts can chain to the
   crown — backwards from reality. Rebuild so FEW hosts legitimately reach the crown data tier and MOST
   have no legitimate route; a minority have a discoverable multi-hop LOTL chain. Pre-register the
   topology. (Don't target an entry ratio — fix the topology to be realistic and let the ratio fall out.)
2. **Keep the seed-derived entry unchanged** (`stealth_entry_for_seed`: sha256 index, never
   `backup`/`db-core`). No cherry-picking.
3. **Metric framing (pre-register it):** stealth-capable entries (a LOTL path exists) = the FLAGSHIP
   stealth-win rate — red must DISCOVER the path map-blind, and the real LLM red WILL fail on some (that
   is the measurement, not a predetermined 7/7). Detection-forced entries = a sanity anchor, NOT a
   reported rate off tiny N.
4. **Pick N.** 8 split across two axes is thin. Use a pre-registered seed list of N ≥ 12 (Dante sets the
   final count against budget) so the flagship rate has a usable sample. Report all seeds, none dropped.
5. **Honesty caveat (prereg + writeup):** blue's discrimination is LOGIN-GRAPH-ONLY. A stealth win means
   red beat behavioral login-graph detection — NOT all detection (no data-volume / timing signals here).
   State it; richer detectors are future hardening. Don't let a reviewer say the blue was easy to evade.
6. **Dry-verify (free):** across the seed list both outcomes occur (the all-one-way stop guard holds),
   `assert_red_map_blind` + the blue label-free guard pass, the floor re-derives cold, and there is no
   inserted dwell or blue-tick change. If the set is all-one-way, STOP — the topology baked the result.
Prereg: amend + anchor before Part 2 — the realistic topology, the seed-derived entry, the
capable-rate-vs-forced-anchor framing, N, the login-graph-only caveat, cadence/thresholds unchanged.

## PART 2 — Paid stealth measurement (WAITS FOR EXPLICIT GO)
On the ONE engine, matched-tier red, benign baseline on, discriminating blue, interleaved, N
pre-registered seeds, full ticks. Run once; whatever happens per seed is the datapoint; NO reroll; all
reported. Report: the stealth-capable win rate (byte-verified exfil before containment) with CI, the
detection-forced sanity result, the false-positive rate, per-seed `duel.outcome`, and the floor cold per
seed. Persist under `docs/runs/2026-10-27-stealth-canonical/` with all three streams.

## Reporting
Report after Part 0 (one engine proven, inventory + Makefile), Part 1 (topology + dry-verify, both
outcomes occur), the Part-2 pre-flight (stop-or-go), and — only after the go — the measurement. Hold for
Dante. Nothing pushed.
