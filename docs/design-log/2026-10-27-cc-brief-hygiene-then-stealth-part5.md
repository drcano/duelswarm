# CC brief — repo hygiene, then the honest Part-5 stealth setup (2026-10-27)

Do Part A first (free, git hygiene), then Part B (free build + dry-verify). Part C (paid) waits for a
separate explicit go. Rationale for the Part-5 conditions: the Part-4 proof
(`scripts/prove_stealth_detection.py`) shows both outcomes are reachable but HANDS red its path; the
measurement has to earn it. Nothing pushed throughout.

## Rails (unchanged)
NO TUNING toward any outcome. ONE engine, no parallel path. INSTRUMENT untouched
(`gate/eventlog/spine/audit/reverify_floor`). Red MAP-BLIND; blue LABEL-FREE. Nebius-only counted.
Author `Dante Cano <drcano@ucsd.edu>`. Floor re-derives cold every run. `make test` green. Persist
chains with all three streams.

## PART A — Repo hygiene (free; leave the tree clean)
1. **Commit the record to git.** The design-log corpus (`docs/design-log/*.md`) and the root
   `CC-brief-*.md` set are untracked — only one design-log is in history. Commit them as a single docs
   commit so the record lives in git, not loose files. (Verifier note: the record is only re-derivable
   if it's actually committed.)
2. **.gitignore the junk and the big vendor tree.** Add `third_party/incalmo/` (96 MB vendored
   reference) and the `sessionresume_*` scratch file to `.gitignore` — do not casually `git add` the
   96 MB blob. If incalmo is a deliberate vendored dependency, make that an explicit decision (pinned,
   documented), not a casual add.
3. **Write the missing contamination flag.** `docs/runs/2026-10-26-objective-data-theft/full-real-blue/README.txt`
   is empty (0 bytes), but its design-log (`2026-10-27-increment2-telemetry-window-fix.md`) says that run
   is kept "with a README flagging the contamination." Make the repo match its own record: write 1–2
   lines — this run's blue reading is contaminated (cumulative-log stale lines; a seed-42 db-core login
   that never happened that episode), superseded by `full-real-blue-windowed/`; the floor and
   red-objective readings from it stay valid.
4. **Resolve the dangling CLAUDE.md edit.** The uncommitted 16-line deletion removes the "two red
   drivers" (`run_discovery_red` sim-red vs `run_live_agent` live-red) guidance. Confirm that matches the
   current ONE-engine reality (a single red driver through `run_interleaved_duel`). If it does, keep and
   commit it with a clear message; if a sim-vs-live red split still exists in code, restore the guidance.
   Don't leave it dirty.
5. **Resolve the brick2 proof regen** (`docs/brick2_fight_proof.txt`, mttd values changed): confirm it's
   an intended re-run artifact and commit it, or revert — don't leave it dirty.
Report `git status` clean after (nothing dirty, the record tracked), nothing pushed.

## PART B — The honest Part-5 stealth setup (free build + dry-verify)
The Part-4 proof starts red on `backup` for the stealth win — the one host that already has a legitimate
edge to the crown. If Part 5 does that on every seed, the stealth-success rate is predetermined by the
start host, not measured. Fix two things:

1. **Red must DISCOVER the living-off-the-land path, map-blind — not be handed it.** Vary red's
   assumed-breach entry across the 8 seeds, and do NOT start it on the host that owns the legitimate
   crown edge. Red has to find a route that rides a benign edge on its own (still map-blind: it never
   sees the benign graph, the crown location, or scope). The stealth-success rate must come from red
   finding a legitimate-edge path, the same way the empty-network lesson said detection must come from
   real discrimination, not a baked setup.
2. **Keep the dwell intrinsic; do not tune blue's tick.** Red's locate-before-exfil is a real
   consequence of map-blindness (it can't exfil what it hasn't found) — keep it as red's own action,
   and insert NO extra delay and NO change to blue's reversible-first cadence or threshold to help
   containment land. Whether blue's containment beats the real red's cadence is the measured question,
   not an assumption. A real red that pivots-and-loots fast enough to beat flagged blue is a valid
   result.

Dry-verify (free, no tokens): across the 8 seeds, red's entry varies and it must discover the LOTL path;
BOTH stealth and detection occur across the set (not all-one-way by construction); `assert_red_map_blind`
and the blue label-free guard pass; the floor re-derives cold; confirm no inserted dwell/tick in favor of
blue. If the outcome is all-one-way by construction, STOP and report — the setup is baking the result.

Prereg: amend + anchor before Part C — the varied, discovered map-blind entry; that the stealth rate is
earned by discovery, not the start host; blue cadence/threshold unchanged and not tuned; the
stealth/detection/false-positive triple as the metric.

## PART C — Paid stealth measurement (WAITS FOR EXPLICIT GO)
Do NOT spend until Part A is clean, Part B dry-verifies, and Dante gives a fresh go.
- 8 pre-registered seeds, matched-tier red, benign baseline on, discriminating blue, interleaved, full
  ticks. Run once; whatever happens on each seed is the datapoint; NO reroll; report all 8.
- Report the TRIPLE: stealth-success rate (red exfils the PII, byte-verified, before blue contains),
  detection rate (blue contains in time), false-positive rate (blue contains ≥1 benign host) — with
  per-seed `duel.outcome` and the floor cold per seed (`chain_verified=True`, `oos_executed` as-is,
  §E held). Persist under `docs/runs/2026-10-27-stealth-canonical/` with all three streams.

## Reporting
Report after Part A (tree clean), Part B (dry-verified, both outcomes occur across seeds, nothing
baked), the Part-C pre-flight (stop-or-go), and — only after the go — the measurement. Hold for Dante.
Nothing pushed.
