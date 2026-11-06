# A10 snapshot — independent verification (2026-11-06)

The A10 snapshot commit (`bc02daf`, "Snapshot today's untracked work (brief v3 A10)…") was
independently re-verified from the device files by the planner/verifier session, outside the
build session. Recorded here so the baseline everything else diffs against is itself pinned by
an independent check, not by the build session's own report.

## What was checked, and the result

- **HEAD** is `bc02daf` on `real-range` (not pushed).
- **Gzip is lossless.** All **111** `*.jsonl.gz` files decompress byte-identical to the
  pre-compression originals (no data was altered by the 103 MB → 11 MB compression).
- **Chains verify independently.** `tools/audit-kit/walk.py` reports **OK on all 111** chain
  files under the stated `sha256(prev+body)` rule.
- **Prove script passes.** `docs/runs/2026-11-05-claim1-sweep/prove_claim1_sweep_exploratory.py`
  (standard library only) **PASS**, with the corroborated-win tally
  **unified 4/11, app_crown_4hop 4/11, app_crown_4hop_44t_shutout 0/10, backup_route_5hop 3/4**.
- **Audit kit is authentic.** `tools/audit-kit/` is **byte-identical** to the delivered kit, which
  is checked against an outside hash manifest at review. The build session must never modify it; if
  an oracle looks wrong, the build session stops and reports rather than editing it.

## Follow-up folded into the next commit (A10 hardening, not a new result)

Three gaps the verifier found in the A10 artifacts, fixed before A1:

1. **The prove script did not assert the exact tallies or inventory.** A copy of the archive with
   every file duplicated printed `8/22` and still passed. The script now asserts the exact
   corroborated-win tallies (4/11, 4/11, 0/10, 3/4) and the exact inventory (exactly 111
   `*.jsonl.gz`, with no chain present in both plain and `.gz` form), so a duplicated or
   partially-unzipped archive fails.
2. **`backup_route_5hop/gen1_139bed8f59d1` is an incomplete episode** — no telemetry sidecar and no
   `duel.verdict`. That is why that folder has 5 chains but 4 verdicts. Now stated in the README and
   asserted by the prove script.
3. **Wording:** `duel.verdict.achieved` is already telemetry-gated (`objective_claimed AND
   loot_corroborated`). The tallies are **corroborated wins**, not raw claims. The README's "raw
   flags / corroboration is in the audit" wording was wrong and is corrected.
