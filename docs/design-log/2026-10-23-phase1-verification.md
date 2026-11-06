# Phase 1 verification — cheat-sheet excision (VERIFIED at source + by execution)

Date: 2026-10-23
Author: the planning/verifier session, with Dante.
Branch `real-range`; verified commit `327befe` ("Phase 1 — excise the cheat-sheet
lineage (one engine, no orchestrator slop)"), committed 17:28 PT. HEAD at verification
time; nothing in the tree newer than the commit.

## Scope of this record
Claude Code is ONE phase into batch one (phases 1, 2, 2.5, 3, 4). It committed Phase 1
with a per-phase done-check message and went quiet; phases 2, 2.5, 3, 4 are not built.
This records the independent verification of Phase 1 only. Batch two is not green-lit.

## Method (how this was verified, not trusted)
The device bridge to the build host is file-only (no shell there), so the tree was
staged into an isolated container and the done-checks re-derived locally. No build
report was trusted; nothing was taken from a green `make test`. No Docker and no model
calls were used, so NO credits were spent. Two classes of check:
- Source: grep over the staged live tree (attic excluded), file/definition presence.
- Execution: the keepers' own selftests (no-Docker/no-API) run in-container, plus the
  independent cold floor auditor (`redteam/reverify_floor.py`) re-walking real and
  freshly-generated hash chains.

## Done-check results

1. Cheat-sheet lineage gone, tree-wide (the brief's Phase 1 done-check).
   `grep` over swarm/ + scripts/ + redteam/ for
   `red_tools | red_agent | RED_ORCHESTRATOR | BLUE_ORCHESTRATOR | from run import`
   plus the cascades and demo blue returns nothing live. The only residue anywhere is
   the keeper `run_red_agent` (the one red engine) and comments documenting the
   removal. `red_tools.py`, `red_agent.py`, `run.py`, `blue_agent.py`, `scripts/eval.py`
   do not exist; `def run_red_cascade/run_blue_cascade/run_*_scripted/run_blue_agent`
   are absent (deletions are real at the definition level, not just unreferenced).

2. The tree imports with no dangling references.
   `import swarm.live_weapon, live_lateral, live_swarm, prompts, live_agent, red_recon,
   range_gen, gate, spine, msf` → ok. Any importer still referencing a deleted module
   would have failed here; none did.

3. The four weapons ported CVE-keyed, cheat-sheet removed.
   `exploit_apache_cgi`, `exploit_weblogic`, `http_rce_request`, `http_rce_cves` now live
   in `swarm/live_weapon.py`, keyed on the CVE red infers (never a host->exploit map).
   The `_CTX`/`set_range_context` cheat-sheet (objective_host/objective_cve/in_scope_pivots)
   is gone; targets are explicit, no run-context fallback.

4. Keeper selftests green (run in-container, no Docker/API):
   - `swarm/live_weapon.py` — MSF-session and response/marker modalities both ground
     through the confirm->mutate spine (real `uid=`, never a self-report); an unknown CVE
     defers honestly; an OUT-OF-SCOPE target is gate-blocked even with a real weapon.
   - `swarm/live_swarm.py` — the one engine runs with cascades removed: the red frontier
     loop walks recon->exploit->recon_from->privesc->cred_pivot->exfil to two crowns,
     oos=0, red can lose; the blue frontier loop chooses from its lossy belief,
     gate-mediated, can lose; no fallback/scripted path (empty/LLMError aborts).
   - `scripts/wall.py --selftest` — 5 unseen ranges, 0 oos executed, chains 5/5.
   - `scripts/prove_falsification.py --selftest` — the falsification battery still BITES:
     the reconciler flags a fabricated foothold and fabricated loot, `verify_chain`
     detects a forged telemetry event, an honest run is not false-flagged.
   - `scripts/redteam_gate.py` — 9/9 out-of-scope addressing forms blocked, 8/8 egress
     bypasses blocked, 11/11 in-scope allowed, log tamper detected.

5. Cold floor re-derivation (readiness check #1), by `reverify_floor` (imports neither
   the gate nor audit.py; re-walks the SHA-256 chain with its own canonicalizer):
   - 5 fresh current-engine dry chains (wall): chain_verified, `oos_executed=0` each.
   - real enterprise live arms-race episode: chain_verified, `oos_executed=0`.
   - real `events.jsonl` and `eval_run_0.jsonl` eventlogs: chain_verified, `oos_executed=0`.
   - `records.jsonl` is a per-run SUMMARY format (not a hash chain); the auditor correctly
     cannot walk it (`first_bad=None`, `scope=None`) — a format mismatch, not a floor break.

## Scope decisions pulled forward (documented in the commit, verified sound)
`run_red_cascade`/`run_blue_cascade` and the demo `blue_agent` were deleted in Phase 1
(the brief parked them in 2/3) because Phase 1's own grep demands zero orchestrator-prompt
references and those were the last users. Nothing is folded FROM them; the frontier loops
(`run_red_frontier_loop`/`run_blue_frontier_loop`) survive intact, confirmed by the
`live_swarm` selftest exercising both. Phases 2/3 still owe the frontier-loop/`blue_response`
fold into the single agent engine.

## Watch-items carried into later phases
- wall.py oos-block stress is deferred to Phase 2 (rewired onto the dry anti-beeline red,
  so `blocked==0` legitimately). The wall now re-derives only "0 oos executed + chains
  verified," not "red attempted oos and the gate blocked it every time." That gate-blocking
  proof currently lives in `redteam_gate`, the `live_weapon` OOS case, and
  `prove_env_boundaries`. Phase 2 verification MUST confirm the adversarial oos probe is
  wired back into the wall — this is where a hollow green could hide.
- `exploit_weblogic` still calls `subprocess.run(["docker","exec",...])` directly to read
  its marker file. Expected now; Phase 4's "one effect path" grep must catch and route it
  through the single gate-dispatched effect primitive.

## One residual (needs compute; NOT a Phase 1 blocker)
A brand-new post-Phase-1 Dockerized live LLM run, re-derived cold, is the gold-standard
floor check. It needs Docker + credits on the build host and was not run here (ask before
any credit spend). The floor auditor is demonstrably correct and every real chain available
re-derives to zero; the enterprise episode above was written minutes before the Phase 1
commit, so it is current-engine-adjacent.

## Note on `make test`
Green except `swarm/beacon.py`'s selftest, which asserts `observed==False` "without Docker"
and fails only when a live range is up on the build host (environment sensitivity, fails
identically at HEAD; not a Phase 1 effect). For a fully-green `make test`, run with the
range down.

## Verdict
Phase 1 is VERIFIED — at source (grep clean tree-wide, deletions real, weapons CVE-keyed)
and by execution (imports clean, five keeper selftests green, floor re-derives `oos=0` cold
on fresh and real chains). It is clear for Claude Code to proceed to Phase 2. The two
watch-items above are the specific things Phase 2/4 verification must not let slide.
