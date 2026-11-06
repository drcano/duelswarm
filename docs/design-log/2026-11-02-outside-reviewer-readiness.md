# Outside-reviewer readiness pass — CC brief (2026-11-02)

Executed before the public push. Six items that would otherwise bounce a cold reviewer. One item
is a measurement-path UX fix (make verify); the rest are docs/metadata hygiene. No TCB touched.
Planner wrote the specs; CC commits; planner cold-verifies after.

## 1. Replace top-level README.md and CLAUDE.md with the drafted versions

Both drafts already sit in the working tree (planner-authored, uncommitted):
- `/README.md` — top-level README written for strangers (no inside jargon, four claims each with
  a falsifier in plain English, three commands to verify, pointer to the deep docs).
- `/CLAUDE.md` — refresh to the current source-of-truth list (adds the Oct-29 brief, Oct-29
  planner handoff, Nov-2 cleanup brief, and `docs/prereg/RATIONALES.md`), adds `make verify` to
  the commands section. Section-2 provider-policy text already in place.

Verify once per section with `git diff --stat`; nothing in `swarm/`, `redteam/`, or
`scripts/mediation/` should change.

## 2. `make verify` UX: deferred line prints DEFERRED, exits 0; add `make verify-strict`

Current `make verify` fails on the last line (`preregister --verify`) because seq-51 is deferred to
the first paid run. First impression a reviewer gets: red failure. Fix the UX without hiding the
truth:

```makefile
verify:               ## cold re-derivation of every pinned invariant from the raw chains (no Docker/API key)
	$(PYTHON) scripts/verify_chain.py data/wall/range_0.jsonl
	$(PYTHON) redteam/reverify_floor.py data/wall/range_0.jsonl
	$(PYTHON) redteam/verify_io_sidecar.py --selftest
	$(PYTHON) redteam/verify_provider_pin.py --selftest
	$(PYTHON) scripts/mediation/static_coverage.py
	$(PYTHON) scripts/redteam_gate.py
	$(PYTHON) scripts/prove_falsification.py --selftest
	$(PYTHON) docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
	@echo "DEFERRED: preregister --verify anchors seq-51 at the first paid run; see docs/prereg/RATIONALES.md"
	-$(PYTHON) scripts/preregister.py --verify

verify-strict:        ## verify with no deferred lines (fails until seq-51 anchors; used for CI post-anchor)
	$(PYTHON) scripts/verify_chain.py data/wall/range_0.jsonl
	$(PYTHON) redteam/reverify_floor.py data/wall/range_0.jsonl
	$(PYTHON) redteam/verify_io_sidecar.py --selftest
	$(PYTHON) redteam/verify_provider_pin.py --selftest
	$(PYTHON) scripts/mediation/static_coverage.py
	$(PYTHON) scripts/redteam_gate.py
	$(PYTHON) scripts/prove_falsification.py --selftest
	$(PYTHON) docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
	$(PYTHON) scripts/preregister.py --verify
```

The `-` prefix on the last line of `verify` makes Make ignore the exit code; the explicit `@echo`
prints DEFERRED first so a reviewer sees the labeled deferral, not a bare failure. `verify-strict`
is the CI target once seq-51 anchors.

Cold-verify: `make verify` exits 0 with "DEFERRED" visible in output; `make verify-strict` exits 1
on the same deferred line (bites as before).

## 3. docs/ top-level attic pass

The current `docs/` top-level has 150+ files mixing current research with hackathon-era one-shot
proofs. A reviewer browsing `docs/` should see the current authoritative artifacts, not a
workbench. Move the following to `docs/archive/` (preserving git history; `git mv`):

**Phase-boundary proof artifacts (superseded by current proofs + cold re-derivations):**
- `brick0_substrate_proof.txt`, `brick1_discovery_proof.txt`, `brick2_fight_proof.txt`,
  `brick3_counter_offensive_proof.txt`, `brick4_coevolution_proof.txt`,
  `brick5_env_coevolution_proof.txt`, `brick6_instrument_proof.txt`,
  `brick6_reflexivity_curve.svg`
- `l1_live_discovery_duel_seed1337.jsonl`, `l1_live_gate_proof.txt`,
  `l2_uninstrumented_duel_seed1337.jsonl`, `l2_uninstrumented_floor_proof.txt`,
  `l3_beacon_proof.txt`, `l3_real_beacon_duel_seed1337.jsonl`, `l4_coevo_proof.txt`,
  `l5_instrument_live.json`, `l5_instrument_proof.txt`, `l5_reflexivity_curve.svg`,
  `l5_tail_at_scale.txt`, `l6_killshot_log.jsonl`, `l6_killshot_report.json`,
  `l6_killshot_report.txt`
- `m1_multiflag_range_proof.txt`, `m2_frontier_proof.txt`, `m3_scorer_proof.txt`,
  `m5_coevolve_proof.txt`, `m6_blue_fights_proof.txt`, `m6_contested_duel.jsonl`,
  `m7_blue_terrain_shaper_proof.txt`, `m7_mtd_campaign.jsonl`, `m7_static_control.jsonl`
- `n0_equifax_boot_log.jsonl`, `n1_pivot_boot_log.jsonl`, `n1_pivot_proof.txt`,
  `n1_recon_boot_log.jsonl`, `n1_recon_proof.txt`, `n2_live_red_boot_log.jsonl`,
  `n2_live_red_proof.txt`, `n2n3_tiered_boot_log.jsonl`, `n2n3_tiered_proof.txt`,
  `n3_live_blue_boot_log.jsonl`, `n3_live_blue_proof.txt`, `n4_arms_race_boot_log.jsonl`,
  `n4_arms_race_proof.txt`, `n_live_flip_boot_log.jsonl`, `n_live_flip_proof.txt`
- `v3_floor_adversarial_boot_log.jsonl`, `v3_floor_adversarial_proof.txt`,
  `v3_full_chain_boot_log.jsonl`, `v3_full_chain_proof.txt`, `v3_real_cve_boot_log.jsonl`,
  `v3_real_cve_proof.txt`, `v3_real_detect_boot_log.jsonl`, `v3_real_detect_proof.txt`
- `d1_credential_chain_boot_log.jsonl`, `d1_credential_chain_proof.txt`,
  `d2_zoned_traversal_boot_log.jsonl`, `d2_zoned_traversal_proof.txt`,
  `d3_multiservice_foothold_boot_log.jsonl`, `d3_multiservice_foothold_proof.txt`,
  `d4_autonomous_agent_boot_log.jsonl`, `d4_autonomous_agent_proof.txt`,
  `d4_telemetry_chain.jsonl`, `d4_turnlog_seed1.jsonl`, `d4_turnlog_seed3.jsonl`,
  `d4_turnlog_seed4.jsonl`, `d4_turnlog_seed5.jsonl`
- `h2_floor_causality_proof.txt`, `h2_floor_causality_telemetry.jsonl`
- `counted_seed_11.jsonl`, `counted_seed_12.jsonl`, `counted_seed_20.jsonl` through
  `counted_seed_26.jsonl`, `counted_enterprise_frontier_seed_0_*.jsonl`,
  `counted_enterprise_frontier_seed_1*.jsonl`
- `coevo_curve_22gen.svg`, `coevo_curve_live.svg`, `coevo_curve_t1.svg`,
  `coevo_live_curve.svg`, `coevo_live_sweep.jsonl`, `coevo_multiseed.jsonl`,
  `coevo_multiseed.svg`, `coevo_multiseed_live.jsonl`, `coevo_multiseed_live.svg`,
  `coevo_sweep_22gen.jsonl`, `coevo_sweep_live.jsonl`, `coevo_sweep_t1.jsonl`,
  `coevo_t1_diversity.jsonl`, `coevo_t1_diversity.svg`
- `ablation_ladder_boot_log.jsonl`, `ablation_ladder_proof.txt`
- `control_reasoning_boot_log.jsonl`, `n_live_flip_*` (listed above)
- `smoke_report.json`, `smoke_seed1337.jsonl`
- `kill_shot.png`, `kill_shot.svg`, `dashboard.jpg`, `dossier.jpg`, `report.jpg`
- `deception.jsonl`, `deception.svg`, `duel_visual.html`, `episodic_liquid.json`,
  `enterprise_arms_race_series.jsonl`
- `engagement_seed2_transcript.txt`, `engagement_seed3_transcript.txt`,
  `engagement_seed4_transcript.txt`, `engagement_seed5_transcript.txt`
- `env_boundary_live_proof.txt`, `external_egress_blocked_proof.txt`,
  `gateway_residual.md`, `live_eviction_proof.txt`, `live_validation_enterprise.log`,
  `measured_duel_proof.txt`, `measured_duel_scripted.jsonl`,
  `measured_duel_smoke_proof.txt`
- `range_curriculum.jsonl`, `range_curriculum.svg`, `regret_terrain.jsonl`,
  `regret_terrain.svg`, `model_catalog_probe_2026-10-19.txt`

**Superseded top-level markdown docs:**
- `AUTONOMY_MEMORY_BUILD_RESULT.md` (superseded by current design-log)
- `CLAIM_EVIDENCE_TABLE.md` (superseded by brief + prereg.jsonl)
- `COEVO_PREREGISTRATION_AMENDMENT_B_DRAFT.md`, `COEVO_PREREGISTRATION_AMENDMENT_DRAFT.md`,
  `COEVO_PREREGISTRATION.md`, `COEVO_RESULTS.md` (superseded by `prereg.jsonl` + current brief)
- `DUELSWARM_FALSIFICATION_REPORT.md`, `DUELSWARM_PAPER_ADDENDUM.md`,
  `DUELSWARM_PREREGISTRATION_FALSIFICATION.md`, `DUELSWARM_RESEARCH_BRIEF.md`,
  `DUELSWARM_RESEARCH_GROUNDING.md` (all pre-thesis-pivot, superseded by current brief)
- `EXPERIMENT_DESIGNS.md`, `EXPERIMENT_reasoning_vs_recall.md`, `FALSIFICATION_REPORT_V3.md`,
  `FULL_BUILD_BRIEF.md`, `P1_PILOT_RESULT.md`, `PHASE2_ARMS_RACE.md`,
  `PHASE2_ENTERPRISE_ARMS_RACE.md`, `PREREG_ENTERPRISE_ADAPTATION.md`,
  `mhbench_openstack_setup.md` (if not already attic'd in Section 1)

**Keep at docs/ top level:**
- `DuelSwarm_Build_Tracker.md` (the claims board per CLAUDE.md)
- `PREREGISTRATION.md` (the pre-reg process explainer)
- `design-log/`, `held-out/`, `mediation/`, `prereg/`, `prereg.jsonl`, `research/`, `runs/`,
  `tasks/`, `experiments/`, `ablation_trials/`, `archive/`, `arms_race_preserved/`,
  `build-bundle/`

If `docs/archive/` does not exist, create it. If any filename collides with an existing
`docs/archive/` entry, prefix the moved file with `2026-11-02-`. Use `git mv` so history is
preserved.

Cold-verify after: `ls docs/` returns a tight list (the keep set above + archive/), `git log
--follow` on any moved file shows unbroken history.

## 4. docs/runs/README.md with the "immutable historical records" note

The planner has drafted it: `/mnt/user-data/outputs/runs_README.md`. CC commits it to
`docs/runs/README.md`.

The file names what the per-run archives contain and explains why older chains carry older field
names (the chain is append-only). A reviewer greps the repo and finds historical mentions of
`nebius_host_guard_active`, `tavily-live`, etc. in old chains; this doc tells them that is
intentional and points at the current-invariants index.

## 5. CITATION.cff at the repo root

The planner has drafted it: `/mnt/user-data/outputs/CITATION.cff`. CC commits it to the repo root.
Standard GitHub citation metadata; makes the repo citable.

## 6. CONTRIBUTING.md at the repo root

The planner has drafted it: `/mnt/user-data/outputs/CONTRIBUTING.md`. CC commits it to the repo
root. Codifies the discipline (pre-registration, one engine, cold re-derivation at source,
decision-neutrality, floor-penetration-is-a-result, one-provider-per-run, air-gap). A reviewer
sees how the repo wants to be engaged with.

## 7. Confirm no stale top-level README survives

The old top-level `README.md` was flagged stale in CLAUDE.md. The planner's new draft replaces it
in Item 1. CC runs `git log --follow -- README.md | head` to confirm the new file is tracked, and
`cat README.md | head -5` shows the new opening paragraph (starts "A sandboxed cyber range for
studying...").

## 8. attic/ spot-check

`attic/` already contains `data/`, `redteam/`, `scripts/`, `swarm/`, a stub `README.md` (413
bytes), and `mhbench_openstack_setup.md` (moved there in Section 1.4 of the cleanup brief). CC
runs a secret-scan for provider API-key assignments, `sk-ant-` tokens and lab-password patterns over the tree
to confirm no credentials ever landed in archive files. Expected: zero matches. Reports the output.

## Commit discipline

One commit per numbered item; one line per commit stating the done-check. Use
`git config user.email drcano@ucsd.edu` (standing instruction). No chain write (no TCB touched;
nothing to amend). Nothing pushed; the push is Dante's.

## Cold-verify (planner, after all seven items land)

- `git diff seq-50-anchor-sha..HEAD -- swarm/ redteam/ scripts/mediation/` is empty (TCB untouched).
- `make test` and `make duel-dry` both green.
- `make verify` exits 0 with "DEFERRED" visible in output.
- `make verify-strict` exits 1 on the deferred line (bites).
- `ls docs/` returns only the keep set + archive.
- `grep -c -E 'nebius_host_guard_active|tavily-live|_assert_nebius_host' $(find . -type f ! -path './.venv/*' ! -path './attic/*' ! -path './.git/*' ! -path './docs/archive/*' ! -path './docs/runs/*' ! -path './docs/design-log/*')` returns 0 (live tree clean; historical chains and design-log preserved).
- CITATION.cff validates against the CFF 1.2.0 schema (optional, offline).

Then Dante runs the pre-push audit (secrets grep over `git log -p --all`), confirms clean, pushes
to `github.com/drcano/duelswarm`.
