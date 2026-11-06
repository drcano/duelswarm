# duelswarm — session handoff bundle (2026-10-26, ~22:40 PT)

Paste this into a new chat to resume. You (the new chat) also have Dante's memory (profile + prefs);
this bundle carries the PROJECT state that memory doesn't.

## Your role — read first
You are Dante's **PLANNER / VERIFIER** for duelswarm. **You do NOT build.** A separate Claude Code (CC)
session builds on Dante's deploy host; you write briefs + design-logs and **verify every CC claim at
source by re-derivation — never trust a build report.** Your bridge is **FILE-ONLY**: stage files with
`mcp__remote-devices__device_stage_files` into `/mnt/user-data/uploads/…`, then `Read`/`Grep`. You have
**no shell, no git, no docker** on his host. Repo: `<repo>`, branch
**`real-range`**, a native-Linux deploy host. Deliver briefs via `SendUserFile`; place
design-logs in the repo via `device_commit_files` (stage to `/mnt/user-data/outputs/` first, then commit).

## The project
duelswarm: an autonomous AI-vs-AI (purple-team) security sandbox. Entry in the **Nebius×NVIDIA Global AI
Hackathon** (Devpost, deadline **Oct 30 2026**); also feeds Dante's **Anthropic AI Safety & Security
Fellows** application. Research matters more to him than winning.

## The thesis (why it's built this way)
You can't read an autonomous agent's intent (Rice's theorem); in a reflexive AI-vs-AI world detection
always loses; the only thing that holds is a deterministic **floor** (authorization gate + complete
mediation + default-deny) + a **tamper-evident hash-chained log**. **Claim 2:** harm accrues via a chain
of individually-ALLOWED actions (valid credential logins) while the floor records `oos_executed=0` —
demonstrated by credential-based lateral movement to the identity tier. A penetration is a RESULT to
study, never a build failure; the only real failure is an **unrecorded effect**.

## The two floors — DO NOT conflate
- **HARD floor = segmentation** (`topo_to_compose.to_compose`: every data-plane net `internal:true` +
  masquerade-off DNAT `ingress` + the §E host firewall `scripts/host_egress_firewall.py`). SAFETY. Must
  ALWAYS hold. A break HALTS the run — it is not a result.
- **EXPERIMENTAL floor = the gate policy** (`swarm/gate.py`, tier-line boundary). The OBJECT OF STUDY.
  `oos_executed` is MEASURED, never a target; holding and breaking are both results; a break is a studied
  penetration (provided it was recorded).
- Falsifier `swarm/uninstrumented.py` (raw `docker exec`, no gate) proves segmentation holds without the
  gate. Twin independent auditors: `swarm/audit.py` + `redteam/reverify_floor.py` (`EXEC_ACTIONS`
  byte-identical drift guard). `probe_boundary` is the kernel-level hard-floor check.

## The rails (load-bearing — hold them, don't relax for the deadline)
No bloat, no parallel universes, **one clean engine** (one red, one blue, one range generator, one
instrument). Nothing hardcoded on the live path; red is **objective-blind** (learns a credential only by
harvesting a host it owns; crown / credential graph / Tier-0 never enter its view). **Readiness =
RE-DERIVATION AT SOURCE**; a green `make test` is a smoke check, NEVER the done-signal. The sandbox is NOT
built to produce any result — report whatever happens, **no tuning** toward a breach OR a hold. All
**counted** model calls through **Nebius Token Factory** (HF/OpenRouter = disqualifier;
`provider_anthropic` control-only, never counted). Everything in the Docker range; no real external
targets. **Nothing pushed / nothing off `real-range` without Dante's explicit go. Ask before any
credit/paid spend.** Commit git author **Dante Cano <drcano@ucsd.edu>** (NOT [redacted] /
[email redacted]). Capture design discussions in dated `docs/design-log/` files.

## Architecture (one engine each; where things live)
- **Instrument (trusted, don't modify):** `gate.py` (`dispatch`; `run_effect` = the one effect site),
  `eventlog.py` (SHA-256 chain), `spine.py` (confirm→mutate), `audit.py` + `redteam/reverify_floor.py`
  (twin auditors), `scripts/mediation/static_coverage.py` (AST one-effect-path oracle — note: 2 raw sinks
  are "UNGOVERNED, confirmed by hand" and benign: `exploit.run_command` urlopen is gate-mediated at every
  caller, `range_runtime.provision_ad_dc` poll is read-only), `uninstrumented.py`, `live_telemetry.py` +
  `live_truth.py` (Falco + reconciler).
- **Range (ONE generator):** `swarm/topo_to_compose.py` — `range_gen.py` is DELETED, its surface re-homed
  here (`generate_unified`, `generate_range`, `build_sourced_range`, `to_compose`, `host_posture`,
  `load_pool`, `source_cves`, `write_range`, `emit_range_topology`). Also `netmodel.py`,
  `mhbench_schema.py`, `range_runtime.py` (`bring_up_generated_range` + `provision_ad_dc`, gate-logged),
  `range_adversary.py`. 6 segments incl. a REAL Samba AD DC (`dc-01.range.lab`); credential-graph
  primitives planted owned-host-only (ssh key, cached-DA NTLM, plaintext DB cred, backup cred).
- **Red (ONE engine):** `live_agent.run_red_agent`; `live_red.py` `run_sim_red` + `run_discovery_duel`
  (re-homed from the DELETED `live_duel.py`); `live_pivot.py` (`cred_pivot`, `kerberoast`,
  `pass_the_hash`, `dc_auth` — all `gate.dispatch` + spine); `live_weapon`/`exploit`/`live_lateral`/
  `live_postex`/`msf`/`arsenal`.
- **Blue (ONE engine):** `live_blue_agent.py` `run_blue_fight` + `DryBlueRouter` + `blue_decision`
  (score = confidence × blast_radius_contained × reversibility_weight ≥ 0.45; reversible wt 1.0,
  irreversible 0.6) + the D3FEND action set (reversible: suspend/lock/isolate/decoy; irreversible:
  auth-cache-invalidate/kill-session/revoke/shutdown). `blue_fast.py` = UTILITIES ONLY (`run_fast_blue`
  DELETED; `run_belief_blue` retired). Emits canonical `blue.contain` beat. `blue_contain`/`blue_detect`/
  `sensor_stack`/`deception`.
- **Paid-run driver:** `scripts/live_arms_race_run.py` (`_run_live_episode`; `max_turns=40` at L186 dry /
  L233 paid); `scripts/verify_live_run.py` (dry e2e via `run_discovery_duel(use_llm=False)` AND the live
  scorer); `scripts/arms_race_enterprise_frontier.py`. Nebius guard: `swarm/llm.py::_assert_nebius_host`.

## State (as of 2026-10-26 ~22:30 PT)
Phases 0a→5-setup DONE + committed on `real-range` (unpushed, ~121 commits ahead). Orchestrated range
booted (seed 1337, 9 containers). **PtH → Tier-0 confirmed end-to-end** (the core credential-reuse edge,
real Impacket). `make test` green; `static_coverage` PASS; `reverify_floor` cold `oos_executed=0`; hard
floor `probe_boundary` ok=true live; real Falco capture (24 events, crown witness fires). Instrument
untouched; one engine red + blue verified; zero dangling refs to deleted modules (range_gen / live_duel /
run_belief_blue / run_fast_blue).
**3 realism findings HELD, NOT tuned** (genuine Samba-vs-Windows): Kerberoast `KRB_AP_ERR_INAPP_CKSUM`;
secretsdump remote-NTDS fails (Samba LDB/TDB, not `NTDS.dit`); BloodHound reaches LDAP but Samba
terminates on LDAP signing. **External validation is PARTIAL and honest:** PtH IS real-tool-validated;
the other three are real Samba scope limits (full Windows fidelity = the heavier GOAD-style scope call,
not needed for the core claim). State this in the demo/prereg; don't gloss it.

## In flight — the execution brief just handed to CC (`CC-brief-execute-launch.md`)
CC runs everything autonomously, reports each stage, stops only on a real problem:
- **Part A (free):** §E `--verify` (NOPASSWD sudoers grant); **git-author history rewrite** to a single
  `Dante Cano <drcano@ucsd.edu>` identity (backup branch `real-range-preauthorfix` first — some commits
  are under `[email redacted]`, the [redacted]-linked email); prereg freeze + lock (tier-line
  boundary + the 3 findings as pre-registered EXPECTATIONS, `preregister.py` anchor); cleanups (the
  `topo_to_compose as range_gen` alias, `arms_race_check` bare import).
- **Part B (PAID, cheap):** integration SMOKE, seed 1337, ~10 turns, `use_llm=True` — PLUMBING ONLY
  (foothold lands, 3 streams capture on live containers, reconciler runs, floor cold on the live chain,
  hard floor holds). Turn-starved by design; NOT a research datapoint; not banked.
- **Part C (PAID):** the full run, seeds 1337 + one more, **40 turns each**, auto-proceed ONLY if the
  smoke's plumbing is clean. Capture all three streams.
- **Credit envelope:** bounded to smoke + 2-seed×40; Dante posting the brief = his go; CC can't exceed it
  without a fresh go.

## What to verify when CC reports back
- **Part A:** git author — CC must paste `git log --format='%an <%ae>' | sort -u` BEFORE and AFTER (after
  = single drcano identity) + confirm the backup branch exists. **You can't run git from the bridge — say
  so; verify from CC's pasted output.** Prereg: anchor seq+hash, `live_telemetry` frozen, tier-line +
  findings pre-registered. Cleanups: `make test` green after; re-grep the alias is gone.
- **Smoke (Part B):** plumbing only — 3 streams on live containers, reconciler ran, `reverify_floor` cold
  on the live chain, hard floor held, no crash. It is NOT a datapoint; don't let it be banked.
- **Full run (Part C):** the measured outcome — crown reached? pivot depth? the floor as a RESULT
  (`chain_verified` + `oos_executed`, whatever its value; a nonzero value is a studied penetration, never
  tuned back; an unrecorded effect is the only failure); hard floor never moved (`probe_boundary`); the 3
  findings as they manifested; token spend; fidelity labeled LIVE.

## Verifier gotchas (hard-won this session)
- **STALE MIRROR / GHOST FILES (bit me twice).** `/mnt/user-data/uploads` accumulates stale copies; a
  deleted file lingers as a ghost and corrupts greps. For any STATE claim (deletions, "zero refs",
  current file content), **`rm -rf /mnt/user-data/uploads/duelswarm` and re-stage FRESH before grepping.**
- `device_stage_files` fails the WHOLE batch if one path is missing (a deleted file) — drop it, re-stage.
- **Pure functions you CAN execution-verify** by extracting + running in your container with `python3 -I`
  (did this for the NTLM/MD4 known-answer and `blue_decision`). Runtime / Docker / sudo / `make test` /
  live-run claims you CANNOT reproduce — take as CC-reported and SAY so explicitly; the code producing
  them is what you verify.
- The `docs/design-log/` files are the durable record — read them for specifics instead of asking CC.

## Design-logs written this session (read for detail)
`2026-10-25-realistic-breach-grounding.md`, `-full-enterprise-realism-external-validation.md`,
`-two-floor-safety-architecture.md`, `-phase0a-hard-floor-verification.md`, `-phase1-kickoff-decisions.md`
(verification ledger for Phase 1 inc1–4), `2026-10-26-phase2b-phase3-verification.md`,
`-phase3-completion-and-bluefast.md`, `-designed-path-boot-decision.md`, `-phase5-audit-and-readiness.md`
(+ verifier confirmation), `-launch-readiness-audit.md` (CC's full-codebase audit).

## What's next to discuss (why the new chat)
The build is firing live. Fresh space for: the live-run results when they land (verify them per above);
the **demo video** (the money shot = the credential chain to the tier line with the floor re-deriving
cold); the **hackathon submission** (thin honest README + demo URL + repo; state the partial-external-
validation honestly); the **Fellows** framing; and whatever Dante wants to dig into. Nothing is pushed —
pushing + the final submission are still his explicit calls.
