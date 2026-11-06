# DUELSWARM — FULL BUILD BRIEF (plan of record)

**Updated 2026-10-22 · branch `real-range` · supersedes the framing in `HANDOFF.md`, `CANONICAL_BUILD.md`, `SCOPE_AND_CLEANUP.md`, `DuelSwarm_Build_Tracker.md` on any conflict.**
**Standard: AIRTIGHT, not fast. Nothing scripted or hardcoded. No bloat. Everything verifiable — logs for everything. This is a research-grade instrument; treat it like one.**

---

## 0. North Star — what we are actually building

The deliverable is the **sandbox itself: a faithful, self-contained snapshot of future
AI-vs-AI cyber conflict.** A real enterprise network where a fully autonomous, adaptive AI
**attacker** and a fully autonomous, adaptive AI **defender** genuinely fight — real tooling,
real telemetry, real stakes — co-evolving on top of the one thing that does not move: **the
floor + the log.** You run that real conflict, and the four claims fall out of the record.

Build for a **complete, real conflict world — NOT minimum-viable-to-measure.** Every host on
the attack surface is a genuinely exploitable real CVE service (no placeholders on any path an
agent can take); every foothold is a real exploit landing a real shell; every lateral move is
a real exploit fired from the shell red earned on the previous host; the defender sees only
real sensor telemetry and fights back with real containment; and every beat is a hash-chained,
independently re-derivable event. The claims are the **readout**, not the build target — the
build target is the world, and the world must be real end to end.

Nothing is proven yet. Every datum collected on the pre-convergence build is discarded; proof
is re-collected on the airtight engine, from the hash chain, independently re-derived.

## 1. The invariant — the only two things that do not move

- **The floor / gate** (`swarm/gate.py`): a deterministic reference monitor. Complete mediation — every effectful action checked against a per-actor authorized set *before* it runs; default-deny; actor- and intent-agnostic. Backed by network segmentation so an out-of-scope host is unroutable even if the string parser slips.
- **The log** (`swarm/eventlog.py`): SHA-256 hash chain, append-only, tamper-evident; re-derived cold by independent auditors (`redteam/reverify_floor.py`, `swarm/audit.py`) that share no code with the gate.

Everything else — attacker, defender, terrain, memory, monitors — is **liquid** and must be genuinely adaptive, genuinely autonomous, genuinely real. No scripted beats. No hardcoded exploit/CVE/host tables on any live path. No oracle (neither side reads the other's log or labels). No fabricated detections or forced containment.

## 2. Canonical architecture — ONE of each (the F1 engine)

| Role | The ONE canonical implementation | Non-negotiables |
|---|---|---|
| **Red (attacker)** | `swarm/live_swarm.run_red_frontier_loop` (Incalmo-lineage belief/frontier planner) + support layer: `env_state`, `attack_graph_service`, `netmodel`, `live_recon`, `live_fingerprint`, `live_vector`, `live_weapon`, `live_msf`, `msf`, `exploit`, `live_pivot`, `live_postex`, `arsenal`, `polymorph`, `beacon`, `red_tools` | Observe → infer CVE → confirm vs **live** MSF catalog → fire real exploit through the gate. No service→CVE/module table on the live path. Vantage-aware multi-hop. |
| **Terrain** | `swarm/range_gen.generate_range(scale="enterprise")` (MHBench-lineage, `third_party/mhbench`) | One generator. Realistic enterprise, scaled to hardware. Floor-shape decoupled from range (fixed range / varied scope) so Q1 is not confounded. Hosts supplied as data — gate must not hardcode them. |
| **Defender (blue)** | `swarm/live_swarm.run_blue_frontier_loop` (+ `blue_response`) on real telemetry `sensor_stack` + `sensor_real`; real effects `live_blue` + `blue_contain`; `blue_fast` (MTTC/MTTD), `overseer` (LLM-in-TCB), `blue_counter_recon`, `canary`, `forensics` | **Blind + air-gapped**: sees only sensor telemetry, never red's actions/labels/log. No hardcoded detections, no forced containment. |
| **Memory** | `swarm/episodic.py` (+ `degeneracy.py`) | Technique-level lessons only; proven to never leak map/goal. Evolves across episodes. |
| **Telemetry / ground truth** | `swarm/live_telemetry.py` + `swarm/live_truth.py` (Falco syscalls + conntrack + service/auth logs) | The targets' own hash-chained record decides what happened; an unwitnessed claim is FLAGGED, never trusted. |
| **Driver** | `scripts/arms_race_enterprise_frontier.py` | Drives the frontier red (and, for the duel, the frontier blue) on `range_gen` enterprise terrain, threading episodic memory, degeneracy, and the reconciler. |
| **Verifier** | `scripts/verify_live_run.py`, `verify_chain.py`, `preregister.py`, floor proofs (`redteam_gate`, `prove_env_boundaries`, `mediation/*`, `host_egress_firewall`) | Re-derive every pop cold; a run counts only if it passes the independent gate. |

## 3. The slop (why it is not airtight today) — inventory + entanglement

The same ladder is implemented 2–3× and the live/kept paths still run the weak copies. The duplicates are **not free-standing** — they share primitives with keepers, so this is extract-and-re-point refactoring, not a delete sweep.

**Keeper → duplicate import edges that must be severed/re-pointed first:**
- `swarm/live_swarm` → `live_red` (the engine itself depends on the single-hop red's primitives) — extract the shared primitives into the canonical engine/support layer, retire only the redundant agent loop.
- `arms_race_enterprise_frontier`, `live_arms_race_run`, `prove_n2n3_tiered`, `prove_d2_zoned_traversal` → `live_red` (and `prove_d2` → `live_terrain`, `live_traverse`).
- `red_tools` → `red_agent`; `gen_corpus` → `red_agent`.
- `llm` → `provider_local`; `arsenal` → `lineage`; `instrument` → `coevolve` + `red_recon`.
- `prove_brick1/2/3/6` → `red_recon` (and `prove_brick6` → `coevolve`, `env_coevo`).
- `instrument_live` → **scripted** `liquid_stage` (Q1/Q6 instruments ride the scripted/oracle co-evo layer — rebuild on the honest engine or park until they can run honestly).

**The `run.py` hub (the worst one):** `run.py` is the fabricated demo (scripted red via `run_dry`; a blue that hardcodes detections and forces `isolate_host`). It is imported by the canonical driver `arms_race_enterprise_frontier` **and** by floor/corpus keepers (`prove_corpus_floor`, `gen_corpus`, `prove_spine`), and it pulls in `blue_agent`, `morpheus`, `report_html`, `term`. **Sever every keeper from `run.py`**; `run.py` becomes a pure, clearly-labeled dry demo that no proof or live path imports — or is retired outright.

**The oracle / scripted co-evo layer (rule-1 violations, must go):** `scripts/liquid_stage.py` (scripted `run_episode`, stubbed outcomes) + the learned monitor that read red's labeled actions off the shared log (`swarm/arms_race.py` oracle path + `swarm/llm_eval.py` host leak) + `scripts/real_run.py`. The defender must be rebuilt blind (§2).

**Duplicate reds** → fold to the frontier red: `live_agent`, `red_agent`, `red_loop`, `red_recon`, `live_traverse`, and `live_red` (keep its primitives, drop its loop).
**Duplicate terrain** → `range_gen`: retire `live_terrain` (re-point `prove_d4`, `prove_d2`).
**Duplicate arms drivers** → `arms_race_enterprise_frontier` + `arms_series`: retire `arms_race_enterprise`, `arms_race_run`, `live_arms_race`, `coevolve`, `env_coevo`.
**Duplicate blue** → frontier blue: retire `blue_agent` (fabricates); fold `blue_llm.was_correct`, keep `blue_detect` oracle mode for the ablation only.
**Scaffolding / small dups, no status question** → cut: `battlefield`, `range_adversary`, `economy`, `morpheus`, `provider_local`, `term`, `response` (→`blue_contain`), `report_html` (→`report`), `lineage` (provenance → fold into `arsenal`).

**Hardcoding liabilities to eliminate (rule 1):** `gate.py` hardcoded range host names; `report.py`/`report_html.py` hardcoded Struts/CVE-2017-5638 narrative; `arsenal.py` model-id vs `PREREGISTRATION.md` panel mismatch; residual hardcoded hosts/IPs in `prompts.py`, `forensics`, `parser_fuzz`.

**Auditor drift:** `audit.EXEC_ACTIONS` ≠ `reverify_floor.EXEC` — give them one shared source so the two independent re-derivations cannot silently disagree.

## 4. Real capability gaps (NOT slop — genuine builds, after convergence)

- **`live_pivot.privesc` is a simulated stub.** Enterprise footholds land as root so it was never exercised. A faithful conflict needs real privilege-escalation exploits.
- **Blind full-capability defender** running the real detect→correlate→contain→forensics loop on real telemetry across the whole network and many runs (today: one service, oracle in the co-evo runs).
- **Enterprise scale** to the hardware limit (detect RAM/cores; grow `range_gen` realistically — more zones, services, hosts).
- **External log anchor** (tie the hash chain to an outside witness) for Q7 reproducibility.

## 5. Verification protocol (airtight — this replaces "make test green")

`make test` currently exercises the bloat, so green partly measures the slop. It is rebuilt to invoke **only** the canonical honest engine + floor/log proofs + the real experiment drivers. The real bar, for every claim:

1. The **canonical engine actually runs** (frontier driver dry selftest asserts crown-at-depth-≥2 from a non-entry vantage, no looping) — then the paid live run on real containers.
2. The **floor holds**, re-derived cold by two independent auditors (`reverify_floor`, `audit`) that share no code with the gate: `oos_executed = 0`.
3. The **log verifies** (hash chain intact; a one-byte change breaks it).
4. The **reconciler is clean**: every red claim witnessed by the targets' own telemetry; unwitnessed → FLAGGED.
5. The **run counts** only if it passes the independent `verify_live_run` gate.
6. **Logs for everything.** No number is cited that is not re-derivable from the chain.

## 6. Phases + gates (phase-gated; each gate verified by §5, not by the bloated suite)

- **Phase 1 — Converge & de-slop (in progress).** Sever keepers from `run.py`/scripted demo; extract shared primitives; retire every duplicate + the oracle/scripted layer; fix hardcoding + auditor drift; rebuild `make test` to the canonical set. **Gate:** one red, one terrain, one blind blue; canonical engine + floor proofs run with logs; zero scripted/hardcoded/oracle on any live path.
- **Phase 2 — Real capability.** Real privesc; blind full-capability defender; scale the enterprise range; kill the Q1 range-confound. **Gate:** faithful conflict runs end to end on real containers.
- **Phase 3 — Run the conflict, read the claims.** Live co-evolution on real containers; the four claims fall out of the hash-chained record, each independently re-derived; regenerate all data clean.
- **Phase 4 — Anchor + publish.** External log anchor; publish code + logs; refresh the status page from the real record.

## 7. Doc hygiene (de-slop the docs too, at the end of Phase 1)

Collapse the overlapping brief/status docs to this one plan of record + the live status page; move the superseded ones (`CANONICAL_BUILD.md`, `SCOPE_AND_CLEANUP.md`, `DuelSwarm_Build_Tracker.md`, stale `CLAUDE.md` Phase-2 claims, `posts-v2/`) to `attic/docs`. One source of truth.
