# Instrument audit — are we airtight enough to START the experiments? (2026-10-29)

Planner/verifier full-codebase audit against the CLAUDE.md mandates (no bloat, one
engine, "the only real build failure is an unrecorded effect"). Four parallel read
agents swept disjoint slices; every load-bearing claim below was **re-derived cold at
source by me** (file:line), not taken on an agent's say-so. Two agent findings were
false (mirror artifacts) and are corrected at the end. Nothing in the codebase was
modified.

## Verdict (one line)
The base is solid enough to start collecting effectful-floor datapoints (claim 2,
composition migration): the gate, the hash log, the one duel engine, the capable
map-blind red, and §E are all sound and re-derive cold. But the **"complete mediation"**
half of the thesis is **not yet airtight**: red's recon/fingerprint first-contact
reaches targets ungated and unrecorded, and the self-check that is supposed to catch
exactly that is structurally blind to it. Close those two before the "every action is
mediated and recorded" claim is stated unqualified to a hostile reviewer.

## Where the build is (current planned phase — not 100% done, by design)
From the roadmap (design-log 2026-10-28-live-arms-race-roadmap-brief + handoff §10):
- **Phase 1 — populate the least-privilege range: ~complete.** 20-host benign range from
  `benign_baseline.topology_spec()`, §E enforced, capable red with the real MSF arsenal,
  reconciler honest. Two paid seeds diagnosed as instrument confounds; Tier-1 recon fix
  landed (`48ad966`).
- **Phase 2 — two-sided contest (active blue + stealth triple): built but not run.**
- **Phase 2.5 — composition migration (red vs floor, vary floor shape): the flagship;
  only needs Phase 1.** This is what the base is nearly ready for.
- **Phase 3 — co-evolution (cross-generation selection around the one live engine): the
  biggest remaining build.**
- **Non-code — external witness / log anchoring: open** (handoff §10; your own "biggest
  taken-seriously gap").

So: a solid base to begin asking claim-1/claim-2 questions, with Phase 3 and the external
witness still ahead. The findings below are what to close so the base is contest-proof.

---

## Findings (my severity calibration, not the agents')

### HIGH-1 — Ungated, unrecorded recon + fingerprint network reach  [verified cold]
Red's first network contact bypasses the gate and the chain. The effectful path does not
— so this is specifically a recon-phase mediation gap, not a breach of the exploit/pivot
floor.

- Connect-scan sweep: `t_scan` → `_recon` (live_red.py:992) → `scan_subnet`
  (live_red.py:243) → `live_recon.scan_many` (live_recon.py:97) → `_exec`
  (live_recon.py:30) → `gate.run_effect` (gate.py:34-46, a bare `subprocess.run`
  pass-through). This fires a real parallel TCP connect to every host in the swept range
  (default `.1`–`.16` × `scan_ports`) **before any gate call and with no chain record**.
  Only the hosts that answer are then handed to `reveal_real` (live_recon.py:128-163),
  which *does* `gate.dispatch` each responder and log a `discovery` event. So the gate and
  the log only ever see hosts that already answered an ungated probe.
- HTTP fingerprint: `ArsenalDriver.fingerprint` (live_red.py:501-517) → `_docker_sh`
  (live_red.py:314-327) → `run_effect` directly; issues real curl/wget//dev/tcp HTTP to
  `ip:port`, logs only a `"fingerprint"` event (live_red.py:515). `"fingerprint"` is **not**
  in `EXEC_ACTIONS`, so both floor auditors skip it. The LLM can aim `t_fingerprint`
  (live_red.py:1069) at an arbitrary `ip`.
- Contrast (why this is inconsistent, not by-design): the real exploit egress **is** gated
  — `real_struts_foothold` runs the RCE inside `gate.dispatch(src,"exploit",...)`
  (live_agent.py:290). `live_recon`'s own docstring claims "The scan is routed through
  gate.dispatch exactly like every other move" (live_recon.py:17-18) — the implementation
  of the live sweep does not. `_docker_sh` even mislabels `run_effect` as "the ONE effect
  path (gate.run_effect)" (live_red.py:315-316), conflating the bare subprocess primitive
  with gate mediation.

Why it matters: CLAUDE.md's one real build failure is "an unrecorded effect," and §7
expects the gate to *record the block* when red attempts an out-of-scope host (dc-01 /
jump-01 / decoy-fin). Under this path, red's scanner touches those hosts ungated; a block
is recorded only if an out-of-scope host both answers the sweep and is re-dispatched. A
serious reviewer can say: "you claim complete mediation, but your scanner connects to
every host in the segment, out-of-scope included, before the gate sees anything, and you
only log the responders." `oos_executed=0` remains true for effectful executions but is
blind to the recon phase's reach.

Fix: route the sweep and the fingerprint through `gate.dispatch` (as `reveal_real` and the
exploit path already do), so every probed target — in or out of scope — yields a
`gate.allow`/`gate.block` and the recon phase becomes auditable. Keep the batched sweep for
speed, but gate the target set first.

*Dynamic check still owed:* on a booted range, confirm the pre-sweep actually contacts an
out-of-scope IP in the segment (kernel segmentation may drop it — but that is the floor
being measured, not mediation; the mediation gap itself is static-certain).

### HIGH-2 — The mediation self-check is blind to the engine's effect primitive  [verified cold]
`scripts/mediation/static_coverage.py` is the frozen oracle that is supposed to prove
complete mediation. Its `EFFECTFUL` set (static_coverage.py:107-116) lists
`subprocess.run/Popen/...`, `os.system`, `socket`, `requests`, `urlopen` — **but not
`run_effect`**. Every engine effect goes through `run_effect`, and the oracle treats the
single `subprocess.run` *inside* `gate.run_effect` as class-1 and exempt
(static_coverage.py:96-101). It never inventories the `run_effect` call sites in
`scan_many` / `fast_web_sweep` / `_docker_sh`, and it only checks dispatch-domination for
`CAPABILITY_FUNCS = {"contain_host","drop_honeytoken"}` (static_coverage.py:105). So it
*assumes* run_effect is only reached via `gate.dispatch` and never verifies it — which is
exactly the assumption HIGH-1 violates. The oracle reports PASS while HIGH-1 exists.

Why it matters: "static_coverage passes" is currently not evidence of complete mediation
for the real engine. This is the check that should have caught HIGH-1.

Fix: make `run_effect` the tracked sink and assert every call site is dispatch-dominated,
except the explicitly TCB-owned ones (`gate.lifecycle`, telemetry reads) and the
deliberate `swarm/uninstrumented` falsifier channel. Closing HIGH-2 is how you keep HIGH-1
from recurring.

### MEDIUM-1 — The "two independent auditors agree" guarantee is weaker than it reads  [verified cold]
The hash-walk is genuinely triple-independent and the `EXEC_ACTIONS` sets are byte-identical
(audit.py:30-34 ≡ reverify_floor.py:23-25, guarded by audit.py:212). But the *scope* logic
diverges, and on the Phase-1 unified-live chains only one auditor actually runs:
- `audit.audit_scope` reads scope only from a dedicated `scope`-**action** event
  (audit.py:105-111). The unified-live chains don't emit one (scope lives in the `roe` /
  `floor.boundary` data), so `verify_chain.py` prints "not audited (log records no scope
  event)" and I had to hand-feed the scope to `audit_scope` to get a number on run2.
- `audit.py` excuses an out-of-scope `gate.allow` if its target was blocked elsewhere
  (audit.py:156-160); `reverify_floor` deliberately does not (reverify_floor.py:145). It
  also has no per-actor `roe` handling and uses aliases that reverify ignores.

On run2 both returned `oos_executed=0` (I ran both cold). But the practical effect is that
`reverify_floor` is the authoritative floor auditor for Phase-1 chains, and the "two
agree" framing overstates the cross-check. Fix: teach `audit.py` to read the unified-live
scope and align the gate.allow excusal, or formally designate `reverify_floor` as the one
floor auditor and drop the second-auditor claim for these chains.

### MEDIUM-2 — Pre-registration anchor excludes the TCB  [verified cold]
`scripts/preregister.py` freezes a fixed `ARTIFACTS` list "before data" (preregister.py:29-121)
and it does include `live_truth.py`, `live_blue_agent.py`, `benign_baseline.py`,
`live_telemetry.py`, `sensor_real.py`, `crown_data.py`, `episodic.py`. It does **not**
include the core TCB: `gate.py`, `eventlog.py`, `audit.py`, `redteam/reverify_floor.py`,
`spine.py`, or `scripts/mediation/static_coverage.py`. The floor, the log writer, and both
auditors — the parts the whole proof rests on — are not in the freeze set; today only git
history attests they were unchanged between runs. Fix: add those six to `ARTIFACTS` (cheap,
high value). This is the same family as the open §10 external-witness gap.

### MEDIUM-3 — More than one paid entrypoint; a direct-Anthropic path; a dormant live driver  [verified cold]
The one *duel* engine is correctly singular (see mandate check), but "the only
live-measurement entrypoint is live_arms_race_run.py" is literally false:
- `scripts/prove_control_reasoning.py` runs a real paid LLM loop
  (prove_control_reasoning.py:143-148), boots its own Docker range (:127), and with
  `--provider anthropic` routes to the direct Anthropic SDK (llm.py:225-227 →
  provider_anthropic.py:135,167). It is a **pre-registered reasoning-vs-recall control**
  (in preregister ARTIFACTS), not a second duel engine, and §11 explicitly allows uncounted
  non-Nebius controls — so this is NOT the automatic-DQ a hackathon reviewer would fear.
  But it spends tokens outside the `_episode` spend-guard, and its Anthropic arm must be
  unmistakably marked uncounted in its own output/log.
- `swarm.live_red.run_live` (live_red.py:2005) is a Nebius-paid (:2045),
  separate-enterprise-range (:2014, :2033) red driver. Its only reference is
  `inspect.getsource(run_live)` in prove_engine.py:199 — never a call. It is dormant, but
  it is a live-paid "measures a separate range" driver that `prove_one_engine` does not
  catch (its guard keys on a hardcoded deleted-file list, prove_one_engine.py:56-67).
- `smoke_test.py` makes one real Nebius call (sanctioned, `make smoke`).

Fix: if "one engine" is meant as "one paid entrypoint," gate/label these the same way
`_episode` is, and either delete `run_live` or add it to the one-engine guard as a
forbidden live driver. The guard itself should assert "no other module stands up a live
router + range," not just "these filenames are gone."

### MEDIUM-4 — Per-turn map-blindness is not machine-checked  [verified cold]
`assert_red_map_blind` (live_agent.py:171-186) checks only red's **static seed**; it is
called with `awareness_text=""` on the live path. Red's per-turn awareness is built from
`EnvState.from_log(log.entries())` over the whole shared chain (live_agent.py:323). No
active leak today, because `EnvState.apply` ingests only `discovery`/`state.mutate`
(env_state.py:106-123) and red's live discoveries are IP-keyed, so the ground-truth host
names in `floor.boundary` / `benign.*` events never surface. But the protection rests
entirely on that allowlist, and the awareness channel is never re-verified against this
range's ground truth. Fix: filter `frontier_awareness` to red-actor events (as its sibling
`red_toolkit_untried` already does) and extend its selftest to plant a `system`/
`floor.boundary`/`benign` event — so map-blindness of the awareness channel is proven, not
inherited. (Related dormant path: `recon_from` logs a `crown_data` discovery with the GT
crown name, live_red.py:856-863 — not wired into the live tool set today, but it would
enter red's belief if it ever were.)

### MEDIUM-5 — Nebius-only rail is env-conditional; the run doesn't witness the host  [verified cold]
`make_router("nebius")` is hardcoded for red and blue on the live path
(live_arms_race_run.py:666,669; live_red.py:2045), and `_assert_nebius_host` guards the
base_url (llm.py:26-33). But the guard is disabled by `NEBIUS_ALLOW_ANY_HOST=1`
(llm.py:28) and `base_url` is env-overridable (llm.py:131), and nothing in the run chain
witnesses the provider host. Fix: have the paid-run acceptance assert the guard was active
and record the resolved host (or at least the Nemotron model ids, which the chain already
carries). `config/models.yaml` is not in my mirror, so confirm the configured base_url is
a `nebius.com` host (the guard regex is `(^|\.)nebius\.com$`, llm.py:18 — a `nebius.ai` /
studio endpoint would be rejected and push operators to the bypass flag).

### MEDIUM-6 — §E `--verify` is less thorough than the run-time witness  [verified cold / dynamic owed]
The run's own `floor.boundary` witness is complete — on run2 I re-derived `ok=true`,
`host_gateway_reachable=false`, `internet_blocked=true`, `internet_reached=[]`,
`oos_tcp_reaches=[]` at `floor.boundary.data.uninstrumented_live`. But the standalone
`scripts/host_egress_firewall.py --verify` never tests internet-blocked (that witness lives
only in `uninstrumented.probe_boundary`), conflates "dropped" with "couldn't probe" in the
gateway check (no liveness precheck, host_egress_firewall.py:266-268 vs the guarded
`uninstrumented.py:118`), and SKIP exits 0 — so a caller trusting the exit code can't tell
SKIP from PASS. Harden `--verify`; the run-time witness itself is sound.

### LOW — cleanup / informational
- **Dead cluster (no-bloat violation):** `swarm/env_coevo.py` → `swarm/range_adversary.py`,
  and `swarm/instrument.py` ← `scripts/instrument_live.py` ← `redteam/stats_tail.py` — a
  self-contained lineage with zero live importers (verified by import grep). Plus unreferenced
  proofs: `killshot.py`, `prove_corpus_floor.py`, `prove_e2e_broad.py`, `mediation/parser_fuzz.py`,
  `mediation/reachability_probe.py` (and `prove_control_reasoning`/`prove_floor_causality` are
  registered standalone controls, runnable, not dead). Cut candidates; the 2026-10-27
  consolidation left them on disk.
- **Stale coverage map:** `static_coverage.py:67,82-84` still lists deleted modules
  `swarm/battlefield`, `swarm/deception` and the orphans `range_adversary`/`instrument`.
  Inert data (not imports), but a reviewer will notice; clean it in the same breath as HIGH-2.
- **Chain truncation/re-hash:** `eventlog.verify()` catches edits/reorders/mid-deletions but
  not tail-truncation or a full re-hash (eventlog.py:5-12, honest about it) — leans on git +
  the prereg anchor. Ties into MEDIUM-2 and the §10 external witness.
- **Minor:** `EventLog.append` swallows `on_append` exceptions (eventlog.py:59-63); non-gate
  append paths trust the caller's actor/action label (the reconciler cross-checks claims
  against telemetry, so this is backstopped); the gate egress parser is best-effort with
  kernel segmentation as the real backstop (gate.py:196-208) — floor penetrable at the
  parser is a thing to measure, not a core-gate bug.

---

## CLAUDE.md mandate check
- **One engine (the duel): HOLDS.** `live_arms_race_run._episode` routes `unified` →
  `_run_unified_live_episode` → `run_interleaved_duel` (live_arms_race_run.py:763); the
  generated+live branch hard-raises "RETIRED" (:185-192); `_run_live_episode` is gone;
  one-of-each imports resolve to a single live copy each (run_red_agent / run_blue_fight /
  run_interleaved_duel / topo_to_compose). Red and blue are both `make_router("nebius")`.
  Caveat: the guard proves properties of one file, not "only one paid entrypoint" — see
  MEDIUM-3.
- **No duplicate implementations: HOLDS.** Every capability is defined once; `live_red.py`
  (179KB) is a genuine orchestrator that imports the `live_*` helpers, not a re-implementation
  (verified: no duplicated/dead logic inside it). attic/ is not imported by any live module.
- **No bloat: holds.** What I first flagged as a "dead cluster" is parked apparatus for
  named future phases, not residue (Dante's correction, confirmed at source — see below).
  Every capability is still defined once and `live_red.py` is an orchestrator, not a
  re-implementation.
- **"Unrecorded effect is the only real build failure": VIOLATED on the recon path** —
  HIGH-1. This is the one that actually bites the mandate.

## Corrections to the sub-audit (kept honest)
- The dead-code agent reported "no attic/ directory exists" and "`make test` references a
  phantom `scripts/validation/`." Both are **false** — artifacts of my incomplete local
  mirror (I had not staged `attic/` or `scripts/validation/`; both exist on disk, the latter
  with all six files). `make test` is not broken on that line.
- The single-engine agent's CRITICAL-1/2 (second paid entrypoint / Anthropic path) are real
  as code but are a sanctioned pre-registered control, so downgraded to MEDIUM-3, not a DQ.
- Its `run_live` HIGH is real but dormant (no entrypoint) → MEDIUM-3.

## Appendix — run2 cold re-derivation (what I reproduced, trusting nothing)
Archive `docs/runs/2026-10-28-phase1-paid-run2/`, chain `episode01_seed1337.jsonl`
(548 events, head `1630dce…`):
- `reverify_floor`: `chain_verified=true`, `oos_executed=0`, `misses=[]`.
- `verify_chain`: VERIFIED (independent hash walk); `audit_scope` with scope hand-fed:
  `out_of_scope_missed=0` — agrees with reverify.
- Provenance: 44/44 moves LLM-driven, 0 silent fallback (`llm_duel=true`); 4 real gate
  blocks (`floor_status=HELD`); all 44 calls ultra-tier (matched-ultra).
- Reconciler re-run cold (mirroring `reconcile.inputs`): 2 claims, 2 corroborated, 0
  flagged — foothold on web01 (T1190 Struts fault) and the dba01 lateral (sshd "Accepted"
  completed auth, not a bare :22 connect). `achieved=false` is the honest negative.
- §E at `floor.boundary.data.uninstrumented_live`: `ok=true`,
  `host_gateway_reachable=false`, `internet_blocked=true`, `oos_tcp_reaches=[]`.
Every handoff §8 claim for run2 holds under independent re-derivation.
