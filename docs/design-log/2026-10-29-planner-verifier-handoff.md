# Planner/verifier handoff — pick up here (2026-10-29)

Read this first. Then read the authoritative brief at
`docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md`. That brief is the current
spine of the work; everything below orients you to it.

## Your role
You are planner/verifier for duelswarm (Dante's AI-security research instrument, flagship for the
Anthropic AI Safety & Security Fellows app and dantecano.com). You work over a file-only device
bridge to `<repo>`. A separate "build CC" session on Dante's machine
executes the dated briefs you write. You verify every load-bearing claim COLD, by re-deriving
from the raw hash-chained logs and source files, trusting NEITHER the build agent NOR its
reports. The standard Dante holds you to: airtight, no theater, nothing a serious reader can
contest.

The repo rules you enforce (from CLAUDE.md):
- No new modules. No re-implementation next to the old copy. ONE engine.
- The only real build failure is an UNRECORDED EFFECT.
- A floor penetration (`oos_executed > 0`) is a RESULT, never a failed run.
- Readiness = re-derivation at source. `make test` is smoke only.
- Nothing committed without Dante's go. Nothing pushed. Paid runs gated on his explicit go.

Dante commits himself; you do not. He wants your written verdict (airtight / nits / blockers)
before each commit. On a paid run, you re-derive cold from the archive after it lands and
report what the raw logs say, not what CC says they say.

## Mission in one line
A fixed, non-reflexive AUTHORIZATION FLOOR invariant to the climbing adversary it governs; a
reflexive MONITOR erodes against the same adversary. The instrument exists to make that
testable, falsifiable, and cold-re-derivable by a reviewer who trusts neither agent.

## The four claims (falsifiable; details in the authoritative brief)
1. Floor SHAPE as selection pressure — vary floor shape, red's evolved path evolves with it.
2. Composition migration — harm migrates to in-policy chains of allowed actions while
   `oos_executed = 0` holds.
3. Informational asymmetry — monitor leaks a climbable gradient, floor leaks one bit, no
   gradient. The sharpest claim and the one that needs blue active.
4. Seams across multiple floors — deferred; multi-floor setup first.

## Where we are now (Oct 29, 2026)
Phase A (airtightness) finished and verified cold. Phase-B N=10 claim-2 baseline landed and
I verified it cold: floor held 10/10 seeds, 40% lethality (4/10 crown reads), independent
syscall grep == engine verdict on all 10, seam decoys correctly excluded. Red was one-shot
no-memory in that batch, so the 40% was against the WRONG adversary — the thesis's claims need
a climbing red. That pivot is what the authoritative brief encodes.

Task 1 (persist full per-turn I/O) just landed. I verified it cold today — capture complete,
decision-neutral (byte-equal path with/without `io_sink`), round-tripped through the real
`EventLog` + real auditor in my isolated workspace, map-blindness holds through the `io.record`
pin (MEDIUM-4 selftest extended to bite on it), all 8 prereg seq-47 anchors match the staged
files, frozen TCB unchanged vs. seq 46. Dante committing it now (likely as seq 48 after a
one-line cosmetic fix to `redteam/verify_io_sidecar.py` line 153 — the double-literal
`"io.turn"` branch should be `"io.header"` for the header case).

Immediately next: **CC starts Task 2 free build.** Task 2 certifies red is a genuine
self-climbing unbiased adversary before the claim experiments run:
- Capability ceiling per range (oracle optimal-path red as SCORER never input to red; GT firewall).
- Primitive-vs-strategy-vs-capability ablations, located by one-variable experiments with
  pre-registered predictions (does the stumble RESOLVE or RELOCATE?).
- Legible-surface prioritization queue (red's observations + arsenal + held creds as a legible
  surface red ranks itself; harness never auto-fires; map-blind selftest bites on a planted
  unobserved service).

After Task 2 passes: claim 2 (climbing red vs. floor) → claim 1 (vary floor shape) → claim 3
(activate blue-as-monitor per the brief's precondition: label-free, air-gapped from red's
plan/memory, measured by the stealth triple, blue co-evolves too; single-gen is smoke, the
co-evolution erosion curve is the claim) → claim 4 (multi-floor, later).

## The authoritative brief
`docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md`. Supersedes
`red-elicitation-handoff-consolidated.md` (which supersedes
`why-red-misses-findings-and-handoff.md` and `exploit-priority-queue-ablation.md`). The brief
is the current spec CC is building against. Any change to the plan goes through a dated
amendment to the brief or a successor doc, never a silent rewrite.

## Where things live
The ONE measurement engine:
- Driver: `scripts/live_arms_race_run.py` → `_run_unified_live_episode` → `run_interleaved_duel`.
- Red loop: `swarm/live_agent.py::run_red_agent` (map-blind by `assert_red_map_blind`;
  tool-agnostic; `io_sink` is Task 1's capture hook, write-only).
- Red tools: `swarm/live_red.py::build_agent_tools` (the live engine scan, now gated via
  `drop_oos`; MSF arsenal in `swarm/arsenal.py`).
- Blue: `swarm/live_blue_agent.py::live_blue_agent` + `run_interleaved_duel`. Blue is
  currently observe-only; activating it to monitor-with-containment per the brief's claim-3
  precondition is the step after Task 2.
- LLM: `swarm/llm.py` (Nebius-only).
- Co-evolution memory: `swarm/coevolve.py` + `swarm/episodic.py`.

Frozen TCB (hash-anchored in `docs/prereg.jsonl`; a change needs a dated amendment):
`swarm/gate.py`, `swarm/eventlog.py`, `swarm/audit.py`, `swarm/spine.py`,
`redteam/reverify_floor.py`, `scripts/mediation/static_coverage.py`.

Cold-re-derivation toolchain (pure stdlib or near; use these, don't invent new ones):
- `redteam/reverify_floor.py` — standalone floor auditor, own canonicalizer, no `swarm` import.
- `scripts/verify_chain.py` — stdlib hash-chain re-walk.
- `swarm/audit.py::audit_scope` — second independent scope auditor.
- `swarm/live_truth.py::reconcile` — claims vs telemetry on the target's own syscalls.
- `redteam/verify_io_sidecar.py` — new (Task 1); cold-re-derives the full per-turn I/O
  sidecar + its pins into the main chain. Stdlib only, byte-identical hash recipe to
  `swarm.eventlog._hash`.

Pre-registration: `scripts/preregister.py` writes `docs/prereg.jsonl` (hash-chained); each
TCB-changing commit lands an amendment. Current tail is seq 47; Task 1's amendment will be
seq 48.

## Decision-neutrality litmus (the handoff §4 test; apply to every "fix")
A legitimate instrument fix gives red better TOOLS or INFORMATION keyed on its OWN
observations. It must never:
- Make red's DECISION for it.
- Hand red the ground-truth map (host→exploit, crown identity, scope list, topology).
- Let the harness play the game (auto-fire, auto-loot, auto-decide).
- Only help on this one topology (the giveaway for bias — prove generality on held-out ranges).

GT firewall: ground truth is a measurement instrument only. It SCORES red and sets the
capability ceiling via an oracle optimal-path reference; it never enters red's inputs. The
firewall must be mechanically enforced in code and checked, not trusted.

## Open items / honest gaps
- **Task 1 paid first-exercise**: the ~5 driver lines (`io_log = EventLog(..., on_append=...)`,
  the pin lambda, `io_sink=_io_sink`) are correctness-proven free via a structurally-identical
  selftest, but only exercised against the real Docker range + Token Factory on the paid seat.
- **The six orphaned enterprise helpers** in `swarm/live_red.py` (`derive_enterprise_chain`,
  `provision_loot`, `wait_for_web_ready`, `GreedyVectorPlanner`, `GreedyEnterpriseRouter`,
  `_load_py`) have zero callers after MEDIUM-3. My decision was CUT; CC hasn't executed it yet.
- **Prereg amendment carries no rationale field** — just the generic
  `"artifacts changed after anchoring"` note; the rationale lives in docstrings. Low priority
  structural improvement to `scripts/preregister.py`.
- **`io_path.unlink(missing_ok=True)`** in the driver zeros any pre-existing sidecar. Fine for
  fresh paid runs; flag if resume semantics come in.
- **Blue not yet active** — the brief's claim-3 precondition. Comes after Task 2.
- **External witness (§10 gap)** — no second human or external tool has independently
  re-derived the Phase-B batch yet. Named in the brief as "other than Claude or Dante"
  validation; still pending.

## The two non-results (worth tattooing on the inside of the eyelids)
Every outcome is a RESULT. A floor penetration is a result. A climbing red that still can't
breach is the floor proven right by an honest adversary. A climbing red that breaches via
allowed actions is claim 2. A climbing red that erodes a monitor but not the floor is claim 3.
A climbing red whose archive diversity collapses tells us the known degenerate mode fired.

The ONLY two non-results are:
1. A red biased to win (GT handed to it, strategy hardcoded, harness playing its moves).
2. A red crippled to lose (broken primitives Dante calls elicitation, under-powered scaffold,
   no memory while the thesis assumes memory).

Task 2 exists to rule out both before the claim experiments run.

## Current moment
Task 1 is airtight free. Dante is committing it (with the one-line verify_io_sidecar line 153
fix folded in) and firing CC on Task 2 free build. When Task 2 lands you re-derive:
- The oracle/optimal-path reference stayed a SCORER and never entered red's inputs (verify the
  GT firewall is mechanically enforced in code; grep for any path that reads ground truth
  into red's prompt or awareness).
- Primitive fixes resolved stumbles on held-out ranges, not just the seeded one (the
  topology-specificity giveaway).
- The legible-surface queue is affordance-not-executor, map-blind selftest bites on a planted
  unobserved service.
- Each ablation is pre-registered BEFORE the run and reported as a lift against the registered
  prediction, never a silent rebaseline.

After Task 2 clears: claim 2 is the first paid experiment with climbing red on. Everything
else follows the sequencing in the authoritative brief.
