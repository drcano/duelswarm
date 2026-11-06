"""Anchor the pre-registration into a hash-chained log BEFORE data (non-negotiable).

Hashes the frozen registration artifacts and appends a `prereg` event to the
tamper-evident chain `data/prereg.jsonl` (same EventLog the duel uses). Committing
that file to git stamps "registered before data" into both git history and the
hash chain — any later edit to the doc/graph/analysis changes the content hash, so
`verify_anchor()` flags it and the change must be logged as a dated amendment.

Idempotent: re-running with unchanged artifacts is a no-op; changed artifacts
append a `prereg.amendment` event (never a silent rewrite).

Offline, deterministic, no API, no credits.
Run:  .venv/bin/python scripts/preregister.py            # anchor / amend
      .venv/bin/python scripts/preregister.py --verify   # check chain + current hashes
"""
import hashlib
import subprocess
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarm.eventlog import EventLog

ROOT = Path(__file__).resolve().parent.parent
# Committed provenance (NOT data/, which is gitignored): the anchor must live in
# git for the "registered before data" guarantee to hold.
PREREG_LOG = ROOT / "docs" / "prereg.jsonl"
ARTIFACTS = [
    "docs/PREREGISTRATION.md",
    "docs/archive/COEVO_PREREGISTRATION.md",
    "config/lineage.yaml",
    "swarm/lineage.py",
    # NOTE (2026-10-27 one-engine cut): the decision-experiment rig + lineage-analysis peripherals
    # (analyze_lineage, power_analysis, orienteering, measured_duel, prove_checkpoint1, power_v4,
    # run_decision_experiment) were deleted with the consolidation, so they are no longer hashed
    # here (verify would crash on the missing files). The anchor chain still records their original
    # registration; a fresh pre-registration is deferred to the built sandbox (Dante, 2026-10-27).
    # Experiment A — the floor's target-mediation under an adversarial red (added to the
    # manifest before any Exp-A data; the frozen artifacts above are unchanged).
    "docs/prereg/EXP_A.md",
    # Increment 1 (2026-10-26 brief) — objective-driven red (intent, map-blind) + real synthetic
    # crown data; frozen before the paid data-theft run. The named map-blindness assertion and the
    # synthetic-crown generator are the load-bearing registered artifacts.
    "docs/prereg/INCREMENT_1_DATA_THEFT.md",
    "swarm/crown_data.py",
    # Amendment (2026-10-29) — swarm/live_agent.py is pinned so the EXACT ran red prompt
    # (RED_AGENT_SYS, the OBJECTIVES enum, and the assert_red_map_blind rail) is HASH-ANCHORED,
    # not merely attested by the doc amendment + the runtime map-blind check. This pins the whole
    # module (the house pattern for source artifacts), so any later edit to red's prompt OR the
    # surrounding engine now requires a dated amendment — tamper-evidence over the ran prompt. The
    # 2026-10-29 decision-neutral loot-on-own affordance (no grounding/auto-fire) is the first
    # change recorded under this pin. Amendment (2026-10-29, audit MEDIUM-4): frontier_awareness now
    # builds red's per-turn awareness from the RED-ACTOR events only (mirrors red_toolkit_untried), so
    # the channel's map-blindness is ENFORCED by an actor filter, not inherited from EnvState.apply's
    # allowlist; its selftest now plants non-red discovery/boundary events with ground-truth names and
    # asserts awareness is byte-identical (it BITES if the filter is removed). RED_AGENT_SYS, the
    # OBJECTIVES enum, and assert_red_map_blind are UNCHANGED.
    # Amendment (2026-10-29, Task 1 — full per-turn I/O persistence): run_red_agent gains an optional
    # WRITE-ONLY `io_sink` that, when wired by the driver, records red's EXACT per-turn cognition — the
    # assembled system prompt (once, by sha), the exact user prompt red was conditioned on, its FULL raw
    # completion (reasoning included), the parsed action, and the exact tool result it received — into a
    # hash-chained sidecar pinned into the main chain. DECISION-NEUTRAL: the sink is write-only, nothing
    # it captures re-enters red's inputs, and the loop's choices are byte-identical with or without it
    # (asserted in the selftest, which also end-to-end cold-verifies the captured record). RED_AGENT_SYS,
    # the OBJECTIVES enum, assert_red_map_blind, and frontier_awareness are UNCHANGED; the map-blindness
    # selftest is EXTENDED to bite on the new system-actor `io.record` pin (it can never reach red).
    # Amendment (2026-10-30, seq 50 — readiness A5 / SEQ50 Part 2): assert_red_map_blind + the awareness
    # assembly now scan the EPISODIC MEMORY channel — what red READS (episodic_recall, folded exactly as
    # run_red_agent folds it) and WRITES (memory_write, flattened so a GT name nested in a structured
    # lesson is caught) — for _map_tokens, extended to the scope (in_scope/out_of_scope) and oracle-output
    # (cred_seam.chain) classes. A one-time GT leak into memory would compound into every future recall;
    # the guard now bites before memory is wired. RED_AGENT_SYS and OBJECTIVES UNCHANGED; the map-blind
    # selftest bites on a planted GT name in recall, in a nested write, and in the awareness assembly.
    "swarm/live_agent.py",
    # Increment 2 (2026-10-27) — the real-telemetry, label-free blue detector, frozen before its
    # verification run. The detector + its air-gap guard are the load-bearing registered artifacts.
    "docs/prereg/INCREMENT_2_REAL_DETECTOR.md",
    "swarm/sensor_real.py",
    # Interleaved duel (2026-10-27) — the deterministic turn-interleaved engine + its fixed cadence
    # and blue thresholds, frozen before the paid canonical run (Increment C).
    # Amendment (2026-10-29, Task 1 — full per-turn I/O persistence): run_interleaved_duel gains an
    # optional `io_sink` passed STRAIGHT THROUGH to run_red_agent (red's cognition persistence). The duel
    # semantics, cadence, thresholds, blue detector, and the red/blue air-gap are UNCHANGED; this threads
    # a write-only logging sink only.
    "docs/prereg/INTERLEAVED_DUEL.md",
    "swarm/live_blue_agent.py",
    # Stealth vs detection (2026-10-27) — benign baseline + quiet (assumed-breach) red + a
    # discriminating (login-graph) blue, frozen BEFORE any stealth measurement (paid Part 5). The
    # benign model, the discriminator, and the free proof that the contest is real are load-bearing.
    # Amendment (2026-10-28d, seq 39) — benign_baseline gains `topology_spec()`: the PHYSICAL
    # projection of the already-registered logical model (per-host tier -> segment -> CIDR, the
    # loud-entry designation `web01` struts/CVE-2017-5638, and the Constraint-1 credential seam). The
    # LOGICAL model is UNCHANGED — host_pairs, net_flows, the per-tick rates, and the one crown edge
    # (db-bastion/backup -> db-core) are byte-identical; this only says WHERE each registered host
    # sits on the wire and how a LOUD breach on web01 COMPOSES to the crown. The seam: web01 holds a
    # harvestable reused cred authorizing dba01 (the ONE anomalous bootstrap hop), then red rides the
    # registered legit admin chain dba01->db-bastion->db-core, harvesting at each hop — map-blind, no
    # single cred reaching the crown (pre-registered as topology, not tuned per outcome). The 3
    # infrastructure hosts (dc-01/jump-01/decoy-fin) are added by the GENERATOR, not to the model.
    # This does NOT target oos_executed=0 — the floor reading stays a MEASURED byproduct of a run.
    "docs/prereg/STEALTH_DETECTION.md",
    "swarm/benign_baseline.py",
    "scripts/prove_stealth_detection.py",
    # Amendment (2026-10-27b) — the honest Part-5 setup: red DISCOVERS the living-off-the-land path
    # map-blind across varied, seed-derived entries (never the handed start host); frozen before the
    # paid measurement so the stealth rate is earned by discovery, not predetermined by the entry.
    "scripts/prove_stealth_setup.py",
    # Unopposed success-rate baseline (2026-10-27): matched-tier red + the pre-registered
    # N-seed list + the rate metric, frozen before the paid measurement.
    "docs/prereg/UNOPPOSED_SUCCESS_RATE.md",
    # Experiment campaign (2026-10-22 brief) — designs + runners frozen before their data runs.
    # H1 reasoning-vs-recall, H2 floor-causality, the falsification battery, and the measurement
    # apparatus (the reconciler + the primary telemetry record) that defines every metric.
    "docs/archive/EXPERIMENT_DESIGNS.md",
    # Amendment (2026-10-29, audit MEDIUM-3) — prove_control_reasoning gains a provenance STAMP only:
    # every output + its boot log is marked counted=False / provider / non_nebius, so the uncounted
    # frontier-model control (--provider != nebius) can never be mistaken for a counted Nebius
    # measurement. The experiment DESIGN (conditions, metric, no-LLM floor) is UNCHANGED — this is a
    # provenance label, not a change to registered intent. prove_one_engine asserts the stamp present.
    "scripts/prove_control_reasoning.py",
    "scripts/prove_floor_causality.py",
    "scripts/prove_falsification.py",
    # Amendment (2026-10-28) — the reconciler (live_truth) was CORRECTED, logged here as a dated
    # §11 amendment (never a silent rewrite of the apparatus). A source audit of the first arsenal
    # live runs found its witness matchers produced FALSE NEGATIVES: it read a flow's `dst` but the
    # real inner pivots are Falco-connect records keyed `dst_ip` (conntrack is L2-blind to intra-
    # bridge traffic), it matched a legacy ".crown" dotfile but the real crown is /home/dbadmin/
    # pii.json, and it keyed syscalls by name while claims carry an IP. So it FLAGGED genuine,
    # telemetry-witnessed pivots/loots (observe1 + the 8/8 baseline all re-derive flagged:2 -> 0).
    # The fix adds a sensor-agnostic flow accessor, a caller-supplied crown-filename marker, and an
    # IP->name resolver — correctness, not tuning to green a number; live_telemetry (emission) was
    # already faithful and is UNCHANGED. Rationale in docs/design-log/2026-10-28-*.
    # Amendment (2026-10-28b) — the SYMMETRIC tightening, logged after Dante's source-verification: the
    # lateral witness no longer accepts a bare `dport=22` flow (red's recon scans :22, so a connect
    # alone was a false-POSITIVE vector). A pivot now needs a COMPLETED auth (T1021 sshd Accepted) or
    # the ENTAILED crown read (a crown-file read ON the destination implies a real session there). This
    # removes a lie-about-a-pivot path, the mirror of the 2026-10-28 false-negative fix — again
    # correctness, not tuning. Run B still corroborates (lateral via Accepted-password + entailed read).
    # Amendment (2026-10-28c, seq 38) — the lateral T1021 witness is tightened to a COMPLETED ssh
    # auth and nothing weaker. The bare `"T1021" in techs` tag is DROPPED: Falco tags both a plain
    # :22 connect AND the per-connection `sshd-session`/`sshd-auth` fork as T1021, and BOTH occur for
    # a FAILED login — observed live on wks-01 (sshd-session fork + `Failed password`, a host red
    # never held a valid cred for). A pivot now corroborates ONLY on the sshd "Accepted password/
    # publickey" success line from the destination's OWN service log (index_telemetry marks it
    # _AUTH_OK_SENTINEL), the T1190/T1210 web-exploit fault, or the entailed crown read. This is
    # STRICTER than the proposing brief, which offered sshd-session as a witness; the source audit
    # showed that fork is not auth-success, so it was excluded. Counts UNCHANGED: the clean seed, the
    # arsenal-first A/B, and the 8/8 unopposed baseline all re-derive flagged/corroborated identical
    # (db-core carries the Accepted line + the entailed read in every lateral-claim episode). A biting
    # self-test holds: an sshd-session fork / bare T1021 (no Accepted) stays FLAGGED. Rationale:
    # docs/design-log/2026-10-28-reconciler-witness-and-killchain-fixes.md.
    "swarm/live_truth.py",
    "swarm/live_telemetry.py",
    # Enterprise navigation-adaptation contrast (2026-10-22) — the coarse-vs-enriched episodic
    # memory experiment, frozen before its paid data run. Design + runner + substrate.
    "docs/archive/PREREG_ENTERPRISE_ADAPTATION.md",
    "swarm/episodic.py",
    # Amendment (2026-10-29, audit MEDIUM-2) — the TCB is now in the freeze set. The whole proof
    # rests on these six: the gate (the chokepoint + single effect primitive), the hash-chained log
    # writer, both floor auditors, the spine (state-advances-only-on-confirmation law), and the
    # frozen mediation oracle. Until now only git history attested they were unchanged between runs;
    # hash-anchoring them makes any edit a dated amendment, same as every other registered artifact.
    # (static_coverage.py is pinned at its post-HIGH-2 state — run_effect now tracked; the gate and
    # the other five are pinned as-is.) This closes the same family as the open §10 external-witness gap.
    "swarm/gate.py",
    "swarm/eventlog.py",
    # Amendment (2026-10-29, audit MEDIUM-1) — audit.py aligned to reverify_floor so the two
    # code-independent auditors AGREE on oos_executed when both run on the production (unified-live)
    # chain: it now reads scope from floor.boundary (`in_scope`) + roe (`scope_by_actor`, per-actor)
    # as well as a `scope` event, audits each EXEC against the ACTING actor's authorized scope, and
    # no longer excuses a gate.allow by an unrelated block (only downstream non-gate.allow byproducts).
    # Its selftest now cross-checks both auditors on a committed paid chain (equal oos_executed) and
    # make test runs it. reverify_floor is the reference and is UNCHANGED. The anti-confirmation-bias
    # cross-check is strengthened, not weakened (rejected: "drop to one auditor").
    "swarm/audit.py",
    "redteam/reverify_floor.py",
    "swarm/spine.py",
    "scripts/mediation/static_coverage.py",
    # Phase B (2026-10-29) — claim-2 baseline: can a map-blind red read the crown via gate-ALLOWED
    # actions while the floor holds (oos_executed=0)? Frozen BEFORE any Phase-B paid data: N=10 of a
    # fixed 12-seed list, turn budget 44, blue observe-only, instrument at post-Phase-A HEAD 240aac4.
    # The head-hash of THIS anchor is committed before the first paid seed (rail #1).
    "docs/prereg/PHASE_B_CLAIM2_BASELINE.md",
    # Amendment (2026-10-29, Task 2 seq 48) — pin the capability-ceiling METRIC and the Task-1 integrity
    # AUDITOR before any Task-2 oracle/ablation run scores against them. capability_ceiling.py is the
    # measured-gap scorer (red's achieved funnel vs the ground-truth optimal chain) — a post-hoc, stdlib,
    # no-swarm SCORER whose GT firewall leak_test enforces; pinning it means the metric cannot move after
    # seeing results (a metric that can move is not a metric). verify_io_sidecar.py is the stdlib cold
    # auditor that re-walks the Task-1 full-I/O sidecar and its main-chain pins (tamper / tail-truncation
    # / pin-edit all bite); pinning it makes the integrity auditor itself tamper-evident — the record Task
    # 2 diagnoses off is load-bearing, so unlike the general-purpose verify_chain.py it is pinned. Neither
    # file is on red's live path (red's import closure is unchanged), and the frozen TCB is untouched.
    "scripts/validation/capability_ceiling.py",
    "redteam/verify_io_sidecar.py",
    # Amendment (2026-10-29, Task 2 seq 49) — the Task-2 pre-registration: the capability-ceiling /
    # best-of-k / primitive-vs-strategy-ablation protocol, frozen BEFORE any paid Task-2 run. Pins the
    # protocol document AND the THREE held-out variant ground_truths (disjoint seeds 2001/2002/2003,
    # distinct seam/crown, ceilings 4/6/4) so the generality set cannot be cherry-picked post-hoc. The
    # pre-commitments: in-sample seeds 1337-1346 (ceiling 5); oracle turn budget 44 (matched to the
    # Phase-B measured red); best-of-k = 3; ablation predictions fingerprint_service_on_inner->RESOLVE,
    # interface_enum_on_owned->RESOLVE, map_blind_cred_targeting->RELOCATE — a fix that lifts in-sample
    # but not held-out is rejected. The metric is seq 48; the frozen TCB is untouched. No paid Task-2 run
    # until this anchor lands.
    "docs/prereg/TASK2_CEILING_ABLATIONS.md",
    "docs/held-out/app_crown_4hop/ground_truth.json",
    "docs/held-out/backup_route_5hop/ground_truth.json",
    "docs/held-out/mgmt_crown_3hop/ground_truth.json",
    # Measured arm (2026-10-30, seq 51) — the claim-3 monitor-erosion pre-registration, frozen BEFORE
    # the first paid generation: the no-blue control (= claim 2) so claim 3 is a DIFFERENCE, the
    # stealth-triple + erosion-curve statistics (slope/CI/G/N/null), the pathology falsifiers
    # (diversity collapse / disengagement / intransitivity), the fixed external yardsticks (oracle
    # ceiling + a frozen Hall-of-Fame panel), the memory-on/off control, and the transfer eval on the
    # held-out ranges. Also dates SEQ50 Part 3 (D1 earned credential). The frozen TCB is untouched
    # beyond the recorded live_agent (seq 50) + live_blue_agent (memory-on) amendments.
    "docs/prereg/MEASURED_ARM_EROSION.md",
    # Amendment (2026-11-04, seq 52) — the behavior-descriptor redesign. The old 4-D descriptor
    # (entry, breadth, stealth, depth) SATURATED on the unified seam range: the Nov-4 paid run put
    # 9/9 crown-reaching episodes in one cell, red_diversity=1/54 (the first falsification the range
    # caught). The new 4-D descriptor (path_idiom, foothold_technique, turn_bin, cred_idiom) binds to
    # signals that vary on red's OWN chains; the Section-1 bite test on the Nov-4 archive via the
    # committed code path reports cells>=4. Pinning swarm/population.py hash-anchors the new descriptor
    # (and the Evolver / MAP-Elites archive / fitness it ships), so any later descriptor change — e.g.
    # claim 1's range-adding generalization of _bd_path_idiom — becomes a dated amendment. Three
    # superseded prereg-manifest docs are archived to docs/archive/ in the same seq-52 amendment.
    "swarm/population.py",
    # Amendment (2026-11-06, seq 58 — brief v3 A6/I3) — pin the files that DEFINE RED AND THE RUN, so
    # a silent change to how red operates or how a paid run is configured becomes a dated amendment the
    # same as the floor and the gate. live_red.py is the red agent/OODA + tool surface; llm.py is the
    # provider pin + model router; topo_to_compose.py builds the range and its compose/ground-truth;
    # live_recon/live_fingerprint/live_pivot/live_lateral are red's effect primitives; and
    # live_arms_race_run.py is the paid run harness (it now re-verifies this registration and records a
    # launch-registry line before any spend). Pinning them does not freeze development — it dates it.
    "swarm/live_red.py",
    "swarm/llm.py",
    "swarm/topo_to_compose.py",
    "swarm/live_recon.py",
    "swarm/live_fingerprint.py",
    "swarm/live_pivot.py",
    "swarm/live_lateral.py",
    "scripts/live_arms_race_run.py",
]


def _hashes():
    out = {}
    for rel in ARTIFACTS:
        p = ROOT / rel
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _git_head():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return None


def _git_branch():
    """Record the CURRENT branch, not a hardcoded one — seq 6 froze a since-deleted
    `arms-race-blindspots`; this derives it so the anchor can never go stale again."""
    try:
        b = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT,
                           capture_output=True, text=True, timeout=5).stdout.strip()
        return b or None
    except Exception:
        return None


def _last_prereg(log):
    for e in reversed(log.entries()):
        if e["action"] in ("prereg", "prereg.amendment"):
            return e
    return None


def anchor(rationale=None):
    log = EventLog(PREREG_LOG)
    cur = _hashes()
    prev = _last_prereg(log)
    if prev and prev["data"].get("artifact_hashes") == cur:
        print("prereg already anchored with identical artifacts — no-op")
        print(f"  anchored hash: {prev['hash'][:16]}…  seq={prev['seq']}")
        return log
    action = "prereg.amendment" if prev else "prereg"
    payload = {
        "registered_on": date.today().isoformat(),
        "branch": _git_branch(),
        "git_head": _git_head(),
        "artifact_hashes": cur,
        "note": ("initial registration before any corpus data"
                 if action == "prereg" else
                 "artifacts changed after anchoring — dated amendment (§11)"),
    }
    # Optional one-line rationale (--rationale "<why>"): the WHY of this amendment, IN-PAYLOAD, so a
    # reviewer tracing the chain finds it here instead of a docstring one hop away. Absent when not
    # passed — existing amendments stay valid (the field is optional). See docs/prereg/RATIONALES.md.
    if rationale:
        payload["rationale"] = rationale
    e = log.append("research", action, payload)
    ok, bad = log.verify()
    assert ok, f"chain broken at {bad}"
    print(f"{action} anchored: seq={e['seq']} hash={e['hash'][:16]}…  chain OK")
    for rel, h in cur.items():
        print(f"  {h[:12]}  {rel}")
    return log


def verify_anchor():
    if not PREREG_LOG.exists():
        print("NOT ANCHORED: data/prereg.jsonl does not exist")
        return False
    log = EventLog(PREREG_LOG)
    ok, bad = log.verify()
    if not ok:
        print(f"CHAIN BROKEN at seq {bad}")
        return False
    prev = _last_prereg(log)
    if not prev:
        print("chain OK but no prereg event found")
        return False
    drift = {r: (prev["data"]["artifact_hashes"].get(r), h)
             for r, h in _hashes().items() if prev["data"]["artifact_hashes"].get(r) != h}
    print(f"chain OK ({len(log.entries())} events); last anchor seq={prev['seq']}")
    if drift:
        print("  ARTIFACTS CHANGED SINCE ANCHOR (re-run to append an amendment):")
        for r in drift:
            print(f"    {r}")
        return False
    print("  all registered artifacts match the anchor")
    return True


if __name__ == "__main__":
    if "--verify" in sys.argv:
        sys.exit(0 if verify_anchor() else 1)
    rationale = None
    if "--rationale" in sys.argv:
        i = sys.argv.index("--rationale")
        rationale = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
    anchor(rationale=rationale)
