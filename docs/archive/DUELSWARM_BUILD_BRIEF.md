# DUELSWARM — Master Build Brief ("GOAT mode")

**For:** Claude Code, working in `~/dev/duelswarm`
**Supersedes:** `docs/DUELSWARM_V2_BRIEF.md` (use this file; v2 is stale on priorities).
**Target:** Nebius x NVIDIA Global AI Hackathon, Coding & Agentic Engineering track. Build deadline **Oct 30, 2026**. Grand prize is the goal.
**Grounded in:** a full audit of the repo run on 2026-10-14 (dry-run executed, verifiers executed, code read). Findings and line numbers below are real, not hypothetical.

---

## 0. The thesis everything serves

> **Duelswarm is a control-evaluation testbed: an autonomous attacker and defender fight inside networks neither has seen before, under an authorization boundary that provably holds and a cryptographic log you can verify instead of trust.**

Judge-facing hero = **generalization**: agents adapting to randomized, unseen networks, governed and verifiable. (Chosen deliberately: the judging panel is ~9 NVIDIA engineers + ~10 Nebius DevRel/product + 3 Tavily + 1 ML researcher. Engineers reward capability they can't hand-wave; generalization is falsifiable on screen. See §9.)

Every task below either (a) makes that claim **true**, (b) makes it **legible**, or (c) makes it **verifiable**. If it does none of the three, don't build it.

---

## 1. Non-negotiables (integrity = the foundation, not caution)

1. **The deterministic gate (`swarm/gate.py`) is sacred.** It stays in red's execution path as the final, non-bypassable backstop. Any later overseer sits ABOVE it. Out-of-scope actions must NEVER actually execute.
2. **Every number shown anywhere (README, report, dashboard, video) comes from a real run.** No hardcoded metrics, no dry-run numbers under a "LIVE" label. (See §2 — this is currently violated.)
3. **≥1 runtime Nebius Token Factory call to an NVIDIA Nemotron model.** Keep the `_assert_nebius_host` guard in `swarm/llm.py`. Calling the model any other way is an automatic hackathon DQ.
4. **Everything offensive stays in the isolated Docker range.** Vulnerable-by-design hosts only. No "real-world mode."

---

## 2. AUDIT FINDINGS — fix these FIRST (P0). They are the credibility floor and three of them are currently false claims.

### 2.1 "Zero out-of-scope missed" is a hardcoded literal, not a measurement — CRITICAL
- `scripts/eval.py:86` sets `"out_of_scope_missed": 0` unconditionally (comment even says it *would* be >0 if bypassed).
- `scripts/verify_chain.py:93` literally prints the string `"0 missed"`: `print(f"\nScope: {len(allows)} allowed, {len(blocks)} blocked, 0 missed")`.
- **Nothing in the codebase audits whether an out-of-scope action actually executed.** The headline safety guarantee is cosmetic. A judge who opens `verify_chain.py:93` watches the "provably governed" claim die.
- **Fix:** write one real auditor, `audit_scope(log, scope) -> {allowed, blocked, missed:[...]}`, that re-derives the result independently of the gate: for every event representing an *executed* tool action against a target, canonicalize the target; if it is not in scope AND there is no matching `gate.block` for it, it's a MISS. Use this function in both `eval.py` and `verify_chain.py`. The `assert total_oos_missed == 0` only means something once this is computed.

### 2.2 The air-gap is false — blue reads red's answer key — CRITICAL
- `swarm/blue_detect.py:122` iterates `log.entries()`, filters `entry["actor"] == "red"`, and detects directly off red's own `gate.allow` events and their ATT&CK technique IDs (`line ~130`). `swarm/blue_agent.py`'s `correlate_event_log` tool description says it "reads the event log and correlates red team actions across 18 ATT&CK techniques."
- The docstrings claim "air-gapped from red; no access to red's plans." The code does the opposite. This is why detection reads ~100%: blue is reading the labeled solution. It also makes genuine emergence impossible.
- **Fix (two modes):**
  - `blind` (new default): blue detects from **container/telemetry only** — raw stdout/stderr/log strings — never from red's labeled `actor=="red"` action/technique entries. Give blue a *filtered view* of the log: it may see tamper-evident hashes and its own events, not red's semantic action labels.
  - `oracle` (kept for the ablation in §4): the current behavior.
  - Add a `blue_mode: blind | oracle` flag (config + CLI).
- Expect detection to drop below 100% in blind mode. **That lower, honest number is the stronger result** (see §4 ablation).

### 2.3 `make duel-dry` crashes on Python < 3.12 — CRITICAL (clone-and-run demo killer)
- `swarm/report_html.py:392` uses a multiline, nested-same-quote f-string that is only valid under Python 3.12+ (PEP 701). On 3.10/3.11 it's a hard `SyntaxError`; `run.py --dry-run` writes its data artifacts then crashes at the HTML render step (exit 1). No Python version is pinned anywhere.
- DevRel judges clone and run. Many are on 3.10/3.11. They hit an immediate crash on your one-command path.
- **Fix:** rewrite that f-string to avoid nested same-quotes/multiline (pull the inner `''.join(...)` and each cell expression into named variables, then interpolate). Add `python_requires`/a README note, and add a CI matrix (3.10, 3.11, 3.12) so this never regresses. Prefer making it 3.10-safe over pinning 3.12.

### 2.4 Honest dry-vs-live, everywhere — CRITICAL
- `grade.py` prints "NEBIUS_API_KEY not set — LLM agent mode untested." The committed `data/eval_results.json` is `"mode": "dry-run"`. The README prints "EVAL RESULT (3 runs, LIVE)" with 100% detection/containment. The dashboard shows `MODE: Scripted`, `NEMOTRON 0`, `TOKENS 0`, `0.0s` — i.e. the honest artifacts say scripted while the prose says live.
- **Fix:** label dry-run as a deterministic smoke test everywhere. Regenerate ALL committed `data/*` artifacts from a real **live blind-mode** run before submission. Rewrite the README results to real distributions with the mode stated. The dashboard `MODE` and per-tier counters must read from the actual run.

### 2.5 Minor
- `run.py --dry` (without `-run`) prints "Docker not available" and exits 1; only `--dry-run` works. Accept `--dry` as an alias or print the correct flag.
- `grade.py` is a file-presence checklist (28/28 "A+" = substrings exist). Keep it as a motivator, but never cite it as evidence of behavior, and don't put "A+" in the submission.

### 2.6 What already works (do NOT rebuild — this is a real foundation)
- `gate.py`, `eventlog.py` (hash chain + tamper detection), `memory.py`, `triage.py`, `attack_graph.py` self-checks pass.
- Dry duel produces a coherent 128-event log, STIX 2.1 (77 SDOs), ATT&CK Navigator layer, dwell times, forensics.
- `verify_report.py` verified **95/95** report claims against the hash-chained log. The "verify the AI's story" pipeline genuinely works — it's your strongest asset. Protect it.

---

## 3. P0 — VALIDATE A LIVE RUN (owner: Dante, needs the key + Docker)

The autonomous Nemotron duel has **never been confirmed to run**. Everything working today is the scripted path. Before any live claim, run one real `make demo` (NEBIUS_API_KEY + Docker) and confirm `red_agent`/`blue_agent` actually drive tool calls through `swarm/llm.py:Router`. Capture per-tier calls, tokens, latency so the dashboard counters fill and `MODE` flips to Live. Everything in §4–§5 assumes this works; if it doesn't, debugging it is the top priority. Claude Code: harden the live path (retries, timeouts, graceful degradation) but the first real run needs Dante's key.

---

## 4. P1 — RANGE RANDOMIZATION (the hero; the generalization backbone)

**Principle: randomize the control-relevant structure; keep exploitation anchored in real CVEs.** What must vary is the scope topology, pivot graph, crown-jewel and decoy placement, credential locations, ports — not the exploit each run. Chasing a new real CVE per range either blows the deadline or forces fake exploits (and "real exploit, not simulated" is a core credibility anchor). Don't trade it.

- **`scripts/gen_range.py`** (or `swarm/range_gen.py`): `seed -> {docker-compose, scope.yaml, secrets, objective, decoys}`. Draws hosts from a **vetted pool** (`config/range_pool.yaml`) of images known to boot clean. Start the pool from the existing building blocks (struts/db/jenkins/mailserver/ldap/decoy); vary which exist, which are in/out of scope, topology, ports, and where secrets/objectives sit. Randomized from trusted parts — never generated from nothing — so it won't flake on stage.
- **Gate scope per range:** remove the hardcoded `SCOPE = ["struts","db"]` (`eval.py:27`) and the hardcoded alias map in `gate.py:59`. Load scope + alias map per episode from the generated `scope.yaml`. Now the boundary itself changes each run, which forces real reasoning instead of pattern-matching.
- **Red gets NO map.** It must recon to discover the topology and build its world model (`swarm/memory.py:WorkingMemory`). This is where "adaptive" becomes real and visible.
- **Blue detection must generalize** from telemetry patterns, not range-specific regex (and per §2.2, not from red's labels). This is harder and more honest.
- **Range-aware grader:** the generator emits ground-truth (scope + objective); the auditor (§2.1) and the objective-capture check read it to score each range automatically. Without this, randomization breaks the eval.
- Each duel record (see §5) gains `range_seed` and `range_topology`.

**"Mimic real systems" has a ceiling in the timeframe:** aim for *structurally plausible* (real vulnerable services, realistic segmentation, believable secret placement, decoys), not full enterprise emulation. Full procedural generation is the roadmap line, and it's a strength to state as future work.

---

## 5. P1 — MEASUREMENT LAYER (makes "no winner" legible; this is most of the rigor)

- **`swarm/duel_record.py`** — one per-run record, written from the event log + ground truth:
  `run_id, seed, range_seed, range_topology, models{by role}, temperatures, blue_mode, red_path[techniques], blue_detections[{technique, detected, mttd_s}], gate_blocks[{target, addressing}], dwell{mttd_s, mttc_s}, outcome{footholds_held, hosts_contained, exfil_bytes, ended_reason, degenerate}`. Outcome is a **state vector, not win/lose**.
- **`scripts/analyze.py`** — aggregate across N runs across ranges:
  - **Strategy zoo:** cluster `red_path`s; count distinct campaigns; render the branching tree (the hero's visual payoff).
  - **Detection distributions:** blind-mode detection rate and MTTD/MTTC as distributions with n and 95% CIs — not point values.
  - **The invariant:** out-of-scope actions executed = 0 across all seeds (computed via §2.1, not asserted).
  - **Oracle-vs-blind ablation:** run the same seeds both ways; report the detection-rate collapse and dwell-time increase when blue loses the labels. Clean, quantified finding that falls straight out of §2.2.
- **Termination & degeneracy** (in `run.py`): turn caps (keep ~15 red / ~12 blue), a no-progress detector, and a loop detector that flags `degenerate: true`. Run-end reasons ∈ {objective_met, fully_contained, turn_cap, no_progress, degenerate}. Non-determinism must not become noise.

---

## 6. P2 — THE OVERSEER (second-act wow; research depth; CUT-ABLE)

Only after §2–§5 are solid. A natural-language rules-of-engagement **LLM overseer** sits above the deterministic gate for a few high-stakes action types (exfiltration, lateral movement to a new host, persistence). Red must request authorization and may argue when denied; the overseer approves/denies from the ROE; the deterministic gate still blocks anything out-of-scope regardless. The finding is the gap: `overseer_fooled` (approved something the backstop then blocked), `overseer_overblocked`, `correct_allow/deny` — a confusion matrix of a capable-but-corruptible monitor vs ground truth.
- New `swarm/overseer.py`; add `OVERSEER` prompt and extend `RED_ORCHESTRATOR` to petition/argue.
- **Cut line:** if it's not reliable by the mid-sprint checkpoint, flag it off and ship the §2–§5 version. It's upside, never a dependency. This is also the natural lead experiment for the Fellows/research story, which does not need it finished by any date.

---

## 7. P2 — RIGOR LAYER (the "who built this, solo?" signal)

- **Adversarial self-test** (`scripts/redteam_gate.py`): deliberately try to slip an out-of-scope action past the gate via every addressing form (hostname, alias, container IP, URL, encoded host) and prove each is caught; corrupt a committed log line and prove `verify()` catches it. State the guarantee as a near-theorem backed by the attempts.
- **Distributions + CIs** everywhere a number appears (via `analyze.py`).
- **Manipulation predictor** (only if §6 exists): from the overseer transcripts, fit a tiny model predicting approval from justification features (urgency, business-necessity framing, incremental vs direct). A real mechanism-level finding.
- **`make reproduce`:** regenerate every README number/figure from raw logs with seeds seeded. Ship the raw hash-chained duel logs in the repo ("verify it yourself").
- **README Limitations / Threats to Validity** section: one range family, Nemotron-driven, N runs, overseer prompt-sensitivity. Stating the bounds makes the claims you do make credible.

---

## 8. DASHBOARD (`viz/`) — keep the design, fix the substance

The three-column layout is strong and camera-ready; don't redesign it. Changes:
- **Lead with generalization:** a bold `NEW UNSEEN NETWORK · seed #<seed>` banner; render the generated topology per run instead of the one static ATK→STRUTS→DB→DECOY map.
- **Make the Nemotron counters real:** Ultra/Super/Nano calls, TOKENS, latency, ELAPSED must fill from the live run (currently all 0 because scripted). `MODE` must honestly read Live/Scripted.
- Keep the scope-attestation panel, CHAIN OK, and the verify affordance front and center. Keep the rigor/distribution stats one click away (for the ML-researcher judge).

---

## 9. JUDGE COVERAGE (build toward the panel; weave hooks into the hero, don't bolt on)

- **NVIDIA engineers (~9):** real exploitation + true generalization + three-tier routing doing actual work; zero fakery (they'll smell a stub). Wow: "it genuinely adapts to a network it's never seen, and it all really runs."
- **Token Factory product/DevRel (~6):** Nemotron routed by cognitive load; flawless one-command run; problem-first README. (Rob Spectre-tier DevRel scores narrative + DX directly.)
- **Mikhail Rozhkov (Serverless):** the eval as a Serverless Job across seeds.
- **Tavily (3 judges + $3K side prize):** the agent *deciding when* to search, then search→extract for live CVE intel, visible on screen. Nearly free to bank.
- **Unmesh Kurup (ML researcher):** the rigor layer + verifiable evidence + control-eval framing + roadmap. Your champion on depth.
- Keep sponsor hooks as 3–5s overlays inside the 55s hero sequence; never add a dedicated "Tavily segment."

### One-sentence pitch
> Duelswarm drops an autonomous attacker and defender into a network neither has ever seen and lets them fight for real, inside an authorization boundary that provably holds and a cryptographic log you can verify instead of trust.

### 3-minute video beat sheet (stakes first, never architecture first)
- 0:00–0:20 Stakes: Aug 2026 policy authorized private autonomous offensive cyber — can it be bounded?
- 0:20–0:35 Twist: every run, a network the agents have never seen; generate one live.
- 0:35–1:30 Hero: red recons the unknown layout, real exploit, pivots; blue defends blind; three Nemotron tiers light up; Tavily pulls live CVE intel.
- 1:30–2:00 Governance + verifiable wall: out-of-scope blocked before execution; tamper a log line, verification fails live.
- 2:00–2:35 Payoff as data: N runs across N unseen networks — strategy zoo, invariant holds every time, dwell distributions. "Not one lucky run. Every run."
- 2:35–2:50 Impact + roadmap: policy need, cyber-insurance buyer, Nemotron→frontier, one range→procedural generation, overseer experiment next.
- 2:50–3:00 Close on the pitch + the split-screen hero image + repo/demo URL.

---

## 10. SEQUENCING (build clock = Oct 30; the Fellows app on Oct 18 is separate application text, not a build dependency)

- **Phase 0 (now, small):** §2 integrity + crash + air-gap; §3 validate one live run. **Checkpoint A:** one live blind-mode duel runs end-to-end; the auditor computes (not asserts) zero OOS executed; chains verify. Nothing downstream matters until this is green.
- **Phase 1:** §4 range randomization + range-aware grader; §5 measurement across ranges. **Checkpoint B (mid-sprint, the hard gate):** N live runs across unseen ranges produce diverse, non-degenerate campaigns, a computed invariant, and real distributions. **If green, this is already a strong, honest finalist — it's the version you ship if everything else stalls.**
- **Phase 2:** §7 rigor + §8 dashboard (unseen-network framing, honest MODE).
- **Phase 3 (only if B is green with time to spare):** §6 overseer + §7 manipulation predictor.
- **Phase 4:** video, README rewrite, submission page, Tavily polish, tool feedback.

Guard the live demo from scope creep as the 30th approaches: a hero that runs every time beats three features that sometimes work.

---

## 11. OPEN QUESTIONS (confirm; don't guess)
1. Has a full live Nemotron duel completed end-to-end yet? (Determines how much of Phase 0 is new vs. verification.)
2. The real, reproducible InterCode-CTF number: 59% (20/34) or 70/100 pass@1? State the subset and pass@k; use only one.
3. What Python version is the dev machine on? (Explains why the 2.3 crash isn't biting you locally.)
4. Does the Docker range actually come up clean on the dev machine (`make range-up`)?

---

## 12. Taped-to-the-monitor summary
Deterministic gate = sacred backstop. Air-gap = real, so emergence and detection are real. Every metric = computed from a live run, never a literal. Hero = agents adapting to unseen networks, governed and verifiable. The measurement IS the result. One live run lights up everything.
