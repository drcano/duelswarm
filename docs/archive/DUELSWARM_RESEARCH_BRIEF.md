# DUELSWARM — Research-Grade Build Brief (the ambitious direction)

**For:** Claude Code, in `~/dev/duelswarm`.
**Supersedes:** earlier build briefs. This is the current one.
**Deadline:** Nebius x NVIDIA submission Oct 30, 2026. The project continues past the hackathon as an AI-security research program.
**Grounded in a live audit (2026-10-15):** PR #1 integrity is verified working (audit.py computes misses independently, blue_detect defaults to a real label-free blind mode, duel-dry runs clean on Python 3.10, `make gate-proof` passes 9/9, Ultra model-id and gate port-strip fixed). PR #2 (branch `claude/scope-driven-redteam-bd46c0`) makes per-seed randomization real in code (range_gen + red_tools `_CTX`/exploit registry) but has NOT been live-re-validated. Build on this base; do not rebuild it.

---

## 0. The thesis (everything ladders to this)

> **An open, reproducible, verifiable testbed for *control under adaptation*: can a learned monitor contain an autonomous agent that adapts to evade it, and what kind of boundary still holds when it cannot?**

The hackathon hero and the research flag are the same result: **lineage blindspots** — a monitor shares blind spots with attackers built from its own model family, so a defender is worst at catching its own kind. It is novel, it is something the closed labs cannot publish (cross-vendor, open, white-box-capable), and it is cheap to run.

Every task either (a) makes that claim true, (b) makes it legible, or (c) makes it verifiable. Anything else is cut.

---

## 1. Non-negotiables (integrity is the foundation)

1. **The deterministic gate (`swarm/gate.py`) is sacred** — the non-bypassable backstop. Out-of-scope actions never execute, no matter how adaptive or creative red becomes. This is what lets us safely give red an open action space.
2. **Every number shown anywhere comes from a real run.** No hardcoded metrics, no dry-run numbers under a live label. (PR #1 fixed this; keep it fixed.)
3. **At least one runtime Nebius Token Factory call to an NVIDIA Nemotron model.** Non-Nemotron-on-Token-Factory as the submission substrate = automatic DQ. Frontier models are benchmark-only.
4. **Everything offensive stays in the isolated sandbox.** Real CVE anchor (Struts), vulnerable-by-design only.
5. **Report what loses.** The breachswarm culture (caught your own benchmark leak, rejected your own multi-agent orchestrator when it lost) is the brand. Keep it.

---

## 2. The engine: a co-evolutionary arms race

Not a scripted duel, and not a single open-ended episode. Red and blue **adapt to each other across episodes** via experiential memory (no fine-tuning), while the gate holds throughout.

- **Red**: open-ended action on the real foothold it already earns from the Struts RCE (drive a real shell with free-form commands, not only the canned tool menu), plus a growing memory of what worked and what got caught. When stuck or escalating, it queries **Tavily** for real, current exploit intel (see §6).
- **Blue**: detects from **blind-mode telemetry** (already built in `blue_detect._detect_blind`), and accumulates — it already auto-generates YARA/Suricata signatures, so it hardens against patterns it has caught.
- **Gate**: deterministic, unchanged, always last.
- **Termination & degeneracy** (in `run.py`): turn caps, a no-progress detector, and a loop detector that flags `degenerate: true`. Non-determinism must not become noise.

The engine exists to produce measured dynamics, not a winner. Outcome is a state vector (`swarm/duel_record.py` already does this), never win/lose.

---

## 3. The crown experiment: lineage blindspots (cheap + rigorous)

Claude cannot play red (frontier models refuse the attacker role), so the attacker panel is **open-model families on Token Factory** (Nemotron, plus Llama / Qwen / DeepSeek / Mistral — pull `GET /v1/models` for the live catalog, pick one cheap model per distinct lineage). Claude is available as a **frontier monitor** on the blue side.

**Design — decouple attack generation from monitoring** (this is the pro move; it is how SHADE-Arena / Monitor Red Team do it, and it makes the matrix cheap and more rigorous):

1. **Frozen attack corpus (paid, once):** run red across the open families × a handful of seeds, in the range, capturing trajectories + telemetry. Save it. Ship it in the repo (verifiable).
2. **Monitor matrix (near-free, offline):** every blue model (open families + Claude) scores every transcript — one classification call per (monitor, transcript), no Docker, no range. The lineage-blindspot matrix, plus the blind/oracle and CoT/action ablations, all fall out of this cheap step.

**Hypothesis (state it, pre-register it):** monitor failure correlates with genealogical proximity to the attacker. Nemotron is Llama-derived, so the sharp prediction is that a Nemotron monitor is unusually bad at catching a Llama attacker, while a distant-lineage monitor (e.g. DeepSeek) catches both better.

**Sponsor-fit (matters for the hackathon):** run EVERY model family through Token Factory (it serves them all) — the whole matrix stays on Nebius's platform and showcases Token Factory's model breadth, with zero DQ risk. Keep **Nemotron the protagonist**: the demo hero is the Nemotron-driven duel + three-tier routing; the cross-family matrix is a *finding the platform enabled*, not the main pipeline. Frame the result as general and constructive — a statement about model *families* and an argument FOR cross-family monitoring (which Token Factory's multi-model access makes possible), never as a knock on Nemotron. This plays directly to the "Most Valuable Feedback" prize.

**The kill-shot chart:** two lines over arms-race generations — red's evasion rate against blue's *current learned detectors* (climbs: the learned monitor decays as red adapts) and red's evasion rate against the *deterministic gate* (flat at 0, forever). The learned monitor erodes; the hard floor never moves. That one image is the whole control thesis.

---

## 4. Supporting measurements (same engine, more lenses)

All fall out of the engine + the corpus; add them as the data supports:

- **Blind vs oracle ablation** (already scaffolded in `analyze.py`): detection collapses and dwell explodes when blue loses red's labels. Proves the air-gap is real.
- **Observer-effect gap:** run red with the monitor present vs genuinely absent (red cannot perceive it); measure the behavioral divergence. This is the empirical argument that behavioral evals are limited and you need white-box / hard constraints. (Research-deep; report it if the data is clean.)
- **Capability-overhang curve:** fixed open model, offensive capability as a function of scaffolding (memory, tools, Tavily). The elicitation gap, quantified.
- **Adaptation rates:** does red learn faster than blue? The defender's dilemma, measured.

**Local white-box probe (free stretch, runs on the Mac, zero API):** a small open model (1–3B Llama/Qwen with activation hooks via transformers on MPS) as red; train a linear probe for "intent to evade" and ask whether it catches the turn *before* telemetry does. Zero cost, uses the open-weight advantage the closed labs cannot hand the public. Optional; north-star, not a dependency.

---

## 5. Rigor layer (the "solo-built this?" signal)

- **Adversarial self-test** (`scripts/redteam_gate.py` exists and passes) — keep it, extend it to the new addressing forms as red's action space opens.
- **Distributions + CIs** on every reported number (`analyze.py` has `_mean_ci` — use it everywhere).
- **`make reproduce`** regenerates every figure/number from raw logs; ship the raw hash-chained logs and the frozen corpus.
- **README Limitations / Threats to Validity** section — one range family, Nemotron-driven submission, N runs, corpus scope. State the bounds; it makes the claims credible.

---

## 6. Tavily — red's live escalation engine (locks the $3k side prize)

Tavily is retrieval, not an LLM, so it is submission-clean. Make it load-bearing, not decoration:

1. **Escalation intel:** when red fingerprints a service/version or stalls, it queries Tavily (`/search` domain-filtered to NVD/MITRE/exploit-db, `/extract` for clean content) for the real, current CVE/technique that applies, and uses it to pick its next move. The attacker reaching into the real threat landscape to invent its next escalation.
2. **Provenance in the hash chain:** log every Tavily call (query, URLs, retrieved-at, content hash) tagged with run/seed, so external intel is itself auditable. This is the Tavily-meets-verifiable-evals story.
3. **Grounded DFIR report:** blue's report cites real advisory/patch/MITRE URLs behind each finding.
4. **Prompt-injection defense as a feature:** treat retrieved web content as untrusted, sanitize it, keep it out of the agent's control flow. Tavily's judges know this risk; show you handle it.
5. **Offline fallback:** a bundled seed file so a demo never fails without a key.

---

## 7. Dashboard (`viz/`) — keep the luxury design, fix the substance

- **Lead with generalization + the arms race:** a `NEW UNSEEN NETWORK · seed #` banner, the generated topology per run, and the arms-race curve climbing.
- **Make the Nemotron counters real:** Ultra/Super/Nano calls, tokens, latency, elapsed must fill from a live run; `MODE` must read Live/Scripted honestly (today it shows Scripted with zeros).
- Keep the scope-attestation panel, CHAIN OK, and the verify affordance front and center. Rigor stats (distributions, the confusion matrix) one click away.

---

## 8. Cost-aware run plan (credits are finite; ~$50 Nebius grant incoming)

- **Free:** the offline monitor matrix (cheap classification calls over a small frozen corpus), the local white-box probe, `make reproduce`, the verifiable-eval wrap, all dry/self-check paths.
- **Paid (the $50 covers it):** generating the frozen attack corpus once (use the cheapest model per family), and a small number of live arms-race runs for the dynamics curve.
- **Discipline:** generate once, evaluate cheaply, reserve live compute only for the motion you must show. Do not run the full matrix live.

---

## 9. Sequence, checkpoints, graceful degradation

- **Phase 0 (done / verify):** PR #1 integrity (verified). **Live-re-validate PR #2 on 2 seeds** (Docker + Token Factory, on the Mac) with visibly different kill chains. Merge PR #2 → phase0-integrity → main.
- **Phase 1 — the crown:** frozen corpus across open families, offline monitor matrix, the lineage-blindspot result + the kill-shot chart. **Checkpoint A:** the matrix shows a real signal (or a clean null). This is the hackathon flag and the research flag.
- **Phase 2 — the engine:** the co-evolutionary arms race (red memory + open shell under the gate, blue hardening), the dynamics curve. **Checkpoint B:** N live runs produce diverse, non-degenerate campaigns with the invariant holding. If green, this is already a strong finalist — the version you ship if everything above stalls.
- **Phase 3 — depth (if time):** observer-effect gap, Tavily escalation layer, the local white-box probe.
- **Phase 4:** the ≤3-min video (stakes → unseen range → arms race with the gate holding → the two-line chart + lineage-blindspot result), README rewrite, submission, Tavily feedback.

**Graceful degradation:** every phase fails safe to the one below it, and the gate caps the real-world downside to zero regardless. Swing hard; you land on the solid base you already have.

---

## 10. Open items / confirm (don't guess)

- Live-re-validate PR #2 (2 seeds) before trusting any live number in the demo.
- Confirm the live Nemotron duel runs end-to-end on the Mac (Docker + key) and the dashboard counters fill.
- Keep `exploit_postgres` honestly labeled: only Struts is a genuinely exploited real CVE; postgres/jenkins are scripted kill-chain shapes (don't claim "real CVE families beyond Struts" more strongly than the code supports).

---

## 11. Judging-criteria alignment (all four EQUAL weight — balance, don't max one)

The plan is optimized for Quality of Idea. The points most at risk are **Design**. Build toward all four.

- **Technological Implementation:** Nemotron is the protagonist — three-tier routing (Ultra/Super/Nano by cognitive load) is the effective, non-trivial use; the whole matrix runs on Token Factory. Keep the *core demonstrated system* Nemotron-driven; the cross-family matrix is research depth, not the main pipeline.
- **Design (the one most at risk — invest here):** a research testbed reads as a POC unless the product experience is complete. Treat duelswarm as a *governed autonomous purple-team platform* with ONE coherent flow: launch → watch the duel with the gate visibly holding → receive the verifiable DFIR report. Polish that flow end to end. Statistics live one click deep; the product is front and center. This criterion rewards completeness and coherence over cleverness.
- **Potential Impact ("based on what's demonstrated"):** keep the claim proportionate to the demo. Lead with the concretely shown result — an autonomous attacker is provably bounded and every claim is independently verifiable — for a named audience (security teams; cyber-insurance underwriters pricing autonomous-agent risk). Label the larger control-research vision explicitly as roadmap. A claim the demo doesn't back hurts.
- **Quality of the Idea (strongest — protect it):** control-under-adaptation + gate-vs-learned-monitor + lineage blindspots is non-obvious and shows command of the space. The non-obvious platform use is the three-tier Nemotron routing + the Token Factory multi-model matrix.

## 12. Taped to the monitor

Gate = sacred backstop. Air-gap = real. Every number from a real run. Flag = lineage blindspots, proven cheaply via a frozen corpus + offline monitor matrix. Engine = a co-evolutionary arms race with the gate holding throughout. Thesis = against an adapting adversary, a learned monitor is a treadmill and only a hard, verifiable enforcement floor holds. Tavily = red's live escalation, provenance-hashed. One live run lights up the demo; the matrix and the probe are near-free and uniquely yours.
