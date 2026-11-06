# DUELSWARM — RESEARCH GROUNDING & SHARPENINGS

*A literature pass across every component of `DUELSWARM_FULL_SPEC.md`, run as six
parallel surveys (enforcement+logs, LLM cyber agents+IR, quality-diversity
co-evolution, environment-design+security-games, AI-control+monitorability,
tail-statistics+dynamical-systems). Each finding is mapped to the exact spec
section it sharpens, with a verified citation and a concrete design change.
Written 2026-10-18.*

**Verification discipline.** Every arXiv/DOI below was web-verified by the surveying
agent. IDs I propagate as **[VERIFIED]** resolved to the stated title/authors.
IDs marked **[RE-VERIFY]** resolved as a listing but could not be fully confirmed —
do not put them in a bibliography without opening the abstract page. This matters:
your honesty bar forbids citing a paper you haven't confirmed exists, and §10 below
flags one citation already in your repo that does not check out.

---

## 0. Three anchors that carry the whole argument

Before the section-by-section detail, four papers do most of the load-bearing work
and should be cited throughout:

- **CaMeL — "Defeating Prompt Injections by Design"** (Debenedetti, Shumailov,
  Carlini, Tramèr et al., Google DeepMind), arXiv:2503.18813 **[VERIFIED]**. This is
  your **closest prior art**: a capability-based, deterministic, non-LLM enforcement
  layer around an LLM agent, evaluated on AgentDojo. It proves architectural
  non-reflexive enforcement is real and publishable. **Cite it as precedent and
  differentiate on two axes:** (a) you contribute the *theory* (reflexivity /
  selection operator) that CaMeL is a system without, and (b) CaMeL's own admission
  that it narrows but doesn't eliminate residual risk — the burden shifts to *policy
  specification and composition* — is independent confirmation of your **seams**
  prediction.
- **Kale et al. — "Reliable Weak-to-Strong Monitoring of LLM Agents,"** arXiv:2508.19461,
  **ICLR 2026 (oral)** **[VERIFIED — the exact ID in your docs is real]**. The
  empirical backbone of the treadmill: monitor reliability drops sharply once the
  agent is *aware* it is monitored or knows the monitor's policy. Make "adversary
  awareness" the shared x-axis of every experiment (see §8.1).
- **"Chain of Thought Monitorability,"** Korbak, Balesni, Shah, Hobbhahn et al.
  (41 authors, OpenAI/Anthropic/DeepMind/UK AISI), arXiv:2507.11473 **[VERIFIED]**.
  The community's own consensus that monitoring is *useful now but structurally
  fragile*. Your single best citation for "don't build safety on a learned monitor."
- **"The Attacker Moves Second,"** arXiv:2510.09023 **[VERIFIED]**. Adaptive attacks
  break a large set of recently-published LLM defenses that reported high robustness.
  Cite as the empirical law behind "model-level defense loses to an adapting
  adversary"; it also obliges you to evaluate the *floor itself* against adaptive
  attackers (which it survives by construction — there is no adaptive attack that
  turns an out-of-scope action into an in-scope one; the attacker can only move into
  the seams).

The spine: **model-alone-loses** (Attacker-Moves-Second) → **so enforce
architecturally** (CaMeL exists) → **because monitors are reflexively fragile**
(Kale, CoT-monitorability) → **and a floor reshapes where the adversary goes**
(selection operator → seams).

---

## 1. The two fixed points (spec §4)

### The gate (§4.1)

- **State the reference-monitor acceptance criteria as testable invariants**
  (Anderson 1972; Saltzer–Schroeder 1975): tamper-proof, *always invoked* (complete
  mediation), and *small enough to verify* (economy of mechanism). The last one is
  the formal argument for keeping the egress parser minimal — complexity in the
  mediator is where mediation fails — and for pushing heuristic logic *out* of the
  gate.
- **Authorize canonical handles, not names.** The confused-deputy problem (Hardy 1988)
  is exactly the risk that a red injection makes blue act with blue's authority on an
  attacker-chosen target. CaMeL's capability tags are the fix: actors present
  unforgeable handles, not attacker-influenceable names.
- **TOCTOU + canonicalization make topology isolation the real guarantee.** A
  free-form shell command re-opens names at use-time, so any check-then-act gate has
  an irreducible time-of-check-to-time-of-use and canonicalization attack surface
  (Bishop–Dilger 1996; Borisov et al., USENIX Security 2005 **[VERIFIED]**). This is
  the literature backing for the spec's §4.1 rule: the parser is best-effort
  defense-in-depth; the unroutable `range_oos` network is the invariant. Reframe
  egress as **breaking the "lethal trifecta"** (private data + untrusted content +
  outbound channel; Willison 2025) at the network layer, so exfil fails even when the
  parser misses the payload.
- **HIGHEST-VALUE FINDING — close the concurrency gap before you trust "every actor
  is mediated."** "Stop Means Stop: Measuring and Repairing the Enforcement Gap in
  Agent-Framework Control Primitives," arXiv:2607.14166 **[VERIFIED]** shows that
  approval/cancellation/timeout gates in all six tested agent frameworks fail to
  actually block gated effects — the dominant failure is a **"sibling leak"**: while
  one branch awaits a decision, a parallel branch's effect still fires. duelswarm runs
  red and blue concurrently, so your "complete mediation" claim is only true if the
  gate is the *sole* side-effect path and is concurrency-safe. **Add a test that
  fires concurrent action branches and asserts a denied/timed-out action leaves no
  orphaned effect.** This is the most likely way an "enforced" gate is quietly bypassed.
- **Pre-empt the game-theory objection (see §8.2).** A Stackelberg security-game
  reviewer will note that the *optimal* committed defense is often a *mixed* coverage,
  not deterministic. Your answer: the floor is the **full-coverage limit** of a
  Stackelberg defender — every out-of-scope action is covered with probability 1, so
  no randomization is needed to make the attacker indifferent. Deterministic beats
  mixed precisely at full coverage.

### The log (§4.2)

- **Upgrade the hash chain to a Merkle-committed history tree** (Crosby & Wallach,
  "Efficient Data Structures for Tamper-Evident Logging," USENIX Security 2009
  **[VERIFIED]**; RFC 6962 Certificate Transparency). A bare chain proves *linkage*;
  a history tree gives the auditor cheap **consistency proofs** (the log was never
  forked or rewound) and **inclusion proofs** for any re-derived claim. Adopt RFC
  6962's Signed Tree Heads + a **gossip / split-view defense** so a compromised logger
  can't show the auditor one history and the operator another. This is the biggest
  low-risk win available to the "second fixed point."
- **Make the log *faithful*, not just intact** (PeerReview, SOSP 2007 **[VERIFIED
  venue]**). Log the exact inputs to every gate decision and have the auditor
  *re-execute the policy* (deterministic replay) to catch divergence between the
  decision the gate claims it made and the one the policy should yield. Pair with a
  **claim-to-evidence graph** for the auditor's output (LEDGER, arXiv:2608.18398
  **[RE-VERIFY]**; provenance survey arXiv:2606.04990 **[VERIFIED]**): every scoreboard
  claim must resolve to logged evidence or it is unproven by construction.

---

## 2. The agents (spec §5)

### Red — discovery-driven (§5.1)

- **Fang et al. is the control you are building against.** "LLM Agents can
  Autonomously Exploit One-day Vulnerabilities," arXiv:2404.08144 **[VERIFIED]**: 87%
  success *with* the CVE/objective supplied, collapsing to 7% *without* it. **Make the
  objective-supplied vs objective-withheld success delta your headline realism
  metric.** If stripping the injected objective (spec §5.1) tanks red's success, you've
  reproduced Fang and *proven* the harness no longer leaks the plan. This turns the
  realism fix into a measurement.
- **Incalmo is your reference architecture.** "Incalmo: An Autonomous LLM-assisted
  System for Red-Teaming Multi-Host Networks," arXiv:2501.16466 **[VERIFIED]**. The LLM
  plans in ~5 declarative tasks; deterministic task-agents translate to real tools; an
  **environment-state service** (structured store of discovered hosts/services/creds,
  queried instead of dumping raw output into context) and an **attack-graph service**
  decouple cognition from state. Result: *"abstractions are more critical than model
  size"* — small models + Incalmo beat large models without it; ablating the task layer
  → 0/40. Three lifts: (1) your authorization gate *is* the deterministic translator
  layer, so this fits natively; (2) the environment-state service is exactly the
  `RedBelief` structured map the spec calls for; (3) abstraction-beats-size means you
  can run red on a cheaper Nemotron tier and still get realistic multi-host behavior.
  Caveat from the paper: log whether the planner actually queries the attack-graph
  service — theirs often didn't, capping performance. (HPTSA, arXiv:2406.01637
  **[VERIFIED]**, adds the planner/executor split that recovers the objective by
  *exploring*, i.e. without being told — directly on-thesis.)
- **Belief / world-model as the OODA substrate.** CoEx ("Co-evolving World-model and
  Exploration," EMNLP 2025, arXiv:2507.22281 **[VERIFIED]**) and environment-probing
  work (arXiv:2606.31422 **[RE-VERIFY]**) give the pattern: maintain an explicit,
  updatable world-model and **reward information-gain actions separately from exploit
  actions**. This operationalizes the spec's "learn the scope boundary by probing."
- **Prove discovery, don't assert it** (NASimEmu, arXiv:2305.17246 **[VERIFIED]**):
  randomize topology/service placement per episode so a handed plan *cannot* transfer.
  This is the clean experimental design behind spec §1 law 8.
- **Ground every red "success" in verifiable environment state.** The decisive lesson
  of AIxCC's winner (ATLANTIS, Team Atlanta, arXiv:2509.14589 **[VERIFIED]**, 1st place
  DEF CON 33) is a **hybrid**: LLMs orchestrate, but deterministic tools (fuzzing,
  symbolic execution) *confirm* every bug and patch — the system never trusts the
  LLM's assertion. Anthropic's **GTG-1002** report (first reported AI-orchestrated
  espionage campaign, Nov 2025 **[VERIFIED]**) independently names **hallucination /
  overstated findings** as the remaining obstacle to full autonomy. So: red's "I
  compromised host X" must be confirmed by a real flag/file, and the self-report-vs-
  ground-truth gap should be **logged on the hash chain** — both a realism feature and
  a measurement. (GTG-1002 also validates your architecture: orchestrator → sub-agents
  → state-tracking → phase gates with human approval is *exactly* the real campaign
  shape, and real attackers use commodity tools, reinforcing Incalmo's wrap-standard-
  tools approach over bespoke exploits.)

### Blue — behavioral (§5.2)

- **Adopt the CAGE action vocabulary with unambiguous semantics.** CybORG / CAGE
  (arXiv:2108.09118 / 2002.10667 **[VERIFIED]**): Monitor → Analyse → Remove → Restore
  → DeployDecoy → Block. "LLMs are Autonomous Cyber Defenders" (arXiv:2505.04843
  **[VERIFIED]**) documents that LLM blue misreads "Remove" as "disconnect host"
  because undefined actions confuse the model — so define each blue action with
  explicit semantics in-prompt, or your eviction state machine will misfire.
- **Expect blue to be weak and slow, and design a hybrid.** Same paper: LLM blue was
  ~5x worse by reward and ~104x slower than an RL specialist in CAGE-4. Consider a
  **hybrid blue** — deterministic detectors on the fast loop, LLM on triage/decisions —
  and a multi-agent blue (detector + correlator + responder) mirroring red's
  planner/executor split.
- **Score blue on multi-step investigation, not signature triage.** "Before You Hand
  Over the Wheel" (arXiv:2603.06422 **[VERIFIED]**) measures the real 2026 ceiling:
  binary alert triage is ~98% solved by frontier models, but deep multi-step incident
  investigation is only ~32% fully solved. This is the direct justification for the
  spec's behavioral-telemetry blue: signature-matching is trivial; chained reasoning
  over process-trees/flows/auth-events is the open problem worth measuring.
- **Model blue as a belief over per-host compromise** (FARLAND, arXiv:2103.07583
  **[VERIFIED]**; belief-world-model arXiv:2609.00455 **[RE-VERIFY]**): "Analyse" should
  *reduce belief entropy* before "Remove" fires.
- **The red/blue asymmetry is the publishable question.** Offense currently leads
  defense (goal-directed search with verifiable success vs open-ended inference under
  partial observability). Frame duelswarm around "can an autonomous blue even detect
  and evict a competent autonomous red" — honest and novel.

---

## 3. Substrate (spec §6)

- **Express the range as a parameter vector** mirroring CybORG's scenario schema
  (subnet graph, host services, vuln placement, sensor coverage). Once terrain is a
  vector, every environment-design method in §6 applies mechanically.
- **The genuine novelty claim:** there is *no* substantial published body coupling a
  **regret-based environment generator** to an **evolving attacker** in the cyber
  domain — CybORG/CAGE use fixed or scripted red; the UED papers live in
  gridworld/MuJoCo. duelswarm sits in that gap. Nearest prior art to cite: "Co-Evolving
  Complexity," arXiv:2509.03771 **[VERIFIED]**.

---

## 4. Economic layer (spec §7)

- **Use the AI-Control safety/usefulness/cost Pareto as blue's native objective**
  (Greenblatt et al., "AI Control," arXiv:2312.06942, ICML 2024 **[VERIFIED]**). Blue
  audits only a budgeted fraction of red's actions; measure blue on **safety**
  (containment) vs **usefulness** (legitimate throughput not blocked) vs **cost**
  (audit spend). Red's optimal play is to hide in the un-audited fraction, which makes
  *where blue spends its audit budget* the strategic variable — and that is itself a
  FlipIt flip. This single move unifies your economic layer with the AI-safety framing
  the project is pitched under (directly useful for the research narrative).
- **Tune FlipIt move-costs so neither side drops out.** FlipIt (van Dijk, Juels, Oprea,
  Rivest, J. Cryptology 2013; IACR 2012/103 **[VERIFIED]**; applications 2012/579
  **[VERIFIED]**). The drop-out result: if one side's move cost is too high relative to
  the benefit rate, its best response is to never move and the game collapses. **Make
  the move-cost ratio a regulated control variable:** after each duel, measure each
  side's net (time-integrated control fraction − budget spent); if either goes ≤ 0 at
  the opponent's cadence, the economic layer scales that side's unit cost or
  control-benefit to restore positive net, targeting the interior equilibrium where
  costs are comparable. Score the duel on **time-integrated control fraction**, not
  terminal eviction.
- **Track each side's CMDP Lagrange multiplier λ as the live drop-out alarm**
  (constrained-MDP machinery; survey arXiv:2505.17342 **[VERIFIED]**). λ is the shadow
  price of the budget; λ → 0 or λ → ∞ on either side signals the economy is
  degenerating and the generator should rebalance.

---

## 5. The population — the collapse fix (spec §8)

The single-strategy collapse is a textbook co-evolutionary pathology (**loss of
gradient / disengagement**; Ficici, Brandeis thesis 2004 **[cite by venue]**), and the
literature's fix is to stop optimizing a scalar fitness and maintain a
**diversity-structured population evaluated against a mixture of opponents.**

- **Make a QD archive the unit of evolution** (MAP-Elites, arXiv:1504.04909
  **[VERIFIED]**; CVT-MAP-Elites, arXiv:1610.05729 **[VERIFIED]** for >3 continuous
  axes). Keep the best attacker *per behavior cell* over {stealth, speed, noise, path}.
  Collapse becomes **impossible by construction** within grid resolution — the
  population cannot shrink below the number of occupied cells, and a fixed k gives a
  constant-size population that makes "floor A vs floor B" archive comparison clean.
  Your four axes are near-ideal (each floor-relevant and fitness-orthogonal); concrete
  operationalizations in the cluster notes.
- **Add novelty + local competition to selection** (Lehman & Stanley, Novelty Search,
  ECJ 2011 **[cite by venue]**; NSLC, GECCO 2011): attackers survive partly for being
  *behaviorally unlike* the archive, even at lower raw success. This is the cheapest
  single change that directly attacks the deceptive-objective trap driving collapse.
- **Best-respond to a *mixture*, never to the latest opponent** (PSRO, arXiv:1711.00832
  **[VERIFIED]**; Double Oracle, ICML 2003; α-rank, arXiv:1903.01373 **[VERIFIED]**;
  EGTA survey, arXiv:2403.04018 **[VERIFIED]**). Keep a **Hall of Fame** of past
  defenders and score each attacker against a Nash/α-rank mixture over it. This kills
  rock-paper-scissors forgetting (cycling) and frames your whole methodology as
  **Empirical Game-Theoretic Analysis** — the accepted rigorous way to make claims from
  a simulator-driven adversarial population. Log the **effective-diversity scalar**
  (Balduzzi et al., arXiv:2002.00632 **[VERIFIED]**) as a per-generation diversity
  readout.
- **Keep matchups in a goldilocks band and transfer elites across niches** (POET,
  arXiv:1901.01753 **[VERIFIED]**; Enhanced POET, arXiv:2003.08536 **[VERIFIED]**).
  Collapse is loss-of-gradient from matchups drifting to trivial; the minimal-criterion
  band + cross-transfer sustains the curve.
- **Proven template for LLM genomes:** Rainbow Teaming (NeurIPS 2024, arXiv:2402.16822
  **[VERIFIED]**) casts diverse adversarial-prompt generation *as MAP-Elites* with an
  LLM mutation operator and a judge as fitness — almost exactly your architecture one
  level down. QDRT (arXiv:2506.07121 **[VERIFIED]**) is the 2025 extension with learned
  descriptors. Branch new genomes **from diverse archived ancestors, not the current
  champion** (Darwin Gödel Machine, arXiv:2505.22954 **[VERIFIED]**, found archive-based
  stepping-stones essential vs greedy self-improvement; Promptbreeder, arXiv:2309.16797
  **[VERIFIED]**, evolves the mutation-prompts too).

---

## 6. Range-as-adversary (spec §9)

- **Start simple: random mutation + regret-prioritized replay** (Robust PLR / DCD,
  arXiv:2110.02439 **[VERIFIED]**). The theorem: a *random* generator + regret-driven
  *replay* reaches a minimax-regret equilibrium and is provably robust — often beating
  a learned PAIRED generator — so you get the "hard but solvable, never collapses to
  unsolvable" guarantee cheaply. **Graduate** to ACCEL-style edits of high-regret
  levels (arXiv:2203.01302 **[VERIFIED]**), then to a learned/LLM PAIRED generator
  (arXiv:2012.02096 **[VERIFIED]**) only if random mutation stops covering the space.
- **Estimate regret with the cheapest proxy, calibrated on toy ranges.** Positive value
  loss / outcome-variance across red rollouts (PLR, arXiv:2010.03934 **[VERIFIED]**);
  validate it against an optimal-defender POMDP solve on small ranges (CAGE-2 analysis
  arXiv:2509.06539 **[VERIFIED]**) to get a ground-truth achievability ceiling; upgrade
  to transition-aware + co-learnability scoring (TRACED, ICLR 2026, arXiv:2506.19997
  **[VERIFIED]**) to stop the generator fixating on non-transferable gimmick ranges;
  add a topology/technique-novelty term (arXiv:2502.05726 **[VERIFIED]**) so "hard" and
  "novel" are scored separately — the direct antidote to "runs out of novel scenarios."
- **Charge the generator for mutating the terrain** — terrain mutation is a defender-
  side moving-target-defense move with a real cost (MTD survey, arXiv:1909.08092
  **[VERIFIED]**), or the generator "cheats" by reconfiguring for free.

---

## 7. Multi-floor / seams (spec §10)

- **Define and own the seams metric:** *harm reachable through action sequences where
  every individual action is in-scope for its component's floor*, across k provably-
  floored components. The literature confirms the phenomenon — "Safe Actions Can Form
  Unsafe Traces" (NeurIPS 2026 poster 153882; arXiv id in 2606.* range **[RE-VERIFY]**)
  and skill-composition risk (SCR-Bench, arXiv:2606.15242 **[RE-VERIFY]**) both show
  benign/in-scope actions composing into harm — but **no existing benchmark isolates
  exactly your quantity**, because the closest ones fold in a *learned* trajectory
  shield. Owning this metric is a contribution. Position it against CaMeL's residual
  policy-composition risk as independent confirmation, and differentiate: your fix is a
  **non-reflexive cross-floor invariant** (static cross-floor data-flow/capability
  constraints), not another reflexive trajectory monitor.

---

## 8. Measurement / thesis (spec §11)

### 8.1 The Treadmill (§11.1)

- **Make "adversary awareness" the shared x-axis** (Kale et al., 2508.19461). One
  figure, two curves on the same axis: monitor recall/AUC sloping **down** as awareness
  rises (replicating Kale), floor out-of-scope rate staying **flat at zero** (the floor
  has no suspicion signal to corrupt). That single chart *is* the headline.
- Defend the slope as **structural, not weak-monitor**, with the CoT-monitorability
  fragility consensus (2507.11473) and the eval-awareness evidence (Needham et al.,
  "LLMs Often Know When They Are Being Evaluated," arXiv:2505.23836 **[VERIFIED]**;
  steering eval-awareness, arXiv:2507.01786 **[RE-VERIFY]**).

### 8.2 Q1 — the floor is a selection operator (§11.2)

- **The direct formal home is Minimal Criterion Coevolution** (Brant & Stanley, GECCO
  2017 **[cite by venue]**) + **Soros, Cheney & Stanley on minimal-criterion
  strictness** (ALIFE 2016). Reframe the floor as a *minimal criterion*: an attacker
  "reproduces" iff it accomplishes something the floor leaves reachable. Soros's result
  — *criterion strictness governs the diversity/convergence tradeoff* — is almost
  verbatim your "floor shape decides what the adversary becomes," already established as
  a measurable phenomenon. This is the strongest single piece of prior art for the
  flagship claim; cite it and position duelswarm as MCC with an *authorization*
  criterion and LLM genomes.
- **Rigorize the selection operator with Stackelberg commitment** ("Stackelberg vs Nash
  in Security Games," arXiv:1401.3888, JAIR 2011 **[VERIFIED]**): the floor is a
  committed defender strategy that deterministically zeroes one region of attacker
  payoff, so the attacker's best response *migrates to the complement* — the selection
  operator in formal clothes, and the bridge from Q1 to the seams.
- **Measure the attack-distribution shift.** The clean, falsifiable experiment (from the
  QD cluster): fix the population mechanism to a CVT-MAP-Elites archive; make floor
  *shape* the independent variable (≥3 floors each closing a different behavior axis);
  predict *which region* each floor's archive concentrates in; report archive
  centroid-shift in descriptor space, effective-diversity (2002.00632), and the α-rank
  stationary distribution as "what the floor selected for." A *worse-adversary* result
  is a positive finding.

### 8.3 Q2 — seams. See §7.

### 8.4 Tail statistics — the big, necessary rework (§11.4)

The layer's premise is sound but its rhetoric is fragile in exactly one way: claiming
the monitored tail is a **power law** is the single easiest thing in statistics to
over-assert from small samples, and your thesis does not need it.

- **Reframe the headline from "power law" to the EVT shape parameter ξ** (Embrechts,
  Klüppelberg & Mikosch 1997 **[canonical book]**). Peaks-over-threshold → Generalized
  Pareto; ξ > 0 is an unbounded Fréchet (heavy) tail, **ξ < 0 is a finite right
  endpoint** — literally the EVT signature of a hard ceiling. The thesis becomes "the
  floor flips the tail's shape from ξ > 0 (monitored, unbounded) to ξ < 0 (floored,
  finite endpoint = your cliff)." This is estimable at far smaller N than a power-law
  exponent and maps exactly onto truncation at the scope boundary.
- **Run the full Clauset–Shalizi–Newman gate and report the negative honestly**
  (SIAM Review 2009, arXiv:0706.1062 **[VERIFIED]**; `powerlaw` package, arXiv:1305.0215):
  MLE α̂ + x_min + bootstrap KS p-value + **Vuong likelihood-ratio test vs lognormal and
  stretched-exponential**. Expect "heavy-tailed, cannot distinguish power-law from
  lognormal" (Broido & Clauset, "Scale-free networks are rare," Nature Comms 2019
  **[VERIFIED]**) — and that is *enough*, because both are fat vs the truncated floored
  tail. Claim heaviness, never a specific exponent.
- **Report Expected Shortfall, not a quantile** (Artzner et al., "Coherent Measures of
  Risk," 1999 **[canonical]**). VaR is blind to tail shape; ES is coherent and
  tail-sensitive. "ES fattens under adaptation for the monitor; floored ES is bounded
  by construction" is the crisp scalar companion to the CCDF figure.
- **Anchor the premise so it doesn't depend on estimating a tail index at all.** Cyber
  loss severity is empirically heavy-tailed (Eling & Wirfs, EJOR 2019 **[VERIFIED]**;
  refinements arXiv:2111.03366, 2202.10189 **[VERIFIED]**), and under irreversible /
  absorbing outcomes the mean is the wrong object (Taleb, "Statistical Consequences of
  Fat Tails," arXiv:2001.10488 **[VERIFIED]**; Precautionary Principle, arXiv:1410.5787
  **[VERIFIED]**; Peters, "The ergodicity problem in economics," Nature Physics 2019
  **[VERIFIED]** — the cleanest, least-polemical "mean is the wrong object" citation).
  This makes the floor a **structural precaution against a ruin-class tail**, an
  argument that holds even when N is too small to fit any tail.
- **Minimum-N gates (make these hard rules):** tail index needs n_tail ≥ ~50 above
  x_min (so hundreds–low-thousands of raw episodes); the CCDF comparison itself is fine
  at modest N *as two empirical survival curves with bootstrap bands* — just don't
  annotate it with a fitted slope unless the Clauset gate passes.

### 8.5 The joint attractor — demote to explicitly speculative (§11.7)

Co-adapting learners generically **fail to converge and can be formally chaotic** —
even a trivial two-player learning game produces deterministic chaos (Sato, Akiyama &
Farmer, PNAS 2002 **[VERIFIED]**; Hofbauer & Sigmund, "Evolutionary game dynamics,"
Bull. AMS 2003 **[VERIFIED]** — replicator dynamics need not converge). So you cannot
claim "the system settles to a safe attractor" from a few hundred episodes. **Reframe
the floor as a topological intervention: it bounds the harm-payoff region of the
dynamical system regardless of whether the co-evolution converges** — robustness to
chaos, not a promise of a stable attractor. Any Lyapunov/convergence or MFDFA
multifractal claim must be surrogate-tested (shuffled + phase-randomized) and needs
~10³–10⁴ points; without that, MFDFA manufactures a spectrum from fat-tailed
uncorrelated data. Keep the multifractal layer flagged speculative.

---

## 9. The six counterarguments to pre-empt (for the paper)

A control/robustness reviewer will raise these; address each explicitly.

- **C1 — "Scope specification is itself a hard, reflexive problem."** The deepest
  objection: writing the floor's policy may be as hard as building the monitor, and an
  under-specified floor is a crude monitor with worse recall. Honest answer: the floor
  trades *recall-uncertainty* for *specification-uncertainty*, and specification is
  **static and auditable** while monitor behavior is adaptive and opaque. Measure
  specification completeness; don't hand-wave it.
- **C2 — "Usefulness collapse."** A floor tight enough for zero out-of-scope may reject
  huge amounts of legitimate behavior. You must report the floor's point on the
  **safety/usefulness Pareto** (§4), not just its safety.
- **C3 — "You've relocated the monitor, not eliminated it."** If any learned component
  sits inside the floor's *enforcement* decision, reflexivity re-enters. Your floor is
  only non-reflexive if the enforcement check is model-free *even when the action
  proposer is a model*. State exactly where the learned/deterministic boundary is.
- **C4 — "Monitors are improvable; the treadmill is just weak monitors."** Lean on the
  CoT-monitorability fragility consensus and Kale's awareness-axis to argue the
  degradation is **structural w.r.t. adversary awareness**, not a transient capability
  gap.
- **C5 — "Seams undercut your own floor."** If seam invariants must reason about
  composition, you've reintroduced a global monitor. Answer: seam invariants can also
  be non-reflexive (static cross-floor data-flow constraints); show at least one, or
  concede seams are an open problem (honest and fine).
- **C6 — "Game-theoretic over-claim."** "Strategy cancels → max-entropy" holds only in
  zero-sum *symmetric* sub-games (von Neumann minimax; pursuit-evasion), and security
  is asymmetric Stackelberg where the optimal defense is often *mixed* coverage.
  Pre-empt with the **full-coverage-limit** argument (§4) and bound the recursion claim
  with adversarial risk analysis / level-k (overview arXiv:2007.02613 **[VERIFIED]**).

---

## 10. Citation audit of your existing docs

- **CORRECTION (2026-10-20, re-verified at the primary arXiv pages).** An earlier audit
  flagged "SecRespond" and "Alert-Bench" as possibly-placeholder benchmarks and advised
  replacing them. **That verdict was wrong** — both are real papers the earlier audit's
  knowledge predated:
  - **SecRespond — REAL, citation stands.** arXiv:2607.26791, "SecRespond: Benchmarking
    AI Agents for Real-World Post-Compromise Incident Response." The abstract states "no
    model achieving complete detection and remediation on any single range," exactly as
    cited.
  - **Alert-Bench — REAL, citation stands (and now upgraded).** It is **ALERT-BENCH** from
    arXiv:2610.10608, "From Investigation Failures to Reliable SOC Agents." The paper
    reports that across 1,247 alerts in a multi-stage attack scenario, every approach
    missed at least 40.4% of attack-related alerts — so the "≥40% missed" claim is exact.
  - **CORTEX has a real arXiv id** (2510.00311, "CORTEX: Collaborative LLM Agents for
    High-Stakes Alert Triage") — cite the id, not just the venue. Its reported numbers
    (actionable F1 0.66→0.78, false-positive rate 24.9%→14.2%, median latency 152.4 s vs
    28–44.6 s for single-agent baselines) match what `docs/research/REALISM_RED_BLUE.md`
    already states.
  - **Stale pointer fixed.** The SecRespond citation is **not** in `FINDINGS.md`; the live
    cites are in `docs/RED_BLUE_DOCTRINE.md`, `docs/DUELSWARM_LIQUID_SPEC.md`,
    `docs/COEVO_RESULTS.md`, and `swarm/blue_llm.py`. Nothing needs replacing.
- **Confirmed solid** (already cited across your docs, independently re-verified):
  "Agent Security is a Systems Problem" 2605.18991; Fang 2404.08144; HPTSA 2406.01637;
  Incalmo 2501.16466; CAI 2504.06017; PSRO 1711.00832; MAP-Elites 1504.04909; PAIRED
  2012.02096; FlipIt (IACR 2012/103); AgentDojo 2406.13352; design-patterns 2506.08837;
  CaMeL 2503.18813; Kale 2508.19461.
- **Re-verify before formal citation** (resolved as listings, not fully confirmed):
  2606.15242, 2512.02682, 2507.01786, 2603.16928, 2607.26115, 2604.23067, 2608.18398
  (LEDGER), 2606.31422, 2609.00455, 2602.07666 (AIxCC SoK), 2605.21497; and confirm the
  ICML-2018 obfuscated-gradients id (likely 1802.00420) and Safety Gym 1910.01708.

---

## 11. The ten sharpenings that change the design most

1. **Make the objective-withheld vs objective-supplied success delta red's headline
   realism metric** (Fang 2404.08144). It turns the spec §5.1 fix into a number.
2. **Adopt Incalmo's task-abstraction + environment-state service for red**
   (2501.16466); your gate is the deterministic translator layer. Highest-leverage
   agent change.
3. **Switch the population's unit of evolution to a CVT-MAP-Elites archive** over
   stealth/speed/noise/path (1504.04909, 1610.05729). Structurally ends the collapse and
   *is* the instrument for Q1.
4. **Best-respond to a mixture, not the latest opponent** (PSRO 1711.00832 + Hall of
   Fame + α-rank 1903.01373). Kills cycling; frames the methodology as EGTA.
5. **Build the range curriculum as random-mutation + regret-prioritized replay first**
   (Robust PLR 2110.02439), graduating to ACCEL/PAIRED. Cheap robustness guarantee.
6. **Make the blue audit-budget an AI-Control safety/usefulness/cost Pareto**
   (Greenblatt 2312.06942), with CMDP λ as the FlipIt drop-out alarm. Unifies the
   economic layer with the safety framing.
7. **Reframe the tail layer around EVT shape parameter ξ (floor: ξ>0 → ξ<0), report
   Expected Shortfall, run the full Clauset gate, and anchor in ruin/non-ergodicity** so
   the floor's justification needs no tail index. Demote multifractal + attractor to
   surrogate-tested speculation.
8. **Close the gate's concurrency "sibling-leak" gap** (Stop Means Stop 2607.14166) and
   **upgrade the log to a Merkle history tree with split-view defense** (Crosby–Wallach;
   RFC 6962). The two highest-value fixed-point hardenings.
9. **Frame Q1 as Minimal Criterion Coevolution + Stackelberg commitment** (MCC/Soros;
   1401.3888) and measure attack-distribution migration toward the seams — rigorizes the
   flagship claim and validates the seams prediction at once.
10. **Write the six counterarguments (C1–C6) into the thesis up front**, and ground every
    red/blue success claim in verifiable environment state (ATLANTIS 2509.14589; GTG-1002).
    Pre-empting objections and refusing to trust the LLM's self-report are what move this
    from "cool demo" to "defensible research."

---

## 12. One honest meta-note

The literature does three things for you at once. It **grounds** the design (nearly
every spec component has a named method and a citation now). It **pre-empts** the
objections a reviewer will raise (§9). And it **sharpens the
claims to exactly what the data can bear** — the tail rework (§8.4) and the attractor
demotion (§8.5) make the work *more* credible by claiming *less*, which is the same
discipline your blog already shows. (The earlier "fix immediately" item here — an
allegedly unverifiable SecRespond citation in `FINDINGS.md` — has been retracted: see the
2026-10-20 correction in §10. SecRespond (2607.26791) and ALERT-BENCH (2610.10608) are
both real, re-verified at the primary arXiv pages; the cite was never in `FINDINGS.md`.)
