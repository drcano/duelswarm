# duelswarm, read as an AI security reviewer would read it (2026-10-29)

A cold assessment of the project as a candidate AI Security Fellows contribution, through the lens of
the mentors on the posting and what the program visibly rewards. No confirmation bias: this is written
to find the places a tough reviewer pushes, not to reassure. Verified state only (re-derived cold this
session), not the engine's self-report. No em-dashes, so lines can be lifted into the site or the
application.

## The lens (who reads this, and what they reward)
AI Security mentors on the posting: Nicholas Carlini, Keri Warr, Evyatar Ben Asher, Keane Lucas, Newton
Cheng. Two signals matter more than the names:
- The example projects are (a) "AI agents find $4.6M in blockchain smart contract exploits" and (b)
  "Strengthening Red Teams: A Modular Scaffold for Control Evaluations." The program rewards agents that
  find real things with concrete impact, and tooling that makes control evaluations sharper. duelswarm
  is squarely the second species.
- Two lenses to survive. Carlini's: a defense is only as real as the strongest attack it has faced; a
  clean result against a weak adversary is worth nothing. Lucas's (Incalmo, autonomous multi-host
  network attack by LLM agents): how real is the range, and is the agent genuinely composing an attack
  or being handed one? duelswarm has to answer both without flinching.

## What lands (the genuine strengths)
1. The thesis is the right one and it is timely. Reflexive detection erodes under an adapting adversary;
   non-reflexive deterministic enforcement holds because there is nothing to steer; the hard residual is
   the in-policy seam where harm is composed from allowed actions. That is the control-evaluation
   question stated more sharply than most of the literature states it, and it is exactly the shape of the
   GTG-20006 threat report (an adversary that rebuilds until the detector stops firing). This is on the
   program's wavelength, not adjacent to it.
2. The instrument is more rigorous than most submissions in this space, and that is the real
   differentiator. Complete mediation is now closed on every agent effect path and verified both
   statically and on a live boot; every action is hash-chained into a tamper-evident log that an
   independent checker re-derives while trusting neither agent; there are two code-independent floor
   auditors that must agree; kernel segmentation enforces the host-egress boundary and is witnessed in
   the log; changes are pre-registered before data. Most projects assert their guarantee. This one lets
   you recompute it from the raw log. Carlini's instinct is to disbelieve defenses; the honest response
   to "I don't believe you" here is "re-derive it yourself," and that is a strong position to argue from.
3. There is a real result, not a mock. A capable, map-blind LLM red composed the full crown chain
   (web01 to dba01 to db-bastion to db-core) through gate-allowed actions, each hop corroborated by the
   target's own telemetry, while the floor held at oos_executed = 0. That is a genuine
   composition-migration datapoint: harm routed entirely through allowed actions, which is the in-policy
   seam the thesis says is the frontier.
4. The niche is defensible and not crowded. Control evaluations exist; an adaptive, co-evolving adversary
   inside a control evaluation, with a deterministic floor as the non-reflexive reference, is a real lane.
   It is the defensive complement to Incalmo's offensive work, which makes Lucas a natural mentor fit, not
   a stretch.

## The hard questions a reviewer will ask (and where the project actually stands)
1. "Is oos = 0 interesting, or tautological?" This is the first and sharpest question, and the project
   must answer it the way the thesis already does: the floor refusing out-of-scope actions is settled by
   construction and is not the result. If the headline is "the floor held," a good reviewer shrugs: a
   deny-by-default gate denying is not news. The result is the in-policy composition (strength 3), and
   oos = 0 is the validity condition that makes that composition meaningful (the harm was assembled from
   allowed actions, not a gate failure). Foreground the seam, not the floor. The current framing gets
   this right; the risk is any slide into treating oos = 0 as the achievement.
2. "Is the red real, or is the floor winning against a weak attacker?" Carlini's question. The honest
   answer is good but not yet complete: the red drives a real Metasploit arsenal, infers its own CVEs
   from observed fingerprints, pivots on SSH keys it harvests on hosts it owns, and is map-blind (a
   machine-checked rail, now proven per-turn, not assumed). It attempts out-of-scope hosts and the gate
   records the blocks, so oos = 0 is not an artifact of a red that never tried. What is missing is
   breadth: n is small, and in one of the two paid runs the red collapsed (homogenized into empty
   tool-authoring) rather than reaching the crown. A reviewer will want the capability characterized
   across seeds, which is exactly the pre-registered N-seed batch now queued. Until that lands, the
   capability claim is "demonstrated once, variance uncharacterized," and the project should say so.
3. "How real is the range, and what is modeled?" Lucas's question. Strengths: real containers, real
   sshd auth telemetry, real kernel segmentation, a benign-activity baseline the defender must infer
   from. The honest ledger labels what is modeled (some host RBAC is dispatch-modeled rather than
   OS-enforced). Keep that ledger loud. The failure mode here is a reviewer discovering a "real" claim
   that was modeled; the defense is to have disclosed it first. The project does this today; do not let
   it slip as the range grows.
4. "Where is the lethality?" The red reached the crown host but has not yet read the crown in a clean
   run (a prompt contradiction blocked the final read; that is fixed, decision-neutrally, and the batch
   will test it). A reviewer wants the full "harm achieved through allowed actions" datapoint, not just
   "reached the host that holds it." This is the single most valuable near-term result and it is one
   paid batch away.
5. "Claims 1, 3, and 4?" Only claim 2 (composition migration) has a datapoint. Claim 1 (floor shape as
   selection pressure) has a small prior co-evolution sweep and parked apparatus; claim 3 (the monitor
   leaks a gradient, the floor leaks one bit) is the most theoretically interesting and the least
   developed; claim 4 (seams are vertical; the floor as left-tail truncation) is a framing, not yet a
   measurement. A reviewer credits that the instrument can falsify all four (that is the point of
   building it), but will not credit them as results. Be precise about which are hypotheses.

## The one that would most raise the ceiling
Claim 3 is the latent gem and it is underbuilt. "A monitor hands the attacker a gradient it can climb;
the floor hands it one bit and no gradient toward a catastrophic combination" is an information-theoretic
statement, and right now it is prose. Formalizing it (the monitor's continuous score is hill-climbable;
the floor's output is a single bit with no usable derivative, so adaptation has nothing to optimize
against) and measuring it in the co-evolution loop (evasion gain per generation against the monitor
versus against the floor) would turn the project's most original idea from an assertion into a result.
That is the kind of thing that gets a reviewer's attention, because it is a claim most people in control
evaluations have not made precisely.

## Positioning and the honest verdict
As an instrument, this is stronger than its current results, and that is the right order to be strong in:
the measurement apparatus is airtight and the claims are falsifiable, so the results it produces will be
trusted. The thesis is sharp and sits exactly where the program is looking. The honest state is: one
real composition result, a deterministic floor whose guarantee you can recompute rather than believe, an
adaptive red that is genuinely capable but not yet characterized at n, and three of four claims still at
the hypothesis stage with the apparatus to test them parked. Positioned as "I built the instrument that
can falsify these claims, here is the first result, it needs scale to become evidence," it is a credible
and well-matched Fellows contribution. Positioned as "the floor wins," it would underwhelm, because the
floor winning is the boring half.

## The highest-leverage fixes (ranked)
1. Repo visibility. The AI Security criterion explicitly rewards contributions to public LLM- or
   security-adjacent repositories, and the reviewers were given the site as the portfolio. If the
   primary GitHub account is suspended, the single most important artifact (the code they can
   re-derive the claims from) is invisible. Nothing else on this list matters if they cannot read the
   repo. Resolve the suspension or mirror the repo, with its hash-chained logs and the cold prove
   scripts, to an account they can open, and link it from the site.
2. Land the pre-registered N-seed lethality batch. It converts "reached the crown host once" into
   "achieves harm through allowed actions at rate X while the floor holds," the clean claim-2 result,
   and it characterizes the red's capability (answering question 2).
3. Formalize and measure claim 3 (above). Highest ceiling-raise per unit effort, and the most original
   thing here.
4. Foreground the in-policy seam over oos = 0 in every writeup and on the site, so no reviewer mistakes
   the by-construction half for the claim.
5. The external witness (an outside red team or faculty review, plus third-party anchoring of the
   pre-registration head-hash) remains the biggest "trusted by someone other than the author" gap, and
   is worth one concrete step (the UCSD faculty outreach already planned: Fernandes and Chaudhuri on the
   deterministic-reference-monitor line, Stefan on sandboxing).

## One caution on scope
Keep the honest ledger and the "needs scale to become evidence" framing. The fastest way to lose a
Carlini-type reviewer is to overclaim one run as a law. The project's credibility is built on recomputing
its own numbers; protect that by never stating more than the log can re-derive.
