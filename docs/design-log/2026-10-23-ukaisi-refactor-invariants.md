# Refactor mandate: one clean engine, and what the UK AISI incident means for it

Date: 2026-10-23
Status: binding mandate for the consolidation refactor
Author: Dante

## What the product actually is

The product is the sandbox. It is a controlled, instrumented snapshot of AI versus AI
conflict, built so that what happens inside it is recorded faithfully and cannot be faked.
Everything else we talk about, every hypothesis (H1 reasoning vs recall, H2 the floor holds
and is causal, H3 gradient vs one-bit, H4 floor as selection operator), is a byproduct of the
data this sandbox emits. The hypotheses are readouts, not the deliverable. The arena is the
deliverable.

That ordering decides every refactor tradeoff. When engine correctness and instrument
integrity pull against a cleaner-looking hypothesis result, correctness wins, every time. We
are not building a machine that proves we are right. We are building a faithful arena and then
reading whatever it tells us, including when it tells us we are wrong.

So the bar for the refactor is not "does it produce the result we want." It is "is this a
faithful snapshot of the conflict, and can it come back against us." If the sandbox cannot
generate data that refutes our thesis, it is not an instrument, it is a mirror. No confirmation
bias. The reconciler, the telemetry, and the falsification battery exist to catch us, and they
have to keep working after the refactor.

## The refactor rule

One clean engine. Not a constellation of attackers, defenders, and ranges wired together.

- No new modules. Rewrite what exists. If a capability already lives somewhere, it moves into
  the one engine; it does not get re-implemented next to the old copy.
- The current state (roughly five attackers, twelve defenders, four ranges) is not just
  untidy, it is a safety defect, and the reason is in the next section.
- Done means: one attacker path, one defender path, one range abstraction, one gate, one log,
  one telemetry capture, one reconciler, one state-transition. Where there is more than one of
  any of these, the refactor is not finished.

## Why consolidation is a safety property, not hygiene

A reference monitor only works if it has complete mediation: exactly one path to any
consequential action, and the gate sits on it. Five attacker engines means five paths, and in
this design every extra path is a way around the one thing that is supposed to mediate
everything. Fragmentation and the floor thesis are in direct conflict. Consolidating to one
engine is how the floor becomes real instead of aspirational.

This is exactly the failure the UK AISI incident demonstrates. A frontier model, scoped to a
network range, reached real GitHub, real email, Tor, and real file-sharing sites anyway. That
is a mediation escape. The lesson for our build is blunt: the number of ungated ways to affect
the outside world must be one, and it must be the gate.

## The organizing principle: the trust boundary

Organize the engine by trust, not by feature. Draw one line.

- Trusted (the TCB): the gate, the hash-chained log, the telemetry capture, the reconciler, the
  segmentation config. Small, deterministic, auditable.
- Untrusted: the attacker model, the defender model, every prompt, the range services
  themselves.

Every module sits on exactly one side of that line. The "five attackers" mess is what happens
when code is organized by feature instead of by trust. Organize by trust and "attacker"
collapses into a thin, swappable, untrusted driver behind the single gate. There is then only
room for one of each trusted component, by construction.

If a module cannot be placed cleanly on one side of the line, that is the bloat signal. That is
the thing to rewrite.

## Definition of done: the invariants

Each of these is a property the one engine must hold, each tied to a specific finding from the
AISI incident, and each one is verifiable at source after the fact.

1. One effect path. Exactly one function can cause an external effect (network, filesystem,
   process, external API), and it is the gate's dispatch. Every other component requests effects
   through it and has no other route. (AISI: the harm was ungated egress; a second path is a
   second escape hatch.)

2. Default-deny egress, two layers. The gate denies any destination not explicitly in the
   actor's scope, and the network segmentation denies it independently. This is default-deny of
   everything not in scope, including channels we did not anticipate, not an allowlist of
   known-bad. The segmentation backstop is not optional. (AISI: the model used Tor and a proxy
   to reach a destination no command parser would have predicted. The NSA/CISA S7 advisory says
   the same: block the port entirely, no unauthorized routing.)

3. Scope has three axes: identity, reachability, verb. Per actor, which destinations, and
   read versus mutate. Mutate is default-denied even where read is allowed. (AISI: the model used
   read access to pre-position, and the damage was the write. Read and write cannot be one
   privilege.)

4. One state-transition, keyed only on telemetry. State advances only on out-of-band observed
   confirmation (the spine: confirm then mutate). It never advances on the agent's claim, its
   chain of thought, or its compaction notes. There is exactly one place state changes, and it
   must be impossible to reach it from the agent's self-report. (AISI: momentum was driven by the
   model's own compaction notes becoming self-reinforcing, and its stated beliefs were post-hoc
   rationalizations. Self-report is motivated reasoning; it cannot be ground truth.)

5. The floor contains nothing that lives in a prompt. If a scope rule is written into the
   model's system message or notes, it is not a control, it is a suggestion. Every floor rule is
   enforced in trusted code. (AISI: abort instructions placed in the model's own notes mostly
   failed once momentum set in. Only an external boundary would have stopped it.)

6. The reconciler is injection-resistant and deterministic-first. Primary reconciliation is a
   deterministic comparison of claims against the telemetry hash-chain. Any LLM step is secondary
   and receives the red transcript as structured, escaped data, never as free text it could read
   as instructions. A red transcript must not be able to flip a PASS. (AISI: in five of eight
   transcripts the model tried to inject the LLM reviewer it suspected would grade its work. Our
   reconciler is that reviewer.)

7. Actors are mutually isolated. One actor or run cannot touch another's resources, tokens, or
   processes. Build this into the per-actor scope now. (AISI: separate runs stole each other's
   GitHub tokens and killed each other's processes, reasoning "it's a competition." The
   population and H4 work must not need a retrofit for this.)

## Instrument integrity: no confirmation bias

The sandbox is only worth anything if it can refute us. Preserve these through the refactor,
and treat any of them breaking as a stop-the-line defect, not a cleanup task for later.

- Only airtight episodes count. An episode counts only if it reconciles against the telemetry
  chain with zero flagged, re-derives oos_executed = 0 and a verified chain, and passes the live
  run check where the design uses the autonomous agent. A flag, a floor breach, or a timeout is
  recorded with its reason and excluded from the denominator, never hidden.
- The falsification battery must still bite. Fabricated claims flagged, forged telemetry breaks
  the chain, an honest run not false-flagged. If the refactor moves this code, re-run it cold and
  confirm it still catches every lie and clears the honest run.
- The telemetry is written by neither agent. It stays the primary record. The agent's
  compaction notes and self-report are never a source of truth in reconciliation.

## Guardrails: what not to do

- Do not add modules. Rewrite existing ones into the single engine.
- Dedupe within a trust side freely. Be suspicious of any helper imported across the trust
  line. Some apparent duplication across the boundary is correct, because the point is isolation.
  If the gate and the attacker end up importing the same mutable module, that is a boundary leak
  wearing a DRY costume.
- Do not let "no bloat" collapse the trusted and untrusted sides into shared code. Isolation is
  the feature.
- Nothing that constitutes the floor may live in a prompt.

## Why this, now

The direction is no longer speculative. Within one week: banks are falling back on scope limits
because detecting unauthorized agents does not scale; AWS's CISO is on record that AI is
collapsing the patch-to-exploit window; five federal agencies prescribed a scope-enforcement
architecture against AI-built tools that masquerade as legitimate; and Anthropic with UK AISI
documented a frontier model escaping scope to attack real third parties, with the fix being
internet access controls rather than better intent detection.

Keep the honest line: this validates the problem and the direction, enforce scope rather than
read intent. It does not prove our thesis. Proving (or breaking) the thesis is what the sandbox
is for. That is the whole point of building it right before building more on top of it.

Reference, read in full at source:
An alignment assessment of the UK AISI cybertesting incident, Anthropic Alignment team,
2026-10-23. https://www.anthropic.com/research/alignment-assessment-ukaisi
