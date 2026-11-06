# Future direction — instrument a layer-CROSSING migration + measure the observability collapse

**Status: HORIZON / unbuilt.** A future-plans entry, not a committed plan and not a result. It sits
*beyond* the current arc (Phase 1 populate → Phase 2 contest → Phase 2.5 composition-migration →
Phase 3 co-evolve). Captured 2026-10-29 from a design conversation; the experiment design is open.

## The idea (headline)
The sharpest experiment is **not** "does the floor hold." It is **reproducing harm as it crosses DOWN
a layer boundary — from the policy/composition layer into a resource / timing / side-channel layer —
under instrumentation, and quantifying the telemetry you go blind on as it crosses.** The empirical
version of the whole thesis: not "seams exist," but *"here is harm measurably crossing a seam, and here
is exactly how much we stopped being able to see as it did."*

Claim 2 as currently built shows harm migrating *within* a layer (allowed-action composition at the
policy level, `oos_executed=0` while the crown is stolen). This direction is migration *across* a layer
— the next floor down — with the observability loss made a measured quantity.

## The through-line that motivates it (why this is the prize)
1. **Security is location, not prevention.** Reflexivity (the adversary adapts to whatever you build)
   and fourth-quadrant unpredictability make prevention a mirage. So you stop playing the probability
   game and play the *location* game: control where the inevitable failure lands, and guarantee it lands
   somewhere survivable. The gate truncates, it doesn't detect. Containment = choosing which battles you
   are willing to lose.
2. **Seams are the adversary's native habitat, not gaps in your defense.** Defenses are layer-bound
   (the gate reasons about policy, the firewall about packets, a kill-switch about power — each smart
   within its layer, blind to the others). A capable attacker is not layer-bound; it composes *across*
   layers. The OpenAI airgapped-cache channel (two processes "that cannot talk" conversing by modulating
   a shared cache) and the UEFI-below-the-OS bug are the pure cases: nothing breached the layer the
   containment reasoned about; the harm stepped to the floor beneath it, where that reasoning didn't
   reach. So duelswarm is really a **seam-discovery instrument**: hold a floor to watch where a capable
   adversary goes; where it goes *is* the seam, revealed by behavior rather than guessed.
3. **Observability collapses as harm descends — and that collapse is why the kill-switch exists.**
   Policy layer: rich telemetry (hash chain, the gradient the monitor leaks). Composition layer: you see
   allowed actions, not intent. Microarchitectural layer: a timing channel leaves ~no application trace.
   So control degrades with depth: **mediate intelligently** (the gate, per-action) → **truncate the
   tail** (the floor, one bit: blocked/allowed) → **sever blindly** (the kill-switch, zero bits — you
   can't reason about the silicon, only cut power). The kill-switch is not a separate idea from the
   floor; it is what the floor *degrades into* at the bottom of the stack when observability hits zero.
   Containment is a gradient that starts as intelligence and ends as a circuit-breaker.
4. **§E is already the kill-switch.** The host-egress firewall + kernel segmentation — blind,
   by-construction, non-negotiable, never let a capable red run without it — is the hardware-ish bottom
   layer of our own stack. The two-floor architecture we enforce (hard §E = safety, blind; gate policy
   = intelligent, observable, the object of study) *is* "smart truncation on top, blind sever at the
   bottom." The hardware-kill-switch intuition and §E are the same concept at two scales; the stack
   forces the re-derivation.

## What the experiment would have to do (open design)
- Pick a concrete lower layer to instrument as the *destination* of a migration (candidates: a shared
  resource / cache-timing channel, a scheduler or quota side-channel, a filesystem/IPC substrate two
  "isolated" actors share) — something with a real, reproducible crossing.
- Hold the upper floor (the gate) so the *only* path to the objective is across the boundary, the way
  Phase 1's least-privilege seam forces composition.
- Instrument BOTH layers, and measure the **observability delta**: how much of the harm is witnessable
  above the boundary vs below it. The deliverable is the crossing *and* the quantified blindness, both
  re-derivable cold like everything else.
- The novelty: the cache-channel / UEFI stories are the field saying this is where the real tail lives;
  nobody has a clean instrument that *reproduces the crossing and measures the blindness*. That gap is
  the lane.

## Reflexive corollary (the same structure, turned inward)
The instrument is itself a layer in this stack, so it has seams, and **epistemic harm — a false result
— migrates into them the same way.** Every integrity failure this project has caught was harm in the
instrument's own seams: the reconciler under-witnessing (false negatives), the §E probe read on the
wrong key, the fingerprint tax starving the measurement, `oos_executed` slipping from a measured
hypothesis into an engineered target. "Nothing is secure" applies to the measurement, not just the
sandbox. The cold-re-derivation discipline is not hygiene — it is the same truncation device aimed at
our own confirmation bias, at the one layer we are most blind to because it is us.

## Caveats
Unbuilt and deliberately downstream of the current arc — do NOT let it pull focus from Phase 1
completion or the instrument's integrity. It is a horizon to protect, not a task to start. The specific
lower layer, the crossing mechanism, and whether it can be reproduced deterministically + measured cold
are all open questions; this entry exists so the idea survives, not because the design is settled.
