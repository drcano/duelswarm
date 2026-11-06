# Sandbox definition-of-done + gap audit (2026-10-27)

The PRODUCT is the sandbox. The answers to the four claims are a BYPRODUCT of a sandbox built well
enough to trust whatever it emits. This is the done-bar and an honest audit of where each piece stands.
No rush; the only standard is airtight, no gaps, nothing a serious reader can contest.

Integrity bar for every line: **runs-for-real and re-derivable cold, or labeled scaffold** — never a
faked result; every statement the range produces is re-derivable from the hash chain, scoped to a
design guarantee, or labeled pending; and load-bearing results are **witnessed by something other than
Dante or Claude** (the kernel, a mechanical checker, an external reviewer).

State tags: [AIRTIGHT] proven + externally re-derivable · [BUILT·VERIFY] built, I verified it this
session but it wants an independent/kernel witness · [BUILT·UNCONFIRMED] built per report, I have not
re-derived it · [GAP] missing or only in a proof script · [SCAFFOLD] stands in, must stay labeled ·
[WITNESS] needs a witness outside Dante+Claude.

Hackathon viz is explicitly OUT of this document — a thin read-only animation over one exfil run, no
research weight, not on this critical path.

---

## A. The non-reflexive invariants — the floor and the log (must be proof-grade)
- **A1 Complete mediation** — every effectful action passes the gate; the one-effect-path is proven by
  a static AST oracle, and the only raw sinks are hand-verified benign.
  State: [BUILT·VERIFY for the old engine] — `static_coverage.py` + the 2 known sinks. GAP: re-run it
  against the ONE consolidated engine and confirm no new ungoverned sink crept in across all the
  increments. Until that's current for the live engine, A1 is not airtight.
- **A2 The gate cannot be bypassed at the boundary** — canonicalization / egress / resolver.
  State: [BUILT, honestly bounded] — the command-text parser is known-insufficient (a fuzzer found 3
  encodings + 21 shell tricks it mis-reads); the real barrier is kernel-level network segmentation,
  confirmed by conntrack/eBPF reachability. Airtight requires: the floor's guarantee is stated as
  resting on the SEGMENTATION (kernel-witnessed), with the text check explicitly a second layer, and
  the fuzzer corpus kept as the standing evidence it's bounded. [WITNESS: kernel]
- **A3 The log is tamper-evident and re-derivable by an independent checker** that trusts neither side.
  State: [BUILT·VERIFY] — hash chain + `reverify_floor` (imports neither gate nor engine); I've
  re-walked it cold many times this session. GAP: the log is tamper-EVIDENT, not tamper-PROOF — Dante
  holds the file; it is not anchored to an outside witness. [WITNESS: external anchor]
- **A4 The policy guarantee (oos=0 where mediated) is PROVEN, with named assumptions** — not merely
  observed across runs.
  State: [BUILT·VERIFY] — `reverify_floor` cold + the falsification harness + static coverage. GAP: the
  invariant is not yet written up with its explicit assumptions and witnessed by a party other than
  Dante or Claude (an external red team / UCSD faculty / a mechanical oracle). This is the single
  biggest "taken seriously" gap. [WITNESS]

## B. The range — a real populated world that mimics real systems
- **B1 Realistic, segmented topology** (tiers, least privilege, the credential graph, the crown),
  seed-generated and reproducible.
  State: [GAP] — the unified Samba-AD/Struts range exists, but it's over-permissive (most candidate
  hosts can reach the crown) and the composition topology the experiments need isn't realized on it.
  Done = a least-privilege segmented range where few hosts legitimately reach the data tier.
- **B2 Real legitimate activity** — the world is not empty; real logins, service traffic, routine
  process activity, so a single event is not uniquely attacker.
  State: [GAP] — the live range generates zero benign activity; the benign baseline exists only in a
  proof script, not wired to the live range as real traffic. This is the biggest construction gap: with
  an empty network the sandbox cannot host the composition story or honest co-evolution.
- **B3 Real services + real vulnerabilities**, real detonation, labeled real-or-modeled.
  State: [BUILT·VERIFY, native] — 5 vetted CVEs, real exploits; must run on the native Intel host (not
  Mac emulation) for anything load-bearing, each break-in labeled real/simulated.
- **B4 Terrain that reshapes** (the liquid stage; terrain-as-adversary).
  State: [SCAFFOLD] — proven offline only so far; must stay labeled scaffold until it runs for real.

## C. Red — a genuine adaptive attacker
- **C1 Autonomous LLM red, map-blind, real tradecraft** (real exploit/pivot/exfil-on-bytes).
  State: [BUILT·VERIFY] — `assert_red_map_blind` enforced + I verified it; real exfil on bytes; matched
  tier (fair duel). Solid.
- **C2 Varied identity as an attribute** (loud/quiet, exploit/assumed-breach) on the LIVE path.
  State: [GAP] — the live path is loud-Struts-only; the varied/quiet identities live only in the proof
  harness, unwired. Done = red's identity is a dimension the live range runs, not a script.
- **C3 Memory + genuine cross-generation co-evolution.**
  State: [BUILT·UNCONFIRMED] — `coevolve`/`episodic`/`population` exist; I have NOT confirmed they are
  wired into the one live engine as real co-evolution (vs separate modules). The goal requires genuine
  co-evolution, so this needs verifying or wiring. [needs source verification]

## D. Blue — a genuine adaptive defender (for the claims that need it)
- **D1 Adaptive LLM blue, label-free, governed by the same floor** (its counter-offense is gated too).
  State: [BUILT·VERIFY] — real-telemetry, label-free (I verified the guard + discriminator), gate
  governs the defender's offense.
- **D2 Blue's role correctly scoped** — blue is for the selection/monitor claims (1, 3); the floor's
  composition claim (2) is red-vs-floor. Blue is never the centerpiece; detection is the thing the floor
  transcends, not a headline metric.
  State: [AIRTIGHT, framing] — corrected today.
- **D3 Blue memory / co-evolution.**
  State: [BUILT·UNCONFIRMED] — same as C3; verify wiring.

## E. The output discipline — the byproduct is airtight
- **E1 Every produced statement is re-derivable cold, scoped to a guarantee, or labeled pending.**
  State: [BUILT·VERIFY] — the discipline is in place; done = it is enforced with no un-re-derivable
  claim anywhere in what gets published.
- **E2 Pre-registration before any measurement**, hash-anchored, nulls kept in.
  State: [BUILT·VERIFY] — `prereg.jsonl`, dated amendments, nulls retained.
- **E3 Falsification harness** — the checker catches fabricated runs; an honest run passes.
  State: [BUILT·VERIFY] — `prove_falsification`.
- **E4 Witnessed by something other than Dante or Claude.**
  State: [WITNESS — GAP] — currently every result is Dante + CC + me. For the research to be taken
  seriously this needs an external leg: kernel-truth, a mechanical oracle, and ideally an outside
  reviewer (UCSD faculty / external red team). The highest-leverage credibility item.

## F. The instrument's own integrity — one engine, no bloat, no theater
- **F1 One red driver, one blue, one range generator, one instrument, one duel loop** — the measurement
  path unambiguous, no parallel rigs, no dead code reachable.
  State: [GAP, in progress] — I found three reachable duel paths (unified interleaved; the legacy
  generated-sequential `_run_live_episode`+`run_blue_fight`; and `measured_duel.py`). Part 0 is closing
  this; done = one reachable measurement engine, verified.
- **F2 No faked results** — every mechanism runs-for-real or is labeled scaffold.
  State: [BUILT·VERIFY, ongoing] — the standing audit; must be re-run whenever the engine changes.

---

## The honest shape of it
Strong and close to airtight: the floor + log + the proof/pre-reg/falsification discipline (A3, A4
mechanics, E1–E3), and red/blue as real agents (C1, D1). The gaps that actually stand between us and a
research instrument with no gaps are four, and they are construction, not measurement:
1. **B2 — a real populated range** (benign activity + realistic segmented topology B1). Nothing honest
   runs on an empty network.
2. **F1 — one engine**, measurement path unambiguous (Part 0).
3. **C2/C3 (and D3) — red/blue as their full varied, co-evolving selves on the live path**, not in
   proof scripts.
4. **E4/A3/A4 — an external witness**: kernel-truth where it isn't yet, log anchoring, the invariant
   written with named assumptions and reviewed by someone who is not Dante or Claude.

Close these, in roughly that order, and the sandbox is the instrument — and the data for the four
claims is what it emits when it runs. Nothing here is driven by a date.
