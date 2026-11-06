# Design log — stealth vs detection, and why the benign baseline is the build (2026-10-27)

Decision record. The loud-entry contest is a foregone conclusion and we are not running it (Dante's
call; confirmed at source — the range generates NO benign activity, so blue detecting the only traffic
on an empty network is trivial, not a result). The real contest is stealth vs detection. This log sets
the design; execution is in `CC-brief-stealth-detection.md`.

## Why "make red quieter" is not enough (the load-bearing point)
A real attacker is not loud, so red should enter via a valid credential (assumed breach), not a ~0.9
Struts fault. But a quiet red on an empty network changes nothing: with zero benign logins, blue just
alerts on the ONLY login that ever happens — still trivial. Stealth is only meaningful when there is
legitimate activity to hide inside. So the irreducible core of the contest is three things TOGETHER;
none works without the benign baseline.

## The three pieces (all required)
1. **Benign baseline (the enabler).** A deterministic-per-seed population of legitimate activity that
   emits the SAME telemetry classes red uses — admin SSH logins between hosts, service-to-service
   connections, routine process/syscall activity. Labeled benign ONLY in ground truth; blue never sees
   the labels and must discriminate from telemetry alone (the mirror of red's map-blindness). Enough
   volume that a single login/connection is not uniquely attacker.
2. **Quiet red (assumed breach).** Red starts from a valid low-priv credential foothold (models initial
   access already achieved by phishing/prior compromise), NOT the loud exploit. Lateral movement is
   credential-reuse / valid logins (T1078/T1021) and living-off-the-land, so red's actions resemble
   benign admin activity. Red stays MAP-BLIND: it holds a cred, not the crown location / graph / scope.
   Objective unchanged — reach db-core, exfil the real PII — but now it must blend to get there.
3. **Discriminating blue.** Blue can no longer alert on the presence of a login (benign logins exist).
   It separates red from the baseline by BEHAVIOR — anomalous login-graph edges (a host that never
   touches db-core suddenly does), lateral sequences, access to sensitive hosts — still LABEL-FREE from
   telemetry. And it now carries a FALSE-POSITIVE cost: containing a benign host is measured damage.

## What this unlocks (the measurement)
A genuinely two-sided contest with a real recall-vs-false-positive tradeoff, over N pre-registered
seeds, reported as a triple:
- stealth-success rate: red exfils the crown without blue containing it in time;
- detection rate: blue contains red in time;
- false-positive rate: blue contains >= 1 benign host.
Blue's threshold trades detection against false positives — a real ROC-like curve, not a foregone
conclusion. The floor reading stays invariant and ordering-independent (`oos_executed`, chain verify,
§E) and re-derives cold on every seed, regardless of the stealth outcome.

## No tuning (the guard)
Pre-register BEFORE measuring: the benign-activity model (rate, which host pairs, pattern), red's
evasion repertoire, and blue's detector logic + threshold. Then measure whatever happens. We do NOT
tune red quiet enough or blue blind enough to manufacture a race. "Stealthy red evades X/N" and "blue
still catches it" are equally valid results. Realistic mechanisms in, measurement out.

## Invariants (unchanged)
- Instrument untouched (`gate/eventlog/spine/audit/reverify_floor`). Benign baseline lives in the range
  generator; quiet entry + evasion in red; discrimination in blue. The gate/chain/auditors don't move.
- Red map-blind; blue label-free (benign/malicious labels are ground-truth for SCORING only, never in
  blue's view — the exact mirror of the map being hidden from red).
- No destructive tooling (log-tampering stays out — it is loud AND instrument-sensitive AND deferred).
- Floor re-derives cold on every seed. Nothing pushed; Nebius-only counted; author drcano.

## Deadline honesty
This is the biggest build yet and the benign baseline is real work; the full version may not land clean
by Thursday. We do NOT fake a stealth result to hit the clock. If it lands, it is the flagship. If not,
the honest Thursday deliverable stands on its own: the verified 8/8 unopposed capability result, the
floor holding cold across every run, the real-time interleaved engine + real-telemetry blue, and this
stealth engine dry-verified — framed as "loud detection is trivial; the meaningful defender problem is
stealth vs detection, and here is the instrument for it."
