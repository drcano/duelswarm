# Design log — the observe-only control, and the confound it resolves (2026-10-27)

## The confound (found at source in the canonical seed-1337 chain)
The one "blue PREVENTED the theft" datapoint
(`docs/runs/2026-10-27-interleaved-canonical/episode01_seed1337.jsonl`) is confounded two ways:
- It ran the OLD flailing red (pre-`fe3e9ba`): one scan then FIVE consecutive fingerprints of the
  same host (seq 13–29) before exploiting at seq 33. The prompt fix came after this run.
- Blue contained dmz-web at tick 7 (seq 51). For the ~250 events after, red NEVER targets db-core
  (10.40.0.10): it loots the foothold itself, re-exploits dmz-web, and throws `cred_pivot` at
  out-of-scope gateways (10.90.0.1 / 10.90.0.12 / 10.0.0.1), all gate-blocked.

So red's failure is indistinguishable between "severed before it could pivot" and "never found the
database segment anyway." `duel.outcome.blue_detections = 1` — blue saw only the loud entry and
contained; there was no further path to observe because red never advanced.

Conclusion: the "data-theft is structurally blue-favored" / "balance impasse" framing is NOT
established. We have shown a loud entry gets contained fast (expected) and a flailing red never
reaches the crown (uninformative about balance). We do not yet know what the FIXED red does.

## Why observe-only is the control, not one option among four
A prevention claim is only meaningful against a red that would otherwise succeed. So before any
"blue prevents" result counts, we must show the SAME (fixed) red steals the crown UNOPPOSED. The
observe-only run is that control: blue runs its full real-telemetry detector every tick and logs its
belief, but takes NO containment/eviction/decoy action, so red is never severed.

It answers the one open question: can the improved red discover the inner segment, pivot to db-core,
and exfil on its own — and in how many ticks (the REAL red-path length, not the theoretical ~6)?

## Branch logic (what the result decides)
- Fixed red steals unopposed → we have a validated baseline + the real path length; the active-blue
  interleaved run becomes a genuine race and "blue prevents" is a causal claim. The honest flagship is
  then the pair: red steals unopposed (control) + active defender prevents (treatment).
- Fixed red still can't reach db-core unopposed → the bottleneck is red TRAVERSAL (inner-segment
  discovery + pivot tradecraft), not blue's speed. That's a red fix, and no cadence rebalancing would
  have made the contest real. Cheaper to learn from a tiny observe-only run than to tune blindly.

## Guardrails
- One engine: observe-only is a PARAMETER of the interleaved driver (blue detects, does not act), not
  a parallel path. The retired sequential path stays retired.
- No tuning in the loop: whatever red does is the datapoint; red is not adjusted mid-run; we analyze
  after it lands and decide on refinement then.
- Diagnostic, not the canonical floor datapoint — but the floor still re-derives cold (invariant),
  the instrument is untouched, blue stays label-free, red stays map-blind.
- We did NOT touch cadence or blue thresholds. The only change from the canonical config is blue's
  containment is disabled for this control.
