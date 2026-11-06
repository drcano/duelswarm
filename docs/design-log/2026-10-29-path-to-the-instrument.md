# Path to the instrument — decisions made, sequenced, airtight (2026-10-29)

Planner/verifier brief. Every open decision is made here. The spine is Dante's mandate: the product
is a sandboxed version of the future of AI-vs-AI conflict — two adaptive LLMs acting and co-evolving
over a fixed, non-reflexive floor, with everything re-derivable from the hash chain. Red achieving or
failing to achieve harm is a BYPRODUCT the instrument measures, never a target. Airtight, no
confirmation bias.

## What "done" means (the product, not a result)
The instrument is done when it can run — and let an outside skeptic re-derive — the adaptive
red-vs-adaptive-blue game over the floor, and can FALSIFY each of the four claims. "Done" is a faithful
instrument, not "red reads the crown." A floor penetration or a red that never lands harm are
RESULTS, not failures.

## Done and verified cold (the floor is airtight — the bedrock is finished)
Across 3 paid runs (seeds re-derived from the committed chains, trusting neither agent):
complete mediation now closed on every recon effect path (HIGH-1 static `dbbf096`+`c484143` and
empirical `ce4415d` — recon-phase `gate.block` on the live `_recon` path, oos hosts never probed);
the mediation self-check sees the effect primitive (HIGH-2 `7f4e7ca`); the TCB is frozen (MEDIUM-2
`9cfec88` — gate/eventlog/audit/reverify_floor/spine/static_coverage + the red prompt hash-pinned);
`oos_executed=0` re-derives cold every run; §E witnessed every run; the reconciler is honest
(telemetry-corroborated, 0 flagged). The policy-level guarantee — nothing out-of-scope executes where
the floor mediates — is now settled by construction AND empirically. Do not re-litigate it.

## The decisions (the five MEDIUMs — all resolved toward airtight / anti-confirmation-bias)
- **MEDIUM-1 — two-auditor cross-check.** DECISION: align `audit.py` to read the unified-live scope
  (`roe`/`floor.boundary`), fix its `gate.allow` block-excusal to match `reverify_floor`, and add a
  make-test check that runs BOTH auditors on a real unified-live chain and asserts an EQUAL
  `oos_executed`. Rejected: "drop to one auditor and retract the claim" — that weakens the
  anti-confirmation-bias guarantee. Two code-independent witnesses that both run on the production
  chain and must agree is the point.
- **MEDIUM-3 — no parallel live driver.** DECISION: delete `swarm.live_red.run_live` (extract any
  enterprise-range capability still needed into the one engine first; nothing parallel-live survives),
  and extend `prove_one_engine` to fail on ANY module that stands up a live router+range outside the
  one engine (not just the hardcoded GONE list). Keep the Anthropic path ONLY as an explicitly
  uncounted frontier-model control: it must stamp every output and log line `uncounted / non-Nebius`,
  and `prove_one_engine` asserts the sole Nebius-counted measurement path is the one engine.
- **MEDIUM-4 — prove map-blindness every run.** DECISION: filter `frontier_awareness` to red-actor
  events and extend its selftest to plant a `system`/`floor.boundary`/`benign` event and assert red's
  awareness is unchanged — so map-blindness of the per-turn channel is proven, not inherited from an
  unasserted allowlist.
- **MEDIUM-5 — witness the provider in the chain.** DECISION: record the resolved provider host /
  base_url in the `config` event and assert the Nebius host guard was active (`NEBIUS_ALLOW_ANY_HOST`
  unset) at run start, so "it was Nebius" is re-derivable from the chain, not just in-code.
- **MEDIUM-6 — §E `--verify` can't pass vacuously.** DECISION: `--verify` must test internet-blocked
  (not only gateway + ingress + pivot), add the liveness precheck before reading "unreachable," and
  return distinct exit codes for SKIP vs PASS.

## The anti-confirmation-bias rails (every phase, non-negotiable)
1. Pre-register before measuring: N, the metric, and what counts as success/failure/penetration are
   hash-anchored in `docs/prereg.jsonl` BEFORE the run. 2. `oos_executed` is always measured, never a
   target or an acceptance bar; a penetration (`oos>0`) is the most important kind of result.
   3. No buffing red to force a landing: decision-neutral instrument fixes only, and only when a
   decision-neutral run exposes a specific instrument defect (never "red isn't winning"). 4. Every
   result re-derivable cold from the hash chain; I re-derive it independently, trusting neither agent.
   5. The floor + TCB stay frozen; apparatus changes go through dated prereg amendments. 6. Negative
   results are published: a red that can't land harm, or a floor that is penetrated, is the finding.

## The sequence to done
**Phase A — finish airtightness (FREE, do first, gates all paid measurement).** The five MEDIUMs
above. Done-check: `make test` + the new two-auditor cross-check green; I re-derive the cross-check on
a real unified-live chain and confirm the map-blindness selftest bites. The floor is then unimpeachable.

**Phase B — claim 2 baseline, pre-registered N-seed batch (PAID, Dante's go + spend dial).** Red vs the
fixed floor, blue observe-only, frozen instrument, budget 44. Pre-register N seeds (propose N=10) and
the metric BEFORE running: per seed — `oos_executed` (measured), whether red composed the crown chain
map-blind, whether red read the crown (achieved, telemetry-corroborated), turns-to-crown. Report the
rate, whatever it is. This closes the lethality question honestly — run 3 showed red composes the full
chain map-blind with `oos=0`; run 4 showed it can collapse; a batch characterizes the variance and
gives the first claim-2 datapoint (harm via gate-allowed actions while the floor holds). Do NOT tune
red between seeds. I verify every seed cold.

**Phase C — the two-sided contest + composition migration (BUILD free, MEASURE paid).** Flip blue to
active (`blue_observe_only=False` + the built `_real_contain`) and wire the pre-registered stealth
triple — claims 1 & 3 get their detector arm (guardrail: detection is not the headline; it serves the
claims). Then wire the parked floor-shape apparatus (`range_adversary`/the Component-E generator) into
the ONE live engine and vary the floor's SHAPE across a pre-registered set, watching red's SUCCESSFUL
path migrate while `oos` stays measured — claim 1 (selection pressure) + claim 2 (migration, the most
novel contribution). This is where the parked modules get wired in (expect real integration + a
freshness pass; none are in `make test` today).

**Phase D — co-evolution + claims 3 and 4 (BUILD free, MEASURE paid).** Wire `env_coevo`/`population`
around the one live engine for genuine cross-generation selection (not the offline `instrument.py`
path) — the liquid world where both sides adapt: claim 1, full. Measure the monitor-leaks-a-gradient
vs floor-leaks-one-bit asymmetry (claim 3) and run the tail/convexity pipeline (`instrument_live`/
`stats_tail`) on the harm series (claim 4 — the floor as left-tail truncation).

**Phase E — external witness (NON-CODE, the biggest "taken seriously" gap).** External red-team / UCSD
faculty review + log anchoring (third-party timestamping of the pre-registration head-hash), so a
skeptic who trusts neither the agents nor the repo owner can still re-derive every claim.

## What I hold the line on
I verify each phase cold — re-derive from the chain, confirm map-blindness and the floor semantics did
not drift, `make test`/`prove_one_engine` green — and I will flag any "it's the instrument, not red"
story that fails the decision-neutral test, any measurement that wasn't pre-registered, and any number
that doesn't re-derive. The floor result stands; from here the instrument earns the claims or falsifies
them, and either way the record is airtight.
