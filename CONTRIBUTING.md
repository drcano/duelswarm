# Contributing to duelswarm

This repo is a research instrument. Contributions and critique are welcome; the discipline the repo
operates under is listed below so new contributors engage with it in the shape the research needs.

## The discipline, in one page

**Pre-registration.** Every measurement-affecting change is pre-registered in
[`docs/prereg.jsonl`](docs/prereg.jsonl) before the paid run that scores against it. The amendment
carries the artifact SHA256 manifest at the time of pre-registration and a one-line rationale.
Amendments cannot be rewritten (the chain breaks); corrections land as a new amendment with its own
rationale.

**One engine.** There is one authorization gate (`swarm/gate.py`), one event log
(`swarm/eventlog.py`), one measurement runner (`scripts/live_arms_race_run.py`). If a capability
needs to be added, it is moved into the one engine, not re-implemented next to it. The import
graph is checked by `scripts/prove_one_engine.py --selftest`.

**Cold re-derivation at source.** Readiness is not `make test` passing; it is a party trusting
neither agent being able to re-derive each result from the raw hash chain. The cold auditors in
`redteam/` are standard-library-only and import nothing from `swarm/` (the lone exception,
`stats_tail.py`, is an offline statistics helper off the floor-re-derivation path). Every committed run writes
a `prove_<name>.py` in its archive that reproduces its claims from the chain alone.

**Decision-neutrality.** A legitimate improvement to the attacker gives it better tools or
information keyed on its own observations. It must never make the attacker's decision, hand it the
ground-truth map, or let the orchestrator play the game. The litmus is specific: a fix that only
helps on the one range it was tested on is bias, not an improvement. Generality is checked on
held-out variants the attacker never saw (`docs/held-out/`).

**A floor penetration is a result, not a build failure.** The one guarantee that must hold by
construction is that every effect is recorded. An unrecorded effect is the only real build failure.
If the authorization enforcer is penetrated on some seed, the chain records it, the cold auditor
surfaces it, and that is the finding.

**One provider per run.** Every run pins its model provider at start, recorded as a
`provider.pinned` event in the hash chain. Any model call whose host does not match the pin is
refused at the API boundary. Any configured provider is valid; what is forbidden is a silent swap.

**Air-gap between red and blue.** Blue reads only the telemetry red's actions emit — never red's
plan, memory, or thoughts. The gap is the asymmetry under study (claim 3); a leak voids the result.

## What a good contribution looks like

- A dated brief in `docs/design-log/` naming the change, the hypothesis it tests or the defect it
  fixes, the pre-registered acceptance criterion, and the cold-re-derivation that would prove it.
- An amendment to `docs/prereg.jsonl` with `--rationale` capturing the WHY in-payload, if the
  change touches the measurement path.
- A `prove_<name>.py` in the run's archive if the contribution is a measured result.
- Tests that bite when they should: a selftest asserting a known-bad input is caught, not only
  that a known-good input passes.
- An honest statement of what the change does not do (gaps are first-class in the design-log).

## Reporting a defect

If `make verify` fails on your machine, that is a finding. Open an issue with the output and the git
SHA. The pre-registration amendment history is in
[`docs/prereg/RATIONALES.md`](docs/prereg/RATIONALES.md).

If you can produce a chain whose hashes verify but whose authorization floor is penetrated
(`oos_executed > 0`), that is one of the strongest results the repo can produce — open an issue
with the chain archive.

## Scope

This repo is a research instrument. It is not a general-purpose attack framework and should not be
pointed at external targets. Everything runs in the sandboxed Docker range. The code is MIT
licensed; the research questions are open.
