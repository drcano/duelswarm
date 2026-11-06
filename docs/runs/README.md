# Committed run archives

> **Shorthand:** the per-run READMEs use project shorthand (`§E` = the host egress firewall,
> `seq-N` = a pre-registration amendment, `A-D1`/`B-E1` = build-phase task IDs, `oos` = out of
> scope, and so on). Every token is glossed in [`../GLOSSARY.md`](../GLOSSARY.md).

Each dated subdirectory holds the committed cold-provable artifact for one run:

- `chains/` — the hash-chained main log, the full-I/O sidecar, and the per-episode telemetry
  sidecar, gzipped. The main chain's hashes link back-to-front; the IO sidecar pins each entry
  into the main chain as an `io.record` event. See `redteam/verify_io_sidecar.py` and
  `redteam/reverify_floor.py` for the cold auditors.
- `prove_<name>.py` — a standard-library-first script that re-derives every claim the run makes
  from the chains alone. No Docker, no API key, no external data. Runs under 30 seconds.
- `README.md` — the dated verification log for the run: what it tested, which invariants held,
  which fields the chain recorded, and what the honest NULL cases are (if any).

A reviewer trusting neither the attacker, the defender, nor the operator can clone the repo and
run `python3 docs/runs/<date>-<name>/prove_<name>.py` to re-derive the run's claims cold.

## About historical field names

Some chains in these archives are from runs that predate specific invariant renames (for example,
the Nebius-only provider rule became the one-provider-per-run pin in November 2026). Those older
chains record the field names current at the time they were written. This is intentional: the
hash chain is append-only, and rewriting an historical chain would break its verification. The
current invariant definitions are indexed in [`docs/prereg/RATIONALES.md`](../prereg/RATIONALES.md),
and each committed `prove_<name>.py` validates its own historical chain against the invariants in
effect when that chain was written.
