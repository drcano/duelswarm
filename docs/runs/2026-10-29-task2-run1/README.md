# Task 2 run 1 — capability-ceiling best-of-k + oracle reference (2026-10-29)

The first Task-2 run: it measures how far the map-blind LLM red gets against the ground-truth
**capability ceiling** (the oracle optimal-path reference), on the in-sample range and on the three
held-out variants. Pre-registered before the run in
[`docs/prereg/TASK2_CEILING_ABLATIONS.md`](../../prereg/TASK2_CEILING_ABLATIONS.md) (seq-49); the
metric and the GT firewall are the pinned `scripts/validation/capability_ceiling.py` (seq-48).

## Layout

- `bestof3/seed<N>/draw<1..3>/` — the measured red, best-of-3 draws per seed (in-sample range).
  Each draw holds its episode chain `episode01_seed<N>.jsonl`, the full-I/O sidecar `…_io.jsonl`,
  Falco telemetry `…_telemetry.jsonl.gz`, and the frozen `ground_truth.json` + `scope.yaml` it ran
  against.
- `oracle-seed<1337..1346>/` — the **oracle optimal-path reference** on the in-sample range for each
  pre-registered seed: the empirical ceiling the measured red is scored against (never a measured-red
  result; the GT chain is handed to the oracle by design).
- `oracle-app_crown_3hop/`, `oracle-backup_route_5hop/`, `oracle-mgmt_crown_3hop/` — the oracle
  reference on the three **held-out variants** (seeds 2001/2002/2003), whose `ground_truth.json` are
  the hash-pinned generality set, so the ceiling cannot be cherry-picked post-hoc.

Every chain re-derives cold with the shipped auditors (`make verify` tools): the floor
(`reverify_floor` + `kernel_witness`), the IO sidecar (`verify_io_sidecar`), and the provider pin
(`verify_provider_pin`). The capability-ceiling scorer is post-hoc, stdlib, and GT-firewalled
(`leak_test`), so the ceiling metric cannot move after seeing results.
