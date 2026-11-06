# Tier 1 recon fix — service-aware fingerprint (2026-10-28)

The one efficiency fix the seed-1337 paid run (`../2026-10-28-phase1-paid-run2/`) called for. That run
spent ~65 of its 82 min on a single defect: an HTTP fingerprint of a host whose only open port is 22
completes the TCP connect then hangs on every probe until timeout, learning nothing (`server=''`). It was
paid both standalone and batched inside a scan's discover-then-fingerprint-each loop, and it starved red of
turns so it reached dba01 only at turn 33/44.

## The fix (live-path only; TCB gate + hash chain untouched; scope unchanged; no hardcoding; map-blind)
- **Service-aware fingerprint** — `swarm/live_fingerprint.py`:
  - `HTTP_PORTS` (a generic protocol convention, not host knowledge). `fingerprint_service` runs the HTTP
    `PROBE_PATHS` loop ONLY for an HTTP port; a non-HTTP port (e.g. 22) returns instantly as `non_http`.
  - Backstop: an HTTP port that answers nothing short-circuits after ONE status probe (no body, no loop).
- **Fingerprint the web port, not :22** — `swarm/live_red.py` `pick_fingerprint_port()`: given a host's open
  ports, prefer an HTTP one (a web host on `[22,8080]` is fingerprinted at 8080); a pure-SSH host stays 22
  and is recorded instantly. Wired into `observe`, `fingerprint_auto`, and the agent `t_scan` discovery loop.
  (Root cause of the paid run's turn-15 batch: `WEB_ENTRY_PORTS` leads with 22 and `observe` used `prts[0]`.)
- **Map-blind guard** — `t_scan` now drops and logs (`scan.subnet_ignored`) an LLM-supplied `subnet` that is
  not one of the vantage's own interfaces (it was already silently ignored; now it is explicit + auditable,
  and red gets feedback). Reinforces: red can only scan what it can see.

## Proof (all free — no API key)
- **Booted-range timing** — `prove_fingerprint_timing.py` (boot the key-seam range, then run):
  - gated fingerprint of SSH-only `dba01:22` → **0.00 s**, `non_http=True`, `server=''`;
  - one old-style HTTP head-probe of open `:22` hangs **~145 s** (no HTTP reply ever comes) — the old
    fingerprint issued ~14 such probes/host (~280 s/host in the paid chain); the gate removes it;
  - web host `web01:8080` still fingerprints → **12.6 s**, `Server: Apache-Coyote/1.1` (HTTP recon intact).
- **`make test`** green; **`live_fingerprint`/`live_red` selftests** green (new asserts: zero HTTP probes
  against `:22`; a dead `:80` costs one probe, not fifteen); **`make duel-dry`** green (engine drives
  end-to-end, floor cold `oos=0`); preregister chain unchanged (40 events, anchor seq-39).

Re-run the timing proof:
```
sg docker -c "docker compose -f docs/runs/2026-10-28-phase1-paid-run2/docker-compose.gen.yml -p dsfpv up -d"
sg docker -c ".venv/bin/python docs/runs/2026-10-28-phase1-tier1-recon-fix/prove_fingerprint_timing.py"
sg docker -c "docker compose -f docs/runs/2026-10-28-phase1-paid-run2/docker-compose.gen.yml -p dsfpv down -v"
```

## What this proves, and what it doesn't
Proven free: the ~280 s/host tax is gone and web recon still works. **Not** proven free: that an LLM red now
reaches dba01 by ~turn 10–15 with turns in hand — the `DryOODARouter` is deterministic and does not model
the wall-clock tax, so turn-count-in-hand is a property only the paid re-run confirms. That is the gated next
step: a matched-ultra re-run of seed 1337, §E-enforced, archived with telemetry under `docs/runs/` like
`../2026-10-28-phase1-paid-run2/`. HOLD for Dante's spend go. Tier 2 (lethality) stays on hold per his call.
