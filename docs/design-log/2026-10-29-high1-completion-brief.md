# HIGH-1 completion — gate the LIVE engine's recon sweep (`_recon`), not just `recon_from` (2026-10-29)

Planner/verifier brief for CC. Cold verification of commit `dbbf096` found HIGH-1 is partial: the
scan-sweep gating was wired into the ArsenalDriver frontier path (`recon_from`), but the ONE
measurement engine scans through a different function (`build_agent_tools._recon`) that was left
ungated. The fingerprint fix IS on the live path and is correct. This brief closes the gap.

## What's already correct (verified cold — don't touch)
- `live_recon.drop_oos` — the gating mechanism. Records a `gate.block` for every KNOWN out-of-scope
  host in a candidate set and drops it before any probe (no-op tool_fn → no network). Selftest green.
- `scan_subnet` / `fast_web_sweep` `ips=` restrict mode. Correct.
- `ArsenalDriver.fingerprint` now runs its HTTP read inside `gate.dispatch` — and `build_agent_tools`
  DOES use `driver.fingerprint`, so the fingerprint half is fixed on the live path. ✓
- HIGH-2 (`run_effect` tracked, class-1, TCB sites exempt, battlefield/deception dropped), MEDIUM-2
  (TCB in the freeze set; prereg chain VERIFIED, 43 events / seq 42; `live_agent` pinned) — all verified.

## The gap (the mandate violation still open on the measurement path)
The one engine's red driver is `build_agent_tools` (`live_red.py:1000`), wired at
`scripts/live_arms_race_run.py:689` (the unified LIVE episode) and `:242` (dry). Its `t_scan`
(`live_red.py:1046`) scans via the LOCAL `_recon` (called at `:1049` and `:1091`), NOT
`driver.recon_from`. And `_recon` (`live_red.py:1029-1034`) is unchanged:

```python
    def _recon(scanner, net, label):
        skip = own_ips(scanner) | {str(ipaddress.ip_network(net).network_address + 1)}
        hits = {ip: ps for ip, ps in scan_subnet(scanner, net, scan_ports).items() if ip not in skip}
        live_recon.reveal_real(log, gate, "red", label, scanner,
                               [(ip, ip, hits[ip]) for ip in hits])
        return hits
```

No `drop_oos`, no `ips=` → `scan_subnet → scan_many → _exec → run_effect` still connect-probes every
host in the subnet (out-of-scope included) ungated, and `reveal_real` records only the responders.
That is the original HIGH-1 defect, live on the path that ran in run 3/4. `drop_oos` is only called at
`:840` and `:878` — both inside `recon_from`, which the one engine does not use for scanning.
(HIGH-2's module-local domination ceiling can't see the shared `_exec`/`scan_many` helper, so
`static_coverage` green does NOT catch this — don't rely on it here.)

## The fix (mirror what `recon_from` already does at `live_red.py:836-841`)
Edit `build_agent_tools._recon` to gate the target set first, then scan only the kept ips:

```python
    def _recon(scanner, net, label):
        base = ipaddress.ip_network(net)
        skip = own_ips(scanner) | {str(base.network_address + 1)}
        # HIGH-1 completion (2026-10-29): gate the sweep's target set FIRST, same as recon_from.
        # drop_oos records a gate.block for every KNOWN out-of-scope host in the swept range and
        # removes it before any probe; scan_subnet then connect-scans only the gate-kept ips, so the
        # §7 block is witnessed in the recon phase on the LIVE-ENGINE path, not just the frontier path.
        cand = [str(base.network_address + i) for i in range(1, 17)
                if str(base.network_address + i) not in skip]
        cand = live_recon.drop_oos(log, gate, "red", cand)
        hits = {ip: ps for ip, ps in scan_subnet(scanner, net, scan_ports, ips=cand).items()
                if ip not in skip}
        live_recon.reveal_real(log, gate, "red", label, scanner,
                               [(ip, ip, hits[ip]) for ip in hits])
        return hits
```

Notes:
- `log`, `gate`, `live_recon`, `ipaddress`, `scan_subnet` are all already in scope in
  `build_agent_tools` (`live_red.py` imports `live_recon` at module level; `gate`/`log` are
  `build_agent_tools` params). No new imports.
- `range(1, 17)` matches `scan_subnet`'s default `lo=1, hi=16` and `recon_from`'s own range — keep the
  sweep width identical so this is a pure gating change, not a scope-width change.
- One edit fixes BOTH `t_scan` call sites (`:1049` entry scan, `:1091` foothold-vantage scan) since
  both go through `_recon`.
- Also check `live_red.py:1904` (`live_red.scan_subnet(attacker_container, entry_net, port)`): confirm
  whether it is on any live/paid path; if so, gate it the same way. If it's frontier/greedy-only and
  never paid-reachable, note that and leave it.

## Decision-neutrality (unchanged from the proven `recon_from` fix — must hold)
`drop_oos` decides purely from the GATE's own alias/scope map (the TCB's knowledge, not red's), records
blocks, and drops OOS hosts before probing. Red's decision (which subnet to scan) and its in-scope
observations are unchanged; red ends up slightly MORE blind (it can no longer physically touch OOS
hosts), never less. No ground truth reaches red. This is the same mechanism already selftested for
`recon_from` — do not add anything that hands red host identity.

## Verify (free; then I re-derive cold)
1. `python swarm/live_recon.py` (drop_oos selftest) + `python swarm/live_red.py` selftest.
2. `make test` + `python scripts/prove_one_engine.py --selftest` green.
3. `python scripts/mediation/static_coverage.py` (regression; won't flag the shared-helper path — expected).
4. A FREE dry run (`make duel-dry` or the dry unified episode) — then re-derive the floor cold:
   `reverify_floor` → `chain_verified=True`, `oos_executed=0`, AND confirm recon-phase `gate.block`
   events now appear for any out-of-scope host in the swept range (the §7 witness on the live-engine
   path). That last point is the proof this fix actually reached `_recon`.

## Commit + gates
- `live_red.py` is NOT in the frozen instrument set, so no prereg amendment is needed (unlike the
  HIGH-2/MEDIUM-2 edits). Branch `real-range`, nothing pushed, author `Dante Cano <drcano@ucsd.edu>`
  (not the [redacted] default).
- Either amend `dbbf096` (it isn't pushed) or add a follow-up commit; either way the message should
  state the done-check: `_recon` (the live-engine scan tool) now gates its target set via drop_oos +
  ips=; dry floor re-derives oos=0 with recon-phase gate.blocks present; make test + prove_one_engine green.
- `dbbf096`'s current message ("gate the recon sweep + fingerprint target set") overstates what landed
  — the amend/follow-up message should scope it honestly (frontier sweep + fingerprint gated there;
  live-engine sweep gated here).

## Then (order)
1. This `_recon` completion → I verify cold.
2. The owed HIGH-1 dynamic check on a booted range (an out-of-scope IP in-segment actually yields a
   recon `gate.block`) — lands before the next paid run.
3. MEDIUM-4 (machine-check the map-blindness awareness channel) and MEDIUM-6 (§E `--verify` thoroughness).
4. The decision items (MEDIUM-1 sole-auditor framing, MEDIUM-3 run_live/Anthropic labeling, MEDIUM-5
   host witness) stay queued for Dante.
