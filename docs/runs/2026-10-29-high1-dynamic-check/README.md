# HIGH-1 dynamic check — recon gating on a real boot (2026-10-29)

The empirical close of audit HIGH-1, after the static fixes (`dbbf096` frontier + fingerprint,
`c484143` the live-engine `_recon` sweep). **FREE** — a booted range, no Nebius, no LLM, no tokens.

The static proof (the `drop_oos` selftest + the `_recon` code) could not show the gating on a real
range, because `drop_oos` keys on the gate's `resolve_ips` alias map, which is only populated against
live containers. This check boots the unified range (seed 1337), drives the ONE engine's LIVE recon
path (`build_agent_tools` → `t_scan` → `_recon`) from a real foothold vantage (**db-bastion**, which
sits on both the mgmt and database segments) with the REAL gate, across two segments that each hold a
KNOWN out-of-scope host — mgmt: `jump-01` (10.60.0.13); database: `decoy-fin` (10.40.0.12) — and
captures the result + the §E witness into one hash chain.

**Result (re-derived cold by `prove_high1_dynamic.py`):**
- recon-phase `gate.block` on the `_recon` path for **both** oos hosts (`decoy-fin`, `jump-01`) — the
  §7 block is now witnessed in the recon phase, not just the exploit phase;
- both oos hosts **excluded from the probe** (no `discovery` event names them — the ungated reach is
  gone); only in-scope hosts (10.40.0.11 db-core, 10.60.0.10/.12) were probed;
- **§E held**: `ok=true`, `host_gateway_reachable=false`, `oos_tcp_reaches=[]`, `internet_blocked=true`;
- chain `verify_chain` → **VERIFIED** (17 events).

This is the gate before paid runs: HIGH-1 is now closed both statically (frontier + `_recon` + the
fingerprint) and empirically (this check). The N-seed lethality batch is unblocked on the mediation
front.

## Files
| file | what |
|---|---|
| `check_chain.jsonl` | the hash chain (17 events) — the witness, source of truth |
| `prove_high1_dynamic.py` | **cold certification** — re-derives the four claims above from the chain alone |
| `run_check.py` | the driver that produced the chain (needs a booted range to re-run; the chain re-derives cold without one) |

## Certify it cold (one command)
```
PYTHONPATH=redteam python3 docs/runs/2026-10-29-high1-dynamic-check/prove_high1_dynamic.py
```

## Provenance
Unified range seed 1337, §E enforced, recon-only (no LLM / no token spend). Branch `real-range`;
nothing pushed. The gate's scope/alias map is the TCB's own knowledge (resolve_ips); no ground truth
reached red — this check drives the recon tool directly, it does not run red's planner.
