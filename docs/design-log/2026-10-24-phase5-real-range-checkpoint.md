# Phase 5 — MHBench-real range (offline substance landed; live retirement + validation gated)

Date: 2026-10-24. Branch `real-range`. Three offline increments landed + structurally verified;
`make test` fully green, `static_coverage` PASS, floor re-derives oos=0. The live_terrain
retirement and the live-boot done-check (incl. the paid crown-depth-2 re-run) are the remaining,
explicitly LIVE/CREDIT-gated work — not advanced on a self-report.

## Landed (offline, verified)
1. **Real exploitable services on the MHBench attack path** (`swarm/topo_to_compose.py`). A host
   whose MHBench vuln installs a service-exploit playbook now boots the REAL vetted image instead
   of an alpine SIMULATED stub. The discriminator is the IR's `playbook_path` (the generated
   corpus loads every vuln as the base `Vulnerability` type, so the Python class never names the
   exploit) — `apacheStruts/setupStruts.yml` → the pool's internet-facing `struts` anchor
   (`piesecurity/apache-struts2-cve-2017-5638`, CVE-2017-5638), sourced from `config/range_pool.yaml`
   via `range_gen.load_pool`, never a host literal, `is_vetted`-gated (boot-clean rule).
   - **Honest, non-breaking guard:** a host red LANDS on (a `setup_ssh_keys` cred pivot or a
     `NetcatShell` listener) or that holds a flag keeps its real sshd/nc + loot command — the real
     service image's native entrypoint runs neither, so swapping it would break the inbound hop.
     Such mixed-role hosts stay honestly labeled `SIMULATED` for the un-booted service vuln.
   - **Structural proof:** across the 32-fixture corpus, **84** hosts boot the real
     `CVE-2017-5638` service across **28/32** fixtures; 0 real-image svc wrongly kept a
     service-killing command; 716 real-sshd nodes stay `SIMULATED`; the module self-check still
     re-derives floor oos=0 on every fixture. The 223→84 narrowing is exactly the mixed-role
     hosts that genuinely need a listener — scoped, not faked away.
2. **Live fingerprint-capture fix** (`scripts/arms_race_enterprise_frontier.py`) — closes the
   P2-live FALSE null (empty entry banner → no CVE inferred → MSF never queried):
   - the agent's `fingerprint` tool is now a REAL attacker-vantage probe
     (`live_fingerprint.fingerprint_service`) that refreshes `observed_fp` (was a no-op stub);
   - a bounded `wait_for_web_ready` polls the entry service from the attacker vantage before the
     agent starts, logging `range.ready` / `range.ready_timeout` (honest, non-fatal);
   - the attacker-vantage curl is hoisted so recon and the on-demand re-fingerprint share it.
   Self-check (`--selftest`, dry twin) still PASSES; the live path is deploy-host/paid, unchanged
   in `make test`.
3. **Entry-host literal removed** (`swarm/range_gen.py`) — the self-check's hardcoded
   `_ENTRY_HOSTS`/`_ENTRY_CVES` name/CVE lists are gone; the A2 invariant is now DERIVED from the
   vetted registry (entry is in-scope, its image `is_vetted`, its CVE is a real `CVE-…`). The
   eligible entry set widens automatically with the arsenal — no literal to maintain. 20-seed +
   enterprise self-check green.

## Remaining (LIVE / CREDIT gated — needs Dante's go)
- **Retire `swarm/live_terrain.py`.** Its only real consumers are the D-series live proofs
  `scripts/prove_d2_zoned_traversal.py` and `scripts/prove_d4_autonomous_agent.py` (prove_d3 +
  `live_traverse` reference it only in comments). They are coupled to live_terrain's legacy
  **credential-pivot zoned** range dict (`t['chain']` hops with planted ssh keys, `t['zones']`,
  `t['lookalikes']`, `t['crown']`, `t['secret']`). The retained generators (`range_gen`,
  `topo_to_compose`) use the newer **exploit-per-hop** model (no planted credentials) — neither is
  a drop-in. Retirement is therefore a MODEL MIGRATION of two live proofs, and the migration can
  only be validated by a live Docker boot (D4 is the paid autonomous agent). Doing it blind would
  advance a live proof on a self-report — deferred for direction.
- **Live-boot done-check:** boot an MHBench range on the deploy host, confirm the real services
  serve on the attack path (red earns a real foothold), `reverify_floor` oos=0, literal-host scan
  clean.
- **Re-run the live crown-depth-2** on the real-image range (the stated Phase-5 goal) — PAID.

## How to re-derive the offline proof
```
.venv/bin/python swarm/topo_to_compose.py            # selftest: terrain + floor oos=0
.venv/bin/python swarm/range_gen.py                  # selftest: derived A2 invariant, 20 seeds
.venv/bin/python scripts/arms_race_enterprise_frontier.py --selftest   # dry twin still green
make test                                            # full offline suite green
.venv/bin/python scripts/mediation/static_coverage.py  # PASS (no new ungoverned sink)
```
