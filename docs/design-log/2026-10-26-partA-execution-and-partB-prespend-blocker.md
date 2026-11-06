# Design log — Part A executed + Part B PRE-SPEND blocker (2026-10-26)

Executing the CC launch brief autonomously. Part A (free prep) is DONE and committed on
`real-range` (nothing pushed). Part B (paid smoke) is **STOPPED BEFORE ANY SPEND** on a real
wiring problem found during pre-flight: the live-duel runner does not target the orchestrated
unified range. Zero credits spent. This is the brief's own stop condition
("If Part B shows ANY wiring problem … STOP and report instead of proceeding").

---

## PART A — done (free, committed on real-range, nothing pushed)

### A.1 §E firewall — reported, not a blocker (per brief)
- `sudo -n /usr/bin/python3` is NOT granted on this session ("interactive authentication is
  required"), so `host_egress_firewall.py --up/--verify` could not be run by me. Per the brief:
  report and continue — the hard floor is already verified closed via `probe_boundary`
  (ok=true, audit's LIVE-RANGE VERIFICATION).
- FREE confirmation run: `host_egress_firewall.py --selftest` → "OK" (rule logic sound).
- `probe_boundary` is re-derived cold on the LIVE chain in Parts B/C regardless, so the §E
  firewall `--verify` remains belt-and-suspenders, not a blocker.

### A.2 git author history fix — DONE
- Backup branch `real-range-preauthorfix` created at the original tip (originals preserved).
- `git filter-repo` not installed → `git filter-branch --env-filter` scoped to `HEAD`
  (real-range only; backup + `verify-mediation` untouched).
- BEFORE (authors): `dante <[email redacted]>` (1), `Dante Cano <drcano@ucsd.edu>` (136),
  `drcano <156254264+drcano@users.noreply.github.com>` (309). Committers also had
  `GitHub <noreply@github.com>` (2).
- AFTER: **446 commits, author AND committer = `Dante Cano <drcano@ucsd.edu>`** (single identity).
- No `[redacted]` anywhere (confirmed pre- and post-). Nothing pushed (origin is a local path).
- NOTE / decision for Dante: `verify-mediation` (the stale old-main branch) was left at its
  original identities. Rewriting another branch is a separate history call; the launch branch
  `real-range` is fully the single identity.

### A.3 prereg freeze + lock — DONE (committed db26fae)
- Appended **Amendment L2** (dated 2026-10-26) to `docs/PREREGISTRATION.md`:
  - L2.1 names the experimental-floor boundary UNDER STUDY = the **TIER LINE** (gate-enforced;
    `oos_executed` re-derived cold; a nonzero value is a studied penetration, never tuned),
    distinct from the hard floor (segmentation + §E = safety; a move halts the run).
  - L2.2 pins the three Samba-vs-Windows findings as pre-registered EXPECTATIONS, captured
    as-is, explicitly NOT tuned (Kerberoast `KRB_AP_ERR_INAPP_CKSUM`; secretsdump remote-NTDS on
    Samba LDB/TDB; BloodHound LDAP-signing). PtH credential-reuse→Tier-0 stays the externally
    tool-validated core claim.
  - L2.3 freezes the measurement apparatus (`live_telemetry.py` + `live_truth.py` re-hashed).
- `scripts/preregister.py` appended a dated `prereg.amendment`:
  **seq=23, hash `ba4b52d1e59a4944…`, chain OK**. `--verify`: "chain OK (24 events); last anchor
  seq=23; all registered artifacts match the anchor".

### A.4 non-blocking cleanups — DONE (committed 1d59a59)
- `arms_race_enterprise_frontier.py`: dropped the `topo_to_compose as range_gen` alias (last
  stale `range_gen` in live code) → direct `topo_to_compose.*`; zero `range_gen` left.
- `arms_race_check.py`: bare `import verify_live_run` → `import scripts.verify_live_run as vlr`
  (ROOT on sys.path → namespace pkg; standalone path preserved).
- `make test` exit 0, fully green (incl. `preregister --verify` seq=23, `reverify_floor` cold
  chain_verified=True oos_executed=0).
- Host note (reported, not fought): `swarm/` + `scripts/` `__pycache__` are root-owned; a cold
  `make test` needs `PYTHONPYCACHEPREFIX` redirected to a writable dir.

### Extra (Part B prep, committed 1ba6968) — `--turns` parameterized
- Added `--turns` (default 40) threaded argparse → `_episode` → `_run_dry/live_episode` →
  `run_red_agent(max_turns=turns)` at both seats. Kills the last hardcoded turn budget; default
  40 preserves every existing caller. Verified: dry `--turns 3` bounds red turns to {0,1,2};
  `make test` green. NOT tuning — parameterizes the cap the audit flagged (2.3).

Commits on real-range (nothing pushed): `00c9768` (author rewrite tip) → `db26fae` (prereg L2)
→ `1d59a59` (cleanups) → `1ba6968` (--turns).

---

## PART B — PRE-SPEND BLOCKER: no live-LLM-duel runner targets the orchestrated unified range

**Zero credits spent.** Found during pre-flight, before any paid call.

### What the brief assumes
Parts B/C: "Real LLM red vs real LLM blue **on the orchestrated unified range**", flip
`use_llm=True`, expecting: real MSF foothold, all three streams, the D4 reconciler, the three
**Samba** findings "as they manifested", loot corroboration, crown/pivot depth, the tier line.
That describes the UNIFIED range (Samba AD DC + tier line + credential graph).

### What is actually up (confirmed via docker labels)
The running range is `duelswarm-mh-unified_enterprise_1337` — the **`generate_unified` /
`write_unified`** topology. Containers: `range-{dmz-web, db-core, wks-01, app-fs, dc-01,
decoy-fin, jump-01, backup-01, attacker}`. `range-dc-01` labels: `duelswarm.role=ad-dc`,
`duelswarm.tier=T0`, `duelswarm.ad_fidelity=real`, and the `duelswarm.provision` Samba label
(`svc_sql` SPN, `svc_da` DA). This is the range the prereg L2, the Samba findings, and the
designed-boot doc all describe. (It was brought up from a prior session's scratchpad compose,
not via `make range-up` this session — a secondary note; the designed-boot doc requires the
paid-run range to come off `bring_up_generated_range`.)

### What the live runner actually drives (confirmed at source)
`scripts/live_arms_race_run.py` sources its range ONLY from:
- `_episode`: `r = generate_range(seed, scale=scale)` (L135)
- `_run_live_episode`: `compose = write_range(r["seed"], …)` (L205), and `write_range` →
  `generate_range(seed)` with **default `scale="small"`** (ignores `--scale` and the passed `r`),
  then `_bring_up_generated_range` brings up THAT range and `_tear_down_generated_range` removes
  it at the end.
- `generate_range(1337, scale="small")` hosts: `webrce, gitlab, weblogic, ldap, decoy,
  mailserver, oos_trap`. `scale="enterprise"`: `webrce, gitlab, weblogic, db, jenkins, …, dc01`
  (25 hosts, different names). **Neither is the unified range** — no Samba `ad_tier`, no
  `range-dc-01`, different host/network names (`duelswarm-range-1337_*` vs the up
  `duelswarm-mh-unified_enterprise_1337_*`).

So `live_arms_race_run.py --mode live` would stand up a SEPARATE `generate_range` range and run
the duel there — NOT against the up unified range, and NOT the experiment the brief/prereg/
findings describe. Running it and labeling it "the unified-range run" would be a mis-measurement.

### Where the audit was imprecise
`2026-10-26-launch-readiness-audit.md` says "the unified-enterprise topology
(generate_unified/write_unified) … which only the paid `_run_live_episode` path drives." The
code contradicts this: `_run_live_episode` uses `write_range`/`generate_range`, never
`generate_unified`/`write_unified`. Real `generate_unified`/`write_unified` CALLS exist only in
topo selftests and `prove_phase2_loot_reuse.py` (an in-memory scripted PtH/loot PROOF, not an
LLM red+blue discovery duel). `measured_duel.py` ("the single live duel") builds its own Struts
star topology (the V4 decision-quality rig), also not the unified AD range. The Makefile has no
consolidated live-duel target ("live entry lands in Phase 2").

**Net:** the full live integration {unified `generate_unified` IR + real MSF foothold + real
Falco + D4 reconciler + LLM red/blue over the one engine} against the up containers is **not
wired**. The audit even said wiring the unified IR through `run_sim_red` "would be real
integration work … not something to add to the live path right before a paid run."

### Why I stopped instead of proceeding or bolting it on
- Spending on `live_arms_race_run.py --mode live` as-is measures the WRONG range → a false
  "unified-range result"; violates "report whatever happens" / instrument integrity.
- Writing new live-path wiring (adapt `_run_live_episode` to the unified IR shape:
  `_range_coords`, `range-{entry}`, `scope_by_actor`, `range-{host}` telemetry all assume the
  `generate_range` dict, not the unified `NetworkTopology`+gt) then immediately spending on it is
  an UNREVIEWED change to the INSTRUMENT right before a paid run — exactly what the audit and the
  rails warn against ("one clean engine", reviewed changes, no bolt-ons).
- The brief's spend envelope presumed a ready run; it did not authorize building a new engine
  integration.

### Options for Dante (decision needed; no spend until then)
1. **Build the integration properly (recommended):** extend `_run_live_episode` (the one engine
   is topology-agnostic by design) to consume the `generate_unified`/`write_unified` IR and drive
   the already-up unified containers (foothold on `range-dmz-web`, telemetry over the real
   `range-*` hosts, reconciler on the live chain), dry-exercise it first, review, THEN smoke
   (`--turns 10`) then full run. This is real engineering, not a flag flip.
2. **Confirm the intended duel topology is actually `generate_range enterprise`** (not the Samba
   unified range). If so, the prereg L2 Samba/tier-line framing and the "three findings" don't
   match that range, so the prereg would need reconciling first — flag before spend.
3. Something else per Dante's read of the original design intent.

Nothing is pushed; the live range is untouched; no credits spent.
