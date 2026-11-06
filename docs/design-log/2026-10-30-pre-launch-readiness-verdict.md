# Pre-launch readiness verdict — claim-3 erosion pilot (2026-10-30)

**VERDICT: NO-GO for the pilot as wired.** It cannot launch yet: as written it crashes
after gen 0's three PAID episodes (confirmed by cold reproduction, deterministic, so a
restart cannot pass), and the seed-1337 unified range it attaches to has no wired standup.

But this is a short, well-scoped build list, not a return to the drawing board. The heart
of the instrument is sound: the deterministic floor logic, the gate, the crown-credential
harvestability, and the map-blind firewall all re-derive clean. Every blocker lives in the
NEW `run_live_generations` generational wrapper and its boot/standup wiring, not in the
measurement engine (`make duel` / `_episode` is floor-safe). And every "missing file"
blocker the audit agents raised turned out to be a staging artifact: the files exist in the
repo. The go-path at the bottom gets us to a real live run after a focused fix pass plus a
FREE dry rehearsal that proves the telemetry surfaces before a single token is spent.

Method: five independent cold agents read the live-path source (not the selftests) and
re-derived; I then re-verified the load-bearing findings myself against the primary source,
trusting neither CC nor the agents. The decisive blocker I reproduced by running the real
`reverify_floor` module.

---

## What I verified cold myself (not taken on report)

1. **The floor/topology crash — REPRODUCED.** I built two faithful hash-chained logs with
   the real `EventLog`, differing only by a `range.topology` event, and ran the real
   `reverify_floor.reverify` on each:
   - WITHOUT `range.topology`: `oos_executed = 2` (two in-scope, IP-addressed `gate.allow`
     actions flagged out-of-scope; both canonicalize to the bare IP).
   - WITH `range.topology`: `oos_executed = 0`.
   Chain verifies in both cases, so this is purely the scope-resolution gap.
2. **The gate/reverify field contract.** `gate.py:232/236`: `gate.allow` records
   `target` = the raw target (the IP red used, since the live gate is built
   `resolve_ips=True` at `live_arms_race_run.py:735`), with the canonical name in a SEPARATE
   `resolved` field. `reverify_floor` reads `d.get("target")` (the IP), not `resolved`.
3. **The bypass.** The live loop's default `episode_fn` (`live_arms_race_run.py:1070-1074`)
   calls `_run_unified_live_episode` DIRECTLY. The `roe` + `range.topology` preamble is only
   in `_episode` (lines 177-188); `_run_unified_live_episode` emits `floor.boundary` (745,
   name-scope) but never `range.topology`. So the committed live chain has name-scope and no
   IP→name map — exactly the condition my repro shows yields `oos > 0`.
4. **The A3 boot path.** `_default_boot_check` (1012-1039) hardwires the witnessed host to
   `entry = r["entry"]` and asserts an sshd "Accepted" line in `range-<entry>`'s docker logs;
   the login TARGET is `boot_benign["ip"]` (any host) but there is NO key to redirect the
   WITNESSED host off the entry. Default `src_container = range-attacker` and default
   `falco_container = live_arms_falco_<seed>` (created only INSIDE an episode, at 727, so it
   does not exist when `boot_check()` runs at 1093).
5. **File existence (real repo, not my stage).** `config/falco_duelswarm.yaml` (2133 B, and
   it contains the crown-read + outbound-connect + shell-exec rules), `config/range_pool.yaml`
   (19838 B), root `docker-compose.yml` (4879 B), `docker/range-node.Dockerfile` (562 B),
   `.env` (251 B) ALL exist. The agents flagged these missing because I had staged only
   `config/models.yaml` from `config/` — their absence was a staging artifact.
6. **The root compose is the wrong range.** `docker-compose.yml` is a fixed 6-host demo
   range (`range-struts/db/jenkins/mail/ldap/decoy`), not the seed-1337 unified seam
   (`range-web01/dba01/db-bastion/db-core`). `make range-up` boots this, not the unified range.

---

## HARD BLOCKERS — the pilot cannot run (or wastes credits) until each is fixed

**B1. The live loop crashes after gen 0's paid episodes (floor false-breach).**
`CONFIRMED COLD.` The default `episode_fn` bypasses the `range.topology`/`roe` preamble, so
every in-scope IP-addressed red action is mis-counted out-of-scope by the per-generation
floor hook; the assertion at `live_arms_race_run.py:1121-1123` fires AFTER `evolver.tick`
has already run all 3 paid episodes of gen 0. Deterministic. The selftest is green because
the stub writes NAME-addressed targets + an explicit scope event, so it never exercises the
IP path. **Fix (small, already proven in the sibling path):** emit the same preamble
`_episode` emits (lines 177-188) before `_run_unified_live_episode` in the loop's
`episode_fn` — or route the loop's episode through `_episode(..., range_kind="unified",
mode="live")` — so the committed live chain carries the live-IP `range.topology` and `roe`.

**B2. The A3 boot-witness is structurally unsatisfiable as wired.** `CONFIRMED COLD.` Three
independent defects: (a) the witnessed host is pinned to the struts entry (`range-web01`),
which runs the real Struts image with no sshd, so the "Accepted" auth witness can never
appear in its docker logs; (b) the default `src_container=range-attacker` (alpine) has no
ssh client, so `docker exec range-attacker ssh …` cannot even perform the benign login; (c)
the default `falco_container` is the per-episode Falco name, which does not exist when
`boot_check()` runs before the gen loop. **Fix:** add a `boot_benign["host"]` to witness the
actual sshd login target (a NODE host such as `db-core` or `dba01`), set `src_container` to a
host that has an ssh client + the benign credential, and start Falco out-of-band before the
loop and pass its name. Plant a benign account + canary on the witnessed host.

**B3. No CLI entry, and the call is missing required args.** `(known 0a, confirmed.)`
`run_live_generations` has no launcher (`main()` drives only `run_series`); the function
requires `out_dir` positionally and `boot_benign` (else it raises before gen 0). **Fix:** add
the `--live-generations` CLI that forces unified+live+observe-only and calls
`run_live_generations(out_dir, seed=…, generations=…, pop_size=…, blue_contains=False,
boot_benign=…, resume=True)`.

**B4. There is no wired standup for the seed-1337 unified range.** `CONFIRMED COLD.`
`make range-up` boots the fixed demo compose, not the unified seam; no make target generates
and boots the unified range for seed 1337. **Fix / recipe:** generate the unified compose
(`topo_to_compose` `--unified` for seed 1337 → `docker-compose.gen.yml`), build/tag the
`duelswarm/range-node:latest` image (its Dockerfile is at `docker/range-node.Dockerfile`),
`docker compose -f docker-compose.gen.yml up -d`, start Falco, apply the §E host firewall.
Confirm the containers come up named `range-attacker` + `range-<host>` for all seam hosts.
**The run spec's STEP 2 ("`make range-up`") is wrong for the pilot and must be corrected.**

---

## CORRUPTIONS — the run goes clean but the SCORED claim-3 result is invalid

These do NOT block the shakeout pilot (the 7 "healthy" criteria don't depend on them), but
each must be resolved before the scale-up is the measurement you report.

**C1. "memory-on" is canned, not learned.** `CONFIRMED by two independent agents.` Memory IS
threaded forward across generations, but the lessons are random draws from a fixed 5-string
`_DEFAULT_LESSONS` pool (`population.py:119-123, 474-476`); there is NO episode→lesson
write-back (`red_mem` is passed `None`; `_evaluate` returns events only and never mutates
`genome.memory`). So "red adapts by distilling its own prior engagements" is NOT what runs.
**Decision before paying for the scored arm:** either add an episode→lesson distillation step,
or re-scope the claim to "an evolving, fitness-selected lesson-set conditions red" (which is
what holds). The memory-on vs memory-off control in the prereg is only meaningful once this
is decided.

**C2. The erosion metric itself is not instrumented.** `Agent D.` `arms_race.LearnedMonitor`
— the static learned monitor whose decay IS claim 3 — is never instantiated in the
observe-only path or the generational loop (it appears only as a class, its own selftest, a
prereg reference, and a `coevolve.py` comment calling it an "ABLATION BASELINE"). Observe-only
blue runs only the real-telemetry Sigma detector + `LoginGraphDiscriminator`. No per-generation
monitor miss-rate `m_g`, no stealth triple (recall/dwell/FP-cost) is recorded. A clean 5-gen
run would prove nothing about claim 3. **Fix:** hold a persistent `LearnedMonitor` across
generations, score red's spine-confirmed actions against it each generation, record `m_g` +
the stealth triple on the chain. (Blocks the SCORED run, not the shakeout.)

**C3. `capability_ceiling` scores against a degenerate ceiling.** `Agent A.` The loop computes
the full ground truth then discards it (`live_arms_race_run.py:1061`) and passes
`r["ground_truth"]` to the hooks, which lacks `cred_seam`/`credential_graph`/`crown_login`, so
the "optimal chain" collapses to ~2 rungs and the gap metric is meaningless. **Fix:** pass the
full `_gt` to `_run_gen_hooks`.

**C4. Detection/dwell predicate mismatch.** `Agent D.` The scoreboard's detector filter
`startswith("detect")` does not match the live blue event names `blue.detect.*`, so live
detections count as zero and dwell is `None` wherever they are computed. **Fix:** match
`blue.detect.*`. (Matters for the stealth triple, i.e. the scored run.)

---

## HAZARDS — set/confirm before any paid spend (none block correctness, all waste credits)

- **H1. Probe the ultra model id live.** `make smoke` only exercises the nano tier; the ultra
  id `nvidia/Nemotron-3-Ultra-550b-a55b` is not externally verified in-session and a wrong id
  404s on red's first call and aborts the run (strict). Confirm against `GET /v1/models` + a
  1-token ultra completion first.
- **H2. Launch with `resume=True` and a persistent `out_dir`.** A terminal `LLMError` or empty
  reply from red re-raises under strict and aborts the whole paid run; checkpointing is
  per-generation and `resume` defaults False, so a mid-run blip restarts at gen 0 and
  re-spends. Ideally also wrap the per-episode call to skip/retry one failed episode.
- **H3. Confirm `NEBIUS_ALLOW_ANY_HOST` is unset.** The host guard allows any `*.nebius.com`
  (not tokenfactory-only), and the live loop lacks `_episode`'s pre-spend provider assertion,
  so the only guard is the router's host check. Keep `NEBIUS_BASE_URL` unset/nebius.
- **H4. Pre-pull images before the §E firewall is up.** `make range-pull` pulls only the 4
  vuln images, not `falcosecurity/falco` or `metasploitframework/metasploit-framework`. Falco
  down for the whole run = full spend, zero scored episodes, late crash (the A3 boot gate is
  the pre-spend guard that prevents this — which is why B2 must be fixed).
- **Also build/confirm the `duelswarm/range-node:latest` image is present** (needed for every
  sshd host incl. the crown); I cannot see local docker images from here, so verify at standup.

---

## DISMISSED — staging artifacts, NOT real gaps (do not chase these)

The agents raised these as blockers because they audited the file subset I had staged. All
exist in the real repo and are fine:
`config/falco_duelswarm.yaml` (present, with the crown-read/connect/exec rules),
`config/range_pool.yaml`, root `docker-compose.yml`, `docker/range-node.Dockerfile`, `.env`.

## CLEARED — validity items checked and holding

- **Crown credential is harvestable on the seed-1337 seam (post-D1).** An agent traced it end
  to end and ran the real logic: the seam plants the svc_dba ed25519 key harvestably on
  db-bastion/dba01, db-core accepts it, `t_loot` draws only from `harvested_creds` (D1), and
  red earns-then-loots `/home/svc_dba/pii.json`. No false red-incapability.
- **The A5 map-blind guard cannot crash on a normal lesson.** Reproduced against the real
  seed-1337 ground truth: gen-0-empty passes, full lesson accumulation passes, a real
  GT-token leak correctly raises. The only lesson pool is GT-token-free.

---

## The go-path (ordered)

1. **CC builds B1-B4** (floor preamble in the loop; A3 boot-witness rewire + benign
   account/canary on an sshd host; the `--live-generations` CLI; a unified-range standup
   path). Each is small; B1's fix is already proven in `_episode`.
2. **Set H1-H4** (ultra probe, `resume=True`, host guard, image pre-pull + range-node build).
3. **FREE dry rehearsal — spends zero tokens.** Boot the seed-1337 unified range and run ONE
   `use_llm=False` generation through `run_live_generations`. This proves, with no spend:
   the A3 boot witness passes (telemetry surfaces live), the floor hook sees
   `oos_executed == 0` on a real IP-addressed chain (B1 fixed), and the per-gen hooks
   re-derive. If the dry generation's floor is nonzero, STOP — B1 is not actually fixed.
4. **Only then the paid pilot** (1 seed × 5 gens × pop 3), on Dante's explicit go. I verify
   the run directory cold against the 7 healthy criteria.
5. **Before the SCORED scale-up:** resolve C1-C4 and decide the memory/erosion claim scope,
   and ride the design-params amendment if the scale-up is the reported result.

Nothing is anchored (seq-51) or spent until B1-B4 are fixed and the FREE dry rehearsal in
step 3 comes back clean. seq-51 should anchor the code that actually runs, so it anchors
AFTER the B1-B4 fixes land, not before.
