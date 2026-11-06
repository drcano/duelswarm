# Design log — full-codebase launch-readiness audit (2026-10-26)

Fresh session, read-only/free checks only. Zero credits spent. STOP after Parts 1–2 for
source verification before any paid run (Part 3). Every check below is backed by the actual
command output captured this session.

Environment note: `swarm/__pycache__` and `scripts/__pycache__` are owned by the `docker`
group and not writable by the session user, so `compileall` and any `.pyc` write fail with
`PermissionError` unless `PYTHONPYCACHEPREFIX` is redirected. All checks below used
`PYTHONPYCACHEPREFIX=<scratchpad>/pycache`. This is a host filesystem-permission quirk, not a
code problem; worth a `chmod`/`chown` so plain `make test` doesn't trip on a cold cache.

---

## PART 1 — readiness audit

### 1A. One engine, zero parallel universes — PASS (one cosmetic cleanup)
- `swarm/range_gen.py` ABSENT (deleted); the one generator is `swarm/topo_to_compose.py`
  (`to_compose` L427, `generate_range` L1249, `build_sourced_range` L1603).
- One red loop: `live_agent.run_red_agent` (L354) + `live_red.run_sim_red` (L626); one
  discovery-duel orchestrator `live_red.run_discovery_duel` (L840); one blue fight
  `live_blue_agent.run_blue_fight` (L354).
- Deleted-symbol sweep (whole tree, `attic/` excluded):
  - `run_fast_blue` → **ZERO** references anywhere. (Deleted in `eaccfd0`.)
  - `live_duel` → comments/docstrings only (live_blue_agent L232/357, live_red L704/706);
    no import/call.
  - `run_belief_blue` → comments/docstrings only (live_blue_agent L185/232/370); no
    import/call.
  - `range_gen` → comments/docstrings throughout, PLUS one **cosmetic alias**
    `from swarm import topo_to_compose as range_gen` in
    `scripts/arms_race_enterprise_frontier.py:754` (calls `range_gen.generate_range` etc.,
    which resolve to `topo_to_compose`). Functionally correct, not a parallel universe;
    recommend renaming the alias to kill the stale name. Listed, not papered over.

### 1B. Everything compiles / imports — PASS
- `compileall swarm scripts redteam` → exit 0, zero `SyntaxError` (after the pycache
  redirect above).
- Import harness: **107 modules** (`swarm.*` + `redteam/reverify_floor` + `stats_tail`) and
  **all scripts** import clean, including the make-test-exempt paid runners
  (`live_arms_race_run`, `arms_race_enterprise_frontier`, `measured_duel`).
- One path-quirk: `scripts/arms_race_check.py` uses a bare `import verify_live_run` that
  resolves only when `scripts/` is `sys.path[0]` (i.e. invoked as a script). Runs clean
  standalone (`--help` exit 0); `verify_live_run.py` exists and is on the live path. Style
  quirk, not a dangling reference. Recommend `import scripts.verify_live_run` or a path shim.

### 1C. Instrument invariants — PASS (2 by-hand findings confirmed benign)
- `scripts/mediation/static_coverage.py` → **PASS**: 38 sinks (3 MEDIATED, 2 UNGOVERNED, 33
  SCAFFOLDING); the 3 class-2 `uninstrumented` entrypoints are import-ISOLATED from counted
  paths; every sink classified.
- The 2 class-1 "confirm by hand" sinks, confirmed at source:
  - `swarm/exploit.run_command:52 urlopen()` — the Struts S2-045 exploit primitive itself,
    lab-`localhost`-only, dispatched THROUGH the gate at the caller (docstring + gate.dispatch
    upstream). Not a new ungoverned sink.
  - `swarm/range_runtime.provision_ad_dc:121 subprocess docker exec` — the flagged call is
    the **read-only** readiness poll (`samba-tool domain level show`) / label `docker inspect`;
    the mutating **apply** goes through `_compose(..., gate, op="provision-ad-dc") →
    gate.lifecycle → run_effect`. The effect is gated; only read-only inspects are raw.
    Honest nuance: the strict reading "subprocess only in gate.run_effect" is not literal —
    there are read-only docker inspect/exec polls in `range_runtime` — but no ungated effect.
- Capability edges: `blue_contain:293/295` are inside the module **selftest** (asserts vs a
  GHOST host); the one live edge is blue's own `_real_contain` (defender-side containment),
  not a red effect.
- Floor auditors AGREE: `audit.EXEC_ACTIONS == reverify_floor.EXEC` (identical 15-element set).
- Instrument baseline: `gate.py` (Phase 4b, 2026-10-23), `eventlog.py` (2026-10-23),
  `spine.py` (harden2, 2026-10-24) were NOT touched by the Phase-5-setup commits
  (`c2a35c5`, `2de94c4`). No new effect site introduced in Phase 5. (Phase 4a `7a42b5c`
  added the gate's read-vs-mutate verb axis — invariant #3 — now live.)

### 1D. Objective-blindness — PASS (both with positive controls)
- `scripts/validation/leak_test.py` → **OK**: red closure 22 modules, 7 validators, none
  cross the boundary. Positive control real: plants `swarm/_leak_positive_control.py`, asserts
  it is caught (exit 0 ⇒ control passed).
- Red-view blindness (`swarm/live_agent.py` selftest) → **OK**: plants scope/crown/decoy/oos
  truth + a blue crown-host discovery into the log, asserts red's derived tokens are unchanged
  and none of {crown,in_scope,out_of_scope,scope,vulnerable,decoy,crown_db,oos,struts_edge}
  surface in red's view. Exit 0 ⇒ planted-leak control passed.

### 1E. Two floors — free parts PASS; kernel-level hard-floor is Docker-gated
- Experimental floor (tier line), FREE: `prove_phase2_loot_reuse` → "Kerberoast + PtH to the
  DC gate-BLOCKED at the tier line (blocked/blocked); floor cold chain_verified=True
  oos_executed=0"; `live_pivot` → "tier-line targets blocked".
- `reverify_floor` cold (wall range_0): chain_verified=True, oos_executed=0. Also cold on the
  dry duel log I generated this session: chain_verified=True, oos_executed=0.
- Hard floor (structural), FREE: `prove_env_boundaries` → "STATIC FLOOR PROVEN (structural)";
  every data-plane segment `internal:true`, no container reaches an OOS host or the internet.
- **Docker-gated (NOT run this session):** the kernel-level `uninstrumented.probe_boundary`
  from the compromised entry (`oos_tcp_reaches==[]`, `internet_blocked`,
  `host_gateway_unreachable==True`, `in_scope_reaches>0`) needs the range up. Must run on the
  deploy host before/at the paid run.

### 1F. Test surface — FULLY GREEN (exit 0), no reds
- `make test` → exit 0, every line green. Notably `preregister.py --verify` **PASSED**
  ("chain OK (23 events); last anchor seq=22; all registered artifacts match the anchor") —
  the brief anticipated this as the one KNOWN red; it is not red here (see Part 2.5).
- No other reds. static_coverage, leak_test, the D2/D3/D4 proofs, tiering, tool-authoring,
  sliver, wall, spine, falsification battery, env boundaries, reverify_floor cold — all green.

### 1G. Repo hygiene
- (i) git authors: `drcano@ucsd.edu`, `[email redacted]`,
  `156254264+drcano@users.noreply.github.com`; names `dante` / `Dante Cano` / `drcano`.
  **NO `[redacted]`** anywhere — the brief's STOP condition is clear. (History is not
  uniformly one email; three drcano-owned identities. If a single author identity is wanted
  for submission, that's a history decision — your call, not mine.)
- (ii) `attic/` is NOT imported by any live code (zero import/from references).
- (iii) No real secrets committed. `.env` is NOT tracked (only `.env.example`). The
  `OPENSSH PRIVATE KEY` at `topo_to_compose.py:799` (`K1_PRIVATE`) is the **intended planted
  lab credential** (the range's ssh-key primitive), not a real key. No `sk-`/`AKIA`/
  `api_key=`-shaped real secrets in tracked files.
- (iv) Working tree: `CLAUDE.md` (yours — untouched), `docs/brick2_fight_proof.txt`,
  `docs/design-log/2026-10-25-phase1-kickoff-decisions.md` modified; ~20 untracked design-logs;
  `sessionresume_RFDzvuuv` (empty, yours); `third_party/incalmo/` untracked. Nothing staged.

---

## PART 2 — launch gate

### 2.1 Dry end-to-end — free proxy PASS; orchestrated-range dry-e2e is Docker-gated
- FREE dry discovery engine (`live_arms_race_run --mode dry`) exit 0; dry episode log carries
  all three streams: **red** 26 events (`move.source:llm`=12), **blue** 11 events
  (blue.observe/detect), **target telemetry** a separate stream (svc.events). reverify_floor
  cold on it: chain_verified=True, oos_executed=0. `verify_live_run --selftest` → OK.
- **Gap (Docker):** the FULL Part-2.1 as specified — `verify_live_run` →
  `run_discovery_duel(use_llm=False)` on the ORCHESTRATED range with real **Falco** syscall
  capture — needs `bring_up_generated_range` (Docker). In dry, simulated web svc.events stand
  in for Falco. Run this on the deploy host before flipping `use_llm=True`.

### 2.2 Nebius routing — PASS
- Enforced at the boundary in `swarm/llm.py::_assert_nebius_host` (host must match
  `nebius.com$`; HF/OpenRouter raises `LLMError` — "a disqualifier"). Base URL
  `https://api.tokenfactory.nebius.com/v1/`, key env `NEBIUS_API_KEY`
  (`config/models.yaml`). Models: ultra `nvidia/Nemotron-3-Ultra-550b-a55b`, super
  `nvidia/nemotron-3-super-120b-a12b`, nano `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`.
- Paid runner: red + blue routers both `make_router("nebius", ...)`
  (live_arms_race_run.py:217/219). `provider_anthropic` is marked "Frontier BENCHMARK ONLY —
  NOT submission-valid", selected only by an explicit `--provider anthropic`; never the
  default. Control-only. ✓

### 2.3 Turn budget — RESOLVED (raised 16 → 40, Dante-authorized 2026-10-26)
- Was `run_red_agent(..., max_turns=16, ...)` at **L186** (dry) and **L233** (paid/live) — the
  exact cap the brief says confounded the earlier null run, with no CLI override.
- On Dante's explicit go this session, both call sites raised to `max_turns=40`
  (`live_arms_race_run.py:186`, `:233`). Runner re-imports clean; diff is exactly those two
  lines. **Not committed** (per instruction). Still worth adding a `--turns` CLI arg later so
  the budget isn't hardcoded, but the ≥40 gate is met.

### 2.4 Falco — wired; real non-zero capture Docker-gated
- Falco is a privileged sensor container stood up programmatically (not a compose service —
  documented carve-out, `topo_to_compose.py:62`). Paid runner calls
  `live_telemetry.start_falco(...)` (L211), reads via `read_falco` (L248); crown-read rule at
  `config/falco_duelswarm.yaml`; `prove_d4` asserts `start_falco` is in the runner. Static
  wiring present. **Real syscall capture (not 0) + `live_truth` corroboration can only be
  confirmed on the live range (Docker).**

### 2.5 Prereg re-anchor — verify is GREEN; the freeze/lock is still yours to stamp
- `preregister.py --verify` passes against the seq=22 anchor (all registered artifacts match).
  The brief's "known stale `live_telemetry` anchor" is not red here. Before the paid run,
  confirm the anchored artifact set includes the CURRENT `live_telemetry` hash (freeze the
  measurement apparatus), and lock the experimental-floor boundary at the **tier line** plus
  the three Samba findings as pre-registered EXPECTATIONS. Prepared for your approval/stamp;
  not stamped autonomously.

### Findings disposition (unchanged, captured as-is — NOT tuned)
Kerberoast `KRB_AP_ERR_INAPP_CKSUM`; secretsdump remote NTDS fails (Samba LDB/TDB, not
NTDS.dit); BloodHound reaches LDAP but Samba terminates on LDAP signing. Genuine
Samba-vs-Windows differences, held as findings. No RC4-enctype / `ldap server require strong
auth = no` / resolver tweaks applied. The PtH edge (core claim) is externally tool-validated;
the other three are honest Samba scope limits to record in the run.

---

---

## LIVE-RANGE VERIFICATION (deploy host, 2026-10-26, NO credits)
Run via `sg docker` (Docker 29.9.2). The orchestrated **unified-enterprise range (seed 1337)**
was already up (9 `range-*` containers incl. the Samba `range-dc-01`). sudo is NOT passwordless
this session, so the §E host-firewall install/verify could not be run by me — but it did not
need to be (see hard floor). Nothing paid; `use_llm` never set.

### Hard floor — kernel `probe_boundary` from the live entry — PASS (ok=true)
Networks: every data-plane segment `internal=true` (app/attacker/database/dmz/identity/mgmt/
user/oos), only `ingress` `internal=false` (the masquerade-off DNAT bridge). `probe_boundary`
from the compromised entry `range-dmz-web` (direct docker exec, no gate):
```
oos_tcp_reaches: []            (decoy-fin 10.99.0.10 unreachable)
internet_blocked: true         (no egress to 1.1.1.1 / example.com)
in_scope_reaches: 2            (>0 — db-core + wks-01 reachable; duel playable)
host_gateway_unreachable: true (172.18.0.1 blocked from the entry)
ok: true
```
Note: `host_gateway_unreachable=true` even without me running the §E firewall — the gateway
block is already in place from the earlier orchestrated boot (or structurally via the
masquerade-off ingress bridge). The SAFETY floor holds on the exact range the paid run will use.
**Confirm the §E firewall is up (`sudo host_egress_firewall.py --verify`) as belt-and-suspenders
before the paid run — that step is yours (sudo).**

### Real Falco capture — PASS (24 events, crown witness fires)
`live_telemetry.start_falco` (modern eBPF, `config/falco_duelswarm.yaml`, `--privileged
--pid=host`) on the live range; generated real activity (shell exec + `/etc/shadow` read +
a `.crown`-style read) in range-dmz-web/db-core/wks-01; `read_falco` → **24 JSON syscall/event
lines** (non-zero), with container attribution (`container=range-dmz-web`), a sensitive-file
read, and the **duelswarm crown rule firing**: `Warning Crown jewel file opened
(file=/root/.crown_probe ...)`. Falco probe container torn down; planted `.crown_probe` markers
removed. Real syscall telemetry + the crown-read witness both work live.

### Orchestrated dry-e2e — SIM green; combined live-dry run has NO free entrypoint (finding)
- SIM: `verify_live_run --selftest` runs `run_discovery_duel(router=None, gate, log, r,
  use_llm=False, rng_seed=1337)` and verifies the log → OK. The dry duel log carries red
  (`move.source:llm`), blue (blue.observe/detect) and a target-telemetry stream; reverify_floor
  cold = chain_verified=True, oos_executed=0.
- **Finding (honest):** `run_discovery_duel(use_llm=False)` is built around the *small*
  `generate_range` IR and runs **in-memory** (every caller: verify_live_run selftest,
  instrument_live, tail_at_scale). The live range is the **unified-enterprise** topology
  (`generate_unified`/`write_unified`), which only the **paid** `_run_live_episode` path drives
  (LLM router + real MSF foothold + `start_falco` + the D4 reconciler). The two do not share a
  dry bridge, so there is **no free command that runs the discovery duel against the live
  unified containers**. `run_discovery_duel` *does* expose live-injection points
  (`probe_boundary=`, `beacon_collector=`), but wiring the unified-enterprise `r` through
  `run_sim_red` would be real integration work — not a free check, and not something to add to
  the live path right before a paid run.
- **Consequence:** the paid run (`use_llm=True`) is ALSO the first full live integration of
  {unified containers + real MSF foothold + real Falco + reconciler}. The brief's "flip only
  `use_llm=True`" assumes the live wiring was already dry-exercised; in the code as built it is
  not. **Recommend a cheap first paid seed (1 seed, ~few turns) as the integration smoke before
  committing to ≥40-turn × ≥2-seed spend** — so a live wiring bug surfaces on minimal credits,
  not a full run. Alternatively, add a dry-router mode to `_run_live_episode` (a small,
  deliberate change, reviewed — not done this session).

## Headline blockers before the paid run (Part 3)
1. ~~Turn budget = 16~~ **RESOLVED** — raised to 40 at both call sites (Dante-authorized,
   uncommitted). See 2.3.
2. Docker-gated live checks — **now mostly verified live this session** (see LIVE-RANGE
   VERIFICATION): hard-floor `probe_boundary` ok=true ✓; real Falco non-zero capture + crown
   witness ✓. **Still open:** (a) the §E host-firewall `--verify` (sudo, yours);
   (b) the live PtH→Tier-0 edge (the paid path); (c) there is NO free combined live-dry duel
   run — the paid run is the first live integration, so a cheap first seed is recommended.
3. **Prereg freeze + tier-line/findings lock** — your stamp.
Plus two trivial cleanups (non-blocking): the `range_gen` cosmetic alias, the
`arms_race_check` bare import, and the docker-group `__pycache__` ownership.

STOP here. Awaiting source verification + explicit go (seed[s] + turn count + credit
authorization) before Part 3.
