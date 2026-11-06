# DuelSwarm — Liquid Stage wired into the live demo (status + findings)

*Branch `frontier-liquid`. Written 2026-10-16 after wiring the LIQUID_REALISM
build (P0→R4) into the demo entrypoint and running it live. GitHub push
suspended — all commits local.*

## 1. What was already there (P0→R4, prior commits)
The realism machinery existed but was **not reachable from the demo**:
- **P0** — `one_real_nemotron_call` fixed to return real content and fail loud on empty.
- **R1** — `range_gen.generate_range(scale="enterprise")`: a segmented ~20-40 host
  breach network, every host tagged a fidelity tier (T1/T2/T3).
- **R2** — `range_gen.build_sourced_range`: Tavily-at-build CVE sourcing cached into
  `ground_truth.cve_cache`, with a `vetted_images` registry for T1.
- **R3** — `red_loop.run_red_loop`: fingerprint → research → exploit-or-pivot,
  branching on tier, everything through `gate.dispatch`.
- **R4** — `red_loop.adaptation_beat`: the no-CVE host as a measured adaptation beat
  (pivot / loop / hallucinate), each handled honestly.

All five were committed with self-checks in `make test`, but
`scripts/liquid_stage.py` and the dashboard still ran the SMALL range — the
enterprise topology and tier-aware loop never appeared on screen.

## 2. What this session built
Three commits that thread `scale` from the CLI down to the dashboard, additively,
leaving `--scale small` byte-identical.

| Commit | File | Change |
|---|---|---|
| `26fdf37` | `swarm/multi_floor.py` | `Floor.__init__` / `open_floors` take `scale="small"` (default). `"enterprise"` builds the floor's range via `build_sourced_range` (R2) so the chain carries `cve_cache` + provenance. |
| `82c17e5` | `scripts/liquid_stage.py` | `run_liquid_stage` + CLI gain `--scale {small,enterprise}`. Enterprise runs `run_red_loop` (R3) + `adaptation_beat` (R4) against the primary floor's gate and the hash-chained log. |
| `85cea45` | `viz/index.html` | Dashboard surfaces the tier chips, the new red beats, the R4 tally, and a chain-derived Bypass floor. |

### Data flow in `--scale enterprise`
```
curate (E)  →  open_floors(scale=enterprise)  →  build_sourced_range (R2)
                                                   → range carries cve_cache
primary floor → main_gate (scope_by_actor)
  generations loop (population D / battlefield C / economy F)   ← unchanged
  run_red_loop (R3)   → red.fingerprint / research.cve / red.compromise(T1)
                        / red.exploit.modeled(T2) / red.pivot(T3)
  [snapshot: run-level degeneracy / canary / arms]
  adaptation_beat (R4) → red.adaptation(+.tally)   ← runs LAST, see §4
liquid.summary → EventLog.verify()
```
Every beat is one `EventLog.append` → the dashboard reads them over SSE. No
on-screen number is a literal.

## 3. Live run (2026-10-16, `--scale enterprise --gens 2 --episodes 2 --live`)
One real Nemotron call; the rest offline; **no Docker booted**.

- **Real Nemotron call** (P0 non-negotiable): `nvidia/nemotron-3-super-120b-a12b`
  returned real content ("ready"), logged as `live.nemotron` (reply_len 5).
- **Hash chain**: 174 events, `verify() = True`, `first_bad = None`.
- **Tier-aware red loop**: 19 fingerprint+research pairs; **3 real compromises,
  all T1**: struts (CVE-2017-5638), jenkins (CVE-2024-23897), db (CVE-2019-9193);
  6 T2 modeled (labeled, uncounted); 14 T3 pivots.
- **R4 adaptation**: pivot/loop/hallucinate tally over the on-path T3 hosts; no
  T3 host ever recorded as a compromise.
- **Floor held**: 4 gate blocks, `out_of_scope_executed = 0`,
  `evasion_vs_gate = 0.0`, canary captured.
- **Dashboard**: renders tier chips, `T1 REAL pop` rows, T2 modeled rows, pivots,
  the `no-CVE walls — pivot:4 loop:3 hallucinate:3` tally, Bypass = 0, no console
  errors.

`make test`: **green at every commit** (`Failed: 0`).

## 4. Findings (the honest notes)

**The honesty bar held end-to-end.** Only T1 hosts are ever a counted compromise;
T2 is gated + labeled `fidelity: "modeled"` and never counted; T3 is never a pop.
The live chain bears this out — all 3 `red.compromise` events are T1/real.

**Run-level `degenerate = True` is honest, not a regression.** The pre-existing
generation loop replays `exploit_struts→struts` each episode; at ≥4 repeats the
degeneracy detector (correctly) flags a loop. This is the same across scales — not
introduced by the enterprise wiring. If the demo top-line should read "not
degenerate," reduce episode repetition or give the generation loop distinct
targets; I left it because changing it risks the "small byte-identical" guarantee.

**The R4 beat deliberately induces a caught loop — so it runs last.** `adaptation_beat`
thrashes a T3 host `_LOOP_THRESHOLD+1` times on purpose, to prove the loop *is*
caught. If folded into the run-level degeneracy snapshot it would dominate the
signal. The fix: snapshot degeneracy/canary/arms over the duel *before* the R4
probe, and scope the probe's own result to its `red.adaptation.tally`.

**Bypass-metric gotcha (fixed).** My first cut defined the dashboard's out-of-scope
floor as "an allow whose target was blocked elsewhere." That false-positives: the
P0 egress proof blocks an **in-scope** host (struts) on its *command*, so struts
appears in both allow and block. The correct, false-positive-free definition —
matching the existing liquid-world floor banner — is a `gate.allow` the gate itself
resolved out-of-scope (`data.scope === 'out'`). Structurally 0 because the gate
never emits such an allow. Both read 0 against the live chain.

**Display gap (not fixed, flagged).** The top-bar "Nemotron" counter tracks
full-swarm `llm.call` events, so it does not tick for the single `live.nemotron`
beat. The live call is truthfully in the chain; it just isn't in that counter.
Honest but easy to misread as "no live call" — surface it if it matters for demo.

**Token Factory budget.** Prior ops notes flagged the budget as spent; this one
cheap live call still went through. One success is not evidence of healthy budget —
treat `--llm-pop-size > 0` (which multiplies calls by pop_size × generations) as a
real spend and ask first.

## 5. Not done (needs explicit OK — credits / Docker at scale)
- The paid corpus + monitor matrix (Phase 1) — unchanged, still parked on credits.
- Booting the ~20 enterprise containers (`make range-up` / a live Docker duel over
  the enterprise topology) — `liquid_stage` is offline except the one Nemotron call.
- `--llm-pop-size > 0` enterprise sweep (per-genome live plans).
