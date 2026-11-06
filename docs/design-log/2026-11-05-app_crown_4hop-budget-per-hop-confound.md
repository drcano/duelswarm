# app_crown_4hop zero-corroborated shutout: a budget-per-hop confound (2026-11-05)

## What happened
The claim-1 range sweep (brief: `docs/design-log/2026-11-05-claim1-range-sweep-brief.md`) fires the
co-evolution loop on four structurally distinct ranges to test whether red's evolved winning *path*
varies with floor shape. The in-sample `unified` range landed first and passed all four pre-flight
gates (floor `oos=0` cold on 11/11 episodes, elitism fired gens 1&2, live-pop win-rate present,
no collapse; flat `1/3` corroborated crowns per gen — the Nov-5 loop-defect fixes held offense steady).

The first variant, **`app_crown_4hop`** (4-hop seam `web01 -> dba01 -> db-bastion -> ci01`, crown
`ci01` in the APP tier), fired at the same **44-turn** budget and produced **zero corroborated crowns
across all 9 population episodes** (`live_pop_win_rate_per_gen=[0,0,0]`, `corrob=[0,0,0]`). Two of the
four gates went red:
- **Gate 4 (no catastrophic collapse): RED** — total corroborated = 0, the pre-registered hold
  condition.
- **Gate 2 (elite re-run fires gens 1,2): RED** — the elite re-run fired only in gen 2, a *downstream*
  consequence of the gen-0 shutout (an empty archive after gen 0 leaves no elite to carry into gen 1),
  not an elitism bug.

Per the sweep's gate discipline (*hold on zero-corroborated, ping, do not fire the next variant*),
the sweep halted here and the remaining two variants were **not** fired.

## First hypothesis (WRONG): a variant crown-provisioning gap
The initial read — mine — was that the live Docker boot of a variant never completed the crown-data
provisioning for the N-hop path, quoting the "pre-paid-boot work remaining" scope comment at
`swarm/topo_to_compose.py:933-939`. That hypothesis was **disproven** by direct investigation. The
discipline failure worth naming: a code comment was quoted as current without verifying its currency,
and a fix was proposed without staging the compose output or the live container filesystem. The right
move — the one that settled it — was to inspect primary source: the generated compose and the running
containers.

### What the investigation actually found (cold, in-container)
- `unified_to_compose` **already generalizes** the crown plant over chain length. Offline, the written
  compose for all three variants plants `pii.json` at the correct crown (`ci01` / `db-core` /
  `db-bastion`) with the correct `crown_flag`. `write_variant -> _write_range -> unified_to_compose`
  is the same emit path as `write_unified`. Nothing in `topo_to_compose.py` needed fixing.
- On a fresh dry standup of `app_crown_4hop`, the live `ci01` container holds
  `/home/svc_dba/pii.json` (2547 B, `svc_dba`-owned, `600`, correct synthetic PII — 900-999 SSNs,
  test-BIN cards, `_SYNTHETIC` banner), the `svc_dba` user, and `.ssh/authorized_keys` with the
  `svc_dba` key. The crown-edge `db-bastion` holds the harvestable `svc_dba` private key and routes to
  `ci01` (`eth1 10.30.0.14/24`; `ci01 = 10.30.0.13`; ping 0% loss). **The range is winnable by
  construction.**

### The true cause: a budget-per-hop confound
Cold from the committed shutout chains:
- Red **never attempted the crown** — zero references to `ci01` / `pii.json` / any `svc_dba` login to
  `ci01` across all 9 IO chains; `10.30.0.13` is never a `pivot_failed`/`exfil_failed` target.
- Red **did progress**: `confirm web01` (9/9), `confirm dba01` (9/9), `confirm db-bastion` (5/9). It
  reached the crown-**edge** but never the crown.
- Red **burned its budget flailing**: 254 `ssh svc_dba publickey Permission denied` (rc=255) + 150
  rc=1, aimed at **non-seam hosts** (`10.35.0.10`, `10.60.0.10`, `10.10.0.11` — decoy/benign hosts on
  the variant's wider segments), plus 85 `lateral_failed` on "no CVE inferred" / "no harvested cred
  authenticated".
- In **2/9** episodes red's recon from `db-bastion` *did* surface the app segment and `ci01`, yet it
  still never pivoted. So discovery is not the hard blocker — the **44-turn budget** is.

`unified` is a 3-hop seam at 44 turns (~15 turns/hop; tight but workable — red converged to a flat
`1/3`). `app_crown_4hop` is a 4-hop seam at the *same* 44 turns (~11 turns/hop). Recon succeeds; red
runs out of turns to act on it. This is neither a floor-shape result nor a harness result — it is a
**budget-per-hop confound**: holding total turns constant while chain length varies silently changes
turns-per-hop, which is not the variable the sweep means to test.

## The fix: scale the per-run turn budget with chain length
Keep turns-per-hop constant across ranges so the only varied knob is floor shape:

```
budget = 44 * (chain_length / 3)
```

| range              | hops | budget | status                         |
|--------------------|------|--------|--------------------------------|
| `unified`          | 3    | 44     | unchanged — existing data stands |
| `app_crown_4hop`   | 4    | 59     | re-fire                        |
| `backup_route_5hop`| 5    | 73     | fire at this budget            |
| `mgmt_crown_3hop`  | 3    | 44     | fire unchanged                 |

The clean comparator sentence a reviewer will defend without wincing: *"red had ~15 turns per hop on
every range."*

- **Why not uniform 44 (accept the null):** it bakes the confound into the record. A reviewer asks
  "did red lose because the shape defeats it, or because 44 turns can't carry 4 hops through decoys?"
  and we have no answer. Scaling removes the question.
- **Why not a flat 73 everywhere:** red then gets more turns than it needs on 3-hop ranges, budget
  pressure (part of what makes red commit to a plan rather than explore indefinitely) drops, and the
  cross-range comparison degrades to "red can solve any range given enough time" — less interesting
  than "red adapts an efficient path per range at constant per-hop pressure."

## Mechanics and pre-registration
- Turn budget is a **run parameter**, not a hash-anchored artifact. `scripts/live_arms_race_run.py`
  already accepts `--turns` as the per-episode red budget (it flows to `max_turns`); an explicit
  `--turns 59` passes straight through the `--live-generations` branch. **No code change and no
  pre-registration amendment** are required to change it. The driver selftest still passes at the
  default budget (flag plumbing does not drift baseline behavior).
- The Nov-5 shutout chains are preserved verbatim as the dated record of the catch at
  `docs/runs/2026-11-05-claim1-sweep/app_crown_4hop_44t_shutout/`; the 59-turn re-fire lands in the
  canonical `.../app_crown_4hop/`. They are not rewritten.

## Why this was caught before it cost anything
The gate discipline — *hold the sweep when a range returns zero corroborated crowns* — is why the
confound surfaced on the first variant instead of silently propagating through all three paid runs (and
into any later adversarial-red run scheduled against the same budget). Pushing the build to the variants
surfaced a confound that unified-only runs never would have. The hold cost nothing; it saved two paid
runs on a mis-budgeted instrument.
