# Design log — Phase 1 inventory: the two range generators, merge direction, prereg boundary (2026-10-25)

Phase 1 step 1 (brief): inventory both generators AT SOURCE before merging, decide the merge direction,
and map every property to re-home BEFORE deleting the loser. This is CC's source-grounded recommendation;
the merge direction and the experimental-floor boundary are flagged as **Dante's calls**, not CC's.

## What each generator emits / proves (read at source)

### `swarm/range_gen.py` (enterprise generator) — the LIVE crown path's base
Emits: `generate_range(seed, scale)` — enterprise topology with branching, depth, **T1/T2/T3 tiers**,
**sectors** (utility/bank/hospital), **zones**, **per-actor scope/ROE**, **decoys/honeypots**, a
**protected crown**, crown behind ≥2 pivots, an out-of-scope **floor tier**. `source_cves` /
`build_sourced_range` — **real NVD/KEV CVE sourcing + cache**. `to_compose` — the segmentation floor
(`range_attacker/dmz/internal/data/oos`, `internal:true`, DNAT-only ingress) + `host_posture()`.
Proves (`__main__`): determinism; ≥20 distinct ranges; in/out network-segmented; entry is a vetted T1
anchor with a real initial-access CVE; crown in-scope behind pivots; decoys oos; F2 egress containment;
Phase-0a posture.
Consumers (the LIVE path): `live_arms_race_run` (the paid crown engagement), `live_duel`, `env_coevo`,
`prove_spine`.

### `swarm/topo_to_compose.py` (MHBench adapter) — the real credential-pivot substrate
Emits: `derive(topo)` from MHBench schema fixtures (**chain / dumbbell / Equifax-hub idioms**);
`to_compose` — **real vetted vuln images** (`_real_vuln_images`), **real sshd + authorized_keys
credential pivots** (`_loot_command`, SSH-key trust edges), **planted loot**, **flags on ≥3 hosts**,
**read-only rootfs on oos hosts** (Phase-4b read-vs-mutate axis), and a **real-service swap** for
pure-foothold hosts. `scope_by_actor` — per-actor scope.
Proves (selftest): multi-flag terrain (≥3 flags, distinct hosts); real segmentation + F2; **per-flag
pivot-gating** (deep flags reachable only via pivot, not directly); floor `oos_executed==0` re-derivable
cold by the real `Gate` + `reverify_floor`, for BOTH actors.
Consumers: `prove_n2n3_tiered`, `prove_n3_live_blue`, `power_v4`, `prove_checkpoint1`, `orienteering`.

### Shared (already converged)
Both emit the SAME segmentation floor and now share `host_posture()` (Phase 0a). Both have a
`topology_event` and a per-actor scope notion.

## Merge direction — CC recommendation (Dante signs off)
**Base = `topo_to_compose` (MHBench-native), fold in `range_gen`'s enterprise structure.** Rationale: the
Phase-1 CORE deliverable is a credential-graph overlay + a real AD tier, and `topo_to_compose` already
holds the **real credential-pivot substrate** (sshd/authorized_keys/loot, real vuln images, flags,
read-vs-mutate axis) that the overlay is built on; re-implementing that on the `range_gen` base would be
the bigger, riskier rewrite. This matches the brief's steer.

**Properties to re-home from `range_gen` BEFORE deleting it** (none may be lost):
1. Enterprise structure: T1/T2/T3 tiers, zones, sectors, branching/depth, protected crown, oos floor tier.
2. Decoys/honeypots (Phase-1 wants honey-cred / honey-SPN / decoy-DB / canary-admin on the paths).
3. Real CVE sourcing (`source_cves` / NVD-KEV cache) for the edge-exploit hosts.
4. `scale` parameter (small → enterprise 20–40+ hosts, per the scale plan).
5. Per-actor scope/ROE + the `generate_range` invariants (determinism, vetted-T1 entry, crown-behind-pivots).

**Migration risk (why it's Dante's call):** the LIVE paid path (`live_arms_race_run`, `live_duel`) is
`range_gen`-based. Moving it onto the unified topo-base generator touches the exact path Phase 5 runs, so
it must be migrated increment-by-increment with the floor re-derived cold at each step, and `range_gen`
deleted LAST — only after every property above is re-homed and every consumer repointed.

## Experimental-floor boundary — prereg MODELING CHOICE (Dante's call, not CC's)
Where the gate-policy scope boundary sits DEFINES THE QUESTION, not the desired answer. Build the generator
so the boundary is a **parameter**; leave it at the **tier line** pending Dante's prereg sign-off.
- **Recommended (brief): tier-line.** Red authorized through DMZ/USER/APP; Tier-0/identity OUT of
  gate-policy scope. Reaching/executing on the DC is itself the authorization crossing, so the measurement
  is whether red crosses it (`oos_executed>0`, a studied penetration) or the gate catches it — while the
  HARD floor contains everything either way. A sandbox-edge boundary would just duplicate the hard floor
  and never bite on credential movement.
- Not chosen to make the floor hold or break — chosen to ask the real question. A null is a result.

## Proposed Phase-1 increments (after sign-off), floor re-derived cold at each
1. Unified generator on the topo base; re-home enterprise structure (tiers/zones/sectors/decoys/CVEs/scale);
   boundary as a parameter (default tier-line). Old generators still present.
2. Add the real **Samba AD DC** identity tier (Kerberos KDC + LDAP + SMB) to the 6-segment topology.
3. Credential-graph overlay: plant the loot→unlock DAG with real primitives (plaintext DB cred, real SPN,
   reused local-admin, cached DA hash, backup/agent cred); reachability invariant ≥2–3 hops; decoys on
   the paths.
4. Repoint consumers (incl. the LIVE crown drivers) onto the unified generator; re-derive the floor cold.
5. Delete `range_gen` (loser) LAST; Phase-0b validators (`bloodhound_paths`, `offensive_probe`) run against
   the booted AD tier as the external realism audit.

## Status
Phases 0a (`f47451d`) and 0b (`067c3a9`) committed on `real-range`, unpushed. Phase 1 is BLOCKED on two
Dante decisions: (a) merge direction sign-off, (b) prereg experimental-floor boundary. No merge or delete
begins until both are settled.
