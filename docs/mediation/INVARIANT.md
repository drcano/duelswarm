# Stage 4 — The Mediation Invariant and its Assumption Ledger

The claim written as a theorem with a stated scope, so it is no longer a sampled
zero. The invariant is a *universal*; it holds not because we counted executions
but because each assumption it rests on is discharged by a stage with an
independent oracle.

## The invariant

> **INV.** An effectful action executes only if its real effect target is in the
> acting actor's authorized set.

Formally, for every effectful action `a` taken by actor `A` with real
(post-resolution, as-routed-by-the-kernel) target `t(a)`:
>
> `executes(a)  ⟹  t(a) ∈ scope(A)`

where `scope(A)` is the per-actor authorized set the gate enforces
(`Gate._scope_for`), and "effectful" is the class-1 definition in
`COVERAGE_SPEC.md` (an effect that crosses to a target).

## Scope of the claim (what INV is asserted over)

- The **counted / live entrypoints**: `prove_n2n3_tiered`, `exp_a_control_eval`,
  `live_swarm` and the live-duel path they drive. These are where the floor
  claim is made.
- Actions routed through the single chokepoint `gate.dispatch`, plus the
  free-form shell path mediated by `gate.check_egress`, backed by the
  network-layer segmentation.

It is **not** asserted over: the Phase-2 arms-race driver
(`scripts/arms_race_run.py`), which has an ungoverned blue-containment path
(finding F1); offline vetting/analysis harnesses (class-4); or the deliberate
gate-off proof channel (`uninstrumented`, class-2), which is isolated from the
above (Stage 1).

## Assumption ledger

INV holds iff all four assumptions below hold. Each maps to the stage + oracle
that discharges it.

| | Assumption | Discharged by | Oracle | Status |
|-|------------|---------------|--------|--------|
| **A** | No un-gated class-1 sink: every effectful actor action is dominated by `gate.dispatch`. | **Stage 1** (`static_coverage.py`) | Python `ast` (mechanical, shares no gate code) | **Holds on the counted path. Finding F1 CLOSED** — blue containment in `blue_agent` now routes through `gate.dispatch` (both capabilities GOVERNED). Named cross-module dominance ceiling remains (confirmed by hand + mooted physically by C). |
| **B** | Canonicalization soundness: the target the gate checks equals the physical target the OS routes to. | **Stage 2** (`parser_fuzz.py`) | OS resolver `inet_aton` + `getaddrinfo` (differential vs gate) | **Does NOT hold at the parser layer** — 3 true bypasses (dotless numeric encodings of the real decoy 172.22.0.4) + 21 shell-expansion slips. **Rescued by C**: the kernel never routes those to the OOS segment. Not patched (gate.py frozen; the close is the network, not a smarter parser). |
| **C** | Segmentation equals the claimed scope: the network cannot route an in-scope host to an out-of-scope target. | **Stage 3** (`reachability_probe.py`) | kernel (`connect(2)` + ICMP), shares no gate code | **KERNEL-CONFIRMED for inter-container reachability.** Measured == claimed exactly; the decoy IP (target of all 3 B-bypasses) is unreachable from the entry at L3+L4; no internet egress. This is the assumption that carries the floor when B slips, and it is now measured, not just claimed. §E host-gateway reach is open (VM-moot here) pending a native-Linux `--up`/`--verify`. |
| **D** | Log + spine integrity: the hash-chained event log and spine are tamper-evident, so "executes(a)" and "gate.allow(a)" are faithful. | existing `redteam/reverify_floor.py` + `scripts/verify_chain.py` + `swarm/spine.py` | sha256 hash chain | Holds (existing `make test` coverage). |

### Why B-slips do not break INV (the network-vs-parser split) — now measured

INV is about the **physical** target `t(a)` (as-routed). Assumption B's failures
are all at the string-parser layer: the gate *allows* a command whose literal
the parser can't resolve (shell expansion) or mis-rejects (dotless numeric). But
by assumption C the kernel never routes that packet to the out-of-scope segment
— `range` (172.20/16) and `range_oos` (172.22/16) share no network. **This is no
longer a claim: the kernel measurement (Stage 3) shows the decoy IP 172.22.0.4 —
the exact target of all three B-bypasses — is unreachable from the entry at L3
and L4, with no internet egress.** So `t(a) ∉ scope(A)` actions do not execute
their effect even when the parser lets the command run. The parser was always
defence-in-depth; **C is the guarantee, and C is now kernel-confirmed.**

## Residual — what is NOT proven (the honest scope, and the seed for next work)

1. **Stage 3 inter-container measure: DONE (kernel-confirmed).** The one
   remaining piece is the §E host-gateway isolation on a **native-Linux deploy
   host**: `host_egress_firewall --up` then `--verify` (the entry reaches the
   LinuxKit VM's ingress gateway here at L3+L4:22 — VM-moot, no onward egress,
   but must be closed+verified on the real host). This is now the single biggest
   open item, and it is a host-firewall confirmation, not a floor unknown.
2. **TOCTOU (time-of-check / time-of-use).** The gate canonicalizes and checks a
   target, then the tool runs. Between check and the kernel's `connect`, a name
   could in principle re-resolve (DNS rebinding, a container IP reassigned). The
   static + parser stages cannot see this window; only a per-`connect` kernel
   hook (eBPF at `connect` time, beyond Stage 3's post-hoc capture) would. Not
   discharged.
3. **Confused-deputy composition across floors.** The gate catches the
   single-floor confused deputy (blue acting on red_infra without active-defense
   ROE — tested in `gate.py`'s self-check). Composition across multiple floors
   (`swarm/multi_floor.py`) — actor A inducing actor B to act outside A's scope
   via a legitimate B capability — is not exhaustively characterized. Partially
   addressed by per-actor scope; not proven for arbitrary compositions.
4. **Assumption A cross-module ceiling.** Stage 1's domination check is
   module-local; cross-module dispatch domination was confirmed by hand for the
   red tool path, not by whole-program binding resolution. A whole-program
   call-graph (or the Stage 3 kernel oracle, which moots it physically) would
   fully discharge A.
5. **Finding F1 is CLOSED.** `blue_agent` now routes containment and honeytoken
   through `gate.dispatch` via the `_gated` helper (the arms-race driver passes
   its gate), so blue's offense is mediated on the legacy cascade path too. The
   Stage-1 capability-edge check reports both GOVERNED. INV's scope now includes
   the Phase-2 driver's blue actions.
6. **Parser hardening (finding, not required for INV).** The 3 true parser
   bypasses could be closed in a gate revision (canonicalize dotless
   numeric/`0x`/v6-mapped host tokens through `inet_aton` before the scope
   check). Not required while C holds, but it would make B hold standalone.

## One-line status

INV is **enclosed and kernel-confirmed for inter-container reachability**: A
holds (F1 closed), B does not hold at the parser layer but is rescued by C, C is
kernel-measured (measured == claimed; decoy unreachable from the entry; no
internet), D holds. The one remaining item is the §E host-gateway isolation on a
native-Linux deploy host (`host_egress_firewall --up`/`--verify`); the 3 parser
bypasses stay recorded as characterized incompleteness (gate.py frozen; the close
is the network, not a smarter parser).
