# Experiment A — build notes (dated; NOT a pre-registration amendment)

## 2026-10-20 — counted boot path generalized (Option A)

**What happened.** The confirmation run (`--frontier --adversarial --range-seed 7
--seed 11`) crashed in topology setup — `KeyError: 'range_db_net'` in
`prove_n2n3_tiered.py main()` — **before any Docker build or LLM call, so zero credits
were spent.** Root cause: `main()` was hard-wired to the EquifaxSmall shape (one attacker
net → one dmz pivot → one inner net literally named `range_db_net`). The anchored
curriculum fixtures use `range_subnet_*` segments with crowns spread across subnets; all
30 generated fixtures (the five anchored among them) lacked `range_db_net` on their flag
hosts, so **none booted through the counted `main()` until this commit.** They parsed
through `emit.derive` (what the terrain-variety check used) but not the boot wiring.

**Fix (non-frozen runner only).** `prove_n2n3_tiered.py`:
- `_derive_terrain(...)` derives the entry net, the inner subnet(s), each flag's inner IP,
  and the ip→name / ip→container maps from the real `plan_ips` keys — no `range_db_net`
  literal, no single-inner-net / single-pivot assumption.
- The frontier `recon_from` now sweeps **every** inner subnet, scanning from the container
  of the host being recon'd (multi-pivot: a host newly held on a deeper segment sweeps that
  segment), so crowns spread across segments become reachable as red pivots. A subnet a
  vantage can't route to returns nothing — honest, never faked.
- The reachable-but-OOS trap (crit-4 / `strong_llm_oos`) is placed on a subnet the entry
  pivot is on AND a flag is on, so red's recon reaches it and the gate denies. The isolated
  `range_oos` backstop is untouched.
- A Docker-free `--selftest` dry-boot derives the net/IP/trap layout + compose for
  EquifaxSmall and all five anchored fixtures (7, 17, 19, 21, 29) and asserts no KeyError,
  inner nets derived, trap placed on a swept subnet and OOS, scope sane. This offline gate
  is the thing that would have caught the KeyError before a spend.

**Regression.** EquifaxSmall resolves **identically** (single `range_db_net` inner net,
same trap segment and free octet) — asserted in the dry-boot. The nine frozen files
(`gate.py`, `eventlog.py`, `spine.py`, `verify_live_run.py`, `reverify_floor.py`,
`attack_graph_service.py`, `mh_generator.py`, `red_recon.py`, `mh_recon.py`) are
byte-identical to `ee61c0c`. `make test` is green.

**No amendment required.** The five fixtures, the four red seeds, the 20-pair run set, and
the floor under test are all **unchanged**. This commit fixes the *harness* that boots the
anchored terrain; it does not touch the pre-registered independent variables, measures, or
decision rule. The anchored `EXP_A.md` (seq 11, sha256 `1eec28bc68b7…`) stands as-is.
