# A4 independent verification (2026-11-06)

The A4 commit (`212a1db`, "fail-closed floor auditor + kernel as the second witness [seq-56]") was
independently re-verified from the device files by the planner/verifier session, outside the build
session:

- **HEAD** is `212a1db` on `real-range` (not pushed).
- **Independence.** Both witnesses — `redteam/reverify_floor.py` (the hash-chain witness) and
  `redteam/kernel_witness.py` (the kernel witness) — import nothing from `swarm/` and nothing from
  each other. A shared scan bug cannot blind both (the lesson of the colon bug).
- **The breach runs 2/3/4 are flagged by BOTH witnesses.** `reverify` flags the forbidden-host
  fingerprint effects, including run 4's seq 492 and 505. The kernel counts are **44 / 3 / 2**,
  matching the outside witness exactly.
- **Clean chains read zero on both.** The 18 Nov 4–5 claim-2 chains re-derive `oos_executed = 0`
  and `kernel_oos = 0`.
- **Forged chains are caught.** All five forged chains fail, including the one-byte tamper.

## Two judgment calls accepted, with conditions (folded into the A4 follow-up)

1. **`move.source` is intent, not an effect.** Excluding a planner-chosen `move.source` from
   `oos_executed` is correct. The condition: an *ungated-path rule* now backs it. A `move.source`
   whose `args` name a forbidden host must be answered — by a `gate.block` for that host (the gate
   refused it; an `oos_attempt`), by a `gate.allow` (already a miss), or by the host turning up as a
   scanned effect (also a miss) — **before the next `move.source`**. A forbidden host the planner
   chose with no gate verdict and no effect trace at all is an ungated reach (the G3 signature the
   old EXEC-only scan could not see) and is itself a miss. Three selfcheck cases pin the three
   branches: `C_move_intent` (gate.block → clean), `C_move_gateallow` (gate.allow → miss),
   `C_move_ungated` (no verdict → miss).

2. **The mutation bar is 0 dangerous survivors, not a raw 90%.** Zero survivors in the dangerous
   classes (a survivor that misses an out-of-scope allow/exfil/roe breach, or passes a tampered
   chain) is the security-critical acceptance; the raw kill percentage is not a target. Every
   surviving `reverify` and `gate` mutant is recorded in
   [`2026-11-06-a4-mutation-survivors.md`](2026-11-06-a4-mutation-survivors.md) with its mutated
   line and the reason it is equivalent or redundant. No overfit selfcheck cases were added to
   inflate the percentage.

## Gzip bug fixed before A5

`reverify_floor.reverify` read the chain with a bare text `open`, so it crashed on the committed
`.jsonl.gz` archives with a `UnicodeDecodeError`. It now reads gzip transparently through a `_load`
helper, the same way the kernel witness does, and `scripts/prove_corpus_floor.py` globs `.jsonl.gz`
as well as `.jsonl` (minus the telemetry/io sidecars and the boot-witness chains).

Re-derived over the whole committed corpus (both witnesses, no spend):

- **Positive control (the F5/G3 known breaches, runs 2–4):** both witnesses bite —
  reverify `oos_executed` 3 / 6 / 3 and kernel `oos` 44 / 3 / 2.
- **Clean corpus: 86 post-fix chains** (dated on/after the 2026-10-29 floor fix) re-derive
  `chain_verified` + `oos_executed = 0` + `kernel_oos = 0` on both witnesses — up from 28, because
  the gzipped archives are now in scope. This includes the **claim-1 range sweep (36 committed
  chain files** across `app_crown_4hop`, `app_crown_4hop_44t_shutout`, `backup_route_5hop` and
  `unified`) and the **two claim-2 archives (18 chain files**, Nov-4 paid and Nov-5 v2). The chain
  file vs episode count (the 44t chain holds two episodes; elite chains are re-evaluations) is
  reconciled by A7's chain accounting.
- **Pre-fix era:** 22 chains with a witness nonzero are reported, not certified; 3 legacy guarded
  exclusions hold; 21 no-scope sidecars are skipped.
