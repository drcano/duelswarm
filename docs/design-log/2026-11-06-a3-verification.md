# A3 independent verification (2026-11-06)

The A3 commit (`8557f46`, "every red-reachable effect passes through gate.dispatch") was
independently re-verified from the device files by the planner/verifier session, outside the
build session:

- **HEAD** is `8557f46` on `real-range` (not pushed).
- **The oracle is authentic.** The two t1b files
  (`tools/audit-kit/instrument_tests/t1b_red_reachable_effects.py`, `t1b_baseline_eeffec7.txt`)
  are byte-identical to the delivered ones.
- **t1b on HEAD = 0 ungated red-reachable sinks**, reproduced with an outside copy of the oracle.
- **No sink is hidden behind renames or aliases** — the import-aware walk finds no red-reachable
  effect outside `gate.dispatch`.

## Two follow-up fixes folded into A4 (recorded here)

1. **Earned-channel command egress.** Every earned-shell wrapper (`live_red._gated_shell`,
   `_run_command_channel`, the `t_harvest` vantage channel; `live_weapon` `exec_channel` and
   `_gated_exec_channel`) now passes `command=cmd` to `gate.dispatch`, so `check_egress` inspects a
   post-exploitation command the same way `t_run_command` does. Regression: through an earned shell
   on an allowed host, `curl 10.50.0.11` is a `gate.block` with no effect.
2. **Gated local reads fail closed.** `own_ips`, `own_subnets` and `_iface_read` no longer accept a
   silent pass-through default: with no gate they RAISE instead of reading. Red call sites pass the
   real gate + the host; the TCB range standup passes an explicit TCB read-gate. Re-verified: t1b
   still 0, `prove_runtime_destinations` still passes.
