"""External-validation auditor rig (Phase 0b).

Real off-the-shelf attacker/detector tools pointed at the range to prove its realism is a
MEASURED property an outside tool confirms — not our assertion. Each module here wraps a real
binary (or does a self-contained analysis) and emits a machine-checkable VERDICT.

Hard rails (enforced by `leak_test`):
  * AUDITOR ONLY. Nothing here touches a live effect site (no `swarm.gate`, no range standup),
    and nothing here is imported by red's path. These tools audit the range's ground truth from
    OUTSIDE, the way `reverify_floor` audits the floor.
  * Validator output is NEVER an input to red. A real tool FAILING against the range is a realism
    FINDING to report, not something to tune around.

Verdict schema (see `_common.verdict`): {validator, available, ok, detail, evidence, ts}.
`available=False` => the tool/target wasn't present (UNMEASURED — never a silent pass); when
available, `ok` is the realism finding (True = behaves as it would on a real network).
"""
