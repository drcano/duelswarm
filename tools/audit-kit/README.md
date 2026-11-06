# audit-kit: independent acceptance oracles for duelswarm

These scripts were written outside the repo and import nothing from it, except where a test
deliberately exercises the repo's own code (mutation and fuzzing). They are the done-signals named in
`2026-11-06-cc-brief-v3.md`.

| Script | Purpose | Run |
|---|---|---|
| `walk.py` | Independent hash-chain walker | `python3 -I walk.py <chain files...>` |
| `floor2.py` | Three-way floor witness: kernel connects to forbidden IPs, sshd `Accepted` on forbidden hosts, and red events naming forbidden hosts. Also splits blocks into red-chosen vs engine-expanded | `python3 -I floor2.py <episode chain(s)>` (looks for `<chain>_telemetry.jsonl[.gz]`) |
| `pathmetric.py` | Claim-1 path metric (sha256 `86ea44f6…bb1f` when last fixed) | import, or see its docstring |
| `forge.py` | Builds forged chains for auditor blind-spot tests | `python3 forge.py <mode> <src> <dst>` |
| `instrument_tests/t1_mediation_graph.py` | AST call graph: effect sites not dominated by `gate.dispatch` | `python t1_mediation_graph.py <repo> out.json` |
| `instrument_tests/t2_imports.py`, `importlinter.ini` | Import contracts (`redteam/` and `verify_chain` independent of `swarm/`) | `python t2_imports.py <repo>` |
| `instrument_tests/t3_mutate.py`, `t3_classify_*.py` | Mutation testing of the floor auditor and the gate, plus classification of dangerous survivors | see each script's argv |
| `instrument_tests/t4_fuzz_gate.py` | Hypothesis fuzzing of gate canonicalization and egress | `python t4_fuzz_gate.py <repo> out.json` |
| `instrument_tests/t5_failclosed_auditor.py` | Fail-closed floor auditor over every committed chain | `python t5_failclosed_auditor.py <repo> out.json` |

Baseline outputs from the 2026-11-06 audit (`t1_mediation_graph.txt`, `t3_*_survivors_classified.txt`,
`t4_fuzz_gate.txt`) are included so improvements can be diffed.
