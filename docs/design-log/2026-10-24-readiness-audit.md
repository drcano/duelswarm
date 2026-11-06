# Readiness audit — TCB line-by-line + invariant battery (independent verification)

Date: 2026-10-24. Branch `real-range`, HEAD `77be87b`. Author: the planning/verifier session.
Method: the trusted core read line-by-line; the invariant battery re-derived cold on HEAD in an
isolated container (file-only bridge, so every file re-staged fresh before any grep/run). Not taken
from a build report or a green `make test`.

## Verdict
The science is READY: the deterministic floor re-derives `oos_executed=0` cold under the first full
multi-hop crown breach (greedy proof, `77be87b`), by an auditor that trusts neither the gate nor the
agents. The trusted core is sound AND honest about its own limits. Nothing found blocks the core
claim or the optional paid autonomy run. A short pre-submission polish list follows; none is
load-bearing.

## Verified at source
- **TCB, line by line:** `gate.py` (complete mediation — block/raise before tool_fn; default-deny;
  read-vs-mutate verb axis), `eventlog.py` (append-only hash chain; verify() catches edit/reorder/
  mid-delete; tail-truncation + full-rehash gaps stated and covered by the external prereg anchor),
  `spine.py` (state mutates only on a non-agent observer's confirmation; anti-self-report),
  `redteam/reverify_floor.py` (non-circular — imports neither gate nor audit, re-derives scope from
  the log's own scope/roe/topology events; anti-gaming — a `gate.allow` is not excused by an
  unrelated earlier block), `scripts/mediation/static_coverage.py` (independent `ast` oracle;
  classifies every effect sink by transparent rules; isolates the class-2 falsifier; admits its
  module-local domination ceiling), `swarm/live_truth.py` (reconciler — corroborates red's claims
  only against the targets' OWN telemetry; refuses incidental-traffic corroboration; the crown-read
  needs the actual `.crown` syscall).
- **Battery cold on HEAD (all green):** `eventlog`/`spine`/`gate`/`live_truth`/`audit` selftests;
  `audit` ≡ `reverify_floor` EXEC parity (15 actions); `static_coverage` PASS (class-2 isolated);
  `prove_falsification` bites; `redteam_gate` proves the gate invariant; the crown chain re-derives
  `oos_executed=0`, chain verified.

## The completeness triad (how "no unrecorded effect" is actually guaranteed)
`reverify_floor` (no out-of-scope LOGGED execution + chain intact) + `static_coverage` (every effect
SITE routes through the one gate primitive) + `live_truth` (red's claims must match the targets' own
telemetry). No single file carries it; the three together do.

## Findings (minor; for pre-submission, none block the science)
1. `static_coverage.COUNTED_ENTRIES` lists `prove_n2n3_tiered` + `exp_a_control_eval`, NOT
   `arms_race_enterprise_frontier` — the entrypoint the crown/floor headline is made over. The
   frontier does not import `uninstrumented` (checked), so isolation holds in fact but is not
   formally asserted over the headline path. Add it.
2. Soft-hardcoded host tables: `reverify_floor.ALIAS` (localhost/127.0.0.1→struts, range-*),
   `spine.DEFAULT_PORTS`, `audit.DEFAULT_ALIASES`, `live_telemetry` subnets. Cannot mask an
   out-of-scope execution on a real run (log topology/coords take precedence), but are a
   "hardcoded host in the independent checker" smell. De-hardcode to topology-driven resolution.
3. `static_coverage` honestly reports 5 un-confirmed sinks (3 DIRECT capability edges — two are the
   `blue_contain` __main__ selftest, one is `live_arms_race_run._real_contain`; 2 undominated
   class-1 — `exploit.run_command` urlopen, msfrpcd `docker run`). The oracle's admitted ceiling;
   close with the Stage-3 runtime reachability probe or a documented reclassification — never by
   silencing.
4. Crown-read corroboration is the honest 1/4 flag; the free Falco-witness fix (separate brief)
   closes it to 4/4 by making a REAL witness fire, not by loosening the rule.
5. HONEST CLAIM SCOPING (narrative): of the four thesis claims, claim 4 (harm in the seams between
   floors = `multi_floor`) and the overseer LLM-in-TCB probe were CUT as unbuilt. The reviewer
   artifact must state: claims 1–3 have instruments/data; claim 4 is framing, not built. 3/4, not
   4/4 — no confirmation bias.

## Not done (does not change the verdict)
Every line of the ~66 swarm modules / ~48 scripts beyond the TCB was not read; those were verified
structurally this session (one-of-each by import graph, no orphans, one effect path, engine
selftests green). Readiness lives in the TCB + invariants + claim map, which were read and
re-derived.
