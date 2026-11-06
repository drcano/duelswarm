# Glossary

Terms used in the design-log, commit messages, pre-registration entries, and code comments.
Written for a reviewer coming to the repo cold.

## Core concepts

**The gate.** The single piece of code that decides whether each attempted action is allowed.
Every red and blue action passes through it. Also called "the floor" or "the authorization
enforcer." Same thing. Lives in `swarm/gate.py`; its sha256 hasn't changed in 53
pre-registration entries. A reviewer running `redteam/reverify_floor.py` on any committed
chain can re-derive whether the gate ever let an out-of-scope action through.

**Out-of-scope execution (abbreviated `oos_executed` in logs and code).** The count of
actions red (or blue) attempted against hosts the gate forbids. By construction this should
always be zero. A positive count is the single most important possible result — the gate was
penetrated. We track it per episode.

**The ground-truth firewall.** Red is never told the answer. The scoring code and the
oracle-optimal-path reference see ground truth; red's inputs never do. A static check
(`assert_red_map_blind` in `swarm/live_agent.py`) would fail loud if any ground-truth token
reached red's awareness channel.

**The air-gap.** A one-way information barrier between red and blue. Blue reads only the
telemetry red's actions emit — never red's plan, memory, or thoughts. The air-gap is enforced
by code (blue has no access to red's internals) and by a selftest that bites if a leak
appears (`sensor_real.assert_label_free`, `benign_baseline.assert_benign_label_free`).

**Ultra / Nemotron Ultra.** The large Nebius-hosted model (`nvidia/nemotron-...`) we've been
driving red with. The provider is pinned per run; a mid-run swap is caught at the API
boundary.

## The pre-registration log

**`docs/prereg.jsonl`.** An append-only hash-chained record. Before any paid experiment, we
commit to exactly what code will run (a sha256 manifest of specific files) and why (a
plain-English rationale). Each entry is numbered (1, 2, 3, ... currently 53). A reviewer can
re-walk this chain with `scripts/verify_chain.py` and confirm every entry hashes correctly
and the file hashes still match today.

**"Anchoring" a change.** Writing a new entry to the pre-registration log. The entry records
the file hashes as they are at that moment. After anchoring, the code at those hashes is what
the subsequent experiment is committed to. Anchoring is irreversible — rewriting an entry
breaks the hash chain.

**`docs/prereg/RATIONALES.md`.** A human-readable index of each pre-registration entry's
rationale. Lists what changed and why, with the entry numbers for cross-reference.

## The files that don't change

**Frozen measurement-path files.** Six files that enforce the gate rules and the integrity
log. Their sha256 hashes are the same in every pre-registration entry from 50 onward: the
gate, the integrity log, the ground-truth scoring, the version-spine check, the cold floor
auditor, and the static-coverage check that proves no action path skips the gate.

**ARTIFACTS manifest.** A list inside `scripts/preregister.py` of the files the
pre-registration log tracks. Currently ~40 files. A reviewer who wants to know which files
were committed to can read it directly.

## How evolution works in this project

**MAP-Elites.** An evolutionary algorithm. Instead of keeping only the best-scoring solution,
it keeps a grid of diverse solutions mapped by their behavior. Our grid has 54 cells. A new
solution replaces the existing one in its cell only if it scores higher. The idea: preserve
behavioral diversity, not just score.

**Behavior descriptor.** The function that maps a completed episode to a grid cell based on
red's actions. We've redesigned it twice. The current version keys on: the structural shape
of red's path through the network, the technique red used to get its initial foothold, how
late in the budget red reached the crown, and whether red used only bootstrap credentials or
chained through earned ones.

**Elite re-run.** In each generation after the first, we re-run the best-scoring genome from
the previous generation alongside the mutated children. This validates that the stored best
is still a winner on fresh runs. Without this, the "best score" number is a frozen record
that doesn't get tested.

**Adaptive novelty scaling.** A selection-pressure fix we landed Nov 5. When MAP-Elites has
collapsed to one cell (the archive shows exploration isn't working), the bonus for divergent
behavior gets dampened so red isn't steered off the one working recipe. When the archive has
multiple cells (exploration is working), the bonus is restored at full weight. This fixes
the "red wins, then mutation steers red off the winning recipe, then red fails" pattern we
saw in the Nov 5 morning run.

## Running the experiments

**Paid run.** An experiment that burns LLM tokens against a real Docker range. Gated on
explicit go. Each run produces a committed archive under `docs/runs/<date>-<name>/` with the
raw hash-chained logs and a `prove_*.py` script that re-derives the run's claims from the
chains cold.

**Dry run.** A run that uses a deterministic stub instead of an LLM. Free. Proves the loop
mechanics without paying for cognition.

**Shakeout run.** A paid run intended to prove the experimental machinery works end-to-end,
not to measure a claim. Produces instrument findings (e.g., "the measurement doesn't see
what we need it to") rather than claim results.

**The range.** The Docker-based target environment red attacks. Multiple variants exist:
`unified` (the default seam), `app_crown_4hop`, `backup_route_5hop`, `mgmt_crown_3hop`. Each
has the same authorization rules but structurally different seams.

**Variable isolation.** When testing a specific claim, we vary one knob at a time and hold
everything else constant from the previous run. Flipping multiple knobs simultaneously
produces results we can't attribute to any specific cause.

## The four claims

**Claim 1.** The shape of the authorization rules steers how red adapts. Vary the gate's
scope policy and watch whether red's evolved winning path varies with it. Falsifier: red's
path is identical across all rule shapes.

**Claim 2.** Harm reaches the crown through in-scope actions, not through actions the gate
would have blocked. Point-level version: measure the ratio of corroborated crown reaches to
episodes. Dynamic version: measure whether red climbs this rate across generations.
Falsifier: the gate is ever penetrated (`oos_executed > 0`).

**Claim 3.** A monitor erodes where an authorization enforcer doesn't. With blue actively
trying to catch red, blue's detection efficacy should fall across generations as red learns
the blind spot. Meanwhile the gate's out-of-scope count stays zero. The sharpest testable
asymmetry in the thesis.

**Claim 4.** Harm concentrates at the seams between multiple authorization enforcers.
Deferred: requires a multi-enforcer setup that doesn't exist yet.

## Internal shorthand found in commits and older design-log entries

**"SEQ50 Parts 1/2/3".** A set of three measurement-path changes committed Oct 30 under one
pre-registration entry. Part 1 swapped a broken held-out range variant for a working one.
Part 2 extended the ground-truth firewall to red's episodic memory channel. Part 3 replaced a
credential-handling fallback that was quietly making red succeed without actually earning the
credential it needed.

**"Fix 1" and "Fix 2" (Nov 5).** Fix 1 added live-population win-rate reporting to the run
summary (the archive-best score we were watching was frozen, not the metric that was
actually moving). Fix 2 added the elite re-run, the adaptive novelty scaling, and a
structural renaming of the path-classification labels — described above.

**"A-D1".** An independent recount of blue's detections directly from the raw chain, as a
cross-check against what the engine's own summary reports.

**"TCB" (trusted computing base).** The frozen measurement-path files. See "Frozen
measurement-path files" above.

**"Crit 1/2/3/4/5/6".** Numbered acceptance criteria from the Nov 2 claim-1 brief. Each
tested one aspect of a successful sweep run (floor held, path varied, descriptor exercised,
etc.). The Nov 5 claim-3 brief uses the same numbering style.
