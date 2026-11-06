# Airtightness backlog — named, not executed (2026-11-02)

Three airtightness upgrades considered during the post-hackathon cleanup (§3.4 of
[2026-11-02-post-hackathon-cleanup-and-public-release.md](2026-11-02-post-hackathon-cleanup-and-public-release.md)).
Recorded here so the design-log shows they were weighed, not overlooked. **None is executed
in the cleanup pass** — these deepen the instrument and wait for their moment.

## 1. Replay verifier (deferred)
Read a committed chain, re-execute red's decisions against the committed tool results, and
assert the outcome is deterministic. Catches non-determinism that slipped past the current
audit stack (`reverify_floor` + the two code-independent auditors + `verify_io_sidecar`).
- **Falsifier value:** a chain that does not replay deterministically is either non-deterministic
  red or a mis-recorded result — both of which the current stack can miss.
- **Why deferred:** non-trivial — needs a deterministic re-router (red's RNG + the tool-result
  feed pinned). Build when a reviewer asks for replay-level determinism.

## 2. Seed-swap test (deferred)
For a pinned (red, blue, floor), re-run the same seed with shuffled host-enumeration order /
reversed service order and assert lethality within CI. A win on seed X but a loss on
X-with-permuted-hosts is a seam dependency, not a strategy.
- **Falsifier value:** separates a real strategy from an artifact of enumeration order — directly
  on-thesis (generalization, not seam-fitting).
- **Why deferred:** mission-aligned but post-Task-2; it measures the robustness of a result we
  have not yet produced at scale.

## 3. Null-adversary control (deferred)
Pin red to a known-random policy; the floor must still hold `oos_executed=0`. If it fails, there
is a stealthy issue the audit stack is not catching.
- **Falsifier value:** a cheap lower bound — the floor's guarantee must not depend on red being
  competent.
- **Why deferred:** cheap to run; add as a pre-registered experiment arm AFTER Task 2 lands, so
  it is registered rather than retro-fitted.

These are the roadmap's calls, not this cleanup's. The cleanup prepares the repo for a reviewer;
these three wait.
