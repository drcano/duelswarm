# 2026-10-24 — Operator doctrine: toolkit-first, author-when-stuck (red AND blue)

Design decision + the evidence that drove it. Captured per the standing rule (don't lose a
direction discussion to context limits).

## Decision
Red and blue model a realistic operator doctrine: **exhaust the applicable capabilities
already in your toolkit before authoring a new tool.** Custom tool authoring is reserved for
when the toolkit does not cover the situation. Symmetric for both sides. This is a property of
the AGENT's tradecraft, not of the floor.

Rationale: duelswarm is a realistic snapshot of AI-vs-AI warfare. A real operator does not
write a custom 0-day when Metasploit already has a working module; it reaches for its known
toolkit first and innovates only when stuck. Building red/blue that way is modeling reality.

## "No hardcoding" — the correct definition (Dante)
No hardcoding means: do NOT hand the agent credentials, a target IP, a scope list, the crown
identity, or a script that reaches the PII. It does NOT mean "impose no methodology." A
toolkit-first doctrine is operator methodology, not an injected solution — the agent still
discovers hosts, chooses targets, order, and weapons itself; only the known-vs-author choice
is doctrine-ordered.

(Planner note: I initially over-applied "nothing hardcoded on the live path" to mean no
control-flow policy at all, and proposed gating authoring. Dante corrected this. The ordering
is realism; the prohibition is on injecting the answer.)

## Evidence (verified at source, seed 0, `615826a`)
- Floor holds cold on BOTH chains (greedy + LLM autonomy): `reverify_floor` →
  `chain_verified=True, oos_executed=0`, one honest `gate.block` (red probed out-of-scope
  `10.11.0.15`; floor denied + recorded). Core result intact.
- The LLM run's 8 `author_tool` turns produced **zero** `tool.author` records. Cause was not
  "red prefers authoring over MSF":
  1. Authoring was never wired into the driver's `agent_tools`
     (`arms_race_enterprise_frontier.py:833–842`) — every authoring choice was "unknown tool".
  2. `harvest` is a stub on a credential-free, exploit-per-hop range (`:839`, `:556`) — red
     hunted creds that don't exist here.
  Red used the arsenal correctly at entry (CVE-2021-41773, `httpd`).
- Therefore the pre-fix null is **confounded** (authoring absent + harvest stubbed) and is
  annotated as such; it cannot support a claim about LLM tool-allocation behavior.

## Why this is thesis-neutral
- The floor still decides what is allowed/blocked; known exploits and authored tools go
  through the same gate under the same scope. The ordering changes neither.
- The allowed-action chain is not injected — red still hits `gate.block`s and re-routes on its
  own; migration stays emergent.
- Touches none of the three realized claims. If anything it improves signal: an authoring
  event now marks "the floor pushed the operator past the edge of its known toolkit."

## Honesty constraints (carried into the CC brief's done-checks)
- "Exhausted the toolkit" is range-blind: author unlocks for a frontier only once every
  service the agent fingerprinted itself that has a matching arsenal/MSF weapon has been tried
  and failed to advance. Computed only from the agent's own observations + its own arsenal —
  no crown/scope/IP/PII in the logic. (Extend the existing `live_vector` leak test.)
- Doctrine lives in the agent layer (`live_agent.py` / `authoring.py`), NOT in `gate.py`. The
  floor stays generic (scope + complete mediation + hash chain).
- Logs for everything: a `doctrine` beat on every defer and unlock, so a log reader
  re-derives that the agent followed toolkit-first.
- Emergent + measured: re-run and report the outcome whatever it is (crown reached or not,
  toolkit-first emerged or not). The pre-fix null stays on the record. Do not tune to green.
- Documented in the prereg as an explicit modeling choice.

## Build constraints
- **No new modules** — edits to existing files only
  (`arms_race_enterprise_frontier.py`, `live_agent.py`, `authoring.py`, `live_blue_agent.py`,
  prereg). Reuse `live_vector`/`arsenal`/`msf` matching. `git status` must show zero new
  `swarm/*.py` / `scripts/*.py`.
- Also fixed as prerequisites: wire authoring into the driver for both sides (the mandated
  "author tools at runtime" capability must actually exist); the credential-free range reality
  is surfaced to the agent via awareness, not by leaking range structure.

## Out of scope
- Package reorg — HELD (architecture doc instead). Falco / loot 4/4 — open (needs a
  crown-reaching run AND Falco actually capturing syscalls on the host).

Implementation detail: see the CC brief `CC-brief-operator-doctrine.md`.
