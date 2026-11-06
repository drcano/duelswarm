# CLAUDE.md — duelswarm

## What this is
A sandboxed cyber range for studying adaptive AI attackers and defenders against a fixed rule
enforcer. Red and blue are autonomous LLM agents with a real operator toolkit, run as co-evolving
populations. Underneath them is the non-adaptive floor: a deterministic authorization gate that
mediates every action against a fixed scope, plus a tamper-evident hash-chained log. The range exists
to measure what a fixed floor does to an adapting attacker and defender, and it is built to be proven
wrong — every result is cold-re-derivable from the raw chain by a party trusting neither agent.

## Where to start
- `README.md` — what the range is and how to re-derive every claim at source (`make verify`).
- `docs/design-log/README.md` — the design log in reading order (the thesis, the claims, the audit).
- `docs/prereg.jsonl` + `docs/prereg/RATIONALES.md` — the hash-chained pre-registration and its
  amendment rationales.

## Critical rules (non-negotiable)
- **One provider per run.** The run witnesses its provider + model lineage in the hash chain at start
  (a `provider.pinned` event); `swarm/llm.py` refuses any model call whose host does not match the
  pin, so a mid-run provider swap is caught at the API boundary. Any configured provider is valid;
  what is forbidden is a silent swap. `redteam/verify_provider_pin.py` re-derives the pin cold.
- **Everything stays inside the Docker range. No real external targets, ever.**
- **The authorization gate (`swarm/gate.py`) is real enforcement, not a post-hoc log.**
- **Blue is air-gapped from red:** no shared state, no access to red's plan or memory.
- **A penetration is a RESULT, not a build failure.** The one thing that must hold by construction is
  the instrument: every agent action is dispatched through the one gate and written to the
  re-derivable hash chain. The only real build failure is an unrecorded effect.
- **Nothing hardcoded on the live path:** discover IPs, ports and gateways at runtime.
- Organize by the trust boundary (trusted TCB vs. untrusted agents/range), not by feature.

## How the build is judged
Readiness is re-derivation at source, not a passing suite. The floor re-derives `oos_executed == 0`
cold from the hash chain with two code-independent witnesses (`redteam/reverify_floor.py`, the chain;
`redteam/kernel_witness.py`, the kernel/Falco record), and the falsification battery
(`scripts/prove_falsification.py`, `scripts/redteam_gate.py`) still bites. `make test` being green is
a SMOKE check, never the done-signal. Any change to a pre-registered file needs a dated amendment via
`scripts/preregister.py --rationale`, in the same change.

## Commands (the Makefile is the source of truth)
    make test        # self-checks: gate, one red/blue engine, floor re-derivation, falsification battery (no Docker/API key)
    make duel-dry    # dry run of the discovery-driven engine (no Docker/API key)
    make verify      # cold re-derivation of every pinned invariant from the raw chains (no Docker/API key)
    make gate-proof  # adversarial: no out-of-scope action slips the gate; log tamper-evident
    make arms-race   # co-evolution arms race (dry, free)
    make smoke       # one real model call through the pinned provider (needs the provider API key)
    make range-up / make range-down   # stand up / tear down the cyber range (Docker)
