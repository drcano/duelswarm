# duelswarm

A sandboxed cyber range for studying what happens when two adaptive LLM agents fight on top of a
non-adaptive rule enforcer. One agent plays attacker, one plays defender. Both run as co-evolving
populations with a real operator toolkit and the ability to write their own tools at runtime. Below
them sits the only fixed part of the system: a deterministic authorization layer that approves or
denies every single action against a fixed scope, and a hash-chained log that records every event.

The question the range exists to answer: does a fixed rule enforcer stay invariant to an adversary
that keeps getting better at attacking, while a monitor sitting at the same interface slowly erodes?
We think the answer is yes and no, respectively. We built the range to prove ourselves wrong.

## What is being tested

Four falsifiable claims, each stated with the specific result that would knock it down. The full
definitions, protocols, and acceptance criteria are in
[`docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md`](docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md).

- **Claim 1 — The shape of the rules steers how the attacker adapts.** Vary the rule enforcer's
  shape across a pre-registered set and watch what the attacker's winning path evolves into under
  each shape. *Falsifier*: the attacker's evolved path is the same no matter the rule shape.
- **Claim 2 — Harm reaches the goal through allowed actions, not disallowed ones.** With the rule
  enforcer fixed, a successful attack is assembled from a chain of allowed actions. Zero actions
  escape the enforcer on any seed. *Falsifier*: any seed records an out-of-scope action executing,
  OR a genuinely climbing attacker never assembles an in-policy winning chain.
- **Claim 3 — A monitor erodes where a rule enforcer does not.** The same attacker aimed at a
  monitor instead of the rule enforcer learns the monitor's blind spot across generations while
  never climbing the rule enforcer. *Falsifier*: the attacker climbs the rule enforcer the same way
  it climbs the monitor, OR it climbs neither.
- **Claim 4 — Harm concentrates at the seams between rule enforcers.** Deferred; scoped after claims
  1-3 produce data.

Each claim becomes a result only after a pre-registered run against a run plan recorded in the
hash chain, with the raw chain cold-re-derivable by someone who trusts neither the attacker, the
defender, nor the operator.

## How you can re-derive every claim at source

The repo is built to be checked at source. Three commands, no Docker and no API key:

```
git clone https://github.com/drcano/duelswarm.git
cd duelswarm && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
make verify
```

`make verify` runs the full set of cold auditors against the committed chains and against planted
adversarial scenarios: the hash chain re-walks, the floor auditor re-derives `oos_executed=0` from
the raw log, the IO-sidecar auditor binds every per-turn record of the attacker's cognition to the
main chain, the provider-pin auditor asserts no silent mid-run swap, the static-coverage check
asserts every effect site is mediated, the adversarial gate proof plants out-of-scope actions and
asserts the enforcer blocks them, the falsification battery runs the planted-attack-against-the-log
test, and the committed dry-generation proof re-derives from its archive. The last line,
`preregister --verify`, re-walks the pre-registration chain and asserts every registered artifact
still matches its anchored hash; the amendment history and its rationales are in
[`docs/prereg/RATIONALES.md`](docs/prereg/RATIONALES.md).

## How to reproduce a specific result

Every committed run writes a self-contained archive under `docs/runs/<date>-<name>/` with its hash
chains, a `prove_<name>.py` script that re-derives every claim the run makes, and a `README.md`
recording the cold-derivation output. From a fresh clone:

```
python3 docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
```

This re-derives, from the committed hash chains, that the boot witness fired correctly, that the
authorization floor held `oos_executed=0` on each of three chains, that an independent recount of
blue's detections matches what the engine wrote, that the co-evolution selection fired with the
expected archive and fitness, and that honest NULL semantics are preserved where the dry router
produces nothing to score. No Docker, no API key, no external data.

More runs land in `docs/runs/` as they happen.

## What is here

- `swarm/` — the measurement engine (one of each: red driver, blue driver, gate, event log, spine,
  co-evolution). The gate (`swarm/gate.py`) is the authorization enforcer; everything that touches
  state goes through it.
- `redteam/` — the cold auditors (`reverify_floor`, `kernel_witness`, `verify_io_sidecar`,
  `verify_provider_pin`): standard-library only, no imports from `swarm/`. These are what a reviewer
  trusting neither agent uses to re-derive each claim from the raw chains. (The one exception,
  `stats_tail.py`, is an offline statistics helper that uses scipy/powerlaw and is not on the
  floor-re-derivation path.)
- `scripts/` — orchestration, the live arms-race runner, mediation checks, validation harnesses,
  pre-registration tooling.
- `scripts/validation/` — the capability-ceiling scorer, the oracle attacker, the boot witness,
  and the auditor-parity check. These are used off the attacker's path (an oracle attacker never
  conditions the measured attacker; the scorer is only called post-hoc).
- `docs/design-log/` — the dated record of the build. The thesis, the experiment brief, the
  planner/verifier handoff, and every intermediate decision.
- `docs/prereg.jsonl` — the hash-chained pre-registration log. Every amendment is one entry;
  entries carry the artifact SHA256 manifest. [`docs/prereg/RATIONALES.md`](docs/prereg/RATIONALES.md)
  indexes each amendment's rationale.
- `docs/runs/` — committed reproducible archives for each cold-provable run.
- `docs/held-out/` — the ground-truth JSONs for the generality-test variants. These are what the
  attacker generalizes to; the attacker never sees them.
- `CLAUDE.md` — the critical invariants, the reading order, and the discipline the repo is built
  under.

## Discipline

The repo operates under a planner/verifier split: one role plans and writes the dated brief that
specifies what changes and why, another role writes the code, and a third cold-re-derives every
result from the raw hash chain, trusting neither the first two. A result is a result only when the
re-derivation produces it. The current state of the discipline is in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Responsible use

duelswarm is a sandboxed research range, not an operational tool. It stands up its own target hosts
as Docker containers on an internet-blocked bridge network and only ever acts against those
containers — there are no real external targets, and the host-egress firewall plus the authorization
gate exist to keep it that way. The attacker's exploits are public, already-patched vulnerabilities
from standard Metasploit modules and Vulhub images (for example the Apache Struts CVE-2017-5638 demo)
fired at deliberately vulnerable fixture containers; nothing here is a novel exploit or a
weaponization aid, and the repository carries no operational targeting or real-world attack content
(the lab SSH keys and passwords are throwaway fixtures generated for the range). Please keep it that
way: run it only against its own range. To report a security issue, see [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

## Citing

See [`CITATION.cff`](CITATION.cff).
