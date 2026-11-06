# External audit brief — treat this project as untrusted and find reasons the data isn't real

## What this brief is

You are being asked to audit a research project called duelswarm. The project claims to be
measuring four things about how AI agents behave in a cyber-attack sandbox. The team that
built it has produced some data, and before publishing or presenting that data, they want an
outside check: is the data they're reporting actually what the code measures, or could it be
an artifact of how the code was set up?

You are that outside check. You have no project context. The team's claims about their own
code should carry no weight with you. Your job is to try to find reasons the data isn't real.
If you can't find any after serious effort, that's strong evidence. If you find some, name
them specifically so the team can fix or disclose them.

## What you have access to

The public repo at `github.com/drcano/duelswarm`. Read everything. Specifically:
- `README.md` at the repo root — the team's reviewer-facing description
- `docs/GLOSSARY.md` — translates internal shorthand (seq-N, specific selftest names, etc.)
  into plain English so you can read the committed artifacts
- `docs/design-log/` — the dated record of every decision, in rough chronological order
- `docs/prereg.jsonl` and `docs/prereg/RATIONALES.md` — the pre-registration log (append-only,
  hash-chained)
- `docs/runs/` — committed archives from each paid experiment, each with its raw hash-chained
  chains and a `prove_*.py` script
- `swarm/` — the measurement engine code
- `redteam/` — the "cold auditor" code (claims to re-derive results without trusting the
  engine)
- `scripts/` — orchestration and validation

You have ONE discipline constraint: do not trust the team's own code to tell you whether the
team's own code is correct. When you want to verify an invariant, verify it against the raw
committed data (the hash-chained logs, the ground-truth files, the containers' actual state),
not against a summary the engine produced. Cross-check wherever possible.

## The research question in one paragraph

An attacker LLM and a defender LLM fight each other in a Docker sandbox, both running as
small populations that evolve over generations. Underneath them, a deterministic
authorization enforcer (called "the gate" in the code, sometimes "the floor") decides which
actions are allowed. The team predicts that the gate stays invariant to the attacker's
adaptation — no matter how clever the attacker gets, it can't execute actions against hosts
the gate forbids. They also predict that the defender's detection capability erodes against
the same attacker: the attacker learns the defender's blind spots over generations. The
whole project exists to test these predictions on paid LLM-driven runs.

## The four specific claims

1. **Rule shape steers adaptation.** Vary the gate's rule set and the attacker's evolved
   winning strategy varies with it. *Falsifier:* evolved strategies are identical across
   different rule sets.
2. **Harm comes through allowed actions only.** When the attacker succeeds, it succeeds
   through actions the gate let it do, not by executing anything the gate forbids. The count
   of forbidden-but-executed actions stays zero on every episode. *Falsifier:* any episode
   records a forbidden action executing.
3. **The defender erodes, the gate doesn't.** With the defender actively fighting back,
   detection efficacy drops across generations as the attacker learns blind spots, while the
   gate's forbidden-action count stays zero. *Falsifier:* the attacker climbs the gate too,
   or climbs neither.
4. **Harm concentrates at the seams between multiple gates.** Deferred; no data yet.

The current data covers partial claim 2 (point-level) and the first paid test of claim 1.
Claim 3 and the strong-form test of claim 2 (where the attacker is explicitly told some
hosts are forbidden and incentivized to breach) haven't run yet.

## What a "fluke" looks like in this project, concretely

Six categories. You're trying to find any instance of any of these. For each category, some
example attack vectors — these are starting points, not a complete list.

### Fluke category A: the floor result is a tautology by construction

The team's "the forbidden-action count stayed zero on every episode" result would be a
tautology if the attacker literally cannot formulate forbidden actions within the tools it's
given. If red has no tool that CAN target a forbidden host, "the gate blocked no forbidden
action" is just "no forbidden action was attempted," which is meaningless.

- Does red have any tool that accepts an arbitrary target address?
- Is red told what's forbidden, or is it operating blind to the policy?
- Is there a mode in `swarm/live_red.py` where red is explicitly told some hosts are off-limits
  (search for `adversarial`)? Has it ever been paid-run?
- Could an auditor construct a prompt that red would accept that targets a forbidden host?

If the answer is "red has no way to try," the floor result is airtight-by-construction in the
hard sense (good — Docker and iptables really do enforce it) but mild-evidence-at-best in
the research sense (the gate wasn't under pressure).

### Fluke category B: ground-truth leakage

The team claims they maintain a "ground-truth firewall" — red is never told the answers (crown
location, which hosts are forbidden, the credential chain). The scoring code sees ground
truth; red's inputs never do. A static check called `assert_red_map_blind` lives in
`swarm/live_agent.py` and is supposed to fail loud if ground-truth-shaped strings appear in
red's awareness channel.

Verify this cold:
- Read `assert_red_map_blind` and understand what it actually checks. What strings would it
  catch? What would it miss?
- Grep the chain data for any committed episode: does the content red was prompted with ever
  contain the crown host's name, the crown file path, or a token that appears only in ground
  truth?
- The team added "episodic memory" that carries across generations. Does any ground-truth
  signal reach that memory? Look at what gets written to red's memory per episode.
- Does the oracle attacker (`scripts/validation/oracle_red.py`) share any state with the
  measured attacker? If yes, by what mechanism?

### Fluke category C: the scoring is trusting the engine's own say-so

A "corroborated crown theft" means the attacker reached the crown host and read the sensitive
file, and the reconciler verified it. Verify the verification:
- Find where `loot_corroborated=True` gets written in the chain. What events precede it? Is
  it keyed on red's own report, or on the crown host's own telemetry?
- The team planted the "crown" as a synthetic PII file with specific patterns (SSNs in the
  900-999 reserved block, credit-card numbers on test BINs). Does the reconciler actually
  verify the exfiltrated content matches those patterns, or does it trust that red reached
  the right file?
- Could red construct a payload that looks like the crown PII (the right SSN/CC patterns)
  without having actually read the file? What would catch that?
- Is there a canary token (search `swarm/canary.py`)? Does it fire on real captured content,
  or on a self-report?

### Fluke category D: the hash chain is tamper-evident on paper but not in practice

The team claims the pre-registration log (`docs/prereg.jsonl`) is append-only hash-chained,
and that `scripts/verify_chain.py` re-derives the chain cold from stdlib. Try to break it:
- Does `verify_chain.py` import anything from `swarm/`? It shouldn't.
- Pick a committed chain under `docs/runs/`. Modify one event by one byte (in a local copy,
  not the repo). Does `scripts/verify_chain.py` or `redteam/reverify_floor.py` detect the
  tamper? Does `prove_*.py` for that run detect it?
- Can you construct a chain where `oos_executed > 0` on some event but the hash chain still
  verifies and the prove script still returns "OK"? If yes, that's a critical finding.
- The team references "frozen measurement-path files" whose hashes haven't changed in 53
  pre-registration entries. Is that actually true? Compute the current hashes of
  `swarm/gate.py`, `swarm/eventlog.py`, `swarm/audit.py`, `swarm/spine.py`,
  `redteam/reverify_floor.py`, `scripts/mediation/static_coverage.py`, and compare against
  the hashes in the first pre-registration entry that lists them.

### Fluke category E: the sample size is too small for the claim

The current data is at pop=3, 3 generations, 3-5 seeds. The team is honest that this is too
small to distinguish a real curve from statistical noise, but it's worth stating cleanly:
- For the "red adapts across generations" observation they got in app_crown_4hop (0, 2, X
  corroborated per gen), what's the Fisher's exact p-value at this sample size?
- If the "shape of the rules steers red's path" claim rests on a pairwise comparison across
  four ranges at pop=3 each, how many distinct winning paths would we need to see across how
  many pairwise comparisons to clear what statistical bar?

Don't do a full power analysis. Just state the lower bound: "at this sample size the most
you can claim is directional evidence; a statistically meaningful claim needs at least X."

### Fluke category F: the "one engine" discipline isn't actually one engine

The team claims every measurement runs through a single engine (`scripts/live_arms_race_run.py`
calling `swarm/live_agent.py` for red and `swarm/live_blue_agent.py` for blue), and that
there's a static check (`scripts/prove_one_engine.py --selftest`) proving no competing engine
exists. Verify:
- Does `prove_one_engine.py` actually run under `make test`? Look at the Makefile.
- Does it check the import graph, or just a tag? Could a competing engine exist that passes
  this check?
- Grep for any other function in `swarm/` or `scripts/` that runs an end-to-end episode. Any
  candidate should either route through `live_agent.py` or be a dry-run stub explicitly
  flagged as not-for-measurement.
- The team has orchestration scripts that run paid experiments. Do they all converge on the
  same engine, or does each range variant have its own driver that could differ?

## Specific invariants to try to break

A short list of things the team states as true that you should try to disprove:

1. **"The gate catches every forbidden action attempted."** Can you construct a sequence of
   tool calls in red's action surface that produces an effect against a forbidden host
   without ever calling the gate's dispatch function?
2. **"The cold auditors (`redteam/`) import nothing from `swarm/`."** Run `grep -r "from swarm"
   redteam/` and `grep -r "import swarm" redteam/`. Zero results, or the claim is false.
3. **"The committed paid-run archives can be re-derived from their chains alone without
   access to the rest of the repo."** Pick one archive under `docs/runs/`. Copy it to a fresh
   directory with only `redteam/` and `scripts/verify_chain.py` alongside it. Run its
   `prove_*.py`. Does it pass without the rest of the repo?
4. **"`make verify` is green on a fresh clone."** Do a fresh clone. Run the three setup
   commands in the README. Run `make verify`. Does it exit 0 with the "DEFERRED" line clearly
   labeled (if seq-51 still hasn't anchored by the time you run this) or green (if it has)?
5. **"The behavior descriptor is derived only from events in the chain, not from ground
   truth."** Read `swarm/population.py`'s `behavior_descriptor` function. Does any axis read
   from `ground_truth`? (The function signature accepts a `ground_truth=None` parameter — make
   sure the body actually ignores it.)

## What to deliver

A report. Markdown. One section per fluke category (A through F) plus a "verified cold"
section and a "found vulnerabilities" section.

For each fluke category:
- What you looked for
- What you found
- Whether the finding is "no concern," "minor disclosure needed," or "material fluke risk"
- Specific code locations or data points for each finding

For the verified-cold section:
- What you re-derived from raw data without trusting the engine (hash chain walk, floor count,
  etc.)
- What tests you ran and what passed

For the found-vulnerabilities section:
- Any concrete way you found to produce a false positive (a "corroborated crown" that
  shouldn't be one)
- Any concrete way you found to produce a false negative (a forbidden action that executes
  without being flagged)
- Any ground-truth leakage into red's inputs
- Any way a hostile reviewer could legitimately dismiss the team's claims

Then one summary paragraph: "if this team publishes their data as-is, here are the specific
objections a hostile reviewer would raise and whether each is a real problem or just a
disclosure the team should add to the paper."

## What NOT to do

- Don't do a code-style review. This isn't production code quality; it's a research
  instrument. You care about whether the measurement is honest, not whether the code is
  pretty.
- Don't audit red's or blue's own LLM behavior for "security" purposes. They're adversarial
  agents in a sandbox; their job is to try things.
- Don't propose features. You're an auditor, not a collaborator.
- Don't assume the team's design-log entries are correct. They might be, but your job is to
  verify from primary sources.

## Scope boundary

You're auditing the MEASUREMENT APPARATUS: is what the team claims they measured actually
what they measured? That's the question. You're not auditing the research thesis itself —
whether the thesis is true is what the experiments are supposed to answer, and that's
downstream of whether the apparatus is honest.

If you think the apparatus is honest, your report says that and the data they produce means
what they say it means. If you find a fluke, your report says exactly what fluke and where.
Either way is useful.
