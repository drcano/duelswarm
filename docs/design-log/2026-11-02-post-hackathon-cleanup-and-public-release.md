# Post-hackathon cleanup, airtightness pass, and public release — authoritative brief (2026-11-02)

Hackathon is done. No submission constraints. This brief executes the cleanup, tightens the engine
where we have evidence it's loose, and prepares the repo for a public release under
`github.com/drcano/duelswarm` (restored as of Oct 30). Four sections, executed in order; I cold-verify
after each before the next starts. Nothing in this brief changes a measurement input to red or blue —
every improvement is either dead-code excision, invariant rewording, or a cold-auditor sharpening.

Planner/verifier wrote the spec; CC executes sections 1-3; Dante executes section 4 (the push itself,
plus pre-push decisions only he can make). Nothing committed off `real-range` without his go. Nothing
pushed except by him.

Commit author discipline (binding, every commit in this brief): `git config user.email drcano@ucsd.edu`
first; `[redacted]@...` is the default on-machine, and a public repo should carry one authorship,
not two. Verify once per section with `git log -1 --format='%ae %an'`.

---

## SECTION 1 — Hackathon-residue ripout

Safe to execute first. No measurement path touched. One commit per numbered item; I cold-verify after.

### 1.1 Delete Tavily entirely

Not on the measurement path. `swarm/intel.py::lookup_cve` is called in exactly one place at build time:
`swarm/topo_to_compose.py:1919` (lazy import, decorates the compose output with NVD/KEV URLs). Run-time
red does its own CVE inference through the LLM planner. The whole subsystem exists to make the hackathon
demo cite real advisory pages.

**Delete:**
- `swarm/intel.py` (the module)
- `docs/TAVILY_COST_CONTROL.md` (the cost-control brief that partly landed in intel.py)
- `data/intel_cache/` if it exists (disk cache)

**Edit:**
- `requirements.txt`: remove the `tavily-python>=0.5.0` line and its block comment
- `.env.example`: remove the `TAVILY_API_KEY` block
- `swarm/topo_to_compose.py`: remove the lazy `from swarm.intel import lookup_cve, _content_hash` at
  line 1919 and whatever helper(s) call into it. The static-URL stand-in (the "canonical NVD + CISA KEV
  URLs synthesized from the CVE id") stays — it's cosmetic range decoration, not a measurement input.
  Prove this cold: `make duel-dry` still produces identical compose output after the cut.

**Cold-verify:** `grep -r -i tavily $(find . -type f ! -path './.venv/*' ! -path './attic/*')` returns
zero matches. `make test` + `make duel-dry` both green.

### 1.2 Rip hackathon branding

- `.env.example`: delete the `Credits: NEBIUS-DEVPOST-GLOBAL26` comment on the NEBIUS_API_KEY line.
  Rewrite the Anthropic block from "FRONTIER BENCHMARK ONLY, never the submission" to a neutral
  "optional provider (used when `make_router(provider='anthropic')`)". The actual rewrite lands in §2.
- `requirements.txt`: strip every "NOT needed for the Nebius submission" / "NOT submission-valid" /
  "the hackathon's hard rule" annotation. Keep the Pydantic/MHBench note (external schema anchor; see §1.4).
- CLAUDE.md: the "automatic hackathon disqualifier" line gets rewritten in §2.

### 1.3 Clutter cleanup

- The 8 top-level `CC-brief-*.md` files are hackathon-era handoff notes. They belong under
  `docs/design-log/` dated to their mtime. The map:
  - `CC-brief-objective-and-defender.md` → `docs/design-log/2026-10-23-cc-brief-objective-and-defender.md`
  - `CC-brief-one-engine-interleaved.md` → `docs/design-log/2026-10-25-cc-brief-one-engine-interleaved.md`
  - `CC-brief-observe-only-control.md` → `docs/design-log/2026-10-25-cc-brief-observe-only-control.md`
  - `CC-brief-pin-red-and-measure-success-rate.md` → `docs/design-log/2026-10-25-cc-brief-pin-red-and-measure-success-rate.md`
  - `CC-brief-active-blue-canonical.md` → `docs/design-log/2026-10-26-cc-brief-active-blue-canonical.md`
  - `CC-brief-stealth-detection.md` → `docs/design-log/2026-10-26-cc-brief-stealth-detection.md`
  - `CC-brief-hygiene-then-stealth-part5.md` → `docs/design-log/2026-10-26-cc-brief-hygiene-then-stealth-part5.md`
  - `CC-brief-one-engine-then-stealth-runs.md` → `docs/design-log/2026-10-26-cc-brief-one-engine-then-stealth-runs.md`

  CC should map each file's actual mtime to its date before moving; the dates above are from the mtime
  stamps in the staging run but CC should re-check.

- Delete `sessionresume_RFDzvuuv` (0-byte scratch; already matched by `.gitignore`'s `sessionresume_*`).

- `Dockerfile.eval` (172 bytes): read it, then decide. If it's hackathon-eval scaffolding (likely),
  delete it. If it's load-bearing for anything in `make test` or CI, keep it and add a one-line comment
  stating its purpose.

### 1.4 MHBench disposition

Keep `swarm/mhbench_schema.py` (pydantic v2 schema that validates the topology IR against Brian Singer
2025 — gives the IR an outside anchor and is already wired into `make test`). Move
`docs/mhbench_openstack_setup.md` to `attic/mhbench_openstack_setup.md` with a one-line note at the top:
"Archived 2026-11-02: OpenStack setup from the Phase-0 scoping; superseded by the Docker range."
Verify `third_party/mhbench/` is still a vendored MIT reference and untouched.

### 1.5 Six orphaned enterprise helpers in `swarm/live_red.py`

My CUT decision from last session (never executed). Zero callers after MEDIUM-3 removed
`run_live`. CC verifies with `grep -r "derive_enterprise_chain\|provision_loot\|wait_for_web_ready\|
GreedyVectorPlanner\|GreedyEnterpriseRouter\|_load_py" swarm/ scripts/ tests/` returning only the
`live_red.py` definitions themselves (no other callers), then deletes them. If any import turns up,
STOP and surface it — do not silently rewire; name the caller and the dependency so I can decide.

### 1.6 Section-1 commit discipline

Each numbered item above is one commit. `swarm/live_red.py` is not in the seq-50 frozen-TCB manifest,
but `swarm/eventlog.py`/`swarm/gate.py`/`swarm/audit.py`/`swarm/spine.py`/`redteam/reverify_floor.py`/
`scripts/mediation/static_coverage.py` are. If any touched file's sha256 changes land outside
`swarm/live_red.py`, `swarm/intel.py`, or `swarm/topo_to_compose.py`, STOP and show me the diff first.

After section 1, I cold-verify: zero Tavily refs anywhere; `make test` green; the 6 helpers gone; the 8
briefs rehomed; the 0-byte scratch deleted; frozen TCB hashes still match seq-50.

---

## SECTION 2 — Provider policy rewrite

The Nebius-only enforcement is the single biggest hackathon shackle. The host-guard **mechanism** is
good (it stops silent provider swaps mid-run — which is what a verifier wants). What's residue is the
**policy**: "Nebius or you're disqualified." Rewrite the policy; keep the mechanism; add a chain
witness so the pin is auditable from the hash chain alone.

### 2.1 The new invariant

Replace, in `CLAUDE.md` (critical rules section):

> All model calls go through Nebius Token Factory — swarm/llm.py enforces it.
> HuggingFace/OpenRouter is an automatic disqualifier.

With:

> One provider per run. The run witnesses its provider + model lineage in the hash chain at start
> (`provider.pinned` system event), and `swarm/llm.py` refuses any model call whose host does not match
> that pin — a mid-run provider swap is caught at the API boundary and raised. Any configured provider
> (Nebius Token Factory, Anthropic, OpenAI, a local server) is valid; what is forbidden is a silent
> swap. The verifier re-derives the pin from the chain and asserts every `*.tier` call matches.

### 2.2 Code changes

- `swarm/llm.py`:
  - Rename `_assert_nebius_host` → `_assert_pinned_host`. Takes `(base_url, pinned_host_regex)` instead
    of hardcoding Nebius. Default `pinned_host_regex` reads from the `provider.pinned` event the Router
    writes at construction time; environment override via `PINNED_HOST_REGEX` for ad-hoc tests.
  - Error message loses "disqualifier" language; gains "mid-run provider swap at base_url {url} vs
    pinned host regex {rx}".
  - Rename `witness_provider` and update its output keys (`nebius_host_guard_active` →
    `pinned_host_guard_active`, `is_nebius_host` → `pinned_host_match`).
  - `make_router(provider=...)` default stays `nebius` (backward-compat for existing scripts). The two
    first-class alternatives are `anthropic` (via `swarm/provider_anthropic.py` which exists) and `local`
    (via `swarm/provider_local.py` — write a thin wrapper around a local OpenAI-compatible server if
    not already present; TBD whether to include this in section 2 or defer).
  - At Router construction, emit a `provider.pinned` system event to the shared log if one is attached:
    `{provider, base_url, pinned_host_regex, model_lineage}`. The verifier reads this and asserts
    every subsequent `delegation` and `*.tier` event used the same provider.

- `.env.example`: rewrite the Anthropic block to a neutral "optional alternative provider." Add a
  stub `ANTHROPIC_BASE_URL` note if different from the default. Keep `NEBIUS_API_KEY` as the primary.

### 2.3 Pre-registration

`swarm/llm.py` is not in the frozen-TCB manifest, but the invariant it enforces IS load-bearing. Land
a dated prereg amendment (seq-51 if this comes before the paid gen; seq-52 otherwise) with:
- The seven-file artifact_hashes manifest refreshed
- A new `rationale` field (see §3.1) stating: "swarm/llm.py: Nebius-only → pin-one-provider; mechanism
  preserved, policy generalized; verifier now cross-checks `provider.pinned` against every `*.tier`."

### 2.4 Cold-verify (I run)

- Host guard still raises on a silent swap: construct a Router pinned to Nebius, then call it with
  `base_url` manually overridden to an Anthropic host. Must raise. Must raise. Must raise.
- `make test` green including `prove_one_engine --selftest`.
- A run with each of the three providers (dry mode, zero tokens) produces a chain with exactly one
  `provider.pinned` event matching every `*.tier` call. The verifier (new, under `redteam/`) walks the
  chain, extracts the pin, and asserts the match. Add this to `make verify` (§3.3).
- The deprecated `_assert_nebius_host` name is gone (no shim); any import of it fails loud. CC should
  grep `_assert_nebius_host` across the whole tree to confirm it's not referenced anywhere else.

### 2.5 What stays Nebius

For now, the paid gen Dante authorizes keeps running on Nebius Nemotron — that's the baseline the four
claims will be measured against first. The Anthropic/local lanes become **first-class but
pre-registered**: a run on them is a new experiment arm, logged in the chain with its `provider.pinned`,
and reported as such, never silently mixed with Nebius results. Multi-provider becomes a claim-invariance
witness (§3 Section D).

---

## SECTION 3 — Airtightness quick wins

Small, structural, no measurement bias risk. Every item below is a defect we can name from the cold
audits already done.

### 3.1 Prereg amendment schema: add a `rationale` field

Last session I flagged seq-47 as having only the generic `"artifacts changed after anchoring"` note,
with the real rationale living in docstrings one hop away. Fix at the writer:

- `scripts/preregister.py`: add an optional `--rationale <text>` CLI flag; the emitted amendment
  carries `data.rationale = <text>` when passed, absent otherwise. Existing amendments stay valid
  (field is optional).
- Backfill: for seq-48 through seq-50, do NOT retroactively rewrite the committed amendments (the
  chain holds; rewriting breaks the hash). Instead, write a one-line `docs/prereg/RATIONALES.md`
  mapping each existing seq to its rationale, so a reviewer tracing an amendment can find it.
- Going forward, every amendment carries a rationale.

### 3.2 Boot witness: name the attributed-vs-total gap in-payload

Confirmed cold: the 2026-10-30 dry-gen boot witness reported `attributed=7, unattributed=0, total=9` —
meaning 2 events sat in a third state the witness didn't name. The witness correctly passes (unattributed
is what fails it), but a reviewer tracing the witness alone will ask "what are the 2?". Fix:

- `swarm/live_telemetry.py` (or wherever the witness is written): extend the payload with
  `syscall_events_other` (= total − attributed − unattributed) and a one-line `other_basis` string
  naming what those are (likely the benign-login warmup events that don't go through host-attribution).
- Update `prove_dry_gen.py` to assert the new field exists and is accounted for.

### 3.3 `make verify` target: one-command cold re-derivation

The CLAUDE.md invariant is "readiness = re-derivation at source." Make that one command, so a reviewer
coming cold from GitHub can run it and see green/red per invariant. Add to `Makefile`:

```
verify:   ## cold re-derivation of every pinned invariant from the raw chains (no Docker, no API key)
	$(PYTHON) scripts/verify_chain.py data/wall/range_0.jsonl
	$(PYTHON) redteam/reverify_floor.py data/wall/range_0.jsonl
	$(PYTHON) redteam/verify_io_sidecar.py --selftest
	$(PYTHON) scripts/mediation/static_coverage.py
	$(PYTHON) scripts/redteam_gate.py
	$(PYTHON) scripts/prove_falsification.py --selftest
	$(PYTHON) docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
	$(PYTHON) scripts/preregister.py --verify
```

Each line prints its own OK/FAIL. If any line exits non-zero, the whole target fails. This is the
reviewer's "does this repo's claims hold at source?" button.

### 3.4 Named-but-deferred airtightness upgrades (backlog, not primary)

Three improvements worth naming in the design-log for later, not executed here:

- **Replay verifier.** Read a committed chain, re-execute red's decisions against the committed tool
  results, assert deterministic. Catches non-determinism that snuck past the current audit stack.
  Non-trivial to build (needs a deterministic re-router); defer until a reviewer asks for it.
- **Seed-swap test.** For a pinned (red, blue, floor) combo, re-run the same seed with shuffled host
  enumeration order / reversed service order, assert lethality within CI. A win on seed X but a loss on
  X-with-permuted-hosts is a seam dependency, not a strategy. Mission-aligned; defer to post-Task 2.
- **Null-adversary control.** Pin red to a known-random policy; the floor should still hold `oos=0`.
  If this fails, we've got a stealthy issue the audit stack isn't catching. Cheap to run; add as a
  pre-registered experiment arm after Task 2 lands.

These three are listed here so the record shows we considered them. Not for this brief.

---

## SECTION 4 — Public-release readiness (Dante executes)

The push itself is Dante's; so is every pre-push decision. CC does not push. I produce the readiness
report; Dante decides and executes.

### 4.1 Pre-push audit (run before any public push)

- **Secrets scan.** `git log -p --all | grep -E 'TAVILY_API_KEY|NEBIUS_API_KEY|ANTHROPIC_API_KEY|
  sk-ant-|sk-[a-zA-Z0-9]{20,}|msfrpc'` must return zero matches. If any real key ever leaked into
  history, rotate first and rewrite that commit before publishing. The `.env` file is already in
  `.gitignore` but historic commits could carry one.
- **Commit-author audit.** `git log --format='%ae' | sort -u` lists every author email in history.
  Expect two: `drcano@ucsd.edu` and `[email redacted]` ([redacted]). Decision point:
  - (a) Accept the dual-author history as-is (fastest; some commits attributed to [redacted]).
  - (b) Rewrite the public branch with a single author (`git filter-branch` or `git-filter-repo`;
    one-time cost, cleaner public history). I recommend (b) for a flagship repo under drcano.
- **File hygiene.** Confirm `.gitignore` covers: `.env`, `.venv/`, `data/`, `__pycache__/`, `.DS_Store`,
  `*.log`, `docs/build-bundle/**/generated-compose-*.yml`, `third_party/incalmo/`, `sessionresume_*`.
  Already in place; one grep to confirm.
- **LICENSE** is already in place (1079 bytes). Confirm it's MIT or Apache-2.0; the Fellows app evaluates
  attribution clarity.

### 4.2 README.md (top-level, for strangers)

The top-level README should be a reviewer's on-ramp, not an insider's status board. Target structure
(write this; current top-level README is stale per CLAUDE.md's "Source of truth" section):

```
# duelswarm

What it is (3-5 lines, prose, no jargon).

## The claims
A short bullet list of the four falsifiable claims (claim 1-4), each with its falsifier in one line.

## Run it
make test        # cold self-checks (no Docker, no API key)
make duel-dry    # dry run of the one measurement engine
make verify      # cold re-derivation of every pinned invariant (see §3.3)

## The reproducible archives
Point to docs/runs/*/README.md and prove_*.py for each committed cold-proof run.

## The authoritative experiment brief
Link to docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md.

## Research grounding
Link to docs/DUELSWARM_RESEARCH_GROUNDING.md (if still current) or the brief above.

## License
MIT.
```

Keep it under 200 lines. The design-log and prereg.jsonl are the deep record; the README is the door.

### 4.3 CLAUDE.md: update "Source of truth"

The current source-of-truth list in CLAUDE.md points to 2026-10-23 docs. Add the two newer
authoritative docs:
- `docs/design-log/2026-10-29-falsifiable-claims-experiment-brief.md` (current experiment spine)
- `docs/design-log/2026-10-29-planner-verifier-handoff.md` (planner/verifier onboarding)
- `docs/design-log/2026-11-02-post-hackathon-cleanup-and-public-release.md` (this brief)

Mark older items as superseded with the date, don't delete.

### 4.4 The push

Dante's call. My recommendation: push to `github.com/drcano/duelswarm` as a new public repo (not a
rename of a private one, so the history is clean), on the `main` branch, after sections 1-3 land and
`make verify` is green. Add a GitHub Actions CI that runs `make test` + `make verify` on every push —
reviewers see the badge and know the invariants hold at the current commit.

---

## Sequencing + verification gates

1. **Section 1 (ripout).** CC executes items 1.1 → 1.6 as separate commits. I cold-verify after 1.6:
   zero Tavily refs, `make test` + `make duel-dry` green, 6 helpers gone, 8 briefs rehomed, TCB hashes
   unchanged.
2. **Section 2 (provider rewrite).** CC executes. I cold-verify: host guard still raises on silent
   swap; three-provider dry runs each produce one `provider.pinned` event matching every `*.tier`;
   `make test` green; no reference to `_assert_nebius_host` anywhere.
3. **Section 3 (airtightness).** CC executes. I cold-verify: `make verify` runs clean and green on
   every line; the boot witness now reports the attributed-vs-total gap in-payload; the prereg writer
   accepts `--rationale`.
4. **Section 4 (public release).** Dante executes the pre-push audit, decides on commit-author
   rewriting, writes the README, pushes. I verify from a cloned-fresh public read: `make verify` green
   on a clean checkout with no state.

Each section's commits land on `real-range`. Nothing pushed except as part of section 4.

## The posture, one line

The engine was built to meet a deadline; it is now being prepared to meet a reviewer. Everything that
served the deadline and does not serve the research gets cut. Everything the research needs that the
deadline did not give it gets added. Then the door opens.
