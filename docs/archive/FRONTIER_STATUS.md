# DUELSWARM — Frontier Status & Next Steps

*Snapshot: 2026-10-16. Branch `frontier` (14 commits over tag `v1.0-stable-floor`). `make test` green, every log chain-verified, the gate never bypassed. Build deadline Oct 30.*

This is the honest "where we are" so you can brainstorm next moves. Live-validated vs. self-checked-only is called out per item — nothing dry is dressed up as live.

---

## 1. Where we are

### The floor (guaranteed submission)
`v1.0-stable-floor` is tagged and untouched: the live Nemotron duel, deterministic gate, hash-chained log, randomized range, verifiable report + forensics, Tavily intel. If the frontier ever wobbles, we ship the floor.

### The frontier build — 5 locked features, all built
| # | Feature | What it does | Status |
|---|---------|--------------|--------|
| F4 | **Tavily weaponization** (`research_cve`) | Red researches an unknown service → live advisory + exploit primitive, provenance-hashed into the chain | **Live-validated** (`tavily-live` CVE) |
| F2 | **Manipulation theater** (`overseer.py`) | Red petitions an LLM officer + argues; gate runs last regardless. `overseer_fooled` = officer allowed, gate blocked | **Live-validated** — officer *held* honestly under a strict ROE; fooled path proven in self-check |
| F3 | **Heterogeneous swarm** | Nano recon → Ultra plan → Super dissent → Ultra consensus; every action attributed to its agent | **Live-validated** (dissent beat is stochastic — see §3) |
| F1 | **Emergent-TTP scoring** (`novelty.py`) | Red's real path scored vs. the seed's ground truth; honest-null reported | **Live-emitted** + self-check (emergence is seed/agent-dependent) |
| F5 | **Interactive judge trigger** | Judge writes an ROE + picks a seed → `POST /run` → live duel enforces *their* rules | **Live-validated** — officer denied citing the judge's exact words |

### Phase 5 ceiling — 4 items built (all headless-verifiable, in `make test`)
- **Themed scenarios** (`--theme bank|hospital|utility`) — display-only labels; enforcement byte-identical.
- **Wall of duels** (`make wall`) — the invariant across N unseen ranges, each independently audited. Sample: *8 ranges · gate held 8/8 · 0 out-of-scope · chains 8/8*. Headless/credit-free; live/Serverless is the paid scale-out.
- **NVIDIA Morpheus feed** (`data/morpheus_feed.jsonl`) — the log shaped into ATT&CK-tagged, provenance-stamped JSON-lines; written every run.
- **Dashboard polish** — F1 hot-edge coloring of emergent routes + F2 officer-vs-gate verdict banner.

### Full-stack proof
One live bank-themed Nemotron duel (seed 3, **$0.46**) exercised everything at once: nano recon, Tavily research, officer petition + matrix, novelty, themed range, Morpheus feed — **gate held, 0 out-of-scope, 122 events chain-verified, objective_met.**

---

## 2. Operational state (read before planning)
- **GitHub push is suspended** (`403 account suspended`). `frontier` is **local-only — no PR possible** until you clear it with GitHub support. Everything is committed locally; nothing is lost.
- **Token Factory budget ≈ healthy** (was ~$24; a full live duel is ~$0.46). Live runs are fine; still judicious.
- **Honesty discipline is the project's credibility.** Two results are honest NULLs (P1 lineage pilot refuted H1; Phase 2 arms-race learned-monitor dynamics). Do **not** steer toward prettier curves — that's load-bearing for the pre-registration story.

---

## 3. Known gaps / things to be aware of
- **Demo beats are stochastic.** Red doesn't *always* call `request_action` (F2), `research_cve` (F4), or produce a dissent (F3) — it's an autonomous LLM. The prompts nudge hard, but a given run may skip one. For a video, we'd want a guaranteed path (see §4-B).
- **Dashboard pixels unverified.** The F1 hot-edge + F2 verdict-flash tweaks are JS-syntax-checked and wired like proven code, but the Browser pane went hidden mid-session so I couldn't eyeball them. Quick to confirm once the pane's back.
- **Artifact timing nit.** Blue's late correlation can append to `events.jsonl` after `main()` computes the Morpheus feed (the same `t_blue.join(120)` overrun that bit the overseer matrix). The feed can slightly undercount a long blue tail. Low-stakes; fixable by recomputing artifacts post-join.
- **Dedicated AUTHORIZATION/INTEL panels not built** — the beats currently render as tagged rows + a flash banner, which is functional but less cinematic than a streaming petition panel.

---

## 4. Potential next steps (brainstorm menu)

### A. Submission / ship (highest leverage, deadline-driven)
1. **Clear the GitHub suspension** → push `frontier` → decide **floor vs. frontier** as the submission branch. (Only you can do the suspension.)
2. **Record the demo video** — a live duel on the dashboard is the money shot. Pick a canonical seed + theme; script the beats.
3. **Devpost write-up** — the README already carries the honest ledger + the five frontier features; adapt it.

### B. Demo reliability (cheap, high-impact for the video)
4. **Guarantee the F2/F3/F4 beats** for the demo run — either harden the prompts further or add a "demo mode" that deterministically triggers one petition + one research + one dissent (clearly labeled), so the video never misses a beat. (Watch the honesty line: label any scripted beat.)
5. **Pick the canonical demo seed/theme** where all beats fire + a novel edge lights (emergence ≠ 0), so the dashboard shows the hot edge.

### C. Dashboard polish (needs the Browser pane visible)
6. Verify the F1 hot-edge + F2 verdict visuals.
7. Dedicated **AUTHORIZATION panel** (streaming petition → argument → verdict) + **INTEL card** (live CVE).
8. Tiled **wall-of-duels** live view ("every gate at 0, tiled").

### D. Remaining ceiling (bigger swings, mind the budget)
9. **Model leaderboard** — run the duel across Nemotron tiers/models, rank attacker/defender strength. *Needs multiple live multi-model runs* to have real data (that's why it's not built — an empty shell would be dishonest scaffolding).
10. **Live wall-of-duels via Nebius Serverless Jobs** — N real duels fanned out, aggregated. Directly targets the Serverless prize; the headless `wall.py` is the local proof-of-concept.
11. **Garak probe tool** (NVIDIA hook) — red pulls a Garak probe category. Heavier dependency; weigh value vs. effort.

### E. Research credibility (the honest nulls)
12. **P1 lineage** — the full S=10 grid (frozen pre-registration is ready). Needs the paid corpus + monitor matrix. Decide if the result is worth the spend.
13. **Phase 2 arms race** — the learned-monitor null; decide whether to invest in a non-degenerate adaptive loop or report it as-is (it's already an honest, defensible null).

---

## 5. My read (for what it's worth)
If the goal is the grand prize and the clock is the constraint: **A → B → C** is the path. The build is done and verified; the remaining risk is *presentation* (a clean, beat-complete demo video) and *distribution* (unblocking the push). The ceiling items (D) are real upside but each costs budget or dependency weight — pick one that maps to a specific prize (Serverless → #10) rather than building breadth. The research nulls (E) are already honest and on-brand; don't let them pull focus from the demo unless you specifically want the research narrative.

*Commands: `make test` (self-checks), `make wall` (invariant at scale), `make duel` / `run.py --agent --overseer --theme bank` (live), `run.py --agent --overseer --theme <t> --range-seed <n>` (pinned).*
