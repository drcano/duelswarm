# DUELSWARM — LIQUID REALISM v2 Execution Brief

*For a fresh Claude Code session. Builds on branch `frontier-liquid`. Two parts: (A) make the realism and the "real exploit" claim actually true, (B) rebuild the dashboard so the duel is visible and reads like a real network diagram. Plan only — follow the non-negotiables.*

---

## PART A — Realism + the honesty of "real"

### A0 (CRITICAL, do first) — "real" must be EARNED, not assigned by tier
In `swarm/red_loop.py::run_red_loop`, the T1 path hardcodes `fidelity: "real"` and increments `tally["real"]` whether a genuine Docker exploit ran OR the offline fallback `_real_exploit_evidence` (a grounded stub) ran. That means offline runs log stub compromises as `fidelity: "real"` — the exact over-claim a reviewer who clones and runs without Docker will catch.
Fix: `fidelity: "real"` and a counted compromise happen ONLY when a real exploit actually executed against a live container AND the XBOW validator confirmed it. The offline/stub path logs `fidelity: "stub"`, lives in a separate `tally["stubbed"]` bucket, and is NEVER counted as a real compromise or rendered as a real pop. Tier is the host's *potential*; execution is what makes it *real*. Add a self-check asserting an offline run yields `tally["real"] == 0`.

### A1 — Expand the T1 vetted-exploitable pool with Vulhub (the realism fix)
Today `config/range_pool.yaml::vetted_images` holds only struts/jenkins/db, so even a Docker-booted run can only really pop three CVEs. Integrate a vetted subset of **Vulhub** (pre-built docker-compose vulnerable environments) into `vetted_images`: target a dozen-plus genuinely-exploitable, boot-clean real CVEs across tiers of an enterprise (e.g. Confluence, GitLab, Spring4Shell, Log4Shell, a container escape, alongside the existing three). Rule: a CVE only enters the T1 pool after its image is confirmed to boot clean in this stack AND is actually exploitable in-sandbox. Anything not meeting that is T2 (real CVE, modeled) or excluded — never a faked T1.

### A2 — De-hardcode the entry anchor
`range_gen` asserts `entry == "struts"`, so every range enters through the same box. Make the entry a deterministic random draw (by seed) from the expanded internet-facing T1 pool, so ranges vary at the front door too. Update the self-checks that assume struts-as-entry.

### A3 — Boot Docker for ONE real enterprise run (earns the claim)
The liquid stage has never actually booted the containers — every run so far is offline, so "real exploit" is currently label-only. Add/execute a real `--scale enterprise` run that brings up the T1 containers (`make range-up`), fires the real exploits through `gate.dispatch`, and records that hash chain as the demo artifact. That run is what makes "real compromise" true. Keep it budget-aware (ask before `--llm-pop-size > 0`).

### A4 — Secondary cleanups (Claude Code already flagged these)
- Give the generation loop distinct targets so the run-level `degenerate=True` (from replaying `exploit_struts`) clears honestly.
- Snapshot degeneracy/canary/arms over the duel BEFORE the R4 adaptation probe, and scope the probe's induced loop to its own `red.adaptation.tally` so it doesn't dominate the top-line.
- Make the dashboard "Nemotron" counter tick for the single `live.nemotron` beat (today it only tracks full-swarm `llm.call`).

---

## PART B — Dashboard rebuild (`viz/index.html`)

Problem: the duel is no longer visible and the attack-grid topology is broken/unreadable. Rebuild it to read like a **standard network topology diagram**, not an abstract graph. Free rein on styling; requirements:

1. **The topology graph is the centerpiece and must be legible at 20-40 nodes.** Lay it out the way real network diagrams are drawn: the zones as distinct segmented regions (internet/entry → DMZ → app tier → identity → data/crown-jewels, plus red-infra and blue-infra as their own regions), hosts as labeled node icons grouped inside their segment, segmentation boundaries drawn explicitly. Group by segment so it doesn't turn into a hairball.
2. **Node visual language**, readable from a legend: shape/border by scope (in-scope vs out-of-scope), color by fidelity tier (T1 real-exploitable / T2 modeled / T3 no-CVE-hardened), a clear crown-jewel marker, and a live STATE per node as the duel runs (untouched → fingerprinted → researched → compromised-REAL vs exploited-modeled vs pivoted vs gate-blocked).
3. **Show the duel unfold.** Highlight/animate the attack path along the pivot edges as red progresses, so a viewer watches red move host to host. The pivot graph references real hosts only.
4. **The floor, always on screen.** A persistent, prominent banner: out-of-scope executed and Bypass, both chain-derived (`gate.allow` with `data.scope === 'out'`, structurally 0), plus a running gate.block count shown as the floor stopping red at the boundary.
5. **Live event feed panel beside the graph** — the hash-chained beats streaming over SSE (fingerprint / research / compromise / modeled / pivot / adaptation / gate.block), human-readable, so the temporal story sits next to the spatial one.
6. **Bind to the ACTUAL emitted events** — confirm the real `action` names and `data` fields in the emitting code before wiring; every rendered element must be backed by a logged event, and no on-screen number is a literal.

---

## Non-negotiables (unchanged)
Gate sacred/non-bypassable incl. blue; real-compromise = executed+XBOW-confirmed T1 only, T2 labeled modeled, T3 never a pop, offline = stub (never real); >=1 real Nemotron call per live run with real content; keep `_assert_nebius_host`; every on-screen beat is a hash-chained event, no literals; `degeneracy.py` + `validate_finding` gate results; `make test` green at every commit.

## Sequencing
A0 (earn "real") -> A1 (Vulhub pool) -> A2 (entry) -> A3 (one real Docker run) -> B (dashboard) -> A4 (cleanups).

## Git
Continue on `frontier-liquid`; tag `v1.0-stable-floor` untouched; commit per item with self-checks in `make test`. GitHub push suspended — local commits only.

---

# DECISIONS ADDENDUM — SETTLED in planning chat, Oct 16 (supersedes any conflict above)

## Target definition (so scope stops moving)
- **Minimum demo-winning version (aim here):** floor + liquid stage (done) + 2 genuinely-real Vulhub exploits (WebLogic + re-vetted struts) + ONE sector topology done richly (utility/OT) + ONE real Docker-booted run recorded as the demo chain + a legible rebuilt dashboard.
- **Upside (only if the above lands with time):** the other two sectors, more Vulhub CVEs, the JNDI/Log4Shell stretch, wall-of-duels, model leaderboard.
Partial is the correct outcome everywhere. A labeled honest T2/stub beats a faked T1.

## CVE / Vulhub decisions
- **runc escape CVE-2019-5736: NEVER detonate** (breaks out onto the host). T2 modeled, vet "vulnerable version present" only.
- **WebLogic CVE-2019-2725: real T1** — the clean self-contained SOAP RCE. Write reusable `exploit_weblogic()`.
- **Spring4Shell CVE-2022-22965: time-boxed** — WAR-on-Tomcat packaging; T1 if it pops reproducibly, else T2 modeled w/ reason.
- **Log4Shell + Fastjson: DEFER to JNDI stretch** — T2 modeled now (reason: needs red-controlled JNDI/LDAP red_infra). Build only if core lands early; it is the best stretch beat (symmetric-range thesis).
- **Re-vet the existing three (struts/jenkins/db) under the earned-proof bar — NO grandfathering.** Only struts has a confirmed real container; jenkins/db were the stub path. They stay T1 only if they genuinely boot+pop on this hardware with captured proof, else drop to T2 until they do.

## Vulhub mechanics
- **Vendor the specific CVE compose dirs** into the repo (e.g. `ranges/vulhub/<cve>/`), pinned to a recorded upstream Vulhub commit SHA. Do NOT reference `vulhub/x:ver` image tags (they don't exist) and do NOT clone the whole repo at demo time.
- **Per-CVE compose-merge adapter:** extract each CVE's service spec from its Vulhub compose and re-home it on the range's zone networks (`range`/`range_oos`) at the right tier/zone. This splice is the real A1 work.
- **arm64:** add `platform: linux/amd64`; vet on THIS hardware; accept partial promotion; boot/vet in batches of 2-3 heavy containers.
- **`vetted: true` = captured hash-chained proof** (boot log + real exploit evidence + pinned commit), never a hand-set flag.
- **Reusable `exploit_<x>()`** in `red_tools.py` shared by the vetting pop and the duel pop.

## Tavily (1,074 credits left — manage, don't fear)
- **Persistent, global, CVE-id-keyed on-disk cache** shared across all builds and runs. Each distinct CVE looked up at most once, ever.
- Run-time `research_cve` reads the cache; hits live Tavily only on a genuine miss, then caches. Never re-query a known CVE.
- Tavily **enriches a known CVE-id from the vetted pool — never open-ended "find vulnerable software" discovery.**
- **Hard call cap + counter, fail-loud.** Wall/leaderboard/curriculum sweeps run offline from the warm cache. (~10-15 distinct CVEs total → trivially within budget.)

## Token Factory (fine — $24.02)
- A3 gets ONE cheap real Nemotron call. Do NOT run `--llm-pop-size > 0` (multiplies spend). If a call fails, label the beat honestly; the exploit chain still stands.

## A2 entry
- Random entry draws only from internet-facing T1 hosts that have a working initial-access exploit (struts, WebLogic, + any promoted). Sequence A2 after promotions are known.

## Themes become STRUCTURAL enterprise templates (realism + critical-infra demos)
- Reconnect `--theme {bank,hospital,utility}` through the enterprise/liquid path (plumbing exists; it got orphaned).
- Upgrade themes from display-only labels to **structural sector reference architectures** driving segments / host roles / crown jewel / pivot graph, grounded in the real breaches:
  - **bank** ≈ Equifax: portal → app → customer/credit DB crown jewel; floor at core-banking/records boundary.
  - **hospital** ≈ healthcare: web/VPN → EHR/PACS/HL7 → patient-records DB + medical-device segment; floor at patient-data store.
  - **utility** ≈ Colonial Pipeline/ICS: corporate IT → IT/OT boundary → SCADA/historian/HMI → process controllers crown jewel; floor at the OT boundary. **Build this one first (canonical demo).**
- Real-CVE Vulhub services populate the exploitable IT-side hosts; sector crown jewels (PLC, medical device, mainframe) stay honest T2/T3 and are never really popped — the floor holding at that boundary is the point.
- Drop the stale "byte-identical across themes" expectation: the gate MECHANISM and honesty rules stay invariant; the topology legitimately differs by sector.

## Cleaned master sequence
A0 (done) → A1 Vulhub (vendor + adapter + boot-vet; WebLogic first; re-vet the three) → A2 entry → themes-as-structural-templates (utility/OT first) → A3 ONE real Docker-booted run (record as demo chain) → B dashboard rebuild → A4 cleanups → JNDI stretch only if time.

Honesty bar and `make test`-green-per-commit unchanged. Branch `frontier-liquid`; tag `v1.0-stable-floor` untouched; local commits (push suspended).

---

# UPDATE — Oct 16 (later): GOAT MODE target + judge-directed attack

## Target reframed: aim at the CEILING
The "minimum demo-winning version" above is NOT the target — it is the guaranteed floor / insurance only, so swinging at the ceiling risks nothing. **Build toward the full ceiling:** all three sector topologies (bank / hospital / utility), the full vetted Vulhub pool (not just WebLogic — promote every CVE that genuinely boots+pops on this hardware), the JNDI red_infra + Log4Shell/Fastjson story, the judge-directed attack (below), the polished network-topology dashboard, and the wall-of-duels + model-leaderboard sweeps (offline from the warm Tavily cache). Partial promotion stays the honest rule, but the AIM is everything, not the minimum. The floor just means nothing is ever lost by reaching.

## NEW ITEM — F5 reconnect + upgrade: the judge DIRECTS the attack
The interactive judge trigger (ROE + seed → `POST /run`) existed and got orphaned in the liquid/enterprise refactor — like the themes. Reconnect it through the enterprise/liquid path and the rebuilt dashboard, and **upgrade it from "set ROE + seed, then watch" to "direct the attack live":**
- From the dashboard control panel the judge picks sector + seed, writes the natural-language ROE, AND issues **live attack direction** — a human-supplied objective / target ("go for the patient-records DB", "pivot to the OT segment", "try the WebLogic box") that threads into red's orchestrator (`RED_ORCHESTRATOR`) as a mid-run human objective.
- Red (the autonomous swarm) executes the judge's direction on its own — the human sets intent/targets, red figures out how.
- **The gate enforces scope on everything the judge directs**, including blocking red when the judge steers it out of scope. That is the demo money beat: the floor holds even when a human drives the attacker. Nobody is trusted — not the LLM, not the judge.
- Every judge direction is its own hash-chained event (provenance: who directed what, and the gate's verdict on it).
- Surface the judge control panel + the live "your command → red's action → gate verdict" trail in the Part B dashboard rebuild.

Thesis framing to make explicit on screen: the deterministic floor is actor-agnostic and intent-agnostic — it does not care whether an LLM or a human is directing the attack; it enforces the invariant either way.
