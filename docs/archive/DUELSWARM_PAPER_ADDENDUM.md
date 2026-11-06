# DUELSWARM — Addendum: refinements from "Agent Security is a Systems Problem"

**For:** Claude Code. Apply these ON TOP of the current build (the `DUELSWARM_RESEARCH_BRIEF.md` work). This is a refinement pass, not a rewrite. Source: Fernandes, Chaudhuri, Jha, Rehberger et al., "Agent Security is a Systems Problem" (arXiv 2605.18991) — the position paper duelswarm empirically instantiates.

Priority: **P0 is a real architecture change; the rest is framing + one small addition.**

---

## P0 — Move the reference monitor to the egress/action boundary (do this BEFORE opening red's shell)

**Problem:** the gate currently mediates at the **tool-call** level (it checks the target of a named tool). The arms-race plan gives red a **real shell with free-form commands**. A tool-name-level gate does NOT completely mediate a free-form shell — red can reach an out-of-scope host with a raw command the gate never inspects. That silently breaks the project's central claim (complete mediation / the gate holds).

**Fix:** the deterministic reference monitor must enforce at the **network-egress / action boundary**, not the tool name. Every outbound connection resolves to a canonical target and is checked against scope there, regardless of how red phrased the command.

**You already have the pattern:** breachswarm's `egress_proxy.py` + the `--enforce` no-bypass egress guard does exactly this (canonical host resolution, default-deny, no-bypass). Port that enforcement point into duelswarm's gate so:
- red can run free-form shell commands (open action space = the emergence the arms race needs), AND
- every egress is still completely mediated by the deterministic monitor (the claim still holds).

This is the one change that is load-bearing: without it, giving red an open shell undermines the thesis you're trying to prove.

---

## P1 — A minimal information-flow check (the captured-flag / canary)

**Gap the paper surfaces:** the gate enforces by *target scope*, not *information flow*. Red could exfiltrate crown-jewel data to an **in-scope** destination and the gate would not catch it (it only checks where you reach, not what leaves). Several of the paper's 11 attacks are exactly this (exfiltration).

**Cheap partial close:** plant a **canary / flag** (a unique secret token) on the crown-jewel host. The breach is only counted when red exfiltrates that exact token across the boundary. That canary-crossing is a lightweight **information-flow** signal and doubles as the external ground-truth validator (did the secret actually leave?).

**Honest scoping:** frame this precisely — duelswarm enforces **complete mediation + least privilege**, and the flag-capture check is a **minimal information-flow property**. Full information-flow control (the paper's open problem 3.3: label propagation, declassification, granularity) is explicitly OUT of scope and belongs in Limitations / roadmap. Do NOT build full IFC.

---

## P1 — Vocabulary & positioning (README, report, dashboard, docs)

Adopt the paper's canonical terms; your components already ARE these, so just name them:
- the gate → a **deterministic reference monitor** enforcing **complete mediation** and **least privilege**
- the enforced-and-trusted core → the **trusted computing base (TCB)**
- the agents + their inputs → the **untrusted system** / the model as an **untrusted component**

Add a one-paragraph positioning note (README + the application write-up): *duelswarm is the empirical testbed for the enforcement-and-monitoring slice of "Agent Security is a Systems Problem." It measures two claims the paper asserts — that stacked/learned guards share correlated failure modes (→ the lineage-blindspot result) and that adaptive attackers defeat model-level defenses (→ the arms-race degradation curve) — and probes one of its open problems (verifiable natural-language-to-policy translation, §3.2).* Cite the paper.

---

## P1 — Reframe the overseer (sharper purpose, same code)

The paper explicitly argues that putting an LLM in the enforcement path makes the TCB **probabilistic with no verifiable contract** — i.e., the overseer is the design they warn against. So reframe it:
- NOT "a softer second gate," but **"we test the LLM-in-the-TCB design the paper argues against, and measure exactly how it fails while the deterministic reference monitor holds underneath."**
- The overseer-fooling confusion matrix becomes an **empirical probe of open problem 3.2** (the gap between the natural-language ROE and the formal enforced policy). Where useful, measure the **divergence** between the NL policy and the deterministic scope, not just a binary "fooled" — that is the paper's "mutual entailment" gap, observed empirically.

---

## What does NOT change (resist scope creep)

Do not add full information-flow control, instruction/data separation, or the rest of the paper's stack. That is their vision, not this hackathon. Deeper, not bigger. List them honestly as Limitations and roadmap, citing the paper's §3.1 and §3.3 as the open problems they are.

---

## Net
One architecture change (egress-level mediation, which you have the pattern for), one small addition (the canary as a minimal IFC + ground-truth check), and framing that positions duelswarm as the empirical instantiation of a paper two of your target UCSD faculty co-authored. After this pass, the remaining work is the live run and the video, not more features.
