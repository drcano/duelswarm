"""Range-as-adversary (Component E) — SPADE-style range generation scored by
learnability p(1-p) (SFL / Zero-Sum Curriculum).

A generator proposes NEW ranges via `swarm.topo_to_compose.generate_range`'s schema
(seeded candidates drawn from the vetted pool); each proposal is probed with a
cheap solver estimate, and the proposals in the HARD-BUT-SOLVABLE band
(p ∈ (0, 1), ideally near 0.5) are kept — the trivial (p=1) and the unsolvable
(p=0) are both rejected, with the reason logged. The survivors feed back as the
next environments.

Everything is seeded + deterministic so the self-check runs with no tokens and
no Docker — the solver estimate is a model of difficulty, not a real duel; a
live driver swaps `estimate_solve_rate` for a function that runs K real duels
against each candidate and returns the empirical rate.

Learnability p(1-p) peaks at p=0.5; `solved_count` in a budget B is a sufficient
statistic for a Bernoulli estimate. We rank candidates by expected learnability
and emit `range.proposal` / `range.accept` / `range.reject` events into any log
the caller passes so the dashboard sees the curriculum tightening.
"""
import math
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm.topo_to_compose import generate_range, load_pool


def learnability(p):
    """SFL / Zero-Sum Curriculum: Bernoulli variance = p * (1 - p). Max at 0.5."""
    return p * (1.0 - p)


# --- PAIRED-style regret objective (G4) ------------------------------------
# Learnability p(1-p) is MONOTONE on each side of 0.5 and so, on a pool whose
# realized difficulty never reaches the unsolvable end, degenerates to "pick
# the hardest." PAIRED (https://arxiv.org/abs/2012.02096) fixes the generic
# failure mode — a pure-minimax/difficulty environment-adversary drifts to
# UNSOLVABLE ranges — by scoring a candidate range by REGRET:
#     regret(range) = solve_prob(strong antagonist) - solve_prob(current protagonist)
# Regret is ~0 for a trivial range (both solvers win) AND ~0 for an unsolvable
# range (both lose), and PEAKS for "hard but still solvable by the strong
# solver" — exactly the band a good curriculum wants. We reuse the file's
# deterministic difficulty model (`_difficulty_signal`) as the range's intrinsic
# easiness and model the two solvers as the SAME model at different competence.
ANTAGONIST_SKILL = 0.8   # strong best-response solver (defines the solvable frontier)
PROTAGONIST_SKILL = 0.5  # current / average solver (what the arms race improves)
SOLVER_STEEPNESS = 15.0  # how sharply solve-prob transitions around skill == challenge


def _solver_success(easiness, competence, steepness=SOLVER_STEEPNESS):
    """Expected solve probability of a solver of `competence` (skill in [0,1])
    against a range of intrinsic `easiness` in [0,1]. A solver wins when its
    skill exceeds the range's challenge (= 1 - easiness); the logistic makes it
    a smooth, deterministic frontier. Reference solver at competence == easiness
    sits at 50/50, so this generalizes `_difficulty_signal` to a skill axis."""
    challenge = 1.0 - max(0.0, min(1.0, easiness))
    return 1.0 / (1.0 + math.exp(-steepness * (competence - challenge)))


def regret_from_easiness(easiness, antagonist=ANTAGONIST_SKILL, protagonist=PROTAGONIST_SKILL):
    """PAIRED regret on the raw easiness axis (antagonist - protagonist solve
    prob). Non-monotonic in difficulty: ~0 at both ends, peaks hard-but-solvable.
    Clamped at 0 — a range the protagonist already beats harder than the
    antagonist carries no curriculum signal."""
    return max(0.0, _solver_success(easiness, antagonist) - _solver_success(easiness, protagonist))


def regret(r, antagonist=ANTAGONIST_SKILL, protagonist=PROTAGONIST_SKILL):
    """Regret of a concrete candidate range, using the file's difficulty model."""
    return regret_from_easiness(_difficulty_signal(r), antagonist, protagonist)


def _difficulty_signal(r):
    """Deterministic, cheap difficulty proxy for a generated range.
    Based on structural knobs the pool exposes:
      - how many pivots the entry must traverse to reach the crown
      - whether the crown has env-based secrets (easier via a leaked env read)
      - how many honeypots sit along the way (noise raises difficulty)
    Returns a p in [0,1] that models the expected solve rate within budget B.
    Chosen so the self-check sees a non-trivial range of p across seeds."""
    gt = r["ground_truth"]
    in_scope = gt["in_scope"]
    crown = gt["crown_jewel_host"]
    pivots_to_cross = max(0, len(in_scope) - 2)   # entry + crown = 2 at minimum
    honeypots = sum(1 for h in r["hosts"] if h.get("honeypot"))
    has_env_secrets = any(h.get("env") for h in r["hosts"] if h["name"] == crown)

    # Start optimistic, discount for depth and noise, bump for env leaks.
    p = 0.85
    p -= 0.15 * pivots_to_cross
    p -= 0.10 * honeypots
    if has_env_secrets:
        p += 0.05
    return max(0.02, min(0.98, p))


def estimate_solve_rate(r, budget=5, seed=0):
    """Model-based solve-rate estimate for a candidate range. Deterministic given
    (seed, candidate signature). In a live driver, replace with K real duels."""
    base = _difficulty_signal(r)
    # Bernoulli draw with mean=base, over `budget` trials; estimator is k/B.
    rng = random.Random(f"solve:{seed}:{r['seed']}")
    k = sum(1 for _ in range(budget) if rng.random() < base)
    return k / budget


def propose_candidates(n, pool=None, start_seed=1_000_000, theme=None):
    """Deterministically generate n candidate ranges from the vetted pool.
    Each candidate carries its seed + full schema; a live driver can instantiate
    the surviving ones via topo_to_compose.write_range."""
    pool = pool or load_pool()
    return [generate_range(start_seed + i, pool, theme=theme) for i in range(n)]


def curate(n_candidates=12, keep=4, budget=5, pool=None, seed=42,
           log=None, lower=0.1, upper=0.9, theme=None):
    """Learnability-scored curriculum. Keep candidates in the hard-but-solvable
    band (lower, upper); reject the trivial (>= upper) and the unsolvable
    (<= lower). Emit range.* events so the dashboard can show the curriculum
    tightening. Returns {kept, rejected, mean_solve_rate}.
    """
    pool = pool or load_pool()
    cands = propose_candidates(n_candidates, pool, start_seed=seed, theme=theme)
    scored = []
    for c in cands:
        p = estimate_solve_rate(c, budget=budget, seed=seed)
        L = learnability(p)
        rec = {"seed": c["seed"], "solve_rate": round(p, 3),
               "learnability": round(L, 4),
               "crown": c["ground_truth"]["crown_jewel_host"],
               "in_scope_n": len(c["ground_truth"]["in_scope"])}
        if log is not None:
            log.append("range", "range.proposal", rec)
        scored.append((rec, c, p, L))

    kept, rejected = [], []
    for rec, c, p, L in scored:
        if p <= lower:
            reason = "unsolvable (solve_rate <= lower band)"
            rejected.append({"seed": c["seed"], "reason": reason, "solve_rate": p})
            if log is not None:
                log.append("range", "range.reject", {**rec, "reason": reason})
        elif p >= upper:
            reason = "trivial (solve_rate >= upper band)"
            rejected.append({"seed": c["seed"], "reason": reason, "solve_rate": p})
            if log is not None:
                log.append("range", "range.reject", {**rec, "reason": reason})
        else:
            kept.append((rec, c, p, L))

    # Rank kept by learnability desc, take `keep`.
    kept.sort(key=lambda t: -t[3])
    survivors = kept[:keep]
    for rec, _, _, _ in survivors:
        if log is not None:
            log.append("range", "range.accept", rec)

    mean_p = (sum(p for _, _, p, _ in survivors) / len(survivors)) if survivors else 0.0
    return {
        "candidates": n_candidates,
        "kept": [rec for rec, _, _, _ in survivors],
        "rejected": rejected,
        "mean_solve_rate": round(mean_p, 3),
        "band": [lower, upper],
    }


class RangeCurriculum:
    """Evolve the range ACROSS generations (Component E, co-evolutionary half).

    Each generation proposes fresh candidates and picks the hardest-but-solvable
    one in a learnability band that TIGHTENS toward harder as red's competence
    rises — a ratchet. The crown / topology / seed move underneath red, so red
    cannot loop one exploit even if the population selection slips (T1). Offline,
    deterministic: the solver estimate is a difficulty model; a live driver swaps
    `estimate_solve_rate` for real duels.

    `next_range(competence)` — competence in [0,1] (e.g. red's recent best-fitness
    or evasion); higher competence => a lower target solve-rate center => a harder
    range. Emits a `range.curriculum` beat so the chain shows the terrain ratcheting.

    `objective` picks the scoring rule (both keep the terrain moving under red):
      - "learnability" (default, unchanged): keep the band near p(1-p)=0.5.
      - "regret" (PAIRED, G4): among the candidates, pick the one that maximizes
        regret = strong-antagonist solve - current-protagonist solve. The
        protagonist's skill IS `competence` (so the band ratchets harder as red
        improves, with no hand-tuned center), and the antagonist is a strong
        best-response always kept ahead, so the chosen range stays solvable by
        the strong solver. The `range.curriculum` beat then carries `regret`.
    """

    def __init__(self, base_seed=42, budget=5, pool=None, n_candidates=10, keep=3,
                 objective="learnability"):
        if objective not in ("learnability", "regret"):
            raise ValueError(f"objective must be 'learnability' or 'regret', got {objective!r}")
        self.base_seed = base_seed
        self.budget = budget
        self.pool = pool or load_pool()
        self.n_candidates = n_candidates
        self.keep = keep
        self.objective = objective
        self.gen = 0
        self.history = []

    def next_range(self, competence=0.0, log=None):
        competence = max(0.0, min(1.0, float(competence)))
        gen_seed = self.base_seed + self.gen * 1000
        if self.objective == "regret":
            rec = self._next_regret(competence, gen_seed, log)
        else:
            rec = self._next_learnability(competence, gen_seed, log)
        if log is not None:
            log.append("range", "range.curriculum", rec)
        self.history.append(rec)
        self.gen += 1
        return self._chosen

    def _beat(self, competence, chosen_seed, extra):
        r = generate_range(chosen_seed, self.pool)
        self._chosen = r
        gt = r["ground_truth"]
        rec = {"generation": self.gen, "competence": round(competence, 3),
               "objective": self.objective, "chosen_seed": chosen_seed,
               "crown": gt["crown_jewel_host"],
               "in_scope": list(gt["in_scope"]),
               "in_scope_n": len(gt["in_scope"])}
        rec.update(extra)
        return rec

    def _next_learnability(self, competence, gen_seed, log):
        center = max(0.15, 0.6 - 0.4 * competence)      # ratchet: harder as red improves
        lower, upper = max(0.05, center - 0.2), min(0.95, center + 0.2)
        out = curate(self.n_candidates, keep=self.keep, budget=self.budget,
                     pool=self.pool, seed=gen_seed, lower=lower, upper=upper, log=log)
        chosen_seed = out["kept"][0]["seed"] if out["kept"] else gen_seed
        return self._beat(competence, chosen_seed,
                          {"band": [round(lower, 3), round(upper, 3)]})

    def _next_regret(self, competence, gen_seed, log):
        # Protagonist = red's current skill; antagonist = a best-response kept
        # strictly ahead so the chosen range is always solvable by the strong solver.
        protagonist = competence
        antagonist = min(0.95, max(ANTAGONIST_SKILL, protagonist + 0.2))
        cands = propose_candidates(self.n_candidates, self.pool, start_seed=gen_seed)
        scored = []
        for c in cands:
            e = _difficulty_signal(c)
            g = regret_from_easiness(e, antagonist, protagonist)
            rec = {"seed": c["seed"], "easiness": round(e, 3), "regret": round(g, 4),
                   "antagonist_solve": round(_solver_success(e, antagonist), 3),
                   "crown": c["ground_truth"]["crown_jewel_host"],
                   "in_scope_n": len(c["ground_truth"]["in_scope"])}
            if log is not None:
                log.append("range", "range.proposal", rec)
            scored.append((g, c, rec))
        # Max regret = hardest-but-still-solvable by the strong antagonist.
        best_g, best_c, best_rec = max(scored, key=lambda t: t[0])
        if log is not None:
            log.append("range", "range.accept", best_rec)
        return self._beat(competence, best_c["seed"],
                          {"regret": round(best_g, 4),
                           "antagonist": round(antagonist, 3),
                           "protagonist": round(protagonist, 3),
                           "antagonist_solve": best_rec["antagonist_solve"],
                           "easiness": best_rec["easiness"]})


if __name__ == "__main__":  # self-check: trivial + unsolvable rejected; kept band near 0.5
    class _Rec:
        def __init__(self): self.events = []
        def append(self, actor, action, data=None):
            self.events.append({"actor": actor, "action": action, "data": data or {}})
            return {}

    assert learnability(0.5) == 0.25 and learnability(0.0) == 0.0
    assert learnability(0.5) > learnability(0.2) > learnability(0.02)

    log = _Rec()
    out = curate(n_candidates=20, keep=6, budget=8, seed=777, log=log)
    # Every candidate was proposed; survivors sit strictly inside the band.
    props = [e for e in log.events if e["action"] == "range.proposal"]
    assert len(props) == 20, len(props)
    for rec in out["kept"]:
        assert 0.1 < rec["solve_rate"] < 0.9, rec
    # Rejections are explained — never just dropped.
    assert all("reason" in r for r in out["rejected"]), out["rejected"]
    # Kept set's solve-rate sits near 0.5, not at an endpoint.
    assert 0.3 < out["mean_solve_rate"] < 0.75, out
    # The log carries the whole decision: proposal + (accept|reject) for each.
    decisions = [e for e in log.events if e["action"] in ("range.accept", "range.reject")]
    assert len(decisions) >= 1, decisions
    # And a kept range actually instantiates — the solver didn't invent a schema.
    gt_fields_present = all("crown_jewel_host" in generate_range(k["seed"])["ground_truth"]
                            for k in out["kept"])
    assert gt_fields_present, "kept candidate schemas must match topo_to_compose's shape"

    # Degenerate-generator case: a pool-free call that would produce all-trivial
    # ranges still logs rejects (never silently reports success).
    # Simulate by setting the band to (0.99, 0.995) so every normal candidate is
    # rejected as "trivial" relative to that near-perfect bar.
    log2 = _Rec()
    harsh = curate(n_candidates=6, keep=4, budget=8, seed=1, log=log2,
                   lower=0.99, upper=0.995)
    assert harsh["kept"] == [] and len(harsh["rejected"]) == 6, harsh
    assert all("reason" in r for r in harsh["rejected"]), harsh["rejected"]
    # RangeCurriculum (T4): the terrain evolves across generations and ratchets
    # harder as red's competence climbs. Consecutive generations must face
    # MEASURABLY different ranges (crown / in-scope / seed), never one fixed box.
    log3 = _Rec()
    cur = RangeCurriculum(base_seed=42, budget=6)
    comps = [0.0, 0.3, 0.6, 0.9]       # red getting better over 4 generations
    ranges = [cur.next_range(competence=c, log=log3) for c in comps]
    sigs = [(r["ground_truth"]["crown_jewel_host"],
             tuple(sorted(r["ground_truth"]["in_scope"])), r["seed"]) for r in ranges]
    assert len(set(sigs)) >= 3, ("curriculum must vary the range across gens", sigs)
    # The band ratchets toward harder (lower center) as competence rises.
    beats = [e["data"] for e in log3.events if e["action"] == "range.curriculum"]
    assert beats[0]["band"][0] > beats[-1]["band"][0] or beats[0]["band"][1] > beats[-1]["band"][1], \
        ("band did not tighten toward harder as competence rose", [b["band"] for b in beats])
    assert len(beats) == 4, beats

    # --- PAIRED regret objective (G4) --------------------------------------
    # Shape test on the raw difficulty axis, solvers held fixed: regret is ~0 for
    # a TRIVIAL range (both solvers win) AND ~0 for an UNSOLVABLE range (both
    # lose), and PEAKS hard-but-solvable — whereas raw difficulty is MONOTONE.
    trivial, hard, unsolvable = 0.95, 0.35, 0.03
    g_triv = regret_from_easiness(trivial)
    g_hard = regret_from_easiness(hard)
    g_uns = regret_from_easiness(unsolvable)
    assert g_triv < 0.05, ("trivial range should carry ~0 regret", g_triv)
    assert g_uns < 0.12, ("unsolvable range should carry ~0 regret", g_uns)
    assert g_hard > 0.5, ("hard-but-solvable range should carry high regret", g_hard)
    assert g_hard > g_triv and g_hard > g_uns, (g_triv, g_hard, g_uns)
    # Non-monotonic: sweeping easiness trivial->unsolvable, regret rises THEN
    # falls (a single interior peak), while difficulty (= 1 - easiness) only rises.
    sweep = [i / 20 for i in range(1, 20)]
    gs = [regret_from_easiness(e) for e in sweep]
    peak_i = max(range(len(gs)), key=lambda i: gs[i])
    assert 0 < peak_i < len(gs) - 1, ("regret peak must be interior, not an endpoint", peak_i)
    assert all(gs[i] <= gs[i + 1] + 1e-9 for i in range(peak_i)), ("regret must rise to the peak", gs)
    assert all(gs[i] >= gs[i + 1] - 1e-9 for i in range(peak_i, len(gs) - 1)), ("regret must fall after the peak", gs)
    # The strong antagonist still solves the peak range (it is SOLVABLE, not just hard).
    assert _solver_success(sweep[peak_i], ANTAGONIST_SKILL) > 0.5, sweep[peak_i]
    # Contrast: raw difficulty is strictly monotone across the same sweep.
    diffs = [1 - e for e in sweep]
    assert all(diffs[i] > diffs[i + 1] for i in range(len(diffs) - 1)), "difficulty must be monotone"

    # Regret-mode curriculum: still varies the terrain across generations, and
    # every chosen range stays solvable by the strong antagonist. Beat carries regret.
    log4 = _Rec()
    rcur = RangeCurriculum(base_seed=42, budget=6, objective="regret")
    rranges = [rcur.next_range(competence=c, log=log4) for c in comps]
    rsigs = [(r["ground_truth"]["crown_jewel_host"],
              tuple(sorted(r["ground_truth"]["in_scope"])), r["seed"]) for r in rranges]
    assert len(set(rsigs)) >= 3, ("regret curriculum must vary the range across gens", rsigs)
    rbeats = [e["data"] for e in log4.events if e["action"] == "range.curriculum"]
    assert len(rbeats) == 4 and all("regret" in b for b in rbeats), rbeats
    assert all(b["antagonist_solve"] > 0.5 for b in rbeats), \
        ("regret mode must keep the terrain solvable by the strong solver", rbeats)
    assert all(b["objective"] == "regret" for b in rbeats), rbeats

    print(f"range_adversary ok: {len(out['kept'])} survived in band "
          f"({out['band']}, mean p={out['mean_solve_rate']}), "
          f"{len(out['rejected'])} rejected with logged reasons; "
          f"RangeCurriculum varied the terrain across 4 gens "
          f"({len(set(sigs))} distinct ranges), band ratcheting harder as red improves; "
          f"regret objective: peak={g_hard:.2f} hard-but-solvable vs "
          f"trivial={g_triv:.2f}/unsolvable={g_uns:.2f} (~0), "
          f"regret-mode varied terrain across {len(set(rsigs))} distinct ranges, all solvable")
