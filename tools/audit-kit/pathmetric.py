"""Claim-1 path metric, proposed by the external auditor (2026-11-05). Stdlib only; reads ONLY the
hash-chained episode log (no ground truth, no compose file, no engine code).

PATH(e): the ordered sequence of RED-CHOSEN, CHAIN-CONFIRMED state transitions:
  E:<entry host>|<cve>     the foothold (state.mutate state=foothold), with the CVE red chose
  L:<src>><dst>            each lateral (state.mutate state=lateral), dst resolved to a host name
                           via the chain's own gate.allow `resolved` field for that IP
  X:<dst>                  the exfil (state.mutate state=exfil)
Repeats of an identical token are collapsed. Excluded on purpose: failed attempts, scans, turn
counts, timing, and which credential the engine's spray happened to land (engine-determined).
DISTANCE: normalized Levenshtein edit distance between token sequences, in [0, 1].
"""
import json, sys, itertools
def path(chain_path):
    ev = [json.loads(l) for l in open(chain_path)]
    ip2host = {}
    for e in ev:
        d = e.get("data") or {}
        if e["action"] in ("gate.allow", "gate.block") and d.get("resolved") and d.get("target"):
            ip2host[d["target"]] = d["resolved"]
        if e["action"] in ("gate.allow",) and d.get("resolved") and d.get("dst_ip"):
            ip2host[d["dst_ip"]] = d["resolved"]
    h = lambda x: ip2host.get(x, x)
    toks = []
    for e in ev:
        if e["actor"] != "red" or e["action"] != "state.mutate":
            continue
        d = e["data"]; st = d.get("state")
        if st == "foothold":   t = f"E:{h(d.get('dst'))}|{d.get('cve') or d.get('via')}"
        elif st == "lateral":  t = f"L:{h(d.get('src'))}>{h(d.get('dst'))}"
        elif st == "exfil":    t = f"X:{h(d.get('dst'))}"
        else: continue
        if not toks or toks[-1] != t:
            if t not in toks: toks.append(t)
    return toks
def lev(a, b):
    m, n = len(a), len(b); D = list(range(n + 1))
    for i in range(1, m + 1):
        prev, D[0] = D[0], i
        for j in range(1, n + 1):
            cur = D[j]; D[j] = min(D[j] + 1, D[j - 1] + 1, prev + (a[i - 1] != b[j - 1])); prev = cur
    return D[n]
def dist(a, b):
    return lev(a, b) / max(len(a), len(b), 1)


# ---- Test statistic (pre-registered with the tokenizer above) ----------------------------------
# Unit of analysis = one LINEAGE (an independent evolving population), represented by its elite's
# paths on the fixed held-out evaluation seeds. `arms` maps floor-shape label -> list of lineages,
# each lineage a list of paths. Only WINNING paths (ending in an X: token) enter the primary test.
def _mean(xs):
    xs = list(xs); return sum(xs) / len(xs) if xs else 0.0

def lineage_dist(A, B):
    """Mean pairwise path distance between two lineages' winning paths."""
    return _mean(dist(a, b) for a in A for b in B)

def separation(arms):
    """S = mean between-arm lineage distance - mean within-arm lineage distance (energy-style).
    0 when floor shape carries no information about the path; larger = arms took different routes."""
    labs = [(a, L) for a, Ls in arms.items() for L in Ls]
    between, within = [], []
    for (a1, L1), (a2, L2) in itertools.combinations(labs, 2):
        (between if a1 != a2 else within).append(lineage_dist(L1, L2))
    return _mean(between) - _mean(within)

def did(arms_gen0, arms_genG, n_perm=10000, seed=0):
    """Claim-1 statistic: D = S(gen G) - S(gen 0). Gen 0 is the same lineages before any selection,
    so S(gen 0) absorbs the MECHANICAL effect of a floor that simply removes routes. Permutation null:
    shuffle floor-shape labels across lineages (keeping each lineage's gen0/genG pair together)."""
    import random
    rng = random.Random(seed)
    keys = [(a, i) for a, Ls in arms_genG.items() for i in range(len(Ls))]
    obs = separation(arms_genG) - separation(arms_gen0)
    labels = [a for a, _ in keys]; ge = 0
    for _ in range(n_perm):
        rng.shuffle(labels)
        g0, gG = {}, {}
        for (a, i), lab in zip(keys, labels):
            g0.setdefault(lab, []).append(arms_gen0[a][i]); gG.setdefault(lab, []).append(arms_genG[a][i])
        ge += (separation(gG) - separation(g0)) >= obs
    return obs, (ge + 1) / (n_perm + 1)
