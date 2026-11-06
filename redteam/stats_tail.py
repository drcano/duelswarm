"""Tail-shape analysis on REAL data:
 (A) VCDB cyber-loss severity (records exposed + USD loss) — external calibration.
 (B) duelswarm records.jsonl harm proxy (n=142) — can we even fit a tail at this N?
Implements the cluster-F rework: EVT shape xi (GPD/POT), Clauset power-law gate
(MLE alpha + x_min + KS + LR vs lognormal), Expected Shortfall. Honest N checks.
"""
import json, glob, warnings, numpy as np
warnings.filterwarnings("ignore")
import powerlaw
from scipy import stats

def tail_report(x, label="", xmin_floor=None):
    """Machine-readable sibling of summarize_tail: the Clauset power-law gate (MLE
    alpha + x_min + n_tail + LR tests) and the EVT/GPD shape xi, returned as a dict
    that SELF-LABELS its statistical power. `credible_alpha` is False (and no tail
    claim may be made) when n_tail < 50 (Clauset guidance); `underpowered` is True
    when the whole sample is too small for any tail claim. Used by the L5 live
    instrument so the tail pipeline's honesty is auditable, not just printed."""
    x = np.asarray([v for v in x if v and v > 0], dtype=float)
    n = int(x.size)
    rep = {"label": label, "n": n, "underpowered": n < 20,
           "alpha": None, "x_min": None, "n_tail": 0, "credible_alpha": False,
           "xi_gpd": None, "n_exc": 0}
    if n < 20 or len(set(x.tolist())) < 3:
        rep["note"] = "n<20 or <3 distinct values: too few points for any tail claim"
        return rep
    fit = powerlaw.Fit(x, discrete=False, verbose=False) if xmin_floor is None \
        else powerlaw.Fit(x, discrete=False, xmin=xmin_floor, verbose=False)
    ntail = int((x >= fit.xmin).sum())
    rep.update({"alpha": round(float(fit.alpha), 3), "x_min": round(float(fit.xmin), 3),
                "n_tail": ntail, "credible_alpha": ntail >= 50})
    try:
        u = float(np.percentile(x, 90))
        exc = x[x > u] - u
        if exc.size >= 5:
            c, _, scale = stats.genpareto.fit(exc, floc=0)
            rep.update({"xi_gpd": round(float(c), 3), "n_exc": int(exc.size),
                        "tail_kind": "unbounded-heavy (Frechet)" if c > 0 else "finite upper endpoint"})
    except Exception:
        pass
    if not rep["credible_alpha"]:
        rep["note"] = (f"n_tail={ntail} < 50: alpha NOT credibly estimable (Clauset) — "
                       "report as underpowered; significance is compute-gated")
    return rep


def summarize_tail(x, label, xmin_floor=None):
    x = np.asarray([v for v in x if v is not None and v > 0], float)
    n = len(x)
    print(f"\n===== {label}  (n={n} positive values) =====")
    if n < 20:
        print("  n < 20: too few points for any tail claim. Report the raw values only.")
        return
    print(f"  median={np.median(x):,.0f}  p95={np.percentile(x,95):,.0f}  max={np.max(x):,.0f}")
    # --- Clauset power-law gate ---
    fit = powerlaw.Fit(x, discrete=False, verbose=False) if xmin_floor is None \
        else powerlaw.Fit(x, discrete=False, xmin=xmin_floor, verbose=False)
    ntail = int(np.sum(x >= fit.xmin))
    print(f"  [power-law MLE] alpha={fit.alpha:.3f}  x_min={fit.xmin:,.0f}  n_tail(>=x_min)={ntail}")
    R_ln, p_ln = fit.distribution_compare('power_law', 'lognormal', normalized_ratio=True)
    R_exp, p_exp = fit.distribution_compare('power_law', 'exponential', normalized_ratio=True)
    def verdict(R, p):
        if p > 0.1: return "indistinguishable"
        return ("power_law favored" if R > 0 else "alternative favored")
    print(f"  [LR vs lognormal]   R={R_ln:+.2f} p={p_ln:.3f} -> {verdict(R_ln,p_ln)}")
    print(f"  [LR vs exponential] R={R_exp:+.2f} p={p_exp:.3f} -> {verdict(R_exp,p_exp)}")
    if ntail < 50:
        print(f"  !! n_tail={ntail} < 50 : alpha is NOT credibly estimable (Clauset guidance). "
              f"Claim 'heavy-tailed', never a specific exponent.")
    # --- EVT: GPD peaks-over-threshold at the 90th pct ---
    u = np.percentile(x, 90)
    exc = x[x > u] - u
    if len(exc) >= 30:
        c, loc, scale = stats.genpareto.fit(exc, floc=0)   # c == xi
        print(f"  [GPD/POT @p90 u={u:,.0f}] xi(shape)={c:+.3f} scale={scale:,.0f} n_exc={len(exc)}")
        print(f"      xi>0 => unbounded heavy (Frechet) tail; xi<0 => FINITE upper endpoint (a ceiling).")
        # Expected Shortfall at 99% (coherent, tail-sensitive) vs VaR
        q99 = np.percentile(x, 99)
        es99 = x[x >= q99].mean() if np.any(x >= q99) else float('nan')
        print(f"      VaR99={q99:,.0f}   ES99(mean beyond VaR99)={es99:,.0f}   ES/VaR={es99/q99:.2f}")
    else:
        print(f"  [GPD/POT] only {len(exc)} exceedances over p90 — too few for a stable xi.")

if __name__ == "__main__":  # the VCDB/records analysis is a script, not run on import
    # ---------- (A) VCDB real cyber-loss severity ----------
    files = glob.glob("/home/claude/vz-risk/vcdb/data/json/validated/*.json")
    data_total, usd = [], []
    for f in files:
        try: d = json.load(open(f))
        except Exception: continue
        dt = (((d.get("attribute") or {}).get("confidentiality") or {}).get("data_total"))
        if isinstance(dt,(int,float)) and dt>0: data_total.append(dt)
        amt = ((d.get("impact") or {}).get("overall_amount"))
        if isinstance(amt,(int,float)) and amt>0 and amt<1e11: usd.append(amt)  # screen the 1e12 artifact
    print(f"VCDB: {len(files)} incidents parsed")
    summarize_tail(data_total, "VCDB records-exposed (attribute.confidentiality.data_total)")
    summarize_tail(usd, "VCDB USD loss (impact.overall_amount, <1e11)")

    # ---------- (B) duelswarm harm proxy from records.jsonl ----------
    recs = [json.loads(l) for l in open("/mnt/user-data/uploads/duelswarm/data/records.jsonl") if l.strip()]
    # transparent harm proxy: depth of realized kill chain = number of distinct ATT&CK
    # techniques red executed in-scope (red_path length). A crude ordinal harm magnitude.
    harm = [len(r.get("red_path") or []) for r in recs]
    print(f"\nduelswarm records.jsonl: n={len(recs)} runs; harm proxy = |red_path| "
          f"(min={min(harm)}, median={int(np.median(harm))}, max={max(harm)})")
    summarize_tail([h for h in harm], "duelswarm harm proxy |red_path| (n=142)")
    print("\nNOTE: |red_path| is bounded by the technique catalog, so it CANNOT be heavy-tailed by "
          "construction — which is the honest point: the current instrument does not emit a "
          "continuous unbounded harm magnitude, so there is no tail to fit yet. The tail layer "
          "needs (1) a continuous harm metric and (2) hundreds-thousands of episodes. Neither exists today.")
