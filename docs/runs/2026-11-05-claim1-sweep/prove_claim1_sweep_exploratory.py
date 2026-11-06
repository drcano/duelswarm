"""Cold re-derivation for the 2026-11-05 claim-1 range sweep.

THIS ARCHIVE IS EXPLORATORY. It is NOT evidence for claim 1 ("rule shape steers the
route"). This script does not try to prove claim 1. It re-derives only the archive's
own facts, so a reviewer can confirm the caveats stated in README.md directly from the
raw chains, and so every later diff is reviewable against a snapshot whose contents are
pinned by re-derivation rather than by description.

The claim-1 critique itself (the layout confound, the single realized route per range,
the path metric) lives in docs/design-log/2026-11-06-full-audit.md (sections 5, E1-E6).
This archive is the raw material that audit was run against, committed so the audit is
reproducible — not an independent result.

Design, per the frozen-audit discipline (brief A6 / I8):
  - standard library only; imports nothing from swarm/, scripts/, or redteam/;
  - reads ONLY files under this script's own directory;
  - re-walks the hash chains with the stated formula (independent of the repo's walker);
  - exits non-zero if any re-derived fact disagrees with README.md.

Run from anywhere:
  python3 -I docs/runs/2026-11-05-claim1-sweep/prove_claim1_sweep_exploratory.py

What it re-derives and asserts:
  1. Inventory + integrity - exactly 111 *.jsonl.gz, none also present ungzipped, and every chain
                         walks clean under sha256(prev+body). A duplicated archive fails here.
  2. range mislabel   - every chain's config.range == "unified", in ALL four variant dirs
                         (I10: the variant that actually ran is only in range.topology).
  3. turns-per-hop    - the recorded turn_budget per variant is 44 / 59 / 73 / 44, i.e.
                         round(44 * label_hops / 3) for unified(3)/4hop(4)/5hop(5), with the
                         *_44t_shutout re-run of the 4hop range forced back to 44 (I4/E4).
  4. same host chain  - the designed (non-forbidden) crown path for unified and app_crown_4hop
                         both have four hosts after "attacker" (E4: the "3-hop vs 4-hop"
                         premise is a miscount; both are four-host / three-pivot chains).
  5. one designed route - each variant's topology lists exactly one in-scope crown path
                         (the only other path ends at the forbidden host dc-01) (E3).
  6. two-episode chain - app_crown_4hop_44t_shutout/gen1_139bed8f59d1 holds two episodes
                         (two config + two duel.verdict events) appended into one file (I9).
  7. corroborated wins - duel.verdict.achieved (already telemetry-gated: objective_claimed AND
                         loot_corroborated) per variant, asserted EXACTLY (4/11, 4/11, 0/10, 3/4).
                         Same 4hop range: 4 at 59 turns, 0 at 44 turns -> the budget confound.
  8. incomplete episode - backup_route_5hop/gen1_139bed8f59d1 has no duel.verdict and no telemetry
                         sidecar, so that folder has 5 chains but 4 verdicts.
"""

import gzip
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FORBIDDEN = {"dc-01", "jump-01", "decoy-fin"}
VARIANTS = ("unified", "app_crown_4hop", "app_crown_4hop_44t_shutout", "backup_route_5hop")

# Expected facts (see README.md). The script FAILS if the raw chains disagree.
EXPECT_BUDGET = {"unified": 44, "app_crown_4hop": 59,
                 "app_crown_4hop_44t_shutout": 44, "backup_route_5hop": 73}
LABEL_HOPS = {"unified": 3, "app_crown_4hop": 4, "backup_route_5hop": 5}
# Exact corroborated-win tallies (wins, episodes) and the exact gzipped-chain inventory.
# A duplicated or partially-unzipped archive fails these (duplication would print e.g. 8/22).
EXPECT_TALLY = {"unified": (4, 11), "app_crown_4hop": (4, 11),
                "app_crown_4hop_44t_shutout": (0, 10), "backup_route_5hop": (3, 4)}
EXPECT_GZ_COUNT = 111
ZERO = "0" * 64

failures = []


def check(ok, msg):
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {msg}")
    if not ok:
        failures.append(msg)


def load_jsonl(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def walk(records):
    """Return ('OK', n) or ('BAD_*', i); independent re-implementation of the chain rule."""
    prev = ZERO
    for i, e in enumerate(records):
        if "hash" not in e or "prev" not in e:
            return ("NOT_A_CHAIN", i)
        if e["prev"] != prev:
            return ("BAD_PREV", i)
        body = json.dumps({k: v for k, v in e.items() if k != "hash"},
                          sort_keys=True, separators=(",", ":"))
        if hashlib.sha256((prev + body).encode()).hexdigest() != e["hash"]:
            return ("BAD_HASH", i)
        prev = e["hash"]
    return ("OK", len(records))


def main_chains(variant_dir):
    """genN_<hex>.jsonl[.gz] main chains (exclude _io / _telemetry / boot_witness sidecars)."""
    out = []
    for name in sorted(os.listdir(variant_dir)):
        base = name[:-3] if name.endswith(".gz") else name
        if not base.endswith(".jsonl") or not base.startswith("gen"):
            continue
        if base.endswith("_io.jsonl") or base.endswith("_telemetry.jsonl"):
            continue
        out.append(os.path.join(variant_dir, name))
    return out


def all_chain_files():
    out = []
    for root, _dirs, files in os.walk(HERE):
        for name in files:
            if name.endswith(".jsonl.gz") or name.endswith(".jsonl"):
                out.append(os.path.join(root, name))
    return sorted(out)


def config_and_topo(records):
    cfgs, topos, verdicts = [], [], []
    for e in records:
        a = e.get("action")
        d = e.get("data", {}) if isinstance(e.get("data"), dict) else {}
        if a == "config":
            cfgs.append(d)
        elif a == "range.topology":
            topos.append(d)
        elif a == "duel.verdict":
            verdicts.append(d)
    return cfgs, topos, verdicts


def designed_paths(topo):
    """attack paths whose final host is in scope (not a forbidden host)."""
    out = []
    for p in topo.get("attack_paths", []):
        hops = p.get("hops", [])
        if hops and hops[-1] not in FORBIDDEN:
            out.append([h for h in hops if h != "attacker"])
    return out


def main():
    print(f"claim-1 sweep (EXPLORATORY) cold re-derivation\n  archive: {HERE}\n")

    present = [v for v in VARIANTS if os.path.isdir(os.path.join(HERE, v))]

    # ---- 1. inventory + hash-chain integrity --------------------------------
    print("1. inventory + hash-chain integrity")
    chain_files = all_chain_files()
    gz = [p for p in chain_files if p.endswith(".jsonl.gz")]
    plain = [p for p in chain_files if p.endswith(".jsonl")]
    check(len(gz) == EXPECT_GZ_COUNT,
          f"{len(gz)} *.jsonl.gz files (expected {EXPECT_GZ_COUNT})")
    check(not plain, f"no plain (ungzipped) *.jsonl present ({len(plain)} found)")
    # no chain present in both plain and .gz form (a duplicated archive trips this)
    stems = {}
    for p in chain_files:
        stem = p[:-3] if p.endswith(".gz") else p
        stems.setdefault(stem, []).append(p)
    dupe = [os.path.relpath(s, HERE) for s, ps in stems.items() if len(ps) > 1]
    check(not dupe, "no chain present in both plain and .gz form"
                    + (f"; dupes: {dupe}" if dupe else ""))
    bad = []
    for p in chain_files:
        status, n = walk(load_jsonl(p))
        if status != "OK":
            bad.append((status, n, os.path.relpath(p, HERE)))
    check(not bad, f"{len(chain_files)} chain files walk clean"
                   + (f"; BAD: {bad}" if bad else ""))

    # ---- 2. range mislabel (I10) --------------------------------------------
    print("\n2. config.range mislabel (I10): all dirs record range='unified'")
    per_variant = {}
    for v in present:
        vdir = os.path.join(HERE, v)
        ranges, budgets, verdicts_all = set(), set(), []
        topo0 = None
        two_ep = {}
        for cf in main_chains(vdir):
            recs = load_jsonl(cf)
            cfgs, topos, verdicts = config_and_topo(recs)
            for c in cfgs:
                ranges.add(c.get("range"))
                budgets.add(c.get("turn_budget"))
            if topos and topo0 is None:
                topo0 = topos[0]
            verdicts_all.extend(verdicts)
            two_ep[os.path.basename(cf)] = len(cfgs)
        per_variant[v] = dict(ranges=ranges, budgets=budgets,
                              verdicts=verdicts_all, topo=topo0, two_ep=two_ep)
        check(ranges == {"unified"},
              f"{v:26s} config.range == {sorted(ranges)}")

    # ---- 3. turns-per-hop budget (I4 / E4) ----------------------------------
    print("\n3. turn budget per variant == round(44 * label_hops / 3), unpinned rule (I4)")
    for v in present:
        budgets = per_variant[v]["budgets"]
        exp = EXPECT_BUDGET[v]
        check(budgets == {exp}, f"{v:26s} turn_budget == {sorted(budgets)} (expected {exp})")
    for v, h in LABEL_HOPS.items():
        if v in present:
            check(round(44 * h / 3) == EXPECT_BUDGET[v],
                  f"{v:26s} label {h}-hop -> round(44*{h}/3) == {EXPECT_BUDGET[v]}")

    # ---- 4. same four-host chain (E4 miscount) ------------------------------
    print("\n4. 'unified' and 'app_crown_4hop' have the SAME four-host designed chain (E4)")
    chain_len = {}
    for v in ("unified", "app_crown_4hop"):
        if v in present and per_variant[v]["topo"]:
            dp = designed_paths(per_variant[v]["topo"])
            if dp:
                chain_len[v] = len(dp[0])
                print(f"       {v:26s} designed in-scope path = {dp[0]}  ({len(dp[0])} hosts)")
    check(chain_len.get("unified") == chain_len.get("app_crown_4hop") == 4,
          f"both four-host chains: {chain_len}")

    # ---- 5. one designed in-scope route per variant (E3) --------------------
    print("\n5. exactly one in-scope crown route per variant (the other path ends at dc-01)")
    for v in present:
        topo = per_variant[v]["topo"]
        if not topo:
            check(False, f"{v:26s} no range.topology found")
            continue
        dp = designed_paths(topo)
        n_forbidden = len(topo.get("attack_paths", [])) - len(dp)
        check(len(dp) == 1,
              f"{v:26s} in-scope routes={len(dp)} forbidden-branch paths={n_forbidden}")

    # ---- 6. two-episode chain (I9) ------------------------------------------
    print("\n6. two episodes appended into one chain file (I9)")
    target = "gen1_139bed8f59d1.jsonl"
    v = "app_crown_4hop_44t_shutout"
    hit = None
    if v in present:
        for name, ncfg in per_variant[v]["two_ep"].items():
            if name.startswith(target):
                hit = (name, ncfg)
    check(hit is not None and hit[1] == 2,
          f"{v}/{hit[0] if hit else target}: config events == {hit[1] if hit else 'MISSING'} (expected 2)")

    # ---- 7. exact corroborated-win tally per variant ------------------------
    # duel.verdict.achieved is already telemetry-gated (objective_claimed AND loot_corroborated),
    # so these are corroborated wins, not raw claims. Asserted EXACTLY: a duplicated archive (which
    # doubles the counts, e.g. unified 8/22) fails here.
    print("\n7. corroborated-win tally per variant (duel.verdict.achieved, exact)")
    tally = {}
    for v in present:
        vers = per_variant[v]["verdicts"]
        wins = sum(1 for d in vers if d.get("achieved"))
        tally[v] = (wins, len(vers))
        exp = EXPECT_TALLY.get(v)
        if exp is None:
            check(False, f"{v:26s} wins {wins}/{len(vers)} (no expected tally!)")
        else:
            check((wins, len(vers)) == exp,
                  f"{v:26s} wins {wins}/{len(vers)} (expected {exp[0]}/{exp[1]})")
    if "app_crown_4hop" in tally and "app_crown_4hop_44t_shutout" in tally:
        w59 = tally["app_crown_4hop"][0]
        w44 = tally["app_crown_4hop_44t_shutout"][0]
        print(f"       budget confound: app_crown_4hop range won {w59} at 59 turns, "
              f"{w44} at 44 turns (same range, same hosts)")
        check(w44 == 0 and w59 > 0,
              "same 4hop range: wins at 59 turns, shutout at 44 turns (search cost, not hop count)")

    # ---- 8. backup_route_5hop has one incomplete episode --------------------
    print("\n8. backup_route_5hop/gen1_139bed8f59d1 is an incomplete episode")
    v = "backup_route_5hop"
    if v in present:
        vdir = os.path.join(HERE, v)
        nchains = len(main_chains(vdir))
        nverd = len(per_variant[v]["verdicts"])
        check(nchains == 5 and nverd == 4,
              f"{v}: {nchains} chains but {nverd} verdicts (expected 5 chains, 4 verdicts)")
        inc = "gen1_139bed8f59d1"
        inc_present, inc_verd = False, None
        for cf in main_chains(vdir):
            if os.path.basename(cf).startswith(inc):
                inc_present = True
                _c, _t, vd = config_and_topo(load_jsonl(cf))
                inc_verd = len(vd)
        no_tele = not (os.path.exists(os.path.join(vdir, inc + "_telemetry.jsonl.gz"))
                       or os.path.exists(os.path.join(vdir, inc + "_telemetry.jsonl")))
        check(inc_present and inc_verd == 0 and no_tele,
              f"{inc}: verdicts={inc_verd}, telemetry_sidecar={'absent' if no_tele else 'present'} "
              f"(incomplete: expected 0 verdicts, no telemetry)")

    # ---- summary -------------------------------------------------------------
    print("\n" + "=" * 70)
    if failures:
        print(f"FAIL: {len(failures)} re-derived fact(s) disagree with README.md:")
        for m in failures:
            print(f"  - {m}")
        sys.exit(1)
    print("PASS: every re-derived fact matches README.md.")
    print("NOTE: this archive is EXPLORATORY, not claim-1 evidence. See")
    print("      docs/design-log/2026-11-06-full-audit.md (sections 5, E1-E6).")


if __name__ == "__main__":
    main()
