#!/usr/bin/env python3
"""Descriptor bite test (Section 1 of the 2026-11-04 next-steps brief).

Applies the PROPOSED 4-D behavior descriptor to the 9 committed Nov-4 paid chains and reports how
many distinct MAP-Elites cells they occupy. The Nov-4 run collapsed all 9 episodes into ONE cell of
54 under the old (entry, breadth, stealth, depth) descriptor (red_diversity = 1/54); this test asks
whether the proposed (path_idiom, foothold_technique, turn_bin, cred_idiom) descriptor actually
separates what varies on red's chains.

Two modes:
  (default)         axis derivation is INLINED here — no dependency on a post-Section-3
                    swarm/population.py. This is what Section 1 runs.
  --via-population  import swarm.population.behavior_descriptor instead (Section 3's re-check;
                    must still report cells >= 4 on the Nov-4 archive once the new descriptor lands).

ACCEPTANCE: cells >= 4 on the 9 Nov-4 chains, AND no single cell holds > 6 of 9 episodes.

Axes (keyed ONLY on red's own chain events — the GT firewall holds; no ground-truth input):

  path_idiom (3):      STRUCTURAL lateral-path shape (seq-53, 2026-11-05) — names NO hosts, so it is
                       range-agnostic. Each foothold|lateral dst is resolved to its range.topology
                       node (by IP or name) and bucketed on the number of distinct network segments
                       the in-scope path crosses: 0 deep-seam = >=3 segments; 1 short-seam = 1-2
                       segments; 2 off-seam = touched an out-of-scope host / decoy / off-topology
                       address, or made no resolvable lateral progress. Supersedes the old unified-
                       seam name match (web01/dba01/db-bastion, web01/dba02), which pinned every path
                       on a differently-shaped range to off-seam.
  foothold_technique (3): first state.mutate(state=foothold). 0 canonical-CVE = its cve is
                       CVE-2017-5638 / S2-045 or its module is the canonical struts module;
                       1 msf-module = via=msf with a different module; 2 authored = the nearest
                       preceding move.source tool is author_tool / call_tool.
  turn_bin (3):        turn of the first state.mutate(state=exfil) OR first corroborated crown read
                       (loot on the flag host). Fixed bootstrap thresholds (the brief's <9-obs rule;
                       only 3 of 9 chains yield a finite crown turn): early <=20, mid 21-33,
                       late >33. Never-reach => late. The quantile alternative is printed for the
                       planner's verify.
  cred_idiom (2):      distinct harvested creds red consumed before the crown read, from
                       pivot move.source args.key. 0 bootstrap-only = 0-1 distinct; 1 chained = 2+.
"""
import argparse, glob, gzip, json, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARCHIVE = ROOT / "docs/runs/2026-11-04-claim2-gen3-paid/chains"

CANONICAL_CVES = {"CVE-2017-5638", "S2-045"}
CANONICAL_MODULE_HINT = "struts2_content_type_ognl"
AUTHORED_TOOLS = {"author_tool", "call_tool"}


def _load(path):
    op = gzip.open if str(path).endswith(".gz") else open
    with op(path, "rt") as f:
        return [json.loads(l) for l in f if l.strip()]


def _ip2name(events):
    """name<->ip map from the chain's own range.topology.nodes (every node: {name, ips:[...]})."""
    m = {}
    for e in events:
        if e.get("action") == "range.topology":
            for n in (e.get("data") or {}).get("nodes") or []:
                for ip in n.get("ips", []):
                    m[ip] = n["name"]
            break
    return m


def _node_index(events):
    """name->node and ip->node maps from range.topology.nodes (node: {name, ips, subnet, scope,
    flag, is_decoy, ...}) — resolves a foothold dst (host NAME) or a lateral dst (IP) to its node.
    MUST match swarm.population._bd_node_index (the seq-53 path_idiom reads the same structure)."""
    byname, byip = {}, {}
    for e in events:
        if e.get("action") == "range.topology":
            for n in (e.get("data") or {}).get("nodes") or []:
                byname[n.get("name")] = n
                for ip in n.get("ips", []):
                    byip[ip] = n
            break
    return byname, byip


def _flag_host_ips(events):
    ips = set()
    for e in events:
        if e.get("action") == "range.topology":
            for n in (e.get("data") or {}).get("nodes") or []:
                if n.get("flag"):
                    ips.update(n.get("ips", []))
            break
    return ips


def _turn_at(events, seq):
    """Turn in progress at a given seq = turn of the latest move.source at or before it."""
    t = None
    for e in events:
        if e.get("seq") is not None and e["seq"] <= seq and e.get("action") == "move.source":
            d = e.get("data") or {}
            if isinstance(d.get("turn"), int):
                t = d["turn"]
        if e.get("seq") is not None and e["seq"] > seq:
            break
    return t


def _red_mutations(events):
    return [e for e in events if e.get("action") == "state.mutate" and e.get("actor") == "red"]


def axis_path_idiom(events):
    """STRUCTURAL lateral-path signature (seq-53). MUST match swarm.population._bd_path_idiom:
    distinct in-scope segments crossed by the foothold|lateral path -> 0 deep (>=3) / 1 short (1-2);
    an out-of-scope / decoy / off-topology hop, or no resolvable progress -> 2 off-seam."""
    byname, byip = _node_index(events)
    segs = []
    touched_off = False
    for e in _red_mutations(events):
        d = e.get("data") or {}
        if d.get("state") not in ("foothold", "lateral"):
            continue
        node = byip.get(d.get("dst")) or byname.get(d.get("dst"))
        if node is None:
            touched_off = True
            continue
        if node.get("scope") not in (None, "in") or node.get("is_decoy"):
            touched_off = True
        seg = node.get("subnet")
        if seg and (not segs or segs[-1] != seg):
            segs.append(seg)
    distinct = len(set(segs))
    if touched_off or distinct == 0:
        return 2
    return 0 if distinct >= 3 else 1


def axis_foothold_technique(events):
    muts = _red_mutations(events)
    first_fh = next((e for e in muts if (e.get("data") or {}).get("state") == "foothold"), None)
    if first_fh is None:
        return 2  # never got a foothold -> treat as non-canonical (authored/other bucket)
    d = first_fh.get("data") or {}
    cve = (d.get("cve") or "").upper()
    module = (d.get("module") or "").lower()
    # nearest preceding move.source tool
    prev_tool = None
    for e in events:
        if e.get("seq") is not None and e["seq"] < first_fh["seq"] and e.get("action") == "move.source":
            prev_tool = (e.get("data") or {}).get("tool")
        if e.get("seq") is not None and e["seq"] >= first_fh["seq"]:
            break
    if prev_tool in AUTHORED_TOOLS:
        return 2  # authored
    if any(c in cve for c in CANONICAL_CVES) or CANONICAL_MODULE_HINT in module:
        return 0  # canonical-CVE
    if d.get("via") == "msf" and module:
        return 1  # msf-module (non-canonical)
    return 2      # other


def _crown_turn(events, flag_ips):
    """Turn of the first exfil state.mutate, else first loot move.source on the flag host."""
    for e in _red_mutations(events):
        d = e.get("data") or {}
        if d.get("state") == "exfil":
            return _turn_at(events, e["seq"])
    for e in events:
        if e.get("action") == "move.source" and (e.get("data") or {}).get("tool") == "loot":
            host = ((e.get("data") or {}).get("args") or {}).get("host")
            if host in flag_ips:
                return (e.get("data") or {}).get("turn")
    return None


def axis_turn_bin_fixed(turn):
    if turn is None:
        return 2  # never reached -> late
    if turn <= 20:
        return 0
    if turn <= 33:
        return 1
    return 2


def axis_cred_idiom(events, crown_turn):
    creds = set()
    for e in events:
        if e.get("action") != "move.source":
            continue
        d = e.get("data") or {}
        if d.get("tool") != "pivot":
            continue
        if crown_turn is not None and isinstance(d.get("turn"), int) and d["turn"] > crown_turn:
            continue
        key = (d.get("args") or {}).get("key")
        if key:
            creds.add(key)
    return 1 if len(creds) >= 2 else 0


def descriptor_inlined(events):
    flag_ips = _flag_host_ips(events)
    crown_turn = _crown_turn(events, flag_ips)
    return (axis_path_idiom(events),
            axis_foothold_technique(events),
            axis_turn_bin_fixed(crown_turn),
            axis_cred_idiom(events, crown_turn)), crown_turn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--via-population", action="store_true",
                    help="use swarm.population.behavior_descriptor instead of the inlined axes")
    ap.add_argument("--archive", default=str(ARCHIVE))
    a = ap.parse_args()

    chains = sorted(p for p in glob.glob(a.archive + "/gen*.jsonl*")
                    if "_io" not in os.path.basename(p) and "_telemetry" not in os.path.basename(p))
    assert len(chains) == 9, f"expected 9 Nov-4 chains, found {len(chains)}: {chains}"

    via_pop = a.via_population
    if via_pop:
        sys.path.insert(0, str(ROOT))
        from swarm.population import behavior_descriptor

    print(f"== descriptor bite test ({'via population.behavior_descriptor' if via_pop else 'inlined axes'}) ==\n")
    print(f"{'chain':26s} {'cell':20s} {'crown_turn':10s}")
    cells = {}
    finite_turns = []
    for p in chains:
        ev = _load(p)
        if via_pop:
            cell = tuple(behavior_descriptor(ev)); ct = None
        else:
            cell, ct = descriptor_inlined(ev)
            if ct is not None:
                finite_turns.append(ct)
        cells[cell] = cells.get(cell, 0) + 1
        print(f"{os.path.basename(p):26s} {str(cell):20s} {str(ct):10s}")

    n = len(cells)
    worst = max(cells.values())
    print(f"\ncells = {n}/54   (diversity {n/54:.4f})")
    print(f"distribution: {cells}")
    print(f"largest single cell: {worst}/9")
    if not via_pop and finite_turns:
        fs = sorted(finite_turns)
        print(f"finite crown turns (for turn_bin): {fs}  "
              f"(fixed-threshold bins used; <9 finite obs -> bootstrap rule per the brief)")

    ok = (n >= 4) and (worst <= 6)
    print(f"\nACCEPTANCE: cells>=4 AND no cell>6/9 -> {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
