"""The benign baseline — the ENABLER for the stealth-vs-detection contest (2026-10-27).

Rationale: docs/design-log/2026-10-27-stealth-vs-detection-benign-baseline.md. A quiet red on an
EMPTY network is still trivially caught, because blue alerts on the only activity that exists.
Stealth is meaningful ONLY when there is legitimate activity to hide inside. This module is the
range-side generator of that legitimate activity.

It is the RANGE's benign-activity source, NOT the instrument (gate/eventlog/spine/audit/
reverify_floor are untouched) and NOT blue (discrimination lives in the blue engine). It emits the
SAME telemetry classes red uses — sshd "Accepted password" auth lines (T1021) between defined host
pairs, and service-to-service net.flow connects — so a SINGLE login/connection is not uniquely
attacker. Benign activity is deterministic PER SEED and tagged benign in GROUND TRUTH ONLY (for
scoring); the detections handed to blue carry NO benign label (the exact mirror of the map being
hidden from red — see assert_blue_label_free in the blue engine).

Pre-registered model (rate + host-pair set + the one legitimate edge into the sensitive tier) lives
in DEFAULT_BENIGN_MODEL. Nothing here is tuned toward an outcome; the model is fixed before any
measurement and the generator is a pure function of (seed, model).
"""
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# The pre-registered benign-activity model. host_pairs is the legitimate admin/service mesh: each
# (src, dst, user) is a route a real account routinely uses. REALISTIC LEAST-PRIVILEGE SEGMENTATION
# (the honest topology, Part 1): the crown DB (`db-core`) is reached legitimately by a NARROW admin
# path ONLY — the two Tier-1 hosts `db-bastion` and `backup` (the DBA jump + the backup service). A
# small set of Tier-2 admin hosts (`dba01/dba02/etl01/bkupctl`) legitimately reach Tier-1, so they
# have a DISCOVERABLE MULTI-HOP living-off-the-land chain to the crown (…->Tier1->db-core). The MOST
# hosts — the general Tier-3 fleet (workstations, web, app, cache, ci, monitoring) — interconnect
# among themselves but have NO legitimate route to the data tier at all. So a breach that lands on a
# fleet host (the majority) MUST hop anomalously to reach the crown (detection-forced); a breach on an
# admin host (the minority) CAN blend if red DISCOVERS the chain map-blind. The ratio is not targeted
# — it falls out of least privilege. `db-core` receives benign logins (from db-bastion+backup), so "a
# login to db-core" is not itself attacker; only one from a source that never legitimately reaches it.
DEFAULT_BENIGN_MODEL = {
    "host_pairs": [
        # (src, dst, user) — legitimate SSH/admin edges (T1021 "Accepted password")
        # ── Tier 3: the general fleet, interconnected but with NO route to the data tier ──
        ("ws01", "app01", "alice"),
        ("ws02", "app02", "bob"),
        ("ws03", "web01", "carol"),
        ("web01", "app01", "svc_web"),
        ("web02", "app02", "svc_web"),
        ("app01", "cache01", "svc_app"),
        ("app02", "cache01", "svc_app"),
        ("mon01", "web01", "svc_mon"),
        ("mon01", "app01", "svc_mon"),
        ("ci01", "app01", "svc_ci"),
        # ── Tier 2 -> Tier 1: the admin hosts that legitimately reach the DB-adjacent tier ──
        ("dba01", "db-bastion", "svc_dba"),
        ("dba02", "db-bastion", "svc_dba"),
        ("etl01", "db-bastion", "svc_etl"),
        ("bkupctl", "backup", "svc_bkup"),
        # ── Tier 1 -> crown: the ONLY direct edges into db-core (least privilege) ──
        ("db-bastion", "db-core", "svc_dba"),
        ("backup", "db-core", "svc_backup"),
    ],
    "net_flows": [
        # (src, dst, port) — routine service-to-service connects (net.flow), no auth line
        ("web01", "app01", 8080),
        ("web02", "app02", 8080),
        ("app01", "cache01", 6379),
        ("app02", "cache01", 6379),
        ("db-bastion", "db-core", 5432),       # the bastion reads db over an EXISTING pool
    ],
    "logins_per_tick": 2.0,     # mean benign SSH logins emitted per contest tick (Poisson mean)
    "flows_per_tick": 3.0,      # mean benign service connects per contest tick
    "warmup_ticks": 20,         # the quiet baseline period blue observes BEFORE the contest
}

CROWN = "db-core"               # the crown host (the exfil target)


def _rng(seed, salt):
    """A per-(seed,salt) deterministic RNG so each stream (warmup/contest, logins/flows) is
    independent yet fully reproducible from the seed alone."""
    h = hashlib.sha256(f"{seed}:{salt}".encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def _poisson(rng, mean):
    """Knuth's deterministic Poisson draw (no numpy dep) — benign volume varies tick to tick but is
    a pure function of the seeded RNG, so the whole baseline re-derives from the seed."""
    import math
    L, k, p = math.exp(-mean), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= L:
            return k - 1


def _login_line(src, dst, user):
    """A real sshd auth line, byte-identical in form to the lateral-movement signature red trips —
    the point is that benign and malicious logins are indistinguishable at the SIGNATURE level, so
    blue cannot discriminate by the presence of the line, only by behavior (the login graph)."""
    return f"Accepted password for {user} from 10.10.0.{abs(hash(src)) % 200 + 20} port 22 ssh2"


def _login_detection(src, dst, user):
    """A label-FREE detection in the shape sensor_real.telemetry_detections emits (stage/technique/
    target/p_fire/basis/confirmed/source_line) — PLUS `source` (the login graph's src), which the
    real auth line carries ("...from <ip>") and the graph discriminator needs. It carries NO benign
    label: blue sees exactly this, the same as a red lateral detection."""
    return {"stage": "lateral_movement", "technique": "T1021", "target": dst, "source": src,
            "p_fire": 0.80, "confirmed": True,
            "basis": "real-telemetry[host]: SSH lateral movement (accepted auth)",
            "source_line": _login_line(src, dst, user)}


def benign_schedule(seed, model=None, n_ticks=40):
    """The deterministic-per-seed benign activity for a contest of `n_ticks`. Returns a list of
    events, each {tick, kind, src, dst, user?, port?, technique, benign: True}. `benign` is GROUND
    TRUTH for scoring ONLY — it is never handed to blue (see benign_window / detections_label_free).
    Pure function of (seed, model): re-derives cold."""
    model = model or DEFAULT_BENIGN_MODEL
    pairs = model["host_pairs"]
    flows = model["net_flows"]
    rlog, rflow = _rng(seed, "contest-logins"), _rng(seed, "contest-flows")
    events = []
    for tick in range(n_ticks):
        for _ in range(_poisson(rlog, model["logins_per_tick"])):
            src, dst, user = pairs[rlog.randrange(len(pairs))]
            events.append({"tick": tick, "kind": "login", "src": src, "dst": dst, "user": user,
                           "technique": "T1021", "benign": True})
        for _ in range(_poisson(rflow, model["flows_per_tick"])):
            src, dst, port = flows[rflow.randrange(len(flows))]
            events.append({"tick": tick, "kind": "flow", "src": src, "dst": dst, "port": port,
                           "technique": "net.flow", "benign": True})
    return events


def warmup_schedule(seed, model=None):
    """The quiet baseline period BEFORE the contest, benign-only, that blue observes to LEARN the
    normal login graph (standard anomaly-detection warmup; pre-registered length). Deterministic per
    seed, independent stream from the contest. Tick 0 is a BASELINE SWEEP — one login on every routine
    host-pair edge — modelling that over a baseline period every normal edge is exercised at least
    once; the remaining ticks are the usual Poisson benign stream. So a blue trained on the full
    warmup learns every ROUTINE edge (no chance-driven false positives on normal traffic), and the
    honest false-positive source is a GENUINELY novel edge or a baseline that was never trained — not
    a routine edge the warmup happened to miss."""
    model = model or DEFAULT_BENIGN_MODEL
    sweep = [{"tick": 0, "kind": "login", "src": s, "dst": d, "user": u, "technique": "T1021",
              "benign": True} for (s, d, u) in model["host_pairs"]]
    rest = benign_schedule(seed, model, n_ticks=model["warmup_ticks"])
    for e in rest:               # shift the Poisson stream after the sweep tick
        e["tick"] += 1
    return sweep + rest


def login_detections(events, tick):
    """The label-FREE login detections for a given contest tick (what blue's telemetry window
    surfaces this tick). Strips the ground-truth `benign` label — blue gets the same detection shape
    for a benign login as for a red lateral. Net flows carry no auth line, so they are not auth
    detections (they feed the net-flow graph separately via `flow_events`)."""
    return [_login_detection(e["src"], e["dst"], e["user"])
            for e in events if e["tick"] == tick and e["kind"] == "login"]


def flow_events(events, tick):
    """The benign net.flow (src,dst,port) connects for a tick — label-free, for the service-to-
    service graph. A single connect is not uniquely attacker either."""
    return [{"source": e["src"], "target": e["dst"], "port": e["port"], "technique": "net.flow",
             "basis": "real-telemetry[net]: service connect"}
            for e in events if e["tick"] == tick and e["kind"] == "flow"]


def benign_window(schedule):
    """A window factory mirroring the duel's telemetry_window(): each call returns the NEXT contest
    tick's label-free benign login detections, in order. The driver calls it once per tick alongside
    red's telemetry window; the two streams merge label-free into blue's belief. Benign ground-truth
    labels stay out of blue's view entirely."""
    ticks = sorted({e["tick"] for e in schedule})
    state = {"i": 0}

    def _w():
        if state["i"] >= len(ticks):
            return []
        t = ticks[state["i"]]
        state["i"] += 1
        return login_detections(schedule, t)
    return _w


def benign_edges(model=None):
    """The ground-truth set of legitimate login-graph edges (src,dst) — for SCORING a containment as
    a false positive (did blue contain a host whose only inbound was a benign edge?). NOT handed to
    blue; blue must LEARN the baseline from observation (warmup), and may differ from this truth
    (that gap is exactly where false positives come from)."""
    model = model or DEFAULT_BENIGN_MODEL
    return {(s, d) for (s, d, _u) in model["host_pairs"]}


def benign_hosts(model=None):
    """Hosts that appear ONLY as benign actors/targets (never a red-owned host) — the set whose
    containment counts as damage. Ground truth for scoring only."""
    model = model or DEFAULT_BENIGN_MODEL
    hs = set()
    for s, d, _u in model["host_pairs"]:
        hs.add(s); hs.add(d)
    for s, d, _p in model["net_flows"]:
        hs.add(s); hs.add(d)
    return hs


# ── Discovery-driven stealth setup (the honest Part-5 conditions) ──────────────────────────────
# Red must DISCOVER the living-off-the-land path, map-blind — not be handed `backup`. These helpers
# model (a) what red learns by LOCAL on-host recon (an owned host's own legitimate outbound edges,
# the realistic ssh known_hosts/history/cron discovery — NOT the global graph, crown, or scope), and
# (b) whether a legitimate-edge path to the crown EXISTS from a given entry (computed here for the
# dry-verify's ground truth; red re-derives it by reconning hop by hop).
def legit_adjacency(model=None):
    """{host: {legit outbound neighbors}} — the benign login graph as adjacency. In the duel red
    learns ONLY the entry of this dict for a host it OWNS (via recon_host), one host at a time; it is
    never handed the whole dict (that would be the map)."""
    model = model or DEFAULT_BENIGN_MODEL
    adj = {}
    for s, d, _u in model["host_pairs"]:
        adj.setdefault(s, set()).add(d)
    return adj


def legit_path(entry, target, model=None):
    """The shortest path from `entry` to `target` over LEGITIMATE edges only (BFS), or None if none
    exists. This is the ground truth for whether a living-off-the-land route is DISCOVERABLE from an
    entry — red finds it by reconning hop by hop (or fails to, and must hop anomalously). Used by the
    dry-verify to check the setup admits BOTH outcomes across entries; never handed to red."""
    adj = legit_adjacency(model)
    if entry == target:
        return [entry]
    seen, frontier = {entry}, [[entry]]
    while frontier:
        path = frontier.pop(0)
        for nxt in sorted(adj.get(path[-1], ())):
            if nxt in seen:
                continue
            if nxt == target:
                return path + [nxt]
            seen.add(nxt)
            frontier.append(path + [nxt])
    return None


# The pre-registered assumed-breach ENTRY for each seed: deterministic from the seed (sha256 index
# into the sorted candidate footholds), VARIED, and never the crown nor a host that OWNS a direct
# crown edge (so red must DISCOVER a multi-hop chain, never be handed the last hop). Deriving it from
# the seed — rather than hand-picking — is the guard against cherry-picking entries to manufacture a
# rate. Whether a given entry has a discoverable LOTL path then falls out of the least-privilege
# topology. N >= 12 (Dante sets the final count against budget) so the flagship stealth-capable
# sub-sample is usable; all seeds reported, none dropped.
# The pre-registered seed list is the FIRST N integers — a rule, not a hand-picked tuple, so no seed
# can be cherry-picked to steer which entries (and thus which outcomes) appear. N is the single knob
# Dante sets against budget (>= 12). Because the realistic least-privilege topology makes only a
# MINORITY of entry candidates stealth-capable (~29% here), the FLAGSHIP stealth-capable sub-sample
# is ~0.29*N; N=48 yields ~13 flagship seeds spanning ALL FOUR admin entries (a usable, diverse
# flagship CI). The low flagship fraction is itself the realistic finding (few breach points can
# reach a well-segmented crown), not a bug — raise N for a tighter flagship CI, never widen the admin
# tier to inflate it.
STEALTH_N = 48                                  # pre-registered N (>= 12); set for a usable flagship CI
STEALTH_SEEDS = tuple(range(1, STEALTH_N + 1))


def crown_edge_hosts(model=None):
    """The Tier-1 hosts with a DIRECT legitimate edge into the crown — the hosts that trivially reach
    it. Topology-driven (read off the graph), not a hardcoded name list."""
    model = model or DEFAULT_BENIGN_MODEL
    return {s for (s, d, _u) in model["host_pairs"] if d == CROWN}


def entry_candidates(model=None):
    """Hosts that may be an assumed-breach foothold: every benign host EXCEPT the crown and the hosts
    that OWN a direct crown edge (excluding those forces red to discover a MULTI-HOP chain, never the
    handed last hop). Sorted for determinism."""
    return sorted(benign_hosts(model) - {CROWN} - crown_edge_hosts(model))


def stealth_entry_for_seed(seed, model=None):
    """The map-blind entry host for a seed — deterministic, varied, never crown/crown-edge-owner."""
    cands = entry_candidates(model)
    idx = int(hashlib.sha256(f"stealth-entry:{seed}".encode()).hexdigest()[:16], 16) % len(cands)
    return cands[idx]


def stealth_capability(model=None, seeds=None):
    """The fall-out (NOT targeted): per seed, its entry and whether a legit LOTL path to the crown
    exists. Returns {seed: (entry, has_lotl_path)}. The stealth-capable seeds are the FLAGSHIP sample
    (red must still DISCOVER the path); the detection-forced seeds are the sanity anchor."""
    seeds = seeds or STEALTH_SEEDS
    return {s: (e, legit_path(e, CROWN, model) is not None)
            for s in seeds for e in [stealth_entry_for_seed(s, model)]}


# ── PHYSICAL projection of the registered logical model (Constraint 2: an ADD, not a model edit) ──
# Where each already-registered benign host sits on the wire (tier -> segment -> CIDR), which host is
# the LOUD published entry, and the Constraint-1 credential seam that lets a loud breach on web01
# COMPOSE a map-blind, gate-allowed, anomalous chain to the crown (no single cred/edge reaches it).
# generate_unified DERIVES its containers/segments/IP plan/credential graph from this. The logical
# graph (host_pairs / net_flows / per-tick rates / the one crown edge) is UNCHANGED.
_TIER_SEGMENTS = [
    # (segment, cidr, tier, external, in_gate_scope)
    ("dmz",      "10.10.0.0/24", "T3", True,  True),   # published fleet (loud entry lives here)
    ("user",     "10.20.0.0/24", "T3", False, True),   # workstations
    ("app",      "10.30.0.0/24", "T3", False, True),   # app/ci/cache/monitoring
    ("admin",    "10.35.0.0/24", "T2", False, True),   # the DBA/ETL/backup admin tier
    ("mgmt",     "10.60.0.0/24", "T1", False, True),   # data-adjacent (db-bastion, backup) — IN scope
    ("database", "10.40.0.0/24", "T1", False, True),   # crown
]
_HOST_SEGMENT = {
    "web01": "dmz", "web02": "dmz",
    "ws01": "user", "ws02": "user", "ws03": "user",
    "app01": "app", "app02": "app", "ci01": "app", "cache01": "app", "mon01": "app",
    "dba01": "admin", "dba02": "admin", "etl01": "admin", "bkupctl": "admin",
    "db-bastion": "mgmt", "backup": "mgmt",
    "db-core": "database",
}
LOUD_ENTRY = {"host": "web01", "service": "struts", "cve": "CVE-2017-5638", "port": 8080}
# Constraint-1 seam: web01 holds a HARVESTABLE reused credential authorizing dba01 (a DBA's
# workstation password left on the public web box) — the ONE anomalous bootstrap hop. From dba01 red
# then rides the ALREADY-REGISTERED legit admin LOTL chain (dba01 -> db-bastion -> db-core) by
# harvesting the legit svc cred at each hop. Composed, map-blind, every hop gate-allowed; NO single
# cred reaches the crown. The anomalous web01 -> dba01 edge is the novel edge blue can flag.
CRED_SEAM = {
    "bootstrap_host": "web01",
    "bootstrap_authorizes": "dba01",
    "chain": ["web01", "dba01", "db-bastion", "db-core"],
}


def topology_spec(model=None):
    """The PHYSICAL projection of the registered logical benign model — a pure function of it, not an
    edit (Constraint 2). Returns per-host segment, the segment/CIDR/tier table, the loud-entry
    designation, and the Constraint-1 composed crown seam. generate_unified builds the Docker range
    (containers / segments / IP plan / credential graph) FROM this, so the range red breaches IS the
    registered least-privilege topology. The 3 infrastructure hosts (dc-01/jump-01/decoy-fin) are
    added by the GENERATOR, never here."""
    model = model or DEFAULT_BENIGN_MODEL
    seg = {h: _HOST_SEGMENT[h] for h in benign_hosts(model)}   # KeyError if a registered host has no segment
    return {
        "segments": [tuple(s) for s in _TIER_SEGMENTS],
        "host_segment": seg,
        "loud_entry": dict(LOUD_ENTRY),
        "cred_seam": {**CRED_SEAM, "chain": list(CRED_SEAM["chain"])},
        "crown": CROWN,
        "crown_edges": sorted(crown_edge_hosts(model)),
    }


def assert_benign_label_free(detections):
    """Air-gap guard (the mirror of sensor_real.assert_label_free and live_agent.assert_red_map_blind
    for the benign dimension): NO detection handed to blue may carry a ground-truth benign/malicious
    label. Raises if any does. Returns the detections."""
    for d in detections:
        for leak in ("benign", "malicious", "is_red", "label", "ground_truth"):
            if leak in d:
                raise RuntimeError(f"benign label leaked into blue's view ({leak}): {d}")
    return detections


if __name__ == "__main__":   # self-check: deterministic per seed, label-free, the one sensitive edge
    import copy

    a = benign_schedule(1337, n_ticks=40)
    b = benign_schedule(1337, n_ticks=40)
    c = benign_schedule(42, n_ticks=40)
    assert a == b, "benign baseline must be deterministic per seed"
    assert a != c, "different seeds must give different baselines"
    assert len(a) > 20, ("baseline must have real volume (not a single login)", len(a))

    # the telemetry classes mirror red's: T1021 accepted-auth lines + net.flow connects
    logins = [e for e in a if e["kind"] == "login"]
    flows = [e for e in a if e["kind"] == "flow"]
    assert logins and flows, "baseline must emit BOTH logins and service flows"
    dets = login_detections(a, logins[0]["tick"])
    assert dets and dets[0]["technique"] == "T1021", dets
    assert "Accepted password for" in dets[0]["source_line"], dets   # same signature red trips
    assert dets[0]["source"] and dets[0]["target"], "a login detection must carry the graph edge"

    # the detections handed to blue carry NO benign label (air-gap, the mirror of map-blindness)
    assert all("benign" not in d for d in dets), "benign label leaked into blue's detection"
    assert_benign_label_free(dets)
    _caught = False
    try:
        assert_benign_label_free([{**dets[0], "benign": True}])
    except RuntimeError:
        _caught = True
    assert _caught, "assert_benign_label_free failed to catch a leaked benign label"

    # least privilege into the crown: db-core receives benign logins ONLY from the two Tier-1 hosts
    # (db-bastion, backup), so "a login to db-core" is NOT by itself attacker; NO fleet host reaches it.
    assert crown_edge_hosts() == {"db-bastion", "backup"}, crown_edge_hosts()
    db_srcs = {e["src"] for e in a if e["kind"] == "login" and e["dst"] == "db-core"}
    assert db_srcs and db_srcs <= {"db-bastion", "backup"}, \
        ("only the Tier-1 admin hosts legitimately log into db-core", db_srcs)
    assert "db-core" in benign_hosts()

    # the window factory walks the contest ticks in order, label-free
    w = benign_window(a)
    seen = []
    for _ in range(45):
        seen.extend(w())
    assert all("benign" not in d for d in seen), "window must be label-free"
    assert len(seen) == len(logins), ("window must surface every benign login once", len(seen), len(logins))

    # warmup is a distinct, deterministic, benign-only period for blue to learn the baseline
    wu = warmup_schedule(1337)
    assert wu == warmup_schedule(1337) and all(e["benign"] for e in wu), "warmup must be deterministic + benign"
    assert copy.deepcopy(a) == a   # purity: generating detections/windows never mutates the schedule

    # ── least-privilege stealth topology: a MULTI-HOP LOTL chain into the crown exists for a MINORITY
    # of entries, and MOST of the fleet has NO route — red must discover the chain, not be handed it ──
    assert legit_path("dba01", "db-core") == ["dba01", "db-bastion", "db-core"], legit_path("dba01", "db-core")
    assert legit_path("bkupctl", "db-core") == ["bkupctl", "backup", "db-core"], legit_path("bkupctl", "db-core")
    assert legit_path("ws01", "db-core") is None, "a fleet workstation has NO legitimate route to the crown"
    assert legit_path("app01", "db-core") is None, "a fleet app server has NO legitimate route to the crown"
    # entries are seed-derived, varied, and never the crown or a direct crown-edge owner (no cherry-pick)
    cap = stealth_capability()
    assert all(e not in (crown_edge_hosts() | {CROWN}) for e, _ in cap.values()), ("entry must never be crown/edge-owner", cap)
    assert len({e for e, _ in cap.values()}) >= 4, ("entries must vary across seeds", cap)
    # MOST entry candidates have no legitimate route; a minority have a discoverable chain (not targeted)
    n_capable = sum(1 for _e, p in cap.values() if p)
    cands = entry_candidates()
    capable_cands = [h for h in cands if legit_path(h, CROWN) is not None]
    assert 0 < len(capable_cands) < len(cands) / 2, \
        ("least privilege: a MINORITY of entry candidates may reach the crown", capable_cands, cands)
    # the seed set must admit BOTH outcomes (not all-one-way by construction, else the topology baked it)
    assert 0 < n_capable < len(cap), ("the seed set must mix stealth-capable and detection-forced", cap)

    # ── Constraint 1 (the spine) + Constraint 2 (add-only physical projection): topology_spec ──
    spec = topology_spec()
    # every registered benign host maps to a segment, and host_segment references only known segments
    assert set(spec["host_segment"]) == benign_hosts(), ("every benign host must map to a segment", spec["host_segment"])
    seg_names = {s[0] for s in spec["segments"]}
    assert set(spec["host_segment"].values()) <= seg_names, (spec["host_segment"], seg_names)
    assert spec["crown"] == CROWN and set(spec["crown_edges"]) == crown_edge_hosts()
    # the LOUD entry is a Tier-3 published (dmz) host with NO legitimate route to the crown
    le = spec["loud_entry"]["host"]
    assert spec["host_segment"][le] == "dmz", le
    assert legit_path(le, CROWN) is None, ("the loud entry must have NO legit route to the crown", le)
    assert (le, CROWN) not in benign_edges() and le not in crown_edge_hosts(), "no single-hop crown reach from the loud entry"
    # the Constraint-1 seam: a COMPOSED chain loud-entry -> ... -> crown-edge (>=2 hops) -> crown, where
    # the FIRST hop is anomalous (a harvestable reused cred, NOT a benign edge) and the rest rides the
    # already-REGISTERED legit admin edges — map-blind, no single cred/edge reaching the crown.
    seam = spec["cred_seam"]; chain = seam["chain"]
    assert chain[0] == le and chain[-1] == CROWN, chain
    assert chain[1] == seam["bootstrap_authorizes"], (chain, seam)
    edge_idx = next(i for i, h in enumerate(chain) if h in crown_edge_hosts())
    assert edge_idx >= 2, ("the crown-edge host must be reached in >=2 composed hops", chain)
    assert (seam["bootstrap_host"], seam["bootstrap_authorizes"]) not in benign_edges(), \
        ("the bootstrap hop must be anomalous (not a registered benign edge)", seam)
    for a, b in zip(chain[1:], chain[2:]):                     # dba01->db-bastion, db-bastion->db-core
        assert (a, b) in benign_edges(), ("the post-bootstrap chain must ride registered legit edges", (a, b))
    # add-only: topology_spec did not alter the logical model (the crown edge set is still the two Tier-1)
    assert crown_edge_hosts() == {"db-bastion", "backup"}, "topology_spec must not have changed the logical model"

    print(f"benign_baseline ok (realistic least-privilege topology: {len(logins)} SSH logins + "
          f"{len(flows)} flows/40 ticks, SAME classes red uses [T1021 + net.flow]; the crown db-core is "
          f"reached legitimately ONLY by Tier-1 {sorted(crown_edge_hosts())}, and only a MINORITY of "
          f"entry candidates have a discoverable multi-hop LOTL chain ({sorted(capable_cands)} of "
          f"{len(cands)}); the rest of the fleet has NO route. Entries seed-derived (N={len(STEALTH_SEEDS)}), "
          f"never crown/edge-owner; {n_capable}/{len(cap)} seeds stealth-capable (fall-out, not targeted). "
          f"Detections LABEL-FREE; warmup lets blue learn the baseline; re-derives cold from the seed)")
