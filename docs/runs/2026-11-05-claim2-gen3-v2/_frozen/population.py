"""Evolving population (Component D) — selection / inheritance over the
agent genome `{prompt, episodic_memory}`, with a MAP-Elites archive keyed by
strategy behavior-descriptors so tactics speciate instead of collapsing.

The dispatch is still through `swarm.gate.Gate.dispatch`, the fitness is still a
real objective (crown-jewel captured is ONE term of several), and
`swarm.degeneracy.detect` gates the result — a generation that collapses to one
strategy or one that produces no non-degenerate episodes is FLAGGED, not reported
as success.

T1 (arms-race dynamics): the old binary fitness (1.0 at crown+exfil, nothing to
climb after) pinned best_fitness at 1.0 and the coarse 2-D descriptor saturated
the archive at 4/16 cells. Fitness is now a CONTINUOUS multi-objective score
(`score_fitness`), selection is NOVELTY-weighted and FREQUENCY-penalized (a
behavior that the population already exhibits pays less, so looping a known
winner stops paying), and the descriptor is 4-D so distinct strategies land in
distinct cells. Fitness is computed in ONE place (`score_fitness`) from the
episode events, so the stub and the live llm_eval evaluator get the same
objective — the evaluator only has to produce the events.

Pure/offline. The evolutionary driver is deterministic given a seed, so a dry
run can show the archive diversifying without burning tokens; a live arms-race
driver can plug a real router/duel in by passing a different `evaluate` function
that writes to the hash-chained log. Child inherits parent's prompt + episodic
memory; MAP-Elites keeps the best variant per cell.
"""
import hashlib
import json
import random
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # runnable as script

from degeneracy import detect as detect_degeneracy
from arms_race import is_blue_detection   # A-D1: unified blue-detection predicate
from novelty import score_novelty


def _genome_hash(g):
    """Stable 12-char hash of a genome — provenance for inheritance claims."""
    body = json.dumps({"prompt": g["prompt"], "memory": g.get("memory", [])},
                      sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()[:12]


@dataclass
class Genome:
    prompt: str                 # the system/plan prompt the agent runs with
    memory: list = field(default_factory=list)  # episodic memory lessons (strings)
    # Phase 6: the tools this lineage INVENTED (swarm/authoring.py), {name -> source}. Evolution
    # now selects over strategy AND the tools each side authors; a child inherits its parent's
    # toolbook. Kept out of `hash` (which stays prompt+memory, so provenance + existing
    # checkpoints are stable) — authored_tools is inherited genome STATE, not identity.
    authored_tools: dict = field(default_factory=dict)
    parent: str = ""            # parent genome hash (empty = ancestor)
    generation: int = 0

    @property
    def hash(self):
        return _genome_hash({"prompt": self.prompt, "memory": self.memory})

    def mutate(self, rng, lesson_pool, prompt_mutators):
        """Return a child genome: inherit parent prompt+memory+authored_tools, apply ONE
        prompt mutator and append up to one new lesson. Deterministic given rng.
        Mutators take (prompt, rng) so persona-shift stays deterministic."""
        new_prompt = rng.choice(prompt_mutators)(self.prompt, rng)
        new_memory = list(self.memory)
        if lesson_pool and rng.random() < 0.7:
            new_memory.append(rng.choice(lesson_pool))
        return Genome(prompt=new_prompt, memory=new_memory,
                      authored_tools=dict(self.authored_tools),   # inherit the invented tools
                      parent=self.hash, generation=self.generation + 1)


# Behavioral PERSONAS (improvement #1): distinct operator styles that steer red
# toward DIFFERENT MAP-Elites cells, so the population illuminates the behavior
# space instead of all converging on one stealthy plan. The keywords are read by
# both the stub descriptor (offline) and the LLM plan prompt (live) — the research
# finding that scaffolding/decomposition beats model size (Incalmo, HPTSA): we
# engineer diversity into the prompts rather than hoping the model varies.
_PERSONAS = [
    "STYLE: stealthy — operate slow and low-noise; one quiet path to the crown; avoid repeating a blocked tool.",
    "STYLE: lateral — prefer in-scope lateral movement; pivot across MANY in-scope hosts before the objective.",
    "STYLE: noisy-fast — move fast; prioritize speed over stealth; it is fine to be loud if the objective is reached sooner.",
    "STYLE: persistent — plant redundant persistence early; assume eviction and prepare to re-establish via another path.",
    "STYLE: recon-heavy — recon and enumerate every service first; exploit only after thorough discovery.",
    "STYLE: minimal — use the FEWEST distinct tools possible; one technique, executed well, varied payload each retry.",
]


def seed_population(pop_size, base_prompt, personas=None, generation=0):
    """Seed a population that SPANS behavioral personas from generation 0, so the
    archive starts diverse instead of as identical clones (the live-diversity fix)."""
    personas = personas or _PERSONAS
    return [Genome(prompt=f"{base_prompt} {personas[i % len(personas)]}",
                   generation=generation)
            for i in range(pop_size)]


# Default prompt mutators — swap-in a different beat; keep each change minimal.
# The persona-shift mutator lets a child adopt a NEIGHBORING style so lineages
# explore new cells rather than drifting within one. Mutators take (prompt, rng).
def _shift_persona(p, rng):
    base = p.split(" STYLE:")[0]            # drop any existing STYLE: clause
    return f"{base} {rng.choice(_PERSONAS)}"


_DEFAULT_MUTATORS = [
    lambda p, rng: p + " Favor slow, low-noise beacons.",
    lambda p, rng: p + " Prefer in-scope lateral over new egress.",
    lambda p, rng: p + " Avoid repeating a blocked tool.",
    _shift_persona,                                        # jump to a new behavioral cell
    _shift_persona,
    lambda p, rng: p + " Stage loot in-scope before any egress.",
    lambda p, rng: p + " Use a varied payload for every retry.",
]

_DEFAULT_LESSONS = [
    "blue flagged C2 beacon last episode", "gate blocked ldap recon",
    "blue caught persistence via cron", "pivot to db unflagged",
    "egress to mailserver is blocked",
]

# Entry-technique classes for the behavior descriptor's first axis — keyed on the ONE engine's
# real tool vocabulary (swarm/live_agent._TOOLS), never the dead cascade names.
_ENTRY_CLASS = {
    "recon": 0, "scan": 0, "network_scan": 0, "discover": 0, "fingerprint": 0,
    "exploit": 1, "exploit_struts": 1,
    "pivot": 2, "lateral_movement": 2, "harvest": 2, "loot": 2,
    "persistence": 2, "shell": 2, "c2_beacon": 2, "author_tool": 2, "call_tool": 2,
}

# Multi-objective fitness weights (sum to 1.0 → score stays in [0,1]).
_W_OBJECTIVE, _W_DEPTH, _W_TECH, _W_EXPLOIT, _W_STEALTH = 0.40, 0.20, 0.15, 0.15, 0.10
# T6: manipulation is an ADDITIVE bonus (capped), rewarding red for displacing
# blue's posture via in-scope actions — on top of the base objective, never in
# place of it. Default 0.0 keeps every existing caller's score byte-identical.
_W_MANIP = 0.25

# Selection knobs. ponytail: fixed constants, promote to args only if a sweep needs them.
_FREQ_ALPHA = 0.5       # how hard a behavior already in the population is discounted
_NOVELTY_LAMBDA = 0.25  # weight of archive-distance novelty in cell competition
_EMERGENCE_BETA = 0.15  # bonus for diverging from the seeded playbook (live only)


def _red_allows(events):
    """data dicts of each authorized red action — the behavior spine."""
    return [(e.get("data") or {}) for e in events
            if e.get("actor") == "red" and e.get("action") == "gate.allow"]


def _has_red(events, actions, tools):
    """True if red ran one of `actions`, or a gate.allow for one of `tools`."""
    for e in events:
        if e.get("actor") != "red":
            continue
        if e.get("action") in actions:
            return True
        if e.get("action") == "gate.allow" and (e.get("data") or {}).get("tool") in tools:
            return True
    return False


def _objective_host(ground_truth):
    gt = ground_truth or {}
    obj = gt.get("objective")
    if isinstance(obj, dict):
        obj = obj.get("host")
    return gt.get("objective_host") or (obj if isinstance(obj, str) else None)


def _spine_confirmed(events):
    """Red's spine-CONFIRMED progress, read off the spine (state.mutate / crown.access), NEVER the
    dead cascade action-names: a crown read is a `crown.access` event; egress is a `state.mutate`
    with state 'exfil'. Fix #4."""
    crown = any(e.get("actor") == "red" and e.get("action") == "crown.access" for e in events)
    exfil = any(e.get("action") == "state.mutate" and (e.get("data") or {}).get("state") == "exfil"
                for e in events)
    return crown, exfil


def manipulation_score(events, ground_truth=None):
    """T6 term: red's measured displacement of blue's ATTENTION — read from BLUE's OWN logged
    `detect.posture` (fix #4: never any red self-reported deception beat). It is how far
    blue's PEAK detection probability sits above its probability on the true objective host: a
    feint 'wins' only when blue is demonstrably looking elsewhere, as blue itself recorded. The
    deterministic gate guarantees any such play stayed in-scope (out-of-scope never executes), so
    no separate in-scope gate on a red claim is needed."""
    by_host = {}
    for e in events:
        if e.get("actor") == "blue" and e.get("action") == "detect.posture":
            d = e.get("data") or {}
            h = d.get("host")
            if h is not None:
                by_host[h] = float(d.get("p_detect", 0.0) or 0.0)
    obj = _objective_host(ground_truth)
    if not by_host or obj not in by_host:
        return 0.0
    return round(min(1.0, max(0.0, max(by_host.values()) - by_host[obj])), 4)


def score_fitness(events, ground_truth=None, *, objective=None):
    """Continuous multi-objective fitness in [0,1] from an episode's events.

    Terms (base weights sum to 1): crown+exfil objective (one term, not the whole
    score), depth of kill chain (distinct hosts reached), distinct ATT&CK
    techniques, distinct exploits/tools exercised, and a stealth bonus. Plus an
    ADDITIVE, capped manipulation bonus (T6) when the events carry a successful
    in-scope deception. Pure. Single source of truth so the stub and the live
    evaluator agree.

    `objective` (A1): the INJECTED objective term. The LIVE/measured co-evo selection path passes
    the telemetry-gated reconciler verdict (1.0/0.0 from `duel.verdict.achieved`) so fitness can
    never reward a win the crown host's own telemetry did not witness. Left None — the dry/offline
    SHAPING path — the objective is derived from the spine (crown.access + 'exfil' state.mutate)
    exactly as before, so every existing caller is byte-identical."""
    allows = _red_allows(events)
    entry = (ground_truth or {}).get("entry") or "struts"

    tools = {d.get("tool") for d in allows}
    tools.discard(None)

    hosts = {d.get("resolved") or d.get("target") for d in allows}
    hosts.discard(None)
    hosts.discard(entry)

    techs = {(e.get("data") or {}).get("attack") for e in events
             if e.get("actor") == "red"}
    techs.discard(None)

    # Fix #4 / A1: the objective term. The dry/offline SHAPING path reads it off the spine
    # (crown.access + state.mutate 'exfil'), never the dead cascade action-names — a full objective
    # is the crown READ and egressed. The LIVE path INJECTS the telemetry-gated reconciler verdict
    # instead (see `live_red_score_fitness`), so a fabricated/unwitnessed win cannot score.
    if objective is None:
        # A1 side-wiring hardening: a reconciled/LIVE chain (one carrying a `duel.verdict` event)
        # must be scored on the telemetry-gated objective (gated_objective / SIDES["red_live"]),
        # NEVER the fidelity-blind spine read — regardless of which side instantiated the Evolver.
        # Refuse objective=None here so a mis-wired live loop cannot silently fall back to it. Dry
        # chains carry no duel.verdict, so they stay byte-identical.
        if any(e.get("action") == "duel.verdict" for e in events):
            raise ValueError(
                "score_fitness: a reconciled/live chain (duel.verdict present) must be scored with "
                "the telemetry-gated objective (population.gated_objective / SIDES['red_live']); "
                "refusing the fidelity-blind _spine_confirmed objective")
        crown, exfil = _spine_confirmed(events)
        objective = 1.0 if (crown and exfil) else 0.0
    else:
        objective = float(objective)

    # A-D1: the shared per-fire predicate (`is_blue_detection`). The previous
    # `startswith("detect")` matched nothing on the live vocabulary (a real fire is
    # `blue.detect.bernoulli`, never an action literally starting with "detect"), so stealth
    # always scored 1.0 on every live chain and the erosion signal read zero.
    detected = sum(1 for e in events if is_blue_detection(e))

    depth = min(len(hosts) / 3.0, 1.0)
    technique = min(len(techs) / 4.0, 1.0)
    exploit = min(len(tools) / 5.0, 1.0)
    stealth = 1.0 - min(detected / 5.0, 1.0)

    score = (_W_OBJECTIVE * objective + _W_DEPTH * depth + _W_TECH * technique
             + _W_EXPLOIT * exploit + _W_STEALTH * stealth)
    score += _W_MANIP * manipulation_score(events, ground_truth)   # T6: 0.0 unless blue's posture shifted
    return round(min(1.0, score), 4)


def gated_objective(events):
    """A1 — the LIVE co-evo objective term, read ONLY from the telemetry-gated reconciler verdict
    the engine writes on the chain (`duel.verdict`, produced by
    `live_arms_race_run._corroborated_objective`), NEVER `_spine_confirmed`. A crown.access +
    'exfil' state.mutate that the crown host's own telemetry did not witness carries
    `duel.verdict.achieved == False`, so it re-derives to 0.0. RAISES if no reconciler verdict is on
    the chain — fitness is never computed on an unreconciled duel (the hard driver assertion the
    brief requires). Re-derives cold from the committed chain."""
    verdicts = [e for e in events if e.get("action") == "duel.verdict"]
    if not verdicts or "achieved" not in (verdicts[-1].get("data") or {}):
        raise ValueError(
            "co-evo fitness requires a telemetry-gated reconciler verdict (duel.verdict.achieved) "
            "on the duel's chain before any fitness is computed; none present")
    return 1.0 if (verdicts[-1].get("data") or {})["achieved"] else 0.0


def live_red_score_fitness(events, ground_truth=None):
    """LIVE/measured red fitness (A1): identical SHAPING to `score_fitness` (depth / technique /
    exploit / stealth / manipulation), but the objective term is the telemetry-gated reconciler
    verdict (`gated_objective`), not the fidelity-blind spine read. This is the ONLY fitness the
    measured co-evo red may select on — the live side wires it (SIDES 'red_live'), and it RAISES on
    a duel carrying no reconciler verdict, so the live loop can never fall back to the
    fidelity-blind objective."""
    return score_fitness(events, ground_truth, objective=gated_objective(events))


# B-M1 (2026-10-30 co-evo erosion build) — per-parent lesson distillation. Grain fixed by the
# pre-registration: (technique, service-type, credential-source) transitions, plus (technique,
# target-service-type) for what was blocked. Host ROLES / IP / exact credentials are NEVER emitted,
# so a lesson distilled on-chain cannot smuggle a GT token into a future child's memory (the A5
# guard scans the memory channel both ways and would bite on any leak).
#
# The distiller reads ONLY red-authored chain events — never ground truth, never a system/benign
# event — and expresses each state.mutate as the triple that led to it: the TECHNIQUE recorded on
# the mutate itself, the SERVICE-TYPE red observed on the host via its OWN fingerprint/discovery
# (so a lesson learns "T1021 against an SSH service" without naming the host), and the CREDENTIAL
# SOURCE red used (its nearest prior harvest / cred_pivot gate.allow — abstracted to "harvested"
# or "none"). Blocked actions are expressed the same way: a blocked (tool, target-service-type)
# pair, so red learns the SHAPE of the gate's boundary without the hosts behind it. Returns None
# when red produced no state.mutate — nothing new to teach.
_CRED_TOOLS = {"harvest", "cred_pivot", "lateral_movement", "pivot"}
_OWN_STATES = {"foothold", "lateral", "exfil"}   # state.mutate states a lesson teaches ON


def _red_observed_services(events):
    """Build `{host|ip: service-type}` from RED's OWN observations. Reads red-authored discovery /
    fingerprint events; drops any entry whose SERVICE value is empty. Falls back to raw banner
    tokens (e.g. 'Apache-Coyote', 'OpenSSH') when a port→service mapping is not present. Keys may
    be host names OR ips as red learned them — we use VALUES only when distilling, so no key ever
    appears in the lesson output."""
    svc = {}
    for e in events:
        if e.get("actor") != "red":
            continue
        d = e.get("data") or {}
        if e.get("action") == "discovery":
            for h in (d.get("hosts") or []):
                services = h.get("services") or {}
                vals = [v for v in services.values() if v]
                if not vals:
                    continue
                v = vals[0]
                for key in (h.get("name"),) + tuple(h.get("ips") or []):
                    if key:
                        svc.setdefault(key, str(v))
        elif e.get("action") == "fingerprint":
            server = d.get("server") or d.get("fingerprint") or ""
            target = d.get("target") or d.get("ip") or d.get("host")
            # extract the first banner token (e.g. 'Apache-Coyote', 'OpenSSH') without versions.
            tok = ""
            for t in str(server).split():
                tok = t.split("/")[0]
                if tok:
                    break
            if target and tok:
                svc.setdefault(target, tok.lower())
    return svc


def _distill_lesson(events):
    """Distill ONE text lesson from red's chain for this episode. Role+technique+credential-source
    grain — NEVER a host name, IP, path or credential value, so the A5 map-blind guard sees no GT
    token. Returns None when there is nothing worth teaching (red produced no state.mutate).

    The lesson text is a `|`-joined sequence of transitions red actually drove:
      "WORKED: T1190 on http foothold | T1021 on ssh via harvested cred lateral | T1041 exfil
       (crown tier) ; BLOCKED: T1021 on mssql, T1041 on http"
    """
    svc = _red_observed_services(events)
    worked, blocked = [], []
    # Build the ordered "WORKED" sequence from each red state.mutate.
    for i, e in enumerate(events):
        if e.get("actor") != "red" or e.get("action") != "state.mutate":
            continue
        d = e.get("data") or {}
        state = d.get("state")
        if state not in _OWN_STATES:
            continue
        dst = d.get("dst") or d.get("host")
        technique = d.get("technique") or d.get("attack") or "T?"
        service_type = svc.get(dst, "unknown") if dst else "unknown"
        # nearest prior red gate.allow with a credential-sourcing tool
        cred = "none"
        for prior in reversed(events[:i]):
            if prior.get("actor") != "red" or prior.get("action") != "gate.allow":
                continue
            tool = (prior.get("data") or {}).get("tool")
            if tool in _CRED_TOOLS:
                cred = "harvested" if tool in {"harvest", "cred_pivot"} else "earned"
                break
        label = {"foothold": "foothold", "lateral": "lateral",
                 "exfil": "exfil (crown tier)"}[state]
        if cred == "none":
            worked.append(f"{technique} on {service_type} {label}")
        else:
            worked.append(f"{technique} on {service_type} via {cred} cred {label}")
    if not worked:
        return None
    # Build the BLOCKED set from red gate.block events; abstract the target to its service-type.
    seen = set()
    for e in events:
        if e.get("actor") != "red" or e.get("action") != "gate.block":
            continue
        d = e.get("data") or {}
        tool = d.get("tool", "?")
        target = d.get("resolved") or d.get("target")
        service_type = svc.get(target, "unknown") if target else "unknown"
        technique = d.get("attack", tool)
        pair = (technique, service_type)
        if pair in seen:
            continue
        seen.add(pair)
        blocked.append(f"{technique} on {service_type}")
    text = "WORKED: " + " | ".join(worked)
    if blocked:
        text += " ; BLOCKED: " + ", ".join(blocked)
    return text


def _is_memory_distilled(lesson):
    """Small marker test for the Unit-L / B-M1 selftests: True iff `lesson` has the structural
    shape of a distilled lesson (one of the WORKED/BLOCKED keywords), as opposed to a canned
    `_DEFAULT_LESSONS` entry. Keeps the test independent of the exact distilled text."""
    s = str(lesson or "")
    return "WORKED:" in s or "BLOCKED:" in s


def falco_degraded(events):
    """A2 — True if this episode's chain marks the Falco SYSCALL telemetry source DOWN: an
    `episode.degraded` with `modality_down == 'falco'`, or a `duel.verdict` carrying
    `falco_wired is False`. Such an episode has NO syscall witness, so a loot can never be
    corroborated — it must be EXCLUDED from co-evo fitness (dropped from the objective denominator),
    never scored as a red loss. Re-derives cold from the committed chain. (The dry/offline duels
    carry no such marker, so this is always False there — the shaping path is unchanged.)"""
    for e in events:
        d = e.get("data") or {}
        if e.get("action") == "episode.degraded" and d.get("modality_down") == "falco":
            return True
        if e.get("action") == "duel.verdict" and d.get("falco_wired") is False:
            return True
    return False


# ── Behavior descriptor (2026-11-04 redesign; WHY in docs/design-log/2026-11-04-descriptor-redesign-brief.md).
# The previous 4-D descriptor (entry, breadth, stealth, depth) SATURATED on the unified seam range:
# every crown-reaching run had one entry type (struts), >=2 distinct tools (breadth capped at 2),
# >1 detection (stealth could never be 0 — stealth was impossible here), and >=2 non-entry hosts
# (depth capped at 2), so the Nov-4 paid run put 9/9 episodes in the single cell (0,2,1,2),
# red_diversity = 1/54 (the first falsification the range caught). The axes below bind instead to
# signals that actually VARY on red's chains, each read from red's OWN chain events (the ground-truth
# firewall holds — no ground_truth is consulted). The computation is identical to the Section-1 bite
# test, scripts/validation/descriptor_bite_test.py (cross-checked there via --via-population).
_BD_CANONICAL_CVES = {"CVE-2017-5638", "S2-045"}
_BD_CANONICAL_MODULE = "struts2_content_type_ognl"
_BD_AUTHORED_TOOLS = {"author_tool", "call_tool"}


def _bd_ip2name(events):
    """IP->name map from the chain's own range.topology.nodes (each node: {name, ips:[...]})."""
    m = {}
    for e in events:
        if e.get("action") == "range.topology":
            for n in (e.get("data") or {}).get("nodes") or []:
                for ip in n.get("ips", []):
                    m[ip] = n.get("name")
            break
    return m


def _bd_flag_host_ips(events):
    ips = set()
    for e in events:
        if e.get("action") == "range.topology":
            for n in (e.get("data") or {}).get("nodes") or []:
                if n.get("flag"):
                    ips.update(n.get("ips", []))
            break
    return ips


def _bd_red_mutations(events):
    return [e for e in events if e.get("action") == "state.mutate" and e.get("actor") == "red"]


def _bd_turn_at(events, seq):
    """Turn in progress at a given seq = turn of the latest move.source at or before it.
    Returns None when the anchor seq is absent (seq-less synthetic/dry chains)."""
    if seq is None:
        return None
    t = None
    for e in events:
        s = e.get("seq")
        if s is not None and s <= seq and e.get("action") == "move.source":
            d = e.get("data") or {}
            if isinstance(d.get("turn"), int):
                t = d["turn"]
        if s is not None and s > seq:
            break
    return t


def _bd_path_idiom(events, ip2name):
    """Ordered dst-names of red's foothold|lateral mutations -> lateral path idiom.

    RANGE-SPECIFIC (backlog, flagged 2026-11-05): the host-NAME literals below are the unified seam
    range's. IP->name resolution is generic (range.topology), but these labels assume this topology.
    Claim 1's floor-shape sweep must generalize this (per-range map, or a structural path signature
    that doesn't name hosts) in the range-adding prereg amendment; the other three axes are already
    structural. Correct for claim 2's current range; do NOT change before the claim-1 range work."""
    seq_dst = []
    for e in _bd_red_mutations(events):
        d = e.get("data") or {}
        if d.get("state") in ("foothold", "lateral"):
            dst = d.get("dst")
            seq_dst.append(ip2name.get(dst, dst))
    if seq_dst[:3] == ["web01", "dba01", "db-bastion"]:
        return 0   # canonical
    if seq_dst[:2] == ["web01", "dba02"]:
        return 1   # alt-dba
    return 2       # off-seam (incl. runs that never reach the crown)


def _bd_foothold_technique(events):
    """First foothold mutation's method + the move.source that drove it -> technique class."""
    first_fh = next((e for e in _bd_red_mutations(events)
                     if (e.get("data") or {}).get("state") == "foothold"), None)
    if first_fh is None:
        return 2   # no foothold -> non-canonical bucket
    d = first_fh.get("data") or {}
    cve = (d.get("cve") or "").upper()
    module = (d.get("module") or "").lower()
    prev_tool = None
    fh_seq = first_fh.get("seq")
    if fh_seq is not None:
        for e in events:
            s = e.get("seq")
            if s is not None and s < fh_seq and e.get("action") == "move.source":
                prev_tool = (e.get("data") or {}).get("tool")
            if s is not None and s >= fh_seq:
                break
    if prev_tool in _BD_AUTHORED_TOOLS:
        return 2   # authored
    if any(c in cve for c in _BD_CANONICAL_CVES) or _BD_CANONICAL_MODULE in module:
        return 0   # canonical-CVE
    if d.get("via") == "msf" and module:
        return 1   # msf-module (non-canonical)
    return 2       # other


def _bd_crown_turn(events, flag_ips):
    """Turn of the first exfil state.mutate, else first loot move.source on the flag host (else None)."""
    for e in _bd_red_mutations(events):
        if (e.get("data") or {}).get("state") == "exfil":
            return _bd_turn_at(events, e.get("seq"))
    for e in events:
        if e.get("action") == "move.source" and (e.get("data") or {}).get("tool") == "loot":
            host = ((e.get("data") or {}).get("args") or {}).get("host")
            if host in flag_ips:
                return (e.get("data") or {}).get("turn")
    return None


def _bd_turn_bin(turn):
    # Fixed bootstrap thresholds (the brief's <9-finite-obs rule; the live quantile reduces to these
    # on thin data). never-reach -> late.
    if turn is None:
        return 2
    if turn <= 20:
        return 0
    if turn <= 33:
        return 1
    return 2


def _bd_cred_idiom(events, crown_turn):
    """Distinct harvested creds red consumed (pivot move.source args.key) before the crown read."""
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


# Behavior-descriptor axis cardinalities (product = archive size).
_BD_CARD = (3, 3, 3, 2)   # path_idiom, foothold_technique, turn_bin, cred_idiom
DESCRIPTOR_CELLS = _BD_CARD[0] * _BD_CARD[1] * _BD_CARD[2] * _BD_CARD[3]  # 54


def behavior_descriptor(episode_events, ground_truth=None):
    """4-D MAP-Elites descriptor keyed on signals that VARY on red's live chains.

    OLD axes (entry, breadth, stealth, depth) saturated on the unified seam range — every
    crown-reaching run had one entry type (struts), >=2 tools (breadth cap 2), >1 detection
    (stealth was impossible here, never 0), and >=2 non-entry hosts (depth cap 2) — so the Nov-4
    paid run put 9/9 episodes in the single cell (0,2,1,2), red_diversity = 1/54 (the first
    falsification the range caught; WHY in docs/design-log/2026-11-04-descriptor-redesign-brief.md).

    NEW axes, all read from red's OWN chain (GT firewall: ground_truth is accepted for call-site
    compatibility but is NEVER referenced in this body):
      - path_idiom        (0..2): the lateral path red took (canonical / alt-dba / off-seam)
      - foothold_technique(0..2): how it got the first foothold (canonical-CVE / msf-module / authored)
      - turn_bin          (0..2): when it reached the crown (early <=20 / mid 21-33 / late >33 or never)
      - cred_idiom        (0..1): bootstrap-only (<=1 harvested cred) vs chained (2+)
    """
    ip2name = _bd_ip2name(episode_events)
    flag_ips = _bd_flag_host_ips(episode_events)
    crown_turn = _bd_crown_turn(episode_events, flag_ips)
    return (_bd_path_idiom(episode_events, ip2name),
            _bd_foothold_technique(episode_events),
            _bd_turn_bin(crown_turn),
            _bd_cred_idiom(episode_events, crown_turn))


# ───────────────────────────── BLUE side (Phase 6) ─────────────────────────
# The SAME MAP-Elites machinery (Genome/MapElitesArchive/Evolver), parameterized by side — NOT a
# second population module. Only the personas, the behavior descriptor, and the fitness differ,
# and blue's fitness is sourced entirely from TELEMETRY (sensor detections, the IR scoreboard,
# crown held vs lost), never a blue self-report.
_BLUE_PERSONAS = [
    "STYLE: tripwire — maximize detection breadth; alert on anything anomalous, accept false positives.",
    "STYLE: surgical — contain precisely; act only on corroborated detections; keep false positives near zero.",
    "STYLE: aggressive-contain — evict on first detection; accept collateral to stop the kill chain early.",
    "STYLE: crown-guard — concentrate sensors and containment on the crown-jewel host and its approaches.",
    "STYLE: patient — correlate across sources before containing; trade some dwell for precision.",
    "STYLE: broad-sensor — run every sensor source for wide coverage; tolerate noise.",
]

_BLUE_MUTATORS = [
    lambda p, rng: p + " Raise sensor sensitivity on the crown approaches.",
    lambda p, rng: p + " Contain on first corroborated detection.",
    lambda p, rng: p + " Correlate two sources before acting to cut false positives.",
    lambda p, rng: p.split(" STYLE:")[0] + " " + rng.choice(_BLUE_PERSONAS),   # jump to a new cell
    lambda p, rng: p.split(" STYLE:")[0] + " " + rng.choice(_BLUE_PERSONAS),
    lambda p, rng: p + " Widen telemetry coverage to a new source.",
]

_BLUE_LESSONS = [
    "red re-entered via cron after eviction", "beacon jitter evaded the eventlog sensor",
    "lateral pivot to db went undetected", "crown read caught by the file-open sensor",
    "a feint pulled attention off the objective last episode",
]

_BD_BLUE_CARD = (3, 3, 2, 2)   # detection-breadth, containment-aggressiveness, FP-cost, crown-protected
BLUE_DESCRIPTOR_CELLS = _BD_BLUE_CARD[0] * _BD_BLUE_CARD[1] * _BD_BLUE_CARD[2] * _BD_BLUE_CARD[3]  # 36


def _blue_detections(events):
    return [e for e in events if is_blue_detection(e)]   # A-D1: shared predicate


def _blue_containments(events):
    out = []
    for e in events:
        if e.get("actor") != "blue":
            continue
        a = e.get("action")
        if a in ("blue.contain", "blue.remove", "blue.restore", "contain_host"):
            out.append(e)
        elif a == "blue.triage" and (e.get("data") or {}).get("action") in ("remove", "restore"):
            out.append(e)
    return out


def blue_behavior_descriptor(episode_events, ground_truth=None):
    """4-D MAP-Elites descriptor for a DEFENDER genome (telemetry-derived):
      - breadth_bin (0..2): distinct detection sources/techniques blue produced, capped at 2
      - contain_bin (0..2): containment/eviction actions blue took, capped at 2
      - fp_bin      (0..1): 0 if no false-positive detections, else 1 (the FP-cost axis)
      - crown_bin   (0..1): 1 if the crown was PROTECTED (not read or egressed), else 0
    Mirrors the red descriptor's shape so one archive machinery serves both sides."""
    dets = _blue_detections(episode_events)
    sources = {(e.get("data") or {}).get("source") or (e.get("data") or {}).get("basis")
               or e.get("action") for e in dets}
    sources.discard(None)
    breadth_bin = min(len(sources), 2)
    contain_bin = min(len(_blue_containments(episode_events)), 2)
    fp = sum(1 for e in dets if (e.get("data") or {}).get("false_positive"))
    fp_bin = 0 if fp == 0 else 1
    crown, exfil = _spine_confirmed(episode_events)
    crown_bin = 0 if (crown or exfil) else 1          # protected iff red never read or egressed it
    return (breadth_bin, contain_bin, fp_bin, crown_bin)


def blue_score_fitness(events, ground_truth=None):
    """Continuous DEFENDER fitness in [0,1], sourced ONLY from telemetry (fix #4 — never a blue
    self-report): crown held vs lost, detection recall over red's spine-confirmed malicious
    actions, containment speed (IR scoreboard MTTC), and low dwell. Weights sum to 1."""
    from arms_race import scoreboard, _MALICIOUS   # spine-confirmed malicious set + IR metrics
    sb = scoreboard(events)

    mal = [e for e in events if e.get("actor") == "red" and e.get("action") in _MALICIOUS]
    dets = _blue_detections(events)
    recall = min(len(dets), len(mal)) / len(mal) if mal else 0.0

    # A1 watch-item (Group B): on a reconciled/LIVE chain, crown-held is read from the telemetry-gated
    # verdict (duel.verdict.achieved), NEVER the fidelity-blind spine — so blue is not scored against a
    # red "win" the crown host's own telemetry never witnessed (a fabricated/unreconciled loot). Dry
    # chains carry no duel.verdict, so they keep the spine read (byte-identical).
    _verdicts = [e for e in events if e.get("action") == "duel.verdict"]
    if _verdicts:
        crown_held = 0.0 if (_verdicts[-1].get("data") or {}).get("achieved") else 1.0
    else:
        crown, exfil = _spine_confirmed(events)
        crown_held = 0.0 if (crown or exfil) else 1.0

    mttc = sb.get("mttc_steps")
    dwell = sb.get("dwell_steps")
    contain_speed = 1.0 - min((mttc if mttc is not None else 10) / 10.0, 1.0)
    low_dwell = 1.0 - min((dwell if dwell is not None else 10) / 10.0, 1.0)

    score = (0.40 * crown_held + 0.25 * recall + 0.20 * contain_speed + 0.15 * low_dwell)
    return round(min(1.0, max(0.0, score)), 4)


@dataclass
class SideSpec:
    """Everything that differs BETWEEN sides. The Evolver/MapElitesArchive machinery is identical;
    it reads its scoring, descriptor, personas and seed from here, so red and blue run on ONE
    population module parameterized by `side`."""
    name: str
    personas: list
    prompt_seed: str
    score_fitness: object        # (events, ground_truth) -> float in [0,1]
    behavior_descriptor: object  # (events, ground_truth) -> cell tuple
    cells: int
    mutators: list
    lesson_pool: list
    # A2: optional episode-EXCLUSION predicate (events -> bool). An episode it flags is dropped from
    # the generation's fitness (not scored as a loss) — the live red side excludes a falco-down
    # (syscall-source-absent) episode. None (the dry/offline default) excludes nothing, byte-identical.
    exclude_episode: object = None
    # B-M1 (2026-10-30 co-evo erosion build): optional PER-PARENT lesson distiller — (events) -> str
    # or None. When set, Evolver.tick caches a distilled lesson per genome (keyed by hash); the
    # breeding step feeds the parent's own lesson to Genome.mutate instead of the canned
    # `lesson_pool`. The output must be GROUND-TRUTH-FREE (role + technique + credential source,
    # not host names / IPs / credentials) — the A5 map-blind guard bites unchanged on any accidental
    # leak. None (every pre-B-M1 side) leaves the canned lesson pool exactly as it was.
    distill_lesson: object = None
    # B-M1: optional memory CLEAR on breed — when True, a child's inherited memory is reset to []
    # after `Genome.mutate`. The "memory-off" control arm uses this: no inherited lesson between
    # episodes, so each generation faces a fresh context. False (every pre-B-M1 side) keeps the
    # inherited memory, byte-identical.
    clear_memory_on_breed: bool = False


SIDES = {
    "red": SideSpec("red", _PERSONAS, "Reach the crown jewels through in-scope hosts.",
                    score_fitness, behavior_descriptor, DESCRIPTOR_CELLS,
                    _DEFAULT_MUTATORS, _DEFAULT_LESSONS),
    # A1: the LIVE/measured red side. Same personas / descriptor / mutators / lessons as the dry
    # 'red' side — ONLY the fitness differs: its objective term is the telemetry-gated reconciler
    # verdict (`live_red_score_fitness`), so the measured co-evo loop cannot select on a
    # fidelity-blind win. The dry 'red' side keeps the spine-read shaping objective (byte-identical).
    "red_live": SideSpec("red", _PERSONAS, "Reach the crown jewels through in-scope hosts.",
                         live_red_score_fitness, behavior_descriptor, DESCRIPTOR_CELLS,
                         _DEFAULT_MUTATORS, _DEFAULT_LESSONS, exclude_episode=falco_degraded),
    # B-M1 (2026-10-30 co-evo erosion build) — the TREATMENT arm. Same measured fitness /
    # descriptor / personas / mutators as `red_live`; the only thing that differs is the memory
    # channel: `lesson_pool` is empty and `distill_lesson` is wired, so each child's memory inherits
    # the parent's distilled lesson from the parent's OWN prior episode (role+technique+credential
    # source grain, GT-free by construction). The arms-race adaptation signal is
    # `erosion(memory_on) - erosion(memory_off)`.
    "red_live_memory_on": SideSpec(
        "red", _PERSONAS, "Reach the crown jewels through in-scope hosts.",
        live_red_score_fitness, behavior_descriptor, DESCRIPTOR_CELLS,
        _DEFAULT_MUTATORS, lesson_pool=[], exclude_episode=falco_degraded,
        distill_lesson=_distill_lesson),
    # B-M1 — the CONTROL arm. Empty lesson pool + clear_memory_on_breed: each generation faces a
    # FRESH context (no inherited lesson between episodes). Still goes through the same measured
    # scorer / descriptor / exclusion as `red_live_memory_on`, so arm comparison is apples-to-apples.
    "red_live_memory_off": SideSpec(
        "red", _PERSONAS, "Reach the crown jewels through in-scope hosts.",
        live_red_score_fitness, behavior_descriptor, DESCRIPTOR_CELLS,
        _DEFAULT_MUTATORS, lesson_pool=[], exclude_episode=falco_degraded,
        distill_lesson=None, clear_memory_on_breed=True),
    "blue": SideSpec("blue", _BLUE_PERSONAS,
                     "Detect and contain the intrusion; protect the crown jewels.",
                     blue_score_fitness, blue_behavior_descriptor, BLUE_DESCRIPTOR_CELLS,
                     _BLUE_MUTATORS, _BLUE_LESSONS),
}


def _cell_novelty(cell, occupied):
    """Behavioral novelty = normalized min Hamming distance from `cell` to any
    occupied archive cell. 1.0 when the archive is empty or the cell is maximally
    far. Works offline (no ground_truth needed) — the QD exploration pressure."""
    if not occupied:
        return 1.0
    dims = len(cell)
    return min(sum(1 for a, b in zip(cell, c) if a != b) for c in occupied) / dims


class MapElitesArchive:
    """Behavior-indexed archive: at most one elite genome per cell. A child
    enters a cell only if it beats the current occupant's QD score; ties favor
    the newer genome so the frontier can drift. Diversity (= cell occupancy /
    total cells) is the number the brief wants to climb over generations."""

    def __init__(self, cells=DESCRIPTOR_CELLS):
        self.by_cell = {}    # cell -> (qd_score, genome, meta)
        self.cells = cells

    def add(self, cell, qd_score, genome, meta=None):
        prev = self.by_cell.get(cell)
        if prev is None or qd_score > prev[0] or (qd_score == prev[0]
                                                  and genome.generation > prev[1].generation):
            self.by_cell[cell] = (qd_score, genome, dict(meta or {}))
            return True
        return False

    def diversity(self):
        return len(self.by_cell) / self.cells

    def best(self):
        """Elite with the highest BASE fitness (not QD score) — the objective
        progress, not the exploration bonus."""
        if not self.by_cell:
            return None
        return max(self.by_cell.values(),
                   key=lambda t: t[2].get("base_fitness", t[0]))

    def best_fitness(self):
        b = self.best()
        return b[2].get("base_fitness", b[0]) if b else 0.0

    def dump(self):
        return [{"cell": list(c), "qd_score": f, "genome": asdict(g), "meta": m}
                for c, (f, g, m) in self.by_cell.items()]

    def save(self, path):
        """Persist the archive to a host JSON file (decoupled from the ephemeral
        range): the evolved MAP-Elites frontier survives a process exit."""
        Path(path).write_text(json.dumps({"cells": self.cells, "entries": self.dump()},
                                         indent=2))

    @classmethod
    def load(cls, path):
        """Rebuild an archive from a save() file. Cells (tuples) and Genomes are
        reconstructed exactly, so diversity()/best() match the saved frontier."""
        blob = json.loads(Path(path).read_text())
        arc = cls(cells=blob["cells"])
        for e in blob["entries"]:
            arc.by_cell[tuple(e["cell"])] = (e["qd_score"], Genome(**e["genome"]),
                                             dict(e.get("meta") or {}))
        return arc


def _evaluate_stub(genome, seed):
    """Dry-mode evaluator: produce a synthetic episode log that varies with the
    genome so dynamics are real but no tokens are spent. A live driver swaps
    this out for a function that runs the duel through the real gate and router.

    Returns (events, _fitness). NOTE: evolve recomputes fitness from events via
    `score_fitness`, so the scalar here is only for direct callers; the events
    are what matter."""
    rng = random.Random(f"{seed}:{_genome_hash({'prompt': genome.prompt, 'memory': genome.memory})}")
    p = genome.prompt
    events = []
    # Real-engine tool vocabulary (swarm/live_agent._TOOLS) — no cascade names.
    tools = ["scan", "exploit", "fingerprint", "pivot", "loot"]
    rng.shuffle(tools)
    # PERSONA cues (improvement #1) steer the synthetic episode toward DIFFERENT
    # descriptor cells, so a persona-seeded population spreads across the archive.
    if "minimal" in p:                     # few distinct tools (narrow breadth)
        tools = tools[:3]
    if "persistent" in p:                  # plant persistence -> extra tool/depth
        tools = tools + ["persistence"]
    if "recon-heavy" in p and "scan" in tools:
        tools = ["scan"] + [t for t in tools if t != "scan"]   # recon-first entry
    stealth = 0.3 + 0.1 * sum(k in p for k in ("slow", "low-noise", "varied", "Avoid repeating"))
    if "noisy-fast" in p or "fast" in p:   # loud -> more detections (low stealth bin)
        stealth = max(0.05, stealth - 0.3)
    reached_crown = False
    # Prompt cues steer which hosts red explores, so a varied genome reaches more
    # hosts (depth) and the richer descriptor can speciate it.
    host_cycle = ["struts", "db", "jenkins"]
    lateral = ("lateral" in p or "persistent" in p)
    for i, t in enumerate(tools):
        target = host_cycle[i % len(host_cycle)] if lateral else "struts"
        events.append({"actor": "red", "action": "gate.allow",
                       "data": {"tool": t, "target": target, "attack": f"T{1190 + i}"}})
        # spine-confirmed progress: a foothold on first exploit, laterals as it moves inward.
        if t == "exploit":
            state = "foothold" if not reached_crown else "lateral"
            events.append({"actor": "red", "action": "state.mutate",
                           "data": {"state": state, "dst": target, "technique": f"T{1190 + i}"}})
        if t == "loot" and lateral and target == "jenkins":
            reached_crown = True
            events.append({"actor": "red", "action": "crown.access",
                           "data": {"host": "jenkins", "sensitive_data": True, "attack": "T1213"}})
            events.append({"actor": "red", "action": "state.mutate",
                           "data": {"state": "exfil", "dst": "jenkins", "nbytes": 2048}})
        if rng.random() > stealth:
            events.append({"actor": "blue", "action": "detect.eventlog",
                           "data": {"description": f"{t}: blind telemetry", "source": "eventlog"}})
    return events, score_fitness(events)


class Evolver:
    """Stateful MAP-Elites evolver: ONE archive + population that PERSIST across
    `tick()` calls, so a live driver can interleave a generation of real episodes
    with one evolutionary step and the population actually evolves across the
    driver's generations.

    The old `evolve(generations=1)`-per-tick pattern re-seeded a fresh archive and
    an unmutated clone population every call, so the archive pinned at 1/cells
    forever (the 22-gen live-sweep null). Holding the state here is the fix.

    Selection is novelty-weighted (archive-distance + optional emergence bonus)
    and frequency-penalized (a behavior the population already shows pays less).
    Fitness is recomputed from the episode events via `score_fitness`, so the stub
    and the live evaluator share one objective — the evaluator only makes events.
    """

    def __init__(self, seed=1337, pop_size=8, cells=None,
                 prompt_seed=None, mutators=None, lesson_pool=None, ground_truth=None,
                 personas=None, side="red"):
        # Phase 6: the side selects which scoring/descriptor/personas/seed this evolver uses — ONE
        # machinery, parameterized. Explicit args still override the side's defaults.
        spec = SIDES[side]
        self.side = side
        self._score = spec.score_fitness
        self._descriptor = spec.behavior_descriptor
        self._exclude = spec.exclude_episode   # A2: episodes this flags are dropped from fitness
        # B-M1: per-parent lesson distillation + memory-channel arm selection.
        self._distill_lesson = spec.distill_lesson
        self._clear_memory_on_breed = spec.clear_memory_on_breed
        self._distilled = {}         # genome.hash -> distilled lesson text (treatment arm)
        self.rng = random.Random(seed)
        self.pop_size = pop_size
        self.mutators = mutators or spec.mutators
        # B-M1: an empty `lesson_pool` on the spec is a DELIBERATE arm setting (memory_on uses the
        # per-parent distilled lesson; memory_off has no inherited lesson at all), so the old
        # `lesson_pool or spec.lesson_pool` would silently swap it for the dry side's canned pool.
        # Prefer the explicit arg when non-None; else take the spec's exact value (including []).
        self.lesson_pool = lesson_pool if lesson_pool is not None else spec.lesson_pool
        self.ground_truth = ground_truth
        self.archive = MapElitesArchive(cells=cells or spec.cells)
        # Seed ACROSS personas so the population spans behavioral cells from gen 0
        # (improvement #1). personas=[] opts out (identical-clone legacy behavior).
        self.population = seed_population(
            pop_size, prompt_seed if prompt_seed is not None else spec.prompt_seed,
            personas=(spec.personas if personas is None else (personas or [""])))
        self.inheritance_proofs = 0
        self.gen = 0
        self.last_gen_events = []    # every genome's realized events this tick (T2: blue's telemetry)

    def tick(self, evaluate=None, eval_seed=None):
        """Evaluate the current population, update the PERSISTENT archive, breed
        the next population. Returns this generation's history dict. Deterministic
        given the constructor seed and the `eval_seed` sequence.

        Side effect: `self.last_gen_events` holds this generation's red behaviors
        (all genomes' events) so a co-evolving blue monitor can score + refit on
        them — the population is the adapting adversary the learned monitor faces."""
        evaluate = evaluate or _evaluate_stub
        if eval_seed is None:
            eval_seed = self.gen
        gt = self.ground_truth
        gen_entries = 0
        gen_degenerate = 0
        gen_excluded = 0          # A2: episodes dropped from fitness (e.g. falco-down syscall source)
        gen_prompts = set()
        gen_cell_counts = Counter()   # frequency-dependent selection, this generation
        self.last_gen_events = []
        # B-M1 — reset the per-genome lesson cache for this tick so a child's inherited lesson is
        # ALWAYS distilled from the parent's MOST RECENT episode (never a stale one from an
        # earlier tick).
        self._distilled = {}
        for g in self.population:
            events, _ = evaluate(g, eval_seed)
            self.last_gen_events.extend(events)
            # B-M1 — distill the per-genome lesson BEFORE the degeneracy / exclusion seats, so even
            # a lesson from an excluded/degenerate episode is reserved on the cache: if its child
            # is bred from this genome's archive-elite entry (an older tick), the stale cache miss
            # falls back to the spec's `lesson_pool` naturally. The lesson is a pure read of red's
            # own chain, GT-free by construction (role+technique+credential-source grain only).
            if self._distill_lesson is not None:
                try:
                    _lesson = self._distill_lesson(events)
                except Exception:                                   # noqa: BLE001
                    _lesson = None
                if _lesson:
                    self._distilled[g.hash] = _lesson
            # A-S1 (2026-10-30 co-evo selection build): compute the telemetry-corroborated win
            # signal from the chain itself, so a WITNESSED win is always scored and offered to the
            # archive and never degenerate-excluded; and so `detect_degeneracy` sees the real win /
            # turn-cap signals it was designed to use (previously both were hard-coded to None /
            # False, which combined with the pre-A-S2 rule dropped two of three pilot wins:
            # archive_entries=0, best_fitness=0, red_cells=0, selection inert).
            #
            # Precedence: a `duel.verdict` on the chain is the telemetry-gated reconciler verdict —
            # the only ground truth the live/measured arm may key on. Only chains WITHOUT a verdict
            # (the pure offline STUB path, `_evaluate_stub` / dry selftests) fall back to the
            # fidelity-blind spine read (crown.access OR state.mutate 'exfil'), which is what the
            # stub emits. The exclusion seat (A2 falco-down, below) runs BEFORE the win-based
            # score-anyway bypass: a falco-down episode has no syscall witness and cannot be a
            # corroborated win regardless of what red claims.
            has_verdict = any(e.get("action") == "duel.verdict" for e in events)
            if has_verdict:
                won = (gated_objective(events) == 1.0)       # raises on a bad/missing verdict
            else:
                _crown, _exfil = _spine_confirmed(events)
                won = bool(_crown or _exfil)
            # `hit_turn_cap` from the engine's own duel.outcome marker when present. Dry chains
            # with no outcome leave it False — the detector's turn-cap reason bites only when a
            # runner explicitly records it, exactly as pre-A-S1.
            hit_turn_cap = any(e.get("action") == "duel.outcome"
                               and (e.get("data") or {}).get("outcome") == "turn_cap"
                               for e in events)
            # A2: a modality-degraded episode (e.g. falco-down syscall source) is EXCLUDED from
            # fitness — dropped from the generation's objective denominator, never scored as a loss.
            # Its events stay in `last_gen_events` so the FLOOR invariant still covers it. This runs
            # BEFORE the A-S1 win-always-scored bypass: no syscall witness ==> no corroborated win.
            if self._exclude and self._exclude(events):
                gen_excluded += 1
                continue
            deg = detect_degeneracy(events, reached_objective=won, hit_turn_cap=hit_turn_cap)
            # A-S1: a telemetry-corroborated win is ALWAYS scored and offered to the archive — it is
            # never degenerate-excluded, regardless of the shape of its tail (the pilot's wins had
            # repeated allowed cred_pivot/exfiltrate beats that the pre-A-S2 rule flagged). The
            # detector itself (A-S2) now clears its reasons when reached_objective is True, so
            # `deg["degenerate"]` is already False on a corroborated win; this guard is the explicit
            # belt + suspenders.
            if deg["degenerate"] and not won:
                gen_degenerate += 1
                continue
            base = self._score(events, gt)
            cell = self._descriptor(events, gt)
            # Frequency penalty: a behavior the population already shows pays less.
            eff = base / (1.0 + _FREQ_ALPHA * gen_cell_counts[cell])
            # Novelty-weighted QD: archive-distance exploration pressure + (live)
            # emergence-vs-playbook bonus, so a novel strategy can claim a cell.
            qd = eff + _NOVELTY_LAMBDA * _cell_novelty(cell, set(self.archive.by_cell))
            if gt and self.side in ("red", "red_live"):  # emergence-vs-playbook is a red-only measure
                emergence = score_novelty(events, gt)["emergence_score"]
                qd += _EMERGENCE_BETA * min(emergence / 3.0, 1.0)
            gen_cell_counts[cell] += 1
            if self.archive.add(cell, qd, g, meta={"seed": eval_seed,
                                                   "n_events": len(events),
                                                   "base_fitness": base}):
                gen_entries += 1
            gen_prompts.add(g.prompt)
        # Selection: pick elites, breed children for the next gen.
        elites = [g for _, g, _ in self.archive.by_cell.values()]
        next_pop = []
        for _ in range(self.pop_size):
            parent = self.rng.choice(elites) if elites else self.population[0]
            # B-M1 (2026-10-30 co-evo erosion build) — per-parent lesson pool for the memory-on
            # arm: if a lesson was distilled from THIS parent's prior episode, feed it to
            # Genome.mutate as the parent's pool so the child inherits the parent's own
            # tradecraft lesson (not a canned string). Falls back to `self.lesson_pool` when no
            # per-parent lesson is cached — a genome bred from an archive elite logged in an
            # earlier tick is handled by this fallback.
            pool = ([self._distilled[parent.hash]]
                    if (self._distill_lesson is not None and parent.hash in self._distilled)
                    else self.lesson_pool)
            child = parent.mutate(self.rng, pool, self.mutators)
            # B-M1 — the memory-OFF control arm: a child inherits no lesson between episodes, so
            # each generation faces a fresh context. The parent's own memory is still the thing
            # Genome.mutate copied; we clear it on the child here so the inheritance invariant
            # below is still well-defined (prefix of an empty list is empty).
            if self._clear_memory_on_breed:
                child.memory = []
            if (child.parent == parent.hash
                    and child.memory[: len(parent.memory)] == parent.memory):
                self.inheritance_proofs += 1
            next_pop.append(child)
        history = {
            "generation": self.gen,
            "pop_size": len(self.population),
            "archive_entries": gen_entries,
            "archive_diversity": round(self.archive.diversity(), 4),
            "degenerate_episodes": gen_degenerate,
            "excluded_episodes": gen_excluded,          # A2: modality-degraded, dropped from fitness
            "distinct_prompts": len(gen_prompts),
            "best_fitness": round(self.archive.best_fitness(), 4),
        }
        self.population = next_pop
        self.gen += 1
        return history

    def save(self, path):
        """Checkpoint the evolver's DYNAMIC state to a host JSON file so a long
        sweep can stop and continue (brief §3 gap #2): generation counter,
        current population, the MAP-Elites archive, inheritance tally, and the RNG
        state (so resumed ticks are byte-for-byte identical to an uninterrupted
        run). Static config (mutators/lesson_pool/ground_truth/personas) is NOT
        serialized — pass the SAME config to restore(). Zero model calls."""
        st = self.rng.getstate()
        Path(path).write_text(json.dumps({
            "gen": self.gen, "pop_size": self.pop_size,
            "inheritance_proofs": self.inheritance_proofs,
            "population": [asdict(g) for g in self.population],
            "archive": {"cells": self.archive.cells, "entries": self.archive.dump()},
            "rng_state": [st[0], list(st[1]), st[2]],
        }, indent=2))

    def restore(self, path):
        """Reload a save() checkpoint onto THIS evolver (built with the same
        config). Returns self so `Evolver(**cfg).restore(p)` reads naturally."""
        blob = json.loads(Path(path).read_text())
        self.gen = blob["gen"]
        self.pop_size = blob["pop_size"]
        self.inheritance_proofs = blob["inheritance_proofs"]
        self.population = [Genome(**g) for g in blob["population"]]
        self.archive = MapElitesArchive(cells=blob["archive"]["cells"])
        for e in blob["archive"]["entries"]:
            self.archive.by_cell[tuple(e["cell"])] = (
                e["qd_score"], Genome(**e["genome"]), dict(e.get("meta") or {}))
        s = blob["rng_state"]
        self.rng.setstate((s[0], tuple(s[1]), s[2]))
        return self


def evolve(seed=1337, generations=3, pop_size=8, cells=None,
           prompt_seed="Reach the crown jewels through in-scope hosts.",
           evaluate=None, mutators=None, lesson_pool=None, ground_truth=None):
    """Deterministic evolutionary loop — a thin wrapper over a single persistent
    `Evolver`. Returns per-generation stats so a dashboard / self-check can see
    the archive diversifying. A live driver that needs to interleave real episodes
    between generations should hold an `Evolver` and call `.tick()` itself."""
    ev = Evolver(seed=seed, pop_size=pop_size, cells=cells, prompt_seed=prompt_seed,
                 mutators=mutators, lesson_pool=lesson_pool, ground_truth=ground_truth)
    history = [ev.tick(evaluate, eval_seed=seed + gen) for gen in range(generations)]
    collapsed = (ev.archive.diversity() <= 1.0 / ev.archive.cells and generations > 1)
    return {
        "archive": ev.archive,
        "history": history,
        "generations": generations,
        "pop_size": pop_size,
        "inheritance_proofs": ev.inheritance_proofs,
        "collapsed": collapsed,     # degeneracy gate on the whole run
    }


if __name__ == "__main__":  # self-check: continuous fitness climbs, archive diversifies past the old 4/16 plateau
    # ── Descriptor proof (2026-11-04 redesign, Option B).  The dry `_evaluate_stub` emits only
    #    gate.allow + bare state.mutate; it carries NONE of the live signals the new descriptor reads
    #    (range.topology, move.source turn/tool/pivot-key, state.mutate cve/via), so it speciates
    #    NOTHING under the new axes — correct, not a regression (the old descriptor keyed on shallow
    #    signals the stub happened to emit, an accident of the old axes).  So the stub proves
    #    MECHANICS only (selection, breeding, memory, determinism) and descriptor DIVERSITY is proved
    #    here against LIVE-SHAPED synthetic chains — a second bite test at selftest time.  Axes are
    #    identical to scripts/validation/descriptor_bite_test.py (cross-checked via --via-population).
    _BD_TOPO = {"actor": "system", "action": "range.topology", "seq": 1, "data": {"nodes": [
        {"name": "web01", "ips": ["10.90.0.11"], "flag": False},
        {"name": "dba01", "ips": ["10.35.0.11"], "flag": False},
        {"name": "dba02", "ips": ["10.35.0.12"], "flag": False},
        {"name": "db-bastion", "ips": ["10.60.0.11"], "flag": False},
        {"name": "db-core", "ips": ["10.40.0.11"], "flag": True}]}}

    def _mk(path, fh, turn, cred):
        """Build a minimal LIVE-SHAPED red chain that lands in cell (path, fh, turn, cred)."""
        ev = [dict(_BD_TOPO)]
        n = [1]
        def _s():
            n[0] += 1
            return n[0]
        if fh == 2:       # authored foothold
            ev += [{"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": 2, "tool": "author_tool", "args": {}}},
                   {"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "foothold", "dst": "web01", "via": "authored"}}]
        elif fh == 1:     # non-canonical msf module
            ev += [{"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": 2, "tool": "exploit", "args": {}}},
                   {"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "foothold", "dst": "web01", "via": "msf", "module": "exploit/linux/other/foo"}}]
        else:             # canonical struts CVE
            ev += [{"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": 2, "tool": "exploit", "args": {"cve": "CVE-2017-5638"}}},
                   {"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "foothold", "dst": "web01", "cve": "CVE-2017-5638", "via": "msf", "module": "exploit/multi/http/struts2_content_type_ognl"}}]
        ev.append({"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": 3, "tool": "pivot", "args": {"key": "/k/a"}}})
        if cred == 1:
            ev.append({"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": 4, "tool": "pivot", "args": {"key": "/k/b"}}})
        if path == 0:     # canonical web01 -> dba01 -> db-bastion
            ev += [{"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "lateral", "dst": "10.35.0.11"}},
                   {"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "lateral", "dst": "10.60.0.11"}}]
        elif path == 1:   # alt-dba web01 -> dba02
            ev.append({"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "lateral", "dst": "10.35.0.12"}})
        else:             # off-seam
            ev.append({"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "lateral", "dst": "10.99.0.99"}})
        _T = {0: 10, 1: 27, 2: 40}[turn]
        ev += [{"seq": _s(), "actor": "red", "action": "move.source", "data": {"turn": _T, "tool": "loot", "args": {"host": "10.40.0.11"}}},
               {"seq": _s(), "actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "10.40.0.11"}}]
        return ev

    # (a) PLANT TEST — from a (0,0,0,0) base, each axis moved ONE AT A TIME lands in a distinct cell,
    #     and a two-axis change lands in a fifth.
    _base = (0, 0, 0, 0)
    assert behavior_descriptor(_mk(*_base)) == _base, behavior_descriptor(_mk(*_base))
    _planted = {}
    for _name, _cell in (("path", (1, 0, 0, 0)), ("foothold", (0, 1, 0, 0)),
                         ("turn", (0, 0, 1, 0)), ("cred", (0, 0, 0, 1))):
        _got = behavior_descriptor(_mk(*_cell))
        assert _got == _cell, (_name, _got, _cell)
        assert sum(a != b for a, b in zip(_got, _base)) == 1, ("must differ from base in one axis", _name, _got)
        _planted[_got] = _name
    _two = behavior_descriptor(_mk(1, 0, 0, 1))
    assert _two == (1, 0, 0, 1) and sum(a != b for a, b in zip(_two, _base)) == 2, _two
    _planted[_two] = "path+cred"
    assert len(_planted) == 5, ("four one-axis + one two-axis must be five distinct cells", _planted)

    # (b) DIVERSITY PROOF — a persona-varied population evaluated on LIVE-SHAPED chains fills the
    #     archive past the Nov-4 live collapse (1/54): a MAP-Elites run reaches >=4 distinct cells.
    def _live_eval(g, seed):
        p = g.prompt
        if "STYLE: stealthy" in p:      cell = (0, 0, 0, 1)
        elif "STYLE: lateral" in p:     cell = (1, 0, 1, 1)
        elif "STYLE: noisy-fast" in p:  cell = (0, 0, 2, 0)
        elif "STYLE: persistent" in p:  cell = (0, 2, 1, 0)
        elif "STYLE: recon-heavy" in p: cell = (0, 1, 0, 0)
        elif "STYLE: minimal" in p:     cell = (2, 0, 2, 0)
        else:                           cell = (0, 0, 1, 0)
        return _mk(*cell), 0.0
    live = evolve(seed=7, generations=4, pop_size=8, evaluate=_live_eval)
    cells = list(live["archive"].by_cell.keys())
    assert len(set(cells)) == len(cells), cells
    assert len(cells) >= 4, ("the new descriptor must spread live-shaped red past the 1/54 collapse", cells)
    assert live["archive"].diversity() > 4.0 / DESCRIPTOR_CELLS, live["archive"].diversity()

    # (c) MECHANICS on the dry stub — determinism, inheritance, continuous fitness. NO descriptor
    #     diversity claim here: the stub cannot exercise the live-only axes, by design.
    out = evolve(seed=42, generations=6, pop_size=8)
    assert len(out["history"]) == 6, out["history"]
    fitnesses = [h["best_fitness"] for h in out["history"]]
    assert any(0.0 < f < 1.0 for f in fitnesses), fitnesses
    assert out["inheritance_proofs"] > 0, out
    out2 = evolve(seed=42, generations=6, pop_size=8)
    assert [h["archive_diversity"] for h in out2["history"]] == \
           [h["archive_diversity"] for h in out["history"]], "stub determinism"
    # Fitness is genuinely multi-objective: depth + techniques raise a non-crown run above 0.
    partial = score_fitness([
        {"actor": "red", "action": "gate.allow", "data": {"tool": "recon", "target": "struts", "attack": "T1595"}},
        {"actor": "red", "action": "gate.allow", "data": {"tool": "pivot", "target": "db", "attack": "T1021"}},
    ])
    assert 0.0 < partial < _W_OBJECTIVE, partial   # progress without the objective still scores
    # score_fitness is bounded.
    assert 0.0 <= score_fitness([]) <= 1.0
    # T6 (fix #4): the manipulation bonus is read from BLUE's OWN logged detect.posture — blue
    # looking away from the objective — never a red self-report. An identical episode with no
    # posture shift is byte-identical (non-breaking default 0.0).
    gt_obj = {"objective_host": "jenkins"}
    base_ev = [{"actor": "red", "action": "gate.allow", "data": {"tool": "scan", "target": "struts", "attack": "T1"}}]
    # blue's posture: high attention on a feint host (struts), low on the true objective (jenkins)
    displaced = base_ev + [
        {"actor": "blue", "action": "detect.posture", "data": {"host": "struts", "p_detect": 0.8}},
        {"actor": "blue", "action": "detect.posture", "data": {"host": "jenkins", "p_detect": 0.2}}]
    assert score_fitness(displaced, gt_obj) > score_fitness(base_ev, gt_obj), \
        "manipulation term must reward blue-measured attention displacement off the objective"
    # No displacement (blue is looking AT the objective) earns no manipulation bonus.
    focused = base_ev + [
        {"actor": "blue", "action": "detect.posture", "data": {"host": "struts", "p_detect": 0.2}},
        {"actor": "blue", "action": "detect.posture", "data": {"host": "jenkins", "p_detect": 0.9}}]
    assert score_fitness(focused, gt_obj) == score_fitness(base_ev, gt_obj), \
        "no attention displacement must not be rewarded"
    # The signal is blue's own log: a red self-reported deception beat is IGNORED (fix #4).
    red_claim = base_ev + [{"actor": "red", "action": "red.deception.summary",
                            "data": {"attention_displacement": 0.9, "oos_executed": 0}}]
    assert score_fitness(red_claim, gt_obj) == score_fitness(base_ev, gt_obj), \
        "a red self-report must never move fitness"

    # A1 (readiness fix): the LIVE objective term is keyed on the telemetry-gated reconciler verdict
    # (duel.verdict.achieved on the chain), NEVER _spine_confirmed. A crafted chain where red emits
    # crown.access + 'exfil' state.mutate but the reconciler FLAGGED the loot (no witness) re-derives
    # the objective term to 0.0, not 1.0 — a fabricated win cannot score.
    gt_db = {"objective_host": "db"}
    flagged_chain = [
        {"actor": "red", "action": "gate.allow", "data": {"tool": "exploit", "target": "struts", "attack": "T1190"}},
        {"actor": "red", "action": "crown.access", "data": {"host": "db", "sensitive_data": True, "attack": "T1213"}},
        {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "db", "nbytes": 2048}},
        {"actor": "system", "action": "duel.verdict",
         "data": {"achieved": False, "objective_claimed": True, "loot_corroborated": False,
                  "reconcile": {"checkable": 3, "corroborated": 1, "flagged": 2}}}]
    blind_chain = flagged_chain[:-1]   # same red events, verdict STRIPPED (a dry-shaped chain)
    # the fidelity-blind spine read calls this a full win (crown + exfil both present) ...
    assert _spine_confirmed(flagged_chain) == (True, True), "fixture must look like a win to the blind path"
    assert score_fitness(blind_chain, gt_db) >= _W_OBJECTIVE, "blind score carries the full objective weight"
    # ... but the LIVE objective term re-derives to 0.0 (the reconciler flagged the loot):
    assert gated_objective(flagged_chain) == 0.0, "flagged loot must re-derive the objective term to 0.0"
    assert live_red_score_fitness(flagged_chain, gt_db) == score_fitness(flagged_chain, gt_db, objective=0.0)
    assert live_red_score_fitness(flagged_chain, gt_db) < score_fitness(blind_chain, gt_db), \
        "the live (gated) fitness must be strictly below the fidelity-blind fitness on a flagged win"
    # a witnessed win (verdict.achieved True) re-derives to 1.0:
    witnessed_chain = blind_chain + [{"actor": "system", "action": "duel.verdict", "data": {"achieved": True}}]
    assert gated_objective(witnessed_chain) == 1.0
    assert live_red_score_fitness(witnessed_chain, gt_db) == score_fitness(witnessed_chain, gt_db, objective=1.0)
    # the hard driver assertion bites: fitness is NEVER computed on a duel with no reconciler verdict.
    try:
        gated_objective(blind_chain)   # crown + exfil, but NO duel.verdict on the chain
        raise AssertionError("gated_objective must RAISE when the reconciler verdict is absent")
    except ValueError:
        pass
    # A1 side-wiring HARDENING: score_fitness REFUSES objective=None on a verdict-carrying chain, so
    # a reconciled/live chain is scored on the gated objective regardless of which side wired it.
    try:
        score_fitness(flagged_chain, gt_db)   # objective=None + duel.verdict present
        raise AssertionError("score_fitness must RAISE on a verdict-carrying chain with objective=None")
    except ValueError:
        pass
    # the live/measured side wires exactly this fitness; the dry side keeps the spine-read objective.
    assert SIDES["red_live"].score_fitness is live_red_score_fitness, SIDES["red_live"]
    assert SIDES["red"].score_fitness is score_fitness, SIDES["red"]
    # a DRY chain (no verdict) leaves every existing (objective=None) caller byte-identical.
    assert score_fitness(blind_chain, gt_db) == score_fitness(blind_chain, gt_db, objective=None)

    # A2 (readiness fix): a falco-down (syscall-source-absent) episode re-derives from the chain and
    # is EXCLUDED from co-evo fitness — the Evolver drops it (excluded_episodes), never scoring it as
    # a red loss. The dry sides carry no exclusion predicate (byte-identical).
    falco_down = flagged_chain[:-1] + [
        {"actor": "system", "action": "episode.degraded", "data": {"modality_down": "falco"}},
        {"actor": "system", "action": "duel.verdict", "data": {"achieved": False, "falco_wired": False}}]
    assert falco_degraded(falco_down) and not falco_degraded(witnessed_chain)
    assert SIDES["red_live"].exclude_episode is falco_degraded and SIDES["red"].exclude_episode is None
    _ev_a2 = Evolver(seed=3, pop_size=1, side="red_live", ground_truth=gt_db)
    _h = _ev_a2.tick(evaluate=lambda g, s: (falco_down, 0.0), eval_seed=3)
    assert _h["excluded_episodes"] == 1 and _h["archive_entries"] == 0, _h

    # Persistence + persona-seeding (the live-diversity fixes): persona seeding
    # spreads the population across cells from gen 0 (so even one tick fills >1
    # cell), and a PERSISTENT Evolver ticked N times keeps diversifying beyond what
    # a single generation reaches — the archive accumulates distinct strategies.
    # Proven on LIVE-SHAPED chains (the dry stub speciates nothing under the live-only axes). A
    # PERSISTENT Evolver ticked N times keeps accumulating distinct cells (MAP-Elites never evicts a
    # cell), so diversity is non-decreasing and ends well past the 1/54 live collapse.
    ev = Evolver(seed=1337, pop_size=6)
    persist = [ev.tick(evaluate=_live_eval, eval_seed=1337 + g)["archive_diversity"] for g in range(8)]
    assert len(ev.archive.by_cell) >= 4 and persist[-1] >= persist[0], persist
    one_tick = evolve(seed=1337, generations=1, pop_size=6,
                      evaluate=_live_eval)["history"][0]["archive_diversity"]
    assert one_tick > 1.0 / DESCRIPTOR_CELLS, ("persona seeding must fill >1 cell in gen 0", one_tick)
    assert persist[-1] >= one_tick, (persist[-1], one_tick)

    # Phase 6: the SAME Evolver runs a BLUE population when constructed with side="blue" — one
    # module, parameterized. Blue fitness is telemetry-sourced; a defender genome that detects +
    # contains + holds the crown outscores one that sees nothing.
    blue_ev = Evolver(seed=7, pop_size=6, side="blue", ground_truth={"objective_host": "jenkins"})

    def _blue_eval(g, seed):
        aggressive = "aggressive" in g.prompt or "crown-guard" in g.prompt
        ev = [{"actor": "red", "action": "state.mutate", "data": {"state": "foothold", "dst": "struts"}},
              {"actor": "red", "action": "state.mutate", "data": {"state": "lateral", "dst": "db"}}]
        # a vigilant blue detects + contains; a passive one does neither (and loses the crown)
        if aggressive:
            ev += [{"seq": 3, "actor": "blue", "action": "detect.killchain", "data": {"host": "db", "source": "edr"}},
                   {"seq": 4, "actor": "blue", "action": "blue.contain", "data": {"host": "db"}}]
        else:
            ev += [{"actor": "red", "action": "crown.access", "data": {"host": "jenkins"}},
                   {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "jenkins"}}]
        ev.append({"actor": "red", "action": "gate.block", "data": {"tool": "pivot", "target": "oos"}})
        return ev, 0.0

    bh = [blue_ev.tick(evaluate=_blue_eval, eval_seed=7 + g)["archive_diversity"] for g in range(5)]
    assert len(blue_ev.archive.by_cell) >= 1 and blue_ev.side == "blue", (bh, blue_ev.side)
    # a crown-holding/ detecting defender scores above a passive one (telemetry-sourced).
    vigilant = blue_score_fitness(_blue_eval(Genome(prompt="x STYLE: aggressive-contain"), 1)[0],
                                  {"objective_host": "jenkins"})
    passive = blue_score_fitness(_blue_eval(Genome(prompt="x STYLE: patient"), 1)[0],
                                 {"objective_host": "jenkins"})
    assert vigilant > passive, ("blue fitness must reward detect+contain+crown-held", vigilant, passive)
    # A1 watch-item (Group B): blue's crown-held reads the TELEMETRY-GATED verdict when present — a
    # fabricated/unwitnessed red win (crown.access + exfil but duel.verdict.achieved=False) must NOT
    # penalize blue (crown_held stays 1.0); a telemetry-witnessed win does.
    _bg = [{"actor": "red", "action": "crown.access", "data": {"host": "db"}},
           {"actor": "red", "action": "state.mutate", "data": {"state": "exfil", "dst": "db"}},
           {"actor": "system", "action": "duel.verdict", "data": {"achieved": False}}]
    _bw = _bg[:-1] + [{"actor": "system", "action": "duel.verdict", "data": {"achieved": True}}]
    assert blue_score_fitness(_bg, {"objective_host": "db"}) > blue_score_fitness(_bw, {"objective_host": "db"}), \
        "blue must be credited crown-held on an UNWITNESSED red win (gated verdict), penalized on a witnessed one"

    # Phase 6 genome: authored_tools (the tools a lineage invents) is inherited by a child, so
    # evolution selects over strategy AND invented tooling. A round-trip through save/restore keeps
    # it (serialized via asdict; reconstructed via Genome(**g)).
    import random as _rnd
    parent = Genome(prompt="p", memory=["m0"], authored_tools={"enum": "id; uname -a"})
    child = parent.mutate(_rnd.Random(0), [], _DEFAULT_MUTATORS)
    assert child.authored_tools == {"enum": "id; uname -a"}, child.authored_tools
    child.authored_tools["sweep"] = "for p in 22 80; do echo $p; done"   # child invents a new tool
    assert "sweep" not in parent.authored_tools, "inheritance must copy, not alias"

    # Degenerate collapse case: a generator that produces BLOCKED loops is flagged. Under A-S2
    # a loop keys on blocked actions only (an allowed-action repeat is not a loop), so this
    # fixture produces six repeated BLOCKED actions and the loop rule still bites.
    def _loop_eval(g, seed):
        ev = [{"actor": "red", "action": "gate.block",
               "data": {"tool": "recon", "target": "ldap"}}] * 6
        return ev, 0.0
    bad = evolve(seed=1, generations=2, pop_size=4, evaluate=_loop_eval)
    assert bad["collapsed"], bad
    assert all(h["degenerate_episodes"] == h["pop_size"] for h in bad["history"]), bad

    # A-S1 regression (2026-10-30 co-evo selection build): a telemetry-corroborated WIN is ALWAYS
    # SCORED (never degenerate-excluded), EVEN WHEN its tail shape would have tripped the pre-A-S2
    # rule (a repeated allowed `cred_pivot -> backup` x12 with no distinct variant). Pilot
    # reproduction: on the committed pilot gen0 chains, this shape dropped two of three wins
    # pre-A-S1/A-S2 (archive_entries=0, red_cells=0). With A-S1 + A-S2 wired, the gated verdict
    # (duel.verdict.achieved=True) clears degeneracy and the Evolver scores it. (Two wins with
    # IDENTICAL behavior descriptors collapse to one archive cell by MAP-Elites design; the right
    # A-S1 check is `degenerate_episodes == 0`, not `archive_entries == 2`.)
    def _winning_pilot_shape_eval(g, seed):
        ev = [{"actor": "red", "action": "gate.allow",
               "data": {"tool": "exploit", "target": "web01", "attack": "T1190"}},
              {"actor": "red", "action": "state.mutate",
               "data": {"state": "foothold", "dst": "web01", "technique": "T1190"}},
              {"actor": "red", "action": "state.mutate",
               "data": {"state": "lateral", "dst": "10.35.0.11", "technique": "T1021"}}]
        ev += [{"actor": "red", "action": "gate.allow",
                "data": {"tool": "cred_pivot", "target": "backup", "attack": "T1021"}}] * 12
        ev += [{"actor": "red", "action": "state.mutate",
                "data": {"state": "exfil", "dst": "db-core", "nbytes": 2048}},
               {"actor": "system", "action": "duel.verdict",
                "data": {"achieved": True, "falco_wired": True, "msf_wired": True,
                         "loot_corroborated": True}}]
        return ev, 0.0
    _as1 = Evolver(seed=1337, pop_size=3, side="red_live", ground_truth={"objective_host": "db-core"})
    _h_as1 = _as1.tick(evaluate=_winning_pilot_shape_eval, eval_seed=1337)
    # A-S1 primary invariant: a corroborated win is NEVER degenerate-excluded.
    assert _h_as1["degenerate_episodes"] == 0, ("A-S1: a corroborated win is never degenerate", _h_as1)
    # And it is scored (best_fitness raised, archive non-empty — identical-descriptor collisions
    # may collapse multiple wins into one cell; one entry is sufficient to prove scoring fired).
    assert _h_as1["archive_entries"] >= 1, ("A-S1: a corroborated win must be scored", _h_as1)
    assert _h_as1["best_fitness"] > 0.0, ("A-S1: a corroborated win must raise best_fitness", _h_as1)

    # B-M1 regression (2026-10-30 co-evo erosion build): the per-episode lesson distiller produces
    # a GROUND-TRUTH-FREE lesson (role+technique+credential-source grain), the A5 map-blind guard
    # passes on it, and the SAME guard STILL BITES on a hand-crafted GT-leaking lesson — so the
    # distillation is safe to flow through red's memory channel. Then the Evolver's memory-on
    # treatment arm feeds that lesson to the child; memory-off keeps a fresh context.
    import sys as _sys
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
    from live_agent import assert_red_map_blind as _amb
    _gt_bm1 = {
        "crown_loot": {"host": "db-core", "path": "/home/dbadmin/pii.json", "user": "dbadmin"},
        "host_tier": {"web01": "T2", "dba01": "T2", "db-bastion": "T1", "db-core": "T1"},
        "scope": {"in_scope": ["web01", "dba01", "db-bastion", "db-core"], "out_of_scope": ["decoy"]},
        "credential_graph": [{"loot_host": "web01", "loot": "bootstrap_pw", "unlocks": "dba01"}]}
    # Craft a winning episode shape that touches 3 roles via 2 techniques + a credential pivot.
    _bm1_chain = [
        {"actor": "red", "action": "discovery",
         "data": {"kind": "hosts", "from": "self",
                  "hosts": [{"name": "web01", "ips": ["10.9.0.10"], "services": {"8080": "http"}}]}},
        {"actor": "red", "action": "fingerprint",
         "data": {"target": "web01", "server": "Apache-Coyote/1.1", "status": 200}},
        {"actor": "red", "action": "gate.allow",
         "data": {"tool": "exploit", "target": "web01", "attack": "T1190"}},
        {"actor": "red", "action": "state.mutate",
         "data": {"state": "foothold", "dst": "web01", "technique": "T1190"}},
        {"actor": "red", "action": "discovery",
         "data": {"kind": "hosts", "from": "web01",
                  "hosts": [{"name": "dba01", "ips": ["10.20.0.11"], "services": {"22": "ssh"}}]}},
        {"actor": "red", "action": "gate.allow",
         "data": {"tool": "harvest", "target": "web01"}},
        {"actor": "red", "action": "gate.allow",
         "data": {"tool": "cred_pivot", "target": "dba01", "attack": "T1021"}},
        {"actor": "red", "action": "state.mutate",
         "data": {"state": "lateral", "dst": "dba01", "technique": "T1021"}},
        {"actor": "red", "action": "state.mutate",
         "data": {"state": "exfil", "dst": "db-core", "technique": "T1041"}},
        {"actor": "red", "action": "gate.block",
         "data": {"tool": "pivot", "target": "decoy", "attack": "T1021"}},
        {"actor": "system", "action": "duel.verdict",
         "data": {"achieved": True, "falco_wired": True, "msf_wired": True}}]
    _lesson = _distill_lesson(_bm1_chain)
    assert _lesson and _is_memory_distilled(_lesson), ("distillation must produce a lesson", _lesson)
    # The lesson teaches technique + service-type + credential source, in order.
    for marker in ("WORKED:", "T1190", "foothold", "T1021", "harvested", "lateral",
                   "T1041", "exfil", "BLOCKED:"):
        assert marker in _lesson, ("B-M1: distilled lesson missing", marker, _lesson)
    # And the A5 map-blind guard passes on the distilled lesson (both read + write channels).
    try:
        _amb(objective="data_theft", ground_truth=_gt_bm1, start_subnet="10.9.0.0/24",
             episodic_recall=[_lesson], memory_write=[_lesson])
    except RuntimeError as _r:
        raise AssertionError(("B-M1: A5 guard must NOT bite on a GT-free distilled lesson", str(_r)))
    # And the SAME guard STILL BITES on a hand-crafted lesson that leaks a GT host name — proving
    # the firewall is active over the memory channel exactly as A5 requires.
    _caught = False
    try:
        _amb(objective="data_theft", ground_truth=_gt_bm1, start_subnet="10.9.0.0/24",
             episodic_recall=["reuse the dbadmin cred on db-core"],
             memory_write=["reuse the dbadmin cred on db-core"])
    except RuntimeError:
        _caught = True
    assert _caught, "B-M1: A5 guard must bite on a GT-leaking lesson"

    # B-M1 Evolver wiring: the memory-ON arm distills a parent's own lesson and feeds it to
    # the child via Genome.mutate's pool; the memory-OFF arm clears the child's memory.
    def _mem_eval(g, seed): return _bm1_chain, 0.0
    # memory-on: a child's memory contains the distilled lesson, not a canned _DEFAULT_LESSONS line.
    _E_on = Evolver(seed=1, pop_size=2, side="red_live_memory_on", ground_truth={"objective_host": "db-core"})
    _E_on.tick(evaluate=_mem_eval, eval_seed=1)
    _childs_on = _E_on.population   # the children bred for the NEXT gen
    _has_distilled = any(_is_memory_distilled(m) for c in _childs_on for m in c.memory)
    assert _has_distilled, ("B-M1 memory-on: a child's memory must contain a distilled lesson",
                            [c.memory for c in _childs_on])
    # memory-off: a child's memory is EMPTY — no inherited lesson between episodes.
    _E_off = Evolver(seed=1, pop_size=2, side="red_live_memory_off", ground_truth={"objective_host": "db-core"})
    _E_off.tick(evaluate=_mem_eval, eval_seed=1)
    _childs_off = _E_off.population
    assert all(c.memory == [] for c in _childs_off), \
        ("B-M1 memory-off: no inherited lesson between episodes", [c.memory for c in _childs_off])

    # A-S1 counter-regression: a chain where the gated verdict is False (reconciler flagged the
    # loot) AND the shape is a stall MUST stay degenerate-excluded. Pre-A-S1 both wins AND losses
    # of this shape were dropped — A-S1 lifts ONLY the corroborated wins, not every episode.
    def _losing_stall_eval(g, seed):
        ev = [{"actor": "red", "action": "gate.allow",
               "data": {"tool": "cred_pivot", "target": "backup", "attack": "T1021"}}] * 10
        ev += [{"actor": "system", "action": "duel.verdict",
                "data": {"achieved": False, "falco_wired": True, "msf_wired": True,
                         "loot_corroborated": False}}]
        return ev, 0.0
    _as1b = Evolver(seed=42, pop_size=3, side="red_live", ground_truth={"objective_host": "db-core"})
    _h_as1b = _as1b.tick(evaluate=_losing_stall_eval, eval_seed=42)
    assert _h_as1b["degenerate_episodes"] == _h_as1b["pop_size"], \
        ("A-S1: an unwitnessed stall must stay degenerate-excluded", _h_as1b)
    assert _h_as1b["archive_entries"] == 0, _h_as1b

    # ── Host-side checkpoint/resume: the archive + evolver survive a process exit
    #    and a restored run is BYTE-IDENTICAL to an uninterrupted one (brief §3). ──
    import tempfile
    ckpt = Evolver(seed=1337, pop_size=6)
    for g in range(4):
        ckpt.tick(eval_seed=1337 + g)
    tf = Path(tempfile.mktemp(suffix=".json")); ckpt.save(tf)
    # Archive alone round-trips (diversity + elite genomes preserved).
    a_tf = Path(tempfile.mktemp(suffix=".json")); ckpt.archive.save(a_tf)
    arc_rt = MapElitesArchive.load(a_tf)
    assert arc_rt.diversity() == ckpt.archive.diversity(), (arc_rt.diversity(), ckpt.archive.diversity())
    assert {c: g.hash for c, (_, g, _) in arc_rt.by_cell.items()} == \
           {c: g.hash for c, (_, g, _) in ckpt.archive.by_cell.items()}, "archive genomes must round-trip"
    # Full evolver restore: fresh instance (same config) + restore() == the saved state.
    restored = Evolver(seed=1337, pop_size=6).restore(tf)
    assert restored.gen == ckpt.gen == 4, (restored.gen, ckpt.gen)
    assert restored.inheritance_proofs == ckpt.inheritance_proofs
    assert [p.hash for p in restored.population] == [p.hash for p in ckpt.population], "population must round-trip"
    # Determinism: continuing the ORIGINAL vs the RESTORED evolver gives identical
    # histories — the RNG state was checkpointed, so resume is not an approximation.
    cont_orig = [ckpt.tick(eval_seed=2000 + g)["archive_diversity"] for g in range(3)]
    cont_rest = [restored.tick(eval_seed=2000 + g)["archive_diversity"] for g in range(3)]
    assert cont_orig == cont_rest, (cont_orig, cont_rest)
    tf.unlink(); a_tf.unlink()

    print(f"population ok: NEW descriptor spreads live-shaped red across {len(cells)}/{DESCRIPTOR_CELLS} "
          f"cells (diversity {len(cells)/DESCRIPTOR_CELLS:.3f} vs the Nov-4 live collapse of 1/54); "
          f"5 planted axis cells distinct; dry stub proves mechanics "
          f"({out['inheritance_proofs']} inheritance proofs, continuous fitness "
          f"{min(fitnesses):.2f}-{max(fitnesses):.2f}, deterministic); degenerate collapse still flagged")
