"""Autonomous blue agent — a real SOC/IR analyst loop (symmetric to swarm.live_agent).

Blue is NOT a scripted policy and NOT handed red's log. Each tick it sees ONLY its lossy
sensor picture — the SOC detector's alerts over the hash-chained TELEMETRY chain (swarm.
sensor_real / sensor_stack on Falco syscalls, Suricata/IDS, auditd, service logs) — plus the
results of its own investigations, and it CHOOSES one action from the toolkit a real defender
actually operates. It can be wrong: miss red (recall < 1), false-positive onto a benign host,
waste a move, or be outmaneuvered. Every action is gate-mediated (blue acts on the SAME floor
as red; an out-of-scope action is denied) and has a REAL effect on the live range.

The defender toolkit (each tool injected, wired to a real effect by the duel driver):
  investigate(host)      triage — pull the host's own process/exec/connection/auth telemetry
  hunt(pattern)          threat-hunt the telemetry chain for an indicator across hosts
  isolate_host(host)     EDR network isolation — quarantine the container
  kill_session(host)     terminate red's shell/session/process on a host
  revoke_cred(host,user) credential containment — remove the pivot key (stolen key goes dead)
  rotate_cred(host,user) moving-target defense — re-key so a stolen credential staleness
  block_ip(ip)           firewall-block an attacker source address
  deploy_decoy(host)     active defense — plant a honeytoken/decoy credential
  counter_recon(ip)      authorized counter-offense — scan/probe red's foothold (gated)
  wait(reason)           hold — the correct move when the picture is noise, not a threat

Emits one move.source:blue beat per tick (a pure-log reader re-derives that BLUE drove its
own decisions). The duel outcome is whatever the telemetry shows — never steered.
"""
import re
import sys
import json
import signal
import contextlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm.live_agent import _TurnTimeout, _wall_clock      # noqa: E402  (reuse the wall-clock)

_BLUE_TOOLS = ("investigate", "hunt",
               # reversible ("watch") D3FEND set — default first moves
               "suspend_process", "lock_account", "isolate_host", "block_egress", "block_dns",
               "deploy_decoy", "rotate_cred", "block_ip",
               # irreversible ("contain/evict") D3FEND set — gated behind high confidence + bounded blast
               "invalidate_auth_cache", "kill_session", "revoke_cred", "shutdown_host",
               "counter_recon", "wait",
               "author_tool", "call_tool")   # runtime authoring — symmetric to red (swarm.authoring)

BLUE_SYS = (
    "You are an autonomous blue-team SOC/IR analyst defending an authorized enterprise range. "
    "You see ONLY your sensor picture — the alerts below, raised by EDR/IDS/host telemetry — "
    "and the results of your own investigations. You do NOT see the attacker's plan or logs; "
    "your view is lossy (real detectors miss things and false-alarm). Defend the crown jewels: "
    "detect the intrusion, investigate to confirm it, and contain/evict/disrupt it — while "
    "avoiding needless damage to benign hosts. Each tick choose ONE action. Over-reacting to "
    "noise (isolating a benign host) is a real cost; so is missing a real intrusion.\n"
    "DOCTRINE (reversible-first): prefer the most REVERSIBLE control that stops the spread, and "
    "escalate to an IRREVERSIBLE eviction ONLY once you understand the scope (you have investigated "
    "the believed-compromised hosts) and your confidence is high. Contain a credential compromise in "
    "this order: lock_account -> invalidate_auth_cache -> revoke_cred.\n"
    "REVERSIBLE tools (watch; your default first moves):\n"
    "  investigate {\"host\":\"<host>\"}            triage/correlate (D3-DA)\n"
    "  hunt {\"pattern\":\"<technique or indicator>\"}\n"
    "  suspend_process {\"host\":\"<host>\"}         D3-PS (freeze red's process)\n"
    "  lock_account {\"host\":\"<host>\",\"user\":\"<user>\"}  D3-AL (disable the account)\n"
    "  isolate_host {\"host\":\"<host>\"}            D3-NI (network-contain the host)\n"
    "  block_egress {\"host\":\"<host>\"}            D3-OTF (temp outbound filter)\n"
    "  block_dns {\"host\":\"<host>\"}               D3-DNSDL (temp DNS denylist)\n"
    "  deploy_decoy {\"host\":\"<host>\"}            D3-DUC/D3-DST (decoy creds + honey-SPN)\n"
    "  rotate_cred {\"host\":\"<host>\",\"user\":\"<user>\"}   moving-target re-key\n"
    "  block_ip {\"ip\":\"<ip>\"}\n"
    "IRREVERSIBLE tools (contain/evict; only once scope is understood + confidence high):\n"
    "  invalidate_auth_cache {\"host\":\"<host>\",\"user\":\"<user>\"}  D3-ANCI (evict live ticket/session)\n"
    "  kill_session {\"host\":\"<host>\"}            D3-ST (terminate red's session)\n"
    "  revoke_cred {\"host\":\"<host>\",\"user\":\"<user>\"}   D3-CR (credential revocation)\n"
    "  shutdown_host {\"host\":\"<host>\"}           D3-HS (last resort; highest blast)\n"
    "  counter_recon {\"ip\":\"<ip>\"}\n"
    "  wait {\"reason\":\"<why holding>\"}\n"
    "  author_tool {\"name\":\"<short>\",\"source\":\"<a shell response you write>\",\"target\":\"<host>\"}\n"
    "  call_tool {\"name\":\"<a response you authored>\",\"target\":\"<host>\"}\n"
    "Your built-in toolkit above covers most situations; author_tool/call_tool are a LAST resort "
    "for when none of your built-in responses fits — try the applicable built-in responses first.\n"
    "Reply with STRICT JSON only: {\"thought\":\"<short>\",\"tool\":\"<name>\",\"args\":{...}}."
)


def _parse_action(raw):
    if not raw:
        return None
    tm = re.search(r'"tool"\s*:\s*"(\w+)"', raw)
    if not tm or tm.group(1) not in _BLUE_TOOLS:
        return None
    args = {}
    am = re.search(r'"args"\s*:\s*(\{.*?\})', raw, re.S)
    if am:
        try:
            args = json.loads(am.group(1))
        except Exception:                                   # noqa: BLE001
            args = {}
    th = re.search(r'"thought"\s*:\s*"([^"]*)"', raw)
    return {"thought": (th.group(1)[:160] if th else ""), "tool": tm.group(1), "args": args}


def blue_frontier_awareness(alerts, *, contained=(), investigated=()):
    """Situational awareness from blue's OWN lossy sensor picture — the folded response-frontier
    machinery (blue_response.BlueResponseFrontier), presented as a HINT, never a ceiling. The
    candidate responses are computed from the suspected-compromised hosts the sensor surfaced
    (alert hosts), minus what blue has already contained/investigated. Symmetric to red's
    `live_agent.frontier_awareness`: blue still composes any tool it judges best; this only shows
    what its current belief suggests. Derived only from the sensor alerts — never red's log."""
    observed = {a.get("host") for a in (alerts or []) if a.get("host")}
    if not observed:
        return ""
    try:
        from swarm.blue_response import BlueResponseFrontier
        moves = BlueResponseFrontier().frontier(observed, contained=set(contained),
                                                investigated=set(investigated))
    except Exception:                                       # noqa: BLE001  (awareness is best-effort)
        moves = []
    if not moves:
        return ""
    out = ["\nSITUATIONAL AWARENESS (from your lossy sensor picture; you are NOT limited to "
           "these — choose any tool you judge best):"]
    for m in moves[:8]:
        out.append(f"    - {m.get('action')} -> {m.get('target')}  ({m.get('reason','')})")
    return "\n".join(out)


def blue_toolkit_untried(log, actor="blue"):
    """The BLUE side of the toolkit-first doctrine (swarm.authoring doctrine_fn): the untried
    applicable built-in responses that remain for the hosts blue SUSPECTS, derived ONLY from blue's
    OWN hash-chained sensor picture + its OWN actions. Returns opaque tokens (len>0 => authoring
    deferred). Blue may author only after its applicable built-in responses are tried.

    Symmetric to red's live_agent.red_toolkit_untried and range-blind BY CONSTRUCTION: it reads only
    blue's own `blue.observe` beats (the lossy alert picture blue logged — never red's log, never
    gate.allow) and blue's own `move.source:blue` decisions, and folds them through the SAME response
    frontier the awareness uses (blue_response.BlueResponseFrontier) — no new policy copy. A suspected
    host is resolved once its applicable built-in responses (investigate + a containment) are tried;
    while any remain, authoring defers. Empty (no suspicion, or every suspected host responded to) =>
    the built-in toolkit is exhausted at blue's frontier and authoring unlocks."""
    mine = [e for e in log.entries() if e.get("actor") == actor]
    suspected, investigated, contained = set(), set(), set()
    for e in mine:
        act, d = e.get("action"), (e.get("data") or {})
        if act == "blue.observe":
            for h in (d.get("alert_hosts") or []):
                suspected.add(h)
        if act == "move.source" and d.get("stage") == "blue" and d.get("source") == "llm":
            args = d.get("args") or {}
            tgt = args.get("host") or args.get("ip")
            if not tgt:
                continue
            if d.get("tool") == "investigate":
                investigated.add(tgt)
            elif d.get("tool") in ("isolate_host", "kill_session", "revoke_cred", "block_ip"):
                contained.add(tgt)
    if not suspected:
        return []                                       # nothing suspected => toolkit not forced
    try:
        from swarm.blue_response import BlueResponseFrontier
        moves = BlueResponseFrontier().frontier(suspected, contained=contained,
                                                investigated=investigated)
    except Exception:                                   # noqa: BLE001  (doctrine is best-effort)
        return []
    return [f"{m.get('action')}:{m.get('target')}" for m in moves]


def _render(alerts, memory):
    lines = ["sensor alerts (your lossy picture this tick):"]
    if alerts:
        for al in alerts[-16:]:
            lines.append(f"  - {al.get('technique','?')} on {al.get('host','?')} "
                         f"[{al.get('source','sensor')}] {al.get('note','')}".rstrip())
    else:
        lines.append("  (no alerts firing)")
    if memory:
        lines.append("your recent actions + findings:")
        for m in memory[-10:]:
            lines.append(f"  - {m.get('tool')}({json.dumps(m.get('args',{}),separators=(',',':'))}) "
                         f"-> {json.dumps(m.get('result',{}),separators=(',',':'))[:140]}")
    return "\n".join(lines)


class DryBlueRouter:
    """The DRY (no-LLM) BlueAgent backend — a deterministic reversible-FIRST escalation policy, so the
    one BlueAgent engine runs without a paid model (the blue proofs re-home onto BlueAgent instead of
    blue_fast / run_belief_blue). It reads ONLY blue's own lossy view (the rendered alerts + blue's
    memory in the prompt), never red's log — the same objective-blindness the LLM path has.

    Policy (D3FEND watch -> contain -> evict): an un-triaged alert -> investigate (understand scope);
    then step down a reversible-FIRST ladder, taking the first rung not yet tried on the host — a
    reversible network-contain, then the credential-eviction escalation Account-Lock ->
    Auth-Cache-Invalidate -> Revoke. The ladder only PROPOSES the order; run_blue_fight's decision
    model is what actually authorizes (or gates) each rung. `.chat()` returns the same
    {thought,tool,args} JSON the LLM router emits, so BlueAgent is unchanged."""

    # reversible network-contain first (the most reversible control that stops spread), then the
    # Account-Lock -> Auth-Cache-Invalidate -> Revoke eviction escalation.
    _LADDER = ("isolate_host", "lock_account", "invalidate_auth_cache", "revoke_cred")

    def __init__(self, ladder=None):
        class _U:
            pass
        self.usage = _U()
        self.usage.calls = []
        self.ladder = tuple(ladder) if ladder else self._LADDER

    def chat(self, role, messages, **kw):
        self.usage.calls.append({"model": "dry-blue", "tier": "nano"})
        text = messages[-1]["content"]
        alert_hosts = re.findall(r"-\s+\S+\s+on\s+(\S+)", text)
        if not alert_hosts:
            return json.dumps({"thought": "no alerts firing", "tool": "wait",
                               "args": {"reason": "quiet"}})
        target = alert_hosts[-1]
        investigated = set(re.findall(r'investigate\(\{"host":"([^"]+)"', text))
        if target not in investigated:
            return json.dumps({"thought": "triage the alert first (understand scope)",
                               "tool": "investigate", "args": {"host": target}})
        for rung in self.ladder:
            tried = set(re.findall(r'%s\(\{"host":"([^"]+)"' % re.escape(rung), text))
            if target not in tried:
                reversible = rung in REVERSIBLE
                thought = ("reversible contain first" if reversible
                           else "still active after a reversible control; escalate to eviction")
                args = {"host": target}
                if rung in ("lock_account", "invalidate_auth_cache", "revoke_cred", "rotate_cred"):
                    args["user"] = "svc"
                return json.dumps({"thought": thought, "tool": rung, "args": args})
        return json.dumps({"thought": "full ladder exhausted; hold", "tool": "wait",
                           "args": {"reason": "contained"}})


# Belief-driven detection (re-homed from live_duel's run_belief_blue, Phase 3): Bernoulli detect
# over the spine STRUCTURE -> noisy-OR belief. Blue's lossy sight, read ONLY from the log (never
# red's labels). The one-engine fight gates on this, and the L1 gate (live_gates) reads these events.
import random as _random  # noqa: E402

_P_FIRE = {
    "recon": 0.15, "discovery": 0.20, "initial_access": 0.25,
    "defense_evasion": 0.15, "privilege_escalation": 0.50,
    "credential_access": 0.60, "lateral_movement": 0.50,
    "collection": 0.50, "command_and_control": 0.60,
    "persistence": 0.65, "exfiltration": 0.80,
}
_CONFIRMED_P = 0.95          # an observer-confirmed state transition is near-certain
_CONTAIN_CONFIDENCE = 0.70   # watch-vs-contain ENTRY gate (blue acts at all only above this)
_P_TAMPER = 0.85             # log-clearing / sensor-disabling (T1070/T1562): FIRST-CLASS detections
#                              (tamper is loud and the chain is tamper-evident — not a stealthy miss)
_P_HONEYTOKEN = 0.98         # a decoy-credential / honey-SPN TRIPWIRE hit: near-certain (~0 false-pos)
_TAMPER_TECHS = {"T1070", "T1562"}


# ── Phase 4: the realistic D3FEND blue action set, split by reversibility, + the decision model ──
# Agent-facing tool name -> (D3FEND id, reversible, escalation_rank). The toolkit BlueAgent operates
# is INJECTED (run_blue_fight wires each to a gate-mediated effect); this table is the taxonomy the
# decision model reasons over. Reversible = a "watch" control that can be lifted (default first
# moves); irreversible = a "contain/evict" control gated behind high confidence + bounded blast.
D3FEND_ACTIONS = {
    # reversible ("watch" / default-first)
    "investigate":           ("D3-DA",    True,  0),   # triage/correlate (information, not an effect)
    "suspend_process":       ("D3-PS",    True,  1),
    "deploy_decoy":          ("D3-DUC",   True,  1),   # decoy creds/tokens + honey-SPN (deception.py)
    "lock_account":          ("D3-AL",    True,  2),
    "isolate_host":          ("D3-NI",    True,  3),   # host network isolation (blue_contain.contain_host)
    "block_egress":          ("D3-OTF",   True,  3),   # temp outbound-traffic filtering
    "block_dns":             ("D3-DNSDL", True,  3),   # temp DNS denylisting
    # irreversible ("contain/evict") — Account-Lock -> Auth-Cache-Invalidate -> Revoke ladder
    "invalidate_auth_cache": ("D3-ANCI",  False, 5),   # evict a live session/ticket (TGT/TGS/NTLM)
    "kill_session":          ("D3-ST",    False, 6),   # terminate red's session (blue_contain.remove_foothold)
    "revoke_cred":           ("D3-CR",    False, 7),   # credential revocation (stolen key/hash dies)
    "rollback_host":         ("D3-RB",    False, 7),   # known-good restore from image (blue_contain.rollback_host)
    "shutdown_host":         ("D3-HS",    False, 8),   # last resort (highest blast)
    # reversible vector closure (B2/B4): stop the vulnerable entry service so re-exploit fails.
    "close_vector":          ("D3-PH",    True,  3),   # shut the entry vector (blue_contain.close_vector)
}
REVERSIBLE = {k for k, (_, rev, _) in D3FEND_ACTIONS.items() if rev}
IRREVERSIBLE = {k for k, (_, rev, _) in D3FEND_ACTIONS.items() if not rev}
# controls that STOP THE SPREAD and so record a host as a confirmed "contained" observable (B2
# MTTC): network isolation + the eviction tier. Account-lock / egress-filter / decoy are responses
# that do not by themselves retire the host.
_STOPS_SPREAD = {"isolate_host", "kill_session", "revoke_cred", "invalidate_auth_cache",
                 "rollback_host", "shutdown_host"}

# Decision model (Phase 4): act when confidence x blast_radius_contained x reversibility >= THRESHOLD.
# The reversibility weight makes an irreversible control require MORE — higher confidence AND an
# understood scope — to clear the SAME bar, so blue prefers the most reversible control that stops
# the spread and escalates to an irreversible evict only once scope is understood (bounded blast).
_REVERSIBILITY_WEIGHT = {True: 1.0, False: 0.6}
_DECISION_THRESHOLD = 0.45


def blue_decision(confidence, blast_radius_contained, reversible, *, threshold=_DECISION_THRESHOLD):
    """The Phase-4 containment decision, pure and testable: score = confidence x
    blast_radius_contained x reversibility_weight; act iff score >= threshold. `confidence` in [0,1]
    is blue's belief the host is compromised; `blast_radius_contained` in [0,1] is how much of the
    believed intrusion scope this action would contain (1.0 = scope fully understood). A reversible
    control (weight 1.0) clears the bar at moderate confidence; an irreversible one (weight 0.6)
    needs high confidence AND an understood scope to clear it — the gate on evictions."""
    w = _REVERSIBILITY_WEIGHT[bool(reversible)]
    score = round(float(confidence) * float(blast_radius_contained) * w, 4)
    return {"score": score, "authorized": score >= threshold, "threshold": threshold,
            "reversibility_weight": w, "reversible": bool(reversible),
            "confidence": round(float(confidence), 4),
            "blast_radius_contained": round(float(blast_radius_contained), 4)}


def _honeytoken_trips(entries, honeytokens=()):
    """Near-certain detections: a red action touching a blue TRIPWIRE — a honey-SPN TGS request, a
    decoy credential/account, or any red event blue flagged as a canary/decoy/honeytoken. Honeytokens
    have ~zero false-positive rate, so a touch is appended DETERMINISTICALLY (the tripwire's value is
    not that it alerts 98% of the time, but that it almost never false-alarms); p_fire records the
    near-certain weight it carries into the noisy-OR belief. Read ONLY from the log + blue's own traps."""
    hset = {str(h).lower() for h in (honeytokens or [])}
    trips = []
    for e in entries:
        if e.get("actor") != "red":
            continue
        d = e.get("data") or {}
        tgt = str(d.get("target") or d.get("dst") or d.get("spn") or d.get("user") or "")
        is_trip = bool(d.get("canary") or d.get("decoy") or d.get("honeytoken") or d.get("honey_spn"))
        if not is_trip and hset and tgt.lower() in hset:
            is_trip = True
        if is_trip:
            trips.append({"seq": e.get("seq"), "stage": "credential_access",
                          "technique": d.get("technique") or d.get("attack") or "T1558.003",
                          "target": tgt or None, "confirmed": True, "p_fire": _P_HONEYTOKEN,
                          "basis": "honeytoken-tripwire (near-zero false-positive)", "d3fend": "D3-DST"})
    return trips


def _bernoulli_detections(entries, rng, honeytokens=()):
    """Per-event Bernoulli detection over the spine stream: a gated red action fires with p keyed
    on its stage's detectability; tamper (T1070/T1562) is first-class (loud, tamper-evident); an
    observer-CONFIRMED state transition is near-certain. A honey-SPN / decoy TRIPWIRE hit is folded
    in near-certain. Blue's partial, noisy sight — read ONLY from the log, never red's ground truth."""
    from swarm.blue_fast import detect_kill_chain
    fired = []
    for d in detect_kill_chain(entries):
        if d.get("technique") in _TAMPER_TECHS:
            p = _P_TAMPER                               # first-class: never a stealthy miss
        elif d.get("confirmed"):
            p = _CONFIRMED_P
        else:
            p = _P_FIRE.get(d["stage"], 0.3)
        if rng.random() < p:
            fired.append({**d, "p_fire": round(p, 2)})
    fired.extend(_honeytoken_trips(entries, honeytokens))   # tripwires: near-certain, ~0 false-positive
    return fired


def _belief(fired):
    """p_compromise via noisy-OR of the fired detections; scope = hosts touched."""
    p_miss = 1.0
    for f in fired:
        p_miss *= (1.0 - f["p_fire"])
    p_comp = round(1.0 - p_miss, 3)
    scope = sorted({f["target"] for f in fired if f.get("target")})
    return {"p_compromise": p_comp, "confidence": p_comp, "scope": scope,
            "impact_active": any(f["stage"] == "exfiltration" for f in fired),
            "detections": len(fired)}


# ── Stealth regime: the login-graph discriminator (the DISCRIMINATING-BLUE layer) ──────────────
# When a benign baseline exists, a bare "Accepted password" (T1021) is NO LONGER evidence of
# intrusion — legitimate logins share the exact signature. Blue must discriminate by BEHAVIOR. The
# load-bearing behavioral signal is the LOGIN GRAPH: blue LEARNS the normal (src->dst) edge set from
# a benign warmup period (label-free — it is told nothing is benign, the period simply has no red),
# then during the contest an edge it never saw in the baseline is ANOMALOUS. Benign contest logins
# ride known edges (silent); red's lateral movement onto a sensitive host it never legitimately
# reached is a NOVEL edge (loud) — UNLESS red rides a legitimate edge (living-off-the-land), which a
# graph-anomaly detector cannot see. That blindness is the detector's real efficacy boundary, not a
# tuned threshold.
class LoginGraphDiscriminator:
    """Blue's learned model of the normal login graph. `observe()` adds an edge to the baseline
    (called on the benign WARMUP stream, before the contest); `is_anomalous()` flags a contest edge
    the baseline never contained. Label-FREE: it reads only (source,target) off a telemetry detection
    — never a benign/malicious label. `frozen` after warmup so red cannot normalize its own edge by
    repeating it (a detector that keeps learning during the attack would launder the intrusion)."""

    def __init__(self):
        self.baseline = set()     # {(src, dst)} learned as normal
        self.frozen = False

    def observe(self, detection):
        src, dst = detection.get("source"), detection.get("target")
        if src and dst and not self.frozen:
            self.baseline.add((src, dst))
        return self

    def learn_from(self, detections):
        for d in detections:
            self.observe(d)
        return self

    def freeze(self):
        self.frozen = True
        return self

    def is_anomalous(self, detection):
        """A lateral-movement (T1021) detection on a (src,dst) edge absent from the learned baseline.
        A known-edge login is NOT anomalous (benign logins ride known edges); a detection with no
        edge (e.g. an exploit fault or exfil) is not a GRAPH judgement — those keep their own weight
        and are handled outside the graph gate."""
        if detection.get("technique") != "T1021":
            return False
        src, dst = detection.get("source"), detection.get("target")
        if not (src and dst):
            return False
        return (src, dst) not in self.baseline


def _discriminate(fired, discriminator):
    """Reweight blue's detections through the graph discriminator (the stealth-regime belief input).
    A lateral login on a KNOWN-benign edge carries ~no intrusion evidence (p_fire -> 0): blue does
    NOT alert on the presence of a login. A lateral login on a NOVEL edge keeps full weight (the
    anomaly). Non-lateral detections (exploit faults, exfil, honeytokens) are not graph-gated and
    pass through unchanged. Returns (discriminated_fired, anomalous_edges)."""
    if discriminator is None:
        return fired, []
    out, anomalous = [], []
    for d in fired:
        if d.get("technique") == "T1021" and d.get("source") and d.get("target"):
            if discriminator.is_anomalous(d):
                anomalous.append((d["source"], d["target"]))
                out.append({**d, "basis": d.get("basis", "") + " | graph-anomaly: novel edge",
                            "anomalous_edge": True})
            # a known-edge login is dropped from the belief input (benign-looking; no alert)
        else:
            out.append(d)
    return out, anomalous


def run_blue_fight(log, gate, *, router=None, contain_fn=None, max_hosts=10, detect=None,
                   ticks_per_host=3, rng_seed=1337, honeytokens=(), executors=None,
                   telemetry_fired=None, **_ignored):
    """The ONE blue fight engine: the single replacement for the retired fast-tier fight loop and
    live_duel's belief blue (both deleted). Detect kill-chain STRUCTURE, then drive BlueAgent to
    triage + contain each confirmed compromise over the realistic D3FEND action set (Phase 4), every
    action gate-mediated (same floor as red) and a stop-the-spread control recorded as a confirmed
    observable (confirm/mutate "contained") via the spine — the semantics mttc_mttd / survive_the_fix
    read. `router` defaults to the dry reversible-first backend (DryBlueRouter); pass an LLM router for
    a real-model blue — the SAME one engine either way.

    Phase 4 decision model (enforced here, not just prompted): each response is authorized by
    `blue_decision(confidence, blast_radius_contained, reversible)` — a reversible control fires
    readily; an irreversible eviction is GATED until a reversible control has been tried on the host
    AND the score clears the bar (high confidence + understood scope), so even an LLM blue cannot fire
    an eviction below threshold. `honeytokens` is blue's own tripwire set (a hit => near-certain
    detection); `executors` injects REAL effect callables per tool (default: a fidelity-labelled sim,
    so the dry proof is offline). `**_ignored` absorbs retired run_belief_blue kwargs.
    Returns {belief, detections, contained, killchain}."""
    from swarm import spine
    from swarm.blue_fast import detect_kill_chain as _default_detect, _sim_contain
    detect = detect or _default_detect
    contain_fn = contain_fn or _sim_contain
    executors = dict(executors or {})

    dets = detect(log.entries())
    log.append("blue", "detect.killchain",
               {"detections": len(dets), "basis": "kill-chain structure (payload-independent)",
                "stages": sorted({d["stage"] for d in dets})})
    compromised = [d for d in dets if d.get("confirmed")
                   and d["stage"] in ("initial_access", "lateral_movement")]

    # belief-driven sight -> noisy-OR belief, the signals the L1 gate (live_gates) reads. The fight
    # is watch-vs-contain gated on the belief. Increment 2: when the caller supplies
    # `telemetry_fired` (sensor_real detections over the REAL captured service logs), belief derives
    # from what the sensors actually saw — label-free, each detection traced to a telemetry line.
    # Without it, blue falls back to the MODELED per-stage Bernoulli over the spine (honestly
    # labelled as such — the no-shortcuts clause: never a fake-real detector).
    if telemetry_fired is not None:
        from swarm import sensor_real
        sensor_real.assert_label_free(telemetry_fired)       # air-gap: every det traces to telemetry
        fired = list(telemetry_fired) + _honeytoken_trips(log.entries(), honeytokens=honeytokens)
        detector = "real-telemetry"
        detector_note = ("sensor_real sigma signatures on the captured service logs (label-free; "
                         "each detection traces to a real log line) + blue's own honeytoken tripwires")
    else:
        fired = _bernoulli_detections(log.entries(), _random.Random(rng_seed), honeytokens=honeytokens)
        detector = "modeled"
        detector_note = ("per-stage Bernoulli over the spine structure (MODELED sight — no "
                         "real-telemetry detector supplied; belief is a model, not sensor-derived)")
    log.append("blue", "blue.detector", {"detector": detector, "basis": detector_note,
               "real_telemetry": telemetry_fired is not None, "detections": len(fired)})
    for f in fired:
        # NOTE: the event name `blue.detect.bernoulli` is a legacy schema key the L1 gate reads; the
        # `basis`/`source_line` fields carry the honest provenance (real-telemetry vs modeled).
        log.append("blue", "blue.detect.bernoulli",
                   {"stage": f["stage"], "technique": f.get("technique"), "target": f.get("target"),
                    "p_fire": f["p_fire"], "basis": f["basis"], "source_line": f.get("source_line"),
                    "confirmed": f.get("confirmed", False), "d3fend": f.get("d3fend", "D3-DA")})
    belief = _belief(fired)
    log.append("blue", "blue.belief", {**belief, "mode": "blind", "detector": detector,
               "note": "Bayesian observer; scope is a LOWER BOUND on true compromise"})
    if not (belief["confidence"] >= _CONTAIN_CONFIDENCE or belief["impact_active"]):
        log.append("blue", "blue.watch", {"reason": "confidence below contain gate",
                   "confidence": belief["confidence"], "threshold": _CONTAIN_CONFIDENCE})
        return {"belief": belief, "detections": fired, "contained": [], "killchain": dets}

    # The D3FEND response tool-set + belief-driven decision machinery, SHARED with the interleaved
    # duel driver (one blue logic; belief is read live by reference so a per-tick driver sees the
    # current belief). `state` tracks investigated/contained/reversible_tried across ticks.
    belief_ref = dict(belief)
    state = {"investigated": set(), "contained": [], "reversible_tried": {}}
    # suspected intrusion scope = confirmed-compromised hosts (killchain), falling back to belief
    # scope — the denominator for an eviction's blast radius. Fixed here (post-hoc); the interleaved
    # driver passes a getter over its LIVE belief instead.
    suspected = {d["target"] for d in compromised if d.get("target")} or set(belief.get("scope") or [])
    tools = build_blue_tools(log, gate, belief_ref, state, contain_fn=contain_fn,
                             executors=executors, suspected_fn=lambda: suspected)

    blue = BlueAgent(router or DryBlueRouter(), log, tools, strict=True)
    for d in compromised[:max_hosts]:
        host = d["target"]
        if host in state["contained"]:
            continue
        alerts = [{"technique": d.get("technique") or "T1021", "host": host,
                   "source": "killchain", "note": d["stage"]}]
        for _ in range(ticks_per_host):   # triage, reversible contain, escalate — up to the tick cap
            blue.tick(alerts)
            if host in state["contained"]:
                break
    return {"belief": belief, "detections": fired, "contained": state["contained"], "killchain": dets}


def build_blue_tools(log, gate, belief_ref, state, *, contain_fn=None, executors=None,
                     suspected_fn=None):
    """The D3FEND response tool-set, gate-mediated — the SINGLE blue action logic shared by the
    post-hoc run_blue_fight and the interleaved duel driver (no parallel blue). `belief_ref` is read
    LIVE (a mutable dict the caller updates per tick), so the reversible-first + blast-bounded
    eviction decision always reflects blue's CURRENT belief. `suspected_fn() -> set` gives the
    believed intrusion scope (the eviction-blast denominator); the driver passes a getter over its
    live belief, run_blue_fight a fixed set. `state` carries investigated/contained/reversible_tried
    across ticks. Returns {tool_name: callable(**args)->result}."""
    from swarm.blue_fast import _sim_contain                 # one effect default (no module-level dep)
    from swarm import spine                                   # confirm/mutate the contained observable
    contain_fn = contain_fn or _sim_contain
    executors = dict(executors or {})
    suspected_fn = suspected_fn or (lambda: set(belief_ref.get("scope") or []))

    def _suspected():
        return suspected_fn()

    def _blast(host, whole_scope):
        """blast_radius_contained in [0,1]. REVERSIBLE: per-host (is THIS host triaged — a reversible
        move is a safe default once understood). IRREVERSIBLE: the fraction of the WHOLE believed
        intrusion scope blue has correlated, so an eviction fires only once scope is understood."""
        if not whole_scope:
            return 1.0 if host in state["investigated"] else 0.3
        suspected = _suspected()
        if not suspected:
            return 1.0 if host in state["investigated"] else 0.0
        return round(len(state["investigated"] & suspected) / len(suspected), 4)

    def _effect(tool, host, user=None):
        """The real executor if injected, else a fidelity-labelled sim. contain_fn remains the
        isolate_host executor for backward-compatibility."""
        fn = executors.get(tool) or (contain_fn if tool == "isolate_host" else None)
        if fn is not None:
            return fn(f"range-{host}")
        return {"fidelity": "sim", "tool": tool, "host": host, "simulated": True}

    def _investigate_tool(host=None, **a):
        state["investigated"].add(host)
        log.append("blue", "blue.investigate", {"host": host, "finding": "confirmed intrusion",
                   "scope_understood": _blast(host, whole_scope=True)})
        return {"finding": "confirmed intrusion", "host": host}

    def _response_tool(tool, d3fend):
        reversible = tool in REVERSIBLE

        def _run(host=None, user=None, **a):
            if host in state["contained"]:
                return {"contained": True, "host": host, "already": True}
            dec = blue_decision(belief_ref.get("confidence", 0.0), _blast(host, whole_scope=not reversible),
                                reversible)
            dec.update({"tool": tool, "host": host, "d3fend": d3fend})
            # reversible-FIRST: an irreversible eviction is never a first move — a reversible control
            # must have been tried on this host, AND the score must clear the bar.
            if not reversible and host not in state["reversible_tried"]:
                log.append("blue", "blue.evict_gated", {"host": host, "tool": tool, "d3fend": d3fend,
                           "reason": "reversible-first: no reversible control tried yet", "decision": dec})
                return {"gated": True, "reason": "reversible-not-tried", "tool": tool, "decision": dec}
            if not dec["authorized"]:
                log.append("blue", "blue.evict_gated", {"host": host, "tool": tool, "d3fend": d3fend,
                           "reason": "decision below threshold", "decision": dec})
                return {"gated": True, "reason": "below-threshold", "tool": tool, "decision": dec}
            res = gate.dispatch("blue", tool, host, lambda: _effect(tool, host, user),
                                meta=spine.coords("blue-sensor", host, 0, d3fend))
            _real = isinstance(res, dict) and str(res.get("fidelity", "")).lower() == "real"
            # a stop-the-spread control emits the CANONICAL "blue.contain" beat the rest of the system
            # recognizes; other D3FEND responses emit "blue.respond".
            beat = "blue.contain" if tool in _STOPS_SPREAD else "blue.respond"
            log.append("blue", beat, {"host": host, "tool": tool, "d3fend": d3fend,
                       "reversible": reversible, "result": res, "decision": dec,
                       "fidelity": "real" if _real else "sim"})
            # B3 — the air-gapped per-tick signal for blue's OWN episodic memory: the response CLASS it
            # chose (its tool + D3FEND technique), never a red label/CVE. EpisodicMemory.distill reads
            # this `move.source` `chose` field, so blue's memory path is non-empty and label-free
            # (closing the chose/tool schema mismatch without a seed-handed technique).
            log.append("blue", "move.source", {"source": "telemetry", "stage": "respond",
                       "chose": f"{tool}->{d3fend}"})
            if reversible:
                state["reversible_tried"].setdefault(host, set()).add(tool)
            if tool in _STOPS_SPREAD:
                # B1 — prevention is gated on a REAL effect (fidelity=="real") or a telemetry-confirmed
                # cessation, NOT dispatch success. A dispatched-but-unverified (SIMULATED) containment
                # is still LOGGED above (the beat, for transparency) but does NOT advance the spine or
                # set contained/prevented — otherwise a no-op containment would score as prevention and
                # inflate MTTC / blue's contain_speed fitness.
                _ceased = isinstance(res, dict) and bool(res.get("telemetry_confirmed_cessation"))
                if _real or _ceased:
                    cf = spine.confirm(log, "contained", host, observed_by="range", simulated=False,
                                       method=((res.get("method") if isinstance(res, dict) else None)
                                               or ("real eviction verified out-of-band" if _real
                                                   else "telemetry-confirmed cessation")))
                    spine.mutate(log, "blue", "contained", host, cf["seq"], technique=d3fend)
                    if host not in state["contained"]:
                        state["contained"].append(host)
                    return {"contained": True, "host": host, "tool": tool}
                log.append("blue", "blue.contain_unverified",
                           {"host": host, "tool": tool, "d3fend": d3fend, "result": res,
                            "note": "dispatched but not fidelity=real / telemetry-confirmed — NOT counted "
                                    "as prevention (B1): no spine mutate, not added to contained"})
                return {"contained": False, "host": host, "tool": tool, "unverified": True}
            return {"responded": True, "host": host, "tool": tool}
        return _run

    tools = {"investigate": _investigate_tool, "wait": lambda **a: {"held": True}}
    for _t, (_d3, _rev, _rank) in D3FEND_ACTIONS.items():
        if _t != "investigate":
            tools[_t] = _response_tool(_t, _d3)
    return tools


def run_interleaved_duel(log, gate, *, red_router, red_tools, start_subnet, telemetry_window,
                         objective=None, awareness=None, strict=True, max_turns=40,
                         contain_fn=None, executors=None, honeytokens=(),
                         threshold=_CONTAIN_CONFIDENCE, blue_router=None, blue_contains=True,
                         benign_window=None, discriminator=None, benign_hosts=(), io_sink=None,
                         episodic_recall=None):
    """The ONE deterministic turn-interleaved duel — REPLACES the sequential run_red_agent-then-
    run_blue_fight. Each tick: RED takes ONE action (through the same gate/spine/eventlog), then BLUE
    observes the telemetry produced SINCE THE LAST TICK (label-free, real-telemetry detector),
    updates belief, and MAY act (contain/evict) — and blue's action LANDS before red's next tick (if
    blue isolates red's foothold at tick N, red's tick N+1 from it fails, route gone). The event
    order is a clean total order (red tick, blue tick, …) that re-derives cold; NO threads/async.

    This measures PREVENTION under a defined observe-cadence (one blue observe+act per red action) —
    a pre-registered parameter, NOT tuned, and not a wall-clock latency claim.

    `telemetry_window()` returns THIS tick's NEW real-telemetry detections (the caller windows docker
    logs `--since` the last tick and runs sensor_real.telemetry_detections; in dry it may return []).
    `contain_fn`/`executors` are blue's REAL effect callables (a no-op contain_fn makes theft
    reachable; a real one makes prevention reachable — the race is real, not rigged).
    `blue_contains=False` is the OBSERVE-ONLY control: blue's full real-telemetry detector runs and
    logs belief + blue.detect.* every tick and records the tick it WOULD have contained
    (`blue.would_contain`), but takes NO containment/eviction/decoy action, so red is never severed —
    the baseline that shows what the red does UNOPPOSED.

    STEALTH REGIME (benign baseline on): `benign_window()` returns this tick's label-free BENIGN
    login detections (same shape/signature as red's — `swarm.benign_baseline`); they merge into
    blue's detection stream with NO benign label. `discriminator` (a LoginGraphDiscriminator pre-
    trained on the benign warmup) makes blue discriminate by BEHAVIOR: a login on a known-benign edge
    is silent, a novel edge is the anomaly. `benign_hosts` is ground-truth (SCORING ONLY, never in
    blue's view) used to record FALSE-POSITIVE containments (`benign_contained`). Returns {red,
    belief, contained, achieved, prevented, duel_outcome}."""
    from swarm.live_agent import run_red_agent
    from swarm import benign_baseline as benign_baseline_mod

    state = {"investigated": set(), "contained": [], "reversible_tried": {}}
    belief_ref = {"p_compromise": 0.0, "confidence": 0.0, "scope": [], "impact_active": False,
                  "detections": 0}
    fired, fired_keys = [], set()
    blue_tools = build_blue_tools(log, gate, belief_ref, state, contain_fn=contain_fn,
                                  executors=executors,
                                  suspected_fn=lambda: set(belief_ref.get("scope") or []))
    blue = BlueAgent(blue_router or DryBlueRouter(), log, blue_tools, strict=False)
    oc = {"first_contain_seq": None, "first_contain_tick": None, "would_contain_tick": None}

    def _blue_step(red_rec):
        """One blue observe+decide+maybe-act, fired by the driver AFTER each red action and BEFORE
        red's next (via run_red_agent's on_turn hook). Belief derives ONLY from real telemetry
        (label-free) + blue's own honeytokens — never red's labels. With `blue_contains=False`
        (observe-only control), blue's full detector runs and logs every tick and records the tick it
        WOULD have contained, but takes NO effect — red is never severed."""
        tick = red_rec.get("turn")
        # the per-tick detections: red's real telemetry + (stealth regime) the benign baseline's
        # label-free logins + blue's own honeytoken tripwires. The benign stream carries NO label —
        # blue cannot tell a benign login from red's by anything but behavior.
        benign_new = list(benign_window() or []) if benign_window else []
        if benign_new:                                  # air-gap: benign labels must never reach blue
            benign_baseline_mod.assert_benign_label_free(benign_new)
        # B3 — the ENGINE self-enforces the air-gap: assert the per-tick real-telemetry window is
        # label-free (every detection traces to a real log line + a real-telemetry basis, never a
        # red-internal label) INSIDE run_interleaved_duel, so a future driver that builds its own
        # window and forgets the wrapper still cannot feed blue red's labels. The driver's own
        # assert_label_free is now belt-and-suspenders, not the only guard.
        from swarm import sensor_real as _sr
        tele_new = _sr.assert_label_free(list(telemetry_window() or []))
        new = (tele_new + benign_new
               + _honeytoken_trips(log.entries(), honeytokens=honeytokens))
        newly = []
        for d in new:
            # the login graph distinguishes edges, so dedup on (source,target,technique): a benign
            # login and a red login to the same host are DIFFERENT detections (different source edge).
            k = (d.get("source"), d.get("target"), d.get("technique"))
            if k not in fired_keys:
                fired_keys.add(k)
                fired.append(d)
                newly.append(d)
        # DISCRIMINATING BLUE: in the stealth regime a bare login is not evidence — only an anomalous
        # login-graph edge is. _discriminate drops known-benign-edge logins from the belief input and
        # keeps novel edges; with no discriminator it is the identity (loud regime unchanged).
        disc, anomalous = _discriminate(fired, discriminator)
        belief_ref.update(_belief(disc))
        for d in newly:                                 # the detection timeline, label-free + traced
            log.append("blue", "blue.detect.bernoulli",
                       {"stage": d.get("stage"), "technique": d.get("technique"), "target": d.get("target"),
                        "source": d.get("source"), "p_fire": d.get("p_fire"), "basis": d.get("basis"),
                        "source_line": d.get("source_line"), "confirmed": d.get("confirmed", False), "tick": tick})
        log.append("blue", "blue.detector", {"detector": "real-telemetry", "tick": tick,
                   "detections": len(fired), "belief_inputs": len(disc), "real_telemetry": True,
                   "blue_contains": blue_contains, "discriminating": discriminator is not None,
                   "anomalous_edges": [list(e) for e in anomalous],
                   "basis": ("sensor_real signatures on the per-tick telemetry window (label-free); "
                             "login-graph discrimination" if discriminator is not None
                             else "sensor_real signatures on the per-tick telemetry window (label-free)")})
        log.append("blue", "blue.belief", {**belief_ref, "mode": "blind", "detector": "real-telemetry",
                   "tick": tick, "note": "Bayesian observer; scope is a LOWER BOUND on true compromise"})
        crossed = belief_ref["confidence"] >= threshold or belief_ref.get("impact_active")
        if crossed and oc["would_contain_tick"] is None:
            oc["would_contain_tick"] = tick             # the tick blue WOULD act (makes the race readable)
            log.append("blue", "blue.would_contain", {"tick": tick, "confidence": belief_ref["confidence"],
                       "threshold": threshold, "scope": belief_ref.get("scope"), "blue_contains": blue_contains,
                       "note": ("belief first crossed the containment threshold; OBSERVE-ONLY control, "
                                "blue takes NO effect" if not blue_contains
                                else "belief crossed the threshold; blue acts this tick")})
        if crossed and blue_contains:                   # observe-only (False): blue never severs red
            # act ONLY on the discriminated belief inputs (the anomalies) — never on a benign login
            # blue dropped as evidence. In the loud regime disc == fired, so this is unchanged.
            alerts = [{"technique": d.get("technique"), "host": d.get("target"), "source": "telemetry",
                       "note": d.get("stage")} for d in disc if d.get("target")]
            if alerts:
                pre = set(state["contained"])
                blue.tick(alerts)                       # one blue decision -> one gate-mediated action
                if set(state["contained"]) - pre and oc["first_contain_tick"] is None:
                    oc["first_contain_tick"] = tick     # when blue FIRST contained (raw fact)
                    oc["first_contain_seq"] = (log.entries()[-1] or {}).get("seq")

    # memory-on (Unit L): red's cross-episode episodic recall (its OWN prior-engagement lessons —
    # general tradecraft, never this range's map) is threaded straight to run_red_agent, which folds
    # it into the system prompt. The driver asserts the recall is map-blind (assert_red_map_blind with
    # episodic_recall=) before this runs, so a memory leak bites at episode start, not here.
    red_res = run_red_agent(log, red_router, tools=red_tools, start_subnet=start_subnet,
                            max_turns=max_turns, strict=strict, awareness=awareness,
                            objective=objective, on_turn=_blue_step, io_sink=io_sink,
                            episodic_recall=episodic_recall)
    achieved = red_res.get("outcome") == "crown_looted"
    prevented = (not achieved) and bool(state["contained"])
    # FALSE-POSITIVE accounting: a contained host that is in the benign baseline AND was NOT actually
    # compromised by red is measured damage (blue cut off a legitimate host). benign_hosts is GROUND
    # TRUTH for scoring — it never entered blue's view; blue contained on its own (mistaken) graph
    # judgement. A host red truly owns is a LEGITIMATE containment even if it also sees benign traffic
    # (db-core receives benign logins yet is red's target), so red-owned hosts are excluded.
    _benign = set(benign_hosts or ())
    _red_owned = set(red_res.get("owned") or [])
    benign_contained = [h for h in state["contained"] if h in _benign and h not in _red_owned]
    # Honest reporting: first_contain_* is the raw fact (when blue first contained, if ever);
    # tick_of_prevention/prevented_by_seq are set ONLY when prevention actually held (red did NOT
    # achieve the objective AND blue contained) — a no-op/ineffective containment is NOT a prevention.
    duel_outcome = {"objective": objective, "achieved": achieved, "prevented": prevented,
                    "blue_contains": blue_contains,
                    "tick_of_objective": (red_res.get("turns", 0) - 1) if achieved else None,
                    "first_contain_tick": oc["first_contain_tick"], "first_contain_seq": oc["first_contain_seq"],
                    "would_contain_tick": oc["would_contain_tick"],   # when blue's belief first crossed
                    "tick_of_prevention": oc["first_contain_tick"] if prevented else None,
                    "prevented_by_seq": oc["first_contain_seq"] if prevented else None,
                    "contained": list(state["contained"]), "blue_detections": len(fired),
                    "benign_contained": benign_contained,       # FALSE POSITIVES (scoring ground truth)
                    "false_positive": bool(benign_contained),
                    "discriminating": discriminator is not None, "benign_baseline": benign_window is not None,
                    "cadence": "one blue observe+act per red action (pre-registered, not tuned)"}
    log.append("system", "duel.outcome", duel_outcome)
    return {"red": red_res, "belief": dict(belief_ref), "contained": list(state["contained"]),
            "achieved": achieved, "prevented": prevented, "duel_outcome": duel_outcome}


class BlueAgent:
    """A standing SOC analyst. `tools` is {name: callable(**args)->result}; each is a real,
    gate-mediated defender action wired by the duel driver. `.tick(alerts)` runs one decision
    (blue's turn), interleaved with red's turns by the duel clock."""

    def __init__(self, router, log, tools, *, role="blue.orchestrator", turn_timeout=120,
                 strict=True, awareness=None):
        self.router, self.log, self.tools = router, log, tools
        self.role, self.turn_timeout, self.strict = role, turn_timeout, strict
        self.awareness = awareness           # folded response-frontier as a hint (not a ceiling)
        self.memory = []
        self.actions = []
        self._investigated, self._contained = set(), set()   # feed the awareness frontier

    def tick(self, alerts):
        uc = getattr(self.router, "usage", None)
        n0 = len(uc.calls) if uc else 0
        action = None
        # Log blue's OWN lossy sensor picture this tick so the toolkit-first doctrine (and any
        # pure-log reader) re-derives which hosts blue suspects — no in-memory claim, never red's
        # log. Logged BEFORE the decision so an author_tool chosen this tick sees it on the chain.
        _alert_hosts = sorted({a.get("host") for a in (alerts or []) if a.get("host")})
        if _alert_hosts:
            self.log.append("blue", "blue.observe", {"stage": "blue", "alert_hosts": _alert_hosts})
        try:
            prompt = _render(alerts, self.memory)
            if self.awareness:                           # folded belief/frontier as a hint
                try:
                    prompt += self.awareness(alerts, contained=self._contained,
                                             investigated=self._investigated) or ""
                except Exception:                        # noqa: BLE001  (awareness is best-effort)
                    pass
            with _wall_clock(self.turn_timeout):
                raw = self.router.chat(self.role, [{"role": "system", "content": BLUE_SYS},
                                       {"role": "user", "content": prompt}],
                                       temperature=0.3, max_tokens=200)
                action = _parse_action(raw)
        except _TurnTimeout:
            self.log.append("blue", "move.source", {"source": "turn_timeout", "stage": "blue"})
            return None
        except Exception as e:                               # noqa: BLE001
            self.log.append("blue", "move.source", {"source": "router_error", "stage": "blue",
                            "error": str(e)[:200]})
            if self.strict:
                raise
            return None
        if action is None:
            self.log.append("blue", "move.source", {"source": "reflector_veto", "stage": "blue",
                            "raw": (raw or "")[:120]})
            return None
        call = uc.calls[-1] if (uc and len(uc.calls) > n0) else {}
        self.log.append("blue", "move.source", {"source": "llm", "stage": "blue",
                        "tool": action["tool"], "args": action["args"], "thought": action["thought"],
                        "model": call.get("model", "?"), "tier": call.get("tier", "?")})
        if action["tool"] == "wait":
            rec = {"tool": "wait", "args": action["args"], "result": {"held": True}}
            self.memory.append(rec); self.actions.append(rec)
            return rec
        fn = self.tools.get(action["tool"])
        if fn is None:
            rec = {"tool": action["tool"], "args": action["args"], "result": {"error": "no such tool"}}
            self.memory.append(rec); return rec
        try:
            result = fn(**(action["args"] or {})) or {}
        except _TurnTimeout:
            raise
        except Exception as e:                               # noqa: BLE001 (OutOfScope etc. -> observation)
            result = {"error": type(e).__name__, "blocked": "OutOfScope" in type(e).__name__}
        rec = {"tool": action["tool"], "args": action["args"], "result": result}
        self.memory.append(rec); self.actions.append(rec)
        # feed the awareness frontier: what blue has investigated / successfully contained.
        tgt = action["args"].get("host") or action["args"].get("ip")
        if tgt and not result.get("error"):
            if action["tool"] == "investigate":
                self._investigated.add(tgt)
            elif action["tool"] in ("isolate_host", "kill_session", "revoke_cred", "block_ip"):
                self._contained.add(tgt)
        return rec


if __name__ == "__main__":  # self-check: autonomous blue decides from alerts, offline (no network)
    from swarm.eventlog import EventLog
    import tempfile

    calls = {"investigate": 0, "revoke": 0, "wait": 0}

    def t_investigate(**a):
        calls["investigate"] += 1
        return {"host": a.get("host"), "finding": "sshd Accepted-publickey for svc; foreign process 'sh'"}

    def t_revoke(**a):
        calls["revoke"] += 1
        return {"contained": True, "host": a.get("host")}

    def t_wait(**a):
        calls["wait"] += 1
        return {"held": True}

    TOOLS = {"investigate": t_investigate, "revoke_cred": t_revoke,
             "isolate_host": lambda **a: {"isolated": True}, "lock_account": lambda **a: {"locked": True},
             "invalidate_auth_cache": lambda **a: {"invalidated": True},
             "kill_session": lambda **a: {"killed": True}, "rotate_cred": lambda **a: {"rotated": True},
             "block_ip": lambda **a: {"blocked": True}, "deploy_decoy": lambda **a: {"planted": True},
             "suspend_process": lambda **a: {"suspended": True}, "block_egress": lambda **a: {"filtered": True},
             "block_dns": lambda **a: {"denylisted": True}, "shutdown_host": lambda **a: {"down": True},
             "counter_recon": lambda **a: {"scanned": True}, "hunt": lambda **a: {"hits": []}}

    # a reactive stub analyst: no alert -> wait; a pivot alert -> investigate, then contain.
    class _Stub:
        def __init__(self):
            class U:
                calls = []
            self.usage = U()
            self.step = 0

        def chat(self, role, messages, **kw):
            self.usage.calls.append({"model": "stub", "tier": "ultra"})
            text = messages[-1]["content"]
            self.step += 1
            if "no alerts firing" in text:
                return json.dumps({"thought": "quiet", "tool": "wait", "args": {"reason": "no threat"}})
            if "foreign process" not in text:   # alert present, not yet triaged -> investigate first
                return json.dumps({"thought": "triage", "tool": "investigate", "args": {"host": "crown_db"}})
            return json.dumps({"thought": "confirmed intrusion", "tool": "revoke_cred",
                               "args": {"host": "crown_db", "user": "svc"}})

    p = Path(tempfile.mktemp(suffix=".jsonl")); log = EventLog(p)
    blue = BlueAgent(_Stub(), log, TOOLS, strict=True)

    # tick 1: no alerts -> blue WAITS (handled internally; does not false-positive on benign hosts)
    r1 = blue.tick([])
    assert r1["tool"] == "wait" and r1["result"].get("held") is True, r1
    # tick 2: a pivot alert -> blue INVESTIGATES first (triage, not reflex)
    r2 = blue.tick([{"technique": "T1021", "host": "crown_db", "source": "auditd", "note": "ssh login"}])
    assert r2["tool"] == "investigate" and calls["investigate"] == 1, r2
    # tick 3: with the finding in memory -> blue CONTAINS (a real gate-mediated effect)
    r3 = blue.tick([{"technique": "T1021", "host": "crown_db", "source": "auditd"}])
    assert r3["tool"] == "revoke_cred" and r3["result"]["contained"] and calls["revoke"] == 1, r3

    ev = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    moves = [e for e in ev if e["action"] == "move.source" and e["data"]["source"] == "llm"]
    assert len(moves) == 3 and all(m["data"]["stage"] == "blue" for m in moves), moves
    assert {m["data"]["tool"] for m in moves} == {"wait", "investigate", "revoke_cred"}, moves
    p.unlink(missing_ok=True)

    # ── DRY BlueAgent backend: the one engine runs the reversible-FIRST escalation ladder with NO
    # LLM. Same BlueAgent, a DryBlueRouter instead of a model. Ladder: investigate (triage) ->
    # isolate_host (reversible network-contain) -> lock_account (reversible) -> invalidate_auth_cache
    # -> revoke_cred (the Account-Lock -> Auth-Cache-Invalidate -> Revoke eviction escalation).
    pd = Path(tempfile.mktemp(suffix=".jsonl"))
    logd = EventLog(pd)
    dblue = BlueAgent(DryBlueRouter(), logd, TOOLS, strict=True)
    al = [{"technique": "T1021", "host": "crown_db", "source": "edr", "note": "anomalous logon"}]
    picks = [dblue.tick([])["tool"]] + [dblue.tick(al)["tool"] for _ in range(5)]
    assert picks[0] == "wait" and picks[1] == "investigate", picks
    assert picks[2] == "isolate_host" and picks[3] == "lock_account", ("reversible first", picks)
    assert picks[4] == "invalidate_auth_cache" and picks[5] == "revoke_cred", ("evict escalation after", picks)
    _first_irrev = next(i for i, t in enumerate(picks) if t in IRREVERSIBLE)
    assert all(t in REVERSIBLE or t in ("wait", "investigate") for t in picks[:_first_irrev]), \
        ("every reversible control precedes the first irreversible one", picks)
    pd.unlink(missing_ok=True)

    # ── run_blue_fight: the one-engine fight (it replaced the retired fast-tier fight loop as a
    # drop-in), re-homing the Brick-2 fight properties onto BlueAgent. Reuses B2's exact setup.
    import sys as _sys
    from swarm.gate import Gate
    from swarm.topo_to_compose import generate_range, load_pool, emit_range_topology
    from swarm.live_red import run_sim_red
    from swarm.blue_fast import mttc_mttd, survive_the_fix
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "redteam"))
    import reverify_floor as _rvf

    rr = generate_range(1337, load_pool())
    pf = Path(tempfile.mktemp(suffix=".jsonl"))
    logf = EventLog(pf)
    logf.append("system", "scope", {"in_scope": rr["scope"]["in_scope"]})
    emit_range_topology(logf, rr)
    gatef = Gate([], logf, scope_by_actor=rr["scope_by_actor"])
    run_sim_red(gatef, logf, rr)                       # Brick-1 red: confirmed footholds
    # B1 — prevention is gated on a REAL effect, so the fight is driven with a REAL containment
    # executor (fidelity=real); a dispatched eviction then registers as a confirmed containment.
    _real_fx = lambda c: {"contained": True, "fidelity": "real",
                          "method": "test: real eviction verified out-of-band"}
    res = run_blue_fight(logf, gatef, contain_fn=_real_fx)   # the one-engine fight (BlueAgent+DryBlueRouter)
    E = logf.entries()
    comp = {(e["data"] or {}).get("dst") for e in E if e["action"] == "state.mutate"
            and (e["data"] or {}).get("state") in ("foothold", "lateral")}
    assert res["contained"] and set(res["contained"]) & comp, (res, "no real compromise contained")
    assert any(e["action"] == "state.mutate" and (e["data"] or {}).get("state") == "contained"
               for e in E), "containment not a confirmed observable"
    m = mttc_mttd(E)
    assert m["containment_confirmed"] and not m["mttc_lt_mttd_inversion"], m   # MTTC real, no inversion
    s = survive_the_fix(E, in_scope=rr["scope"]["in_scope"])
    assert s["survived"] and s["sdr"] == 0.0, s                                # survive-the-fix, no self-DoS
    vr = _rvf.reverify(str(pf))
    assert vr["chain_verified"] and vr["oos_executed"] == 0, vr                # floor cold
    # B1 (negative) — a SIMULATED containment is LOGGED (transparency) but does NOT set
    # contained/prevented or advance the spine, so a no-op eviction never scores as prevention.
    pS = Path(tempfile.mktemp(suffix=".jsonl")); logS = EventLog(pS)
    logS.append("system", "scope", {"in_scope": rr["scope"]["in_scope"]}); emit_range_topology(logS, rr)
    gateS = Gate([], logS, scope_by_actor=rr["scope_by_actor"])
    run_sim_red(gateS, logS, rr)
    resS = run_blue_fight(logS, gateS, contain_fn=lambda c: {"contained": True, "fidelity": "SIMULATED"})
    assert resS["contained"] == [], ("B1: a simulated containment must NOT register as contained", resS)
    assert any(e["action"] == "blue.contain_unverified" for e in logS.entries()), \
        "B1: an unverified containment must still be LOGGED (transparency)"
    assert not any(e["action"] == "state.mutate" and (e["data"] or {}).get("state") == "contained"
                   for e in logS.entries()), "B1: a sim containment must not advance the spine"
    pS.unlink(missing_ok=True)
    # Phase 4 — gate-mediated action set: the fight's containment went through the ONE gate under a
    # D3FEND tool name (not a side effect), and each performed response is a logged blue.respond beat.
    assert any(e["actor"] == "blue" and e["action"] == "gate.allow"
               and (e["data"] or {}).get("tool") == "isolate_host" for e in E), \
        "D3FEND containment must be gate-mediated under its tool name"
    assert all(any(x["actor"] == "blue" and x["action"] == "gate.allow"
                   and (x["data"] or {}).get("tool") == (e["data"] or {}).get("tool")
                   and (x["data"] or {}).get("target") == (e["data"] or {}).get("host") for x in E)
               for e in E if e["action"] in ("blue.contain", "blue.respond")), \
        "every performed D3FEND response (blue.contain / blue.respond) had a gate.allow"
    pf.unlink(missing_ok=True)

    # ── Phase 4: the decision model (confidence x blast_radius_contained x reversibility) ──────────
    # registry integrity: reversible/irreversible partition the D3FEND set, and the named eviction
    # ladder is irreversible.
    assert REVERSIBLE and IRREVERSIBLE and not (REVERSIBLE & IRREVERSIBLE)
    assert REVERSIBLE | IRREVERSIBLE == set(D3FEND_ACTIONS)
    assert {"invalidate_auth_cache", "revoke_cred", "kill_session", "shutdown_host"} <= IRREVERSIBLE
    assert {"isolate_host", "lock_account", "deploy_decoy", "suspend_process"} <= REVERSIBLE
    # a reversible control clears the bar at moderate confidence + a triaged host; an irreversible
    # eviction is GATED until the whole scope is understood, then authorized.
    assert blue_decision(0.75, 1.0, True)["authorized"], "reversible control should fire readily"
    assert not blue_decision(0.95, 0.3, False)["authorized"], "eviction gated while scope not understood"
    assert blue_decision(0.95, 1.0, False)["authorized"], "eviction authorized once scope understood"
    # monotonic: for the SAME confidence+blast, a reversible control scores higher than an eviction.
    assert blue_decision(0.9, 0.9, True)["score"] > blue_decision(0.9, 0.9, False)["score"]

    # ── Phase 4: a decoy-credential / honey-SPN TRIPWIRE hit is a NEAR-CERTAIN detection ──────────
    ph = Path(tempfile.mktemp(suffix=".jsonl")); logh = EventLog(ph)
    logh.append("system", "scope", {"in_scope": ["app-fs", "dc-01"]})
    logh.append("red", "gate.allow", {"tool": "kerberoast", "target": "app-fs",
                "technique": "T1558.003", "honey_spn": True, "spn": "MSSQL/honey-svc"})
    gateh = Gate([], logh, scope_by_actor={"blue": ["app-fs", "dc-01"]})
    resh = run_blue_fight(logh, gateh, honeytokens={"MSSQL/honey-svc"})
    assert resh["belief"]["confidence"] >= 0.95, \
        ("a honey-SPN hit must be near-certain detection", resh["belief"])
    assert any(e["action"] == "blue.detect.bernoulli"
               and "honeytoken" in str((e["data"] or {}).get("basis", "")) for e in logh.entries()), \
        "the honey-SPN tripwire detection must be recorded on the chain"
    ph.unlink(missing_ok=True)

    # ── Phase 4: reversible-FIRST is ENFORCED (not just prompted) — an LLM blue that reaches for an
    #    irreversible eviction as its FIRST move on a host is GATED by the decision model. ──────────
    class _EagerEvict:
        def __init__(self):
            class U:
                calls = []
            self.usage = U()

        def chat(self, role, messages, **kw):
            self.usage.calls.append({"model": "stub", "tier": "ultra"})
            hosts = re.findall(r"-\s+\S+\s+on\s+(\S+)", messages[-1]["content"])
            if not hosts:
                return json.dumps({"thought": "quiet", "tool": "wait", "args": {"reason": "q"}})
            return json.dumps({"thought": "evict now", "tool": "revoke_cred",
                               "args": {"host": hosts[-1], "user": "svc"}})

    pe = Path(tempfile.mktemp(suffix=".jsonl")); loge = EventLog(pe)
    loge.append("system", "scope", {"in_scope": ["wks-01"]})
    loge.append("red", "gate.allow", {"tool": "exploit", "target": "wks-01", "technique": "T1190"})
    loge.append("range", "confirm", {"confirms": "foothold", "dst": "wks-01"})
    loge.append("red", "state.mutate", {"state": "foothold", "dst": "wks-01", "via_confirm": 2})
    gatee = Gate([], loge, scope_by_actor={"blue": ["wks-01"]})
    rese = run_blue_fight(loge, gatee, router=_EagerEvict(), ticks_per_host=3)
    assert rese["contained"] == [], ("an eviction-first blue is gated; nothing contained", rese)
    assert any(e["action"] == "blue.evict_gated"
               and "reversible-first" in str((e["data"] or {}).get("reason", "")) for e in loge.entries()), \
        "reversible-first must be enforced at the effect, not merely prompted"
    pe.unlink(missing_ok=True)

    # ── Brick-2's remaining properties, re-homed here before deleting prove_brick2 ──
    from swarm.blue_fast import compare_detectors
    _variants = [[{"seq": 0, "actor": "system", "action": "scope", "data": {"in_scope": ["struts"]}},
                  {"seq": 1, "actor": "red", "action": "gate.allow",
                   "data": {"tool": "exploit", "target": "struts", "technique": "T1190",
                            "command": pay, "output": pay}},
                  {"seq": 2, "actor": "range", "action": "confirm",
                   "data": {"confirms": "foothold", "dst": "struts"}},
                  {"seq": 3, "actor": "red", "action": "state.mutate",
                   "data": {"state": "foothold", "dst": "struts", "via_confirm": 2}}]
                 for pay in ["ProcessBuilder('/bin/sh')", "%50rocess%42uilder", "\\u0050rocessBuilder",
                             "eval(atob('x'))", "python -c os.system", "gzip|base64 blob",
                             "${jndi:ldap} marshaller", "hex:2f62696e2f7368"]]
    _cmp = compare_detectors(_variants)
    assert _cmp["behavioral"] == 8 and _cmp["regex"] < _cmp["behavioral"], _cmp   # structure beats bytes
    # fast-path law: the belief/fight/detector utilities (blue_fast) import no LLM/router/provider
    _bf = (Path(__file__).resolve().parent / "blue_fast.py").read_text()
    _imp = [ln for ln in _bf.splitlines() if ln.strip().startswith(("import ", "from "))]
    assert not [ln for ln in _imp if any(t in ln for t in ("llm", "router", "provider_"))], \
        "fast-path law broken: a blue utility imports an LLM dependency"

    # ── toolkit-first doctrine + runtime authoring for blue (symmetric to red) ─────────────────
    from swarm.gate import Gate
    from swarm import authoring

    # A) blue_toolkit_untried derived ONLY from blue's OWN sensor picture + its OWN actions, and
    #    range-blind: a suspected host with no response defers authoring; responding shrinks the
    #    untried set; planted red-log / scope events never change it.
    pb = Path(tempfile.mktemp(suffix=".jsonl")); logb = EventLog(pb)
    logb.append("blue", "blue.observe", {"stage": "blue", "alert_hosts": ["h1"]})
    before = blue_toolkit_untried(logb, "blue")
    assert before, ("a suspected host with no built-in response must defer authoring", before)
    logb.append("blue", "move.source", {"stage": "blue", "source": "llm", "tool": "investigate", "args": {"host": "h1"}})
    logb.append("blue", "move.source", {"stage": "blue", "source": "llm", "tool": "revoke_cred", "args": {"host": "h1"}})
    after = blue_toolkit_untried(logb, "blue")
    assert len(after) < len(before), ("trying the built-in responses must shrink the untried set", before, after)
    logb.append("red", "move.source", {"stage": "vector", "source": "llm", "chose": "10.0.0.5->CVE-2017-5638"})
    logb.append("system", "scope", {"in_scope": ["h1"], "crown": "crown_db"})
    assert blue_toolkit_untried(logb, "blue") == after, "blue doctrine must ignore red's log + scope"
    pb.unlink(missing_ok=True)

    # B) the doctrine RIDE through the blue loop: author_tool DEFERS while the injected doctrine
    #    reports untried responses, and UNLOCKS (through the one gate path) once exhausted.
    pc = Path(tempfile.mktemp(suffix=".jsonl")); logc = EventLog(pc)
    logc.append("system", "scope", {"in_scope": ["h1"]})
    gatec = Gate([], logc, scope_by_actor={"blue": ["h1"]})
    ranb, bookb, st = [], authoring.AuthoredToolbook(), {"untried": ["isolate_host:h1"]}
    btools = dict(authoring.make_authoring_tools(gatec, logc, "blue",
                  lambda command, target: (ranb.append((target, command)) or "ok"),
                  bookb, doctrine_fn=lambda _l, _a: st["untried"]))

    class _AuthorStub:
        def __init__(self):
            class U:
                calls = []
            self.usage = U()

        def chat(self, role, messages, **kw):
            self.usage.calls.append({"model": "stub", "tier": "ultra"})
            return json.dumps({"thought": "toolkit gap", "tool": "author_tool",
                               "args": {"name": "probe", "source": "id", "target": "h1"}})

    bagent2 = BlueAgent(_AuthorStub(), logc, btools, strict=True)
    r_def = bagent2.tick([{"technique": "T1021", "host": "h1", "source": "sensor"}])
    assert r_def["result"].get("deferred") and ranb == [], ("blue defers authoring while responses remain", r_def, ranb)
    st["untried"] = []                                   # built-in toolkit exhausted at the frontier
    r_ok = bagent2.tick([{"technique": "T1021", "host": "h1", "source": "sensor"}])
    assert r_ok["result"].get("authored") and ranb == [("h1", "id")], ("blue authoring must UNLOCK + run", r_ok, ranb)
    evc = [json.loads(x) for x in pc.read_text().splitlines() if x.strip()]
    assert any(e["action"] == "doctrine" and e["data"]["event"] == "author_deferred" for e in evc), "defer beat on chain"
    assert any(e["action"] == "tool.author" for e in evc), "unlocked blue author must reach the chain"
    pc.unlink(missing_ok=True)

    # ── Interleaved duel: BOTH outcomes reachable, driven only by whether blue's containment is
    #    effective (NOT a threshold tune). Offline + deterministic (no Docker), proving the race is
    #    real and re-derivable from the one chain. ──
    from swarm.llm import UsageCounter as _UC

    def _fake_red(world):
        class _R:
            usage = _UC()
            def model_for(self, r): return "nano", "test/red"
            def chat(self, role, messages, **kw):
                w = world
                if not w["scanned"]:
                    w["scanned"] = True
                    return json.dumps({"thought": "recon", "tool": "scan", "args": {"from": "self"}})
                if "entry" not in w["owned"]:
                    return json.dumps({"thought": "foothold", "tool": "exploit", "args": {"ip": "entry"}})
                if not w["harvested"]:
                    w["harvested"] = True
                    return json.dumps({"thought": "harvest creds on the foothold", "tool": "harvest",
                                       "args": {"host": "entry"}})
                if "db" not in w["owned"] and "db" not in w["pivot_tried"]:
                    w["pivot_tried"].add("db")
                    return json.dumps({"thought": "pivot to the data host", "tool": "pivot", "args": {"to": "db"}})
                if "db" in w["owned"] and not w["looted"] and "db" not in w["loot_tried"]:
                    w["loot_tried"].add("db")
                    return json.dumps({"thought": "exfiltrate the crown", "tool": "loot", "args": {"host": "db"}})
                return json.dumps({"thought": "no viable move", "tool": "done", "args": {}})
        return _R()

    def _red_tools(world):
        def t_scan(**k): return {"hosts": [{"ip": "entry"}]}
        def t_exploit(ip=None, **k):
            world["owned"].add(ip); return {"grounded": True, "host": ip}
        def t_harvest(**k): return {"creds": ["dbadmin"]}      # a red action; no new ownership
        def t_pivot(to=None, **k):
            if "entry" in world["contained"]:           # route through the foothold is severed
                return {"owned": False, "host": None, "blocked": True}
            world["owned"].add(to); return {"owned": True, "host": to}
        def t_loot(host=None, **k):
            # exfil needs the live channel through the (owned, un-contained) foothold AND the target
            if "entry" in world["contained"] or host in world["contained"] or host not in world["owned"]:
                return {"looted": False, "host": host}
            world["looted"].append(host); return {"looted": True, "host": host}
        return {"scan": t_scan, "exploit": t_exploit, "harvest": t_harvest, "pivot": t_pivot, "loot": t_loot}

    def _telemetry_window(world):
        # blue sees the foothold signature once red owns the entry, the pivot once it owns db —
        # exactly the real-telemetry signals the live detector would surface, one window at a time.
        sent = set()
        def _w():
            out = []
            if "entry" in world["owned"] and "e" not in sent:
                sent.add("e"); out.append({"stage": "initial_access", "technique": "T1190",
                    "target": "entry", "p_fire": 0.9, "confirmed": True,
                    "basis": "real-telemetry[web]: struts fault", "source_line": "JakartaMultiPartRequest"})
            if "db" in world["owned"] and "d" not in sent:
                sent.add("d"); out.append({"stage": "lateral_movement", "technique": "T1021",
                    "target": "db", "p_fire": 0.8, "confirmed": True,
                    "basis": "real-telemetry[host]: accepted auth", "source_line": "Accepted password for"})
            return out
        return _w

    def _run_duel(real_contain, blue_contains=True):
        world = {"owned": set(), "contained": set(), "looted": [], "scanned": False,
                 "harvested": False, "pivot_tried": set(), "loot_tried": set()}
        pth = Path(tempfile.mktemp(suffix=".jsonl")); lgd = EventLog(pth)
        gd = Gate([], lgd, scope_by_actor={"red": ["entry", "db"], "blue": ["entry", "db"]})
        def _contain(c):
            host = c.replace("range-", "")
            if real_contain:
                world["contained"].add(host)
                return {"fidelity": "real", "contained": True, "method": "test isolate (route severed)"}
            return {"fidelity": "sim", "contained": False, "method": "no-op (observe-only)"}
        res = run_interleaved_duel(lgd, gd, red_router=_fake_red(world), red_tools=_red_tools(world),
                                   start_subnet="10.0.0.0/24", telemetry_window=_telemetry_window(world),
                                   objective="data_theft", max_turns=10, contain_fn=_contain,
                                   blue_contains=blue_contains)
        dl = [json.loads(x) for x in pth.read_text().splitlines() if x.strip()]
        pth.unlink(missing_ok=True)
        return res, world, dl

    prev, wprev, dprev = _run_duel(real_contain=True)      # blue's containment is EFFECTIVE
    theft, wtheft, dtheft = _run_duel(real_contain=False)  # blue observes but cannot stop the spread
    # OBSERVE-ONLY control: blue detects + would-contain but takes NO effect even with a real
    # contain_fn — red is never severed, so it steals unopposed; the baseline for a causal race.
    obs, wobs, dobs = _run_duel(real_contain=True, blue_contains=False)
    assert obs["achieved"] and not obs["prevented"], ("observe-only: red should steal unopposed", obs["duel_outcome"])
    assert not wobs["contained"] and not obs["contained"], ("observe-only must take NO containment", wobs, obs)
    assert not any(e["action"] == "blue.contain" for e in dobs), "observe-only logged a blue.contain"
    assert not any(e["action"] == "state.mutate" and (e["data"] or {}).get("state") == "contained" for e in dobs), \
        "observe-only produced a contained state.mutate"
    assert obs["duel_outcome"]["would_contain_tick"] is not None, "observe-only must record the would-contain tick"
    assert any(e["action"] == "blue.would_contain" for e in dobs), "observe-only must log blue.would_contain"
    assert any(e["action"] == "blue.belief" for e in dobs), "observe-only must still form belief"

    assert prev["prevented"] and not prev["achieved"], ("expected PREVENTION", prev["duel_outcome"])
    assert not wprev["looted"], ("crown must NOT have egressed when contained in time", wprev)
    assert prev["duel_outcome"]["tick_of_prevention"] is not None, prev["duel_outcome"]
    assert theft["achieved"] and not theft["prevented"], ("expected THEFT", theft["duel_outcome"])
    assert wtheft["looted"] == ["db"], ("crown must have egressed when blue couldn't stop it", wtheft)
    # the race result is a first-class, re-derivable fact on EACH chain (interleaved total order):
    for dl, exp in ((dprev, dict(achieved=False, prevented=True)), (dtheft, dict(achieved=True, prevented=False))):
        do = next(e["data"] for e in dl if e["action"] == "duel.outcome")
        assert do["achieved"] == exp["achieved"] and do["prevented"] == exp["prevented"], (do, exp)
        # a clean total order: red move.source and blue belief/action beats INTERLEAVE on the one chain
        assert any(e["action"] == "move.source" and e.get("actor") == "red" for e in dl)
        assert any(e["action"] == "blue.belief" for e in dl)
        # blue acted ONLY on real telemetry (label-free): every belief is tagged real-telemetry
        assert all((e["data"].get("detector") == "real-telemetry") for e in dl if e["action"] == "blue.belief")

    print("live_blue_agent ok (autonomous SOC analyst: holds on no alert, TRIAGES a pivot alert "
          "before reacting, then contains with a real gate-mediated effect; decides only from its "
          "lossy alert picture + its own findings, each tick a logged move.source:blue — never a "
          "scripted policy, never red's log, and free to wait/miss. Phase 4: the realistic D3FEND "
          "action set split by reversibility; the confidence x blast_radius_contained x reversibility "
          "decision model ENFORCES reversible-first + gates evictions until scope is understood; a "
          "honey-SPN / decoy hit is near-certain; tamper T1070/T1562 first-class). INTERLEAVED "
          "duel: deterministic turn-interleave (red tick -> blue observe+act, landing before red's "
          "next) — BOTH outcomes reachable on the one re-derivable chain: blue PREVENTS the exfil "
          "when its containment is effective in time, red STEALS when it is not; the difference is "
          "containment efficacy, not a tuned threshold; belief is real-telemetry-only (label-free)")
