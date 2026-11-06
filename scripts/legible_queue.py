"""legible_queue — the legible-surface prioritisation queue, SCAFFOLD (Task 2, Unit 3).

Make red's OWN arsenal x observations x held credentials LEGIBLE so red (and its memory) can prioritise.
It is an AFFORDANCE, never an auto-fire, and never a HARNESS-computed strategic ranking — ranking by
strategy is red's job. The load-bearing invariant: the queue surfaces ONLY what red has OBSERVED — a
ground-truth service red never observed must NEVER appear (`assert_queue_map_blind` bites on a planted
unobserved GT service, extending the red map-blindness rail to the queue surface).

SCAFFOLD, per the brief: do NOT fully build first — a queue starved of inputs measures nothing. The
first paid Unit-1/2 run answers "do inner-host scans return open ports?" and decides whether the queue
keys on ports or scan coverage needs fixing upstream. So this builds + proves the queue's SHAPE and its
map-blind guard; wiring it into red's loop (affordance surfaced to red, author_tool to last resort) is
the next increment. Stdlib only, no swarm import.
"""
import sys

# `author_tool` is deliberately NOT a default means — per the brief it is the LAST RESORT, chosen by red
# only when no built-in affordance fits, never auto-surfaced as a ranked option.
_BUILTIN_MEANS = ("pivot", "exploit")


def legible_surface(observations, held_creds=(), arsenal=()):
    """Build the LEGIBLE affordance set from red's OWN inputs — nothing else.

    observations: red's own scan/fingerprint results, each {"ip": str, "ports": [int], "banner": str?}.
    held_creds:   red's own harvested credentials, each {"path"|"user": str} (a MEANS to pivot).
    arsenal:      the generic weapon catalog red carries, each {"cve": str, "ports": [int]} (range-agnostic).

    Returns a list of affordances {target, surface, means, basis} for each OBSERVED target that red has a
    MEANS against — an SSH port x a held credential (pivot), or a service port x an arsenal CVE (exploit).
    It does NOT execute anything (no auto-fire) and does NOT impose a strategic ranking (the order is the
    stable observation order; red prioritises). An observed target with no means yields no affordance; an
    UNOBSERVED target can never appear (it is not in `observations`)."""
    affordances = []
    for obs in observations or []:
        ip, ports = obs.get("ip"), list(obs.get("ports") or [])
        if not ip:
            continue
        # a held credential is a means to pivot into any observed host exposing SSH (22).
        if 22 in ports:
            for cred in held_creds or []:
                means = cred.get("path") or cred.get("user")
                if means:
                    affordances.append({"target": ip, "surface": "tcp/22",
                                        "means": {"kind": "pivot", "cred": means}, "basis": "observed-ssh x held-cred"})
        # a generic arsenal CVE is a means to exploit an observed service port it applies to.
        for w in arsenal or []:
            cve, wports = w.get("cve"), set(w.get("ports") or [])
            for p in ports:
                if p in wports and cve:
                    affordances.append({"target": ip, "surface": f"tcp/{p}",
                                        "means": {"kind": "exploit", "cve": cve}, "basis": "observed-port x arsenal-cve"})
    return affordances


def observed_targets(observations):
    """The set of IPs red has actually observed (the only legitimate queue targets)."""
    return {o.get("ip") for o in (observations or []) if o.get("ip")}


def assert_queue_map_blind(queue, observations, ground_truth):
    """The queue surface must be a subset of what red OBSERVED: every affordance target is an observed
    IP, and no ground-truth host/service that red never observed appears anywhere in the queue. Raises
    RuntimeError on a leak; returns True when clean. This EXTENDS the red map-blindness rail to the
    queue: a planted unobserved GT service must bite."""
    seen = observed_targets(observations)
    # (1) every affordance targets an OBSERVED ip.
    off = sorted({a.get("target") for a in queue if a.get("target") not in seen})
    if off:
        raise RuntimeError(f"QUEUE MAP-BLINDNESS VIOLATED: affordance(s) target un-observed host(s): {off}")
    # (2) no ground-truth host NAME that red never observed appears in the queue text (an unobserved GT
    #     service can enter only by a map leak — the queue keys on IPs red discovered, never names).
    gt = ground_truth or {}
    gt_hosts = set(gt.get("tiers") or {}) | set(gt.get("declared_terrain") or [])
    crown = gt.get("crown") or {}
    gt_hosts |= {v for v in crown.values() if v}
    import json as _json
    blob = _json.dumps(queue)
    leaked = sorted(h for h in gt_hosts if h and f'"{h}"' in blob)
    if leaked:
        raise RuntimeError(f"QUEUE MAP-BLINDNESS VIOLATED: ground-truth host name(s) in the queue: {leaked}")
    return True


def _selftest():
    gt = {
        "tiers": {"web01": "T3", "dba01": "T3", "db-bastion": "T1", "db-core": "T1"},
        "declared_terrain": ["web01", "dba01", "db-bastion", "db-core"],
        "crown": {"data": "db-core", "identity": "dc-01"},
    }
    # red OBSERVED two inner hosts by IP (it scanned/fingerprinted them); it has NOT observed db-core.
    observations = [{"ip": "10.35.0.11", "ports": [22]}, {"ip": "10.10.0.11", "ports": [8080]}]
    held_creds = [{"path": "/home/svc_dba/.ssh/id_ed25519"}]
    arsenal = [{"cve": "CVE-2017-5638", "ports": [8080]}]

    q = legible_surface(observations, held_creds, arsenal)
    # (1) an affordance for the observed SSH host (pivot via the held cred) and the observed web host
    #     (exploit via the arsenal CVE); nothing for an unobserved target.
    targets = {a["target"] for a in q}
    assert targets == {"10.35.0.11", "10.10.0.11"}, targets
    kinds = {(a["target"], a["means"]["kind"]) for a in q}
    assert ("10.35.0.11", "pivot") in kinds and ("10.10.0.11", "exploit") in kinds, kinds
    # (2) AFFORDANCE, not auto-fire: entries are candidates, nothing is executed; author_tool is not a
    #     surfaced means (last resort).
    assert all(a["means"]["kind"] in _BUILTIN_MEANS for a in q), q
    assert not any(a["means"]["kind"] == "author_tool" for a in q), "author_tool must not be auto-surfaced"
    # (3) map-blind: the clean queue passes.
    assert assert_queue_map_blind(q, observations, gt)
    # (4) the guard BITES two ways: an affordance targeting an UN-observed host, and a planted GT host
    #     name the queue should never carry.
    for bad in ([{"target": "10.40.0.11", "surface": "tcp/22", "means": {"kind": "pivot", "cred": "k"}, "basis": "x"}],
                [{"target": "10.35.0.11", "surface": "tcp/22", "means": {"kind": "pivot", "cred": "db-core"}, "basis": "x"}]):
        caught = False
        try:
            assert_queue_map_blind(bad, observations, gt)
        except RuntimeError:
            caught = True
        assert caught, ("queue map-blind guard failed to bite", bad)
    # (5) a target red has NOT observed yields NO affordance even if a means exists for it.
    assert not legible_surface([], held_creds, arsenal), "a starved queue (no observations) must be empty"

    print(f"legible_queue selftest ok (affordances from red's OWN observations x means only [{len(q)} for "
          "2 observed hosts]; no auto-fire, author_tool not surfaced; map-blind guard bites on an "
          "un-observed target AND a planted ground-truth host name; starved-of-inputs queue is empty)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print("usage: legible_queue.py --selftest")
        sys.exit(2)
