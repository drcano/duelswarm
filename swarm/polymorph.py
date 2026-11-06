"""Finding validator (Component B) — the counter-hallucination precondition gate.

`validate_finding` is the XBOW-style gate from Anthropic's Nov-2025 report: a claimed
credential / RCE capability is admitted only after a cheap, deterministic precondition check,
so an obviously-ungrounded model claim is refused BEFORE a follow-on tool runs. It is pure — no
network, no tokens — and the exploit itself still goes through `gate.dispatch` regardless.

Honesty about scope (do not overstate): the RCE check is a SHAPE/precondition check — it
rejects a naive claim with no RCE indicator at all, but it does NOT by itself prove a real pop
(any text containing `uid=` passes). Real grounding comes from the CALLER feeding the target's
OWN captured output (e.g. swarm/live_lateral grounds on a uid=/nonce that the exploited host
actually returned, and swarm/live_weapon the same). The creds check is stronger: a claimed
credential must have appeared in a PRIOR harvest/discover event in the hash-chained log, or it
is refused as likely hallucinated.

(A polymorphic payload-mutation half once lived here but was unused by every live path and
hardcoded a single CVE; it was removed. Git history / attic retain it if ever needed.)
"""
import re


_CRED_RE = re.compile(r"\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(\S+)",
                      re.I)
_RCE_INDICATORS = ("uid=", "gid=", "ProcessBuilder", "Runtime.exec", "/bin/sh")


def _recent_values(events, kinds):
    """Values that have appeared in red's own log so far, across the given
    action kinds — the validator uses this to confirm a claim is grounded."""
    out = set()
    for e in events:
        if e.get("actor") != "red" or e.get("action") not in kinds:
            continue
        d = e.get("data") or {}
        for v in d.values():
            if isinstance(v, str):
                out.add(v)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    if isinstance(x, str):
                        out.add(x)
    return out


def validate_finding(finding, log_events, kind):
    """XBOW-style precondition check. Returns {valid, reason}.

    - kind="rce": a SHAPE check — refuse a claim with no RCE indicator at all (uid=/gid=/
      Runtime.exec/ProcessBuilder//bin/sh). This is NOT a full grounding on its own; the caller
      is responsible for passing the target's OWN captured output, which is the real evidence.
    - kind="creds": the claimed credential must appear in a PRIOR harvest/discover/exploit event
      in the hash-chained log, else it is refused as likely hallucinated.
    """
    kind = (kind or "").lower()
    text = finding if isinstance(finding, str) else (
        (finding.get("output") or finding.get("evidence") or
         str(finding.get("creds") or "")))
    if kind == "rce":
        if not any(ind.lower() in text.lower() for ind in _RCE_INDICATORS):
            return {"valid": False,
                    "reason": "no RCE indicator (uid=/ProcessBuilder/Runtime.exec) in evidence"}
    elif kind == "creds":
        # creds that pass validation must appear in a prior harvest/discover event
        claimed = _CRED_RE.findall(text or "")
        if not claimed:
            return {"valid": False, "reason": "no credential pattern in evidence"}
        seen = _recent_values(log_events,
                              kinds={"gate.allow", "credential_harvest", "discover",
                                     "red.polymorph", "exploit"})
        if not any(any(c in s for s in seen) for c in claimed):
            return {"valid": False,
                    "reason": "credential never appeared in prior tool output (likely hallucinated)"}
    return {"valid": True, "reason": "evidence grounds the claim (shape check; caller supplies real output)"}


if __name__ == "__main__":  # self-check: the validator refuses hallucinated creds/RCE
    # RCE claim with no indicator is REFUSED; a target's real uid= output passes the shape check.
    bad = validate_finding("I got RCE and ran commands successfully.", [], "rce")
    assert not bad["valid"], bad
    good = validate_finding({"output": "uid=0(root) gid=0(root)"}, [], "rce")
    assert good["valid"], good

    # Hallucinated creds: a model claim with no prior appearance -> refused; a prior-seen one passes.
    prior = [{"actor": "red", "action": "credential_harvest",
              "data": {"creds": ["admin:realpass123"]}}]
    hallu = validate_finding({"output": "password: unseen_hallucinated_pw"}, prior, "creds")
    assert not hallu["valid"], hallu
    grounded = validate_finding({"output": "password: realpass123"}, prior, "creds")
    assert grounded["valid"], grounded
    print("polymorph ok: validator refuses hallucinated creds/RCE (shape check; real grounding "
          "is the caller's captured target output)")
