"""Re-derive the run's pinned provider from the hash chain and assert every model call matches.

One provider per run (CLAUDE.md): the run writes exactly one `provider.pinned` system event at
start — BEFORE any model call — carrying {provider, base_url, pinned_host_regex, model_lineage}
(swarm/llm.resolved_provider, emitted in the live preamble of scripts/live_arms_race_run.py). This
verifier walks a committed chain and asserts, trusting neither the runner nor in-code config:

  1. exactly ONE provider.pinned event (one provider per run), and it precedes every llm.call;
  2. every llm.call's model is in that pin's declared model_lineage (basename-compared) — so a
     silent mid-run swap to a model the run did not pin is caught cold from the chain.

A dry / no-LLM episode pins nothing and calls nothing — vacuously OK. Stdlib only; offline,
deterministic, no API, no Docker. The hash chain itself is verified by scripts/verify_chain.py;
this auditor is about the provider pin, not the link integrity.

Run:  .venv/bin/python redteam/verify_provider_pin.py <chain.jsonl>
      .venv/bin/python redteam/verify_provider_pin.py --selftest
"""
import json
import sys
from pathlib import Path


def _basename(m):
    return (m or "").split("/")[-1]


def verify_provider_pin(events):
    """events: list of chain event dicts (action/actor/data/seq/...). Returns (ok, detail)."""
    pins = [e for e in events if e.get("action") == "provider.pinned"]
    calls = [e for e in events if e.get("action") == "llm.call"]
    if not calls and not pins:
        return True, {"pins": 0, "calls": 0, "note": "no model calls and no pin — vacuously OK"}
    if len(pins) != 1:
        return False, {"pins": len(pins), "calls": len(calls),
                       "note": "a run must pin EXACTLY one provider before any model call"}
    pin = pins[0]
    pin_seq = pin.get("seq")
    data = pin.get("data") or {}
    lineage_models = {_basename(m) for m in (data.get("model_lineage") or {}).values() if m}
    early = [c for c in calls if c.get("seq") is not None and pin_seq is not None
             and c["seq"] < pin_seq]
    if early:
        return False, {"note": "a model call precedes provider.pinned (pin must fire first)",
                       "first_early_seq": early[0].get("seq"), "pin_seq": pin_seq}
    off = sorted({_basename((c.get("data") or {}).get("model")) for c in calls
                  if _basename((c.get("data") or {}).get("model"))
                  and _basename((c.get("data") or {}).get("model")) not in lineage_models})
    if off:
        return False, {"note": "model call(s) off the pinned lineage (a silent swap)",
                       "off_models": off, "lineage": sorted(lineage_models),
                       "provider": data.get("provider")}
    return True, {"provider": data.get("provider"), "pinned_host_regex": data.get("pinned_host_regex"),
                  "calls": len(calls), "lineage": sorted(lineage_models)}


def _load(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def _selftest():
    lineage = {"ultra": "nvidia/nemotron-ultra", "super": "nvidia/nemotron-super",
               "nano": "nvidia/nemotron-nano"}
    pin = {"action": "provider.pinned", "actor": "system", "seq": 1,
           "data": {"provider": "nebius", "base_url": "https://api.tokenfactory.nebius.com/v1/",
                    "pinned_host_regex": r"(^|\.)nebius\.com$", "model_lineage": lineage}}

    def call(seq, model):
        return {"action": "llm.call", "actor": "system", "seq": seq,
                "data": {"tier": "super", "model": model}}

    ok, d = verify_provider_pin([pin, call(2, "nemotron-super"), call(3, "nemotron-nano")])
    assert ok, ("clean chain must verify", d)

    ok, d = verify_provider_pin([pin, call(2, "nemotron-super"), call(3, "claude-opus-4")])
    assert not ok and "claude-opus-4" in d["off_models"], ("off-lineage swap must BITE", d)

    ok, d = verify_provider_pin([pin, dict(pin, seq=2), call(3, "nemotron-nano")])
    assert not ok and d["pins"] == 2, ("two providers in one run must BITE", d)

    ok, d = verify_provider_pin([call(1, "nemotron-super"), dict(pin, seq=2)])
    assert not ok and "precedes" in d["note"], ("a model call before the pin must BITE", d)

    ok, d = verify_provider_pin([{"action": "config", "seq": 1, "data": {}}])
    assert ok, ("a dry / no-LLM episode must be vacuously OK", d)

    # calls with no pin at all is unauditable -> must bite
    ok, d = verify_provider_pin([call(1, "nemotron-super")])
    assert not ok and d["pins"] == 0, ("a model call with no pin must BITE", d)

    print("verify_provider_pin selftest ok (clean verifies; off-lineage swap, two-provider, "
          "call-before-pin, and call-without-pin all BITE; a no-call dry episode is vacuously OK)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        args = [a for a in sys.argv[1:] if not a.startswith("-")]
        if not args:
            print("usage: verify_provider_pin.py <chain.jsonl> | --selftest")
            sys.exit(2)
        ok, detail = verify_provider_pin(_load(args[0]))
        print(("PASS" if ok else "FAIL") + ": " + json.dumps(detail))
        sys.exit(0 if ok else 1)
