"""Shared helpers for the validation auditor rig — verdict schema + real-binary invocation.

Deliberately dependency-free (stdlib only) and side-effect-free: importing this, or any validator,
must never stand up a range, touch the gate, or reach a live effect site. The actual tool runs
happen only when a validator function is CALLED with a real target.
"""
import json
import shutil
import subprocess
import time


def have(binary):
    """Is `binary` on PATH? (A missing tool => the validator reports UNMEASURED, not a failure.)"""
    return shutil.which(binary) is not None


def first_available(candidates):
    """The first of `candidates` present on PATH, or None."""
    return next((b for b in candidates if have(b)), None)


def run_tool(argv, timeout=120, input_text=None):
    """Run a real tool, never raising: a missing binary or a hang becomes a result dict, so a
    validator always returns a verdict instead of crashing the rig.

    Returns {rc, out, err, timed_out}. rc 127 = binary absent, 124 = timed out."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_text)
        return {"rc": r.returncode, "out": r.stdout or "", "err": r.stderr or "", "timed_out": False}
    except FileNotFoundError:
        return {"rc": 127, "out": "", "err": f"{argv[0]}: not found", "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": f"timeout after {timeout}s", "timed_out": True}
    except Exception as e:  # never let a tool wrapper crash the auditor
        return {"rc": 1, "out": "", "err": f"{type(e).__name__}: {e}", "timed_out": False}


def verdict(name, *, available, ok, detail, evidence=None):
    """A machine-checkable auditor verdict.

    available=False  -> tool/target not present: `ok` is None (UNMEASURED, never a silent pass).
    available=True   -> `ok` is the realism finding (True = the tool behaved as on a real network).
    """
    return {
        "validator": name,
        "available": bool(available),
        "ok": (None if not available else bool(ok)),
        "detail": detail,
        "evidence": evidence or {},
        "ts": time.time(),
    }


def unmeasured(name, detail):
    """Shorthand for 'the tool or target wasn't available' — the honest non-pass."""
    return verdict(name, available=False, ok=None, detail=detail)


def print_verdict(v):
    """One-line human summary + the JSON (what a CI/auditor step reads)."""
    state = "UNMEASURED" if not v["available"] else ("OK" if v["ok"] else "FINDING")
    print(f"[{v['validator']}] {state}: {v['detail']}")
    print(json.dumps(v, indent=2, default=str))
    return v


def _selftest():
    # schema + degradation are stable (the contract every validator and the leak test rely on).
    u = unmeasured("x", "no target")
    assert u["available"] is False and u["ok"] is None, u
    ok = verdict("x", available=True, ok=True, detail="d", evidence={"k": 1})
    assert ok["ok"] is True and ok["evidence"] == {"k": 1}, ok
    bad = verdict("x", available=True, ok=False, detail="d")
    assert bad["ok"] is False, bad
    r = run_tool(["definitely-not-a-real-binary-xyz"], timeout=2)
    assert r["rc"] == 127 and "not found" in r["err"], r
    r2 = run_tool(["sleep", "5"], timeout=1)
    assert r2["timed_out"] and r2["rc"] == 124, r2
    print("validation/_common selftest: OK")


if __name__ == "__main__":
    _selftest()
