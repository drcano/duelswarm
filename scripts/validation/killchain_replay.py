"""killchain_replay — run a documented, published attack sequence end-to-end against the range
and report which steps the range SUPPORTS.

An external ground-truth chain (not our own red agent) is the realism check: if a real documented
kill chain executes against the range, the terrain is faithful; steps the range can't support are
realism findings. Auditor only; output never fed to red.

A chain is a list of steps: {id, technique, cmd, expect}. `expect` is a substring the step's output
must contain to count as supported (or a callable(out)->bool). Replay is parameterized by an
`exec_fn(cmd)->(rc, out)` so it runs against any earned channel; the default execs on a container
via docker. The replay accounting is what the offline selftest pins (stub exec channel).

The default chain is a Linux living-off-the-land discovery -> credential-access -> lateral sequence
(the idiom CISA documents for stealthy actors like Volt Typhoon, mapped to this Linux/Samba range).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.validation._common import verdict, unmeasured, run_tool  # noqa: E402


# A documented LOLBin discovery/cred/lateral chain, ATT&CK-mapped, runnable on the Linux range.
VOLT_TYPHOON_LINUX = [
    {"id": "whoami", "technique": "T1033", "cmd": "id", "expect": "uid="},
    {"id": "sysinfo", "technique": "T1082", "cmd": "uname -a", "expect": "Linux"},
    {"id": "accounts", "technique": "T1087", "cmd": "cat /etc/passwd", "expect": "root:"},
    {"id": "net-config", "technique": "T1016", "cmd": "cat /etc/hosts", "expect": "localhost"},
    {"id": "file-discovery", "technique": "T1083", "cmd": "find / -name 'id_rsa' 2>/dev/null; true", "expect": None},
    {"id": "ssh-key-access", "technique": "T1552.004", "cmd": "cat ~/.ssh/id_rsa 2>/dev/null; true", "expect": None},
    {"id": "history-creds", "technique": "T1552.003", "cmd": "cat ~/.bash_history 2>/dev/null; true", "expect": None},
    {"id": "remote-svc-enum", "technique": "T1046", "cmd": "command -v ssh nc nmap 2>/dev/null; true", "expect": None},
]


def docker_exec_channel(container):
    """An exec_fn that runs a command inside `container` via docker (the earned-foothold view)."""
    def _exec(cmd):
        r = run_tool(["docker", "exec", container, "sh", "-c", cmd], timeout=30)
        return r["rc"], (r["out"] + r["err"])
    return _exec


def _step_supported(step, rc, out):
    exp = step.get("expect")
    if exp is None:
        return rc != 127          # the command RAN (shell reachable); no content gate for this step
    if callable(exp):
        return bool(exp(out))
    return exp in (out or "")


def replay(chain, exec_fn, min_supported=0.75):
    """Replay `chain` through `exec_fn`. Returns a verdict: ok iff the supported fraction clears
    `min_supported` (the documented chain executes end-to-end on the range)."""
    if not chain:
        return unmeasured("killchain_replay", "empty chain")
    results = []
    for step in chain:
        try:
            rc, out = exec_fn(step["cmd"])
        except Exception as e:
            rc, out = 1, f"{type(e).__name__}: {e}"
        sup = _step_supported(step, rc, out)
        results.append({"id": step["id"], "technique": step["technique"], "supported": sup, "rc": rc})
    n = len(results)
    sup_n = sum(1 for r in results if r["supported"])
    frac = sup_n / n
    ok = frac >= min_supported
    return verdict("killchain_replay", available=True, ok=ok,
                   detail=f"{sup_n}/{n} steps supported ({frac:.0%}); "
                          f"unsupported: {[r['id'] for r in results if not r['supported']] or 'none'}",
                   evidence={"steps": results, "supported_fraction": round(frac, 3)})


def replay_on_container(container, chain=None, min_supported=0.75):
    """Replay against a booted range container. UNMEASURED if docker/the container is absent."""
    probe = run_tool(["docker", "exec", container, "true"], timeout=10)
    if probe["rc"] != 0:
        return unmeasured("killchain_replay", f"container {container} not reachable (no docker / not booted)")
    return replay(chain or VOLT_TYPHOON_LINUX, docker_exec_channel(container), min_supported=min_supported)


def _selftest():
    # Chain structure is well-formed (every step has the fields replay needs).
    for s in VOLT_TYPHOON_LINUX:
        assert {"id", "technique", "cmd"} <= set(s), s
        assert s["technique"].startswith("T"), s

    # Replay accounting with a STUB channel (no docker): supported iff expect-substring present
    # or (expect None) the command ran. One step's expectation is deliberately unmet -> unsupported.
    canned = {
        "id": (0, "uid=0(root) gid=0(root)"),
        "uname -a": (0, "Linux range-struts 7.0"),
        "cat /etc/passwd": (0, "daemon:x:1:1"),           # missing "root:" -> UNSUPPORTED
        "cat /etc/hosts": (0, "127.0.0.1 localhost"),
    }

    def stub(cmd):
        return canned.get(cmd, (0, "ran-ok"))             # unknown cmds "ran" (expect None -> supported)

    chain = VOLT_TYPHOON_LINUX
    v = replay(chain, stub, min_supported=0.75)
    steps = {s["id"]: s for s in v["evidence"]["steps"]}
    assert steps["whoami"]["supported"] and steps["sysinfo"]["supported"], steps
    assert steps["accounts"]["supported"] is False, steps["accounts"]   # "root:" absent
    assert steps["file-discovery"]["supported"] is True, steps          # expect None + ran
    # 7/8 supported = 0.875 >= 0.75 -> ok
    assert v["available"] and v["ok"] is True, v
    assert abs(v["evidence"]["supported_fraction"] - 7 / 8) < 1e-6, v

    # A channel where nothing runs (rc 127) -> steps with a content gate fail; ok False.
    def dead(cmd):
        return 127, "not found"
    vb = replay(chain, dead, min_supported=0.75)
    assert vb["ok"] is False, vb

    assert replay([], stub)["available"] is False
    print("killchain_replay selftest: OK")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="replay a documented kill chain against the range")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--container", help="booted range container to replay inside (e.g. range-struts)")
    ap.add_argument("--min-supported", type=float, default=0.75)
    a = ap.parse_args()
    if a.selftest or not a.container:
        _selftest()
    else:
        from scripts.validation._common import print_verdict
        import sys as _s
        v = replay_on_container(a.container, min_supported=a.min_supported)
        print_verdict(v)
        _s.exit(0 if v["available"] and v["ok"] else (2 if not v["available"] else 1))
