"""Blue team containment + tiered eviction (SPEC §5.7, RED_BLUE_DOCTRINE Part 5 B1-B5).

Blue contains: disconnects the compromised host from the range network so
red's next move fails for real. This is the adaptive loop — the wow.

Eviction ladder — REAL actions on a live container via the docker CLI, the
live analogue of the offline economics model in swarm/response.py:
  * remove_foothold  — CAGE 'Remove': kill red's live processes/sessions.
                       Cheap; does NOT touch on-disk persistence, so red
                       re-establishes from a surviving implant.
  * rollback_host    — CAGE 'Restore': recreate the container from its image
                       (known-good rollback). Clears the writable layer (all
                       on-disk persistence), evicts any privilege. Named
                       distinctly so the existing restore_host (network
                       reconnect, used by run.py) keeps its meaning.
  * close_vector     — B4 vector closure: stop the vulnerable service on the
                       initial-access port so re-exploit fails.

Process matching uses a pure-bash /proc scan (kill is a bash builtin; grep/tr
are in base Debian) — no procps, so it works on minimal hosts like the
python:3.12-slim proof nodes as well as a real Struts/tomcat image.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect, EffectTimeout  # one effect path (invariant #1)
import json


def _exec(container, cmd, timeout=15):
    """docker exec `cmd` inside `container` via bash; returns (rc, stdout+stderr).
    Degrades to a nonzero rc with an error string when Docker/container is absent
    — never raises, never hangs (effect timeout, not shell `timeout`)."""
    try:
        r = run_effect(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except EffectTimeout:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "docker not available"
    except Exception as e:  # pragma: no cover - defensive
        return 1, f"exec error: {e}"


def _pids_matching(container, pattern):
    """PIDs inside `container` whose /proc cmdline contains `pattern` (fixed
    string). Pure bash — no procps. Returns a sorted list of ints."""
    # Skip $$ (this scanning shell): the pattern is a literal arg in our own
    # cmdline, so without this the scan always matches itself.
    scan = (
        "for p in /proc/[0-9]*; do "
        "  pid=${p#/proc/}; "
        "  [ \"$pid\" = \"$$\" ] && continue; "
        f"  if tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null | grep -qF -- {_shq(pattern)}; "
        "  then echo \"$pid\"; fi; "
        "done"
    )
    rc, out = _exec(container, scan)
    pids = []
    for line in out.split():
        if line.isdigit():
            pids.append(int(line))
    return sorted(set(pids))


def _shq(s):
    """Minimal single-quote shell-quote for a fixed-string grep pattern."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _container_networks(container):
    """The docker networks a container is currently attached to (empty on error)."""
    try:
        r = run_effect(
            ["docker", "inspect", "-f",
             "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", container],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.split() if r.returncode == 0 else []
    except Exception:
        return []


def contain_host(container="range-struts", network=None):
    """Disconnect a container from the range network(s) (isolation).

    With the Brick 0 segmented substrate a pivot is MULTI-HOMED (on several
    segment subnets), so true isolation means disconnecting it from EVERY network
    it is on — not one hardcoded name. `network=None` (default) inspects the
    container and disconnects all of them; pass an explicit name to target one.
    Returns a dict; `contained` is True only if at least one disconnect succeeded
    and no attempted disconnect failed.
    """
    nets = [network] if network else _container_networks(container)
    if not nets:
        return {"contained": False, "host": container, "error": "no networks found"}
    disconnected, errors = [], []
    for net in nets:
        try:
            r = run_effect(
                ["docker", "network", "disconnect", net, container],
                capture_output=True, text=True, timeout=10,
            )
            (disconnected if r.returncode == 0 else errors).append(
                net if r.returncode == 0 else f"{net}: {r.stderr.strip()}")
        except Exception as e:
            errors.append(f"{net}: {e}")
    return {"contained": bool(disconnected) and not errors, "host": container,
            "action": "network-disconnect", "networks": disconnected,
            **({"error": "; ".join(errors)} if errors else {})}


def restore_host(container="range-struts", network=None, networks=None):
    """Reconnect a contained host (for resetting the range after a duel).

    Pass `networks=[...]` (e.g. the list `contain_host` returned) to restore a
    multi-homed host to every segment it was on; `network=` restores one.
    """
    nets = networks or ([network] if network else [])
    ok = True
    for net in nets:
        try:
            r = run_effect(
                ["docker", "network", "connect", net, container],
                capture_output=True, text=True, timeout=10,
            )
            ok = ok and r.returncode == 0
        except Exception:
            ok = False
    return ok


def drop_honeytoken(container="range-struts", token_path="/tmp/.db_backup_creds.txt",
                    token_content="postgres://admin:H0n3yT0k3n@db-backup:5432/secrets"):
    """Plant a honeytoken on the compromised host.

    If red reads this file, it proves they're still enumerating — and
    the fake creds point to a non-existent host, causing a detectable failure.
    """
    try:
        run_effect(
            ["docker", "exec", container, "bash", "-c",
             f"echo '{token_content}' > {token_path}"],
            capture_output=True, text=True, timeout=5,
        )
        return {"planted": True, "path": token_path}
    except Exception as e:
        return {"planted": False, "error": str(e)}


# ── tiered eviction (RED_BLUE_DOCTRINE B2/B3/B4) ──────────────────────────────

def remove_foothold(container="range-struts",
                    patterns=("implant", "beacon", "red_shell"), timeout=15):
    """CAGE 'Remove' tier (D3-PT): kill red's live processes/sessions on the host.

    Kills every process whose cmdline matches one of `patterns`, then re-scans to
    prove they are gone. Cheap, containment-grade: it evicts the *running*
    foothold but leaves on-disk persistence untouched — so red re-establishes
    from a surviving implant. (Live analogue of response.Scenario.blue_remove.)
    """
    killed, before = [], []
    for pat in patterns:
        pids = _pids_matching(container, pat)
        before.extend(pids)
        for pid in pids:
            _exec(container, f"kill -9 {pid} 2>/dev/null || true")
            killed.append(pid)
    # Re-scan: what still matches after the kill (should be empty).
    remaining = []
    for pat in patterns:
        remaining.extend(_pids_matching(container, pat))
    return {
        "action": "remove_foothold", "host": container,
        "killed_pids": sorted(set(killed)),
        "remaining_pids": sorted(set(remaining)),
        "removed": not remaining and bool(before),
        "note": "user-level eviction; on-disk persistence NOT cleared",
    }


def _inspect(container):
    rc, out = _exec_host(["docker", "inspect", container])
    if rc != 0:
        return None
    try:
        return json.loads(out)[0]
    except Exception:
        return None


def _exec_host(argv, timeout=90):
    """Run a docker CLI command on the host; returns (rc, stdout+stderr)."""
    try:
        r = run_effect(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except EffectTimeout:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "docker not available"
    except Exception as e:  # pragma: no cover - defensive
        return 1, f"error: {e}"


def rollback_host(container="range-struts", image=None, network=None,
                  command=None, timeout=90):
    """CAGE 'Restore' tier (D3-OTF): recreate the container from its image.

    Known-good rollback — `docker rm -f` then re-run from the image on the same
    network. This throws away the container's writable layer, so EVERY on-disk
    persistence artifact (webshell, implant, authorized_keys, cron) is cleared
    and red is evicted at any privilege. Expensive (downtime).

    image/network/command are read from `docker inspect` when not given, so the
    caller need not remember how the host was launched. Returns a result dict;
    never raises.
    """
    info = None
    if image is None or network is None or command is None:
        info = _inspect(container)
        if info is None and image is None:
            return {"action": "rollback_host", "host": container,
                    "rolled_back": False,
                    "error": "cannot inspect container and no image given"}
    if info is not None:
        cfg, netset = info.get("Config", {}), info.get("NetworkSettings", {})
        image = image or cfg.get("Image")
        command = command if command is not None else cfg.get("Cmd") or []
        nets = list((netset.get("Networks") or {}).keys())
        network = network or (nets[0] if nets else None)

    rc_rm, out_rm = _exec_host(["docker", "rm", "-f", container], timeout=timeout)
    run_argv = ["docker", "run", "-d", "--name", container]
    if network:
        run_argv += ["--network", network]
    run_argv.append(image)
    if command:
        run_argv += list(command)
    rc_run, out_run = _exec_host(run_argv, timeout=timeout)
    return {
        "action": "rollback_host", "host": container, "image": image,
        "network": network, "rolled_back": rc_run == 0,
        "note": "known-good rollback — writable layer (persistence) discarded",
        "error": None if rc_run == 0 else (out_run.strip() or out_rm.strip())[:300],
    }


def close_vector(container="range-struts", port=8080,
                 service_patterns=("http.server", "catalina", "tomcat", "struts"),
                 timeout=15):
    """B4 vector closure (D3-PH): stop the vulnerable service on the initial-access
    port so re-exploit of the entry vuln fails.

    Kills the listener process(es) matching `service_patterns`. After this, a
    connection to the host's `port` is refused — the free re-exploit path in
    response.Scenario (vector_open -> re-exploit) is shut. `port` is recorded for
    the caller's post-check; the kill is by process pattern (procps-free).
    """
    killed = []
    for pat in service_patterns:
        pids = _pids_matching(container, pat)
        for pid in pids:
            _exec(container, f"kill -9 {pid} 2>/dev/null || true")
            killed.append(pid)
    remaining = []
    for pat in service_patterns:
        remaining.extend(_pids_matching(container, pat))
    return {
        "action": "close_vector", "host": container, "port": port,
        "killed_pids": sorted(set(killed)),
        "service_still_up_pids": sorted(set(remaining)),
        "closed": not remaining and bool(killed),
        "note": f"initial-access service on :{port} stopped; re-exploit must fail",
    }


# ── B2: the eviction ladder as GATE-DISPATCHED executors ─────────────────────
# The primitives above call run_effect (the one effect path) directly. B2 routes them into the duel
# ONLY as `executors` that run_interleaved_duel invokes INSIDE `gate.dispatch("blue", ...)` (via
# build_blue_tools._effect), so every blue host-affecting effect is scope-mediated + chain-recorded —
# a blue action is on the SAME floor as a red action, and reverify_floor sees it. A duel must NEVER
# call a blue_contain primitive directly (scripts/mediation/blue_mediation.py enforces this). Each
# executor is wrapped to carry a `fidelity` so B1 counts a REAL eviction (success) and does not count
# a no-op (sim) one.

def _evict_executor(primitive, success_key):
    """Wrap a blue_contain primitive as a duel executor: run it on `range-<host>` and label the
    result `fidelity` real/sim from its own success flag, so the contain beat (B1) counts a real
    eviction and logs — but does not count — an unverified one."""
    def _fx(container):
        r = primitive(container)
        if isinstance(r, dict):
            r = {**r, "fidelity": "real" if r.get(success_key) else "sim"}
        return r
    return _fx


def blue_eviction_executors():
    """The canonical B2 wiring: the D3FEND tool name blue chooses -> the real blue_contain primitive,
    each gate-dispatched by the duel. `isolate_host` stays the duel's `contain_fn` (contain_host)."""
    return {
        "kill_session":  _evict_executor(remove_foothold, "removed"),   # D3-ST  remove live foothold
        "rollback_host": _evict_executor(rollback_host, "rolled_back"),  # D3-RB  known-good restore
        "close_vector":  _evict_executor(close_vector, "closed"),        # D3-PH  shut the entry vector
    }


if __name__ == "__main__":  # self-check: schema + clean no-Docker/absent-host degradation
    # Every primitive must return a dict and degrade cleanly against a host that
    # isn't there (Docker missing, or container absent) — never raise, never hang.
    GHOST = "nonexistent-eviction-host-xyz"
    r = remove_foothold(GHOST, patterns=("implant",), timeout=3)
    assert isinstance(r, dict) and r["removed"] is False, r
    assert r["killed_pids"] == [] and r["remaining_pids"] == [], r
    rb = rollback_host(GHOST, timeout=5)
    assert isinstance(rb, dict) and rb["rolled_back"] is False, rb
    cv = close_vector(GHOST, port=8080, timeout=3)
    assert isinstance(cv, dict) and cv["closed"] is False, cv
    # Existing primitives still return their documented shapes against the ghost.
    assert contain_host(GHOST)["contained"] is False
    assert restore_host(GHOST) in (True, False)   # best-effort, never raises
    assert drop_honeytoken(GHOST)["planted"] in (True, False)
    assert _pids_matching(GHOST, "implant") == []
    print("blue_contain ok: contain/restore/honeytoken + remove_foothold/"
          "rollback_host/close_vector all degrade cleanly (no Docker/host needed)")
