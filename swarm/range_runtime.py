"""Clean range runtime helpers — the real up/down of a generated range.

Extracted out of the fabricated demo `run.py` so the canonical driver
(`scripts/arms_race_enterprise_frontier.py`) and the floor/corpus proofs
(`gen_corpus`, `prove_corpus_floor`, `live_arms_race_run`) depend on THIS, not on
`run.py`'s scripted `run_dry()`/`run_live()` theater. No cosmetic/term dependency,
no scripted beats — just: start a fresh hash-chain file, and bring a per-seed
generated range up and down via `docker compose`.

This is part of the F1-engine convergence: one real runtime on the live path.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from swarm.gate import run_effect, EffectTimeout  # one effect path (invariant #1)
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"
FIREWALL = REPO_ROOT / "scripts" / "host_egress_firewall.py"

# Phase 0a privilege model (the host-side §E firewall needs root for iptables):
# the duel process NEVER runs as root. It invokes the one audited firewall script via
# `sudo -n` (non-interactive: fail fast, never hang an automated run on a password
# prompt), and root is confined to that script by a NARROW NOPASSWD sudoers line. The
# root-needing actions run under a FIXED /usr/bin/python3 (stdlib-only) so the sudoers
# rule is stable (independent of the venv path). Authorize with, e.g.:
#   <user> ALL=(root) NOPASSWD: /usr/bin/python3 <repo>/scripts/host_egress_firewall.py --up, \
#                               /usr/bin/python3 <repo>/scripts/host_egress_firewall.py --down
# --verify is non-root (docker inspect + a container-side probe) and is AUTHORITATIVE:
# if §E is open the standup HALTS before any tooling runs (a hard-floor break is never a
# result — it stops the run). The firewall is reached by SUBPROCESS, never imported, so
# the class-2 channel it uses for the probe stays out of this module's import closure.


def _say(msg):
    """Plain stderr progress line (no cosmetic dependency)."""
    print(f"[range] {msg}", file=sys.stderr, flush=True)


def _fresh_log(path):
    """Start a fresh event-log file. `unlink(missing_ok=True)` only swallows
    FileNotFoundError, so on a no-delete / read-only mount it RAISES; degrade instead:
    try to delete, else truncate in place, else leave it (a fully read-only DATA
    surfaces when EventLog tries to append)."""
    path = Path(path)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        try:
            path.write_text("")
        except OSError:
            pass
    return path


def _compose(argv, gate, *, seed=None, op=None, **run_kw):
    """Run a compose lifecycle command. When a `gate` is given, route it through the TCB-owned
    `range.lifecycle` verb (gate.lifecycle: logged + the single effect primitive); otherwise
    the single effect primitive directly. Either way the actual spawn is run_effect in gate.py."""
    if gate is not None:
        return gate.lifecycle(argv, meta={"seed": seed, "op": op}, **run_kw)
    return run_effect(argv, **run_kw)


def _firewall_argv(action, sudo=False):
    """Argv to invoke the §E host firewall. Root-needing actions (--up/--down) run under
    `sudo -n` + a FIXED /usr/bin/python3 (stdlib-only; keeps the NOPASSWD sudoers rule
    stable). --verify imports swarm.uninstrumented, so it uses the project interpreter."""
    if sudo:
        return ["sudo", "-n", "/usr/bin/python3", str(FIREWALL), action]
    return [sys.executable or "python3", str(FIREWALL), action]


def _firewall(action, gate, seed, *, sudo=False):
    """Run a firewall action through the logged lifecycle path, never raising: a missing
    `sudo`/sudoers entry must degrade to a non-zero result (caught by --verify), not crash
    the standup. Returns an object with `.returncode`/`.stderr`/`.stdout`."""
    try:
        return _compose(_firewall_argv(action, sudo), gate, seed=seed,
                        op=f"firewall{action}", cwd=str(REPO_ROOT),
                        capture_output=True, text=True, timeout=60)
    except Exception as e:
        _say(f"firewall {action} not run ({e})")
        class _R:
            returncode = 1
            stderr = str(e)
            stdout = ""
        return _R()


def provision_ad_dc(gate=None, *, seed=None, container="range-dc-01", wait=120):
    """Apply the DC's DECLARED AD provisioning (the `duelswarm.provision` label) to the live Samba
    DC after boot — the orchestrated step that turns the declared kerberoastable SPN + Domain-Admin
    edges into REAL domain accounts. The label is metadata built by the generator (topo_to_compose)
    and leak-tested, but nothing else executes it, so a freshly booted DC carries only the default
    domain accounts until this runs. Waits for samba-tool/KDC readiness (the nowsci/samba-domain
    image provisions the domain on first boot, ~tens of seconds), then applies the label idempotently
    (each `samba-tool` ends in `|| true`). Gate-logged via the TCB `range.lifecycle` path (docker exec
    is the single effect primitive), so provisioning is attributable on the hash chain. Returns the
    CompletedProcess, or None when there is no DC / no provision label (a non-AD range)."""
    import subprocess
    try:   # the provision commands as DECLARED on the live DC container (no yaml dep; applied truth)
        prov = subprocess.run(
            ["docker", "inspect", "-f", '{{index .Config.Labels "duelswarm.provision"}}', container],
            capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception as e:                                       # noqa: BLE001
        _say(f"AD provision: cannot read the label on {container} ({e})")
        return None
    if not prov or prov == "<no value>":
        _say(f"AD provision: no duelswarm.provision label on {container} (non-AD range) — skipping")
        return None
    deadline = time.time() + wait                               # wait for the KDC before applying
    ready = False
    while time.time() < deadline:
        try:
            r = subprocess.run(["docker", "exec", container, "samba-tool", "domain", "level", "show"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                ready = True
                break
        except Exception:                                       # noqa: BLE001
            pass
        time.sleep(3)
    if not ready:
        _say(f"AD provision: samba-tool not ready on {container} after {wait}s — applying anyway")
    res = _compose(["docker", "exec", container, "bash", "-lc", prov], gate, seed=seed,
                   op="provision-ad-dc", capture_output=True, text=True, timeout=180)
    _say(f"AD provision applied on {container}: rc={getattr(res, 'returncode', '?')}")
    return res


def bring_up_generated_range(compose_path, seed, boot_wait=8, gate=None):
    """Stand up the per-seed generated range. Tears down the canonical fixed range
    first to free port 8080, then `docker compose -f <seed>/docker-compose.gen.yml up
    -d`. Project name is per-seed so parallel seeds don't collide. Compose lifecycle is the
    TCB-owned `range.lifecycle` verb when a `gate` is supplied (gate-logged)."""
    compose_path = Path(compose_path)
    _say("tearing down any fixed range (frees port 8080)")
    try:
        _compose(["docker", "compose", "down", "--remove-orphans"], gate, seed=seed,
                 op="down-fixed", cwd=str(REPO_ROOT), capture_output=True, timeout=30)
    except Exception as e:
        _say(f"compose down (fixed) failed, continuing: {e}")
    _say(f"docker compose up for seed {seed}")
    try:
        up = _compose(
            ["docker", "compose", "-f", str(compose_path), "up", "-d"], gate, seed=seed, op="up",
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=180,
        )
        if up.returncode != 0:
            _say(f"compose up failed: {up.stderr[:500]}")
            raise SystemExit(1)
    except EffectTimeout:
        _say("compose up timed out (image pull slow?). Pre-pull with: docker compose pull")
        raise SystemExit(1)
    time.sleep(boot_wait)  # Struts/Tomcat needs ~5-8s before it serves

    # Phase 0a HARD FLOOR: install the host-side egress firewall for THIS range's ingress
    # bridge, then VERIFY §E is actually closed from the compromised entry. The install is
    # best-effort (root via `sudo -n`); the verify is authoritative (non-root). A hard-floor
    # break is NEVER a result — if the host gateway stays reachable we HALT and tear down
    # before any tooling runs. Off-Linux, --verify SKIPs (returns 0: the Docker VM isolates).
    fw_up = _firewall("--up", gate, seed, sudo=True)
    if getattr(fw_up, "returncode", 1) != 0:
        _say(f"host firewall --up did not apply: {(getattr(fw_up, 'stderr', '') or '')[:200]}")
    fw_v = _firewall("--verify", gate, seed)
    if getattr(fw_v, "returncode", 1) != 0:
        _say("HARD FLOOR NOT HOLDING — §E open (host gateway reachable from the entry). "
             "Halting the standup. Authorize the firewall via the NOPASSWD sudoers line for "
             f"{FIREWALL} (see swarm/range_runtime.py), or run "
             f"`sudo /usr/bin/python3 {FIREWALL} --up`, then retry.")
        tear_down_generated_range(compose_path, seed, gate=gate)
        raise SystemExit(1)
    _say(f"seed {seed} up (compose: {compose_path.name}); hard floor verified (§E closed)")
    # Orchestrated AD provisioning: apply the DC's declared SPN/DA edges to the live Samba DC (no-op
    # for a non-AD range). Only after §E is verified closed — provisioning touches the identity tier.
    provision_ad_dc(gate=gate, seed=seed)


def tear_down_generated_range(compose_path, seed, gate=None):
    """Tear down the per-seed generated range after a run (TCB-owned range.lifecycle verb)."""
    compose_path = Path(compose_path)
    _say(f"tearing down seed {seed}")
    try:
        _compose(
            ["docker", "compose", "-f", str(compose_path), "down", "-v", "--remove-orphans"],
            gate, seed=seed, op="down-seed", cwd=str(REPO_ROOT), capture_output=True, timeout=60,
        )
    except Exception as e:
        _say(f"compose down (seed {seed}) failed: {e}")
    # Remove this range's §E host firewall (best-effort; root via sudo -n).
    _firewall("--down", gate, seed, sudo=True)


# Back-compat aliases: the keepers historically called the run.py names (leading _).
_bring_up_generated_range = bring_up_generated_range
_tear_down_generated_range = tear_down_generated_range


if __name__ == "__main__":  # self-check: importable, helpers present, DATA resolves
    assert DATA.name == "data" and DATA.parent == REPO_ROOT
    for fn in (_fresh_log, bring_up_generated_range, tear_down_generated_range,
               _bring_up_generated_range, _tear_down_generated_range):
        assert callable(fn)
    # _fresh_log degrades, never raises, on a fresh path
    import tempfile
    p = Path(tempfile.mkdtemp()) / "chain.jsonl"
    assert _fresh_log(p) == p
    # Phase 0a firewall argv: root-needing actions run under non-interactive sudo + a
    # FIXED system interpreter (stable sudoers rule); --verify uses the project interpreter.
    assert FIREWALL.name == "host_egress_firewall.py"
    up = _firewall_argv("--up", sudo=True)
    assert up[:3] == ["sudo", "-n", "/usr/bin/python3"] and up[-2:] == [str(FIREWALL), "--up"]
    dn = _firewall_argv("--down", sudo=True)
    assert dn[:3] == ["sudo", "-n", "/usr/bin/python3"] and dn[-1] == "--down"
    ver = _firewall_argv("--verify")
    assert ver[0] != "sudo" and ver[-2:] == [str(FIREWALL), "--verify"]
    print("range_runtime ok (clean helpers, no term/scripted dependency; "
          "§E firewall wired into standup, non-root duel + sudo-confined install)")
