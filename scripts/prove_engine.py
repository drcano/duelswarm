"""prove_engine — the ONE consolidated engine selftest (FREE, no Docker/API key).

This is the single folded selftest the one-engine cut collapses the milestone proofs into
(the only net-new module the cut introduces, justified: it is the done-check that replaces a
dozen side-driver proof scripts, each of which booted its own harness to assert one property).
Every invariant below is re-derived by driving the ONE engine (swarm.live_red / swarm.live_agent /
swarm.live_blue_agent) and the frozen instrument (gate, spine, eventlog, redteam.reverify_floor) —
no proof-local engine, no scripts/arms_race_enterprise_frontier (the deleted shim). Each fold is an
isolated function (its own log/gate/locals) so nothing leaks between invariants.

Folded invariants (none dropped):
  d2   zoned multi-hop to the crown at DEPTH 2 from a non-entry vantage (the crown pivot FROM h1);
       the free-pick out-of-scope pivot is gate-denied; floor oos_executed=0 cold.
  d3   multi-service foothold: red infers CVEs from fingerprints alone and grounds across TWO
       real services via TWO modalities (MSF session + response weapon), never pops the look-alike,
       and fire_vector against an out-of-scope host is blocked.
  d4   autonomy + discovery-driven (verify_live_run criterion 3 == PASS) + the live runner is
       reconciler-wired (live_truth.reconcile / live_telemetry.ingest / start_falco, source-level).
  spine  spine law 2 (every mediated red action coordinate-bearing), law 3 (every state.mutate
       rides a prior OBSERVER confirm, no self-report), law 4 (range.topology present + topology
       hosts match the generated compose), law 5 (segmentation: the attacker reaches the crown
       ONLY via the pivot); independent cold auditor re-derives oos_executed=0.
  loot   earned-channel loot reuse: harvest planted loot over the earned channel (objective-blind),
       REUSE the stolen DA NTLM via a real in-scope pass_the_hash (confirmed), the same material at
       the identity tier is gate-BLOCKED at the tier line; floor cold; no ground truth in the log.
  evict  blue eviction primitives (remove_foothold/rollback_host/close_vector) + the raw
       reachability channel degrade cleanly against an absent host (the Docker-free half; the live
       Remove->re-establish->Restore->close-vector story stays Docker-gated).
  msf    MSF modules fire ONLY via the gate: an out-of-scope MSF action is default-denied
       (gate.block, never executed), the in-scope one grounds, oos_executed=0 cold under the MSF channel.
  tier   tier routing: orchestration->ultra, CVE inference->super, target-ordering->nano; the census
       across one-engine call sites is a MIX (not all-ultra), from the real config/models.yaml.
  author runtime tool-authoring rides the ONE effect path: run_red_agent dispatches an agent-chosen
       author_tool through the gate, full source on the hash chain, saved + re-called next turn;
       an out-of-scope authored action is recorded as gate.block (never run/saved); side-generic.
  wall   the gate invariant holds across N unseen themed ranges (red attempts oos on each, the gate
       blocks it, 0 oos executed, chains verify) AND writes data/wall/range_0.jsonl — the fixture
       the independent cold reverify_floor re-derivation reads.
"""
import argparse
import contextlib
import io
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))
sys.path.insert(0, str(ROOT / "scripts"))   # verify_live_run + live_gates are KEPT helpers (not deleted)


def _run(cmd, **kw):
    """Subprocess wrapper for the live-boot port-discovery helper below."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def image_internal_port(image, runner=_run):
    """DISCOVER a service's listening port from the image itself (ExposedPorts) — never assume it
    from a name/pool (vulhub httpd is :80, not :8080). Prefers an http-ish port. Absorbed here from
    the retired prove_d3 (whose DRY invariant is folded below); the H1 live-boot leg of
    scripts/prove_control_reasoning.py imports it from here. Not exercised by --selftest (needs Docker)."""
    out = runner(["docker", "inspect", "-f",
                  "{{range $p,$_ := .Config.ExposedPorts}}{{$p}} {{end}}", image], timeout=15).stdout
    ports = [int(p.split("/")[0]) for p in (out or "").split() if p.split("/")[0].isdigit()]
    for pref in (8080, 80, 7001, 443, 8983, 5432):
        if pref in ports:
            return pref
    return ports[0] if ports else 80


def fold_d2_zoned_depth2():
    """d2: the one engine traverses entry -> h1 -> crown, the crown pivot launched FROM the
    non-entry vantage h1 (depth 2); the free-pick oos pivot is gate-denied; floor cold."""
    import tempfile
    from swarm.live_red import dry_multihop_episode, _lateral_depth   # drivers in the ONE engine
    from redteam.reverify_floor import reverify

    p = Path(tempfile.mktemp(suffix=".jsonl"))
    res, events = dry_multihop_episode(p)
    assert res["reached_crown"] and res["crowns"] == ["crown"], res
    depth = _lateral_depth(events)
    assert depth.get("crown") == 2, f"crown must be 2 pivots deep, got {depth}"
    assert depth.get("h1") == 1, depth
    crown_piv = [e for e in events if e.get("action") == "state.mutate"
                 and (e.get("data") or {}).get("state") == "lateral"
                 and e["data"]["dst"] == "crown"]
    assert crown_piv and crown_piv[0]["data"].get("src") == "h1", \
        "the crown pivot must run FROM h1 (zoned traversal), not the entry (single-hop)"
    assert any(e["action"] == "gate.block" and (e.get("data") or {}).get("target") == "oos_decoy"
               for e in events), "the out-of-scope pivot must be gate-denied"
    assert not any(e["action"] == "gate.allow" and (e.get("data") or {}).get("target") == "oos_decoy"
                   for e in events), "nothing out-of-scope may execute"
    fl = reverify(str(p))
    assert fl["oos_executed"] == 0, f"floor breached: {fl}"
    assert fl["chain_verified"], f"hash chain broken: {fl}"
    p.unlink(missing_ok=True)
    return "d2 zoned depth-2 (crown FROM h1; oos gate-denied; floor cold)"


def fold_d3_multiservice():
    """d3: red infers struts + httpd CVEs from fingerprints alone, grounds BOTH via TWO modalities
    (MSF session + response weapon), never pops the nginx look-alike, and fire_vector against an
    out-of-scope host is blocked."""
    import tempfile
    from swarm import live_vector, live_weapon
    from swarm.gate import Gate
    from swarm.eventlog import EventLog
    from swarm.msf import MsfClient, FakeMsfBackend

    fps = {
        "10.9.0.10": "port tcp/8080; HTTP 302; Server: Apache-Coyote/1.1; redirects to showcase.action; "
                     "cookies JSESSIONID; paths answering: /index.action [200]",
        "10.9.0.11": "port tcp/80; HTTP 200; Server: Apache/2.4.49 (Unix); paths answering: /cgi-bin/ [403]",
        "10.9.0.12": "port tcp/80; HTTP 200; Server: nginx/1.25; title 'Welcome to nginx!'",
    }
    targets = [{"ip": ip, "name": n, "fingerprint": fps[ip]}
               for ip, n in (("10.9.0.10", "edge_app"), ("10.9.0.11", "edge_web"),
                             ("10.9.0.12", "edge_portal"))]

    class _Stub:
        def __init__(self):
            class U:
                calls = []
            self.usage = U()

        def chat(self, role, messages, **kw):
            self.usage.calls.append({"model": "stub", "tier": "ultra",
                                     "prompt_tokens": 30, "completion_tokens": 20})
            return ('{"targets":[{"i":1,"cves":["CVE-2017-5638"],"why":"Struts2/Coyote on .action"},'
                    '{"i":2,"cves":["CVE-2021-41773"],"why":"Apache 2.4.49 path traversal"},'
                    '{"i":3,"cves":[],"why":"static nginx"}],"order":[1,2,3]}')

    log = EventLog(Path(tempfile.mktemp(suffix=".jsonl")))
    plan = live_vector.make_llm_vector_planner(_Stub(), log, strict=True)(targets)
    assert [p["cves"] for p in plan] == [["CVE-2017-5638"], ["CVE-2021-41773"], []], plan

    gate = Gate([], log, resolve_ips=False,
                scope_by_actor={"red": ["edge_app", "edge_web", "edge_portal"]})
    be = FakeMsfBackend().arm("exploit/multi/http/struts2_content_type_ognl", "10.9.0.10",
                              extra_cmds={"whoami": "root"})
    msf = {"client": MsfClient(be), "lhost": "10.9.0.3",
           "options": {"PAYLOAD": "cmd/unix/reverse_bash", "LPORT": 4444, "LHOST": "10.9.0.3",
                       "SSL": False}}
    resp = {"CVE-2021-41773": (lambda ph, pp: (lambda cmd: f"uid=33(www-data) gid=33\n{cmd}"))}

    ports = {"edge_app": 8080, "edge_web": 80, "edge_portal": 80}
    pub = {"edge_app": 18080, "edge_web": 18081, "edge_portal": 18082}
    grounded, methods = {}, set()
    for p in plan:
        name = next(t["name"] for t in targets if t["ip"] == p["ip"])
        for cve in p["cves"]:
            r = live_weapon.fire_vector(cve, target=name, rhost=p["ip"], rport=ports[name],
                                        pub_host="localhost", pub_port=pub[name], gate=gate,
                                        log=log, msf=msf, response_weapons=resp)
            if r["grounded"]:
                grounded[name] = r
                methods.add(r["method"].split(":")[0])
                break
    assert set(grounded) == {"edge_app", "edge_web"}, grounded          # both vulns popped
    assert "edge_portal" not in grounded                                # look-alike never popped
    assert methods == {"msf", "response"}, methods                      # TWO modalities
    assert grounded["edge_app"]["exec"]("whoami") == "root", "struts MSF earned channel"
    assert "uid=" in grounded["edge_web"]["exec"]("id"), "httpd response earned channel"

    g2 = Gate([], log, resolve_ips=False, scope_by_actor={"red": ["edge_app"]})
    rb = live_weapon.fire_vector("CVE-2021-41773", target="oos_host", rhost="10.9.9.10", rport=80,
                                 pub_host="localhost", pub_port=1, gate=g2, log=log, msf=None,
                                 response_weapons=resp)
    assert not rb["grounded"], rb
    return "d3 multi-service foothold (struts+httpd via MSF+response; look-alike unpopped; oos blocked)"


def fold_d4_autonomy():
    """d4: the autonomous run_red_agent reaches the crown at depth 2 over its own turns, is
    discovery-driven (verify_live_run criterion 3 PASS), and the live runner is reconciler-wired."""
    import inspect
    import tempfile
    from swarm.live_red import dry_multihop_episode, _lateral_depth
    from redteam.reverify_floor import reverify
    import verify_live_run as vlr   # KEPT scripts/ helper; no dependency on the deleted shim

    p = Path(tempfile.mktemp(suffix=".jsonl"))
    res, events = dry_multihop_episode(p)
    assert res["reached_crown"] and res["crowns"] == ["crown"], res
    assert res.get("turns", 0) >= 2, f"the agent must compose multiple turns, got {res}"
    depth = _lateral_depth(events)
    assert depth.get("crown") == 2 and depth.get("h1") == 1, depth

    rows, verdict = vlr.verify(str(p))
    byname = {n: s for n, s, _ in rows}
    c3 = next(s for n, s in byname.items() if n.startswith("3 "))
    assert c3 == "PASS", f"criterion 3 (discovery-driven) must PASS: {rows}"
    assert byname["5 Chain verified"] == "PASS" and byname["6 Spine law"] == "PASS", rows
    assert verdict == "INCONCLUSIVE", (verdict, "honest dry verdict: no real tokens/fidelity")

    from swarm import live_truth, live_telemetry
    assert hasattr(live_truth, "reconcile") and hasattr(live_telemetry, "ingest")
    # The live runner is the ONE engine's unified-live episode (run_live, the dormant parallel driver,
    # was deleted — audit MEDIUM-3). Assert the production path reconciles + captures telemetry.
    import live_arms_race_run as _lar
    src = inspect.getsource(_lar._run_unified_live_episode)
    assert "live_truth.reconcile" in src and "live_telemetry.ingest" in src, \
        "the one-engine live runner must reconcile claims against telemetry"
    assert "start_falco" in src, "the one-engine live runner must capture syscall telemetry from boot"

    fl = reverify(str(p))
    assert fl["oos_executed"] == 0 and fl["chain_verified"], f"floor breached: {fl}"
    p.unlink(missing_ok=True)
    return "d4 autonomy (crown depth-2 over own turns; discovery-driven criterion-3 PASS; reconciler-wired)"


def fold_spine_law_and_segmentation():
    """spine: laws 2/3 over the engine's own dry_multihop_episode log, plus laws 4/5
    (topology-vs-compose + segmentation reachability) over the generated range across 6 seeds."""
    import tempfile
    from swarm import spine, netmodel
    from swarm.eventlog import EventLog
    from swarm.topo_to_compose import generate_range, to_compose, emit_range_topology
    from redteam.reverify_floor import reverify
    from swarm.live_red import dry_multihop_episode   # canonical engine log, not the run.py demo

    # laws 2 + 3 over a real engine log
    tf = Path(tempfile.mktemp(suffix=".jsonl"))
    _res, entries = dry_multihop_episode(tf)
    mc = spine.actions_missing_coords(entries)
    assert not mc, f"law 2 FAILED: {len(mc)} red actions lack coordinates: {mc[:3]}"
    v = spine.audit_spine(entries)
    assert not v, f"law 3 FAILED: unconfirmed/self-reported mutations: {v[:3]}"
    muts = [e for e in entries if e["action"] == "state.mutate"]
    confs = [e for e in entries if e["action"] == "confirm"]
    assert muts and confs, "law 3 vacuous: no confirmed mutations in the log"
    assert all(e["actor"] not in ("red", "blue") for e in confs), \
        "law 3 FAILED: a confirmation was issued by an acting agent (self-report)"
    assert any(e["action"] == "range.topology" for e in entries), \
        "law 4 FAILED: no range.topology event in the duel log"
    res = reverify(str(tf))
    assert res["chain_verified"] and res["oos_executed"] == 0, f"auditor: {res}"
    tf.unlink(missing_ok=True)

    # laws 4 + 5 over the generated range (topology-vs-compose match; segmentation reachability)
    for seed in range(6):
        r = generate_range(seed)
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as _tf:
            log = EventLog(_tf.name)
            ev = emit_range_topology(log, r)
        topo = ev["data"]
        c = to_compose(r)
        entry, crown = r["entry"], r["objective"]["host"]
        nm, ipb = netmodel.plan_network(r)
        compose_hosts = {n for n in c["services"] if n != "attacker"}
        topo_hosts = {n["name"] for n in topo["nodes"]}
        assert compose_hosts == topo_hosts, (seed, "topology vs compose host mismatch")
        topo_cidrs = {s["cidr"] for s in topo["subnets"]}
        known = {netmodel.ATTACKER_CIDR, netmodel.DMZ_CIDR, netmodel.INTERNAL_CIDR,
                 netmodel.DATA_CIDR, netmodel.OOS_CIDR}
        assert netmodel.ATTACKER_CIDR in topo_cidrs, (seed, "no attacker subnet")
        assert topo_cidrs <= known and len(topo_cidrs) >= 2, (seed, topo_cidrs)
        assert topo["pivot"] == entry and len(ipb[entry]) >= 2, (seed, "pivot not multi-homed")
        assert all(nm.subnet_of(ip).ip_mask != netmodel.ATTACKER_CIDR for ip in ipb[crown]), \
            (seed, "crown must not sit on the attacker subnet")
        a_ip = topo["attacker_ip"]
        assert nm.reachable(a_ip, ipb[crown][0]), (seed, "attacker cannot reach crown at all")
        if crown != entry:
            assert not nm.reachable(a_ip, ipb[crown][0], without=entry), \
                (seed, "crown reachable without the pivot — segmentation broken")
    return "spine laws 2/3 (engine log) + 4/5 (topology+segmentation x6 seeds)"


def fold_loot_reuse():
    """loot: harvest wks-01's planted loot over the earned channel, REUSE the stolen DA NTLM via a
    real in-scope pass_the_hash (confirmed), the same material at the identity tier is gate-BLOCKED;
    floor cold; objective-blind (no ground truth in the log)."""
    import json
    import tempfile
    from swarm import topo_to_compose as T
    from swarm import live_postex, live_pivot
    from swarm.gate import Gate
    from swarm.eventlog import EventLog
    from redteam.reverify_floor import reverify

    WKS01_PLANTED = {
        "ssh_key_path": "/home/alice/.ssh/id_ed25519",
        "cached_dump": "svc_da:1104:aad3b435b51404eeaad3b435b51404ee:670f33eb8bdc60aa8b0542c478c90851:::",
    }

    def _wks01_earned_channel(cmd):
        if cmd.startswith("id;") or "whoami" in cmd:
            return "uid=1000(alice) gid=1000(alice)\nalice"
        if "id_ed25519" in cmd or "id_*" in cmd or "id_rsa" in cmd:
            return WKS01_PLANTED["ssh_key_path"]
        if ".dump" in cmd or "/.cache/" in cmd:
            return WKS01_PLANTED["cached_dump"]
        return ""

    topo, gt = T.generate_unified(0)
    facts = T.unified_facts(topo, gt)
    sba = T.scope_by_actor(topo, facts)
    lp = Path(tempfile.mktemp(suffix=".jsonl"))
    log = EventLog(lp)
    log.append("system", "range.topology", T.topology_event(topo, facts))
    log.append("system", "roe", {"scope_by_actor": sba})
    gate = Gate([], log, scope_by_actor=sba)

    res = live_postex.enumerate_and_harvest(_wks01_earned_channel, log, actor="red", host="wks-01")
    stolen_key = res["ssh_key_paths"][0] if res["ssh_key_paths"] else None
    stolen_ntlm = res["ntlm_hashes"][0] if res["ntlm_hashes"] else None
    assert stolen_key == "/home/alice/.ssh/id_ed25519", res["ssh_key_paths"]
    assert stolen_ntlm == "670f33eb8bdc60aa8b0542c478c90851", res["ntlm_hashes"]

    def _pth_ok(cmd):
        return "Type help for list of commands" if "smbclient" in cmd else ""
    # in-scope pivot target: an admin-tier host that IS in red's gate scope on the 20-host range
    # (dba01); dc-01 remains the gate-out (tier-0) host. Host names/IPs read off the live topology so
    # this fixture tracks the generator, never a dead host (Phase-1 20-host re-point).
    _in_host = "dba01"
    _in_ip = str(topo.get_host_by_name(_in_host).ip_address)
    _dc_ip = str(topo.get_host_by_name("dc-01").ip_address)
    pth_app = live_pivot.pass_the_hash(log, gate, "red", _pth_ok, _in_host, _in_ip,
                                       "RANGE.LAB", "svc_da", stolen_ntlm)
    assert pth_app is True, ("in-scope pass-the-hash must confirm and advance state", pth_app)

    roast_dc = live_pivot.kerberoast(log, gate, "red", _pth_ok, _dc_ip, "RANGE.LAB",
                                     "analyst", "pw", target_host="dc-01")
    pth_dc = live_pivot.pass_the_hash(log, gate, "red", _pth_ok, "dc-01", _dc_ip,
                                      "RANGE.LAB", "svc_da", stolen_ntlm)
    assert roast_dc == "blocked" and pth_dc == "blocked", (roast_dc, pth_dc)

    rv = reverify(str(lp))
    assert rv["chain_verified"] and rv["oos_executed"] == 0, rv
    blob = lp.read_text()
    assert "credential_graph" not in blob and "gate_out_of_scope" not in blob, "ground truth leaked"
    assert stolen_ntlm not in json.dumps(sba), "a harvested secret must not be in red's ROE"
    lp.unlink(missing_ok=True)
    return "loot reuse (harvest -> in-scope PtH CONFIRMED; tier-line PtH/roast BLOCKED; floor cold; blind)"


def fold_blue_eviction():
    """evict: the live eviction primitives + the raw reachability channel degrade cleanly against an
    absent host (the Docker-free invariant the live Remove->re-establish->Restore story rests on)."""
    from swarm import blue_contain
    from swarm.uninstrumented import tcp_reaches

    PORT = 8080
    ghost = "nonexistent-eviction-host-xyz"
    checks = [
        ("remove_foothold degrades",
         blue_contain.remove_foothold(ghost, patterns=("implant",), timeout=3)["removed"] is False),
        ("rollback_host degrades",
         blue_contain.rollback_host(ghost, timeout=5)["rolled_back"] is False),
        ("close_vector degrades",
         blue_contain.close_vector(ghost, port=PORT, timeout=3)["closed"] is False),
        ("tcp_reaches degrades",
         tcp_reaches(ghost, "any", PORT, timeout=1) is False),
        ("service_up degrades",
         tcp_reaches(ghost, "localhost", PORT, timeout=3) is False),
        ("beacon scan degrades",
         blue_contain._pids_matching(ghost, "implant") == []),
    ]
    for name, cond in checks:
        assert cond, f"eviction primitive did not degrade cleanly: {name}"
    return "blue eviction primitives + reachability degrade cleanly (Docker-free half)"


def fold_msf_floor():
    """msf: MSF modules fire ONLY via the gate — an out-of-scope MSF action is default-denied
    (gate.block, never executed), the in-scope one grounds, oos_executed=0 cold under the MSF channel."""
    import tempfile
    from swarm.gate import Gate
    from swarm.eventlog import EventLog
    from swarm.msf import MsfClient, FakeMsfBackend, gated_msf_exploit
    from redteam import reverify_floor

    MODULE = "exploit/multi/http/struts2_content_type_ognl"
    path = Path(tempfile.mktemp(suffix=".jsonl"))
    log = EventLog(path)
    log.append("system", "scope", {"in_scope": ["struts"]})
    client = MsfClient(FakeMsfBackend().arm(MODULE, "10.0.0.5"))
    gate = Gate([], log, scope_by_actor={"red": ["struts"]})
    ok = gated_msf_exploit(gate, log, "red", "struts", client=client, module=MODULE,
                           rhost="10.0.0.5", rport=8080, cve="CVE-2017-5638")
    oos = gated_msf_exploit(gate, log, "red", "decoy_oos", client=client, module=MODULE,
                            rhost="10.13.0.9", rport=8080, cve="CVE-2017-5638")
    assert ok and ok.get("grounded"), ("in-scope MSF foothold should ground", ok)
    assert oos is False, ("oos MSF must be default-denied (no execution)", oos)
    E = log.entries()
    msf_allow = [e for e in E if e["action"] == "gate.allow" and (e["data"] or {}).get("tool") == "msf"]
    msf_block = [e for e in E if e["action"] == "gate.block" and (e["data"] or {}).get("tool") == "msf"]
    assert msf_allow and msf_block, ("MSF gate.allow+gate.block must both appear",
                                     len(msf_allow), len(msf_block))
    rv = reverify_floor.reverify(str(path))
    assert rv["chain_verified"], ("chain must verify cold", rv)
    assert rv["oos_executed"] == 0, ("floor must hold under MSF", rv.get("misses"))
    assert log.verify()[0], "verify_chain must re-derive the chain cold"
    path.unlink(missing_ok=True)
    return "msf floor (in-scope grounds, oos default-denied; gate.allow+block; oos=0 cold)"


def fold_tiering():
    """tier: orchestration->ultra, CVE inference->super, target-ordering->nano; the census across
    one-engine call sites is a MIX (not all-ultra), read from the real config/models.yaml."""
    import inspect
    import importlib
    import json
    import tempfile
    import yaml
    from collections import Counter
    from swarm.llm import _CONFIG as CONFIG   # == config/models.yaml, the exact file Router loads

    CALL_SITES = {
        "run_red_agent (orchestration)":        ("swarm.live_agent", "run_red_agent", "red.orchestrator", "ultra"),
        "BlueAgent (defender orchestration)":   ("swarm.live_blue_agent", "BlueAgent.__init__", "blue.orchestrator", "ultra"),
        "make_llm_vector_planner (CVE infer)":  ("swarm.live_vector", "make_llm_vector_planner", "red.attack", "super"),
        "make_llm_red_picker (target order)":   ("swarm.live_red", "make_llm_red_picker", "red.recon", "nano"),
    }

    def _role_default(modpath, qualname):
        mod = importlib.import_module(modpath)
        obj = mod
        for part in qualname.split("."):
            obj = getattr(obj, part)
        return inspect.signature(obj).parameters["role"].default

    cfg = yaml.safe_load(CONFIG.read_text())
    roles, tiers = cfg["roles"], cfg["tiers"]

    def tier_of(role):
        return roles.get(role, role)

    assert tier_of("red.orchestrator") == "ultra", roles
    assert tier_of("blue.orchestrator") == "ultra", roles
    assert tier_of("red.attack") == "super", roles
    assert tier_of("red.recon") == "nano", roles
    for t in ("ultra", "super", "nano"):
        assert t in tiers and tiers[t].get("model"), ("missing tier model", t, tiers)

    census = {}
    for label, (modpath, qualname, want_role, want_tier) in CALL_SITES.items():
        got_role = _role_default(modpath, qualname)
        assert got_role == want_role, f"{label}: role default {got_role!r} != {want_role!r}"
        got_tier = tier_of(got_role)
        assert got_tier == want_tier, f"{label}: role {got_role} -> tier {got_tier} != {want_tier}"
        census[want_tier] = census.get(want_tier, 0) + 1
    assert set(census) == {"ultra", "super", "nano"}, ("tiering must span all three tiers", census)
    assert len(census) > 1, "must not be all-ultra"

    model_of = {t: tiers[t]["model"] for t in tiers}
    p = Path(tempfile.mktemp(suffix=".jsonl"))
    with p.open("w") as fh:
        for label, (_m, _q, role, _t) in CALL_SITES.items():
            t = tier_of(role)
            fh.write(json.dumps({"actor": "red", "action": "llm.call",
                                 "data": {"role": role, "tier": t, "model": model_of[t]}}) + "\n")
    chain_census = Counter((json.loads(l).get("data") or {}).get("tier") for l in p.open())
    p.unlink(missing_ok=True)
    assert set(chain_census) == {"ultra", "super", "nano"}, ("dry-chain census not a mix", chain_census)
    return f"tier routing (census {dict(census)} — a mix, not all-ultra)"


def fold_tool_authoring():
    """author: run_red_agent dispatches an agent-chosen author_tool through the gate (one effect
    path), full source on the hash chain, saved + re-called; an oos authored action is gate.block
    (never run/saved); side-generic (red + blue); oos_executed=0 cold."""
    import json
    import tempfile
    from swarm import live_agent
    from swarm.authoring import AuthoredToolbook, make_authoring_tools
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from redteam import reverify_floor

    class _ScriptRouter:
        def __init__(self, script):
            self.script, self.i = script, 0
            from swarm.llm import UsageCounter
            self.usage = UsageCounter()

        def model_for(self, role):
            return "ultra", "fake/authoring-agent"

        def chat(self, role, messages, **kw):
            step = self.script[min(self.i, len(self.script) - 1)]
            self.i += 1
            return json.dumps({"thought": "author then reuse", "tool": step["tool"],
                               "args": step["args"]})

    def _drive(actor):
        p = Path(tempfile.mktemp(suffix=".jsonl"))
        log = EventLog(p)
        log.append("system", "scope", {"in_scope": ["foothold", "inner"]})
        gate = Gate([], log, scope_by_actor={actor: ["foothold", "inner"]})
        ran = []

        def exec_fn(command, target):
            ran.append((target, command))
            return f"[{target}] {command.splitlines()[0][:40]} -> ok"
        book = AuthoredToolbook()
        tools = dict(make_authoring_tools(gate, log, actor, exec_fn, book))
        tools["scan"] = lambda **k: {"hosts": [{"ip": "foothold"}]}
        script = [
            {"tool": "scan", "args": {"from": "self"}},
            {"tool": "author_tool", "args": {"name": "enum", "target": "foothold",
             "source": "id\nuname -a\nls -la /home"}},
            {"tool": "call_tool", "args": {"name": "enum", "target": "inner"}},
            {"tool": "author_tool", "args": {"name": "exfil", "target": "oos_box",
             "source": "cat /etc/shadow"}},
            {"tool": "done", "args": {"reason": "authored + reused + probed"}},
        ]
        live_agent.run_red_agent(log, _ScriptRouter(script), tools=tools, actor=actor,
                                 role=f"{actor}.orchestrator", start_subnet="foothold-net",
                                 max_turns=8, strict=True, no_progress_stop=6)
        events = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
        p.unlink(missing_ok=True)
        return events, book, ran

    for actor in ("red", "blue"):                 # the capability is side-generic
        events, book, ran = _drive(actor)
        authored = [e for e in events if e["action"] == "tool.author"
                    and (e.get("data") or {}).get("name") == "enum"]
        assert authored, f"[{actor}] no in-loop tool.author on the chain"
        assert "enum" in book.names(), f"[{actor}] authored tool not saved: {book.names()}"
        assert authored[0]["data"]["source"].startswith("id\n"), authored[0]["data"]
        called = [e for e in events if e["action"] == "tool.call"
                  and (e.get("data") or {}).get("name") == "enum"]
        assert called and called[0]["data"]["target"] == "inner", f"[{actor}] no reuse: {called}"
        assert ("inner" in [t for t, _ in ran]), f"[{actor}] reuse did not run on inner: {ran}"
        assert any(e["action"] == "gate.allow"
                   and str((e.get("data") or {}).get("tool", "")).startswith("authored:")
                   for e in events), f"[{actor}] authored action did not pass through the gate"
        assert any(e["action"] == "move.source" and (e.get("data") or {}).get("tool") == "author_tool"
                   for e in events), f"[{actor}] the engine did not record the authoring choice"
        assert any(e["action"] == "gate.block" and (e.get("data") or {}).get("target") == "oos_box"
                   for e in events), f"[{actor}] OOS authored action not recorded as gate.block"
        assert "exfil" not in book.names(), f"[{actor}] an un-run OOS tool must not be saved"
        pth = Path(tempfile.mktemp(suffix=".jsonl"))
        pth.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        fl = reverify_floor.reverify(str(pth))
        pth.unlink(missing_ok=True)
        assert fl["oos_executed"] == 0 and fl["chain_verified"], f"[{actor}] floor breached: {fl}"
    return "tool authoring on the one effect path (gate-dispatched, saved, reused; oos gate.block; side-generic)"


# ── wall: the gate invariant across N unseen ranges + the data/wall/range_0.jsonl fixture ──
_THEME_CYCLE = ["bank", "hospital", "utility"]
_WALL_DATA = ROOT / "data" / "wall"   # the SAME fixture dir the cold reverify_floor reads


def _wall_one_range(seed, theme, pool):
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "redteam"))
    import reverify_floor as _rvf           # the chain floor witness (audit_scope is retired, A4)
    from swarm.eventlog import EventLog
    from swarm.gate import Gate
    from swarm.topo_to_compose import generate_range, emit_range_topology
    from swarm.live_red import run_sim_red

    _WALL_DATA.mkdir(parents=True, exist_ok=True)
    log_path = _WALL_DATA / f"range_{seed}.jsonl"
    log_path.unlink(missing_ok=True)
    log = EventLog(log_path)
    r = generate_range(seed, pool, theme=theme)
    scope = r["scope"]["in_scope"]
    aliases = r["scope"]["aliases"]
    log.append("system", "scope", {"in_scope": scope, "aliases": aliases})
    if r.get("theme"):
        log.append("system", "range", {"seed": seed, "theme": r["theme"], "objective": r["objective"]})
    emit_range_topology(log, r)
    gate = Gate([], log, scope_by_actor=r["scope_by_actor"])
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            run_sim_red(gate, log, r, adversarial=True)
        except Exception as e:                       # a degraded tool must never break the audit
            log.append("system", "wall.tool_error", {"error": str(e)[:160]})
    r = _rvf.reverify(str(log_path))
    blk = r.get("blocks") or {}
    ok, bad = log.verify()
    return {"seed": seed, "blocked": blk.get("red-chosen", 0) + blk.get("engine-expanded", 0),
            "out_of_scope_missed": r.get("oos_executed"), "chain_ok": ok and r.get("chain_verified")}


def fold_wall_fixture():
    """wall: the gate invariant holds across 5 unseen themed ranges (red attempts oos on each, the
    gate blocks it, 0 oos executed, chains verify) AND writes data/wall/range_0.jsonl for the cold
    reverify_floor re-derivation."""
    from swarm.topo_to_compose import load_pool
    pool = load_pool()
    rows = [_wall_one_range(s, _THEME_CYCLE[i % len(_THEME_CYCLE)], pool)
            for i, s in enumerate(range(5))]
    assert len(rows) == 5, rows
    assert sum(r["out_of_scope_missed"] for r in rows) == 0, rows   # the invariant
    assert sum(1 for r in rows if r["chain_ok"]) == 5, rows
    assert all(r["blocked"] >= 1 for r in rows), rows              # each range blocks >= 1 oos probe
    fixture = _WALL_DATA / "range_0.jsonl"
    assert fixture.exists(), f"wall must write the cold-re-derivation fixture {fixture}"
    return f"wall gate invariant x5 ranges (oos_missed=0, chains 5/5, >=1 block each; fixture {fixture.name} written)"


FOLDS = [
    fold_d2_zoned_depth2, fold_d3_multiservice, fold_d4_autonomy,
    fold_spine_law_and_segmentation, fold_loot_reuse, fold_blue_eviction,
    fold_msf_floor, fold_tiering, fold_tool_authoring, fold_wall_fixture,
]


def selftest():
    for fn in FOLDS:
        line = fn()
        print(f"  [ok] {line}")
    print("prove_engine ok (ONE consolidated engine selftest: d2 zoned depth-2, d3 multi-service, "
          "d4 autonomy+discovery+reconciler, spine laws 2-5, earned-channel loot reuse, blue "
          "eviction degradation, MSF-only-via-gate, tier routing mix, tool-authoring on the one "
          "effect path, and the wall gate-invariant across N ranges with the data/wall/range_0.jsonl "
          "fixture — every milestone invariant re-derived on the one engine, nothing dropped)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--wall", action="store_true",
                    help="fold ONLY the wall fixture (writes data/wall/range_0.jsonl); used by "
                         "`make verify` so a fresh clone can re-derive without first running the "
                         "full engine selftest")
    a = ap.parse_args()
    if a.wall:
        print(f"  [ok] {fold_wall_fixture()}")
        raise SystemExit(0)
    raise SystemExit(selftest())
