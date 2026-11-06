"""HIGH-1 dynamic check (FREE — booted range, no Nebius/LLM). Drives the ONE engine's LIVE recon
path (build_agent_tools -> t_scan -> _recon) from a real foothold vantage (db-bastion) with the REAL
gate (resolve_ips=True, so gate.aliases carries every range host incl. the out-of-scope ones), across
two segments that each contain a KNOWN out-of-scope host (mgmt: jump-01 .13; database: decoy-fin .12).
Captures the recon-phase gate.block(s) AND the §E floor.boundary witness into one hash chain for cold
re-derivation. Asserts: an oos host is gate-blocked in the recon phase on the _recon path and never
appears in a discovery (never probed); §E enforced (host gateway unreachable)."""
import os, sys, json
sys.path.insert(0, os.getcwd())
from swarm.topo_to_compose import generate_unified, unified_facts, scope_by_actor
from swarm.gate import Gate
from swarm.eventlog import EventLog
from swarm import live_red, uninstrumented

OUT = os.path.dirname(os.path.abspath(__file__))
chain = os.path.join(OUT, "check_chain.jsonl")
if os.path.exists(chain):
    os.remove(chain)
log = EventLog(chain)

topo, gt = generate_unified(1337)
facts = unified_facts(topo, gt)
sba = scope_by_actor(topo, facts)
log.append("system", "config", {"check": "high1-dynamic", "range": "unified", "seed": 1337,
                                "use_llm": False, "note": "free recon-only mediation witness"})
log.append("system", "roe", {"scope_by_actor": sba})

gate = Gate([], log, resolve_ips=True, scope_by_actor=sba)
# sanity: the gate KNOWS the oos hosts (aliases from resolve_ips) and denies them to red
OOS = {"jump-01": "10.60.0.13", "decoy-fin": "10.40.0.12", "dc-01": "10.50.0.11"}
for name, ip in OOS.items():
    assert ip in gate.aliases, ("oos ip not in gate aliases", name, ip)
    assert gate.allows(ip, "red") is False, ("gate must DENY oos host to red", name, ip)

tools, st = live_red.build_agent_tools(
    log, gate, attacker_container="range-attacker", foothold_container="range-web01",
    entry_net="10.90.0.0/24", scan_ports=(22, 8080))

# Mark db-bastion an OWNED foothold so t_scan will scan ITS segments (mgmt + database) via _recon.
st["entry"] = "10.90.0.11"            # web01 (entry), so db-bastion is a non-entry owned vantage
st["owned"].add("10.60.0.11")         # db-bastion (mgmt iface) — canon -> db-bastion
res = tools["scan"](**{"from": "10.60.0.11"})   # drives _recon over db-bastion's mgmt + database nets
print("scan result hosts:", res)

evs = log.entries()
blocks = [(e["data"].get("resolved") or e["data"].get("target"), e["data"].get("mv_kind"))
          for e in evs if e.get("action") == "gate.block"]
disc_hosts = set()
for e in evs:
    if e.get("action") == "discovery":
        disc_hosts.add(e["data"].get("host")); disc_hosts.add(e["data"].get("scanned_ip"))
print("recon gate.block (host, mv_kind):", blocks)

# §E witness into the same chain (probe from the entry container, uninstrumented kernel probe)
boundary = {"entry": "web01", "in_scope": facts.get("in_scope"),
            "out_of_scope": facts.get("gate_out_of_scope")}
boundary["uninstrumented_live"] = uninstrumented.probe_boundary(
    "range-web01", list(OOS.values()), ["10.35.0.11", "10.90.0.12"], host_gateway="172.18.0.1")
log.append("system", "floor.boundary", boundary)
ul = boundary["uninstrumented_live"]
print("§E uninstrumented_live:", json.dumps({k: ul.get(k) for k in
      ("ok", "internet_blocked", "oos_tcp_reaches", "host_gateway_reachable")}))

# ---- assertions (the empirical close) ----
blocked_names = {h for h, mv in blocks if mv == "recon"}
assert "jump-01" in blocked_names or "decoy-fin" in blocked_names, ("no recon gate.block for an oos host", blocks)
for ip in ("10.60.0.13", "10.40.0.12"):          # oos ips must NEVER be probed (no discovery)
    assert ip not in disc_hosts, ("oos ip was probed/discovered — NOT excluded", ip, disc_hosts)
assert ul.get("ok") is True and ul.get("host_gateway_reachable") is False, ("§E not enforced", ul)
assert ul.get("oos_tcp_reaches") == [], ("oos tcp reached under §E", ul)
print("\nPASS (dynamic): recon gate.block on the _recon path for", sorted(blocked_names),
      "(oos, never probed); §E witnessed (host gateway unreachable, oos_tcp_reaches=[]).")
