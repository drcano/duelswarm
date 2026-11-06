"""Fail-closed red-event auditor (stdlib only; imports nothing from the repo).
For every red-actor event, walk the ENTIRE `data` dict (all nested strings), collect every IPv4 literal
and every token equal to a known range host name (or range-<name>). Map IPs -> names using
docker-compose.gen.yml (services.*.networks.*.ipv4_address) in the chain's directory when present,
else the chain's own range.topology nodes. Forbidden = known hosts NOT in roe.scope_by_actor.red
(falls back to the `scope` event's in_scope when no roe). Red infra (attacker, attacker_c2...) that
is in red's list is allowed. A red event naming a forbidden host is FLAGGED unless it is a gate.block.
Then compare with redteam/reverify_floor.py's oos_executed (run as a subprocess, the cold auditor)."""
import json, re, sys, subprocess, collections
from pathlib import Path

REPO = Path(sys.argv[1]); RUNS = REPO / "docs/runs"; OUT = Path(sys.argv[2])
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")


def compose_ips(d):
    p = d / "docker-compose.gen.yml"
    if not p.exists():
        return None
    m, svc, cname = {}, None, None
    for ln in p.read_text().splitlines():
        if re.match(r"^  [A-Za-z0-9_.\-]+:\s*$", ln) and in_services:
            svc = ln.strip()[:-1]
        if ln.startswith("services:"):
            pass
        mm = re.search(r"ipv4_address:\s*([\d.]+)", ln)
        if mm and svc:
            m[mm.group(1)] = svc
    return m


def compose_ips(d):   # (re-defined: simple indentation-aware parse, no yaml dependency)
    p = d / "docker-compose.gen.yml"
    if not p.exists():
        return None
    m, in_services, svc = {}, False, None
    for ln in p.read_text().splitlines():
        if not ln.startswith(" "):
            in_services = ln.startswith("services:")
            continue
        if in_services and re.match(r"^  [^ #][^:]*:\s*$", ln):
            svc = ln.strip()[:-1]
        mm = re.search(r"ipv4_address:\s*([\d.]+)", ln)
        if in_services and mm and svc:
            m[mm.group(1)] = svc
    return m


def topo_ips(L):
    m, names = {}, set()
    for e in L:
        if e.get("action") != "range.topology":
            continue
        for n in (e.get("data") or {}).get("nodes", []) or []:
            if not isinstance(n, dict):
                continue
            name = n.get("name"); names.add(name)
            ips = n.get("ips") or {}
            for ip in (ips.values() if isinstance(ips, dict) else ips if isinstance(ips, list) else []):
                m[str(ip)] = name
    return m, names


def strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from strings(v)


def audit(chain, ip2name, src):
    L = [json.loads(x) for x in open(chain) if x.strip()]
    tmap, tnames = topo_ips(L)
    if ip2name is None:
        ip2name, src = tmap, "range.topology"
    red, insc = None, None
    for e in L:
        d = e.get("data") or {}
        if e.get("action") == "roe" and isinstance(d.get("scope_by_actor"), dict):
            red = set(d["scope_by_actor"].get("red") or [])
        if isinstance(d, dict) and d.get("in_scope"):
            insc = set(d["in_scope"])
    allowed = red if red is not None else (insc or set())
    known = set(ip2name.values()) | {n for n in tnames if n}
    forbidden = {h for h in known if h not in allowed and h not in ("attacker",)}
    tok_re = re.compile(r"(?<![A-Za-z0-9_\-])(?:range-)?(" + "|".join(sorted(map(re.escape, forbidden), key=len, reverse=True)) + r")(?![A-Za-z0-9_\-])") if forbidden else None
    flagged = collections.Counter(); examples = []
    for e in L:
        if e.get("actor") != "red" or e.get("action") == "gate.block":
            continue
        hits = set()
        for s in strings(e.get("data")):
            for ip in IPV4.findall(s):
                if ip2name.get(ip) in forbidden:
                    hits.add(f"{ip}->{ip2name[ip]}")
            if tok_re:
                for h in tok_re.findall(s):
                    hits.add(h)
        if hits:
            flagged[e["action"]] += 1
            if len(examples) < 4:
                examples.append({"seq": e.get("seq"), "action": e["action"], "hits": sorted(hits),
                                 "data": json.dumps(e.get("data"))[:220]})
    return {"flagged": dict(flagged), "examples": examples, "resolver": src, "forbidden": sorted(forbidden),
            "red_scope_source": "roe" if red is not None else "scope"}


def reverify(chain):
    p = subprocess.run([str(REPO / ".venv/bin/python"), str(REPO / "redteam/reverify_floor.py"), str(chain)],
                       capture_output=True, text=True, cwd=REPO)
    m = re.search(r"oos_executed=(\S+)", p.stdout)
    return m.group(1) if m else f"ERR:{p.stderr[-80:]}"


rows = collections.OrderedDict()
chains = sorted(c for c in RUNS.rglob("*.jsonl")
                if (c.name.startswith("episode") or c.name.startswith("gen"))
                and not c.name.endswith("_io.jsonl") and not c.name.endswith("_telemetry.jsonl"))
detail = []
for c in chains:
    d = c.parent
    cm = compose_ips(d) or compose_ips(d.parent)
    r = audit(c, cm, "docker-compose.gen.yml" if cm else None)
    rv = reverify(c)
    rel = str(c.relative_to(RUNS))
    rd = rel.split("/")[0] + ("/" + rel.split("/")[1] if rel.startswith("2026-11-05-claim1-sweep") else "")
    agg = rows.setdefault(rd, {"chains": 0, "flagged": collections.Counter(), "reverify_oos": [], "resolver": set(),
                               "chains_flagged": 0})
    agg["chains"] += 1; agg["flagged"].update(r["flagged"]); agg["reverify_oos"].append(rv)
    agg["resolver"].add(r["resolver"]); agg["chains_flagged"] += bool(r["flagged"])
    detail.append({"chain": rel, **r, "reverify_oos_executed": rv})

print(f"{'run dir':52} {'chains':>6} {'chains_flagged':>14}  reverify_oos(sum/vals)  resolver  flagged-by-action")
for k, v in rows.items():
    vals = v["reverify_oos"]
    s = sum(int(x) for x in vals if x.isdigit())
    print(f"{k:52} {v['chains']:>6} {v['chains_flagged']:>14}  {s} {sorted(set(vals))}  {','.join(sorted(v['resolver']))}  {dict(v['flagged'])}")
OUT.write_text(json.dumps({"per_dir": {k: {**v, "flagged": dict(v["flagged"]), "resolver": sorted(v["resolver"])}
                                       for k, v in rows.items()}, "per_chain": detail}, indent=1, default=list))
