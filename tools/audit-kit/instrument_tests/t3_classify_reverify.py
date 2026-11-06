"""Classify surviving reverify_floor mutants by consequence: rebuild each mutant source (same generator),
exec it in an isolated namespace, and run it on crafted chains:
  C1 honest chain with ONE out-of-scope gate.allow (dc-01)        -> correct: oos_executed=1
  C2 same but target given as the dc-01 IP from range.topology    -> correct: 1
  C3 tampered chain (data edited after hashing)                    -> correct: chain_verified False
  C4 OOS 'exfiltrate' event (non-gate.allow EXEC action)           -> correct: 1
  C5 per-actor roe grant: blue allowed dc-01, red not; red allow   -> correct: 1
A survivor is DANGEROUS if it returns oos_executed 0/None on C1/C2/C4/C5 or chain_verified True on C3."""
import json, hashlib, sys, tempfile, os, ast, copy
from pathlib import Path

REPO = Path(sys.argv[1]); RES = json.load(open(sys.argv[2])); OUT = Path(sys.argv[3])
sys.argv = [sys.argv[0], str(REPO), "redteam/reverify_floor.py", "/dev/null",
            "canon,_ip2name,getscope,reverify,_destrip,_hash", "EXEC"]
# reuse the generator from t3_mutate without running its main loop
src = Path(__file__).with_name("t3_mutate.py").read_text().split("base_unparse = ast.unparse(tree0)")[0]
ns = {"__name__": "gen"}; exec(src, ns)
specs = ns["gen_mutants"](); apply = ns["apply"]
by_desc = {}
for sp in specs:
    try:
        s = apply(sp); compile(s, "m", "exec")
    except Exception:
        continue
    by_desc.setdefault(sp[0], s)

G = "0" * 64


def chain(events, tamper=False):
    prev, out = G, []
    for i, (actor, action, data) in enumerate(events):
        rec = {"seq": i, "ts": 0, "actor": actor, "action": action, "data": data, "prev": prev}
        h = hashlib.sha256((prev + json.dumps(rec, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()
        rec["hash"] = h; out.append(rec); prev = h
    if tamper:
        out[2]["data"]["target"] = "web01-edited"
    f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
    for r in out:
        f.write(json.dumps(r) + "\n")
    f.close(); return f.name


topo = ("system", "range.topology", {"nodes": [{"name": "web01", "ips": {"n": "10.50.0.10"}},
                                               {"name": "dc-01", "ips": {"n": "10.50.0.11"}}]})
scope = ("system", "scope", {"in_scope": ["web01"]})
C = {
    "C1_oos_allow": chain([scope, topo, ("red", "gate.allow", {"tool": "x", "target": "web01"}),
                           ("red", "gate.allow", {"tool": "x", "target": "dc-01"})]),
    "C2_oos_allow_by_ip": chain([scope, topo, ("red", "gate.allow", {"tool": "x", "target": "web01"}),
                                 ("red", "gate.allow", {"tool": "x", "target": "10.50.0.11"})]),
    "C3_tampered": chain([scope, topo, ("red", "gate.allow", {"tool": "x", "target": "web01"})], tamper=True),
    "C4_oos_exfil": chain([scope, topo, ("red", "gate.allow", {"tool": "x", "target": "web01"}),
                           ("red", "exfiltrate", {"target": "dc-01"})]),
    "C5_roe_other_actor": chain([scope, topo, ("system", "roe", {"scope_by_actor": {"blue": ["web01", "dc-01"], "red": ["web01"]}}),
                                 ("red", "gate.allow", {"tool": "x", "target": "dc-01"})]),
}


def run(source):
    ns = {"__name__": "m"}
    exec(compile(source, "m", "exec"), ns)
    r = {}
    for k, p in C.items():
        try:
            o = ns["reverify"](p)
            r[k] = (o.get("chain_verified"), o.get("oos_executed")) if isinstance(o, dict) else ("ret", repr(o)[:30])
        except Exception as e:
            r[k] = ("EXC", type(e).__name__)
    return r


orig = run((REPO / "redteam/reverify_floor.py").read_text())
print("ORIGINAL:", orig)


def dangerous(r):
    why = []
    for k in ("C1_oos_allow", "C2_oos_allow_by_ip", "C4_oos_exfil", "C5_roe_other_actor"):
        v = r[k]
        if v[0] != "EXC" and v[1] in (0, None) and orig[k][1] == 1:
            why.append(f"{k}: misses OOS ({v})")
    if r["C3_tampered"][0] is True:
        why.append("C3: tampered chain reported verified")
    return why


rows = []
for m in RES["mutants"]:
    if m["killed"]:
        continue
    s = by_desc.get(m["desc"])
    if s is None:
        rows.append({"desc": m["desc"], "status": "not-rebuilt"}); continue
    r = run(s)
    w = dangerous(r)
    rows.append({"desc": m["desc"], "diff": m["diff"][:300], "result": {k: list(v) for k, v in r.items()},
                 "dangerous": w})
    print(("DANGER " if w else "benign ") + m["desc"] + ("  -> " + "; ".join(w) if w else ""))
OUT.write_text(json.dumps({"original": {k: list(v) for k, v in orig.items()}, "survivors": rows}, indent=1))
print(f"survivors={len(rows)} dangerous={sum(bool(r.get('dangerous')) for r in rows)}")
for p in C.values():
    os.unlink(p)
