"""Consequence check for SURVIVING gate.py mutants: exec each mutant module in isolation and probe
scope decisions the floor depends on. DANGER = an out-of-scope target runs, or a block is not logged."""
import json, sys, subprocess
from pathlib import Path

REPO = Path(sys.argv[1]); RES = json.load(open(sys.argv[2])); OUT = Path(sys.argv[3])
sys.argv = [sys.argv[0], str(REPO), "swarm/gate.py", "/dev/null",
            "_canonicalize,_scope_for,allows,_is_real_target,check_egress,dispatch,_egress_targets,effect,lifecycle,__init__", ""]
src = Path(__file__).with_name("t3_mutate.py").read_text().split("base_unparse = ast.unparse(tree0)")[0]
ns = {"__name__": "gen"}; exec(src, ns)
by_desc = {}
for sp in ns["gen_mutants"]():
    try:
        s = ns["apply"](sp); compile(s, "m", "exec")
    except Exception:
        continue
    by_desc.setdefault(sp[0], s)


class Log:
    def __init__(s): s.ev = []
    def append(s, a, act, d=None): s.ev.append((a, act, d)); return {}


def probe(source):
    m = {"__name__": "gate_mut"}
    exec(compile(source, "gate_mut", "exec"), m)
    Gate, OOS = m["Gate"], m["OutOfScope"]
    out = {}

    def mk():
        lg = Log()
        g = Gate([], lg, scope_by_actor={"red": ["web01"], "blue": ["web01", "sensor"]},
                 known_hosts=["web01", "dc-01", "sensor"])
        g.aliases.update({"10.50.0.10": "web01", "10.50.0.11": "dc-01", "range-web01": "web01", "range-dc-01": "dc-01"})
        return g, lg

    def disp(target, command=None, verb=None, actor="red"):
        g, lg = mk(); ran = []
        try:
            g.dispatch(actor, "t", target, lambda: ran.append(1), command=command, verb=verb)
        except OOS:
            pass
        except Exception as e:
            return ("EXC", type(e).__name__)
        blocks = sum(1 for _, a, _ in lg.ev if a == "gate.block")
        return ("RAN" if ran else "blocked", blocks)
    cases = {
        "oos_name": disp("dc-01"), "oos_range_prefix": disp("range-dc-01"), "oos_ip": disp("10.50.0.11"),
        "oos_url": disp("http://10.50.0.11:22/"), "oos_ip_port": disp("10.50.0.11:22"),
        "blue_only_host_for_red": disp("sensor"),
        "egress_url": disp("web01", command="curl http://range-dc-01/x"),
        "egress_nc": disp("web01", command="nc dc-01 22"),
        "egress_ip": disp("web01", command="curl 10.50.0.11"),
        "crafted_6char_prefix": disp("XXXXXXweb01"),
    }
    g, lg = mk()
    try:
        cases["allows_oos_ip_red"] = g.allows("10.50.0.11", "red")
        cases["allows_blue_host_red"] = g.allows("sensor", "red")
    except Exception as e:
        cases["allows_oos_ip_red"] = ("EXC", type(e).__name__)
    return cases


orig = probe((REPO / "swarm/gate.py").read_text())
print("ORIGINAL", orig)
rows = []
for mres in RES["mutants"]:
    if mres["killed"]:
        continue
    s = by_desc.get(mres["desc"])
    if s is None:
        continue
    try:
        r = probe(s)
    except Exception as e:
        r = {"probe_error": repr(e)[:80]}
    why = []
    for k, v in r.items():
        if k.startswith("allows_"):
            if v is True and orig[k] is False:
                why.append(f"{k}: allows() says True for an out-of-scope host (drop_oos would keep it -> probed ungated)")
        elif isinstance(v, tuple) and v[0] == "RAN" and orig[k][0] == "blocked":
            why.append(f"{k}: OUT-OF-SCOPE CLOSURE RAN")
        elif isinstance(v, tuple) and v[0] == "blocked" and v[1] < orig[k][1]:
            why.append(f"{k}: blocked but gate.block NOT logged")
    rows.append({"desc": mres["desc"], "diff": mres["diff"][:300], "result": {k: str(v) for k, v in r.items()}, "danger": why})
    print(("DANGER " if why else "benign ") + mres["desc"] + ("  -> " + "; ".join(why) if why else ""))
OUT.write_text(json.dumps({"original": {k: str(v) for k, v in orig.items()}, "survivors": rows}, indent=1))
print(f"survivors={len(rows)} dangerous={sum(bool(r['danger']) for r in rows)}")
