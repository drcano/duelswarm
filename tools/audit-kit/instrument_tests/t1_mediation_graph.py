"""Independent static mediation check (stdlib ast). Enumerates effect sinks in swarm/ and scripts/,
builds a per-module function call graph (nested defs keyed by qualified name), seeds governed
functions from every `.dispatch(...)` tool_fn argument (Name / Lambda body calls / nested def), and
classifies each sink by whether its enclosing function is reachable only from governed seeds.
Cross-module edges are resolved by bare function name (over-approximation, noted in output)."""
import ast, json, sys
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
SINK_ATTRS = {("subprocess", a) for a in ("run", "Popen", "call", "check_output", "check_call")} | {
    ("os", "system"), ("os", "popen"), ("socket", "socket"), ("socket", "create_connection"),
    ("request", "urlopen"), ("urllib", "urlopen"), ("http", "HTTPConnection"), ("client", "HTTPConnection"),
    ("client", "HTTPSConnection"), ("requests", "get"), ("requests", "post"), ("requests", "request")}
SINK_NAMES = {"run_effect", "urlopen", "HTTPConnection"}
WRAPPERS = {"_exec", "_docker_sh", "_sh", "_ssh", "_run", "scan_many", "scan_port", "scan_host",
            "fast_web_sweep", "scan_subnet", "own_ips", "own_subnets", "run_command",
            "fingerprint_service", "exploit_weblogic", "exploit_apache_cgi", "enumerate_and_harvest"}
AGENT_MODS = {"swarm/live_red", "swarm/live_recon", "swarm/live_pivot", "swarm/live_lateral",
              "swarm/live_fingerprint", "swarm/live_postex", "swarm/live_msf", "swarm/msf",
              "swarm/authoring", "swarm/live_agent"}


def cname(n):
    f = n.func
    if isinstance(f, ast.Attribute):
        v = f.value
        recv = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else None)
        return recv, f.attr
    if isinstance(f, ast.Name):
        return None, f.id
    return None, None


class W(ast.NodeVisitor):
    def __init__(s, mod):
        s.mod, s.stack, s.sinks, s.edges, s.seeds, s.lambdas = mod, [], [], {}, set(), 0

    def cur(s):
        return ".".join(s.stack) or "<module>"

    def _f(s, n):
        s.stack.append(n.name); s.edges.setdefault(s.cur(), set()); s.generic_visit(n); s.stack.pop()
    visit_FunctionDef = visit_AsyncFunctionDef = _f

    def visit_Lambda(s, n):
        s.lambdas += 1
        s.stack.append(f"<lambda@{n.lineno}>"); s.edges.setdefault(s.cur(), set())
        s.generic_visit(n); s.stack.pop()

    def visit_Call(s, n):
        recv, attr = cname(n)
        enc = s.cur()
        if attr:
            s.edges.setdefault(enc, set()).add(attr)
            # a function passed as an argument (callback) is also an edge
        for a in list(n.args) + [k.value for k in n.keywords]:
            if isinstance(a, ast.Name):
                s.edges.setdefault(enc, set()).add(a.id)
        if attr == "dispatch" and len(n.args) >= 4:
            tf = n.args[3]
            if isinstance(tf, ast.Name):
                s.seeds.add(tf.id)
            elif isinstance(tf, ast.Lambda):
                s.seeds.add(f"<lambda@{tf.lineno}>")
            elif isinstance(tf, ast.Attribute):
                s.seeds.add(tf.attr)
        kind = None
        if (recv, attr) in SINK_ATTRS or attr in SINK_NAMES and recv in (None, "gate", "self", "_gate"):
            kind = f"{recv+'.' if recv else ''}{attr}"
        if kind:
            argv0 = None
            if n.args and isinstance(n.args[0], ast.List) and n.args[0].elts:
                e = n.args[0].elts
                argv0 = " ".join(x.value if isinstance(x, ast.Constant) else "$" for x in e[:2])
            s.sinks.append({"line": n.lineno, "func": enc, "sink": kind, "argv": argv0})
        s.generic_visit(n)


def main():
    mods = {}
    for d in ("swarm", "scripts"):
        for p in sorted((ROOT / d).rglob("*.py")):
            if "__pycache__" in str(p):
                continue
            m = str(p.relative_to(ROOT))[:-3]
            w = W(m); w.visit(ast.parse(p.read_text())); mods[m] = w
    # global graph keyed by (mod, qualname); leaf name -> nodes for name resolution
    by_leaf = {}
    for m, w in mods.items():
        for q in w.edges:
            by_leaf.setdefault(q.split(".")[-1], set()).add((m, q))
    callers = {}
    for m, w in mods.items():
        for q, cs in w.edges.items():
            for c in cs:
                for tgt in by_leaf.get(c, ()):
                    callers.setdefault(tgt, set()).add((m, q))
    seeds = set()
    for m, w in mods.items():
        for s in w.seeds:
            for q in w.edges:
                if q.split(".")[-1] == s or q.endswith("." + s) or q == s:
                    seeds.add((m, q))

    def governed(node, depth=0, seen=None):
        """(a) node itself or a lexical ancestor is a dispatch seed; (b) every caller is governed (<=3)."""
        seen = seen or set()
        m, q = node
        parts = q.split(".")
        for i in range(len(parts), 0, -1):
            if (m, ".".join(parts[:i])) in seeds:
                return "a" if i == len(parts) else "a(enclosing)"
        if depth >= 3 or node in seen:
            return None
        seen = seen | {node}
        cs = callers.get(node, set())
        if not cs:
            return None
        res = [governed(c, depth + 1, seen) for c in cs]
        return "b" if all(res) else None

    rows = []
    for m, w in mods.items():
        for s in w.sinks:
            node = (m, s["func"])
            g = governed(node)
            ungov_callers = sorted(f"{cm}:{cq}" for cm, cq in callers.get(node, ())
                                   if not governed((cm, cq)))
            rows.append({**s, "module": m, "governed": g, "agent_mod": m in AGENT_MODS,
                         "ungoverned_callers": ungov_callers[:12]})
    OUT.write_text(json.dumps(rows, indent=1))
    for r in rows:
        if r["agent_mod"]:
            print(f"{r['module']}:{r['line']} {r['func']} {r['sink']}[{r['argv']}] governed={r['governed']}")
            for c in r["ungoverned_callers"]:
                print("      ungoverned caller:", c)
    print(f"total sinks swarm+scripts: {len(rows)}; agent-module sinks: {sum(r['agent_mod'] for r in rows)}")


main()
