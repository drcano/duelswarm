"""t1b: red-reachable effects that do not pass through gate.dispatch (stdlib ast only, imports nothing
from the repo).

Question asked: starting from red's tool functions (every nested or top-level def named t_* in
swarm/live_red.py and swarm/live_agent.py), can a call path reach an effect sink without going
through gate.dispatch? A sink is subprocess / os.system / os.popen / socket / urlopen / HTTP
connection / run_effect.

How calls are resolved (import-aware, unlike t1, which resolves by bare name across all modules):
  - f(...)          -> a def named f in an enclosing scope of the same module, else a top-level def
                       f in the same module, else `from M import f` -> M.f. Unresolved names
                       (builtins, stdlib) are ignored.
  - alias.f(...)    -> M.f when `import M as alias` / `from pkg import M as alias`.
  - obj.f(...)      -> conservative: every def whose leaf name is f in ANY swarm/ module (object
                       types are not inferred). scripts/ is never reached this way: the engine
                       does not import harness scripts, so a harness function that happens to
                       share a name is not a red-reachable caller. That is the only narrowing
                       relative to t1.
  - a function or lambda passed as an argument is an edge (callbacks), EXCEPT the tool_fn argument
    of a .dispatch(actor, tool, target, tool_fn) call, which is governed by definition.
  - a nested def or lambda inside a reached function is treated as reached (it may be returned and
    called through a variable, e.g. a channel closure), unless it is the tool_fn of a dispatch.
  - anything defined in swarm/gate.py is the trusted boundary; traversal stops there.

What this cannot see: an effect inside a dispatched tool_fn that touches MORE destinations than the
one target the gate checked (e.g. a subnet sweep dispatched against the foothold). Static analysis
can't decide that; it needs the runtime destination check described in the A3 acceptance.

Output: every sink reached, with one shortest call path from a red tool root. Exit 1 if any
sink is reached (the acceptance condition for A3 is: zero).

Usage: python3 -I t1b_red_reachable_effects.py <repo_root> [out.json]
"""
import ast, json, sys
from collections import deque
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else None
SINK_ATTRS = {("subprocess", a) for a in ("run", "Popen", "call", "check_output", "check_call")} | {
    ("os", "system"), ("os", "popen"), ("socket", "socket"), ("socket", "create_connection"),
    ("request", "urlopen"), ("urllib", "urlopen"), ("http", "HTTPConnection"), ("client", "HTTPConnection"),
    ("client", "HTTPSConnection"), ("requests", "get"), ("requests", "post"), ("requests", "request")}
SINK_NAMES = {"run_effect", "urlopen", "HTTPConnection", "create_connection"}
ROOT_MODS = {"swarm/live_red", "swarm/live_agent"}
TCB = {"swarm/gate"}


def modname(p):
    return str(p.relative_to(ROOT))[:-3]


def dotted_to_mod(d):
    return d.replace(".", "/")


class Mod(ast.NodeVisitor):
    def __init__(s, m):
        s.m, s.stack, s.defs, s.calls, s.sinks = m, [], set(), {}, {}
        s.mod_alias, s.name_import, s.governed = {}, {}, set()

    def cur(s):
        return ".".join(s.stack) or "<module>"

    def visit_Import(s, n):
        for a in n.names:
            s.mod_alias[a.asname or a.name.split(".")[-1]] = dotted_to_mod(a.name)

    def visit_ImportFrom(s, n):
        base = n.module or ""
        for a in n.names:
            full = f"{base}.{a.name}" if base else a.name
            # `from swarm import live_recon` binds a module; `from swarm.x import f` binds a name.
            s.mod_alias[a.asname or a.name] = dotted_to_mod(full)
            s.name_import[a.asname or a.name] = (dotted_to_mod(base), a.name)

    def _def(s, n):
        s.stack.append(n.name); q = s.cur(); s.defs.add(q); s.calls.setdefault(q, [])
        s.generic_visit(n); s.stack.pop()
    visit_FunctionDef = visit_AsyncFunctionDef = _def

    def visit_Lambda(s, n):
        enc = s.cur()
        s.stack.append(f"<lambda@{n.lineno}>"); q = s.cur(); s.defs.add(q); s.calls.setdefault(q, [])
        s.generic_visit(n); s.stack.pop()
        if not getattr(n, "_governed", False):
            s.calls.setdefault(enc, []).append(("lambda", None, q))

    def visit_Call(s, n):
        enc = s.cur()
        f = n.func
        recv = attr = None
        if isinstance(f, ast.Attribute):
            v = f.value
            recv = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else "?")
            attr = f.attr
        elif isinstance(f, ast.Name):
            attr = f.id
        is_dispatch = attr == "dispatch"
        governed_arg = n.args[3] if is_dispatch and len(n.args) >= 4 else None
        if governed_arg is not None and isinstance(governed_arg, ast.Lambda):
            governed_arg._governed = True
            s.governed.add(f"{enc + '.' if enc != '<module>' else ''}<lambda@{governed_arg.lineno}>")
        elif isinstance(governed_arg, ast.Name):
            s.governed.add(f"{enc + '.' if enc != '<module>' else ''}{governed_arg.id}")
        if attr:
            if (recv, attr) in SINK_ATTRS or (attr in SINK_NAMES and recv in (None, "self", "_gate", "gate")):
                s.sinks.setdefault(enc, []).append((n.lineno, f"{recv + '.' if recv else ''}{attr}"))
            if not is_dispatch:
                s.calls.setdefault(enc, []).append(("call", recv, attr))
            else:
                s.calls.setdefault(enc, []).append(("dispatch", recv, attr))
        for a in list(n.args) + [k.value for k in n.keywords]:
            if a is governed_arg:
                continue
            if isinstance(a, ast.Name):
                s.calls.setdefault(enc, []).append(("call", None, a.id))
            elif isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name):
                s.calls.setdefault(enc, []).append(("call", a.value.id, a.attr))
        s.generic_visit(n)


def main():
    mods = {}
    for d in ("swarm", "scripts"):
        for p in sorted((ROOT / d).rglob("*.py")):
            if "__pycache__" in str(p):
                continue
            w = Mod(modname(p)); w.visit(ast.parse(p.read_text())); mods[w.m] = w
    swarm_by_leaf = {}
    for m, w in mods.items():
        if m.startswith("swarm/"):
            for q in w.defs:
                swarm_by_leaf.setdefault(q.split(".")[-1], set()).add((m, q))

    def resolve(m, enc, recv, name):
        w = mods[m]
        if recv is None:
            parts = enc.split(".") if enc != "<module>" else []
            for i in range(len(parts), -1, -1):
                q = ".".join(parts[:i] + [name])
                if q in w.defs:
                    return {(m, q)}
            if name in w.name_import:
                tm, tn = w.name_import[name]
                if tm in mods and tn in mods[tm].defs:
                    return {(tm, tn)}
            return set()
        if recv in w.mod_alias and w.mod_alias[recv] in mods:
            tm = w.mod_alias[recv]
            return {(tm, name)} if name in mods[tm].defs else set()
        return set(swarm_by_leaf.get(name, ()))

    roots = [(m, q) for m in ROOT_MODS if m in mods for q in mods[m].defs if q.split(".")[-1].startswith("t_")]
    prev = {r: None for r in roots}
    dq = deque(roots)
    while dq:
        node = dq.popleft()
        m, q = node
        if m in TCB:
            continue
        # Conservative closure rule: a nested def (or lambda) inside a reached function may be
        # returned and called later through a variable (e.g. _docker_sh returns _sh), which the
        # call graph can't see. So every nested def of a reached function counts as reached.
        for d in mods[m].defs:
            if (d.startswith(q + ".") and d.count(".") == q.count(".") + 1 and (m, d) not in prev
                    and d not in mods[m].governed):
                prev[(m, d)] = node
                dq.append((m, d))
        for kind, recv, name in mods[m].calls.get(q, []):
            if kind == "dispatch":
                continue
            targets = {(m, name)} if kind == "lambda" else resolve(m, q, recv, name)
            for t in targets:
                if t not in prev and t[0] in mods:
                    prev[t] = node
                    dq.append(t)

    rows = []
    for node in prev:
        m, q = node
        if m in TCB:
            continue
        for line, sink in mods[m].sinks.get(q, []):
            path, cur = [], node
            while cur is not None:
                path.append(f"{cur[0]}:{cur[1]}"); cur = prev[cur]
            rows.append({"module": m, "func": q, "line": line, "sink": sink, "path": path[::-1]})
    rows.sort(key=lambda r: (r["module"], r["line"]))
    for r in rows:
        print(f"{r['module']}:{r['line']} {r['func']} -> {r['sink']}")
        print("      path: " + "  ->  ".join(r["path"]))
    print(f"roots: {len(roots)}; reachable functions: {len(prev)}; ungated red-reachable sinks: {len(rows)}")
    if OUT:
        OUT.write_text(json.dumps(rows, indent=1))
    sys.exit(1 if rows else 0)


main()
