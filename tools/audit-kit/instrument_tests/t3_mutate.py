"""Stdlib mutation harness (mutmut not used: see report). For a target file, enumerate single-point
AST mutants inside chosen functions/assignments, write each mutant over the file (original backed up),
run the repo's five checks, compare rc + normalized output to the baseline, restore. Always restores
in `finally` and verifies the sha256 at the end."""
import ast, copy, hashlib, json, re, shutil, subprocess, sys, difflib
from pathlib import Path

REPO = Path(sys.argv[1]); TARGET = sys.argv[2]; OUTJ = Path(sys.argv[3])
FUNCS = set(sys.argv[4].split(","))     # function names (qualified leaf) to mutate in
ASSIGNS = set(sys.argv[5].split(",")) if len(sys.argv) > 5 and sys.argv[5] else set()
PY = str(REPO / ".venv/bin/python")
CHECKS = [["scripts/redteam_gate.py"], ["scripts/prove_falsification.py", "--selftest"], ["swarm/gate.py"],
          ["redteam/reverify_floor.py", "docs/runs/2026-10-29-phase-b-claim2/seed1337/episode01_seed1337.jsonl"],
          ["scripts/prove_engine.py", "--selftest"]]


def norm(s):
    s = re.sub(r"[0-9a-f]{16,}", "<HEX>", s)
    s = re.sub(r"/tmp/\S+", "<TMP>", s)
    s = re.sub(r"\d+\.\d+s\b", "<T>s", s)
    return s


def run_checks():
    res = []
    for c in CHECKS:
        try:
            p = subprocess.run([PY] + c, cwd=REPO, capture_output=True, text=True, timeout=180)
            res.append((p.returncode, norm(p.stdout + p.stderr)))
        except subprocess.TimeoutExpired:
            res.append((-9, "TIMEOUT"))
    return res


path = REPO / TARGET
orig = path.read_text()
orig_sha = hashlib.sha256(orig.encode()).hexdigest()
tree0 = ast.parse(orig)


def in_scope_nodes(tree):
    """Yield (owner_name, node) for nodes inside the target functions or target module assignments."""
    for top in ast.walk(tree):
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)) and top.name in FUNCS:
            for n in ast.walk(top):
                yield top.name, n
        if isinstance(top, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ASSIGNS for t in top.targets):
            for n in ast.walk(top):
                yield "assign:" + top.targets[0].id, n


CMP_SWAP = {ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
            ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.Lt: ast.GtE, ast.GtE: ast.Lt,
            ast.Gt: ast.LtE, ast.LtE: ast.Gt}


def gen_mutants():
    """Return list of (desc, transform) where transform(tree)->None mutates the k-th matching node."""
    specs = []
    nodes = list(in_scope_nodes(tree0))
    for idx, (owner, n) in enumerate(nodes):
        ln = getattr(n, "lineno", "?")
        if isinstance(n, ast.Compare):
            for j, op in enumerate(n.ops):
                if type(op) in CMP_SWAP:
                    specs.append((f"{owner}:L{ln} compare {type(op).__name__}->{CMP_SWAP[type(op)].__name__}",
                                  idx, ("cmp", j)))
        if isinstance(n, ast.BoolOp):
            specs.append((f"{owner}:L{ln} boolop {type(n.op).__name__} flipped", idx, ("bool",)))
            for j in range(len(n.values)):
                specs.append((f"{owner}:L{ln} boolop drop operand {j}", idx, ("dropop", j)))
        if isinstance(n, (ast.If, ast.While)) or isinstance(n, ast.IfExp):
            specs.append((f"{owner}:L{ln} {type(n).__name__} condition negated", idx, ("neg",)))
        if isinstance(n, ast.comprehension) and n.ifs:
            specs.append((f"{owner}:L{ln} comprehension filter removed", idx, ("compif",)))
        if isinstance(n, ast.Return) and n.value is not None:
            specs.append((f"{owner}:L{ln} return -> None", idx, ("retnone",)))
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            specs.append((f"{owner}:L{ln} 'not' removed", idx, ("unnot",)))
        if isinstance(n, (ast.Set, ast.Tuple, ast.List)) and owner.startswith("assign:") and len(n.elts) > 1:
            specs.append((f"{owner}:L{ln} collection emptied", idx, ("empty",)))
            for j in range(len(n.elts)):
                specs.append((f"{owner}:L{ln} collection element {j} removed", idx, ("dropel", j)))
        for field in ("body", "orelse"):
            stmts = getattr(n, field, None)
            if isinstance(stmts, list) and stmts and isinstance(stmts[0], ast.stmt) and not isinstance(n, ast.Module):
                for j, st in enumerate(stmts):
                    if isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant):
                        continue  # docstring
                    specs.append((f"{owner}:L{getattr(st,'lineno','?')} statement deleted ({type(st).__name__})",
                                  idx, ("del", field, j)))
    return specs


def apply(spec):
    desc, idx, op = spec
    t = copy.deepcopy(tree0)
    n = list(in_scope_nodes(t))[idx][1]
    k = op[0]
    if k == "cmp":
        n.ops[op[1]] = CMP_SWAP[type(n.ops[op[1]])]()
    elif k == "bool":
        n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
    elif k == "dropop":
        del n.values[op[1]]
        if len(n.values) == 1:
            pass
    elif k == "neg":
        n.test = ast.UnaryOp(op=ast.Not(), operand=n.test)
    elif k == "compif":
        n.ifs = []
    elif k == "retnone":
        n.value = ast.Constant(None)
    elif k == "unnot":
        # replace UnaryOp(Not, x) with x: find parent
        for p in ast.walk(t):
            for f, v in ast.iter_fields(p):
                if v is n:
                    setattr(p, f, n.operand)
                elif isinstance(v, list):
                    for i, x in enumerate(v):
                        if x is n:
                            v[i] = n.operand
    elif k == "empty":
        n.elts = []
        if isinstance(n, ast.Set):  # empty set literal is invalid; use set()
            for p in ast.walk(t):
                for f, v in ast.iter_fields(p):
                    if v is n:
                        setattr(p, f, ast.Call(func=ast.Name("set", ast.Load()), args=[], keywords=[]))
    elif k == "dropel":
        del n.elts[op[1]]
    elif k == "del":
        body = getattr(n, op[1])
        body[op[2]] = ast.Pass()
    ast.fix_missing_locations(t)
    return ast.unparse(t)


base_unparse = ast.unparse(tree0)
results = {"target": TARGET, "orig_sha": orig_sha, "mutants": []}
try:
    baseline = run_checks()
    # sanity: the identity-unparsed file must reproduce the baseline (else formatting noise)
    path.write_text(base_unparse)
    ident = run_checks()
    results["identity_matches_baseline"] = [a[0] == b[0] and a[1] == b[1] for a, b in zip(baseline, ident)]
    seen_src = set()
    specs = gen_mutants()
    for spec in specs:
        try:
            src = apply(spec)
            compile(src, TARGET, "exec")
        except Exception as e:
            continue
        if src in seen_src or src == base_unparse:
            continue
        seen_src.add(src)
        path.write_text(src)
        r = run_checks()
        rc_fail = [i for i, (a, b) in enumerate(zip(ident, r)) if a[0] != b[0]]
        out_diff = [i for i, (a, b) in enumerate(zip(ident, r)) if a[1] != b[1] and i not in rc_fail]
        diff = "".join(difflib.unified_diff(base_unparse.splitlines(1), src.splitlines(1), n=0))
        diff = "\n".join(l for l in diff.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))
        results["mutants"].append({"desc": spec[0], "rc_fail_checks": rc_fail, "output_diff_checks": out_diff,
                                   "killed": bool(rc_fail or out_diff), "diff": diff[:600],
                                   "reverify_out": r[3][1][-300:] if 3 in out_diff else None})
        print(("KILLED " if rc_fail else "OUTDIFF" if out_diff else "SURVIVE"), spec[0], flush=True)
finally:
    path.write_text(orig)
    assert hashlib.sha256(path.read_text().encode()).hexdigest() == orig_sha, "RESTORE FAILED"
    results["restored_sha_ok"] = True
    OUTJ.write_text(json.dumps(results, indent=1))
m = results["mutants"]
print(f"{TARGET}: mutants={len(m)} killed_by_failure={sum(bool(x['rc_fail_checks']) for x in m)} "
      f"killed_by_output_change_only={sum(bool(x['output_diff_checks']) and not x['rc_fail_checks'] for x in m)} "
      f"survived={sum(not x['killed'] for x in m)} identity_ok={results['identity_matches_baseline']}")
