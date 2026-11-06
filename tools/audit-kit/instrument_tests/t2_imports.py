"""AST import walk: every import (top-level or inside functions), every sys.path manipulation,
every importlib/__import__/runpy/exec use. Reports which files reach swarm/ or scripts/."""
import ast, sys
from pathlib import Path

ROOT = Path(sys.argv[1])


def scan(p):
    tree = ast.parse(p.read_text())
    hits = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                hits.append((n.lineno, "import", a.name))
        elif isinstance(n, ast.ImportFrom):
            hits.append((n.lineno, "from", (n.module or "") + " import " + ",".join(a.name for a in n.names)))
        elif isinstance(n, ast.Call):
            src = ast.unparse(n.func)
            if src in ("importlib.import_module", "__import__", "importlib.util.spec_from_file_location",
                       "runpy.run_path", "runpy.run_module", "exec", "subprocess.run", "subprocess.check_output",
                       "os.system") or src.endswith("sys.path.insert") or src.endswith("sys.path.append"):
                hits.append((n.lineno, "dyn", ast.unparse(n)[:140]))
    return hits


def bad(h):
    kind, what = h[1], h[2]
    if kind in ("import", "from"):
        mod = what.split(" import ")[0]
        return mod.split(".")[0] in ("swarm", "scripts", "redteam") or what.startswith(" import")
    return ("swarm" in what or "scripts" in what or "python" in what.lower())


groups = {
    "redteam/*.py (must import nothing from swarm/ or scripts/)": sorted((ROOT / "redteam").glob("*.py")),
    "scripts/verify_chain.py (must import nothing from swarm/)": [ROOT / "scripts/verify_chain.py"],
    "docs/runs/*/prove_*.py": sorted((ROOT / "docs/runs").rglob("prove_*.py")),
}
for g, files in groups.items():
    print(f"=== {g}")
    for p in files:
        hs = scan(p)
        rel = p.relative_to(ROOT)
        sp = [h for h in hs if h[1] == "dyn" and "sys.path" in h[2]]
        viol = [h for h in hs if bad(h)]
        tag = "VIOLATION/REACHES" if any(h[1] in ("import", "from") and h[2].split(".")[0].split(" ")[0] in ("swarm", "scripts", "redteam") for h in viol) or any(h[1]=="dyn" and ("swarm" in h[2] or "scripts" in h[2]) for h in viol) else "clean"
        print(f"  {rel}: {tag}")
        for h in hs:
            if bad(h) or h[1] == "dyn":
                print(f"     {rel}:{h[0]} [{h[1]}] {h[2]}")
