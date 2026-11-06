#!/usr/bin/env python3
"""Stage 1 — static mediation coverage (free, offline, mechanical).

Oracle = the Python `ast` module. It shares no code with gate.py; anyone who
re-runs this query on the repo gets the same sink list and the same flags. The
script asserts nothing about whether the gate is *correct* — only the SHAPE of
the code:

  (A) every effectful sink is inventoried and classified by TRANSPARENT RULES
      (literal argv of the call, else module location) — not a hand verdict;
  (B) every class-2 (deliberately ungoverned) path is import-isolated from the
      counted/live entrypoints the floor claim is made over;
  (C) class-1 (mediated) sinks are checked for dispatch-domination by a
      module-local call-graph pass seeded at every `gate.dispatch` tool_fn;
      survivors are reported as FINDINGS, never silently passed.

Taxonomy (docs/mediation/COVERAGE_SPEC.md — the committed definition):
  1 MEDIATED    actor action; must run inside a gate.dispatch tool_fn.
  2 UNGOVERNED  deliberate gate-off proof channel; must be ISOLATED.
  3 OBSERVER    read-only telemetry, reaches no target; out of scope.
  4 SCAFFOLDING range setup / harness orchestration, not an actor move.

CEILING (ponytail): domination is proved MODULE-LOCALLY (closures and their
intra-module callees reached from a dispatch seed). It does not resolve
cross-module bindings, so a sink dispatched only from another module shows as an
undominated FINDING to confirm by hand — honest over-reporting, not a false
clear. The kernel-reachability oracle (Stage 3) is what physically closes the
domination gap; this layer is the code-shape guard a reviewer re-runs.
"""
import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = ["swarm", "scripts", "redteam"]
SCAN_FILES = []           # run.py (the fabricated cheat-sheet engine) is deleted — no loose files to scan

# Counted/live entrypoints the floor claim is made over (brief). Class-2 paths
# must be unreachable (by import) from the import-closure of these modules.
# Re-pointed 2026-10-27 (Dante-approved reviewed change to this frozen instrument's DATA, not its
# oracle logic): the one-engine cut deletes all three prior entries (prove_n2n3_tiered,
# exp_a_control_eval, arms_race_enterprise_frontier), and isolation() only walks entries that
# exist — so leaving them would make the class-2 isolation check pass VACUOUSLY once they are gone.
# Re-point to the AGENT CLOSURES that must stay blind to the gate-off channel, mirroring leak_test's
# agent-scoped RED_ENTRYPOINTS so the two instruments agree. NOT scripts/live_arms_race_run.py: the
# harness deliberately imports the class-2 `uninstrumented` channel for the §E hard-floor probe
# (sanctioned class-4 MEASUREMENT, not an agent move), so counting it would be a false LEAK.
COUNTED_ENTRIES = [
    "swarm/live_agent.py",
    "swarm/live_red.py",
    "swarm/live_blue_agent.py",
]

# Pure class-2 module (the gate-off proof channel). Isolation target.
CLASS2_MODULE = "swarm/uninstrumented"

# Committed module-level overrides for the SWARM CORE package only (the in-duel
# code). Rule-based argv classification handles the rest; these pin the few
# modules whose role is not legible from a single call's argv.
MODULE_CLASS = {
    "swarm/uninstrumented": 2,      # deliberate gate-off channel
    "swarm/beacon": 3, "swarm/sensor_real": 3, "swarm/blue_detect": 3,
    "swarm/forensics": 3, "swarm/intel": 3,
    "swarm/topo_to_compose": 4, "swarm/netmodel": 4,   # range_gen merged into topo_to_compose (inc4)
    # battlefield/deception removed 2026-10-29 (audit LOW): those modules are deleted (deception is in
    # prove_one_engine's GONE list) — inert dead map entries, dropped so the coverage map tracks reality.
    "swarm/range_adversary": 4,
    # live_msf stands up red's OWN msfrpcd C2 container (docker run/network/inspect/rm) —
    # control-plane scaffolding for red's toolkit, NOT an actor move on a target. The actual
    # exploitation sink is gated_msf_exploit in swarm/msf.py (class-1, gate-dispatched); this
    # module never fires a module itself, so its stand-up docker calls are class-4.
    "swarm/live_msf": 4,
    # live_telemetry is the OBSERVER layer: it reads the world's OWN record (Falco syscalls,
    # conntrack flows, target container logs) into the hash-chained telemetry chain. Its
    # subprocess calls (docker run falco / docker logs / conntrack) capture ground truth; they
    # are neither an actor move nor the gate — class-3 observer, like sensor_real / beacon.
    "swarm/live_telemetry": 3,
}
# instrument.py mixes a governed arm (_governed_log, real gate) and the class-2
# ungoverned arm (_ungoverned_log/_allow). Classify by enclosing function.
FUNC_CLASS = {
    ("swarm/instrument", "_ungoverned_log"): 2,
    ("swarm/instrument", "_allow"): 2,
    ("swarm/instrument", "_governed_log"): 1,
    # blue_contain._exec_host runs host-affecting docker commands (the executor
    # behind containment); dynamic argv, so pin it — class-1, surfaces as F1.
    ("swarm/blue_contain", "_exec_host"): 1,
    # scripts/live_arms_race_run._standup_msfrpcd `docker run`s red's OWN msfrpcd C2 container —
    # attacker-toolkit stand-up (control-plane scaffolding), identical in role to swarm/live_msf
    # (MODULE_CLASS=4). It is not an actor move on a target; the exploitation sink is the
    # gate-dispatched gated_msf_exploit. Reviewer-checkable: same named-container stand-up pattern.
    ("scripts/live_arms_race_run", "_standup_msfrpcd"): 4,
    # gate.run_effect is THE single effect primitive (invariant #1, one effect path): the only
    # subprocess sink in the governed engine. Every agent effect reaches it via gate.dispatch
    # (scope-checked) and every TCB/observer effect via gate.lifecycle / a direct call; it is the
    # gate-owned chokepoint itself, so it is class-1 (mediated) and exempt from the call-site
    # dispatch-domination check below (it is the dispatched-TO primitive, not a caller).
    ("swarm/gate", "run_effect"): 1,
}
# The single effect primitive is the chokepoint, not an undominated call site — never flag it. The
# gate's OWN run_effect call sites are TCB-owned by construction: `lifecycle` is the TCB range
# lifecycle (docker compose up/down, logged under range.lifecycle), and `effect` performs run_effect
# strictly inside its own gate.dispatch tool_fn. Both are exempt from the agent-move domination check.
_EFFECT_PRIMITIVE = ("swarm/gate", "run_effect")
_TCB_EFFECT_SITES = {("swarm/gate", "run_effect"), ("swarm/gate", "lifecycle"),
                     ("swarm/gate", "effect")}

# Class-1 capability functions: the low-level effectful helpers whose every call
# site we check for dispatch-domination (resolves brief seed finding F1).
CAPABILITY_FUNCS = {"contain_host", "drop_honeytoken"}

EFFECTFUL = {
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("os", "system"), ("os", "popen"),
    ("socket", "socket"), ("socket", "create_connection"),
    (None, "urlopen"), ("request", "urlopen"),
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("requests", "request"), ("requests", "head"),
    # The engine's SINGLE effect primitive (gate.run_effect). Every agent/observer effect reaches
    # the real subprocess through it, so it is the sink the mediation check must SEE — tracking only
    # bare `subprocess.run` (which appears once, inside gate.run_effect itself) left every
    # run_effect CALL SITE invisible to this oracle (2026-10-29 audit HIGH-2). Both the bare-name
    # call (imported `from swarm.gate import run_effect`) and the `gate.run_effect` attribute form.
    (None, "run_effect"), ("gate", "run_effect"), ("self", "run_effect"),
}
EFFECTFUL_METHODS = {"connect", "urlopen"}
CLASS_NAME = {1: "MEDIATED", 2: "UNGOVERNED", 3: "OBSERVER", 4: "SCAFFOLDING",
              None: "UNCLASSIFIED"}

# docker subcommands that are range CONTROL (scaffolding), vs exec/run (a process
# ON a host = an actor move).
DOCKER_SCAFFOLD = {"compose", "build", "up", "down", "ps", "inspect", "network",
                   "pull", "cp", "rm", "stop", "start", "kill", "logs", "pause",
                   "unpause", "volume", "image", "version", "info", "wait"}
HARNESS_ARGV0 = {"make", "python", "python3", "sh", "bash", "git", "iptables",
                 "nft", "sysctl", "ip", "pytest", "pip"}


def _rel(path):
    return str(path.relative_to(ROOT)).replace(".py", "")


def _call_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        recv = f.value.id if isinstance(f.value, ast.Name) else (
            f.value.attr if isinstance(f.value, ast.Attribute) else None)
        return recv, f.attr
    if isinstance(f, ast.Name):
        return None, f.id
    return None, None


def _is_effectful(node):
    recv, attr = _call_name(node)
    if (recv, attr) in EFFECTFUL:
        return True
    if attr in EFFECTFUL_METHODS and recv is not None:
        return True
    return False


def _literal_argv(node):
    """If the first positional arg is a literal list of strings, return it."""
    if not node.args:
        return None
    a0 = node.args[0]
    if isinstance(a0, ast.List):
        out = []
        for e in a0.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                out.append(e.value)
            else:
                out.append(None)  # a variable element
        return out
    return None


class _Walker(ast.NodeVisitor):
    def __init__(self, mod):
        self.mod = mod
        self.func_stack = []
        self.sinks = []            # (line, enclosing_func, recv, attr, argv)
        self.callees = {}          # func name -> set of callee names
        self.dispatch_seeds = set()  # tool_fn names handed to gate.dispatch
        self.dispatch_funcs = set()  # funcs whose body calls X.dispatch(...)
        self.imports = set()
        self.cap_calls = []        # (line, enclosing_func, callee) for CAPABILITY_FUNCS
        self.wrapped_cap_lines = set()  # cap-call lines inside a lambda passed to
        #                                 a gating wrapper (func that dispatches)
        self._pending_wrapped = []  # (cap_line, outer_callee_name) to resolve

    def visit_Import(self, n):
        for a in n.names:
            self.imports.add(a.name)
        self.generic_visit(n)

    def visit_ImportFrom(self, n):
        base = n.module or ""
        for a in n.names:
            self.imports.add(f"{base}.{a.name}" if base else a.name)
            if base:
                self.imports.add(base)
        self.generic_visit(n)

    def _enter_func(self, n):
        self.func_stack.append(n.name)
        self.callees.setdefault(n.name, set())
        self.generic_visit(n)
        self.func_stack.pop()

    visit_FunctionDef = _enter_func
    visit_AsyncFunctionDef = _enter_func

    def visit_Call(self, n):
        recv, attr = _call_name(n)
        enc = self.func_stack[-1] if self.func_stack else "<module>"
        if attr:
            self.callees.setdefault(enc, set()).add(attr)
        if attr == "dispatch":
            self._record_dispatch(n)
            self.dispatch_funcs.add(enc)
        # A capability call inside a Lambda ARG of this call is governed iff the
        # callee is a gating wrapper (it dispatches). Record the cap line now;
        # resolve "callee is a gating wrapper" after the full pass.
        for arg in n.args:
            if isinstance(arg, ast.Lambda):
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Call):
                        _, a = _call_name(sub)
                        if a in CAPABILITY_FUNCS:
                            self._pending_wrapped.append((sub.lineno, attr))
        if attr in CAPABILITY_FUNCS:
            self.cap_calls.append((n.lineno, enc, attr))
        if _is_effectful(n):
            self.sinks.append((n.lineno, enc, recv, attr, _literal_argv(n)))
        self.generic_visit(n)

    def _record_dispatch(self, n):
        tool_fn = n.args[3] if len(n.args) >= 4 else None
        if isinstance(tool_fn, ast.Name):
            self.dispatch_seeds.add(tool_fn.id)
        elif isinstance(tool_fn, ast.Lambda):
            for sub in ast.walk(tool_fn):
                if isinstance(sub, ast.Call):
                    _, a = _call_name(sub)
                    if a:
                        self.dispatch_seeds.add(a)
        elif isinstance(tool_fn, ast.Attribute):
            self.dispatch_seeds.add(tool_fn.attr)


def _governed_funcs(w):
    """Module-local forward reachability from every dispatch seed over callees."""
    gov, stack = set(), list(w.dispatch_seeds)
    while stack:
        f = stack.pop()
        if f in gov:
            continue
        gov.add(f)
        stack.extend(w.callees.get(f, ()))
    return gov


def _dominated_funcs(w):
    """A function is MEDIATED only if EVERY caller path is dispatch-dominated (brief v3 A3): it is a
    dispatch seed, OR it has >=1 caller and ALL of its (module-local) callers are themselves
    dominated. A function with NO caller that is not a seed is reachable from module top / outside
    without a dispatch, so it is NOT dominated.

    This replaces 'reachable from ANY dispatch seed' (`_governed_funcs`) for the mediation check: a
    SHARED sink reached from one gated caller AND one ungated caller (e.g. live_recon._exec from the
    gated scan_host and an ungated sweep) used to clear the moment the gated path existed -- the bug
    that let static_coverage pass while G3 was open. Module-local only (the stated ceiling), so it
    over-reports a cross-module-dispatched sink; the import-aware t1b oracle, not this, is the A3
    authority. Reported as a finding, never silently cleared."""
    callers = {}
    for caller, callees in w.callees.items():
        for c in callees:
            callers.setdefault(c, set()).add(caller)
    dom = set(w.dispatch_seeds)
    changed = True
    while changed:
        changed = False
        for f in w.callees:
            if f in dom:
                continue
            cs = callers.get(f, set())
            if cs and all(c in dom for c in cs):
                dom.add(f)
                changed = True
    return dom


def _classify_sink(mod, func, recv, attr, argv):
    """Transparent rule-based class for one sink."""
    # Committed overrides first (swarm core role modules).
    if (mod, func) in FUNC_CLASS:
        return FUNC_CLASS[(mod, func)]
    if mod in MODULE_CLASS:
        return MODULE_CLASS[mod]
    # The single effect primitive: every CALL of run_effect is a mediated (class-1) effect, whatever
    # its argv (often a variable, which would otherwise fall through to UNCLASSIFIED). The call SITES
    # are then dispatch-domination-checked below; the primitive's own definition + the TCB-owned call
    # sites (gate.lifecycle / gate.effect) are exempted there.
    if attr == "run_effect":
        return 1
    # Literal-argv mechanical rules.
    if argv:
        a0 = argv[0]
        if a0 == "docker":
            sub = argv[1] if len(argv) > 1 else None
            if sub in ("exec", "run"):
                return 1                      # a process ON a host = actor move
            if sub in DOCKER_SCAFFOLD:
                return 4
            return 4                          # unknown docker verb: control plane
        if a0 in HARNESS_ARGV0:
            return 4                          # harness orchestration
    # urllib/requests/socket to a target.
    if attr in ("urlopen", "get", "post", "put", "request", "head",
                "create_connection", "socket", "connect"):
        # in the swarm core package it is a red/blue tool reaching a target
        if mod.startswith("swarm/"):
            return 1
        return 4                              # in a harness: fetching infra/health
    # Dynamic-argv subprocess in a harness script -> orchestration (scaffolding).
    if mod.startswith("scripts/") or mod == "run":
        return 4
    return None                               # swarm core, unknown -> must triage


def scan():
    files = []
    for d in SCAN_DIRS:
        files += sorted((ROOT / d).rglob("*.py"))
    files += [ROOT / f for f in SCAN_FILES]
    per_module = {}
    for path in files:
        if "__pycache__" in str(path) or "/.venv/" in str(path):
            continue
        # The mediation verifiers are the measurement instruments, not the
        # system under test (class-4 by taxonomy). Auditing the prober's own
        # --measure docker-exec as a mediation gap is a category error.
        if "scripts/mediation/" in str(path):
            continue
        mod = _rel(path)
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except Exception as e:
            per_module[mod] = {"error": str(e)}
            continue
        w = _Walker(mod)
        w.visit(tree)
        # Resolve: a cap-call inside a lambda passed to a gating wrapper (a func
        # that calls .dispatch, or dispatch itself) is governed.
        gating = w.dispatch_funcs | {"dispatch"}
        for line, outer in w._pending_wrapped:
            if outer in gating:
                w.wrapped_cap_lines.add(line)
        per_module[mod] = w
    return per_module


def analyze(per_module):
    inventory, undominated, unclassified = [], [], []
    for mod, w in per_module.items():
        if isinstance(w, dict):
            continue
        dom = _dominated_funcs(w)       # brief v3 A3: EVERY caller dominated, not reachable-from-one
        for line, func, recv, attr, argv in w.sinks:
            cls = _classify_sink(mod, func, recv, attr, argv)
            rec = {"module": mod, "line": line, "func": func, "class": cls,
                   "class_name": CLASS_NAME[cls],
                   "sink": (f"{recv}.{attr}" if recv else attr)
                   + ("[" + " ".join(x or "$" for x in argv[:2]) + "]" if argv else "()")}
            inventory.append(rec)
            if cls is None:
                unclassified.append(rec)
            elif cls == 1:
                if (mod, func) not in _TCB_EFFECT_SITES \
                        and func not in dom and func not in w.dispatch_seeds:
                    undominated.append(rec)
    return inventory, undominated, unclassified


def capability_edges(per_module):
    """Every call site of a CAPABILITY_FUNC, tagged GOVERNED (enclosing func is
    dispatch-reachable in its module) or DIRECT (ungoverned path — a finding)."""
    edges = []
    for mod, w in per_module.items():
        if isinstance(w, dict):
            continue
        gov = _governed_funcs(w)
        for line, func, callee in w.cap_calls:
            governed = (func in gov or func in w.dispatch_seeds
                        or line in w.wrapped_cap_lines)
            edges.append({"module": mod, "line": line, "caller": func,
                          "capability": callee,
                          "path": "GOVERNED" if governed else "DIRECT"})
    return edges


def isolation(per_module):
    name_to_mod = {}
    for mod in per_module:
        name_to_mod[mod.replace("/", ".")] = mod
        name_to_mod[mod.split("/")[-1]] = mod
    results = []
    for entry in COUNTED_ENTRIES:
        emod = entry.replace(".py", "")
        seen, stack, reaches = set(), [emod], False
        calls_ungoverned = False
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in per_module:
                continue
            seen.add(cur)
            w = per_module[cur]
            if isinstance(w, dict):
                continue
            for callees in w.callees.values():
                if "_ungoverned_log" in callees or "_allow" in callees:
                    calls_ungoverned = True
            for imp in w.imports:
                m = name_to_mod.get(imp) or name_to_mod.get(imp.replace(".", "/"))
                if m == CLASS2_MODULE:
                    reaches = True
                if m:
                    stack.append(m)
        results.append({"entry": entry, "reaches_uninstrumented": reaches,
                        "closure_calls_ungoverned_log": calls_ungoverned,
                        "isolated": not reaches and not calls_ungoverned,
                        "closure_size": len(seen)})
    return results


def build(per_module):
    inventory, undominated, unclassified = analyze(per_module)
    counts = {}
    for r in inventory:
        counts[r["class_name"]] = counts.get(r["class_name"], 0) + 1
    return {
        "total_sinks": len(inventory),
        "by_class": counts,
        "inventory": inventory,
        "unclassified": unclassified,
        "undominated_class1": undominated,
        "capability_edges": capability_edges(per_module),
        "isolation": isolation(per_module),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit raw oracle JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    out = build(scan())
    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    print(f"[ast oracle] {out['total_sinks']} effectful sinks")
    for k in ("MEDIATED", "UNGOVERNED", "OBSERVER", "SCAFFOLDING", "UNCLASSIFIED"):
        if k in out["by_class"]:
            print(f"    {k:12s} {out['by_class'][k]}")
    print("[isolation] class-2 (uninstrumented) vs counted entrypoints:")
    for r in out["isolation"]:
        tag = "ISOLATED" if r["isolated"] else "LEAK"
        print(f"    [{tag}] {r['entry']}  closure={r['closure_size']} "
              f"uninst={r['reaches_uninstrumented']} "
              f"ungoverned_call={r['closure_calls_ungoverned_log']}")
    direct = [e for e in out["capability_edges"] if e["path"] == "DIRECT"]
    print(f"[capability edges] {len(out['capability_edges'])} call site(s) to "
          f"{sorted(CAPABILITY_FUNCS)}; {len(direct)} DIRECT (ungoverned):")
    for e in out["capability_edges"]:
        print(f"    [{e['path']}] {e['module']}.{e['caller']}:{e['line']} "
              f"-> {e['capability']}")
    if out["undominated_class1"]:
        print(f"[findings] {len(out['undominated_class1'])} class-1 sink(s) not "
              f"module-locally dominated (confirm by hand):")
        for r in out["undominated_class1"]:
            print(f"    {r['module']}.{r['func']}:{r['line']} {r['sink']}")

    hard_fail = bool(out["unclassified"]) or any(
        not r["isolated"] for r in out["isolation"])
    if hard_fail:
        print("\nFAIL: unclassified swarm-core sink(s) or class-2 isolation leak.")
        return 1
    print(f"\nPASS (ast oracle): every sink classified; class-2 isolated from "
          f"counted paths. Findings recorded, not suppressed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
