"""leak_test — the objective-blindness rail for the validation rig.

The external validators audit the range's ground truth from OUTSIDE; their output must NEVER be an
input to red (the no-hardcoding / objective-blind rule applied to the validation layer). This proves
it by STATIC IMPORT CLOSURE, the same kind of check static_coverage uses for the class-2 channel:

  1. Red's import closure (live_agent / live_red / the frontier driver) imports NOTHING under
     scripts/validation — validator code and its findings can't reach red's prompt/belief/memory
     because red's process never loads them.
  2. No validation module imports red's agent (live_agent / live_red) or its move/prompt builders —
     so a validator can't push data into red from its side either.
  3. No validation module imports swarm.gate — the rig is AUDITOR-ONLY, touching no live effect site.

Static closure is the strong, deterministic proof (no run, no flakiness). Run as `--selftest`
(wired into make test).
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# Red's live path — the entrypoints whose closure must stay blind to the validators.
RED_ENTRYPOINTS = [
    "swarm/live_agent.py",
    "swarm/live_red.py",
]
# Forbidden in any validation module's imports (would let a validator feed red / touch effects).
RED_SINKS = {"swarm.live_agent", "swarm.live_red"}
EFFECT_SINKS = {"swarm.gate"}

# The ORACLE rail (Task 2, Unit 1). The oracle optimal-path reference (scripts/validation/oracle_red.py)
# is HANDED the ground-truth chain — a red told the answer looks expert because it was told the answer —
# so its knowledge must never reach the MEASURED red. This set names the oracle module(s); the ORACLE
# checks below are NAMED, specific versions of the general rails (O1 the measured red never imports the
# oracle, O2 the oracle never imports the measured red, O3 the runtime isolation guard exists), so the
# "same leak_test boundary" the planner required is ENFORCED for the oracle, not merely attested.
ORACLE_MODULES = {"scripts/validation/oracle_red.py"}
ORACLE_RUNTIME_GUARD = "assert_measured_red_oracle_free"


def _module_to_path(mod):
    """Map a local dotted module (swarm.x, scripts.y, scripts.validation.z) to a file, or None."""
    parts = mod.split(".")
    if parts[0] not in ("swarm", "scripts"):
        return None
    p = ROOT / Path(*parts).with_suffix(".py")
    if p.exists():
        return p
    pkg = ROOT / Path(*parts) / "__init__.py"
    return pkg if pkg.exists() else None


def _imports(path):
    """Dotted module names imported by `path` (import X / from X import ...), local ones kept."""
    try:
        tree = ast.parse(Path(path).read_text())
    except (OSError, SyntaxError):
        return set()
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:                       # relative import -> resolve against package
                base = ".".join(Path(path).relative_to(ROOT).with_suffix("").parts[:-node.level])
                mod = f"{base}.{node.module}" if node.module else base
            else:
                mod = node.module or ""
            if mod:
                mods.add(mod)
    return mods


def import_closure(entry_rel_paths):
    """Transitive closure of LOCAL (swarm./scripts.) imports from the entry files. Returns
    {dotted_module: file_path}."""
    seen = {}
    stack = []
    for rel in entry_rel_paths:
        p = ROOT / rel
        if p.exists():
            stack.append(p)
    while stack:
        path = stack.pop()
        for mod in _imports(path):
            mp = _module_to_path(mod)
            if mp and mod not in seen:
                seen[mod] = mp
                stack.append(mp)
    return seen


def validation_modules():
    return sorted(str(p.relative_to(ROOT)) for p in (ROOT / "scripts" / "validation").glob("*.py"))


def check():
    """Returns (ok, findings). findings is [] when the rail holds."""
    findings = []

    # (1) red's closure must not reach scripts/validation.
    red_closure = import_closure(RED_ENTRYPOINTS)
    leaked = {m: str(p.relative_to(ROOT)) for m, p in red_closure.items()
              if "scripts/validation" in str(p).replace("\\", "/") or m.startswith("scripts.validation")}
    if leaked:
        findings.append(f"red path imports validator module(s): {leaked}")

    # (2)+(3) no validation module imports red's agent or the gate.
    for vmod_path in (ROOT / "scripts" / "validation").glob("*.py"):
        imps = _imports(vmod_path)
        bad_red = {m for m in imps if m in RED_SINKS or m.startswith("swarm.live_agent")
                   or m.startswith("swarm.live_red")}
        bad_eff = {m for m in imps if m in EFFECT_SINKS or m.startswith("swarm.gate")}
        if bad_red:
            findings.append(f"{vmod_path.name} imports red agent: {sorted(bad_red)}")
        if bad_eff:
            findings.append(f"{vmod_path.name} imports a live effect site: {sorted(bad_eff)}")

    # ── ORACLE rail (named, specific — the planner's mechanical requirement for Unit 1) ──
    red_closure_paths = {str(p.relative_to(ROOT)).replace("\\", "/") for p in red_closure.values()}
    for orel in sorted(ORACLE_MODULES):
        op = ROOT / orel
        # (O1) the MEASURED red's import closure must never reach the oracle reference.
        if orel in red_closure_paths:
            findings.append(f"ORACLE LEAK (O1): measured red path imports the oracle reference {orel}")
        if not op.exists():
            continue
        # (O2) the oracle must not import the measured red's move/prompt builders.
        oimps = _imports(op)
        bad = {m for m in oimps if m in RED_SINKS or m.startswith("swarm.live_agent")
               or m.startswith("swarm.live_red")}
        if bad:
            findings.append(f"ORACLE LEAK (O2): oracle {orel} imports the measured red: {sorted(bad)}")
        # (O3) the oracle must define the runtime isolation guard the driver calls before the measured
        #      red runs (its biting is proven in the selftest). A static presence check here.
        if ORACLE_RUNTIME_GUARD not in op.read_text():
            findings.append(f"ORACLE LEAK (O3): oracle {orel} defines no runtime guard "
                            f"{ORACLE_RUNTIME_GUARD!r}")

    return (not findings), findings


def _selftest():
    global RED_ENTRYPOINTS
    ok, findings = check()
    # Sanity: the closure walker actually traversed red's path (non-trivial), so a pass means
    # something, not an empty walk.
    red_closure = import_closure(RED_ENTRYPOINTS)
    assert len(red_closure) >= 3, f"red closure too small ({len(red_closure)}) — walker likely broken"
    assert validation_modules(), "no validation modules found to check"
    assert ok, f"LEAK: validator output can reach red / rig touches effects: {findings}"

    # POSITIVE CONTROL: prove check() actually FIRES on a leak (the guard is load-bearing for
    # Phase 1). Plant a fake red entrypoint that imports a validator, point check() at it, and
    # assert it reports the leak — then restore. Without this, a silently-broken walker would
    # "pass" vacuously.
    import os
    probe_rel = "swarm/_leak_positive_control.py"
    probe_abs = ROOT / probe_rel
    saved = RED_ENTRYPOINTS
    try:
        probe_abs.write_text("from scripts.validation import detection_eval  # planted leak\n")
        RED_ENTRYPOINTS = [probe_rel]
        ok_leak, findings_leak = check()
        assert not ok_leak and any("validator" in f for f in findings_leak), \
            f"positive control FAILED: a planted leak was not caught ({findings_leak})"
    finally:
        RED_ENTRYPOINTS = saved
        if probe_abs.exists():
            os.remove(probe_abs)
    assert import_closure([]) == {}, "empty entry set must yield empty closure"

    # ── ORACLE positive controls: prove the ORACLE rail actually FIRES (not a vacuous pass) ──
    global ORACLE_MODULES
    import os
    # (O1) a planted red entrypoint that imports the oracle reference must be caught by O1.
    o1_rel = "swarm/_oracle_o1_control.py"
    o1_abs = ROOT / o1_rel
    saved_red = RED_ENTRYPOINTS
    try:
        o1_abs.write_text("import scripts.validation.oracle_red  # planted oracle->red leak\n")
        RED_ENTRYPOINTS = [o1_rel]
        ok_o1, f_o1 = check()
        assert not ok_o1 and any("O1" in f for f in f_o1), ("O1 positive control failed", f_o1)
    finally:
        RED_ENTRYPOINTS = saved_red
        if o1_abs.exists():
            os.remove(o1_abs)
    # (O2)+(O3) a planted oracle module that imports the measured red AND defines no guard must be
    #           caught by O2 and O3. Planted OUTSIDE scripts/validation so only the ORACLE rail fires.
    o2_rel = "swarm/_oracle_o2_control.py"
    o2_abs = ROOT / o2_rel
    saved_oracle = set(ORACLE_MODULES)
    try:
        o2_abs.write_text("import swarm.live_red  # planted oracle importing the measured red\n")
        ORACLE_MODULES = {o2_rel}
        ok_o2, f_o2 = check()
        assert not ok_o2 and any("O2" in f for f in f_o2), ("O2 positive control failed", f_o2)
        assert any("O3" in f for f in f_o2), ("O3 positive control failed (guard-presence)", f_o2)
    finally:
        ORACLE_MODULES = saved_oracle
        if o2_abs.exists():
            os.remove(o2_abs)
    # (O3 runtime) the oracle's runtime isolation guard exists and BITES on an oracle-as-measured-red.
    sys.path.insert(0, str(ROOT))
    import scripts.validation.oracle_red as oracle_red

    class _FakeOracle:
        is_oracle = True
    _bit = False
    try:
        oracle_red.assert_measured_red_oracle_free(red_router=_FakeOracle())
    except RuntimeError:
        _bit = True
    assert _bit, "O3 runtime guard did not bite on an oracle handed to the measured red"

    print(f"validation/leak_test: OK — red closure {len(red_closure)} modules, "
          f"{len(validation_modules())} validators (oracle rail O1/O2/O3 bites), "
          f"none cross the boundary")


if __name__ == "__main__":
    ok, findings = (None, None)
    if "--check" in sys.argv:
        ok, findings = check()
        print("LEAK-FREE" if ok else "LEAK:")
        for f in findings or []:
            print("  -", f)
        sys.exit(0 if ok else 1)
    _selftest()
