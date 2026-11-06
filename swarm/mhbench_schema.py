"""duelswarm's stable handle on the MHBench NetworkTopology IR (M0).

The schema itself is VENDORED under `third_party/mhbench/` (MIT © 2025 Brian
Singer — see `third_party/mhbench/LICENSE` and `LICENSES/MHBench-MIT.txt`); only
the `src.*` -> `mhbench.*` import prefixes were changed. This module adds
`third_party/` to the path and re-exports the public schema so the rest of
duelswarm imports one name (`swarm.mhbench_schema`) instead of reaching into the
vendored tree.

Why adopt it: MHBench environments carry MANY goals (one JSONDataExfiltrationGoal
per goal-host) each gated by its own attack_path (the intended LM/PE chain), plus
credential-pivot (`User.ssh_keys`, MisconfiguredSSHKeys) and privilege-escalation
(SudoBaron, WriteablePasswd) vuln classes — exactly the multi-flag terrain + red
frontier the audits found missing. M1 emits a topology to our Docker substrate;
M2/M3/M5 build on the richer IR. The OpenStack/Terraform/Ansible deployers were
deliberately NOT vendored (substrate-locked).

    from swarm.mhbench_schema import load_topology, iter_fixtures
    topo = load_topology("tests/fixtures/mhbench/generated_mini.json")
    topo.goals            # [JSONDataExfiltrationGoal, ...]  — the flags
    topo.attack_paths     # [AttackPath, ...]                — the ground-truth chains
"""
import sys
import json
import glob
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_VENDOR = _REPO / "third_party"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

from mhbench.models import (                                    # noqa: E402
    NetworkTopology, Network, Subnet, Host, User, SubnetConnection,
    Goal, JSONDataExfiltrationGoal, GoalUnion,
    Vulnerability, MergeStrategy,
    AttackPath, LateralMovementStep, PrivilegeEscalationStep,
    AttackGraph, AttackGraphNode, AttackGraphEdge,
    OSType, FlavorType, VulnerabilityType, GoalType, ProtocolType,
)
from mhbench.models.attack_graph import validate_attack_graph   # noqa: E402
from mhbench.models.vulnerabilities import (                    # noqa: E402
    MisconfiguredSSHKeysVulnerability, SudoBaronVulnerability,
    WriteablePasswdVulnerability, ApacheStrutsVulnerability,
)

FIXTURES_DIR = _REPO / "tests" / "fixtures" / "mhbench"

__all__ = [
    "NetworkTopology", "Network", "Subnet", "Host", "User", "SubnetConnection",
    "Goal", "JSONDataExfiltrationGoal", "GoalUnion", "Vulnerability", "MergeStrategy",
    "AttackPath", "LateralMovementStep", "PrivilegeEscalationStep",
    "AttackGraph", "AttackGraphNode", "AttackGraphEdge",
    "OSType", "FlavorType", "VulnerabilityType", "GoalType", "ProtocolType",
    "MisconfiguredSSHKeysVulnerability", "SudoBaronVulnerability",
    "WriteablePasswdVulnerability", "ApacheStrutsVulnerability",
    "validate_attack_graph", "load_topology", "iter_fixtures", "FIXTURES_DIR",
]


def load_topology(path):
    """Parse + validate a NetworkTopology JSON. The model's own validators run on
    load (attack-path continuity + subnet-connectivity), so a malformed env raises."""
    return NetworkTopology.model_validate(json.loads(Path(path).read_text()))


def iter_fixtures():
    """Every vendored MHBench env fixture, sorted by name."""
    return sorted(glob.glob(str(FIXTURES_DIR / "*.json")))


if __name__ == "__main__":  # self-check (M0 §3): all fixtures validate, >=1 goal, connected graph
    fixtures = iter_fixtures()
    assert fixtures, f"no MHBench fixtures under {FIXTURES_DIR}"
    assert len(fixtures) >= 30, f"expected >=30 vendored envs, found {len(fixtures)}"
    total_goals = 0
    for fp in fixtures:
        t = load_topology(fp)                       # raises on continuity/connectivity failure
        name = Path(fp).name
        assert t.goals, f"{name}: a NetworkTopology must carry >=1 goal (the flags)"
        # every goal is a real data-exfil flag with a concrete loot destination
        for g in t.goals:
            assert isinstance(g, JSONDataExfiltrationGoal), (name, type(g).__name__)
            assert g.dst_path and g.host_user, (name, "goal lacks dst_path/host_user")
        # the attack graph is connected and every goal node exists in it (MHBench's own check)
        assert t.attack_graph is not None, f"{name}: no attack_graph"
        validate_attack_graph(t.attack_graph, t.goals)
        # one ground-truth attack_path per goal, each continuous (model_validator already ran)
        assert t.attack_paths, f"{name}: no attack_paths (the ground-truth chains)"
        for p in t.attack_paths:
            assert p.validate_path_continuity(), f"{name}: discontinuous attack_path {p.id}"
        total_goals += len(t.goals)
    print(f"mhbench_schema ok ({len(fixtures)} envs validate; {total_goals} goals total, "
          f"each a JSONDataExfiltrationGoal with a loot dst_path; attack_graphs connected; "
          f"one continuous ground-truth attack_path per goal) — vendored MIT (c) 2025 Brian Singer")
