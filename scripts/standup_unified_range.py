#!/usr/bin/env python3
"""B4 — stand up (and tear down) the seed-1337 UNIFIED range the pilot measures on.

`make range-up` boots the ROOT docker-compose.yml, which is the FIXED 6-host demo range
(range-struts/db/jenkins/mail/ldap/decoy) — NOT the least-privilege unified seam the one engine
attaches to (range-web01/dba01/db-bastion/db-core). This driver boots the RIGHT range:

  1) build the generic-host image (duelswarm/range-node:latest) from docker/range-node.Dockerfile
     if it is not already present (the real sshd/ssh-client base every NODE host + the crown runs);
  2) write_unified(seed) -> <outdir>/docker-compose.gen.yml + scope.yaml + ground_truth.json + the
     real-image loot mounts (the seam bootstrap cred on web01), with the A3 boot-witness svc_boot
     account/key/canary planted into the crown + crown-edge NODE hosts (B2, via topo_to_compose);
  3) stage the self-contained modern SSH client into ./sshstage for the DMZ foothold tool-drop;
  4) bring_up_generated_range(): tear down the fixed range (frees :8080), `docker compose up -d` the
     unified compose, install + VERIFY the §E host egress firewall (HALTS if the hard floor is open),
     and apply any DC provisioning (a no-op for this inert-infra Phase-1 range);
  5) assert the containers came up named range-attacker + range-<host> for every seam host — the exact
     names _unified_coords / live_telemetry key their introspection off (a name drift degrades the
     loop SILENTLY, so it is a hard standup check, not a warning).

The live loop (`live_arms_race_run.py --live-generations`) then ATTACHES by querying these running
containers; it does not read the compose. Nothing here spends tokens. `--down` reverses step 4.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarm.topo_to_compose import (write_unified, write_variant, stage_foothold_ssh_client,
                                   generate_unified, generate_variant, unified_facts,
                                   HELD_OUT_VARIANTS, HELD_OUT_SEEDS, RANGE_NODE_IMAGE)
from swarm.range_runtime import bring_up_generated_range, tear_down_generated_range

NODE_DOCKERFILE = ROOT / "docker" / "range-node.Dockerfile"
DEFAULT_OUTDIR = ROOT / "data" / "unified_range"


def _run(argv, timeout=600):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def ensure_node_image(image=RANGE_NODE_IMAGE):
    """Build the generic-host base image if it is not already present. No COPY in the Dockerfile, so
    the build context is irrelevant; the apk install needs host egress (available at standup)."""
    have = _run(["docker", "images", "-q", image]).stdout.strip()
    if have:
        print(f"[standup] image {image} already present ({have})")
        return True
    print(f"[standup] building {image} from {NODE_DOCKERFILE.name} (needs host egress for apk)…")
    r = _run(["docker", "build", "-f", str(NODE_DOCKERFILE), "-t", image, str(NODE_DOCKERFILE.parent)])
    if r.returncode != 0:
        print(f"[standup] FAILED to build {image}:\n{r.stderr[:800]}", file=sys.stderr)
        return False
    print(f"[standup] built {image}")
    return True


def _seam_hosts(seed, variant=None):
    """The seam hosts (chain) + entry + crown for the name-check, from the range's own ground truth.
    A held-out `variant` reconstructs via generate_variant(name) — the SAME (topo, gt) the one engine
    attaches to (and write_variant booted), so the live container name-check matches the variant seam."""
    topo, gt = generate_variant(variant) if variant else generate_unified(seed)
    facts = unified_facts(topo, gt)
    chain = list(((gt or {}).get("cred_seam") or {}).get("chain") or [])
    entry = (facts.get("entry_hosts") or [None])[0]
    crown = (gt.get("crown") or {}).get("data")
    return sorted(set([h for h in chain if h] + ([entry] if entry else []) + ([crown] if crown else [])))


def _running_containers():
    out = _run(["docker", "ps", "--format", "{{.Names}}"]).stdout
    return set(n.strip() for n in out.splitlines() if n.strip())


def _range_seed(seed, variant):
    """The docker project / §E-firewall key. A held-out variant uses its OWN dedicated seed
    (HELD_OUT_SEEDS) so its compose project name is distinct from the in-sample 1337 range and from
    the other variants — the claim-1 sweep boots ONE range at a time, but distinct keys keep a stale
    container or firewall from a prior range from bleeding into the next."""
    return HELD_OUT_SEEDS[variant] if variant else seed


def up(seed, outdir, variant=None):
    outdir = Path(outdir)
    if not ensure_node_image():
        return 1
    rseed = _range_seed(seed, variant)
    if variant:
        print(f"[standup] writing held-out variant range {variant!r} "
              f"({HELD_OUT_VARIANTS[variant][1]}) to {outdir}")
        write_variant(variant, outdir)                          # generalized N-hop cred-plant compose
    else:
        print(f"[standup] writing the unified range for seed {seed} to {outdir}")
        write_unified(seed, outdir)                             # compose + scope + gt + loot mounts
    staged = stage_foothold_ssh_client(outdir)                  # ./sshstage for the DMZ tool-drop
    print(f"[standup] ssh client staged: {staged}")
    compose = outdir / "docker-compose.gen.yml"
    # tears down the fixed range, boots the compose, installs + VERIFIES §E (halts if open), applies
    # DC provisioning (no-op here). Raises SystemExit(1) on a hard-floor break or compose fail.
    bring_up_generated_range(compose, rseed)
    # Hard name check: the loop keys off these exact container names; a drift degrades it silently.
    running = _running_containers()
    want = {"range-attacker"} | {f"range-{h}" for h in _seam_hosts(seed, variant)}
    missing = sorted(want - running)
    if missing:
        print(f"[standup] FAIL: expected containers not running: {missing}\n"
              f"          running range containers: {sorted(n for n in running if n.startswith('range-'))}",
              file=sys.stderr)
        return 1
    label = f"variant {variant}" if variant else f"unified range for seed {seed}"
    attach = (f"--live-generations N --mode dry --seeds {seed}"
              + (f" --variant {variant}" if variant else ""))
    print(f"[standup] OK — {label} up (project seed {rseed}); verified {sorted(want)} running, "
          f"§E closed. Attach with:  {Path(sys.executable).name} scripts/live_arms_race_run.py {attach}")
    return 0


def down(seed, outdir, variant=None):
    compose = Path(outdir) / "docker-compose.gen.yml"
    rseed = _range_seed(seed, variant)
    tear_down_generated_range(compose, rseed)
    label = f"variant {variant}" if variant else f"unified range for seed {seed}"
    print(f"[standup] {label} torn down (project seed {rseed}; §E firewall removed)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="stand up / tear down the unified seam range (B4)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--up", action="store_true", help="build image, write + boot the unified range, verify §E")
    g.add_argument("--down", action="store_true", help="tear down the unified range + remove §E firewall")
    ap.add_argument("--seed", type=int, default=1337, help="unified range seed (default 1337, the pilot seed)")
    ap.add_argument("--variant", choices=sorted(HELD_OUT_VARIANTS),
                    help="stand up a HELD-OUT variant range (claim-1 sweep: app_crown_4hop / "
                         "backup_route_5hop / mgmt_crown_3hop) instead of the in-sample unified seam. "
                         "Uses the variant's OWN dedicated seed for the compose project; attach the "
                         "driver with the matching --variant.")
    ap.add_argument("--out", default=str(DEFAULT_OUTDIR), help="compose/loot output dir")
    a = ap.parse_args()
    return up(a.seed, a.out, a.variant) if a.up else down(a.seed, a.out, a.variant)


if __name__ == "__main__":
    raise SystemExit(main())
