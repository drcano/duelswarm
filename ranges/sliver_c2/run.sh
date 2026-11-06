#!/usr/bin/env bash
# Stand up the Sliver C2 server on a range's red-infra (attacker) network. The entrypoint
# brings up the gRPC daemon, generates the operator config, and starts the HTTP C2 listener;
# implants generated inside this container beacon back to it. One shared C2 for v1 (the
# per-actor handle in swarm/beacon.py makes a later multi-APT split a config change).
#   usage: run.sh <docker-network> [c2-ip] [version]
set -euo pipefail
NET="${1:?usage: run.sh <docker-network> [c2-ip] [version]}"
IP="${2:-10.9.0.250}"
VER="${3:-v1.7.8}"
docker rm -f range-attacker_c2 >/dev/null 2>&1 || true
docker run -d --name range-attacker_c2 --hostname attacker_c2 \
  --network "$NET" --ip "$IP" "duelswarm-sliver-c2:${VER}"
echo "range-attacker_c2 up on $NET ($IP); wait for SLIVER_C2_READY in docker logs"
