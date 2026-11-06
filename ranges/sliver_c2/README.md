# Sliver C2 (duelswarm red infrastructure — Phase 2.5)

A real [Sliver](https://github.com/BishopFox/sliver) command-and-control server, run as a
container on red's infra network. A foothold installs a real Sliver implant that beacons to
this server; `swarm/beacon.py` queries it (`check_new_agents`) as the real confirmation signal,
and the implant's beacon session is red's earned post-exploitation channel (gate-mediated and
hash-chain-logged, like any action). This replaces the out-of-band docker-exec marker, which
remains the honest fallback when no C2 is present.

- `build.sh` — download the pinned Sliver binaries (gitignored) and build the image (offline after).
- `run.sh <net> [ip]` — stand the C2 up on a range's attacker network.
- `swarm/beacon.py` — the real callback (`sliver_handle`, `c2_new_agents`, `observe_beacon_sliver`,
  `implant_execute`); `make_collector(r, c2=...)` uses it when a C2 handle is given.
- `scripts/prove_sliver_c2.py --live` — the Phase 2.5 done-check against a running C2 + beacon.

The data-plane range networks stay `internal: true`; the C2 lives on red's own segment, so the
beacon channel is real on the wire yet never leaves the sandbox.
