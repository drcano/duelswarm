# Mediation verification — prove the attack surface is enclosed, don't sample it

The claim is a **universal**: every effectful action is mediated by the gate (an
action executes only if its real target is in the acting actor's authorized
set). No number of episodes establishes a universal, so these stages prove the
surface is *enclosed* rather than count executions against a planted trap. Each
stage names an **independent oracle** and reports its raw output.

| Stage | What it proves | Oracle | Checker | Report | Status |
|-------|----------------|--------|---------|--------|--------|
| 0 | The taxonomy (the definition) | — | — | `COVERAGE_SPEC.md` | done |
| 1 | Every class-1 sink dominated by dispatch; class-2 isolated from counted paths | Python `ast` | `scripts/mediation/static_coverage.py` | `coverage_report.md` | done; **F1 CLOSED**, F2 characterized |
| 2 | Parser slip surface + true bypasses | OS resolver (`inet_aton`/`getaddrinfo`) | `scripts/mediation/parser_fuzz.py` | `parser_slip_report.md` | done (3 true bypasses → real decoy 172.22.0.4, 0 FP) |
| 3 | Network carries the floor; every connect accounted for | kernel (`connect(2)`+ICMP) | `scripts/mediation/reachability_probe.py` | `reachability_matrix.md` | **MEASURED: measured==claimed, decoy unreachable from entry, no internet; §E host-gw VM-moot (native-Linux `--up`/`--verify` pending)** |
| 4 | The invariant + assumption ledger | — | — | `INVARIANT.md` | done; C kernel-confirmed |
| 5 | Gate-breaker adversary (optional, may spend) | syscall truth | — | — | **deferred (Stage 2 already did it, free; would spend)** |

Live artifacts (this run): `measured_matrix.json`, `connect_capture.json` (48
connects). Captured on Docker Desktop (LinuxKit VM) — inter-container
segmentation is real kernel truth; §E host-gateway isolation needs the
native-Linux deploy host.

Re-run everything free + offline:

```bash
make test        # includes stages 1,2,3-selftest (plus the whole existing suite)
python scripts/mediation/static_coverage.py
python scripts/mediation/parser_fuzz.py
python scripts/mediation/reachability_probe.py --claimed
```

The inter-container floor is kernel-confirmed (this run). The one remaining step
is the §E host-gateway isolation on a **native-Linux deploy host**:

```bash
sudo python scripts/host_egress_firewall.py --up      # install (Linux, range up)
sudo python scripts/host_egress_firewall.py --verify  # confirm §E closed (SKIPs on macOS)
```

Open items (recorded, scoped, not silently closed): **3 parser bypasses**
(dotless numeric encodings — kept as characterized incompleteness; gate.py is
frozen and the close is the network, not a smarter parser); **§E**
docker-host-gateway (VM-moot here, native-Linux `--up`/`--verify` pending).
**F1 is CLOSED** (blue containment now gated). See `INVARIANT.md` §residual.
