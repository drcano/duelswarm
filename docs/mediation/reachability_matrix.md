# Stage 3 — Kernel-Truth Reachability Matrix

**Oracle:** the kernel, read from inside the containers — real `connect(2)` via
bash `/dev/tcp` (L4) and ICMP (L3). The checker
(`scripts/mediation/reachability_probe.py`) shares no code with `swarm/gate.py`
or the duel engine: it reads only the compose topology (claimed) and the live
`docker inspect` IPs + connect outcomes (measured).

```bash
python scripts/mediation/reachability_probe.py --selftest   # pure logic (make test)
python scripts/mediation/reachability_probe.py --claimed     # the promised matrix
# measured here (range booted on Docker Desktop):
python scripts/mediation/reachability_probe.py --measure --gateway 172.21.0.1 \
    --capture docs/mediation/connect_capture.json
```

## STATUS: MEASURED (inter-container, kernel-confirmed) · §E host-gateway open here (VM-moot)

The range was booted (`make range-up`) and probed from the kernel. **Measured ==
claimed exactly** — the network carries the floor. Raw capture (48 connects):
`docs/mediation/connect_capture.json`; measured matrix:
`docs/mediation/measured_matrix.json`.

What is kernel-confirmed here: **inter-container L3/L4 segmentation** — identical
on any host because it is Docker's `internal: true` network isolation. What stays
VM-caveated: the entry→docker-host-gateway (§E) reaches the *LinuxKit VM's* own
ingress bridge gateway, not Dante's mac; `host_egress_firewall --up/--verify`
must run on the native-Linux deploy host (its `--verify` SKIPs on Darwin by
design; rule logic passes `--selftest`).

## The decisive question — direct yes/no

> Are the three Stage-2 bypass IPs (all resolving to the decoy) kernel-unreachable
> from the compromised entry?

**YES.** The live range assigns `range_oos` = **172.22.0.0/16**, decoy =
**172.22.0.4** (Stage 2's encodings were corrected to this real IP — an earlier
`172.20.0.9` guess was wrong; 172.20/16 is the *in-scope* block). From the entry
(`range-struts`), the capture shows:

```
struts -> decoy  (172.22.0.4)   l4=None  l3=False  reached=False
struts -> mail   (172.22.0.3)   l4=None  l3=False  reached=False
struts -> ldap   (172.22.0.2)   l4=None  l3=False  reached=False
struts -> db     (172.20.0.2)   l4=5432  l3=True   reached=True
struts -> jenkins(172.20.0.3)   l4=8080  l3=True   reached=True
struts -> internet:1.1.1.1      l3=False           reached=False
struts -> internet:example.com  l3=False           reached=False
struts -> docker-host-gateway (172.21.0.1)  l4=22  l3=True  reached=True   ← §E
```

The decoy IP that the Stage-2 parser bypasses resolve to is **unreachable at both
L3 and L4** from the entry. **The network backstops the parser slips.** The
parser was never the guarantee; the segmentation is — and the kernel confirms it.

## Measured matrix (kernel) == Claimed matrix (topology)

| from \ to | struts | db | jenkins | mail | ldap | decoy | host-gw | internet |
|-----------|:------:|:--:|:-------:|:----:|:----:|:-----:|:-------:|:--------:|
| **struts**  | — | ✓ | ✓ | ✗ | ✗ | ✗ | ⚠︎§E | ✗ |
| **db**      | ✓ | — | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **jenkins** | ✓ | ✓ | — | ✗ | ✗ | ✗ | ⚠︎§E | ✗ |
| **mail**    | ✗ | ✗ | ✗ | — | ✓ | ✓ | ✗ | ✗ |
| **ldap**    | ✗ | ✗ | ✗ | ✓ | — | ✓ | ✗ | ✗ |
| **decoy**   | ✗ | ✗ | ✗ | ✓ | ✓ | — | ✗ | ✗ |

`diff(claimed, measured)` → **`violations: []`**. `floor_invariants` →
**`oos_tcp_reaches: []`, `internet_reaches: []`, `floor_holds: true`**. The
in-scope mesh {struts, db, jenkins} is reachable (floor playable); the OOS mesh
{mail, ldap, decoy} is reachable only internally; **no cross-reach, no
internet**.

## The network-versus-parser split, stated

- **The network carries the floor.** Measured ⊆ claimed, and specifically the
  decoy IP (target of all three Stage-2 parser bypasses) is kernel-unreachable
  from the entry. Assumption C (segmentation = claimed scope) is **confirmed by
  the kernel** for inter-container reachability.
- **The parser is defence-in-depth only.** Its 3 true bypasses + 21
  shell-expansion slips (Stage 2) never reach an effect, because the kernel does
  not route to the out-of-scope segment regardless of how the command is phrased.

## §E — the one open residual (recorded honestly, not retried away)

From the entry, the docker-host-gateway `172.21.0.1` is reachable at **L3 (ping)
and L4 (port 22 open)**. On this macOS box that gateway is the **LinuxKit VM's**
ingress bridge — the VM is the isolation boundary, and the entry has **no onward
internet egress** (both internet probes `reached=False`), so it is *moot here*
per `host_egress_firewall`'s own platform note. On a **native-Linux deploy host**
the same reach would be to the real host, which is the §E gap that
`host_egress_firewall --up` closes and `--verify` confirms. That verify must run
there:

```
host_egress_firewall --selftest  → OK (rule logic, any OS)
host_egress_firewall --verify    → SKIP: needs the native-Linux deploy host (Darwin here)
```

So §E is: **inter-container floor kernel-CONFIRMED; host-gateway isolation
CLOSEABLE and VM-moot here, pending a native-Linux `--up`/`--verify`.**

## Correlation (connect ↔ gate.allow)

`correlate(capture, log)` requires every real outbound connect to ride a
`gate.allow` or carry `raw_path=True` (the labeled class-2 channel). The capture
here is the **active measurement probes** (direct `docker exec`, so
`raw_path=True` by construction) — correlation returns 0 unexplained, exercising
the checker on real input. The fuller correlation — a **passive syscall trace of
a gated live duel** (`strace -f -e connect` / eBPF) joined to that duel's
`data/events.jsonl` — needs `strace`/eBPF on the Linux deploy host (not present
on the mac host). The checker logic is self-tested on fixtures and ready for that
capture.

## Pure-logic selftest (verbatim)

```
reachability_probe selftest ok (claimed matrix from compose; diff/floor/correlate
logic verified on fixtures; live measurer UNRUN on this LinuxKit VM — run
--measure on the Linux deploy host)
```

(The selftest string still says "UNRUN" for the *pure-logic* path that needs no
Docker; the live `--measure` above DID run against the booted range and produced
the matrix and capture in this directory.)
