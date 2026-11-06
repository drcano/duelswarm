# Design log — the two-floor safety architecture (2026-10-25)

Confirmed at source this session (`gate.py`, `uninstrumented.py`, `audit.py`, `range_gen.to_compose`).
Records a safety principle Dante stated and we verified: duelswarm has **two floors**, and they play
opposite roles. Conflating them is the mistake this entry exists to prevent.

## What is actually built (re-derived at source)

**Floor 1 — the gate policy (the EXPERIMENTAL floor). `swarm/gate.py`.**
A reference monitor in Python. Every red action routes through `Gate.dispatch`, which checks the target
against that actor's authorized scope (per-actor, and per-verb on a read-vs-mutate axis), parses any
free-form `command=` for egress targets and default-denies anything out of scope however phrased, logs
`gate.allow` / `gate.block`, and only then runs the tool. It is a **static action-boundary check** in
the execution path. This is the authorization boundary whose holding-or-breaking is the thing we study.

**Floor 2 — the segmentation floor (the HARD / SAFETY floor). `swarm/range_gen.to_compose`.**
Kernel/Docker network isolation. Every data-plane segment (`range_attacker/dmz/internal/data/oos`) is a
Docker bridge with `internal: true` + a real IPAM CIDR, so **no container egresses to the host or the
internet**. Out-of-scope hosts live on an isolated `range_oos` net (topologically unreachable from the
in-scope segments). The only externally reachable path is a DNAT-only `ingress` bridge with
`enable_ip_masquerade: false` — inbound reachability to the published entry, never an egress route out.
`to_compose`'s own asserts enforce all of this (every data-plane net internal with a real CIDR; ingress
DNAT-only; attacker box on its subnet only with no published port; traps on an internal segment, never
`range_oos`). This is containment at the kernel layer, and `gate.py` itself names it "the complete
backstop that holds even against a target obfuscated past [the egress] parser."

**The falsifier. `swarm/uninstrumented.py`.** Exists only to prove Floor 2 holds *without* Floor 1: it
opens a raw `docker exec` shell on the compromised foothold — no gate, no logging, the attacker's real
point of view — and measures whether any out-of-scope host is TCP-reachable (must be `[]`), whether the
open internet is reachable (must be blocked), and whether in-scope pivots still work (must be `>0`, so
the duel stays playable). "The segmentation at the Docker/Linux bridge layer, not red's cooperation, is
what keeps `oos_missed == 0`."

**Two independent auditors. `swarm/audit.py` + `redteam/reverify_floor.py`.** Recompute `oos_executed`
from the finished hash-chained log, with separate canonicalization and a byte-identical `EXEC_ACTIONS`
drift guard, so the number is derived twice independently and never asserted.

## The principle (the decision)

- **The hard floor (segmentation) is SAFETY. It is never the experiment.** It protects the container and
  the real deploy host. It must always hold. If it ever breaks, that is not an interesting result — it is
  a containment failure that halts the run and is fixed before anything else.
- **The experimental floor (gate policy) is the OBJECT OF STUDY.** It lives inside the range. We may draw
  it at a tier line, let the adversary push on it, and watch how the adversary's behavior adapts.
  `oos_executed` is a measured result, never a target; an experimental-floor break is a result to capture
  and study, not a failure.
- **Why the split is what makes "a floor break is a result we want" SAFE:** letting the experimental floor
  break is acceptable *only because* the hard segmentation floor guarantees nothing escapes the range
  regardless. The two layers together are what let us run a real, breakable test with no real-world risk.
  The only thing that is always a build failure is an **unrecorded effect** — an effect that reached a
  target without being gate-mediated and logged.

## Confirmed gap + the hardening decision

`uninstrumented.py`'s own probe records a known gap: the published entry is attached to the non-internal
DNAT `ingress` bridge, so it can reach that bridge's gateway — the Docker host — at L3. Masquerade-off
blocks internet egress but not reaching the gateway IP, and compose cannot drop host-gateway traffic:
"L3 reach to Docker-host gateway OPEN — needs a host-side egress firewall; not closable in compose."

This was acceptable when the host was disposable. It is not now: the deploy host is Dante's real Linux
machine (a native-Linux deploy host), and we are about to run real offensive tooling (Impacket, NetExec,
Kerberoast), real C2 (Sliver), and a real Samba AD tier inside the range. So the hard floor gets hardened
(Phase 0a of the master brief): a **host-side egress firewall** dropping range-bridge → host/beyond, plus
a **tightened container-runtime posture** (`cap_drop: ALL` + only needed caps, `no-new-privileges`,
read-only rootfs where feasible, resource limits), with **Falco's required privilege/eBPF carved out as a
documented exception** (Falco runs as its own privileged sensor, not on the range hosts; the range hosts
are locked down). Acceptance: the `uninstrumented.py` probe shows out-of-scope reaches `[]`, internet
blocked, **and the host gateway now unreachable**, while in-scope pivots still work.

## Sources (read at source this session)
- `swarm/gate.py` — `Gate.dispatch`, per-actor/per-verb scope, egress parse, the one effect site.
- `swarm/range_gen.py` `to_compose` (~L473–552) + the `verify` asserts (~L648–704) — the segmentation.
- `swarm/uninstrumented.py` — the falsifier channel + `probe_boundary` + the host-gateway gap note.
- `swarm/audit.py` (+ `redteam/reverify_floor.py` by reference) — the independent oos auditors.
