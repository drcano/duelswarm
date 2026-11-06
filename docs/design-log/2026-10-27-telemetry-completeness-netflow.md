# Design log — complete per-run telemetry: red + blue + the network record (2026-10-27)

Audited what the committed runs actually log against the requirement that each run capture RED's
thinking + actions, BLUE's thinking + actions, and the network telemetry of exactly what happened.
Red and blue were already complete; the network record had a real gap, now closed.

## What was already captured (verified in the committed chains)
- **Red thinking + actions:** `move.source` (source=llm) carries the model's `thought`, chosen
  `tool`, `args`, model/tier/tokens; plus `gate.allow`, spine `confirm`, `state.mutate` for effects.
- **Blue thinking + actions:** blue's `move.source` (its reasoning), `blue.investigate`,
  `blue.detect.*` (the real-telemetry detections with `source_line`), `blue.belief`, `blue.contain`,
  `state.mutate` (contained).
- **Syscall + service telemetry:** `sys.syscall` (Falco eBPF — execs, file opens, connects) and
  `svc.event` (sshd auth, the Struts fault) — both in the `_telemetry.jsonl` chain.

## The network-flow gap (and why it was not a simple bug)
`net.flow` (the kernel connection record) was EMPTY. Two reasons, the second structural:
1. `capture_conntrack` tried to `apk add conntrack-tools` inside a throwaway container — impossible
   on the air-gapped range (no internet in the container).
2. More fundamentally: the range's internal pivots are container-to-container on the SAME Docker
   bridge, which is L2-switched and NEVER enters the host conntrack table. Host conntrack is blind
   to intra-bridge traffic (short of a global `bridge-nf` sysctl), so even a working `conntrack -L`
   would not record the dmz-web→db-core pivot.

Falco's eBPF `connect()` probe, however, sees every connection regardless of bridging and attributes
it to the process + container — it had already captured the pivots (e.g. `Outbound connect
(dst=10.40.0.10 dport=22 proc=bash container=range-dmz-web)`), just buried in `sys.syscall.raw`.

## The fix
- `live_telemetry.parse_falco_netflows` turns Falco's outbound-connect events into first-class
  `net.flow` records (src container, dst ip, dport, proc). `ingest` now emits `net.flow` from BOTH
  Falco connects (intra-bridge pivots) AND the host conntrack snapshot (routed/NAT flows, e.g. the
  ingress entry). `capture_conntrack` now reads the host table via the whitelisted
  `sudo -n conntrack -L` (no apk-in-container). The earlier `conntrack -E` sampler idea was dropped:
  event mode is not whitelisted, and it chased flows conntrack structurally cannot see.

## Verified FREE (no tokens) — `telemetry-completeness-verify/`
A dry run now records 66 `net.flow` events including: `10.40.0.10:22 ×5 (src=dmz-web)` — the pivot to
the crown host; `10.20.0.11:22 ×4` — the wks-01 pivot attempts; `10.90.0.11:8080 ×2 (src=attacker)`
— the entry foothold; `10.99.0.10:80 (src=dmz-web)` — a connect to the decoy honeypot. Alongside 618
`sys.syscall` and 10 `svc.event`, and the full red/blue duel chain. `make test` green; prereg
re-anchored (seq 27). Instrument untouched.

## State of the prior paid runs
The committed paid runs (`full-real-blue-windowed/`, `full/`) already contain the network activity as
Falco `sys.syscall` connect events and `svc.event` auth records, but NOT the parsed `net.flow` (the
parser post-dates them). A fresh paid run would carry all three streams fully structured; the current
ones are not re-derivable to clean `net.flow` because `sys.syscall.raw` is truncated. Nothing pushed.
