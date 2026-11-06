# Pre-registration — Increment 2: a real-telemetry, label-free blue detector
## Blue's belief derives from what the sensors actually saw, not a modeled probability

Dated amendment (2026-10-27) to the Increment-1 preregistration
(`docs/prereg/INCREMENT_1_DATA_THEFT.md`), anchored BEFORE the Increment-2 verification run.
The Increment-1 prereg already named this as the landing detector ("Real-telemetry detector
(if Increment 2 lands) — label-free"); this fixes its mechanism before it is measured. Rationale:
`docs/design-log/2026-10-26-objective-driven-red-and-realistic-defender.md` (Decision 4).

### What changes
Blue's detection stops being a hardcoded per-stage Bernoulli coin-flip over red's spine actions
(`_P_FIRE` in `swarm.live_blue_agent`) and becomes a REAL detector over the REAL telemetry already
captured for the reconciler. The instrument (gate/eventlog/spine/audit/reverify_floor) and the floor
reading are unchanged; only how BLUE sees changes.

### The detector (fixed in advance)
`swarm.sensor_real.telemetry_detections(service_logs)` matches community-recognizable Sigma-style
SIGNATURES against the targets' own service logs (the real `docker logs` — sshd `-e` auth records,
the Struts Jakarta-Multipart fault an S2-045 OGNL RCE throws, the Apache path-traversal tell):
- T1190 (initial access): the S2-045 Jakarta Multipart exploit fault.
- T1190 (lateral): the CVE-2021-41773 path-traversal → mod_cgi RCE tell in an access log.
- T1021 (lateral): sshd "Accepted publickey/password" — a real authenticated session on a host.
- T1110 (credential access): sshd "Failed password" — noisy, mostly benign.
Each detection carries the matched LOG LINE (`source_line`) so it traces to a concrete telemetry
event, and a per-signature RELIABILITY prior (its precision, `1 - false_positive_rate`) — NOT a
per-stage probability over red's actions. Blue's belief is the noisy-OR over these real detections,
plus blue's OWN honeytoken tripwires (its planted decoys — blue-owned, not red's labels).

### Label-free / air-gap (machine-checked)
The detector reads observable log PATTERNS and the detector's own taxonomy ONLY. It never reads
red's event labels, techniques, or the ground truth. `swarm.sensor_real.assert_label_free(...)`
raises unless every detection traces to a real telemetry line (`source_line` + a `real-telemetry[...]`
basis); it is run at detection time in the unified episode and guarded in `make test` (with a
positive control that a fabricated, non-telemetry detection is caught). `run_blue_fight` records
`blue.detector` stating which detector ran.

### Recall is MEASURED, not assumed (the honest lossiness)
`sensor_real.score_classifier` scores the detector as a classifier against ground-truth + benign
events, producing real recall/precision/ROC/AUC. Recall EMERGES below 1.0 because some actions
leave no telemetry: exfil over an ALREADY-established SSH session writes no new auth line, so it is
undetectable from auth telemetry — a real sensor blind spot, reported, not hidden. A benign login is
identical to a malicious one in the auth log, so the lateral rule false-positives — a real precision
limit, reported.

### No-shortcuts clause (binding)
If, for a given run, no real service-log telemetry is available, `run_blue_fight` falls back to the
MODELED Bernoulli and records `blue.detector="modeled"` — it NEVER presents the modeled belief as
sensor-derived. No fake-real detector is ever shipped. Every run's report states which detector ran.

### What the verifier re-derives (file-only bridge)
- Every blue detection on a real run carries a `source_line` and a `real-telemetry[...]` basis; the
  label-free assertion passes; no detection reads a red label/gt field.
- Blue's belief (`blue.belief`) re-derives from the `blue.detect.*` events, which derive from the
  captured service-log telemetry — not from `_P_FIRE`.
- The detector in use is recorded (`blue.detector` / `system.blue.detector_in_use`), honestly.
- Floor reading unchanged: `chain_verified=True`, `oos_executed` as-is, re-derived cold.

### Amendment (2026-10-27) — per-episode telemetry windowing
The first paid run with this detector surfaced that `tail_service_logs`/`tail_logs` read the
CUMULATIVE `docker logs` on the persistent range, so blue detected on stale lines from prior
episodes. Fixed: the capture is windowed to the episode under test via `docker logs --since` an
episode-start timestamp (`sensor_real.tail_logs(..., since=...)`, `live_telemetry.tail_service_logs`).
This corrects measurement fidelity only — the detector, its signatures, the air-gap guard, and the
label-free property are unchanged. Re-anchored to record the artifact hash change.

### Amendment (2026-10-27) — net.flow from Falco connects (intra-bridge coverage)
The telemetry's network-flow record (`net.flow`) was empty because Docker container-to-container
traffic on the SAME bridge is L2-switched and never enters the host conntrack table (and the old
capture tried to `apk add` conntrack-tools inside an offline container). Fix: `net.flow` now also
derives from Falco's eBPF `connect()` events (`live_telemetry.parse_falco_netflows`), which DO see
intra-bridge flows and attribute each to its process+container; the host conntrack snapshot
(`sudo -n conntrack -L`) is kept for routed/NAT flows (the ingress entry). Verified free: a dry run
records the dmz-web→db-core:22 pivot, the wks-01 pivot attempts, the attacker→entry foothold, and a
connect to the decoy as net.flow events. Telemetry/detector semantics and the air-gap are unchanged;
this is measurement coverage only. Re-anchored to record the artifact hash change.
