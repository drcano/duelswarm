# Design log — Phase 0a hard-floor hardening: source verification (2026-10-25)

Planner/verifier's independent re-derivation of CC's Phase 0a implementation (hard-floor hardening),
done AT SOURCE, not from CC's build report. Companion to `2026-10-25-two-floor-safety-architecture.md`.
Phase 0a is implemented on `real-range`, **uncommitted**.

> Provenance: the round-1 body below is the planner/verifier's independent source re-derivation. The
> in-place corrections (firewall bullet, the SETFCAP finding, the changed-file count) and the **Round-2
> addendum** at the end were reconciled by CC to match the mechanism actually shipping after the first live
> run surfaced the hairpin bug — so the committed record is accurate, not independently re-derived there.
> The outstanding live re-verify under the corrected rules is called out in the addendum.

## Method
Diffed the pre-0a staged copies of `range_gen.py` and `uninstrumented.py` against the current working
tree; read `topo_to_compose.py`, `scripts/host_egress_firewall.py`, `scripts/preregister.py`, and the
`Makefile` at source. The build report ("all green except a pre-existing red") was NOT taken on trust.
Behavioral checks that need a booted range + host sudo are deferred to the deploy host (below) — they
cannot be re-derived from source alone.

## Confirmed at source
- **One shared posture helper, both generators.** `host_posture()` lives once in `range_gen.py`;
  `topo_to_compose.py` imports it (`from swarm.range_gen import host_posture`, L48) rather than
  duplicating — the "one helper / no bloat" rail holds. Applied via `**host_posture()` to the red-origin
  box and every range host in BOTH `range_gen.to_compose` and `topo_to_compose.to_compose`.
- **Posture content:** `cap_drop: ALL` + a minimal `cap_add`, `security_opt: no-new-privileges:true`,
  and resource ceilings (`mem_limit 2g`, `pids_limit 2048`, `cpus 2`). Both generators' `verify()`
  selftests now assert, per service: `cap_drop==["ALL"]`, `no-new-privileges` present, NET_RAW and MKNOD
  absent from `cap_add`, and resource ceilings set.
- **Segmentation floor survived the change intact** in both generators: every data-plane net still
  `internal: true` with a real IPAM CIDR; out-of-scope hosts still isolated; ingress still DNAT-only with
  masquerade off. The hard floor was hardened, not weakened.
- **`probe_boundary` now MEASURES the gateway.** The old hardcoded `"OPEN … not closable in compose"`
  string is gone, replaced by `host_gateway_reachable()`: a TCP-response probe where a completed connect
  OR an active RST ("refused") both prove reach, and only a silent timeout counts as dropped —
  deliberately NOT ICMP, because 0a drops CAP_NET_RAW so `ping` would false-read as unreachable.
  `host_gateway_unreachable` is folded into `ok`, and the no-Docker / undiscoverable-gateway path returns
  `None` (reported UNMEASURED) so `ok` is honestly `False` — no silent pass. On a booted range whose host
  firewall is not yet up, the gateway answers and `ok` is correctly `False`.
- **Host-side firewall logic is sound (conntrack-only §E — see the round-2 addendum for why the raw
  rule was dropped).** §E is closed entirely in `filter/INPUT`: accept `ESTABLISHED,RELATED` from the
  bridge, then drop the rest. A compromised container's reach to the gateway/host is a NEW connection →
  hits the DROP; the only `ESTABLISHED` flows to the gateway are replies to host-initiated connections
  (the docker-proxy localhost hairpin), which the container cannot turn into a new outbound connection.
  Pivots (dest = a container IP → FORWARD, not INPUT) and inbound DNAT are untouched. Discovery is
  de-hardcoded (finds any `*_ingress` net; entry/pivot/published-port discovered from the booted range).
  `verify()` reuses the canonical reach probe in `swarm.uninstrumented` instead of re-implementing it, and
  `_run` is timeout-bounded so no probe can hang. `make range-up`/`range-down` install/remove it as
  best-effort sudo hooks (no-op off Linux); `--selftest` is wired into `make test`.
- **Instrument untouched / class-2 isolation intact.** `gate`/`eventlog`/`spine` not in the changed set.
  `uninstrumented.py`'s additions use its own `subprocess` and add NO `swarm.gate` import, so the
  CLASS-2 (deliberately ungoverned) isolation the static-coverage check enforces is preserved.

## Finding (RESOLVED round-2) — the cap set did not match its own comment
`_POSTURE_CAP_ADD` lists 11 caps; the round-1 comment called it "Docker's default cap set MINUS NET_RAW
and MKNOD." Docker's default set is 14 caps, so the list actually drops **three** — NET_RAW, MKNOD, and
**SETFCAP** (file capabilities; nothing in sshd or the JVM vuln services needs it, so dropping it is
harmless-to-better). **Fixed round-2:** the comment now reads "minus NET_RAW, MKNOD, and SETFCAP" in both
spots, SETFCAP stays dropped, and a `SETFCAP not in cap_add` assert was added to BOTH generators'
`verify()` selftests so the "kept dropped" claim is enforced, not just stated.

## The pre-existing `preregister --verify` red — confirmed independent of 0a
Read `preregister.py`'s `ARTIFACTS` at source. `swarm/live_telemetry.py` IS an anchored artifact; NONE of
CC's eight changed files (`range_gen.py`, `topo_to_compose.py`, `uninstrumented.py`, `range_runtime.py`,
`scripts/host_egress_firewall.py`, `scripts/prove_env_boundaries.py`, `docker-compose.yml`, `Makefile`)
are in `ARTIFACTS`. Since `--verify` only hashes files in that list, CC's changes cannot move its verdict
— a stronger proof than "fails identically when stashed."
The red is a stale anchor on `live_telemetry.py` (per CC, from commit 7c275da; the specific commit was not
git-confirmed here, but the independence is airtight regardless).

## Deferred to the deploy host (cannot be re-derived from source)
The live 0a done-check needs a booted range + host sudo: `make range-up`, then
`host_egress_firewall.py --verify` and `uninstrumented.probe_boundary`, confirming `oos_tcp_reaches==[]`,
internet blocked, **host gateway now unreachable**, in-scope pivots still work, and the real vuln services
still boot/play under the hardened caps.

## Recommendations (Dante's call)
1. **Verify-first, then commit.** This is SAFETY code; the two-floor principle says the hard floor must
   actually hold before real tooling runs. Run the live done-check on the host before banking 0a; fix the
   SETFCAP comment in the same pass.
2. **Keep the prereg re-anchor a separate, deliberate step.** Re-running `preregister.py` appends a logged,
   dated `prereg.amendment` stamping the Falco-fixed `live_telemetry.py` as registered. Doing it now is
   correct IF framed as a conscious freeze of the measurement apparatus before Phase 5's paid runs, with an
   amendment note naming the 7c275da change. Do NOT bundle it into the 0a commit — keep the experimental
   record clean. Must be settled before any new data run.

---

## Round-2 addendum (2026-10-25) — the hairpin fix, conntrack-only §E, and the live-path wiring

Round-1 above verified the implementation as it then stood. Acting on round-1's recommendations and the
first live run exposed real issues; this addendum records the corrected mechanism that is actually shipping,
so the committed record matches it. Reconciled to source after the fixes; `make test` green except the
pre-existing `preregister`/`live_telemetry` red.

### Why the `raw/PREROUTING` rule was dropped (the hairpin bug)
The first live `--verify` on the deploy host showed `(E) … UNREACHABLE-OK` (§E closed) but then HUNG on the
`(B)` check (`curl localhost:<published>`). Root cause: `curl localhost:<port>` reaches the entry through
docker-proxy, which sources its connection to the container from the bridge **gateway** IP — so the
container's reply has `dst=gateway`. The `raw/PREROUTING -d <gateway> -j DROP` rule, being pre-conntrack,
dropped that reply, breaking the hairpin. This is not a test-only concern: the **live Struts foothold**
fires at `http://127.0.0.1:<port>/` (`live_arms_race_run.py:374`), and `measured_duel`, `prove_n2n3`, and
`vet_pool` also hit the published port over localhost. The raw rule would have broken the live duel.

### The corrected §E mechanism (conntrack-only)
§E is now enforced entirely in `filter/INPUT` (`_install_rules`): accept `ESTABLISHED,RELATED` from the
bridge, then drop the rest. This closes §E **identically** for the thing §E is about — a compromised
container INITIATING contact to the gateway/host (a NEW connection → DROP) — while letting the
host-initiated hairpin's replies through. A container cannot promote a reply flow into a new outbound
connection, so no escape is reopened. The deprecated raw rule is retained ONLY in `_legacy_rules` so
`--down` cleans hosts that ran the old version. `_run` is now timeout-bounded (rc 124 on timeout) so a
stuck probe can never hang `--verify` again. Selftest updated: install set is filter/INPUT-only, the raw
rule appears only in the teardown set, and the timeout guard is exercised.

### §E holds without the raw rule — the proof that matters
`uninstrumented.probe_boundary` tests exactly the container-INITIATED path (NEW `/dev/tcp` connect from the
entry to the gateway). It never tests the localhost hairpin, so it is the right judge of §E. Note this means
the raw rule was never necessary for the §E done-check — the `filter/INPUT` DROP already blocks the
container-initiated NEW connection.

### Live-path wiring (round-1 had the firewall only on `make range-up`)
Round-1 wired the firewall into `make range-up`, but the path real runs use (`range_runtime`,
`live_arms_race_run`) never installed it. Fixed: `swarm/range_runtime.bring_up_generated_range` now installs
the firewall and runs an authoritative `--verify`, HALTING the standup (and tearing down) if §E is open —
a hard-floor break stops the run, never a result. Privilege model: the duel process never runs as root; it
calls the one audited firewall script via `sudo -n` (narrow NOPASSWD sudoers line, root-needing actions
under a fixed `/usr/bin/python3` so the rule is stable), and reaches the script by SUBPROCESS, never import,
so the class-2 channel the probe uses stays out of `range_runtime`'s import closure (static-coverage still
shows the counted entrypoints `uninst=False`).

### Root compose hardened to match + drift guard
The legacy root `docker-compose.yml` (what `make range-up`'s fixed range boots) carried no posture in
round-1. Fixed: one `x-hardfloor` YAML anchor mirroring `host_posture()` is merged into all six services,
confirmed via `yaml.safe_load` to resolve to the exact posture with networks intact (`reachability_probe`'s
selftest, which parses this file, still passes). To prevent silent divergence, a no-Docker guard in
`prove_env_boundaries.py` (in `make test`) asserts every root-compose service's posture equals
`host_posture()`; verified it both passes clean and catches a simulated drift.

### Live verification run on the deploy host (round-2)
On the deploy host: `docker compose config` parses the hardened compose; the booted range brings up
all six vuln services serving under the dropped caps / 2g limit with **no restart loops** (struts 302,
jenkins 403, postgres accepting connections, the three oos nginx serving); `probe_boundary` returns
`oos_tcp_reaches=[]`, `internet_blocked=true`, `in_scope_reaches=2`, `host_gateway_unreachable=true`,
`ok=true`. **Caveat (honest):** that green probe was taken while the OLD raw rules were still installed from
the first `--up`. The **outstanding** live step is re-applying the corrected conntrack-only set
(`--down`/`--up`) and re-running `--verify` — expected `(E) UNREACHABLE-OK`, `(B) REACHABLE-OK` (hairpin
restored), `(C) PIVOT-OK` — plus a `probe_boundary` re-dump confirming `host_gateway_unreachable` stays
`true` under filter/INPUT alone. The 0a code + this record are committed now on Dante's go; this corrected-
rules live re-verify is a REQUIRED host gate that MUST pass before any real tooling runs (Phase 5), and is
tracked here as the one outstanding 0a item.
