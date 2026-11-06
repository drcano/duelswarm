# Reconciler witness fix + live kill-chain fixes (2026-10-28)

At-source record of the fixes made against the 2026-10-28 brief
(`2026-10-28-fix-live-killchain-and-report-gaps-brief.md`), and the finding that reordered them.

## The finding that inverted the brief's Fix 3
The brief read the first arsenal live runs as *"the engine's `achieved` flag was fooled; the
reconciler (which trusts nothing) caught it"* — i.e. red's loot was a self-report the telemetry
refuted. A source audit of the committed chains found the **opposite**: the reconciler produced
**false negatives**. Red genuinely completed the kill chain; the reconciler failed to re-derive it
because of three matcher bugs between what `live_telemetry` writes and what `live_truth` matched:

1. **net.flow destination field.** On a Docker range the inner pivots are L2-switched and never
   enter host conntrack; they are witnessed only by Falco's `connect()` records, which
   `parse_falco_netflows` keys as `dst_ip` (conntrack keys `dst`). `_corroborated` read `f.get("dst")`
   only — so the **607** real ssh flows to db-core:22 never matched, and every inner pivot flagged.
2. **crown-read marker.** The reconciler matched a legacy `.crown` dotfile; the real crown is
   `/home/dbadmin/pii.json`. The crown read WAS captured on `range-db-core`
   (`cat /home/dbadmin/pii.json`, 2 syscalls) but never recognised.
3. **IP vs name key.** Claims carry the dst IP (`10.40.0.10`); syscall/service records are keyed by
   container name (`range-db-core`). With no resolver, even a correct marker/technique on the crown
   host was looked up under the wrong key.

Evidence it was false-negatives, not red lying: the crown host's own telemetry contains the `cat
pii.json` exec AND 607 flows to :22 AND an sshd Accepted line — the events were on the wire; only the
re-derivation missed them. The same `flagged:2` shape appears on the committed **8/8 "unopposed
success"** baseline (`docs/runs/2026-10-27-unopposed-success-rate/`): under the amended reconciler all
8 seeds re-derive `flagged:0, corroborated:3`. No run had ever actually corroborated the crown read —
because the witness could not match it.

Dante approved reordering: **fix the reconciler first**, re-derive to confirm it corroborates the real
chain, THEN gate `achieved` on the corrected reconciler. Gating on the buggy reconciler (the brief's
literal Fix 3) would have stamped `achieved=false` on genuine, witnessed theft — a new dishonesty.

## The fixes

### Reconciler (`swarm/live_truth.py`) — a §11 pre-registration amendment (prereg.jsonl seq 36)
`live_truth` is registered measurement apparatus, so the change is logged as a dated amendment, never
a silent rewrite. Changes: a sensor-agnostic flow accessor (`_flow_dst`/`_flow_src` read `dst`||`dst_ip`,
`src`||`src_host`); `index_telemetry`/`reconcile` take `crown_markers` so the caller passes the REAL
crown filename (harness ground truth — what to look for, never red's claim); the live caller passes an
IP→name `resolve` from the gate. `live_telemetry` (emission) was already faithful and is UNCHANGED.
Regression tests added for the falco-connect flow and the real-filename crown marker.

### Reconciler lateral witness — the symmetric tightening (prereg.jsonl seq 37, then seq 38)
seq 36 fixed FALSE NEGATIVES (the witness under-counted real pivots). The mirror risk is a FALSE
POSITIVE — corroborating a pivot red never landed — so the lateral witness was tightened in two dated
amendments after Dante's source-verification.

**seq 37 (2026-10-28b)** dropped the bare `dport=22` net.flow fallback. conntrack and Falco log *every*
`:22` connect, including red's own recon scans of a host's ssh port (the observe1 chain holds 607 such
connects), so a connect alone was a false-positive vector — it would rubber-stamp a pivot that never
authenticated. A lateral now needs the pivot's own EARNED signature: a completed auth, a web-exploit
fault (T1190/T1210), or the ENTAILED crown read — a crown-file read ON the destination can only happen
through a real session there, so it entails the pivot (this is also what un-flagged Run B's genuine
crown pivot, the mirror of the seq-36 false-negative). Biting regression: a `src→dst:22` connect flow
as the only evidence stays FLAGGED.

**seq 38 (2026-10-28c)** carried the same logic one level further, after a source audit of the clean
seed's telemetry. The completed-auth branch had accepted any `T1021`-tagged record — but Falco tags
BOTH a plain `:22` connect AND the per-connection `sshd-session`/`sshd-auth` fork as T1021, and both
occur for a FAILED login. This was observed live: wks-01 carries an `sshd-session` fork and a `Failed
password` line in every episode, a host red never held a valid cred for. So the bare `T1021` tag was
dropped too; the only ssh witness now is the sshd **"Accepted password/publickey"** success line from
the destination's own service log (`index_telemetry` marks it `_AUTH_OK_SENTINEL`). This is STRICTER
than the brief that proposed it (which offered the `sshd-session` fork as a witness — the audit showed
that fork is not auth-success). Done-check held: the clean seed, the arsenal-first A/B, and the 8/8
unopposed baseline all re-derive with flagged/corroborated counts UNCHANGED (db-core carries the
`Accepted` line + the entailed crown read in every lateral-claim episode). Biting regression: an
`sshd-session` fork / bare `T1021` with no `Accepted` line stays FLAGGED.

### Fix 3 — telemetry-gated objective verdict (`scripts/live_arms_race_run.py`)
New authoritative `duel.verdict` event: `achieved = red's grounded loot claim AND the reconciler
witnessed the loot on the crown host's own telemetry`. `duel.outcome.achieved` remains red's grounded
self-report; `duel.verdict.achieved` is the telemetry-gated authority Phase-6 fitness reads, so a
fabricated win scores 0. `_corroborated_objective` is unit-tested to BITE: claimed-but-unwitnessed →
`achieved=False`. The reconcile inputs (resolver + crown markers) are persisted as a `reconcile.inputs`
telemetry record so future runs re-derive cold; the committed runs re-derive from the seed.

### Fix 1 — the live credential chain (`swarm/live_postex.py`, `swarm/live_red.py`)
- **1.1** `ArsenalDriver` now reuses HARVESTED creds per target: each harvested private key is used
  with its OWN owning user (read off the path — `/home/alice/.ssh/…` → `alice`), and a harvested
  config password as a candidate; the static seed cred is the last resort. The rewrite's single
  static `login_user=dbadmin` for every hop was what failed `dbadmin@wks-01` on `Permission denied`.
- **1.2** The config-cred search pattern broadened from `password|secret|credential|apikey` to
  `pass|secret|cred|apikey|token` (so `db_cred=` is caught), and the harvester now EXTRACTS the
  credential VALUES from matched config files so red PIVOTS WITH THE HARVESTED cred. Values never
  enter the log (only the keys), so the find re-derives without leaking a secret.

### Fix 2 — msfrpcd attacker-net (`scripts/live_arms_race_run.py`)
`_standup_msfrpcd` DISCOVERS the attacker net via `live_msf.discover_attacker_net("range-attacker")`
instead of constructing `duelswarm-range-<seed>_range_attacker` (which did not exist → `network … not
found` on BOTH live runs). When msfrpcd cannot stand up the episode is flagged `episode.degraded` and
`duel.verdict.msf_wired=False`, so a degraded episode is never silently counted as a clean
arsenal-fired test.

## Verification (all free, no Docker/API)
- `make test` green; `prove_one_engine` one-of-each; floor re-derives cold (`oos_executed=0`).
- `live_truth` / `live_postex` / `live_red` self-tests cover every fix above.
- `docs/runs/2026-10-27-arsenal-first-live/rederive.py` re-derives both committed runs cold: chains
  verify, floor cold, Run B `flagged:0 / corroborated:3 / verdict achieved=True`, Run A verdict
  `achieved=False` (blue prevented).

## What stays open (gated / not done here)
- **Fix 5 (paid, gated on Dante)**: a clean re-run with msfrpcd UP and the cred chain fixed — now
  mainly to exercise the MSF modality + harvested-key pivots, since matched-tier corroborated theft is
  already shown by Run B and the 8/8 baseline. Held for the go.
- ~~The harvested-password pivot still takes the DB user from the seed cred (the planted dbconfig has
  no user line); a fully map-blind DB login (harvest user too) is a recommended hardening, not done
  here.~~ **SUPERSEDED by `971e7ad` (2026-10-28).** The planted DMZ loot is now the realistic
  `db_cred=dbadmin:S3cr3t-DB-Range!` connstring form (`topo_to_compose.DB_PLAINTEXT_CRED`), the
  harvester catches the `db_cred=` key, and `live_red._split_user_pass` splits `user:pass` so red
  harvests the login **user** (`dbadmin`) too — no seed hand-off. Shown FREE by self-tests:
  `swarm/live_postex.py` asserts the `db_cred` value is harvested; `swarm/live_red.py` asserts the
  reuse layer splits it to `login_user=dbadmin`. NOTE: the harvested VALUES are suppressed in the
  chain (only keys are logged), so the user-harvest is backed by the CODE PATH + those self-tests,
  **not** independently witnessed in the committed chain — `as_user=dbadmin` on the wire is consistent
  with harvest or a seed cred, and the `Accepted password for dbadmin` svc.event proves the value
  worked, not the user string's origin.
- Benign noise floor not yet wired into the live duel (a separate Phase-6 prerequisite).
