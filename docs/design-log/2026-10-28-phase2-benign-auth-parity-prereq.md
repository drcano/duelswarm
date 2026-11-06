# Phase-2 prerequisite: benign svc_dba auth-method parity (tracked, NOT a Phase-1 blocker)

**Raised:** 2026-10-28, by Dante, when approving the 3c key-based inner seam.

## The coupling
The seam-fix made the svc_dba admin LOTL chain (`dba01 -> db-bastion -> db-core`) **key-based** (a service
account authenticating by SSH key — the faithful model for automated service movement). Red's inner pivots
are now real `Accepted publickey for svc_dba` events in the target telemetry.

But the benign model still emits **password** auth for those same edges: `benign_baseline._login_line` is
`"Accepted password for {user} …"`, including for svc_dba activity on the admin/db tiers. So red's
living-off-the-land movement carries an **auth-method signature benign does not** — `publickey` vs
`password` on the exact edges red rides.

## Why it matters (Phase 2 only)
The whole point of LOTL is that the ONLY thing that can catch red is the behavioral / graph anomaly (the
thesis's informational-asymmetry claim). An auth-method leak is a trivial extra discriminator that
distinguishes red from legitimate traffic WITHOUT any behavioral reasoning — it would silently inflate
blue's stealth-detection numbers and confound the asymmetry result.

## Phase 1: harmless
Phase 1 is loud red, blue **observe-only**, no stealth scoring — blue takes no action and nothing is scored
on stealth. So the leak changes no Phase-1 result. It is NOT a blocker for the seam-fix commit or the paid
re-run.

## The Phase-2 action (lock it in before stealth scoring begins)
When stealth scoring starts, the benign `svc_dba` admin activity on the seam edges must ALSO become
key-based — an `Accepted publickey` benign login line — so red's LOTL is indistinguishable from benign on
auth method. That is a change to the registered `benign_baseline` logical model, hence a **pre-registration
amendment** (the model is anchored at seq-39; this would be a seq-40 amendment, recorded like any other).

Scope of the amendment (do NOT over-reach):
- Change: benign svc_dba admin-tier logins (`dba01/db-bastion/db-core` edges) -> `Accepted publickey`.
- Keep password: the **workstation / bootstrap tier** (the reused DBA workstation cred into dba01 — the
  anomalous first hop is *meant* to look like a human password login).
- Unchanged: the crown objective stays the plaintext synthetic PII harvest (`crown_data`); the gate, the
  hash chain, and the segmentation are untouched.

## Verification when done
- `benign_baseline` emits `Accepted publickey for svc_dba` on the seam edges; the auth-method distribution
  of benign vs red on those edges is identical (no method-only discriminator).
- A stealth-scored duel shows blue cannot separate red from benign on auth method alone (only behavior).
- The prereg anchor advances (seq-40) with the amendment recorded.

Until then: this file + the memory `[[phase1-20host-benign-range-done]]` carry the debt so Phase 2 does not
inherit it silently.
