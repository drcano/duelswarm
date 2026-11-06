# Design log — Phase 5 setup audit + engineering readiness (2026-10-26)

## Phase-5-setup code audit (`c2a35c5`, `2de94c4`) — CONFIRMED at source
- `range_runtime.provision_ad_dc` (L96): reads the `duelswarm.provision` label off the live DC, waits
  for KDC readiness, applies it via `_compose(op="provision-ad-dc")` → `gate.lifecycle` (TCB
  range.lifecycle verb) → `run_effect`. Gate-logged, one effect path, no new sink. Wired into
  `bring_up_generated_range:182`, AFTER the §E verify — the designed boot provisions the DC itself
  (resolves the earlier open question: provisioning is part of the orchestrated path, not a manual step).
- `host_egress_firewall._discover_entry_and_pivot` (L189): now prefers an in-scope host that shares a
  data segment with the entry (`adjacent = [n for n in in_scope if _data_nets(n) & entry_nets]`). The
  recommended adjacency fix; stops the (C) leg false-failing so the designed boot won't false-halt.
- `topo_to_compose` (L874): DC container `hostname` set to `dc-01` so Samba registers `dc-01.range.lab`.
  Legit DNS fix.
- `live_pivot.pass_the_hash` (L191): `echo quit | smbclient.py -hashes :{nthash} {domain}/{user}@{dst_ip}`
  over the earned channel (Impacket 0.13 dropped `-c`). A REAL Impacket attack with the real stolen hash
  vs the real Samba DC, still `gate.dispatch` + spine, success read from the tool's output — not faked.
Instrument discipline intact throughout (gate + spine, one effect path, no new effect site).

## Source-vs-runtime boundary (honest)
Verified at source: all build phases 0a→5-setup, the floor instrument, one-engine red+blue,
objective-blindness, zero dangling refs, the PtH code is a real attack. NOT reproducible from the
file bridge (taken as CC-reported, host-side): orchestrated-boot PASS, §E `--verify` PASS, the live PtH
admin session, `make test` green, `static_coverage` PASS, `reverify_floor` cold. The code producing these
is sound; the runtime results are CC's observations on the host.

## External validation is PARTIAL — state it, don't gloss
PtH (the core credential-reuse-to-Tier-0 edge) IS externally validated (real Impacket admin SMB session).
Kerberoast / secretsdump / BloodHound hit genuine Samba-vs-Windows walls (Kerberos checksum, LDB/TDB not
NTDS.dit, LDAP signing) — real differences, not range bugs. Honest framing for prereg + demo: the
credential-reuse path is real-tool-validated; the AD tier is a real Kerberos/LDAP/SMB Samba DC, not a
Windows NTDS, so some Windows-specific attacks don't transfer. Full Windows fidelity = the heavier
GOAD-style scope call, not needed for the core claim. Disposition rec: CAPTURE AS-IS, do not tune (RC4
enctype / disable LDAP signing / resolver tweaks are tuning unless adopted as a deliberate, pre-registered
realism config).

## Engineering pre-go checklist (before spending credits)
1. **Dry end-to-end first (the airtight-ing step).** Run the FREE dry pipeline on the orchestrated range
   — `verify_live_run` / `run_discovery_duel(use_llm=False)` — and confirm the plumbing: all three log
   streams land (red reasoning, blue reasoning, Falco telemetry), `reverify_floor` cold, `verify_live_run`
   prints its verdict, no crash. Then the paid run changes only `use_llm=True`, so the sole new variable is
   model behavior, not plumbing. Don't spend credits to discover a wiring bug.
2. **git author** on the 121 unpushed commits = `drcano@ucsd.edu`, NOT `[redacted]` (the machine's
   default). Confirm `git log --format='%ae' | sort -u` before any push/submission.
3. **Nebius routing** — the paid run's COUNTED red+blue calls go through Nebius Token Factory (HF/
   OpenRouter = disqualifier); `provider_anthropic` stays control-only/never-counted.
4. **Turn budget ≥40** actually set on the runner (the earlier null was turn-cap-confounded at 16).
5. **Falco capturing** on the orchestrated range (real syscalls, not 0).
6. **preregister re-anchor** (stale `live_telemetry` anchor) + lock the tier-line boundary and the three
   findings as pre-registered expectations — freezes the measurement apparatus before data.
Items 2–6 + the findings disposition + the paid-run go (seed/turns, explicit credit spend) are Dante's.
