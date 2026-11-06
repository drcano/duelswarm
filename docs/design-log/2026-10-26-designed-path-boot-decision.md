# Design log — the paid-run range boots the designed way (2026-10-26)

Decision + the fix that gates it, ahead of Phase 5.

## The §E "asymmetric drop" was a probe artifact — retracted, range is correctly wired
An earlier alarm about a firewall/fabric drop breaking the chain was wrong. Causes, all tooling not
network: `CAP_NET_RAW` dropped by the container posture makes `ping` fail ("Lacking privilege for raw
socket") — every ping-based "unreachable" was a capability error; minimal images lack `nc`/`bash`/
`python3` in combinations that failed the probes; and the multi-homed addressing (a multi-homed host
takes `.10`, bumping the segment's own host to `.11`) meant the wrong IP was tested repeatedly
(`10.20.0.10` is dmz-web itself, `10.50.0.10` is app-fs itself; real targets were `.11`).

Confirmed reachable (raw-socket-free probes, correct IPs): dmz-web→wks-01:22, dmz-web→db-core:22,
wks-01→app-fs:22, app-fs→dc-01:445/88/389/636 (AD tier reachable from app-fs, which multi-homes
app↔identity); wks-01→dc-01:445 correctly BLOCKED (wks-01 isn't on identity — red reaches the DC via
wks-01→app-fs→dc-01). DC Samba up (88/389/445/636 listening).

§E design confirmed SOUND (not just harmless): `br_netfilter` inactive, so same-bridge container↔container
is L2-switched and never touches iptables — the firewall can't affect pivots; container→host-gateway is
L3-delivered to `filter/INPUT`, which the firewall DOES catch. Escape blocked, chain untouched.

## Decision — the paid-run / demo range comes off the ONE designed path
`bring_up_generated_range` / `make range-up`, NOT a hand-provisioned `docker compose up`. A raw compose-up
skipped the provisioner AND the firewall install + `--verify`; hand-provisioning that range with
`samba-tool` would make the paid-run range a non-reproducible one-off that diverges from what the
orchestrated boot produces — a parallel range state, against the mandate. The designed path: installs the
§E firewall + runs the authoritative `--verify` (hard floor enforced, not skipped), runs the
`duelswarm.provision` label the orchestrated way (`svc_sql` SPN + `svc_da` DA created reproducibly), and
exercises `bring_up_generated_range` end-to-end (needed for the paid run regardless).
A hand-provisioned current range is acceptable ONLY as an explicitly throwaway smoke test of the
Samba↔Impacket compat risk — never the paid-run range.

## Prerequisite fix (gates the clean boot)
`scripts/host_egress_firewall.py` `_discover_entry_and_pivot` picks the first `scope==in` host
(`jump-01`, non-adjacent to the entry), so the `--verify` (C) pivot leg FALSE-FAILS; and
`bring_up_generated_range` HALTS the standup on any `--verify` non-zero. Fix: pick a pivot that SHARES A
NETWORK with the entry (an adjacent in-scope host, e.g. `wks-01`/`db-core` off `dmz-web`). Safety (E)
gateway-unreachable already passes; this only corrects the pivot-reachability leg.

## Sequence
1. Fix `_discover_entry_and_pivot` (entry-adjacent in-scope pivot).
2. Tear down the hand-booted range.
3. `make range-up` / `bring_up_generated_range` — firewall + `--verify` + provisioner.
4. Offensive confirmations on THAT range: `bloodhound` / `GetUserSPNs` / `secretsdump` / PtH; report
   Samba↔Impacket compat findings honestly.

## Open to confirm on the host
Whether `bring_up_generated_range` itself applies the `duelswarm.provision` label, or provisioning is a
separate runner step (the topo comment says "the auditor/host runner applies these post-up"). If the boot
doesn't apply it, wire the provisioner into the designed path rather than assume the boot does it.

## Verifier pass after the designed boot
Provisioner ran (`svc_sql` SPN roastable; `svc_da` in Domain Admins); offensive tools succeed against the
real edges; BloodHound path matches the credential graph; floor re-derives cold on the orchestrated range;
the range came up via the designed path (not hand-patched). Host-only items still Dante's: §E `--verify`
(sudo), `preregister` re-anchor before the paid run.
