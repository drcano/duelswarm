# Design log — full enterprise realism + external validation (2026-10-25)

Companion to `2026-10-25-realistic-breach-grounding.md`. Records a scope decision Dante made
explicitly: build the **full** sandboxed enterprise — a faithful snapshot of AI-vs-AI warfare — and
prove its realism with **real tools**, not by our assertion. Research-first; the sandbox is still NOT
built to produce the answer we want.

## Why this is the right bar (not just a bigger one)
The earlier brief grounded "realistic" in digested taxonomy (ATT&CK/D3FEND pages, CISA narratives, my
synthesis). A top offensive/detection professional does not call a range realistic because it was
designed from best practice; they **point real attacker and defender tooling at it and require those
tools to behave as they would against a real network.** Realism is a measured property an outside tool
confirms. That is the deepening here: external validation. The one deliberately-bigger axis Dante chose
on top of it is a **real identity tier**.

## Decision 1 — the identity tier is a REAL Samba AD Domain Controller, not a mock
Real intrusions are won at **Tier 0** (Domain Admin / the domain controller), not at data exfil alone
(Microsoft AD tier model; ATT&CK TA0006 Credential Access, T1558 Kerberoasting, T1550 pass-the-hash,
T1003 OS credential dumping / DCSync). MHBench/Incalmo has no identity tier — that absence is the gap we
close.

Feasibility is clean and was checked at source this turn: the deploy host is
**Linux x64** (get_device_info), not macOS as I had wrongly assumed — so Docker runs Linux containers
natively and a **Samba AD DC** container is first-class. Samba AD DC provides a real Kerberos KDC, LDAP,
SMB, machine/user accounts, SPNs and GPO. That realness is exactly what makes external validation
possible: the AD attack paths become genuine (roast a real SPN, pass a real NTLM hash, dump via a real
`secretsdump`), so real tools can succeed against them. Containerized Samba AD DC is a well-documented,
maintained pattern.

GOAD (Game of Active Directory) and the Splunk Attack Range are Windows-VM-based and too heavy for this
Docker host; we mirror their **graph structure and SPN/credential idioms** on Samba rather than copying
their infrastructure. That keeps full identity-tier realism without a VM farm.

## Decision 2 — realism is externally validated, never asserted
Acceptance is "a real off-the-shelf tool behaves against the range as it would on a real network / real
telemetry." The validators and what each one proves:
- **bloodhound-python** (dirkjanm; cross-platform, collects over LDAP/SMB from a Linux host) — the
  credential graph is realistic iff BloodHound computes the same *shape* of attack paths a real AD env
  yields. This is the external judge of the credential-DAG.
- **Impacket** `secretsdump`, `GetUserSPNs` (Kerberoast), pass-the-hash; **NetExec/CrackMapExec** SMB
  sweeps + PtH; **nmap** — if these real tools work against the range, the surface is real.
- **Sigma rules + the live Falco capture** (already working) — a real detection ruleset fires on red's
  actions over the captured telemetry at realistic rates; the telemetry is realistic iff real detectors
  trip on it.
- **A documented kill-chain replay** (e.g. the Volt Typhoon living-off-the-land sequence, or a DFIR
  Report case) runs end-to-end on the range — an external, published ground-truth sequence.

Rawest starting material (instead of digested summaries): the Center for Threat-Informed Defense /
MITRE adversary-emulation library (command-level TTP plans), The DFIR Report (raw command lines +
timelines), real attack-telemetry corpora (OTRF Security-Datasets / Mordor, Splunk BOTS,
EVTX-ATTACK-SAMPLES, DARPA OpTC), and GOAD/DetectionLab/Splunk Attack Range + the MHBench/Incalmo
networks as reference topologies and graph shapes.

## Guardrail — validators are AUDITORS, never fed to red
This is the no-hardcoding / objective-blind rule applied to the validation layer. BloodHound, Impacket,
nmap, the Sigma eval and the kill-chain replay audit the RANGE's ground truth from the outside — the way
`reverify_floor` audits the floor and `static_coverage` audits mediation. **None of their output is ever
handed to the red agent.** Red still learns a credential only by harvesting a host it already owns, and
the crown/graph/scope never appears in red's prompt (the existing leak tests extend to cover this). A
real tool *failing* against the range is a **realism finding to report**, not something to paper over or
tune around. The validators live external to the engine (a `scripts/validation/` auditor rig), touch no
live effect site, and leave the floor instrument untouched.

## Scope, cost, timing (honest)
This is bigger than the prior brief — a real AD tier plus an external-validation harness. Dante chose it
deliberately: the research instrument is the priority over the Oct 30 hackathon. The rebuild stays
**phased so an honest, submittable slice exists at each checkpoint** (the instrument + a
credential-chain breach is already demoable), so full realism and a hackathon submission are not in
tension. Paid live runs stay gated until the build phases are verified at source. No tuning toward any
outcome; label fidelity (LIVE vs SIM) on everything.

## Open items (unchanged)
Re-verify the DBIR / CrowdStrike / M-Trends statistics at primary source before any public use; write
the preregistered modeling-choice note (why credential-graph + identity tier is the right mechanism, and
what a null would mean) before the paid runs.

## Sources (secondary; the primary validation is the tools running against the range)
- MITRE ATT&CK: T1558 Kerberoasting, T1550 use alternate auth material, T1003 OS credential dumping,
  TA0006 — https://attack.mitre.org/
- Microsoft Active Directory tier model (Tier 0 = DC/identity) —
  https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
- Samba as an AD Domain Controller (official wiki) —
  https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller ; containerized
  pattern e.g. https://helgeklein.com/blog/samba-active-directory-in-a-docker-container-installation-guide/
- BloodHound.py (dirkjanm), collects from Linux — https://github.com/dirkjanm/BloodHound.py ;
  https://bloodhound.readthedocs.io/en/latest/data-collection/bloodhound-py.html
- Impacket (GetUserSPNs/secretsdump) — https://github.com/fortra/impacket ; NetExec —
  https://github.com/Pennyw0rth/NetExec
- Sigma detection rules — https://github.com/SigmaHQ/sigma ; Elastic detection-rules —
  https://github.com/elastic/detection-rules
- CTID adversary emulation library — https://github.com/center-for-threat-informed-defense/adversary_emulation_library ;
  The DFIR Report — https://thedfirreport.com/
- Attack telemetry corpora: OTRF Security-Datasets — https://github.com/OTRF/Security-Datasets ;
  EVTX-ATTACK-SAMPLES — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES ; Splunk BOTS —
  https://github.com/splunk/botsv3
- Reference AD labs/topologies: GOAD — https://github.com/Orange-Cyberdefense/GOAD ; DetectionLab —
  https://github.com/clong/DetectionLab ; Splunk Attack Range — https://github.com/splunk/attack_range
- MHBench/Incalmo — arXiv 2501.16466
- CISA Volt Typhoon advisory (living-off-the-land) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
(URLs to re-verify at primary source before any public/submission use.)
