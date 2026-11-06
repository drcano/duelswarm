# Design log: what the S7 PLC advisory (AA26-231A) says about how to build the floor

Date: 2026-10-22. This is a design note, not a result and not evidence. It records how a
current government advisory maps onto the gate, what it confirms, and the one thing it says
we are missing.

## The source (verified)
NSA/CISA/FBI/DOE/EPA joint advisory **AA26-231A**, "Defending Against an Active Threat to
Siemens S7 Series PLCs," Aug 19 2026. Checked against the CISA page and several independent
write-ups on 2026-10-22, not taken on the word of the analysis that flagged it.

The attacker builds tools on open-source libraries (snap7.dll / python-snap7) with AI-assisted
scripting, and the tools are made to look like legitimate OT monitoring software (no CVE was
assigned). Because the tool is built to look legitimate, the advisory cannot say "detect the
bad tool by signature." Instead it says: isolate, mediate access by identity, scope what you
can do, and then watch for deviation from a known-good baseline. Enforce scope first, detect
deviations second.

## How to read it (honest framing)
The advisory does **not** say detection is futile. It lists monitoring and hunting right next
to isolation and access control, and recommends both. So the support for our design is in the
structure and the reasoning, not in any sentence that says detection loses: the controls it
prescribes are scope-enforcement primitives, and it frames monitoring as deviation-from-policy
precisely because the AI-built tool is designed to look legitimate. Cite it that way.

## What it confirms about the gate as built (no change needed)
- **Mediate the flow, not the payload.** Its first network control is "Block TCP port 102 at
  perimeter firewalls entirely," plus a DMZ splitting OT from IT and no unauthorized routing.
  That is our two-layer design: the gate default-denies a flow by source and destination, and
  the split network is the backstop that holds even if a target is obfuscated past the command
  parser. The parser is rightly a second check, not the floor.
- **Authorize by identity allowlist.** It says restrict access "to authorized engineering
  workstations only by MAC/IP allowlisting on PLCs." That is `scope_by_actor` plus the
  `resolve_ips` IP-to-scope map: an explicit source-to-destination allowlist, default-deny
  everything else. The reference monitor keys on identity and reachability, which is what the
  gate already does.
- **Keep an independent record; alert on deviation.** It says log all connections with
  timestamps and source IPs, "establish a baseline for legitimate behavior and ... alert on
  deviations," and "alert on unauthorized PUT/GET operations." That is `live_telemetry` plus
  the reconciler: a record the actor does not write, with detection framed as
  deviation-from-policy rather than signature.

So the two load-bearing choices (chokepoint mediation by identity allowlist; an independent
deviation log) are what a five-agency consensus prescribes. That is validation, not new work.

## What it changes: make read-vs-write a real scope axis
Today the gate scopes **reachability**: can this actor reach this target. It does not scope the
**action**: what the actor may do once it can. The advisory argues this gap directly.

- Its control #4 is "Configure protection levels (such as write protection and read/write
  protection)." Reach is not enough; read and write are different privileges.
- Its threat analysis says the actors are "leveraging read access to understand target
  environments, enabling preparation and positioning for future write operations" (it ties the
  write step to T0821). So read looks benign and is the setup for the write that does harm.

Design implication: make read-vs-write (more generally, read-vs-mutate) a first-class scope
dimension, with **write default-denied even where read is allowed**, and default-read-only for
any actor that merely looks authorized (the known integrator, the approved tool, the trusted
agent). That last point is the seam the advisory keeps hammering: the dangerous actor is the
one that looks in-policy, so you scope it explicitly rather than trust the label.

One clean property falls out: the same read/write line serves both halves of the system. A
write attempt where only read is allowed is a gate block (prevention) and, at the same time, a
deviation-log entry (detection). One axis, both uses.

## Status and guardrails
- This is a design direction, not a built feature. The read/write axis is not in `swarm/gate.py`.
- The gate is the trusted core (the floor's TCB). Changing what counts as "out of scope" there
  changes the invariant the whole project rests on, so **implementing the verb axis needs its
  own pre-registration** and its own re-derivation that the floor still holds at zero. Do not
  bolt it on mid-experiment.
- An ICS/OT demonstration terrain (a PLC behind the gate, read scoped-allowed,
  write-to-data-blocks default-denied, the attacker an AI client masquerading as a monitoring
  tool) is the cleanest real-world instantiation of the floor, and it is the scenario the
  government flagged as active. File it as a possible scope extension for **after** the IT-side
  experiments, not something to add now.

## Source
CISA AA26-231A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a
