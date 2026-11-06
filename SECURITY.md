# Security

duelswarm is a sandboxed research range. It runs entirely inside its own Docker network and never
touches any host outside that network (see "Responsible use" in the [README](README.md)).

## Reporting a vulnerability

If you find a security issue in this code — for example a way for the range to affect anything
outside its own Docker containers, or a way an agent's effect can bypass the authorization gate
without being recorded on the hash chain — please report it privately through this repository's
GitHub **"Report a vulnerability"** (Security Advisories) rather than opening a public issue. Include
the commit SHA and, where possible, a chain or log that reproduces it.

Note the project's own threat model: the one guarantee that must hold by construction is that every
effect is recorded. An authorization-floor penetration that the chain records and the cold auditors
surface is a research *finding*, not a vulnerability. A way to produce an effect the chain does **not**
record is a vulnerability.
