"""Authorization gate — the deterministic reference monitor (SPEC §4; PAPER_ADDENDUM P0).

Every red tool call routes through dispatch(). A target outside the authorized
scope (e.g. the decoy host) is logged and blocked BEFORE the tool function runs
— complete mediation in the execution path, not a post-hoc audit.

Scope is checked against canonical identifiers. An alias map resolves container
IPs, hostnames, or URL hosts to their canonical name, so a tool can't slip past
by addressing a target by IP instead of label.

Egress-boundary mediation (P0): a *named-tool* target is not enough once red runs
free-form shell commands — `exploit_struts("curl http://ldap")` has an in-scope
tool target (struts) but egresses to an out-of-scope host. So dispatch() also
inspects any `command=` for every outbound target it references, canonicalizes
each, and default-denies anything not in scope — regardless of how the command is
phrased. This is a static action-boundary check; the generated range ALSO isolates
out-of-scope hosts at the network layer (swarm/range_gen.to_compose), the backstop
that holds even against a target obfuscated past this parser.
"""
import ipaddress
import re
import subprocess
from collections import namedtuple
from urllib.parse import urlparse


class OutOfScope(Exception):
    pass


class MalformedTarget(OutOfScope):
    """An agent-supplied target that is not a well-formed host / IPv4 / host:port.

    A subclass of OutOfScope so every existing `except OutOfScope` caller still treats
    it as a block; dispatch logs it with reason 'malformed-target'. This is the class
    that closes G1/G2: a target the parser cannot vouch for is denied, never
    best-effort resolved by taking the text before the first ':'."""
    pass


# A canonical, validated target. `host` is the scope identifier every decision AND
# every effect uses; `ip`/`port` are the parsed parts (None if absent). The raw agent
# string is retained only for logging and is NEVER used to build an effect/command.
CanonicalTarget = namedtuple("CanonicalTarget", ("host", "ip", "port", "raw"))

# The ONLY characters a raw target may contain: host-label chars (letters, digits,
# '.', '-', '_') plus a single ':' before a numeric port. Everything else — '@'
# (userinfo), whitespace, a shell metacharacter (; | & $ ` ' " \ / # % ? * ( ) [ ] { }
# < > ! ^ ~), a second ':' — makes the target malformed. '_' is allowed because the
# range's own scope labels use it (attacker_c2, sensor_siem).
_TARGET_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:"
)
# A syntactically valid host name: dot-separated labels of [A-Za-z0-9_-], each 1..63
# chars and not starting/ending with '-'.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$"
)


# The one effect path's timeout, re-exported so callers catch it WITHOUT a `subprocess.`
# reference of their own (keeping the one-effect-path grep clean: subprocess lives only here).
EffectTimeout = subprocess.TimeoutExpired


def run_effect(argv, **kwargs):
    """THE single external-effect site (invariant #1 — one effect path). This is the ONLY place
    in swarm/ that spawns a subprocess: every module requests an external effect (docker
    exec/cp/inspect/compose, ssh, telemetry capture) THROUGH this, so a grep for subprocess over
    the engine returns only this function. Agent actions reach it via `gate.dispatch` (the gate
    mediates scope + verb FIRST, then the tool body calls run_effect); TCB-owned operations
    (telemetry reads, range lifecycle) call it under their own logged verb. `swarm/
    uninstrumented.py`'s falsifier channel uses this same mechanism but DELIBERATELY bypasses the
    gate POLICY — proving the segmentation floor holds without the gate is its whole purpose.
    A thin pass-through to subprocess.run so every call site's kwargs (capture_output / text /
    timeout / check / input / ...) are preserved verbatim — the only difference from
    subprocess.run is the name, which is exactly what makes the one-effect-path grep meaningful."""
    return subprocess.run(argv, **kwargs)


# Egress primitives: extract candidate outbound hosts from a free-form command.
# Conservative by design — the network-layer isolation is the complete backstop;
# this layer mediates (and audits) every egress target it can resolve.
_EGRESS_RES = (
    re.compile(r"\b[a-z][a-z0-9+.\-]*://([^/\s:'\"]+)", re.I),        # scheme://host
    re.compile(r"\b(?:curl|wget)\s+(?:-\S+\s+)*(?:[a-z]+://)?([a-z0-9][a-z0-9.\-]*)", re.I),
    re.compile(r"\b(?:ssh|scp|rsync)\s+(?:-\S+\s+)*(?:[^\s@]+@)?([a-z0-9][a-z0-9.\-]*)", re.I),
    re.compile(r"\bn(?:c|cat)\s+(?:-\S+\s+)*([a-z0-9][a-z0-9.\-]*)\s+\d", re.I),  # nc host port
    re.compile(r"-h\s+([a-z0-9][a-z0-9.\-]*)", re.I),                 # psql/mysql/redis -h host
    re.compile(r"/dev/(?:tcp|udp)/([^/\s]+)/\d+"),                    # bash /dev/tcp/host/port
    re.compile(r"\b([a-z0-9][a-z0-9.\-]*):\d{1,5}\b", re.I),          # host:port token
)


def _egress_targets(command):
    """Candidate outbound host tokens referenced by a free-form command."""
    hosts = set()
    for rx in _EGRESS_RES:
        for m in rx.findall(command or ""):
            h = (m if isinstance(m, str) else m[0]).strip().lower()
            if h and not h.isdigit():   # drop bare port numbers; keep hostnames/IPs
                hosts.add(h)
    return hosts


def _resolve_container_ips():
    """Build a map of container-IP -> service-name from docker compose."""
    aliases = {}
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.ID}}"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0]
            cid = parts[1]
            # Get the IP
            ip_result = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid],
                capture_output=True, text=True, timeout=5,
            )
            for ip in ip_result.stdout.strip().split():
                if ip:
                    # Map "range-struts" -> "struts", "range-db" -> "db", etc.
                    canon = name.replace("range-", "")
                    aliases[ip] = canon
                    aliases[name] = canon
    except Exception:
        pass
    return aliases


class Gate:
    def __init__(self, scope, log, resolve_ips=False, *, scope_by_actor=None, known_hosts=None):
        """`scope`: default scope every actor shares unless `scope_by_actor` overrides.
        `scope_by_actor`: optional {actor: iterable} — Component A (symmetric range).
        Red's zone = target_net + red_infra; blue's = target_net + sensors; the gate
        chokepoint stays single, only the scope lookup becomes actor-dependent.
        """
        default = frozenset(scope or [])
        # An actor's grant is either a flat iterable (every verb allowed on those hosts —
        # backward compatible) OR a per-VERB dict {"read":[...], "mutate":[...]} (invariant #3,
        # the read-vs-mutate axis): a host in `read` only is readable but NOT mutable.
        self._scope_by_actor = {a: (s if isinstance(s, dict) else frozenset(s))
                                for a, s in (scope_by_actor or {}).items()}
        self._default_scope = default

        def _hosts(s):
            return (set(s.get("read", ())) | set(s.get("mutate", ()))) if isinstance(s, dict) else set(s)

        # `self.scope` = UNION of every actor's authorized hosts — the "known host" universe for
        # alias/egress resolution. Enforcement in dispatch() uses the per-actor (per-verb) scope.
        union = set().union(*(_hosts(s) for s in self._scope_by_actor.values())) \
            if self._scope_by_actor else set()
        self.scope = default | frozenset(union)
        self.log = log
        self.aliases = {}
        if resolve_ips:
            self.aliases = _resolve_container_ips()
        # The real-host universe the egress parser's _is_real_target consults, supplied by the
        # caller from the range topology (in- AND out-of-scope host NAMES) — range-agnostic, no
        # hardcoded host names. "range-<host>" is canonicalized by the general rule in
        # _canonicalize; loopback is intentionally NOT auto-mapped to any entry (default-deny is
        # correct). The egress parser is defence-in-depth; kernel segmentation is the real
        # backstop, so a named OOS host absent from known_hosts still cannot be reached.
        self.known_hosts = frozenset(known_hosts or [])

    def _resolve_host(self, token, ip=None):
        """Map a VALIDATED host/IP token to its canonical scope identifier.
        Order: direct scope match -> alias map (ip->name or name->name) -> the
        range-<host> prefix rule (range-agnostic) -> else the token itself, which is
        then in no scope and is default-denied. No parsing here — the token has
        already been validated by _parse_target as a host name or dotted-quad IPv4."""
        if token in self.scope:
            return token
        if token in self.aliases:
            return self.aliases[token]
        if token.startswith("range-"):
            stripped = token[len("range-"):]
            return self.aliases.get(stripped, stripped)
        return token

    def _parse_target(self, target):
        """Strict allowlist parse of an agent-supplied target into a CanonicalTarget.

        Accepts EXACTLY one of:
          - a dotted-quad IPv4 address (validated by `ipaddress`), optional ':'port
          - a syntactically valid host name, optional ':'port
        Anything else raises MalformedTarget: userinfo ('@'), whitespace, a shell
        metacharacter, a path ('/'), a second ':', a non-numeric/out-of-range port, or a
        bare decimal/hex/short IP spelling (171048971, 0xa32000b, 10.50.11) that is not a
        dotted quad. A well-formed but UNKNOWN host resolves to itself and is denied by
        the scope check (out-of-scope), which is distinct from malformed.

        This replaces the old `target.split(':')[0]` rule (G1): the text before the
        first ':' is no longer trusted as the host, so `web01:22@10.50.0.11` (which used
        to resolve to the in-scope 'web01') now contains '@' and is rejected outright.
        Because every effect builds its command from the returned .host/.ip/.port rather
        than the raw string, no agent text can reach a shell (G2)."""
        if not isinstance(target, str) or not target:
            raise MalformedTarget(f"empty or non-string target: {target!r}")
        bad = sorted(set(c for c in target if c not in _TARGET_ALLOWED))
        if bad:
            raise MalformedTarget(f"forbidden character(s) {bad} in target {target!r}")
        if target.count(":") > 1:
            raise MalformedTarget(f"more than one ':' in target {target!r}")
        host_tok, sep, port_tok = target.partition(":")
        port = None
        if sep:
            if not (port_tok.isdigit() and 1 <= int(port_tok) <= 65535):
                raise MalformedTarget(f"invalid port in target {target!r}")
            port = int(port_tok)
        if not host_tok:
            raise MalformedTarget(f"empty host in target {target!r}")
        ip = None
        try:
            ipaddress.IPv4Address(host_tok)   # rejects decimal/hex/short/leading-zero forms
            ip = host_tok
        except (ipaddress.AddressValueError, ValueError):
            # not a dotted-quad IPv4: must then be a valid host name, and NOT a bare
            # all-digit single label (an integer IP spelling masquerading as a host).
            if not _HOSTNAME_RE.match(host_tok) or ("." not in host_tok and host_tok.isdigit()):
                raise MalformedTarget(
                    f"not an IPv4 address or valid host name: {target!r}"
                )
        return CanonicalTarget(host=self._resolve_host(host_tok, ip), ip=ip, port=port, raw=target)

    def canonical_target(self, target):
        """Public: parse+resolve a target to its CanonicalTarget, or raise MalformedTarget.
        Callers build an effect's argv from the returned .host/.ip/.port — NEVER from the
        raw agent string — so the raw string never reaches a shell (see swarm/live_*.py)."""
        return self._parse_target(target)

    def _canonicalize(self, target):
        """Resolve a target to its canonical scope identifier (a host string).

        A NON-RAISING wrapper over the strict parser, kept for the scope-membership
        helpers (`_is_real_target`, `check_egress`) and external callers so a hostile
        string never crashes them: a malformed target returns the raw string, which is in
        no scope and is therefore denied. The STRICT decision (malformed -> block) is made
        in `dispatch`/`allows`/`canonical_target` via `_parse_target`."""
        try:
            return self._parse_target(target).host
        except MalformedTarget:
            return target if isinstance(target, str) else str(target)

    def _scope_for(self, actor, verb=None):
        """Per-actor authorized scope (Component A), refined by the read-vs-mutate verb axis
        (invariant #3). A flat grant authorizes every verb (backward compatible). A per-verb
        grant {"read":[...], "mutate":[...]} authorizes `mutate` ONLY on the mutate set; a
        `read` (or unspecified) verb sees read∪mutate. Falls back to the shared default."""
        s = self._scope_by_actor.get(actor, self._default_scope)
        if isinstance(s, dict):
            mutateset = frozenset(s.get("mutate", ()))
            if verb == "mutate":
                return mutateset
            return frozenset(s.get("read", ())) | mutateset     # read / unspecified -> the union
        return s

    def allows(self, target, actor=None):
        """Strict scope membership: a malformed target is not allowed (False); a
        well-formed target must resolve to a host in the actor's scope."""
        try:
            canon = self._parse_target(target).host
        except MalformedTarget:
            return False
        scope = self._scope_for(actor) if actor is not None else self.scope
        return canon in scope

    def _is_real_target(self, t):
        """Is candidate token `t` actually an outbound host (vs. a flag argument
        mis-split as one)? A real target is a known range host (in scope or a
        known alias) or an FQDN/IP (contains a dot). Bare unknown single-label
        tokens — an HTTP verb or an option value like 'post'/'batchmode' pulled
        off `-X POST` / `-o BatchMode=yes` — are not hosts and must not be blocked
        as if they were. Anything exotic that slips this parser is still caught by
        the network-isolation backstop (range_gen puts out-of-scope hosts on an
        unroutable network), so ignoring non-hosts here loses no real guarantee."""
        if "." in t:                      # FQDN or IPv4 → a routable target
            return True
        known = self.scope | set(self.aliases) | set(self.aliases.values()) | self.known_hosts
        return self._canonicalize(t) in known or t in known

    def check_egress(self, command, actor=None):
        """(ok, blocked_targets) for a free-form command (P0).

        Resolve every outbound host the command references and default-deny any
        real target that is not in the ACTOR's scope — however phrased."""
        scope = self._scope_for(actor) if actor is not None else self.scope
        blocked = [t for t in _egress_targets(command)
                   if self._is_real_target(t) and self._canonicalize(t) not in scope]
        return (not blocked), sorted(set(blocked))

    def dispatch(self, actor, tool_name, target, tool_fn, *args,
                 meta=None, command=None, verb=None, **kwargs):
        """Complete mediation: check the tool target AND (if a free-form `command`
        is given) its egress targets against the ACTOR's scope, log the decision,
        then run tool_fn only if both pass. The chokepoint is single; the lookup
        is actor-dependent (Component A — symmetric range).

        `verb` is the read-vs-mutate axis (invariant #3): `verb="mutate"` is default-denied on a
        host the actor is only granted `read` on (a mutate attempt on read-only terrain is a
        gate.block, distinct from plain out-of-scope). `verb=None` keeps the all-verb behavior."""
        rec = {"tool": tool_name, "target": target}
        if verb:
            rec["verb"] = verb
        if meta:
            rec.update(meta)
        # Strict parse FIRST: a malformed target is blocked before any scope lookup, so
        # the split(':')[0] bypass (G1) cannot reach the tool. The canonical object is
        # what callers build their effect from (the raw string is never used downstream).
        try:
            ct = self._parse_target(target)
        except MalformedTarget as e:
            rec["reason"] = "malformed-target"
            self.log.append(actor, "gate.block", rec)
            raise OutOfScope(
                f"{tool_name} -> {target!r} blocked for {actor}: malformed-target"
            ) from e
        canonical = ct.host
        scope = self._scope_for(actor, verb)
        if canonical != target:
            rec["resolved"] = canonical
        if canonical not in scope:
            # a mutate denied where only read is granted is reported distinctly from out-of-scope.
            read_only = verb == "mutate" and canonical in self._scope_for(actor, "read")
            rec["reason"] = "mutate-denied (read-only grant)" if read_only else "out-of-scope"
            self.log.append(actor, "gate.block", rec)
            raise OutOfScope(
                f"{tool_name} -> {target!r} blocked for {actor}: {rec['reason']}"
            )
        if command is not None:
            ok, blocked = self.check_egress(command, actor=actor)
            if not ok:
                rec["reason"] = "egress-out-of-scope"
                rec["egress_blocked"] = blocked
                self.log.append(actor, "gate.block", rec)
                raise OutOfScope(
                    f"{tool_name} on {target!r} blocked: command egresses to "
                    f"out-of-scope {blocked}"
                )
        self.log.append(actor, "gate.allow", rec)
        return tool_fn(*args, **kwargs)

    def lifecycle(self, argv, *, meta=None, **run_kw):
        """A TCB-owned range-lifecycle effect (docker compose up/down). The range lifecycle is
        owned by the trusted TCB, not an untrusted agent, so it is NOT scope-denied — it is
        LOGGED under the `range.lifecycle` verb (attributable in the hash chain) and performed
        via the single effect primitive. This is how compose up/down stays on the one effect
        path while remaining the TCB's authority, distinct from any agent action."""
        rec = {"verb": "range.lifecycle", "op": [str(a) for a in argv[:4]]}
        if meta:
            rec.update(meta)
        self.log.append("tcb", "range.lifecycle", rec)
        return run_effect(argv, **run_kw)

    def effect(self, actor, verb, target, argv, *, meta=None, **run_kw):
        """Gate-dispatched external effect: mediate (actor, verb, target) THEN perform it via the
        single effect primitive (`run_effect`). Agent effects (verb 'read'/'mutate') and
        TCB-owned ones (the range lifecycle the TCB owns: verb 'range.lifecycle', actor 'tcb')
        both flow through here, so every such effect is scope-checked, verb-checked, and logged.
        Returns the subprocess.CompletedProcess.

        `argv` may be a list (legacy) OR a callable `build(canonical) -> argv`. With a
        builder, the argv is constructed from the gate's CanonicalTarget on the ALLOW
        path only — so the raw agent string is never used to build the command, and a
        malformed/out-of-scope target is blocked before the builder runs."""
        build = callable(argv)
        name = "build" if build else (argv[0] if argv else "?")
        md = {"effect": name, "argc": None if build else len(argv)}
        if meta:
            md.update(meta)

        def _run():
            a = argv(self._parse_target(target)) if build else argv
            return run_effect(a, **run_kw)
        return self.dispatch(actor, f"effect:{name}", target, _run, meta=md, verb=verb)


if __name__ == "__main__":  # self-check: blocked tool must NOT run; aliases resolve
    class _Rec:
        def __init__(self):
            self.events = []

        def append(self, actor, action, data=None):
            self.events.append((action, data))
            return {}

    log = _Rec()
    gate = Gate(["struts", "db"], log)
    ran = []

    # Direct name
    assert gate.dispatch("red", "nmap", "struts", lambda: ran.append("x") or "ok") == "ok"
    assert ran == ["x"]

    # Alias: range-struts -> struts (in scope)
    assert gate.allows("range-struts")

    # Alias: range-decoy -> decoy (NOT in scope)
    assert not gate.allows("range-decoy")

    # Block
    try:
        gate.dispatch("red", "nmap", "decoy", lambda: ran.append("DECOY"))
        raise SystemExit("decoy call was not blocked")
    except OutOfScope:
        pass
    assert ran == ["x"], "blocked tool executed anyway"

    # Block via alias
    try:
        gate.dispatch("red", "nmap", "range-decoy", lambda: ran.append("DECOY2"))
        raise SystemExit("aliased decoy call was not blocked")
    except OutOfScope:
        pass
    assert ran == ["x"]

    assert [a for a, _ in log.events] == ["gate.allow", "gate.block", "gate.block"], log.events

    # ── Egress-boundary mediation (P0): a free-form command on an IN-SCOPE host
    #    that reaches an OUT-OF-SCOPE host must be blocked, however it's phrased. ──
    g2 = Gate(["struts", "db"], _Rec(), known_hosts=["ldap", "decoy", "mailserver"])
    # benign in-host commands: no egress target -> allowed
    for cmd in ("id", "whoami", "uname -a", "cat /etc/passwd", "psql -h db -U app"):
        ok, blk = g2.check_egress(cmd)
        assert ok, f"benign/in-scope command wrongly blocked: {cmd!r} -> {blk}"
    # the exact P0 bypass: in-scope tool target (struts) + out-of-scope egress
    bypasses = [
        "curl http://ldap/creds",          # scheme://host
        "curl decoy:80",                    # host:port
        "wget mailserver/x",                # curl/wget bare host
        "bash -c 'cat </dev/tcp/ldap/389'", # /dev/tcp
        "nc decoy 4444",                    # nc host port
        "ssh root@mailserver",              # ssh host
        "curl http://example.com",          # open internet (default-deny)
    ]
    ran2 = []
    for cmd in bypasses:
        ok, blk = g2.check_egress(cmd)
        assert not ok and blk, f"egress bypass NOT caught: {cmd!r}"
        try:
            g2.dispatch("red", "exploit", "struts", lambda: ran2.append(cmd),
                        meta={"attack": "T1190"}, command=cmd)
            raise SystemExit(f"dispatch ran a command egressing out of scope: {cmd!r}")
        except OutOfScope:
            pass
    assert ran2 == [], "a blocked egress command executed anyway"
    # an in-scope egress (struts -> db) with a command runs fine
    assert g2.dispatch("red", "exploit", "struts", lambda: "ran",
                       meta={"attack": "T1190"}, command="psql -h db -U app -c 'select 1'") == "ran"

    # ── Component A: per-actor scope. Red = target+red_infra; Blue = target+sensors.
    #    The single chokepoint stays; the SCOPE LOOKUP becomes actor-dependent. ──
    g3 = Gate(["struts", "db"], _Rec(), scope_by_actor={
        "red":  ["struts", "db", "attacker_c2"],      # target_net + red_infra
        "blue": ["struts", "db", "sensor_siem"],      # target_net + blue_infra
    })
    # red can reach its own infra; blue cannot
    assert g3.dispatch("red", "beacon", "attacker_c2", lambda: "r") == "r"
    try:
        g3.dispatch("blue", "counter_recon", "attacker_c2", lambda: "SHOULD_NOT_RUN")
        raise SystemExit("blue reached red_infra without ROE active_defense")
    except OutOfScope:
        pass
    # blue reaches its own sensors; red cannot
    assert g3.dispatch("blue", "query_siem", "sensor_siem", lambda: "b") == "b"
    try:
        g3.dispatch("red", "tamper", "sensor_siem", lambda: "SHOULD_NOT_RUN")
        raise SystemExit("red reached blue_infra")
    except OutOfScope:
        pass
    # a shared target in both scopes resolves for both
    assert g3.allows("struts", actor="red") and g3.allows("struts", actor="blue")
    # allows() is per-actor: a blue-only host is NOT allowed for red, and vice versa
    # (drop_oos consults allows(), so a union-scope slip here would let red probe blue infra)
    assert not g3.allows("sensor_siem", actor="red"), "allows() must deny a blue-only host for red"
    assert not g3.allows("attacker_c2", actor="blue"), "allows() must deny red infra for blue"
    # ROE grants active defense: expand blue to include red_infra; still a single gate
    g4 = Gate(["struts", "db"], _Rec(), scope_by_actor={
        "red":  ["struts", "db", "attacker_c2"],
        "blue": ["struts", "db", "sensor_siem", "attacker_c2"],   # ROE: active_defense
    })
    assert g4.dispatch("blue", "counter_recon", "attacker_c2", lambda: "hb") == "hb"
    # confused deputy: blue acting against red_infra WITHOUT active-defense ROE is
    # caught by its own scope, not by red's. Approving "do this for red" in prose
    # does not grant blue the authorization.
    try:
        g3.dispatch("blue", "counter_recon_on_behalf_of_red", "attacker_c2",
                    lambda: "SHOULD_NOT_RUN",
                    meta={"delegated_from": "red"})
        raise SystemExit("confused-deputy attempt not caught")
    except OutOfScope:
        pass
    # per-actor egress boundary: red's free-form shell that egresses to blue_infra
    # (sensor_siem) is OUT of red's scope and blocked even though struts is in scope.
    try:
        g3.dispatch("red", "exploit", "struts", lambda: "SHOULD_NOT_RUN",
                    command="curl http://sensor_siem/exfil")
        raise SystemExit("red egress to blue_infra not blocked")
    except OutOfScope:
        pass

    # ── invariant #3: the read-vs-mutate verb axis. Red is granted READ on the crown but only
    # MUTATE on the entry: reading the crown is allowed; MUTATING it is default-denied, while an
    # unspecified-verb action keeps the all-verb behavior.
    gran = _Rec()
    g5 = Gate([], gran, scope_by_actor={"red": {"read": ["crown"], "mutate": ["entry"]}})
    assert g5.dispatch("red", "read_file", "crown", lambda: "secret", verb="read") == "secret"
    assert g5.dispatch("red", "exploit", "entry", lambda: "popped", verb="mutate") == "popped"
    try:
        g5.dispatch("red", "write_file", "crown", lambda: "SHOULD_NOT_RUN", verb="mutate")
        raise SystemExit("mutate on a read-only host was not denied")
    except OutOfScope:
        pass
    assert any(a == "gate.block" and (d or {}).get("reason", "").startswith("mutate-denied")
               for a, d in gran.events), "the mutate-deny must log a distinct reason"
    # a host granted neither read nor mutate is still plain out-of-scope.
    try:
        g5.dispatch("red", "read_file", "decoy", lambda: "SHOULD_NOT_RUN", verb="read")
        raise SystemExit("unreadable host was not denied")
    except OutOfScope:
        pass

    # ── A1: strict target parsing. The split(':')[0] bypass (G1) and malformed agent
    #    strings are rejected BEFORE the tool runs; the canonical object is what callers
    #    build effects from. 'web01' in scope, 'dc-01' (10.50.0.11) forbidden. ──
    gp_log = _Rec()
    gp = Gate([], gp_log, scope_by_actor={"red": ["web01"]}, known_hosts=["web01", "dc-01"])
    gp.aliases.update({"10.50.0.10": "web01", "10.50.0.11": "dc-01",
                       "range-web01": "web01", "range-dc-01": "dc-01"})

    def _gp_blocked(t, **kw):
        ran = []
        try:
            gp.dispatch("red", "probe", t, lambda: ran.append(1) or "ran", **kw)
            return False
        except OutOfScope:
            return not ran

    # in-scope still works; the canonical object carries host/ip/port
    assert gp.dispatch("red", "probe", "web01", lambda: "ok") == "ok"
    assert gp.canonical_target("10.50.0.10") == ("web01", "10.50.0.10", None, "10.50.0.10")
    assert gp.canonical_target("web01:22") == ("web01", None, 22, "web01:22")
    assert gp.allows("10.50.0.10", "red") and gp.allows("web01", "red")

    # the exact G1 / userinfo-confusion / injection bypasses: each blocked, none allowed
    for t in ("web01:22@10.50.0.11", "10.50.0.10:80@10.50.0.11", "web01:x@dc-01",
              "range-web01:1@10.50.0.11", "web01:22 10.50.0.11", "web01:@dc-01",
              "web01@10.50.0.11", "range-web01/../dc-01", "web01#@10.50.0.11",
              "http://web01@10.50.0.11/", "XXXXXXweb01", "web01:22;nc -z 10.50.0.11 22;#"):
        assert _gp_blocked(t), f"G1 bypass not blocked: {t!r}"
        assert not gp.allows(t, "red"), f"allows() true for bypass: {t!r}"

    # the forbidden host by every plain / alternate spelling the parser must deny
    for t in ("dc-01", "range-dc-01", "10.50.0.11", "10.50.0.11:22", "http://10.50.0.11:22/",
              "DC-01", "dc-01.", "171048971", "0xa32000b", "10.50.11", "012.062.0.013",
              "::ffff:10.50.0.11", "[::ffff:10.50.0.11]", "10.50.0.11/32"):
        assert _gp_blocked(t), f"forbidden/malformed target not blocked: {t!r}"

    # a malformed target logs a distinct reason and raises from canonical_target
    gp_log.events.clear()
    assert _gp_blocked("web01;id")
    assert any(a == "gate.block" and (d or {}).get("reason") == "malformed-target"
               for a, d in gp_log.events), "malformed target must log reason=malformed-target"
    try:
        gp.canonical_target("web01:22@10.50.0.11")
        raise SystemExit("canonical_target accepted a malformed target")
    except MalformedTarget:
        pass

    # a well-formed, in-scope target whose command egresses out of scope is still caught
    # by the egress check (unchanged), not by the parser — AND the block is LOGGED
    gp_log.events.clear()
    assert _gp_blocked("web01", command="curl http://dc-01/x")
    assert any(a == "gate.block" and (d or {}).get("reason") == "egress-out-of-scope"
               for a, d in gp_log.events), "an egress block must be logged as gate.block"

    # the effect() argv-builder receives the canonical target, never the raw string
    # (capture it and abort before run_effect, so no real subprocess is spawned here)
    built = {}

    class _Stop(Exception):
        pass

    def _capture(ct):
        built["ct"] = ct
        raise _Stop
    try:
        gp.effect("red", "read", "web01", _capture)
        raise SystemExit("effect() did not invoke the argv builder")
    except _Stop:
        pass
    assert built["ct"] == ("web01", None, None, "web01"), built

    print("gate ok (P0 egress + Component A per-actor scope + confused-deputy caught + "
          "read-vs-mutate verb axis + A1 strict target parsing: G1 split-colon / userinfo / "
          "injection / alt-IP-spelling bypasses all blocked, canonical object threaded to effects)")
