"""Shell-safety for the live tools (brief v3 A2).

The one effect primitive is `gate.run_effect(argv)`, but several tools must hand a command
STRING to a shell (`docker exec C sh -c <cmd>`, `bash -c <cmd>`, a `/dev/tcp` probe, an earned
`exec_fn` that runs under `/bin/bash -c`). Whenever an agent-supplied value is interpolated into
such a string it must be inert:

  - a TARGET host/IP uses `host()` — it must be a bare host name or dotted-quad IPv4 (no port, no
    metacharacter), the same grammar the gate's `_parse_target` enforces, so there is nothing to
    inject; an unclean value raises and the caller drops the probe rather than running it;
  - a PORT uses `port()` — coerced to an int in 1..65535;
  - ANY other agent string (a path, user, password, key path, domain, NT hash, remote command)
    uses `arg()` = `shlex.quote`, so it is a single inert shell token.

This mirrors the gate grammar on purpose: it is defence-in-depth ENFORCEMENT downstream of the
gate, not the floor auditor (which, per A4, must keep an INDEPENDENT parser). Prefer an argv list
over a shell string wherever the command needs no shell features; use these only where a shell is
unavoidable.
"""
import ipaddress
import re
import shlex

# Same host grammar as swarm.gate._parse_target: dot-separated labels of [A-Za-z0-9_-], 1..63 each,
# not starting/ending with '-'. (Underscore is allowed because scope labels use it.)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$"
)


class UnsafeValue(ValueError):
    """An agent-supplied value that cannot be made a safe bare host / port."""


def is_host(value):
    """True iff `value` is a bare host name or dotted-quad IPv4 (no port, no metacharacter)."""
    s = str(value)
    try:
        ipaddress.IPv4Address(s)
        return True
    except (ipaddress.AddressValueError, ValueError):
        pass
    return bool(_HOST_RE.match(s)) and not ("." not in s and s.isdigit())


def host(value):
    """Return `value` iff it is a bare host/IPv4 the shell cannot misread; else raise UnsafeValue.
    A scan/lateral target that is not a clean host/IP is dropped, never interpolated into a shell."""
    if is_host(value):
        return str(value)
    raise UnsafeValue(f"not a bare host/IPv4: {value!r}")


def port(value):
    """Return `value` as an int in 1..65535; else raise UnsafeValue."""
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise UnsafeValue(f"not an integer port: {value!r}")
    if not (1 <= p <= 65535):
        raise UnsafeValue(f"port out of range: {value!r}")
    return p


def arg(value):
    """shlex.quote an arbitrary agent string into a single inert shell token."""
    return shlex.quote(str(value))


if __name__ == "__main__":
    # bare hosts / IPs accepted
    for ok in ("web01", "db-bastion", "attacker_c2", "10.50.0.10", "dc-01"):
        assert is_host(ok) and host(ok) == ok, ok
    # everything a target bypass / injection would carry is rejected as a host
    # rejected: anything carrying a shell metacharacter, a port, a path, or an all-digit non-IPv4
    # label. (A clean alnum token like "0xa32000b" is shell-INERT, so host() accepts it; the gate,
    # not shellsafe, is what denies it on scope — shellsafe only guarantees it cannot inject.)
    for bad in ("web01:22@10.50.0.11", "10.50.0.5;id", "web01 10.50.0.11", "a;b", "$(id)",
                "10.50.0.11:22", "http://x/", "171048971", "a|b", "`id`", "x/../y",
                "web01;touch /tmp/PWNED;#"):
        assert not is_host(bad), bad
        try:
            host(bad)
            raise SystemExit(f"host() accepted an unsafe value: {bad!r}")
        except UnsafeValue:
            pass
    # ports
    assert port("80") == 80 and port(443) == 443
    for bad in ("0", "70000", "22;id", "", None, "8080x"):
        try:
            port(bad)
            raise SystemExit(f"port() accepted {bad!r}")
        except UnsafeValue:
            pass
    # arg() makes an injection a single inert token
    assert arg("a; rm -rf /") == "'a; rm -rf /'"
    assert arg("pw'; id") == "'pw'\"'\"'; id'"
    import shlex as _s
    for v in ("a; rm -rf /", "pw'; id", "/etc/x; rm", "$(id)", "`id`"):
        assert _s.split(arg(v)) == [v], (v, arg(v))   # quotes back to exactly one token
    print("shellsafe ok (bare host/IPv4 grammar; int ports; shlex.quote for arbitrary agent "
          "strings — every injection payload becomes a single inert token or is rejected)")
