# Stage 2 — Egress-Parser / Resolver Slip Report

**Oracle:** the OS resolver — `socket.inet_aton` and `socket.getaddrinfo(…,
AI_NUMERICHOST)`, the same libc a real `curl`/`wget` hands the string to.
Computed independently of the gate's own canonicalizer → a true differential
(gate-canon vs OS). No DNS, no packet leaves the box (IP-literal arithmetic +
`AI_NUMERICHOST` forbids name lookup).

Re-derive:

```bash
python scripts/mediation/parser_fuzz.py            # grammar corpus
python scripts/mediation/parser_fuzz.py --selftest  # + 200 bounded fuzz (make test)
python scripts/mediation/parser_fuzz.py --json      # full per-string rows
```

Full rows: `docs/mediation/parser_slip.json`.

## Raw oracle output (verbatim)

```
[OS oracle: inet_aton + getaddrinfo(AI_NUMERICHOST)]  exhausted corpus = 65 adversarial strings
  slip surface by class (gate ALLOWED / total):
    cmdsub      6/6
    concat      3/3
    direct      0/12
    flags       0/6
    ipenc       3/5
    mangle      0/12
    proto       0/9
    quote       6/6
    var         6/6
  parser-incomplete slips (shell expansion; backstop catches): 21
  resolver disagreements (inet_aton != getaddrinfo): 0
  TRUE BYPASSES (gate allows; OS routes out of scope): 3
      [BYPASS] (ipenc) curl http://2887122948/  aton=172.22.0.4 gai=172.22.0.4
      [BYPASS] (ipenc) curl http://0xac160004/  aton=172.22.0.4 gai=172.22.0.4
      [BYPASS] (ipenc) curl http://[::ffff:172.22.0.4]/  aton=172.22.0.4 gai=172.22.0.4
  false positives (in-scope wrongly blocked): 0
```

> **Corrected after the live range boot (Stage 3).** The out-of-scope decoy is
> really **172.22.0.4** (`range_oos` = 172.22.0.0/16); an earlier draft used
> `172.20.0.9`, but 172.20.0.0/16 turned out to be the **in-scope** `range`
> block — so that encoding was not even out-of-scope. The kernel measurement
> caught it. Encodings are now generated from the real decoy IP, and
> **Stage 3 confirms 172.22.0.4 is unreachable from the entry** (L3+L4), so
> these bypasses hit a wall at the network.

## The slip surface, quantified (not an anecdote)

Of the 65-string hand grammar, the gate parser lets through 24 (37%). Split by
the honest distinction the brief demands:

- **Caught (0 allowed):** `direct`, `mangle` (uppercase / tab / trailing dot /
  comment), `flags` (`--url`, `-- http://…`), `proto` (`/dev/tcp`, `socat`,
  inline `urllib`). Every form carrying a literal host **or a dot** is
  canonicalised and default-denied.
- **Parser-incomplete slips — 21, characterised, NOT a failure:** `var`
  (`$H`), `cmdsub` (`$(echo …)`, backticks), `concat` (`${D}${E}`), `quote`
  (`de''coy`, `de\coy`). The parser sees the *literal*, not the shell-expanded
  value; it structurally cannot resolve a value the shell computes at runtime.
  **The parser was never the guarantee** — the network-isolation backstop (both
  range segments `internal: true`, out-of-scope hosts unroutable) is. Stage 3
  confirms that backstop from the kernel.

## True parser bypasses — 3 (named findings, surfaced not retried away)

A **true bypass** = the gate ALLOWS the string AND the OS resolves its real
target out of scope (the 172.20/16 range block). All three are dotless numeric
encodings the gate's `_is_real_target` rejects (no dot ⇒ "not a host"), but libc
resolves to the out-of-scope IP:

| Class | Command | `inet_aton` | `getaddrinfo` |
|-------|---------|-------------|---------------|
| ipenc | `curl http://2887122948/` (decimal) | 172.22.0.4 | 172.22.0.4 |
| ipenc | `curl http://0xac160004/` (hex) | 172.22.0.4 | 172.22.0.4 |
| ipenc | `curl http://[::ffff:172.22.0.4]/` (v6-mapped) | 172.22.0.4 | 172.22.0.4 |

These are genuine gaps **in the parser layer**. They are caught by the network
backstop — **Stage 3 measured that 172.22.0.4 (the decoy) is kernel-unreachable
from the entry at L3 and L4** — which is why the floor holds; but as *parser*
findings they are real and recorded. A minimal parser hardening (does not touch the frozen gate — would be
a wrapper or a future gate revision): treat a dotless all-numeric / `0x…` /
bracketed-v6 host token as a real target and canonicalise it through
`inet_aton` before the scope check.

## A note on the oracle itself: the OS has more than one answer

During search the two libc resolvers **disagree** on octal dotted-quads:
`0254.0024.0.011` → `inet_aton` 172.20.0.9 (octal) vs `getaddrinfo` 254.24.0.11
(decimal). It does not surface as a bypass here because any dotted form is
already caught by the gate — but it sharpens the thesis: "what the OS routes to"
is *resolver/tool-dependent*, so a string parser can never be complete against
every tool an attacker might use. Only the layer that sees the post-resolution
packet (the network segment / the kernel) is the guarantee. That is precisely
what Stage 3 measures.

## Also discovered: a label bug in the (non-frozen) seed corpus

`redteam/redteam_egress.py` labels `2886864905` as "decoy-as-decimal-ip", but
libc resolves it to **172.18.16.9**, not the decoy's 172.20/16 block. The OS
oracle caught the mislabel; this harness generates decimal/hex from
`ipaddress.ip_address` so its encodings are correct by construction. (Left as a
note — `redteam/` is outside the frozen nine; fix separately if desired.)

## Verdict

`make test` fails only on a **false positive** (an in-scope command wrongly
blocked — a correctness break). There are **0**. True bypasses and
parser-incomplete slips are recorded findings, not build breaks: the parser is
defence-in-depth, the network backstop is the guarantee, and the kernel (Stage
3) is the oracle that confirms it physically.
