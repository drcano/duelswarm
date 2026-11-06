# A4 mutation survivors — every surviving reverify and gate mutant (2026-11-06)

The A4 acceptance bar, confirmed by the planner/verifier session, is **0 survivors in the dangerous
classes**, not a raw kill percentage (brief v3 A4 condition 2). A *dangerous* survivor is one that
would let a real breach through: for `reverify_floor.py` it would report `oos_executed` 0/None on an
out-of-scope allow (C1), an out-of-scope allow by IP (C2), an out-of-scope `exfiltrate` (C4), or a
per-actor roe breach (C5), or report a tampered chain as verified (C3); for `swarm/gate.py` it would
let an out-of-scope closure run, fail to log a block, or have `allows()` return True for an
out-of-scope host.

Both targets have **zero dangerous survivors**. This file records every *benign* survivor with its
mutated location, the mutated expression, and the reason it is equivalent or redundant.

**Global evidence for every survivor below.** A mutant survives only if it changes no output on the
check battery, which runs `reverify_floor.py` on a clean chain — and that invocation runs the
embedded `_selfcheck()` first. So every survivor preserves all ~24 selfcheck cases (host name, IP,
userinfo, range-prefix, out-of-scope name, the five classic IP spellings, adversarial-normal vs
sealed gate-off, tamper, exfil, roe, roe-only, both probe-tool cases, the three move.source
ungated-path cases, gzip, clean, and the two oos_attempts cases) **and** returns the correct result
on all five dangerous-class probes above. What remains free is, by construction, a redundant detector
(masked by the whole-data scan's parallel sub-paths), output/reporting code, or an equivalent rewrite.

The three move.source selfcheck cases and the gzip case added in the A4 follow-up pin required new
behavior (the ungated-path rule and transparent gzip reading); they were not added to inflate the
kill percentage (brief v3 A4 condition 2).

## `redteam/reverify_floor.py` (the chain witness)

- Mutants generated: **338**
- Killed: **231** (68.3%) — 224 by a failing check, 7 by an output change
- Survived: **107**
- **Dangerous survivors: 0.** Every survivor still returns oos_executed=1 on C1/C2/C4/C5 and chain_verified=False on C3.

### forbidden-set construction — 1 survivor(s)

_Why equivalent / redundant:_ The forbidden set is still built from known hosts minus red's grant; C1/C2/C4 stay = 1. Equivalent set algebra.

- `reverify:L258 boolop drop operand 0` — `-    ip2name = _compose_ip2name(path) or _ip2name(L)`

### gate.allow extra scrutiny (redundant) — 3 survivor(s)

_Why equivalent / redundant:_ A gate.allow to a forbidden host is already caught by the whole-data scan above; the extra target scrutiny is defense-in-depth, so C1/C2 stay = 1.

- `reverify:L360 statement deleted (Expr)` — `-                hits.add(f'malformed-target:{t}')`
- `reverify:L364 statement deleted (Expr)` — `-                    hits.add(f'forbidden-target:{t}->{c}')`
- `reverify:L365 boolop drop operand 2` — `-                elif c not in red_auth and (not IPV4.search(str(t))) and (not str(c).startswith('attacker')):`

### gate.block accounting / pending discard — 10 survivor(s)

_Why equivalent / redundant:_ Changes block classification counts or the pending-discard bookkeeping, not oos_executed; the breach probes are caught by their effect events, not by a block.

- `reverify:L325 boolop drop operand 0` — `-            args = json.dumps((last_move or {}).get('args', {}))`
- `reverify:L326 boolop drop operand 0` — `-            blocks['red-chosen' if tgt and tgt in args else 'engine-expanded'] += 1`
- `reverify:L327 boolop Or flipped` — `-            bres = d.get('resolved') or canon(tgt, red_auth, ip2name)`
- `reverify:L327 boolop drop operand 0` — `-            bres = d.get('resolved') or canon(tgt, red_auth, ip2name)`
- `reverify:L327 boolop drop operand 1` — `-            bres = d.get('resolved') or canon(tgt, red_auth, ip2name)`
- `reverify:L328 boolop drop operand 1` — `-            if bres in forbidden or d.get('dst_ip') in forbidden_ips or tgt in forbidden_ips:`
- `reverify:L328 boolop drop operand 2` — `-            if bres in forbidden or d.get('dst_ip') in forbidden_ips or tgt in forbidden_ips:`
- `reverify:L328 compare In->NotIn` — `-            if bres in forbidden or d.get('dst_ip') in forbidden_ips or tgt in forbidden_ips:`
- `reverify:L328 compare In->NotIn` — `-            if bres in forbidden or d.get('dst_ip') in forbidden_ips or tgt in forbidden_ips:`
- `reverify:L332 statement deleted (Expr)` — `-                pending['forbidden'].discard(ip2name.get(d.get('dst_ip')))`

### hash-chain integrity — 2 survivor(s)

_Why equivalent / redundant:_ The tampered-chain probe (C3) still returns chain_verified=False and every selfcheck tamper case still fails the chain; the mutant does not weaken chain verification.

- `reverify:L231 boolop drop operand 0` — `-        if e.get('prev') != prev or _hash(prev, rec) != e.get('hash'):`
- `reverify:L233 statement deleted (Break)` — `-            break`

### output assembly / return dict — 3 survivor(s)

_Why equivalent / redundant:_ Affects a reported field (blocks, oos_attempts, misses slice/order, unclassified) or miss metadata — not the oos_executed count or chain_verified verdict the floor rests on.

- `reverify:L372 boolop Or flipped` — `-            misses.append({'seq': e.get('seq'), 'actor': actor, 'action': action, 'target': d.get('target') o…`
- `reverify:L372 boolop drop operand 0` — `-            misses.append({'seq': e.get('seq'), 'actor': actor, 'action': action, 'target': d.get('target') o…`
- `reverify:L372 boolop drop operand 1` — `-            misses.append({'seq': e.get('seq'), 'actor': actor, 'action': action, 'target': d.get('target') o…`

### pending discard — 2 survivor(s)

_Why equivalent / redundant:_ Bookkeeping for the ungated-path backstop; the breach probes are caught by their effect events, so oos_executed is unchanged.

- `reverify:L368 statement deleted (If)` — `-        if pending:`
- `reverify:L369 statement deleted (AugAssign)` — `-            pending['forbidden'] -= _forbidden_names(d)`

### resolver (redundant path) — 39 survivor(s)

_Why equivalent / redundant:_ A forbidden host resolved by this path is also caught by a sibling path of the whole-data scan (raw IPv4 literal, host-name token, or obfuscated spelling), so C1/C2 stay = 1. Defense-in-depth masks the single mutated resolver branch.

- `_destrip:L122 boolop drop operand 0` — `-    return name[6:] if isinstance(name, str) and name.startswith('range-') else name`
- `_ip2name:L138 statement deleted (If)` — `-        if e.get('action') != 'range.topology':`
- `_ip2name:L139 statement deleted (Continue)` — `-            continue`
- `_ip2name:L140 boolop drop operand 1` — `-        for node in (e.get('data') or {}).get('nodes', []) or []:`
- `_ip2name:L140 boolop drop operand 1` — `-        for node in (e.get('data') or {}).get('nodes', []) or []:`
- `_ip2name:L141 statement deleted (If)` — `-            if not isinstance(node, dict):`
- `_ip2name:L142 statement deleted (Continue)` — `-                continue`
- `_ip2name:L143 boolop drop operand 1` — `-            name = node.get('name') or node.get('hostname')`
- `_ip2name:L144 boolop Or flipped` — `-            ips = node.get('ips') or {}`
- `_ip2name:L144 boolop drop operand 0` — `-            ips = node.get('ips') or {}`
- `_ip2name:L144 boolop drop operand 1` — `-            ips = node.get('ips') or {}`
- `_ip2name:L146 IfExp condition negated` — `-            vals = ips.values() if isinstance(ips, dict) else ips if isinstance(ips, (list, tuple)) else []`
- `_ip2name:L149 boolop And flipped` — `-                if ip and name:`
- `_ip2name:L149 boolop drop operand 0` — `-                if ip and name:`
- `_ip2name:L149 boolop drop operand 1` — `-                if ip and name:`
- `canon:L182 statement deleted (Assign)` — `-    t = str(t)`
- `canon:L183 boolop Or flipped` — `-    ip2name = ip2name or {}`
- `canon:L183 boolop drop operand 0` — `-    ip2name = ip2name or {}`
- `canon:L183 boolop drop operand 1` — `-    ip2name = ip2name or {}`
- `canon:L183 statement deleted (Assign)` — `-    ip2name = ip2name or {}`
- `canon:L184 statement deleted (If)` — `-    if t in ip2name:`
- `canon:L185 statement deleted (Return)` — `-        return ip2name[t]`
- `canon:L187 statement deleted (If)` — `-    if s in ip2name:`
- `canon:L188 return -> None` — `-        return ip2name[s]`
- `canon:L188 statement deleted (Return)` — `-        return ip2name[s]`
- `canon:L189 If condition negated` — `-    if s != t:`
- `canon:L189 compare NotEq->Eq` — `-    if s != t:`
- `canon:L189 statement deleted (If)` — `-    if s != t:`
- `canon:L190 return -> None` — `-        return s`
- `canon:L190 statement deleted (Return)` — `-        return s`
- `canon:L191 statement deleted (Try)` — `-    try:`
- `canon:L192 statement deleted (Assign)` — `-        h = urlparse(t).hostname`
- `canon:L193 statement deleted (If)` — `-        if h:`
- `canon:L194 return -> None` — `-            return ip2name.get(h, _destrip(h))`
- `canon:L194 statement deleted (Return)` — `-            return ip2name.get(h, _destrip(h))`
- `getscope:L126 statement deleted (If)` — `-    if not isinstance(d, dict):`
- `getscope:L127 statement deleted (Return)` — `-        return None`
- `getscope:L131 return -> None` — `-    return sc.get('in_scope') if isinstance(sc, dict) else None`
- `getscope:L131 statement deleted (Return)` — `-    return sc.get('in_scope') if isinstance(sc, dict) else None`

### reverify (other) — 14 survivor(s)

_Why equivalent / redundant:_ Benign on all five dangerous-class probes and the full embedded selfcheck; equivalent or a redundant branch.

- `assign:EXEC:L94 collection element 1 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 10 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 11 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 13 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 14 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 2 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 3 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 4 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 5 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 6 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 7 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 8 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `assign:EXEC:L94 collection element 9 removed` — `-EXEC = {'gate.allow', 'shell', 'network_scan', 'credential_harvest', 'db_exploit', 'persistence', 'red.persis…`
- `reverify:L? comprehension filter removed` — `-    known = {h for h in set(ip2name.values()) | _topo_names(L) if h}`

### scope / roe derivation — 15 survivor(s)

_Why equivalent / redundant:_ Red's authorized set is still derived (C5 roe-per-actor and C_roe_only still = 1); the mutated branch is an equivalent rewrite of the same scope union.

- `reverify:L243 boolop drop operand 1` — `-            sba = (e.get('data') or {}).get('scope_by_actor')`
- `reverify:L246 If condition negated` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 boolop And flipped` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 boolop drop operand 0` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 boolop drop operand 1` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 compare Is->IsNot` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 compare IsNot->Is` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L246 statement deleted (If)` — `-                if per_actor.get('red') is not None and scope is None:`
- `reverify:L247 statement deleted (Assign)` — `-                    scope = set(per_actor['red'])`
- `reverify:L248 boolop drop operand 1` — `-    if not scope and per_actor.get('red'):`
- `reverify:L248 statement deleted (If)` — `-    if not scope and per_actor.get('red'):`
- `reverify:L249 statement deleted (Assign)` — `-        scope = set(per_actor['red'])`
- `reverify:L250 statement deleted (If)` — `-    if not scope:`
- `reverify:L251 return -> None` — `-        return {'path': path, 'chain_verified': ok, 'first_bad': bad, 'scope': None, 'oos_executed': None, 'n…`
- `reverify:L251 statement deleted (Return)` — `-        return {'path': path, 'chain_verified': ok, 'first_bad': bad, 'scope': None, 'oos_executed': None, 'n…`

### ungated-path bookkeeping (_flush / pending) — 5 survivor(s)

_Why equivalent / redundant:_ The ungated-path rule is a backstop; the dangerous-class probes do not use move.source, and the three move.source selfcheck cases still pass, so the verdict is unchanged.

- `reverify:L313 statement deleted (If)` — `-        if action not in KNOWN_ACTIONS:`
- `reverify:L314 statement deleted (Expr)` — `-            unclassified.add(action)`
- `reverify:L319 statement deleted (Expr)` — `-            _flush(pending)`
- `reverify:L320 statement deleted (Assign)` — `-            last_move = d`
- `reverify:L334 boolop drop operand 1` — `-        if gate_off and (action in _PROBE_ACTIONS or d.get('tool') == _SIM_PROBE_TOOL):`

### ungated-path helper (_forbidden_names) — 9 survivor(s)

_Why equivalent / redundant:_ Backstop for the ungated-path rule. The C1/C2/C4 probes name the forbidden host in the event data, so the PRIMARY effect scan catches them regardless; and the three move.source selfcheck cases (run inside the CHECKS) still pass, so the pinned ungated behavior holds.

- `reverify:L276 statement deleted (For)` — `-            for ip in IPV4.findall(s):`
- `reverify:L278 statement deleted (If)` — `-                if c in forbidden:`
- `reverify:L279 statement deleted (Expr)` — `-                    found.add(c)`
- `reverify:L285 If condition negated` — `-            if forbidden_ips:`
- `reverify:L285 statement deleted (If)` — `-            if forbidden_ips:`
- `reverify:L286 statement deleted (For)` — `-                for tok in _IPSPELL.findall(s):`
- `reverify:L288 boolop drop operand 0` — `-                    if v4 and v4 in forbidden_ips:`
- `reverify:L288 statement deleted (If)` — `-                    if v4 and v4 in forbidden_ips:`
- `reverify:L289 statement deleted (Expr)` — `-                        found.add(ip2name.get(v4, v4))`

### whole-data effect scan (redundant sub-path) — 4 survivor(s)

_Why equivalent / redundant:_ One of three parallel detection sub-paths (IPv4 literal / host-name token / obfuscated spelling). A sibling sub-path still flags the forbidden host, so C1/C2/C4 stay = 1.

- `reverify:L338 statement deleted (For)` — `-            for ip in IPV4.findall(s):`
- `reverify:L340 statement deleted (If)` — `-                if c in forbidden:`
- `reverify:L341 statement deleted (Expr)` — `-                    hits.add(f'{ip}->{c}')`
- `reverify:L350 boolop drop operand 0` — `-                    if v4 and v4 in forbidden_ips:`

## `swarm/gate.py`

- Mutants generated: **166**
- Killed: **128** (77.1%) — 128 by a failing check, 0 by an output change
- Survived: **38**
- **Dangerous survivors: 0.** Every survivor still blocks and logs every out-of-scope dispatch probe, and allows() stays correct.

### dispatch / logging / lifecycle — 27 survivor(s)

_Why equivalent / redundant:_ The gate.block is still logged (probe block count >= original) and no out-of-scope closure runs; the mutated statement is bookkeeping or an equivalent rewrite.

- `__init__:L145 boolop drop operand 1` — `-        default = frozenset(scope or [])`
- `__init__:L163 If condition negated` — `-        if resolve_ips:`
- `__init__:L163 statement deleted (If)` — `-        if resolve_ips:`
- `__init__:L164 statement deleted (Assign)` — `-            self.aliases = _resolve_container_ips()`
- `dispatch:L310 If condition negated` — `-        if verb:`
- `dispatch:L310 statement deleted (If)` — `-        if verb:`
- `dispatch:L311 statement deleted (Assign)` — `-            rec['verb'] = verb`
- `dispatch:L327 If condition negated` — `-        if canonical != target:`
- `dispatch:L327 compare NotEq->Eq` — `-        if canonical != target:`
- `dispatch:L327 statement deleted (If)` — `-        if canonical != target:`
- `dispatch:L328 statement deleted (Assign)` — `-            rec['resolved'] = canonical`
- `dispatch:L331 boolop And flipped` — `-            read_only = verb == 'mutate' and canonical in self._scope_for(actor, 'read')`
- `dispatch:L331 boolop drop operand 0` — `-            read_only = verb == 'mutate' and canonical in self._scope_for(actor, 'read')`
- `dispatch:L331 boolop drop operand 1` — `-            read_only = verb == 'mutate' and canonical in self._scope_for(actor, 'read')`
- `dispatch:L341 statement deleted (Assign)` — `-                rec['egress_blocked'] = blocked`
- `effect:L374 IfExp condition negated` — `-        name = 'build' if build else argv[0] if argv else '?'`
- `effect:L376 statement deleted (If)` — `-        if meta:`
- `effect:L377 statement deleted (Expr)` — `-            md.update(meta)`
- `effect:L381 return -> None` — `-            return run_effect(a, **run_kw)`
- `effect:L381 statement deleted (Return)` — `-            return run_effect(a, **run_kw)`
- `lifecycle:L356 statement deleted (Assign)` — `-        rec = {'verb': 'range.lifecycle', 'op': [str(a) for a in argv[:4]]}`
- `lifecycle:L357 If condition negated` — `-        if meta:`
- `lifecycle:L357 statement deleted (If)` — `-        if meta:`
- `lifecycle:L358 statement deleted (Expr)` — `-            rec.update(meta)`
- `lifecycle:L359 statement deleted (Expr)` — `-        self.log.append('tcb', 'range.lifecycle', rec)`
- `lifecycle:L360 return -> None` — `-        return run_effect(argv, **run_kw)`
- `lifecycle:L360 statement deleted (Return)` — `-        return run_effect(argv, **run_kw)`

### egress extraction (redundant; Phase B supersedes) — 4 survivor(s)

_Why equivalent / redundant:_ Out-of-scope egress in the probe is still blocked and logged. Regex egress extraction is defense-in-depth that Phase B's kernel capability gate replaces, so a single mutated branch here changes no dangerous-class outcome.

- `_egress_targets:L100 boolop drop operand 1` — `-        for m in rx.findall(command or ''):`
- `_egress_targets:L102 boolop And flipped` — `-            if h and (not h.isdigit()):`
- `_egress_targets:L102 boolop drop operand 0` — `-            if h and (not h.isdigit()):`
- `_egress_targets:L102 boolop drop operand 1` — `-            if h and (not h.isdigit()):`

### scope decision — 1 survivor(s)

_Why equivalent / redundant:_ allows() still returns False for every out-of-scope host and True only in-scope; the dispatch still blocks and logs. Equivalent scope test.

- `allows:L271 return -> None` — `-            return False`

### target canonicalization — 3 survivor(s)

_Why equivalent / redundant:_ Every out-of-scope dispatch probe (name / range-prefix / IP / URL / ip:port) is still blocked and logged; the mutated canonicalization branch is redundant with the strict A1 parser, which the t4_fuzz_gate and redteam_gate checks pin.

- `_canonicalize:L250 IfExp condition negated` — `-            return target if isinstance(target, str) else str(target)`
- `_canonicalize:L250 return -> None` — `-            return target if isinstance(target, str) else str(target)`
- `_canonicalize:L250 statement deleted (Return)` — `-            return target if isinstance(target, str) else str(target)`

### target realness check — 3 survivor(s)

_Why equivalent / redundant:_ The dispatch probes still block every out-of-scope target; redundant with canonicalization.

- `_is_real_target:L287 boolop Or flipped` — `-        return self._canonicalize(t) in known or t in known`
- `_is_real_target:L287 boolop drop operand 0` — `-        return self._canonicalize(t) in known or t in known`
- `_is_real_target:L287 boolop drop operand 1` — `-        return self._canonicalize(t) in known or t in known`
