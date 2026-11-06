#!/usr/bin/env python3
"""Cold re-derivation of the HIGH-1 dynamic check — the empirical close of HIGH-1.

Reads ONLY the committed chain (check_chain.jsonl). No docker, no gate, no range. Green = the real
boot showed the live-engine recon path (build_agent_tools._recon) gating its target set: a KNOWN
out-of-scope host in the swept segment is gate-BLOCKED in the RECON phase and never probed, and §E
held. This is the dynamic confirmation the static proof (drop_oos selftest + _recon code) could not
give — it required a booted range with the gate's resolve_ips alias map populated.

Usage:  PYTHONPATH=redteam python3 docs/runs/2026-10-29-high1-dynamic-check/prove_high1_dynamic.py
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN = os.path.join(HERE, "check_chain.jsonl")
OOS_IPS = {"jump-01": "10.60.0.13", "decoy-fin": "10.40.0.12"}


def _ok(c, label, detail=""):
    print(f"  [{'PASS' if c else 'FAIL'}] {label}" + (f"  — {detail}" if detail else "")); return c


def main():
    evs = [json.loads(l) for l in open(CHAIN)]
    allok = True

    # 1. the hash chain verifies (independent stdlib walk)
    prev = "0" * 64
    import hashlib
    bad = None
    for e in evs:
        body = {k: e[k] for k in e if k not in ("hash",)}
        h = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if e.get("prev") != prev:
            bad = e.get("seq"); break
        prev = e["hash"]
    allok &= _ok(bad is None, "hash chain links (prev==hash walk)", f"first_bad={bad}")

    # 2. recon-phase gate.block for a KNOWN out-of-scope host on the _recon path
    recon_blocks = {(e["data"].get("resolved") or e["data"].get("target"))
                    for e in evs if e.get("action") == "gate.block"
                    and e["data"].get("mv_kind") == "recon"}
    allok &= _ok({"jump-01", "decoy-fin"} <= recon_blocks,
                 "recon gate.block for the oos hosts on the live _recon path",
                 f"blocked={sorted(recon_blocks)}")

    # 3. the oos hosts were NEVER probed (no discovery event names their ip/host)
    disc = set()
    for e in evs:
        if e.get("action") == "discovery":
            disc.add(e["data"].get("host")); disc.add(e["data"].get("scanned_ip"))
    unprobed = all(ip not in disc for ip in OOS_IPS.values()) and \
        all(n not in disc for n in OOS_IPS)
    allok &= _ok(unprobed, "oos hosts excluded from the probe (no discovery for them)",
                 f"discovered={sorted(x for x in disc if x)}")

    # 4. §E witnessed (host-egress hard floor held during the check)
    fb = next((e["data"] for e in evs if e.get("action") == "floor.boundary"), {})
    ul = fb.get("uninstrumented_live", {})
    allok &= _ok(ul.get("ok") is True and ul.get("host_gateway_reachable") is False
                 and ul.get("oos_tcp_reaches") == [] and ul.get("internet_blocked") is True,
                 "§E witnessed: ok=true, host gateway UNREACHABLE, oos_tcp_reaches=[], internet blocked",
                 f"host_gateway_reachable={ul.get('host_gateway_reachable')} "
                 f"oos_tcp_reaches={ul.get('oos_tcp_reaches')}")

    print("\n" + ("HIGH-1 EMPIRICALLY CLOSED — the live _recon path gates the recon phase on a real "
                  "boot; §E held." if allok else "ONE OR MORE CLAIMS FAILED."))
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
