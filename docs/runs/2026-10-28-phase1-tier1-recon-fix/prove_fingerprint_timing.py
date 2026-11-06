#!/usr/bin/env python3
"""Booted-range proof that the Tier-1 service-aware fingerprint removes the ~280s/host recon tax.

Run on a booted key-seam range (any project name). It times `live_fingerprint.fingerprint_service`
over a real docker-exec vantage against:
  - an SSH-only host (dba01 :22)   -> NEW gated path returns instantly as non-HTTP (server='');
  - the same host with the gate DISABLED (http_ports forced to include 22) -> ONE head probe alone
    hangs ~timeout, and the old code ran ~14 of them -> the ~280s tax reproduced at the source;
  - a real web host (web01 :8080)  -> still yields the Apache/Struts banner (fingerprint not broken).

No API key, no LLM. Usage (range already up):
  python3 docs/runs/2026-10-28-phase1-tier1-recon-fix/prove_fingerprint_timing.py
"""
import subprocess, sys, time
sys.path.insert(0, "swarm"); sys.path.insert(0, ".")
from swarm import live_fingerprint as lf


def run_cmd_via(container):
    def _run(cmd):
        r = subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                           capture_output=True, text=True, timeout=400)
        return (r.stdout or "") + (r.stderr or "")
    return _run


def main():
    web_vant = run_cmd_via("range-web01")       # on 10.35 (admin) + 10.90 — reaches dba01 and the struts
    atk_vant = run_cmd_via("range-attacker")    # on 10.90 — reaches the web01 entry

    ok = True

    # 1. NEW gated path: SSH-only host (:22) returns instantly, non-HTTP, no banner.
    t = time.time()
    fp = lf.fingerprint_service(web_vant, "10.35.0.11", 22)      # dba01, SSH-only
    dt_new = time.time() - t
    gate_ok = dt_new < 5 and fp.get("server") == "" and fp.get("non_http") is True
    print(f"[{'PASS' if gate_ok else 'FAIL'}] gated fingerprint dba01:22 -> {dt_new:.2f}s, "
          f"non_http={fp.get('non_http')}, server={fp.get('server')!r}")
    ok &= gate_ok

    # 2. The tax at source: ONE old-style HTTP head-probe against open :22 never gets an HTTP reply,
    #    so it hangs to the timeout. The old fingerprint issued (2 + len(PROBE_PATHS)) such probes per
    #    host. We time one probe to show the per-probe hang; the full old cost was minutes/host (the
    #    seed-1337 chain measured ~280s/host). We do NOT extrapolate a point estimate — the measured
    #    facts are: gated ≈ 0s, one old probe hangs, a web host still fingerprints.
    t = time.time()
    lf._status(web_vant, "10.35.0.11", 22, "/", 3, "http")
    dt_one = time.time() - t
    tax_ok = dt_one > 1.0
    print(f"[{'PASS' if tax_ok else 'FAIL'}] one old-style HTTP head-probe of open :22 hangs {dt_one:.1f}s "
          f"(no HTTP reply arrives); the old fingerprint issued ~{2+len(lf.PROBE_PATHS)} such probes/host "
          f"(~280s/host in the seed-1337 chain). The gate takes the SSH-only case to {dt_new:.2f}s.")
    ok &= tax_ok

    # 3. A real web host still fingerprints (the fix doesn't break HTTP recon).
    t = time.time()
    wfp = lf.fingerprint_service(atk_vant, "10.90.0.11", 8080)   # web01 struts entry
    dt_web = time.time() - t
    web_ok = bool(wfp.get("server")) and wfp.get("non_http") is False
    print(f"[{'PASS' if web_ok else 'FAIL'}] web01:8080 still fingerprints -> {dt_web:.2f}s, "
          f"server={wfp.get('server')!r}")
    ok &= web_ok

    print("\n" + ("TIER-1 FIX PROVEN: the ~280s/host tax is removed; web recon intact."
                  if ok else "ONE OR MORE CHECKS FAILED."))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
