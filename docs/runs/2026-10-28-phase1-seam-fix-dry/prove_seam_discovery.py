"""FREE booted-range proof of the seam discovery fix (#1) — no API key, no spend, Docker only.

On the REAL 20-host range, show the premise the fix relies on and that the old entry-pinned scan
could never satisfy:
  (a) dba01 is multi-homed onto the mgmt segment 10.60 (own_subnets(range-dba01) includes it);
  (b) a scan FROM range-dba01 over 10.60 discovers db-bastion (10.60.0.11 answers on 22) — the
      hop-2 target the paid seed-1337 run never saw;
  (c) web01 (the entry) is NOT on 10.60 and a scan FROM range-web01 over 10.60 finds nothing —
      so only the dba01 vantage reveals it. This is exactly what t_scan now enumerates.

Run AFTER the range is booted (range containers named range-<host>).
"""
import sys, ipaddress
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from swarm import live_red

MGMT = "10.60.0.0/24"
BASTION = "10.60.0.11"

def nets(container):
    return [str(n) for n in live_red.own_subnets(container)]

web_nets = nets("range-web01")
dba_nets = nets("range-dba01")
print(f"range-web01 interfaces: {web_nets}")
print(f"range-dba01 interfaces: {dba_nets}")

# (a) dba01 sits on the mgmt segment; web01 does not.
dba_on_mgmt = any(ipaddress.ip_network(n) == ipaddress.ip_network(MGMT) for n in dba_nets)
web_on_mgmt = any(ipaddress.ip_network(n) == ipaddress.ip_network(MGMT) for n in web_nets)
assert dba_on_mgmt, f"(a) FAIL: dba01 not on mgmt {MGMT}; nets={dba_nets}"
assert not web_on_mgmt, f"(a) FAIL: web01 unexpectedly on mgmt {MGMT}; nets={web_nets}"
print(f"(a) OK: dba01 IS on {MGMT}; web01 is NOT")

# (b) a scan FROM dba01 over mgmt discovers db-bastion.
from_dba = live_red.scan_subnet("range-dba01", MGMT, ports=(22,), lo=1, hi=32)
print(f"(b) scan FROM range-dba01 over {MGMT}: {from_dba}")
assert BASTION in from_dba, f"(b) FAIL: db-bastion {BASTION} not discovered from dba01; got {from_dba}"
print(f"(b) OK: db-bastion {BASTION} answers on 22 FROM the dba01 vantage")

# (c) a scan FROM web01 over mgmt finds nothing (web01 has no route onto 10.60).
from_web = live_red.scan_subnet("range-web01", MGMT, ports=(22,), lo=1, hi=32)
print(f"(c) scan FROM range-web01 over {MGMT}: {from_web}")
assert BASTION not in from_web, f"(c) FAIL: web01 unexpectedly reached db-bastion; got {from_web}"
print(f"(c) OK: the ENTRY (web01) cannot reach {MGMT} — only the dba01 foothold reveals db-bastion")

print("\nSEAM DISCOVERY PROOF PASS: the hop-2 target (db-bastion on mgmt 10.60) is discoverable ONLY "
      "from the dba01 vantage — which t_scan now enumerates (old entry-pinned scan could not).")
