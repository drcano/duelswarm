#!/usr/bin/env bash
# Phase-B claim-2 baseline batch runner. Runs the first N=10 of the pre-registered ordered seed list
# that BOOT a valid range, no tuning between seeds, instrument frozen at the anchored HEAD. Per seed:
# generate+stage -> boot -> §E up+verify (abort WITHOUT spend if not enforced) -> paid duel (budget 44,
# matched-ultra, blue observe-only) -> teardown -> archive (gzip telemetry, drop secrets). Every
# excluded seed + reason is logged. Idempotent-ish: skips a seed whose chain is already archived.
set -u
cd "$(dirname "$0")/../../.." || exit 2          # repo root
ROOT="$(pwd)"
BATCH="$ROOT/docs/runs/2026-10-29-phase-b-claim2"
FW="$ROOT/scripts/host_egress_firewall.py"
PY="$ROOT/.venv/bin/python"
SEEDS="1337 1338 1339 1340 1341 1342 1343 1344 1345 1346 1347 1348"
N_TARGET=10
LOG="$BATCH/batch.log"; EXC="$BATCH/exclusions.log"
: > "$LOG"; : > "$EXC"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

teardown(){ # $1 = compose file
  sudo -n /usr/bin/python3 "$FW" --down >>"$LOG" 2>&1 || true
  [ -f "$1" ] && docker compose -f "$1" down -v >>"$LOG" 2>&1 || true
  docker rm -f "live_arms_falco_$2" >/dev/null 2>&1 || true
}

done_count=0
for seed in $SEEDS; do
  [ "$done_count" -ge "$N_TARGET" ] && break
  OUT="$BATCH/seed$seed"; CF="$OUT/docker-compose.gen.yml"
  if [ -f "$OUT/episode01_seed${seed}.jsonl" ]; then
    say "seed $seed: already archived, counting it"; done_count=$((done_count+1)); continue
  fi
  mkdir -p "$OUT"
  say "seed $seed: generate + stage"
  if ! "$PY" -c "from swarm.topo_to_compose import write_unified, stage_foothold_ssh_client as s; write_unified($seed,'$OUT'); s('$OUT')" >>"$LOG" 2>&1; then
    say "seed $seed: GEN FAILED -> excluded (spare pulled)"; echo "$seed gen_failed" >>"$EXC"; continue
  fi
  say "seed $seed: boot range"
  if ! docker compose -f "$CF" up -d >>"$LOG" 2>&1; then
    say "seed $seed: BOOT FAILED -> excluded (spare pulled)"; echo "$seed boot_failed" >>"$EXC"; teardown "$CF" "$seed"; continue
  fi
  cnt=$(docker ps --format '{{.Names}}' | grep -c '^range-')
  if [ "$cnt" -lt 18 ]; then
    say "seed $seed: BOOT INCOMPLETE ($cnt range containers) -> excluded"; echo "$seed boot_incomplete:$cnt" >>"$EXC"; teardown "$CF" "$seed"; continue
  fi
  say "seed $seed: §E up + verify"
  sudo -n /usr/bin/python3 "$FW" --up >>"$LOG" 2>&1 || true
  if ! sudo -n /usr/bin/python3 "$FW" --verify 2>>"$LOG" | tee -a "$LOG" | grep -q "RESULT: PASS"; then
    say "seed $seed: §E NOT ENFORCED -> ABORT (no spend)"; echo "$seed se_not_enforced" >>"$EXC"; teardown "$CF" "$seed"; continue
  fi
  say "seed $seed: PAID duel (--turns 44, matched-ultra, observe-only)"
  ( set -a; . "$ROOT/.env"; set +a
    timeout 1800 "$PY" scripts/live_arms_race_run.py --range unified --mode live \
      --seeds "$seed" --turns 44 --red-matched-tier --blue-observe-only --out "$OUT" ) >>"$LOG" 2>&1
  rc=$?
  say "seed $seed: duel exit rc=$rc"
  teardown "$CF" "$seed"
  # archive: gzip telemetry, drop staged secrets + working files (keep chain + range facts)
  [ -f "$OUT/episode01_seed${seed}_telemetry.jsonl" ] && gzip -f "$OUT/episode01_seed${seed}_telemetry.jsonl"
  rm -rf "$OUT/loot" "$OUT/sshstage" "$OUT/run.log" "$OUT/red_memory.json" "$OUT/series.json" "$OUT/arsenal_archive.json"
  if [ -f "$OUT/episode01_seed${seed}.jsonl" ]; then
    done_count=$((done_count+1)); say "seed $seed: ARCHIVED (valid run #$done_count of $N_TARGET)"
  else
    say "seed $seed: NO CHAIN WRITTEN (run error rc=$rc) -> still a booted seed; recorded as run_error"; echo "$seed run_error_no_chain:rc=$rc" >>"$EXC"
    done_count=$((done_count+1))
  fi
done
say "BATCH COMPLETE: $done_count seed(s) run; exclusions in $EXC"
# final safety: ensure nothing left up
sudo -n /usr/bin/python3 "$FW" --down >/dev/null 2>&1 || true
echo "range containers left: $(docker ps --format '{{.Names}}'|grep -c '^range-')" | tee -a "$LOG"
