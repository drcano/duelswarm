#!/usr/bin/env bash
# Task-2 paid run #1 — best-of-k MEASURED red (SPENDS TOKENS). Per the seq-49 prereg: k=3 draws of the
# map-blind matched-ultra LLM red per range, observe-only blue, budget 44; capability_ceiling takes the
# best funnel per range (corroborated read first). Per draw, the Phase-B recipe: generate+stage -> boot
# -> §E up+verify (ABORT WITHOUT SPEND if not enforced) -> PAID duel -> teardown -> gzip telemetry, drop
# secrets. Resumable: skips a draw whose chain is already archived. Usage: run_task2_bestof3.sh [k] [seeds...]
set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
FW="$ROOT/scripts/host_egress_firewall.py"
PY="$ROOT/.venv/bin/python"
K="${1:-3}"; shift 2>/dev/null || true
SEEDS="${*:-1337 1338 1339 1340 1341 1342 1343 1344 1345 1346}"
BATCH="$ROOT/docs/runs/2026-10-29-task2-run1/bestof3"
LOG="$BATCH/bestof3.log"
mkdir -p "$BATCH"; : > "$LOG"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

[ -f "$ROOT/.env" ] || { say "NO .env (NEBIUS_API_KEY) present -> ABORT before any spend"; exit 9; }

teardown(){ # $1 = compose file, $2 = seed
  sudo -n /usr/bin/python3 "$FW" --down >>"$LOG" 2>&1 || true
  [ -f "$1" ] && docker compose -f "$1" down -v >>"$LOG" 2>&1 || true
  docker rm -f "live_arms_falco_$2" "live_arms_msfrpcd_$2" >/dev/null 2>&1 || true
}

for seed in $SEEDS; do
  for k in $(seq 1 "$K"); do
    OUT="$BATCH/seed$seed/draw$k"; CF="$OUT/docker-compose.gen.yml"
    ch="$OUT/episode01_seed${seed}.jsonl"
    # Resume-safe: skip a draw ONLY if its chain is COMPLETE (carries a duel.verdict). A partial chain
    # from an interrupted/credit-exhausted draw is dropped so it re-runs cleanly, never mistaken for done.
    if [ -f "$ch" ] && grep -q 'duel.verdict' "$ch" 2>/dev/null; then
      say "seed $seed draw $k: complete, skip"; continue; fi
    rm -rf "$OUT"
    mkdir -p "$OUT"
    say "seed $seed draw $k: generate + stage"
    "$PY" -c "from swarm.topo_to_compose import write_unified, stage_foothold_ssh_client as s; write_unified($seed,'$OUT'); s('$OUT')" >>"$LOG" 2>&1 \
      || { say "seed $seed draw $k: GEN FAILED"; continue; }
    say "seed $seed draw $k: boot"
    timeout 600 docker compose -f "$CF" up -d >>"$LOG" 2>&1 || { say "seed $seed draw $k: BOOT FAILED"; teardown "$CF" "$seed"; continue; }
    sleep 6
    cnt=$(docker ps --format '{{.Names}}' | grep -c '^range-'); say "seed $seed draw $k: containers up: $cnt"
    [ "$cnt" -lt 18 ] && { say "seed $seed draw $k: BOOT INCOMPLETE -> skip"; teardown "$CF" "$seed"; continue; }
    sudo -n /usr/bin/python3 "$FW" --up >>"$LOG" 2>&1 || true
    if ! sudo -n /usr/bin/python3 "$FW" --verify 2>>"$LOG" | tee -a "$LOG" | grep -q "RESULT: PASS"; then
      say "seed $seed draw $k: §E NOT ENFORCED -> ABORT this draw (no spend)"; teardown "$CF" "$seed"; continue; fi
    say "seed $seed draw $k: PAID measured duel (matched-ultra, observe-only, budget 44)"
    ( set -a; . "$ROOT/.env"; set +a
      timeout 2400 "$PY" scripts/live_arms_race_run.py --range unified --mode live \
        --seeds "$seed" --turns 44 --red-matched-tier --blue-observe-only --out "$OUT" ) >>"$LOG" 2>&1
    rc=$?; say "seed $seed draw $k: duel rc=$rc"
    teardown "$CF" "$seed"
    [ -f "$OUT/episode01_seed${seed}_telemetry.jsonl" ] && gzip -f "$OUT/episode01_seed${seed}_telemetry.jsonl"
    rm -rf "$OUT/loot" "$OUT/sshstage" "$OUT/docker-compose.gen.yml" \
           "$OUT/red_memory.json" "$OUT/series.json" "$OUT/arsenal_archive.json"
  done
done
say "BEST-OF-$K MEASURED BATCH DONE"
sudo -n /usr/bin/python3 "$FW" --down >/dev/null 2>&1 || true
echo "range containers left: $(docker ps --format '{{.Names}}'|grep -c '^range-')" | tee -a "$LOG"
