#!/usr/bin/env bash
# Task-2 paid run #1 — ORACLE validation on a single in-sample seed (TOKEN-FREE: observe-only, no Nebius).
# Validates the new --oracle live path end-to-end before the token-spending best-of-3 batch. Per the
# Phase-B recipe: generate+stage -> boot -> §E up+verify (ABORT WITHOUT SPEND if not enforced) -> oracle
# duel (budget 44) -> teardown -> gzip telemetry. The oracle is the EXPERT reference (handed the GT
# chain); the prediction is gap 0 (crown looted) within 44 turns. Usage: run_task2_oracle.sh <seed> <outdir>
set -u
cd "$(dirname "$0")/.." || exit 2            # repo root
ROOT="$(pwd)"
SEED="${1:?seed}"; OUT="${2:?outdir}"; VARIANT="${3:-}"   # VARIANT empty = in-sample; else held-out name
FW="$ROOT/scripts/host_egress_firewall.py"
PY="$ROOT/.venv/bin/python"
CF="$OUT/docker-compose.gen.yml"
LOG="$OUT/run.log"
mkdir -p "$OUT"; : > "$LOG"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
teardown(){
  sudo -n /usr/bin/python3 "$FW" --down >>"$LOG" 2>&1 || true
  [ -f "$CF" ] && docker compose -f "$CF" down -v >>"$LOG" 2>&1 || true
  docker rm -f "live_arms_falco_${SEED}" "live_arms_msfrpcd_${SEED}" >/dev/null 2>&1 || true
}

if [ -n "$VARIANT" ]; then
  say "generate + stage (HELD-OUT variant $VARIANT, seed $SEED)"
  "$PY" -c "from swarm.topo_to_compose import write_variant, stage_foothold_ssh_client as s; write_variant('$VARIANT','$OUT'); s('$OUT')" >>"$LOG" 2>&1 \
    || { say "GEN FAILED"; exit 2; }
  RUN_ARGS="--oracle --variant $VARIANT --seeds $SEED"
else
  say "generate + stage (in-sample seed $SEED)"
  "$PY" -c "from swarm.topo_to_compose import write_unified, stage_foothold_ssh_client as s; write_unified($SEED,'$OUT'); s('$OUT')" >>"$LOG" 2>&1 \
    || { say "GEN FAILED"; exit 2; }
  RUN_ARGS="--oracle --seeds $SEED"
fi
say "boot range"
timeout 600 docker compose -f "$CF" up -d >>"$LOG" 2>&1 || { say "BOOT FAILED"; teardown; exit 3; }
sleep 6
cnt=$(docker ps --format '{{.Names}}' | grep -c '^range-')
say "range containers up: $cnt"
[ "$cnt" -lt 18 ] && { say "BOOT INCOMPLETE ($cnt) -> abort"; teardown; exit 4; }
say "§E host-egress firewall up + verify (ABORT WITHOUT SPEND if not enforced)"
sudo -n /usr/bin/python3 "$FW" --up >>"$LOG" 2>&1 || true
if ! sudo -n /usr/bin/python3 "$FW" --verify 2>>"$LOG" | tee -a "$LOG" | grep -q "RESULT: PASS"; then
  say "§E NOT ENFORCED -> ABORT (no run)"; teardown; exit 5
fi
say "ORACLE duel (token-free; --oracle forces budget 44 + observe-only + no-llm) [$RUN_ARGS]"
timeout 1800 "$PY" scripts/live_arms_race_run.py $RUN_ARGS --out "$OUT" >>"$LOG" 2>&1
rc=$?
say "oracle duel exit rc=$rc"
teardown
[ -f "$OUT/episode01_seed${SEED}_telemetry.jsonl" ] && gzip -f "$OUT/episode01_seed${SEED}_telemetry.jsonl"
# drop staged secrets + the secrets-bearing generated compose + working files; keep the chain, the
# Task-1 I/O sidecar, gzipped telemetry, ground_truth + scope (range facts) for cold re-derivation.
rm -rf "$OUT/loot" "$OUT/sshstage" "$OUT/docker-compose.gen.yml" \
       "$OUT/red_memory.json" "$OUT/series.json" "$OUT/arsenal_archive.json"
say "DONE rc=$rc (chain: $OUT/episode01_seed${SEED}.jsonl)"
echo "range containers left: $(docker ps --format '{{.Names}}'|grep -c '^range-')" | tee -a "$LOG"
exit $rc
