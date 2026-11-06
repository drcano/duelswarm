PYTHON ?= $(shell command -v .venv/bin/python 2>/dev/null || command -v python3 2>/dev/null || echo python)

.PHONY: range-up range-down range-up-unified range-down-unified range-pull smoke duel duel-dry test verify clean all reproduce gate-proof arms-race range-prove-live live-gates

all: test duel-dry   ## self-checks + dry-run (no Docker, no API key needed)

range-up:             ## stand up the range + install the host egress firewall
	docker compose up -d
	@echo "installing the host egress firewall (needs sudo on Linux, no-op elsewhere)…"
	-sudo $(PYTHON) scripts/host_egress_firewall.py --up

range-down:            ## remove the host firewall, then tear down the range
	-sudo $(PYTHON) scripts/host_egress_firewall.py --down
	docker compose down -v

range-up-unified:      ## stand up the seed-1337 UNIFIED seam range (the pilot's range) + host egress firewall + name check
	$(PYTHON) scripts/standup_unified_range.py --up --seed 1337

range-down-unified:    ## tear down the unified seam range + remove its host egress firewall
	$(PYTHON) scripts/standup_unified_range.py --down --seed 1337

range-pull:            ## pre-pull every pool image so the first randomized run doesn't block
	docker pull piesecurity/apache-struts2-cve-2017-5638
	docker pull postgres:16-alpine
	docker pull jenkins/jenkins:lts-alpine
	docker pull nginx:alpine
	-docker pull falcosecurity/falco@sha256:69e957f91b3a6beb5c82e2afae33ec3e4479dab2d4421475d288d0cd113cedf6
	-docker pull metasploitframework/metasploit-framework@sha256:10dc102716318c6e7c232bc39c7dd5938aaa771d05b446f78af0a6199a4676ab

smoke:                 ## one real Nemotron call through Token Factory (needs NEBIUS_API_KEY)
	$(PYTHON) scripts/smoke_test.py

# The ONE measurement engine (2026-10-27 consolidation): the interleaved duel
# (run_interleaved_duel) on the UNIFIED orchestrated range. `make duel` runs it live (PAID,
# gated). The generated range is a FREE dry shakeout only; `--range generated --mode live` is
# refused.
duel:                 ## the ONE measurement engine — interleaved duel on the unified range (PAID, gated; needs range-up + key)
	@echo "PAID measurement (gated). Stand the orchestrated range up first:  make range-up"
	@echo "Then, only on Dante's go:"
	@echo "  $(PYTHON) scripts/live_arms_race_run.py --range unified --mode live --red-matched-tier"

duel-dry:             ## FREE dry shakeout of the discovery-driven engine (no Docker, no API key)
	$(PYTHON) scripts/live_arms_race_run.py --episodes 1 --mode dry

verify:               ## cold re-derivation of every pinned invariant from the raw chains (no Docker/API key)
	$(PYTHON) scripts/prove_engine.py --wall            # generate data/wall/range_0.jsonl so a FRESH CLONE can verify
	$(PYTHON) scripts/verify_chain.py data/wall/range_0.jsonl
	$(PYTHON) scripts/verify_scope.py data/wall/range_0.jsonl
	$(PYTHON) redteam/reverify_floor.py data/wall/range_0.jsonl
	$(PYTHON) redteam/kernel_witness.py data/wall/range_0.jsonl
	$(PYTHON) redteam/verify_io_sidecar.py --selftest
	$(PYTHON) redteam/verify_provider_pin.py --selftest
	$(PYTHON) scripts/mediation/static_coverage.py
	$(PYTHON) scripts/redteam_gate.py
	$(PYTHON) scripts/prove_falsification.py --selftest
	$(PYTHON) docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
	$(PYTHON) scripts/preregister.py --verify

test:                 ## canonical self-checks: gate + one red/blue engine, floor re-derivation, falsification battery, the folded engine selftest + kept proofs (no Docker/API key)
	$(PYTHON) swarm/gate.py && $(PYTHON) swarm/live_agent.py && $(PYTHON) swarm/live_red.py && $(PYTHON) swarm/live_blue_agent.py && $(PYTHON) swarm/coevolve.py
	$(PYTHON) swarm/benign_baseline.py && $(PYTHON) scripts/prove_stealth_detection.py --selftest && $(PYTHON) scripts/prove_stealth_setup.py --selftest
	$(PYTHON) scripts/prove_one_engine.py --selftest
	$(PYTHON) swarm/audit.py
	$(PYTHON) scripts/prove_env_boundaries.py && $(PYTHON) scripts/redteam_gate.py && $(PYTHON) scripts/prove_falsification.py --selftest
	$(PYTHON) scripts/mediation/static_coverage.py && $(PYTHON) scripts/mediation/parser_fuzz.py --selftest && $(PYTHON) scripts/mediation/reachability_probe.py --selftest && $(PYTHON) scripts/mediation/blue_mediation.py --selftest && $(PYTHON) scripts/mediation/egress_mediation.py --selftest
	$(PYTHON) scripts/validation/_common.py && $(PYTHON) scripts/validation/detection_eval.py --selftest && $(PYTHON) scripts/validation/offensive_probe.py --selftest && $(PYTHON) scripts/validation/bloodhound_paths.py --selftest && $(PYTHON) scripts/validation/killchain_replay.py --selftest && $(PYTHON) scripts/validation/leak_test.py && $(PYTHON) scripts/validation/capability_ceiling.py --selftest && $(PYTHON) scripts/validation/oracle_red.py --selftest && $(PYTHON) scripts/validation/boot_witness.py --selftest
	$(PYTHON) scripts/prove_oracle.py --selftest
	$(PYTHON) swarm/topo_to_compose.py --unified
	$(PYTHON) swarm/topo_to_compose.py --held-out && $(PYTHON) scripts/prove_held_out.py --selftest
	$(PYTHON) scripts/ablations.py --selftest && $(PYTHON) scripts/legible_queue.py --selftest
	$(PYTHON) swarm/live_postex.py && $(PYTHON) swarm/live_pivot.py
	$(PYTHON) scripts/prove_engine.py --selftest
	$(PYTHON) scripts/prove_sliver_c2.py --selftest
	$(PYTHON) redteam/verify_io_sidecar.py --selftest
	$(PYTHON) scripts/preregister.py --verify
	$(PYTHON) -c "import sys; sys.path.insert(0,'redteam'); import reverify_floor as r; x=r.reverify('data/wall/range_0.jsonl'); assert x['chain_verified'] and x['oos_executed']==0, x; print(f'reverify_floor (cold): wall range_0 chain_verified={x[\"chain_verified\"]} oos_executed={x[\"oos_executed\"]}')"

arms-race:            ## co-evolution arms race (dry, FREE; add --resume to continue a stopped run)
	$(PYTHON) scripts/live_arms_race_run.py --episodes 3 --mode dry

gate-proof:           ## adversarial proof: no out-of-scope action slips the gate, log is tamper-evident
	$(PYTHON) scripts/redteam_gate.py

range-prove-live:     ## LIVE kernel-level floor proof (needs Docker; minimal range avoids the WebLogic disk wall)
	$(PYTHON) scripts/prove_env_boundaries.py --live --minimal

reproduce:            ## regenerate every artifact + proof from raw logs, seeds seeded (no Docker/API key)
	$(PYTHON) scripts/live_arms_race_run.py --episodes 1 --mode dry
	$(PYTHON) scripts/prove_engine.py --selftest
	$(PYTHON) scripts/verify_chain.py data/wall/range_0.jsonl
	$(PYTHON) scripts/redteam_gate.py

live-gates:           ## live acceptance gates L1-L6 against a live log (needs NEBIUS_API_KEY; SKIPs without)
	$(PYTHON) scripts/live_gates.py $(LOG)

clean:                ## remove generated data
	rm -rf data/
