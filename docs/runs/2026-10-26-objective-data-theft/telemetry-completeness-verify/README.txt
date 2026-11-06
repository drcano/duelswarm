FREE dry run (no tokens) demonstrating the COMPLETE telemetry record now captured per run:
  - duel chain (episode01_seed1337.jsonl): RED thinking+actions (move.source carries the
    model thought + tool + args; gate.allow/confirm/state.mutate) and BLUE thinking+actions
    (blue move.source reasoning, blue.investigate, blue.detect.*, blue.belief, blue.contain).
  - telemetry chain (episode01_seed1337_telemetry.jsonl): net.flow (connections incl. the
    dmz-web->db-core:22 pivot, attacker->entry, decoy touch), sys.syscall (Falco: execs, opens,
    connects), svc.event (sshd auth, the Struts fault). net.flow now derives from Falco connects
    (intra-bridge flows the host conntrack table cannot see) + conntrack (routed flows).
