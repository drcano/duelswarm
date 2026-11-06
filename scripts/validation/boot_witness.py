"""A3 — the per-boot runtime WITNESS assertion for the live unified range.

The reconciler (swarm.live_truth) is correct GIVEN the telemetry witnesses appear; the unit tests
feed those witnesses as FIXTURES (sensor_real / live_telemetry selftests), so they cannot catch a
range whose telemetry does not actually surface live. Two silent failure modes empty the
ground-truth the whole measurement rests on:

  * sshd without `-e`: auth goes to SYSLOG, not stdout, so the destination container's `docker logs`
    carries NO "Accepted" line — the lateral-movement witness vanishes.
  * a mis-mounted docker.sock: Falco still emits syscalls, but every line is `container.name=<NA>`,
    filed under host "?" by live_telemetry.parse_syscall_events — the crown-read witness can no
    longer be ATTRIBUTED to its host.

Either way the reconciler would flag a real red action as uncorroborated, and (post-A1) the co-evo
fitness would score it a red loss, all because a SENSOR was broken — not because red failed. This is
the one-time check that FAILS THE BOOT before any episode is scored against the telemetry: it
triggers a known benign login + a known benign file read on the live range, captures the telemetry
the real engine captures (`docker logs` + Falco stdout), and asserts BOTH witnesses are present and
ATTRIBUTED. The verdict is recorded as a `boot.witness_check` system event on the chain, so a party
trusting neither agent re-derives — cold, from the committed chain — that the telemetry was proven
live before it was trusted.

The pure core (`witness_verdict`) REUSES the real parsers (sensor_real's T1021 "Accepted" Sigma
signature, live_telemetry.parse_syscall_events) — never a second copy — so the boot check and the
reconciler read the same telemetry the same way. `--selftest` re-derives the acceptance cold (no
Docker): a healthy boot records ok=true with both witnesses attributed; a range without sshd `-e`
and one with a mis-mounted docker.sock each FAIL.

Intended driver call site: after the unified range is booted (`make range-up`) and Falco is up, and
BEFORE the first live episode is scored —
    run_boot_witness(log, entry_host,
                     trigger=<one benign `ssh benign_user@range-<host>` that `cat`s a benign file>,
                     capture=lambda: capture_boot_telemetry(entry_host, falco["container"], since=boot_ts),
                     benign_file=<the benign canary path>)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # repo root, so `from swarm import …`

from swarm import sensor_real, live_telemetry   # noqa: E402  (pure parsers; no effect at import)

# Reuse the REAL "Accepted publickey/password" lateral-movement signature (one source of truth with
# the reconciler's detector), so the auth witness is recognized exactly as blue would recognize it.
_AUTH_RX = next(r[1] for r in sensor_real.SIGMA_RULES if r[0] == "T1021")


def _auth_witnessed(dst_logs):
    """True if a benign sshd 'Accepted' auth line is present in the destination container's docker
    logs. A range whose sshd lacks `-e` logs auth to syslog instead of stdout — then `docker logs`
    carries no such line and this is False (the failure the check must catch)."""
    return any(_AUTH_RX.search(ln) for ln in (dst_logs or "").splitlines())


def witness_verdict(*, host, dst_logs, falco_lines, benign_file=None):
    """PURE boot-witness verdict (re-derives cold from captured telemetry; no Docker):

      - auth_witness    : the benign sshd 'Accepted' line surfaced in `host`'s docker logs.
      - syscall_witness : a Falco syscall event is ATTRIBUTED to `range-<host>` (not '?'), and — when
                          `benign_file` is given — mentions that file. A mis-mounted docker.sock
                          files every line under '?', so no event is attributed and this is False.
      - ok              : both witnesses present.

    `syscall_events_{total,attributed,unattributed,other}` localize a failure AND account for every
    event: total>0 with attributed==0 is the docker.sock-mis-mount signature (Falco produces output,
    but unattributed); `other` are events attributed to a DIFFERENT range host (benign-login warmup /
    activity elsewhere) — counted, never a failure. total == attributed + unattributed + other."""
    syscalls = live_telemetry.parse_syscall_events(falco_lines)
    want = f"range-{host}"
    attributed = [e for e in syscalls if e.get("host") == want]
    unattributed = [e for e in syscalls if e.get("host") in ("?", None)]
    other = [e for e in syscalls if e.get("host") not in (want, "?", None)]
    auth_ok = _auth_witnessed(dst_logs)
    syscall_ok = bool(attributed) and (
        benign_file is None
        or any(benign_file in (e.get("signal") or "") or benign_file in (e.get("raw") or "")
               for e in attributed))
    return {
        "host": host,
        "auth_witness": auth_ok,
        "syscall_witness": syscall_ok,
        "syscall_events_total": len(syscalls),
        "syscall_events_attributed": len(attributed),
        "syscall_events_unattributed": len(unattributed),
        "syscall_events_other": len(other),
        "other_basis": ("syscalls Falco attributed to a range host OTHER than range-<host> "
                        "(benign-login warmup / activity on other hosts) — host-attributed and "
                        "accounted for, never a witness failure; only unattributed '?' fails"),
        "benign_file": benign_file,
        "ok": bool(auth_ok and syscall_ok),
        "basis": ("a benign login's 'Accepted' line must surface in the dst container's docker logs "
                  "(catches sshd without -e / auth-to-syslog), AND a benign file-open must surface in "
                  "Falco attributed to range-<host>, not '?' (catches a mis-mounted docker.sock)"),
    }


def capture_boot_telemetry(host, falco_container, *, since=None, runner=None):
    """LIVE capture (needs Docker): the telemetry the real engine captures — the destination
    container's `docker logs` (windowed with `since`) + Falco's emitted lines — reusing
    sensor_real.tail_logs and live_telemetry.read_falco (no second copy). Returns (dst_logs,
    falco_lines)."""
    dst_logs = sensor_real.tail_logs(f"range-{host}", since=since)
    falco_lines = (live_telemetry.read_falco(falco_container, runner=runner) if runner
                   else live_telemetry.read_falco(falco_container))
    return dst_logs, falco_lines


def run_boot_witness(log, host, *, trigger, capture, benign_file=None, settle_s=3, sleeper=None,
                     attempts=6):
    """Run the one-time per-boot witness check on the live range and record it on `log`.

    `trigger()` performs the known benign login + benign file read on `range-<host>` (the driver
    passes a single `ssh benign_user@<host-ip>` that `cat`s the benign canary — one call that raises
    BOTH witnesses). `capture()` returns (dst_logs, falco_lines) — typically `capture_boot_telemetry`.
    Both are injected so the live driver passes real range helpers and the selftest drives it cold.

    The modern-eBPF probe attaches a few seconds AFTER Falco's `docker run`, and its readiness marker
    can precede actual event delivery — so a single benign trigger races the attach and can miss the
    file-open (observed: ~2 of 3 live boots failed on exactly this). The benign canary read is
    idempotent, so this RE-TRIGGERS it up to `attempts` times (settling `settle_s` between), accepting
    the first attempt whose verdict is ok. It does NOT weaken the check — acceptance still requires
    BOTH witnesses genuinely attributed (`witness_verdict` is unchanged); it only stops the trigger
    from firing before the probe is delivering. Only the final (accepted, or last-failed) verdict is
    recorded on the chain.

    Records `boot.witness_check` on the chain either way (transparency / cold re-derivation), then
    RAISES — failing the boot — if either witness is still missing after `attempts`. Returns the
    verdict on success."""
    sleep = sleeper or (lambda s: __import__("time").sleep(s))
    v = None
    for i in range(1, attempts + 1):
        trigger()
        # the out-of-band sensors are async (docker logs / Falco stdout flush after the syscalls, and
        # a just-attached eBPF probe may not be delivering yet); settle before capturing, then re-try
        # the benign read if the probe wasn't live yet. Injectable so the selftest spends no wall-clock.
        sleep(settle_s)
        dst_logs, falco_lines = capture()
        v = witness_verdict(host=host, dst_logs=dst_logs, falco_lines=falco_lines, benign_file=benign_file)
        v["attempt"], v["attempts_max"] = i, attempts
        if v["ok"]:
            break
    log.append("system", "boot.witness_check", v)
    if not v["ok"]:
        raise RuntimeError(
            "range boot FAILED the runtime witness check — the telemetry the reconciler relies on is "
            f"not surfacing live after {v['attempt']}/{attempts} benign re-triggers (fix the sensor, "
            f"do not score episodes against it): {v}")
    return v


def _selftest():
    """FREE, no Docker: re-derive the A3 acceptance cold on fixtures standing in for the telemetry a
    healthy boot and the two broken ranges produce."""
    import json as _json
    import shutil
    import tempfile
    from swarm.eventlog import EventLog

    host = "web01"
    canary = "/etc/boot_witness.canary"
    # A HEALTHY boot: the dst sshd "Accepted" line in its docker logs, and a Falco file-open
    # ATTRIBUTED to range-web01 (container.name enriched because docker.sock is mounted).
    good_logs = ("Server listening on 0.0.0.0 port 22.\n"
                 "sshd[71]: Accepted publickey for svc_boot from 10.9.0.9 port 51002 ssh2\n")
    good_falco = ['{"output":"File opened for reading (file=%s container=range-web01 proc=cat)",'
                  '"output_fields":{"container.name":"range-web01"},'
                  '"priority":"Notice","rule":"Benign read"}' % canary]
    v = witness_verdict(host=host, dst_logs=good_logs, falco_lines=good_falco, benign_file=canary)
    assert v["ok"] and v["auth_witness"] and v["syscall_witness"], v
    assert v["syscall_events_attributed"] == 1 and v["syscall_events_unattributed"] == 0, v
    # every syscall is ACCOUNTED FOR: total == attributed + unattributed + other, and the new
    # syscall_events_other + other_basis fields are present.
    assert "syscall_events_other" in v and v["other_basis"], v
    assert v["syscall_events_total"] == (v["syscall_events_attributed"]
           + v["syscall_events_unattributed"] + v["syscall_events_other"]), v
    # a syscall attributed to ANOTHER range host is counted as `other` (not unattributed, not a fail).
    other_falco = good_falco + ['{"output":"File opened for reading (file=/x container=range-dba01)",'
                                '"output_fields":{"container.name":"range-dba01"},'
                                '"priority":"Notice","rule":"Benign read"}']
    vo = witness_verdict(host=host, dst_logs=good_logs, falco_lines=other_falco, benign_file=canary)
    assert vo["ok"] and vo["syscall_events_other"] == 1 and vo["syscall_events_unattributed"] == 0, vo
    assert vo["syscall_events_total"] == vo["syscall_events_attributed"] + vo["syscall_events_other"], vo

    # the full flow records a `boot.witness_check` event on the chain and RE-DERIVES from it (cold).
    td = Path(tempfile.mkdtemp(prefix="boot_witness_"))
    log = EventLog(td / "boot_ok.jsonl")
    out = run_boot_witness(log, host, trigger=lambda: None,
                           capture=lambda: (good_logs, good_falco),
                           benign_file=canary, sleeper=lambda _s: None)
    assert out["ok"], out
    chain = [_json.loads(x) for x in (td / "boot_ok.jsonl").read_text().splitlines() if x.strip()]
    rec = [e for e in chain if e["action"] == "boot.witness_check"]
    assert len(rec) == 1 and rec[0]["data"]["ok"] is True, rec
    assert rec[0]["data"]["auth_witness"] and rec[0]["data"]["syscall_witness"], rec[0]

    # FAIL MODE 1 — sshd without `-e`: auth goes to SYSLOG, so `docker logs` has NO "Accepted" line.
    # The benign read's syscall is still attributed; the auth witness is absent -> the boot FAILS.
    no_e_logs = "Server listening on 0.0.0.0 port 22.\n<auth went to syslog; no Accepted line here>\n"
    v1 = witness_verdict(host=host, dst_logs=no_e_logs, falco_lines=good_falco, benign_file=canary)
    assert v1["ok"] is False and v1["auth_witness"] is False and v1["syscall_witness"] is True, v1
    log1 = EventLog(td / "boot_no_e.jsonl")
    _raised = False
    try:
        run_boot_witness(log1, host, trigger=lambda: None, capture=lambda: (no_e_logs, good_falco),
                         benign_file=canary, sleeper=lambda _s: None)
    except RuntimeError:
        _raised = True
    assert _raised, "a range without sshd -e must FAIL the boot witness check"
    c1 = [_json.loads(x) for x in (td / "boot_no_e.jsonl").read_text().splitlines() if x.strip()]
    assert any(e["action"] == "boot.witness_check" and e["data"]["ok"] is False for e in c1), c1

    # FAIL MODE 2 — docker.sock MIS-MOUNTED: Falco emits syscalls but container.name=<NA>, so every
    # event is filed under host "?" (unattributed) — the crown open could not be attributed to its
    # host. The boot FAILS even though Falco is producing output.
    na_falco = ['{"output":"File opened for reading (file=%s container=<NA>) ",'
                '"priority":"Notice","rule":"Benign read"}' % canary]
    assert live_telemetry.parse_syscall_events(na_falco)[0]["host"] == "?", \
        "a mis-mounted docker.sock must file the syscall under host '?'"
    v2 = witness_verdict(host=host, dst_logs=good_logs, falco_lines=na_falco, benign_file=canary)
    assert v2["ok"] is False and v2["auth_witness"] is True and v2["syscall_witness"] is False, v2
    assert v2["syscall_events_total"] >= 1 and v2["syscall_events_attributed"] == 0, v2
    log2 = EventLog(td / "boot_na.jsonl")
    _raised = False
    try:
        run_boot_witness(log2, host, trigger=lambda: None, capture=lambda: (good_logs, na_falco),
                         benign_file=canary, sleeper=lambda _s: None)
    except RuntimeError:
        _raised = True
    assert _raised, "a mis-mounted docker.sock must FAIL the boot witness check"
    c2 = [_json.loads(x) for x in (td / "boot_na.jsonl").read_text().splitlines() if x.strip()]
    assert any(e["action"] == "boot.witness_check" and e["data"]["ok"] is False for e in c2), c2

    shutil.rmtree(td, ignore_errors=True)
    print("boot_witness ok (A3): a healthy boot records boot.witness_check{ok:true} with BOTH "
          "witnesses attributed and re-derives cold; a range without sshd -e FAILS (no 'Accepted' "
          "line in docker logs); a mis-mounted docker.sock FAILS (Falco syscalls filed under host "
          "'?', unattributed) — the boot is failed before any episode is scored against the telemetry")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("usage: boot_witness.py --selftest   (the live check runs at range standup; see the module "
          "docstring for the driver call site)")
