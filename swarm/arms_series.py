"""Shared arms-race SERIES driver — the cross-episode host-side state, factored out.

ONE implementation of the machinery both arms-race drivers need, so the convergence
never forks it three ways (consult decision, 2026-10-21):

  * family rotation across the resolved 5-panel (`force_model` is applied by the caller's
    episode body; this module only picks the family per episode),
  * checkpoint / resume — episodic memory, the episode series, AND the service×family
    arsenal archive are written PER EPISODE and decoupled from the ephemeral range, so a
    long run can STOP and CONTINUE and re-spend nothing,
  * the run-dir layout the per-episode acceptance gate reads: `series.json` +
    `arsenal_archive.json` + `episodeNN_seedS.jsonl` (the latter written by `episode_fn`),
  * the floor invariant across the whole run (evasion_vs_gate == 0 on every
    non-degenerate episode).

The PER-EPISODE body is injected as `episode_fn(seed, mode, red_mem, out_dir, *,
episode_idx, family) -> metrics` so the honest discovery-driven driver
(`scripts/live_arms_race_run.py`, live_red) and the quarantined Phase-2 driver
share this file verbatim. `metrics` must carry
`entry_service`, `attacker_model`, `attacker_family`, `evasion_vs_learned_monitor`, and
`evasion_vs_gate`; `degenerate` is optional (defaults False).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python swarm/arms_series.py`

from swarm import episodic                                        # noqa: E402
from swarm.arsenal import ATTACKER_PANEL, LiveArsenalArchive      # noqa: E402


def write_series(series_path, mode, series):
    """Persist the running series — called PER EPISODE so a crash (or an interrupted paid
    live run) never loses completed episodes."""
    Path(series_path).write_text(json.dumps({"mode": mode, "series": series}, indent=2))


def run_series(seeds, mode, out_dir, episode_fn, *, families=None, resume=False,
               verbose=True, memory_side="red"):
    """Run (or resume) an arms-race series with an injected per-episode body.

    `episode_fn(seed, mode, red_mem, out_dir, *, episode_idx, family) -> metrics`.
    Returns the full series; the arsenal archive is written to out_dir/arsenal_archive.json.
    The deterministic floor (evasion_vs_gate == 0 on every non-degenerate episode) is
    asserted across the whole run — a nonzero value aborts loudly (the floor moved)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    series_path = out_dir / "series.json"
    archive_path = out_dir / "arsenal_archive.json"
    red_mem = episodic.EpisodicMemory(out_dir / "red_memory.json", side=memory_side)
    families = list(families or ATTACKER_PANEL)

    series, done_eps = [], set()
    archive = (LiveArsenalArchive.load(archive_path)
               if resume and archive_path.exists() else LiveArsenalArchive())
    if resume and series_path.exists():
        prior = json.loads(series_path.read_text())
        series = prior.get("series", [])
        done_eps = {m["episode"] for m in series}
        if verbose:
            print(f"[resume] loaded {len(series)} completed episode(s) from {series_path}; continuing")

    for i, seed in enumerate(seeds):
        ep_idx = i + 1
        if ep_idx in done_eps:
            if verbose:
                print(f"ep{ep_idx} seed={seed}: already complete — skipped (resume)")
            continue
        family = families[i % len(families)]
        m = episode_fn(seed, mode, red_mem, out_dir, episode_idx=ep_idx, family=family)
        m["episode"] = ep_idx
        series.append(m)
        # Feed the diverse-red archive: keep the strongest (best-evading) red per
        # (service, family) niche. Out-of-arsenal entries are not counted (honest).
        archive.record(m["entry_service"], m["attacker_model"],
                       fitness=m["evasion_vs_learned_monitor"],
                       meta={"episode": ep_idx, "seed": seed})
        if verbose:
            flag = "  [DEGENERATE]" if m.get("degenerate") else ""
            extra = ""
            if "malicious_actions" in m:
                extra = (f" (mal={m['malicious_actions']} det={m.get('detected')} "
                         f"oos={m.get('out_of_scope_attempts')})")
            print(f"ep{ep_idx} seed={seed} svc={m['entry_service']} "
                  f"fam={m['attacker_family']}: "
                  f"evasion_vs_learned={m['evasion_vs_learned_monitor']:.2f} "
                  f"evasion_vs_gate={m['evasion_vs_gate']:.2f}{extra}{flag}")
        # Checkpoint AFTER each episode: lessons + series + archive survive a crash.
        red_mem.save()
        write_series(series_path, mode, series)
        archive.save(archive_path)

    # Invariant across the whole run: the deterministic floor never moved.
    assert all(m["evasion_vs_gate"] == 0.0 for m in series if not m.get("degenerate")), \
        "GATE FAILED during the arms race"
    write_series(series_path, mode, series)
    archive.save(archive_path)
    if verbose:
        warn = "  [COLLAPSED — red homogenized]" if archive.collapsed() else ""
        print(f"arsenal archive: {archive.coverage()}/{archive.cells} cells "
              f"(diversity {archive.diversity():.3f}){warn}")
    return series


if __name__ == "__main__":  # self-check: rotation + resume + archive + floor, no Docker/API
    import tempfile
    from swarm.arsenal import ARSENAL_SERVICES, family_of

    # A trivial injected episode body: cycle the real arsenal services so family rotation
    # (driven by run_series) × service (driven here) spreads the archive. Writes the
    # episode's run-dir file so the layout matches what the acceptance gate reads.
    def _fake_episode(seed, mode, red_mem, out_dir, *, episode_idx, family):
        (out_dir / f"episode{episode_idx:02d}_seed{seed}.jsonl").write_text(
            json.dumps({"seq": 0, "actor": "system", "action": "arsenal",
                        "data": {"episode": episode_idx}}) + "\n")
        # service depends on SEED (few services) so the FAMILY axis is what discriminates
        # diverse from homogeneous — exactly the go/no-go the archive must make.
        svc = ARSENAL_SERVICES[seed % 2]
        return {"entry_service": svc, "attacker_model": family,
                "attacker_family": family_of(family),
                "evasion_vs_learned_monitor": 0.5, "evasion_vs_gate": 0.0,
                "degenerate": False}

    tmp = Path(tempfile.mkdtemp(prefix="arms_series_"))
    s1 = run_series([1, 2, 3], "dry", tmp, _fake_episode, resume=False, verbose=False)
    assert len(s1) == 3 and {m["episode"] for m in s1} == {1, 2, 3}, s1
    assert (tmp / "series.json").exists() and (tmp / "arsenal_archive.json").exists()
    assert all((tmp / f"episode{m['episode']:02d}_seed{m['episode']}.jsonl").exists() for m in s1)
    assert len({m["attacker_family"] for m in s1}) == 3, "family rotation did not vary"

    # Resume: nothing left to do, all episodes skipped, series intact (no recompute/spend).
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        s2 = run_series([1, 2, 3], "dry", tmp, _fake_episode, resume=True, verbose=True)
    assert len(s2) == 3 and buf.getvalue().count("already complete — skipped") == 3, buf.getvalue()

    # The family axis DISCRIMINATES: the full panel out-spreads a single-family control.
    seeds = [11, 22, 33, 44, 55]
    d = Path(tempfile.mkdtemp(prefix="arms_series_div_"))
    run_series(seeds, "dry", d, _fake_episode, resume=False, verbose=False)
    div = LiveArsenalArchive.load(d / "arsenal_archive.json").coverage()
    h = Path(tempfile.mkdtemp(prefix="arms_series_homo_"))
    run_series(seeds, "dry", h, _fake_episode, resume=False, verbose=False,
               families=[ATTACKER_PANEL[0]])
    homo = LiveArsenalArchive.load(h / "arsenal_archive.json").coverage()
    assert div > homo, ("diverse panel did not out-spread homogeneous control", div, homo)

    # The floor invariant aborts loudly if a non-degenerate episode breaches it.
    def _breach(seed, mode, red_mem, out_dir, *, episode_idx, family):
        (out_dir / f"episode{episode_idx:02d}_seed{seed}.jsonl").write_text("{}\n")
        return {"entry_service": "struts", "attacker_model": family,
                "attacker_family": family_of(family),
                "evasion_vs_learned_monitor": 0.3, "evasion_vs_gate": 0.5,  # floor moved!
                "degenerate": False}
    try:
        run_series([7], "dry", Path(tempfile.mkdtemp()), _breach, verbose=False)
        raise SystemExit("floor breach must abort run_series")
    except AssertionError as e:
        assert "GATE FAILED" in str(e), e

    import shutil
    for dd in (tmp, d, h):
        shutil.rmtree(dd, ignore_errors=True)
    print(f"arms_series ok: run-dir (series+archive+episodeNN) written per episode; "
          f"family rotation varies; resume skips completed (no recompute); diverse "
          f"panel out-spreads homogeneous ({div} > {homo}); floor breach aborts loudly")
